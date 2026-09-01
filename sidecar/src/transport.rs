//! Iroh transport core: endpoint handling, Hermes ALPN handler, and the
//! outbound `call_peer` request path.
//!
//! The inbound side is a [`ProtocolHandler`](iroh::protocol::ProtocolHandler)
//! that reads one bounded frame per bi-stream, validates it as an interconnect
//! envelope, runs the task through the configured [`TaskEngine`], and writes
//! one reply frame. The outbound side dials a peer, sends one request frame,
//! and reads one reply frame — a strict request/response contract that keeps
//! every peer interaction bounded.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr};
use serde::Deserialize;

use crate::envelope::{self, Envelope};
use crate::protocol;

/// Hermes-owned ALPN. Never advertise the generic `/iroh-rings/2`.
pub const HERMES_ALPN: &[u8] = b"/hermes/interconnect/1";

/// Static configuration for the transport layer.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub max_frame_bytes: usize,
    pub request_timeout_secs: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_frame_bytes: protocol::MAX_FRAME_BYTES,
            request_timeout_secs: 300,
        }
    }
}

/// Authenticated identity of the remote peer, captured from the QUIC
/// connection. The `endpoint_id` is asserted by the TLS handshake — it is
/// NOT attacker-controlled claim data — so downstream authorization can
/// trust it as the sender's cryptographic identity (z32 encoding).
#[derive(Clone, Debug)]
pub struct PeerContext {
    pub endpoint_id: String,
}

impl PeerContext {
    pub fn from_connection(conn: &Connection) -> Self {
        Self {
            endpoint_id: conn.remote_id().to_z32(),
        }
    }
}

/// Processes a validated task envelope and produces the reply text + status.
///
/// In the sidecar binary this forwards the text to the local Hermes plugin
/// over the control channel; tests inject a closure. Keeping it a trait
/// object makes the transport layer testable without a live agent.
pub trait TaskEngine: Send + Sync + 'static {
    fn handle_task(&self, request: &Envelope) -> (String, String); // (text, status)

    /// Same, but with the authenticated sender identity. The default
    /// delegates to [`TaskEngine::handle_task`] so existing engines keep
    /// compiling; engines that authorize by peer override this.
    fn handle_task_from(&self, peer: &PeerContext, request: &Envelope) -> (String, String) {
        let _ = peer;
        self.handle_task(request)
    }
}

/// Echo engine used by tests and by the bare sidecar before plugin wiring.
pub struct EchoEngine;

impl TaskEngine for EchoEngine {
    fn handle_task(&self, request: &Envelope) -> (String, String) {
        let text = request
            .payload
            .get("text")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        (format!("echo: {text}"), "completed".to_string())
    }
}

/// Reply extracted from a peer's response frame. The reply payload for a
/// task.result/task.error envelope is nested at `payload.{status,text,error}`
/// (plan §5), so deserialization flattens that here.
#[derive(Debug, Deserialize)]
pub struct PeerReply {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub error: String,
}

impl PeerReply {
    pub fn parse(json: &str) -> Result<PeerReply> {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(rename = "type")]
            msg_type: String,
            #[serde(default)]
            payload: serde_json::Value,
        }
        let wire: Wire =
            serde_json::from_str(json).context("reply frame is not a valid envelope")?;
        let status = wire
            .payload
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let text = wire
            .payload
            .get("text")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let error = wire
            .payload
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        // A task.error envelope carries failure in its type even if no
        // structured status field was written.
        let status = if status.is_empty() && wire.msg_type == "task.error" {
            "failed".to_string()
        } else {
            status
        };
        Ok(PeerReply {
            status,
            text,
            error,
        })
    }
}

/// Inbound per-stream handler: one request frame in, one reply frame out.
///
/// Every request passes the admission guard (replay / concurrency cap /
/// per-peer rate limit) before reaching the task engine; rejected requests
/// get a structured `task.error` and never touch the engine.
#[derive(Clone)]
pub struct HermesHandler {
    engine: Arc<dyn TaskEngine>,
    guard: Arc<crate::guard::Guarded>,
    in_flight: Arc<std::sync::atomic::AtomicUsize>,
    max_frame_bytes: usize,
}

impl Default for HermesHandler {
    fn default() -> Self {
        Self {
            engine: Arc::new(EchoEngine),
            // Defaults: 8 concurrent tasks, 30 req/peer/minute.
            guard: Arc::new(crate::guard::Guarded::new(8, 30, 60.0)),
            in_flight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            max_frame_bytes: protocol::MAX_FRAME_BYTES,
        }
    }
}

impl HermesHandler {
    pub fn new(engine: Arc<dyn TaskEngine>) -> Self {
        Self {
            engine,
            // Defaults: 8 concurrent tasks, 30 req/peer/minute.
            guard: Arc::new(crate::guard::Guarded::new(8, 30, 60.0)),
            in_flight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            max_frame_bytes: protocol::MAX_FRAME_BYTES,
        }
    }

    async fn handle_stream(
        &self,
        _conn: &Connection,
        peer: &PeerContext,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<()> {
        // Read exactly one frame header, reject oversize before allocation.
        let mut header = [0u8; 4];
        recv.read_exact(&mut header)
            .await
            .context("reading frame header")?;
        let len = u32::from_be_bytes(header) as usize;
        if len > self.max_frame_bytes {
            bail!(
                "frame length {len} too large (max {})",
                self.max_frame_bytes
            );
        }
        let mut payload = vec![0u8; len];
        recv.read_exact(&mut payload)
            .await
            .context("reading frame payload")?;

        let text = std::str::from_utf8(&payload).context("frame payload is not valid UTF-8")?;

        // Validate the envelope; malformed input produces task.error, never a panic.
        let reply = match envelope::parse(text) {
            Ok(env) => {
                // Admission guard: replay, concurrency cap, per-peer rate
                // limit. Rejected requests never reach the engine.
                let in_flight = self.in_flight.load(std::sync::atomic::Ordering::SeqCst);
                let guard_result = self.guard.admit(peer, &env.request_id, in_flight);
                if let Err(err) = guard_result {
                    let reply = serde_json::json!({
                        "protocol": envelope::PROTOCOL_NAME,
                        "version": envelope::PROTOCOL_VERSION,
                        "type": "task.error",
                        "requestId": env.request_id,
                        "payload": {"status": "failed", "error": err.to_string()},
                    });
                    let reply_bytes = serde_json::to_vec(&reply)?;
                    send.write_all(&protocol::encode_frame(&reply_bytes))
                        .await?;
                    send.finish()?;
                    return Ok(());
                }
                self.in_flight
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let (reply_text, status) = self.engine.handle_task_from(peer, &env);
                self.in_flight
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                serde_json::json!({
                    "protocol": envelope::PROTOCOL_NAME,
                    "version": envelope::PROTOCOL_VERSION,
                    "type": "task.result",
                    "requestId": env.request_id,
                    "payload": {"status": status, "text": reply_text},
                })
            }
            Err(err) => serde_json::json!({
                "protocol": envelope::PROTOCOL_NAME,
                "version": envelope::PROTOCOL_VERSION,
                "type": "task.error",
                "requestId": "unknown",
                "payload": {"status": "failed", "error": err},
            }),
        };

        let reply_bytes = serde_json::to_vec(&reply)?;
        send.write_all(&protocol::encode_frame(&reply_bytes))
            .await?;
        send.finish()?;
        Ok(())
    }
}

impl std::fmt::Debug for HermesHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HermesHandler")
            .field("max_frame_bytes", &self.max_frame_bytes)
            .finish_non_exhaustive()
    }
}

impl iroh::protocol::ProtocolHandler for HermesHandler {
    async fn accept(&self, conn: Connection) -> Result<(), iroh::protocol::AcceptError> {
        // One bi-stream per request keeps every interaction bounded; the
        // library never grows a queue from remote input. The sender's
        // identity is captured once per connection (TLS-authenticated) and
        // cloned into each per-stream task.
        let peer = PeerContext::from_connection(&conn);
        while let Ok((send, recv)) = conn.accept_bi().await {
            let handler = self.clone();
            let peer = peer.clone();
            let conn = conn.clone();
            tokio::spawn(async move {
                if let Err(e) = handler.handle_stream(&conn, &peer, send, recv).await {
                    // Per-stream errors are logged and dropped; the connection
                    // stays healthy for the next request.
                    eprintln!("hermes-iroh-sidecar: stream error: {e:#}");
                }
            });
        }
        Ok(())
    }
}

/// Dials `addr`, sends one request frame, and reads one reply frame.
pub async fn call_peer(
    endpoint: &Endpoint,
    addr: EndpointAddr,
    request_frame: Vec<u8>,
) -> Result<PeerReply> {
    // Reject oversized requests before opening a connection.
    if request_frame.len() > 4 && request_frame[..4] == 0xFFFF_FFFFu32.to_be_bytes() {
        bail!("frame too large");
    }
    let header_len = u32::from_be_bytes(request_frame[..4].try_into().unwrap()) as usize;
    if header_len > protocol::MAX_FRAME_BYTES {
        bail!(
            "frame length {header_len} too large (max {})",
            protocol::MAX_FRAME_BYTES
        );
    }

    let conn = endpoint.connect(addr, HERMES_ALPN).await?;
    let (mut send, mut recv) = conn.open_bi().await?;

    send.write_all(&request_frame).await?;
    send.finish()?;

    // Read one reply frame with the same bounded contract.
    let mut header = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(120), recv.read_exact(&mut header))
        .await
        .context("timed out waiting for reply header")?
        .context("peer closed before reply header")?;
    let len = u32::from_be_bytes(header) as usize;
    if len > protocol::MAX_FRAME_BYTES {
        bail!("reply frame length {len} too large");
    }
    let mut payload = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(120), recv.read_exact(&mut payload))
        .await
        .context("timed out waiting for reply payload")?
        .context("peer closed before reply payload")?;

    let text = std::str::from_utf8(&payload).context("reply frame payload is not valid UTF-8")?;
    PeerReply::parse(text)
}
