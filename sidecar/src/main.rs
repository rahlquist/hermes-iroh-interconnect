//! `hermes-iroh-sidecar` binary.
//!
//! v0.1 control surface (matches ``sidecar_client.py``):
//!
//! ```text
//! sidecar call --endpoint <endpoint-id>   # one JSON request on stdin,
//!                                         # one JSON reply on stdout
//! sidecar serve                           # (reserved) long-lived listener
//! ```
//!
//! The binary owns the Iroh endpoint; the Python plugin never touches
//! sockets (plan §2 architecture boundary). v0.1 ships the loopback-verified
//! echo engine; task forwarding to the local Hermes session lands with the
//! inbound platform adapter.

use std::io::Read;

use anyhow::{bail, Context, Result};
use hermes_iroh_sidecar::transport::{EchoEngine, TaskEngine};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct ControlRequest {
    #[serde(default)]
    #[serde(rename = "endpointId")]
    endpoint_id: String,
    #[serde(default)]
    request: serde_json::Value,
}

fn read_stdin_json() -> Result<ControlRequest> {
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .context("reading control request from stdin")?;
    if buf.len() > hermes_iroh_sidecar::protocol::MAX_FRAME_BYTES {
        bail!("control request too large");
    }
    serde_json::from_slice(&buf).context("control request is not valid JSON")
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("call") => {
            let endpoint = args
                .iter()
                .position(|a| a == "--endpoint")
                .and_then(|i| args.get(i + 1))
                .cloned()
                .unwrap_or_default();
            let req = read_stdin_json()?;
            // v0.1: the echo engine answers tasks without a peer dial.
            // Peer dialing is exercised in the loopback integration tests
            // and lands in the binary once the pairing surface is stable.
            let engine = EchoEngine;
            let text = req
                .request
                .get("payload")
                .and_then(|p| p.get("text"))
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            let request_id = req
                .request
                .get("requestId")
                .and_then(|r| r.as_str())
                .unwrap_or("unknown")
                .to_string();
            let (reply_text, status) = engine.handle_task(
                &hermes_iroh_sidecar::envelope::Envelope {
                    protocol: "hermes-interconnect".to_string(),
                    version: 1,
                    msg_type: "task.request".to_string(),
                    request_id: request_id.clone(),
                    session_id: String::new(),
                    payload: json!({"text": text}),
                },
            );
            let reply = json!({
                "status": status,
                "text": reply_text,
                "endpointId": endpoint,
                "requestId": request_id,
            });
            println!("{}", serde_json::to_string(&reply)?);
            Ok(())
        }
        Some("serve") => {
            bail!("serve mode requires the inbound pairing surface (not yet implemented)")
        }
        Some("version") => {
            println!("hermes-iroh-sidecar {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => {
            bail!("usage: hermes-iroh-sidecar <call --endpoint <id> | serve | version>")
        }
    }
}
