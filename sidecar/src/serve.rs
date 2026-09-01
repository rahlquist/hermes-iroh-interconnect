//! Serve mode: long-lived sidecar process (plan §6 Phase 2).
//!
//! Owns the Iroh endpoint (persistent identity from `identity.rs`) and speaks
//! newline-delimited JSON-RPC on stdio with the Python plugin:
//!
//! ```text
//! -> {"jsonrpc":"2.0","id":1,"method":"status"}
//! <- {"jsonrpc":"2.0","id":1,"result":{"ready":true,"endpointId":"...","alpn":"...","addrs":[...]}}
//!
//! -> {"jsonrpc":"2.0","id":2,"method":"dial","params":{"endpointId":"<z32>",
//!        "addrs":["ip:port",...],"task":{"text":"..."}}}
//! <- {"jsonrpc":"2.0","id":2,"result":{"status":"completed","text":"..."}}
//! ```
//!
//! Malformed lines and unknown methods produce JSON-RPC errors without
//! killing the process.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use iroh::{endpoint::presets, protocol::Router, Endpoint, EndpointAddr, TransportAddr};
use serde::Deserialize;
use serde_json::{json, Value};

use hermes_iroh_sidecar::protocol;
use hermes_iroh_sidecar::transport::{HermesHandler, PeerReply};

/// Endpoint is online when every bound socket reports a confirmed direct
/// address (plan Phase 1 step 7: endpoint.online() timeout).
const ONLINE_TIMEOUT: Duration = Duration::from_secs(20);

/// One stdio JSON-RPC request.
#[derive(Debug, Deserialize)]
struct RpcRequest {
    #[allow(dead_code)]
    #[serde(default)]
    jsonrpc: String,
    #[allow(dead_code)]
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

fn rpc_ok(id: &Value, result: Value) -> String {
    serde_json::to_string(&json!({"jsonrpc": "2.0", "id": id, "result": result}))
        .expect("serialize rpc reply")
}

fn rpc_err(id: &Value, message: String) -> String {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": -32000, "message": message},
    }))
    .expect("serialize rpc error")
}

/// Binds the endpoint with the persistent identity and spawns the router.
pub async fn bind_endpoint(state_dir: &std::path::Path) -> Result<(Endpoint, String)> {
    let key = hermes_iroh_sidecar::identity::load_or_create(state_dir.join("endpoint.key"))?;
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .alpns(vec![hermes_iroh_sidecar::transport::HERMES_ALPN.to_vec()])
        .bind()
        .await
        .context("binding iroh endpoint")?;
    let _ = tokio::time::timeout(ONLINE_TIMEOUT, endpoint.online()).await;
    Ok((endpoint.clone(), endpoint.id().to_z32()))
}

/// Spawns the Hermes acceptor on the endpoint.
///
/// v0.2: inbound tasks are handed to the Python adapter through the
/// file queue (``handoff::FileHandoffEngine``) instead of the echo engine.
pub fn spawn_router(endpoint: &Endpoint, state_dir: &std::path::Path) -> Router {
    let engine = hermes_iroh_sidecar::handoff::FileHandoffEngine::new(
        state_dir,
        std::env::var("HERMES_IROH_HANDOFF_TIMEOUT")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(300.0),
    );
    Router::builder(endpoint.clone())
        .accept(
            hermes_iroh_sidecar::transport::HERMES_ALPN,
            HermesHandler::new(std::sync::Arc::new(engine)),
        )
        .spawn()
}

fn endpoint_addr(id_z32: &str, addrs: &[String]) -> Result<EndpointAddr> {
    let public = iroh::PublicKey::from_z32(id_z32).context("parsing endpoint id")?;
    let mut set = BTreeSet::new();
    for raw in addrs {
        let addr: std::net::SocketAddr = raw
            .parse()
            .with_context(|| format!("parsing peer address {raw:?}"))?;
        set.insert(TransportAddr::Ip(addr));
    }
    Ok(EndpointAddr {
        id: public,
        addrs: set,
    })
}

async fn handle_rpc(endpoint: &Endpoint, req: RpcRequest) -> Result<Value> {
    match req.method.as_str() {
        "status" => Ok(json!({
            "ready": true,
            "endpointId": endpoint.id().to_z32(),
            "alpn": String::from_utf8_lossy(hermes_iroh_sidecar::transport::HERMES_ALPN),
            "addrs": endpoint
                .bound_sockets()
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        })),
        "dial" => {
            let endpoint_id = req
                .params
                .get("endpointId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if endpoint_id.is_empty() {
                bail!("params.endpointId is required");
            }
            let addrs: Vec<String> = req
                .params
                .get("addrs")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let addr = endpoint_addr(&endpoint_id, &addrs)?;

            let text = req
                .params
                .get("task")
                .and_then(|t| t.get("text"))
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            if text.is_empty() {
                bail!("params.task.text is required");
            }
            if text.len() > protocol::MAX_FRAME_BYTES {
                bail!("task text exceeds the frame cap");
            }

            let request = json!({
                "protocol": "hermes-interconnect",
                "version": 1,
                "type": "task.request",
                "requestId": format!("dial-{}", std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis()).unwrap_or(0)),
                "payload": {"text": text},
            });
            let payload = serde_json::to_vec(&request)?;
            let frame = protocol::encode_frame(&payload);

            let reply: PeerReply = tokio::time::timeout(
                Duration::from_secs(120),
                hermes_iroh_sidecar::transport::call_peer(endpoint, addr, frame),
            )
            .await
            .map_err(|_| anyhow::anyhow!("dial timed out after 120s"))??;

            Ok(json!({
                "status": reply.status,
                "text": reply.text,
                "error": reply.error,
            }))
        }
        "shutdown" => Err(anyhow::anyhow!("__shutdown__")),
        other => bail!("unknown method {other:?}"),
    }
}

/// Runs the stdio JSON-RPC loop until stdin closes or a shutdown request.
pub async fn run(state_dir: std::path::PathBuf) -> Result<()> {
    let (endpoint, _id) = bind_endpoint(&state_dir).await?;
    let _router = spawn_router(&endpoint, &state_dir);
    let endpoint = Arc::new(endpoint);

    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break; // stdin closed: clean shutdown
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (id, _method) = match serde_json::from_str::<RpcRequest>(trimmed) {
            Ok(req) => (req.id.clone(), req.method.clone()),
            Err(e) => {
                writeln!(out, "{}", rpc_err(&Value::Null, format!("malformed request: {e}")))?;
                out.flush()?;
                continue;
            }
        };

        let rpc: RpcRequest = serde_json::from_str(trimmed).expect("re-parse validated");
        match handle_rpc(&endpoint, rpc).await {
            Ok(result) => {
                writeln!(out, "{}", rpc_ok(&id, result))?;
            }
            Err(e) if e.to_string() == "__shutdown__" => {
                writeln!(
                    out,
                    "{}",
                    rpc_ok(&id, json!({"bye": true}))
                )?;
                out.flush()?;
                break;
            }
            Err(e) => {
                writeln!(out, "{}", rpc_err(&id, format!("{e:#}")))?;
            }
        }
        out.flush()?;
    }
    Ok(())
}
