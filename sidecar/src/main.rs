//! `hermes-iroh-sidecar` binary.
//!
//! Control surface:
//!
//! ```text
//! sidecar serve --state-dir <dir>          # long-lived: NDJSON JSON-RPC on stdio
//! sidecar call --endpoint <endpoint-id>    # one-shot: request on stdin, reply on stdout
//! sidecar version
//! ```
//!
//! The binary owns the Iroh endpoint; the Python plugin never touches
//! sockets (plan §2 architecture boundary).

#[path = "serve.rs"]
mod serve;

use std::io::Read;

use anyhow::{bail, Context, Result};
use hermes_iroh_sidecar::transport::{EchoEngine, TaskEngine};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct ControlRequest {
    #[serde(default)]
    #[serde(rename = "endpointId")]
    #[allow(dead_code)] // accepted for CLI-shape compatibility; serve mode owns dialing
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
        Some("id") => {
            // Print this machine's persistent endpoint id (z32) without
            // binding any network: derive the public key from (or reuse)
            // the persistent endpoint key, then encode it.
            let state_dir = args
                .iter()
                .position(|a| a == "--state-dir")
                .and_then(|i| args.get(i + 1))
                .map(std::path::PathBuf::from)
                .unwrap_or_else(default_state_dir);
            let key =
                hermes_iroh_sidecar::identity::load_or_create(state_dir.join("endpoint.key"))?;
            let id = iroh::EndpointId::from(key.public());
            println!("{}", serde_json::json!({"endpointId": id.to_z32()}));
            Ok(())
        }
        Some("addr") => {
            // Bind the endpoint briefly (persistent identity + ALPN), print
            // the endpoint id and direct addresses, then exit. Used by the
            // ticket flow so pairing tickets can carry dialable addrs.
            let state_dir = args
                .iter()
                .position(|a| a == "--state-dir")
                .and_then(|i| args.get(i + 1))
                .map(std::path::PathBuf::from)
                .unwrap_or_else(default_state_dir);
            let relay = args
                .iter()
                .position(|a| a == "--relay")
                .and_then(|i| args.get(i + 1))
                .map(|s| serve::RelayPolicy::parse(s))
                .unwrap_or(serve::RelayPolicy::Default);
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let info = runtime.block_on(serve::endpoint_info(&state_dir, &relay))?;
            println!("{}", serde_json::to_string(&info)?);
            Ok(())
        }
        Some("serve") => {
            let state_dir = args
                .iter()
                .position(|a| a == "--state-dir")
                .and_then(|i| args.get(i + 1))
                .map(std::path::PathBuf::from)
                .unwrap_or_else(default_state_dir);
            let relay = args
                .iter()
                .position(|a| a == "--relay")
                .and_then(|i| args.get(i + 1))
                .map(|s| serve::RelayPolicy::parse(s))
                .unwrap_or(serve::RelayPolicy::Default);
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let keep_alive = args.iter().any(|a| a == "--keep-alive");
            runtime.block_on(serve::run(state_dir, &relay, keep_alive))
        }
        Some("call") => {
            let endpoint = args
                .iter()
                .position(|a| a == "--endpoint")
                .and_then(|i| args.get(i + 1))
                .cloned()
                .unwrap_or_default();
            let req = read_stdin_json()?;
            // One-shot mode answers via the echo engine without a peer dial;
            // remote dialing goes through `serve` + the `dial` method.
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
            let (reply_text, status) =
                engine.handle_task(&hermes_iroh_sidecar::envelope::Envelope {
                    protocol: "hermes-interconnect".to_string(),
                    version: 1,
                    msg_type: "task.request".to_string(),
                    request_id: request_id.clone(),
                    session_id: String::new(),
                    payload: json!({"text": text}),
                });
            let reply = json!({
                "status": status,
                "text": reply_text,
                "endpointId": endpoint,
                "requestId": request_id,
            });
            println!("{}", serde_json::to_string(&reply)?);
            Ok(())
        }
        Some("version") => {
            println!("hermes-iroh-sidecar {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => {
            bail!("usage: hermes-iroh-sidecar <serve --state-dir <dir> | call --endpoint <id> | version>")
        }
    }
}

fn default_state_dir() -> std::path::PathBuf {
    if let Ok(home) = std::env::var("HERMES_HOME") {
        return std::path::PathBuf::from(home).join("iroh-interconnect");
    }
    dirs_home().join(".hermes/iroh-interconnect")
}

fn dirs_home() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}
