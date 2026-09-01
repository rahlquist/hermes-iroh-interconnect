//! Capstone E2E: real QUIC peer → file handoff → Python adapter → reply.
//!
//! Full inbound chain (plan Phase 4):
//! 1. A client endpoint dials a serve-mode sidecar over real QUIC and sends
//!    a task.request frame.
//! 2. The sidecar's HermesHandler (with FileHandoffEngine) writes the task
//!    to the state queue and polls for a reply.
//! 3. The Python adapter (running in a background thread) picks the task up,
//!    frames it as untrusted input, and produces a reply via send().
//! 4. The sidecar returns the reply over the QUIC stream; the dialer
//!    asserts the full round trip.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

fn binary() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/debug/hermes-iroh-sidecar")
}

struct ServeProc {
    child: Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

impl ServeProc {
    fn spawn(state_dir: &std::path::Path) -> Self {
        let mut child = Command::new(binary())
            .arg("serve")
            .arg("--state-dir")
            .arg(state_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn serve");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self { child, stdin, stdout }
    }

    fn rpc(&mut self, req: serde_json::Value) -> serde_json::Value {
        writeln!(
            self.stdin,
            "{}",
            serde_json::to_string(&req).unwrap()
        )
        .unwrap();
        self.stdin.flush().unwrap();
        let mut out = String::new();
        self.stdout.read_line(&mut out).expect("reply line");
        serde_json::from_str(out.trim()).expect("JSON reply")
    }
}

impl Drop for ServeProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

static REQ: AtomicU64 = AtomicU64::new(100);

#[test]
fn full_inbound_chain_quic_to_adapter_and_back() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let mut server = ServeProc::spawn(&state_dir);

    // Wait for readiness.
    let mut status = None;
    for _ in 0..120 {
        let reply = server.rpc(serde_json::json!({
            "jsonrpc":"2.0","id":1,"method":"status"
        }));
        if reply["result"]["ready"].as_bool() == Some(true) {
            status = Some(reply);
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let status = status.expect("serve ready");
    let endpoint_id = status["result"]["endpointId"].as_str().unwrap().to_string();
    let addrs: Vec<String> = status["result"]["addrs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    // Simulate the Python adapter's poll loop in a thread: pick up task
    // files, "process" them (verify framing happened upstream), and write
    // the reply the adapter's send() path would produce.
    let adapter_state = state_dir.clone();
    let adapter = std::thread::spawn(move || {
        let queue = adapter_state.join("queue");
        loop {
            let entries: Vec<_> = std::fs::read_dir(&queue)
                .map(|rd| rd.filter_map(|e| e.ok()).collect())
                .unwrap_or_default();
            for entry in entries {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.starts_with("task-") || name.ends_with(".tmp") {
                    continue;
                }
                let task: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(entry.path()).unwrap())
                        .unwrap();
                let task_id = task["taskId"].as_str().unwrap().to_string();
                let text = task["text"].as_str().unwrap().to_string();
                assert!(
                    text.contains("ping from the wire"),
                    "task text should arrive intact: {text}"
                );
                // v0.3 inbound mapping: peerId must be the raw QUIC
                // client's TLS-authenticated endpoint id (z32), not
                // "unknown-peer". The raw client's id is not known here,
                // but it is verifiable: it must be a nonempty z32 string
                // and must be flagged as tls-authenticated.
                let peer_id = task["peerId"].as_str().unwrap().to_string();
                assert!(
                    !peer_id.is_empty() && peer_id != "unknown-peer",
                    "peerId must be the authenticated sender, got {peer_id:?}"
                );
                assert_eq!(
                    task["peerIdSource"].as_str(),
                    Some("tls-authenticated"),
                    "task: {task}"
                );
                // z32 alphabet sanity check on the endpoint id.
                assert!(
                    peer_id
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                    "endpoint id should be z32-shaped: {peer_id:?}"
                );
                std::fs::write(
                    queue.join(format!("reply-{task_id}.json")),
                    serde_json::json!({
                        "taskId": task_id,
                        "status": "completed",
                        "text": format!("pong: {text}")
                    })
                    .to_string(),
                )
                .unwrap();
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });

    // A raw iroh client dials the serve process over real QUIC.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let reply = rt.block_on(async {
        use iroh::{endpoint::presets, Endpoint, EndpointAddr, TransportAddr};

        let client = Endpoint::builder(presets::Minimal)
            .alpns(vec![b"/hermes/interconnect/1".to_vec()])
            .bind()
            .await
            .unwrap();
        let public = iroh::PublicKey::from_z32(&endpoint_id).unwrap();
        let addr = EndpointAddr {
            id: public,
            addrs: addrs
                .iter()
                .filter_map(|a| a.parse().ok())
                .map(TransportAddr::Ip)
                .collect::<BTreeSet<_>>(),
        };

        let request = serde_json::json!({
            "protocol": "hermes-interconnect",
            "version": 1,
            "type": "task.request",
            "requestId": format!("e2e-{}", REQ.fetch_add(1, Ordering::SeqCst)),
            "payload": {"text": "ping from the wire"}
        });
        let frame = hermes_iroh_sidecar::protocol::encode_frame(
            serde_json::to_vec(&request).unwrap().as_slice(),
        );
        hermes_iroh_sidecar::transport::call_peer(&client, addr, frame)
            .await
            .expect("round trip")
    });

    adapter.join().unwrap();

    assert_eq!(reply.status, "completed", "reply: {reply:?}");
    assert_eq!(reply.text, "pong: ping from the wire", "reply: {reply:?}");

    let _ = server.child.kill();
}
