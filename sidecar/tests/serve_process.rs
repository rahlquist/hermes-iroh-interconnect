//! RED tests for the sidecar `serve` mode, driven as a REAL subprocess.
//!
//! Contract (plan §6 Phase 2 / §5):
//! - `serve` binds the Iroh endpoint with a persistent identity and speaks
//!   newline-delimited JSON-RPC on stdio.
//! - `status` reports endpoint id, alpn, ready state.
//! - `dial` connects to a peer by EndpointId (z32) + addresses and performs
//!   one task round trip through the Hermes ALPN handler.
//! - Unknown methods error; malformed lines error without killing the process.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct ServeProc {
    child: Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

impl ServeProc {
    fn spawn(binary: &std::path::Path, state_dir: &std::path::Path) -> Self {
        let mut child = Command::new(binary)
            .arg("serve")
            .arg("--state-dir")
            .arg(state_dir)
            .env("HERMES_IROH_TEST", "1")
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
        let line = serde_json::to_string(&req).unwrap();
        writeln!(self.stdin, "{line}").unwrap();
        self.stdin.flush().unwrap();
        let mut out = String::new();
        self.stdout.read_line(&mut out).expect("read reply line");
        serde_json::from_str(out.trim()).expect("reply is JSON")
    }
}

impl Drop for ServeProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_ready(p: &mut ServeProc) -> serde_json::Value {
    for _ in 0..120 {
        let reply = p.rpc(serde_json::json!({"jsonrpc":"2.0","id":1,"method":"status"}));
        if reply["result"]["ready"].as_bool() == Some(true) {
            return reply;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("serve never became ready");
}

fn binary() -> std::path::PathBuf {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/debug/hermes-iroh-sidecar");
    // The test harness builds the bin via cargo test; ensure it exists.
    assert!(p.exists(), "sidecar binary missing at {p:?} (run cargo build)");
    p
}

#[test]
fn serve_reports_status_with_stable_endpoint_id() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = ServeProc::spawn(&binary(), dir.path());

    let reply = wait_ready(&mut p);
    let id = reply["result"]["endpointId"].as_str().unwrap().to_string();
    assert_eq!(id.len(), 52, "z32 endpoint id");
    assert_eq!(reply["result"]["alpn"], "/hermes/interconnect/1");

    // Identity persists across a restart.
    drop(p);
    let mut p2 = ServeProc::spawn(&binary(), dir.path());
    let reply2 = wait_ready(&mut p2);
    assert_eq!(
        reply2["result"]["endpointId"].as_str().unwrap(),
        id,
        "endpoint id must survive restart"
    );
}

#[test]
fn serve_rejects_unknown_method_without_dying() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = ServeProc::spawn(&binary(), dir.path());
    wait_ready(&mut p);

    let reply = p.rpc(serde_json::json!({"jsonrpc":"2.0","id":2,"method":"explode"}));
    assert!(reply["error"].is_object(), "got: {reply}");

    // Process still alive: a subsequent status succeeds.
    let ok = p.rpc(serde_json::json!({"jsonrpc":"2.0","id":3,"method":"status"}));
    assert_eq!(ok["result"]["ready"], true);
}

#[test]
fn dial_performs_full_task_round_trip_between_two_serve_processes() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();

    let mut a = ServeProc::spawn(&binary(), dir_a.path());
    let mut b = ServeProc::spawn(&binary(), dir_b.path());
    let ready_b = wait_ready(&mut b);
    let id_b = ready_b["result"]["endpointId"].as_str().unwrap().to_string();
    let addrs_b: Vec<String> = ready_b["result"]["addrs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(!addrs_b.is_empty(), "peer B must expose at least one address");

    // Serve-mode B hands inbound tasks to its file queue; a thread answers
    // them the way the Python adapter would (write reply-*.json). It exits
    // as soon as its stop flag is set so join() cannot hang the test.
    let b_state = dir_b.path().to_path_buf();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_writer = stop.clone();
    let adapter = std::thread::spawn(move || {
        let queue = b_state.join("queue");
        while !stop_writer.load(std::sync::atomic::Ordering::SeqCst) {
            let entries: Vec<_> = std::fs::read_dir(&queue)
                .map(|rd| rd.filter_map(|e| e.ok()).collect())
                .unwrap_or_default();
            for entry in entries {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.starts_with("task-") || name.ends_with(".tmp") {
                    continue;
                }
                if let Ok(task) =
                    serde_json::from_str::<serde_json::Value>(
                        &std::fs::read_to_string(entry.path()).unwrap_or_default(),
                    )
                {
                    if let Some(task_id) = task["taskId"].as_str() {
                        std::fs::write(
                            queue.join(format!("reply-{task_id}.json")),
                            serde_json::json!({
                                "taskId": task_id,
                                "status": "completed",
                                "text": format!("echo: {}", task["text"].as_str().unwrap_or(""))
                            })
                            .to_string(),
                        )
                        .unwrap();
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });

    // A dials B by endpoint id + addresses; the handoff+adapter answers.
    let reply = a.rpc(serde_json::json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "dial",
        "params": {
            "endpointId": id_b,
            "addrs": addrs_b,
            "task": {"text": "what is 2+2?"}
        }
    }));
    let result = &reply["result"];
    assert_eq!(result["status"], "completed", "got: {reply}");
    assert!(
        result["text"].as_str().unwrap().contains("what is 2+2?"),
        "got: {reply}"
    );
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    adapter.join().ok();
}
