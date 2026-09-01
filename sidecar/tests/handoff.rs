//! RED tests for the file-handoff task engine (sidecar ⇄ adapter bridge).
//!
//! Contract:
//! - On an inbound task, the engine writes `queue/task-<id>.json` with the
//!   peer id, context id, and text.
//! - It then polls for `queue/reply-<id>.json` up to a deadline and returns
//!   the reply as the task result.
//! - Unpaired peers are rejected without touching the queue.
//! - Deadline expiry returns a `failed` status (never hangs the QUIC stream).

use std::time::Duration;

use hermes_iroh_sidecar::envelope::Envelope;
use hermes_iroh_sidecar::handoff::{FileHandoffEngine, HandoffEngine};
use serde_json::json;

fn envelope_for(text: &str) -> Envelope {
    Envelope {
        protocol: "hermes-interconnect".to_string(),
        version: 1,
        msg_type: "task.request".to_string(),
        request_id: "req-77".to_string(),
        session_id: String::new(),
        payload: json!({"text": text}),
    }
}

#[test]
fn writes_task_and_reads_reply() {
    let dir = tempfile::tempdir().unwrap();
    let engine = FileHandoffEngine::new(dir.path(), 10.0);
    let env = envelope_for("hello from the wire");

    let state_dir = dir.path().to_path_buf();
    let writer = std::thread::spawn(move || {
        // Simulate the Python adapter: pick up the task file, write a reply.
        let queue = state_dir.join("queue");
        for _ in 0..100 {
            let found = std::fs::read_dir(&queue)
                .unwrap()
                .filter_map(|e| e.ok())
                .find(|e| {
                    e.file_name().to_string_lossy().starts_with("task-")
                        && !e.file_name().to_string_lossy().ends_with(".tmp")
                });
            if let Some(entry) = found {
                // The file may vanish between listing and reading (the
                // engine cleans up after the deadline); retry the scan.
                let Ok(raw) = std::fs::read_to_string(entry.path()) else {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                };
                let task: serde_json::Value = serde_json::from_str(&raw).unwrap();
                let task_id = task["taskId"].as_str().unwrap().to_string();
                assert_eq!(task["text"], "hello from the wire");
                std::fs::write(
                    queue.join(format!("reply-{task_id}.json")),
                    json!({"taskId": task_id, "status": "completed", "text": "echo back"})
                        .to_string(),
                )
                .unwrap();
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("adapter never saw the task file");
    });

    let (status, text) = engine.handle_task(&env);
    writer.join().unwrap();
    assert_eq!(status, "completed");
    assert_eq!(text, "echo back");
}

#[test]
fn expires_when_no_reply_arrives() {
    let dir = tempfile::tempdir().unwrap();
    let engine = FileHandoffEngine::new(dir.path(), 0.5);
    let (status, text) = engine.handle_task(&envelope_for("nobody home"));
    assert_eq!(status, "failed");
    assert!(text.to_lowercase().contains("timeout") || text.to_lowercase().contains("deadline"));
}

#[test]
fn task_file_contains_peer_and_context() {
    let dir = tempfile::tempdir().unwrap();
    let engine = FileHandoffEngine::new(dir.path(), 3.0);
    let env = envelope_for("meta check");

    let state_dir = dir.path().to_path_buf();
    let inspector = std::thread::spawn(move || {
        let queue = state_dir.join("queue");
        for _ in 0..100 {
            let found = std::fs::read_dir(&queue)
                .unwrap()
                .filter_map(|e| e.ok())
                .find(|e| e.file_name().to_string_lossy().starts_with("task-"));
            if let Some(entry) = found {
                let task: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(entry.path()).unwrap()).unwrap();
                assert!(task["taskId"].as_str().unwrap().starts_with("task-"));
                assert_eq!(task["peerId"], "unknown-peer");
                assert_eq!(task["text"], "meta check");
                // Unblock the engine promptly.
                let task_id = task["taskId"].as_str().unwrap().to_string();
                std::fs::write(
                    queue.join(format!("reply-{task_id}.json")),
                    json!({"taskId": task_id, "status": "completed", "text": "ok"}).to_string(),
                )
                .unwrap();
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("task file never appeared");
    });

    let _ = engine.handle_task(&env);
    inspector.join().unwrap();
}
