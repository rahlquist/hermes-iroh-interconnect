//! File-handoff bridge between the sidecar's inbound QUIC handler and the
//! Python adapter (v0.2 inbound path).
//!
//! The sidecar accepts peer tasks over QUIC but does NOT run an agent. It
//! hands each task to the Python adapter through the state directory:
//!
//! ```text
//! sidecar (QUIC accept)                python adapter (poll loop)
//!   write queue/task-<id>.json  ──────►  read task file
//!   poll queue/reply-<id>.json  ◄──────  write reply file
//!   return reply on QUIC stream
//! ```
//!
//! This keeps the plugin side socket-free (plan §2) and every handoff
//! bounded: the engine polls on a deadline and returns `failed` when the
//! adapter does not answer in time.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::json;

use crate::envelope::Envelope;

/// Contract shared with the transport layer (per-stream task handler).
///
/// Note the tuple orders: `TaskEngine::handle_task` returns `(text, status)`
/// while `HandoffEngine::handle_task` returns `(status, text)`; this impl
/// converts between them.
impl crate::transport::TaskEngine for FileHandoffEngine {
    fn handle_task(&self, request: &Envelope) -> (String, String) {
        let (status, text) = HandoffEngine::handle_task(self, request);
        (text, status)
    }

    fn handle_task_from(
        &self,
        peer: &crate::transport::PeerContext,
        request: &Envelope,
    ) -> (String, String) {
        // The sender's endpoint id comes from the authenticated TLS
        // handshake, not from envelope content. It is written verbatim so
        // the adapter can authorize against the peer store; unpaired
        // senders are rejected there (fail closed).
        let (status, text) = FileHandoffEngine::handle_task_for(self, peer, request);
        (text, status)
    }
}

/// Contract shared with the Python adapter and the serve-mode wiring.
pub trait HandoffEngine: Send + Sync + 'static {
    /// Runs one task through the handoff. Returns `(status, text)`.
    fn handle_task(&self, request: &Envelope) -> (String, String);
}

/// File-queue handoff rooted at the plugin state directory.
pub struct FileHandoffEngine {
    state_dir: PathBuf,
    deadline_secs: f64,
}

impl FileHandoffEngine {
    pub fn new(state_dir: &Path, deadline_secs: f64) -> Self {
        Self {
            state_dir: state_dir.to_path_buf(),
            deadline_secs,
        }
    }

    fn queue_dir(&self) -> PathBuf {
        self.state_dir.join("queue")
    }
}

impl HandoffEngine for FileHandoffEngine {
    fn handle_task(&self, request: &Envelope) -> (String, String) {
        // No authenticated identity available (e.g. echo/loopback paths):
        // tagged `unknown-peer`, which the adapter rejects fail-closed.
        self.handle_task_for(
            &crate::transport::PeerContext {
                endpoint_id: "unknown-peer".to_string(),
            },
            request,
        )
    }
}

impl FileHandoffEngine {
    /// Peer-aware handoff: `peer.endpoint_id` is the TLS-authenticated
    /// sender identity (z32). Written verbatim as the task's `peerId`; the
    /// Python adapter maps it to a paired peer and rejects unknown ids.
    pub fn handle_task_for(
        &self,
        peer: &crate::transport::PeerContext,
        request: &Envelope,
    ) -> (String, String) {
        let queue = self.queue_dir();
        let _ = std::fs::create_dir_all(&queue);

        let task_id = format!(
            "task-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        );
        let text = request
            .payload
            .get("text")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let task = json!({
            "taskId": task_id,
            "peerId": peer.endpoint_id,
            "peerIdSource": "tls-authenticated",
            "contextId": request.request_id,
            "text": text,
        });
        let task_path = queue.join(format!("{task_id}.json"));
        let tmp_path = queue.join(format!("{task_id}.json.tmp"));
        if let Err(e) = std::fs::write(&tmp_path, serde_json::to_string(&task).unwrap()) {
            return ("failed".into(), format!("handoff write failed: {e}"));
        }
        if let Err(e) = std::fs::rename(&tmp_path, &task_path) {
            return ("failed".into(), format!("handoff rename failed: {e}"));
        }

        let reply_path = queue.join(format!("reply-{task_id}.json"));
        let deadline = std::time::Instant::now() + Duration::from_secs_f64(self.deadline_secs);
        loop {
            if std::time::Instant::now() >= deadline {
                let _ = std::fs::remove_file(&task_path);
                return (
                    "failed".into(),
                    "adapter deadline exceeded (no reply file before timeout)".into(),
                );
            }
            if let Ok(raw) = std::fs::read_to_string(&reply_path) {
                if let Ok(reply) = serde_json::from_str::<serde_json::Value>(&raw) {
                    let _ = std::fs::remove_file(&reply_path);
                    let _ = std::fs::remove_file(&task_path);
                    let status = reply
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("failed")
                        .to_string();
                    let text = reply
                        .get("text")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    return (status, text);
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}
