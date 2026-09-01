//! RED tests for inbound hardening: replay protection, concurrency caps,
//! and per-peer rate limiting.
//!
//! Contract (hardening pass):
//! - A `requestId` seen before (within the dedupe window) is rejected with
//!   a structured task.error — the engine is never invoked twice for the
//!   same request.
//! - Concurrent inbound tasks are capped; excess requests get a bounded
//!   task.error rather than growing unbounded work.
//! - Requests arriving faster than the per-peer rate limit get a bounded
//!   task.error (no engine invocation, no queue growth).

use std::sync::atomic::Ordering;

use hermes_iroh_sidecar::envelope::Envelope;
use hermes_iroh_sidecar::guard::GuardError;
use hermes_iroh_sidecar::transport::{PeerContext, TaskEngine};

fn env_with_id(request_id: &str) -> Envelope {
    Envelope {
        protocol: "hermes-interconnect".into(),
        version: 1,
        msg_type: "task.request".into(),
        request_id: request_id.into(),
        session_id: String::new(),
        payload: serde_json::json!({"text": "hi"}),
    }
}

fn peer(id: &str) -> PeerContext {
    PeerContext {
        endpoint_id: id.into(),
    }
}

#[test]
fn rejects_replayed_request_id() {
    let engine = GuardEngine::new(10, 100, 5.0);
    let p = peer("peerz");
    let first = engine.handle_task_from(&p, &env_with_id("req-1"));
    assert_eq!(first.1, "completed");
    let replay = engine.handle_task_from(&p, &env_with_id("req-1"));
    assert_eq!(replay.1, "failed");
    assert!(replay.0.contains("replay"), "replay: {replay:?}");
}

#[test]
fn distinct_request_ids_pass() {
    let engine = GuardEngine::new(10, 100, 5.0);
    let p = peer("peerz");
    for i in 0..5 {
        let out = engine.handle_task_from(&p, &env_with_id(&format!("req-{i}")));
        assert_eq!(out.1, "completed", "out: {out:?}");
    }
}

#[test]
fn enforces_concurrency_cap() {
    // Cap of 1 in-flight task: while one "in flight" (we simulate by not
    // releasing), the second is rejected.
    let engine = GuardEngine::new(1, 100, 5.0);
    let p = peer("peerz");
    engine.acquire();
    let out = engine.handle_task_from(&p, &env_with_id("req-a"));
    assert_eq!(out.1, "failed");
    assert!(out.0.contains("busy"), "out: {out:?}");
    engine.release();
    let out = engine.handle_task_from(&p, &env_with_id("req-b"));
    assert_eq!(out.1, "completed");
}

#[test]
fn enforces_rate_limit_per_peer() {
    // 2 requests per 5s window per peer.
    let engine = GuardEngine::new(10, 2, 5.0);
    let p = peer("peerz");
    assert_eq!(
        engine.handle_task_from(&p, &env_with_id("r1")).1,
        "completed"
    );
    assert_eq!(
        engine.handle_task_from(&p, &env_with_id("r2")).1,
        "completed"
    );
    let third = engine.handle_task_from(&p, &env_with_id("r3"));
    assert_eq!(third.1, "failed");
    assert!(third.0.contains("rate"), "third: {third:?}");
    // A different peer is unaffected.
    let other = peer("otherpeer");
    assert_eq!(
        engine.handle_task_from(&other, &env_with_id("r4")).1,
        "completed"
    );
}

// ---------------------------------------------------------------------------
// Test double: the real GuardedEngine composes the guard + an inner engine.
// ---------------------------------------------------------------------------

struct GuardEngine {
    inner: hermes_iroh_sidecar::guard::Guarded,
    in_flight: std::sync::atomic::AtomicUsize,
}

impl GuardEngine {
    fn new(cap: usize, rate: usize, window: f64) -> Self {
        Self {
            inner: hermes_iroh_sidecar::guard::Guarded::new(cap, rate, window),
            in_flight: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn acquire(&self) {
        self.in_flight
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn release(&self) {
        self.in_flight
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl TaskEngine for GuardEngine {
    fn handle_task(&self, _request: &Envelope) -> (String, String) {
        unreachable!("handle_task_from is always used in these tests")
    }

    fn handle_task_from(&self, peer: &PeerContext, request: &Envelope) -> (String, String) {
        let _guard_error: Option<GuardError> = None;
        match self.inner.admit(
            peer,
            &request.request_id,
            self.in_flight.load(Ordering::SeqCst),
        ) {
            Ok(()) => (
                format!("echo: {:?}", request.payload.get("text")),
                "completed".into(),
            ),
            Err(e) => (format!("guard: {e}"), "failed".into()),
        }
    }
}
