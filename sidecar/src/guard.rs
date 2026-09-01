//! Inbound admission guard: replay protection, concurrency cap, rate limit.
//!
//! Composed in front of any [`crate::transport::TaskEngine`] (or directly
//! by engines) so that hostile peers cannot exhaust the sidecar or the
//! agent behind it:
//!
//! - **Replay protection**: a `requestId` is admitted exactly once within
//!   the dedupe window; repeats are rejected before any work happens.
//! - **Concurrency cap**: the caller reports its in-flight count; admits
//!   are refused above the cap (bounded work, no unbounded queues — the
//!   same principle as the frame cap).
//! - **Per-peer rate limit**: a sliding window bounds requests per peer;
//!   other peers are unaffected.
//!
//! All state is in-memory: restart resets the windows, which is safe
//! because the deadline-bounded handoff plus the adapter's fail-closed
//! peer check remain the real authorization boundary.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::transport::PeerContext;

/// How long a `requestId` is remembered as already-seen.
const DEDUPE_WINDOW: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardError {
    /// This `requestId` was already admitted (replay).
    Replay,
    /// Too many in-flight tasks.
    Busy { cap: usize },
    /// Peer exceeded its request rate.
    RateLimited {
        allowed: usize,
        retry_after_secs: u64,
    },
}

impl std::fmt::Display for GuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Replay => write!(f, "replay rejected: requestId already seen"),
            Self::Busy { cap } => {
                write!(f, "busy: concurrency cap {cap} reached, retry later")
            }
            Self::RateLimited {
                allowed,
                retry_after_secs,
            } => write!(
                f,
                "rate limited: max {allowed} requests in window, retry after {retry_after_secs}s"
            ),
        }
    }
}

struct PeerWindow {
    /// Timestamps of admitted requests inside the current window.
    admitted: Vec<Instant>,
    /// RequestIds seen recently (dedupe), with their admission time.
    seen: Vec<(String, Instant)>,
}

impl PeerWindow {
    fn new() -> Self {
        Self {
            admitted: Vec::new(),
            seen: Vec::new(),
        }
    }
}

/// The admission guard. Cheap to clone behind an Arc; internally locked.
pub struct Guarded {
    cap: usize,
    rate: usize,
    window: f64,
    peers: Mutex<HashMap<String, PeerWindow>>,
}

impl Guarded {
    pub fn new(cap: usize, rate: usize, window_secs: f64) -> Self {
        Self {
            cap,
            rate,
            window: window_secs,
            peers: Mutex::new(HashMap::new()),
        }
    }

    /// Decides whether this request may proceed. `in_flight` is the
    /// caller's current in-flight task count.
    pub fn admit(
        &self,
        peer: &PeerContext,
        request_id: &str,
        in_flight: usize,
    ) -> Result<(), GuardError> {
        if in_flight >= self.cap {
            return Err(GuardError::Busy { cap: self.cap });
        }

        let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let window = Duration::from_secs_f64(self.window);

        let entry = peers
            .entry(peer.endpoint_id.clone())
            .or_insert_with(PeerWindow::new);

        // 1. Replay check (dedupe window is independent of the rate window).
        entry
            .seen
            .retain(|(_, t)| now.duration_since(*t) < DEDUPE_WINDOW);
        if entry.seen.iter().any(|(id, _)| id == request_id) {
            return Err(GuardError::Replay);
        }

        // 2. Rate limit: sliding window of admitted requests.
        entry.admitted.retain(|t| now.duration_since(*t) < window);
        if entry.admitted.len() >= self.rate {
            let oldest = entry.admitted.first().copied();
            let retry = oldest.map(|t| t.duration_since(now)).unwrap_or(window);
            return Err(GuardError::RateLimited {
                allowed: self.rate,
                retry_after_secs: retry.as_secs() + 1,
            });
        }

        // Admitted: record both.
        entry.admitted.push(now);
        entry.seen.push((request_id.to_string(), now));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: &str) -> PeerContext {
        PeerContext {
            endpoint_id: id.into(),
        }
    }

    #[test]
    fn admit_then_replay() {
        let g = Guarded::new(10, 100, 5.0);
        let p = peer("px");
        assert!(g.admit(&p, "r1", 0).is_ok());
        assert_eq!(g.admit(&p, "r1", 0), Err(GuardError::Replay));
    }

    #[test]
    fn busy_when_at_cap() {
        let g = Guarded::new(2, 100, 5.0);
        let p = peer("px");
        assert_eq!(g.admit(&p, "r1", 2), Err(GuardError::Busy { cap: 2 }));
    }

    #[test]
    fn rate_window_per_peer() {
        let g = Guarded::new(10, 2, 5.0);
        let a = peer("a");
        let b = peer("b");
        assert!(g.admit(&a, "1", 0).is_ok());
        assert!(g.admit(&a, "2", 0).is_ok());
        assert!(matches!(
            g.admit(&a, "3", 0),
            Err(GuardError::RateLimited { .. })
        ));
        assert!(g.admit(&b, "1", 0).is_ok());
    }
}
