//! Library surface for the Hermes interconnect sidecar.
//!
//! Exposes the bounded frame protocol so integration tests can exercise the
//! wire contract without spawning processes.

pub mod envelope;
pub mod handoff;
pub mod identity;
pub mod protocol;
pub mod transport;
