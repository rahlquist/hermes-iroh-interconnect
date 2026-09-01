//! Interconnect envelope: validated JSON message contract (plan §5).
//!
//! Every frame payload is an envelope. Parsing is fail-closed on protocol
//! identity, version, message type, and required fields; unknown fields are
//! tolerated for forward compatibility.

use serde::Deserialize;

pub const PROTOCOL_NAME: &str = "hermes-interconnect";
pub const PROTOCOL_VERSION: u32 = 1;

/// All message types accepted in v1.
pub const V1_MESSAGE_TYPES: &[&str] = &[
    "hello",
    "hello.accepted",
    "hello.rejected",
    "pair.request",
    "pair.confirmed",
    "pair.rejected",
    "task.request",
    "task.progress",
    "task.result",
    "task.input_required",
    "task.error",
    "ping",
    "pong",
    "peer.revoked",
    "close",
];

/// A validated interconnect envelope.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Envelope {
    pub protocol: String,
    pub version: u32,
    #[serde(rename = "type")]
    pub msg_type: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(default)]
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(default)]
    pub payload: serde_json::Value,
}

/// Parses and validates a JSON envelope from a frame payload.
///
/// Unknown fields are ignored. Violations of the v1 contract return a
/// descriptive error string (fail closed).
pub fn parse(json: &str) -> Result<Envelope, String> {
    let env: Envelope =
        serde_json::from_str(json).map_err(|e| format!("invalid envelope JSON: {e}"))?;

    if env.protocol != PROTOCOL_NAME {
        return Err(format!(
            "unknown protocol {:?} (expected {PROTOCOL_NAME:?})",
            env.protocol
        ));
    }
    if env.version != PROTOCOL_VERSION {
        return Err(format!(
            "unsupported protocol version {} (expected {PROTOCOL_VERSION})",
            env.version
        ));
    }
    if !V1_MESSAGE_TYPES.contains(&env.msg_type.as_str()) {
        return Err(format!(
            "unknown message type {:?}; known types: {}",
            env.msg_type,
            V1_MESSAGE_TYPES.join(", ")
        ));
    }
    if env.request_id.trim().is_empty() {
        return Err("requestId must be a non-empty string".to_string());
    }
    if !env.payload.is_null() && !env.payload.is_object() && !env.payload.is_string() {
        return Err("payload must be an object or string".to_string());
    }
    Ok(env)
}
