//! RED tests for the interconnect envelope (plan §5 envelope sketch).
//!
//! Contract:
//! - `protocol` field must be `"hermes-interconnect"`.
//! - `version` must be `1`.
//! - `type` must be a known v1 message type.
//! - Unknown fields are tolerated (forward compatibility).
//! - Missing required fields fail closed.

use hermes_iroh_sidecar::envelope;

fn base_envelope() -> String {
    r#"{
        "protocol": "hermes-interconnect",
        "version": 1,
        "type": "task.request",
        "requestId": "11111111-2222-3333-4444-555555555555",
        "payload": {"text": "summarize the repo"}
    }"#
    .to_string()
}

#[test]
fn parses_a_valid_task_request() {
    let env = envelope::parse(&base_envelope()).unwrap();
    assert_eq!(env.msg_type, "task.request");
    assert_eq!(env.request_id, "11111111-2222-3333-4444-555555555555");
    assert!(env.payload.get("text").is_some());
}

#[test]
fn tolerates_unknown_fields() {
    let with_extra = base_envelope().replace(
        "}}",
        r#"}, "futureField": {"nested": true}}"#,
    );
    let env = envelope::parse(&with_extra).unwrap();
    assert_eq!(env.msg_type, "task.request");
}

#[test]
fn rejects_wrong_protocol() {
    let bad = base_envelope().replace("hermes-interconnect", "other-protocol");
    let err = envelope::parse(&bad).unwrap_err();
    assert!(err.contains("protocol"), "got: {err}");
}

#[test]
fn rejects_unsupported_version() {
    let bad = base_envelope().replace("\"version\": 1", "\"version\": 99");
    let err = envelope::parse(&bad).unwrap_err();
    assert!(err.contains("version"), "got: {err}");
}

#[test]
fn rejects_unknown_message_type() {
    let bad = base_envelope().replace("task.request", "task.blast");
    let err = envelope::parse(&bad).unwrap_err();
    assert!(err.contains("type"), "got: {err}");
}

#[test]
fn rejects_missing_request_id() {
    let bad = base_envelope()
        .lines()
        .filter(|l| !l.contains("requestId"))
        .collect::<Vec<_>>()
        .join("\n");
    let err = envelope::parse(&bad).unwrap_err();
    assert!(err.contains("requestId"), "got: {err}");
}

#[test]
fn rejects_non_object_payload() {
    let bad = base_envelope().replace(
        "\"payload\": {\"text\": \"summarize the repo\"}",
        "\"payload\": 42",
    );
    let err = envelope::parse(&bad).unwrap_err();
    assert!(err.contains("payload"), "got: {err}");
}

#[test]
fn all_v1_message_types_parse() {
    for t in envelope::V1_MESSAGE_TYPES {
        let raw = base_envelope().replace("task.request", t);
        let env = envelope::parse(&raw).unwrap();
        assert_eq!(env.msg_type, *t);
    }
}

#[test]
fn parses_task_result_and_error_types() {
    for t in ["task.result", "task.error", "task.input_required", "task.progress", "hello", "hello.accepted", "hello.rejected", "ping", "pong", "close"] {
        let raw = base_envelope().replace("task.request", t);
        assert!(envelope::parse(&raw).is_ok(), "type {t} should parse");
    }
}
