//! RED tests for the Hermes interconnect wire protocol framing.
//!
//! Contract (from the feasibility plan §5):
//! - Every application frame is a 4-byte big-endian length followed by UTF-8 JSON.
//! - Frames larger than the hard limit are rejected before allocation.
//! - Malformed (truncated/short) payloads fail closed.

use hermes_iroh_sidecar::protocol;

#[test]
fn round_trips_a_frame() {
    let payload = br#"{"hello":"world"}"#;
    let mut buf = protocol::encode_frame(payload);
    let (frame, rest) = protocol::decode_frame(&buf).unwrap().unwrap();
    assert_eq!(frame, payload);
    assert!(rest.is_empty());
    buf.drain(..(4 + frame.len()));
    assert!(buf.is_empty());
}

#[test]
fn encodes_big_endian_length_prefix() {
    let payload = b"abc";
    let buf = protocol::encode_frame(payload);
    assert_eq!(&buf[..4], &[0, 0, 0, 3]);
    assert_eq!(&buf[4..], b"abc");
}

#[test]
fn multiple_frames_round_trip() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&protocol::encode_frame(br#"{"a":1}"#));
    buf.extend_from_slice(&protocol::encode_frame(br#"{"b":2}"#));
    let (f1, rest) = protocol::decode_frame(&buf).unwrap().unwrap();
    assert_eq!(f1, br#"{"a":1}"#);
    let (f2, rest) = protocol::decode_frame(rest).unwrap().unwrap();
    assert_eq!(f2, br#"{"b":2}"#);
    assert!(rest.is_empty());
}

#[test]
fn incomplete_frame_returns_none() {
    let buf = &protocol::encode_frame(br#"{"partial"#)[..6]; // 4-byte header + 2 bytes
    let result = protocol::decode_frame(buf).unwrap();
    assert!(result.is_none(), "incomplete frame must signal need-for-more");
}

#[test]
fn oversized_length_is_rejected_before_allocation() {
    // A header claiming ~5 GiB must be rejected without allocating.
    let header = (4_294_967_295u32).to_be_bytes(); // u32::MAX — far above the 4 MiB cap
    let err = protocol::decode_frame(&header).unwrap_err();
    assert!(err.contains("too large"), "got: {err}");
}

#[test]
fn exactly_at_limit_is_accepted() {
    let payload = vec![b'x'; protocol::MAX_FRAME_BYTES];
    let buf = protocol::encode_frame(&payload);
    let (frame, _) = protocol::decode_frame(&buf).unwrap().unwrap();
    assert_eq!(frame.len(), protocol::MAX_FRAME_BYTES);
}

#[test]
fn empty_frame_is_valid_json_transport() {
    let buf = protocol::encode_frame(b"{}");
    let (frame, _) = protocol::decode_frame(&buf).unwrap().unwrap();
    assert_eq!(frame, b"{}");
}

#[test]
fn decode_rejects_non_utf8_payload() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0, 0, 0, 2]);
    buf.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
    let err = protocol::decode_frame(&buf).unwrap_err();
    assert!(err.contains("utf"), "got: {err}");
}
