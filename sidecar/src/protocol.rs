//! Bounded, length-prefixed JSON frame protocol (plan §5).
//!
//! Every application frame is a 4-byte big-endian length followed by UTF-8
//! JSON. Frames larger than [`MAX_FRAME_BYTES`] are rejected *before* any
//! allocation, so a malicious peer's length prefix cannot cause OOM.

/// Hard cap on a single frame's payload size (4 MiB). Task payloads are
/// text-dominant; this bounds memory per in-flight request.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Encodes `payload` as a frame: `[u32-be length][payload bytes]`.
pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    assert!(
        payload.len() <= MAX_FRAME_BYTES,
        "payload {} exceeds MAX_FRAME_BYTES {}",
        payload.len(),
        MAX_FRAME_BYTES,
    );
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Decodes one frame from the front of `buf`.
///
/// Returns:
/// - `Ok(Some((payload, rest)))` when a complete frame is present;
/// - `Ok(None)` when more bytes are needed (header or payload incomplete);
/// - `Err(message)` when the length exceeds [`MAX_FRAME_BYTES`] or the
///   payload is not valid UTF-8.
///
/// Decoded frame result: the payload slice plus the remaining buffer (for
/// pipelined streams). `None` payload means an empty frame.
pub type DecodedFrame<'a> = Result<Option<(&'a [u8], &'a [u8])>, String>;

pub fn decode_frame(buf: &[u8]) -> DecodedFrame<'_> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&buf[..4]);
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(format!(
            "frame length {len} too large (max {MAX_FRAME_BYTES})"
        ));
    }
    let end = 4 + len;
    if buf.len() < end {
        return Ok(None);
    }
    let payload = &buf[4..end];
    std::str::from_utf8(payload).map_err(|e| format!("frame payload is not valid UTF-8: {e}"))?;
    Ok(Some((payload, &buf[end..])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_matches_be_prefix() {
        assert_eq!(encode_frame(b"ab"), vec![0, 0, 0, 2, b'a', b'b']);
    }
}
