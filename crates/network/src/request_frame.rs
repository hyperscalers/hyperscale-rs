//! Type-id prefix framing for request-response dispatch.
//!
//! When a request is sent over a stream, it is prefixed with a type identifier
//! so the receiver can dispatch to the correct handler.
//!
//! # Wire Format
//!
//! ```text
//! [type_id_len: u16 LE][type_id: UTF-8][SBOR payload]
//! ```

use thiserror::Error;

/// Errors from request frame parsing.
#[derive(Debug, Error)]
pub enum RequestFrameError {
    #[error("request frame too short")]
    FrameTooShort,

    #[error("invalid type_id: not valid UTF-8")]
    InvalidTypeId,
}

/// Frame a request with a type_id prefix for dispatch by the receiver.
///
/// Used by the `Network::request<R>()` sender to tag opaque request bytes
/// with a type identifier. The receiver (`InboundRouter`) calls
/// [`parse_request_frame`] to extract the type_id and dispatch accordingly.
pub fn frame_request(type_id: &str, payload: &[u8]) -> Vec<u8> {
    let type_id_bytes = type_id.as_bytes();
    let type_id_len = type_id_bytes.len() as u16;
    let mut framed = Vec::with_capacity(2 + type_id_bytes.len() + payload.len());
    framed.extend_from_slice(&type_id_len.to_le_bytes());
    framed.extend_from_slice(type_id_bytes);
    framed.extend_from_slice(payload);
    framed
}

/// Parse a framed request into `(type_id, payload)`.
///
/// Inverse of [`frame_request`]. Returns the type identifier string and
/// the remaining SBOR payload bytes.
pub fn parse_request_frame(data: &[u8]) -> Result<(&str, &[u8]), RequestFrameError> {
    if data.len() < 2 {
        return Err(RequestFrameError::FrameTooShort);
    }
    let type_id_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + type_id_len {
        return Err(RequestFrameError::FrameTooShort);
    }
    let type_id = std::str::from_utf8(&data[2..2 + type_id_len])
        .map_err(|_| RequestFrameError::InvalidTypeId)?;
    let payload = &data[2 + type_id_len..];
    Ok((type_id, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_request_roundtrip() {
        let type_id = "block.request";
        let payload = b"some sbor data here";
        let framed = frame_request(type_id, payload);
        let (parsed_type_id, parsed_payload) = parse_request_frame(&framed).unwrap();
        assert_eq!(parsed_type_id, type_id);
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn test_frame_request_empty_payload() {
        let framed = frame_request("test", b"");
        let (type_id, payload) = parse_request_frame(&framed).unwrap();
        assert_eq!(type_id, "test");
        assert!(payload.is_empty());
    }

    #[test]
    fn test_parse_request_frame_too_short() {
        assert!(matches!(
            parse_request_frame(&[]),
            Err(RequestFrameError::FrameTooShort)
        ));
        assert!(matches!(
            parse_request_frame(&[1]),
            Err(RequestFrameError::FrameTooShort)
        ));
        // type_id_len says 5 but only 2 bytes of type_id available
        assert!(matches!(
            parse_request_frame(&[5, 0, b'a', b'b']),
            Err(RequestFrameError::FrameTooShort)
        ));
    }

    #[test]
    fn test_parse_request_frame_invalid_utf8() {
        // Build a frame with 2-byte type_id containing invalid UTF-8
        let mut data = vec![2, 0]; // type_id_len = 2
        data.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
        data.extend_from_slice(b"payload");
        assert!(matches!(
            parse_request_frame(&data),
            Err(RequestFrameError::InvalidTypeId)
        ));
    }

    #[test]
    fn test_frame_request_long_type_id() {
        let type_id = "a.very.long.message.type.identifier.for.testing";
        let payload = b"data";
        let framed = frame_request(type_id, payload);
        let (parsed_type_id, parsed_payload) = parse_request_frame(&framed).unwrap();
        assert_eq!(parsed_type_id, type_id);
        assert_eq!(parsed_payload, payload);
    }
}
