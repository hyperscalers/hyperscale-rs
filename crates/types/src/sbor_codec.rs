//! Shared SBOR decode helpers.
//!
//! `Vec<u8>` and `Vec<i8>` are the only collection variants where the SBOR
//! decoder pre-allocates `len` bytes up front via `read_slice` (other `Vec<T>`
//! caps `with_capacity` at 1024). Without an explicit length cap a peer can
//! claim up to the entire libp2p frame budget for a single byte field.

use sbor::{DecodeError, Decoder, NoCustomValueKind, ValueKind};

/// Decode a `Vec<u8>` field while rejecting peer-claimed lengths above
/// `max_len` before any allocation.
pub fn decode_bounded_bytes<D: Decoder<NoCustomValueKind>>(
    decoder: &mut D,
    max_len: usize,
) -> Result<Vec<u8>, DecodeError> {
    decoder.read_and_check_value_kind(ValueKind::Array)?;
    decoder.read_and_check_value_kind(ValueKind::U8)?;
    let len = decoder.read_size()?;
    if len > max_len {
        return Err(DecodeError::UnexpectedSize {
            expected: max_len,
            actual: len,
        });
    }
    let slice = decoder.read_slice(len)?;
    Ok(slice.to_vec())
}
