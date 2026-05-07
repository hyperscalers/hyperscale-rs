//! Shared SBOR decode helpers.
//!
//! `Vec<u8>` and `Vec<i8>` are the only collection variants where the SBOR
//! decoder pre-allocates `len` bytes up front via `read_slice` (other `Vec<T>`
//! caps `with_capacity` at 1024). Without an explicit length cap a peer can
//! claim up to the entire libp2p frame budget for a single byte field.
//!
//! Set/map decode paths don't pre-allocate, but they still read `len`
//! elements in a loop — bounded helpers reject oversized claims before any
//! per-element work happens.
//!
//! ## No `HashMap`/`HashSet` in wire types
//!
//! SBOR upstream impls `Encode`/`Decode` for `HashMap`/`HashSet`, but their
//! iteration order is undefined — encoding a logically equal value produces
//! different byte sequences across runs, and any merkle root or signature
//! over the bytes diverges. Use `BTreeMap`/`BTreeSet` (or a sorted `Vec`)
//! for fields on any encoded type. Enforced by
//! `crates/types/tests/no_hash_collections_on_wire.rs`.

use std::collections::BTreeSet;

use sbor::{Categorize, Decode, DecodeError, Decoder, NoCustomValueKind, ValueKind};

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

/// Decode a `String` field while rejecting peer-claimed lengths above
/// `max_len` before any allocation. SBOR's default `String` decode reads
/// `len` bytes via `read_slice` up front — same pre-allocation footgun as
/// `Vec<u8>`.
pub fn decode_bounded_string<D: Decoder<NoCustomValueKind>>(
    decoder: &mut D,
    max_len: usize,
) -> Result<String, DecodeError> {
    decoder.read_and_check_value_kind(ValueKind::String)?;
    let len = decoder.read_size()?;
    if len > max_len {
        return Err(DecodeError::UnexpectedSize {
            expected: max_len,
            actual: len,
        });
    }
    let slice = decoder.read_slice(len)?;
    String::from_utf8(slice.to_vec()).map_err(|_| DecodeError::InvalidUtf8)
}

/// Decode a `Vec<T>` field while rejecting peer-claimed lengths above
/// `max_len` before any per-element decode work, and capping the
/// `with_capacity` hint so the pre-allocation can't be driven past the
/// per-element pacing of the rest of the loop.
pub fn decode_bounded_vec<D, T>(decoder: &mut D, max_len: usize) -> Result<Vec<T>, DecodeError>
where
    D: Decoder<NoCustomValueKind>,
    T: Categorize<NoCustomValueKind> + Decode<NoCustomValueKind, D>,
{
    decoder.read_and_check_value_kind(ValueKind::Array)?;
    let element_kind = decoder.read_and_check_value_kind(T::value_kind())?;
    let len = decoder.read_size()?;
    if len > max_len {
        return Err(DecodeError::UnexpectedSize {
            expected: max_len,
            actual: len,
        });
    }
    let mut out = Vec::with_capacity(len.min(1024));
    for _ in 0..len {
        out.push(decoder.decode_deeper_body_with_value_kind(element_kind)?);
    }
    Ok(out)
}

/// Decode a `BTreeSet<T>` field while rejecting peer-claimed lengths above
/// `max_len` before any per-element decode work.
///
/// Mirrors SBOR's `BTreeSet` decode contract: the wire form is an Array of
/// `T`, and a duplicate element is a hard error.
pub fn decode_bounded_btree_set<D, T>(
    decoder: &mut D,
    max_len: usize,
) -> Result<BTreeSet<T>, DecodeError>
where
    D: Decoder<NoCustomValueKind>,
    T: Categorize<NoCustomValueKind> + Decode<NoCustomValueKind, D> + Ord,
{
    decoder.read_and_check_value_kind(ValueKind::Array)?;
    let element_kind = decoder.read_and_check_value_kind(T::value_kind())?;
    let len = decoder.read_size()?;
    if len > max_len {
        return Err(DecodeError::UnexpectedSize {
            expected: max_len,
            actual: len,
        });
    }
    let mut out = BTreeSet::new();
    for _ in 0..len {
        if !out.insert(decoder.decode_deeper_body_with_value_kind(element_kind)?) {
            return Err(DecodeError::DuplicateKey);
        }
    }
    Ok(out)
}
