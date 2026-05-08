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
use std::fmt::{self, Display, Formatter};
use std::ops::Deref;

use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, ValueKind,
};

/// Returned by the `try_from_*` constructors on `Bounded*` types when an
/// input exceeds the type's `MAX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedLengthError {
    /// The compile-time maximum.
    pub max: usize,
    /// The actual length of the rejected input.
    pub actual: usize,
}

impl Display for BoundedLengthError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "bounded value overflow: max {}, got {}",
            self.max, self.actual
        )
    }
}

impl std::error::Error for BoundedLengthError {}

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

// ============================================================================
// Bounded newtype wrappers
// ============================================================================
//
// Each wrapper encodes byte-identically to its inner collection but rejects
// peer-claimed lengths above `MAX` on decode, *before* any allocation. The
// length cap lives in the type — readers see the bound at the field
// declaration without scrolling into a manual decode impl.
//
// All wrappers `Deref` to the inner collection so call-site reads
// (`bytes.len()`, `vec.iter()`, etc.) work unchanged. Wrappers do *not*
// implement `DerefMut` — bound-violating mutations should require
// reaching into the public tuple field on purpose, and the encode-time
// check catches the bypass either way.
//
// Bound enforcement is layered: `From<Inner>` panics on overflow,
// inherent `try_from_*` methods return `BoundedLengthError`, and
// `Encode::encode_body` fails with `EncodeError::SizeTooLarge` if the
// value somehow grew past `MAX` between construction and the wire (e.g.
// via direct `.0` access). `Decode` rejects oversized peer payloads as
// before.
//
// `Describe` forwards to the inner collection's schema, so wrappers are
// schema-transparent: a `BoundedBytes<MAX>` field describes the same as
// `Vec<u8>` and types embedding the wrappers compose cleanly with `BasicSbor`
// derive.

/// `Vec<u8>` with a compile-time max-length cap on decode.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BoundedBytes<const MAX: usize>(pub Vec<u8>);

impl<const MAX: usize> BoundedBytes<MAX> {
    /// Construct an empty `BoundedBytes`.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Consume the wrapper and return the inner `Vec<u8>`.
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    /// Fallible counterpart of `From<Vec<u8>>` — returns `Err` instead of
    /// panicking when `value.len() > MAX`.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedLengthError`] when the input exceeds `MAX`.
    pub fn try_from_vec(value: Vec<u8>) -> Result<Self, BoundedLengthError> {
        if value.len() > MAX {
            return Err(BoundedLengthError {
                max: MAX,
                actual: value.len(),
            });
        }
        Ok(Self(value))
    }
}

impl<const MAX: usize> From<Vec<u8>> for BoundedBytes<MAX> {
    /// Panics if `value.len() > MAX`. Use [`Self::try_from_vec`] for
    /// fallible construction from untrusted input.
    fn from(value: Vec<u8>) -> Self {
        assert!(
            value.len() <= MAX,
            "BoundedBytes<{MAX}> overflow: got {} bytes",
            value.len()
        );
        Self(value)
    }
}

impl<const MAX: usize> Deref for BoundedBytes<MAX> {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl<const MAX: usize> Categorize<NoCustomValueKind> for BoundedBytes<MAX> {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Array
    }
}

impl<E: Encoder<NoCustomValueKind>, const MAX: usize> Encode<NoCustomValueKind, E>
    for BoundedBytes<MAX>
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Array)
    }
    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        if self.0.len() > MAX {
            return Err(EncodeError::SizeTooLarge {
                actual: self.0.len(),
                max_allowed: MAX,
            });
        }
        self.0.encode_body(encoder)
    }
}

impl<D: Decoder<NoCustomValueKind>, const MAX: usize> Decode<NoCustomValueKind, D>
    for BoundedBytes<MAX>
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Array)?;
        decoder.read_and_check_value_kind(ValueKind::U8)?;
        let len = decoder.read_size()?;
        if len > MAX {
            return Err(DecodeError::UnexpectedSize {
                expected: MAX,
                actual: len,
            });
        }
        let slice = decoder.read_slice(len)?;
        Ok(Self(slice.to_vec()))
    }
}

impl<const MAX: usize> Describe<NoCustomTypeKind> for BoundedBytes<MAX> {
    const TYPE_ID: RustTypeId = <Vec<u8> as Describe<NoCustomTypeKind>>::TYPE_ID;
    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        <Vec<u8> as Describe<NoCustomTypeKind>>::type_data()
    }
}

/// `String` with a compile-time max-length cap on decode (in bytes).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BoundedString<const MAX: usize>(pub String);

impl<const MAX: usize> BoundedString<MAX> {
    /// Construct an empty `BoundedString`.
    #[must_use]
    pub const fn new() -> Self {
        Self(String::new())
    }

    /// Consume the wrapper and return the inner `String`.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }

    /// Fallible counterpart of `From<String>` — returns `Err` when the
    /// input exceeds `MAX` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedLengthError`] when `value.len() > MAX`.
    pub fn try_from_string(value: String) -> Result<Self, BoundedLengthError> {
        if value.len() > MAX {
            return Err(BoundedLengthError {
                max: MAX,
                actual: value.len(),
            });
        }
        Ok(Self(value))
    }
}

impl<const MAX: usize> From<String> for BoundedString<MAX> {
    /// Panics if `value.len() > MAX`. Use [`Self::try_from_string`] for
    /// fallible construction from untrusted input.
    fn from(value: String) -> Self {
        assert!(
            value.len() <= MAX,
            "BoundedString<{MAX}> overflow: got {} bytes",
            value.len()
        );
        Self(value)
    }
}

impl<const MAX: usize> Deref for BoundedString<MAX> {
    type Target = String;
    fn deref(&self) -> &String {
        &self.0
    }
}

impl<const MAX: usize> Categorize<NoCustomValueKind> for BoundedString<MAX> {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::String
    }
}

impl<E: Encoder<NoCustomValueKind>, const MAX: usize> Encode<NoCustomValueKind, E>
    for BoundedString<MAX>
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::String)
    }
    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        if self.0.len() > MAX {
            return Err(EncodeError::SizeTooLarge {
                actual: self.0.len(),
                max_allowed: MAX,
            });
        }
        self.0.encode_body(encoder)
    }
}

impl<D: Decoder<NoCustomValueKind>, const MAX: usize> Decode<NoCustomValueKind, D>
    for BoundedString<MAX>
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::String)?;
        let len = decoder.read_size()?;
        if len > MAX {
            return Err(DecodeError::UnexpectedSize {
                expected: MAX,
                actual: len,
            });
        }
        let slice = decoder.read_slice(len)?;
        let s = String::from_utf8(slice.to_vec()).map_err(|_| DecodeError::InvalidUtf8)?;
        Ok(Self(s))
    }
}

impl<const MAX: usize> Describe<NoCustomTypeKind> for BoundedString<MAX> {
    const TYPE_ID: RustTypeId = <String as Describe<NoCustomTypeKind>>::TYPE_ID;
    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        <String as Describe<NoCustomTypeKind>>::type_data()
    }
}

/// `Vec<T>` with a compile-time max-length cap on decode.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BoundedVec<T, const MAX: usize>(pub Vec<T>);

impl<T, const MAX: usize> BoundedVec<T, MAX> {
    /// Construct an empty `BoundedVec`.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Consume the wrapper and return the inner `Vec<T>`.
    #[must_use]
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }

    /// Fallible counterpart of `From<Vec<T>>` — returns `Err` when the
    /// input exceeds `MAX` elements.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedLengthError`] when `value.len() > MAX`.
    pub fn try_from_vec(value: Vec<T>) -> Result<Self, BoundedLengthError> {
        if value.len() > MAX {
            return Err(BoundedLengthError {
                max: MAX,
                actual: value.len(),
            });
        }
        Ok(Self(value))
    }

    /// Append an element to the back of the inner `Vec`.
    ///
    /// # Panics
    ///
    /// Panics if pushing would exceed `MAX`. Use [`Self::try_push`] for
    /// fallible append.
    pub fn push(&mut self, value: T) {
        assert!(
            self.0.len() < MAX,
            "BoundedVec<_, {MAX}> overflow on push: already at {} elements",
            self.0.len()
        );
        self.0.push(value);
    }

    /// Fallible counterpart of [`Self::push`] — returns the rejected
    /// element back to the caller when the wrapper is at capacity.
    ///
    /// # Errors
    ///
    /// Returns the input `value` unchanged when `self.len() == MAX`.
    pub fn try_push(&mut self, value: T) -> Result<(), T> {
        if self.0.len() >= MAX {
            return Err(value);
        }
        self.0.push(value);
        Ok(())
    }
}

impl<T, const MAX: usize> From<Vec<T>> for BoundedVec<T, MAX> {
    /// Panics if `value.len() > MAX`. Use [`Self::try_from_vec`] for
    /// fallible construction from untrusted input.
    fn from(value: Vec<T>) -> Self {
        assert!(
            value.len() <= MAX,
            "BoundedVec<_, {MAX}> overflow: got {} elements",
            value.len()
        );
        Self(value)
    }
}

impl<T, const MAX: usize> Deref for BoundedVec<T, MAX> {
    type Target = Vec<T>;
    fn deref(&self) -> &Vec<T> {
        &self.0
    }
}

impl<T, const MAX: usize> Categorize<NoCustomValueKind> for BoundedVec<T, MAX> {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Array
    }
}

impl<T, E, const MAX: usize> Encode<NoCustomValueKind, E> for BoundedVec<T, MAX>
where
    T: Categorize<NoCustomValueKind> + Encode<NoCustomValueKind, E>,
    E: Encoder<NoCustomValueKind>,
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Array)
    }
    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        if self.0.len() > MAX {
            return Err(EncodeError::SizeTooLarge {
                actual: self.0.len(),
                max_allowed: MAX,
            });
        }
        self.0.encode_body(encoder)
    }
}

impl<T, D, const MAX: usize> Decode<NoCustomValueKind, D> for BoundedVec<T, MAX>
where
    T: Categorize<NoCustomValueKind> + Decode<NoCustomValueKind, D>,
    D: Decoder<NoCustomValueKind>,
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Array)?;
        let element_kind = decoder.read_and_check_value_kind(T::value_kind())?;
        let len = decoder.read_size()?;
        if len > MAX {
            return Err(DecodeError::UnexpectedSize {
                expected: MAX,
                actual: len,
            });
        }
        let mut out = Vec::with_capacity(len.min(1024));
        for _ in 0..len {
            out.push(decoder.decode_deeper_body_with_value_kind(element_kind)?);
        }
        Ok(Self(out))
    }
}

impl<T: Describe<NoCustomTypeKind>, const MAX: usize> Describe<NoCustomTypeKind>
    for BoundedVec<T, MAX>
{
    const TYPE_ID: RustTypeId = <Vec<T> as Describe<NoCustomTypeKind>>::TYPE_ID;
    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        <Vec<T> as Describe<NoCustomTypeKind>>::type_data()
    }
}

/// `BTreeSet<T>` with a compile-time max-length cap on decode.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BoundedBTreeSet<T, const MAX: usize>(pub BTreeSet<T>);

impl<T: Ord, const MAX: usize> BoundedBTreeSet<T, MAX> {
    /// Construct an empty `BoundedBTreeSet`.
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeSet::new())
    }

    /// Consume the wrapper and return the inner `BTreeSet<T>`.
    #[must_use]
    pub fn into_inner(self) -> BTreeSet<T> {
        self.0
    }

    /// Fallible counterpart of `From<BTreeSet<T>>` — returns `Err` when
    /// the input exceeds `MAX` elements.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedLengthError`] when `value.len() > MAX`.
    pub fn try_from_btree_set(value: BTreeSet<T>) -> Result<Self, BoundedLengthError> {
        if value.len() > MAX {
            return Err(BoundedLengthError {
                max: MAX,
                actual: value.len(),
            });
        }
        Ok(Self(value))
    }
}

impl<T: Ord, const MAX: usize> From<BTreeSet<T>> for BoundedBTreeSet<T, MAX> {
    /// Panics if `value.len() > MAX`. Use [`Self::try_from_btree_set`] for
    /// fallible construction from untrusted input.
    fn from(value: BTreeSet<T>) -> Self {
        assert!(
            value.len() <= MAX,
            "BoundedBTreeSet<_, {MAX}> overflow: got {} elements",
            value.len()
        );
        Self(value)
    }
}

impl<T, const MAX: usize> Deref for BoundedBTreeSet<T, MAX> {
    type Target = BTreeSet<T>;
    fn deref(&self) -> &BTreeSet<T> {
        &self.0
    }
}

impl<T, const MAX: usize> Categorize<NoCustomValueKind> for BoundedBTreeSet<T, MAX> {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Array
    }
}

impl<T, E, const MAX: usize> Encode<NoCustomValueKind, E> for BoundedBTreeSet<T, MAX>
where
    T: Categorize<NoCustomValueKind> + Encode<NoCustomValueKind, E>,
    E: Encoder<NoCustomValueKind>,
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Array)
    }
    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        if self.0.len() > MAX {
            return Err(EncodeError::SizeTooLarge {
                actual: self.0.len(),
                max_allowed: MAX,
            });
        }
        self.0.encode_body(encoder)
    }
}

impl<T, D, const MAX: usize> Decode<NoCustomValueKind, D> for BoundedBTreeSet<T, MAX>
where
    T: Categorize<NoCustomValueKind> + Decode<NoCustomValueKind, D> + Ord,
    D: Decoder<NoCustomValueKind>,
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Array)?;
        let element_kind = decoder.read_and_check_value_kind(T::value_kind())?;
        let len = decoder.read_size()?;
        if len > MAX {
            return Err(DecodeError::UnexpectedSize {
                expected: MAX,
                actual: len,
            });
        }
        let mut out = BTreeSet::new();
        for _ in 0..len {
            if !out.insert(decoder.decode_deeper_body_with_value_kind(element_kind)?) {
                return Err(DecodeError::DuplicateKey);
            }
        }
        Ok(Self(out))
    }
}

impl<T: Describe<NoCustomTypeKind>, const MAX: usize> Describe<NoCustomTypeKind>
    for BoundedBTreeSet<T, MAX>
{
    const TYPE_ID: RustTypeId = <BTreeSet<T> as Describe<NoCustomTypeKind>>::TYPE_ID;
    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        <BTreeSet<T> as Describe<NoCustomTypeKind>>::type_data()
    }
}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;

    #[test]
    fn bounded_bytes_roundtrip_and_reject_oversize() {
        let inner = vec![1u8, 2, 3, 4];
        let value = BoundedBytes::<8>(inner.clone());
        let bytes = basic_encode(&value).unwrap();
        let decoded: BoundedBytes<8> = basic_decode(&bytes).unwrap();
        assert_eq!(decoded.0, inner);

        // Same wire bytes refused by a tighter bound.
        let err = basic_decode::<BoundedBytes<2>>(&bytes).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: 2,
                actual: 4
            }
        ));
    }

    #[test]
    fn bounded_string_roundtrip_and_reject_oversize() {
        let inner = "hello".to_string();
        let value = BoundedString::<8>(inner.clone());
        let bytes = basic_encode(&value).unwrap();
        let decoded: BoundedString<8> = basic_decode(&bytes).unwrap();
        assert_eq!(decoded.0, inner);

        let err = basic_decode::<BoundedString<2>>(&bytes).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: 2,
                actual: 5
            }
        ));
    }

    #[test]
    fn bounded_vec_roundtrip_and_reject_oversize() {
        let inner = vec![10u32, 20, 30];
        let value = BoundedVec::<u32, 8>(inner.clone());
        let bytes = basic_encode(&value).unwrap();
        let decoded: BoundedVec<u32, 8> = basic_decode(&bytes).unwrap();
        assert_eq!(decoded.0, inner);

        let err = basic_decode::<BoundedVec<u32, 2>>(&bytes).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: 2,
                actual: 3
            }
        ));
    }

    #[test]
    fn bounded_btree_set_roundtrip_and_reject_oversize() {
        let inner: BTreeSet<u16> = [1u16, 2, 3].into_iter().collect();
        let value = BoundedBTreeSet::<u16, 8>(inner.clone());
        let bytes = basic_encode(&value).unwrap();
        let decoded: BoundedBTreeSet<u16, 8> = basic_decode(&bytes).unwrap();
        assert_eq!(decoded.0, inner);

        let err = basic_decode::<BoundedBTreeSet<u16, 2>>(&bytes).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: 2,
                actual: 3
            }
        ));
    }

    /// Confirms that wire bytes from a bounded wrapper are byte-identical
    /// to the equivalent unwrapped collection — wrapping a field can't
    /// change any merkle root.
    #[test]
    fn bounded_bytes_wire_matches_vec_u8() {
        let raw = vec![7u8; 16];
        let bounded = BoundedBytes::<32>(raw.clone());
        assert_eq!(basic_encode(&bounded).unwrap(), basic_encode(&raw).unwrap());
    }

    #[test]
    #[should_panic(expected = "BoundedBytes<2> overflow")]
    fn bounded_bytes_from_panics_on_overflow() {
        let _ = BoundedBytes::<2>::from(vec![0u8; 3]);
    }

    #[test]
    fn bounded_bytes_try_from_vec_returns_err_on_overflow() {
        let err = BoundedBytes::<2>::try_from_vec(vec![0u8; 5]).unwrap_err();
        assert_eq!(err, BoundedLengthError { max: 2, actual: 5 });
    }

    /// Bypasses construction by reaching into the public tuple field, then
    /// asserts that `Encode` still refuses to ship oversized bytes.
    #[test]
    fn bounded_bytes_encode_rejects_oversize_when_field_bypassed() {
        let smuggled = BoundedBytes::<2>(vec![0u8; 5]);
        let err = basic_encode(&smuggled).unwrap_err();
        assert!(matches!(
            err,
            EncodeError::SizeTooLarge {
                actual: 5,
                max_allowed: 2,
            }
        ));
    }

    #[test]
    #[should_panic(expected = "BoundedString<2> overflow")]
    fn bounded_string_from_panics_on_overflow() {
        let _ = BoundedString::<2>::from("abc".to_string());
    }

    #[test]
    fn bounded_string_try_from_string_returns_err_on_overflow() {
        let err = BoundedString::<2>::try_from_string("abcd".to_string()).unwrap_err();
        assert_eq!(err, BoundedLengthError { max: 2, actual: 4 });
    }

    #[test]
    fn bounded_string_encode_rejects_oversize_when_field_bypassed() {
        let smuggled = BoundedString::<2>("abcd".to_string());
        let err = basic_encode(&smuggled).unwrap_err();
        assert!(matches!(
            err,
            EncodeError::SizeTooLarge {
                actual: 4,
                max_allowed: 2,
            }
        ));
    }

    #[test]
    #[should_panic(expected = "BoundedVec<_, 2> overflow")]
    fn bounded_vec_from_panics_on_overflow() {
        let _ = BoundedVec::<u32, 2>::from(vec![1u32, 2, 3]);
    }

    #[test]
    fn bounded_vec_try_from_vec_returns_err_on_overflow() {
        let err = BoundedVec::<u32, 2>::try_from_vec(vec![1u32, 2, 3, 4]).unwrap_err();
        assert_eq!(err, BoundedLengthError { max: 2, actual: 4 });
    }

    #[test]
    fn bounded_vec_encode_rejects_oversize_when_field_bypassed() {
        let smuggled = BoundedVec::<u32, 2>(vec![1u32, 2, 3, 4]);
        let err = basic_encode(&smuggled).unwrap_err();
        assert!(matches!(
            err,
            EncodeError::SizeTooLarge {
                actual: 4,
                max_allowed: 2,
            }
        ));
    }

    #[test]
    #[should_panic(expected = "BoundedBTreeSet<_, 2> overflow")]
    fn bounded_btree_set_from_panics_on_overflow() {
        let huge: BTreeSet<u16> = (0..3).collect();
        let _ = BoundedBTreeSet::<u16, 2>::from(huge);
    }

    #[test]
    fn bounded_btree_set_try_from_btree_set_returns_err_on_overflow() {
        let huge: BTreeSet<u16> = (0..5).collect();
        let err = BoundedBTreeSet::<u16, 2>::try_from_btree_set(huge).unwrap_err();
        assert_eq!(err, BoundedLengthError { max: 2, actual: 5 });
    }

    #[test]
    fn bounded_btree_set_encode_rejects_oversize_when_field_bypassed() {
        let huge: BTreeSet<u16> = (0..5).collect();
        let smuggled = BoundedBTreeSet::<u16, 2>(huge);
        let err = basic_encode(&smuggled).unwrap_err();
        assert!(matches!(
            err,
            EncodeError::SizeTooLarge {
                actual: 5,
                max_allowed: 2,
            }
        ));
    }
}
