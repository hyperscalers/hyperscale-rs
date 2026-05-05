//! Bitfield for tracking which validators have signed.

use sbor::prelude::*;
use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, TypeKind, ValueKind,
};

/// Hard cap on validators a single bitfield may describe.
///
/// Bounds attacker-controlled `num_validators` decoded from the wire so
/// `set_indices()` and `set(_)` cannot iterate or index past sane committee
/// sizes. Sized ~40× the current production committee (100); covers any
/// realistic scaling without permitting OOM/DoS via crafted headers.
pub const MAX_VALIDATORS: usize = 4096;

/// A compact bitfield representing which validators have signed.
///
/// Used in `QuorumCertificate` and other aggregated structures to track
/// which validators contributed to the aggregated signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerBitfield {
    bits: Vec<u8>,
    num_validators: usize,
}

impl SignerBitfield {
    /// Create a new empty bitfield for the given number of validators.
    ///
    /// # Panics
    /// Panics if `num_validators > MAX_VALIDATORS`.
    #[must_use]
    pub fn new(num_validators: usize) -> Self {
        assert!(
            num_validators <= MAX_VALIDATORS,
            "num_validators {num_validators} exceeds MAX_VALIDATORS {MAX_VALIDATORS}"
        );
        let num_bytes = num_validators.div_ceil(8);
        Self {
            bits: vec![0u8; num_bytes],
            num_validators,
        }
    }

    /// Create an empty bitfield (for genesis).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            bits: Vec::new(),
            num_validators: 0,
        }
    }

    /// Set a bit (mark validator as having signed).
    pub fn set(&mut self, index: usize) {
        if index < self.num_validators {
            let byte_idx = index / 8;
            let bit_idx = index % 8;
            self.bits[byte_idx] |= 1 << bit_idx;
        }
    }

    /// Clear a bit.
    pub fn clear(&mut self, index: usize) {
        if index < self.num_validators {
            let byte_idx = index / 8;
            let bit_idx = index % 8;
            self.bits[byte_idx] &= !(1 << bit_idx);
        }
    }

    /// Check if a bit is set.
    #[must_use]
    pub fn is_set(&self, index: usize) -> bool {
        if index >= self.num_validators {
            return false;
        }
        let byte_idx = index / 8;
        let bit_idx = index % 8;
        if byte_idx >= self.bits.len() {
            return false;
        }
        (self.bits[byte_idx] >> bit_idx) & 1 == 1
    }

    /// Count the number of set bits.
    #[must_use]
    pub fn count_ones(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// Count the number of set bits (alias for `count_ones`).
    #[must_use]
    pub fn count(&self) -> usize {
        self.count_ones()
    }

    /// Get the number of validators this bitfield can represent.
    #[must_use]
    pub const fn num_validators(&self) -> usize {
        self.num_validators
    }

    /// Get iterator over indices of set bits.
    pub fn set_indices(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.num_validators).filter(|&i| self.is_set(i))
    }

    /// Check if the bitfield is empty (no bits set).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&b| b == 0)
    }
}

impl Default for SignerBitfield {
    fn default() -> Self {
        Self::empty()
    }
}

// SBOR: encode as `(Vec<u8>, usize)` matching the prior derived layout, with
// a manual decoder that rejects attacker-supplied (bits, num_validators) pairs
// where the bit-length and byte-vector are inconsistent or where
// num_validators exceeds MAX_VALIDATORS. Without these checks a peer can
// supply num_validators = u64::MAX, hanging set_indices() and panicking set().

impl<E: Encoder<NoCustomValueKind>> Encode<NoCustomValueKind, E> for SignerBitfield {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_size(2)?;
        encoder.encode(&self.bits)?;
        encoder.encode(&self.num_validators)?;
        Ok(())
    }
}

impl<D: Decoder<NoCustomValueKind>> Decode<NoCustomValueKind, D> for SignerBitfield {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 2 {
            return Err(DecodeError::UnexpectedSize {
                expected: 2,
                actual: length,
            });
        }
        let bits: Vec<u8> = decoder.decode()?;
        let num_validators: usize = decoder.decode()?;
        if num_validators > MAX_VALIDATORS {
            return Err(DecodeError::InvalidCustomValue);
        }
        if bits.len() != num_validators.div_ceil(8) {
            return Err(DecodeError::InvalidCustomValue);
        }
        Ok(Self {
            bits,
            num_validators,
        })
    }
}

impl Categorize<NoCustomValueKind> for SignerBitfield {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Tuple
    }
}

impl Describe<NoCustomTypeKind> for SignerBitfield {
    const TYPE_ID: RustTypeId = RustTypeId::novel_with_code("SignerBitfield", &[], &[]);

    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        TypeData::unnamed(TypeKind::Any)
    }
}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;

    #[test]
    fn test_bitfield_basic() {
        let mut bf = SignerBitfield::new(10);

        assert!(!bf.is_set(0));
        assert!(!bf.is_set(5));

        bf.set(0);
        bf.set(5);
        bf.set(9);

        assert!(bf.is_set(0));
        assert!(bf.is_set(5));
        assert!(bf.is_set(9));
        assert!(!bf.is_set(1));
        assert!(!bf.is_set(10)); // Out of bounds

        assert_eq!(bf.count_ones(), 3);
    }

    #[test]
    fn test_bitfield_clear() {
        let mut bf = SignerBitfield::new(8);
        bf.set(3);
        assert!(bf.is_set(3));

        bf.clear(3);
        assert!(!bf.is_set(3));
    }

    #[test]
    fn test_set_indices() {
        let mut bf = SignerBitfield::new(10);
        bf.set(1);
        bf.set(4);
        bf.set(7);

        let indices: Vec<_> = bf.set_indices().collect();
        assert_eq!(indices, vec![1, 4, 7]);
    }

    #[test]
    fn test_empty_bitfield() {
        let bf = SignerBitfield::empty();
        assert!(bf.is_empty());
        assert_eq!(bf.num_validators(), 0);
        assert!(!bf.is_set(0));
    }

    #[test]
    fn sbor_roundtrip() {
        let mut bf = SignerBitfield::new(100);
        for i in (0..100).step_by(3) {
            bf.set(i);
        }
        let bytes = basic_encode(&bf).unwrap();
        let decoded: SignerBitfield = basic_decode(&bytes).unwrap();
        assert_eq!(bf, decoded);
    }

    #[test]
    fn decode_rejects_oversized_num_validators() {
        // Hand-roll a bitfield with num_validators > MAX_VALIDATORS.
        let attacker = ManualBitfield {
            bits: vec![0u8; (MAX_VALIDATORS + 8).div_ceil(8)],
            num_validators: MAX_VALIDATORS + 1,
        };
        let bytes = basic_encode(&attacker).unwrap();
        assert!(basic_decode::<SignerBitfield>(&bytes).is_err());
    }

    #[test]
    fn decode_rejects_inconsistent_lengths() {
        // num_validators says 100 but only one byte of bits supplied.
        let attacker = ManualBitfield {
            bits: vec![0u8; 1],
            num_validators: 100,
        };
        let bytes = basic_encode(&attacker).unwrap();
        assert!(basic_decode::<SignerBitfield>(&bytes).is_err());
    }

    #[test]
    fn decode_rejects_empty_bits_with_huge_num_validators() {
        // The exact attack pattern: bits empty, num_validators large.
        // Pre-fix this would decode and then panic in set(0) / hang in set_indices().
        let attacker = ManualBitfield {
            bits: Vec::new(),
            num_validators: usize::MAX,
        };
        let bytes = basic_encode(&attacker).unwrap();
        assert!(basic_decode::<SignerBitfield>(&bytes).is_err());
    }

    /// Mirror of the `SignerBitfield` wire layout, used in tests to forge
    /// payloads that the production decoder must reject.
    #[derive(BasicSbor)]
    struct ManualBitfield {
        bits: Vec<u8>,
        num_validators: usize,
    }
}
