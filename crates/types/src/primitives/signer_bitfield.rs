//! Bitfield for tracking which validators have signed.

use hyperscale_hbor::error::{DecodeError as HborDecodeError, EncodeError as HborEncodeError};
use hyperscale_hbor::{
    Decoder, Encoder, HborDecode, HborEncode, HborWidth, Sink, bounded as hbor_bounded,
};

/// Hard cap on signers a single bitfield may describe.
///
/// Bounds attacker-controlled `num_validators` decoded from the wire so
/// `set_indices()` and `set(_)` cannot iterate or index past sane committee
/// sizes. Sized ~40× the current production committee (100); covers any
/// realistic scaling without permitting OOM/DoS via crafted headers.
pub const MAX_SIGNERS: usize = 4096;

/// Cap on the byte-vector length that backs a `SignerBitfield`. Tied to
/// `MAX_SIGNERS` — one bit per signer, packed eight per byte.
const MAX_BITS_BYTES_LEN: usize = MAX_SIGNERS.div_ceil(8);

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
    /// Panics if `num_validators > MAX_SIGNERS`.
    #[must_use]
    pub fn new(num_validators: usize) -> Self {
        assert!(
            num_validators <= MAX_SIGNERS,
            "num_validators {num_validators} exceeds MAX_SIGNERS {MAX_SIGNERS}"
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
    pub(crate) fn count_ones(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// Count the number of set bits (alias for `count_ones`).
    #[must_use]
    pub fn count(&self) -> usize {
        self.count_ones()
    }

    /// Get the number of validators this bitfield can represent.
    #[must_use]
    pub(crate) const fn num_validators(&self) -> usize {
        self.num_validators
    }

    /// Get iterator over indices of set bits.
    pub fn set_indices(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.num_validators).filter(|&i| self.is_set(i))
    }

    /// Check if the bitfield is empty (no bits set).
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.bits.iter().all(|&b| b == 0)
    }
}

impl Default for SignerBitfield {
    fn default() -> Self {
        Self::empty()
    }
}

// Manual codec — the cross-field validation (bits.len() must equal
// num_validators div_ceil 8, num_validators must not exceed MAX_SIGNERS,
// padding bits in the trailing byte must be zero) doesn't fit a derive.
// Without these checks a peer can supply an absurd num_validators, hanging
// set_indices() and panicking set(). The count travels as a `u16`: the
// signer cap fits one, and a fixed narrow width is not a claim a peer can
// inflate.

impl HborWidth for SignerBitfield {
    const MIN_ENCODED_LEN: usize = 1 + 2;
}

impl HborEncode for SignerBitfield {
    fn encode<S: Sink>(&self, encoder: &mut Encoder<S>) -> Result<(), HborEncodeError> {
        hbor_bounded::check_encoded_len("bits", self.bits.len(), MAX_BITS_BYTES_LEN)?;
        encoder.descend(|encoder| hbor_bounded::encode_bytes(encoder, &self.bits))?;
        let count =
            u16::try_from(self.num_validators).map_err(|_| HborEncodeError::BoundExceeded {
                field: "num_validators",
                actual: self.num_validators,
                max: MAX_SIGNERS,
            })?;
        encoder.nested(&count)
    }
}

impl HborDecode for SignerBitfield {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, HborDecodeError> {
        let bits = decoder
            .descend(|decoder| hbor_bounded::decode_bounded_bytes(decoder, MAX_BITS_BYTES_LEN))?;
        let num_validators = usize::from(decoder.nested::<u16>()?);
        if num_validators > MAX_SIGNERS {
            return Err(HborDecodeError::FailedValidation(
                "num_validators past the signer cap",
            ));
        }
        if bits.len() != num_validators.div_ceil(8) {
            return Err(HborDecodeError::FailedValidation(
                "bit bytes must match the validator count",
            ));
        }
        // Reject non-canonical encodings where padding bits in the trailing
        // byte (positions ≥ num_validators within the final byte) are set.
        // `count_ones()` / `is_empty()` walk the raw `bits` vec, so a peer
        // could inflate signer counts with spurious bits without this
        // check — and two byte-distinct encodings would decode to
        // functionally-equal bitfields, breaking content-addressed hashing.
        let used_bits_in_last_byte = num_validators % 8;
        if used_bits_in_last_byte != 0 {
            let last = *bits
                .last()
                .expect("bits non-empty when num_validators % 8 != 0");
            let padding_mask = !((1u8 << used_bits_in_last_byte) - 1);
            if last & padding_mask != 0 {
                return Err(HborDecodeError::FailedValidation(
                    "padding bits past the validator count are set",
                ));
            }
        }
        Ok(Self {
            bits,
            num_validators,
        })
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{
        DecodeError, Hbor, from_slice as hbor_from_slice, to_vec as hbor_to_vec,
    };

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
    fn hbor_roundtrip() {
        let mut bf = SignerBitfield::new(100);
        for i in (0..100).step_by(3) {
            bf.set(i);
        }
        let bytes = hbor_to_vec(&bf).unwrap();
        let decoded: SignerBitfield = hbor_from_slice(&bytes).unwrap();
        assert_eq!(bf, decoded);
    }

    #[test]
    fn decode_rejects_oversized_num_validators() {
        // Hand-roll a bitfield with num_validators > MAX_SIGNERS.
        let attacker = ManualBitfield {
            bits: vec![0u8; (MAX_SIGNERS + 8).div_ceil(8)],
            num_validators: u16::try_from(MAX_SIGNERS + 1).unwrap(),
        };
        let bytes = hbor_to_vec(&attacker).unwrap();
        assert!(hbor_from_slice::<SignerBitfield>(&bytes).is_err());
    }

    #[test]
    fn decode_rejects_inconsistent_lengths() {
        // num_validators says 100 but only one byte of bits supplied.
        let attacker = ManualBitfield {
            bits: vec![0u8; 1],
            num_validators: 100,
        };
        let bytes = hbor_to_vec(&attacker).unwrap();
        assert!(hbor_from_slice::<SignerBitfield>(&bytes).is_err());
    }

    #[test]
    fn decode_rejects_empty_bits_with_huge_num_validators() {
        // The exact attack pattern: bits empty, num_validators large.
        // Pre-fix this would decode and then panic in set(0) / hang in set_indices().
        let attacker = ManualBitfield {
            bits: Vec::new(),
            num_validators: u16::MAX,
        };
        let bytes = hbor_to_vec(&attacker).unwrap();
        assert!(hbor_from_slice::<SignerBitfield>(&bytes).is_err());
    }

    #[test]
    fn decode_rejects_nonzero_padding_bits() {
        // num_validators = 5 means the trailing byte uses bits 0..=4; bits
        // 5..=7 must be zero. Setting bit 7 there inflates count_ones() by
        // one and breaks canonical encoding without affecting set_indices.
        let attacker = ManualBitfield {
            bits: vec![0b1000_0000],
            num_validators: 5,
        };
        let bytes = hbor_to_vec(&attacker).unwrap();
        let err = hbor_from_slice::<SignerBitfield>(&bytes).unwrap_err();
        assert!(matches!(err, DecodeError::FailedValidation(_)));
    }

    #[test]
    fn decode_accepts_canonical_partial_byte() {
        // num_validators = 5 with all valid bits set and padding bits zero.
        // Confirms the new check doesn't reject legitimate encodings.
        let attacker = ManualBitfield {
            bits: vec![0b0001_1111],
            num_validators: 5,
        };
        let bytes = hbor_to_vec(&attacker).unwrap();
        let decoded: SignerBitfield = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded.num_validators(), 5);
        assert_eq!(decoded.count_ones(), 5);
    }

    /// Mirror of the `SignerBitfield` wire layout, used in tests to forge
    /// payloads that the production decoder must reject. The count is a
    /// `u16` on the wire, as the codec writes it.
    #[derive(Hbor)]
    struct ManualBitfield {
        bits: Vec<u8>,
        num_validators: u16,
    }
}
