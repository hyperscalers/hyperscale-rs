//! Bitfield for tracking which validators have signed.

use sbor::prelude::*;

/// A compact bitfield representing which validators have signed.
///
/// Used in `QuorumCertificate` and other aggregated structures to track
/// which validators contributed to the aggregated signature.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SignerBitfield {
    /// The bitfield bytes.
    bits: Vec<u8>,
    /// Number of validators (bits that are valid).
    num_validators: usize,
}

impl SignerBitfield {
    /// Create a new empty bitfield for the given number of validators.
    #[must_use]
    pub fn new(num_validators: usize) -> Self {
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

#[cfg(test)]
mod tests {
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
}
