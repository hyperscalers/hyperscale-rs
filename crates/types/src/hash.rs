//! Cryptographic hash type using Blake3.

use sbor::prelude::*;
use std::fmt;

/// A 32-byte cryptographic hash using Blake3.
///
/// Provides constant-time comparison and is safe to use as a HashMap key.
/// All hashing operations are deterministic.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, BasicSbor)]
#[sbor(transparent)]
pub struct Hash([u8; 32]);

impl Hash {
    /// Size of hash in bytes.
    pub const BYTES: usize = 32;

    /// Zero hash (all bytes are 0x00).
    pub const ZERO: Self = Self([0u8; 32]);

    /// Max hash (all bytes are 0xFF).
    pub const MAX: Self = Self([0xFFu8; 32]);

    /// Create hash from bytes using Blake3.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let hash = blake3::hash(bytes);
        Self(*hash.as_bytes())
    }

    /// Create a Hash from raw hash bytes (without hashing).
    ///
    /// # Panics
    ///
    /// Panics if bytes length is not exactly 32.
    pub fn from_hash_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 32, "Hash must be exactly 32 bytes");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Self(arr)
    }

    /// Create hash from multiple byte slices.
    pub fn from_parts(parts: &[&[u8]]) -> Self {
        let mut hasher = blake3::Hasher::new();
        for part in parts {
            hasher.update(part);
        }
        Self(*hasher.finalize().as_bytes())
    }

    /// Parse hash from hex string.
    pub fn from_hex(hex: &str) -> Result<Self, HexError> {
        if hex.len() != 64 {
            return Err(HexError::InvalidLength {
                expected: 64,
                actual: hex.len(),
            });
        }

        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex, &mut bytes).map_err(|_| HexError::InvalidHex)?;

        Ok(Self(bytes))
    }

    /// Convert hash to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Get bytes as slice reference.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to bytes array.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Count leading zero bits.
    pub fn leading_zero_bits(&self) -> u32 {
        let mut count = 0u32;
        for &byte in &self.0 {
            if byte == 0 {
                count += 8;
            } else {
                count += byte.leading_zeros();
                break;
            }
        }
        count
    }

    /// Interpret first 8 bytes as u64 (little-endian).
    pub fn as_u64(&self) -> u64 {
        u64::from_le_bytes(self.0[0..8].try_into().unwrap())
    }

    /// Check if this is the zero hash.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Compute a 64-bit value from all 32 bytes using polynomial hash.
    pub fn as_long(&self) -> i64 {
        let mut hash: i64 = 17;
        for &byte in &self.0 {
            hash = hash.wrapping_mul(31).wrapping_add(byte as i64);
        }
        hash
    }
}

/// Compute a binary merkle root from a list of hashes.
///
/// Uses Blake3 to combine sibling pairs at each level. For odd-length levels,
/// the last hash is promoted unchanged to the next level.
///
/// Returns `Hash::ZERO` for an empty list.
///
/// # Algorithm
///
/// ```text
/// Level 0 (leaves): [H0, H1, H2, H3, H4]
/// Level 1:          [hash(H0||H1), hash(H2||H3), H4]
/// Level 2:          [hash(L1_0||L1_1), H4]
/// Level 3 (root):   [hash(L2_0||L2_1)]
/// ```
pub fn compute_merkle_root(hashes: &[Hash]) -> Hash {
    if hashes.is_empty() {
        return Hash::ZERO;
    }
    if hashes.len() == 1 {
        return hashes[0];
    }

    let mut level: Vec<Hash> = hashes.to_vec();

    while level.len() > 1 {
        let mut next_level = Vec::with_capacity(level.len().div_ceil(2));

        for chunk in level.chunks(2) {
            let hash = if chunk.len() == 2 {
                Hash::from_parts(&[chunk[0].as_bytes(), chunk[1].as_bytes()])
            } else {
                // Odd node promotes up unchanged
                chunk[0]
            };
            next_level.push(hash);
        }

        level = next_level;
    }

    level[0]
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.to_hex();
        write!(f, "Hash({}..{})", &hex[..8], &hex[56..])
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Errors that can occur when parsing hex strings.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HexError {
    /// Invalid hex string length.
    #[error("Invalid hex length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// Invalid hex characters.
    #[error("Invalid hex string")]
    InvalidHex,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_deterministic() {
        let data = b"hello world";
        let hash1 = Hash::from_bytes(data);
        let hash2 = Hash::from_bytes(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_collision_resistance() {
        let hash1 = Hash::from_bytes(b"hello");
        let hash2 = Hash::from_bytes(b"world");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hex_roundtrip() {
        let original = Hash::from_bytes(b"test data");
        let hex = original.to_hex();
        assert_eq!(hex.len(), 64);

        let parsed = Hash::from_hex(&hex).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_is_zero() {
        assert!(Hash::ZERO.is_zero());
        assert!(!Hash::MAX.is_zero());
        assert!(!Hash::from_bytes(b"test").is_zero());
    }

    #[test]
    fn test_merkle_root_empty() {
        assert_eq!(compute_merkle_root(&[]), Hash::ZERO);
    }

    #[test]
    fn test_merkle_root_single() {
        let h = Hash::from_bytes(b"single");
        assert_eq!(compute_merkle_root(&[h]), h);
    }

    #[test]
    fn test_merkle_root_two() {
        let h0 = Hash::from_bytes(b"left");
        let h1 = Hash::from_bytes(b"right");
        let expected = Hash::from_parts(&[h0.as_bytes(), h1.as_bytes()]);
        assert_eq!(compute_merkle_root(&[h0, h1]), expected);
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let hashes: Vec<Hash> = (0..5).map(|i| Hash::from_bytes(&[i])).collect();
        let root1 = compute_merkle_root(&hashes);
        let root2 = compute_merkle_root(&hashes);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_merkle_root_order_matters() {
        let h0 = Hash::from_bytes(b"a");
        let h1 = Hash::from_bytes(b"b");
        let root_ab = compute_merkle_root(&[h0, h1]);
        let root_ba = compute_merkle_root(&[h1, h0]);
        assert_ne!(root_ab, root_ba);
    }

    #[test]
    fn test_merkle_root_odd_count() {
        // With 3 hashes: hash(hash(h0||h1) || h2)
        let h0 = Hash::from_bytes(b"0");
        let h1 = Hash::from_bytes(b"1");
        let h2 = Hash::from_bytes(b"2");

        let level1_left = Hash::from_parts(&[h0.as_bytes(), h1.as_bytes()]);
        // h2 promotes up unchanged
        let expected = Hash::from_parts(&[level1_left.as_bytes(), h2.as_bytes()]);

        assert_eq!(compute_merkle_root(&[h0, h1, h2]), expected);
    }
}
