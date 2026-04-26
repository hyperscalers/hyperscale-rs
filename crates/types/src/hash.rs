//! Cryptographic hash type using Blake3.

use sbor::prelude::*;
use std::fmt;

/// A 32-byte cryptographic hash using Blake3.
///
/// Provides constant-time comparison and is safe to use as a `HashMap` key.
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
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let hash = blake3::hash(bytes);
        Self(*hash.as_bytes())
    }

    /// Create a Hash from raw hash bytes (without hashing).
    ///
    /// # Panics
    ///
    /// Panics if bytes length is not exactly 32.
    #[must_use]
    pub fn from_hash_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 32, "Hash must be exactly 32 bytes");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Self(arr)
    }

    /// Create hash from multiple byte slices.
    #[must_use]
    pub fn from_parts(parts: &[&[u8]]) -> Self {
        let mut hasher = blake3::Hasher::new();
        for part in parts {
            hasher.update(part);
        }
        Self(*hasher.finalize().as_bytes())
    }

    /// Parse hash from hex string.
    ///
    /// # Errors
    ///
    /// Returns [`HexError::InvalidLength`] if `hex` is not 64 chars, or
    /// [`HexError::InvalidHex`] if it contains non-hex characters.
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
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Get bytes as slice reference.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to bytes array.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Count leading zero bits.
    #[must_use]
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
    ///
    /// # Panics
    ///
    /// Cannot panic: a `Hash` is 32 bytes so the first 8 always exist.
    #[must_use]
    pub fn as_u64(&self) -> u64 {
        u64::from_le_bytes(self.0[0..8].try_into().unwrap())
    }

    /// Check if this is the zero hash.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Compute a 64-bit value from all 32 bytes using polynomial hash.
    #[must_use]
    pub fn as_long(&self) -> i64 {
        let mut hash: i64 = 17;
        for &byte in &self.0 {
            hash = hash.wrapping_mul(31).wrapping_add(i64::from(byte));
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
#[must_use]
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

// ============================================================================
// Merkle Proof Helpers
// ============================================================================

/// Compute a binary merkle root AND a proof (siblings + leaf index) for a specific leaf.
///
/// **Important**: This does NOT use the same odd-node-promotion rule as
/// [`compute_merkle_root`]. Instead, it pads the leaf list to the next power
/// of 2 with `Hash::ZERO` entries, creating a perfect binary tree. This makes
/// proofs a fixed `ceil(log2(N))` siblings and eliminates the odd-node edge case.
///
/// The root produced will DIFFER from `compute_merkle_root` for non-power-of-2
/// leaf counts. Callers must use this function (or [`compute_padded_merkle_root`])
/// consistently when both generating and verifying proofs.
///
/// Returns `(root, siblings, leaf_index)`.
///
/// # Panics
///
/// Panics if `index >= hashes.len()` or `hashes` is empty.
#[must_use]
pub fn compute_merkle_root_with_proof(hashes: &[Hash], index: usize) -> (Hash, Vec<Hash>, u32) {
    assert!(!hashes.is_empty(), "cannot prove in empty tree");
    assert!(index < hashes.len(), "index out of bounds");

    // Pad to next power of 2
    let padded_len = hashes.len().next_power_of_two();
    let mut level: Vec<Hash> = Vec::with_capacity(padded_len);
    level.extend_from_slice(hashes);
    level.resize(padded_len, Hash::ZERO);

    let mut siblings = Vec::new();
    let mut target = index;

    while level.len() > 1 {
        let mut next_level = Vec::with_capacity(level.len() / 2);

        for i in (0..level.len()).step_by(2) {
            let combined = Hash::from_parts(&[level[i].as_bytes(), level[i + 1].as_bytes()]);
            if target == i {
                siblings.push(level[i + 1]);
            } else if target == i + 1 {
                siblings.push(level[i]);
            }
            next_level.push(combined);
        }

        target /= 2;
        level = next_level;
    }

    (level[0], siblings, u32::try_from(index).unwrap_or(u32::MAX))
}

/// Compute a padded merkle root (power-of-2 padding with `Hash::ZERO`).
///
/// This produces the same root as [`compute_merkle_root_with_proof`] for the
/// same input. Use this when you need to compute the root for verification
/// but don't need a proof.
#[must_use]
pub fn compute_padded_merkle_root(hashes: &[Hash]) -> Hash {
    if hashes.is_empty() {
        return Hash::ZERO;
    }
    let padded_len = hashes.len().next_power_of_two();
    let mut level: Vec<Hash> = Vec::with_capacity(padded_len);
    level.extend_from_slice(hashes);
    level.resize(padded_len, Hash::ZERO);

    while level.len() > 1 {
        let mut next_level = Vec::with_capacity(level.len() / 2);
        for i in (0..level.len()).step_by(2) {
            next_level.push(Hash::from_parts(&[
                level[i].as_bytes(),
                level[i + 1].as_bytes(),
            ]));
        }
        level = next_level;
    }
    level[0]
}

/// Verify a merkle inclusion proof against a known root.
///
/// Reconstructs the root from the leaf hash and sibling path, then compares
/// against the expected root.
#[must_use]
pub fn verify_merkle_inclusion(
    root: Hash,
    leaf_hash: Hash,
    siblings: &[Hash],
    leaf_index: u32,
) -> bool {
    let mut current = leaf_hash;
    let mut index = leaf_index as usize;

    for sibling in siblings {
        if index.is_multiple_of(2) {
            current = Hash::from_parts(&[current.as_bytes(), sibling.as_bytes()]);
        } else {
            current = Hash::from_parts(&[sibling.as_bytes(), current.as_bytes()]);
        }
        index /= 2;
    }

    current == root
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

/// Domain-specific hash kinds that wrap [`Hash`] for compile-time safety.
///
/// Implementors are `#[repr(transparent)]` newtypes over [`Hash`] with identical
/// SBOR encoding (`#[sbor(transparent)]`), so adopting a newtype for an existing
/// field requires no wire-format or storage migration.
///
/// Construct via [`TypedHash::from_raw`] (or the inherent `from_raw`); unwrap via
/// [`TypedHash::into_raw`] or `Into<Hash>`. Conversion is deliberately explicit —
/// there is no `Deref<Target = Hash>`, since that would silently re-admit the
/// cross-kind confusion this trait exists to prevent.
pub trait TypedHash:
    Copy + Eq + Ord + core::hash::Hash + fmt::Debug + fmt::Display + Into<Hash>
{
    /// Human-readable name for this hash kind (used in `Debug` output).
    const KIND: &'static str;

    /// Wrap a raw [`Hash`] as this kind.
    fn from_raw(raw: Hash) -> Self;

    /// Unwrap into the underlying raw [`Hash`].
    fn into_raw(self) -> Hash;

    /// Borrow the underlying raw [`Hash`].
    fn as_raw(&self) -> &Hash;
}

/// Declare a `#[repr(transparent)]` newtype around [`Hash`] implementing [`TypedHash`].
///
/// Expands to a tuple struct with:
/// - `Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, BasicSbor` derives
/// - `#[sbor(transparent)]` for wire-format compatibility with raw `Hash`
/// - Inherent `ZERO` const, `from_raw`, `into_raw`, `as_raw`
/// - `From<Self> for Hash` (one-way; reverse is explicit via `from_raw`)
/// - `Debug` prints as `Kind(abcd1234..wxyz5678)`
/// - `Display` delegates to the underlying hex
macro_rules! hash_newtype {
    ($(#[$meta:meta])* $vis:vis $name:ident, $kind:literal) => {
        $(#[$meta])*
        #[repr(transparent)]
        #[derive(
            Clone,
            Copy,
            PartialEq,
            Eq,
            ::core::hash::Hash,
            PartialOrd,
            Ord,
            ::sbor::BasicSbor,
        )]
        #[sbor(transparent)]
        $vis struct $name($crate::Hash);

        impl $name {
            /// Zero-valued hash of this kind (all bytes `0x00`).
            pub const ZERO: Self = Self($crate::Hash::ZERO);

            /// Wrap a raw [`Hash`] as this kind.
            pub const fn from_raw(raw: $crate::Hash) -> Self {
                Self(raw)
            }

            /// Unwrap into the underlying raw [`Hash`].
            pub const fn into_raw(self) -> $crate::Hash {
                self.0
            }

            /// Borrow the underlying raw [`Hash`].
            pub const fn as_raw(&self) -> &$crate::Hash {
                &self.0
            }

            /// Borrow the raw 32-byte representation. Delegates to
            /// [`Hash::as_bytes`] for ergonomic use in signing/hashing code.
            pub fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }

            /// Check whether this is the all-zero hash.
            pub fn is_zero(&self) -> bool {
                self.0.is_zero()
            }
        }

        impl $crate::TypedHash for $name {
            const KIND: &'static str = $kind;

            fn from_raw(raw: $crate::Hash) -> Self {
                Self(raw)
            }

            fn into_raw(self) -> $crate::Hash {
                self.0
            }

            fn as_raw(&self) -> &$crate::Hash {
                &self.0
            }
        }

        impl From<$name> for $crate::Hash {
            fn from(v: $name) -> $crate::Hash {
                v.0
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                let hex = self.0.to_hex();
                write!(f, "{}({}..{})", $kind, &hex[..8], &hex[56..])
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

pub(crate) use hash_newtype;

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

    // ── Inclusion proof tests ─────────────────────────────────────────

    #[test]
    fn test_inclusion_proof_two_leaves() {
        let h0 = Hash::from_bytes(b"left");
        let h1 = Hash::from_bytes(b"right");
        let hashes = vec![h0, h1];
        // Power-of-2: padded root == normal root
        let expected_root = compute_merkle_root(&hashes);

        for idx in 0..2 {
            let (root, siblings, leaf_index) = compute_merkle_root_with_proof(&hashes, idx);
            assert_eq!(root, expected_root);
            assert!(verify_merkle_inclusion(
                root,
                hashes[idx],
                &siblings,
                leaf_index
            ));
        }
    }

    #[test]
    fn test_inclusion_proof_single_leaf() {
        let h = Hash::from_bytes(b"only");
        let (root, siblings, leaf_index) = compute_merkle_root_with_proof(&[h], 0);
        assert_eq!(root, h);
        assert!(siblings.is_empty());
        assert!(verify_merkle_inclusion(root, h, &siblings, leaf_index));
    }

    #[test]
    fn test_inclusion_proof_odd_count() {
        let hashes: Vec<Hash> = (0..5u8).map(|i| Hash::from_bytes(&[i])).collect();
        // Padded tree root differs from compute_merkle_root for non-power-of-2
        let padded_root = compute_padded_merkle_root(&hashes);

        for idx in 0..5 {
            let (proof_root, siblings, leaf_index) = compute_merkle_root_with_proof(&hashes, idx);
            assert_eq!(proof_root, padded_root);
            assert!(
                verify_merkle_inclusion(padded_root, hashes[idx], &siblings, leaf_index),
                "proof failed for index {idx}"
            );
        }
    }

    #[test]
    fn test_inclusion_proof_large_tree() {
        let hashes: Vec<Hash> = (0..100u8).map(|i| Hash::from_bytes(&[i])).collect();
        let padded_root = compute_padded_merkle_root(&hashes);

        // Verify every leaf
        for idx in 0..100 {
            let (proof_root, siblings, leaf_index) = compute_merkle_root_with_proof(&hashes, idx);
            assert_eq!(proof_root, padded_root);
            assert!(
                verify_merkle_inclusion(padded_root, hashes[idx], &siblings, leaf_index),
                "proof failed for index {idx}"
            );
        }
    }

    #[test]
    fn test_inclusion_proof_tampered_rejected() {
        let hashes: Vec<Hash> = (0..8u8).map(|i| Hash::from_bytes(&[i])).collect();
        let (root, siblings, leaf_index) = compute_merkle_root_with_proof(&hashes, 3);

        // Wrong leaf hash should fail
        let wrong_leaf = Hash::from_bytes(b"wrong");
        assert!(!verify_merkle_inclusion(
            root, wrong_leaf, &siblings, leaf_index
        ));

        // Wrong root should fail
        let wrong_root = Hash::from_bytes(b"bad_root");
        assert!(!verify_merkle_inclusion(
            wrong_root, hashes[3], &siblings, leaf_index
        ));
    }

    #[test]
    fn test_inclusion_proof_power_of_two() {
        let hashes: Vec<Hash> = (0..8u8).map(|i| Hash::from_bytes(&[i])).collect();
        // Power-of-2: padded root == normal root
        let root = compute_merkle_root(&hashes);

        for idx in 0..8 {
            let (proof_root, siblings, leaf_index) = compute_merkle_root_with_proof(&hashes, idx);
            assert_eq!(proof_root, root);
            assert_eq!(siblings.len(), 3); // log2(8) = 3
            assert!(verify_merkle_inclusion(
                root,
                hashes[idx],
                &siblings,
                leaf_index
            ));
        }
    }

    // ── Original merkle root tests ──────────────────────────────────

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
