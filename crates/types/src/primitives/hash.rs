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
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to bytes array.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
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
            pub const fn as_bytes(&self) -> &[u8; 32] {
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
}
