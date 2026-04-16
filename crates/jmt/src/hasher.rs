//! Hash function abstraction.
//!
//! The JMT is generic over a hash function. The default is Blake3.
//! Future work may plug in Poseidon2 (or another algebraic hash) to
//! support ZK-STARK-wrapped proofs.
//!
//! Hashes are fixed at 32 bytes. Blake3 produces 256-bit digests natively;
//! Poseidon2 over a ~254-bit scalar field fits in 32 bytes with a single
//! leading byte of padding. This constraint keeps node storage layout
//! hasher-independent, so changing the hasher does not require
//! re-serializing existing state.
//!
//! Implementations MUST domain-separate leaf and internal hashes to
//! prevent second-preimage attacks (a leaf hash must never collide with
//! an internal hash at the same depth).

/// 32-byte digest. All hashers in this crate produce 32-byte output.
pub type Hash = [u8; 32];

/// Sentinel hash for empty subtrees. An empty slot in an internal node
/// is represented by this value when computing the parent's hash.
pub const EMPTY_HASH: Hash = [0u8; 32];

/// Hash function used for tree construction and proof verification.
pub trait Hasher: Send + Sync + 'static {
    /// Hash arbitrary bytes (e.g. for value hashing).
    fn hash(input: &[u8]) -> Hash;

    /// Hash a leaf node. The key is the full 32-byte key; `value_hash`
    /// is the pre-computed hash of the value bytes.
    fn hash_leaf(key: &[u8; 32], value_hash: &Hash) -> Hash;

    /// Hash an internal node over its children. `children.len()` must
    /// equal the tree's arity (`1 << ARITY_BITS`). Empty children are
    /// passed as [`EMPTY_HASH`].
    fn hash_internal(children: &[Hash]) -> Hash;
}

/// Blake3-based hasher. Default and recommended choice.
///
/// Uses versioned domain-separation tags so the same bytes hashed as a
/// leaf and as an internal node produce different digests.
pub struct Blake3Hasher;

const DOMAIN_LEAF: &[u8] = b"JMT:LEAF:v1";
const DOMAIN_INTERNAL: &[u8] = b"JMT:INTERNAL:v1";

impl Hasher for Blake3Hasher {
    fn hash(input: &[u8]) -> Hash {
        *blake3::hash(input).as_bytes()
    }

    fn hash_leaf(key: &[u8; 32], value_hash: &Hash) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_LEAF);
        hasher.update(key);
        hasher.update(value_hash);
        *hasher.finalize().as_bytes()
    }

    fn hash_internal(children: &[Hash]) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_INTERNAL);
        for child in children {
            hasher.update(child);
        }
        *hasher.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_and_internal_are_domain_separated() {
        let key = [1u8; 32];
        let value_hash = [2u8; 32];
        let leaf = Blake3Hasher::hash_leaf(&key, &value_hash);

        // Internal over (key, value_hash) — bytes happen to match the leaf
        // content but domain tag differs.
        let internal = Blake3Hasher::hash_internal(&[key, value_hash]);

        assert_ne!(leaf, internal);
    }

    #[test]
    fn empty_hash_distinct_from_all_zero_leaf() {
        let zero_key = [0u8; 32];
        let zero_val = [0u8; 32];
        let leaf = Blake3Hasher::hash_leaf(&zero_key, &zero_val);
        assert_ne!(leaf, EMPTY_HASH);
    }
}
