//! Merkle multiproof generation and verification.
//!
//! Thin adapter between `hyperscale_jmt`'s `MultiProof` and the
//! on-wire `MerkleInclusionProof` (opaque bytes wrapper). The wire
//! format is owned by the JMT crate; this module only wraps it in the
//! hyperscale type system.

use hyperscale_jmt::{self as jmt, Blake3Hasher, MultiProof, Tree};
use hyperscale_types::{BlockHeight, MerkleInclusionProof, StateRoot};

use super::{hash_storage_key, hash_value, Jmt};

// ============================================================================
// Proof generation
// ============================================================================

/// Generate a batched merkle multiproof for a set of storage keys against
/// a committed root.
///
/// Takes any `jmt::TreeReader` backed by the caller's storage. Returns
/// `None` if the root at `block_height` is not in the store.
pub fn generate_proof<S: jmt::TreeReader>(
    store: &S,
    storage_keys: &[Vec<u8>],
    block_height: BlockHeight,
) -> Option<MerkleInclusionProof> {
    let root_key = jmt::NodeKey::root(block_height.0);

    let jmt_keys: Vec<jmt::Key> = storage_keys.iter().map(|sk| hash_storage_key(sk)).collect();

    Jmt::prove(store, &root_key, &jmt_keys)
        .ok()
        .map(|proof| MerkleInclusionProof::new(proof.encode()))
}

/// Verify a merkle multiproof against a state root.
///
/// For each entry, checks that the proof asserts the expected inclusion
/// (with `hash_value(value)` for `Set`) or non-inclusion (for `None`).
pub fn verify_proof(
    proof: &MerkleInclusionProof,
    entries: &[hyperscale_types::StateEntry],
    state_root: StateRoot,
    storage_key_for_entry: impl Fn(&hyperscale_types::StateEntry) -> &[u8],
) -> bool {
    if proof.as_bytes().is_empty() {
        return entries.is_empty();
    }

    let multi_proof = match MultiProof::decode(proof.as_bytes()) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let expected: Vec<(jmt::Key, Option<jmt::ValueHash>)> = entries
        .iter()
        .map(|e| {
            let key = hash_storage_key(storage_key_for_entry(e));
            let value_hash = e.value.as_ref().map(|v| hash_value(v));
            (key, value_hash)
        })
        .collect();

    let root_bytes: [u8; 32] = *state_root.as_raw().as_bytes();
    <Tree<Blake3Hasher, 1>>::verify(&multi_proof, root_bytes, &expected).is_ok()
}
