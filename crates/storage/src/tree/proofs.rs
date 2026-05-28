//! Merkle multiproof generation.
//!
//! Thin adapter between `hyperscale_jmt`'s `MultiProof` and the on-wire
//! [`MerkleInclusionProof`] (opaque bytes wrapper). The wire format is
//! owned by the JMT crate; this module wraps it in the hyperscale type
//! system. Verification lives on `Verify<&ProvisionsContext<'_>> for
//! Provisions` in `crates/types/src/provisioning/provisions.rs`.

use hyperscale_jmt::{Key, NodeKey, TreeReader};
use hyperscale_types::{BlockHeight, MerkleInclusionProof};

use super::{Jmt, hash_storage_key};

/// Generate a batched merkle multiproof for a set of storage keys against
/// a committed root.
///
/// Takes any `TreeReader` backed by the caller's storage. Returns
/// `None` if the root at `block_height` is not in the store.
pub fn generate_proof<S: TreeReader>(
    store: &S,
    storage_keys: &[Vec<u8>],
    block_height: BlockHeight,
) -> Option<MerkleInclusionProof> {
    let root_key = NodeKey::root(block_height.inner());

    let jmt_keys: Vec<Key> = storage_keys.iter().map(|sk| hash_storage_key(sk)).collect();

    Jmt::prove(store, &root_key, &jmt_keys)
        .ok()
        .map(|proof| MerkleInclusionProof::new(proof.encode()))
}
