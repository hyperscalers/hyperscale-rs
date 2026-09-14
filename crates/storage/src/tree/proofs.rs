//! Merkle multiproof generation.
//!
//! Thin adapter between `hyperscale_jmt`'s `MultiProof` and the on-wire
//! [`MerkleInclusionProof`] (opaque bytes wrapper). The wire format is
//! owned by the JMT crate; this module wraps it in the hyperscale type
//! system. Verification lives on `Verify<&ProvisionsContext<'_>> for
//! Provisions` in `crates/types/src/provisioning/provisions.rs`.

use hyperscale_jmt::{Key, MAX_PROOF_SIBLINGS, NodeKey, TreeReader};
use hyperscale_types::{BlockHeight, MerkleInclusionProof, SubstateKey};

use super::Jmt;

/// Generate a batched merkle multiproof for a set of substate keys
/// against a committed root.
///
/// Takes any `TreeReader` backed by the caller's storage. Returns `None`
/// if the root at `block_height` is not in the store.
pub fn generate_proof<S: TreeReader>(
    store: &S,
    keys: &[SubstateKey],
    block_height: BlockHeight,
) -> Option<MerkleInclusionProof> {
    let root_key = NodeKey::new(block_height.inner(), store.root_path());

    let jmt_keys: Vec<Key> = keys.iter().map(SubstateKey::to_bytes).collect();

    Jmt::prove(store, &root_key, &jmt_keys)
        .ok()
        // Held to the cap the reader's decoder enforces. The sibling
        // count is the claims times the tree's depth, so it moves with
        // the tree and nothing on the asking side bounds it: a query
        // legal by every leaf cap can still build a proof no asker can
        // decode. Answered as unprovable rather than sent, so the cost
        // is the walk rather than the walk and an answer thrown away.
        .filter(|proof| proof.siblings.len() <= MAX_PROOF_SIBLINGS)
        .map(|proof| MerkleInclusionProof::new(proof.encode()))
}
