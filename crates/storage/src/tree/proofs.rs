//! Merkle multiproof generation.
//!
//! Thin adapter between `hyperscale_jmt`'s `MultiProof` and the on-wire
//! [`MerkleInclusionProof`] (opaque bytes wrapper). The wire format is
//! owned by the JMT crate; this module wraps it in the hyperscale type
//! system. Verification lives on `Verify<&ProvisionContext> for
//! Provision` in `crates/types/src/provisioning/provision.rs`.

use hyperscale_jmt::{Key, MAX_PROOF_CLAIMS, MAX_PROOF_SIBLINGS, NodeKey, TreeReader};
use hyperscale_types::{BlockHeight, MAX_MERKLE_PROOF_LEN, MerkleInclusionProof, SubstateKey};

use super::Jmt;

/// Generate a batched merkle multiproof for a set of substate keys
/// against a committed root.
///
/// Takes any `TreeReader` backed by the caller's storage. Returns `None`
/// if the root at `block_height` is not in the store, or if the proof is
/// one no reader could take: past the claims or siblings its decoder
/// accepts, or past the bytes a [`MerkleInclusionProof`] carries.
pub fn generate_proof<S: TreeReader>(
    store: &S,
    keys: &[SubstateKey],
    block_height: BlockHeight,
) -> Option<MerkleInclusionProof> {
    let root_key = NodeKey::new(block_height.inner(), store.root_path());

    let jmt_keys: Vec<Key> = keys.iter().map(SubstateKey::to_bytes).collect();

    Jmt::prove(store, &root_key, &jmt_keys)
        .ok()
        // Held to the caps the reader's decoder enforces. The sibling
        // count is the claims times the tree's depth, so it moves with
        // the tree and nothing on the asking side bounds it: a query
        // legal by every leaf cap can still build a proof no asker can
        // decode. Answered as unprovable rather than sent, so the cost
        // is the walk rather than the walk and an answer thrown away.
        .filter(|proof| {
            proof.claims.len() <= MAX_PROOF_CLAIMS && proof.siblings.len() <= MAX_PROOF_SIBLINGS
        })
        .map(|proof| proof.encode())
        // A leaf-mismatch claim is wider than a leaf claim, so the two
        // counts above do not bound the encoding on their own.
        .filter(|bytes| bytes.len() <= MAX_MERKLE_PROOF_LEN)
        .map(MerkleInclusionProof::new)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_jmt::{LeafValue, MemoryStore};
    use hyperscale_types::LocalKey;
    use hyperscale_types::test_utils::test_prefix;

    use super::*;

    /// A store whose tree at height 1 holds `count` leaves under one
    /// owner, adjacent in the key space, and those leaves' keys.
    fn one_owner_with(count: u32) -> (MemoryStore, Vec<SubstateKey>) {
        let keys: Vec<SubstateKey> = (0..count)
            .map(|order| {
                let mut local = [0u8; 16];
                local[12..].copy_from_slice(&order.to_be_bytes());
                SubstateKey {
                    owner: test_prefix(1),
                    local: LocalKey(local),
                }
            })
            .collect();
        let updates: BTreeMap<Key, Option<LeafValue>> = keys
            .iter()
            .map(|key| (key.to_bytes(), Some(LeafValue::new([7; 32], 1))))
            .collect();
        let mut store = MemoryStore::new();
        let applied = Jmt::apply_updates(&store, None, 1, &updates).expect("a fresh tree takes");
        store.apply(&applied);
        (store, keys)
    }

    /// One claim past the decoder's cap is a proof no reader accepts, so
    /// none is built.
    #[test]
    fn a_proof_past_the_readers_claim_cap_is_unprovable() {
        let count = u32::try_from(MAX_PROOF_CLAIMS + 1).unwrap();
        let (store, keys) = one_owner_with(count);
        assert!(generate_proof(&store, &keys, BlockHeight::new(1)).is_none());
        assert!(generate_proof(&store, &keys[1..], BlockHeight::new(1)).is_some());
    }

    /// Adjacent leaves share every sibling, so the claims alone carry
    /// the encoding past the bytes a proof may hold: answered as
    /// unprovable, not a panic in the builder.
    #[test]
    fn a_proof_past_its_byte_cap_is_unprovable() {
        let count = u32::try_from(MAX_MERKLE_PROOF_LEN / 64).unwrap();
        let (store, keys) = one_owner_with(count);
        assert!(generate_proof(&store, &keys, BlockHeight::new(1)).is_none());
    }
}
