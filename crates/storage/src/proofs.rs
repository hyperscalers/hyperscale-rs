//! Proof generation and verification for the flat verkle state tree.
//!
//! Delegates to `hyperscale_state_tree::proofs` for the actual cryptographic
//! operations. This module provides the storage-layer API that consumers use.

use crate::jmt::ReadableTreeStore;
use crate::keys::to_storage_key;
use hyperscale_types::{Hash, SubstateInclusionProof};
use radix_substate_store_interface::interface::{DbPartitionKey, DbSortKey};

/// Generate an aggregated verkle proof for a set of storage keys.
///
/// Produces a single ~576-byte proof covering ALL entries, regardless of count.
pub fn generate_proof<S: ReadableTreeStore>(
    tree_store: &S,
    storage_keys: &[Vec<u8>],
    block_height: u64,
    node_cache: Option<&hyperscale_state_tree::NodeCache>,
) -> Option<SubstateInclusionProof> {
    hyperscale_state_tree::proofs::generate_proof(
        tree_store,
        storage_keys,
        block_height,
        node_cache,
    )
}

/// Verify an aggregated verkle proof against a state root.
///
/// The proof covers ALL entries in a single multipoint verification.
pub fn verify_all_merkle_proofs(
    entries: &[hyperscale_types::StateEntry],
    proof: &SubstateInclusionProof,
    expected_state_root: Hash,
) -> bool {
    hyperscale_state_tree::proofs::verify_proof(proof, entries, expected_state_root, |entry| {
        &entry.storage_key
    })
}

/// Build a storage key from partition key + sort key (for proof generation).
pub fn build_storage_key(partition_key: &DbPartitionKey, sort_key: &DbSortKey) -> Vec<u8> {
    to_storage_key(partition_key, sort_key)
}
