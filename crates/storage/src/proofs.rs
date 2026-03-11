//! Merkle proof generation and verification for 3-tier JMT.
//!
//! Provides functions to generate and verify `SubstateInclusionProof`s against
//! the Jellyfish Merkle Tree. Uses Blake3 for all proof computations.

use crate::jmt::{
    EntityTier, IteratedLeafKey, LeafKey, PartitionTier, ReadableTier, ReadableTreeStore,
    SparseMerkleProof, SubstateTier, INTERNAL_HASH_DOMAIN, LEAF_HASH_DOMAIN,
};
use crate::keys::decompose_storage_key;
use hyperscale_types::{Hash, MerkleInclusionProof, SubstateInclusionProof};

/// Convert a JMT `SparseMerkleProof` to our serializable `MerkleInclusionProof`.
fn to_merkle_inclusion_proof(proof: SparseMerkleProof) -> MerkleInclusionProof {
    let (leaf_key, leaf_value_hash) = match proof.leaf() {
        Some(leaf) => (Some(leaf.key().bytes.clone()), Some(*leaf.value_hash())),
        None => (None, None),
    };
    MerkleInclusionProof {
        leaf_key,
        leaf_value_hash,
        siblings: proof.siblings().to_vec(),
    }
}

/// Generate 3-tier JMT inclusion proofs for a set of storage keys.
///
/// For each storage key, produces a `SubstateInclusionProof` containing entity,
/// partition, and substate tier proofs chained together.
///
/// # Panics
///
/// Panics if the JMT is in an inconsistent state (missing nodes that should exist).
pub fn generate_merkle_proofs<S: ReadableTreeStore>(
    tree_store: &S,
    storage_keys: &[Vec<u8>],
    block_height: u64,
) -> Vec<SubstateInclusionProof> {
    storage_keys
        .iter()
        .map(|storage_key| {
            let (entity_key, partition_num, sort_key) =
                decompose_storage_key(storage_key).expect("invalid storage key format");

            // Entity tier: get proof + payload (partition tier root version)
            let entity_tier = EntityTier::new(tree_store, Some(block_height));
            let entity_leaf_key = LeafKey::new(entity_key);
            let (entity_data, entity_proof) = entity_tier
                .jmt()
                .get_with_proof(&entity_leaf_key, block_height)
                .expect("entity tier JMT error");

            let (_entity_value_hash, partition_root_version, _) =
                entity_data.expect("entity key not found in JMT");

            // Partition tier: get proof + payload (substate tier root version)
            let partition_tier = PartitionTier::new(
                tree_store,
                Some(partition_root_version),
                entity_key.to_vec(),
            );
            let partition_leaf_key = LeafKey::new(&[partition_num]);
            let (partition_data, partition_proof) = partition_tier
                .jmt()
                .get_with_proof(&partition_leaf_key, partition_root_version)
                .expect("partition tier JMT error");

            let (_partition_value_hash, substate_root_version, _) =
                partition_data.expect("partition key not found in JMT");

            // Substate tier: get proof
            let substate_tier = SubstateTier::new(
                tree_store,
                Some(substate_root_version),
                entity_key.to_vec(),
                partition_num,
            );
            let substate_leaf_key = LeafKey::new(sort_key);
            let (_substate_data, substate_proof) = substate_tier
                .jmt()
                .get_with_proof(&substate_leaf_key, substate_root_version)
                .expect("substate tier JMT error");

            SubstateInclusionProof {
                entity: to_merkle_inclusion_proof(entity_proof),
                partition: to_merkle_inclusion_proof(partition_proof),
                substate: to_merkle_inclusion_proof(substate_proof),
            }
        })
        .collect()
}

/// Verify a single-tier merkle proof using Blake3.
///
/// Recomputes the root hash bottom-up from the leaf and sibling hashes.
/// Returns the computed root hash, or `None` if the proof is malformed.
fn verify_single_tier(
    proof: &MerkleInclusionProof,
    key: &[u8],
    value_hash: &[u8; 32],
) -> Option<[u8; 32]> {
    let (leaf_key, leaf_value_hash) = match (&proof.leaf_key, &proof.leaf_value_hash) {
        (Some(lk), Some(lvh)) => (lk.as_slice(), lvh),
        _ => return None, // Non-inclusion proof can't verify inclusion
    };

    // The stored leaf key must match the queried key
    if leaf_key != key {
        return None;
    }

    // The stored value hash must match
    if leaf_value_hash.as_bytes() != value_hash {
        return None;
    }

    // Compute leaf hash: blake3(LEAF_DOMAIN || leaf_key || leaf_value_hash)
    let mut current_hash =
        Hash::from_parts(&[LEAF_HASH_DOMAIN, leaf_key, leaf_value_hash.as_bytes()]);

    // Walk up the tree using sibling hashes
    // The key bits (from MSB) determine left/right placement
    let key_nibble_path = LeafKey::new(key);
    let mut bit_iter = IteratedLeafKey::iter_bits(&key_nibble_path);

    // Siblings are bottom-to-top (deepest first); bits from iter_bits are
    // top-to-bottom (MSB = root level first). We walk UP from the leaf,
    // so we consume bits from the deepest level first using next_back().
    let total_bits = key.len() * 8;
    let proof_depth = proof.siblings.len();
    // Skip trailing bits beyond the proof depth (key may be longer than tree depth)
    for _ in 0..(total_bits.saturating_sub(proof_depth)) {
        bit_iter.next_back();
    }

    for sibling in &proof.siblings {
        let is_right = bit_iter.next_back().unwrap_or(false);

        current_hash = if is_right {
            Hash::from_parts(&[
                INTERNAL_HASH_DOMAIN,
                sibling.as_bytes(),
                current_hash.as_bytes(),
            ])
        } else {
            Hash::from_parts(&[
                INTERNAL_HASH_DOMAIN,
                current_hash.as_bytes(),
                sibling.as_bytes(),
            ])
        };
    }

    Some(current_hash.to_bytes())
}

/// Verify a 3-tier substate inclusion proof against an expected state root.
///
/// Performs chained verification using **Blake3**:
/// 1. Verify the substate proof -> compute `substate_tier_root`
/// 2. Verify the partition proof (with `substate_tier_root` as value) -> compute `partition_tier_root`
/// 3. Verify the entity proof (with `partition_tier_root` as value) -> compute `entity_root`
/// 4. Compare `entity_root` against `expected_state_root`
///
/// The `value` parameter is the raw substate value (will be Blake3-hashed).
/// Pass `None` for deleted/non-existent substates.
pub fn verify_substate_inclusion_proof(
    proof: &SubstateInclusionProof,
    storage_key: &[u8],
    value: Option<&[u8]>,
    expected_state_root: Hash,
) -> bool {
    let Some((entity_key, partition_num, sort_key)) = decompose_storage_key(storage_key) else {
        return false;
    };

    // Hash the value with Blake3
    let value_hash = match value {
        Some(v) => Hash::from_bytes(v).to_bytes(),
        None => [0u8; 32], // Zero hash for non-existent/deleted substates
    };

    // 1. Verify substate tier proof -> get substate_tier_root
    let Some(substate_tier_root) = verify_single_tier(&proof.substate, sort_key, &value_hash)
    else {
        return false;
    };

    // 2. Verify partition tier proof (value = substate_tier_root) -> get partition_tier_root
    let Some(partition_tier_root) =
        verify_single_tier(&proof.partition, &[partition_num], &substate_tier_root)
    else {
        return false;
    };

    // 3. Verify entity tier proof (value = partition_tier_root) -> get entity_root
    let Some(entity_root) = verify_single_tier(&proof.entity, entity_key, &partition_tier_root)
    else {
        return false;
    };

    // 4. Compare against expected state root
    entity_root == expected_state_root.to_bytes()
}

/// Verify a batch of merkle inclusion proofs against a state root.
///
/// Returns `false` if:
/// - `entries` and `merkle_proofs` have different lengths
/// - `entries` is empty
/// - any individual proof fails verification
pub fn verify_all_merkle_proofs(
    entries: &[hyperscale_types::StateEntry],
    merkle_proofs: &[SubstateInclusionProof],
    expected_state_root: Hash,
) -> bool {
    if entries.is_empty() || entries.len() != merkle_proofs.len() {
        return false;
    }
    entries
        .iter()
        .zip(merkle_proofs.iter())
        .all(|(entry, proof)| {
            verify_substate_inclusion_proof(
                proof,
                &entry.storage_key,
                entry.value.as_deref(),
                expected_state_root,
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jmt::{put_at_version_and_apply, TypedInMemoryTreeStore};
    use crate::keys::to_storage_key;
    use hyperscale_dispatch_sync::SyncDispatch;
    use radix_common::prelude::DatabaseUpdate;
    use radix_substate_store_interface::interface::{
        DatabaseUpdates, DbPartitionKey, DbSortKey, NodeDatabaseUpdates, PartitionDatabaseUpdates,
    };

    /// Build a DatabaseUpdates for a single substate write.
    fn make_update(
        node_key: &[u8],
        partition: u8,
        sort_key: &[u8],
        value: &[u8],
    ) -> DatabaseUpdates {
        let mut updates = DatabaseUpdates::default();
        updates.node_updates.insert(
            node_key.to_vec(),
            NodeDatabaseUpdates {
                partition_updates: [(
                    partition,
                    PartitionDatabaseUpdates::Delta {
                        substate_updates: [(
                            DbSortKey(sort_key.to_vec()),
                            DatabaseUpdate::Set(value.to_vec()),
                        )]
                        .into_iter()
                        .collect(),
                    },
                )]
                .into_iter()
                .collect(),
            },
        );
        updates
    }

    /// Build the storage key for a given (node_key, partition, sort_key).
    fn build_storage_key(node_key: &[u8], partition: u8, sort_key: &[u8]) -> Vec<u8> {
        let pk = DbPartitionKey {
            node_key: node_key.to_vec(),
            partition_num: partition,
        };
        let sk = DbSortKey(sort_key.to_vec());
        to_storage_key(&pk, &sk)
    }

    #[test]
    fn test_generate_and_verify_roundtrip() {
        let tree_store = TypedInMemoryTreeStore::new().with_pruning_enabled();

        // Use a 50-byte entity key (required by decompose_storage_key)
        let entity_key = [42u8; 50];
        let partition = 0u8;
        let sort_key = vec![10, 20];
        let value = vec![1, 2, 3, 4, 5];

        // Commit the substate to the JMT
        let updates = make_update(&entity_key, partition, &sort_key, &value);
        let state_root =
            put_at_version_and_apply(&tree_store, None, 1, &updates, &SyncDispatch::new());
        let block_height = 1u64;

        let storage_key = build_storage_key(&entity_key, partition, &sort_key);

        // Generate proof
        let proofs = generate_merkle_proofs(
            &tree_store,
            std::slice::from_ref(&storage_key),
            block_height,
        );
        assert_eq!(proofs.len(), 1);

        // Verify proof
        let valid =
            verify_substate_inclusion_proof(&proofs[0], &storage_key, Some(&value), state_root);
        assert!(
            valid,
            "proof should verify against correct state root and value"
        );
    }

    #[test]
    fn test_verify_rejects_wrong_value() {
        let tree_store = TypedInMemoryTreeStore::new().with_pruning_enabled();

        let entity_key = [42u8; 50];
        let partition = 0u8;
        let sort_key = vec![10];
        let value = vec![1, 2, 3];

        let updates = make_update(&entity_key, partition, &sort_key, &value);
        let state_root =
            put_at_version_and_apply(&tree_store, None, 1, &updates, &SyncDispatch::new());
        let storage_key = build_storage_key(&entity_key, partition, &sort_key);

        let proofs = generate_merkle_proofs(&tree_store, std::slice::from_ref(&storage_key), 1);

        // Wrong value should fail
        let wrong_value = vec![99, 99, 99];
        let valid = verify_substate_inclusion_proof(
            &proofs[0],
            &storage_key,
            Some(&wrong_value),
            state_root,
        );
        assert!(!valid, "proof should reject incorrect value");
    }

    #[test]
    fn test_verify_rejects_wrong_state_root() {
        let tree_store = TypedInMemoryTreeStore::new().with_pruning_enabled();

        let entity_key = [42u8; 50];
        let partition = 0u8;
        let sort_key = vec![10];
        let value = vec![1, 2, 3];

        let updates = make_update(&entity_key, partition, &sort_key, &value);
        put_at_version_and_apply(&tree_store, None, 1, &updates, &SyncDispatch::new());
        let storage_key = build_storage_key(&entity_key, partition, &sort_key);

        let proofs = generate_merkle_proofs(&tree_store, std::slice::from_ref(&storage_key), 1);

        // Wrong state root should fail
        let wrong_root = Hash::from_bytes(b"definitely_wrong_root");
        let valid =
            verify_substate_inclusion_proof(&proofs[0], &storage_key, Some(&value), wrong_root);
        assert!(!valid, "proof should reject incorrect state root");
    }

    #[test]
    fn test_multiple_substates_independent_proofs() {
        let tree_store = TypedInMemoryTreeStore::new().with_pruning_enabled();

        // Two different entities
        let entity_a = [7u8; 50];
        let entity_b = [8u8; 50];
        let value_a = vec![10, 20];
        let value_b = vec![30, 40];

        // Commit both in one update
        let mut updates = make_update(&entity_a, 0, &[1], &value_a);
        let updates_b = make_update(&entity_b, 0, &[2], &value_b);
        updates.node_updates.extend(updates_b.node_updates);

        let state_root =
            put_at_version_and_apply(&tree_store, None, 1, &updates, &SyncDispatch::new());

        let key_a = build_storage_key(&entity_a, 0, &[1]);
        let key_b = build_storage_key(&entity_b, 0, &[2]);

        let proofs = generate_merkle_proofs(&tree_store, &[key_a.clone(), key_b.clone()], 1);
        assert_eq!(proofs.len(), 2);

        assert!(verify_substate_inclusion_proof(
            &proofs[0],
            &key_a,
            Some(&value_a),
            state_root
        ));
        assert!(verify_substate_inclusion_proof(
            &proofs[1],
            &key_b,
            Some(&value_b),
            state_root
        ));
    }
}
