//! `SubstateStore` implementation for `SimStorage`.

use crate::core::SimStorage;
use crate::snapshot::SimSnapshot;

use hyperscale_storage::{keys, DbSortKey, SubstateStore};
use hyperscale_types::{Hash, NodeId};

impl SubstateStore for SimStorage {
    type Snapshot<'a> = SimSnapshot;

    fn snapshot(&self) -> Self::Snapshot<'_> {
        // O(1) clone with structural sharing!
        let data = self.state.read().unwrap().data.clone();
        SimSnapshot { data }
    }

    fn list_substates_for_node(
        &self,
        node_id: &NodeId,
    ) -> Box<dyn Iterator<Item = (u8, DbSortKey, Vec<u8>)> + '_> {
        let prefix = keys::node_prefix(node_id);
        let prefix_len = prefix.len();
        let end = keys::next_prefix(&prefix).expect("storage key prefix overflow");

        let items = self.iter_range(&prefix, &end);

        Box::new(items.into_iter().filter_map(move |(full_key, value)| {
            if full_key.len() > prefix_len {
                let partition_num = full_key[prefix_len];
                let sort_key_bytes = full_key[prefix_len + 1..].to_vec();
                Some((partition_num, DbSortKey(sort_key_bytes), value))
            } else {
                None
            }
        }))
    }

    fn jvt_version(&self) -> u64 {
        self.state.read().unwrap().current_block_height
    }

    fn state_root_hash(&self) -> Hash {
        self.state.read().unwrap().current_root_hash
    }

    fn list_substates_for_node_at_height(
        &self,
        node_id: &NodeId,
        block_height: u64,
    ) -> Option<Vec<(u8, DbSortKey, Vec<u8>)>> {
        let entity_key = keys::node_entity_key(node_id);
        let s = self.state.read().unwrap();

        if block_height > s.current_block_height {
            return None;
        }

        // MVCC prefix scan: iterate the versioned store for entries under this
        // entity, taking the latest version <= block_height for each storage key.
        // Key ordering: (storage_key, version) — ascending on both.
        let entity_len = entity_key.len();
        let end_key = keys::next_prefix(&entity_key).unwrap_or_default();
        let mut results = Vec::new();
        let mut current_sk: Option<&Vec<u8>> = None;
        let mut current_best: Option<&Vec<u8>> = None;

        let range_start = (entity_key.clone(), 0u64);
        let range_end = (end_key, 0u64);

        for ((sk, ver), value) in s.versioned_substates.range(range_start..range_end) {
            // Storage key changed — flush previous group.
            if current_sk != Some(sk) {
                if let (Some(prev_sk), Some(val)) = (current_sk, current_best) {
                    if prev_sk.len() > entity_len {
                        let partition_num = prev_sk[entity_len];
                        let sort_key = DbSortKey(prev_sk[entity_len + 1..].to_vec());
                        results.push((partition_num, sort_key, val.clone()));
                    }
                }
                current_sk = Some(sk);
                current_best = None;
            }
            // Ascending version order: overwrite candidate with each version <= height.
            if *ver <= block_height {
                match value {
                    Some(v) => current_best = Some(v),
                    None => current_best = None, // tombstone: substate deleted
                }
            }
        }
        // Flush last group.
        if let (Some(prev_sk), Some(val)) = (current_sk, current_best) {
            if prev_sk.len() > entity_len {
                let partition_num = prev_sk[entity_len];
                let sort_key = DbSortKey(prev_sk[entity_len + 1..].to_vec());
                results.push((partition_num, sort_key, val.clone()));
            }
        }

        Some(results)
    }

    fn generate_verkle_proofs(
        &self,
        storage_keys: &[Vec<u8>],
        block_height: u64,
    ) -> Option<hyperscale_types::SubstateInclusionProof> {
        let s = self.state.read().unwrap();
        hyperscale_storage::proofs::generate_proof(&s.tree_store, storage_keys, block_height, None)
    }
}
