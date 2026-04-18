//! MVCC-aware in-memory snapshot.
//!
//! Mirrors the RocksDB snapshot's seek-for-prev behaviour using
//! `BTreeMap::range(..=(key, target_version))` + `next_back()`. A `get` is
//! O(log N) on the BTreeMap regardless of how many historical versions a
//! key has accumulated, matching the RocksDB path's complexity.

use hyperscale_storage::{
    keys, DbPartitionKey, DbSortKey, DbSubstateValue, PartitionEntry, SubstateDatabase,
};
use std::collections::BTreeMap;
use std::ops::Bound;

/// Snapshot of in-memory storage scoped to a specific JMT version.
pub struct SimSnapshot {
    pub(crate) substates: BTreeMap<(Vec<u8>, u64), Option<Vec<u8>>>,
    pub(crate) version: u64,
}

impl SubstateDatabase for SimSnapshot {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        // Upper-bound range: `(storage_key, target_version)`. The last
        // entry in this range is the floor for this storage_key — the
        // largest version ≤ target. If it belongs to a different key,
        // this storage_key has no entry at or below target.
        let storage_key = keys::to_storage_key(partition_key, sort_key);
        let upper = (storage_key.clone(), self.version);
        let ((found_key, _found_ver), value) = self
            .substates
            .range((Bound::Unbounded, Bound::Included(upper)))
            .next_back()?;
        if found_key != &storage_key {
            return None;
        }
        value.clone()
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = PartitionEntry> + '_> {
        // Per-storage-key seek: walk unique storage_keys within the
        // partition and, for each, look up the floor via range-next_back.
        let prefix = keys::partition_prefix(partition_key);
        let prefix_len = prefix.len();
        let start = match from_sort_key {
            Some(sk) => {
                let mut s = prefix.clone();
                s.extend_from_slice(&sk.0);
                s
            }
            None => prefix.clone(),
        };
        let end = keys::next_prefix(&prefix).expect("storage key prefix overflow");
        let target = self.version;

        let mut results: Vec<PartitionEntry> = Vec::new();
        let mut cursor: Vec<u8> = start;

        while cursor < end {
            // Find the first entry with storage_key ≥ cursor.
            let first = self
                .substates
                .range((Bound::Included((cursor.clone(), 0u64)), Bound::Unbounded))
                .next();
            let Some(((sk_full, _), _)) = first else {
                break;
            };
            if sk_full >= &end {
                break;
            }
            let storage_key = sk_full.clone();

            // Floor for this storage_key at target version.
            let upper = (storage_key.clone(), target);
            if let Some(((found_key, _), value)) = self
                .substates
                .range((Bound::Unbounded, Bound::Included(upper)))
                .next_back()
            {
                if found_key == &storage_key {
                    if let Some(v) = value {
                        if storage_key.len() > prefix_len {
                            let sort_key_bytes = storage_key[prefix_len..].to_vec();
                            results.push((DbSortKey(sort_key_bytes), v.clone()));
                        }
                    }
                }
            }

            // Advance cursor past all versions of this storage_key.
            match keys::next_prefix(&storage_key) {
                Some(next) => cursor = next,
                None => break,
            }
        }

        Box::new(results.into_iter())
    }
}
