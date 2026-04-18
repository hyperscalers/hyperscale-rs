//! MVCC-aware in-memory snapshot.
//!
//! Reads walk the versioned_substates map and take the latest write at or
//! below the snapshot's target version. Used for both current-state reads
//! (via `snapshot_at(jmt_version())`) and anchor-based reads from
//! [`SubstateView`](hyperscale_storage::SubstateView).

use hyperscale_storage::{
    keys, DbPartitionKey, DbSortKey, DbSubstateValue, PartitionEntry, SubstateDatabase,
};
use std::collections::BTreeMap;

/// Snapshot of in-memory storage scoped to a specific JMT version.
///
/// Walks the `versioned_substates` map, taking the latest version ≤ target
/// per storage key. Tombstones (None values) correctly resolve to `None`.
pub struct SimSnapshot {
    pub(crate) versioned_substates: BTreeMap<(Vec<u8>, u64), Option<Vec<u8>>>,
    pub(crate) version: u64,
}

impl SubstateDatabase for SimSnapshot {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        let key = keys::to_storage_key(partition_key, sort_key);
        let range_start = (key.clone(), 0u64);
        let range_end = (key.clone(), u64::MAX);
        let mut best: Option<Vec<u8>> = None;
        for ((_, ver), value) in self.versioned_substates.range(range_start..=range_end) {
            if *ver > self.version {
                break;
            }
            best = value.clone();
        }
        best
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = PartitionEntry> + '_> {
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

        // Group by storage_key, pick latest version <= self.version per group.
        let range_start = (start, 0u64);
        let range_end = (end, 0u64);
        let target = self.version;

        let mut results: Vec<PartitionEntry> = Vec::new();
        let mut current_key: Option<&Vec<u8>> = None;
        let mut current_best: Option<Vec<u8>> = None;

        for ((sk_full, ver), value) in self.versioned_substates.range(range_start..range_end) {
            if current_key != Some(sk_full) {
                if let (Some(prev), Some(val)) = (current_key, current_best.take()) {
                    if prev.len() > prefix_len {
                        let sort_key_bytes = prev[prefix_len..].to_vec();
                        results.push((DbSortKey(sort_key_bytes), val));
                    }
                }
                current_key = Some(sk_full);
                current_best = None;
            }
            if *ver <= target {
                current_best = value.clone();
            }
        }
        if let (Some(prev), Some(val)) = (current_key, current_best) {
            if prev.len() > prefix_len {
                let sort_key_bytes = prev[prefix_len..].to_vec();
                results.push((DbSortKey(sort_key_bytes), val));
            }
        }

        Box::new(results.into_iter())
    }
}
