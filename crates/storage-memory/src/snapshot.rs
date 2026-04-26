//! State-history-based in-memory snapshot.
//!
//! Reads at the current tip are a direct `BTreeMap::get` on
//! `current_state`. Reads at a historical version V use a single
//! forward-scan on `state_history` to find the smallest entry `(K, v')`
//! with `v' > V`; its stored prior value is the value of K at V. If no
//! such entry exists, `current_state[K]` was stable since V and is the
//! answer.

use hyperscale_storage::{
    DbPartitionKey, DbSortKey, DbSubstateValue, PartitionEntry, SubstateDatabase, keys,
};
use hyperscale_types::NodeId;
use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;

/// Point-in-time snapshot of in-memory storage scoped to a specific
/// version within the retention window. Retention enforcement happens
/// at construction in `SimStorage::snapshot_at`.
pub struct SimSnapshot {
    pub(crate) current_state: BTreeMap<Vec<u8>, Vec<u8>>,
    pub(crate) state_history: BTreeMap<(Vec<u8>, u64), Option<Vec<u8>>>,
    /// Target version for all reads from this snapshot.
    pub(crate) version: u64,
    /// Current committed tip at snapshot-construction time. When
    /// `version >= current_version` we take the trivial branch
    /// (direct `current_state` read) for every operation.
    pub(crate) current_version: u64,
}

impl SimSnapshot {
    /// Shared 2-pass algorithm: list `(storage_key, value)` pairs for
    /// all keys under `prefix` at `self.version`.
    ///
    /// - Pass 1: every state-history entry `(K, v')` with `K` under
    ///   prefix and `v' > version` contributes "value-at-version for K"
    ///   via its prior value. First entry per K wins (smallest v').
    /// - Pass 2: for keys in `current_state` under prefix not touched
    ///   by pass 1, the current value IS the value at version (no
    ///   writes since).
    ///
    /// Returns live (non-None) entries sorted by `storage_key` ascending.
    fn list_at_prefix(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let end = keys::next_prefix(prefix).expect("storage key prefix overflow");

        if self.version >= self.current_version {
            // Trivial: direct scan of current_state.
            return self
                .current_state
                .range(prefix.to_vec()..end)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
        }

        let mut value_at_v: HashMap<Vec<u8>, Option<Vec<u8>>> = HashMap::new();

        // Pass 1: scan state_history for the whole prefix range.
        // BTreeMap range iterates in ascending key order — for each
        // storage_key, the first entry with v' > version is the
        // smallest, which is what we want.
        let history_start = (prefix.to_vec(), 0u64);
        let history_end = (end.clone(), 0u64);
        for ((k, v_prime), prior) in self.state_history.range(history_start..history_end) {
            if *v_prime <= self.version {
                continue;
            }
            value_at_v.entry(k.clone()).or_insert_with(|| prior.clone());
        }

        // Pass 2: fill in unchanged keys from current_state.
        for (k, v) in self.current_state.range(prefix.to_vec()..end) {
            value_at_v
                .entry(k.clone())
                .or_insert_with(|| Some(v.clone()));
        }

        let mut out: Vec<_> = value_at_v
            .into_iter()
            .filter_map(|(k, v)| v.map(|val| (k, val)))
            .collect();
        out.sort_by(|(a, _), (b, _)| a.cmp(b));
        out
    }

    /// Entity-scoped list used by cross-shard provisioning.
    /// Decomposes each `storage_key` into `(partition_num, sort_key, value)`.
    #[must_use]
    pub fn list_raw_values_for_node(&self, node_id: &NodeId) -> Vec<(u8, DbSortKey, Vec<u8>)> {
        let entity_key = keys::node_entity_key(node_id);
        let entity_len = entity_key.len();
        self.list_at_prefix(&entity_key)
            .into_iter()
            .filter_map(|(k, v)| {
                if k.len() <= entity_len {
                    return None;
                }
                let partition_num = k[entity_len];
                let sort_key = DbSortKey(k[entity_len + 1..].to_vec());
                Some((partition_num, sort_key, v))
            })
            .collect()
    }
}

impl SubstateDatabase for SimSnapshot {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        let storage_key = keys::to_storage_key(partition_key, sort_key);
        let current = self.current_state.get(&storage_key).cloned();

        if self.version >= self.current_version {
            return current;
        }

        // Historical: smallest state-history entry for K with
        // v' > version. Its prior value is the state at `version`
        // (value-just-before v', which equals value-at-version since no
        // writes happened between).
        let lower = (storage_key.clone(), self.version + 1);
        let next = self
            .state_history
            .range((Bound::Included(lower), Bound::Unbounded))
            .next();
        match next {
            Some(((k, _v_prime), prior)) if k == &storage_key => prior.clone(),
            _ => current,
        }
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = PartitionEntry> + '_> {
        let prefix = keys::partition_prefix(partition_key);
        let prefix_len = prefix.len();
        let from_sort_key = from_sort_key.cloned();
        Box::new(
            self.list_at_prefix(&prefix)
                .into_iter()
                .filter_map(move |(k, v)| {
                    if k.len() < prefix_len {
                        return None;
                    }
                    let sort_key_bytes = k[prefix_len..].to_vec();
                    let sort_key = DbSortKey(sort_key_bytes);
                    if let Some(from) = &from_sort_key
                        && sort_key < *from
                    {
                        return None;
                    }
                    Some((sort_key, v))
                }),
        )
    }
}
