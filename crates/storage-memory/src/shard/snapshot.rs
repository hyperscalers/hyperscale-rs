//! State-history-based in-memory snapshot.
//!
//! Reads at the current tip are a direct `get` on `current_state`. Reads
//! at a historical version V use a single forward-scan on `state_history`
//! to find the smallest entry `(K, v')` with `v' > V`; its stored prior
//! value is the value of K at V. If no such entry exists,
//! `current_state[K]` was stable since V and is the answer.

use std::collections::BTreeMap;
use std::ops::Bound;

use hyperscale_storage::{Anchored, Substates};
use hyperscale_types::{BlockHeight, EntryKey, SubstateKey};
use hyperscale_vm_types::{Address, CollectionId};

use super::state::{CellHistory, Cells, Entries, EntryHistory};

/// Point-in-time snapshot of in-memory storage scoped to a specific
/// version within the retention window. Retention enforcement happens
/// at construction in `SimShardStorage::snapshot_at`.
pub struct SimSnapshot {
    pub(crate) current_state: Cells,
    pub(crate) state_history: CellHistory,
    pub(crate) current_entries: Entries,
    pub(crate) entries_history: EntryHistory,
    /// Target version for all reads from this snapshot.
    pub(crate) version: u64,
    /// Current committed tip at snapshot-construction time. When
    /// `version >= current_version` we take the trivial branch
    /// (direct `current_state` read) for every operation.
    pub(crate) current_version: u64,
}

/// Value of `key` at `version`: the prior value of the smallest
/// state-history write after `version` (value-just-before that write,
/// which equals value-at-version since no writes happened between), or
/// the current value when no later write exists.
pub fn value_at_version(
    current_state: &Cells,
    state_history: &CellHistory,
    key: SubstateKey,
    version: u64,
    current_version: u64,
) -> Option<Vec<u8>> {
    let current = current_state.get(&key);

    if version >= current_version {
        return current.map(|value| value.to_vec());
    }

    let next = state_history
        .range((Bound::Included((key, version + 1)), Bound::Unbounded))
        .next();
    match next {
        Some(((k, _v_prime), prior)) if *k == key => prior.as_ref().map(|value| value.to_vec()),
        _ => current.map(|value| value.to_vec()),
    }
}

/// The entries of one collection's `[lo, hi]` interval at `version`:
/// the current index rows corrected by the per-order first history
/// write after `version` — the rule [`value_at_version`] applies to a
/// cell, applied per order over the interval.
pub fn entries_in_range_at(
    current_entries: &Entries,
    entries_history: &EntryHistory,
    lo_key: EntryKey,
    hi_key: EntryKey,
    limit: usize,
    version: u64,
    current_version: u64,
) -> Vec<(u128, Vec<u8>)> {
    if lo_key.order > hi_key.order || limit == 0 {
        return Vec::new();
    }
    let mut merged: BTreeMap<u128, Vec<u8>> = current_entries
        .range(lo_key..=hi_key)
        .map(|(key, value)| (key.order, value.to_vec()))
        .collect();
    if version < current_version {
        let mut overridden: BTreeMap<u128, Option<Vec<u8>>> = BTreeMap::new();
        for ((key, write_version), prior) in entries_history.range((lo_key, 0)..=(hi_key, u64::MAX))
        {
            if *write_version > version && !overridden.contains_key(&key.order) {
                overridden.insert(key.order, prior.as_ref().map(|value| value.to_vec()));
            }
        }
        for (order, prior) in overridden {
            match prior {
                Some(value) => {
                    merged.insert(order, value);
                }
                None => {
                    merged.remove(&order);
                }
            }
        }
    }
    merged.into_iter().take(limit).collect()
}

impl Anchored for SimSnapshot {
    fn anchor(&self) -> BlockHeight {
        BlockHeight::new(self.version)
    }
}

impl Substates for SimSnapshot {
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        value_at_version(
            &self.current_state,
            &self.state_history,
            key,
            self.version,
            self.current_version,
        )
    }

    fn entries_in_range(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        entries_in_range_at(
            &self.current_entries,
            &self.entries_history,
            EntryKey {
                owner,
                collection,
                order: lo,
            },
            EntryKey {
                owner,
                collection,
                order: hi,
            },
            limit,
            self.version,
            self.current_version,
        )
    }
}
