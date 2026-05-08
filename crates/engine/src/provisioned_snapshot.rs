//! Read-only overlay that layers cross-shard provisions on top of local storage.
//!
//! When a transaction reads state owned by another shard, the sending
//! shard ships a [`SubstateEntry`] list with pre-computed storage keys
//! (full `db_node_key || partition || sort_key`). The receiving shard
//! wraps its base storage in [`ProvisionedSnapshot`] so the Radix
//! Engine sees a unified view: provisions shadow base, deletions in
//! provisions hide base entries.
//!
//! # Why pre-computed storage keys
//!
//! `SpreadPrefixKeyMapper::to_db_node_key` is a Blake2b hash. Computing
//! it once on the sender (where ownership is naturally known) instead
//! of every lookup on the receiver removes hash work from the hot path
//! and lets us key provisions by raw bytes in a flat `BTreeMap`.
//!
//! # Iterator semantics
//!
//! [`SubstateDatabase::list_raw_values_from_db_key`] returns base
//! and provision entries merge-sorted by sort key. On collision the
//! provision wins; a `None` provision value (deletion) suppresses both
//! the base entry and any earlier-only provision entry. See
//! [`MergedPartitionIterator`].

use std::collections::BTreeMap;

use hyperscale_storage::keys;
use hyperscale_types::SubstateEntry;
use radix_engine::transaction::{ExecutionConfig, TransactionReceipt, execute_transaction};
use radix_engine::vm::DefaultVmModules;
use radix_substate_store_interface::interface::{DbPartitionKey, DbSortKey, SubstateDatabase};
use radix_transactions::prelude::ExecutableTransaction;

/// A snapshot with provisions overlaid using pre-computed storage keys.
///
/// - Uses pre-computed storage keys (no `SpreadPrefixKeyMapper` calls)
/// - Uses a flat `BTreeMap` keyed by full storage key (faster lookups)
/// - Supports efficient range queries via `BTreeMap::range()`
///
/// # Usage
///
/// ```ignore
/// let entries: Vec<SubstateEntry> = /* provisions with pre-computed keys */;
/// let snapshot = ProvisionedSnapshot::from_provisions(&base_storage, &[entries.as_slice()]);
/// let receipt = execute_transaction(&snapshot, vm_modules, config, executable);
/// ```
pub struct ProvisionedSnapshot<'a, S> {
    base: &'a S,
    /// Provisions keyed by full storage key.
    /// Value is None for deletions, Some(bytes) for sets.
    provisions: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl<'a, S: SubstateDatabase> ProvisionedSnapshot<'a, S> {
    /// Create from one or more provision lists (typically one per source shard).
    pub fn from_provisions(base: &'a S, provisions_list: &[&[SubstateEntry]]) -> Self {
        let mut provisions = BTreeMap::new();

        for entries in provisions_list {
            for entry in *entries {
                provisions.insert(
                    entry.storage_key.0.clone(),
                    entry.value.as_ref().map(|v| v.0.clone()),
                );
            }
        }

        Self { base, provisions }
    }

    /// Execute a transaction against this provisioned snapshot.
    #[must_use]
    pub fn execute(
        &self,
        executable: &ExecutableTransaction,
        vm_modules: &DefaultVmModules,
        exec_config: &ExecutionConfig,
    ) -> TransactionReceipt {
        execute_transaction(self, vm_modules, exec_config, executable)
    }
}

impl<S: SubstateDatabase> SubstateDatabase for ProvisionedSnapshot<'_, S> {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<Vec<u8>> {
        let key = keys::to_storage_key(partition_key, sort_key);

        // Provisions take precedence: hit means use it (None = deletion).
        if let Some(value) = self.provisions.get(&key) {
            return value.clone();
        }

        self.base
            .get_raw_substate_by_db_key(partition_key, sort_key)
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = (DbSortKey, Vec<u8>)> + '_> {
        let prefix = keys::partition_prefix(partition_key);
        let prefix_len = prefix.len();
        let prefix_end = keys::next_prefix(&prefix).expect("storage key prefix overflow");

        let start = match from_sort_key {
            Some(sk) => {
                let mut s = prefix;
                s.extend_from_slice(&sk.0);
                s
            }
            None => prefix,
        };

        let base_iter = self
            .base
            .list_raw_values_from_db_key(partition_key, from_sort_key);

        // Collect provisions falling in [start, prefix_end) — i.e. this
        // partition, at or after `from_sort_key`. Provisions are stored
        // by full storage key, so we strip the partition prefix to get
        // bare sort keys for the merge.
        let prov_entries: Vec<_> = self
            .provisions
            .range(start..prefix_end)
            .filter_map(|(k, v)| {
                if k.len() > prefix_len {
                    let sort_key = DbSortKey(k[prefix_len..].to_vec());
                    Some((sort_key, v.clone()))
                } else {
                    None
                }
            })
            .collect();

        if prov_entries.is_empty() {
            return base_iter;
        }

        Box::new(MergedPartitionIterator::new(base_iter, prov_entries))
    }
}

/// Iterator that merges base storage entries with provision overrides.
///
/// Both inputs must be sorted by sort key. On collision the provision
/// wins; a `None` provision value suppresses the matching base entry.
struct MergedPartitionIterator<'a> {
    base: std::iter::Peekable<Box<dyn Iterator<Item = (DbSortKey, Vec<u8>)> + 'a>>,
    provisions: std::iter::Peekable<std::vec::IntoIter<(DbSortKey, Option<Vec<u8>>)>>,
}

impl<'a> MergedPartitionIterator<'a> {
    fn new(
        base: Box<dyn Iterator<Item = (DbSortKey, Vec<u8>)> + 'a>,
        provisions: Vec<(DbSortKey, Option<Vec<u8>>)>,
    ) -> Self {
        Self {
            base: base.peekable(),
            provisions: provisions.into_iter().peekable(),
        }
    }
}

impl Iterator for MergedPartitionIterator<'_> {
    type Item = (DbSortKey, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match (self.base.peek(), self.provisions.peek()) {
                (Some((base_key, _)), Some((prov_key, _))) => {
                    match base_key.0.cmp(&prov_key.0) {
                        std::cmp::Ordering::Less => {
                            // Base key is smaller; emit it (no provision shadows it).
                            return self.base.next();
                        }
                        std::cmp::Ordering::Equal => {
                            // Same key — provision wins; consume both.
                            let _ = self.base.next();
                            let (key, value) = self.provisions.next().unwrap();
                            if let Some(v) = value {
                                return Some((key, v));
                            }
                            // Deletion — both consumed, loop to next pair.
                        }
                        std::cmp::Ordering::Greater => {
                            // Provision key is smaller; it's a new entry not in base.
                            let (key, value) = self.provisions.next().unwrap();
                            if let Some(v) = value {
                                return Some((key, v));
                            }
                            // Deletion of a non-existent base entry — skip.
                        }
                    }
                }
                (Some(_), None) => {
                    return self.base.next();
                }
                (None, Some(_)) => {
                    let (key, value) = self.provisions.next().unwrap();
                    if let Some(v) = value {
                        return Some((key, v));
                    }
                }
                (None, None) => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    /// In-memory `SubstateDatabase` keyed by full storage key.
    /// Mirrors the layout `ProvisionedSnapshot` overlays on top of.
    #[derive(Default)]
    struct MapDb {
        entries: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    impl MapDb {
        fn insert(&mut self, partition: &DbPartitionKey, sort: &DbSortKey, value: Vec<u8>) {
            self.entries
                .insert(keys::to_storage_key(partition, sort), value);
        }
    }

    impl SubstateDatabase for MapDb {
        fn get_raw_substate_by_db_key(
            &self,
            partition_key: &DbPartitionKey,
            sort_key: &DbSortKey,
        ) -> Option<Vec<u8>> {
            self.entries
                .get(&keys::to_storage_key(partition_key, sort_key))
                .cloned()
        }

        fn list_raw_values_from_db_key(
            &self,
            partition_key: &DbPartitionKey,
            from_sort_key: Option<&DbSortKey>,
        ) -> Box<dyn Iterator<Item = (DbSortKey, Vec<u8>)> + '_> {
            let prefix = keys::partition_prefix(partition_key);
            let prefix_len = prefix.len();
            let prefix_end = keys::next_prefix(&prefix).expect("prefix overflow");
            let start = match from_sort_key {
                Some(sk) => {
                    let mut s = prefix;
                    s.extend_from_slice(&sk.0);
                    s
                }
                None => prefix,
            };
            Box::new(
                self.entries
                    .range(start..prefix_end)
                    .map(move |(k, v)| (DbSortKey(k[prefix_len..].to_vec()), v.clone())),
            )
        }
    }

    fn partition() -> DbPartitionKey {
        DbPartitionKey {
            node_key: vec![0x42; 50],
            partition_num: 7,
        }
    }

    fn sort(b: u8) -> DbSortKey {
        DbSortKey(vec![b])
    }

    /// Build a `SubstateEntry` whose `storage_key` lives in `partition()` at `sort(b)`.
    fn entry(part: &DbPartitionKey, b: u8, value: Option<Vec<u8>>) -> SubstateEntry {
        SubstateEntry::new(keys::to_storage_key(part, &sort(b)), value)
    }

    #[test]
    fn get_provision_shadows_base() {
        let part = partition();
        let mut base = MapDb::default();
        base.insert(&part, &sort(1), b"base".to_vec());
        let provisions = vec![entry(&part, 1, Some(b"prov".to_vec()))];
        let snap = ProvisionedSnapshot::from_provisions(&base, &[provisions.as_slice()]);

        assert_eq!(
            snap.get_raw_substate_by_db_key(&part, &sort(1)),
            Some(b"prov".to_vec()),
        );
    }

    #[test]
    fn get_provision_deletion_masks_base() {
        let part = partition();
        let mut base = MapDb::default();
        base.insert(&part, &sort(1), b"base".to_vec());
        let provisions = vec![entry(&part, 1, None)];
        let snap = ProvisionedSnapshot::from_provisions(&base, &[provisions.as_slice()]);

        assert_eq!(snap.get_raw_substate_by_db_key(&part, &sort(1)), None);
    }

    #[test]
    fn get_falls_through_to_base_when_no_provision() {
        let part = partition();
        let mut base = MapDb::default();
        base.insert(&part, &sort(2), b"base".to_vec());
        let snap: ProvisionedSnapshot<'_, MapDb> = ProvisionedSnapshot::from_provisions(&base, &[]);

        assert_eq!(
            snap.get_raw_substate_by_db_key(&part, &sort(2)),
            Some(b"base".to_vec()),
        );
    }

    #[test]
    fn list_merges_base_and_provisions_in_order() {
        let part = partition();
        let mut base = MapDb::default();
        base.insert(&part, &sort(1), b"b1".to_vec());
        base.insert(&part, &sort(3), b"b3".to_vec());
        let provisions = vec![
            entry(&part, 2, Some(b"p2".to_vec())),
            entry(&part, 4, Some(b"p4".to_vec())),
        ];
        let snap = ProvisionedSnapshot::from_provisions(&base, &[provisions.as_slice()]);

        let collected: Vec<_> = snap
            .list_raw_values_from_db_key(&part, None)
            .map(|(k, v)| (k.0, v))
            .collect();

        assert_eq!(
            collected,
            vec![
                (vec![1], b"b1".to_vec()),
                (vec![2], b"p2".to_vec()),
                (vec![3], b"b3".to_vec()),
                (vec![4], b"p4".to_vec()),
            ],
        );
    }

    #[test]
    fn list_provision_overrides_base_at_same_key() {
        let part = partition();
        let mut base = MapDb::default();
        base.insert(&part, &sort(1), b"base".to_vec());
        base.insert(&part, &sort(2), b"base".to_vec());
        let provisions = vec![entry(&part, 1, Some(b"prov".to_vec()))];
        let snap = ProvisionedSnapshot::from_provisions(&base, &[provisions.as_slice()]);

        let collected: Vec<_> = snap
            .list_raw_values_from_db_key(&part, None)
            .map(|(k, v)| (k.0, v))
            .collect();

        assert_eq!(
            collected,
            vec![(vec![1], b"prov".to_vec()), (vec![2], b"base".to_vec())],
        );
    }

    #[test]
    fn list_provision_deletion_hides_base_entry() {
        let part = partition();
        let mut base = MapDb::default();
        base.insert(&part, &sort(1), b"base".to_vec());
        base.insert(&part, &sort(2), b"base".to_vec());
        let provisions = vec![entry(&part, 1, None)];
        let snap = ProvisionedSnapshot::from_provisions(&base, &[provisions.as_slice()]);

        let collected: Vec<_> = snap
            .list_raw_values_from_db_key(&part, None)
            .map(|(k, v)| (k.0, v))
            .collect();

        assert_eq!(collected, vec![(vec![2], b"base".to_vec())]);
    }

    #[test]
    fn list_provision_deletion_of_absent_key_is_a_noop() {
        let part = partition();
        let mut base = MapDb::default();
        base.insert(&part, &sort(2), b"base".to_vec());
        let provisions = vec![entry(&part, 1, None)];
        let snap = ProvisionedSnapshot::from_provisions(&base, &[provisions.as_slice()]);

        let collected: Vec<_> = snap
            .list_raw_values_from_db_key(&part, None)
            .map(|(k, v)| (k.0, v))
            .collect();

        assert_eq!(collected, vec![(vec![2], b"base".to_vec())]);
    }

    #[test]
    fn list_respects_from_sort_key() {
        let part = partition();
        let mut base = MapDb::default();
        base.insert(&part, &sort(1), b"b1".to_vec());
        base.insert(&part, &sort(3), b"b3".to_vec());
        let provisions = vec![entry(&part, 2, Some(b"p2".to_vec()))];
        let snap = ProvisionedSnapshot::from_provisions(&base, &[provisions.as_slice()]);

        let collected: Vec<_> = snap
            .list_raw_values_from_db_key(&part, Some(&sort(2)))
            .map(|(k, v)| (k.0, v))
            .collect();

        assert_eq!(
            collected,
            vec![(vec![2], b"p2".to_vec()), (vec![3], b"b3".to_vec())],
        );
    }

    #[test]
    fn list_other_partition_unaffected_by_provisions() {
        let part_a = partition();
        let part_b = DbPartitionKey {
            node_key: vec![0x42; 50],
            partition_num: 8,
        };
        let mut base = MapDb::default();
        base.insert(&part_b, &sort(1), b"b1".to_vec());
        // Provision in partition A should NOT appear in partition B's listing.
        let provisions = vec![entry(&part_a, 1, Some(b"p1".to_vec()))];
        let snap = ProvisionedSnapshot::from_provisions(&base, &[provisions.as_slice()]);

        let collected: Vec<_> = snap
            .list_raw_values_from_db_key(&part_b, None)
            .map(|(k, v)| (k.0, v))
            .collect();

        assert_eq!(collected, vec![(vec![1], b"b1".to_vec())]);
    }

    #[test]
    fn from_provisions_merges_multiple_lists() {
        let part = partition();
        let base = MapDb::default();
        let list_a = vec![entry(&part, 1, Some(b"a1".to_vec()))];
        let list_b = vec![entry(&part, 2, Some(b"b2".to_vec()))];
        let snap =
            ProvisionedSnapshot::from_provisions(&base, &[list_a.as_slice(), list_b.as_slice()]);

        assert_eq!(
            snap.get_raw_substate_by_db_key(&part, &sort(1)),
            Some(b"a1".to_vec()),
        );
        assert_eq!(
            snap.get_raw_substate_by_db_key(&part, &sort(2)),
            Some(b"b2".to_vec()),
        );
    }
}
