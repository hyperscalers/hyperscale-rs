//! Utilities for merging, filtering, and reconstructing `DatabaseUpdates`.

use hyperscale_types::ReceiptBundle;
use radix_common::prelude::DatabaseUpdate;
use radix_substate_store_interface::interface::{
    DatabaseUpdates, NodeDatabaseUpdates, PartitionDatabaseUpdates,
};
use std::sync::Arc;

/// Extract and merge `DatabaseUpdates` from receipt bundles.
///
/// This is the canonical way to derive state updates from receipts for
/// JMT computation and substate writes. Used internally by `ChainWriter`
/// implementations.
pub fn merge_updates_from_receipts(receipts: &[ReceiptBundle]) -> DatabaseUpdates {
    if receipts.is_empty() {
        return DatabaseUpdates::default();
    }
    if receipts.len() == 1 {
        return receipts[0].local_receipt.database_updates.clone();
    }
    let mut merged = DatabaseUpdates::default();
    for bundle in receipts {
        merge_into(&mut merged, &bundle.local_receipt.database_updates);
    }
    merged
}

/// Merge a slice of per-certificate `DatabaseUpdates` into a single combined update.
///
/// Later certificates take precedence for conflicting keys (last writer wins).
/// This is deterministic: certificates are processed left-to-right.
pub fn merge_database_updates(updates_list: &[DatabaseUpdates]) -> DatabaseUpdates {
    if updates_list.is_empty() {
        return DatabaseUpdates::default();
    }
    if updates_list.len() == 1 {
        return updates_list[0].clone();
    }
    let mut merged = DatabaseUpdates::default();
    for updates in updates_list {
        merge_into(&mut merged, updates);
    }
    merged
}

/// Merge a slice of Arc-wrapped per-certificate `DatabaseUpdates` into a single combined update.
///
/// Same semantics as [`merge_database_updates`] but dereferences through `Arc`.
pub fn merge_database_updates_from_arcs(updates_list: &[Arc<DatabaseUpdates>]) -> DatabaseUpdates {
    if updates_list.is_empty() {
        return DatabaseUpdates::default();
    }
    if updates_list.len() == 1 {
        return (*updates_list[0]).clone();
    }
    let mut merged = DatabaseUpdates::default();
    for updates in updates_list {
        merge_into(&mut merged, updates);
    }
    merged
}

/// Merge `source` into `target` in place.
///
/// Later entries (from `source`) take precedence for conflicting keys.
pub fn merge_into(target: &mut DatabaseUpdates, source: &DatabaseUpdates) {
    for (entity_key, node_updates) in &source.node_updates {
        merge_node_updates(
            target.node_updates.entry(entity_key.clone()).or_default(),
            node_updates,
        );
    }
}

fn merge_node_updates(target: &mut NodeDatabaseUpdates, source: &NodeDatabaseUpdates) {
    for (partition, part_updates) in &source.partition_updates {
        match target.partition_updates.entry(*partition) {
            indexmap::map::Entry::Vacant(e) => {
                e.insert(part_updates.clone());
            }
            indexmap::map::Entry::Occupied(mut e) => {
                merge_partition_updates(e.get_mut(), part_updates);
            }
        }
    }
}

fn merge_partition_updates(
    target: &mut PartitionDatabaseUpdates,
    source: &PartitionDatabaseUpdates,
) {
    match (target, source) {
        // Delta + Delta: extend substate_updates, source wins for same key.
        (
            PartitionDatabaseUpdates::Delta {
                substate_updates: target_updates,
            },
            PartitionDatabaseUpdates::Delta {
                substate_updates: source_updates,
            },
        ) => {
            target_updates.extend(source_updates.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        // Delta + Reset: source Reset replaces target entirely.
        // Reset + Reset: source Reset replaces target entirely.
        (target, PartitionDatabaseUpdates::Reset { .. }) => {
            *target = source.clone();
        }
        // Reset + Delta: apply delta on top of Reset's values.
        (
            PartitionDatabaseUpdates::Reset {
                new_substate_values,
            },
            PartitionDatabaseUpdates::Delta { substate_updates },
        ) => {
            for (sort_key, update) in substate_updates {
                match update {
                    DatabaseUpdate::Set(value) => {
                        new_substate_values.insert(sort_key.clone(), value.clone());
                    }
                    DatabaseUpdate::Delete => {
                        new_substate_values.swap_remove(sort_key);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use radix_common::prelude::DatabaseUpdate;
    use radix_substate_store_interface::interface::DbSortKey;

    // Helper to create a Delta DatabaseUpdates with a single node/partition/substate.
    fn make_delta_updates(
        node_key: &[u8],
        partition: u8,
        sort_key: Vec<u8>,
        update: DatabaseUpdate,
    ) -> DatabaseUpdates {
        let mut updates = DatabaseUpdates::default();
        let node_updates = updates.node_updates.entry(node_key.to_vec()).or_default();
        let partition_updates = node_updates
            .partition_updates
            .entry(partition)
            .or_insert_with(|| PartitionDatabaseUpdates::Delta {
                substate_updates: indexmap::IndexMap::new(),
            });
        if let PartitionDatabaseUpdates::Delta { substate_updates } = partition_updates {
            substate_updates.insert(DbSortKey(sort_key), update);
        }
        updates
    }

    fn make_reset_updates(
        node_key: &[u8],
        partition: u8,
        values: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> DatabaseUpdates {
        let mut new_substate_values = indexmap::IndexMap::new();
        for (k, v) in values {
            new_substate_values.insert(DbSortKey(k), v);
        }
        let mut updates = DatabaseUpdates::default();
        let node_updates = updates.node_updates.entry(node_key.to_vec()).or_default();
        node_updates.partition_updates.insert(
            partition,
            PartitionDatabaseUpdates::Reset {
                new_substate_values,
            },
        );
        updates
    }

    fn get_delta_value(
        updates: &DatabaseUpdates,
        node_key: &[u8],
        partition: u8,
        sort_key: &[u8],
    ) -> Option<DatabaseUpdate> {
        let nk: Vec<u8> = node_key.to_vec();
        let pk: u8 = partition;
        let sk = DbSortKey(sort_key.to_vec());
        updates.node_updates.get(&nk).and_then(|n| {
            n.partition_updates.get(&pk).and_then(|p| {
                if let PartitionDatabaseUpdates::Delta { substate_updates } = p {
                    substate_updates.get(&sk).cloned()
                } else {
                    None
                }
            })
        })
    }

    fn get_reset_values(
        updates: &DatabaseUpdates,
        node_key: &[u8],
        partition: u8,
    ) -> Option<indexmap::IndexMap<DbSortKey, Vec<u8>>> {
        let nk: Vec<u8> = node_key.to_vec();
        let pk: u8 = partition;
        updates.node_updates.get(&nk).and_then(|n| {
            n.partition_updates.get(&pk).and_then(|p| {
                if let PartitionDatabaseUpdates::Reset {
                    new_substate_values,
                } = p
                {
                    Some(new_substate_values.clone())
                } else {
                    None
                }
            })
        })
    }

    #[test]
    fn test_merge_delta_delta_same_key_last_wins() {
        let u1 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![10]));
        let u2 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![20]));
        let merged = merge_database_updates(&[u1, u2]);
        assert!(
            matches!(get_delta_value(&merged, b"node1", 0, &[1]), Some(DatabaseUpdate::Set(v)) if v == vec![20])
        );
    }

    #[test]
    fn test_merge_delta_delta_disjoint_keys() {
        let u1 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![10]));
        let u2 = make_delta_updates(b"node1", 0, vec![2], DatabaseUpdate::Set(vec![20]));
        let merged = merge_database_updates(&[u1, u2]);
        assert!(get_delta_value(&merged, b"node1", 0, &[1]).is_some());
        assert!(get_delta_value(&merged, b"node1", 0, &[2]).is_some());
    }

    #[test]
    fn test_merge_delta_then_reset_replaces() {
        let u1 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![10]));
        let u2 = make_reset_updates(b"node1", 0, vec![(vec![5], vec![50])]);
        let merged = merge_database_updates(&[u1, u2]);
        let vals = get_reset_values(&merged, b"node1", 0).unwrap();
        assert_eq!(vals.len(), 1);
        assert_eq!(vals.get(&DbSortKey(vec![5])).unwrap(), &vec![50]);
    }

    #[test]
    fn test_merge_reset_then_delta_set() {
        let u1 = make_reset_updates(b"node1", 0, vec![(vec![1], vec![10])]);
        let u2 = make_delta_updates(b"node1", 0, vec![2], DatabaseUpdate::Set(vec![20]));
        let merged = merge_database_updates(&[u1, u2]);
        let vals = get_reset_values(&merged, b"node1", 0).unwrap();
        assert_eq!(vals.len(), 2);
        assert_eq!(vals.get(&DbSortKey(vec![1])).unwrap(), &vec![10]);
        assert_eq!(vals.get(&DbSortKey(vec![2])).unwrap(), &vec![20]);
    }

    #[test]
    fn test_merge_reset_then_delta_delete() {
        let u1 = make_reset_updates(b"node1", 0, vec![(vec![1], vec![10]), (vec![2], vec![20])]);
        let u2 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Delete);
        let merged = merge_database_updates(&[u1, u2]);
        let vals = get_reset_values(&merged, b"node1", 0).unwrap();
        assert_eq!(vals.len(), 1);
        assert!(vals.get(&DbSortKey(vec![1])).is_none());
        assert_eq!(vals.get(&DbSortKey(vec![2])).unwrap(), &vec![20]);
    }

    #[test]
    fn test_merge_reset_then_reset_replaces() {
        let u1 = make_reset_updates(b"node1", 0, vec![(vec![1], vec![10])]);
        let u2 = make_reset_updates(b"node1", 0, vec![(vec![2], vec![20])]);
        let merged = merge_database_updates(&[u1, u2]);
        let vals = get_reset_values(&merged, b"node1", 0).unwrap();
        assert_eq!(vals.len(), 1);
        assert_eq!(vals.get(&DbSortKey(vec![2])).unwrap(), &vec![20]);
    }

    #[test]
    fn test_merge_multi_cert_ordering() {
        let u1 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![10]));
        let u2 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![20]));
        let u3 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![30]));
        let merged = merge_database_updates(&[u1, u2, u3]);
        assert!(
            matches!(get_delta_value(&merged, b"node1", 0, &[1]), Some(DatabaseUpdate::Set(v)) if v == vec![30])
        );
    }

    #[test]
    fn test_merge_with_empty_is_identity() {
        let u1 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![10]));
        let empty = DatabaseUpdates::default();
        let merged = merge_database_updates(&[u1.clone(), empty]);
        assert!(get_delta_value(&merged, b"node1", 0, &[1]).is_some());
    }

    #[test]
    fn test_merge_different_entities() {
        let u1 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![10]));
        let u2 = make_delta_updates(b"node2", 0, vec![1], DatabaseUpdate::Set(vec![20]));
        let merged = merge_database_updates(&[u1, u2]);
        assert_eq!(merged.node_updates.len(), 2);
        assert!(get_delta_value(&merged, b"node1", 0, &[1]).is_some());
        assert!(get_delta_value(&merged, b"node2", 0, &[1]).is_some());
    }

    #[test]
    fn test_merge_different_partitions_same_entity() {
        let u1 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![10]));
        let u2 = make_delta_updates(b"node1", 1, vec![1], DatabaseUpdate::Set(vec![20]));
        let merged = merge_database_updates(&[u1, u2]);
        assert_eq!(merged.node_updates.len(), 1);
        let nk: Vec<u8> = b"node1".to_vec();
        let node = merged.node_updates.get(&nk).unwrap();
        assert_eq!(node.partition_updates.len(), 2);
    }

    #[test]
    fn test_merge_delta_set_then_delete() {
        let u1 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![10]));
        let u2 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Delete);
        let merged = merge_database_updates(&[u1, u2]);
        assert!(matches!(
            get_delta_value(&merged, b"node1", 0, &[1]),
            Some(DatabaseUpdate::Delete)
        ));
    }

    #[test]
    fn test_merge_empty_list() {
        let merged = merge_database_updates(&[]);
        assert!(merged.node_updates.is_empty());
    }

    #[test]
    fn test_merge_single_element_is_identity() {
        let u1 = make_delta_updates(b"node1", 0, vec![1], DatabaseUpdate::Set(vec![10]));
        let merged = merge_database_updates(std::slice::from_ref(&u1));
        assert!(
            matches!(get_delta_value(&merged, b"node1", 0, &[1]), Some(DatabaseUpdate::Set(v)) if v == vec![10]),
            "single-element merge should be identity"
        );
    }
}
