//! Utilities for merging, filtering, and reconstructing `DatabaseUpdates`.

use hyperscale_types::{
    LedgerTransactionReceipt, PartitionNumber, ShardGroupId, SubstateChange, SubstateChangeAction,
    SubstateRef,
};
use radix_common::prelude::DatabaseUpdate;
use radix_substate_store_interface::interface::{
    DatabaseUpdates, DbSortKey, NodeDatabaseUpdates, PartitionDatabaseUpdates,
};
use std::sync::Arc;

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

/// Extract state changes from `DatabaseUpdates` without reading previous values.
///
/// Inverse of [`receipt_to_database_updates`]. All `Set` operations are
/// classified as `Create` (no previous_value lookup). `Delete` operations use
/// an empty previous_value. This is safe because `state_changes` are NOT part
/// of the consensus receipt hash — the distinction between Create/Update is
/// purely informational for clients/indexers.
///
/// The round-trip through `receipt_to_database_updates` is unaffected: both
/// Create and Update map to `DatabaseUpdate::Set(new_value)`.
pub fn extract_state_changes(db_updates: &DatabaseUpdates) -> Vec<SubstateChange> {
    use crate::keys::db_node_key_to_node_id;

    let mut changes = Vec::new();

    for (db_node_key, node_updates) in &db_updates.node_updates {
        let Some(node_id) = db_node_key_to_node_id(db_node_key) else {
            continue;
        };

        for (partition_num, partition_updates) in &node_updates.partition_updates {
            let partition = PartitionNumber(*partition_num);

            match partition_updates {
                PartitionDatabaseUpdates::Delta { substate_updates } => {
                    for (db_sort_key, update) in substate_updates {
                        let substate_ref = SubstateRef {
                            node_id,
                            partition,
                            sort_key: db_sort_key.0.clone(),
                        };

                        let action = match update {
                            DatabaseUpdate::Set(new_value) => SubstateChangeAction::Create {
                                new_value: new_value.clone(),
                            },
                            DatabaseUpdate::Delete => SubstateChangeAction::Delete {
                                previous_value: vec![],
                            },
                        };

                        changes.push(SubstateChange {
                            substate_ref,
                            action,
                        });
                    }
                }
                PartitionDatabaseUpdates::Reset {
                    new_substate_values,
                } => {
                    for (sort_key, new_value) in new_substate_values {
                        changes.push(SubstateChange {
                            substate_ref: SubstateRef {
                                node_id,
                                partition,
                                sort_key: sort_key.0.clone(),
                            },
                            action: SubstateChangeAction::Create {
                                new_value: new_value.clone(),
                            },
                        });
                    }
                }
            }
        }
    }

    changes
}

/// Reconstruct `DatabaseUpdates` from a ledger receipt's state changes.
///
/// This converts the receipt's `SubstateChange` entries into the `DatabaseUpdates`
/// format used by the JVT commit path. Used by syncing nodes that receive receipts
/// from peers instead of executing transactions locally.
///
/// The resulting `DatabaseUpdates` contain ALL nodes (not filtered to any shard).
/// Call `filter_updates_to_shard` afterward to restrict to the local shard.
pub fn receipt_to_database_updates(receipt: &LedgerTransactionReceipt) -> DatabaseUpdates {
    use crate::keys::node_entity_key;
    use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};

    let mut updates = DatabaseUpdates::default();

    for change in &receipt.state_changes {
        let db_node_key = node_entity_key(&change.substate_ref.node_id);
        let radix_partition = radix_common::types::PartitionNumber(change.substate_ref.partition.0);
        let db_partition_num = SpreadPrefixKeyMapper::to_db_partition_num(radix_partition);
        let db_sort_key = DbSortKey(change.substate_ref.sort_key.clone());

        let db_update = match &change.action {
            SubstateChangeAction::Create { new_value } => DatabaseUpdate::Set(new_value.clone()),
            SubstateChangeAction::Update { new_value, .. } => {
                DatabaseUpdate::Set(new_value.clone())
            }
            SubstateChangeAction::Delete { .. } => DatabaseUpdate::Delete,
        };

        let node_updates = updates.node_updates.entry(db_node_key).or_default();
        let partition_updates = node_updates
            .partition_updates
            .entry(db_partition_num)
            .or_insert_with(|| PartitionDatabaseUpdates::Delta {
                substate_updates: indexmap::IndexMap::new(),
            });

        if let PartitionDatabaseUpdates::Delta { substate_updates } = partition_updates {
            substate_updates.insert(db_sort_key, db_update);
        }
    }

    updates
}

/// Filter DatabaseUpdates to only include writes for the local shard.
///
/// Uses `db_node_key_to_node_id` to extract the NodeId from each db_node_key,
/// then `shard_for_node` to determine ownership. Only updates for nodes
/// owned by `local_shard` are included in the output.
pub fn filter_updates_to_shard(
    updates: &DatabaseUpdates,
    local_shard: ShardGroupId,
    num_shards: u64,
) -> DatabaseUpdates {
    use crate::keys::db_node_key_to_node_id;
    use hyperscale_types::shard_for_node;

    let mut filtered = DatabaseUpdates::default();
    for (db_node_key, node_updates) in &updates.node_updates {
        let Some(node_id) = db_node_key_to_node_id(db_node_key) else {
            continue;
        };
        if shard_for_node(&node_id, num_shards) != local_shard {
            continue;
        }
        filtered
            .node_updates
            .insert(db_node_key.clone(), node_updates.clone());
    }
    filtered
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
        let merged = merge_database_updates(&[u1.clone()]);
        assert!(
            matches!(get_delta_value(&merged, b"node1", 0, &[1]), Some(DatabaseUpdate::Set(v)) if v == vec![10]),
            "single-element merge should be identity"
        );
    }

    // ── extract_state_changes tests ──────────────────────────────────────

    mod extract_state_changes_tests {
        use super::super::extract_state_changes;
        use hyperscale_types::{NodeId, PartitionNumber, SubstateChangeAction};
        use indexmap::indexmap;
        use radix_common::prelude::DatabaseUpdate;
        use radix_substate_store_interface::db_key_mapper::{
            DatabaseKeyMapper, SpreadPrefixKeyMapper,
        };
        use radix_substate_store_interface::interface::{
            DatabaseUpdates, DbSortKey, NodeDatabaseUpdates, PartitionDatabaseUpdates,
        };

        fn make_db_node_key(node_id: &[u8; 30]) -> Vec<u8> {
            let radix_id = radix_common::types::NodeId(*node_id);
            SpreadPrefixKeyMapper::to_db_node_key(&radix_id)
        }

        fn make_set_updates(
            node_id: [u8; 30],
            partition: u8,
            sort_key: Vec<u8>,
            value: Vec<u8>,
        ) -> DatabaseUpdates {
            let db_node_key = make_db_node_key(&node_id);
            DatabaseUpdates {
                node_updates: indexmap! {
                    db_node_key => NodeDatabaseUpdates {
                        partition_updates: indexmap! {
                            partition => PartitionDatabaseUpdates::Delta {
                                substate_updates: indexmap! {
                                    DbSortKey(sort_key) => DatabaseUpdate::Set(value),
                                }
                            }
                        }
                    }
                },
            }
        }

        fn make_delete_updates(
            node_id: [u8; 30],
            partition: u8,
            sort_key: Vec<u8>,
        ) -> DatabaseUpdates {
            let db_node_key = make_db_node_key(&node_id);
            DatabaseUpdates {
                node_updates: indexmap! {
                    db_node_key => NodeDatabaseUpdates {
                        partition_updates: indexmap! {
                            partition => PartitionDatabaseUpdates::Delta {
                                substate_updates: indexmap! {
                                    DbSortKey(sort_key) => DatabaseUpdate::Delete,
                                }
                            }
                        }
                    }
                },
            }
        }

        fn make_reset_updates(
            node_id: [u8; 30],
            partition: u8,
            new_values: Vec<(Vec<u8>, Vec<u8>)>,
        ) -> DatabaseUpdates {
            let db_node_key = make_db_node_key(&node_id);
            let new_substate_values = new_values
                .into_iter()
                .map(|(k, v)| (DbSortKey(k), v))
                .collect();
            DatabaseUpdates {
                node_updates: indexmap! {
                    db_node_key => NodeDatabaseUpdates {
                        partition_updates: indexmap! {
                            partition => PartitionDatabaseUpdates::Reset {
                                new_substate_values,
                            }
                        }
                    }
                },
            }
        }

        #[test]
        fn test_set_classifies_as_create() {
            let node_id = [1u8; 30];
            let db_updates = make_set_updates(node_id, 0, vec![42], b"new_value".to_vec());

            let changes = extract_state_changes(&db_updates);

            assert_eq!(changes.len(), 1);
            assert_eq!(changes[0].substate_ref.node_id, NodeId(node_id));
            assert_eq!(changes[0].substate_ref.partition, PartitionNumber(0));
            assert_eq!(changes[0].substate_ref.sort_key, vec![42]);
            match &changes[0].action {
                SubstateChangeAction::Create { new_value } => {
                    assert_eq!(new_value, b"new_value");
                }
                other => panic!("Expected Create, got {other:?}"),
            }
        }

        #[test]
        fn test_delete() {
            let node_id = [3u8; 30];
            let db_updates = make_delete_updates(node_id, 1, vec![5]);

            let changes = extract_state_changes(&db_updates);

            assert_eq!(changes.len(), 1);
            match &changes[0].action {
                SubstateChangeAction::Delete { previous_value } => {
                    assert!(previous_value.is_empty());
                }
                other => panic!("Expected Delete, got {other:?}"),
            }
        }

        #[test]
        fn test_multiple_nodes_and_partitions() {
            let node_a = [10u8; 30];
            let node_b = [20u8; 30];
            let db_node_key_a = make_db_node_key(&node_a);
            let db_node_key_b = make_db_node_key(&node_b);

            let db_updates = DatabaseUpdates {
                node_updates: indexmap! {
                    db_node_key_a => NodeDatabaseUpdates {
                        partition_updates: indexmap! {
                            0 => PartitionDatabaseUpdates::Delta {
                                substate_updates: indexmap! {
                                    DbSortKey(vec![1]) => DatabaseUpdate::Set(b"a1".to_vec()),
                                }
                            },
                            5 => PartitionDatabaseUpdates::Delta {
                                substate_updates: indexmap! {
                                    DbSortKey(vec![2]) => DatabaseUpdate::Set(b"a2".to_vec()),
                                }
                            }
                        }
                    },
                    db_node_key_b => NodeDatabaseUpdates {
                        partition_updates: indexmap! {
                            0 => PartitionDatabaseUpdates::Delta {
                                substate_updates: indexmap! {
                                    DbSortKey(vec![3]) => DatabaseUpdate::Delete,
                                }
                            }
                        }
                    }
                },
            };

            let changes = extract_state_changes(&db_updates);

            assert_eq!(changes.len(), 3);
            let node_ids: Vec<_> = changes.iter().map(|c| c.substate_ref.node_id).collect();
            assert!(node_ids.contains(&NodeId(node_a)));
            assert!(node_ids.contains(&NodeId(node_b)));
        }

        #[test]
        fn test_reset_partition() {
            let node_id = [5u8; 30];
            let db_updates = make_reset_updates(node_id, 2, vec![(vec![1], b"reset_val".to_vec())]);

            let changes = extract_state_changes(&db_updates);

            assert_eq!(changes.len(), 1);
            match &changes[0].action {
                SubstateChangeAction::Create { new_value } => {
                    assert_eq!(new_value, b"reset_val");
                }
                other => panic!("Expected Create for Reset partition, got {other:?}"),
            }
        }

        #[test]
        fn test_empty_updates() {
            let db_updates = DatabaseUpdates::default();
            let changes = extract_state_changes(&db_updates);
            assert!(changes.is_empty());
        }

        #[test]
        fn test_invalid_node_key_skipped() {
            let db_updates = DatabaseUpdates {
                node_updates: indexmap! {
                    vec![0u8; 10] => NodeDatabaseUpdates {
                        partition_updates: indexmap! {
                            0 => PartitionDatabaseUpdates::Delta {
                                substate_updates: indexmap! {
                                    DbSortKey(vec![1]) => DatabaseUpdate::Set(b"val".to_vec()),
                                }
                            }
                        }
                    }
                },
            };
            let changes = extract_state_changes(&db_updates);
            assert!(changes.is_empty(), "Malformed node key should be skipped");
        }
    }

    // ── receipt_to_database_updates tests ────────────────────────────────

    mod receipt_conversion {
        use super::super::receipt_to_database_updates;
        use hyperscale_types::{
            LedgerTransactionOutcome, LedgerTransactionReceipt, NodeId, PartitionNumber,
            SubstateChange, SubstateChangeAction, SubstateRef,
        };
        use radix_common::prelude::DatabaseUpdate;
        use radix_substate_store_interface::interface::PartitionDatabaseUpdates;

        #[test]
        fn test_empty_receipt_produces_empty_updates() {
            let receipt = LedgerTransactionReceipt {
                outcome: LedgerTransactionOutcome::Success,
                state_changes: vec![],
                application_events: vec![],
            };
            let updates = receipt_to_database_updates(&receipt);
            assert!(updates.node_updates.is_empty());
        }

        #[test]
        fn test_create_produces_set() {
            let receipt = LedgerTransactionReceipt {
                outcome: LedgerTransactionOutcome::Success,
                state_changes: vec![SubstateChange {
                    substate_ref: SubstateRef {
                        node_id: NodeId([1; 30]),
                        partition: PartitionNumber(0),
                        sort_key: vec![10],
                    },
                    action: SubstateChangeAction::Create {
                        new_value: vec![42],
                    },
                }],
                application_events: vec![],
            };
            let updates = receipt_to_database_updates(&receipt);
            assert_eq!(updates.node_updates.len(), 1);

            let node = updates.node_updates.values().next().unwrap();
            let part = node.partition_updates.values().next().unwrap();
            match part {
                PartitionDatabaseUpdates::Delta { substate_updates } => {
                    assert_eq!(substate_updates.len(), 1);
                    let val = substate_updates.values().next().unwrap();
                    assert!(matches!(val, DatabaseUpdate::Set(v) if v == &vec![42]));
                }
                _ => panic!("expected Delta"),
            }
        }

        #[test]
        fn test_delete_produces_delete() {
            let receipt = LedgerTransactionReceipt {
                outcome: LedgerTransactionOutcome::Failure,
                state_changes: vec![SubstateChange {
                    substate_ref: SubstateRef {
                        node_id: NodeId([2; 30]),
                        partition: PartitionNumber(1),
                        sort_key: vec![20],
                    },
                    action: SubstateChangeAction::Delete {
                        previous_value: vec![99],
                    },
                }],
                application_events: vec![],
            };
            let updates = receipt_to_database_updates(&receipt);
            assert_eq!(updates.node_updates.len(), 1);

            let node = updates.node_updates.values().next().unwrap();
            let part = node.partition_updates.values().next().unwrap();
            match part {
                PartitionDatabaseUpdates::Delta { substate_updates } => {
                    assert_eq!(substate_updates.len(), 1);
                    let val = substate_updates.values().next().unwrap();
                    assert!(matches!(val, DatabaseUpdate::Delete));
                }
                _ => panic!("expected Delta"),
            }
        }

        #[test]
        fn test_update_uses_new_value() {
            let receipt = LedgerTransactionReceipt {
                outcome: LedgerTransactionOutcome::Success,
                state_changes: vec![SubstateChange {
                    substate_ref: SubstateRef {
                        node_id: NodeId([3; 30]),
                        partition: PartitionNumber(2),
                        sort_key: vec![30],
                    },
                    action: SubstateChangeAction::Update {
                        previous_value: vec![10],
                        new_value: vec![20],
                    },
                }],
                application_events: vec![],
            };
            let updates = receipt_to_database_updates(&receipt);

            let node = updates.node_updates.values().next().unwrap();
            let part = node.partition_updates.values().next().unwrap();
            match part {
                PartitionDatabaseUpdates::Delta { substate_updates } => {
                    let val = substate_updates.values().next().unwrap();
                    assert!(
                        matches!(val, DatabaseUpdate::Set(v) if v == &vec![20]),
                        "should use new_value, not previous_value"
                    );
                }
                _ => panic!("expected Delta"),
            }
        }

        #[test]
        fn test_multiple_changes_same_node_different_partitions() {
            let receipt = LedgerTransactionReceipt {
                outcome: LedgerTransactionOutcome::Success,
                state_changes: vec![
                    SubstateChange {
                        substate_ref: SubstateRef {
                            node_id: NodeId([4; 30]),
                            partition: PartitionNumber(0),
                            sort_key: vec![1],
                        },
                        action: SubstateChangeAction::Create {
                            new_value: vec![10],
                        },
                    },
                    SubstateChange {
                        substate_ref: SubstateRef {
                            node_id: NodeId([4; 30]),
                            partition: PartitionNumber(5),
                            sort_key: vec![2],
                        },
                        action: SubstateChangeAction::Create {
                            new_value: vec![20],
                        },
                    },
                ],
                application_events: vec![],
            };
            let updates = receipt_to_database_updates(&receipt);
            // Same node_id → same db_node_key → one entry
            assert_eq!(updates.node_updates.len(), 1);
            let node = updates.node_updates.values().next().unwrap();
            assert_eq!(node.partition_updates.len(), 2);
        }
    }
}
