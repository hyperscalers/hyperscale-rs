//! Shard assignment and write filtering for Radix Engine DatabaseUpdates.
//!
//! Maps Radix Engine's hierarchical object model to the sharding model:
//! - Global entities (accounts, components) are assigned to shards by hash
//! - Internal entities (vaults, KV stores) inherit their parent's shard
//! - System entities (ConsensusManager, TransactionTracker) are filtered out
//!
//! This module consolidates all RE-specific shard/node resolution logic.

use hyperscale_storage::{DatabaseUpdates, DbPartitionKey, DbSortKey, SubstateDatabase};
use hyperscale_types::{NodeId, ShardGroupId};
use std::collections::BTreeSet;

/// System entity type bytes that should be filtered from DatabaseUpdates.
///
/// These are global system components whose state is replicated to all shards
/// and not yet set up for sharded consensus. Writes to these nodes must be
/// excluded from the per-shard state_root computation.
const SYSTEM_ENTITY_TYPES: &[u8] = &[
    0x86, // GlobalConsensusManager
    0x82, // GlobalTransactionTracker
    0x83, // GlobalValidator
];

/// Internal entity type bytes (children of a global entity).
const INTERNAL_ENTITY_TYPES: &[u8] = &[
    0x58, // InternalFungibleVault
    0x98, // InternalNonFungibleVault
    0xb0, // InternalKeyValueStore
    0x80, // InternalGenericComponent
];

/// Filter DatabaseUpdates for a single shard.
///
/// Performs two operations in a single pass:
/// 1. **System filtering**: removes writes to system entities (ConsensusManager,
///    TransactionTracker, Validator) and their internal children (fee vault, etc.)
/// 2. **Shard assignment**: keeps only writes belonging to the local shard.
///    Internal nodes (vaults) are assigned to the shard of their parent global
///    entity, not by hashing their own NodeId.
///
/// The `storage` parameter is used to look up vault → parent ownership via the
/// TypeInfo substate (partition 0, field 0). This is a cheap single-key read.
pub fn filter_updates_for_shard<S: SubstateDatabase>(
    updates: &DatabaseUpdates,
    local_shard: ShardGroupId,
    num_shards: u64,
    storage: &S,
) -> DatabaseUpdates {
    let mut filtered = DatabaseUpdates::default();

    for (db_node_key, node_updates) in &updates.node_updates {
        let Some(node_id) = db_node_key_to_node_id(db_node_key) else {
            continue;
        };

        let entity_type = node_id.0[0];

        // Filter out known system global entities by type byte.
        if SYSTEM_ENTITY_TYPES.contains(&entity_type) {
            continue;
        }

        // Resolve the shard-owning global entity for this node.
        // For global entities: use the node's own ID.
        // For internal entities: look up the parent (outer_object).
        let is_internal = INTERNAL_ENTITY_TYPES.contains(&entity_type);
        let shard_node_id = if is_internal {
            match read_outer_object(storage, db_node_key) {
                Some(parent_id) => {
                    // Filter out internal nodes owned by system entities.
                    if SYSTEM_ENTITY_TYPES.contains(&parent_id.0[0]) {
                        continue;
                    }
                    parent_id
                }
                None => {
                    // Can't determine parent — skip to be safe.
                    // This shouldn't happen for well-formed substates.
                    continue;
                }
            }
        } else {
            node_id
        };

        // Shard assignment based on the resolved global entity.
        let node_shard = hyperscale_types::shard_for_node(&shard_node_id, num_shards);
        if node_shard != local_shard {
            continue;
        }

        filtered
            .node_updates
            .insert(db_node_key.clone(), node_updates.clone());
    }

    filtered
}

/// Extract deduplicated, deterministically-ordered NodeIds from DatabaseUpdates.
///
/// Uses BTreeSet to ensure all validators within a shard produce identical
/// write_nodes vectors (deterministic ordering from identical execution).
pub fn extract_write_nodes(updates: &DatabaseUpdates) -> Vec<NodeId> {
    updates
        .node_updates
        .keys()
        .filter_map(|db_node_key| db_node_key_to_node_id(db_node_key))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Extract the NodeId from a SpreadPrefixKeyMapper db_node_key.
///
/// DbNodeKey format: 20-byte hash prefix + 30-byte NodeId = 50 bytes.
/// Returns None if the key is too short.
pub fn db_node_key_to_node_id(db_node_key: &[u8]) -> Option<NodeId> {
    const HASH_PREFIX_LEN: usize = 20;
    const NODE_ID_LEN: usize = 30;
    if db_node_key.len() < HASH_PREFIX_LEN + NODE_ID_LEN {
        return None;
    }
    let mut id = [0u8; NODE_ID_LEN];
    id.copy_from_slice(&db_node_key[HASH_PREFIX_LEN..HASH_PREFIX_LEN + NODE_ID_LEN]);
    Some(NodeId(id))
}

/// Read the `outer_object` (parent global entity) for an internal node.
///
/// Reads the TypeInfo substate at partition 0, field 0. The TypeInfo contains
/// an `OuterObjectInfo` which, for internal nodes, points to the parent
/// global component (e.g., a vault's owning account).
///
/// Returns `None` if the substate doesn't exist or can't be decoded.
fn read_outer_object<S: SubstateDatabase>(storage: &S, db_node_key: &[u8]) -> Option<NodeId> {
    let partition_key = DbPartitionKey {
        node_key: db_node_key.to_vec(),
        partition_num: 0, // TYPE_INFO_FIELD_PARTITION
    };
    let sort_key = DbSortKey(vec![0]); // TypeInfoField::TypeInfo = 0

    let raw = storage.get_raw_substate_by_db_key(&partition_key, &sort_key)?;
    decode_outer_object_from_type_info(&raw)
}

/// Decode the outer_object NodeId from a raw TypeInfoSubstate.
fn decode_outer_object_from_type_info(raw: &[u8]) -> Option<NodeId> {
    use radix_common::prelude::scrypto_decode;
    use radix_engine::system::type_info::TypeInfoSubstate;

    let type_info: TypeInfoSubstate = scrypto_decode(raw).ok()?;
    let global_addr = type_info.outer_object()?;
    Some(NodeId(global_addr.into_node_id().0))
}

// ============================================================================
// RE key format conversions (moved from storage/writes.rs)
// ============================================================================

/// Compute the SpreadPrefixKeyMapper db_node_key for a NodeId.
///
/// Returns the 50-byte key: 20-byte hash prefix + 30-byte NodeId.
pub fn node_entity_key(node_id: &NodeId) -> Vec<u8> {
    use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};
    let radix_node_id = radix_common::types::NodeId(node_id.0);
    SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id)
}

/// Extract state changes from `DatabaseUpdates` without reading previous values.
///
/// All `Set` operations are classified as `Create` (no previous_value lookup).
/// `Delete` operations use an empty previous_value. This is safe because
/// `state_changes` are NOT part of the consensus receipt hash.
pub fn extract_state_changes(
    db_updates: &hyperscale_storage::DatabaseUpdates,
) -> Vec<hyperscale_types::SubstateChange> {
    use hyperscale_storage::PartitionDatabaseUpdates;
    use hyperscale_types::{PartitionNumber, SubstateChange, SubstateChangeAction, SubstateRef};
    use radix_common::prelude::DatabaseUpdate;

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
/// Inverse of `extract_state_changes`. Used by syncing nodes that receive
/// receipts from peers instead of executing transactions locally.
///
/// The resulting `DatabaseUpdates` contain ALL nodes (not filtered to any shard).
/// Call `filter_updates_for_shard` afterward to restrict to the local shard.
pub fn receipt_to_database_updates(
    receipt: &hyperscale_types::LedgerTransactionReceipt,
) -> hyperscale_storage::DatabaseUpdates {
    use hyperscale_storage::PartitionDatabaseUpdates;
    use hyperscale_types::SubstateChangeAction;
    use radix_common::prelude::DatabaseUpdate;
    use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};
    use radix_substate_store_interface::interface::DbSortKey;

    let mut updates = hyperscale_storage::DatabaseUpdates::default();

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

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{PartitionNumber, SubstateChangeAction};
    use indexmap::indexmap;
    use radix_common::prelude::DatabaseUpdate;
    use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};
    use radix_substate_store_interface::interface::{
        DatabaseUpdates, DbSortKey, NodeDatabaseUpdates, PartitionDatabaseUpdates,
    };

    fn make_db_node_key(node_id: &[u8; 30]) -> Vec<u8> {
        let radix_id = radix_common::types::NodeId(*node_id);
        SpreadPrefixKeyMapper::to_db_node_key(&radix_id)
    }

    // ── extract_state_changes tests ──────────────────────────────────────

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

    fn make_delete_updates(node_id: [u8; 30], partition: u8, sort_key: Vec<u8>) -> DatabaseUpdates {
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

    // ── receipt_to_database_updates tests ────────────────────────────────

    use hyperscale_types::{
        LedgerTransactionOutcome, LedgerTransactionReceipt, SubstateChange, SubstateRef,
    };

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
        assert_eq!(updates.node_updates.len(), 1);
        let node = updates.node_updates.values().next().unwrap();
        assert_eq!(node.partition_updates.len(), 2);
    }
}
