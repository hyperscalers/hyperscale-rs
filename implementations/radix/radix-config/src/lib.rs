//! Concrete `TypeConfig` binding for the Radix implementation.
//!
//! Maps the framework's generic associated types to Radix-specific types:
//! - `Transaction` → `RoutableTransaction`
//! - `ExecutionReceipt` → `LedgerTransactionReceipt`
//! - `StateUpdate` → `DatabaseUpdates`

pub mod merge;

use std::sync::Arc;

use hyperscale_radix_types::RoutableTransaction;
use hyperscale_types::{
    LedgerTransactionReceipt, NodeId, PartitionNumber, ShardGroupId, SubstateChange,
    SubstateChangeAction, SubstateRef, TypeConfig,
};
use radix_substate_store_interface::interface::DatabaseUpdates;

/// Length of the hash prefix in spread-prefix-mapped db node keys.
const HASH_PREFIX_LEN: usize = 20;
/// Length of the raw NodeId bytes after the hash prefix.
const NODE_ID_LEN: usize = 30;

/// Extract a `NodeId` from a spread-prefix-mapped db node key.
///
/// Returns `None` if the key is too short (e.g., metadata keys).
fn node_id_from_db_key(db_node_key: &[u8]) -> Option<NodeId> {
    if db_node_key.len() >= HASH_PREFIX_LEN + NODE_ID_LEN {
        let mut bytes = [0u8; NODE_ID_LEN];
        bytes.copy_from_slice(&db_node_key[HASH_PREFIX_LEN..HASH_PREFIX_LEN + NODE_ID_LEN]);
        Some(NodeId(bytes))
    } else {
        None
    }
}

/// Radix-specific `TypeConfig` implementation.
///
/// This is the reference (and currently only) implementation. It binds the
/// framework's generic types to the concrete Radix ledger types.
///
/// Transaction and receipt operations are provided by the [`ConsensusTransaction`]
/// and [`ConsensusExecutionReceipt`] trait impls on the concrete types themselves.
#[derive(Debug, Clone)]
pub struct RadixConfig;

impl TypeConfig for RadixConfig {
    type Transaction = RoutableTransaction;
    type ExecutionReceipt = LedgerTransactionReceipt;
    type StateUpdate = DatabaseUpdates;

    fn merge_state_updates(updates: &[DatabaseUpdates]) -> DatabaseUpdates {
        merge::merge_database_updates(updates)
    }

    fn merge_state_updates_from_arcs(updates: &[Arc<DatabaseUpdates>]) -> DatabaseUpdates {
        let dereffed: Vec<DatabaseUpdates> = updates.iter().map(|a| (**a).clone()).collect();
        Self::merge_state_updates(&dereffed)
    }

    fn filter_state_update_to_shard(
        update: &DatabaseUpdates,
        local_shard: ShardGroupId,
        num_shards: u64,
    ) -> DatabaseUpdates {
        if num_shards <= 1 {
            return update.clone();
        }
        let mut filtered = DatabaseUpdates::default();
        for (db_node_key, node_updates) in &update.node_updates {
            let dominated_by_local = node_id_from_db_key(db_node_key)
                .map(|id| hyperscale_types::shard_for_node(&id, num_shards) == local_shard)
                .unwrap_or(true); // keep metadata keys
            if dominated_by_local {
                filtered
                    .node_updates
                    .insert(db_node_key.clone(), node_updates.clone());
            }
        }
        filtered
    }

    fn filter_state_update_to_writes(
        update: &DatabaseUpdates,
        declared_writes: &[NodeId],
    ) -> DatabaseUpdates {
        if declared_writes.is_empty() {
            // No declared writes = no filtering (pass everything through).
            return update.clone();
        }
        let allowed: std::collections::HashSet<NodeId> = declared_writes.iter().copied().collect();
        let mut filtered = DatabaseUpdates::default();
        for (db_node_key, node_updates) in &update.node_updates {
            let passes = node_id_from_db_key(db_node_key)
                .map(|id| allowed.contains(&id))
                .unwrap_or(true); // keep metadata keys
            if passes {
                filtered
                    .node_updates
                    .insert(db_node_key.clone(), node_updates.clone());
            }
        }
        filtered
    }

    fn extract_write_nodes(update: &DatabaseUpdates) -> Vec<NodeId> {
        update
            .node_updates
            .keys()
            .filter_map(|db_node_key| node_id_from_db_key(db_node_key))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn receipt_to_state_update(receipt: &LedgerTransactionReceipt) -> DatabaseUpdates {
        use hyperscale_types::SubstateChangeAction;
        use radix_common::prelude::DatabaseUpdate;
        use radix_substate_store_interface::db_key_mapper::{
            DatabaseKeyMapper, SpreadPrefixKeyMapper,
        };
        use radix_substate_store_interface::interface::{DbSortKey, PartitionDatabaseUpdates};

        let mut updates = DatabaseUpdates::default();
        for change in &receipt.state_changes {
            let radix_node_id = radix_common::types::NodeId(change.substate_ref.node_id.0);
            let db_node_key = SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id);
            let radix_partition =
                radix_common::types::PartitionNumber(change.substate_ref.partition.0);
            let db_partition_num = SpreadPrefixKeyMapper::to_db_partition_num(radix_partition);
            let db_sort_key = DbSortKey(change.substate_ref.sort_key.clone());

            let db_update = match &change.action {
                SubstateChangeAction::Create { new_value } => {
                    DatabaseUpdate::Set(new_value.clone())
                }
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
                    substate_updates: radix_common::prelude::IndexMap::new(),
                });

            if let PartitionDatabaseUpdates::Delta { substate_updates } = partition_updates {
                substate_updates.insert(db_sort_key, db_update);
            }
        }
        updates
    }

    fn enrich_receipt_for_storage(
        receipt: &LedgerTransactionReceipt,
        state_update: &DatabaseUpdates,
    ) -> LedgerTransactionReceipt {
        use radix_common::prelude::DatabaseUpdate;
        use radix_substate_store_interface::interface::PartitionDatabaseUpdates;

        let mut changes = Vec::new();
        for (db_node_key, node_updates) in &state_update.node_updates {
            let node_id = match node_id_from_db_key(db_node_key) {
                Some(id) => id,
                None => continue,
            };
            for (partition_num, partition_updates) in &node_updates.partition_updates {
                let partition = PartitionNumber(*partition_num);
                match partition_updates {
                    PartitionDatabaseUpdates::Delta { substate_updates } => {
                        for (db_sort_key, update) in substate_updates {
                            let action = match update {
                                DatabaseUpdate::Set(new_value) => SubstateChangeAction::Create {
                                    new_value: new_value.clone(),
                                },
                                DatabaseUpdate::Delete => SubstateChangeAction::Delete {
                                    previous_value: vec![],
                                },
                            };
                            changes.push(SubstateChange {
                                substate_ref: SubstateRef {
                                    node_id,
                                    partition,
                                    sort_key: db_sort_key.0.clone(),
                                },
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

        let mut enriched = receipt.clone();
        enriched.state_changes = changes;
        enriched
    }
}
