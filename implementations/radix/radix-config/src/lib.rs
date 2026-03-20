//! Concrete `TypeConfig` binding for the Radix implementation.
//!
//! Maps the framework's generic associated types to Radix-specific types:
//! - `Transaction` → `RoutableTransaction`
//! - `ExecutionReceipt` → `LedgerTransactionReceipt`
//! - `StateUpdate` → `DatabaseUpdates`

use std::sync::Arc;

use hyperscale_radix_types::RoutableTransaction;
use hyperscale_types::{
    LedgerTransactionReceipt, NodeId, PartitionNumber, ShardGroupId, SubstateChange,
    SubstateChangeAction, SubstateRef, TypeConfig,
};
use radix_substate_store_interface::interface::DatabaseUpdates;

/// Radix-specific `TypeConfig` implementation.
///
/// This is the reference (and currently only) implementation. It binds the
/// framework's generic types to the concrete Radix ledger types.
///
/// Transaction and receipt operations are provided by the [`ConsensusTransaction`]
/// and [`ConsensusExecutionReceipt`] trait impls on the concrete types themselves.
/// Only state update operations remain here.
#[derive(Debug, Clone)]
pub struct RadixConfig;

impl TypeConfig for RadixConfig {
    type Transaction = RoutableTransaction;
    type ExecutionReceipt = LedgerTransactionReceipt;
    type StateUpdate = DatabaseUpdates;

    fn merge_state_updates(updates: &[DatabaseUpdates]) -> DatabaseUpdates {
        use radix_substate_store_interface::interface::NodeDatabaseUpdates;
        if updates.is_empty() {
            return DatabaseUpdates::default();
        }
        if updates.len() == 1 {
            return updates[0].clone();
        }
        let mut merged = DatabaseUpdates::default();
        for update in updates {
            for (entity_key, node_updates) in &update.node_updates {
                let target = merged
                    .node_updates
                    .entry(entity_key.clone())
                    .or_insert_with(NodeDatabaseUpdates::default);
                for (partition, part_updates) in &node_updates.partition_updates {
                    target
                        .partition_updates
                        .entry(*partition)
                        .and_modify(|existing| {
                            match (existing, part_updates) {
                                (
                                    radix_substate_store_interface::interface::PartitionDatabaseUpdates::Delta { substate_updates: target_updates },
                                    radix_substate_store_interface::interface::PartitionDatabaseUpdates::Delta { substate_updates: source_updates },
                                ) => {
                                    for (k, v) in source_updates {
                                        target_updates.insert(k.clone(), v.clone());
                                    }
                                }
                                (existing, source) => {
                                    *existing = source.clone();
                                }
                            }
                        })
                        .or_insert_with(|| part_updates.clone());
                }
            }
        }
        merged
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
        const HASH_PREFIX_LEN: usize = 20;
        const NODE_ID_LEN: usize = 30;
        let mut filtered = DatabaseUpdates::default();
        for (db_node_key, node_updates) in &update.node_updates {
            if db_node_key.len() >= HASH_PREFIX_LEN + NODE_ID_LEN {
                let mut bytes = [0u8; NODE_ID_LEN];
                bytes.copy_from_slice(&db_node_key[HASH_PREFIX_LEN..HASH_PREFIX_LEN + NODE_ID_LEN]);
                let node_id = NodeId(bytes);
                if hyperscale_types::shard_for_node(&node_id, num_shards) == local_shard {
                    filtered
                        .node_updates
                        .insert(db_node_key.clone(), node_updates.clone());
                }
            } else {
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
            return update.clone();
        }
        const HASH_PREFIX_LEN: usize = 20;
        const NODE_ID_LEN: usize = 30;
        let allowed: std::collections::HashSet<NodeId> = declared_writes.iter().copied().collect();
        let mut filtered = DatabaseUpdates::default();
        for (db_node_key, node_updates) in &update.node_updates {
            if db_node_key.len() >= HASH_PREFIX_LEN + NODE_ID_LEN {
                let mut bytes = [0u8; NODE_ID_LEN];
                bytes.copy_from_slice(&db_node_key[HASH_PREFIX_LEN..HASH_PREFIX_LEN + NODE_ID_LEN]);
                let node_id = NodeId(bytes);
                if allowed.contains(&node_id) {
                    filtered
                        .node_updates
                        .insert(db_node_key.clone(), node_updates.clone());
                }
            } else {
                filtered
                    .node_updates
                    .insert(db_node_key.clone(), node_updates.clone());
            }
        }
        filtered
    }

    fn extract_write_nodes(update: &DatabaseUpdates) -> Vec<NodeId> {
        const HASH_PREFIX_LEN: usize = 20;
        const NODE_ID_LEN: usize = 30;
        update
            .node_updates
            .keys()
            .filter_map(|db_node_key| {
                if db_node_key.len() >= HASH_PREFIX_LEN + NODE_ID_LEN {
                    let mut bytes = [0u8; NODE_ID_LEN];
                    bytes.copy_from_slice(
                        &db_node_key[HASH_PREFIX_LEN..HASH_PREFIX_LEN + NODE_ID_LEN],
                    );
                    Some(NodeId(bytes))
                } else {
                    None
                }
            })
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

        const HASH_PREFIX_LEN: usize = 20;
        const NODE_ID_LEN: usize = 30;

        let mut changes = Vec::new();
        for (db_node_key, node_updates) in &state_update.node_updates {
            let node_id = if db_node_key.len() >= HASH_PREFIX_LEN + NODE_ID_LEN {
                let mut id = [0u8; NODE_ID_LEN];
                id.copy_from_slice(&db_node_key[HASH_PREFIX_LEN..HASH_PREFIX_LEN + NODE_ID_LEN]);
                NodeId(id)
            } else {
                continue;
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
