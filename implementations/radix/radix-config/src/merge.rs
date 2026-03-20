//! Utilities for merging `DatabaseUpdates`.
//!
//! These operate on Radix's `DatabaseUpdates` type and are used by storage
//! backends that need to merge per-certificate writes into a single update.

use radix_common::prelude::DatabaseUpdate;
use radix_substate_store_interface::interface::{
    DatabaseUpdates, NodeDatabaseUpdates, PartitionDatabaseUpdates,
};

/// Merge a slice of `DatabaseUpdates` into a single combined update.
///
/// Later entries take precedence for conflicting keys (last writer wins).
/// This is deterministic: updates are processed left-to-right.
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

/// Merge `source` into `target` in place (last writer wins).
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
        // Delta + Reset or Reset + Reset: source replaces target entirely.
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
