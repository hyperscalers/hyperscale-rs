//! Jellyfish Merkle Tree (JMT) implementation using Blake3.
//!
//! Forked from Radix's JMT (originally from Aptos) and modified to use
//! Blake3 hashing via `hyperscale_types::Hash`.
//!
//! # 3-Tier Architecture
//!
//! The tree is organized in three tiers:
//! - **Entity tier**: Top-level, keyed by entity (node) keys
//! - **Partition tier**: Middle level, keyed by partition numbers within an entity
//! - **Substate tier**: Bottom level, keyed by sort keys within a partition
//!
//! Each tier uses a separate JMT instance with version-tracked payloads.

pub mod entity_tier;
pub mod jellyfish;
pub mod partition_tier;
pub mod substate_tier;
pub mod tier_framework;
pub mod tree_store;
pub mod types;

mod conversions;

#[cfg(test)]
mod tests;

use entity_tier::EntityTier;
use hyperscale_types::Hash;
use tree_store::*;
use types::*;

/// Inserts a new set of nodes at version `current_state_version` + 1 into the "3-Tier JMT"
/// persisted within the given `TreeStore`.
///
/// Returns the hash of the newly-created root (i.e. representing state at version
/// `current_state_version` + 1).
///
/// # Panics
/// Panics if a root node for `current_state_version` does not exist. The caller should use `None`
/// to denote an empty, initial state of the tree (i.e. inserting at version 1).
pub fn put_at_next_version<S: TreeStore>(
    tree_store: &S,
    current_state_version: Option<Version>,
    database_updates: &radix_substate_store_interface::interface::DatabaseUpdates,
) -> Hash {
    EntityTier::new(tree_store, current_state_version)
        .put_next_version_entity_updates(database_updates)
        .unwrap_or(Hash::ZERO)
}
