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
use hyperscale_dispatch::Dispatch;
use hyperscale_types::Hash;
use tier_framework::TierCollectedWrites;
use tree_store::*;
use types::*;

/// Computes new JMT nodes for the given database updates, returning the
/// new root hash and all collected writes (nodes, stale parts, associations).
///
/// The store only needs `ReadableTreeStore + Sync` — no writes are performed.
/// The caller is responsible for applying the returned `TierCollectedWrites`.
///
/// `parent_version` is the version of the existing root to read from
/// (None for initial state). `new_version` is the version to write new
/// nodes at (typically block height).
pub fn put_at_version<S: ReadableTreeStore + Sync, D: Dispatch>(
    tree_store: &S,
    parent_version: Option<Version>,
    new_version: Version,
    database_updates: &radix_substate_store_interface::interface::DatabaseUpdates,
    dispatch: &D,
) -> (Hash, TierCollectedWrites) {
    assert!(
        parent_version.is_none_or(|pv| new_version > pv),
        "put_at_version: new_version ({new_version}) must be greater than parent_version ({parent_version:?})"
    );
    let (root, collected) = EntityTier::new(tree_store, parent_version).put_entity_updates(
        new_version,
        database_updates,
        dispatch,
    );
    (root.unwrap_or(Hash::ZERO), collected)
}

/// Compute and immediately apply JMT updates. Convenience for callers
/// that own both read and write access to the same store (tests, direct commits).
pub fn put_at_version_and_apply<S: ReadableTreeStore + WriteableTreeStore + Sync, D: Dispatch>(
    tree_store: &S,
    parent_version: Option<Version>,
    new_version: Version,
    database_updates: &radix_substate_store_interface::interface::DatabaseUpdates,
    dispatch: &D,
) -> Hash {
    let (root, collected) = put_at_version(
        tree_store,
        parent_version,
        new_version,
        database_updates,
        dispatch,
    );
    // Associations are for substate-tier leaf→value correlation used by inclusion
    // proofs. This convenience path (tests, direct commits) doesn't need them;
    // production callers use the two-phase put_at_version + collected.apply_to().
    let _associations = collected.apply_to(tree_store);
    root
}
