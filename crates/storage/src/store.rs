//! Storage traits for Radix Engine execution.
//!
//! This module defines the storage abstraction used by runners to persist Radix state.

use hyperscale_types::{Hash, MerkleInclusionProof, NodeId};
use radix_substate_store_interface::interface::{DbSortKey, SubstateDatabase};

/// Extension trait for substate storage with snapshots, node listing, and JMT state roots.
///
/// This trait extends Radix's `SubstateDatabase` with additional methods needed
/// for deterministic simulation and state commitment:
/// - `snapshot()` - Create isolated views for parallel execution
/// - `jmt_version()` / `state_root_hash()` - JMT state commitment
///
/// All implementations use a binary Blake3 Jellyfish Merkle Tree (JMT)
/// internally to maintain cryptographic state roots, updated on each
/// `commit_block()`.
///
/// Runner storage types (`SimStorage`, `RocksDbStorage`) implement this trait
/// along with `SubstateDatabase`. They additionally implement [`VersionedStore`]
/// for explicit MVCC-version reads; views do not, since a view carries a
/// bound anchor and has no meaningful answer for an arbitrary version.
pub trait SubstateStore: SubstateDatabase + Send + Sync + 'static {
    /// The snapshot type returned by this storage.
    ///
    /// All snapshots are MVCC-aware — reads return the value as of some
    /// specific version. For base storage types, that version is chosen
    /// by the impl's [`Self::snapshot`] default (typically the current
    /// committed tip). For views, it is the view's bound anchor height.
    type Snapshot<'a>: SubstateDatabase + Send + Sync
    where
        Self: 'a;

    /// Create a snapshot at the impl-defined default version.
    ///
    /// - Base storage (`RocksDbStorage`, `SimStorage`): snapshots at the
    ///   current `jmt_version()`, i.e. the latest committed state.
    /// - [`crate::pending_chain::SubstateView`]: snapshots at the view's
    ///   bound anchor height, combining the overlay with a version-anchored
    ///   base read — deterministic across validators regardless of each
    ///   validator's persistence lag.
    ///
    /// Snapshots provide a consistent point-in-time view of the database,
    /// essential for parallel transaction execution where each transaction
    /// needs an isolated view.
    fn snapshot(&self) -> Self::Snapshot<'_>;

    /// Returns the block height of the last committed JMT state.
    ///
    /// This equals the block height because JMT version = block height.
    /// Returns 0 for fresh/genesis state.
    fn jmt_version(&self) -> u64;

    /// Current JMT state root hash.
    ///
    /// Returns the Blake3 root of all substates at the current version.
    /// This hash cryptographically commits to the entire state and can be used
    /// for state sync, light client proofs, and cross-validator consistency checks.
    ///
    /// Returns a zero hash if no commits have occurred.
    fn state_root_hash(&self) -> Hash;

    /// List all substates for a node at a specific historical block height (= JMT version).
    ///
    /// Traverses the JMT at the given height and looks up raw substate
    /// values from the leaf association table.
    ///
    /// Returns `Some(entries)` on success (may be empty if the node has no
    /// substates at that height), or `None` if the height is unavailable
    /// (e.g. garbage-collected or not yet committed).
    ///
    /// Used by cross-shard provision paths to serve historical state that
    /// can be verified against the original block's `state_root`.
    fn list_substates_for_node_at_height(
        &self,
        node_id: &NodeId,
        block_height: u64,
    ) -> Option<Vec<(u8, DbSortKey, Vec<u8>)>>;

    /// Generate a batched merkle multiproof for the given storage keys.
    /// Returns `None` if the requested version is unavailable (GC'd or not committed).
    fn generate_merkle_proofs(
        &self,
        storage_keys: &[Vec<u8>],
        block_height: u64,
    ) -> Option<MerkleInclusionProof>;
}

/// Storage that supports reads at an explicit MVCC version.
///
/// Implemented by base storage types that own the `versioned_substates`
/// history — `RocksDbStorage` and `SimStorage`. Views do **not** implement
/// this: a view is bound to a single anchor, so asking for "snapshot at
/// arbitrary version V" is not meaningful. Views produce anchor-based
/// snapshots via [`SubstateStore::snapshot`], which internally delegate
/// to the underlying base's `snapshot_at`.
///
/// The returned snapshot reads substate values as of `version`. When
/// `version` exceeds the persisted tip, MVCC walk-back clamps to the
/// tip — callers that need overlay coverage above the persisted tip
/// must go through a [`crate::pending_chain::SubstateView`].
///
/// `version` must be within the MVCC retention window (currently 256
/// blocks). Requests beyond the window fall back to the retention
/// boundary, not the literal version asked for.
pub trait VersionedStore: SubstateStore {
    /// Create a snapshot anchored at the given MVCC version.
    fn snapshot_at(&self, version: u64) -> Self::Snapshot<'_>;
}
