//! Storage traits for execution.
//!
//! This module defines the storage abstraction used by runners to persist
//! substate state.

use hyperscale_types::{BlockHeight, DeclaredRange, StateRoot, SubstateKey};

use crate::Substates;

/// A reader whose version was fixed when it was made.
///
/// Every snapshot is one. A store is not, and neither is a
/// [`crate::SubstateView`] read directly: both resolve
/// against whatever has persisted by the time the read happens. The
/// difference is invisible at a call site and decides the state root — a
/// movement resolved against a baseline that moves with one validator's
/// persistence progress forks against every replica that lagged
/// differently. So the places that must not read live ask for this, and
/// handing them a live reader stops compiling.
pub trait Anchored: Substates {
    /// The height every read through this reader resolves at.
    ///
    /// Knowing a version was fixed is not enough for a caller that needs
    /// a *particular* one — a snapshot of the wrong block is as wrong as
    /// a live read, and looks the same at the call site. This is what
    /// lets the caller check.
    fn anchor(&self) -> BlockHeight;
}

/// Extension trait for substate storage with snapshots, historical reads,
/// and JMT state roots.
///
/// This trait extends `Substates` with additional methods needed
/// for deterministic simulation and state commitment:
/// - `snapshot()` - Create isolated views for parallel execution
/// - `jmt_height()` / `state_root()` - JMT state commitment
///
/// All implementations use a binary Blake3 Jellyfish Merkle Tree (JMT)
/// internally to maintain cryptographic state roots, updated on each
/// commit.
///
/// Runner storage types (`SimShardStorage`, `RocksDbShardStorage`) implement this trait
/// along with `Substates`. They additionally implement [`VersionedStore`]
/// for explicit historical-version reads; views do not, since a view carries
/// a bound anchor and has no meaningful answer for an arbitrary version.
pub trait SubstateStore: Substates + Send + Sync + 'static {
    /// The snapshot type returned by this storage.
    ///
    /// All snapshots are version-aware — reads return the value as of
    /// some specific version. For base storage types, that version is
    /// chosen by the impl's [`Self::snapshot`] default (typically the
    /// current committed tip). For views, it is the view's bound
    /// anchor height.
    type Snapshot<'a>: Anchored + Send + Sync
    where
        Self: 'a;

    /// Create a snapshot at the impl-defined default version.
    ///
    /// - Base storage (`RocksDbShardStorage`, `SimShardStorage`): snapshots at the
    ///   current `jmt_height()`, i.e. the latest committed state.
    /// - [`crate::SubstateView`]: snapshots at the view's
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
    /// Genesis maps to `BlockHeight::GENESIS`.
    fn jmt_height(&self) -> BlockHeight;

    /// Current JMT state root hash.
    ///
    /// Returns the Blake3 root of all substates at the current version.
    /// This hash cryptographically commits to the entire state and can be used
    /// for state sync, light client proofs, and cross-validator consistency checks.
    ///
    /// Returns a zero hash if no commits have occurred.
    fn state_root(&self) -> StateRoot;

    /// Read one substate at a specific historical block height.
    ///
    /// Provision targets are substate-granular, so serving reads points,
    /// never scans. Used by cross-shard provision paths to serve
    /// historical state that can be verified against the original block's
    /// `state_root`.
    ///
    /// Returns `None` if the height is unavailable (garbage-collected or
    /// not yet committed); `Some(None)` when the cell is absent at that
    /// height.
    fn get_substate_at_height(
        &self,
        key: SubstateKey,
        block_height: BlockHeight,
    ) -> Option<Option<Vec<u8>>>;

    /// The entries of one collection interval at a specific historical
    /// block height, capped and ascending — the enumeration a provision
    /// serves, byte-identical to what an executor materializing the
    /// declared range at that height would read.
    ///
    /// Returns `None` if the height is unavailable (garbage-collected or
    /// not yet committed).
    fn get_entries_at_height(
        &self,
        range: DeclaredRange,
        block_height: BlockHeight,
    ) -> Option<Vec<(u128, Vec<u8>)>>;
}

/// Storage that supports reads at an explicit historical version.
///
/// Implemented by base storage types that own the state-history log —
/// `RocksDbShardStorage` and `SimShardStorage`. Views do **not** implement this:
/// a view is bound to a single anchor, so asking for "snapshot at
/// arbitrary version V" is not meaningful. Views produce anchor-based
/// snapshots via [`SubstateStore::snapshot`], which internally delegate
/// to the underlying base's `snapshot_at`.
///
/// The returned snapshot reads substate values as of `version`. When
/// `version` exceeds the persisted tip, the snapshot reads the current
/// value directly — callers that need overlay coverage above the
/// persisted tip must go through a [`crate::SubstateView`].
///
/// Two spellings of one read. [`Self::snapshot_held_at`] answers `None`
/// for a height the store does not hold, and is what every reader of a
/// network-supplied height goes through; [`Self::snapshot_at`] panics
/// below the floor, for internal callers whose anchor is licensed by
/// construction — below the retention floor the history log has been
/// collected, and an internal caller asking there is a DA-assumption
/// bug, not a case to degrade through.
pub trait VersionedStore: SubstateStore {
    /// The snapshot at `height`, or `None` when this store does not hold
    /// that height: above its tip, or below its retention floor. Tip and
    /// floor are read together, so the answer is one store's at one
    /// instant.
    fn snapshot_held_at(&self, height: BlockHeight) -> Option<Self::Snapshot<'_>>;

    /// Create a snapshot anchored at `height`, which must be at or above
    /// the retention floor; above the tip the snapshot reads the tip.
    ///
    /// # Panics
    ///
    /// If `height` is below the retention floor.
    fn snapshot_at(&self, height: BlockHeight) -> Self::Snapshot<'_>;

    /// Committed substate byte total after the commit at `height`,
    /// or `None` if no commit at that height recorded one (never
    /// committed, or pruned past the retention horizon).
    ///
    /// Consensus-critical: shard-witness derivation reads the count
    /// behind a block's parent state, so the value must be identical on
    /// every replica — it is written atomically with the commit, never
    /// recomputed out-of-band.
    fn substate_bytes_at(&self, height: BlockHeight) -> Option<u64>;

    /// The oldest height this store answers historical reads at.
    ///
    /// The bound every external-facing reader owes the contract above,
    /// stated rather than inferred: a caller that decides what it serves
    /// by whether the collector has run yet answers for heights the
    /// store no longer promises, and two such callers answer differently
    /// for the same height.
    fn retention_floor(&self) -> u64;
}
