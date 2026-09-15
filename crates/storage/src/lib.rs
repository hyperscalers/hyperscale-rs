//! Storage traits and shared types.
//!
//! This crate defines the storage abstraction used by runners to persist substate state,
//! along with shared types and utilities that both in-memory and `RocksDB` storage
//! implementations need.
//!
//! # Design
//!
//! Storage is an implementation detail of runners, not the state machine.
//! The state machine emits `Action::ExecuteTransactions` and receives
//! `ProtocolEvent::ExecutionBatchCompleted` - it never touches storage directly.
//!
//! Runners own storage and pass it to the executor:
//! - `SimulationRunner` uses in-memory storage (`SimShardStorage`)
//! - `ProductionRunner` uses `RocksDB` (`RocksDbShardStorage`)
//!
//! # Jellyfish Merkle Tree (JMT)
//!
//! The `tree` module provides the binary Blake3 JMT state tree adapter.
//! Storage backends implement `jmt::TreeReader` to provide tree access —
//! both `RocksDB` and `SimShardStorage` hook into the same trait.

#![warn(missing_docs)]

pub mod beacon;
pub mod lock_recover;
pub mod shard;
pub mod tree;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_helpers;

pub use beacon::chain_reader::BeaconChainReader;
pub use beacon::chain_writer::BeaconChainWriter;
pub use beacon::packages::FetchedPackageStore;
pub use beacon::ratify_registers::RatifyRegisterStore;
pub use beacon::storage::BeaconStorage;
use hyperscale_jmt::TreeReader;
/// The substate content contract state backends implement — the vm
/// kernel's, so the executor and the chain read one vocabulary.
pub use hyperscale_vm_kernel::Substates;
pub use shard::boundary::{
    AdoptSource, Adoption, BOUNDARY_RETAIN, BoundaryStore, ImportCursor, ImportProgress, Subtree,
    Vintage, WitnessSeed, adopt_plan, holds_state,
};
pub use shard::chain_reader::{BlockForSync, ShardChainReader, holds_this_block_at};
pub use shard::chain_writer::{ParentAnchor, ShardChainWriter};
pub use shard::committed_provisions::CommittedProvisions;
pub use shard::dedup_window::{DedupWindow, FeeHold};
pub use shard::derived::{LeafRows, index_leaf};
pub use shard::genesis::GenesisCommit;
pub use shard::packages::{PackageArtifactStore, package_of_cell};
pub use shard::pending_chain::{
    BaseReadCache, ChainEntry, PendingChain, SubstateView, TerminalWindow,
};
pub use shard::recovered_state::RecoveredState;
pub use shard::retention::{Retired, retire_dated};
pub use shard::store::{Anchored, SubstateStore, VersionedStore};
pub use shard::sweep::{
    SweepIndex, SweepRow, SweepRows, committed_tx_cell_key, committed_tx_cells,
    followed_block_writes, is_record_cell, merge_sweep_overlay, sweep_for_block, sweep_through,
    sweepable_expiry, with_sweep,
};
pub use shard::tick_certs::{covers_strictly_more, widest_tick_copies};
pub use shard::tick_chain::{
    ProvisionalTx, TickChain, TickOutput, TickResolution, TickView, TickViewSnapshot,
};
pub use shard::unresolved::{ReplayWindow, replay_window, unresolved_replay_floor};
pub use shard::vote_registers::SafeVoteRegisterStore;
pub use shard::writes::{
    entry_from_leaf, entry_leaf_rows, entry_leaf_value, entry_overlay_range,
    filter_state_writes_to_prefix, filter_writes_to_prefix, fold_state_writes, key_under_prefix,
    merge_entry_overlay, merge_entry_overlay_with, merge_receipts, merge_state_writes,
    merge_writes_from_receipts, pending_write, prefix_low_key, settle_writes, settled_writes_at,
};
pub use tree::{CollectedWrites, JmtSnapshot};

/// Umbrella bound for storage backends threaded as a generic `S` through
/// node-side machinery (the `IoLoop` and its delegated action handler).
///
/// Use this only at sites that *thread* storage generically — i.e. the
/// `IoLoop<S>` impls and entry points that must satisfy every capability
/// `IoLoop` ultimately needs. For narrower scopes (block commit, shard consensus
/// proposal building, provision handlers), bound on the specific traits
/// directly so the signature reflects what the function actually touches.
pub trait ShardStorage:
    ShardChainWriter
    + SubstateStore
    + VersionedStore
    + ShardChainReader
    + TreeReader
    + BoundaryStore
    + PackageArtifactStore
    + SafeVoteRegisterStore
    + SweepIndex
    + Send
    + Sync
    + 'static
{
}

impl<S> ShardStorage for S where
    S: ShardChainWriter
        + SubstateStore
        + VersionedStore
        + ShardChainReader
        + TreeReader
        + BoundaryStore
        + PackageArtifactStore
        + SafeVoteRegisterStore
        + SweepIndex
        + Send
        + Sync
        + 'static
{
}
