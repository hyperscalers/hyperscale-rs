//! Storage traits and shared types.
//!
//! This crate defines the storage abstraction used by runners to persist Radix state,
//! along with shared types and utilities that both in-memory and RocksDB storage
//! implementations need.
//!
//! # Design
//!
//! Storage is an implementation detail of runners, not the state machine.
//! The state machine emits `Action::ExecuteTransactions` and receives
//! `ProtocolEvent::ExecutionBatchCompleted` - it never touches storage directly.
//!
//! Runners own storage and pass it to the executor:
//! - `SimulationRunner` uses in-memory storage (`SimStorage`)
//! - `ProductionRunner` uses RocksDB (`RocksDbStorage`)
//!
//! # Architecture
//!
//! Rather than having our own `Storage` trait that we adapt to Radix's `SubstateDatabase`,
//! runner storage types implement `SubstateDatabase` directly, plus our `SubstateStore`
//! extension trait for snapshots, node listing, and JVT state roots.
//!
//! # Jellyfish Verkle Tree (JVT)
//!
//! All `SubstateStore` implementations use JVT internally to maintain a cryptographic
//! commitment to the entire state. This provides:
//! - `jvt_version()` - Block height of last committed JVT state
//! - `state_root_hash()` - Verkle root of all substates at current version

#![warn(missing_docs)]

mod commit;
mod consensus;
mod genesis;
mod jvt_snapshot;
pub mod keys;
mod overlay;
pub mod proofs;
mod store;
mod writes;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_helpers;

pub use commit::{CommitStore, ConsensusCommitData};
pub use consensus::ConsensusStore;
pub use genesis::{GenesisWrapper, SubstatesOnlyCommit};
pub use jvt_snapshot::{JvtSnapshot, LeafSubstateKeyAssociation};
pub use overlay::{SubstateDbLookup, SubstateLookup};
pub use store::SubstateStore;
pub use writes::{
    extract_state_changes, filter_updates_to_shard, merge_database_updates,
    merge_database_updates_from_arcs, merge_into, receipt_to_database_updates,
};

/// Returns `None` when the JVT is truly empty (height 0 with zero root),
/// indicating no parent node exists. Otherwise returns `Some(block_height)`.
pub fn jvt_parent_height(block_height: u64, root: StateRootHash) -> Option<u64> {
    if block_height == 0 && root == StateRootHash::ZERO {
        None
    } else {
        Some(block_height)
    }
}

// Re-export commonly needed Radix types for storage implementations
pub use hyperscale_types::Hash as StateRootHash;
pub use radix_common::prelude::{DatabaseUpdate, DbSubstateValue};
pub use radix_substate_store_interface::interface::{
    CommittableSubstateDatabase, DatabaseUpdates, DbPartitionKey, DbSortKey, NodeDatabaseUpdates,
    PartitionDatabaseUpdates, PartitionEntry, SubstateDatabase,
};

/// State tree implementation types re-exported for storage backends.
///
/// These are implementation details needed by `storage-memory` and `storage-rocksdb`.
/// They are not part of the abstract storage interface.
pub mod jmt {
    pub use hyperscale_state_tree::put_at_version;
    pub use hyperscale_state_tree::put_at_version_and_apply;
    pub use hyperscale_state_tree::tree_store::{
        encode_key, ReadableTreeStore, StaleTreePart, StoredNode, StoredNodeKey,
        TypedInMemoryTreeStore, Version, VersionedStoredNode, WriteableTreeStore,
    };
    pub use hyperscale_state_tree::CollectedWrites;
    pub use hyperscale_state_tree::NodeCache;
}
