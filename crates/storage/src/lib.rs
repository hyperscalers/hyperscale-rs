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
//! `Event::TransactionsExecuted` - it never touches storage directly.
//!
//! Runners own storage and pass it to the executor:
//! - `SimulationRunner` uses in-memory storage (`SimStorage`)
//! - `ProductionRunner` uses RocksDB (`RocksDbStorage`)
//!
//! # Architecture
//!
//! Rather than having our own `Storage` trait that we adapt to Radix's `SubstateDatabase`,
//! runner storage types implement `SubstateDatabase` + `CommittableSubstateDatabase` directly,
//! plus our `SubstateStore` extension trait for snapshots, node listing, and JMT state roots.
//!
//! # Jellyfish Merkle Tree (JMT)
//!
//! All `SubstateStore` implementations use JMT internally to maintain a cryptographic
//! commitment to the entire state. This provides:
//! - `state_version()` - Monotonically increasing version number
//! - `state_root_hash()` - Merkle root of all substates at current version

#![warn(missing_docs)]

mod commit;
mod consensus;
mod jmt_snapshot;
pub mod keys;
mod overlay;
mod store;
mod writes;

pub use commit::{CommitResult, CommitStore};
pub use consensus::ConsensusStore;
pub use jmt_snapshot::{JmtSnapshot, LeafSubstateKeyAssociation};
pub use overlay::{OverlayTreeStore, SubstateDbLookup, SubstateLookup};
pub use store::{SubstateStore, RADIX_PREFIX};
pub use writes::{extract_writes_per_cert, substate_writes_to_database_updates};

// Re-export commonly needed Radix types for storage implementations
pub use radix_common::crypto::Hash as StateRootHash;
pub use radix_common::prelude::{DatabaseUpdate, DbSubstateValue};
pub use radix_substate_store_interface::interface::{
    CommittableSubstateDatabase, DatabaseUpdates, DbPartitionKey, DbSortKey, NodeDatabaseUpdates,
    PartitionDatabaseUpdates, PartitionEntry, SubstateDatabase,
};

/// JMT implementation types re-exported for storage backends.
///
/// These are implementation details needed by `storage-memory` and `storage-rocksdb`.
/// They are not part of the abstract storage interface.
pub mod jmt {
    pub use radix_substate_store_impls::state_tree::put_at_next_version;
    pub use radix_substate_store_impls::state_tree::tree_store::{
        encode_key, AssociatedSubstateValue, ReadableTreeStore, StaleTreePart, StoredTreeNodeKey,
        TreeNode, TypedInMemoryTreeStore, Version as StateVersion, VersionedTreeNode,
        WriteableTreeStore,
    };
}
