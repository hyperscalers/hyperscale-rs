//! Storage traits and shared types.
//!
//! This crate defines the storage abstraction used by runners to persist state,
//! along with shared types and utilities that storage implementations need.
//!
//! # Design
//!
//! Storage is an implementation detail of runners, not the state machine.
//! The state machine emits `Action::ExecuteTransactions` and receives
//! `ProtocolEvent::ExecutionBatchCompleted` — it never touches storage directly.
//!
//! Runners own storage and pass it to the executor:
//! - `SimulationRunner` uses in-memory storage (`SimStorage`)
//! - `ProductionRunner` uses RocksDB (`RocksDbStorage`)
//!
//! # Framework Traits
//!
//! The framework-level storage traits ([`SubstateReader`], [`SubstateStore`],
//! [`CommitStore`], [`ConsensusStore`]) are generic — they use `TypeConfig`
//! associated types and raw byte interfaces, with no Radix-specific types.
//!
//! Storage backends additionally implement Radix's `SubstateDatabase` trait
//! for engine execution compatibility.
//!
//! # Jellyfish Merkle Tree (JMT)
//!
//! All `SubstateStore` implementations use JMT internally to maintain a cryptographic
//! commitment to the entire state. This provides:
//! - `jmt_version()` — Block height of last committed JMT state
//! - `state_root_hash()` — Merkle root of all substates at current version

#![warn(missing_docs)]

mod commit;
mod consensus;
mod genesis;
mod jmt_snapshot;
pub mod keys;
mod overlay;
pub mod proofs;
mod reader;
mod store;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_helpers;

pub use commit::{CommitStore, ConsensusCommitData};
pub use consensus::ConsensusStore;
pub use genesis::{GenesisWrapper, SubstatesOnlyCommit};
pub use jmt_snapshot::{JmtSnapshot, LeafSubstateKeyAssociation};
pub use overlay::{SubstateDbLookup, SubstateLookup};
pub use reader::SubstateReader;
pub use store::{RawSubstateEntry, SubstateStore, RADIX_PREFIX};

/// Returns `None` when the JMT is truly empty (height 0 with zero root),
/// indicating no parent node exists. Otherwise returns `Some(block_height)`.
pub fn jmt_parent_height(block_height: u64, root: StateRootHash) -> Option<u64> {
    if block_height == 0 && root == StateRootHash::ZERO {
        None
    } else {
        Some(block_height)
    }
}

/// Framework-level state root hash type.
pub use hyperscale_types::Hash as StateRootHash;

// ── Radix type re-exports for storage backends ──────────────────────────────
//
// Storage backends (storage-memory, storage-rocksdb) and runners need these
// Radix types. They are re-exported here as a convenience so backends don't
// need to add direct deps on radix-common / radix-substate-store-interface.
//
// Framework crates (core, bft, execution, node, etc.) should NOT import these.
// The framework uses generic TypeConfig associated types instead.
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
    pub use hyperscale_jmt::put_at_version;
    pub use hyperscale_jmt::put_at_version_and_apply;
    pub use hyperscale_jmt::tier_framework::TierCollectedWrites;
    pub use hyperscale_jmt::tree_store::{
        encode_key, ReadableTreeStore, StaleTreePart, StoredTreeNodeKey, TreeNode,
        TypedInMemoryTreeStore, Version, VersionedTreeNode, WriteableTreeStore,
    };

    // Re-export types needed for proof generation and verification
    pub use hyperscale_jmt::types::{
        IteratedLeafKey, LeafKey, SparseMerkleLeafNode, SparseMerkleProof, INTERNAL_HASH_DOMAIN,
        LEAF_HASH_DOMAIN,
    };

    // Re-export tier types for proof generation and historical reads
    pub use hyperscale_jmt::entity_tier::EntityTier;
    pub use hyperscale_jmt::partition_tier::PartitionTier;
    pub use hyperscale_jmt::substate_tier::{SubstateSummary, SubstateTier};
    pub use hyperscale_jmt::tier_framework::ReadableTier;
}
