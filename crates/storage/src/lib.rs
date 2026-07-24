//! Storage traits and shared types.
//!
//! This crate defines the storage abstraction used by runners to persist Radix state,
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
pub use beacon::ratify_registers::RatifyRegisterStore;
pub use beacon::storage::BeaconStorage;
use hyperscale_jmt::TreeReader;
pub use shard::boundary::{
    BOUNDARY_RETAIN, BoundaryStore, ImportCursor, ImportLeaf, ImportProgress, ResolveLeaf,
    WitnessSeed,
};
pub use shard::chain_reader::{BlockForSync, ShardChainReader};
pub use shard::chain_writer::ShardChainWriter;
pub use shard::genesis::GenesisCommit;
pub use shard::overlay::{SubstateDbLookup, SubstateLookup};
pub use shard::pending_chain::{BaseReadCache, ChainEntry, PendingChain, SubstateView};
pub use shard::recovered_state::RecoveredState;
pub use shard::store::{SubstateStore, VersionedStore};
pub use shard::vote_registers::SafeVoteRegisterStore;
pub use shard::writes::{
    filter_updates_to_prefix, merge_database_updates, merge_into, merge_owned_nodes,
    merge_updates_from_receipts,
};
pub use tree::{CollectedWrites, JmtSnapshot, LeafSubstateKeyAssociation};

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
    + SafeVoteRegisterStore
    + Send
    + Sync
{
}

impl<S> ShardStorage for S where
    S: ShardChainWriter
        + SubstateStore
        + VersionedStore
        + ShardChainReader
        + TreeReader
        + BoundaryStore
        + SafeVoteRegisterStore
        + Send
        + Sync
{
}

/// An empty `SubstateDatabase` for use in tests and single-shard contexts
/// where no storage reads are needed.
#[must_use]
pub fn empty_substate_database() -> impl SubstateDatabase {
    struct Empty;
    impl SubstateDatabase for Empty {
        fn get_raw_substate_by_db_key(
            &self,
            _partition_key: &DbPartitionKey,
            _sort_key: &DbSortKey,
        ) -> Option<Vec<u8>> {
            None
        }
        fn list_raw_values_from_db_key(
            &self,
            _partition_key: &DbPartitionKey,
            _from_sort_key: Option<&DbSortKey>,
        ) -> Box<dyn Iterator<Item = (DbSortKey, Vec<u8>)> + '_> {
            Box::new(std::iter::empty())
        }
    }
    Empty
}

// Re-export commonly needed Radix types for storage implementations
pub use radix_common::prelude::{DatabaseUpdate, DbSubstateValue};
pub use radix_substate_store_interface::interface::{
    CommittableSubstateDatabase, DatabaseUpdates, DbPartitionKey, DbSortKey, NodeDatabaseUpdates,
    PartitionDatabaseUpdates, PartitionEntry, SubstateDatabase,
};
