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
//! # Jellyfish Merkle Tree (JMT)
//!
//! The `tree` module provides the binary Blake3 JMT state tree adapter.
//! Storage backends implement `jmt::TreeReader` to provide tree access —
//! both RocksDB and SimStorage hook into the same trait.

#![warn(missing_docs)]

mod chain_reader;
mod chain_writer;
mod genesis;
pub mod keys;
mod overlay;
pub mod pending_chain;
mod store;
pub mod tree;
mod writes;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_helpers;

pub use chain_reader::ChainReader;
pub use chain_writer::ChainWriter;
pub use genesis::{GenesisWrapper, SubstatesOnlyCommit};
pub use hyperscale_jmt::TreeReader as JmtTreeReader;
pub use overlay::{SubstateDbLookup, SubstateLookup};
pub use pending_chain::{ChainEntry, PendingChain, SubstateView};
pub use store::{SubstateStore, VersionedStore};
pub use tree::{CollectedWrites, JmtNodeKey, JmtSnapshot, LeafSubstateKeyAssociation};
pub use writes::{
    merge_database_updates, merge_database_updates_from_arcs, merge_into,
    merge_updates_from_receipts,
};

/// An empty SubstateDatabase for use in tests and single-shard contexts
/// where no storage reads are needed.
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
pub use hyperscale_types::Hash as StateRootHash;
pub use radix_common::prelude::{DatabaseUpdate, DbSubstateValue};
pub use radix_substate_store_interface::interface::{
    CommittableSubstateDatabase, DatabaseUpdates, DbPartitionKey, DbSortKey, NodeDatabaseUpdates,
    PartitionDatabaseUpdates, PartitionEntry, SubstateDatabase,
};
