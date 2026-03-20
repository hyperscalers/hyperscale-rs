//! Production setup trait.
//!
//! Defines the interface that implementations fulfill to customize the
//! production runner with their specific executor, validator, and genesis logic.

use hyperscale_core::{ExecutionBackend, TransactionValidator};
use hyperscale_dispatch_pooled::PooledDispatch;
use hyperscale_network_libp2p::Libp2pNetwork;
use hyperscale_node::NodeConfig;
use hyperscale_storage::DatabaseUpdates;
use hyperscale_storage_rocksdb::SharedStorage;
use hyperscale_types::{Hash, TypeConfig};
use std::marker::PhantomData;
use std::sync::Arc;

/// Trait that implementations fulfill to customize the production runner.
///
/// The generic `ProductionRunner<S>` handles all production infrastructure
/// (pinned thread, libp2p networking, RocksDB storage, timer management,
/// metrics collection, RPC server).
/// Implementations provide their TypeConfig, executor, validator, and genesis.
///
/// Storage (`SharedStorage<PooledDispatch>`), network (`Libp2pNetwork`), and
/// dispatch (`PooledDispatch`) are always the same for production — only the
/// execution layer varies.
pub trait ProductionSetup: Send + Sync + 'static {
    /// The TypeConfig for this implementation.
    ///
    /// `StateUpdate = DatabaseUpdates` is required because `SharedStorage` (RocksDB)
    /// stores state updates as `DatabaseUpdates` internally.
    type C: TypeConfig<StateUpdate = DatabaseUpdates>;

    /// The execution backend.
    type E: ExecutionBackend<Self::C>;

    /// The transaction validator.
    type V: TransactionValidator<Self::C>;

    /// Opaque genesis configuration type.
    type GenesisConfig: Send + 'static;

    /// Create an executor and transaction validator.
    fn create_executor_and_validator() -> (Self::E, Arc<Self::V>);

    /// Run genesis bootstrap on storage.
    ///
    /// Called once during initialization if no committed blocks exist.
    /// Must write initial state and compute the JMT root at version 0.
    ///
    /// Returns the JMT state root hash after genesis bootstrap.
    fn run_genesis(
        storage: &SharedStorage<PooledDispatch>,
        executor: &Self::E,
        genesis_config: Option<Self::GenesisConfig>,
    ) -> Result<Hash, Box<dyn std::error::Error>>;
}

/// Internal `NodeConfig` binding for a `ProductionSetup`.
///
/// Maps `S::C`, `S::E`, `S::V` to the fixed production infrastructure types.
pub struct ProdNodeConfig<S: ProductionSetup>(PhantomData<fn() -> S>);

impl<S: ProductionSetup> NodeConfig for ProdNodeConfig<S> {
    type C = S::C;
    type S = SharedStorage<PooledDispatch>;
    type N = Libp2pNetwork;
    type D = PooledDispatch;
    type E = S::E;
    type V = S::V;
}
