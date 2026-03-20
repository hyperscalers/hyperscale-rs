//! Simulation setup trait.
//!
//! Defines the interface that implementations fulfill to customize the
//! simulation runner with their specific executor, validator, and genesis logic.

use hyperscale_core::{ExecutionBackend, TransactionValidator};
use hyperscale_dispatch_sync::SyncDispatch;
use hyperscale_network_memory::SimNetworkAdapter;
use hyperscale_node::NodeConfig;
use hyperscale_radix_config::RadixStateUpdate;
use hyperscale_storage_memory::SimStorage;
use hyperscale_types::TypeConfig;
use std::marker::PhantomData;
use std::sync::Arc;

/// Trait that implementations fulfill to customize the simulation runner.
///
/// The generic `SimulationRunner<S>` handles all deterministic simulation
/// infrastructure (event queue, network simulation, timer management).
/// Implementations provide their TypeConfig, executor, validator, and genesis.
///
/// Storage (`SimStorage`), network (`SimNetworkAdapter`), and dispatch
/// (`SyncDispatch`) are always the same for simulation — only the execution
/// layer varies.
pub trait SimulationSetup: 'static {
    /// The TypeConfig for this implementation.
    ///
    /// `StateUpdate = RadixStateUpdate` is required because `SimStorage`
    /// stores state updates as `DatabaseUpdates` internally.
    type C: TypeConfig<StateUpdate = RadixStateUpdate>;

    /// The execution backend.
    type E: ExecutionBackend<Self::C>;

    /// The transaction validator.
    type V: TransactionValidator<Self::C>;

    /// Create an executor and transaction validator for a simulation node.
    fn create_executor_and_validator(node_index: u32) -> (Self::E, Arc<Self::V>);

    /// Run genesis bootstrap on a node's storage.
    ///
    /// Called once per node during initialization. Should write initial state
    /// and compute the JMT root at version 0.
    fn run_genesis(
        storage: &SimStorage<SyncDispatch>,
        executor: &Self::E,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

/// Internal `NodeConfig` binding for a `SimulationSetup`.
///
/// Maps `S::C`, `S::E`, `S::V` to the fixed simulation infrastructure types.
pub struct SimNodeConfig<S: SimulationSetup>(PhantomData<fn() -> S>);

impl<S: SimulationSetup> NodeConfig for SimNodeConfig<S> {
    type Types = S::C;
    type Storage = SimStorage<SyncDispatch>;
    type Net = SimNetworkAdapter;
    type Pool = SyncDispatch;
    type Executor = S::E;
    type Validator = S::V;
}
