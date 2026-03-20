//! Radix simulation setup for hyperscale.
//!
//! Provides [`RadixSimulationSetup`] which implements [`SimulationSetup`] to
//! customize the generic simulation runner with Radix Engine execution,
//! transaction validation, and genesis bootstrapping.

use hyperscale_dispatch_sync::SyncDispatch;
use hyperscale_engine::{RadixExecutor, TransactionValidation};
use hyperscale_radix_config::RadixConfig;
use hyperscale_simulation::SimulationSetup;
use hyperscale_storage::GenesisWrapper;
use hyperscale_storage_memory::SimStorage;
use radix_common::network::NetworkDefinition;
use std::sync::Arc;
use tracing::warn;

/// Radix-specific simulation setup.
///
/// Creates Radix Engine executors and transaction validators, and runs
/// the Radix genesis bootstrap on each node's storage.
pub struct RadixSimulationSetup;

impl SimulationSetup for RadixSimulationSetup {
    type C = RadixConfig;
    type E = RadixExecutor;
    type V = TransactionValidation;

    fn create_executor_and_validator(
        _node_index: u32,
    ) -> (RadixExecutor, Arc<TransactionValidation>) {
        let network_def = NetworkDefinition::simulator();
        let executor = RadixExecutor::new(network_def.clone());
        let validator = Arc::new(TransactionValidation::permissive(network_def));
        (executor, validator)
    }

    fn run_genesis(
        storage: &SimStorage<SyncDispatch>,
        executor: &RadixExecutor,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut wrapper = GenesisWrapper::new(storage);
        executor.run_genesis(&mut wrapper)?;
        let merged = wrapper.into_merged();
        storage.finalize_genesis_jmt(&merged);
        Ok(())
    }
}

/// Extension trait for Radix-specific genesis with pre-funded accounts.
pub trait RadixGenesisExt {
    /// Initialize genesis with pre-funded accounts.
    fn initialize_genesis_with_balances(
        &mut self,
        balances: Vec<(
            radix_common::types::ComponentAddress,
            radix_common::math::Decimal,
        )>,
    );
}

impl RadixGenesisExt for hyperscale_simulation::SimulationRunner<RadixSimulationSetup> {
    fn initialize_genesis_with_balances(
        &mut self,
        balances: Vec<(
            radix_common::types::ComponentAddress,
            radix_common::math::Decimal,
        )>,
    ) {
        use hyperscale_engine::GenesisConfig;

        let num_nodes = self.num_nodes();
        for node_idx in 0..num_nodes {
            if !self.is_genesis_executed(node_idx) {
                let balances = balances.clone();
                self.with_storage_and_executor(node_idx, |storage, executor| {
                    let mut wrapper = GenesisWrapper::new(storage);
                    let config = GenesisConfig {
                        xrd_balances: balances,
                        ..GenesisConfig::test_default()
                    };
                    if let Err(e) = executor.run_genesis_with_config(&mut wrapper, config) {
                        warn!(node = node_idx, "Radix Engine genesis failed: {:?}", e);
                        return;
                    }
                    let merged = wrapper.into_merged();
                    storage.finalize_genesis_jmt(&merged);
                });
                self.mark_genesis_executed(node_idx);
            }
        }
        tracing::info!(
            num_nodes,
            num_funded_accounts = balances.len(),
            "Radix Engine genesis complete with funded accounts"
        );

        self.finalize_genesis();
    }
}
