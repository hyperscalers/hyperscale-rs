//! Radix production setup for hyperscale.
//!
//! Provides [`RadixProductionSetup`] which implements [`ProductionSetup`] to
//! customize the generic production runner with Radix Engine execution,
//! transaction validation, and genesis bootstrapping.

use hyperscale_dispatch_pooled::PooledDispatch;
use hyperscale_engine::{GenesisConfig, RadixExecutor, TransactionValidation};
use hyperscale_production::ProductionSetup;
use hyperscale_radix_config::RadixConfig;
use hyperscale_storage::GenesisWrapper;
use hyperscale_storage_rocksdb::{RocksDbStorage, SharedStorage};
use hyperscale_types::Hash;
use radix_common::network::NetworkDefinition;
use std::sync::Arc;
use tracing::info;

/// Type alias for the production genesis wrapper.
type GenesisMutWrapper<'a> = GenesisWrapper<'a, RocksDbStorage<PooledDispatch>>;

/// Radix-specific production setup.
///
/// Creates Radix Engine executors and transaction validators, and runs
/// the Radix genesis bootstrap on production (RocksDB) storage.
pub struct RadixProductionSetup;

impl ProductionSetup for RadixProductionSetup {
    type C = RadixConfig;
    type E = RadixExecutor;
    type V = TransactionValidation;
    type GenesisConfig = GenesisConfig;

    fn create_executor_and_validator() -> (RadixExecutor, Arc<TransactionValidation>) {
        let network_def = NetworkDefinition::simulator();
        let executor = RadixExecutor::new(network_def.clone());
        let validator = Arc::new(TransactionValidation::new(network_def));
        (executor, validator)
    }

    fn run_genesis(
        storage: &SharedStorage<PooledDispatch>,
        executor: &RadixExecutor,
        genesis_config: Option<GenesisConfig>,
    ) -> Result<Hash, Box<dyn std::error::Error>> {
        // GenesisMutWrapper writes substates only (no JMT) during bootstrap, then
        // we compute the JMT once at version 0. This ensures block 1 cleanly
        // writes at JMT version 1 without colliding with genesis versions.
        let mut wrapper: GenesisMutWrapper<'_> = GenesisWrapper::new(storage);

        if let Some(config) = genesis_config {
            info!(
                xrd_balances = config.xrd_balances.len(),
                "Running genesis with custom configuration"
            );
            executor.run_genesis_with_config(&mut wrapper, config)?;
        } else {
            executor.run_genesis(&mut wrapper)?;
        }

        // Compute JMT once at version 0 from merged genesis updates.
        let merged = wrapper.into_merged();
        let jmt_root = storage.finalize_genesis_jmt(&merged);

        Ok(jmt_root)
    }
}
