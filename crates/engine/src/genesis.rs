//! Genesis bootstrapping.

use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::prelude::Epoch;
use radix_common::types::ComponentAddress;
use radix_engine::system::bootstrap::{
    GenesisDataChunk, GenesisReceipts, GenesisStakeAllocation, GenesisValidator,
};
use radix_engine::updates::{BabylonSettings, ProtocolBuilder};
use radix_engine::vm::VmModules;
use radix_engine_interface::blueprints::consensus_manager::ConsensusManagerConfig;
use radix_substate_store_interface::interface::{CommittableSubstateDatabase, SubstateDatabase};
use thiserror::Error;

/// Default faucet supply (100 billion XRD).
pub const DEFAULT_FAUCET_SUPPLY: &str = "100000000000";

/// Errors that can occur during genesis.
#[derive(Debug, Error)]
pub enum GenesisError {
    /// Genesis has already been executed.
    #[error("genesis already executed")]
    AlreadyExecuted,

    /// Invalid decimal value.
    #[error("invalid decimal: {0}")]
    InvalidDecimal(String),

    /// Genesis execution failed.
    #[error("genesis execution failed: {0}")]
    ExecutionFailed(String),
}

/// Configuration for genesis bootstrapping.
#[derive(Debug, Clone)]
pub struct GenesisConfig {
    /// Initial epoch number.
    pub genesis_epoch: Epoch,

    /// Consensus manager configuration.
    pub consensus_manager_config: ConsensusManagerConfig,

    /// Initial timestamp (milliseconds since Unix epoch).
    pub initial_time_ms: i64,

    /// Initial leader index.
    pub initial_current_leader: Option<u8>,

    /// XRD supply for the faucet (zero for production).
    pub faucet_supply: Decimal,

    /// Genesis validators.
    pub validators: Vec<GenesisValidator>,

    /// Stake allocations per validator.
    pub stake_allocations: Vec<(usize, Vec<GenesisStakeAllocation>)>,

    /// Staker accounts.
    pub staker_accounts: Vec<ComponentAddress>,

    /// Initial XRD balances.
    pub xrd_balances: Vec<(ComponentAddress, Decimal)>,
}

impl Default for GenesisConfig {
    fn default() -> Self {
        Self::test_default()
    }
}

impl GenesisConfig {
    /// Create a minimal test configuration.
    pub fn test_minimal() -> Self {
        Self {
            genesis_epoch: Epoch::of(1),
            consensus_manager_config: ConsensusManagerConfig::test_default(),
            initial_time_ms: 1,
            initial_current_leader: Some(0),
            faucet_supply: Decimal::try_from(DEFAULT_FAUCET_SUPPLY).unwrap(),
            validators: Vec::new(),
            stake_allocations: Vec::new(),
            staker_accounts: Vec::new(),
            xrd_balances: Vec::new(),
        }
    }

    /// Create a test configuration with default faucet supply.
    pub fn test_default() -> Self {
        Self::test_minimal()
    }

    /// Create a production configuration (no faucet).
    pub fn production() -> Self {
        Self {
            genesis_epoch: Epoch::of(1),
            consensus_manager_config: ConsensusManagerConfig::test_default(),
            initial_time_ms: 0,
            initial_current_leader: None,
            faucet_supply: Decimal::ZERO,
            validators: Vec::new(),
            stake_allocations: Vec::new(),
            staker_accounts: Vec::new(),
            xrd_balances: Vec::new(),
        }
    }

    fn to_babylon_settings(&self) -> BabylonSettings {
        let mut chunks = Vec::new();

        if !self.validators.is_empty() {
            chunks.push(GenesisDataChunk::Validators(self.validators.clone()));

            if !self.stake_allocations.is_empty() && !self.staker_accounts.is_empty() {
                let allocations: Vec<_> = self
                    .stake_allocations
                    .iter()
                    .filter_map(|(validator_idx, allocs)| {
                        self.validators
                            .get(*validator_idx)
                            .map(|v| (v.key, allocs.clone()))
                    })
                    .collect();

                if !allocations.is_empty() {
                    chunks.push(GenesisDataChunk::Stakes {
                        accounts: self.staker_accounts.clone(),
                        allocations,
                    });
                }
            }
        }

        if !self.xrd_balances.is_empty() {
            chunks.push(GenesisDataChunk::XrdBalances(self.xrd_balances.clone()));
        }

        BabylonSettings {
            genesis_data_chunks: chunks,
            genesis_epoch: self.genesis_epoch,
            consensus_manager_config: self.consensus_manager_config.clone(),
            initial_time_ms: self.initial_time_ms,
            initial_current_leader: self.initial_current_leader,
            faucet_supply: self.faucet_supply,
        }
    }
}

/// Builder for genesis bootstrapping.
pub struct GenesisBuilder {
    network: NetworkDefinition,
    config: GenesisConfig,
}

impl GenesisBuilder {
    /// Create a new genesis builder.
    pub fn new(network: NetworkDefinition) -> Self {
        Self {
            network,
            config: GenesisConfig::default(),
        }
    }

    /// Set the genesis configuration.
    pub fn with_config(mut self, config: GenesisConfig) -> Self {
        self.config = config;
        self
    }

    /// Execute genesis on the provided database.
    pub fn build<S>(self, store: &mut S) -> Result<GenesisReceipts, GenesisError>
    where
        S: SubstateDatabase + CommittableSubstateDatabase,
    {
        let babylon_settings = self.config.to_babylon_settings();

        let mut hooks = radix_engine::system::bootstrap::GenesisReceiptExtractionHooks::new();
        let vm_modules = VmModules::default();

        ProtocolBuilder::for_network(&self.network)
            .configure_babylon(|_| babylon_settings)
            .only_babylon()
            .commit_each_protocol_update_advanced(store, &mut hooks, &vm_modules);

        Ok(hooks.into_genesis_receipts())
    }
}
