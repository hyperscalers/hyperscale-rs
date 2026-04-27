//! Genesis bootstrapping.

use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::prelude::Epoch;
use radix_common::types::ComponentAddress;
use radix_engine::system::bootstrap::{GenesisDataChunk, GenesisStakeAllocation, GenesisValidator};
use radix_engine::updates::{BabylonSettings, ProtocolBuilder, ProtocolVersion};
use radix_engine::vm::VmModules;
use radix_engine_interface::blueprints::consensus_manager::ConsensusManagerConfig;
use radix_substate_store_interface::interface::{CommittableSubstateDatabase, SubstateDatabase};

/// Default faucet supply (100 billion XRD).
const DEFAULT_FAUCET_SUPPLY: &str = "100000000000";

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

impl GenesisConfig {
    /// Minimal test configuration: faucet funded, no validators or accounts.
    ///
    /// # Panics
    ///
    /// Panics if [`DEFAULT_FAUCET_SUPPLY`] cannot be converted to a [`Decimal`] —
    /// the constant is fixed, so this is unreachable in practice.
    #[must_use]
    pub fn test_default() -> Self {
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

    /// Production configuration: no faucet, no preset leader.
    #[must_use]
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

    /// Mix the canonical inputs to genesis bootstrap into the given hasher.
    ///
    /// Stable across runs of the same process; suitable as a cache key for
    /// memoizing the resulting [`crate::DatabaseUpdates`].
    ///
    /// # Panics
    ///
    /// Panics if SBOR encoding of [`BabylonSettings`] fails — unreachable in
    /// practice; the type is fully Scrypto-encodable.
    pub fn cache_hash<H: std::hash::Hasher>(&self, hasher: &mut H) {
        use radix_common::prelude::scrypto_encode;
        use std::hash::Hash;

        let settings = self.to_babylon_settings();
        scrypto_encode(&settings)
            .expect("BabylonSettings is encodable")
            .hash(hasher);
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

/// Run genesis bootstrap for `(network, config)` against `store`.
///
/// Drives the Radix Engine through bootstrap → `CuttlefishPart2`; the resulting
/// substate writes land in `store`. Internal to the engine crate — callers
/// should go through [`crate::prepared_genesis`], which memoizes the merged
/// [`radix_substate_store_interface::interface::DatabaseUpdates`] per
/// `(network, config)`.
pub fn bootstrap<S>(network: &NetworkDefinition, config: &GenesisConfig, store: &mut S)
where
    S: SubstateDatabase + CommittableSubstateDatabase,
{
    let babylon_settings = config.to_babylon_settings();
    let mut hooks = radix_engine::system::bootstrap::GenesisReceiptExtractionHooks::new();
    let vm_modules = VmModules::default();

    ProtocolBuilder::for_network(network)
        .configure_babylon(|_| babylon_settings)
        .from_bootstrap_to(ProtocolVersion::CuttlefishPart2)
        .commit_each_protocol_update_advanced(store, &mut hooks, &vm_modules);
}
