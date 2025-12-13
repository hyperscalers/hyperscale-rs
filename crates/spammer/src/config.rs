//! Configuration types for the spammer.

use crate::accounts::SelectionMode;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use std::time::Duration;

/// Configuration for the transaction spammer.
#[derive(Clone, Debug)]
pub struct SpammerConfig {
    /// Number of shards in the network.
    pub num_shards: u64,

    /// Number of validators (endpoints) per shard.
    /// Used to distribute load across multiple nodes in each shard.
    pub validators_per_shard: usize,

    /// RPC endpoints for each shard (at least one per shard).
    pub rpc_endpoints: Vec<String>,

    /// Number of accounts to generate per shard.
    pub accounts_per_shard: usize,

    /// Target transactions per second.
    pub target_tps: u64,

    /// Ratio of cross-shard transactions (0.0 to 1.0).
    pub cross_shard_ratio: f64,

    /// Account selection mode.
    pub selection_mode: SelectionMode,

    /// Initial account balance for genesis.
    pub initial_balance: Decimal,

    /// Network definition (mainnet/testnet/simulator).
    pub network: NetworkDefinition,

    /// Batch size for transaction generation.
    pub batch_size: usize,

    /// Interval between progress reports.
    pub progress_interval: Duration,

    /// Whether to track transaction latency by polling for completion.
    pub latency_tracking: bool,

    /// Sample rate for latency measurement (0.0 to 1.0).
    /// Only this fraction of transactions will be tracked.
    pub latency_sample_rate: f64,

    /// Poll interval for checking transaction status.
    pub latency_poll_interval: Duration,
}

impl Default for SpammerConfig {
    fn default() -> Self {
        Self {
            num_shards: 2,
            validators_per_shard: 1,
            rpc_endpoints: vec![
                "http://localhost:8080".into(),
                "http://localhost:8083".into(),
            ],
            accounts_per_shard: 100,
            target_tps: 1000,
            cross_shard_ratio: 0.3,
            selection_mode: SelectionMode::Random,
            initial_balance: Decimal::from(1_000_000u32),
            network: NetworkDefinition::simulator(),
            batch_size: 100,
            progress_interval: Duration::from_secs(10),
            latency_tracking: false,
            latency_sample_rate: 0.01,
            latency_poll_interval: Duration::from_millis(100),
        }
    }
}

impl SpammerConfig {
    /// Create a new configuration with the given endpoints.
    pub fn new(endpoints: Vec<String>) -> Self {
        Self {
            rpc_endpoints: endpoints,
            ..Default::default()
        }
    }

    /// Set the number of shards.
    pub fn with_num_shards(mut self, num_shards: u64) -> Self {
        self.num_shards = num_shards;
        self
    }

    /// Set the number of validators per shard.
    pub fn with_validators_per_shard(mut self, validators: usize) -> Self {
        self.validators_per_shard = validators.max(1);
        self
    }

    /// Set accounts per shard.
    pub fn with_accounts_per_shard(mut self, accounts: usize) -> Self {
        self.accounts_per_shard = accounts;
        self
    }

    /// Set target TPS.
    pub fn with_target_tps(mut self, tps: u64) -> Self {
        self.target_tps = tps;
        self
    }

    /// Set cross-shard ratio.
    pub fn with_cross_shard_ratio(mut self, ratio: f64) -> Self {
        self.cross_shard_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    /// Set selection mode.
    pub fn with_selection_mode(mut self, mode: SelectionMode) -> Self {
        self.selection_mode = mode;
        self
    }

    /// Set initial balance.
    pub fn with_initial_balance(mut self, balance: Decimal) -> Self {
        self.initial_balance = balance;
        self
    }

    /// Set network definition.
    pub fn with_network(mut self, network: NetworkDefinition) -> Self {
        self.network = network;
        self
    }

    /// Set batch size.
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Enable or disable latency tracking.
    pub fn with_latency_tracking(mut self, enabled: bool) -> Self {
        self.latency_tracking = enabled;
        self
    }

    /// Set the sample rate for latency tracking (0.0 to 1.0).
    pub fn with_latency_sample_rate(mut self, rate: f64) -> Self {
        self.latency_sample_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Set the poll interval for latency tracking.
    pub fn with_latency_poll_interval(mut self, interval: Duration) -> Self {
        self.latency_poll_interval = interval;
        self
    }

    /// Calculate the sleep duration between batches to achieve target TPS.
    pub fn batch_interval(&self) -> Duration {
        if self.target_tps == 0 || self.batch_size == 0 {
            return Duration::from_millis(100);
        }
        let batches_per_sec = self.target_tps as f64 / self.batch_size as f64;
        let interval_ms = (1000.0 / batches_per_sec) as u64;
        Duration::from_millis(interval_ms.max(1))
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.rpc_endpoints.is_empty() {
            return Err(ConfigError::NoEndpoints);
        }
        if self.num_shards == 0 {
            return Err(ConfigError::InvalidShards);
        }
        if self.accounts_per_shard == 0 {
            return Err(ConfigError::InvalidAccounts);
        }
        Ok(())
    }
}

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("No RPC endpoints configured")]
    NoEndpoints,

    #[error("Number of shards must be greater than 0")]
    InvalidShards,

    #[error("Accounts per shard must be greater than 0")]
    InvalidAccounts,
}
