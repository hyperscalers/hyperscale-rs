//! Configuration types for the simulator.

use hyperscale_simulation::NetworkConfig;
use hyperscale_spammer::SelectionMode;
use radix_common::math::Decimal;
use std::time::Duration;

/// Configuration for a simulation run.
#[derive(Clone, Debug)]
pub struct SimulatorConfig {
    /// Number of shards in the network.
    pub num_shards: u32,

    /// Number of validators per shard.
    pub validators_per_shard: u32,

    /// Number of accounts to create per shard.
    pub accounts_per_shard: usize,

    /// Initial XRD balance for each account.
    pub initial_balance: Decimal,

    /// Workload configuration.
    pub workload: WorkloadConfig,

    /// Random seed for deterministic simulation.
    pub seed: u64,
}

impl SimulatorConfig {
    /// Create a new simulator configuration.
    #[must_use]
    pub fn new(num_shards: u32, validators_per_shard: u32) -> Self {
        Self {
            num_shards,
            validators_per_shard,
            accounts_per_shard: 50,
            initial_balance: Decimal::from(10_000u32),
            workload: WorkloadConfig::default(),
            seed: 12345,
        }
    }

    /// Set the number of accounts per shard.
    #[must_use]
    pub fn with_accounts_per_shard(mut self, accounts: usize) -> Self {
        self.accounts_per_shard = accounts;
        self
    }

    /// Set the initial balance for accounts.
    #[must_use]
    pub fn with_initial_balance(mut self, balance: Decimal) -> Self {
        self.initial_balance = balance;
        self
    }

    /// Set the workload configuration.
    #[must_use]
    pub fn with_workload(mut self, workload: WorkloadConfig) -> Self {
        self.workload = workload;
        self
    }

    /// Set the random seed.
    #[must_use]
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Total number of validators across all shards.
    #[must_use]
    pub fn total_validators(&self) -> u32 {
        self.num_shards * self.validators_per_shard
    }

    /// Total number of accounts across all shards.
    #[must_use]
    pub fn total_accounts(&self) -> usize {
        self.num_shards as usize * self.accounts_per_shard
    }

    /// Convert to a `NetworkConfig` for the underlying simulation.
    #[must_use]
    pub fn to_network_config(&self) -> NetworkConfig {
        NetworkConfig {
            num_shards: self.num_shards,
            validators_per_shard: self.validators_per_shard,
            ..Default::default()
        }
    }
}

impl Default for SimulatorConfig {
    fn default() -> Self {
        Self::new(2, 4)
    }
}

/// Workload configuration.
#[derive(Clone, Debug)]
pub struct WorkloadConfig {
    /// Ratio of transfer transactions (vs other types in future).
    /// 1.0 = all transfers.
    pub transfer_ratio: f64,

    /// Ratio of cross-shard transactions (vs same-shard).
    /// 1.0 = all cross-shard, 0.0 = all same-shard.
    pub cross_shard_ratio: f64,

    /// Number of transactions to generate per batch.
    pub batch_size: usize,

    /// Time between transaction batches (simulated time).
    pub batch_interval: Duration,

    /// Account selection mode.
    pub selection_mode: SelectionMode,
}

impl Default for WorkloadConfig {
    fn default() -> Self {
        Self {
            transfer_ratio: 1.0,
            cross_shard_ratio: 0.3,
            batch_size: 10,
            batch_interval: Duration::from_millis(500),
            selection_mode: SelectionMode::default(),
        }
    }
}

impl WorkloadConfig {
    /// Create a transfer-only workload.
    #[must_use]
    pub fn transfers_only() -> Self {
        Self {
            transfer_ratio: 1.0,
            ..Default::default()
        }
    }

    /// Set the cross-shard ratio.
    #[must_use]
    pub fn with_cross_shard_ratio(mut self, ratio: f64) -> Self {
        self.cross_shard_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    /// Set the batch size.
    #[must_use]
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Set the batch interval.
    #[must_use]
    pub fn with_batch_interval(mut self, interval: Duration) -> Self {
        self.batch_interval = interval;
        self
    }

    /// Set the account selection mode.
    #[must_use]
    pub fn with_selection_mode(mut self, mode: SelectionMode) -> Self {
        self.selection_mode = mode;
        self
    }

    /// Use round-robin account selection (minimal contention).
    #[must_use]
    pub fn with_round_robin(self) -> Self {
        self.with_selection_mode(SelectionMode::RoundRobin)
    }

    /// Use Zipf distribution for realistic hotspot patterns.
    #[must_use]
    pub fn with_zipf(self, exponent: f64) -> Self {
        self.with_selection_mode(SelectionMode::Zipf { exponent })
    }

    /// Use partitioned accounts for zero contention testing.
    #[must_use]
    pub fn with_no_contention(self) -> Self {
        self.with_selection_mode(SelectionMode::NoContention)
    }
}
