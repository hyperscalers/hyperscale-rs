//! Configuration types for the spammer.

use std::time::Duration;

use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;

use crate::accounts::SelectionMode;

/// Configuration for the transaction spammer.
#[derive(Clone, Debug)]
pub struct SpammerConfig {
    /// Number of shards in the network.
    pub num_shards: u64,

    /// Number of validators per shard.
    /// Used to distribute load across multiple nodes in each shard.
    pub validators_per_shard: usize,

    /// Number of validators packed into each host process. Matches
    /// `launch-cluster.sh --vnodes-per-host`. Under same-shard packing the
    /// per-shard host count is `validators_per_shard / vnodes_per_host`,
    /// so each endpoint serves exactly one shard. Under cross-shard packing
    /// every endpoint serves every shard and this value is unused.
    pub vnodes_per_host: usize,

    /// True iff hosts run one vnode from each shard (the
    /// `launch-cluster.sh --cross-shard-pack` layout). Routing then ignores
    /// the per-shard endpoint partition because every host is reachable for
    /// every shard.
    pub cross_shard_pack: bool,

    /// RPC endpoints. Indexed in host order. Under same-shard packing
    /// endpoints are flat-grouped by shard:
    /// `[shard0_host0, shard0_host1, …, shard1_host0, …]`. Under
    /// cross-shard packing every endpoint serves every shard.
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

    /// Timeout for waiting for in-flight transactions to complete after spammer stops.
    pub latency_finalization_timeout: Duration,

    /// Number of worker threads for parallel submission.
    /// Each worker gets its own partition of accounts.
    pub num_workers: usize,
}

impl Default for SpammerConfig {
    fn default() -> Self {
        Self {
            num_shards: 2,
            validators_per_shard: 1,
            vnodes_per_host: 1,
            cross_shard_pack: false,
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
            latency_finalization_timeout: Duration::from_secs(30),
            num_workers: 1,
        }
    }
}

impl SpammerConfig {
    /// Create a new configuration with the given endpoints.
    #[must_use]
    pub fn new(endpoints: Vec<String>) -> Self {
        Self {
            rpc_endpoints: endpoints,
            ..Default::default()
        }
    }

    /// Set the number of shards.
    #[must_use]
    pub const fn with_num_shards(mut self, num_shards: u64) -> Self {
        self.num_shards = num_shards;
        self
    }

    /// Set the number of validators per shard.
    #[must_use]
    pub fn with_validators_per_shard(mut self, validators: usize) -> Self {
        self.validators_per_shard = validators.max(1);
        self
    }

    /// Set the number of vnodes bundled into each host process.
    #[must_use]
    pub fn with_vnodes_per_host(mut self, vnodes: usize) -> Self {
        self.vnodes_per_host = vnodes.max(1);
        self
    }

    /// Toggle cross-shard packing (one vnode from each shard per host).
    #[must_use]
    pub const fn with_cross_shard_pack(mut self, pack: bool) -> Self {
        self.cross_shard_pack = pack;
        self
    }

    /// Build the standalone [`EndpointRouting`] policy implied by this
    /// config. Held by spammer workers so they can pick endpoints without
    /// carrying the whole config.
    #[must_use]
    pub fn routing(&self) -> EndpointRouting {
        EndpointRouting::from_config(self)
    }

    /// Return the `[base, end)` range of `rpc_endpoints` indices that serve
    /// `shard`. Convenience wrapper around [`EndpointRouting`].
    #[must_use]
    pub fn endpoint_range_for_shard(&self, shard: usize) -> std::ops::Range<usize> {
        self.routing().range_for_shard(shard)
    }

    /// Set accounts per shard.
    #[must_use]
    pub const fn with_accounts_per_shard(mut self, accounts: usize) -> Self {
        self.accounts_per_shard = accounts;
        self
    }

    /// Set target TPS.
    #[must_use]
    pub const fn with_target_tps(mut self, tps: u64) -> Self {
        self.target_tps = tps;
        self
    }

    /// Set cross-shard ratio.
    #[must_use]
    pub const fn with_cross_shard_ratio(mut self, ratio: f64) -> Self {
        self.cross_shard_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    /// Set selection mode.
    #[must_use]
    pub const fn with_selection_mode(mut self, mode: SelectionMode) -> Self {
        self.selection_mode = mode;
        self
    }

    /// Set initial balance.
    #[must_use]
    pub const fn with_initial_balance(mut self, balance: Decimal) -> Self {
        self.initial_balance = balance;
        self
    }

    /// Set network definition.
    #[must_use]
    pub fn with_network(mut self, network: NetworkDefinition) -> Self {
        self.network = network;
        self
    }

    /// Set batch size.
    #[must_use]
    pub const fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Enable or disable latency tracking.
    #[must_use]
    pub const fn with_latency_tracking(mut self, enabled: bool) -> Self {
        self.latency_tracking = enabled;
        self
    }

    /// Set the sample rate for latency tracking (0.0 to 1.0).
    #[must_use]
    pub const fn with_latency_sample_rate(mut self, rate: f64) -> Self {
        self.latency_sample_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Set the poll interval for latency tracking.
    #[must_use]
    pub const fn with_latency_poll_interval(mut self, interval: Duration) -> Self {
        self.latency_poll_interval = interval;
        self
    }

    /// Set the finalization timeout for latency tracking.
    #[must_use]
    pub const fn with_latency_finalization_timeout(mut self, timeout: Duration) -> Self {
        self.latency_finalization_timeout = timeout;
        self
    }

    /// Set the number of worker threads for parallel submission.
    #[must_use]
    pub fn with_num_workers(mut self, num_workers: usize) -> Self {
        self.num_workers = num_workers.max(1);
        self
    }

    /// Calculate the sleep duration between batches to achieve target TPS.
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    // Heuristic for human-friendly TPS pacing; precision/sign aren't material.
    pub fn batch_interval(&self) -> Duration {
        if self.target_tps == 0 || self.batch_size == 0 {
            return Duration::from_millis(100);
        }
        let batches_per_sec = self.target_tps as f64 / self.batch_size as f64;
        let interval_ms = (1000.0 / batches_per_sec) as u64;
        Duration::from_millis(interval_ms.max(1))
    }

    /// Validate the configuration.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] if RPC endpoints are missing, shard count is
    /// zero, or per-shard account count is zero.
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
        if self.vnodes_per_host == 0 {
            return Err(ConfigError::InvalidVnodesPerHost);
        }
        if !self
            .validators_per_shard
            .is_multiple_of(self.vnodes_per_host)
        {
            return Err(ConfigError::VnodesPerHostDoesNotDivide {
                vnodes_per_host: self.vnodes_per_host,
                validators_per_shard: self.validators_per_shard,
            });
        }
        let expected_hosts = if self.cross_shard_pack {
            self.validators_per_shard
        } else {
            let hosts_per_shard = self.validators_per_shard / self.vnodes_per_host;
            usize::try_from(self.num_shards).unwrap_or(usize::MAX) * hosts_per_shard
        };
        if self.rpc_endpoints.len() != expected_hosts {
            return Err(ConfigError::EndpointCountMismatch {
                got: self.rpc_endpoints.len(),
                expected: expected_hosts,
            });
        }
        Ok(())
    }
}

/// Routing policy used to pick which endpoint to send a shard-X transaction
/// to. Standalone Clone struct so workers can hold a copy without keeping
/// the whole [`SpammerConfig`] around.
#[derive(Clone, Debug)]
pub struct EndpointRouting {
    cross_shard_pack: bool,
    hosts_per_shard: usize,
    total_endpoints: usize,
}

impl EndpointRouting {
    /// Derive the policy from a [`SpammerConfig`].
    #[must_use]
    pub fn from_config(cfg: &SpammerConfig) -> Self {
        let hosts_per_shard = if cfg.cross_shard_pack {
            0
        } else {
            (cfg.validators_per_shard / cfg.vnodes_per_host.max(1)).max(1)
        };
        Self {
            cross_shard_pack: cfg.cross_shard_pack,
            hosts_per_shard,
            total_endpoints: cfg.rpc_endpoints.len(),
        }
    }

    /// `[base, end)` slice of `rpc_endpoints` that serves `shard`.
    #[must_use]
    pub const fn range_for_shard(&self, shard: usize) -> std::ops::Range<usize> {
        if self.cross_shard_pack {
            0..self.total_endpoints
        } else {
            let base = shard * self.hosts_per_shard;
            base..base + self.hosts_per_shard
        }
    }
}

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// No RPC endpoints were configured.
    #[error("No RPC endpoints configured")]
    NoEndpoints,

    /// Configured `num_shards` is zero.
    #[error("Number of shards must be greater than 0")]
    InvalidShards,

    /// Configured `accounts_per_shard` is zero.
    #[error("Accounts per shard must be greater than 0")]
    InvalidAccounts,

    /// Configured `vnodes_per_host` is zero.
    #[error("Vnodes per host must be greater than 0")]
    InvalidVnodesPerHost,

    /// `vnodes_per_host` doesn't evenly divide `validators_per_shard`,
    /// so same-shard hosts can't be enumerated cleanly.
    #[error(
        "vnodes_per_host ({vnodes_per_host}) must divide validators_per_shard ({validators_per_shard})"
    )]
    VnodesPerHostDoesNotDivide {
        /// Configured `vnodes_per_host`.
        vnodes_per_host: usize,
        /// Configured `validators_per_shard`.
        validators_per_shard: usize,
    },

    /// The number of supplied endpoints doesn't match the host count
    /// implied by `(num_shards, validators_per_shard, vnodes_per_host,
    /// cross_shard_pack)`. Without one endpoint per host the per-shard
    /// routing can't pick the right target.
    #[error("Expected {expected} endpoints (one per host) but got {got}")]
    EndpointCountMismatch {
        /// Number of endpoints supplied.
        got: usize,
        /// Number of endpoints expected.
        expected: usize,
    },
}
