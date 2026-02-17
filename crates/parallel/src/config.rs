//! Configuration for parallel simulation.

use hyperscale_dispatch_pooled::ThreadPoolConfig;
use hyperscale_simulation::NetworkConfig;
use std::time::Duration;

/// Configuration for parallel simulation.
///
/// The parallel simulator processes nodes using rayon for CPU parallelism,
/// enabling multi-core utilization for performance testing.
///
/// Uses simulated time (not wall-clock time) so that:
/// - Timers fire based on simulated time (no wall-clock delays)
/// - Crypto verification is done synchronously inline
/// - Simulation runs as fast as the CPU can process
#[derive(Debug, Clone)]
pub struct ParallelConfig {
    /// Number of shards in the network.
    pub num_shards: usize,
    /// Number of validators per shard.
    pub validators_per_shard: usize,
    /// Random seed for key generation.
    pub seed: u64,
    /// Thread pool configuration (for crypto verification).
    pub thread_pools: ThreadPoolConfig,
    /// Network simulation configuration (latency, loss, partitions).
    pub network: NetworkConfig,
    /// Drain duration after submission ends (default 5s).
    /// Allows in-flight transactions to complete before collecting final metrics.
    pub drain_duration: Duration,
}

impl ParallelConfig {
    /// Create a new configuration with defaults.
    pub fn new(num_shards: usize, validators_per_shard: usize) -> Self {
        Self {
            num_shards,
            validators_per_shard,
            seed: 42,
            thread_pools: ThreadPoolConfig::auto(),
            network: NetworkConfig {
                num_shards: num_shards as u32,
                validators_per_shard: validators_per_shard as u32,
                ..NetworkConfig::default()
            },
            drain_duration: Duration::from_secs(5),
        }
    }

    /// Total number of nodes in the simulation.
    pub fn total_nodes(&self) -> usize {
        self.num_shards * self.validators_per_shard
    }

    /// Set network configuration.
    pub fn with_network(mut self, network: NetworkConfig) -> Self {
        self.network = network;
        self
    }

    /// Set drain duration.
    pub fn with_drain_duration(mut self, duration: Duration) -> Self {
        self.drain_duration = duration;
        self
    }

    /// Set the random seed.
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Set thread pool configuration.
    pub fn with_thread_pools(mut self, thread_pools: ThreadPoolConfig) -> Self {
        self.thread_pools = thread_pools;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_config() {
        let config = ParallelConfig::new(2, 4);
        assert_eq!(config.num_shards, 2);
        assert_eq!(config.validators_per_shard, 4);
        assert_eq!(config.total_nodes(), 8);
        assert_eq!(config.seed, 42);
    }

    #[test]
    fn test_builder_pattern() {
        let config = ParallelConfig::new(1, 4)
            .with_seed(123)
            .with_drain_duration(Duration::from_secs(10));

        assert_eq!(config.seed, 123);
        assert_eq!(config.drain_duration, Duration::from_secs(10));
    }
}
