//! The portable [`ScenarioConfig`]: the harness-agnostic knobs a scenario sets.

use std::time::Duration;

/// Portable cluster configuration.
///
/// Each adaptor translates this into its harness's native config — the sim's
/// `SimConfig`, production's `ClusterSpec` over `TestFixtures` — deriving
/// identical keys and topology from one seed. The fields are the knobs
/// scenarios actually vary.
///
/// `split_bytes` is the lever that makes reshape scenarios portable: a scenario
/// arms an *organic* split by setting it to `0` and then awaits the children to
/// be served, rather than calling a harness-only `grow_to` command. `u64::MAX`
/// disarms resharding entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScenarioConfig {
    /// Committee validators per shard.
    pub validators_per_shard: u32,
    /// Vnodes hosted per physical host.
    pub vnodes_per_host: u32,
    /// Spare validators beyond the seated committees — the observer/keeper stock.
    pub pool_surplus: u32,
    /// Genesis shard count.
    pub num_shards: u64,
    /// Substate-byte split threshold: `0` arms a split at once, `u64::MAX` never.
    pub split_bytes: u64,
    /// Base inter-host latency.
    pub latency: Duration,
    /// Whether each pool extra seats on its own host (shuffle/flip layouts).
    pub dedicated_hosts: bool,
}
