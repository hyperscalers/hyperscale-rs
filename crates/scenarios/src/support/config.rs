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
/// be served. The portable [`grow_to`](crate::grow_to) combinator builds on this
/// to grow a single-shard genesis to a deeper partition on either harness;
/// `u64::MAX` disarms resharding entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScenarioConfig {
    /// Committee size each shard maintains — the per-shard committee count the
    /// beacon preserves as the single ROOT genesis grows to `num_shards`, not a
    /// genesis-only total. At genesis its lone shard has `shard_size` members.
    pub shard_size: u32,
    /// Vnodes hosted per physical host.
    pub vnodes_per_host: u32,
    /// Spare validators beyond the seated committees — the observer/keeper stock.
    pub pool_surplus: u32,
    /// The shard count `with_grown_balances` pre-grows to before the scenario
    /// runs, walking `log2(num_shards)` split generations to reach it (must be a
    /// power of two). Genesis is always a single ROOT shard, so the flat-genesis
    /// constructors (`new`/`with_balances`/`start`) ignore this field.
    pub num_shards: u32,
    /// Substate-byte split threshold: `0` arms a split at once, `u64::MAX` never.
    pub split_bytes: u64,
    /// Base inter-host latency.
    pub latency: Duration,
}
