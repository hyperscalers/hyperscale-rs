//! `ProdCluster`: the production adaptor implementing [`Cluster`].
//!
//! Wraps the real QUIC + `RocksDB` [`Harness`] driven on wall-clock. The harness
//! observations are synchronous, so each [`Cluster`] method delegates directly;
//! only [`Cluster::run_until`] needs the async bridge — it `block_on`s a poll
//! loop on an owned multi-thread runtime, the same cadence the harness's own
//! `await_*` helpers use. The runtime never leaks into a scenario body.

use std::sync::Arc;
use std::time::{Duration, Instant};

use hyperscale_engine::GenesisConfig;
use hyperscale_production::LocalValidator;
use hyperscale_scenarios::tx::{merge_vote_payer, straddler_genesis_balances};
use hyperscale_scenarios::{Budget, Cluster, ScenarioConfig, grow_to, vote_reshape_threshold};
use hyperscale_test_helpers::fixtures::TestFixtures;
use hyperscale_types::{
    BeaconChainConfig, BeaconState, BlockHeight, ReshapeThresholds, RoutableTransaction, ShardId,
    StateRoot, TransactionDecision, TransactionStatus, TxHash, ValidatorId,
};
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use tokio::runtime::{Builder, Runtime};
use tokio::time::{sleep, timeout};

use crate::cluster::{Cluster as Harness, ClusterSpec, HostSpec};

/// Poll cadence between predicate samples in `run_until`, matching the
/// harness's own `await_*` interval.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The production adaptor: a [`Cluster`] over the real QUIC + `RocksDB` harness.
pub struct ProdCluster {
    runtime: Runtime,
    inner: Harness,
    epoch_ms: u64,
    /// Wall-clock instant captured at genesis, the origin `now` measures from.
    started: Instant,
}

impl ProdCluster {
    /// Build and start a genesis cluster from `config`, seeded by `seed`, at
    /// `epoch_ms`. The seed drives the fixtures' deterministic keys and
    /// topology; reshape scenarios are seed-sensitive.
    #[must_use]
    pub fn start(config: &ScenarioConfig, seed: u64, epoch_ms: u64) -> Self {
        Self::start_with_balances(config, seed, epoch_ms, straddler_genesis_balances())
    }

    /// Build and start a genesis cluster funding `balances` instead of the
    /// default straddler accounts — for scenarios that seat their own genesis
    /// distribution (a byte-skewed split-straddler topology). The simulation
    /// installs the identical balances.
    #[must_use]
    pub fn start_with_balances(
        config: &ScenarioConfig,
        seed: u64,
        epoch_ms: u64,
        balances: Vec<(ComponentAddress, Decimal)>,
    ) -> Self {
        let runtime = Builder::new_multi_thread()
            .worker_threads(16)
            .enable_all()
            .build()
            .expect("tokio runtime");
        let spec = Self::spec(config, seed, epoch_ms, balances);
        let started = Instant::now();
        let inner = runtime.block_on(Harness::start(spec));
        Self {
            runtime,
            inner,
            epoch_ms,
            started,
        }
    }

    /// Build a cluster grown to `config.num_shards` with `config.split_bytes` as
    /// the live reshape threshold. Genesis is always a single ROOT shard, so a
    /// scenario that needs a deeper partition reaches it the only way the network
    /// does — by splitting into it, here via [`grow_to`]. The mirror of
    /// `SimCluster::with_grown_balances`, so a scenario starts identically on both
    /// harnesses.
    #[must_use]
    pub fn with_grown_balances(
        config: &ScenarioConfig,
        seed: u64,
        epoch_ms: u64,
        balances: Vec<(ComponentAddress, Decimal)>,
    ) -> Self {
        let grow_config = ScenarioConfig {
            split_bytes: 0,
            ..*config
        };
        let mut cluster = Self::start_with_balances(&grow_config, seed, epoch_ms, balances);
        grow_to(&mut cluster, config.num_shards);
        vote_reshape_threshold(&mut cluster, &merge_vote_payer(), config.split_bytes);
        cluster
    }

    /// Drive the cluster to a clean shutdown, joining every host's runner task.
    pub fn shutdown(self) {
        let Self { runtime, inner, .. } = self;
        runtime.block_on(inner.shutdown());
    }

    /// Translate the portable config into a production `ClusterSpec`. Genesis is
    /// always a single ROOT shard (a deeper partition is reached by growing): the
    /// committee is `shard_size` validators plus `pool_surplus`
    /// followers (the reshape cohort), chunked `vnodes_per_host` per host. At one
    /// vnode per host each validator lands on its own host, the layout the
    /// reshape flip needs (each seat its own store).
    fn spec(
        config: &ScenarioConfig,
        seed: u64,
        epoch_ms: u64,
        balances: Vec<(ComponentAddress, Decimal)>,
    ) -> ClusterSpec {
        let fixtures = TestFixtures::with_surplus(seed, config.shard_size, config.pool_surplus);
        let total = config.shard_size + config.pool_surplus;
        let validators: Vec<LocalValidator> = (0..total)
            .map(|i| LocalValidator {
                validator_id: ValidatorId::new(u64::from(i)),
                signing_key: fixtures.signing_key(i),
            })
            .collect();
        let group = config.vnodes_per_host.max(1) as usize;
        let hosts: Vec<HostSpec> = validators
            .chunks(group)
            .map(|chunk| HostSpec::new(chunk.to_vec()))
            .collect();
        ClusterSpec {
            genesis: fixtures.genesis_validators(),
            hosts,
            beacon_chain_config: BeaconChainConfig {
                epoch_duration_ms: epoch_ms,
                // Genesis is always a single ROOT shard; `config.num_shards` is
                // the target `with_grown_balances` pre-grows to, not a width.
                num_shards: 1,
                shard_size: config.shard_size,
                reshape_thresholds: ReshapeThresholds {
                    split_bytes: config.split_bytes,
                },
                ..BeaconChainConfig::default()
            },
            // Match the simulation's engine genesis: a funded faucet (100B XRD)
            // plus a funded account in each child span of the first split, so
            // both a faucet-funded transfer and the cross-shard scenarios behave
            // identically on both harnesses. The production default leaves the
            // faucet empty and seeds no accounts.
            genesis_config: Some(GenesisConfig {
                xrd_balances: balances,
                ..GenesisConfig::test_default()
            }),
            simulated_outbound_latency: config.latency,
        }
    }

    /// A host serving any shard `tx` touches, for submission routing.
    ///
    /// Resolves each touched node against the live partition derived from the
    /// latest committed beacon state — post-split the genesis `num_shards` no
    /// longer routes, since the live shards are the split children. Submitting
    /// through a host that serves a touched shard admits the transaction
    /// directly rather than relying on a gossip hop. The network only governs
    /// address encoding, not shard routing, so any definition resolves the same
    /// shards.
    fn host_for_tx(&self, tx: &RoutableTransaction) -> Option<usize> {
        let topology_snapshot = self
            .inner
            .beacon_state()?
            .derive_topology_snapshot(NetworkDefinition::simulator());
        tx.all_declared_nodes()
            .map(|node| topology_snapshot.shard_for_node_id(node))
            .find_map(|shard| self.inner.host_serving(shard))
    }
}

/// Rank a status so the cluster-wide view takes the most advanced observation.
const fn status_rank(status: &TransactionStatus) -> u8 {
    match status {
        TransactionStatus::Pending => 0,
        TransactionStatus::Committed(_) => 1,
        TransactionStatus::Completed(_) => 2,
    }
}

impl Cluster for ProdCluster {
    fn submit(&mut self, tx: Arc<RoutableTransaction>) {
        let host = self.host_for_tx(&tx).unwrap_or(0);
        self.inner.submit_transaction(host, tx);
    }

    fn run_until(&mut self, budget: Budget, cond: impl Fn(&Self) -> bool) -> bool {
        let within = Duration::from_millis(self.epoch_ms) * budget.0;
        self.runtime.block_on(async {
            timeout(within, async {
                while !cond(self) {
                    sleep(POLL_INTERVAL).await;
                }
            })
            .await
            .is_ok()
        })
    }

    fn now(&self) -> Duration {
        self.started.elapsed()
    }

    fn committed_height(&self, shard: ShardId) -> Option<BlockHeight> {
        self.inner.committed_height(shard).map(BlockHeight::new)
    }

    fn committed_state_root(&self, shard: ShardId) -> Option<StateRoot> {
        self.inner.committed_state_root_raw(shard)
    }

    fn serves_shard(&self, shard: ShardId) -> bool {
        self.inner.any_host_serves(shard)
    }

    fn beacon_state(&self) -> Option<Arc<BeaconState>> {
        self.inner.beacon_state()
    }

    fn tx_status(&self, tx: TxHash) -> Option<TransactionStatus> {
        (0..self.inner.host_count())
            .filter_map(|idx| self.inner.tx_status(idx, &tx))
            .max_by_key(status_rank)
    }

    fn chain_fate(
        &self,
        shard: ShardId,
        tx: TxHash,
    ) -> (
        Option<BlockHeight>,
        Option<(BlockHeight, TransactionDecision)>,
    ) {
        self.inner.chain_fate(shard, tx)
    }
}
