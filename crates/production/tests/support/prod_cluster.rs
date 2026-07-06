//! `ProdCluster`: the production adaptor implementing [`Cluster`].
//!
//! Wraps the real QUIC + `RocksDB` [`Harness`] driven on wall-clock. The harness
//! observations are synchronous, so each [`Cluster`] method delegates directly;
//! only [`Cluster::run_until`] needs the async bridge — it `block_on`s a poll
//! loop on an owned multi-thread runtime, the same cadence the harness's own
//! `await_*` helpers use. The runtime never leaks into a scenario body.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use hyperscale_engine::GenesisConfig;
use hyperscale_metrics::set_global_recorder;
use hyperscale_metrics_memory::MemoryRecorder;
use hyperscale_network_libp2p::fault::{DropSpec, HostId, RuleHandle};
use hyperscale_network_libp2p::test_utils::TestFixtures;
use hyperscale_production::LocalValidator;
use hyperscale_scenarios::query::status_rank;
use hyperscale_scenarios::tx::{merge_vote_payer, straddler_genesis_balances};
use hyperscale_scenarios::{
    Budget, Cluster, FaultHandle, FaultableCluster, ScenarioConfig, grow_to, vote_reshape_threshold,
};
use hyperscale_types::{
    BeaconChainConfig, BeaconState, BlockHeight, ReshapeThresholds, RoutableTransaction, ShardId,
    StateRoot, TransactionDecision, TransactionStatus, TxHash, ValidatorId,
};
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use tokio::runtime::{Builder, Runtime};
use tokio::time::{sleep, timeout};

use super::cluster::{Cluster as Harness, ClusterSpec, HostSpec};

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
        // Claim the global recorder before the runner installs its Prometheus one
        // (`set_global_recorder` is first-wins), so `metric()` reads node counters.
        // Every `ProdCluster` claims it, so all prod scenario tests — fault or
        // not — run on the in-memory recorder; only fault runs read it back.
        let _ = global_recorder();
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

/// The process-global in-memory recorder. Prod emissions fire on async tasks and
/// thread pools, so a thread-local scoped recorder would miss them — the global
/// recorder captures every host's counters. Installed once (`set_global_recorder`
/// is a `OnceLock`); each fault run `reset()`s it.
static RECORDER: OnceLock<MemoryRecorder> = OnceLock::new();

/// Install (once) and return the process-global in-memory recorder. Called
/// before the cluster starts so it wins the `set_global_recorder` `OnceLock`
/// ahead of the runner's Prometheus recorder — otherwise every metric read
/// would come back zero.
fn global_recorder() -> MemoryRecorder {
    RECORDER
        .get_or_init(|| {
            let recorder = MemoryRecorder::new();
            set_global_recorder(Box::new(recorder.clone()));
            recorder
        })
        .clone()
}

impl ProdCluster {
    /// Run a fault `scenario`: install and reset the global recorder so
    /// [`FaultableCluster::metric`] reads this run's counters, configure every
    /// host's fault gate, then drive the scenario. Mirrors
    /// `SimCluster::run_faultable`.
    ///
    /// The recorder is process-global, so this `reset()` clears counts across
    /// the whole process. Every fault scenario that reads metrics must run
    /// `#[serial]` — two concurrent runs would clobber each other's counters.
    pub fn run_faultable<R>(&mut self, scenario: impl FnOnce(&mut Self) -> R) -> R {
        global_recorder().reset();
        self.inner.fault_configure_all();
        scenario(self)
    }
}

impl FaultableCluster for ProdCluster {
    fn host_count(&self) -> usize {
        self.inner.host_count()
    }

    fn drop_type(&mut self, type_id: &'static str) -> FaultHandle {
        let handles = self.inner.fault_install_drop(&DropSpec {
            type_id: Some(type_id),
            ..DropSpec::default()
        });
        FaultHandle::new(move || handles.iter().map(RuleHandle::fired).sum())
    }

    fn drop_type_with_probability(
        &mut self,
        type_id: &'static str,
        probability: f64,
    ) -> FaultHandle {
        let handles = self.inner.fault_install_drop(&DropSpec {
            type_id: Some(type_id),
            probability: Some(probability),
            ..DropSpec::default()
        });
        FaultHandle::new(move || handles.iter().map(RuleHandle::fired).sum())
    }

    fn partition(&mut self, group_a: &[usize], group_b: &[usize]) {
        self.inner.fault_partition(group_a, group_b);
    }

    fn isolate(&mut self, host: usize) {
        self.inner.fault_isolate(host);
    }

    fn heal_between(&mut self, a: usize, b: usize) {
        self.inner.fault_heal_between(a, b);
    }

    fn heal_all(&mut self) {
        self.inner.fault_heal_all();
    }

    fn clear_drops(&mut self) {
        self.inner.fault_clear_all();
    }

    fn drop_type_between(
        &mut self,
        from: &[usize],
        to: &[usize],
        type_id: &'static str,
    ) -> FaultHandle {
        let mut handles = Vec::new();
        for &src in from {
            for &dst in to {
                if src == dst {
                    continue;
                }
                let from = u32::try_from(src).expect("host index fits u32");
                let to = u32::try_from(dst).expect("host index fits u32");
                handles.extend(self.inner.fault_install_drop(&DropSpec {
                    type_id: Some(type_id),
                    from: Some(HostId(from)),
                    to: Some(HostId(to)),
                    ..DropSpec::default()
                }));
            }
        }
        FaultHandle::new(move || handles.iter().map(RuleHandle::fired).sum())
    }

    fn committee_hosts(&self, shard: ShardId) -> Vec<usize> {
        self.inner.hosts_serving(shard)
    }

    fn host_committed_height(&self, host: usize, shard: ShardId) -> Option<BlockHeight> {
        self.inner
            .host_committed_height(host, shard)
            .map(BlockHeight::new)
    }

    fn host_committed_state_root(&self, host: usize, shard: ShardId) -> Option<StateRoot> {
        self.inner.host_committed_state_root(host, shard)
    }

    fn metric(&self, name: &'static str, label: Option<&str>) -> u64 {
        global_recorder().counter(name, label)
    }
}
