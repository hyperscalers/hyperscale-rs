//! `ProdCluster`: the production adaptor implementing [`Cluster`].
//!
//! Wraps the real QUIC + `RocksDB` [`Harness`] driven on wall-clock. The harness
//! observations are synchronous, so each [`Cluster`] method delegates directly;
//! only [`Cluster::run_until`] needs the async bridge — it `block_on`s a poll
//! loop on an owned multi-thread runtime, the same cadence the harness's own
//! `await_*` helpers use. The runtime never leaks into a scenario body.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use hyperscale_engine::genesis::GenesisPackages;
use hyperscale_engine::{ExecutionMode, Executor, GenesisConfig};
use hyperscale_metrics::set_global_recorder;
use hyperscale_metrics_memory::MemoryRecorder;
use hyperscale_network_libp2p::fault::{DropSpec, HostId, RuleHandle};
use hyperscale_network_libp2p::test_utils::TestFixtures;
use hyperscale_production::LocalValidator;
use hyperscale_scenarios::query::{RanAs, status_rank};
use hyperscale_scenarios::tx::{staking_genesis_accounts, world_pools};
use hyperscale_scenarios::{
    Budget, Cluster, FaultHandle, FaultableCluster, ScenarioConfig, grow_to, submission_shards,
    vote_reshape_threshold,
};
use hyperscale_types::{
    BeaconChainConfig, BeaconState, BlockHeight, Derivation, NetworkDefinition, PrincipalAddr,
    ReshapeThresholds, ShardId, StateRoot, Transaction, TransactionDecision, TransactionStatus,
    TxHash, ValidatorId, WeightedTimestamp, WorkInFlight,
};
use tokio::runtime::{Builder, Runtime};
use tokio::time::{sleep, timeout};
use tracing_subscriber::{EnvFilter, fmt};

use super::harness::{ClusterSpec, Harness, HostSpec};

/// Poll cadence between predicate samples in `run_until`, matching the
/// harness's own `await_*` interval.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The full constructor input, so the knobs don't fan out across every
/// constructor's signature.
struct StartArgs<'a> {
    config: &'a ScenarioConfig,
    seed: u64,
    epoch_ms: u64,
    accounts: Vec<(PrincipalAddr, u128)>,
}

/// The production adaptor: a [`Cluster`] over the real QUIC + `RocksDB` harness.
pub struct ProdCluster {
    runtime: Runtime,
    inner: Harness,
    epoch_ms: u64,
    /// Wall-clock instant captured at genesis, the origin `now` measures from.
    started: Instant,
    /// A derivation over the same genesis the hosts run, for the routed
    /// facts the harness reads off a transaction it built itself. The
    /// hosts hold their own; this one answers alike for anything the
    /// chain has not sealed since.
    derivation: Arc<dyn Derivation>,
}

impl ProdCluster {
    /// Build and start a genesis cluster from `config`, seeded by `seed`, at
    /// `epoch_ms`. The seed drives the fixtures' deterministic keys and
    /// topology; reshape scenarios are seed-sensitive.
    #[must_use]
    pub fn start(config: &ScenarioConfig, seed: u64, epoch_ms: u64) -> Self {
        Self::start_with_accounts(config, seed, epoch_ms, Vec::new())
    }

    /// [`Self::start`] with funded accounts — the mirror of
    /// `SimCluster::with_accounts`, so the catalogue runs identically
    /// on both harnesses.
    #[must_use]
    pub fn start_with_accounts(
        config: &ScenarioConfig,
        seed: u64,
        epoch_ms: u64,
        accounts: Vec<(PrincipalAddr, u128)>,
    ) -> Self {
        Self::start_full(&StartArgs {
            config,
            seed,
            epoch_ms,
            accounts,
        })
    }

    fn start_full(args: &StartArgs<'_>) -> Self {
        // `RUST_LOG` steers per-crate levels when set (diagnosing a long
        // real-network run); the default stays plain info.
        let _ = fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .with_test_writer()
            .try_init();
        let runtime = Builder::new_multi_thread()
            .worker_threads(16)
            .enable_all()
            .build()
            .expect("tokio runtime");
        let spec = Self::spec(args);
        let epoch_ms = args.epoch_ms;
        // Claim the global recorder before the runner installs its Prometheus one
        // (`set_global_recorder` is first-wins), so `metric()` reads node counters.
        // Every `ProdCluster` claims it, so all prod scenario tests — fault or
        // not — run on the in-memory recorder; only fault runs read it back.
        let _ = global_recorder();
        let started = Instant::now();
        let inner = runtime.block_on(Harness::start(spec));
        let derivation = Executor::new(ExecutionMode::Serial).derivation();
        Self {
            runtime,
            inner,
            epoch_ms,
            started,
            derivation,
        }
    }

    /// Build a cluster grown to `config.num_shards` with `config.split_bytes`
    /// as the live reshape threshold, with `accounts` funded at the
    /// single ROOT genesis so the grow moves their cells to their prefix
    /// shards.
    ///
    /// Genesis is always a single ROOT shard, so a scenario that needs a
    /// deeper partition reaches it the only way the network does — by
    /// splitting into it, here via [`grow_to`]. The mirror of
    /// `SimCluster::with_grown_accounts`, so a scenario starts
    /// identically on both harnesses.
    #[must_use]
    pub fn start_with_grown_accounts(
        config: &ScenarioConfig,
        seed: u64,
        epoch_ms: u64,
        accounts: Vec<(PrincipalAddr, u128)>,
    ) -> Self {
        let grow_config = ScenarioConfig {
            split_bytes: 0,
            ..*config
        };
        let mut cluster = Self::start_with_accounts(&grow_config, seed, epoch_ms, accounts);
        grow_to(&mut cluster, config.num_shards);
        vote_reshape_threshold(&mut cluster, config.split_bytes);
        cluster
    }

    /// Translate the portable config into a production `ClusterSpec`. Genesis is
    /// always a single ROOT shard (a deeper partition is reached by growing): the
    /// committee is `shard_size` validators plus `pool_surplus`
    /// followers (the reshape cohort), chunked `vnodes_per_host` per host. At one
    /// vnode per host each validator lands on its own host, the layout the
    /// reshape flip needs (each seat its own store).
    fn spec(args: &StartArgs<'_>) -> ClusterSpec {
        let config = args.config;
        let fixtures =
            TestFixtures::with_surplus(args.seed, config.shard_size, config.pool_surplus);
        let total = config.shard_size + config.pool_surplus;
        let validators: Vec<LocalValidator> = (0..total)
            .map(|i| LocalValidator {
                validator_id: ValidatorId::new(u64::from(i)),
                signer: fixtures.signer(i),
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
                epoch_duration_ms: args.epoch_ms,
                shard_size: config.shard_size,
                reshape_thresholds: ReshapeThresholds {
                    split_bytes: config.split_bytes,
                },
                ..BeaconChainConfig::default()
            },
            // Match the simulation's genesis, so a scenario's accounts
            // behave identically on both harnesses. Every cluster funds
            // the pool operator and seats the pools: the founding pool's
            // vote is how any cluster retunes a network parameter.
            genesis_config: Some(GenesisConfig {
                accounts: args
                    .accounts
                    .iter()
                    .copied()
                    .chain(staking_genesis_accounts())
                    .collect(),
                pools: world_pools(),
                packages: GenesisPackages::protocol(),
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
    fn host_for_tx(&self, tx: &Transaction) -> Option<usize> {
        // The harness builds transactions outside every host, so nothing
        // has derived this one and routing is a derived fact.
        tx.try_derived(self.derivation.as_ref()).ok()?;
        let topology_snapshot = self
            .inner
            .beacon_state()?
            .derive_topology_snapshot(NetworkDefinition::simulator());
        submission_shards(&topology_snapshot, tx)
            .into_iter()
            .find_map(|shard| {
                self.inner
                    .host_serving_in(shard, topology_snapshot.committee_for_shard(shard))
                    .or_else(|| self.inner.host_serving(shard))
            })
    }
}

/// Drive the cluster to a clean shutdown, joining every host's runner task.
/// Running on drop rather than by explicit call means a scenario that panics
/// mid-run still tears its hosts down instead of leaking QUIC ports and
/// runner threads into the next `#[serial]` test.
impl Drop for ProdCluster {
    fn drop(&mut self) {
        self.runtime.block_on(self.inner.shutdown());
    }
}

impl Cluster for ProdCluster {
    fn derivation(&self) -> Arc<dyn Derivation> {
        Arc::clone(&self.derivation)
    }

    fn submit(&mut self, tx: Arc<Transaction>) {
        let host = self.host_for_tx(&tx).unwrap_or(0);
        self.inner.submit_transaction(host, tx);
    }

    fn vote_fold_budget_ms(&self) -> u64 {
        // Real QUIC pays wall-clock for every hop of the cast-to-fold cascade:
        // inclusion, the epoch-boundary crossing, and a beacon quorum
        // remote-syncing that crossing.
        240_000
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
        self.inner.committed_state_root(shard)
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

    fn chain_origin_anchor(&self, shard: ShardId) -> Option<WeightedTimestamp> {
        self.inner.chain_origin_anchor(shard)
    }

    fn committed_work_in_flight(&self, shard: ShardId) -> Option<WorkInFlight> {
        self.inner.committed_work_in_flight(shard)
    }

    fn ran(&self, shard: ShardId, tx: TxHash) -> Vec<RanAs> {
        self.inner.ran(shard, tx)
    }

    fn named_unsettled(&self, shard: ShardId, tx: TxHash) -> Vec<(BlockHeight, ShardId)> {
        self.inner.named_unsettled(shard, tx)
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
