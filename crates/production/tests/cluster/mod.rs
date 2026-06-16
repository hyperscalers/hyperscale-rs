//! Multi-host production cluster harness for the reshape e2e suite.
//!
//! Spins up an N-host localhost-QUIC cluster on real `RocksDbShardStorage`
//! and a real beacon chain, bootstrap-peers the hosts to host 0, drives
//! real consensus, and exposes poll-with-timeout observation hooks:
//! `local_shards` (the shards a host serves), per-shard committed height
//! (the RPC status `block_height`), and the committed beacon epoch (read
//! straight from each host's beacon store). Reshape scenarios drive this
//! harness instead of injecting `ShardCommand`s, so the production
//! beacon-fold → duty → flip chain runs end to end.
//!
//! These are real-time tests: there is no logical clock. Callers set a
//! small `epoch_duration_ms`, mark `#[serial]`, and assert against the
//! `await_*` helpers — never fixed sleeps.

// Shared harness consumed piecemeal across reshape test binaries; each
// compiles its own copy and exercises a different subset.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use hex::encode as hex_encode;
use hyperscale_engine::GenesisConfig;
use hyperscale_network_libp2p::{Libp2pAdapter, Libp2pConfig};
use hyperscale_production::rpc::NodeStatusState;
use hyperscale_production::{
    ProductionRunner, RunnerError, ShutdownHandle, StorageDirResolver, StorageFactory, VnodeConfig,
};
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BeaconChainReader, BeaconStorage};
use hyperscale_storage_rocksdb::{RocksDbBeaconStorage, RocksDbShardStorage};
use hyperscale_types::{
    BeaconChainConfig, BeaconState, Epoch, PendingReshape, ShardId, TopologySnapshot,
    shard_prefix_path,
};
use libp2p::Multiaddr;
use tempfile::TempDir;
use tokio::task::{JoinHandle, spawn};
use tokio::time::{sleep, timeout};

/// How long to wait for host 0 to surface a listen address before
/// bootstrapping the rest of the cluster to it.
const LISTEN_ADDR_TIMEOUT: Duration = Duration::from_secs(5);

/// Cadence for the `await_*` observation polls.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Graceful-shutdown budget per host on teardown.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Storage-directory resolver rooted in a host's temp dir, mirroring the
/// validator binary's `shard-d{depth}p{path}` data-dir convention.
pub fn temp_storage_dir(dir: &TempDir) -> StorageDirResolver {
    let root = dir.path().to_path_buf();
    Arc::new(move |shard: ShardId| root.join(format!("shard-d{}p{}", shard.depth(), shard.path())))
}

/// Storage factory rooted in a host's temp dir, opening a fresh
/// `RocksDbShardStorage` for any shard the supervisor joins at runtime
/// (the split children / merged parent of a reshape).
pub fn temp_storage_factory(dir: &TempDir) -> StorageFactory {
    let resolve = temp_storage_dir(dir);
    Arc::new(move |shard: ShardId| {
        RocksDbShardStorage::open(resolve(shard), shard_prefix_path(shard))
            .map(Arc::new)
            .map_err(|e| format!("{e:?}"))
    })
}

/// One host's seating: the vnodes it runs. The hosted shard set is
/// derived from the vnodes' `local_shard`s.
pub struct HostSpec {
    pub vnodes: Vec<VnodeConfig>,
}

impl HostSpec {
    /// A host running exactly the given vnodes.
    pub const fn new(vnodes: Vec<VnodeConfig>) -> Self {
        Self { vnodes }
    }
}

/// Inputs for [`Cluster::start`].
pub struct ClusterSpec {
    /// Identity-agnostic snapshot shared across every host and vnode.
    pub topology: Arc<TopologySnapshot>,
    /// Per-host seating; host 0 is the bootstrap peer for the rest.
    pub hosts: Vec<HostSpec>,
    /// Beacon sizing knobs — small `epoch_duration_ms` for real-time
    /// tests, and the reshape `split_bytes` when a scenario enables a
    /// trigger.
    pub beacon_chain_config: BeaconChainConfig,
    /// Genesis balances routed per shard; `None` installs the default
    /// production genesis (the liveness baseline needs no funded
    /// accounts).
    pub genesis_config: Option<GenesisConfig>,
}

/// A running host: its network adapter, RPC status slot, beacon store,
/// and the handles to shut it down and join its runner task.
struct Host {
    adapter: Arc<Libp2pAdapter>,
    rpc_status: Arc<ArcSwap<NodeStatusState>>,
    beacon_storage: Arc<RocksDbBeaconStorage>,
    shutdown: Option<ShutdownHandle>,
    join: JoinHandle<Result<(), RunnerError>>,
}

/// A running multi-host production cluster.
pub struct Cluster {
    hosts: Vec<Host>,
    // Temp dirs kept alive for the cluster's lifetime; the on-disk stores
    // are deleted only when the cluster (and these) drop.
    _temp_dirs: Vec<TempDir>,
}

impl Cluster {
    /// Build and start the cluster: open per-host stores, build runners,
    /// bootstrap-peer the hosts to host 0, and spawn every runner. The
    /// adapters peer during the build; consensus starts when the runners
    /// are spawned.
    pub async fn start(spec: ClusterSpec) -> Self {
        let ClusterSpec {
            topology,
            hosts,
            beacon_chain_config,
            genesis_config,
        } = spec;
        assert!(!hosts.is_empty(), "cluster needs at least one host");

        // Anchor the consensus clock for every host to one shared genesis
        // instant captured now, so weighted-time and the beacon epoch clock
        // start near zero (epoch 0) instead of ~1.7e12 ms into the Unix
        // epoch. All hosts subtracting the same offset keeps their relative
        // clocks consistent.
        let mut chain_config = beacon_chain_config;
        chain_config.genesis_timestamp_ms = now_millis();

        let mut temp_dirs = Vec::with_capacity(hosts.len());
        let mut built = Vec::with_capacity(hosts.len());

        // Build host 0 first so the rest can bootstrap to its address.
        let mut bootstrap_addr: Option<Multiaddr> = None;
        for (idx, host) in hosts.into_iter().enumerate() {
            let temp_dir = TempDir::new().expect("temp dir");
            let bootstrap_peers: Vec<Multiaddr> = bootstrap_addr.iter().cloned().collect();
            let built_host = build_host(BuildHostArgs {
                temp_dir: &temp_dir,
                topology: &topology,
                vnodes: host.vnodes,
                beacon_chain_config: chain_config,
                genesis_config: genesis_config.clone(),
                bootstrap_peers,
            });
            if idx == 0 {
                bootstrap_addr = Some(wait_for_listen_addr(&built_host.adapter).await);
            }
            temp_dirs.push(temp_dir);
            built.push(built_host);
        }

        // Spawn every runner now that all adapters are peering.
        let mut running = Vec::with_capacity(built.len());
        for mut bh in built {
            let shutdown = bh.runner.shutdown_handle().expect("shutdown handle");
            let join = spawn(bh.runner.run());
            running.push(Host {
                adapter: bh.adapter,
                rpc_status: bh.rpc_status,
                beacon_storage: bh.beacon_storage,
                shutdown: Some(shutdown),
                join,
            });
        }

        Self {
            hosts: running,
            _temp_dirs: temp_dirs,
        }
    }

    /// Number of hosts in the cluster.
    pub const fn host_count(&self) -> usize {
        self.hosts.len()
    }

    /// The shards host `idx` currently serves (children of a split / the
    /// merged parent appear here once the flip seats them).
    pub fn local_shards(&self, idx: usize) -> Arc<HashSet<ShardId>> {
        self.hosts[idx].adapter.local_shards()
    }

    /// Highest committed height observed for `shard` across all hosts'
    /// RPC status (`block_height`). `None` until some host reports a
    /// vnode in `shard`.
    pub fn committed_height(&self, shard: ShardId) -> Option<u64> {
        let key = shard.inner();
        self.hosts
            .iter()
            .flat_map(|h| {
                h.rpc_status
                    .load()
                    .vnodes
                    .iter()
                    .filter(|v| v.shard == key)
                    .map(|v| v.block_height)
                    .collect::<Vec<_>>()
            })
            .max()
    }

    /// The hex-encoded committed JMT root observed for `shard` across all
    /// hosts' RPC status (`state_root_hash`). All committee members converge
    /// on the same root, so any one host's entry suffices; `None` until some
    /// host reports a vnode in `shard`.
    pub fn committed_state_root(&self, shard: ShardId) -> Option<String> {
        let key = shard.inner();
        self.hosts.iter().find_map(|h| {
            h.rpc_status
                .load()
                .vnodes
                .iter()
                .find(|v| v.shard == key)
                .map(|v| v.state_root_hash.clone())
        })
    }

    /// Whether any host in the cluster currently serves `shard` — the
    /// "the reshape seated this shard" signal (a split's children, the
    /// merged parent).
    pub fn any_host_serves(&self, shard: ShardId) -> bool {
        self.hosts
            .iter()
            .any(|h| h.adapter.local_shards().contains(&shard))
    }

    /// The latest committed beacon state across all hosts (highest epoch) —
    /// the source of truth for `pending_reshapes` (a split's admitted
    /// cohort) and `boundaries` (the beacon-composed per-shard anchor a
    /// flip must reproduce).
    pub fn beacon_state(&self) -> Option<Arc<BeaconState>> {
        self.hosts
            .iter()
            .filter_map(|h| h.beacon_storage.latest_committed())
            .max_by_key(|(_, state)| state.current_epoch)
            .map(|(_, state)| state)
    }

    /// Wait until any host serves `shard`. Panics on timeout.
    pub async fn await_any_host_serves(&self, shard: ShardId, within: Duration) {
        self.poll(within, || self.any_host_serves(shard).then_some(()))
            .await
            .unwrap_or_else(|| panic!("no host served {shard:?} within {within:?}"));
    }

    /// Whether the beacon has admitted a split for `parent` — a pending
    /// `Split` record carrying the drawn observer cohort.
    pub fn split_admitted(&self, parent: ShardId) -> bool {
        self.beacon_state().is_some_and(|state| {
            matches!(
                state.pending_reshapes.get(&parent),
                Some(PendingReshape::Split { .. })
            )
        })
    }

    /// Wait until the beacon admits a split for `parent`. Panics on timeout.
    pub async fn await_split_admitted(&self, parent: ShardId, within: Duration) {
        self.poll(within, || self.split_admitted(parent).then_some(()))
            .await
            .unwrap_or_else(|| panic!("split for {parent:?} not admitted within {within:?}"));
    }

    /// The beacon-composed anchor root for `shard` (hex of the
    /// `boundaries` `state_root`), to compare against a flipped shard's
    /// committed root.
    pub fn anchor_root(&self, shard: ShardId) -> Option<String> {
        self.beacon_state().and_then(|state| {
            state
                .boundaries
                .get(&shard)
                .map(|b| hex_encode(b.state_root.as_bytes()))
        })
    }

    /// Wait until `shard`'s committed root matches the beacon-composed
    /// anchor — the subtree-root-continuity check a flip must satisfy. The
    /// adopted child seats at the composed root, so the two agree at the
    /// child's genesis. Panics on timeout.
    pub async fn await_root_matches_anchor(&self, shard: ShardId, within: Duration) {
        self.poll(within, || {
            let committed = self.committed_state_root(shard)?;
            let anchor = self.anchor_root(shard)?;
            (committed == anchor).then_some(())
        })
        .await
        .unwrap_or_else(|| {
            panic!(
                "{shard:?} committed root never matched the anchor within {within:?}; \
                 committed = {:?}, anchor = {:?}",
                self.committed_state_root(shard),
                self.anchor_root(shard),
            )
        });
    }

    /// Assert `shard`'s committed height does not change over `window` —
    /// the "this shard stopped" signal (a terminated split parent). Unlike
    /// the `await_*` helpers this is a confirm-no-change check, so it sleeps
    /// the full window rather than polling for a condition.
    pub async fn assert_height_frozen(&self, shard: ShardId, window: Duration) {
        let before = self.committed_height(shard);
        sleep(window).await;
        let after = self.committed_height(shard);
        assert_eq!(
            before, after,
            "{shard:?} height changed from {before:?} to {after:?} over {window:?}; expected frozen"
        );
    }

    /// Wait for `shard` to report a committed height and then advance past
    /// it — proof the seated store + committee commit blocks. Returns the
    /// advanced height. Panics on timeout.
    pub async fn await_height_advances(&self, shard: ShardId, within: Duration) -> u64 {
        let baseline = self
            .poll(within, || self.committed_height(shard))
            .await
            .unwrap_or_else(|| panic!("{shard:?} reported no committed height within {within:?}"));
        self.poll(within, || {
            self.committed_height(shard).filter(|h| *h > baseline)
        })
        .await
        .unwrap_or_else(|| {
            panic!("{shard:?} height did not advance past {baseline} within {within:?}")
        })
    }

    /// Highest committed beacon epoch across all hosts' beacon stores.
    pub fn beacon_epoch(&self) -> Option<u64> {
        self.hosts
            .iter()
            .filter_map(|h| h.beacon_storage.latest_committed_epoch())
            .map(Epoch::inner)
            .max()
    }

    /// Wait until the committed beacon epoch reaches `target`, returning
    /// the observed epoch. Panics on timeout.
    pub async fn await_beacon_epoch(&self, target: u64, within: Duration) -> u64 {
        self.poll(within, || self.beacon_epoch().filter(|e| *e >= target))
            .await
            .unwrap_or_else(|| {
                panic!(
                    "beacon did not reach epoch {target} within {within:?}; latest = {:?}",
                    self.beacon_epoch()
                )
            })
    }

    /// Wait until `shard`'s committed height reaches `target`, returning
    /// the observed height. Panics on timeout.
    pub async fn await_committed_height(
        &self,
        shard: ShardId,
        target: u64,
        within: Duration,
    ) -> u64 {
        self.poll(within, || {
            self.committed_height(shard).filter(|h| *h >= target)
        })
        .await
        .unwrap_or_else(|| {
            panic!(
                "shard {shard:?} did not reach height {target} within {within:?}; latest = {:?}",
                self.committed_height(shard)
            )
        })
    }

    /// Wait until host `idx` serves `shard`. Panics on timeout.
    pub async fn await_local_shard(&self, idx: usize, shard: ShardId, within: Duration) {
        self.poll(within, || {
            self.local_shards(idx).contains(&shard).then_some(())
        })
        .await
        .unwrap_or_else(|| {
            panic!(
                "host {idx} did not serve {shard:?} within {within:?}; serving = {:?}",
                self.local_shards(idx)
            )
        });
    }

    /// Poll `f` every [`POLL_INTERVAL`] until it returns `Some` or
    /// `within` elapses.
    async fn poll<T>(&self, within: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
        timeout(within, async {
            loop {
                if let Some(v) = f() {
                    return v;
                }
                sleep(POLL_INTERVAL).await;
            }
        })
        .await
        .ok()
    }

    /// Signal every host to shut down and join its runner task. Drops the
    /// real shard threads so they don't leak across `#[serial]` tests.
    pub async fn shutdown(mut self) {
        for host in &mut self.hosts {
            if let Some(s) = host.shutdown.take() {
                s.shutdown();
            }
        }
        for host in self.hosts.drain(..) {
            let _ = timeout(SHUTDOWN_TIMEOUT, host.join).await;
        }
    }
}

/// A built-but-not-yet-spawned host.
struct BuiltHost {
    runner: ProductionRunner,
    adapter: Arc<Libp2pAdapter>,
    rpc_status: Arc<ArcSwap<NodeStatusState>>,
    beacon_storage: Arc<RocksDbBeaconStorage>,
}

struct BuildHostArgs<'a> {
    temp_dir: &'a TempDir,
    topology: &'a Arc<TopologySnapshot>,
    vnodes: Vec<VnodeConfig>,
    beacon_chain_config: BeaconChainConfig,
    genesis_config: Option<GenesisConfig>,
    bootstrap_peers: Vec<Multiaddr>,
}

/// Open a host's stores and build its runner (the adapter binds and
/// starts peering immediately; the runner is spawned separately).
fn build_host(args: BuildHostArgs<'_>) -> BuiltHost {
    let hosted_shards: HashSet<ShardId> = args.vnodes.iter().map(|v| v.local_shard).collect();
    let resolve = temp_storage_dir(args.temp_dir);
    let storages: HashMap<ShardId, Arc<RocksDbShardStorage>> = hosted_shards
        .iter()
        .map(|shard| {
            let store = RocksDbShardStorage::open(resolve(*shard), shard_prefix_path(*shard))
                .map(Arc::new)
                .expect("open shard store");
            (*shard, store)
        })
        .collect();

    let beacon_storage = Arc::new(
        RocksDbBeaconStorage::open(args.temp_dir.path().join("beacon_db")).expect("open beacon db"),
    );
    let rpc_status = Arc::new(ArcSwap::new(Arc::new(NodeStatusState {
        num_shards: args.topology.num_shards(),
        ..Default::default()
    })));

    let network_config = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: args.bootstrap_peers,
        ..Default::default()
    };

    let beacon_reader: Arc<dyn BeaconStorage> = beacon_storage.clone();
    let mut builder = ProductionRunner::builder(
        args.vnodes,
        Arc::clone(args.topology),
        ShardConsensusConfig::default(),
        storages,
        beacon_reader,
        network_config,
        temp_storage_factory(args.temp_dir),
        temp_storage_dir(args.temp_dir),
    )
    .beacon_chain_config(args.beacon_chain_config)
    .rpc_status(Arc::clone(&rpc_status));
    if let Some(cfg) = args.genesis_config {
        builder = builder.genesis_config(cfg);
    }
    let runner = builder.build().expect("build runner");
    let adapter = Arc::clone(runner.network());

    BuiltHost {
        runner,
        adapter,
        rpc_status,
        beacon_storage,
    }
}

/// Wall-clock milliseconds since the Unix epoch — the shared genesis
/// instant the cluster anchors every host's consensus clock to.
fn now_millis() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

/// Poll an adapter's listen addresses until one appears.
async fn wait_for_listen_addr(adapter: &Arc<Libp2pAdapter>) -> Multiaddr {
    timeout(LISTEN_ADDR_TIMEOUT, async {
        loop {
            if let Some(addr) = adapter.listen_addresses().await.into_iter().next() {
                return addr;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("host 0 surfaced a listen address")
}
