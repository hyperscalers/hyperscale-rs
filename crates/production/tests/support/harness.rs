//! Multi-host production cluster harness.
//!
//! Spins up an N-host localhost-QUIC cluster of [`Node`]s, each on its own
//! data directory in the production layout, bootstrap-peers the hosts to
//! host 0, drives real consensus, and exposes synchronous observation hooks
//! (committed heights and state roots, beacon state, transaction status)
//! plus per-host fault gates, all read through each host's [`NodeHandle`].
//! The portable scenarios drive it through the `ProdCluster` adaptor rather
//! than injecting `ShardCommand`s, so the production beacon-fold → duty →
//! flip chain runs end to end.
//!
//! These are real-time tests: there is no logical clock. Callers set a
//! small `epoch_duration_ms` and mark `#[serial]`.

use std::fs::remove_dir_all;
use std::io::ErrorKind;
use std::ops::Range;
use std::panic::resume_unwind;
use std::sync::Arc;
use std::time::Duration;
use std::{iter, thread};

use hyperscale_beacon::genesis::{build_genesis, seed_founding_members};
use hyperscale_engine::GenesisConfig;
use hyperscale_engine::genesis::{genesis_seats, seat_pool};
use hyperscale_network_iroh::fault::{DropSpec, HostId, Rewrite, RuleHandle};
use hyperscale_network_iroh::{EndpointAddr, EndpointId, IrohAdapter, SecretKey};
use hyperscale_node::{SharedTopologySnapshot, network_genesis_block};
use hyperscale_production::testing::Probe;
use hyperscale_production::{LocalValidator, Node, NodeHandle, shard_data_dir};
use hyperscale_scenarios::query::{
    RanAs, chain_burn, chain_fate, chain_membership, declines_naming, reads_record, records_naming,
};
use hyperscale_storage::{BeaconChainReader, ShardChainReader, SubstateStore, VersionedStore};
use hyperscale_storage_rocksdb::RocksDbShardStorage;
use hyperscale_types::{
    BeaconChainConfig, BeaconState, BlockHeight, ChainOrigin, DeclaredRange, Derivation,
    GenesisValidators, ShardId, StateRoot, SubstateKey, TopologySnapshot, Transaction,
    TransactionDecision, TransactionStatus, TxHash, TxsInFlight, ValidatorId, WeightedTimestamp,
    shard_prefix_path,
};
use tempfile::TempDir;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};

use super::{test_config, test_setup};

/// How long the cluster's seated hosts have to install the network genesis
/// once they start.
const GENESIS_INSTALL_TIMEOUT: Duration = Duration::from_secs(60);

/// One host's seating: the validators it runs. Shard participation is not
/// named — the host derives each validator's seat (or pool membership)
/// from the committed beacon state, which mirrors the cluster topology.
pub struct HostSpec {
    pub validators: Vec<LocalValidator>,
}

impl HostSpec {
    /// A host running exactly the given validators.
    pub const fn new(validators: Vec<LocalValidator>) -> Self {
        Self { validators }
    }
}

/// Inputs for [`Harness::start`].
pub struct ClusterSpec {
    /// The genesis validators each host projects its topology from.
    pub genesis: GenesisValidators,
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
    /// Per-message outbound latency injected on every host's network sends.
    /// Zero-latency localhost lets a loadless committee form quorum
    /// certificates dozens of times a second — far faster than any real
    /// deployment — which floods this single-process harness and lags the
    /// consensus clock behind wall-clock. A scenario whose reshape duties
    /// must seat inside the real-time budget sets a realistic delay to pace
    /// quorum formation to a few blocks a second; scenarios that only check
    /// liveness leave it at [`Duration::ZERO`].
    pub simulated_outbound_latency: Duration,
}

/// One host: what it is started from, and the running node while it is
/// up.
struct Host {
    /// The validators this host runs, with their signers.
    validators: Vec<LocalValidator>,
    /// The host's network identity, kept across restarts.
    key: SecretKey,
    /// The host's data directory. Kept for the cluster's life, so a
    /// restarted host reopens what its previous run left.
    dir: TempDir,
    /// How many times the host has started; a fault rule belongs to the
    /// run that installed it.
    incarnation: u64,
    running: Option<Running>,
}

/// A started host: its owner, which stops it, and the handle every read
/// goes through.
struct Running {
    node: Node,
    handle: NodeHandle,
}

impl Host {
    /// Whether this host runs `validator`.
    fn runs(&self, validator: ValidatorId) -> bool {
        self.validators
            .iter()
            .any(|local| local.validator_id == validator)
    }

    /// The running host's handle; `None` while it is down.
    fn handle(&self) -> Option<&NodeHandle> {
        self.running.as_ref().map(|running| &running.handle)
    }

    /// Runs `look` inside the running host; `None` while it is down.
    fn probe<T>(&self, look: impl FnOnce(Probe<'_>) -> T) -> Option<T> {
        self.handle()?.probe(look)
    }

    /// Runs `read` on the host's store for `shard`; `None` when the host
    /// is down or holds none there.
    fn read_store<T>(
        &self,
        shard: ShardId,
        read: impl FnOnce(&RocksDbShardStorage) -> T,
    ) -> Option<T> {
        self.probe(|p| p.shard_store(shard, read))?
    }

    /// Whether the host is up and its transport carries `shard`.
    fn serves(&self, shard: ShardId) -> bool {
        self.probe(|p| p.network().local_shards().contains(&shard))
            .unwrap_or(false)
    }

    /// Runs `act` on the host's transport, which carries its fault gate;
    /// `None` while the host is down.
    fn network<T>(&self, act: impl FnOnce(&IrohAdapter) -> T) -> Option<T> {
        self.probe(|p| act(p.network()))
    }

    /// The host's network identity, which it keeps across restarts.
    fn endpoint_id(&self) -> EndpointId {
        self.key.public()
    }
}

/// A fault rule installed on one host's gate, in the run that installed
/// it.
#[derive(Clone)]
pub struct HostRule {
    host: usize,
    incarnation: u64,
    handle: RuleHandle,
}

impl HostRule {
    /// How many times the rule fired.
    pub fn fired(&self) -> u64 {
        self.handle.fired()
    }
}

/// A running multi-host production cluster.
pub struct Harness {
    hosts: Vec<Host>,
    /// What every host is started from, for starting one again on a
    /// restart.
    build: ClusterBuild,
}

/// The cluster-wide inputs every host shares.
struct ClusterBuild {
    genesis: GenesisValidators,
    /// Carries the shared genesis instant, so a restarted host keeps the
    /// cluster's clock origin.
    beacon_chain_config: BeaconChainConfig,
    genesis_config: Option<GenesisConfig>,
    simulated_outbound_latency: Duration,
}

impl ClusterBuild {
    /// The genesis config a host's fresh store installs: the cluster's,
    /// with each pool's founding members read off the beacon genesis, as
    /// the runner derives it.
    fn network_genesis_config(&self) -> GenesisConfig {
        let mut config = self.genesis_config.clone().unwrap_or_default();
        config.pools = genesis_seats(&config.pools);
        let boot = build_genesis(
            &self.genesis,
            self.beacon_chain_config,
            &config.pools,
            seat_pool,
        );
        seed_founding_members(&boot.state, &mut config.pools, seat_pool);
        config
    }

    /// Starts a host running `validators` at `dir` under `key`,
    /// bootstrapped to `bootstrap_peers`. Blocks while its stores open and
    /// its network binds.
    fn start(
        &self,
        dir: &TempDir,
        validators: Vec<LocalValidator>,
        key: &SecretKey,
        bootstrap_peers: Vec<EndpointAddr>,
    ) -> Running {
        let node = Node::start(test_setup(
            dir.path().to_path_buf(),
            validators,
            self.genesis.clone(),
            self.beacon_chain_config,
            self.genesis_config.clone().unwrap_or_default(),
            test_config(key, bootstrap_peers, self.simulated_outbound_latency),
        ))
        .expect("start a harness host");
        let handle = node.handle();
        Running { node, handle }
    }
}

impl Harness {
    /// Start the cluster: host 0 first, then every other host at once,
    /// each bootstrapped to host 0. Returns once every host seated on the
    /// genesis committee has installed the network genesis.
    pub async fn start(spec: ClusterSpec) -> Self {
        let ClusterSpec {
            genesis,
            hosts,
            beacon_chain_config,
            genesis_config,
            simulated_outbound_latency,
        } = spec;
        assert!(!hosts.is_empty(), "cluster needs at least one host");

        // Every host shares one genesis instant captured now, so epoch 0
        // opens as the cluster starts rather than paced from a fixed date.
        let mut chain_config = beacon_chain_config;
        chain_config.genesis_timestamp_ms = now_millis();
        let build = ClusterBuild {
            genesis,
            beacon_chain_config: chain_config,
            genesis_config,
            simulated_outbound_latency,
        };

        let mut specs = hosts.into_iter();
        let first = specs.next().expect("cluster needs at least one host");
        let first = start_host(&build, first, Vec::new());
        let bootstrap = first
            .probe(|p| p.network().endpoint_addr())
            .expect("the first host is running");
        let rest: Vec<Host> = thread::scope(|scope| {
            // Every start is spawned before any is joined, so the hosts
            // open their stores and bind at once.
            let mut starting = Vec::new();
            for spec in specs {
                let (build, bootstrap) = (&build, bootstrap.clone());
                starting.push(scope.spawn(move || start_host(build, spec, vec![bootstrap])));
            }
            starting
                .into_iter()
                .map(|host| host.join().unwrap_or_else(|panic| resume_unwind(panic)))
                .collect()
        });

        let harness = Self {
            hosts: iter::once(first).chain(rest).collect(),
            build,
        };
        harness.await_genesis_installed().await;
        harness
    }

    /// Runs `f` on a derivation over everything the cluster's chains have
    /// created: the lowest up host's engine's, as a scenario asks of any
    /// host.
    ///
    /// # Panics
    ///
    /// Panics if no host is up.
    pub fn with_derivation<T>(&self, f: impl FnOnce(&dyn Derivation) -> T) -> T {
        let host = self.live_host().expect("a derivation needs an up host");
        self.hosts[host]
            .probe(|p| f(p.derivation()))
            .expect("the lowest up host is running")
    }

    /// The lowest host that is up, if any.
    pub fn live_host(&self) -> Option<usize> {
        self.hosts.iter().position(|host| host.running.is_some())
    }

    /// Whether host `host` is up.
    pub fn is_up(&self, host: usize) -> bool {
        self.hosts[host].running.is_some()
    }

    /// Wait until every host seated on the genesis ROOT committee holds a
    /// ROOT store that installed the network genesis. A host opens and
    /// installs its stores only once its runner runs, so until then a
    /// scenario reading the cluster's state would find nothing there at all.
    async fn await_genesis_installed(&self) {
        let committee = &self.build.genesis.committee;
        let seated: Vec<&Host> = self
            .hosts
            .iter()
            .filter(|host| committee.iter().any(|&validator| host.runs(validator)))
            .collect();
        let installed = || {
            seated.iter().all(|host| {
                host.read_store(ShardId::ROOT, |store| store.installed_genesis().is_some())
                    .unwrap_or(false)
            })
        };
        timeout(GENESIS_INSTALL_TIMEOUT, async {
            while !installed() {
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("every seated host installs the network genesis");
    }

    /// Restart host `host` with its stores for `shards` wiped: stop the
    /// host, delete those stores from its data directory, and start it
    /// again on what is left, so its beacon chain and every other shard's
    /// store survive. The restarted host bootstraps to the lowest other up
    /// host. Returns the topology it starts on, read before its runner
    /// runs and so before it folds any beacon block.
    ///
    /// # Panics
    ///
    /// Panics if `host` is down or no other host is up (nothing to
    /// bootstrap to), or the host does not stop cleanly.
    pub async fn restart_with_wiped_shards(
        &mut self,
        host: usize,
        shards: &[ShardId],
    ) -> Arc<TopologySnapshot> {
        self.restart_with(host, shards, Replacement::Wiped).await
    }

    /// Restart host `host` with its stores for `shards` replaced by stores
    /// that installed the network genesis and committed nothing past it:
    /// the disk a host leaves when it crashes between a fresh store's
    /// genesis install and its first block. Otherwise as
    /// [`Self::restart_with_wiped_shards`].
    pub async fn restart_with_installed_genesis(
        &mut self,
        host: usize,
        shards: &[ShardId],
    ) -> Arc<TopologySnapshot> {
        let topology = self.topology(self.peer_of(host)).load_full();
        self.restart_with(host, shards, Replacement::InstalledGenesis(topology))
            .await
    }

    /// The lowest up host other than `host`.
    ///
    /// # Panics
    ///
    /// Panics if no other host is up.
    fn peer_of(&self, host: usize) -> usize {
        (0..self.hosts.len())
            .find(|&i| i != host && self.is_up(i))
            .expect("a restart bootstraps to another up host")
    }

    async fn restart_with(
        &mut self,
        host: usize,
        shards: &[ShardId],
        replacement: Replacement,
    ) -> Arc<TopologySnapshot> {
        let bootstrap = self.endpoint_addr(self.peer_of(host));
        self.stop_host(host).await;
        self.replace_stores(host, shards, replacement);
        self.start_host(host, Some(bootstrap));
        self.hosts[host]
            .probe(|p| p.startup_topology())
            .expect("the restarted host is running")
    }

    /// Stop host `host`'s node and wait until it has closed every store.
    ///
    /// # Panics
    ///
    /// Panics if the host is down or does not stop cleanly.
    pub async fn stop_host(&mut self, host: usize) {
        let running = self.hosts[host]
            .running
            .take()
            .expect("only an up host stops");
        running.node.stop().await.expect("the host stops cleanly");
    }

    /// Start host `host` again on the data directory it left, under its
    /// own key, bootstrapped to `bootstrap` when given, and configure its
    /// gate with every host's identity, its rules empty. Blocks while its
    /// stores open and its network binds.
    ///
    /// # Panics
    ///
    /// Panics if the host is up.
    pub fn start_host(&mut self, host: usize, bootstrap: Option<EndpointAddr>) {
        let peers = self.peer_map();
        let restarted = &mut self.hosts[host];
        assert!(restarted.running.is_none(), "only a down host starts");
        restarted.running = Some(self.build.start(
            &restarted.dir,
            restarted.validators.clone(),
            &restarted.key,
            bootstrap.into_iter().collect(),
        ));
        restarted.incarnation += 1;
        restarted.network(|network| network.fault_configure(host_id(host), peers));
    }

    /// Replace host `host`'s stores for `shards` as `replacement` says,
    /// writing each replacement into a directory the removal left absent:
    /// a clone does not land on an existing store, and a genesis install
    /// over a store with blocks resets nothing.
    ///
    /// # Panics
    ///
    /// Panics if the host is up, or a store cannot be removed or written.
    fn replace_stores(&self, host: usize, shards: &[ShardId], replacement: Replacement) {
        assert!(
            !self.is_up(host),
            "a store is replaced only while its host is down"
        );
        let dir = self.hosts[host].dir.path();
        for &shard in shards {
            match remove_dir_all(shard_data_dir(dir, shard)) {
                Err(e) if e.kind() != ErrorKind::NotFound => {
                    panic!("wipe the host's store for {shard:?}: {e}")
                }
                _ => {}
            }
        }
        match replacement {
            Replacement::Wiped => {}
            Replacement::InstalledGenesis(topology) => {
                let config = self.build.network_genesis_config();
                for &shard in shards {
                    let at = shard_data_dir(dir, shard);
                    assert!(!at.exists(), "the genesis installs into an absent store");
                    let store = RocksDbShardStorage::open(at, shard_prefix_path(shard))
                        .expect("open the store the genesis installs into");
                    let _ = network_genesis_block(
                        &store,
                        shard,
                        &topology,
                        &config,
                        WeightedTimestamp::from_millis(
                            self.build.beacon_chain_config.genesis_timestamp_ms,
                        ),
                    );
                }
            }
            Replacement::ParentClone(parent) => {
                let store = RocksDbShardStorage::open(
                    shard_data_dir(dir, parent),
                    shard_prefix_path(parent),
                )
                .expect("open the parent store the clones are cut from");
                for &shard in shards {
                    let at = shard_data_dir(dir, shard);
                    assert!(!at.exists(), "the clone lands in an absent store");
                    store.checkpoint_into(&at).expect("clone the parent store");
                }
            }
        }
    }

    /// Replace down host `host`'s stores for split `children` by clones of
    /// its store for their `parent` that no adoption ran over: the disk a
    /// parent half leaves when it crashes between seeding a child's store
    /// and adopting the child's genesis into it.
    ///
    /// # Panics
    ///
    /// Panics if the host is up or holds no store for `parent`.
    pub fn clone_unadopted(&self, host: usize, parent: ShardId, children: &[ShardId]) {
        self.replace_stores(host, children, Replacement::ParentClone(parent));
    }

    /// Runs `read` on down host `host`'s store for `shard` as it lies on
    /// disk, opened as the host opens it; `None` when it holds none there.
    ///
    /// # Panics
    ///
    /// Panics if the host is up or the store does not open.
    pub fn read_stored<T>(
        &self,
        host: usize,
        shard: ShardId,
        read: impl FnOnce(&RocksDbShardStorage) -> T,
    ) -> Option<T> {
        assert!(
            !self.is_up(host),
            "a store is read off disk only while its host is down"
        );
        let at = shard_data_dir(self.hosts[host].dir.path(), shard);
        if !at.exists() {
            return None;
        }
        let store =
            RocksDbShardStorage::open(at, shard_prefix_path(shard)).expect("open the stored shard");
        Some(read(&store))
    }

    /// The address host `host` binds, to bootstrap another host to.
    ///
    /// # Panics
    ///
    /// Panics if the host is down.
    pub fn endpoint_addr(&self, host: usize) -> EndpointAddr {
        self.hosts[host]
            .network(IrohAdapter::endpoint_addr)
            .expect("an up host has an address")
    }

    /// Number of hosts in the cluster, up or down.
    pub const fn host_count(&self) -> usize {
        self.hosts.len()
    }

    /// The handle every call on `host` goes through.
    ///
    /// # Panics
    ///
    /// Panics if the host is down.
    pub fn handle(&self, host: usize) -> &NodeHandle {
        self.hosts[host].handle().expect("the host is up")
    }

    /// The topology snapshot `host` reads.
    ///
    /// # Panics
    ///
    /// Panics if the host is down.
    pub fn topology(&self, host: usize) -> SharedTopologySnapshot {
        self.hosts[host]
            .probe(|p| p.topology())
            .expect("the host is up")
    }

    /// Highest committed height observed for `shard` across all hosts'
    /// status (`block_height`). `None` until some host reports a vnode in
    /// `shard`.
    pub fn committed_height(&self, shard: ShardId) -> Option<u64> {
        (0..self.hosts.len())
            .filter_map(|host| self.host_committed_height(host, shard))
            .max()
    }

    /// The committed JMT root for `shard`, read straight off a serving host's
    /// live store — for typed comparison against a beacon-composed anchor.
    /// `None` if no host serves `shard`.
    pub fn committed_state_root(&self, shard: ShardId) -> Option<StateRoot> {
        self.read_any(shard, SubstateStore::state_root)
    }

    /// The committed height on `shard` at host `host` specifically — read off
    /// that host's own status, not the cluster-wide max — so a scenario can
    /// watch a lagging fragment catch up after a heal.
    pub fn host_committed_height(&self, host: usize, shard: ShardId) -> Option<u64> {
        let key = shard.inner();
        self.hosts.get(host)?.probe(|p| {
            p.node_status()
                .vnodes
                .iter()
                .find(|v| v.shard == key)
                .map(|v| v.block_height)
        })?
    }

    /// The raw committed JMT root for `shard` on host `host` specifically, read
    /// off that host's own live store. `None` if host `host` serves no vnode
    /// there.
    pub fn host_committed_state_root(&self, host: usize, shard: ShardId) -> Option<StateRoot> {
        self.hosts
            .get(host)?
            .read_store(shard, SubstateStore::state_root)
    }

    /// Whether any host in the cluster currently serves `shard` — the
    /// "the reshape seated this shard" signal (a split's children, the
    /// merged parent).
    pub fn any_host_serves(&self, shard: ShardId) -> bool {
        self.hosts.iter().any(|h| h.serves(shard))
    }

    /// The latest committed beacon state across all hosts (highest epoch) —
    /// the source of truth for `pending_reshapes` (a split's admitted
    /// cohort) and `boundaries` (the beacon-composed per-shard anchor a
    /// flip must reproduce).
    pub fn beacon_state(&self) -> Option<Arc<BeaconState>> {
        self.hosts
            .iter()
            .filter_map(|h| h.handle()?.history().latest_committed())
            .max_by_key(|(_, state)| state.current_epoch)
            .map(|(_, state)| state)
    }

    /// Submit a transaction into host `idx`'s process — the production
    /// analog of the sim's `ProcessScopedInput::SubmitTransaction`. The
    /// process computes the touched-shard fanout and admits onto every
    /// hosted shard's mempool, gossiping any it doesn't host. Returns
    /// `false` when the host is down or shutting down. Submit through a host
    /// that runs the transaction's source shard so it admits directly
    /// rather than relying on a gossip hop.
    ///
    /// The host takes the envelope alone, as the RPC decodes it: an
    /// envelope the harness already derived would hand the host a
    /// routing it never reached itself, and with it skip the record
    /// fetch its replay of the commit reads back after a restart.
    pub fn submit_transaction(&self, idx: usize, tx: &Transaction) -> bool {
        self.hosts[idx]
            .handle()
            .is_some_and(|handle| handle.submit(Transaction::new(tx.body().clone())))
    }

    /// The status host `idx`'s process recorded for `hash`, with the
    /// hosted shard that reported it, if any.
    pub fn tx_status(&self, idx: usize, hash: &TxHash) -> Option<(TransactionStatus, ShardId)> {
        self.hosts[idx].probe(|p| p.tx_status(hash))?
    }

    /// The first host index serving `shard`, if any — used to address a
    /// transaction's source committee.
    pub fn host_serving(&self, shard: ShardId) -> Option<usize> {
        self.hosts.iter().position(|h| h.serves(shard))
    }

    /// The first host serving `shard` that runs one of `committee`, if
    /// any — a host the beacon seats there, not one whose supervisor has
    /// yet to retire a replaced loop.
    pub fn host_serving_in(&self, shard: ShardId, committee: &[ValidatorId]) -> Option<usize> {
        self.hosts
            .iter()
            .position(|h| h.serves(shard) && committee.iter().any(|&v| h.runs(v)))
    }

    /// The host running `validator`, up or down, if any.
    pub fn host_of(&self, validator: ValidatorId) -> Option<usize> {
        self.hosts.iter().position(|h| h.runs(validator))
    }

    /// Every host index serving `shard` — its committee members, before a
    /// terminating reshape relocates them.
    pub fn hosts_serving(&self, shard: ShardId) -> Vec<usize> {
        self.hosts
            .iter()
            .enumerate()
            .filter(|(_, h)| h.serves(shard))
            .map(|(i, _)| i)
            .collect()
    }

    /// Runs `read` on the first host's store for `shard`. Every committee
    /// member commits the same chain, so the first match suffices. A host
    /// whose runner has torn the shard down holds no store there and is
    /// skipped.
    fn read_any<T>(&self, shard: ShardId, read: impl Fn(&RocksDbShardStorage) -> T) -> Option<T> {
        self.hosts.iter().find_map(|h| h.read_store(shard, &read))
    }

    /// Runs `read` on the furthest-along live store any host holds for
    /// `shard`, at that store's own JMT height. The greatest height rather
    /// than the first host: a reseated or merged host holds a frozen
    /// predecessor under the same id, and only the live copy has committed
    /// past the cut.
    fn read_furthest<T>(
        &self,
        shard: ShardId,
        read: impl Fn(&RocksDbShardStorage, BlockHeight) -> T,
    ) -> Option<T> {
        self.hosts
            .iter()
            .filter_map(|h| {
                h.read_store(shard, |store| {
                    let height = store.jmt_height();
                    (height, read(store, height))
                })
            })
            .max_by_key(|(height, _)| *height)
            .map(|(_, read)| read)
    }

    /// The committed value of `key` on `shard`, read off the furthest-along
    /// live store any host holds for it. `None` when no host serves
    /// `shard`, the height is unavailable, or the cell is absent.
    pub fn substate(&self, shard: ShardId, key: SubstateKey) -> Option<Vec<u8>> {
        self.read_furthest(shard, |store, height| {
            store.get_substate_at_height(key, height)
        })??
    }

    /// The committed entries of `range` on `shard`, read off the
    /// furthest-along live store any host holds for it, as
    /// [`substate`](Self::substate) reads a cell. `None` when no host
    /// serves `shard` or the height is unavailable.
    pub fn entries(&self, shard: ShardId, range: DeclaredRange) -> Option<Vec<(u128, Vec<u8>)>> {
        self.read_furthest(shard, |store, height| {
            store.get_entries_at_height(range, height)
        })?
    }

    /// The committed substate byte total `shard`'s live store recorded at
    /// its genesis. `None` if no host serves `shard`.
    pub fn genesis_substate_bytes(&self, shard: ShardId) -> Option<u64> {
        self.read_any(shard, |store| store.substate_bytes_at(BlockHeight::GENESIS))?
    }

    /// The substate byte total each committed block's header claims, from
    /// height 1 through `through`, read off the live store. Empty if no
    /// host serves `shard`.
    pub fn substate_claims(&self, shard: ShardId, through: BlockHeight) -> Vec<Option<u64>> {
        self.read_any(shard, |store| {
            (1..=through.inner())
                .filter_map(|h| store.get_block(BlockHeight::new(h)))
                .map(|block| block.block().header().load().substate_bytes)
                .collect()
        })
        .unwrap_or_default()
    }

    /// Where `shard`'s chain starts, read off the live store's recovered
    /// consensus state. `None` if no host serves `shard`.
    pub fn chain_origin(&self, shard: ShardId) -> Option<ChainOrigin> {
        let genesis =
            WeightedTimestamp::from_millis(self.build.beacon_chain_config.genesis_timestamp_ms);
        self.read_any(shard, |store| {
            store
                .load_recovered_state(shard)
                .chain_origin
                .unwrap_or_else(|| ChainOrigin::root(genesis))
        })
    }

    /// The work `shard`'s committed tip leaves owing against the drain,
    /// read off the tip header the live store holds. `None` if no host
    /// serves `shard` or the tip carries no header.
    pub fn committed_txs_in_flight(&self, shard: ShardId) -> Option<TxsInFlight> {
        self.read_any(shard, |store| {
            store
                .get_certified_header(store.committed_height())
                .map(|header| header.header().txs_in_flight())
        })?
    }

    /// [`chain_membership`] over the live store — what `shard`'s own
    /// certificates said it ran of `hash`. Empty if no host serves
    /// `shard` or no committed finalization names it.
    pub fn ran(&self, shard: ShardId, hash: TxHash) -> Vec<RanAs> {
        self.read_any(shard, |store| chain_membership(store, hash))
            .unwrap_or_default()
    }

    /// [`records_naming`] over the live store — every record on `shard`'s
    /// chain naming `hash`. Empty if no host serves `shard`.
    pub fn named_unsettled(&self, shard: ShardId, hash: TxHash) -> Vec<(BlockHeight, ShardId)> {
        self.read_any(shard, |store| records_naming(store, hash))
            .unwrap_or_default()
    }

    /// [`reads_record`] over the live store — whether `shard`'s chain has
    /// carried a held reading of `key`. False if no host serves `shard`.
    #[must_use]
    pub fn reads_record(&self, shard: ShardId, key: SubstateKey) -> bool {
        self.read_any(shard, |store| reads_record(store, key))
            .unwrap_or(false)
    }

    /// [`declines_naming`] over the live store — every crossing on
    /// `shard`'s chain that it refused for `hash`.
    #[must_use]
    pub fn declined(&self, shard: ShardId, hash: TxHash) -> Vec<(BlockHeight, SubstateKey)> {
        self.read_any(shard, |store| declines_naming(store, hash))
            .unwrap_or_default()
    }

    /// [`chain_fate`] over the live store the runner writes to — the shared
    /// committed/finalized walk both harness adaptors use. `(None, None)` if
    /// no host serves `shard`.
    pub fn chain_fate(
        &self,
        shard: ShardId,
        hash: TxHash,
    ) -> (
        Option<BlockHeight>,
        Option<(BlockHeight, TransactionDecision)>,
    ) {
        self.read_any(shard, |store| chain_fate(store, hash))
            .unwrap_or((None, None))
    }

    /// [`chain_burn`] over the live store the runner writes to. `None` if
    /// no host serves `shard`.
    pub fn chain_burn(&self, shard: ShardId, hash: TxHash) -> Option<BlockHeight> {
        self.read_any(shard, |store| chain_burn(store, hash))?
    }

    /// What credits committed on `shard`'s chain burned past
    /// `u128::MAX` on `key`: the most any host's store counted.
    pub fn credit_burned(&self, shard: ShardId, key: SubstateKey) -> u128 {
        self.hosts
            .iter()
            .filter_map(|h| h.read_store(shard, |store| store.credit_burned(key)))
            .max()
            .unwrap_or(0)
    }

    /// Stop every up host at once and wait until each has: its stores
    /// closed, its sockets released and its threads joined, so nothing
    /// leaks across `#[serial]` tests. Idempotent: the hosts are drained,
    /// so a second call is a no-op.
    pub async fn shutdown(&mut self) {
        let mut stopping = JoinSet::new();
        for host in self.hosts.drain(..) {
            let Some(running) = host.running else {
                continue;
            };
            stopping.spawn(async move {
                let stopped = running.node.stop().await;
                drop(host.dir);
                stopped
            });
        }
        while let Some(stopped) = stopping.join_next().await {
            if let Ok(Err(e)) = stopped {
                tracing::warn!(error = %e, "A harness host stopped with an error");
            }
        }
    }
}

/// A `0..host_count` host index as a [`HostId`].
fn host_id(index: usize) -> HostId {
    HostId(u32::try_from(index).expect("host index fits a HostId"))
}

/// Fault injection: drive every up host's gate; a down host has none, and
/// starts again with an empty one. The cluster addresses hosts by index;
/// each host's gate keys on [`HostId`].
impl Harness {
    /// Every host's identity, up or down, mapped to its [`HostId`].
    fn peer_map(&self) -> Vec<(EndpointId, HostId)> {
        self.hosts
            .iter()
            .enumerate()
            .map(|(i, h)| (h.endpoint_id(), host_id(i)))
            .collect()
    }

    /// Configure every up host's gate with its own id and the full peer to
    /// `HostId` map, so partition and gossip filtering resolve peers. Call once
    /// before installing faults.
    pub fn fault_configure_all(&self) {
        let map = self.peer_map();
        for (i, host) in self.hosts.iter().enumerate() {
            host.network(|network| network.fault_configure(host_id(i), map.clone()));
        }
    }

    /// Install `spec` as a drop rule on every up host's gate; one rule per
    /// host.
    pub fn fault_install_drop(&self, spec: &DropSpec) -> Vec<HostRule> {
        self.hosts
            .iter()
            .enumerate()
            .filter_map(|(i, h)| {
                let handle =
                    h.network(|network| network.fault_gate().install_drop(spec.clone()))?;
                Some(HostRule {
                    host: i,
                    incarnation: h.incarnation,
                    handle,
                })
            })
            .collect()
    }

    /// Remove rules [`Self::fault_install_drop`] installed. A rule whose
    /// host has stopped since went with that run's gate and is skipped.
    pub fn fault_remove_drop(&self, rules: &[HostRule]) {
        for rule in rules {
            let host = &self.hosts[rule.host];
            if host.incarnation == rule.incarnation {
                host.network(|network| network.fault_gate().remove_fault(&rule.handle));
            }
        }
    }

    /// Install `rewrite` over the answers host `host` serves for requests of
    /// `type_id`; `None` when the host is down.
    pub fn fault_install_response_rewrite(
        &self,
        host: usize,
        type_id: &'static str,
        rewrite: Rewrite,
    ) -> Option<RuleHandle> {
        self.hosts[host].network(|network| {
            network
                .fault_gate()
                .install_response_rewrite(type_id, rewrite)
        })
    }

    /// Partition host groups `a` and `b` — each side blocks the other, so both
    /// outbound unicast and inbound gossip are cut in both directions.
    pub fn fault_partition(&self, a: &[usize], b: &[usize]) {
        for &i in a {
            for &j in b {
                self.hosts[i].network(|network| network.fault_gate().block_host(host_id(j)));
                self.hosts[j].network(|network| network.fault_gate().block_host(host_id(i)));
            }
        }
    }

    /// Partition groups `a` and `b` during each of `windows`, offsets from
    /// now on each host's own gate clock.
    pub fn fault_partition_during(&self, a: &[usize], b: &[usize], windows: &[Range<Duration>]) {
        for &i in a {
            for &j in b {
                self.hosts[i].network(|network| {
                    network.fault_gate().block_host_during(host_id(j), windows);
                });
                self.hosts[j].network(|network| {
                    network.fault_gate().block_host_during(host_id(i), windows);
                });
            }
        }
    }

    /// Isolate one host: it blocks every other, and every other blocks it.
    pub fn fault_isolate(&self, host: usize) {
        self.hosts[host].network(|network| network.fault_gate().block_all_hosts());
        for (i, h) in self.hosts.iter().enumerate() {
            if i != host {
                h.network(|network| network.fault_gate().block_host(host_id(host)));
            }
        }
    }

    /// Heal the partition between hosts `a` and `b` only — each side lifts
    /// its block against the other, leaving every other cut intact.
    pub fn fault_heal_between(&self, a: usize, b: usize) {
        self.hosts[a].network(|network| network.fault_gate().unblock_host(host_id(b)));
        self.hosts[b].network(|network| network.fault_gate().unblock_host(host_id(a)));
    }

    /// Heal every partition on every host.
    pub fn fault_heal_all(&self) {
        for h in &self.hosts {
            h.network(|network| network.fault_gate().heal());
        }
    }

    /// Remove every installed drop rule and rewrite on every host, leaving
    /// partitions intact.
    pub fn fault_clear_all(&self) {
        for h in &self.hosts {
            h.network(|network| network.fault_gate().clear_faults());
        }
    }
}

/// Starts a host from `spec` in a fresh data directory under a fresh
/// network key, bootstrapped to `bootstrap_peers`.
fn start_host(build: &ClusterBuild, spec: HostSpec, bootstrap_peers: Vec<EndpointAddr>) -> Host {
    let dir = TempDir::new().expect("temp dir");
    let key = SecretKey::generate();
    let running = build.start(&dir, spec.validators.clone(), &key, bootstrap_peers);
    Host {
        validators: spec.validators,
        key,
        dir,
        incarnation: 1,
        running: Some(running),
    }
}

/// What a restart puts in place of each store it drops.
enum Replacement {
    /// Nothing: the store is gone.
    Wiped,
    /// A store that installed the network genesis, projected from this
    /// topology, and committed nothing.
    InstalledGenesis(Arc<TopologySnapshot>),
    /// A clone of the host's store for this split parent, never adopted.
    ParentClone(ShardId),
}

/// Wall-clock milliseconds since the Unix epoch — the shared genesis
/// instant the cluster opens epoch 0 at.
fn now_millis() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}
