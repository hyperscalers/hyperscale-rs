//! Multi-host production cluster harness.
//!
//! Spins up an N-host localhost-QUIC cluster on real `RocksDbShardStorage`
//! and a real beacon chain, bootstrap-peers the hosts to host 0, drives
//! real consensus, and exposes synchronous observation hooks (committed
//! heights and state roots, beacon state, transaction status) plus per-host
//! fault gates. The portable scenarios drive it through the `ProdCluster`
//! adaptor rather than injecting `ShardCommand`s, so the production
//! beacon-fold → duty → flip chain runs end to end.
//!
//! These are real-time tests: there is no logical clock. Callers set a
//! small `epoch_duration_ms` and mark `#[serial]`.

use std::collections::HashMap;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use arc_swap::ArcSwap;
use hyperscale_beacon::genesis::{build_genesis, seed_founding_members};
use hyperscale_engine::GenesisConfig;
use hyperscale_network_libp2p::fault::{DropSpec, HostId, RuleHandle};
use hyperscale_network_libp2p::{Libp2pAdapter, Libp2pConfig};
use hyperscale_node::{SharedTopologySnapshot, TxStatusCache, network_genesis_block};
use hyperscale_production::rpc::{NodeStatusState, TxSubmissionSender};
use hyperscale_production::{
    LocalValidator, ProductionRunner, RunnerError, ShardCommand, ShutdownHandle, StorageFactory,
    shard_data_dir,
};
use hyperscale_scenarios::query::{
    RanAs, chain_fate, chain_membership, declines_naming, reads_record, records_naming,
};
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BeaconChainReader, BeaconStorage, ShardChainReader, SubstateStore};
use hyperscale_storage_rocksdb::{RocksDbBeaconStorage, RocksDbShardStorage};
use hyperscale_types::{
    BeaconChainConfig, BeaconState, BlockHeight, ChainOrigin, GenesisValidators, ShardId,
    StateRoot, SubstateKey, TopologySnapshot, Transaction, TransactionDecision, TransactionStatus,
    TxHash, TxsInFlight, ValidatorId, shard_prefix_path,
};
use libp2p::{Multiaddr, PeerId};
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, spawn};
use tokio::time::{sleep, timeout};

use super::temp_storage_dir;

/// Per-host registry of every `RocksDbShardStorage` the host has opened —
/// the startup shards plus any the supervisor opens at a reshape flip or a
/// runtime join. Entries are `Weak`: the harness observes the runner's
/// stores, it never extends their lives. A strong clone here would hold the
/// `RocksDB` directory lock through the runner's teardown, and any later
/// re-seat of the host onto that shard — a halt-recovery redraw of a
/// jailed-out member — would spin forever on "lock hold by current
/// process" at the storage open. Reads upgrade per call: a torn-down
/// shard's entry resolves `None`, and the cluster-level scan finds a host
/// that still serves the shard.
pub type StoreRegistry = Arc<Mutex<HashMap<ShardId, Weak<RocksDbShardStorage>>>>;

/// How long to wait for host 0 to surface a listen address before
/// bootstrapping the rest of the cluster to it.
const LISTEN_ADDR_TIMEOUT: Duration = Duration::from_secs(5);

/// Graceful-shutdown budget per host on teardown.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Like [`temp_storage_factory`], but records every opened store into a
/// shared registry so the harness can scan a runtime-joined shard's chain
/// (a split child, a merged parent) the same way it scans a startup shard.
///
/// Only a store at the shard's own directory is recorded; a rebuild's
/// staging store beside it holds no chain the harness should read.
fn capturing_storage_factory(dir: &TempDir, registry: StoreRegistry) -> StorageFactory {
    let resolve = temp_storage_dir(dir);
    Arc::new(move |path: &Path, shard: ShardId| {
        let store = RocksDbShardStorage::open(path, shard_prefix_path(shard))
            .map(Arc::new)
            .map_err(|e| format!("{e:?}"))?;
        if path == resolve(shard) {
            registry
                .lock()
                .expect("store registry")
                .insert(shard, Arc::downgrade(&store));
        }
        Ok(store)
    })
}

/// One host's seating: the validators it runs. Shard participation is not
/// named — the runner derives each validator's seat (or pool membership)
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
    /// Per-message outbound latency injected on every host's libp2p sends.
    /// Zero-latency localhost lets a loadless committee form quorum
    /// certificates dozens of times a second — far faster than any real
    /// deployment — which floods this single-process harness and lags the
    /// consensus clock behind wall-clock. A scenario whose reshape duties
    /// must seat inside the real-time budget sets a realistic delay to pace
    /// quorum formation to a few blocks a second; scenarios that only check
    /// liveness leave it at [`Duration::ZERO`].
    pub simulated_outbound_latency: Duration,
}

/// A running host: its network adapter, RPC status slot, beacon store,
/// the live shard-store registry and transaction hooks, and the handles
/// to shut it down and join its runner task.
struct Host {
    /// The validators this host runs, for routing a submission to a
    /// host the beacon seats on the shard rather than one still carrying
    /// a retired loop.
    validator_ids: Vec<ValidatorId>,
    /// The same validators with their signers, for rebuilding the host
    /// on a restart.
    validators: Vec<LocalValidator>,
    adapter: Arc<Libp2pAdapter>,
    rpc_status: Arc<ArcSwap<NodeStatusState>>,
    beacon_storage: Arc<RocksDbBeaconStorage>,
    /// Submit a transaction into this host's process (the production
    /// analog of the sim's `ProcessScopedInput::SubmitTransaction`): routes
    /// to the touched shards' mempools, gossiping any it doesn't host.
    tx_submission: TxSubmissionSender,
    /// Process-wide status cache — every shard thread on this host records
    /// its terminal verdict here, the only place a counterpart abort (which
    /// never lands on-chain) is observable.
    tx_status: Arc<TxStatusCache>,
    /// Every `RocksDbShardStorage` this host has opened, shared live with
    /// the runner for chain scans and byte-total reads.
    stores: StoreRegistry,
    /// Membership commands into this host's supervisor.
    reconfigure: mpsc::Sender<ShardCommand>,
    /// The topology snapshot this host's shards and supervisor read.
    topology: SharedTopologySnapshot,
    shutdown: Option<ShutdownHandle>,
    join: JoinHandle<Result<(), RunnerError>>,
}

/// A running multi-host production cluster.
pub struct Harness {
    hosts: Vec<Host>,
    /// Each host's data directory, by host index. Kept alive for the
    /// cluster's lifetime; the on-disk stores are deleted only when the
    /// cluster (and these) drop, so a restarted host reopens what its
    /// previous run left.
    temp_dirs: Vec<TempDir>,
    /// What every host is built from, for rebuilding one on a restart.
    build: ClusterBuild,
}

/// The cluster-wide build inputs every host shares.
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
        let boot = build_genesis(&self.genesis, self.beacon_chain_config, &config.pools);
        seed_founding_members(&boot.state, &mut config.pools);
        config
    }
}

impl Harness {
    /// Build and start the cluster: open per-host stores, build runners,
    /// bootstrap-peer the hosts to host 0, and spawn every runner. The
    /// adapters peer during the build; consensus starts when the runners
    /// are spawned.
    pub async fn start(spec: ClusterSpec) -> Self {
        let ClusterSpec {
            genesis,
            hosts,
            beacon_chain_config,
            genesis_config,
            simulated_outbound_latency,
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
                genesis: &genesis,
                validators: host.validators,
                beacon_chain_config: chain_config,
                genesis_config: genesis_config.clone(),
                bootstrap_peers,
                simulated_outbound_latency,
            });
            if idx == 0 {
                bootstrap_addr = Some(wait_for_listen_addr(&built_host.adapter).await);
            }
            temp_dirs.push(temp_dir);
            built.push(built_host);
        }

        // Spawn every runner now that all adapters are peering.
        let running = built.into_iter().map(spawn_host).collect();

        Self {
            hosts: running,
            temp_dirs,
            build: ClusterBuild {
                genesis,
                beacon_chain_config: chain_config,
                genesis_config,
                simulated_outbound_latency,
            },
        }
    }

    /// Restart host `host` with its stores for `shards` wiped: shut the
    /// host down, and rebuild it over a copy of its data directory with
    /// those stores left out, so its beacon chain and every other shard's
    /// store survive. The rebuilt host bootstraps to another
    /// running host. Returns the topology the rebuilt host starts on, read
    /// before its runner runs and so before it folds any beacon block.
    ///
    /// The rebuild runs on a copy because a stopped runner's process
    /// resources are not all released in-process, and `RocksDB` refuses a
    /// second open of a directory the process still holds. The copy is
    /// what a restarted process would find on disk: the runner has
    /// stopped writing, and its transport is closed.
    ///
    /// # Panics
    ///
    /// Panics if the cluster has a single host (nothing to bootstrap to)
    /// or the copy fails.
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
        self.restart_with(host, shards, Replacement::InstalledGenesis)
            .await
    }

    /// Restart host `host` with its stores for split `children` replaced
    /// by clones of its store for their `parent` that no adoption ran
    /// over: the disk a parent half leaves when it crashes between
    /// seeding a child's store and adopting the child's genesis into it.
    /// Otherwise as [`Self::restart_with_wiped_shards`].
    pub async fn restart_with_unadopted_clones(
        &mut self,
        host: usize,
        parent: ShardId,
        children: &[ShardId],
    ) -> Arc<TopologySnapshot> {
        self.restart_with(host, children, Replacement::ParentClone(parent))
            .await
    }

    async fn restart_with(
        &mut self,
        host: usize,
        shards: &[ShardId],
        replacement: Replacement,
    ) -> Arc<TopologySnapshot> {
        let peer = (0..self.hosts.len())
            .find(|&i| i != host)
            .expect("a restart bootstraps to another host");
        let bootstrap = wait_for_listen_addr(&self.hosts[peer].adapter).await;

        let mut old = self.hosts.remove(host);
        if let Some(s) = old.shutdown.take() {
            s.shutdown();
        }
        let _ = timeout(SHUTDOWN_TIMEOUT, old.join).await;

        let data = TempDir::new().expect("temp dir");
        let wiped: Vec<PathBuf> = shards
            .iter()
            .map(|&shard| shard_data_dir(self.temp_dirs[host].path(), shard))
            .collect();
        copy_dir_except(self.temp_dirs[host].path(), data.path(), &wiped)
            .expect("copy the host's data directory");
        match replacement {
            Replacement::Wiped => {}
            Replacement::InstalledGenesis => {
                let topology = self.hosts[peer - usize::from(peer > host)]
                    .topology
                    .load_full();
                let config = self.build.network_genesis_config();
                for &shard in shards {
                    let store = RocksDbShardStorage::open(
                        shard_data_dir(data.path(), shard),
                        shard_prefix_path(shard),
                    )
                    .expect("open the store the genesis installs into");
                    let _ = network_genesis_block(&store, shard, &topology, &config);
                }
            }
            Replacement::ParentClone(parent) => {
                let store = RocksDbShardStorage::open(
                    shard_data_dir(data.path(), parent),
                    shard_prefix_path(parent),
                )
                .expect("open the parent store the clones are cut from");
                for &shard in shards {
                    store
                        .checkpoint_into(&shard_data_dir(data.path(), shard))
                        .expect("clone the parent store");
                }
            }
        }
        self.temp_dirs[host] = data;
        let built = build_host(BuildHostArgs {
            temp_dir: &self.temp_dirs[host],
            genesis: &self.build.genesis,
            validators: old.validators,
            beacon_chain_config: self.build.beacon_chain_config,
            genesis_config: self.build.genesis_config.clone(),
            bootstrap_peers: vec![bootstrap],
            simulated_outbound_latency: self.build.simulated_outbound_latency,
        });
        let startup = built.runner.topology_snapshot().load_full();
        self.hosts.insert(host, spawn_host(built));
        startup
    }

    /// Number of hosts in the cluster.
    pub const fn host_count(&self) -> usize {
        self.hosts.len()
    }

    /// Membership commands into `host`'s supervisor.
    pub fn reconfigure(&self, host: usize) -> mpsc::Sender<ShardCommand> {
        self.hosts[host].reconfigure.clone()
    }

    /// The topology snapshot `host` reads.
    pub fn topology(&self, host: usize) -> SharedTopologySnapshot {
        Arc::clone(&self.hosts[host].topology)
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

    /// The committed JMT root for `shard`, read straight off a serving host's
    /// live store — for typed comparison against a beacon-composed anchor.
    /// `None` if no host serves `shard`.
    pub fn committed_state_root(&self, shard: ShardId) -> Option<StateRoot> {
        self.store_for(shard).map(|store| store.state_root())
    }

    /// The committed height on `shard` at host `host` specifically — read off
    /// that host's own RPC status, not the cluster-wide max — so a scenario can
    /// watch a lagging fragment catch up after a heal.
    pub fn host_committed_height(&self, host: usize, shard: ShardId) -> Option<u64> {
        let key = shard.inner();
        self.hosts
            .get(host)?
            .rpc_status
            .load()
            .vnodes
            .iter()
            .find(|v| v.shard == key)
            .map(|v| v.block_height)
    }

    /// The raw committed JMT root for `shard` on host `host` specifically, read
    /// off that host's own live store. `None` if host `host` serves no vnode
    /// there.
    pub fn host_committed_state_root(&self, host: usize, shard: ShardId) -> Option<StateRoot> {
        self.host_store(host, shard).map(|store| store.state_root())
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

    /// Submit a transaction into host `idx`'s process — the production
    /// analog of the sim's `ProcessScopedInput::SubmitTransaction`. The
    /// process computes the touched-shard fanout and admits onto every
    /// hosted shard's mempool, gossiping any it doesn't host. Returns
    /// `false` only when the host is shutting down. Submit through a host
    /// that runs the transaction's source shard so it admits directly
    /// rather than relying on a gossip hop.
    pub fn submit_transaction(&self, idx: usize, tx: Arc<Transaction>) -> bool {
        (self.hosts[idx].tx_submission)(tx)
    }

    /// The terminal verdict host `idx`'s process recorded for `hash`, if
    /// any. Mirrors the sim's `tx_status`: a counterpart abort never lands
    /// on-chain, so this status cache is the only place it surfaces.
    pub fn tx_status(&self, idx: usize, hash: &TxHash) -> Option<TransactionStatus> {
        self.hosts[idx]
            .tx_status
            .get(hash)
            .map(|(status, _)| status)
    }

    /// The first host index serving `shard`, if any — used to address a
    /// transaction's source committee.
    pub fn host_serving(&self, shard: ShardId) -> Option<usize> {
        self.hosts
            .iter()
            .position(|h| h.adapter.local_shards().contains(&shard))
    }

    /// The first host serving `shard` that runs one of `committee`, if
    /// any — a host the beacon seats there, not one whose supervisor has
    /// yet to retire a replaced loop.
    pub fn host_serving_in(&self, shard: ShardId, committee: &[ValidatorId]) -> Option<usize> {
        self.hosts.iter().position(|h| {
            h.adapter.local_shards().contains(&shard)
                && h.validator_ids.iter().any(|v| committee.contains(v))
        })
    }

    /// The host running `validator`, if any.
    pub fn host_of(&self, validator: ValidatorId) -> Option<usize> {
        self.hosts
            .iter()
            .position(|h| h.validator_ids.contains(&validator))
    }

    /// Every host index serving `shard` — its committee members, before a
    /// terminating reshape relocates them.
    pub fn hosts_serving(&self, shard: ShardId) -> Vec<usize> {
        self.hosts
            .iter()
            .enumerate()
            .filter(|(_, h)| h.adapter.local_shards().contains(&shard))
            .map(|(i, _)| i)
            .collect()
    }

    /// A live handle to any host's `RocksDbShardStorage` for `shard`. Every
    /// committee member commits the same chain, so the first match suffices.
    /// A host whose runner has torn the shard down upgrades to `None` and is
    /// skipped — only stores the consensus threads actually hold are read.
    fn store_for(&self, shard: ShardId) -> Option<Arc<RocksDbShardStorage>> {
        self.hosts.iter().find_map(|h| {
            h.stores
                .lock()
                .expect("store registry")
                .get(&shard)
                .and_then(Weak::upgrade)
        })
    }

    /// The committed value of `key` on `shard`, read off the furthest-along
    /// live store any host holds for it, at that store's own JMT height.
    /// The greatest height rather than the first host: a reseated or
    /// merged host holds a frozen predecessor under the same id, and only
    /// the live copy has committed past the cut. `None` when no host
    /// serves `shard`, the height is unavailable, or the cell is absent.
    pub fn substate(&self, shard: ShardId, key: SubstateKey) -> Option<Vec<u8>> {
        let store = self
            .hosts
            .iter()
            .filter_map(|h| {
                h.stores
                    .lock()
                    .expect("store registry")
                    .get(&shard)
                    .and_then(Weak::upgrade)
            })
            .max_by_key(|store| store.jmt_height())?;
        store.get_substate_at_height(key, store.jmt_height())?
    }

    /// A live handle to host `host`'s `RocksDbShardStorage` for `shard`, or
    /// `None` if that host does not currently hold one there.
    fn host_store(&self, host: usize, shard: ShardId) -> Option<Arc<RocksDbShardStorage>> {
        self.hosts
            .get(host)?
            .stores
            .lock()
            .expect("store registry")
            .get(&shard)
            .and_then(Weak::upgrade)
    }

    /// Where `shard`'s chain starts, read off the live store's recovered
    /// consensus state. `None` if no host serves `shard`.
    pub fn chain_origin(&self, shard: ShardId) -> Option<ChainOrigin> {
        let store = self.store_for(shard)?;
        Some(store.load_recovered_state(shard).chain_origin)
    }

    /// The work `shard`'s committed tip leaves owing against the drain,
    /// read off the tip header the live store holds. `None` if no host
    /// serves `shard` or the tip carries no header.
    pub fn committed_txs_in_flight(&self, shard: ShardId) -> Option<TxsInFlight> {
        let store = self.store_for(shard)?;
        store
            .get_certified_header(store.committed_height())
            .map(|header| header.header().txs_in_flight())
    }

    /// [`chain_membership`] over the live store — what `shard`'s own
    /// certificates said it ran of `hash`. Empty if no host serves
    /// `shard` or no committed finalization names it.
    pub fn ran(&self, shard: ShardId, hash: TxHash) -> Vec<RanAs> {
        self.store_for(shard)
            .map_or_else(Vec::new, |store| chain_membership(store.as_ref(), hash))
    }

    /// [`records_naming`] over the live store — every record on `shard`'s
    /// chain naming `hash`. Empty if no host serves `shard`.
    pub fn named_unsettled(&self, shard: ShardId, hash: TxHash) -> Vec<(BlockHeight, ShardId)> {
        self.store_for(shard)
            .map_or_else(Vec::new, |store| records_naming(store.as_ref(), hash))
    }

    /// [`reads_record`] over the live store — whether `shard`'s chain has
    /// carried a held reading of `key`. False if no host serves `shard`.
    #[must_use]
    pub fn reads_record(&self, shard: ShardId, key: SubstateKey) -> bool {
        self.store_for(shard)
            .is_some_and(|store| reads_record(store.as_ref(), key))
    }

    /// [`declines_naming`] over the live store — every crossing on
    /// `shard`'s chain that it refused for `hash`.
    #[must_use]
    pub fn declined(&self, shard: ShardId, hash: TxHash) -> Vec<(BlockHeight, SubstateKey)> {
        self.store_for(shard)
            .map_or_else(Vec::new, |store| declines_naming(store.as_ref(), hash))
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
        let Some(store) = self.store_for(shard) else {
            return (None, None);
        };
        chain_fate(store.as_ref(), hash)
    }

    /// Signal every host to shut down and join its runner task. Drops the
    /// real shard threads so they don't leak across `#[serial]` tests.
    /// Idempotent: the hosts are drained, so a second call is a no-op.
    pub async fn shutdown(&mut self) {
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

/// A `0..host_count` host index as a [`HostId`].
fn host_id(index: usize) -> HostId {
    HostId(u32::try_from(index).expect("host index fits a HostId"))
}

/// Fault injection: drive every host's gate. The cluster addresses hosts by
/// index; each host's gate keys on [`HostId`].
impl Harness {
    /// Configure every host's gate with its own id and the full `PeerId →
    /// HostId` map, so partition and gossip filtering resolve peers. Call once
    /// before installing faults.
    pub fn fault_configure_all(&self) {
        let map: Vec<(PeerId, HostId)> = self
            .hosts
            .iter()
            .enumerate()
            .map(|(i, h)| (h.adapter.local_peer_id(), host_id(i)))
            .collect();
        for (i, host) in self.hosts.iter().enumerate() {
            host.adapter.fault_configure(host_id(i), map.clone());
        }
    }

    /// Install `spec` as a drop rule on every host's gate; one handle per host.
    pub fn fault_install_drop(&self, spec: &DropSpec) -> Vec<RuleHandle> {
        self.hosts
            .iter()
            .map(|h| h.adapter.fault_gate().install_drop(spec.clone()))
            .collect()
    }

    /// Partition host groups `a` and `b` — each side blocks the other, so both
    /// outbound unicast and inbound gossip are cut in both directions.
    pub fn fault_partition(&self, a: &[usize], b: &[usize]) {
        for &i in a {
            for &j in b {
                self.hosts[i].adapter.fault_gate().block_host(host_id(j));
                self.hosts[j].adapter.fault_gate().block_host(host_id(i));
            }
        }
    }

    /// Partition groups `a` and `b` during each of `windows`, offsets from
    /// now on each host's own gate clock.
    pub fn fault_partition_during(&self, a: &[usize], b: &[usize], windows: &[Range<Duration>]) {
        for &i in a {
            for &j in b {
                self.hosts[i]
                    .adapter
                    .fault_gate()
                    .block_host_during(host_id(j), windows);
                self.hosts[j]
                    .adapter
                    .fault_gate()
                    .block_host_during(host_id(i), windows);
            }
        }
    }

    /// Isolate one host: it blocks every other, and every other blocks it.
    pub fn fault_isolate(&self, host: usize) {
        self.hosts[host].adapter.fault_gate().block_all_hosts();
        for (i, h) in self.hosts.iter().enumerate() {
            if i != host {
                h.adapter.fault_gate().block_host(host_id(host));
            }
        }
    }

    /// Heal the partition between hosts `a` and `b` only — each side lifts
    /// its block against the other, leaving every other cut intact.
    pub fn fault_heal_between(&self, a: usize, b: usize) {
        self.hosts[a].adapter.fault_gate().unblock_host(host_id(b));
        self.hosts[b].adapter.fault_gate().unblock_host(host_id(a));
    }

    /// Heal every partition on every host.
    pub fn fault_heal_all(&self) {
        for h in &self.hosts {
            h.adapter.fault_gate().heal();
        }
    }

    /// Remove every installed drop rule on every host, leaving partitions intact.
    pub fn fault_clear_all(&self) {
        for h in &self.hosts {
            h.adapter.fault_gate().clear_faults();
        }
    }
}

/// Spawn a built host's runner and keep the handles the harness drives it
/// through.
fn spawn_host(mut bh: BuiltHost) -> Host {
    let shutdown = bh.runner.shutdown_handle().expect("shutdown handle");
    let reconfigure = bh.runner.reconfigure_handle();
    let topology = Arc::clone(bh.runner.topology_snapshot());
    let join = spawn(bh.runner.run());
    Host {
        validator_ids: bh.validator_ids,
        validators: bh.validators,
        adapter: bh.adapter,
        rpc_status: bh.rpc_status,
        beacon_storage: bh.beacon_storage,
        tx_submission: bh.tx_submission,
        tx_status: bh.tx_status,
        stores: bh.stores,
        reconfigure,
        topology,
        shutdown: Some(shutdown),
        join,
    }
}

/// A built-but-not-yet-spawned host.
struct BuiltHost {
    validator_ids: Vec<ValidatorId>,
    validators: Vec<LocalValidator>,
    runner: ProductionRunner,
    adapter: Arc<Libp2pAdapter>,
    rpc_status: Arc<ArcSwap<NodeStatusState>>,
    beacon_storage: Arc<RocksDbBeaconStorage>,
    tx_submission: TxSubmissionSender,
    tx_status: Arc<TxStatusCache>,
    stores: StoreRegistry,
}

struct BuildHostArgs<'a> {
    temp_dir: &'a TempDir,
    genesis: &'a GenesisValidators,
    validators: Vec<LocalValidator>,
    beacon_chain_config: BeaconChainConfig,
    genesis_config: Option<GenesisConfig>,
    bootstrap_peers: Vec<Multiaddr>,
    simulated_outbound_latency: Duration,
}

/// Build a host's runner (the adapter binds and starts peering immediately;
/// the runner is spawned separately). The runner derives the host's seats
/// from the beacon genesis and opens their stores through the factory, so
/// nothing is pre-opened here.
fn build_host(args: BuildHostArgs<'_>) -> BuiltHost {
    let beacon_storage = Arc::new(
        RocksDbBeaconStorage::open(args.temp_dir.path().join("beacon_db")).expect("open beacon db"),
    );
    let rpc_status = Arc::new(ArcSwap::new(Arc::new(NodeStatusState {
        // Genesis is always a single ROOT shard; the runner republishes the live
        // count from the committed beacon state on its first status tick.
        num_shards: 1,
        ..Default::default()
    })));

    let network_config = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: args.bootstrap_peers,
        simulated_outbound_latency: args.simulated_outbound_latency,
        ..Default::default()
    };

    // The factory records every store it opens — startup seats and
    // reshape-opened children alike — into this registry, which starts empty.
    let stores: StoreRegistry = Arc::new(Mutex::new(HashMap::new()));

    let beacon_reader: Arc<dyn BeaconStorage> = beacon_storage.clone();
    let validator_ids: Vec<ValidatorId> = args.validators.iter().map(|v| v.validator_id).collect();
    let validators = args.validators.clone();
    let mut builder = ProductionRunner::builder(
        args.validators,
        args.genesis.clone(),
        ShardConsensusConfig::default(),
        beacon_reader,
        network_config,
        capturing_storage_factory(args.temp_dir, Arc::clone(&stores)),
        temp_storage_dir(args.temp_dir),
    )
    .beacon_chain_config(args.beacon_chain_config)
    .rpc_status(Arc::clone(&rpc_status));
    if let Some(cfg) = args.genesis_config {
        builder = builder.genesis_config(cfg);
    }
    let runner = builder.build().expect("build runner");
    let adapter = Arc::clone(runner.network());
    // Capture the submission + status hooks before `run()` consumes the host.
    let tx_submission = runner.tx_submission_sender();
    let tx_status = runner.tx_status_cache();

    BuiltHost {
        validator_ids,
        validators,
        runner,
        adapter,
        rpc_status,
        beacon_storage,
        tx_submission,
        tx_status,
        stores,
    }
}

/// What a restart puts in place of each store it drops.
enum Replacement {
    /// Nothing: the store is gone.
    Wiped,
    /// A store that installed the network genesis and committed nothing.
    InstalledGenesis,
    /// A clone of the host's store for this split parent, never adopted.
    ParentClone(ShardId),
}

/// Copy the tree at `from` into `to`, leaving out the subtrees at `skip`.
fn copy_dir_except(from: &Path, to: &Path, skip: &[PathBuf]) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let path = entry.path();
        if skip.contains(&path) {
            continue;
        }
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_except(&path, &target, skip)?;
        } else {
            std::fs::copy(&path, &target)?;
        }
    }
    Ok(())
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
