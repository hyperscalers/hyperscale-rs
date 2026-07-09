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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use hex::encode as hex_encode;
use hyperscale_engine::GenesisConfig;
use hyperscale_network_libp2p::fault::{DropSpec, HostId, RuleHandle};
use hyperscale_network_libp2p::{Libp2pAdapter, Libp2pConfig};
use hyperscale_node::TxStatusCache;
use hyperscale_production::rpc::{NodeStatusState, TxSubmissionSender};
use hyperscale_production::{
    LocalValidator, ProductionRunner, RunnerError, ShutdownHandle, StorageFactory,
};
use hyperscale_scenarios::query::chain_fate;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BeaconChainReader, BeaconStorage, ShardChainReader, SubstateStore};
use hyperscale_storage_rocksdb::{RocksDbBeaconStorage, RocksDbShardStorage};
use hyperscale_types::{
    BeaconChainConfig, BeaconState, BlockHeight, Epoch, GenesisValidators, PendingReshape,
    RoutableTransaction, ShardId, StateRoot, TransactionDecision, TransactionStatus, TxHash,
    shard_prefix_path,
};
use libp2p::{Multiaddr, PeerId};
use tempfile::TempDir;
use tokio::task::{JoinHandle, spawn};
use tokio::time::{sleep, timeout};

use super::temp_storage_dir;

/// Per-host registry of every `RocksDbShardStorage` the host has opened —
/// the startup shards plus any the supervisor opens at a reshape flip.
/// Shared with the live runner (`RocksDB` permits concurrent reads on a
/// single open handle), so a test scans committed chains and reads byte
/// totals straight off the same store the consensus threads write into,
/// no second open and no lock contention.
pub type StoreRegistry = Arc<Mutex<HashMap<ShardId, Arc<RocksDbShardStorage>>>>;

/// How long to wait for host 0 to surface a listen address before
/// bootstrapping the rest of the cluster to it.
const LISTEN_ADDR_TIMEOUT: Duration = Duration::from_secs(5);

/// Cadence for the `await_*` observation polls.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Graceful-shutdown budget per host on teardown.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Like [`temp_storage_factory`], but records every opened store into a
/// shared registry so the harness can scan a runtime-joined shard's chain
/// (a split child, a merged parent) the same way it scans a startup shard.
fn capturing_storage_factory(dir: &TempDir, registry: StoreRegistry) -> StorageFactory {
    let resolve = temp_storage_dir(dir);
    Arc::new(move |shard: ShardId| {
        let store = RocksDbShardStorage::open(resolve(shard), shard_prefix_path(shard))
            .map(Arc::new)
            .map_err(|e| format!("{e:?}"))?;
        registry
            .lock()
            .expect("store registry")
            .insert(shard, Arc::clone(&store));
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

/// Inputs for [`Cluster::start`].
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
        let mut running = Vec::with_capacity(built.len());
        for mut bh in built {
            let shutdown = bh.runner.shutdown_handle().expect("shutdown handle");
            let join = spawn(bh.runner.run());
            running.push(Host {
                adapter: bh.adapter,
                rpc_status: bh.rpc_status,
                beacon_storage: bh.beacon_storage,
                tx_submission: bh.tx_submission,
                tx_status: bh.tx_status,
                stores: bh.stores,
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

    /// The raw committed JMT root for `shard`, read straight off a serving
    /// host's live store — the byte-exact `StateRoot` that
    /// [`Self::committed_state_root`] hex encodes, for typed comparison against
    /// a beacon-composed anchor. `None` if no host serves `shard`.
    pub fn committed_state_root_raw(&self, shard: ShardId) -> Option<StateRoot> {
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

    /// The number of keepers drawn for a merge into `parent`, once the
    /// beacon has paired it (both children hold a live half). `None` before
    /// pairing.
    pub fn merge_keeper_count(&self, parent: ShardId) -> Option<usize> {
        self.beacon_state()
            .and_then(|state| match state.pending_reshapes.get(&parent) {
                Some(PendingReshape::Merge {
                    keepers,
                    admitted_at: Some(_),
                    ..
                }) => Some(keepers.len()),
                _ => None,
            })
    }

    /// Wait until the beacon pairs a merge into `parent` with exactly
    /// `keepers` keepers drawn. Panics on timeout.
    pub async fn await_merge_paired(&self, parent: ShardId, keepers: usize, within: Duration) {
        self.poll(within, || {
            self.merge_keeper_count(parent)
                .filter(|count| *count == keepers)
                .map(|_| ())
        })
        .await
        .unwrap_or_else(|| {
            panic!(
                "merge into {parent:?} did not pair {keepers} keepers within {within:?}; \
                 latest keeper count = {:?}",
                self.merge_keeper_count(parent)
            )
        });
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

    /// Submit a transaction into host `idx`'s process — the production
    /// analog of the sim's `ProcessScopedInput::SubmitTransaction`. The
    /// process computes the touched-shard fanout and admits onto every
    /// hosted shard's mempool, gossiping any it doesn't host. Returns
    /// `false` only when the host is shutting down. Submit through a host
    /// that runs the transaction's source shard so it admits directly
    /// rather than relying on a gossip hop.
    pub fn submit_transaction(&self, idx: usize, tx: Arc<RoutableTransaction>) -> bool {
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
    fn store_for(&self, shard: ShardId) -> Option<Arc<RocksDbShardStorage>> {
        self.hosts.iter().find_map(|h| {
            h.stores
                .lock()
                .expect("store registry")
                .get(&shard)
                .cloned()
        })
    }

    /// A live handle to host `host`'s `RocksDbShardStorage` for `shard`, or
    /// `None` if that host has not opened one there.
    fn host_store(&self, host: usize, shard: ShardId) -> Option<Arc<RocksDbShardStorage>> {
        self.hosts
            .get(host)?
            .stores
            .lock()
            .expect("store registry")
            .get(&shard)
            .cloned()
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

    /// The committed JMT byte total `shard` carries at its tip — the input
    /// to the reshape threshold. Lets a straddle test measure and bracket
    /// `split_bytes` against the real production genesis rather than guess.
    pub fn substate_bytes(&self, shard: ShardId) -> Option<u64> {
        let store = self.store_for(shard)?;
        store.substate_bytes_at_version(store.committed_height().inner())
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
impl Cluster {
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

/// A built-but-not-yet-spawned host.
struct BuiltHost {
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
        runner,
        adapter,
        rpc_status,
        beacon_storage,
        tx_submission,
        tx_status,
        stores,
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
