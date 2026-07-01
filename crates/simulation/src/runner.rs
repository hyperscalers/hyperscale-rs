//! Deterministic simulation runner.
//!
//! Uses [`NodeHost`] to process all actions per-node, with the simulation harness
//! controlling event scheduling, network delivery, and time.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use crossbeam::channel::{Receiver, Sender, unbounded};
use hyperscale_beacon::genesis::{GenesisBoot, build_genesis};
use hyperscale_core::{ParticipationChange, ProtocolEvent, TimerId};
use hyperscale_dispatch_sync::SyncDispatch;
use hyperscale_engine::{GenesisConfig, RadixExecutor, TransactionValidation};
use hyperscale_mempool::MempoolConfig;
use hyperscale_network_memory::{
    BandwidthReport, HostLayout, NetworkConfig, NetworkTrafficAnalyzer, NodeIndex,
    SimNetworkAdapter, SimulatedNetwork,
};
use hyperscale_node::reshape::orchestrator::{ReshapeEvent, ReshapeOrchestrator};
use hyperscale_node::shard::{HostEvent, StepOutput};
use hyperscale_node::{
    NodeConfig, NodeHost, NodeStateMachine, SeatFollower, SeatVnodeGroup, ShardGenesis, TimerOp,
    VnodeInit, seat_follower, seat_vnode_group, timer_event,
};
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BeaconStorage, RecoveredState};
use hyperscale_storage_memory::{SimBeaconStorage, SimShardStorage};
use hyperscale_types::{
    BeaconChainConfig, Bls12381G1PrivateKey, Bls12381G1PublicKey, Epoch, GenesisConfigHash,
    GenesisValidators, LocalTimestamp, ShardId, TopologySnapshot, TransactionStatus, TxHash,
    ValidatorId, ValidatorInfo, ValidatorSet, bls_keypair_from_seed, shard_prefix_path,
};
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use tracing::{debug, info, trace};

use crate::event_queue::EventKey;

pub mod relocation;
pub mod reshape;
pub mod system_action;

use reshape::ReshapeStore;

/// Cluster and transport configuration for a simulation.
///
/// Genesis is always a single ROOT shard: the network reaches a multi-shard
/// topology by driving the real split lifecycle (`grow_to`), never by
/// genesising into it. The cluster fields describe the genesis committee and
/// host bundling; the latency / jitter / loss fields configure the transport,
/// which the runner hands over as a [`NetworkConfig`].
#[derive(Debug, Clone)]
pub struct SimConfig {
    /// Committee size each shard maintains. Genesis seats its single ROOT
    /// shard with this many validators; each split child is drawn to the same
    /// size from the pool.
    pub shard_size: u32,
    /// Consecutive validators bundled into each host. Must divide
    /// `shard_size`.
    pub vnodes_per_host: u32,
    /// Validators registered in beacon genesis beyond the ROOT committee.
    /// They land `Pooled` and run no host, giving the shuffle refill stock
    /// and the cohorts each `grow_to` split draws.
    pub pool_extra_validators: u32,
    /// Give each pool extra its own shard-less follower host instead of
    /// leaving it host-less — the layout the shuffle's cross-shard relocation
    /// needs (a vnode can move onto a host not already serving the
    /// destination). Default `false` preserves the co-hosting layout.
    pub dedicated_pool_hosts: bool,
    /// Override the beacon chain config (epoch duration, committee sizes).
    /// `None` uses [`BeaconChainConfig::default`].
    pub beacon_chain_config: Option<BeaconChainConfig>,
    /// Base latency between two hosts that serve a shard in common.
    pub intra_shard_latency: Duration,
    /// Base latency between two hosts that serve no shard in common.
    pub cross_shard_latency: Duration,
    /// Jitter as a fraction of base latency (0.0 - 1.0).
    pub jitter_fraction: f64,
    /// Packet loss rate (0.0 - 1.0).
    pub packet_loss_rate: f64,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            shard_size: 4,
            vnodes_per_host: 1,
            pool_extra_validators: 0,
            dedicated_pool_hosts: false,
            beacon_chain_config: None,
            intra_shard_latency: Duration::from_millis(150),
            cross_shard_latency: Duration::from_millis(150),
            jitter_fraction: 0.1,
            packet_loss_rate: 0.0,
        }
    }
}

impl SimConfig {
    /// The transport-only config the simulated network consumes.
    const fn network_config(&self) -> NetworkConfig {
        NetworkConfig {
            intra_shard_latency: self.intra_shard_latency,
            cross_shard_latency: self.cross_shard_latency,
            jitter_fraction: self.jitter_fraction,
            packet_loss_rate: self.packet_loss_rate,
        }
    }
}

/// Type alias for the simulation's concrete `NodeHost`.
type SimHost = NodeHost<SimShardStorage, SimNetworkAdapter, SyncDispatch>;

/// Logical cadence at which a syncing follower pool retries deferred
/// beacon-block fetches. Mirrors the production pool thread's tick interval;
/// an idle pool schedules none.
const POOL_FETCH_TICK_INTERVAL: Duration = Duration::from_secs(1);

/// Deterministic simulation runner.
///
/// Processes events in deterministic order using [`NodeHost`] for action handling.
/// Given the same seed, produces identical results every run.
///
/// Each node has its own independent storage and executor inside its `NodeHost`.
/// The harness controls the event queue, network delivery (latency, partitions,
/// packet loss), and time advancement.
pub struct SimulationRunner {
    /// Per-node `NodeHost` instances. Index corresponds to `NodeIndex`.
    hosts: Vec<SimHost>,

    /// Per-node event receivers (from crossbeam channels passed to `NodeHost`).
    event_rxs: Vec<Receiver<HostEvent>>,

    /// Per-node event senders, retained so a shard added at runtime
    /// (vnode relocation) can be wired onto the host's existing channel.
    event_txs: Vec<Sender<HostEvent>>,

    /// Signing keys for every registered validator, retained so a
    /// relocated vnode's state machine can be rebuilt on its new shard.
    signing_keys: Vec<Arc<Bls12381G1PrivateKey>>,

    /// Beacon genesis config hash, retained for runtime-built
    /// `BeaconCoordinator`s.
    beacon_config_hash: GenesisConfigHash,

    /// Beacon network definition, retained for runtime-built
    /// `BeaconCoordinator`s.
    beacon_network: NetworkDefinition,

    /// Placement deltas the hosted vnodes emitted via
    /// `Action::ReconfigureParticipation`, in deterministic event
    /// order. Drained by the harness via
    /// [`Self::take_reconfigurations`].
    pending_reconfigurations: Vec<(NodeIndex, ParticipationChange)>,

    /// Global event queue, ordered deterministically.
    event_queue: BTreeMap<EventKey, HostEvent>,

    /// Sequence counter for deterministic ordering.
    sequence: u64,

    /// Current simulation time.
    now: Duration,

    /// Network simulator (latency, partitions, packet loss).
    network: SimulatedNetwork,

    /// RNG for network conditions (seeded for determinism).
    rng: ChaCha8Rng,

    /// Timer registry for cancellation support.
    /// Maps `(node, timer_id) -> event_key` for removal.
    timers: HashMap<(NodeIndex, ShardId, TimerId), EventKey>,

    /// Statistics.
    stats: SimulationStats,

    /// Optional traffic analyzer for bandwidth estimation.
    traffic_analyzer: Option<Arc<NetworkTrafficAnalyzer>>,

    /// Last time gossip dedup caches were pruned.
    last_gossip_dedup_prune: Duration,

    /// Epoch window length from the beacon chain config, retained so a
    /// merge keeper's flip can recompute the cut the children crossed.
    epoch_duration_ms: u64,

    /// Per-host flag: whether a beacon-sync retry tick is already queued for
    /// the host's follower pool. Keeps the harness from scheduling duplicate
    /// ticks while a catch-up sync runs; production's pool thread self-ticks
    /// off its `select!` timeout instead.
    pool_tick_pending: Vec<bool>,

    /// One reshape orchestrator per host, each `me`-scoped to that host's home
    /// validators. Pumped once per slice by [`Self::pump_reshape`] — the
    /// deterministic counterpart of the production supervisor's per-host
    /// reshape pump.
    reshape: Vec<ReshapeOrchestrator>,

    /// In-flight reshape stores the orchestrators opened, imported, and adopted
    /// into, keyed by `(host, duty shard)`, held until the seat installs each.
    reshape_stores: HashMap<(NodeIndex, ShardId), ReshapeStore>,

    /// Per-host reshape fetches whose target block had not committed yet,
    /// carried to the next slice as `FetchFailed` events so the sequencer
    /// re-arms and re-requests — the in-memory stand-in for production's
    /// fetch callback firing on a later tick.
    reshape_pending: Vec<Vec<ReshapeEvent>>,

    /// Storage handles stashed by a placement leave, keyed by `(host, shard)`,
    /// so a later rejoin of the same shard takes the retained fast path —
    /// the in-memory stand-in for the production supervisor's retained store.
    retained_storages: HashMap<(NodeIndex, ShardId), SimShardStorage>,

    /// Per-host committed beacon epoch last reconciled by `pump_placement`.
    /// Committee membership only changes at an epoch boundary, so the
    /// reconciliation runs once per host per epoch rather than every slice.
    placement_epoch: Vec<Option<Epoch>>,

    /// Fixed home host per registered validator, by id. A validator's keys live
    /// on one host for the run, so the host whose orchestrator runs its reshape
    /// duties and seats it is stable — the simulation's stand-in for
    /// production's per-host key bundle. Committee validators home to their
    /// genesis host; pool extras home to their dedicated host, or round-robin
    /// across the committee hosts when co-hosted.
    validator_home: Vec<NodeIndex>,
}

/// Statistics collected during simulation.
#[derive(Debug, Default, Clone)]
pub struct SimulationStats {
    /// Total events processed.
    pub events_processed: u64,
    /// Events processed by type.
    pub events_by_priority: [u64; 4],
    /// Total actions generated.
    pub actions_generated: u64,
    /// Messages sent (successfully scheduled for delivery).
    pub messages_sent: u64,
    /// Messages dropped due to network partition.
    pub messages_dropped_partition: u64,
    /// Messages dropped due to packet loss.
    pub messages_dropped_loss: u64,
    /// Messages deduplicated (same message already received by node).
    pub messages_deduplicated: u64,
    /// Timers set.
    pub timers_set: u64,
    /// Timers cancelled.
    pub timers_cancelled: u64,
}

impl SimulationRunner {
    // ═══════════════════════════════════════════════════════════════════════
    // Construction
    // ═══════════════════════════════════════════════════════════════════════

    /// Create a new simulation runner with the given configuration.
    ///
    /// # Panics
    ///
    /// Panics if generated key bytes round-trip fails (unreachable; the keypair
    /// constructor produces canonical bytes).
    #[must_use]
    #[allow(clippy::too_many_lines)] // straight-line construction of per-shard hosts
    pub fn new(network_config: &SimConfig, seed: u64) -> Self {
        assert!(
            network_config.vnodes_per_host >= 1,
            "vnodes_per_host must be at least 1"
        );
        // The harness owns cluster placement: the host layout drives both the
        // transport's routing tables and the per-host vnode seating below.
        let host_layout = build_host_layout(network_config);
        let num_hosts = host_layout.len();
        let network = SimulatedNetwork::new(
            network_config.network_config(),
            network_layout(&host_layout),
        );
        let rng = ChaCha8Rng::seed_from_u64(seed);

        // Generate keys for all registered validators using deterministic
        // seeding. Pool extras are registered in beacon genesis (landing
        // `Pooled`, giving the shuffle refill stock) but run no host.
        let committee_size = network_config.shard_size;
        let registered_validators = committee_size + network_config.pool_extra_validators;
        let keys: Vec<Bls12381G1PrivateKey> = (0..registered_validators)
            .map(|i| {
                let mut seed_bytes = [0u8; 32];
                let key_seed = seed
                    .wrapping_add(u64::from(i))
                    .wrapping_mul(0x517c_c1b7_2722_0a95);
                seed_bytes[..8].copy_from_slice(&key_seed.to_le_bytes());
                seed_bytes[8..16].copy_from_slice(&u64::from(i).to_le_bytes());
                bls_keypair_from_seed(&seed_bytes)
            })
            .collect();
        let public_keys: Vec<Bls12381G1PublicKey> =
            keys.iter().map(Bls12381G1PrivateKey::public_key).collect();

        // Build global validator set (pool extras included — fold-derived
        // snapshots carry every registered validator, so genesis matches)
        let global_validators: Vec<ValidatorInfo> = (0..registered_validators)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(u64::from(i)),
                public_key: public_keys[i as usize],
            })
            .collect();
        let global_validator_set = ValidatorSet::new(global_validators);

        // Genesis is a single ROOT shard: the first `committee_size`
        // validators form its committee; the pool extras stay off-committee so
        // they land `Pooled`, giving the shuffle and each `grow_to` split a
        // cohort to draw.
        let root_committee: Vec<ValidatorId> = (0..committee_size)
            .map(|i| ValidatorId::new(u64::from(i)))
            .collect();
        let genesis_validators = GenesisValidators::new(
            NetworkDefinition::simulator(),
            global_validator_set,
            root_committee,
        );
        let chain_config = network_config.beacon_chain_config.unwrap_or_default();

        // Build the genesis beacon chain once, reused across every host's
        // per-vnode `BeaconCoordinator`, and project the shared topology from
        // its folded state — one allocation shared across every host and
        // vnode. Pool extras are absent from every committee, so they project
        // as `Pooled`; the seated ROOT validators, capped at the beacon
        // committee size, form the genesis beacon committee.
        let beacon_network = genesis_validators.network.clone();
        let GenesisBoot {
            chain: genesis_chain,
            topology_snapshot: projected_topology,
        } = build_genesis(&genesis_validators, chain_config);
        let beacon_genesis_block = genesis_chain.block;
        let beacon_genesis_state = genesis_chain.state;
        let beacon_config_hash = genesis_chain.config_hash;
        let shared_topology = Arc::new(projected_topology);

        // Build the host→validators layout based on the hosting mode.
        // Each host carries a list of (validator_idx, shard) tuples.
        let mut hosts = Vec::with_capacity(num_hosts);
        let mut event_rxs = Vec::with_capacity(num_hosts);
        let mut host_event_txs = Vec::with_capacity(num_hosts);

        for (host_index, plan) in host_layout.iter().enumerate() {
            // Group this host's seated vnodes by shard. For cross-shard
            // hosting each group has one vnode; for same-shard hosting
            // there's one group per host with `vnodes_per_host` entries. A
            // dedicated pool host has no seated vnodes — only followers.
            let mut by_shard: BTreeMap<ShardId, Vec<u32>> = BTreeMap::new();
            for &(validator_idx, shard) in &plan.seated {
                by_shard.entry(shard).or_default().push(validator_idx);
            }

            // Per-host beacon storage. Warm-restart: resume from the latest
            // committed (block, state); commit the genesis pair first on an
            // empty store so fresh-start and restart share one load path.
            let beacon_storage: Arc<dyn BeaconStorage> = Arc::new(SimBeaconStorage::new());
            if beacon_storage.latest_committed_epoch().is_none() {
                beacon_storage.commit_beacon_block(&beacon_genesis_block, &beacon_genesis_state);
            }

            // Seat each host's vnodes. Same-shard vnodes share one store
            // bundle, created inside `seat_vnode_group`; a dedicated pool
            // host's validators follow the beacon shard-less. Genesis boots a
            // fresh chain, so `recovered` is default and `now` is zero.
            let mut vnode_inits: Vec<VnodeInit> =
                Vec::with_capacity(plan.seated.len() + plan.followers.len());
            for (shard, validator_idxs) in &by_shard {
                let vnodes: Vec<(ValidatorId, Arc<Bls12381G1PrivateKey>)> = validator_idxs
                    .iter()
                    .map(|&idx| {
                        let key_bytes = keys[idx as usize].to_bytes();
                        (
                            ValidatorId::new(u64::from(idx)),
                            Arc::new(
                                Bls12381G1PrivateKey::from_bytes(&key_bytes)
                                    .expect("valid key bytes"),
                            ),
                        )
                    })
                    .collect();
                vnode_inits.extend(seat_vnode_group(SeatVnodeGroup {
                    beacon_storage: beacon_storage.as_ref(),
                    beacon_network: beacon_network.clone(),
                    beacon_config_hash,
                    now: LocalTimestamp::ZERO,
                    shard: *shard,
                    recovered: &RecoveredState::default(),
                    shard_config: &ShardConsensusConfig::default(),
                    mempool_config: MempoolConfig::default(),
                    provision_config: ProvisionConfig::default(),
                    vnodes,
                }));
            }
            for &validator_idx in &plan.followers {
                let key_bytes = keys[validator_idx as usize].to_bytes();
                let signing_key = Arc::new(
                    Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes"),
                );
                vnode_inits.push(seat_follower(SeatFollower {
                    beacon_storage: beacon_storage.as_ref(),
                    beacon_network: beacon_network.clone(),
                    beacon_config_hash,
                    now: LocalTimestamp::ZERO,
                    validator: ValidatorId::new(u64::from(validator_idx)),
                    signing_key,
                }));
            }
            let topology_arc_for_host = Arc::new(ArcSwap::from(Arc::clone(&shared_topology)));

            let (event_tx, event_rx) = unbounded();

            let network_def = NetworkDefinition::simulator();
            let tx_validator = Arc::new(TransactionValidation::new(network_def.clone()));
            let executor = RadixExecutor::new(network_def);

            // One `SimShardStorage` per hosted shard on this host.
            let storages: HashMap<ShardId, SimShardStorage> = by_shard
                .keys()
                .map(|s| (*s, SimShardStorage::new(shard_prefix_path(*s))))
                .collect();
            // Single receiver per host: every hosted shard's sender is a
            // clone of the same `event_tx`, and the harness drains all
            // shards through `event_rx` deterministically.
            let shard_event_senders: BTreeMap<ShardId, Sender<HostEvent>> =
                by_shard.keys().map(|s| (*s, event_tx.clone())).collect();
            let host = NodeHost::new(
                vnode_inits,
                storages,
                beacon_storage,
                beacon_network.clone(),
                executor,
                network.create_adapter(
                    NodeIndex::try_from(host_index).expect("host_index fits NodeIndex"),
                ),
                SyncDispatch,
                shard_event_senders,
                event_tx.clone(),
                topology_arc_for_host,
                NodeConfig::default(),
                tx_validator,
            );

            // Seat each genesis vnode's beacon-signing registry entry —
            // the same wiring the production supervisor runs at spawn.
            // At genesis every validator hosts one vnode, so each claim
            // is the first and wins.
            for (shard, validator_idxs) in &by_shard {
                for &validator_idx in validator_idxs {
                    host.process()
                        .assign_beacon_signer(ValidatorId::new(u64::from(validator_idx)), *shard);
                }
            }

            hosts.push(host);
            event_rxs.push(event_rx);
            host_event_txs.push(event_tx);
        }

        info!(
            num_nodes = hosts.len(),
            shard_size = network_config.shard_size,
            seed,
            "Created single-shard (ROOT) simulation runner"
        );

        let signing_keys: Vec<Arc<Bls12381G1PrivateKey>> = keys
            .iter()
            .map(|key| {
                Arc::new(
                    Bls12381G1PrivateKey::from_bytes(&key.to_bytes()).expect("valid key bytes"),
                )
            })
            .collect();

        // Fixed home host per registered validator: committee validators home
        // to their genesis host, pool extras to their dedicated host or — when
        // co-hosted — round-robin across the committee hosts. The orchestrator
        // on a validator's home host runs its reshape duties and seats it there.
        let committee_hosts = committee_size / network_config.vnodes_per_host;
        let validator_home: Vec<NodeIndex> = (0..registered_validators)
            .map(|v| {
                if v < committee_size {
                    v / network_config.vnodes_per_host
                } else {
                    let k = v - committee_size;
                    if network_config.dedicated_pool_hosts {
                        committee_hosts + k
                    } else {
                        k % committee_hosts
                    }
                }
            })
            .collect();
        let epoch_duration_ms = network_config
            .beacon_chain_config
            .unwrap_or_default()
            .epoch_duration_ms;
        let reshape: Vec<ReshapeOrchestrator> = (0..num_hosts)
            .map(|host| {
                let host = NodeIndex::try_from(host).expect("host index fits NodeIndex");
                let me: Vec<ValidatorId> = (0..registered_validators)
                    .filter(|&v| validator_home[v as usize] == host)
                    .map(|v| ValidatorId::new(u64::from(v)))
                    .collect();
                ReshapeOrchestrator::new(me)
            })
            .collect();

        Self {
            hosts,
            event_rxs,
            event_txs: host_event_txs,
            signing_keys,
            beacon_config_hash,
            beacon_network,
            pending_reconfigurations: Vec::new(),
            event_queue: BTreeMap::new(),
            sequence: 0,
            now: Duration::ZERO,
            network,
            rng,
            timers: HashMap::new(),
            stats: SimulationStats::default(),
            traffic_analyzer: None,
            last_gossip_dedup_prune: Duration::ZERO,
            epoch_duration_ms,
            pool_tick_pending: vec![false; num_hosts],
            reshape,
            reshape_stores: HashMap::new(),
            reshape_pending: vec![Vec::new(); num_hosts],
            retained_storages: HashMap::new(),
            placement_epoch: vec![None; num_hosts],
            validator_home,
        }
    }

    /// Enable traffic analysis on an existing runner.
    pub fn enable_traffic_analysis(&mut self) {
        if self.traffic_analyzer.is_none() {
            let analyzer = Arc::new(NetworkTrafficAnalyzer::new());
            self.network.set_traffic_analyzer(Arc::clone(&analyzer));
            self.traffic_analyzer = Some(analyzer);
        }
    }

    /// Check if traffic analysis is enabled.
    #[must_use]
    pub const fn has_traffic_analysis(&self) -> bool {
        self.traffic_analyzer.is_some()
    }

    /// Get a bandwidth report from the traffic analyzer.
    #[must_use]
    pub fn traffic_report(&self) -> Option<BandwidthReport> {
        self.traffic_analyzer
            .as_ref()
            .map(|analyzer| analyzer.generate_report(self.now, self.network.total_nodes()))
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Accessors
    // ═══════════════════════════════════════════════════════════════════════

    /// Number of hosts in the simulation.
    ///
    /// # Panics
    ///
    /// Panics if the host count exceeds `NodeIndex` (test harnesses are
    /// far smaller).
    #[must_use]
    pub fn num_hosts(&self) -> NodeIndex {
        NodeIndex::try_from(self.hosts.len()).expect("host count fits NodeIndex")
    }

    /// Get a reference to a node's storage for a specific hosted shard,
    /// or `None` when the host doesn't carry it.
    #[must_use]
    pub fn hosts_shard(&self, node: NodeIndex, shard: ShardId) -> Option<&SimShardStorage> {
        let host = self.hosts.get(node as usize)?;
        host.hosted_shards()
            .any(|s| s == shard)
            .then(|| &**host.shard_io(shard).storage())
    }

    /// Process-shared beacon storage for a host. One handle per host,
    /// shared across every vnode on that host.
    #[must_use]
    pub fn beacon_storage(&self, node: NodeIndex) -> Option<&Arc<dyn BeaconStorage>> {
        self.hosts.get(node as usize).map(NodeHost::beacon_storage)
    }

    /// Number of shard-less beacon-following vnodes in `node`'s pool.
    #[must_use]
    pub fn pooled_len(&self, node: NodeIndex) -> usize {
        self.hosts
            .get(node as usize)
            .map_or(0, NodeHost::pooled_len)
    }

    /// The shards `node` currently hosts. A grown host retains its
    /// terminated parent alongside its active child, so this can hold more
    /// than the live leaf.
    #[must_use]
    pub fn hosted_shards_of(&self, node: NodeIndex) -> Vec<ShardId> {
        self.hosts
            .get(node as usize)
            .map(|h| h.hosted_shards().collect())
            .unwrap_or_default()
    }

    /// Get the last emitted transaction status for a node.
    #[must_use]
    pub fn tx_status(&self, node: NodeIndex, tx_hash: &TxHash) -> Option<TransactionStatus> {
        self.hosts
            .get(node as usize)
            .and_then(|nl| nl.tx_status(tx_hash))
    }

    /// Get simulation statistics.
    #[must_use]
    pub const fn stats(&self) -> &SimulationStats {
        &self.stats
    }

    /// Get current simulation time.
    #[must_use]
    pub const fn now(&self) -> Duration {
        self.now
    }

    /// Get a reference to a host's first-vnode state machine.
    ///
    /// With `vnodes_per_host == 1` (the default) this is the only
    /// state machine on that host. For multi-vnode hosting, use
    /// [`Self::vnode_state_in`] to pick a specific host's shard vnode.
    #[must_use]
    pub fn node(&self, index: NodeIndex) -> Option<&NodeStateMachine> {
        let host = self.hosts.get(index as usize)?;
        let shard = host.hosted_shards().next()?;
        Some(host.vnode_state(shard, 0))
    }

    /// Every live vnode on `shard`, across all hosts.
    ///
    /// Walks each host, keeps those that carry `shard`, and collects every
    /// matching vnode's state machine. Use this — not host-indexed
    /// [`Self::node`] — to assert over a committee after a split: a flip
    /// leaves the terminated parent vnodes lingering on their hosts under the
    /// parent shard, and a host seated cross-shard carries a second vnode that
    /// host-indexing hides.
    #[must_use]
    pub fn shard_vnodes(&self, shard: ShardId) -> Vec<&NodeStateMachine> {
        let mut vnodes = Vec::new();
        for host in &self.hosts {
            if host.hosted_shards().any(|s| s == shard) {
                for v in 0..host.vnodes_len(shard) {
                    vnodes.push(host.vnode_state(shard, v));
                }
            }
        }
        vnodes
    }

    /// Host `node`'s current topology snapshot, or `None` if `node` is out of
    /// range.
    #[must_use]
    pub fn host_topology(&self, node: NodeIndex) -> Option<Arc<TopologySnapshot>> {
        Some(
            self.hosts
                .get(node as usize)?
                .process()
                .topology_snapshot()
                .load_full(),
        )
    }

    /// Get a reference to the network.
    #[must_use]
    pub const fn network(&self) -> &SimulatedNetwork {
        &self.network
    }

    /// Get a mutable reference to the network for partition/loss configuration.
    pub const fn network_mut(&mut self) -> &mut SimulatedNetwork {
        &mut self.network
    }

    /// Schedule an initial event (e.g., to start the simulation).
    /// Schedule an event for initial delivery. The event must be wrapped
    /// in the appropriate [`HostEvent`] envelope: shard-scoped variants
    /// via [`HostEvent::shard`] / [`HostEvent::protocol`],
    /// `SubmitTransaction` via [`HostEvent::process`].
    pub fn schedule_initial_event(&mut self, node: NodeIndex, delay: Duration, event: HostEvent) {
        let time = self.now + delay;
        self.schedule_event(node, time, event);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Genesis
    // ═══════════════════════════════════════════════════════════════════════

    /// Initialize all nodes with genesis blocks and start consensus.
    pub fn initialize_genesis(&mut self) {
        self.run_genesis(&GenesisConfig::test_default());
    }

    /// Initialize genesis with pre-funded accounts.
    ///
    /// Genesis is a single ROOT shard, so every funded account lands on ROOT;
    /// a later `grow_to` partitions them across the children by prefix. The
    /// account count is bounded by the Radix Engine genesis limit (~8000) —
    /// callers past it fund the surplus at runtime instead.
    pub fn initialize_genesis_with_balances(&mut self, balances: &[(ComponentAddress, Decimal)]) {
        // One GenesisConfig for the whole ROOT shard; the engine cache
        // memoizes the merged DatabaseUpdates so installing it on each ROOT
        // host is cheap.
        let config = GenesisConfig {
            xrd_balances: balances.to_vec(),
            ..GenesisConfig::test_default()
        };
        self.run_genesis(&config);
    }

    /// Install and commit genesis across the cluster, then wire the hosts
    /// into the in-memory network.
    ///
    /// Genesis is a single ROOT shard. Every ROOT-serving host runs the
    /// shared [`NodeHost::build_shard_genesis`] ceremony — identical config
    /// yields an identical block on each — and the certified block is
    /// *scheduled* for commit rather than stepped inline: deferring it until
    /// after [`NodeHost::register_inbound_handlers`] keeps genesis consensus
    /// I/O from firing into an unwired network.
    fn run_genesis(&mut self, config: &GenesisConfig) {
        let shard = ShardId::ROOT;
        let proposer = ValidatorId::new(0);
        let num_hosts = NodeIndex::try_from(self.hosts.len()).expect("host count fits NodeIndex");
        let hosts_for_shard: Vec<NodeIndex> = (0..num_hosts)
            .filter(|&h| self.hosts[h as usize].hosted_shards().any(|s| s == shard))
            .collect();

        for &host_index in &hosts_for_shard {
            let i = host_index as usize;
            let ShardGenesis {
                block,
                certified,
                setup_output,
            } = self.hosts[i].build_shard_genesis(shard, proposer, config);
            if host_index == hosts_for_shard[0] {
                info!(
                    shard = ?shard,
                    genesis_jmt_root = ?block.header().state_root(),
                    genesis_hash = ?block.hash(),
                    hosts = hosts_for_shard.len(),
                    "Initialized genesis for the ROOT shard"
                );
            }
            self.drain_node_io(host_index);
            self.process_step_output(host_index, setup_output);
            self.schedule_event(
                host_index,
                self.now,
                HostEvent::protocol(shard, ProtocolEvent::BlockCommitted { certified }),
            );
        }

        // Wire each node into the in-memory network now that genesis is settled.
        for host in &mut self.hosts {
            host.register_inbound_handlers();
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Main Loop
    // ═══════════════════════════════════════════════════════════════════════

    /// Run simulation until no more events or time limit reached.
    ///
    /// # Panics
    ///
    /// Panics if `event_queue.pop_first()` returns `None` after `first_key_value()`
    /// returned `Some` (impossible: `&mut self` blocks any other writer).
    pub fn run_until(&mut self, end_time: Duration) {
        // Prune gossip dedup caches every 5 simulated seconds.
        // Dedup only needs to cover the window in which duplicate broadcasts
        // arrive (~cross-shard latency), so 5s is very conservative.
        const GOSSIP_DEDUP_PRUNE_INTERVAL: Duration = Duration::from_secs(5);

        trace!(
            end_time_secs = end_time.as_secs_f64(),
            "Running simulation step"
        );

        loop {
            // Determine next time: min(event_queue, all pending deliveries)
            let next_event = self.event_queue.first_key_value().map(|(k, _)| k.time);
            let next_delivery = self.network.next_delivery_time();

            let next_time = match (next_event, next_delivery) {
                (Some(e), Some(d)) => e.min(d),
                (Some(t), None) | (None, Some(t)) => t,
                (None, None) => break,
            };

            if next_time > end_time {
                debug!(
                    remaining_events = self.event_queue.len(),
                    "Time limit reached"
                );
                break;
            }

            self.now = next_time;

            if self.now.saturating_sub(self.last_gossip_dedup_prune) >= GOSSIP_DEDUP_PRUNE_INTERVAL
            {
                self.network.prune_gossip_dedup();
                self.last_gossip_dedup_prune = self.now;
            }

            // Flush all delivery queues that are due — handlers/callbacks push
            // events into crossbeam channels.
            let gossip_delivered = self.network.flush_gossip(self.now);
            let notif_delivered = self.network.flush_notifications(self.now);
            let response_delivered = self.network.flush_responses(self.now);

            if gossip_delivered + notif_delivered + response_delivered > 0 {
                // Drain events that handlers pushed into channels.
                for node_idx in 0..u32::try_from(self.hosts.len()).unwrap_or(u32::MAX) {
                    while let Ok(event) = self.event_rxs[node_idx as usize].try_recv() {
                        self.schedule_event(node_idx, self.now, event);
                    }
                }
            }

            // Process all events at current time.
            while let Some((&key, _)) = self.event_queue.first_key_value() {
                if key.time > self.now {
                    break;
                }

                let (key, event) = self.event_queue.pop_first().unwrap();
                let node_index = key.node_index;

                trace!(
                    time = ?self.now,
                    node = node_index,
                    "Processing event"
                );

                self.stats.events_processed += 1;
                self.stats.events_by_priority[event.priority() as usize] += 1;

                // A fired pool tick clears its pending slot so the post-step
                // refresh can re-arm the next one if the sync is still running.
                let fired_pool_tick = event.is_pool_fetch_tick();

                self.hosts[node_index as usize].set_time(LocalTimestamp::from_millis(
                    u64::try_from(self.now.as_millis()).unwrap_or(u64::MAX),
                ));
                let output = self.hosts[node_index as usize].step(event);
                self.hosts[node_index as usize].flush_all_batches();

                self.drain_node_io(node_index);
                self.process_step_output(node_index, output);
                self.refresh_pool_tick(node_index, fired_pool_tick);
            }
        }

        if self.now < end_time {
            self.now = end_time;
        }

        trace!(
            events_processed = self.stats.events_processed,
            actions_generated = self.stats.actions_generated,
            final_time = ?self.now,
            "Simulation step complete"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Output Draining
    // ═══════════════════════════════════════════════════════════════════════

    /// Drain network outbox, pending requests, pending notifications, and
    /// buffered events from a node.
    ///
    /// Converts host-internal outputs into harness-level operations:
    /// - Outbox entries → gossip latency queue
    /// - Pending requests → handler invoked, response callback deferred
    /// - Pending notifications → notification latency queue
    /// - Buffered events (from error callbacks, `NodeHost` step) → event queue
    fn drain_node_io(&mut self, node: NodeIndex) {
        let i = node as usize;
        let outbox = self.hosts[i].network().drain_outbox();

        for entry in outbox {
            let stats = self
                .network
                .accept_gossip(node, self.now, entry, &mut self.rng);
            self.stats.messages_sent += stats.messages_sent;
            self.stats.messages_dropped_partition += stats.messages_dropped_partition;
            self.stats.messages_dropped_loss += stats.messages_dropped_loss;
            self.stats.messages_deduplicated += stats.messages_deduplicated;
        }

        // Accept pending requests: handler invoked now, response callback
        // deferred with round-trip latency. Error callbacks fire immediately
        // and push events into channels, so drain must happen after this.
        let pending_requests = self.hosts[i].network().drain_pending_requests();
        if !pending_requests.is_empty() {
            let stats =
                self.network
                    .accept_requests(node, self.now, pending_requests, &mut self.rng);
            self.stats.messages_sent += stats.messages_sent;
            self.stats.messages_dropped_partition += stats.messages_dropped_partition;
            self.stats.messages_dropped_loss += stats.messages_dropped_loss;
        }

        // Accept pending notifications: queued for deferred delivery with latency.
        let pending_notifications = self.hosts[i].network().drain_pending_notifications();
        if !pending_notifications.is_empty() {
            let stats = self.network.accept_notifications(
                node,
                self.now,
                pending_notifications,
                &mut self.rng,
            );
            self.stats.messages_sent += stats.messages_sent;
            self.stats.messages_dropped_partition += stats.messages_dropped_partition;
            self.stats.messages_dropped_loss += stats.messages_dropped_loss;
        }

        // Drain buffered events (from error callbacks in accept_requests,
        // plus any events the host's step itself pushed).
        while let Ok(event) = self.event_rxs[i].try_recv() {
            self.schedule_event(node, self.now, event);
        }
    }

    /// Process `StepOutput`: stats, timer ops, and placement deltas.
    fn process_step_output(&mut self, node: NodeIndex, output: StepOutput) {
        self.stats.actions_generated += u64::try_from(output.actions_generated).unwrap_or(u64::MAX);
        for op in output.timer_ops {
            self.process_timer_op(node, op);
        }
        for change in output.reconfigurations {
            self.pending_reconfigurations.push((node, change));
        }
    }

    /// Re-arm the follower pool's catch-up retry tick. Called after every host
    /// step: while the pool is syncing, keep exactly one tick queued so a
    /// deferred fetch eventually retries; once the pool catches up, stop. The
    /// production pool thread self-ticks off its `select!` timeout instead.
    fn refresh_pool_tick(&mut self, node: NodeIndex, fired_tick: bool) {
        let i = node as usize;
        if fired_tick {
            self.pool_tick_pending[i] = false;
        }
        if !self.hosts[i].pool_is_syncing() {
            self.pool_tick_pending[i] = false;
            return;
        }
        if !self.pool_tick_pending[i] {
            self.pool_tick_pending[i] = true;
            let fire = self.now + POOL_FETCH_TICK_INTERVAL;
            self.schedule_event(node, fire, HostEvent::beacon_fetch_tick());
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Timer Handling
    // ═══════════════════════════════════════════════════════════════════════

    /// Process a [`TimerOp`] emitted by a node's state machine.
    fn process_timer_op(&mut self, node: NodeIndex, op: TimerOp) {
        match op {
            TimerOp::Set {
                shard,
                id,
                duration,
            } => {
                let fire_time = self.now + duration;
                let event = timer_event(&id, shard);
                // Re-arming replaces the pending fire, matching the
                // production runner (which aborts the old sleep task).
                // Leaving the old event queued would deliver a stale fire
                // for every re-arm.
                if let Some(old) = self.timers.remove(&(node, shard, id.clone())) {
                    self.event_queue.remove(&old);
                }
                let key = self.schedule_event(node, fire_time, event);
                self.timers.insert((node, shard, id), key);
                self.stats.timers_set += 1;
            }
            TimerOp::Cancel { shard, id } => {
                if let Some(key) = self.timers.remove(&(node, shard, id)) {
                    self.event_queue.remove(&key);
                    self.stats.timers_cancelled += 1;
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Helpers
    // ═══════════════════════════════════════════════════════════════════════

    fn schedule_event(&mut self, node: NodeIndex, time: Duration, event: HostEvent) -> EventKey {
        self.sequence += 1;
        let key = EventKey::new(time, &event, node, self.sequence);
        self.event_queue.insert(key, event);
        key
    }
}

/// Project the host plans into the [`HostLayout`] the simulated transport
/// routes on: each host's hosted-shard set (empty for a follower-only host)
/// and the validator→host map.
fn network_layout(plans: &[HostPlan]) -> HostLayout {
    let mut hosted = Vec::with_capacity(plans.len());
    let mut validator_to_host = HashMap::new();
    for (host_index, plan) in plans.iter().enumerate() {
        let host = NodeIndex::try_from(host_index).expect("host index fits NodeIndex");
        let mut shards = BTreeSet::new();
        for &(validator_idx, shard) in &plan.seated {
            shards.insert(shard);
            validator_to_host.insert(ValidatorId::new(u64::from(validator_idx)), host);
        }
        for &validator_idx in &plan.followers {
            validator_to_host.insert(ValidatorId::new(u64::from(validator_idx)), host);
        }
        hosted.push(shards);
    }
    HostLayout {
        hosted,
        validator_to_host,
    }
}

/// Compute the host→validators layout for a simulation network.
///
/// Genesis is a single ROOT shard, so every seated vnode is on ROOT. Returns
/// one [`HostPlan`] per host: the committee hosts are
/// `shard_size / vnodes_per_host`, host `h` carrying
/// `vnodes_per_host` consecutive ROOT validators starting at
/// `h * vnodes_per_host`.
///
/// When [`SimConfig::dedicated_pool_hosts`] is set, one shard-less follower
/// host per pool extra is appended past the committee hosts, at the
/// validator-index slot the `validator_to_node` formula maps it to.
fn build_host_layout(config: &SimConfig) -> Vec<HostPlan> {
    let mut plans: Vec<HostPlan> = build_committee_host_layout(config)
        .into_iter()
        .map(|seated| HostPlan {
            seated,
            followers: Vec::new(),
        })
        .collect();
    if config.dedicated_pool_hosts {
        // Each pool extra gets its own host running a shard-less beacon
        // follower. Pool-extra validator ids start past the committee
        // validators, and the `vnodes_per_host == 1` invariant the
        // dedicated layout requires puts each at its own node.
        for k in 0..config.pool_extra_validators {
            plans.push(HostPlan {
                seated: Vec::new(),
                followers: vec![config.shard_size + k],
            });
        }
    }
    plans
}

/// One host's construction plan: seated `(validator_idx, shard)` vnodes plus
/// any shard-less beacon-follower validator ids.
struct HostPlan {
    /// Seated vnodes the host runs shard consensus for.
    seated: Vec<(u32, ShardId)>,
    /// Shard-less validators the host follows the beacon for (the pool).
    followers: Vec<u32>,
}

/// The committee host layout — one entry per host that carries a ROOT vnode
/// at construction. Host `h` bundles `vnodes_per_host` consecutive ROOT
/// validators starting at `h * vnodes_per_host`. Dedicated pool-extra hosts
/// are appended separately by [`build_host_layout`].
fn build_committee_host_layout(config: &SimConfig) -> Vec<Vec<(u32, ShardId)>> {
    assert_eq!(
        config.shard_size % config.vnodes_per_host,
        0,
        "vnodes_per_host must divide shard_size"
    );
    let host_count = config.shard_size / config.vnodes_per_host;
    (0..host_count)
        .map(|h| {
            let host_first_validator = h * config.vnodes_per_host;
            (0..config.vnodes_per_host)
                .map(|v| (host_first_validator + v, ShardId::ROOT))
                .collect()
        })
        .collect()
}
