//! Deterministic simulation runner.
//!
//! Uses [`NodeHost`] to process all actions per-host, with the simulation harness
//! controlling event scheduling, network delivery, and time.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::ops::{Index, IndexMut, Range};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use arc_swap::ArcSwap;
use archive::ChainArchive;
use blake3::Hasher as Blake3Hasher;
use crossbeam::channel::{Receiver, Sender, unbounded};
use hyperscale_beacon::genesis::{build_genesis, seed_founding_members};
use hyperscale_core::{ParticipationChange, ProtocolEvent, TimerId};
use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};
use hyperscale_crypto_mock::{MockSigner, MockVerifier};
use hyperscale_dispatch_sync::{DeferredJobs, ProcessingTimes, SyncDispatch};
use hyperscale_engine::genesis::GenesisPackages;
use hyperscale_engine::{ExecutionMode, Executor, GenesisConfig};
use hyperscale_mempool::MempoolConfig;
use hyperscale_network_memory::{
    BandwidthReport, DeliveryDrain, FulfillmentStats, HostLayout, LinkStreams, NetworkConfig,
    NetworkTrafficAnalyzer, NodeIndex, RegionPlan, SimNetworkAdapter, SimulatedNetwork,
};
use hyperscale_node::pool_loop::POOL_FETCH_TICK_INTERVAL;
use hyperscale_node::reshape::PreparedStore;
use hyperscale_node::reshape::orchestrator::{ReshapeEvent, ReshapeOrchestrator};
use hyperscale_node::shard::{HostEvent, StepOutput};
use hyperscale_node::{
    NodeConfig, NodeHost, NodeStateMachine, SeatConfig, SeatFollower, SeatVnodeGroup, ShardGenesis,
    TimerOp, TimerOwner, VnodeInit, seat_follower, seat_vnode_group, timer_event,
};
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::{ShardConsensusConfig, ShardStats};
use hyperscale_storage::{BeaconStorage, RecoveredState, ShardChainReader};
use hyperscale_storage_memory::{SimBeaconStorage, SimShardStorage, crash_point};
use hyperscale_types::test_utils::{Withheld, WithholdingSigner};
use hyperscale_types::{
    BeaconChainConfig, Block, ConsensusPublicKey, Derivation, Epoch, GenesisConfigHash,
    GenesisValidators, LocalTimestamp, NetworkDefinition, PrincipalAddr, RoutingCommittees,
    ShardId, Signer, StakePoolSeat, TopologySnapshot, TransactionStatus, TxHash, ValidatorId,
    ValidatorInfo, ValidatorSet, Verifier, cache, shard_prefix_path,
};
use invariants::Invariants;
use tracing::{debug, info, trace};

use crate::event_queue::{EventKey, SimEvent};
use crate::memo_verifier::MemoVerifier;
use crate::runner::crash::CrashKind;

pub mod archive;
pub mod crash;
mod invariants;
pub mod membership;
pub mod reshape;

/// Consensus crypto scheme the simulated validators run.
///
/// Every scheme is constructible on any build; the feature only moves the
/// default, so a test that targets the signature path can name [`Self::Bls`]
/// outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoScheme {
    /// Deterministic keyed-hash mock — constant-cost sign/verify.
    Mock,
    /// Real BLS12-381, for tests that target the signature path itself.
    Bls,
}

impl Default for CryptoScheme {
    /// Real BLS under the `bls` feature, which runs the sims at production
    /// parity; the constant-cost mock otherwise, so local runs finish
    /// quickly.
    fn default() -> Self {
        if cfg!(feature = "bls") {
            Self::Bls
        } else {
            Self::Mock
        }
    }
}

/// The verifier `scheme` selects.
fn scheme_verifier(scheme: CryptoScheme) -> Arc<dyn Verifier> {
    match scheme {
        CryptoScheme::Mock => Arc::new(MockVerifier),
        CryptoScheme::Bls => Arc::new(MemoVerifier::new(BlsVerifier)),
    }
}

/// A deterministic signer for `seed` under `scheme`.
fn scheme_signer(scheme: CryptoScheme, seed: &[u8; 32]) -> Arc<dyn Signer> {
    match scheme {
        CryptoScheme::Mock => Arc::new(MockSigner::from_seed(seed)),
        CryptoScheme::Bls => Arc::new(BlsSigner::from_seed(seed)),
    }
}

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
    /// Validators hosted beyond the ROOT committee. They follow the beacon
    /// shard-less on their home host from boot, as a production node
    /// follows every local validator it has not seated. Those beacon
    /// genesis registers land `Pooled`, giving the shuffle refill stock and
    /// the cohorts each `grow_to` split draws.
    pub pool_surplus: u32,
    /// How many of the `pool_surplus` extras, the highest ids, beacon
    /// genesis leaves out. They follow the beacon unregistered until a
    /// registration transaction admits them; see
    /// [`SimulationRunner::staged_validators`].
    pub staged_pool_extras: u32,
    /// Give each pool extra a host of its own instead of co-hosting it on
    /// a committee host — the layout the shuffle's cross-shard relocation
    /// needs (a vnode can move onto a host not already serving the
    /// destination). Default `false` co-hosts the pool extras round-robin
    /// across the committee hosts.
    pub dedicated_pool_hosts: bool,
    /// Override the beacon chain config (epoch duration, committee sizes).
    /// `None` uses [`BeaconChainConfig::default`].
    pub beacon_chain_config: Option<BeaconChainConfig>,
    /// Base latency between any two hosts.
    pub latency: Duration,
    /// Jitter as a fraction of base latency (0.0 - 1.0).
    pub jitter_fraction: f64,
    /// Packet loss rate (0.0 - 1.0).
    pub packet_loss_rate: f64,
    /// Probability a delivered copy arrives twice (0.0 - 1.0).
    pub duplicate_rate: f64,
    /// Probability a delivered copy brings an old payload of its type
    /// with it (0.0 - 1.0).
    pub replay_rate: f64,
    /// Probability one delivery's latency spikes 10-50x (0.0 - 1.0).
    pub spike_rate: f64,
    /// Hosts spread over regions, each link priced by its region pair.
    /// `None` prices every link at `latency`.
    pub regions: Option<RegionPlan>,
    /// How long each host's dispatched work takes. Work that takes time
    /// runs once its processing time has passed, against the state it
    /// finds then; instant work runs as it is dispatched.
    pub processing: ProcessingTimes,
    /// Seed for validator keys, and so committees and leader schedules,
    /// when it should differ from the run seed. `None` draws them from the
    /// run seed; a fixed value sweeps network schedules over one world.
    pub world_seed: Option<u64>,
    /// Every host's node configuration: fetch schedules and batch windows.
    pub node_config: NodeConfig,
    /// Largest offset any host's clock reads from simulated time, either
    /// way. Each host draws its own offset from the seed.
    pub clock_skew: Duration,
    /// Largest rate, in parts per million, at which any host's clock runs
    /// fast or slow. Each host draws its own from the seed.
    pub clock_drift_ppm: u32,
    /// Largest delay between a timer coming due and its host taking the
    /// fire, as a busy runtime's timer wheel adds. Each fire draws its own
    /// delay up to it from its host's stream.
    pub timer_lateness: Duration,
    /// Consensus crypto scheme every simulated validator runs.
    pub crypto_scheme: CryptoScheme,
    /// Genesis-funded accounts (owner prefix, balance). Seeds the funded
    /// vault cells at genesis. Empty runs no traffic.
    pub accounts: Vec<(PrincipalAddr, u128)>,
    /// Stake pools the beacon folds facts for: the pool instance's owner
    /// prefix and the identifier it is folded under.
    pub pools: Vec<StakePoolSeat>,
    /// The batch executor's group scheduling. Receipts are
    /// schedule-invariant, so this cannot change any outcome — the
    /// serial-vs-parallel A/B constructs one cluster per mode and
    /// asserts exactly that.
    pub execution_mode: ExecutionMode,
    /// The packages this network is born running.
    ///
    /// The protocol's own by default rather than every fixture the
    /// workspace ships: a genesis package is genesis substate, and a
    /// cluster tuned to reshape at a byte threshold is a cluster whose
    /// behaviour a spare artifact changes. A scenario that calls a
    /// fixture asks for it.
    pub packages: GenesisPackages,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            shard_size: 4,
            vnodes_per_host: 1,
            pool_surplus: 0,
            staged_pool_extras: 0,
            dedicated_pool_hosts: false,
            beacon_chain_config: None,
            latency: Duration::from_millis(150),
            jitter_fraction: 0.1,
            packet_loss_rate: 0.0,
            duplicate_rate: 0.0,
            replay_rate: 0.0,
            spike_rate: 0.0,
            regions: None,
            processing: ProcessingTimes::INSTANT,
            world_seed: None,
            node_config: NodeConfig::default(),
            clock_skew: Duration::ZERO,
            clock_drift_ppm: 0,
            timer_lateness: Duration::ZERO,
            crypto_scheme: CryptoScheme::default(),
            accounts: Vec::new(),
            pools: Vec::new(),
            execution_mode: ExecutionMode::Serial,
            packages: GenesisPackages::protocol(),
        }
    }
}

impl SimConfig {
    /// The transport-only config the simulated network consumes.
    const fn network_config(&self) -> NetworkConfig {
        NetworkConfig {
            latency: self.latency,
            jitter_fraction: self.jitter_fraction,
            packet_loss_rate: self.packet_loss_rate,
            duplicate_rate: self.duplicate_rate,
            replay_rate: self.replay_rate,
            spike_rate: self.spike_rate,
            regions: self.regions,
        }
    }
}

/// Type alias for the simulation's concrete `NodeHost`.
type SimHost = NodeHost<SimShardStorage, SimNetworkAdapter, SyncDispatch>;

/// Every host's process, indexed by [`NodeIndex`]; a crashed one is
/// absent until it restarts.
///
/// Indexing a down host panics: nothing may read what a dead process
/// held. [`Self::get`] and [`Self::iter`] see only the hosts that are up.
struct Hosts(Vec<Option<SimHost>>);

impl Hosts {
    /// How many hosts the cluster has, up or down.
    const fn len(&self) -> usize {
        self.0.len()
    }

    /// `index`'s process, if it is up.
    fn get(&self, index: usize) -> Option<&SimHost> {
        self.0.get(index)?.as_ref()
    }

    /// Every process that is up.
    fn iter(&self) -> impl Iterator<Item = &SimHost> {
        self.0.iter().flatten()
    }

    /// Every process that is up, mutably.
    fn iter_mut(&mut self) -> impl Iterator<Item = &mut SimHost> {
        self.0.iter_mut().flatten()
    }

    /// Whether `index`'s process is up.
    fn is_up(&self, index: usize) -> bool {
        self.get(index).is_some()
    }

    /// Take `index`'s process down, handing it back.
    fn take(&mut self, index: usize) -> SimHost {
        self.0[index].take().expect("a running host crashes")
    }

    /// Bring `index`'s process up as `host`.
    fn put(&mut self, index: usize, host: SimHost) {
        assert!(self.0[index].is_none(), "a host restarts once it is down");
        self.0[index] = Some(host);
    }
}

impl Index<usize> for Hosts {
    type Output = SimHost;

    fn index(&self, index: usize) -> &SimHost {
        self.0[index].as_ref().expect("host is up")
    }
}

impl IndexMut<usize> for Hosts {
    fn index_mut(&mut self, index: usize) -> &mut SimHost {
        self.0[index].as_mut().expect("host is up")
    }
}

/// Deterministic simulation runner.
///
/// Processes events in deterministic order using [`NodeHost`] for action handling.
/// Given the same seed, produces identical results every run.
///
/// Each host has its own independent storage and executor inside its `NodeHost`.
/// The harness controls the event queue, network delivery (latency, partitions,
/// packet loss), and time advancement.
pub struct SimulationRunner {
    /// Per-host `NodeHost` instances. Index corresponds to `NodeIndex`.
    hosts: Hosts,

    /// Per-host event receivers (from crossbeam channels passed to `NodeHost`).
    event_rxs: Vec<Receiver<HostEvent>>,

    /// Per host, the work its deferred dispatcher has queued and the
    /// runner has not yet scheduled.
    deferred: Vec<Option<Arc<DeferredJobs>>>,

    /// Per-host event senders, retained so a shard added at runtime
    /// (vnode relocation) can be wired onto the host's existing channel.
    event_txs: Vec<Sender<HostEvent>>,

    /// Signing keys for every hosted validator, retained so a
    /// relocated vnode's state machine can be rebuilt on its new shard.
    /// The same signers as [`Self::withholding`], shared with every vnode
    /// a validator runs.
    signers: Vec<Arc<dyn Signer>>,

    /// Every hosted validator's signer, able to withhold its shard
    /// consensus when a scenario asks it to.
    withholding: Vec<Arc<WithholdingSigner>>,

    /// Scheme verifier every simulated coordinator runs, per
    /// [`SimConfig::crypto_scheme`]. Cloned into runtime-built
    /// coordinators and exposed for fixtures that must aggregate or
    /// verify with the harness's own scheme.
    verifier: Arc<dyn Verifier>,

    /// Scheme the runner was configured with, retained so fixtures can
    /// derive additional signers (e.g. registration scenarios) under
    /// the same scheme.
    crypto_scheme: CryptoScheme,

    /// [`SimConfig::accounts`], retained so genesis seeds the same
    /// world the executor and statics were built with.
    accounts: Vec<(PrincipalAddr, u128)>,

    /// [`SimConfig::pools`] with each seat's founding members filled
    /// in from the folded genesis beacon state, so the contract's record
    /// of who a pool operates and the beacon's agree from the first
    /// block.
    pools: Vec<StakePoolSeat>,

    /// [`SimConfig::packages`], retained for the same reason the
    /// accounts are: genesis seeds the set the executor and the beacon
    /// registry were built with, or the chain cannot route to its own
    /// code.
    packages: GenesisPackages,

    /// The [`Executor`] every host runs, retained so a harness can reach
    /// engine-side surfaces that are not part of tick execution, such as
    /// preview.
    engine: Arc<Executor>,

    /// Beacon genesis config hash, retained for runtime-built
    /// `BeaconCoordinator`s.
    beacon_config_hash: GenesisConfigHash,

    /// Beacon network definition, retained for runtime-built
    /// `BeaconCoordinator`s.
    beacon_network: NetworkDefinition,

    /// Placement deltas the hosted vnodes emitted via
    /// `Action::ReconfigureParticipation`, in deterministic event
    /// order. Drained by the harness via
    /// [`Self::take_participation_changes`].
    pending_participation_changes: Vec<(NodeIndex, ParticipationChange)>,

    /// Shards a host's loop asked to re-seat: its store needs a height
    /// beneath every serving peer's chain floor. Drained by
    /// [`Self::topology_step`].
    pending_reseats: Vec<(NodeIndex, ShardId)>,

    /// Global event queue, ordered deterministically.
    event_queue: BTreeMap<EventKey, SimEvent>,

    /// Sequence counter for deterministic ordering.
    sequence: u64,

    /// Current simulation time.
    now: Duration,

    /// Network simulator (latency, partitions, packet loss).
    network: SimulatedNetwork,

    /// The transport's random streams, one per link, derived from the seed.
    streams: LinkStreams,

    /// Timer registry for cancellation support.
    /// Maps `(host, owner, timer_id) -> event_key` for removal.
    timers: HashMap<(NodeIndex, TimerOwner, TimerId), EventKey>,

    /// Statistics.
    stats: SimulationStats,

    /// Running digest of every event processed, in order: its time, host,
    /// scope, type and sequence. Two runs agree on it exactly when they
    /// processed the same events in the same order.
    trace: Blake3Hasher,

    /// Cross-replica safety checks, run at the end of every `run_until`.
    invariants: Invariants,
    /// Every block the run committed, for scenario history queries.
    archive: ChainArchive,
    /// When the chains were last walked into the invariants and the
    /// archive.
    last_chain_walk: Duration,

    /// The seed this run was built from.
    seed: u64,

    /// The seed its keys and committees were drawn from: the run seed
    /// unless [`SimConfig::world_seed`] pinned another.
    world_seed: u64,

    /// Each host's clock: its offset from simulated time and its drift.
    clocks: Vec<HostClock>,

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

    /// Each host's pending wake at its nearest batch deadline, re-armed
    /// after every step it takes.
    batch_wakes: Vec<Option<EventKey>>,

    /// One reshape orchestrator per host, each `me`-scoped to that host's home
    /// validators. Stepped once per slice by [`Self::reshape_step`] — the
    /// deterministic counterpart of the production supervisor's per-host
    /// `reshape_step`.
    reshape: Vec<ReshapeOrchestrator>,

    /// In-flight reshape stores the orchestrators opened, imported, and adopted
    /// into, keyed by `(host, duty shard)`, held until the seat installs each.
    reshape_stores: HashMap<(NodeIndex, ShardId), PreparedStore<SimShardStorage>>,

    /// Per-host reshape fetches whose target block had not committed yet,
    /// carried to the next slice as `FetchFailed` events so the sequencer
    /// re-arms and re-requests — the in-memory stand-in for production's
    /// fetch callback firing on a later tick.
    reshape_pending: Vec<Vec<ReshapeEvent>>,

    /// Storage handles stashed by a placement leave, keyed by `(host, shard)`,
    /// so a later rejoin of the same shard takes the retained fast path —
    /// the in-memory stand-in for the production supervisor's retained store.
    retained_storages: HashMap<(NodeIndex, ShardId), SimShardStorage>,

    /// Per-host committed beacon epoch last reconciled by `reconcile_placement`.
    /// Committee membership only changes at an epoch boundary, so the
    /// reconciliation runs once per host per epoch rather than every slice.
    placement_epoch: Vec<Option<Epoch>>,

    /// Fixed home host per hosted validator, by id. A validator's keys live
    /// on one host for the run, so the host whose orchestrator runs its reshape
    /// duties and seats it is stable — the simulation's stand-in for
    /// production's per-host key bundle. Committee validators home to their
    /// genesis host; pool extras home to their dedicated host, or round-robin
    /// across the committee hosts when co-hosted.
    validator_home: Vec<NodeIndex>,

    /// The ids of the pool extras beacon genesis left out, per
    /// [`SimConfig::staged_pool_extras`].
    staged: Range<u32>,

    /// Each host's beacon store, the one its process runs on and a
    /// restart reopens.
    beacon_stores: Vec<Arc<SimBeaconStorage>>,

    /// [`SimConfig::execution_mode`], for the engine a restarted host
    /// builds.
    execution_mode: ExecutionMode,

    /// [`SimConfig::node_config`], for a restarted host.
    node_config: NodeConfig,

    /// Per host, the crash armed at one of its coming storage writes.
    write_crashes: Vec<Option<WriteCrash>>,

    /// [`SimConfig::timer_lateness`].
    timer_lateness: Duration,

    /// Per host, the state of the stream each timer fire's lateness is
    /// drawn from.
    lateness_streams: Vec<u64>,
}

/// A crash armed at a host's coming storage write.
#[derive(Clone, Copy, Debug)]
struct WriteCrash {
    /// Writes the host makes before the one it crashes at.
    writes_before: u64,
    /// What the crash takes with it.
    kind: CrashKind,
    /// How long the host stays down.
    downtime: Duration,
}

/// Statistics collected during simulation.
#[derive(Debug, Default, Clone)]
pub struct SimulationStats {
    /// Total events processed.
    pub events_processed: u64,
    /// Events processed by type.
    pub(crate) events_by_priority: [u64; 4],
    /// Total actions generated.
    pub actions_generated: u64,
    /// Messages sent (successfully scheduled for delivery).
    pub messages_sent: u64,
    /// Messages dropped due to network partition.
    pub(crate) messages_dropped_partition: u64,
    /// Gossip and notification copies dropped due to packet loss.
    pub messages_dropped_loss: u64,
    /// Request and response legs that lost a packet and arrived a
    /// retransmission round trip late.
    pub messages_retransmitted: u64,
    /// Messages dropped by an installed fault rule.
    pub messages_dropped_fault: u64,
    /// Messages deduplicated (same message already received by host).
    pub(crate) messages_deduplicated: u64,
    /// Timers set.
    pub timers_set: u64,
    /// Timers cancelled.
    pub(crate) timers_cancelled: u64,
    /// Host processes crashed, whether named or at an armed write.
    pub crashes: u64,
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
        // Every cache a host builds evicts by its keys' hashes; fixed keys
        // make that eviction replay identically in any process.
        cache::pin_hashing();
        // The harness owns cluster placement: the host layout drives both the
        // transport's routing tables and the per-host vnode seating below.
        let host_layout = build_host_layout(network_config);
        let num_hosts = host_layout.len();
        let network = SimulatedNetwork::new(
            network_config.network_config(),
            network_layout(&host_layout),
            seed,
        );
        let streams = LinkStreams::new(seed);
        // Keys, and so committees and leader schedules, come from the world
        // seed; the transport's draws from the run seed. Pinning the world
        // seed sweeps schedules over one fixed set of committees.
        let world_seed = network_config.world_seed.unwrap_or(seed);
        let clocks: Vec<HostClock> = (0..num_hosts)
            .map(|host| {
                HostClock::drawn(
                    seed,
                    host,
                    network_config.clock_skew,
                    network_config.clock_drift_ppm,
                )
            })
            .collect();

        // The engine the first host runs, and the one every other host's
        // is forked from below. Each holds its own world, its own
        // derivation and its own compiled code, so a host that committed
        // neither a publish nor a seal answers for neither until its own
        // fetch lands — which is what puts the acquisition paths under
        // test instead of around them.
        let engine = Arc::new(Executor::with_genesis(
            &network_config.pools,
            &network_config.packages,
            network_config.execution_mode,
        ));

        // Generate keys for every hosted validator using deterministic
        // seeding. Pool extras follow the beacon from their home host;
        // those beacon genesis registers land `Pooled`, giving the shuffle
        // refill stock, and the staged rest wait on a registration.
        let committee_size = network_config.shard_size;
        let hosted_validators = committee_size + network_config.pool_surplus;
        assert!(
            network_config.staged_pool_extras <= network_config.pool_surplus,
            "only pool extras can be staged",
        );
        let registered_validators = hosted_validators - network_config.staged_pool_extras;
        let crypto_scheme = network_config.crypto_scheme;
        let verifier: Arc<dyn Verifier> = scheme_verifier(crypto_scheme);
        let withholding: Vec<Arc<WithholdingSigner>> = (0..hosted_validators)
            .map(|i| {
                let mut seed_bytes = [0u8; 32];
                let key_seed = world_seed
                    .wrapping_add(u64::from(i))
                    .wrapping_mul(0x517c_c1b7_2722_0a95);
                seed_bytes[..8].copy_from_slice(&key_seed.to_le_bytes());
                seed_bytes[8..16].copy_from_slice(&u64::from(i).to_le_bytes());
                Arc::new(WithholdingSigner::new(scheme_signer(
                    crypto_scheme,
                    &seed_bytes,
                )))
            })
            .collect();
        let signers: Vec<Arc<dyn Signer>> = withholding
            .iter()
            .map(|signer| Arc::clone(signer) as Arc<dyn Signer>)
            .collect();
        let public_keys: Vec<ConsensusPublicKey> =
            signers.iter().map(|key| key.public_key()).collect();

        // Build global validator set (registered pool extras included —
        // fold-derived snapshots carry every registered validator, so
        // genesis matches)
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
        let boot = build_genesis(&genesis_validators, chain_config, &network_config.pools);
        let mut pools = network_config.pools.clone();
        seed_founding_members(&boot.state, &mut pools);
        let beacon_config_hash = boot.config_hash;
        let shared_topology = Arc::clone(&boot.topology_snapshot);

        // Build the host→validators layout based on the hosting mode.
        // Each host carries a list of (validator_idx, shard) tuples.
        let mut hosts = Vec::with_capacity(num_hosts);
        let mut event_rxs = Vec::with_capacity(num_hosts);
        let mut host_event_txs = Vec::with_capacity(num_hosts);
        let mut deferred = Vec::with_capacity(num_hosts);
        let mut beacon_stores = Vec::with_capacity(num_hosts);

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
            let beacon_store = Arc::new(SimBeaconStorage::new());
            boot.commit_if_empty(beacon_store.as_ref());
            beacon_stores.push(Arc::clone(&beacon_store));
            let beacon_storage: Arc<dyn BeaconStorage> = beacon_store;

            // The first host runs the engine the derivation is held by —
            // the one the commit-time compile feeds — and every other
            // host runs its own, holding only what it fetched.
            let executor = if host_index == 0 {
                Arc::clone(&engine)
            } else {
                Arc::new(engine.peer(network_config.execution_mode))
            };

            // Seat each host's vnodes. Same-shard vnodes share one store
            // bundle, created inside `seat_vnode_group`; the host's pool
            // extras follow the beacon shard-less. Genesis boots a fresh
            // chain, so `recovered` is default and `now` is what this
            // host's clock reads at simulated zero: a follower arms its
            // beacon startup timers off it at construction.
            let now = LocalTimestamp::from_millis(clocks[host_index].read(Duration::ZERO));
            let mut vnode_inits: Vec<VnodeInit> =
                Vec::with_capacity(plan.seated.len() + plan.followers.len());
            for (shard, validator_idxs) in &by_shard {
                let vnodes: Vec<(ValidatorId, Arc<dyn Signer>)> = validator_idxs
                    .iter()
                    .map(|&idx| {
                        (
                            ValidatorId::new(u64::from(idx)),
                            Arc::clone(&signers[idx as usize]),
                        )
                    })
                    .collect();
                vnode_inits.extend(seat_vnode_group(SeatVnodeGroup {
                    config: SeatConfig {
                        verifier: Arc::clone(&verifier),
                        derivation: executor.derivation(),
                        code: Arc::clone(&executor) as _,
                        beacon_network: beacon_network.clone(),
                        beacon_config_hash,
                        shard_config: ShardConsensusConfig::default(),
                        mempool_config: MempoolConfig::default(),
                        provision_config: ProvisionConfig::default(),
                    },
                    beacon_storage: beacon_storage.as_ref(),
                    now,
                    shard: *shard,
                    recovered: &RecoveredState::default(),
                    vnodes,
                }));
            }
            for &validator_idx in &plan.followers {
                let signer = Arc::clone(&signers[validator_idx as usize]);
                vnode_inits.push(seat_follower(SeatFollower {
                    verifier: Arc::clone(&verifier),
                    beacon_storage: beacon_storage.as_ref(),
                    beacon_network: beacon_network.clone(),
                    beacon_config_hash,
                    now,
                    validator: ValidatorId::new(u64::from(validator_idx)),
                    signer,
                }));
            }
            let topology_arc_for_host = Arc::new(ArcSwap::from(Arc::clone(&shared_topology)));

            let (event_tx, event_rx) = unbounded();
            let host_deferred = network_config.processing.takes_time().then(|| {
                Arc::new(DeferredJobs::new(
                    network_config.processing,
                    seed ^ (u64::try_from(host_index).expect("host index fits u64") + 1)
                        .wrapping_mul(0x9e37_79b9_7f4a_7c15),
                ))
            });
            let dispatch = host_deferred
                .clone()
                .map_or_else(SyncDispatch::new, SyncDispatch::deferred);

            // One `SimShardStorage` per hosted shard on this host.
            let storages: BTreeMap<ShardId, SimShardStorage> = by_shard
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
                dispatch,
                shard_event_senders,
                event_tx.clone(),
                topology_arc_for_host,
                network_config.node_config.clone(),
            );

            hosts.push(host);
            event_rxs.push(event_rx);
            host_event_txs.push(event_tx);
            deferred.push(host_deferred);
        }

        info!(
            num_nodes = hosts.len(),
            shard_size = network_config.shard_size,
            seed,
            "Created single-shard (ROOT) simulation runner"
        );

        // Fixed home host per hosted validator: the host its genesis
        // plan runs it on, seated or following. The orchestrator on a
        // validator's home host runs its reshape duties and seats it there.
        let mut validator_home: Vec<NodeIndex> = vec![0; hosted_validators as usize];
        for (host, plan) in host_layout.iter().enumerate() {
            let host = NodeIndex::try_from(host).expect("host index fits NodeIndex");
            for validator_idx in plan.validators() {
                validator_home[validator_idx as usize] = host;
            }
        }
        let epoch_duration_ms = network_config
            .beacon_chain_config
            .unwrap_or_default()
            .epoch_duration_ms;
        let reshape: Vec<ReshapeOrchestrator> = (0..num_hosts)
            .map(|host| {
                let host = NodeIndex::try_from(host).expect("host index fits NodeIndex");
                let me: Vec<ValidatorId> = (0..hosted_validators)
                    .filter(|&v| validator_home[v as usize] == host)
                    .map(|v| ValidatorId::new(u64::from(v)))
                    .collect();
                ReshapeOrchestrator::new(me)
            })
            .collect();

        Self {
            hosts: Hosts(hosts.into_iter().map(Some).collect()),
            event_rxs,
            deferred,
            event_txs: host_event_txs,
            signers,
            withholding,
            verifier,
            crypto_scheme,
            accounts: network_config.accounts.clone(),
            pools,
            packages: network_config.packages.clone(),
            engine,
            beacon_config_hash,
            beacon_network,
            pending_participation_changes: Vec::new(),
            pending_reseats: Vec::new(),
            event_queue: BTreeMap::new(),
            sequence: 0,
            now: Duration::ZERO,
            network,
            streams,
            world_seed,
            clocks,
            timers: HashMap::new(),
            stats: SimulationStats::default(),
            trace: Blake3Hasher::new(),
            invariants: Invariants::default(),
            archive: ChainArchive::default(),
            last_chain_walk: Duration::ZERO,
            seed,
            traffic_analyzer: None,
            last_gossip_dedup_prune: Duration::ZERO,
            epoch_duration_ms,
            pool_tick_pending: vec![false; num_hosts],
            batch_wakes: vec![None; num_hosts],
            reshape,
            reshape_stores: HashMap::new(),
            reshape_pending: vec![Vec::new(); num_hosts],
            retained_storages: HashMap::new(),
            placement_epoch: vec![None; num_hosts],
            validator_home,
            staged: registered_validators..hosted_validators,
            beacon_stores,
            execution_mode: network_config.execution_mode,
            node_config: network_config.node_config.clone(),
            write_crashes: vec![None; num_hosts],
            timer_lateness: network_config.timer_lateness,
            lateness_streams: (0..num_hosts)
                .map(|host| {
                    seed ^ 0x5449_4D45_524C_4154 ^ u64::try_from(host).expect("host index fits u64")
                })
                .collect(),
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

    /// Get a reference to a host's storage for a specific hosted shard,
    /// or `None` when the host doesn't carry it.
    #[must_use]
    pub fn hosts_shard(&self, host: NodeIndex, shard: ShardId) -> Option<&SimShardStorage> {
        let host = self.hosts.get(host as usize)?;
        host.hosted_shards()
            .any(|s| s == shard)
            .then(|| &**host.shard_io(shard).storage())
    }

    /// The cluster's engine, for engine-side surfaces that are not part
    /// of tick execution, such as preview.
    #[must_use]
    pub fn engine(&self) -> &Executor {
        &self.engine
    }

    /// Process-shared beacon storage for a host. One handle per host,
    /// shared across every vnode on that host.
    #[must_use]
    pub fn beacon_storage(&self, host: NodeIndex) -> Option<&Arc<dyn BeaconStorage>> {
        self.hosts.get(host as usize).map(NodeHost::beacon_storage)
    }

    /// Number of shard-less beacon-following vnodes in `host`'s pool.
    #[must_use]
    pub fn pooled_len(&self, host: NodeIndex) -> usize {
        self.hosts
            .get(host as usize)
            .map_or(0, NodeHost::pooled_len)
    }

    /// The shards `host` currently hosts. A grown host retains its
    /// terminated parent alongside its active child, so this can hold more
    /// than the live leaf.
    #[must_use]
    pub fn hosted_shards_of(&self, host: NodeIndex) -> Vec<ShardId> {
        self.hosts
            .get(host as usize)
            .map_or_default(|h| h.hosted_shards().collect())
    }

    /// Shard consensus statistics of `host`'s vnodes in `shard`, in vnode
    /// order; empty when the host doesn't carry it.
    #[must_use]
    pub fn shard_stats(&self, host: NodeIndex, shard: ShardId) -> Vec<ShardStats> {
        self.hosts
            .get(host as usize)
            .map_or_else(Vec::new, |h| h.shard_stats(shard))
    }

    /// Get the last emitted transaction status for a host.
    #[must_use]
    pub fn tx_status(&self, host: NodeIndex, tx_hash: &TxHash) -> Option<TransactionStatus> {
        self.hosts
            .get(host as usize)
            .and_then(|nl| nl.tx_status(tx_hash))
    }

    /// A host's last emitted status for `tx_hash`, with the shard that
    /// emitted it.
    #[must_use]
    pub fn tx_status_entry(
        &self,
        host: NodeIndex,
        tx_hash: &TxHash,
    ) -> Option<(TransactionStatus, ShardId)> {
        self.hosts
            .get(host as usize)
            .and_then(|nl| nl.tx_status_entry(tx_hash))
    }

    /// Get simulation statistics.
    #[must_use]
    pub const fn stats(&self) -> &SimulationStats {
        &self.stats
    }

    /// The seed this run was built from.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Stop treating conflicting commits as a failure, for a run that
    /// drives a shard past its fault bound on purpose. The other
    /// invariants still hold.
    pub const fn permit_forks(&mut self) {
        self.invariants.permit_forks();
    }

    /// Digest of every event processed so far, in processing order. Equal
    /// digests mean two runs processed the same events in the same order;
    /// it is the check that a seed replays identically.
    #[must_use]
    pub fn trace_digest(&self) -> [u8; 32] {
        *self.trace.finalize().as_bytes()
    }

    /// Start recording what the transport delivers, keeping at most
    /// `capacity` records between drains.
    ///
    /// Off by default. Recording is pure observation — it draws no randomness
    /// and reads no simulation state — so a seeded run behaves identically
    /// whether or not it is on.
    pub const fn enable_delivery_log(&mut self, capacity: usize) {
        self.network.enable_delivery_log(capacity);
    }

    /// Take every delivery recorded since the last drain.
    pub fn drain_deliveries(&mut self) -> DeliveryDrain {
        self.network.drain_deliveries()
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
    pub fn first_vnode_state(&self, index: NodeIndex) -> Option<&NodeStateMachine> {
        let host = self.hosts.get(index as usize)?;
        let shard = host.hosted_shards().next()?;
        Some(host.vnode_state(shard, 0))
    }

    /// Every live vnode on `shard`, across all hosts.
    ///
    /// Walks each host, keeps those that carry `shard`, and collects every
    /// matching vnode's state machine. Use this — not host-indexed
    /// [`Self::first_vnode_state`] — to assert over a committee after a split: a flip
    /// leaves the terminated parent vnodes lingering on their hosts under the
    /// parent shard, and a host seated cross-shard carries a second vnode that
    /// host-indexing hides.
    #[must_use]
    pub fn shard_vnodes(&self, shard: ShardId) -> Vec<&NodeStateMachine> {
        let mut vnodes = Vec::new();
        for host in self.hosts.iter() {
            if host.hosted_shards().any(|s| s == shard) {
                for v in 0..host.vnodes_len(shard) {
                    vnodes.push(host.vnode_state(shard, v));
                }
            }
        }
        vnodes
    }

    /// Every live vnode state machine across every host and shard.
    #[must_use]
    pub fn all_vnode_states(&self) -> Vec<&NodeStateMachine> {
        let mut vnodes = Vec::new();
        for host in self.hosts.iter() {
            let shards: Vec<ShardId> = host.hosted_shards().collect();
            for shard in shards {
                for v in 0..host.vnodes_len(shard) {
                    vnodes.push(host.vnode_state(shard, v));
                }
            }
        }
        vnodes
    }

    /// The state machine of `host`'s vnode in `shard`, or `None` when
    /// the host doesn't carry that shard. Relocation puts two vnodes
    /// with one validator id on a host (the draining shard's and the
    /// joined shard's), so lookups here are shard-scoped where a
    /// validator-id walk would be ambiguous.
    #[must_use]
    pub fn vnode_state_in(&self, host: NodeIndex, shard: ShardId) -> Option<&NodeStateMachine> {
        let host = self.hosts.get(host as usize)?;
        host.hosted_shards()
            .any(|s| s == shard)
            .then(|| host.vnode_state(shard, 0))
    }

    /// Every vnode `host` carries on `shard`, or nothing when it carries
    /// none.
    ///
    /// The whole group rather than its first member: a host seated
    /// cross-shard carries a second vnode on the same store, and which of
    /// the two sits in the shard's committee is not decided by its index.
    #[must_use]
    pub fn shard_vnodes_in(&self, host: NodeIndex, shard: ShardId) -> Vec<&NodeStateMachine> {
        let Some(host) = self.hosts.get(host as usize) else {
            return Vec::new();
        };
        if !host.hosted_shards().any(|s| s == shard) {
            return Vec::new();
        }
        (0..host.vnodes_len(shard))
            .map(|v| host.vnode_state(shard, v))
            .collect()
    }

    /// Host `host`'s current topology snapshot, or `None` if `host` is out of
    /// range.
    #[must_use]
    pub fn host_topology(&self, host: NodeIndex) -> Option<Arc<TopologySnapshot>> {
        Some(
            self.hosts
                .get(host as usize)?
                .process()
                .topology_snapshot()
                .load_full(),
        )
    }

    /// The routing committees host `host`'s network resolves a fetch
    /// against, or `None` if `host` is out of range.
    ///
    /// Written by the topology fold, and seeded from the boot schedule
    /// before any fold has run — which is what a restart depends on.
    #[must_use]
    pub fn host_routing_committees(&self, host: NodeIndex) -> Option<Arc<RoutingCommittees>> {
        Some(
            self.hosts
                .get(host as usize)?
                .process()
                .network()
                .routing_committees(),
        )
    }

    /// Host `host`'s derivation — what that node can resolve an envelope
    /// against — or `None` if `host` is out of range.
    ///
    /// A harness building a transaction outside any node still has to
    /// derive it through some node's caches before reading a routed fact
    /// off it, the way an RPC submission derives through the node it
    /// reaches.
    #[must_use]
    pub fn host_derivation(&self, host: NodeIndex) -> Option<Arc<dyn Derivation>> {
        Some(self.hosts.get(host as usize)?.derivation())
    }

    /// The signing key of a hosted validator, by id. Validator ids index
    /// the hosted set, so this is a direct lookup. Fault scenarios
    /// use it to forge Byzantine artifacts that must authenticate against the
    /// live committee — a synthesized shard fork proof, say — where a
    /// [`TestCommittee`](hyperscale_types::test_utils)'s keys would not match
    /// the seated committee.
    #[must_use]
    pub fn validator_signer(&self, validator: ValidatorId) -> Option<Arc<dyn Signer>> {
        self.signers
            .get(usize::try_from(validator.inner()).ok()?)
            .map(Arc::clone)
    }

    /// The validators this runner hosts that beacon genesis left out, with
    /// their signers, for a scenario to register by transaction.
    #[must_use]
    pub fn staged_validators(&self) -> Vec<(ValidatorId, Arc<dyn Signer>)> {
        self.staged
            .clone()
            .map(|idx| {
                (
                    ValidatorId::new(u64::from(idx)),
                    Arc::clone(&self.signers[idx as usize]),
                )
            })
            .collect()
    }

    /// The scheme verifier every simulated coordinator runs — fixtures
    /// that aggregate or pre-verify artifacts the cluster must accept
    /// (e.g. forged fork proofs) go through this, not a hardcoded
    /// scheme.
    #[must_use]
    pub fn verifier(&self) -> Arc<dyn Verifier> {
        Arc::clone(&self.verifier)
    }

    /// Make `validator` withhold exactly `withheld` of its shard consensus
    /// from now on, on every vnode it runs, and return its signer to count
    /// what it refuses. [`Withheld::Nothing`] lifts the fault.
    ///
    /// # Panics
    ///
    /// Panics if `validator` is not registered.
    pub fn withhold(&self, validator: ValidatorId, withheld: Withheld) -> Arc<WithholdingSigner> {
        let signer = Arc::clone(
            &self.withholding[usize::try_from(validator.inner()).expect("id fits usize")],
        );
        signer.withhold(withheld);
        signer
    }

    /// Derive a fresh signer under the runner's configured scheme —
    /// for scenario fixtures that mint keys outside the registered
    /// validator set (e.g. validator-registration witnesses whose
    /// possession proofs the beacon fold verifies with the cluster's
    /// verifier).
    #[must_use]
    pub fn signer_from_seed(&self, seed: &[u8; 32]) -> Arc<dyn Signer> {
        scheme_signer(self.crypto_scheme, seed)
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
    pub fn schedule_initial_event(&mut self, host: NodeIndex, delay: Duration, event: HostEvent) {
        let time = self.now + delay;
        self.schedule_event(host, time, event);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Genesis
    // ═══════════════════════════════════════════════════════════════════════

    /// The genesis config this cluster installs: its funded accounts and
    /// the pools its beacon folds facts for.
    pub(crate) fn genesis_config(&self) -> GenesisConfig {
        GenesisConfig {
            accounts: self.accounts.clone(),
            pools: self.pools.clone(),
            packages: self.packages.clone(),
        }
    }

    /// Initialize all nodes with genesis blocks and start consensus.
    pub fn initialize_genesis(&mut self) {
        self.run_genesis(&self.genesis_config());
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
        let num_hosts = NodeIndex::try_from(self.hosts.len()).expect("host count fits NodeIndex");
        let hosts_for_shard: Vec<NodeIndex> = (0..num_hosts)
            .filter(|&h| self.hosts[h as usize].hosted_shards().any(|s| s == shard))
            .collect();

        for &host_index in &hosts_for_shard {
            let block = self.install_shard_genesis(host_index, shard, config);
            if host_index == hosts_for_shard[0] {
                info!(
                    shard = ?shard,
                    genesis_jmt_root = ?block.header().state_root(),
                    genesis_hash = ?block.hash(),
                    hosts = hosts_for_shard.len(),
                    "Initialized genesis for the ROOT shard"
                );
            }
        }

        // Drain every host's construction-time output: a follower pool arms
        // its beacon startup timers at construction, and a follower-only
        // host runs no genesis ceremony to sweep them up.
        for host_index in 0..num_hosts {
            let output = self.hosts[host_index as usize].drain_pending_output();
            self.process_step_output(host_index, output);
        }

        // Wire each host into the in-memory network now that genesis is settled.
        for host in self.hosts.iter_mut() {
            host.register_inbound_handlers();
        }
    }

    /// Run the network genesis ceremony for `shard` on `host`, whose store for
    /// it is fresh, and schedule the genesis commit. Every store that runs it
    /// builds the same block: the config and the proposer are the network's.
    pub(crate) fn install_shard_genesis(
        &mut self,
        host: NodeIndex,
        shard: ShardId,
        config: &GenesisConfig,
    ) -> Block {
        // Genesis arms the first beacon timers off the host's own clock.
        let now = self.local_now(host);
        self.hosts[host as usize].set_time(now);
        let ShardGenesis {
            block,
            certified,
            setup_output,
        } = self.hosts[host as usize].build_shard_genesis(shard, config);
        self.drain_host_io(host);
        self.process_step_output(host, setup_output);
        self.schedule_event(
            host,
            self.now,
            HostEvent::protocol(
                shard,
                ProtocolEvent::BlockCommitted {
                    // A genesis block anchors its own committee.
                    committee_anchor: certified.block().header().parent_qc().weighted_timestamp(),
                    certified,
                },
            ),
        );
        block
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Main Loop
    // ═══════════════════════════════════════════════════════════════════════

    /// Every block the run committed, for scenario questions about a
    /// chain's whole history.
    #[must_use]
    pub const fn archive(&self) -> &ChainArchive {
        &self.archive
    }

    /// Walk every store's newly committed heights into the invariants and
    /// the archive.
    fn walk_chains(&mut self) {
        let mut invariants = std::mem::take(&mut self.invariants);
        invariants.check(self);
        self.invariants = invariants;
        let mut archive = std::mem::take(&mut self.archive);
        archive.record(self);
        self.archive = archive;
        self.last_chain_walk = self.now;
    }

    /// Run simulation until no more events or time limit reached.
    ///
    /// # Panics
    ///
    /// Panics if `event_queue.pop_first()` returns `None` after `first_key_value()`
    /// returned `Some` (impossible: `&mut self` blocks any other writer).
    pub fn run_until(&mut self, end_time: Duration) {
        // Walk the committed chains every simulated minute, far inside the
        // span a replica keeps a block for before its chain floor passes
        // it, so the invariants and the archive see every height.
        const CHAIN_WALK_INTERVAL: Duration = Duration::from_secs(60);
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

            if self.now.saturating_sub(self.last_chain_walk) >= CHAIN_WALK_INTERVAL {
                self.walk_chains();
            }

            if self.now.saturating_sub(self.last_gossip_dedup_prune) >= GOSSIP_DEDUP_PRUNE_INTERVAL
            {
                self.network.prune_gossip_dedup();
                self.last_gossip_dedup_prune = self.now;
            }

            // Flush all delivery queues that are due — handlers/callbacks push
            // events into crossbeam channels.
            let (gossip_delivered, gossip_stats) = self.network.flush_gossip(self.now);
            self.tally(&gossip_stats);
            let (notif_delivered, notif_stats) = self.network.flush_notifications(self.now);
            self.tally(&notif_stats);
            let (response_delivered, request_stats) =
                self.network.flush_requests(self.now, &mut self.streams);
            self.tally(&request_stats);

            if gossip_delivered + notif_delivered + response_delivered > 0 {
                // Drain events that handlers pushed into channels.
                for node_idx in 0..u32::try_from(self.hosts.len()).unwrap_or(u32::MAX) {
                    self.drain_events(node_idx);
                }
            }

            // Process all events at current time.
            while let Some((&key, _)) = self.event_queue.first_key_value() {
                if key.time > self.now {
                    break;
                }

                let (key, event) = self.event_queue.pop_first().unwrap();
                let host_index = key.node_index;

                trace!(
                    time = ?self.now,
                    host = host_index,
                    "Processing event"
                );

                self.stats.events_processed += 1;
                self.stats.events_by_priority[event.priority() as usize] += 1;
                self.fold_into_trace(key, &event);

                self.process_event(host_index, event);
            }
        }

        if self.now < end_time {
            self.now = end_time;
        }

        self.walk_chains();

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
    /// buffered events from a host.
    ///
    /// Converts host-internal outputs into harness-level operations:
    /// - Outbox entries → gossip latency queue
    /// - Pending requests → first attempt dispatched
    /// - Pending notifications → notification latency queue
    /// - Buffered events (from error callbacks, `NodeHost` step) → event queue
    fn drain_host_io(&mut self, host: NodeIndex) {
        let i = host as usize;
        let outbox = self.hosts[i].network().drain_outbox();

        for entry in outbox {
            let stats = self
                .network
                .accept_gossip(host, self.now, entry, &mut self.streams);
            self.tally(&stats);
        }

        // Accept pending requests: each dispatches its first attempt now; its
        // legs, timeouts and result are request events the loop flushes.
        let pending_requests = self.hosts[i].network().drain_pending_requests();
        if !pending_requests.is_empty() {
            let stats =
                self.network
                    .accept_requests(host, self.now, pending_requests, &mut self.streams);
            self.tally(&stats);
        }

        // Accept pending notifications: queued for deferred delivery with latency.
        let pending_notifications = self.hosts[i].network().drain_pending_notifications();
        if !pending_notifications.is_empty() {
            let stats = self.network.accept_notifications(
                host,
                self.now,
                pending_notifications,
                &mut self.streams,
            );
            self.tally(&stats);
        }

        // Drain buffered events the host's step pushed.
        self.drain_events(host);
    }

    /// Schedule every event `host` has sent, now, and every job its
    /// deferred dispatcher has queued, each to run once its processing
    /// time has passed.
    fn drain_events(&mut self, host: NodeIndex) {
        let i = host as usize;
        while let Ok(event) = self.event_rxs[i].try_recv() {
            self.schedule_event(host, self.now, event);
        }
        if let Some(jobs) = self.deferred[i].clone() {
            for (due, job) in jobs.take() {
                self.schedule(host, self.now + due, SimEvent::Deferred(job));
            }
        }
    }

    /// Fold what the transport sent and dropped into the run's stats.
    const fn tally(&mut self, stats: &FulfillmentStats) {
        self.stats.messages_sent += stats.messages_sent;
        self.stats.messages_dropped_partition += stats.messages_dropped_partition;
        self.stats.messages_dropped_loss += stats.messages_dropped_loss;
        self.stats.messages_retransmitted += stats.messages_retransmitted;
        self.stats.messages_dropped_fault += stats.messages_dropped_fault;
        self.stats.messages_deduplicated += stats.messages_deduplicated;
    }

    /// Process `StepOutput`: stats, timer ops, and placement deltas.
    fn process_step_output(&mut self, host: NodeIndex, output: StepOutput) {
        self.stats.actions_generated += u64::try_from(output.actions_generated).unwrap_or(u64::MAX);
        for op in output.timer_ops {
            self.process_timer_op(host, op);
        }
        for change in output.participation_changes {
            self.pending_participation_changes.push((host, change));
        }
        for shard in output.reseats {
            if !self.pending_reseats.contains(&(host, shard)) {
                self.pending_reseats.push((host, shard));
            }
        }
    }

    /// Re-arm the follower pool's catch-up retry tick. Called after every host
    /// step: while the pool is syncing, keep exactly one tick queued so a
    /// deferred fetch eventually retries; once the pool catches up, stop. The
    /// production pool thread self-ticks off its `select!` timeout instead.
    fn refresh_pool_tick(&mut self, host: NodeIndex, fired_tick: bool) {
        let i = host as usize;
        if fired_tick {
            self.pool_tick_pending[i] = false;
        }
        if !self.hosts[i].pool_is_syncing() {
            self.pool_tick_pending[i] = false;
            return;
        }
        if !self.pool_tick_pending[i] {
            self.pool_tick_pending[i] = true;
            let fire = self.clocks[i].fire_after(self.now, POOL_FETCH_TICK_INTERVAL);
            self.schedule_event(host, fire, HostEvent::beacon_fetch_tick());
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Timer Handling
    // ═══════════════════════════════════════════════════════════════════════

    /// Process a [`TimerOp`] emitted by a host's state machine.
    ///
    /// Re-arming or cancelling a timer drops its pending fire, as the
    /// production runner aborts the sleep behind it — unless the fire is
    /// already due. A sleep that has finished has sent its event, which
    /// no abort recalls, so the host takes that fire after the re-arm.
    fn process_timer_op(&mut self, host: NodeIndex, op: TimerOp) {
        match op {
            TimerOp::Set {
                owner,
                id,
                duration,
            } => {
                let fire_time = self.clocks[host as usize].fire_after(self.now, duration)
                    + self.draw_lateness(host);
                let event = timer_event(&id, owner);
                if let Some(old) = self.timers.remove(&(host, owner, id.clone())) {
                    self.drop_pending_fire(old);
                }
                let key = self.schedule_event(host, fire_time, event);
                self.timers.insert((host, owner, id), key);
                self.stats.timers_set += 1;
            }
            TimerOp::Cancel { owner, id } => {
                if let Some(key) = self.timers.remove(&(host, owner, id)) {
                    self.drop_pending_fire(key);
                    self.stats.timers_cancelled += 1;
                }
            }
        }
    }

    /// Drop a timer fire that has not yet come due.
    fn drop_pending_fire(&mut self, fire: EventKey) {
        if fire.time > self.now {
            self.event_queue.remove(&fire);
        }
    }

    /// How late `host` takes its next timer fire.
    fn draw_lateness(&mut self, host: NodeIndex) -> Duration {
        if self.timer_lateness.is_zero() {
            return Duration::ZERO;
        }
        let nanos = u64::try_from(self.timer_lateness.as_nanos()).unwrap_or(u64::MAX);
        let state = &mut self.lateness_streams[host as usize];
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Duration::from_nanos((z ^ (z >> 31)) % nanos.saturating_add(1))
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Helpers
    // ═══════════════════════════════════════════════════════════════════════

    fn schedule_event(&mut self, host: NodeIndex, time: Duration, event: HostEvent) -> EventKey {
        self.schedule(host, time, SimEvent::Host(event))
    }

    fn schedule(&mut self, host: NodeIndex, time: Duration, event: SimEvent) -> EventKey {
        self.sequence += 1;
        let key = EventKey::new(time, &event, host, self.sequence, self.seed);
        self.event_queue.insert(key, event);
        key
    }

    /// Keep `host`'s one wake at its nearest batch deadline, read off its
    /// own clock, or none when no batch is waiting.
    fn arm_batch_deadline(&mut self, host: NodeIndex) {
        let i = host as usize;
        let fire = self.hosts[i].nearest_batch_deadline().map(|deadline| {
            let wait = deadline
                .as_millis()
                .saturating_sub(self.clocks[i].read(self.now));
            self.clocks[i].fire_after(self.now, Duration::from_millis(wait))
        });
        if let Some(armed) = self.batch_wakes[i] {
            if Some(armed.time) == fire {
                return;
            }
            self.event_queue.remove(&armed);
            self.batch_wakes[i] = None;
        }
        if let Some(fire) = fire {
            self.batch_wakes[i] = Some(self.schedule(host, fire, SimEvent::BatchDeadline));
        }
    }

    /// Fold one processed event into the trace digest.
    fn fold_into_trace(&mut self, key: EventKey, event: &SimEvent) {
        self.trace.update(&key.time.as_nanos().to_le_bytes());
        self.trace.update(&key.node_index.to_le_bytes());
        self.trace.update(&key.sequence.to_le_bytes());
        let event = match event {
            SimEvent::Host(event) => event,
            SimEvent::BatchDeadline => {
                self.trace.update(&[3]);
                return;
            }
            SimEvent::Deferred(_) => {
                self.trace.update(&[4]);
                return;
            }
            SimEvent::Restart => {
                self.trace.update(&[5]);
                return;
            }
        };
        match event {
            HostEvent::Shard(shard, _) => {
                self.trace.update(&[0]);
                self.trace.update(&shard.depth().to_le_bytes());
                self.trace.update(&shard.path().to_le_bytes());
            }
            HostEvent::Process(_) => {
                self.trace.update(&[1]);
            }
            HostEvent::Beacon(_) => {
                self.trace.update(&[2]);
            }
        }
        // Type names are ASCII, so a 0xFF terminator delimits them.
        self.trace.update(event.type_name().as_bytes());
        self.trace.update(&[0xFF]);
    }

    /// Hand `host` one event, then keep its batch wake at its nearest
    /// deadline.
    fn process_event(&mut self, host: NodeIndex, event: SimEvent) {
        match event {
            SimEvent::Restart => self.restart_host(host),
            // A down host takes nothing: what was addressed to it is lost
            // with the process.
            _ if !self.hosts.is_up(host as usize) => return,
            SimEvent::Host(event) => {
                let now = self.wake(host);
                // A fired pool tick clears its pending slot so the post-step
                // refresh can re-arm the next one if the sync is still
                // running.
                let fired_pool_tick = event.is_pool_fetch_tick();
                let Some(output) = self.armed(host, |h| {
                    let output = h.step(event);
                    h.flush_expired_batches(now);
                    output
                }) else {
                    return;
                };
                self.drain_host_io(host);
                self.process_step_output(host, output);
                self.refresh_pool_tick(host, fired_pool_tick);
            }
            SimEvent::BatchDeadline => {
                let now = self.wake(host);
                self.batch_wakes[host as usize] = None;
                if self.armed(host, |h| h.flush_expired_batches(now)).is_none() {
                    return;
                }
                self.drain_host_io(host);
            }
            SimEvent::Deferred(job) => {
                self.wake(host);
                if self.armed(host, |_| job()).is_none() {
                    return;
                }
                self.drain_host_io(host);
            }
        }
        self.arm_batch_deadline(host);
    }

    /// Run `work` on `host`, crashing it at the write its armed crash
    /// names. `None` when it crashed: nothing the work queued leaves the
    /// process.
    fn armed<R>(&mut self, host: NodeIndex, work: impl FnOnce(&mut SimHost) -> R) -> Option<R> {
        let i = host as usize;
        let countdown = self.write_crashes[i].map(|crash| crash.writes_before);
        let hosts = &mut self.hosts;
        let (ran, left) = crash_point::armed(countdown, || work(&mut hosts[i]));
        let Ok(value) = ran else {
            let crash = self.write_crashes[i]
                .take()
                .expect("only an armed crash fires");
            self.crash_host(host, crash.kind, crash.downtime);
            return None;
        };
        if let (Some(crash), Some(left)) = (&mut self.write_crashes[i], left) {
            crash.writes_before = left;
        }
        Some(value)
    }

    /// Set `host`'s clock to what it reads now, before it handles an event,
    /// and return that reading.
    fn wake(&mut self, host: NodeIndex) -> LocalTimestamp {
        let now = self.local_now(host);
        self.hosts[host as usize].set_time(now);
        now
    }

    /// The current simulation time as the [`LocalTimestamp`] fed to hosts.
    fn local_now(&self, host: NodeIndex) -> LocalTimestamp {
        LocalTimestamp::from_millis(self.clocks[host as usize].read(self.now))
    }
}

/// One host's clock: a fixed offset from simulated time and a drift rate,
/// both drawn from the seed within the configured bounds.
///
/// The drift is the host's oscillator, so it paces the host's timers as
/// well as the time it reads: a production node's local clock advances
/// with the same monotonic source its timers sleep on, and a timer never
/// fires before its own clock has advanced the armed duration.
#[derive(Debug, Clone, Copy)]
struct HostClock {
    offset_ms: i64,
    drift_ppm: i64,
}

impl HostClock {
    fn drawn(seed: u64, host: usize, skew: Duration, drift_ppm: u32) -> Self {
        let mut hasher = Blake3Hasher::new();
        hasher.update(&seed.to_le_bytes());
        hasher.update(b"clock");
        hasher.update(&(host as u64).to_le_bytes());
        let digest = hasher.finalize();
        let bytes = digest.as_bytes();
        let draw = |at: usize, bound: i64| -> i64 {
            if bound == 0 {
                return 0;
            }
            let raw = u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"));
            let span = u64::try_from(2 * bound + 1).expect("a positive span");
            i64::try_from(raw % span).expect("within the span") - bound
        };
        Self {
            offset_ms: draw(0, i64::try_from(skew.as_millis()).unwrap_or(i64::MAX / 4)),
            drift_ppm: draw(8, i64::from(drift_ppm)),
        }
    }

    /// What this host's clock reads, in milliseconds, at simulated `now`.
    fn read(self, now: Duration) -> u64 {
        let now_ms = i64::try_from(now.as_millis()).unwrap_or(i64::MAX / 4);
        let drifted = now_ms + now_ms * self.drift_ppm / 1_000_000;
        u64::try_from((drifted + self.offset_ms).max(0)).unwrap_or(0)
    }

    /// The simulated instant a timer armed at `now` for `duration` fires:
    /// the first millisecond at which this clock reads `duration` past
    /// what it read when armed.
    fn fire_after(self, now: Duration, duration: Duration) -> Duration {
        let target = self
            .read(now)
            .saturating_add(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX));
        let rate =
            u128::try_from(1_000_000 + self.drift_ppm).expect("drift is under a million ppm");
        let scaled = duration.as_nanos() * 1_000_000 / rate;
        let mut fire = now + Duration::from_nanos(u64::try_from(scaled).unwrap_or(u64::MAX));
        while self.read(fire) < target {
            fire += Duration::from_millis(1);
        }
        fire
    }
}

/// A run that panics names what replays it: the seed, the features that
/// shape its sample space, and a command that reruns the failing test.
impl Drop for SimulationRunner {
    fn drop(&mut self) {
        if !thread::panicking() {
            return;
        }
        let test = thread::current().name().unwrap_or("<test name>").to_owned();
        let mut features = Vec::new();
        if cfg!(feature = "bls") {
            features.push("bls");
        }
        if cfg!(feature = "production-epochs") {
            features.push("production-epochs");
        }
        let feature_args = if features.is_empty() {
            String::new()
        } else {
            format!(" --features {}", features.join(","))
        };
        let profile = if cfg!(debug_assertions) {
            "--cargo-profile ci"
        } else {
            "--release"
        };
        let world = if self.world_seed == self.seed {
            String::new()
        } else {
            format!(" HYPERSCALE_SIM_WORLD_SEED={}", self.world_seed)
        };
        eprintln!(
            "\nsimulation failed: seed {} at {:?} after {} events, trace {}\n\
             replay: HYPERSCALE_SIM_SEED={}{world} cargo nextest run {profile} \
             -p hyperscale-simulation{feature_args} -E 'test(={test})'\n",
            self.seed,
            self.now,
            self.stats.events_processed,
            hex_digest(&self.trace_digest()),
            self.seed,
        );
        eprintln!("committed heights per host:");
        for host in 0..self.num_hosts() {
            let heights: Vec<String> = self
                .hosted_shards_of(host)
                .into_iter()
                .filter_map(|shard| {
                    let store = self.hosts_shard(host, shard)?;
                    Some(format!(
                        "{}/{}@{}",
                        shard.depth(),
                        shard.path(),
                        store.committed_height().inner()
                    ))
                })
                .collect();
            eprintln!("  host {host}: {}", heights.join(" "));
        }
    }
}

fn hex_digest(digest: &[u8; 32]) -> String {
    digest
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
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
        shards.extend(plan.seated.iter().map(|&(_, shard)| shard));
        for validator_idx in plan.validators() {
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
/// Every pool extra follows the beacon shard-less from boot. When
/// [`SimConfig::dedicated_pool_hosts`] is set, each runs on a follower host
/// of its own appended past the committee hosts; otherwise the extras
/// co-host round-robin across the committee hosts.
fn build_host_layout(config: &SimConfig) -> Vec<HostPlan> {
    let mut plans: Vec<HostPlan> = build_committee_host_layout(config)
        .into_iter()
        .map(|seated| HostPlan {
            seated,
            followers: Vec::new(),
        })
        .collect();
    let committee_hosts = plans.len();
    // Pool-extra validator ids start past the committee validators.
    for k in 0..config.pool_surplus {
        let validator_idx = config.shard_size + k;
        if config.dedicated_pool_hosts {
            plans.push(HostPlan {
                seated: Vec::new(),
                followers: vec![validator_idx],
            });
        } else {
            plans[k as usize % committee_hosts]
                .followers
                .push(validator_idx);
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

impl HostPlan {
    /// Every validator the host runs, seated or following.
    fn validators(&self) -> impl Iterator<Item = u32> + '_ {
        self.seated
            .iter()
            .map(|&(validator_idx, _)| validator_idx)
            .chain(self.followers.iter().copied())
    }
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

#[cfg(test)]
mod clock_tests {
    use super::*;

    #[test]
    fn a_clock_with_no_skew_or_drift_reads_simulated_time() {
        let clock = HostClock::drawn(7, 3, Duration::ZERO, 0);
        assert_eq!(clock.read(Duration::from_secs(90)), 90_000);
    }

    #[test]
    fn a_timer_fires_once_its_own_clock_has_advanced_the_duration() {
        let skew = Duration::from_millis(700);
        for host in 0..64 {
            let clock = HostClock::drawn(11, host, skew, 100);
            for armed_ms in [0_u64, 1_234, 600_000, 899_999] {
                let armed = Duration::from_millis(armed_ms) + Duration::from_micros(417);
                for duration_ms in [0_u64, 1, 15_000, 30_000] {
                    let fire = clock.fire_after(armed, Duration::from_millis(duration_ms));
                    let target = clock.read(armed) + duration_ms;
                    assert!(fire >= armed, "host {host} fired before it was armed");
                    assert!(
                        clock.read(fire) >= target,
                        "host {host} fired early: armed {armed_ms}ms for {duration_ms}ms",
                    );
                    assert!(
                        fire == armed
                            || fire
                                .checked_sub(Duration::from_millis(2))
                                .is_none_or(|before| clock.read(before) < target),
                        "host {host} fired late: armed {armed_ms}ms for {duration_ms}ms",
                    );
                }
            }
        }
    }

    #[test]
    fn a_skewed_clock_stays_within_its_bounds() {
        let skew = Duration::from_millis(700);
        for host in 0..64 {
            let clock = HostClock::drawn(7, host, skew, 100);
            let read = i64::try_from(clock.read(Duration::from_secs(1000))).expect("fits");
            // 700ms of offset and 100ppm of 1000s of drift.
            assert!(
                (read - 1_000_000).abs() <= 700 + 100,
                "host {host} read {read}"
            );
        }
    }
}
