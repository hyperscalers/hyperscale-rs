//! Deterministic simulation runner.
//!
//! Uses [`NodeHost`] to process all actions per-node, with the simulation harness
//! controlling event scheduling, network delivery, and time.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use crossbeam::channel::{Receiver, Sender, unbounded};
use hyperscale_beacon::coordinator::BeaconCoordinator;
use hyperscale_beacon::genesis::build_genesis_beacon_state;
use hyperscale_beacon::proposal_pool::BeaconProposalPool;
use hyperscale_core::{ProtocolEvent, TimerId};
use hyperscale_dispatch_sync::SyncDispatch;
use hyperscale_engine::{GenesisConfig, RadixExecutor, TransactionValidation};
use hyperscale_execution::{ExecCertStore, FinalizedWaveStore};
use hyperscale_mempool::{MempoolConfig, TxStore};
use hyperscale_network_memory::{
    BandwidthReport, HostingMode, NetworkConfig, NetworkTrafficAnalyzer, NodeIndex,
    SimNetworkAdapter, SimulatedNetwork,
};
use hyperscale_node::shard_loop::{ShardEvent, StepOutput};
use hyperscale_node::{NodeConfig, NodeHost, NodeStateMachine, TimerOp, VnodeInit, timer_event};
use hyperscale_provisions::{ProvisionConfig, ProvisionStore};
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BeaconStorage, RecoveredState, ShardChainReader};
use hyperscale_storage_memory::{SimBeaconStorage, SimShardStorage};
use hyperscale_types::{
    BeaconGenesisConfig, BeaconState, BlockHeight, Bls12381G1PrivateKey, Bls12381G1PublicKey,
    CertifiedBeaconBlock, CertifiedBlock, Epoch, GenesisPool, GenesisValidator, LocalTimestamp,
    MIN_STAKE_FLOOR, NodeId, Randomness, ShardId, Stake, StakePoolId, TopologySnapshot,
    TransactionStatus, TxHash, ValidatorId, ValidatorInfo, ValidatorSet, Verified,
    WeightedTimestamp, bls_keypair_from_seed, genesis_config_hash, shard_prefix_path,
    uniform_shard_for_node,
};
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use tracing::{debug, info, trace};

use crate::event_queue::EventKey;

/// Type alias for the simulation's concrete `NodeHost`.
type SimHost = NodeHost<SimShardStorage, SimNetworkAdapter, SyncDispatch>;

/// Per-(host, shard) shared store bundle — `ProvisionStore`, `TxStore`,
/// `ExecCertStore`, and `FinalizedWaveStore` cloned into every same-shard
/// vnode on the host so the per-shard coordinators converge on one
/// canonical view.
type ShardStoreBundle = (
    Arc<ProvisionStore>,
    Arc<TxStore>,
    Arc<ExecCertStore>,
    Arc<FinalizedWaveStore>,
);

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
    event_rxs: Vec<Receiver<ShardEvent>>,

    /// Global event queue, ordered deterministically.
    event_queue: BTreeMap<EventKey, ShardEvent>,

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

    /// Whether engine genesis has been executed on each node's storage.
    genesis_executed: Vec<bool>,

    /// Optional traffic analyzer for bandwidth estimation.
    traffic_analyzer: Option<Arc<NetworkTrafficAnalyzer>>,

    /// Last time gossip dedup caches were pruned.
    last_gossip_dedup_prune: Duration,
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

impl SimulationStats {
    /// Total messages dropped (partition + packet loss).
    #[must_use]
    pub const fn messages_dropped(&self) -> u64 {
        self.messages_dropped_partition + self.messages_dropped_loss
    }

    /// Message delivery rate (sent / (sent + dropped)).
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // headline ratio for human-readable stats
    pub fn delivery_rate(&self) -> f64 {
        let total = self.messages_sent + self.messages_dropped();
        if total == 0 {
            1.0
        } else {
            self.messages_sent as f64 / total as f64
        }
    }
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
    pub fn new(network_config: &NetworkConfig, seed: u64) -> Self {
        let network = SimulatedNetwork::new(network_config.clone());
        let rng = ChaCha8Rng::seed_from_u64(seed);

        // Generate keys for all validators using deterministic seeding
        let total_validators = network_config.num_shards * network_config.validators_per_shard;
        let keys: Vec<Bls12381G1PrivateKey> = (0..total_validators)
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

        // Build global validator set
        let global_validators: Vec<ValidatorInfo> = (0..total_validators)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(u64::from(i)),
                public_key: public_keys[i as usize],
            })
            .collect();
        let global_validator_set = ValidatorSet::new(global_validators);

        // Build per-shard committee mappings
        let mut shard_committees: HashMap<ShardId, Vec<ValidatorId>> = HashMap::new();
        let shard_depth = network_config.num_shards.trailing_zeros();
        for shard_id in 0..network_config.num_shards {
            let shard = ShardId::leaf(shard_depth, u64::from(shard_id));
            let shard_start = shard_id * network_config.validators_per_shard;
            let shard_end = shard_start + network_config.validators_per_shard;
            let committee: Vec<ValidatorId> = (shard_start..shard_end)
                .map(|i| ValidatorId::new(u64::from(i)))
                .collect();
            shard_committees.insert(shard, committee);
        }

        // Identity-agnostic snapshot — one allocation shared across every
        // host and every vnode.
        let shared_topology = Arc::new(TopologySnapshot::with_shard_committees(
            NetworkDefinition::simulator(),
            u64::from(network_config.num_shards),
            &global_validator_set,
            shard_committees.clone(),
        ));

        // Beacon genesis: one config + derived (block, state) reused
        // across every host's per-vnode `BeaconCoordinator`. All
        // validators land in a single pool; the first
        // `chain_config.beacon_committee_size` form the beacon committee.
        let (beacon_genesis_block, beacon_genesis_state, beacon_config_hash, beacon_network) = {
            let network = NetworkDefinition::simulator();
            let pool_id = StakePoolId::new(0);
            let n = u128::from(total_validators);
            let initial_validators: Vec<GenesisValidator> = (0..total_validators)
                .map(|i| GenesisValidator {
                    id: ValidatorId::new(u64::from(i)),
                    pool: pool_id,
                    pubkey: public_keys[i as usize],
                })
                .collect();
            let initial_pools = vec![GenesisPool {
                id: pool_id,
                total_stake: Stake::from_attos(n * MIN_STAKE_FLOOR.attos()),
            }];
            let chain_config = network_config.beacon_chain_config.unwrap_or_default();
            let beacon_committee_size =
                u64::from(total_validators.min(chain_config.beacon_committee_size));
            let initial_beacon_committee: Vec<ValidatorId> =
                (0..beacon_committee_size).map(ValidatorId::new).collect();
            let initial_shard_committees: BTreeMap<ShardId, Vec<ValidatorId>> = shard_committees
                .iter()
                .map(|(s, v)| (*s, v.clone()))
                .collect();
            let config = BeaconGenesisConfig {
                chain_config,
                initial_validators,
                initial_pools,
                initial_beacon_committee,
                initial_shard_committees,
                initial_randomness: Randomness::new([0x42; 32]),
            };
            let state = Arc::new(build_genesis_beacon_state(&config));
            let config_hash = genesis_config_hash(&config, &network);
            let block = Arc::new(Verified::<CertifiedBeaconBlock>::genesis(config_hash));
            (block, state, config_hash, network)
        };

        // Build the host→validators layout based on the hosting mode.
        // Each host carries a list of (validator_idx, shard) tuples.
        let vnodes_per_host = network_config.vnodes_per_host;
        assert!(vnodes_per_host >= 1, "vnodes_per_host must be at least 1");
        let host_layout = build_host_layout(network_config);
        let num_hosts = host_layout.len();
        let mut hosts = Vec::with_capacity(num_hosts);
        let mut event_rxs = Vec::with_capacity(num_hosts);

        for (host_index, host_vnodes) in host_layout.iter().enumerate() {
            // Group this host's vnodes by shard. For cross-shard
            // hosting each group has one vnode; for same-shard hosting
            // there's one group per host with `vnodes_per_host` entries.
            let mut by_shard: BTreeMap<ShardId, Vec<u32>> = BTreeMap::new();
            for &(validator_idx, shard) in host_vnodes {
                by_shard.entry(shard).or_default().push(validator_idx);
            }

            // Build per-(host, shard) store bundles. Vnodes in the same
            // shard on the same host share the bundle. Per-shard scoping
            // for `ProvisionStore` keeps a co-hosted source shard's
            // `OutboundProvisionTracker` from evicting entries the target
            // shard's inbound coordinator still needs to verify proposals
            // against.
            let mut shard_stores: HashMap<ShardId, ShardStoreBundle> = HashMap::new();
            for shard in by_shard.keys() {
                shard_stores.insert(
                    *shard,
                    (
                        Arc::new(ProvisionStore::new()),
                        Arc::new(TxStore::new()),
                        Arc::new(ExecCertStore::new()),
                        Arc::new(FinalizedWaveStore::new()),
                    ),
                );
            }

            // Per-host beacon storage. Warm-restart: resume from the latest
            // committed (block, state); commit the genesis pair first on an
            // empty store so fresh-start and restart share one load path.
            let beacon_storage: Arc<dyn BeaconStorage> = Arc::new(SimBeaconStorage::new());
            if beacon_storage.latest_committed_epoch().is_none() {
                beacon_storage.commit_beacon_block(&beacon_genesis_block, &beacon_genesis_state);
            }
            let (beacon_latest_block, beacon_latest_state) = beacon_storage
                .latest_committed()
                .expect("beacon chain is non-empty after the genesis commit above");

            // One `Arc<BeaconProposalPool>` per host, shared across every
            // co-hosted vnode's coordinator and the inbound
            // `GetBeaconProposalRequest` handler.
            let beacon_proposal_pool = Arc::new(BeaconProposalPool::new(
                beacon_latest_state.current_epoch.next(),
            ));

            // Load the full committed history: sim vnodes start with fresh
            // shard chains (`RecoveredState::default()` anchors at genesis),
            // so every committed epoch is still within the chain frontier.
            let beacon_history: Vec<BeaconState> = beacon_storage
                .states_since(Epoch::GENESIS)
                .into_iter()
                .map(|state| state.as_ref().clone())
                .collect();

            let mut vnode_inits: Vec<VnodeInit> = Vec::with_capacity(host_vnodes.len());
            for (shard, validator_idxs) in &by_shard {
                let (provision_store, tx_store, exec_cert_store, fw_store) =
                    shard_stores.get(shard).expect("shard bundle just inserted");
                for &validator_idx in validator_idxs {
                    let validator_id = ValidatorId::new(u64::from(validator_idx));
                    let key_bytes = keys[validator_idx as usize].to_bytes();
                    let signing_key = Arc::new(
                        Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes"),
                    );

                    let beacon_coordinator = BeaconCoordinator::new(
                        Arc::clone(&beacon_latest_block),
                        beacon_history.clone(),
                        validator_id,
                        *shard,
                        WeightedTimestamp::ZERO,
                        beacon_network.clone(),
                        beacon_config_hash,
                        Arc::clone(&beacon_proposal_pool),
                    );

                    let state = NodeStateMachine::new(
                        validator_id,
                        *shard,
                        &ShardConsensusConfig::default(),
                        RecoveredState::default(),
                        beacon_coordinator,
                        MempoolConfig::default(),
                        ProvisionConfig::default(),
                        Arc::clone(provision_store),
                        Arc::clone(tx_store),
                        Arc::clone(exec_cert_store),
                        Arc::clone(fw_store),
                    );

                    vnode_inits.push(VnodeInit { state, signing_key });
                }
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
            let shard_event_senders: HashMap<ShardId, Sender<ShardEvent>> =
                by_shard.keys().map(|s| (*s, event_tx.clone())).collect();
            let host = NodeHost::new(
                vnode_inits,
                storages,
                beacon_storage,
                Arc::clone(&beacon_proposal_pool),
                executor,
                network.create_adapter(
                    NodeIndex::try_from(host_index).expect("host_index fits NodeIndex"),
                ),
                SyncDispatch,
                shard_event_senders,
                topology_arc_for_host,
                NodeConfig::default(),
                tx_validator,
            );

            hosts.push(host);
            event_rxs.push(event_rx);
        }

        info!(
            num_nodes = hosts.len(),
            num_shards = network_config.num_shards,
            validators_per_shard = network_config.validators_per_shard,
            seed,
            "Created simulation runner"
        );

        Self {
            hosts,
            event_rxs,
            event_queue: BTreeMap::new(),
            sequence: 0,
            now: Duration::ZERO,
            network,
            rng,
            timers: HashMap::new(),
            stats: SimulationStats::default(),
            genesis_executed: vec![false; num_hosts],
            traffic_analyzer: None,
            last_gossip_dedup_prune: Duration::ZERO,
        }
    }

    /// Create a new simulation runner with traffic analysis enabled.
    #[must_use]
    pub fn with_traffic_analysis(network_config: &NetworkConfig, seed: u64) -> Self {
        let mut runner = Self::new(network_config, seed);
        let analyzer = Arc::new(NetworkTrafficAnalyzer::new());
        runner.network.set_traffic_analyzer(Arc::clone(&analyzer));
        runner.traffic_analyzer = Some(analyzer);
        runner
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

    /// Get a reference to a node's storage. Returns the storage for the
    /// host's first hosted shard.
    #[must_use]
    pub fn node_storage(&self, node: NodeIndex) -> Option<&SimShardStorage> {
        let host = self.hosts.get(node as usize)?;
        let shard = host.hosted_shards().next()?;
        Some(&host.shard_io(shard).storage)
    }

    /// Process-shared beacon storage for a host. One handle per host,
    /// shared across every vnode on that host.
    #[must_use]
    pub fn beacon_storage(&self, node: NodeIndex) -> Option<&Arc<dyn BeaconStorage>> {
        self.hosts.get(node as usize).map(NodeHost::beacon_storage)
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
    /// [`Self::vnode_state`] to pick a specific validator.
    #[must_use]
    pub fn node(&self, index: NodeIndex) -> Option<&NodeStateMachine> {
        let host = self.hosts.get(index as usize)?;
        let shard = host.hosted_shards().next()?;
        Some(host.vnode_state(shard, 0))
    }

    /// Get a reference to a specific validator's state machine,
    /// regardless of which host bundles it. Works for both same-shard
    /// and cross-shard hosting — walks every host's vnodes looking
    /// for a matching `validator_id`.
    #[must_use]
    pub fn vnode_state(&self, validator_id: ValidatorId) -> Option<&NodeStateMachine> {
        let host_index = self.network.validator_to_node(validator_id) as usize;
        let host = self.hosts.get(host_index)?;
        for shard in host.hosted_shards() {
            for v in 0..host.vnodes_len(shard) {
                let state = host.vnode_state(shard, v);
                if state.validator_id() == validator_id {
                    return Some(state);
                }
            }
        }
        None
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

    /// Get the number of committed blocks stored for a specific node.
    #[must_use]
    pub fn committed_block_count(&self, node: NodeIndex) -> usize {
        self.hosts.get(node as usize).map_or(0, |nl| {
            let Some(shard) = nl.hosted_shards().next() else {
                return 0;
            };
            let s = &nl.shard_io(shard).storage;
            let committed = s.committed_height();
            if committed == BlockHeight::GENESIS {
                usize::from(s.get_block(BlockHeight::GENESIS).is_some())
            } else {
                usize::try_from(committed.inner() + 1).unwrap_or(usize::MAX)
            }
        })
    }

    /// Check if a specific block is stored for a node.
    #[must_use]
    pub fn has_committed_block(&self, node: NodeIndex, height: BlockHeight) -> bool {
        self.hosts.get(node as usize).is_some_and(|nl| {
            nl.hosted_shards()
                .next()
                .is_some_and(|shard| nl.shard_io(shard).storage.get_block(height).is_some())
        })
    }

    /// Schedule an initial event (e.g., to start the simulation).
    /// Schedule an event for initial delivery. The event must be wrapped
    /// in the appropriate [`ShardEvent`] envelope: shard-scoped variants
    /// via [`ShardEvent::shard`] / [`ShardEvent::protocol`],
    /// `SubmitTransaction` via [`ShardEvent::process`].
    pub fn schedule_initial_event(&mut self, node: NodeIndex, delay: Duration, event: ShardEvent) {
        let time = self.now + delay;
        self.schedule_event(node, time, event);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Genesis
    // ═══════════════════════════════════════════════════════════════════════

    /// Initialize all nodes with genesis blocks and start consensus.
    pub fn initialize_genesis(&mut self) {
        self.install_engine_genesis(&GenesisConfig::test_default(), |_| true);
        info!(
            num_nodes = self.hosts.len(),
            "Radix Engine genesis complete on all nodes"
        );
        self.finalize_genesis();
    }

    /// Initialize genesis with pre-funded accounts.
    ///
    /// Each node only receives the accounts that belong to its shard, avoiding
    /// the Radix Engine genesis limit (~8000 accounts per node). The `balances`
    /// list may contain accounts from all shards — they are filtered per-node.
    ///
    /// # Panics
    ///
    /// Panics if a Radix `ComponentAddress` payload is shorter than 30 bytes
    /// (unreachable: `ComponentAddress` is always 30 bytes).
    pub fn initialize_genesis_with_balances(&mut self, balances: &[(ComponentAddress, Decimal)]) {
        let num_shards = u64::from(self.network.config().num_shards);
        let hosts_per_shard =
            self.network.config().validators_per_shard / self.network.config().vnodes_per_host;

        // Pre-group balances by shard so we don't re-filter for every node.
        let mut balances_by_shard: HashMap<ShardId, Vec<_>> = HashMap::new();
        for (address, balance) in balances {
            let radix_node_id = address.into_node_id();
            let det_node_id = NodeId(radix_node_id.0[..30].try_into().unwrap());
            let shard = uniform_shard_for_node(&det_node_id, num_shards);
            balances_by_shard
                .entry(shard)
                .or_default()
                .push((*address, *balance));
        }

        // Each node receives only its own shard's balances. Build one
        // GenesisConfig per shard up-front; the engine cache then memoizes
        // the merged DatabaseUpdates per unique config across the process.
        let configs_by_shard: HashMap<ShardId, GenesisConfig> = balances_by_shard
            .into_iter()
            .map(|(shard_id, shard_balances)| {
                let config = GenesisConfig {
                    xrd_balances: shard_balances,
                    ..GenesisConfig::test_default()
                };
                (shard_id, config)
            })
            .collect();
        let empty_config = GenesisConfig::test_default();

        let shard_depth = self.network.config().num_shards.trailing_zeros();
        for shard_idx in 0..self.network.config().num_shards {
            let shard_id = ShardId::leaf(shard_depth, u64::from(shard_idx));
            let config = configs_by_shard.get(&shard_id).unwrap_or(&empty_config);
            self.install_engine_genesis(config, |node_idx| {
                ShardId::leaf(shard_depth, node_idx as u64 / u64::from(hosts_per_shard)) == shard_id
            });
        }

        info!(
            num_nodes = self.hosts.len(),
            num_funded_accounts = balances.len(),
            "Radix Engine genesis complete with funded accounts"
        );

        self.finalize_genesis();
    }

    /// Apply a prepared engine genesis snapshot to every node selected by
    /// `select`. Inbound handler registration happens once for all nodes in
    /// [`Self::finalize_genesis`]. Cross-shard hosts install genesis
    /// against every hosted shard's storage.
    fn install_engine_genesis(
        &mut self,
        config: &GenesisConfig,
        mut select: impl FnMut(usize) -> bool,
    ) {
        for node_idx in 0..self.hosts.len() {
            if self.genesis_executed[node_idx] || !select(node_idx) {
                continue;
            }
            let hosted: Vec<ShardId> = self.hosts[node_idx].hosted_shards().collect();
            for shard in hosted {
                self.hosts[node_idx].install_engine_genesis(shard, config);
            }
            self.genesis_executed[node_idx] = true;
        }
    }

    /// Initialize state-machine genesis on all nodes and register inbound
    /// network handlers. Called after engine genesis on every node.
    ///
    /// For each shard, locate every host that serves it (across both
    /// same-shard and cross-shard hosting layouts), initialize that
    /// shard's genesis block on those hosts, and schedule the
    /// `BlockCommitted` event.
    fn finalize_genesis(&mut self) {
        use hyperscale_storage::SubstateStore;
        use hyperscale_types::Block;

        let num_shards = self.network.config().num_shards;
        let shard_depth = num_shards.trailing_zeros();

        for shard_id in 0..num_shards {
            let shard = ShardId::leaf(shard_depth, u64::from(shard_id));

            // Hosts that carry at least one vnode in this shard.
            let num_hosts =
                NodeIndex::try_from(self.hosts.len()).expect("host count fits NodeIndex");
            let hosts_for_shard: Vec<NodeIndex> = (0..num_hosts)
                .filter(|&h| self.hosts[h as usize].hosted_shards().any(|s| s == shard))
                .collect();

            let first_host = *hosts_for_shard
                .first()
                .expect("every shard must have at least one host");
            let first_node_storage = &self.hosts[first_host as usize].shard_io(shard).storage;
            let genesis_jmt_root = first_node_storage.state_root();

            info!(
                shard = shard_id,
                genesis_jmt_root = ?genesis_jmt_root,
                "JMT state after genesis bootstrap"
            );

            // Proposer = first validator in the shard's committee
            // (shard_id * validators_per_shard).
            let proposer = ValidatorId::new(u64::from(
                shard_id * self.network.config().validators_per_shard,
            ));
            let genesis_block = Block::genesis(shard, proposer, genesis_jmt_root);

            for host_index in &hosts_for_shard {
                let i = *host_index as usize;
                self.hosts[i].initialize_shard_genesis(&genesis_block);
                self.hosts[i].flush_all_batches();

                // Drain outputs from genesis initialization (timer sets, etc.)
                let output = self.hosts[i].drain_pending_output();
                self.drain_node_io(*host_index);
                self.process_step_output(*host_index, output);

                // Sync state machine with actual JMT state after genesis bootstrap.
                let genesis_certified = Arc::new(Verified::<CertifiedBlock>::genesis(
                    shard,
                    proposer,
                    genesis_jmt_root,
                ));
                let genesis_commit_event = ShardEvent::protocol(
                    shard,
                    ProtocolEvent::BlockCommitted {
                        certified: genesis_certified,
                    },
                );
                self.schedule_event(*host_index, self.now, genesis_commit_event);
            }

            info!(
                shard = shard_id,
                genesis_hash = ?genesis_block.hash(),
                hosts = hosts_for_shard.len(),
                "Initialized genesis for shard"
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

                self.hosts[node_index as usize].set_time(LocalTimestamp::from_millis(
                    u64::try_from(self.now.as_millis()).unwrap_or(u64::MAX),
                ));
                let output = self.hosts[node_index as usize].step(event);
                self.hosts[node_index as usize].flush_all_batches();

                self.drain_node_io(node_index);
                self.process_step_output(node_index, output);
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

    /// Process `StepOutput`: stats and timer ops.
    fn process_step_output(&mut self, node: NodeIndex, output: StepOutput) {
        self.stats.actions_generated += u64::try_from(output.actions_generated).unwrap_or(u64::MAX);
        for op in output.timer_ops {
            self.process_timer_op(node, op);
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

    fn schedule_event(&mut self, node: NodeIndex, time: Duration, event: ShardEvent) -> EventKey {
        self.sequence += 1;
        let key = EventKey::new(time, &event, node, self.sequence);
        self.event_queue.insert(key, event);
        key
    }
}

/// Compute the host→validators layout for a simulation network.
///
/// Returns one entry per host, each a list of `(validator_idx, shard)`
/// tuples the host carries. The shape depends on `config.hosting_mode`:
///
/// - [`HostingMode::SameShardBundled`]: hosts are
///   `num_shards * validators_per_shard / vnodes_per_host`. Host `h`
///   in shard `s` carries `vnodes_per_host` consecutive validators
///   starting at `h * vnodes_per_host` within that shard.
/// - [`HostingMode::CrossShard`]: hosts are `validators_per_shard`.
///   Host `h` carries one validator from every shard — specifically
///   `{s * validators_per_shard + h : s in 0..num_shards}`.
fn build_host_layout(config: &NetworkConfig) -> Vec<Vec<(u32, ShardId)>> {
    match config.hosting_mode {
        HostingMode::SameShardBundled => {
            assert_eq!(
                config.validators_per_shard % config.vnodes_per_host,
                0,
                "vnodes_per_host must divide validators_per_shard"
            );
            let hosts_per_shard = config.validators_per_shard / config.vnodes_per_host;
            let shard_depth = config.num_shards.trailing_zeros();
            let mut layout = Vec::with_capacity((config.num_shards * hosts_per_shard) as usize);
            for shard_id in 0..config.num_shards {
                let shard = ShardId::leaf(shard_depth, u64::from(shard_id));
                for h in 0..hosts_per_shard {
                    let host_first_validator =
                        shard_id * config.validators_per_shard + h * config.vnodes_per_host;
                    let host_vnodes: Vec<(u32, ShardId)> = (0..config.vnodes_per_host)
                        .map(|v| (host_first_validator + v, shard))
                        .collect();
                    layout.push(host_vnodes);
                }
            }
            layout
        }
        HostingMode::CrossShard => {
            let shard_depth = config.num_shards.trailing_zeros();
            let mut layout = Vec::with_capacity(config.validators_per_shard as usize);
            for h in 0..config.validators_per_shard {
                let host_vnodes: Vec<(u32, ShardId)> = (0..config.num_shards)
                    .map(|s| {
                        let validator_idx = s * config.validators_per_shard + h;
                        (validator_idx, ShardId::leaf(shard_depth, u64::from(s)))
                    })
                    .collect();
                layout.push(host_vnodes);
            }
            layout
        }
    }
}
