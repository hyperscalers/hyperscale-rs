//! A host with seats on one shard, for tests of what its loop does with
//! more than one of them.

use std::collections::BTreeMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use crossbeam::channel::{Receiver, unbounded};
use hyperscale_beacon::genesis::build_genesis_beacon_state;
use hyperscale_crypto_bls::BlsVerifier;
use hyperscale_dispatch_sync::SyncDispatch;
use hyperscale_engine::{AllCodeRuns, ExecutionMode, Executor};
use hyperscale_mempool::MempoolConfig;
use hyperscale_network::HandlerRegistry;
use hyperscale_network_memory::SimNetworkAdapter;
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BeaconStorage, RecoveredState};
use hyperscale_storage_memory::{SimBeaconStorage, SimShardStorage};
use hyperscale_types::test_utils::{StubVmStatics, TestCommittee};
use hyperscale_types::{
    BeaconChainConfig, BeaconGenesisConfig, BeaconState, BlockHeight, CertifiedBeaconBlock,
    GenesisConfigHash, GenesisPool, GenesisValidator, LocalTimestamp, MIN_STAKE_FLOOR,
    NetworkDefinition, Randomness, ShardAnchor, ShardId, Signer, Stake, StakePoolId,
    TopologySnapshot, ValidatorId, ValidatorInfo, ValidatorSet, Verified, genesis_config_hash,
    shard_prefix_path,
};

use crate::shard::{HostEvent, ShardLoop};
use crate::{NodeConfig, NodeHost, SeatConfig, StartupChain, VnodeSeat};

pub const SHARD: ShardId = ShardId::leaf(1, 0);

pub type Host = NodeHost<SimShardStorage, SimNetworkAdapter, SyncDispatch>;
pub type Loop = ShardLoop<SimShardStorage, SimNetworkAdapter, SyncDispatch>;

/// A one-pool genesis whose first two validators seat on `SHARD`.
pub struct Fixture {
    pub committee: TestCommittee,
    genesis_block: Arc<Verified<CertifiedBeaconBlock>>,
    genesis_state: BeaconState,
    config_hash: GenesisConfigHash,
    validator_set: ValidatorSet,
    topology_snapshot: Arc<TopologySnapshot>,
}

impl Fixture {
    pub fn new() -> Self {
        let committee = TestCommittee::new(4, 7);
        let network = NetworkDefinition::simulator();
        let pool = StakePoolId::new(0);
        let ids: Vec<ValidatorId> = (0..4).map(|i| committee.validator_id(i)).collect();
        let config = BeaconGenesisConfig {
            chain_config: BeaconChainConfig::default(),
            initial_validators: (0..4)
                .map(|i| GenesisValidator {
                    id: committee.validator_id(i),
                    pool,
                    pubkey: *committee.public_key(i),
                })
                .collect(),
            initial_pools: vec![GenesisPool {
                id: pool,
                total_stake: Stake::from_quanta(4 * MIN_STAKE_FLOOR.quanta()),
            }],
            initial_beacon_committee: ids.clone(),
            initial_shard_committee: ids,
            initial_randomness: Randomness::new([0x42; 32]),
        };
        let genesis_state = build_genesis_beacon_state(&config);
        let config_hash = genesis_config_hash(&config, &network, &[]);
        let genesis_block = Arc::new(Verified::<CertifiedBeaconBlock>::genesis(config_hash));
        let validator_set = ValidatorSet::new(
            (0..4)
                .map(|i| ValidatorInfo {
                    validator_id: committee.validator_id(i),
                    public_key: *committee.public_key(i),
                })
                .collect(),
        );
        let shard_committees = BTreeMap::from([(
            SHARD,
            vec![committee.validator_id(0), committee.validator_id(1)],
        )]);
        let topology_snapshot = Arc::new(TopologySnapshot::with_shard_committees(
            network,
            2,
            &validator_set,
            shard_committees,
        ));
        Self {
            committee,
            genesis_block,
            genesis_state,
            config_hash,
            validator_set,
            topology_snapshot,
        }
    }

    /// A two-leaf topology over this committee with `committees` seated.
    pub fn topology(&self, committees: BTreeMap<ShardId, Vec<ValidatorId>>) -> TopologySnapshot {
        self.topology_of(2, committees)
    }

    /// A `leaves`-leaf topology over this committee with `committees`
    /// seated.
    pub fn topology_of(
        &self,
        leaves: u64,
        committees: BTreeMap<ShardId, Vec<ValidatorId>>,
    ) -> TopologySnapshot {
        TopologySnapshot::with_shard_committees(
            NetworkDefinition::simulator(),
            leaves,
            &self.validator_set,
            committees,
        )
    }

    /// The beacon state every host here starts from.
    pub const fn genesis_state(&self) -> &BeaconState {
        &self.genesis_state
    }

    /// The genesis beacon block every host here starts from.
    pub fn genesis_block(&self) -> Arc<Verified<CertifiedBeaconBlock>> {
        Arc::clone(&self.genesis_block)
    }

    /// How every host here builds its vnodes and its fold.
    pub fn seat_config(&self) -> SeatConfig {
        SeatConfig {
            verifier: Arc::new(BlsVerifier),
            derivation: Arc::new(StubVmStatics),
            code: Arc::new(AllCodeRuns),
            beacon_network: NetworkDefinition::simulator(),
            beacon_config_hash: self.config_hash,
            shard_config: ShardConsensusConfig::default(),
            mempool_config: MempoolConfig::default(),
            provision_config: ProvisionConfig::default(),
        }
    }

    /// A queued seat for `committee[idx]`.
    pub fn seat(&self, idx: usize) -> VnodeSeat {
        VnodeSeat {
            config: self.seat_config(),
            validator: self.committee.validator_id(idx),
            signer: self.committee.signer(idx),
        }
    }

    /// `committee[idx]`'s identity and key.
    pub fn identity(&self, idx: usize) -> (ValidatorId, Arc<dyn Signer>) {
        (self.committee.validator_id(idx), self.committee.signer(idx))
    }

    /// A host running `SHARD` with `committee[0]` seated, restored at
    /// `committed` over an empty store.
    pub fn host(&self, committed: BlockHeight) -> Host {
        self.host_with_events(committed).0
    }

    /// [`Self::host`], beside the channel its loops push their own
    /// events into.
    pub fn host_with_events(&self, committed: BlockHeight) -> (Host, Receiver<HostEvent>) {
        self.host_with_events_over(SimShardStorage::new(shard_prefix_path(SHARD)), committed)
    }

    /// [`Self::host_with_events`] over `storage`.
    pub fn host_with_events_over(
        &self,
        storage: SimShardStorage,
        committed: BlockHeight,
    ) -> (Host, Receiver<HostEvent>) {
        self.host_on(storage, committed, Arc::clone(&self.topology_snapshot))
    }

    /// A host running `SHARD` with `committee[0]` seated over `storage`,
    /// restored at `committed`, on a topology attesting `boundary` for
    /// the shard.
    pub fn host_over(
        &self,
        storage: SimShardStorage,
        committed: BlockHeight,
        boundary: ShardAnchor,
    ) -> Host {
        let topology = TopologySnapshot::clone(&self.topology_snapshot)
            .with_boundaries(BTreeMap::from([(SHARD, boundary)]));
        self.host_on(storage, committed, Arc::new(topology)).0
    }

    fn host_on(
        &self,
        storage: SimShardStorage,
        committed: BlockHeight,
        topology: Arc<TopologySnapshot>,
    ) -> (Host, Receiver<HostEvent>) {
        let registry = Arc::new(HandlerRegistry::new(std::iter::once(SHARD).collect()));
        self.host_through(
            storage,
            committed,
            topology,
            SimNetworkAdapter::new(registry),
            SyncDispatch::new(),
        )
    }

    /// A host running `SHARD` with `committee[0]` seated at genesis, whose
    /// requests go out through `network` and whose delegated work runs on
    /// `dispatch`, beside the channel its loops push their own events into.
    pub fn host_through_network(
        &self,
        network: SimNetworkAdapter,
        dispatch: SyncDispatch,
    ) -> (Host, Receiver<HostEvent>) {
        self.host_through(
            SimShardStorage::new(shard_prefix_path(SHARD)),
            BlockHeight::GENESIS,
            Arc::clone(&self.topology_snapshot),
            network,
            dispatch,
        )
    }

    /// A host running no shard and no participant, at `now`, over beacon
    /// storage holding `history`'s blocks and states.
    pub fn host_over_history(
        &self,
        history: Vec<(Arc<Verified<CertifiedBeaconBlock>>, BeaconState)>,
        now: LocalTimestamp,
    ) -> (Host, Receiver<HostEvent>) {
        let (event_tx, events) = unbounded();
        let beacon_storage: Arc<dyn BeaconStorage> = Arc::new(SimBeaconStorage::new());
        for (block, state) in history {
            beacon_storage.commit_beacon_block(&block, &Arc::new(state));
        }
        let registry = Arc::new(HandlerRegistry::new(std::collections::BTreeSet::new()));
        let host = NodeHost::new(
            self.seat_config(),
            Vec::new(),
            Vec::new(),
            beacon_storage,
            Arc::new(Executor::new(ExecutionMode::Serial)),
            SimNetworkAdapter::new(registry),
            SyncDispatch::new(),
            BTreeMap::new(),
            event_tx,
            Arc::new(ArcSwap::from(Arc::clone(&self.topology_snapshot))),
            NodeConfig::default(),
            now,
        );
        (host, events)
    }

    /// A host restarted from what it persisted: beacon storage holding
    /// `history`'s blocks and states, and `SHARD`'s `storage`, resumed
    /// from what the store recovers with `committee[0]` seated, at `now`.
    pub fn host_resumed(
        &self,
        history: Vec<(Arc<Verified<CertifiedBeaconBlock>>, BeaconState)>,
        storage: SimShardStorage,
        now: LocalTimestamp,
    ) -> (Host, Receiver<HostEvent>) {
        let (event_tx, events) = unbounded();
        let beacon_storage: Arc<dyn BeaconStorage> = Arc::new(SimBeaconStorage::new());
        for (block, state) in history {
            beacon_storage.commit_beacon_block(&block, &Arc::new(state));
        }
        let recovered = storage.load_recovered_state(SHARD);
        let registry = Arc::new(HandlerRegistry::new(std::iter::once(SHARD).collect()));
        let host = NodeHost::new(
            self.seat_config(),
            vec![StartupChain {
                shard: SHARD,
                storage,
                recovered: &recovered,
                vnodes: vec![self.identity(0)],
            }],
            Vec::new(),
            beacon_storage,
            Arc::new(Executor::new(ExecutionMode::Serial)),
            SimNetworkAdapter::new(registry),
            SyncDispatch::new(),
            std::iter::once((SHARD, event_tx.clone())).collect(),
            event_tx,
            Arc::new(ArcSwap::from(Arc::clone(&self.topology_snapshot))),
            NodeConfig::default(),
            now,
        );
        (host, events)
    }

    /// A host running `SHARD` with `committee[0]` seated at genesis over
    /// beacon storage whose committed tip is `state`.
    pub fn host_over_state(&self, state: BeaconState) -> Host {
        let registry = Arc::new(HandlerRegistry::new(std::iter::once(SHARD).collect()));
        self.host_through_state(
            SimShardStorage::new(shard_prefix_path(SHARD)),
            BlockHeight::GENESIS,
            Arc::clone(&self.topology_snapshot),
            SimNetworkAdapter::new(registry),
            SyncDispatch::new(),
            state,
        )
        .0
    }

    fn host_through(
        &self,
        storage: SimShardStorage,
        committed: BlockHeight,
        topology: Arc<TopologySnapshot>,
        network: SimNetworkAdapter,
        dispatch: SyncDispatch,
    ) -> (Host, Receiver<HostEvent>) {
        self.host_through_state(
            storage,
            committed,
            topology,
            network,
            dispatch,
            self.genesis_state.clone(),
        )
    }

    fn host_through_state(
        &self,
        storage: SimShardStorage,
        committed: BlockHeight,
        topology: Arc<TopologySnapshot>,
        network: SimNetworkAdapter,
        dispatch: SyncDispatch,
        state: BeaconState,
    ) -> (Host, Receiver<HostEvent>) {
        let (event_tx, events) = unbounded();
        let beacon_storage: Arc<dyn BeaconStorage> = Arc::new(SimBeaconStorage::new());
        beacon_storage.commit_beacon_block(&self.genesis_block, &Arc::new(state));
        let recovered = RecoveredState {
            committed_height: committed,
            ..RecoveredState::default()
        };
        let host = NodeHost::new(
            self.seat_config(),
            vec![StartupChain {
                shard: SHARD,
                storage,
                recovered: &recovered,
                vnodes: vec![self.identity(0)],
            }],
            Vec::new(),
            beacon_storage,
            Arc::new(Executor::new(ExecutionMode::Serial)),
            network,
            dispatch,
            std::iter::once((SHARD, event_tx.clone())).collect(),
            event_tx,
            Arc::new(ArcSwap::from(topology)),
            NodeConfig::default(),
            LocalTimestamp::ZERO,
        );
        (host, events)
    }
}

/// The loop `host` runs `SHARD` on.
pub fn loop_of(host: &mut Host) -> &mut Loop {
    host.shard_loop_mut(SHARD)
}
