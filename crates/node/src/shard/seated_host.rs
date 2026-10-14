//! A host with seats on one shard, for tests of what its loop does with
//! more than one of them.

use std::collections::BTreeMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use crossbeam::channel::{Receiver, unbounded};
use hyperscale_beacon::coordinator::{BeaconCoordinator, LocalChainAnchors};
use hyperscale_beacon::genesis::build_genesis_beacon_state;
use hyperscale_crypto_bls::BlsVerifier;
use hyperscale_dispatch_sync::SyncDispatch;
use hyperscale_engine::{AllCodeRuns, ExecutionMode, Executor};
use hyperscale_execution::{CrossingIndexSlot, ExecCertStore, FinalizationStore};
use hyperscale_mempool::{MempoolConfig, TxStore};
use hyperscale_network::HandlerRegistry;
use hyperscale_network_memory::SimNetworkAdapter;
use hyperscale_provisions::{ProvisionConfig, ProvisionStore};
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BeaconStorage, RecoveredState};
use hyperscale_storage_memory::{SimBeaconStorage, SimShardStorage};
use hyperscale_types::test_utils::{StubVmStatics, TestCommittee};
use hyperscale_types::{
    BeaconChainConfig, BeaconGenesisConfig, BeaconState, BlockHeight, CertifiedBeaconBlock,
    GenesisConfigHash, GenesisPool, GenesisValidator, MIN_STAKE_FLOOR, NetworkDefinition,
    Randomness, ShardAnchor, ShardId, Stake, StakePoolId, TopologySnapshot, ValidatorId,
    ValidatorInfo, ValidatorSet, Verified, genesis_config_hash, shard_prefix_path,
};

use crate::shard::{HostEvent, ShardLoop};
use crate::{NodeConfig, NodeHost, NodeStateMachine, SeatConfig, VnodeInit, VnodeSeat};

pub const SHARD: ShardId = ShardId::leaf(1, 0);

pub type Host = NodeHost<SimShardStorage, SimNetworkAdapter, SyncDispatch>;
pub type Loop = ShardLoop<SimShardStorage, SimNetworkAdapter, SyncDispatch>;

/// A one-pool genesis whose first two validators seat on `SHARD`.
pub struct Fixture {
    pub committee: TestCommittee,
    genesis_block: Arc<Verified<CertifiedBeaconBlock>>,
    genesis_state: BeaconState,
    config_hash: GenesisConfigHash,
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
            topology_snapshot,
        }
    }

    /// A vnode for `committee[idx]` on `SHARD`, restored at `recovered`.
    fn vnode_init(&self, idx: usize, recovered: &RecoveredState) -> VnodeInit {
        let me = self.committee.validator_id(idx);
        let beacon = BeaconCoordinator::new(
            Arc::new(BlsVerifier),
            Arc::clone(&self.genesis_block),
            vec![self.genesis_state.clone()],
            me,
            SHARD,
            Some(LocalChainAnchors::GENESIS),
            NetworkDefinition::simulator(),
            self.config_hash,
        );
        let state = NodeStateMachine::new(
            me,
            Arc::new(StubVmStatics),
            Arc::new(AllCodeRuns),
            SHARD,
            &ShardConsensusConfig::default(),
            recovered,
            beacon,
            MempoolConfig::default(),
            ProvisionConfig::default(),
            Arc::new(ProvisionStore::new()),
            Arc::new(TxStore::new()),
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::new(CrossingIndexSlot::default()),
        );
        VnodeInit {
            state,
            signer: self.committee.signer(idx),
        }
    }

    /// A queued seat for `committee[idx]`.
    pub fn seat(&self, idx: usize) -> VnodeSeat {
        VnodeSeat {
            config: SeatConfig {
                verifier: Arc::new(BlsVerifier),
                derivation: Arc::new(StubVmStatics),
                code: Arc::new(AllCodeRuns),
                beacon_network: NetworkDefinition::simulator(),
                beacon_config_hash: self.config_hash,
                shard_config: ShardConsensusConfig::default(),
                mempool_config: MempoolConfig::default(),
                provision_config: ProvisionConfig::default(),
            },
            validator: self.committee.validator_id(idx),
            signer: self.committee.signer(idx),
        }
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
        let (event_tx, events) = unbounded();
        let beacon_storage: Arc<dyn BeaconStorage> = Arc::new(SimBeaconStorage::new());
        beacon_storage
            .commit_beacon_block(&self.genesis_block, &Arc::new(self.genesis_state.clone()));
        let recovered = RecoveredState {
            committed_height: committed,
            ..RecoveredState::default()
        };
        let host = NodeHost::new(
            vec![self.vnode_init(0, &recovered)],
            std::iter::once((SHARD, storage)).collect(),
            beacon_storage,
            NetworkDefinition::simulator(),
            Arc::new(Executor::new(ExecutionMode::Serial)),
            SimNetworkAdapter::new(registry),
            SyncDispatch::new(),
            std::iter::once((SHARD, event_tx.clone())).collect(),
            event_tx,
            Arc::new(ArcSwap::from(topology)),
            NodeConfig::default(),
        );
        (host, events)
    }
}

/// The loop `host` runs `SHARD` on.
pub fn loop_of(host: &mut Host) -> &mut Loop {
    host.shard_loop_mut(SHARD)
}
