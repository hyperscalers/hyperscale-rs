//! Runtime shard add/remove on `NodeHost`.
//!
//! A host starts on shard A, adds shard B mid-run, and drops it again.
//! Assertions ride the externally observable seams: the handler
//! registry's request map (serving), gossip fan-out into the event
//! channel (routing), and the host's own shard accessors.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use arc_swap::ArcSwap;
use crossbeam::channel::unbounded;
use hyperscale_beacon::coordinator::BeaconCoordinator;
use hyperscale_beacon::genesis::build_genesis_beacon_state;
use hyperscale_dispatch_sync::SyncDispatch;
use hyperscale_engine::{RadixExecutor, TransactionValidation};
use hyperscale_execution::{ExecCertStore, FinalizedWaveStore};
use hyperscale_mempool::{MempoolConfig, TxStore};
use hyperscale_network::HandlerRegistry;
use hyperscale_network_memory::SimNetworkAdapter;
use hyperscale_node::shard_loop::{ShardEvent, ShardScopedInput};
use hyperscale_node::{NodeConfig, NodeHost, NodeStateMachine, VnodeInit};
use hyperscale_provisions::{ProvisionConfig, ProvisionStore};
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BeaconStorage, RecoveredState};
use hyperscale_storage_memory::{SimBeaconStorage, SimShardStorage};
use hyperscale_test_helpers::TestCommittee;
use hyperscale_types::network::gossip::TransactionGossip;
use hyperscale_types::network::request::GetBlockRequest;
use hyperscale_types::test_utils::test_transaction;
use hyperscale_types::{
    BeaconChainConfig, BeaconGenesisConfig, BeaconState, BlockHeight, Bls12381G1PrivateKey,
    CertifiedBeaconBlock, GenesisConfigHash, GenesisPool, GenesisValidator, MIN_STAKE_FLOOR,
    NetworkDefinition, Randomness, ShardId, Stake, StakePoolId, TopologySnapshot, ValidatorId,
    ValidatorInfo, ValidatorSet, Verified, WeightedTimestamp, genesis_config_hash,
    shard_prefix_path,
};

const SHARD_A: ShardId = ShardId::leaf(1, 0);
const SHARD_B: ShardId = ShardId::leaf(1, 1);

/// Shared two-shard genesis: validators 0–1 on shard A, 2–3 on shard B,
/// everyone in one pool.
struct Fixture {
    committee: TestCommittee,
    genesis_block: Arc<Verified<CertifiedBeaconBlock>>,
    genesis_state: BeaconState,
    config_hash: GenesisConfigHash,
    topology: Arc<TopologySnapshot>,
}

fn fixture() -> Fixture {
    let committee = TestCommittee::new(4, 7);
    let network = NetworkDefinition::simulator();
    let pool_id = StakePoolId::new(0);
    let initial_validators: Vec<GenesisValidator> = (0..4)
        .map(|i| GenesisValidator {
            id: committee.validator_id(i),
            pool: pool_id,
            pubkey: *committee.public_key(i),
        })
        .collect();
    let shard_committees: BTreeMap<ShardId, Vec<ValidatorId>> = [
        (
            SHARD_A,
            vec![committee.validator_id(0), committee.validator_id(1)],
        ),
        (
            SHARD_B,
            vec![committee.validator_id(2), committee.validator_id(3)],
        ),
    ]
    .into_iter()
    .collect();
    let config = BeaconGenesisConfig {
        chain_config: BeaconChainConfig {
            num_shards: 2,
            shard_size: 2,
            ..BeaconChainConfig::default()
        },
        initial_validators,
        initial_pools: vec![GenesisPool {
            id: pool_id,
            total_stake: Stake::from_attos(4 * MIN_STAKE_FLOOR.attos()),
        }],
        initial_beacon_committee: (0..4).map(|i| committee.validator_id(i)).collect(),
        initial_shard_committees: shard_committees.clone(),
        initial_randomness: Randomness::new([0x42; 32]),
    };
    let genesis_state = build_genesis_beacon_state(&config);
    let config_hash = genesis_config_hash(&config, &network);
    let genesis_block = Arc::new(Verified::<CertifiedBeaconBlock>::genesis(config_hash));

    let validator_set = ValidatorSet::new(
        (0..4)
            .map(|i| ValidatorInfo {
                validator_id: committee.validator_id(i),
                public_key: *committee.public_key(i),
            })
            .collect(),
    );
    let topology = Arc::new(TopologySnapshot::with_shard_committees(
        network,
        2,
        &validator_set,
        shard_committees
            .into_iter()
            .collect::<HashMap<ShardId, Vec<ValidatorId>>>(),
    ));
    Fixture {
        committee,
        genesis_block,
        genesis_state,
        config_hash,
        topology,
    }
}

impl Fixture {
    /// A vnode for `committee[idx]` homed on `shard`.
    fn vnode_init(&self, idx: usize, shard: ShardId) -> VnodeInit {
        let me = self.committee.validator_id(idx);
        let beacon = BeaconCoordinator::new(
            Arc::clone(&self.genesis_block),
            vec![self.genesis_state.clone()],
            me,
            shard,
            WeightedTimestamp::ZERO,
            NetworkDefinition::simulator(),
            self.config_hash,
        );
        let state = NodeStateMachine::new(
            me,
            shard,
            &ShardConsensusConfig::default(),
            RecoveredState::default(),
            beacon,
            MempoolConfig::default(),
            ProvisionConfig::default(),
            Arc::new(ProvisionStore::new()),
            Arc::new(TxStore::new()),
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizedWaveStore::new()),
        );
        VnodeInit {
            state,
            signing_key: Arc::new(
                Bls12381G1PrivateKey::from_bytes(&self.committee.keypair(idx).to_bytes())
                    .expect("valid key bytes"),
            ),
        }
    }
}

fn block_request() -> GetBlockRequest {
    GetBlockRequest::new(BlockHeight::new(1), BlockHeight::new(1))
}

#[test]
fn add_and_remove_shard_at_runtime() {
    let fix = fixture();
    let registry = Arc::new(HandlerRegistry::new(std::iter::once(SHARD_A).collect()));
    let network = SimNetworkAdapter::new(Arc::clone(&registry));
    let (event_tx, event_rx) = unbounded();
    let beacon_storage: Arc<dyn BeaconStorage> = Arc::new(SimBeaconStorage::new());
    beacon_storage.commit_beacon_block(&fix.genesis_block, &Arc::new(fix.genesis_state.clone()));

    let mut host = NodeHost::new(
        vec![fix.vnode_init(0, SHARD_A)],
        std::iter::once((SHARD_A, SimShardStorage::new(shard_prefix_path(SHARD_A)))).collect(),
        Arc::clone(&beacon_storage),
        NetworkDefinition::simulator(),
        RadixExecutor::new(NetworkDefinition::simulator()),
        network,
        SyncDispatch,
        std::iter::once((SHARD_A, event_tx.clone())).collect(),
        Arc::new(ArcSwap::from(Arc::clone(&fix.topology))),
        NodeConfig::default(),
        Arc::new(TransactionValidation::new(NetworkDefinition::simulator())),
    );
    host.register_inbound_handlers();
    // Drain anything startup produced so later assertions see only
    // reconfiguration traffic.
    while event_rx.try_recv().is_ok() {}

    // Shard B is unknown: no request serving, no gossip routing.
    assert!(!host.hosted_shards().any(|s| s == SHARD_B));
    assert!(
        registry
            .local_dispatch_request(SHARD_B, block_request())
            .is_none()
    );
    let gossip = TransactionGossip::new(vec![Arc::new(test_transaction(1))]);
    let _ = registry.local_dispatch_gossip(&gossip, Some(SHARD_B));
    assert!(
        event_rx.try_recv().is_err(),
        "gossip for an unhosted shard must not route"
    );

    // Add shard B at runtime.
    host.add_shard(
        vec![fix.vnode_init(2, SHARD_B)],
        SimShardStorage::new(shard_prefix_path(SHARD_B)),
        event_tx.clone(),
    );
    assert!(host.hosted_shards().any(|s| s == SHARD_B));
    assert_eq!(host.vnodes_len(SHARD_B), 1);
    assert!(
        registry
            .local_dispatch_request(SHARD_B, block_request())
            .is_some(),
        "request handlers for the added shard serve"
    );
    let gossip = TransactionGossip::new(vec![Arc::new(test_transaction(2))]);
    let _ = registry.local_dispatch_gossip(&gossip, Some(SHARD_B));
    let event = event_rx
        .try_recv()
        .expect("gossip for the added shard routes to its channel");
    assert!(matches!(event, ShardEvent::Shard(s, _) if s == SHARD_B));
    // The host steps the routed event without panicking.
    let _ = host.step(event);

    // Remove shard B.
    let removed = host.remove_shard(SHARD_B);
    assert!(removed.is_some());
    drop(removed);
    assert!(!host.hosted_shards().any(|s| s == SHARD_B));
    assert!(
        registry
            .local_dispatch_request(SHARD_B, block_request())
            .is_none(),
        "request handlers for the dropped shard are gone"
    );
    let gossip = TransactionGossip::new(vec![Arc::new(test_transaction(3))]);
    let _ = registry.local_dispatch_gossip(&gossip, Some(SHARD_B));
    assert!(
        event_rx.try_recv().is_err(),
        "gossip for a dropped shard must not route"
    );
    // Events still addressed to the dropped shard are discarded, not a panic.
    let _ = host.step(ShardEvent::shard(SHARD_B, ShardScopedInput::FetchTick));

    // Re-join: the shard registers afresh.
    host.add_shard(
        vec![fix.vnode_init(3, SHARD_B)],
        SimShardStorage::new(shard_prefix_path(SHARD_B)),
        event_tx,
    );
    assert!(
        registry
            .local_dispatch_request(SHARD_B, block_request())
            .is_some(),
        "a re-added shard serves again"
    );
}

/// `remove_shard` on a shard the host never carried is a no-op.
#[test]
fn remove_unknown_shard_is_none() {
    let fix = fixture();
    let registry = Arc::new(HandlerRegistry::new(std::iter::once(SHARD_A).collect()));
    let network = SimNetworkAdapter::new(Arc::clone(&registry));
    let (event_tx, _event_rx) = unbounded();
    let beacon_storage: Arc<dyn BeaconStorage> = Arc::new(SimBeaconStorage::new());
    beacon_storage.commit_beacon_block(&fix.genesis_block, &Arc::new(fix.genesis_state.clone()));

    let mut host = NodeHost::new(
        vec![fix.vnode_init(0, SHARD_A)],
        std::iter::once((SHARD_A, SimShardStorage::new(shard_prefix_path(SHARD_A)))).collect(),
        beacon_storage,
        NetworkDefinition::simulator(),
        RadixExecutor::new(NetworkDefinition::simulator()),
        network,
        SyncDispatch,
        std::iter::once((SHARD_A, event_tx)).collect(),
        Arc::new(ArcSwap::from(Arc::clone(&fix.topology))),
        NodeConfig::default(),
        Arc::new(TransactionValidation::new(NetworkDefinition::simulator())),
    );
    assert!(host.remove_shard(SHARD_B).is_none());
    assert!(host.hosted_shards().any(|s| s == SHARD_A));
}
