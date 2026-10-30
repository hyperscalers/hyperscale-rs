//! Runtime shard add/remove on `NodeHost`.
//!
//! A host starts on shard A, adds shard B mid-run, and drops it again.
//! Assertions ride the externally observable seams: the handler
//! registry's request map (serving), gossip fan-out into the event
//! channel (routing), and the host's own shard accessors.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use arc_swap::ArcSwap;
use crossbeam::channel::{Receiver, Sender, unbounded};
use hyperscale_beacon::genesis::build_genesis_beacon_state;
use hyperscale_crypto_bls::BlsVerifier;
use hyperscale_dispatch_sync::SyncDispatch;
use hyperscale_engine::{AllCodeRuns, ExecutionMode, Executor};
use hyperscale_hbor::Capped;
use hyperscale_mempool::MempoolConfig;
use hyperscale_network::{HandlerRegistry, Verdict};
use hyperscale_network_memory::SimNetworkAdapter;
use hyperscale_node::shard::{HostEvent, ProcessScopedInput, ShardScopedInput};
use hyperscale_node::{HostResources, HostedChain, NodeConfig, NodeHost, ReplicaConfig};
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BeaconStorage, RecoveredState};
use hyperscale_storage_memory::{SimBeaconStorage, SimShardStorage};
use hyperscale_types::network::gossip::TransactionGossip;
use hyperscale_types::network::gossip::beacon::BeaconBlockGossip;
use hyperscale_types::network::request::{BlockIntent, GetBlockRequest};
use hyperscale_types::test_utils::{StubVmStatics, TestCommittee, test_pool, test_transaction};
use hyperscale_types::{
    BeaconChainConfig, BeaconGenesisConfig, BeaconState, BlockHeight, CertifiedBeaconBlock,
    GenesisConfigHash, GenesisPool, GenesisValidator, LocalTimestamp, MIN_STAKE_FLOOR,
    NetworkDefinition, Randomness, ShardId, Signer, Stake, TopologySnapshot, Transaction,
    ValidatorId, ValidatorInfo, ValidatorSet, Verifiable, Verified, genesis_config_hash,
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
    topology_snapshot: Arc<TopologySnapshot>,
}

fn fixture() -> Fixture {
    let committee = TestCommittee::new(4, 7);
    let network = NetworkDefinition::simulator();
    let pool_id = test_pool(0);
    let initial_validators: Vec<GenesisValidator> = (0..4)
        .map(|i| GenesisValidator {
            id: committee.validator_id(i),
            pool: pool_id,
            pubkey: *committee.public_key(i),
        })
        .collect();
    // The chain genesises as a single ROOT shard; the two-shard A/B split
    // this test drives is a later runtime state, presented directly through
    // the topology snapshot below rather than baked into genesis.
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
        chain_config: BeaconChainConfig::at_unix_epoch(),
        initial_validators,
        initial_pools: vec![GenesisPool {
            id: pool_id,
            total_stake: Stake::from_quanta(4 * MIN_STAKE_FLOOR.quanta()),
        }],
        initial_beacon_committee: (0..4).map(|i| committee.validator_id(i)).collect(),
        initial_shard_committee: (0..4).map(|i| committee.validator_id(i)).collect(),
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
    let topology_snapshot = Arc::new(TopologySnapshot::with_shard_committees(
        network,
        2,
        &validator_set,
        shard_committees,
    ));
    Fixture {
        committee,
        genesis_block,
        genesis_state,
        config_hash,
        topology_snapshot,
    }
}

type Host = NodeHost<SimShardStorage, SimNetworkAdapter, SyncDispatch>;

impl Fixture {
    /// How every host here builds its replicas and its fold.
    fn replica_config(&self) -> ReplicaConfig {
        ReplicaConfig {
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

    /// `committee[idx]`'s identity and key.
    fn identity(&self, idx: usize) -> (ValidatorId, Arc<dyn Signer>) {
        (self.committee.validator_id(idx), self.committee.signer(idx))
    }

    /// A host over fresh genesis beacon storage running each of `chains`
    /// at genesis with `committee[idx]` attached, and a beacon participant
    /// for each of `participants`.
    fn host(
        &self,
        chains: &[(ShardId, usize)],
        participants: &[usize],
        registry: Arc<HandlerRegistry>,
        topology: Arc<TopologySnapshot>,
        event_tx: &Sender<HostEvent>,
    ) -> Host {
        let beacon_storage: Arc<dyn BeaconStorage> = Arc::new(SimBeaconStorage::new());
        beacon_storage
            .commit_beacon_block(&self.genesis_block, &Arc::new(self.genesis_state.clone()));
        let fresh = RecoveredState::default();
        NodeHost::new(
            &self.replica_config(),
            HostResources {
                beacon_storage,
                executor: Arc::new(Executor::new(ExecutionMode::Serial)),
                network: SimNetworkAdapter::new(registry),
                dispatch: SyncDispatch::new(),
                beacon_event_sender: event_tx.clone(),
                topology_snapshot: Arc::new(ArcSwap::from(topology)),
            },
            chains
                .iter()
                .map(|&(shard, idx)| HostedChain {
                    shard,
                    storage: SimShardStorage::new(shard_prefix_path(shard)),
                    recovered: &fresh,
                    signers: vec![self.identity(idx)],
                    inbox: event_tx.clone().into(),
                })
                .collect(),
            participants.iter().map(|&idx| self.identity(idx)).collect(),
            NodeConfig::default(),
            LocalTimestamp::ZERO,
        )
    }

    /// A host running shard A with `committee[0]` attached, plus a beacon
    /// participant for each of `participants`.
    fn shard_a_host(&self, participants: &[usize]) -> Host {
        let registry = Arc::new(HandlerRegistry::new(std::iter::once(SHARD_A).collect()));
        let (event_tx, _event_rx) = unbounded();
        self.host(
            &[(SHARD_A, 0)],
            participants,
            registry,
            Arc::clone(&self.topology_snapshot),
            &event_tx,
        )
    }

    /// Run shard `shard` on `host` at runtime with `committee[idx]` attached.
    fn add_shard(&self, host: &mut Host, shard: ShardId, idx: usize, event_tx: Sender<HostEvent>) {
        host.add_shard(
            &self.replica_config(),
            HostedChain {
                shard,
                storage: SimShardStorage::new(shard_prefix_path(shard)),
                recovered: &RecoveredState::default(),
                signers: vec![self.identity(idx)],
                inbox: event_tx.into(),
            },
        );
    }
}

fn block_request() -> GetBlockRequest {
    GetBlockRequest::new(BlockHeight::new(1), BlockIntent::Execute)
}

#[test]
fn add_and_remove_shard_at_runtime() {
    let fix = fixture();
    let registry = Arc::new(HandlerRegistry::new(std::iter::once(SHARD_A).collect()));
    let (event_tx, event_rx) = unbounded();
    let mut host = fix.host(
        &[(SHARD_A, 0)],
        &[],
        Arc::clone(&registry),
        Arc::clone(&fix.topology_snapshot),
        &event_tx,
    );
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
    let gossip = TransactionGossip::new(Capped::from_array([Arc::new(test_transaction(1))]));
    let _ = registry.local_dispatch_gossip(&gossip, Some(SHARD_B));
    assert!(
        event_rx.try_recv().is_err(),
        "gossip for an unhosted shard must not route"
    );

    // Add shard B at runtime.
    fix.add_shard(&mut host, SHARD_B, 2, event_tx.clone());
    assert!(host.hosted_shards().any(|s| s == SHARD_B));
    assert_eq!(host.signers(SHARD_B), vec![fix.committee.validator_id(2)]);
    assert!(
        registry
            .local_dispatch_request(SHARD_B, block_request())
            .is_some(),
        "request handlers for the added shard serve"
    );
    let gossip = TransactionGossip::new(Capped::from_array([Arc::new(test_transaction(2))]));
    let _ = registry.local_dispatch_gossip(&gossip, Some(SHARD_B));
    let event = event_rx
        .try_recv()
        .expect("gossip for the added shard routes to its channel");
    assert!(matches!(event, HostEvent::Shard(s, _) if s == SHARD_B));
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
    let gossip = TransactionGossip::new(Capped::from_array([Arc::new(test_transaction(3))]));
    let _ = registry.local_dispatch_gossip(&gossip, Some(SHARD_B));
    assert!(
        event_rx.try_recv().is_err(),
        "gossip for a dropped shard must not route"
    );
    // Events still addressed to the dropped shard are discarded, not a panic.
    let _ = host.step(HostEvent::shard(SHARD_B, ShardScopedInput::FetchTick));

    // Re-join: the shard registers afresh.
    fix.add_shard(&mut host, SHARD_B, 3, event_tx);
    assert!(
        registry
            .local_dispatch_request(SHARD_B, block_request())
            .is_some(),
        "a re-added shard serves again"
    );
}

/// A host that runs no shard and no participant still feeds every beacon
/// block to its beacon loop: the host-level handler runs on every host
/// with no route gate, and the fold follows the chain whoever the host
/// signs for.
#[test]
fn a_shard_less_host_receives_beacon_gossip_with_no_route_gate() {
    let fix = fixture();
    let registry = Arc::new(HandlerRegistry::new(BTreeSet::new()));
    let (event_tx, event_rx) = unbounded::<HostEvent>();
    let mut host = fix.host(
        &[],
        &[],
        Arc::clone(&registry),
        Arc::clone(&fix.topology_snapshot),
        &event_tx,
    );
    while event_rx.try_recv().is_ok() {}
    assert_eq!(host.hosted_shards().count(), 0);
    assert_eq!(host.participants().count(), 0);

    // Global scope, no source shard: with no hosted shard only the
    // host-level handler runs.
    let gossip = BeaconBlockGossip::new(Arc::new(Verifiable::from((*fix.genesis_block).clone())));
    let _ = registry.local_dispatch_gossip(&gossip, None);
    let event = event_rx
        .try_recv()
        .expect("the host-level handler routes the beacon block to the beacon loop");
    assert!(matches!(event, HostEvent::Beacon(_)));

    // The genesis block is at the tip, so the fold ignores it and raises
    // no seat trigger.
    host.set_time(LocalTimestamp::from_millis(1_000));
    let out = host.step(event);
    assert!(out.participation_changes.is_empty());
}

/// On a host that runs a shard, the per-shard beacon handler defers its
/// verdict to the beacon loop's check of the copy the host-level handler
/// hands the loop. A
/// block the fold never checks — one at its tip — is never settled: the
/// loop dispatches nothing for it, so the item stays deferred.
#[test]
fn a_beacon_item_the_loop_never_checks_stays_deferred_on_a_hosted_shard_host() {
    let fix = fixture();
    let registry = Arc::new(HandlerRegistry::new(std::iter::once(SHARD_A).collect()));
    let (event_tx, event_rx) = unbounded::<HostEvent>();
    let mut host = fix.host(
        &[(SHARD_A, 0)],
        &[0],
        Arc::clone(&registry),
        Arc::clone(&fix.topology_snapshot),
        &event_tx,
    );
    while event_rx.try_recv().is_ok() {}

    let gossip = BeaconBlockGossip::new(Arc::new(Verifiable::from((*fix.genesis_block).clone())));
    let verdict = registry.local_dispatch_gossip(&gossip, None);
    assert!(
        matches!(verdict, Some(Verdict::Defer(_))),
        "the per-shard handler defers its verdict: got {verdict:?}",
    );
    let events: Vec<HostEvent> = event_rx.try_iter().collect();
    assert!(
        matches!(events.as_slice(), [HostEvent::Beacon(_)]),
        "the block goes to the beacon loop once, never to a shard's loop",
    );
    for event in events {
        let out = host.step(event);
        assert_eq!(
            out.actions_generated, 0,
            "the fold dispatches no check for its own tip, so nothing settles the verdict",
        );
    }
}

/// `remove_shard` on a shard the host never carried is a no-op.
#[test]
fn remove_unknown_shard_is_none() {
    let fix = fixture();
    let mut host = fix.shard_a_host(&[]);
    assert!(host.remove_shard(SHARD_B).is_none());
    assert!(host.hosted_shards().any(|s| s == SHARD_A));
}

/// A validator drawn onto a shard its host already runs attaches to the
/// running replica in the step that asks, and keeps its beacon
/// participant.
#[test]
fn a_second_signer_attaches_to_the_running_replica() {
    let fix = fixture();
    let mut host = fix.shard_a_host(&[1]);

    let (validator, signer) = fix.identity(1);
    let out = host.attach_signer(SHARD_A, validator, signer);

    assert_eq!(out.attached, vec![validator]);
    assert_eq!(
        host.signers(SHARD_A),
        vec![fix.committee.validator_id(0), validator]
    );
    assert_eq!(
        host.participants().collect::<Vec<_>>(),
        vec![validator],
        "attaching does not touch the participant",
    );
}

/// Attaching a validator the replica already signs for changes nothing.
#[test]
fn attaching_an_attached_signer_changes_nothing() {
    let fix = fixture();
    let mut host = fix.shard_a_host(&[]);

    let (validator, signer) = fix.identity(0);
    let out = host.attach_signer(SHARD_A, validator, signer);

    assert!(out.attached.is_empty());
    assert_eq!(host.signers(SHARD_A), vec![validator]);
}

/// Detaching one of two signers leaves the other attached, and detaching
/// one never attached reports so.
#[test]
fn detaching_one_signer_leaves_the_other_attached() {
    let fix = fixture();
    let mut host = fix.shard_a_host(&[]);
    let (validator, signer) = fix.identity(1);
    let _ = host.attach_signer(SHARD_A, validator, signer);

    assert!(host.detach_signer(SHARD_A, fix.committee.validator_id(0)));

    assert!(host.hosted_shards().any(|s| s == SHARD_A));
    assert_eq!(host.signers(SHARD_A), vec![validator]);
    assert!(!host.detach_signer(SHARD_A, fix.committee.validator_id(2)));
}

/// Detaching the last signer leaves the shard hosted, its replica
/// following the chain with no signer.
#[test]
fn detaching_the_last_signer_keeps_the_shard_hosted() {
    let fix = fixture();
    let mut host = fix.shard_a_host(&[]);

    assert!(host.detach_signer(SHARD_A, fix.committee.validator_id(0)));

    assert!(host.hosted_shards().any(|s| s == SHARD_A));
    assert!(host.signers(SHARD_A).is_empty());
}

/// The split predecessor a mid-handoff host still serves, its two
/// children, and an unrelated live leaf.
const PREDECESSOR: ShardId = ShardId::leaf(1, 0);
const SUCCESSOR: ShardId = ShardId::leaf(2, 0);
const UNRELATED: ShardId = ShardId::leaf(2, 2);

impl Fixture {
    /// A host on a four-leaf trie that still serves `PREDECESSOR`, whose
    /// children are in the trie but not yet live, beside `UNRELATED`.
    fn seating_host(&self, event_tx: &Sender<HostEvent>) -> Host {
        let validator_set = ValidatorSet::new(
            (0..4)
                .map(|i| ValidatorInfo {
                    validator_id: self.committee.validator_id(i),
                    public_key: *self.committee.public_key(i),
                })
                .collect(),
        );
        let committees: BTreeMap<ShardId, Vec<ValidatorId>> = (0..4u64)
            .map(|i| {
                let idx = usize::try_from(i).expect("small index");
                (ShardId::leaf(2, i), vec![self.committee.validator_id(idx)])
            })
            .collect();
        let topology = Arc::new(TopologySnapshot::with_shard_committees(
            NetworkDefinition::simulator(),
            4,
            &validator_set,
            committees,
        ));
        assert!(topology.reshape_handoff_pending(PREDECESSOR));
        let hosted = [PREDECESSOR, UNRELATED];
        let registry = Arc::new(HandlerRegistry::new(hosted.into_iter().collect()));
        self.host(
            &[(PREDECESSOR, 0), (UNRELATED, 2)],
            &[],
            registry,
            topology,
            event_tx,
        )
    }
}

/// Submit a transaction touching only `SUCCESSOR`, returning it once the
/// host has routed it and its channel is drained.
fn submit_to_successor(host: &mut Host, event_rx: &Receiver<HostEvent>) -> Arc<Transaction> {
    let tx = Arc::new(test_transaction(1));
    let _ = host.step(HostEvent::process(ProcessScopedInput::SubmitTransaction {
        tx: Arc::clone(&tx),
    }));
    while event_rx.try_recv().is_ok() {}
    tx
}

/// The shard and input that first carry `tx` out of `event_rx`.
fn routed(event_rx: &Receiver<HostEvent>, tx: &Transaction) -> Option<(ShardId, ShardScopedInput)> {
    event_rx.try_iter().find_map(|event| match event {
        HostEvent::Shard(shard, input) => match &input {
            ShardScopedInput::AdmitAndGossipTransaction { tx: routed, .. }
            | ShardScopedInput::GossipTransaction { tx: routed, .. }
                if routed.hash() == tx.hash() =>
            {
                Some((shard, input))
            }
            _ => None,
        },
        _ => None,
    })
}

#[test]
fn a_submission_parked_on_a_seating_successor_is_admitted_once_it_attaches() {
    let fix = fixture();
    let (event_tx, event_rx) = unbounded();
    let mut host = fix.seating_host(&event_tx);
    while event_rx.try_recv().is_ok() {}

    let tx = submit_to_successor(&mut host, &event_rx);
    fix.add_shard(&mut host, SUCCESSOR, 0, event_tx);

    let (shard, input) = routed(&event_rx, &tx).expect("the attach releases the submission");
    assert_eq!(
        shard, SUCCESSOR,
        "the successor admits what it was held for"
    );
    assert!(matches!(
        input,
        ShardScopedInput::AdmitAndGossipTransaction { .. }
    ));
}

#[test]
fn a_submission_parked_on_a_seating_successor_is_gossiped_once_its_predecessor_detaches() {
    let fix = fixture();
    let (event_tx, event_rx) = unbounded();
    let mut host = fix.seating_host(&event_tx);
    while event_rx.try_recv().is_ok() {}

    let tx = submit_to_successor(&mut host, &event_rx);
    assert!(host.remove_shard(PREDECESSOR).is_some());

    let (shard, input) = routed(&event_rx, &tx).expect("the detach releases the submission");
    assert_eq!(
        shard, UNRELATED,
        "a host seating nothing gossips through what it serves"
    );
    assert!(matches!(input, ShardScopedInput::GossipTransaction { .. }));
}
