//! Beacon timer-chain liveness at the participant seam.
//!
//! Every ratify-eligible validator runs a live beacon timer chain: a
//! beacon participant's `BeaconRatifyTrigger` re-arm survives to the
//! loop's timer seam instead of being discarded, and a participant arms
//! the beacon startup timers (`BeaconCommitteeStart` +
//! `BeaconRatifyTrigger`) the moment the host runs it. Without the chain,
//! a validator adopts beacon blocks by gossip but never proposes, never
//! drives SPC rounds, and never casts ratify votes; enough of them in one
//! ratify pool starves the pool quorum and parks the beacon. A shard
//! replica arms no beacon timer: its signers' chains run on their
//! participants.

use std::collections::BTreeMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use crossbeam::channel::{Receiver, unbounded};
use hyperscale_beacon::genesis::build_genesis_beacon_state;
use hyperscale_core::{ProtocolEvent, TimerId};
use hyperscale_crypto_bls::BlsVerifier;
use hyperscale_dispatch_sync::SyncDispatch;
use hyperscale_engine::{AllCodeRuns, ExecutionMode, Executor};
use hyperscale_mempool::MempoolConfig;
use hyperscale_network::HandlerRegistry;
use hyperscale_network_memory::SimNetworkAdapter;
use hyperscale_node::event::{HostEvent, TimerOp};
use hyperscale_node::{HostResources, HostedChain, NodeConfig, NodeHost, ReplicaConfig};
use hyperscale_provisions::ProvisionConfig;
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BeaconStorage, RecoveredState};
use hyperscale_storage_memory::{SimBeaconStorage, SimShardStorage};
use hyperscale_types::network::gossip::beacon::RatifyVoteGossip;
use hyperscale_types::test_utils::{StubVmStatics, TestCommittee, test_pool};
use hyperscale_types::{
    BeaconBlockHash, BeaconChainConfig, BeaconGenesisConfig, CertifiedBeaconBlock, Epoch,
    GenesisConfigHash, GenesisPool, GenesisValidator, LocalTimestamp, MIN_STAKE_FLOOR,
    NetworkDefinition, Randomness, RatifyPhase, RatifyRound, RatifyVote, ShardId, Signer, Stake,
    TopologySnapshot, ValidatorId, ValidatorInfo, ValidatorSet, Verifiable, Verified,
    genesis_config_hash, shard_prefix_path,
};

const SHARD_A: ShardId = ShardId::leaf(1, 0);

/// Shared genesis: four validators in one pool, all on the initial
/// committees; shard A staffed by validators 0–1.
struct Fixture {
    committee: TestCommittee,
    config_hash: GenesisConfigHash,
    topology_snapshot: Arc<TopologySnapshot>,
    beacon_storage: Arc<dyn BeaconStorage>,
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
    let shard_committees: BTreeMap<ShardId, Vec<ValidatorId>> = std::iter::once((
        SHARD_A,
        vec![committee.validator_id(0), committee.validator_id(1)],
    ))
    .collect();
    let topology_snapshot = Arc::new(TopologySnapshot::with_shard_committees(
        network,
        2,
        &validator_set,
        shard_committees,
    ));
    let beacon_storage: Arc<dyn BeaconStorage> = Arc::new(SimBeaconStorage::new());
    beacon_storage.commit_beacon_block(&genesis_block, &Arc::new(genesis_state));
    Fixture {
        committee,
        config_hash,
        topology_snapshot,
        beacon_storage,
    }
}

impl Fixture {
    /// How the host builds its replicas and its fold.
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

    /// Run `shard` at runtime with `committee[idx]` attached for each of
    /// `idxs`, through the real seating seam — the runtime-join
    /// construction, not the genesis ceremony.
    fn seat(
        &self,
        host: &mut NodeHost<SimShardStorage, SimNetworkAdapter, SyncDispatch>,
        idxs: &[usize],
        shard: ShardId,
    ) {
        let (event_tx, _event_rx) = unbounded::<HostEvent>();
        host.add_shard(
            &self.replica_config(),
            HostedChain {
                shard,
                storage: SimShardStorage::new(shard_prefix_path(shard)),
                recovered: &RecoveredState::default(),
                signers: idxs.iter().map(|&idx| self.identity(idx)).collect(),
                inbox: event_tx.into(),
            },
        );
    }

    /// A host with no hosted shard and one participant. Returns the
    /// network registry and the host's event receiver alongside so tests
    /// can drive inbound gossip and observe routing.
    fn follower_host(
        &self,
        idx: usize,
    ) -> (
        NodeHost<SimShardStorage, SimNetworkAdapter, SyncDispatch>,
        Arc<HandlerRegistry>,
        Receiver<HostEvent>,
    ) {
        let registry = Arc::new(HandlerRegistry::new(std::collections::BTreeSet::new()));
        let network = SimNetworkAdapter::new(Arc::clone(&registry));
        let (event_tx, event_rx) = unbounded::<HostEvent>();
        let host = NodeHost::new(
            &self.replica_config(),
            HostResources {
                beacon_storage: Arc::clone(&self.beacon_storage),
                executor: Arc::new(Executor::new(ExecutionMode::Serial)),
                network,
                dispatch: SyncDispatch::new(),
                beacon_event_sender: event_tx,
                topology_snapshot: Arc::new(ArcSwap::from(Arc::clone(&self.topology_snapshot))),
            },
            Vec::new(),
            vec![self.identity(idx)],
            NodeConfig::default(),
            LocalTimestamp::ZERO,
        );
        (host, registry, event_rx)
    }
}

/// Whether `ops` holds a `Set` for timer `want`.
fn has_set(ops: &[TimerOp], want: &TimerId) -> bool {
    ops.iter()
        .any(|op| matches!(op, TimerOp::Set { id, .. } if id == want))
}

/// A participant's `BeaconRatifyTrigger` re-arm must reach the runner's
/// timer seam. The ratify handler re-arms on every fire (early or due), so
/// the chain stays alive only if the loop honors the `SetTimer` instead of
/// discarding it — a participant is a ratify-pool voter, and the trigger
/// is what starts its skip prevotes when an epoch stalls.
#[test]
fn follower_ratify_rearm_survives_to_the_timer_seam() {
    let fix = fixture();
    let (mut host, _registry, _event_rx) = fix.follower_host(0);
    host.set_time(LocalTimestamp::from_millis(1_000));

    let out = host.step(HostEvent::beacon(ProtocolEvent::BeaconRatifyTimer));

    assert!(
        has_set(&out.timer_ops, &TimerId::BeaconRatifyTrigger),
        "the follower's BeaconRatifyTrigger re-arm must survive to the loop's \
         timer seam, not be dropped: got {:?}",
        out.timer_ops
    );
}

/// A participant must arm the beacon startup timers when the host starts
/// running it: `BeaconRatifyTrigger` because it votes in the ratify pool
/// from the moment it is active, and `BeaconCommitteeStart` because any
/// pool validator can be drawn onto the next epoch's SPC committee.
#[test]
fn follower_seat_arms_the_startup_timers() {
    let fix = fixture();
    let (mut host, _registry, _event_rx) = fix.follower_host(0);

    let out = host.drain_pending_output();

    assert!(
        has_set(&out.timer_ops, &TimerId::BeaconRatifyTrigger),
        "a participant must arm BeaconRatifyTrigger: got {:?}",
        out.timer_ops
    );
    assert!(
        has_set(&out.timer_ops, &TimerId::BeaconCommitteeStart),
        "a participant must arm BeaconCommitteeStart: got {:?}",
        out.timer_ops
    );
}

/// A replica taken up mid-life arms no beacon timer at its resume: its
/// validator's beacon chain runs on its participant, which the seat does
/// not touch, so a second chain for the same identity never starts.
#[test]
fn midlife_seat_arms_no_beacon_timer() {
    let fix = fixture();
    let (mut host, _registry, _host_rx) = fix.follower_host(0);
    let _ = host.drain_pending_output();
    fix.seat(&mut host, &[0], SHARD_A);

    let out = host.resume_shard_committed(SHARD_A, &RecoveredState::default());

    assert!(
        !has_set(&out.timer_ops, &TimerId::BeaconRatifyTrigger)
            && !has_set(&out.timer_ops, &TimerId::BeaconCommitteeStart),
        "a mid-life seat arms no beacon timer: got {:?}",
        out.timer_ops
    );
}

/// A ratify-pool member's skip prevote must actually be signed —
/// persisted to the durable ratify register, then broadcast — not dropped
/// as an unexpected action. The ratify fire lands past the epoch's skip
/// deadline, so the tracker asks for a skip prevote, and the
/// persist-before-sign register write is the observable proof it was
/// signed.
#[test]
fn pooled_ratify_voter_signs_its_skip_prevote() {
    let fix = fixture();
    let (mut host, _registry, _event_rx) = fix.follower_host(0);
    let me = fix.committee.validator_id(0);
    assert!(
        fix.beacon_storage.ratify_record(me).is_none(),
        "no ratify position is spent before the fire"
    );

    // Well past epoch 0's boundary plus the skip timeout, so the fire is
    // due and the tracker prevotes the canonical skip hash.
    let epoch_ms = BeaconChainConfig::default().epoch_duration_ms;
    host.set_time(LocalTimestamp::from_millis(3 * epoch_ms));
    let _ = host.step(HostEvent::beacon(ProtocolEvent::BeaconRatifyTimer));

    assert!(
        fix.beacon_storage.ratify_record(me).is_some(),
        "the voter's skip prevote must reach the durable ratify \
         register (persist-before-sign), not be dropped"
    );
}

/// Ratify votes gossip globally, but the per-shard handler never runs on
/// a host with no hosted shards — the host-level route must carry them to
/// the beacon loop's channel, since a ratify voter precommits only when
/// it observes a prevote quorum.
#[test]
fn ratify_vote_gossip_routes_to_the_beacon_loop() {
    let fix = fixture();
    let (mut host, registry, event_rx) = fix.follower_host(0);
    while event_rx.try_recv().is_ok() {}

    // A peer's signed prevote arrives via global gossip.
    let signer = fix.committee.signer(1);
    let vote = Verified::<RatifyVote>::sign_local(
        signer.as_ref(),
        fix.committee.validator_id(1),
        &NetworkDefinition::simulator(),
        BeaconBlockHash::ZERO,
        Epoch::new(1),
        RatifyRound::new(0),
        RatifyPhase::Prevote,
        BeaconBlockHash::ZERO,
    )
    .expect("test committee key signs");
    let gossip = RatifyVoteGossip::new(Arc::new(Verifiable::from(vote)));
    let _ = registry.local_dispatch_gossip(&gossip, None);

    let event = event_rx
        .try_recv()
        .expect("the host-level route must carry the ratify vote to the beacon loop");
    assert!(
        matches!(event, HostEvent::Beacon(_)),
        "the ratify vote arrives as a beacon-scoped envelope"
    );
    // The beacon loop folds it without treating it as unexpected.
    let _ = host.step(event);
}
