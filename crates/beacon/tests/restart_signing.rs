//! A beacon committee member that crashes after signing a PC vote, a
//! ratify vote or its proposal and restarts in the same instance signs
//! nothing that contradicts it.
//!
//! The process's beacon store is all that survives a crash. A restart
//! rebuilds the coordinator from that store and runs the actions it emits
//! through the same handlers over the same store, with nothing else
//! carried over.

use std::sync::{Arc, Mutex};

use hyperscale_beacon::action_handlers::handle_action;
use hyperscale_beacon::coordinator::{BeaconCoordinator, LocalChainAnchors};
use hyperscale_beacon::genesis::build_genesis_beacon_state;
use hyperscale_core::{Action, BeaconActionContext, ProtocolEvent, SignerGate};
use hyperscale_crypto_bls::BlsVerifier;
use hyperscale_network::{
    Answerers, GossipHandler, Network, NotificationHandler, RequestError, RequestHandler,
    ResponseVerdict,
};
use hyperscale_storage::RatifyRegisterStore;
use hyperscale_storage_memory::SimBeaconStorage;
use hyperscale_types::test_utils::{TestCommittee, test_pool};
use hyperscale_types::{
    BeaconBlock, BeaconBlockHash, BeaconChainConfig, BeaconGenesisConfig, BlockHash, BlockHeight,
    CertifiedBeaconBlock, ConsensusSignature, Epoch, GenesisPool, GenesisValidator, GossipMessage,
    Hash, LocalTimestamp, MIN_STAKE_FLOOR, MessageClass, NetworkDefinition, NetworkMessage,
    PcValueElement, PcVector, Randomness, RatifyPhase, RatifyRound, RatifyVote, Request, Round,
    RoutingCommittees, SKIP_TIMEOUT, ShardId, ShardVoteEquivocation, SpcView, Stake,
    TopologySnapshot, ValidatorId, Verified, genesis_config_hash,
};

/// A network that counts the notifications it is asked to send.
#[derive(Default)]
struct Outbox {
    notified: Mutex<usize>,
}

impl Network for Outbox {
    fn broadcast_to_shard<M: GossipMessage + 'static>(&self, _: ShardId, _: &M) {}
    fn broadcast_global<M: GossipMessage + 'static>(&self, _: &M) {}
    fn register_gossip_handler<M: GossipMessage + 'static>(&self, _: impl GossipHandler<M>) {}
    fn register_host_gossip_handler<M: GossipMessage + 'static>(
        &self,
        _: impl Fn(M) + Send + Sync + 'static,
    ) {
    }
    fn register_request_handler<R: Request + Send + 'static>(
        &self,
        _: ShardId,
        _: impl RequestHandler<R>,
    ) where
        R::Response: Send + 'static,
    {
    }
    fn notify<M: NetworkMessage + 'static>(&self, _: &[ValidatorId], _: &M) {
        *self.notified.lock().expect("outbox lock") += 1;
    }
    fn register_notification_handler<M: NetworkMessage + Clone + 'static>(
        &self,
        _: impl NotificationHandler<M>,
    ) {
    }
    fn subscribe_shard(&self, _: ShardId) {}
    fn unsubscribe_shard(&self, _: ShardId) {}
    fn update_topology(&self, _: Arc<TopologySnapshot>) {}
    fn update_routing_committees(&self, _: Arc<RoutingCommittees>) {}
    fn request_from<R: Request + Clone + 'static>(
        &self,
        _: ShardId,
        _: Answerers,
        _: Option<ValidatorId>,
        _: R,
        _: Option<MessageClass>,
        _: Box<dyn FnOnce(Result<R::Response, RequestError>) -> ResponseVerdict + Send>,
    ) {
    }
}

/// One process lifetime of a committee member: the handlers' context
/// over `storage`, and what they signed and sent.
struct Member {
    committee: TestCommittee,
    topology: TopologySnapshot,
    network: Arc<Outbox>,
    signed: Arc<Mutex<Vec<PcVector>>>,
    events: Arc<Mutex<Vec<ProtocolEvent>>>,
}

impl Member {
    fn start() -> Self {
        let committee = TestCommittee::new(4, 7);
        let topology = committee.topology_snapshot(1);
        Self {
            committee,
            topology,
            network: Arc::new(Outbox::default()),
            signed: Arc::new(Mutex::new(Vec::new())),
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Run `action` through the handlers over `storage`, keeping the
    /// events it feeds back.
    fn run(&self, storage: &SimBeaconStorage, action: Action) {
        let sink = Arc::clone(&self.events);
        let notify: Arc<dyn Fn(ProtocolEvent) + Send + Sync> =
            Arc::new(move |event| sink.lock().expect("events lock").push(event));
        let key = self.committee.signer(0);
        let ctx = BeaconActionContext {
            topology_snapshot: &self.topology,
            me: self.committee.validator_id(0),
            ratify_registers: storage,
            beacon_vote_registers: storage,
            network: &self.network,
            signer: &key,
            verifier: &BlsVerifier,
            notify,
            cache_beacon_proposal: &|_, _, _| {},
            cache_beacon_candidate: &|_| {},
            gate: &SignerGate::new(),
        };
        handle_action(action, &ctx);
    }

    /// The member's coordinator, rebuilt from genesis and the ratify
    /// record `storage` holds for it.
    fn coordinator(&self, storage: &SimBeaconStorage) -> BeaconCoordinator {
        let network = NetworkDefinition::simulator();
        let pool = test_pool(0);
        let size = self.committee.size();
        let config = BeaconGenesisConfig {
            chain_config: BeaconChainConfig::default(),
            initial_validators: (0..size)
                .map(|i| GenesisValidator {
                    id: self.committee.validator_id(i),
                    pool,
                    pubkey: *self.committee.public_key(i),
                })
                .collect(),
            initial_pools: vec![GenesisPool {
                id: pool,
                total_stake: Stake::from_quanta(size as u128 * MIN_STAKE_FLOOR.quanta()),
            }],
            initial_beacon_committee: self.committee.validator_ids().to_vec(),
            initial_shard_committee: self.committee.validator_ids().to_vec(),
            initial_randomness: Randomness::new([0xAB; 32]),
        };
        let config_hash = genesis_config_hash(&config, &network, &[]);
        let me = self.committee.validator_id(0);
        let mut coordinator = BeaconCoordinator::new(
            Arc::new(BlsVerifier),
            Arc::new(Verified::<CertifiedBeaconBlock>::genesis(config_hash)),
            vec![build_genesis_beacon_state(&config)],
            me,
            ShardId::ROOT,
            Some((LocalChainAnchors::GENESIS, BlockHeight::GENESIS)),
            network,
            config_hash,
        );
        if let Some(record) = storage.ratify_record(me) {
            coordinator.install_recovered_ratify_record(&record);
        }
        coordinator
    }

    /// Run the signing actions among `actions` through the handlers over
    /// `storage`.
    fn sign(&self, storage: &SimBeaconStorage, actions: Vec<Action>) {
        for action in actions {
            if matches!(
                action,
                Action::SignAndBroadcastRatifyVote { .. }
                    | Action::BuildAndBroadcastBeaconProposal { .. }
            ) {
                self.run(storage, action);
            }
        }
    }

    /// The ratify votes signed, as `(round, phase, block_hash)`.
    fn ratify_votes(&self) -> Vec<(RatifyRound, RatifyPhase, BeaconBlockHash)> {
        self.events
            .lock()
            .expect("events lock")
            .iter()
            .filter_map(|event| match event {
                ProtocolEvent::VerifiedRatifyVoteReceived { vote } => {
                    Some((vote.round(), vote.phase(), vote.block_hash()))
                }
                _ => None,
            })
            .collect()
    }

    /// How many shard double-vote pairs each signed proposal carries.
    fn proposals(&self) -> Vec<usize> {
        self.events
            .lock()
            .expect("events lock")
            .iter()
            .filter_map(|event| match event {
                ProtocolEvent::BeaconProposalReceived { proposal, .. } => {
                    Some(proposal.as_unverified().vote_equivocations().len())
                }
                _ => None,
            })
            .collect()
    }

    /// A ratify vote for the coordinator's pending epoch, signed by
    /// committee member `signer`.
    fn peer_vote(
        &self,
        coordinator: &BeaconCoordinator,
        signer: usize,
        phase: RatifyPhase,
        block_hash: BeaconBlockHash,
    ) -> Arc<Verified<RatifyVote>> {
        Arc::new(
            Verified::<RatifyVote>::sign_local(
                self.committee.signer(signer).as_ref(),
                self.committee.validator_id(signer),
                &NetworkDefinition::simulator(),
                coordinator.latest_block().block_hash(),
                coordinator.current_epoch().next(),
                RatifyRound::INITIAL,
                phase,
                block_hash,
            )
            .expect("sign"),
        )
    }

    /// Run `SignAndBroadcastPcVote1` for `v_in` at view 1 of epoch 3.
    fn vote1(&self, storage: &SimBeaconStorage, v_in: &PcVector) {
        let sink = Arc::clone(&self.signed);
        let notify: Arc<dyn Fn(ProtocolEvent) + Send + Sync> = Arc::new(move |event| {
            if let ProtocolEvent::VerifiedPcVote1Received { vote, .. } = event {
                sink.lock().expect("signed lock").push(vote.v_in().clone());
            }
        });
        let key = self.committee.signer(0);
        let ctx = BeaconActionContext {
            topology_snapshot: &self.topology,
            me: self.committee.validator_id(0),
            ratify_registers: storage,
            beacon_vote_registers: storage,
            network: &self.network,
            signer: &key,
            verifier: &BlsVerifier,
            notify,
            cache_beacon_proposal: &|_, _, _| {},
            cache_beacon_candidate: &|_| {},
            gate: &SignerGate::new(),
        };
        handle_action(
            Action::SignAndBroadcastPcVote1 {
                epoch: Epoch::new(3),
                view: SpcView::new(1),
                v_in: v_in.clone(),
                recipients: self.committee.validator_ids().to_vec(),
            },
            &ctx,
        );
    }

    fn signed(&self) -> Vec<PcVector> {
        self.signed.lock().expect("signed lock").clone()
    }

    fn notified(&self) -> usize {
        *self.network.notified.lock().expect("outbox lock")
    }
}

fn vector(tag: u8) -> PcVector {
    PcVector::new([PcValueElement::new([tag; 32]), PcValueElement::BOTTOM])
}

#[test]
fn a_restarted_member_does_not_sign_a_conflicting_vote1() {
    let storage = SimBeaconStorage::new();
    let before = Member::start();
    before.vote1(&storage, &vector(1));
    assert_eq!(before.signed(), vec![vector(1)]);
    assert_eq!(before.notified(), 1);

    // The process dies and the machine loses every unsynced write; the
    // restarted member pooled other proposals, so its view-1 input
    // differs.
    drop(before);
    storage.lose_unsynced();
    let after = Member::start();
    after.vote1(&storage, &vector(2));
    after.vote1(&storage, &PcVector::new([PcValueElement::new([1; 32])]));
    assert!(
        after.signed().is_empty(),
        "neither a different vector nor a prefix of the signed one is signed"
    );
    assert_eq!(after.notified(), 0, "nothing reaches the network");

    // The vector it signed before the crash is still its vote: re-signing
    // it is a retransmission, not a second vote.
    after.vote1(&storage, &vector(1));
    assert_eq!(after.signed(), vec![vector(1)]);
    assert_eq!(after.notified(), 1);
}

/// Move `coordinator`'s clock past the pending epoch's skip deadline.
fn pass_skip_deadline(coordinator: &mut BeaconCoordinator) {
    let state = coordinator.current_state();
    let boundary = state
        .chain_config
        .epoch_windows()
        .window_of(state.current_epoch)
        .end
        .as_millis();
    let timeout = u64::try_from(SKIP_TIMEOUT.as_millis()).expect("fits in u64 millis");
    coordinator.set_now(LocalTimestamp::from_millis(boundary + timeout));
}

#[test]
fn a_participant_rebuilt_from_its_records_abstains_at_spent_ratify_slots() {
    let storage = SimBeaconStorage::new();
    let before = Member::start();
    let mut coordinator = before.coordinator(&storage);
    pass_skip_deadline(&mut coordinator);
    let skip = BeaconBlock::skip(
        coordinator.current_epoch().next(),
        coordinator.latest_block().block_hash(),
    )
    .block_hash();
    let actions = coordinator.on_beacon_ratify_timer();
    before.sign(&storage, actions);
    assert_eq!(
        before.ratify_votes(),
        vec![(RatifyRound::INITIAL, RatifyPhase::Prevote, skip)]
    );

    // Rebuilt, it sees the rest of the pool prevote a candidate it never
    // received. A polka leads a member that has not prevoted in the round
    // to prevote the polka's value there; this one already has.
    drop(coordinator);
    drop(before);
    storage.lose_unsynced();
    let after = Member::start();
    let mut coordinator = after.coordinator(&storage);
    let candidate = BeaconBlockHash::from_raw(Hash::from_bytes(b"candidate"));
    for signer in 1..4 {
        let vote = after.peer_vote(&coordinator, signer, RatifyPhase::Prevote, candidate);
        let actions = coordinator.on_verified_ratify_vote_received(vote);
        after.sign(&storage, actions);
    }
    assert_eq!(
        after.ratify_votes(),
        vec![(RatifyRound::INITIAL, RatifyPhase::Precommit, candidate)],
        "the spent prevote slot signs no second value; the free precommit \
         slot follows the polka",
    );
}

/// A shard double-vote pair, unverified: only its presence in a
/// proposal body matters here.
fn vote_equivocation() -> ShardVoteEquivocation {
    ShardVoteEquivocation {
        validator: ValidatorId::new(2),
        shard: ShardId::ROOT,
        height: BlockHeight::new(1),
        round: Round::INITIAL,
        block_hash_a: BlockHash::from_raw(Hash::from_bytes(b"a")),
        parent_block_hash_a: BlockHash::ZERO,
        sig_a: ConsensusSignature::ZERO,
        block_hash_b: BlockHash::from_raw(Hash::from_bytes(b"b")),
        parent_block_hash_b: BlockHash::ZERO,
        sig_b: ConsensusSignature::ZERO,
    }
}

#[test]
fn a_rebuilt_participant_does_not_sign_a_second_proposal_for_its_epoch() {
    let storage = SimBeaconStorage::new();
    let before = Member::start();
    let mut coordinator = before.coordinator(&storage);
    let actions = coordinator.on_beacon_committee_start_timer();
    before.sign(&storage, actions);
    assert_eq!(before.proposals(), vec![0]);

    // Rebuilt, it has observed differently and builds another body.
    drop(coordinator);
    drop(before);
    storage.lose_unsynced();
    let after = Member::start();
    let mut coordinator = after.coordinator(&storage);
    assert!(coordinator.observe_vote_equivocation(vote_equivocation()));
    let actions = coordinator.on_beacon_committee_start_timer();
    assert!(
        actions.iter().any(|action| matches!(
            action,
            Action::BuildAndBroadcastBeaconProposal { vote_equivocations, .. }
                if vote_equivocations.len() == 1
        )),
        "the rebuilt participant builds a different body",
    );
    after.sign(&storage, actions);
    assert!(after.proposals().is_empty(), "a second body is not signed");
    assert_eq!(after.notified(), 0, "nothing reaches the network");

    // Rebuilt again with what it first observed, it builds the body it
    // signed, which is still its proposal.
    let again = Member::start();
    let mut coordinator = again.coordinator(&storage);
    let actions = coordinator.on_beacon_committee_start_timer();
    again.sign(&storage, actions);
    assert_eq!(again.proposals(), vec![0]);
}
