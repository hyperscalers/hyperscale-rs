use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crossbeam::channel::{Receiver, unbounded};
use hyperscale_beacon::coordinator::LocalChainAnchors;
use hyperscale_core::{BeaconFetchIds, TimerId};
use hyperscale_crypto_bls::BlsVerifier;
use hyperscale_dispatch_sync::{DeferredJobs, ProcessingTimes, SyncDispatch};
use hyperscale_hbor::{Bytes, Capped};
use hyperscale_network::ResponseVerdict;
use hyperscale_network_memory::{
    BroadcastTarget, HostLayout, LinkStreams, NetworkConfig, PendingRequest, SimNetworkAdapter,
    SimulatedNetwork,
};
use hyperscale_storage::RecoveredState;
use hyperscale_storage::test_helpers::commit_one;
use hyperscale_storage_memory::{SimShardStorage, crash_point};
use hyperscale_types::network::gossip::beacon::BeaconBlockGossip;
use hyperscale_types::network::notification::beacon::BeaconProposalNotification;
use hyperscale_types::network::request::GetInstanceRecordsRequest;
use hyperscale_types::network::request::beacon::{
    GetBeaconBlockRequest, GetBeaconCandidateRequest, GetBeaconProposalRequest,
};
use hyperscale_types::network::response::GetInstanceRecordsResponse;
use hyperscale_types::network::response::beacon::{
    GetBeaconBlockResponse, GetBeaconCandidateResponse, GetBeaconProposalResponse,
};
use hyperscale_types::test_utils::{certify, make_live_block, test_pool, test_transaction};
use hyperscale_types::{
    Address, AddressClass, AggregateSignature, BeaconBlock, BeaconBlockHash, BeaconCert,
    BeaconChainConfig, BeaconProposal, BeaconProposalDraft, BeaconWitnessLeafCount,
    BeaconWitnessRoot, BlockHash, BlockHeader, BlockHeaderParts, BlockHeight, BlockVote,
    CertifiedBeaconBlock, CertifiedBlock, CertifiedBlockHeader, ConsensusSignature, Hash,
    LeafIndex, ProposerTimestamp, QuorumCertificate, RatifyCert, RatifyPhase, RatifyRound,
    RatifyVote, Round, SignerBitfield, TopologySchedule, Unresolved, ValidatorStatus, VrfProof,
    WeightedTimestamp, shard_prefix_path,
};
use hyperscale_vm_effects::{Hash32, InstanceMeta, PackageHash, ProtocolHasher};

use super::records::InstanceRecordBinding;
use super::*;
use crate::HostedChain;
use crate::event::{BeaconInput, FetchFailureKind, ShardScopedInput, TimerOwner};
use crate::fetch::settle_solicited;
use crate::shard::ThreadShardLoop;
use crate::shard::mempool::DeferredTransaction;
use crate::shard::test_host::{Fixture, Host, SHARD, loop_of};

type Loop = BeaconLoop<SimShardStorage, SimNetworkAdapter, SyncDispatch>;

const PROPOSAL: (Epoch, ValidatorId) = (Epoch::new(1), ValidatorId::new(1));

fn participant(n: u64) -> BeaconOwner {
    BeaconOwner::Participant(Attachment::new(ValidatorId::new(n), n))
}

fn proposals(ids: &[(Epoch, ValidatorId)]) -> FetchIds {
    FetchIds::Beacon(BeaconFetchIds::Proposals(ids.to_vec()))
}

/// `owner` asks for `ids` through the loop, as its participant would.
fn ask(beacon: &mut Loop, owner: BeaconOwner, ids: &[(Epoch, ValidatorId)]) {
    beacon.ask(owner, proposals(ids), ShardId::ROOT, None, None);
}

fn in_flight(beacon: &Loop) -> usize {
    beacon.fetches.beacon_proposal.in_flight_count()
}

fn fetch_ticks(ops: &[TimerOp]) -> Vec<bool> {
    ops.iter()
        .filter_map(|op| match op {
            TimerOp::Set {
                owner: TimerOwner::Beacon,
                id: TimerId::FetchTick,
                ..
            } => Some(true),
            TimerOp::Cancel {
                owner: TimerOwner::Beacon,
                id: TimerId::FetchTick,
            } => Some(false),
            _ => None,
        })
        .collect()
}

fn attachment(host: &Host, idx: usize, fix: &Fixture) -> Attachment {
    host.beacon.participants[&fix.committee.validator_id(idx)].attachment
}

/// A host with no participant still runs its beacon loop: the loop
/// asks for what an owner wants and arms its own fetch tick.
#[test]
fn every_host_runs_a_beacon_loop_with_no_participant() {
    let fix = Fixture::new();
    let mut host = fix.host(BlockHeight::GENESIS);
    assert_eq!(host.participants().count(), 0);
    ask(&mut host.beacon, participant(2), &[PROPOSAL]);
    assert!(host.beacon.fetches_pending());
    host.beacon.update_fetch_tick_timer();
    let out = host.drain_pending_output();
    assert_eq!(fetch_ticks(&out.timer_ops), vec![true]);
    let out = host.step(HostEvent::beacon_fetch_tick());
    assert_eq!(
        fetch_ticks(&out.timer_ops),
        vec![true],
        "the tick fires on the beacon loop and re-arms while the ask is pending",
    );
}

/// One participant's abandon releases nothing another still wants;
/// the last abandon releases the id.
#[test]
fn a_participant_abandoning_a_fetch_keeps_a_siblings_interest() {
    let fix = Fixture::new();
    let mut host = fix.host(BlockHeight::GENESIS);
    let beacon = &mut host.beacon;
    ask(beacon, participant(2), &[PROPOSAL]);
    ask(beacon, participant(3), &[PROPOSAL]);
    beacon.abandon(participant(2), proposals(&[PROPOSAL]));
    assert_eq!(
        beacon.fetches.beacon_proposal.pending_count(),
        1,
        "a sibling still wants the proposal",
    );
    beacon.abandon(participant(3), proposals(&[PROPOSAL]));
    assert_eq!(beacon.fetches.beacon_proposal.pending_count(), 0);
}

/// An id held after two failures since the tick stays held when a
/// second participant asks for it: the hold is the entry's, not the
/// asker's.
#[test]
fn a_second_owner_asking_for_a_held_id_does_not_lift_its_hold() {
    let fix = Fixture::new();
    let mut host = fix.host(BlockHeight::GENESIS);
    let beacon = &mut host.beacon;
    ask(beacon, participant(2), &[PROPOSAL]);
    beacon.release(proposals(&[PROPOSAL]), Release::Failed);
    beacon.release(proposals(&[PROPOSAL]), Release::Failed);
    assert_eq!(in_flight(beacon), 0, "a second failure holds the id");
    ask(beacon, participant(3), &[PROPOSAL]);
    assert_eq!(
        in_flight(beacon),
        0,
        "a second asker does not lift the hold"
    );
    beacon.dispatch_event(BeaconScopedInput::FetchTick);
    assert_eq!(in_flight(beacon), 1, "the tick lifts it");
}

/// A witness run the fold refuses is released as failed rather than
/// retired: it is asked again at once the first time and, refused
/// again, waits for the tick, so a run served the same way each time
/// costs one retry a tick instead of one per refusal.
#[test]
fn a_refused_witness_run_retries_once_and_then_on_the_tick() {
    use hyperscale_types::{ShardWitnessPayload, Stake};

    let fix = Fixture::new();
    let mut host = fix.host(BlockHeight::GENESIS);
    let _ = host.beacon.fold.set_host_on_committee(true);
    let anchor = BlockHash::from_raw(Hash::from_bytes(b"unheld anchor"));
    let run = (
        SHARD,
        BlockHeight::new(5),
        anchor,
        LeafIndex::new(0),
        LeafIndex::new(1),
    );
    let ids = || FetchIds::Beacon(BeaconFetchIds::Witnesses(vec![run]));
    host.beacon.ask(BeaconOwner::Fold, ids(), SHARD, None, None);
    let in_flight = |beacon: &Loop| beacon.fetches.shard_witness.in_flight_count();
    assert_eq!(in_flight(&host.beacon), 1);
    let refused = || BeaconScopedInput::Answered {
        ids: ids(),
        event: Box::new(ProtocolEvent::ShardWitnessesReceived {
            shard_id: SHARD,
            committed_block_hash: anchor,
            lo: LeafIndex::new(0),
            payloads: vec![ShardWitnessPayload::StakeDeposit {
                pool_id: test_pool(0),
                amount: Stake::from_whole_tokens(1),
            }],
            range_proof: Vec::new(),
        }),
    };

    host.beacon.dispatch_event(refused());
    assert_eq!(in_flight(&host.beacon), 1, "the first refusal asks again");
    host.beacon.dispatch_event(refused());
    assert_eq!(in_flight(&host.beacon), 0, "the second waits for the tick");
    assert_eq!(host.beacon.fetches.shard_witness.pending_count(), 1);
    host.beacon.dispatch_event(BeaconScopedInput::FetchTick);
    assert_eq!(in_flight(&host.beacon), 1, "the tick asks again");
}

/// A candidate extending the fixture's genesis whose certificate's
/// aggregate signatures are forged.
fn forged_candidate(fix: &Fixture) -> CandidateBeaconBlock {
    use hyperscale_types::{PcQc2, PcQc3, PcSignerLengths, PcVector, PcXpProof, SpcCert, SpcView};

    let block = BeaconBlock::new(
        Epoch::new(1),
        fix.genesis_block().block_hash(),
        Capped::empty(),
    );
    let qc2 = PcQc2::new(
        PcVector::empty(),
        SignerBitfield::new(4),
        AggregateSignature::new([0x11; 96]),
        PcXpProof::Full,
    );
    let qc3 = PcQc3::new(
        PcVector::empty(),
        qc2,
        None,
        None,
        SignerBitfield::new(4),
        PcSignerLengths::Uniform(0),
        AggregateSignature::new([0x11; 96]),
    );
    CandidateBeaconBlock::new(
        block,
        Box::new(SpcCert::Direct {
            prev_view: SpcView::INITIAL,
            value: PcVector::empty(),
            proof: qc3.into(),
        }),
    )
}

/// A fetched candidate whose certificate does not verify resolves
/// nothing: its id is asked again rather than retired once the
/// loop's check fails.
#[test]
fn a_fetched_candidate_failing_verification_is_asked_again() {
    let fix = Fixture::new();
    let (mut host, events) = fix.host_with_events(BlockHeight::GENESIS);
    let forged = forged_candidate(&fix);
    let ids = || {
        FetchIds::Beacon(BeaconFetchIds::Candidates(vec![(
            Epoch::new(1),
            forged.block_hash(),
        )]))
    };
    host.beacon
        .ask(participant(2), ids(), ShardId::ROOT, None, None);
    let _ = host.step(HostEvent::Beacon(BeaconScopedInput::Answered {
        ids: ids(),
        event: Box::new(ProtocolEvent::BeaconCandidateReceived {
            candidate: Arc::new(Verifiable::from(forged.clone())),
        }),
    }));
    while let Ok(event) = events.try_recv() {
        let _ = host.step(event);
    }
    let fetch = &host.beacon.fetches.beacon_candidate;
    assert_eq!(
        fetch.pending_count(),
        1,
        "the forged answer does not retire the id"
    );
    assert_eq!(fetch.in_flight_count(), 1, "it is asked again at once");
}

/// A peer that answers a candidate fetch with a forged candidate is
/// distrusted once the loop's off-thread check finds it false.
#[test]
fn a_peer_answering_a_forged_candidate_is_distrusted() {
    let fix = Fixture::new();
    let (mut wire, mut host, events) = wired(&fix, SyncDispatch::new());
    let forged = forged_candidate(&fix);
    let served = Arc::new(Verifiable::from(forged.clone()));
    wire.peer
        .register_request_handler(SHARD, move |_: GetBeaconCandidateRequest| {
            GetBeaconCandidateResponse::new(Some(Arc::clone(&served)))
        });

    host.beacon.ask(
        participant(2),
        FetchIds::Beacon(BeaconFetchIds::Candidates(vec![(
            Epoch::new(1),
            forged.block_hash(),
        )])),
        SHARD,
        None,
        None,
    );
    wire.pump(&mut host, &events);
    assert!(
        wire.network.distrust(0, 1, wire.now) > 0.5,
        "the peer that served a forged candidate is distrusted"
    );
}

/// A record fetch action from a participant asks nothing and holds
/// no interest: records are wanted by chain loops alone.
#[test]
fn a_participants_record_fetch_is_dropped() {
    let fix = Fixture::new();
    let mut host = fix.host(BlockHeight::GENESIS);
    let _ = host.network().drain_pending_requests();
    let instance = Address::new([3; 31], AddressClass::Component);
    let unhandled = host.beacon.process_shared_action(
        participant(2),
        Action::Fetch(FetchRequest::Ask {
            ids: FetchIds::Beacon(BeaconFetchIds::InstanceRecords(vec![instance])),
            shard: SHARD,
            preferred: None,
            class: None,
        }),
    );
    assert!(unhandled.is_none());
    assert!(host.beacon.interest.records.is_empty());
    assert_eq!(host.beacon.fetches.instance_record.pending_count(), 0);
    assert!(host.network().drain_pending_requests().is_empty());
}

/// The loop's own tick retries a held proposal fetch whether or not a
/// block sync runs.
#[test]
fn a_held_proposal_fetch_retries_on_the_loops_tick_with_no_block_sync() {
    let fix = Fixture::new();
    let mut host = fix.host(BlockHeight::GENESIS);
    ask(&mut host.beacon, participant(2), &[PROPOSAL]);
    host.beacon.release(proposals(&[PROPOSAL]), Release::Failed);
    host.beacon.release(proposals(&[PROPOSAL]), Release::Failed);
    assert_eq!(in_flight(&host.beacon), 0);
    assert!(!has_pending(&host.beacon.beacon_block));
    let _ = host.step(HostEvent::beacon_fetch_tick());
    assert_eq!(in_flight(&host.beacon), 1);
}

/// The loop's tick is armed while a fetch or the catch-up sync has
/// work, and cancelled once neither has.
#[test]
fn the_beacon_loops_tick_is_armed_only_while_a_fetch_or_sync_is_pending() {
    let fix = Fixture::new();
    let mut host = fix.host(BlockHeight::GENESIS);
    let _ = host.drain_pending_output();

    ask(&mut host.beacon, participant(2), &[PROPOSAL]);
    host.beacon.update_fetch_tick_timer();
    assert_eq!(
        fetch_ticks(&host.drain_pending_output().timer_ops),
        vec![true],
        "a pending fetch arms the tick",
    );
    host.beacon
        .release(proposals(&[PROPOSAL]), Release::Admitted);
    host.beacon.update_fetch_tick_timer();
    assert_eq!(
        fetch_ticks(&host.drain_pending_output().timer_ops),
        vec![false],
        "an answered fetch leaves nothing pending",
    );

    host.beacon.start_sync(Epoch::new(5));
    host.beacon.update_fetch_tick_timer();
    assert_eq!(
        fetch_ticks(&host.drain_pending_output().timer_ops),
        vec![true],
        "a running sync keeps the tick armed",
    );
    let out = host.step(HostEvent::Beacon(BeaconScopedInput::Protocol(Box::new(
        ProtocolEvent::BeaconRatifyTimer,
    ))));
    assert!(
        fetch_ticks(&out.timer_ops).is_empty(),
        "a step while the armed tick is not yet due leaves it be",
    );
}

/// A live leaf with no committee answers nothing, so no spread lands
/// on one.
#[test]
fn the_fetch_shard_picks_a_live_leaf_with_a_committee() {
    let fix = Fixture::new();
    let host = fix.host(BlockHeight::GENESIS);
    let topology = host.process.topology_snapshot.load();
    assert!(
        topology.shard_trie().leaves().count() > 1,
        "the fixture's trie carries a leaf with no committee",
    );
    for spread in 0..4 {
        assert_eq!(host.beacon.fetch_shard(spread), Some(SHARD),);
    }
}

/// Two hosts over a simulated network: this one, running `SHARD` with
/// `committee[0]` seated, and a peer serving `SHARD` for `committee[1]`.
struct Wire {
    network: SimulatedNetwork,
    streams: LinkStreams,
    peer: SimNetworkAdapter,
    now: Duration,
}

fn wired(fix: &Fixture, dispatch: SyncDispatch) -> (Wire, Host, Receiver<HostEvent>) {
    let validator_to_host = HashMap::from([
        (fix.committee.validator_id(0), 0),
        (fix.committee.validator_id(1), 1),
        (fix.committee.validator_id(2), 0),
        (fix.committee.validator_id(3), 0),
    ]);
    let network = SimulatedNetwork::new(
        NetworkConfig::default(),
        HostLayout {
            hosted: vec![BTreeSet::from([SHARD]); 2],
            validator_to_host,
        },
        7,
    );
    let (host, events) = fix.host_through_network(network.create_adapter(0), dispatch);
    let peer = network.create_adapter(1);
    let wire = Wire {
        network,
        streams: LinkStreams::new(7),
        peer,
        now: Duration::ZERO,
    };
    (wire, host, events)
}

impl Wire {
    /// Carry `host`'s requests to their answers and step everything
    /// they and the host's own continuations push, until quiet.
    fn pump(&mut self, host: &mut Host, events: &Receiver<HostEvent>) {
        loop {
            let requests = host.network().drain_pending_requests();
            let asked = !requests.is_empty();
            self.network
                .accept_requests(0, self.now, requests, &mut self.streams);
            self.now += Duration::from_secs(1);
            self.network.flush_requests(self.now, &mut self.streams);
            let mut stepped = false;
            while let Ok(event) = events.try_recv() {
                let _ = host.step(event);
                stepped = true;
            }
            if !asked && !stepped {
                return;
            }
        }
    }
}

fn add(host: &mut Host, fix: &Fixture, idx: usize) {
    let (validator, signer) = fix.identity(idx);
    host.add_participant(validator, signer);
    let _ = host.drain_pending_output();
}

/// A validator added to a running host's beacon loop starts its
/// participation there: the loop runs it and its startup timers arm.
#[test]
fn a_validator_added_at_runtime_runs_a_participant() {
    let fix = Fixture::new();
    let mut host = fix.host(BlockHeight::GENESIS);
    let (validator, signer) = fix.identity(2);
    assert!(host.beacon.participant(validator).is_none());
    let out = host.step(HostEvent::Beacon(BeaconScopedInput::AddParticipant {
        validator,
        signer,
    }));
    assert!(host.beacon.participant(validator).is_some());
    assert!(
        out.timer_ops.iter().any(|op| matches!(
            op,
            TimerOp::Set {
                owner: TimerOwner::Participant(attachment),
                ..
            } if attachment.validator == validator
        )),
        "its startup timers arm: {:?}",
        out.timer_ops
    );
}

/// A participant on the SPC committee asks for the proposals its
/// dwell finds missing, and the beacon loop's fetch brings one back
/// from a peer into its pool.
#[test]
fn a_participant_on_the_spc_committee_recovers_a_lost_proposal_through_the_host_fetch() {
    let fix = Fixture::new();
    let (mut wire, mut host, events) = wired(&fix, SyncDispatch::new());
    let author = fix.committee.validator_id(1);
    add(&mut host, &fix, 2);

    let network = NetworkDefinition::simulator();
    let signer = fix.committee.signer(1);
    let lost = Arc::new(Verifiable::from(
        BeaconProposalDraft::new(
            signer.as_ref(),
            &network,
            Epoch::new(1),
            BTreeMap::new(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
        )
        .and_then(BeaconProposalDraft::sign)
        .expect("the author's key signs its proposal"),
    ));
    wire.peer
        .register_request_handler(SHARD, move |request: GetBeaconProposalRequest| {
            GetBeaconProposalResponse::new((request.validator == author).then(|| Arc::clone(&lost)))
        });

    let participant = attachment(&host, 2, &fix);
    let timer = |event| {
        HostEvent::Beacon(BeaconScopedInput::ParticipantTimer {
            participant,
            event: Box::new(event),
        })
    };
    let _ = host.step(timer(ProtocolEvent::BeaconCommitteeStartTimer));
    wire.pump(&mut host, &events);
    let pool = |host: &Host| {
        host.beacon
            .participant(fix.committee.validator_id(2))
            .expect("the participant runs")
            .proposal_pool()
            .get(author)
            .is_some()
    };
    assert!(
        !pool(&host),
        "the author's proposal never arrived by gossip"
    );

    let _ = host.step(timer(ProtocolEvent::BeaconSpcInputDwellTimer));
    wire.pump(&mut host, &events);
    assert!(
        pool(&host),
        "the dwell's fetch brings the lost proposal into the participant's pool",
    );
}

/// A peer's proposal reaches the beacon loop only once the wire
/// handler has checked its VRF reveal, and carries that check: one
/// whose reveal fails is dropped there, never forwarded.
#[test]
fn a_wire_proposal_reaches_the_loop_only_once_checked() {
    let fix = Fixture::new();
    let (mut wire, _host, events) = wired(&fix, SyncDispatch::new());
    let author = fix.committee.validator_id(1);
    let network = NetworkDefinition::simulator();
    let signer = fix.committee.signer(1);
    let honest = BeaconProposalDraft::new(
        signer.as_ref(),
        &network,
        Epoch::new(1),
        BTreeMap::new(),
        Vec::new(),
        BTreeMap::new(),
        Vec::new(),
    )
    .and_then(BeaconProposalDraft::sign)
    .expect("the author's key signs its proposal")
    .into_inner();
    let forged = BeaconProposal::new(
        BTreeMap::new(),
        Vec::new(),
        BTreeMap::new(),
        Vec::new(),
        VrfProof::ZERO,
    );
    for proposal in [forged, honest] {
        wire.peer.notify(
            &[fix.committee.validator_id(0)],
            &BeaconProposalNotification::new(
                author,
                Epoch::new(1),
                Arc::new(Verifiable::from(proposal)),
            ),
        );
    }
    let pending = wire.peer.drain_pending_notifications();
    wire.network
        .accept_notifications(1, wire.now, pending, &mut wire.streams);
    wire.network
        .flush_notifications(wire.now + Duration::from_secs(10));

    let received = events
        .try_iter()
        .filter(|event| {
            matches!(
                event,
                HostEvent::Beacon(BeaconScopedInput::Protocol(event))
                    if matches!(**event, ProtocolEvent::BeaconProposalReceived { .. })
            )
        })
        .count();
    assert_eq!(received, 1, "only the honest proposal reaches the loop");
}

/// A peer's beacon gossip reaches a seated host's beacon loop once,
/// through the host-level handler; the per-shard handler only holds
/// the item's verdict.
#[test]
fn beacon_gossip_reaches_a_seated_hosts_loop_once() {
    let fix = Fixture::new();
    let (mut wire, _host, events) = wired(&fix, SyncDispatch::new());
    wire.peer
        .broadcast_global(&BeaconBlockGossip::new(Arc::new(Verifiable::from(
            (*fix.genesis_block()).clone(),
        ))));
    for entry in wire.peer.drain_outbox() {
        wire.network
            .accept_gossip(1, wire.now, entry, &mut wire.streams);
    }
    wire.network
        .flush_gossip(wire.now + Duration::from_secs(10));

    let received = events
        .try_iter()
        .filter(|event| {
            matches!(
                event,
                HostEvent::Beacon(BeaconScopedInput::Protocol(event))
                    if matches!(**event, ProtocolEvent::BeaconBlockReceived { .. })
            )
        })
        .count();
    assert_eq!(received, 1);
}

/// Two co-hosted participants handed the same peer ratify vote check
/// it once between them, and both take the outcome.
#[test]
fn co_hosted_participants_check_a_peer_vote_once() {
    let fix = Fixture::new();
    let (_wire, mut host, events) = wired(&fix, SyncDispatch::new());
    add(&mut host, &fix, 2);
    add(&mut host, &fix, 3);
    while events.try_recv().is_ok() {}
    let fold = host.beacon.fold();
    let vote = Arc::new(Verifiable::from(RatifyVote::new(
        fold.latest_block().block_hash(),
        fold.state().current_epoch.next(),
        RatifyRound::INITIAL,
        RatifyPhase::Prevote,
        BeaconBlockHash::ZERO,
        fix.committee.validator_id(1),
        ConsensusSignature::new([0; 96]),
    )));
    let _ = host.step(HostEvent::beacon(
        ProtocolEvent::UnverifiedRatifyVoteReceived { vote },
    ));
    let outcomes: Vec<HostEvent> = events
        .try_iter()
        .filter(|event| {
            matches!(
                event,
                HostEvent::Beacon(BeaconScopedInput::Continuation { event, .. })
                    if matches!(**event, ProtocolEvent::RatifyVoteVerified { .. })
            )
        })
        .collect();
    assert_eq!(outcomes.len(), 1, "one check runs for both participants");
    for outcome in outcomes {
        let _ = host.step(outcome);
    }
    assert!(
        host.beacon.shared_checks.is_empty(),
        "the outcome reaches every participant waiting on it",
    );
}

/// The catch-up sync asks the committee's other members even where
/// this host serves the shard and holds an answer of its own.
#[test]
fn the_beacon_loops_block_sync_asks_past_the_host() {
    let fix = Fixture::new();
    let (mut wire, mut host, events) = wired(&fix, SyncDispatch::new());
    let counter = |count: &Arc<AtomicUsize>, block: Arc<Verified<CertifiedBeaconBlock>>| {
        let count = Arc::clone(count);
        move |_: GetBeaconBlockRequest| {
            count.fetch_add(1, Ordering::SeqCst);
            GetBeaconBlockResponse::found(Arc::new(Verifiable::from((*block).clone())))
        }
    };
    let here = Arc::new(AtomicUsize::new(0));
    let there = Arc::new(AtomicUsize::new(0));
    // Swap the host's own block handler for one that counts what it is
    // asked: dropping the shard drops its handlers, and serving it again
    // takes a fresh one.
    host.network().unsubscribe_shard(SHARD);
    host.network().subscribe_shard(SHARD);
    host.network()
        .register_request_handler(SHARD, counter(&here, fix.genesis_block()));
    wire.peer
        .register_request_handler(SHARD, counter(&there, fix.genesis_block()));

    host.beacon.start_sync(Epoch::new(1));
    wire.pump(&mut host, &events);
    assert_eq!(
        here.load(Ordering::SeqCst),
        0,
        "the host's own store is not asked"
    );
    assert_eq!(there.load(Ordering::SeqCst), 1);
}

/// A sync answer carrying a block for another epoch is no answer:
/// the epoch backs off for another ask instead of parking as if its
/// bytes had landed.
#[test]
fn a_beacon_sync_answer_for_another_epoch_is_refused() {
    let fix = Fixture::new();
    let (mut wire, mut host, events) = wired(&fix, SyncDispatch::new());
    let genesis = fix.genesis_block();
    wire.peer
        .register_request_handler(SHARD, move |_: GetBeaconBlockRequest| {
            GetBeaconBlockResponse::found(Arc::new(Verifiable::from((*genesis).clone())))
        });
    host.beacon.start_sync(Epoch::new(1));
    wire.pump(&mut host, &events);
    assert!(
        host.beacon.beacon_block.has_deferred(),
        "the epoch waits on the backoff, not on an admission"
    );
}

/// A catch-up ask that fails goes to another leaf's committee next,
/// rather than back to the one that just failed it.
#[test]
fn a_failed_beacon_sync_ask_moves_to_another_leaf() {
    let fix = Fixture::new();
    let id = |idx| fix.committee.validator_id(idx);
    let mut host = fix.host(BlockHeight::GENESIS);
    let topology = fix.topology(BTreeMap::from([
        (ShardId::ROOT.children().0, vec![id(0), id(1)]),
        (ShardId::ROOT.children().1, vec![id(2), id(3)]),
    ]));
    host.process.topology_snapshot.store(Arc::new(topology));
    let _ = host.network().drain_pending_requests();
    let asked = |host: &mut Host| {
        let requests = host.network().drain_pending_requests();
        assert_eq!(requests.len(), 1);
        requests[0].shard
    };
    host.beacon.start_sync(Epoch::new(1));
    let first = asked(&mut host);
    host.beacon
        .on_sync_fetch_failed(Epoch::new(1), FetchFailureKind::Exhausted);
    assert_ne!(asked(&mut host), first, "the retry asks the other leaf");
}

/// Past epoch 0's boundary plus the skip timeout, so a ratify timer
/// makes the tracker prevote the skip hash.
fn past_the_skip_timeout() -> LocalTimestamp {
    LocalTimestamp::from_millis(3 * BeaconChainConfig::default().epoch_duration_ms)
}

/// A ratify timer handed back to `participant` as the outcome of its
/// own dispatched work.
fn ratify_timer(participant: Attachment) -> HostEvent {
    HostEvent::Beacon(BeaconScopedInput::Continuation {
        owner: BeaconOwner::Participant(participant),
        event: Box::new(ProtocolEvent::BeaconRatifyTimer),
    })
}

/// A signature a participant's dispatch queued before the participant
/// left the host never leaves it: removal closes its release gate.
#[test]
fn a_removed_participants_queued_signature_never_leaves() {
    let fix = Fixture::new();
    let jobs = Arc::new(DeferredJobs::new(ProcessingTimes::disk(7), 7));
    let (_wire, mut host, _events) = wired(&fix, SyncDispatch::deferred(Arc::clone(&jobs)));
    let validator = fix.committee.validator_id(2);
    add(&mut host, &fix, 2);

    host.set_time(past_the_skip_timeout());
    let _ = host.step(ratify_timer(attachment(&host, 2, &fix)));
    let queued = jobs.take();
    assert!(!queued.is_empty(), "the skip prevote is queued on the pool");

    assert!(host.remove_participant(validator));
    for (_, job) in queued {
        job();
    }
    assert!(
        host.beacon_storage().ratify_record(validator).is_none(),
        "no ratify slot is spent, so no prevote was signed",
    );
}

/// An identity removed and added again is a new attachment: what the
/// old one left in flight is dropped on arrival, and only the new
/// one's own outcomes reach it.
#[test]
fn a_reattached_identity_never_sees_its_predecessors_continuation() {
    let fix = Fixture::new();
    let jobs = Arc::new(DeferredJobs::new(ProcessingTimes::disk(7), 7));
    let (_wire, mut host, _events) = wired(&fix, SyncDispatch::deferred(Arc::clone(&jobs)));
    let validator = fix.committee.validator_id(2);
    add(&mut host, &fix, 2);
    let predecessor = attachment(&host, 2, &fix);
    assert!(host.remove_participant(validator));
    add(&mut host, &fix, 2);
    let successor = attachment(&host, 2, &fix);
    assert_eq!(successor.validator, predecessor.validator);
    assert_ne!(successor, predecessor);

    host.set_time(past_the_skip_timeout());
    let _ = host.step(ratify_timer(predecessor));
    assert!(
        jobs.take().is_empty(),
        "the predecessor's continuation reaches nobody",
    );
    let _ = host.step(ratify_timer(successor));
    assert!(
        !jobs.take().is_empty(),
        "the successor's own continuation drives it",
    );
}

/// Dropping the loop, however it goes away, closes every
/// participant's release gate.
#[test]
fn dropping_the_beacon_loop_closes_its_participants_gates() {
    let fix = Fixture::new();
    let mut host = fix.host(BlockHeight::GENESIS);
    add(&mut host, &fix, 2);
    let gate = Arc::clone(&host.beacon.participants[&fix.committee.validator_id(2)].gate);
    assert!(gate.enter().is_some(), "a live participant's gate is open");
    drop(host);
    assert!(gate.enter().is_none(), "the dropped loop closed it");
}

/// A proposal ask goes to the committee of the author it prefers, as
/// the fold places it; an author on no live shard with a committee
/// falls back to the live-leaf rule.
#[test]
fn a_proposal_ask_goes_to_its_authors_shard() {
    let fix = Fixture::new();
    let id = |idx| fix.committee.validator_id(idx);
    let (left, right) = ShardId::ROOT.children();
    let topology = Arc::new(fix.topology(BTreeMap::from([
        (left, vec![id(0), id(1)]),
        (right, vec![id(2), id(3)]),
    ])));
    let spread_of = |host: &Host| {
        host.process.topology_snapshot.store(Arc::clone(&topology));
        host.beacon
            .fetch_shard(id(2).inner())
            .expect("both leaves carry a committee")
    };
    let spread = spread_of(&fix.host(BlockHeight::GENESIS));
    let away = if spread == left { right } else { left };

    // The fold places `id(1)` on `away`; genesis leaves `id(3)` on the
    // root, which is no live leaf.
    let mut state = fix.genesis_state().clone();
    state
        .validators
        .get_mut(&id(1))
        .expect("a genesis validator")
        .status = ValidatorStatus::OnShard {
        shard: away,
        ready: true,
        placed_at_epoch: Epoch::GENESIS,
    };
    let mut host = fix.host_over_state(state);
    assert_eq!(spread_of(&host), spread);
    add(&mut host, &fix, 2);
    let _ = host.network().drain_pending_requests();

    let owner = BeaconOwner::Participant(attachment(&host, 2, &fix));
    let mut routed = |author: ValidatorId| {
        let unhandled = host.beacon.process_shared_action(
            owner,
            Action::Fetch(FetchRequest::Ask {
                ids: proposals(&[(Epoch::new(1), author)]),
                shard: ShardId::ROOT,
                preferred: Some(author),
                class: None,
            }),
        );
        assert!(unhandled.is_none());
        let requests = host.network().drain_pending_requests();
        assert_eq!(requests.len(), 1);
        requests[0].shard
    };
    assert_eq!(routed(id(1)), away, "the author's committee is asked");
    assert_eq!(
        routed(id(3)),
        spread,
        "an author on no live shard falls back to the live-leaf rule",
    );
}

/// The certified header of an empty `shard` block at `height`, its
/// parent's certificate dated `anchor_ms`.
fn header_at(shard: ShardId, height: u64, anchor_ms: u64) -> Arc<Verified<CertifiedBlockHeader>> {
    let block = make_live_block(
        shard,
        BlockHeight::new(height),
        anchor_ms,
        ValidatorId::new(0),
        vec![],
        vec![],
    );
    let certified = Verified::<CertifiedBlock>::new_unchecked_for_test(certify(block, anchor_ms));
    Arc::new(certified.certified_header())
}

fn report(host: &mut Host, chain: ChainRegistration, input: BeaconInput) {
    let _ = host.step(HostEvent::Beacon(BeaconScopedInput::Shard { chain, input }));
}

/// A commit reported twice shifts the chain's anchors once: the fold
/// shifts them once per committed height, so the committee anchor
/// stays one hop behind the tip.
#[test]
fn a_commit_reported_twice_keeps_the_fold_anchors_one_hop_apart() {
    let fix = Fixture::new();
    let mut host = fix.host(BlockHeight::GENESIS);
    let chain = loop_of(&mut host).chain;
    let anchors = |host: &Host| host.beacon.fold().chain(chain).expect("registered").anchors;
    let before = anchors(&host).block;
    for (height, anchor_ms) in [(1, 10_000), (2, 20_000)] {
        let header = header_at(SHARD, height, anchor_ms);
        for _ in 0..2 {
            report(
                &mut host,
                chain,
                BeaconInput::LocalCommit {
                    header: Arc::clone(&header),
                },
            );
        }
    }
    let after = anchors(&host);
    assert_eq!(after.block, WeightedTimestamp::from_millis(20_000));
    assert_eq!(
        after.committee,
        WeightedTimestamp::from_millis(10_000),
        "the committee anchor trails the tip by exactly one commit",
    );
    assert_ne!(before, after.committee);
}

/// A certified header reported twice is held once, as the copy first
/// held.
#[test]
fn a_certified_header_reported_twice_is_recorded_once() {
    let fix = Fixture::new();
    let mut host = fix.host(BlockHeight::GENESIS);
    let chain = loop_of(&mut host).chain;
    let first = header_at(SHARD, 1, 10_000);
    let second = Arc::new((*first).clone());
    for header in [Arc::clone(&first), second] {
        report(&mut host, chain, BeaconInput::CertifiedHeader { header });
    }
    let held = host
        .beacon
        .fold()
        .shard_source()
        .header(SHARD, BlockHeight::new(1))
        .expect("the certified header is recorded");
    assert!(
        Arc::ptr_eq(held, &first),
        "a header reported twice keeps the copy first held",
    );
}

/// Two participants on one host: each signs its own beacon duty, under
/// its own key and into its own durable record.
#[test]
fn two_identities_on_one_host_each_sign_their_own_spc_view() {
    let fix = Fixture::new();
    let (mut wire, mut host, events) = wired(&fix, SyncDispatch::new());
    add(&mut host, &fix, 2);
    add(&mut host, &fix, 3);
    for idx in [2, 3] {
        let participant = attachment(&host, idx, &fix);
        let _ = host.step(HostEvent::Beacon(BeaconScopedInput::ParticipantTimer {
            participant,
            event: Box::new(ProtocolEvent::BeaconCommitteeStartTimer),
        }));
    }
    wire.pump(&mut host, &events);
    for idx in [2, 3] {
        let validator = fix.committee.validator_id(idx);
        assert!(
            host.beacon_storage()
                .beacon_vote_record(validator)
                .is_some(),
            "validator {idx} signed its own SPC duty",
        );
        assert!(
            host.beacon
                .participant(validator)
                .expect("the participant runs")
                .proposal_pool()
                .get(validator)
                .is_some(),
            "validator {idx} pooled its own proposal",
        );
    }
}

/// Commit a skip block for every epoch in `1..=tip` over the genesis
/// state, each state's live boundary at its own epoch, so the fold a
/// host resumes over them retains only the windows at its tip.
fn advanced_history(
    fix: &Fixture,
    tip: u64,
) -> Vec<(Arc<Verified<CertifiedBeaconBlock>>, BeaconState)> {
    let mut history = vec![(fix.genesis_block(), fix.genesis_state().clone())];
    for epoch in 1..=tip {
        let (parent, state) = history.last().expect("genesis is first").clone();
        let mut state = state;
        state.current_epoch = Epoch::new(epoch);
        for boundary in state.boundaries.values_mut() {
            boundary.last_live_epoch = Epoch::new(epoch);
        }
        history.push((skip_block(&parent, Epoch::new(epoch)), state));
    }
    history
}

/// A ratified skip for `epoch` over `parent`.
fn skip_block(
    parent: &Verified<CertifiedBeaconBlock>,
    epoch: Epoch,
) -> Arc<Verified<CertifiedBeaconBlock>> {
    let tip = parent.block_hash();
    let block = BeaconBlock::skip(epoch, tip);
    let cert = RatifyCert::new(
        tip,
        epoch,
        RatifyRound::INITIAL,
        block.block_hash(),
        SignerBitfield::new(4),
        AggregateSignature::new([0; 96]),
    );
    Arc::new(Verified::new_unchecked_for_test(
        CertifiedBeaconBlock::new_unchecked(block, BeaconCert::Skip(cert)),
    ))
}

/// A chain anchored below the oldest window the fold retains widens
/// the schedule at registration, so the reply resolves the committee
/// its tip anchors on.
#[test]
fn a_shard_registered_below_the_fold_floor_resolves_its_tip_committee() {
    let fix = Fixture::new();
    let (mut host, _events) = fix.host_over_history(advanced_history(&fix, 8), far_future());
    let anchor = in_epoch(&fix, 2);
    assert!(
        host.beacon.fold().schedule().at(anchor).is_none(),
        "the fold resumed past the anchor's window",
    );
    let (sender, _receiver) = unbounded();
    let registration = host.beacon.register(
        SHARD,
        LocalChainAnchors {
            committee: anchor,
            block: anchor,
        },
        BlockHeight::new(5),
        sender,
    );
    assert!(
        registration.schedule.at(anchor).is_some(),
        "the registration widened the schedule back to the anchor",
    );
}

/// A shard a host joins at runtime builds its replica from the
/// registration's reply: the widened schedule, not the process's.
#[test]
fn a_runtime_join_builds_its_replica_from_the_registration_reply() {
    let fix = Fixture::new();
    let (mut host, events) = fix.host_over_history(advanced_history(&fix, 8), far_future());
    let anchor = in_epoch(&fix, 2);
    let recovered = RecoveredState {
        committed_height: BlockHeight::new(5),
        committed_block_anchor_wt: Some(anchor),
        committed_committee_anchor_wt: Some(anchor),
        ..RecoveredState::default()
    };
    let (sender, _receiver) = unbounded();
    host.add_shard(
        &fix.replica_config(),
        HostedChain {
            shard: SHARD,
            storage: SimShardStorage::new(shard_prefix_path(SHARD)),
            recovered: &recovered,
            signers: vec![fix.identity(0)],
            inbox: sender.into(),
        },
    );
    drop(events);
    let replica = host.replica(SHARD);
    assert!(
        replica.schedule().at(anchor).is_some(),
        "the replica resolves its tip's committee from its first schedule",
    );
    assert_eq!(replica.schedule_epoch(), Epoch::new(8));
}

/// A host restarted from its stores holds the schedule the next
/// beacon block folds once the beacon loop hands it over, and not
/// before.
#[test]
fn a_restarted_host_installs_the_next_beacon_blocks_schedule() {
    let fix = Fixture::new();
    let history = advanced_history(&fix, 2);
    let tip = Arc::clone(&history.last().expect("a tip").0);
    let storage = SimShardStorage::new(shard_prefix_path(SHARD));
    commit_one(&storage, 1);
    let (mut host, events) = fix.host_resumed(history, storage, far_future());
    let replica_epoch = |host: &Host| host.replica(SHARD).schedule_epoch();
    assert_eq!(replica_epoch(&host), Epoch::new(2));

    let _ = host.step(fold_outcome(ProtocolEvent::BeaconBlockVerified {
        result: Ok(skip_block(&tip, Epoch::new(3))),
    }));
    assert_eq!(host.beacon.fold().state().current_epoch, Epoch::new(3));
    assert_eq!(
        replica_epoch(&host),
        Epoch::new(2),
        "the schedule reaches the replica as an event of its own",
    );
    for event in events.try_iter() {
        let _ = host.step(event);
    }
    assert_eq!(replica_epoch(&host), Epoch::new(3));
}

/// A block that reaches the loop again — a second verified copy off
/// gossip, then a sync delivery of it — is written to beacon storage
/// once, by the fold's one adoption.
#[test]
fn the_fold_commits_each_beacon_block_once() {
    let fix = Fixture::new();
    let (mut host, events) = fix.host_over_history(advanced_history(&fix, 0), far_future());
    let block = skip_block(&fix.genesis_block(), Epoch::new(1));
    let verified = || {
        fold_outcome(ProtocolEvent::BeaconBlockVerified {
            result: Ok(Arc::clone(&block)),
        })
    };
    let (ran, left) = crash_point::armed(Some(u64::MAX), || {
        let _ = host.step(verified());
        let _ = host.step(verified());
        host.beacon.on_sync_response(
            Epoch::new(1),
            Some(Arc::new(Verifiable::from((*block).clone()))),
        );
        for event in events.try_iter() {
            let _ = host.step(event);
        }
    });
    assert!(ran.is_ok());
    assert_eq!(host.beacon.fold().state().current_epoch, Epoch::new(1));
    assert_eq!(
        left,
        Some(u64::MAX - 1),
        "one storage write across every copy of the block",
    );
    assert_eq!(
        host.beacon_storage().latest_committed_epoch(),
        Some(Epoch::new(1)),
        "the one write is the block's commit",
    );
}

/// A host restarted over beacon storage whose tip is epoch 8 syncs
/// from 9: its catch-up starts at the storage tip, with nothing
/// committed in this run.
#[test]
fn beacon_sync_resumes_from_the_storage_tip_after_a_restart() {
    let fix = Fixture::new();
    let (mut host, _events) = fix.host_resumed(
        advanced_history(&fix, 8),
        SimShardStorage::new(shard_prefix_path(SHARD)),
        far_future(),
    );
    host.beacon.start_sync(Epoch::new(10));
    let status = host.beacon.beacon_block.status(&());
    assert_eq!(status.current_height, 8, "the watermark is the storage tip");
    assert_eq!(status.blocks_behind, 2);
    assert_eq!(
        beacon_blocks_asked(&host),
        vec![Epoch::new(9)],
        "one epoch in flight, the one above the tip",
    );
}

/// A sync started while no live leaf has a committee to ask holds its
/// epoch behind the backoff rather than in flight, so once a committee
/// appears the next tick asks it.
#[test]
fn a_beacon_sync_with_no_committee_to_ask_retries_once_one_appears() {
    let fix = Fixture::new();
    let mut host = fix.host(BlockHeight::GENESIS);
    let live = host.process.topology_snapshot.load_full();
    host.process
        .topology_snapshot
        .store(Arc::new(fix.topology(BTreeMap::new())));

    host.beacon.start_sync(Epoch::new(1));
    assert!(beacon_blocks_asked(&host).is_empty(), "no committee to ask");

    host.process.topology_snapshot.store(live);
    let later = host.beacon.now.plus(Duration::from_secs(60));
    host.set_time(later);
    let _ = host.step(HostEvent::beacon_fetch_tick());
    assert_eq!(
        beacon_blocks_asked(&host),
        vec![Epoch::new(1)],
        "the tick asks the committee"
    );
}

/// The epochs of the beacon blocks `host` has asked for since the
/// last call.
fn beacon_blocks_asked(host: &Host) -> Vec<Epoch> {
    let mut asked = Vec::new();
    for pending in host.network().drain_pending_requests() {
        if let Some(request) = pending.request::<GetBeaconBlockRequest>() {
            asked.push(request.epoch);
        }
    }
    asked
}

/// The beacon loop's fold hands back `event` as its own outcome.
fn fold_outcome(event: ProtocolEvent) -> HostEvent {
    HostEvent::Beacon(BeaconScopedInput::Continuation {
        owner: BeaconOwner::Fold,
        event: Box::new(event),
    })
}

/// An adoption that lands after a chain registers and before its loop
/// runs reaches the loop's channel, so the loop's first event is the
/// schedule it would otherwise miss.
#[test]
fn an_adoption_between_register_and_spawn_reaches_the_new_loop() {
    let fix = Fixture::new();
    let (mut host, _events) = fix.host_over_history(advanced_history(&fix, 0), far_future());
    let (sender, receiver) = unbounded();
    let _ = host.beacon.register(
        SHARD,
        LocalChainAnchors::GENESIS,
        BlockHeight::GENESIS,
        sender,
    );
    let _ = host.step(fold_outcome(ProtocolEvent::BeaconBlockVerified {
        result: Ok(skip_block(&fix.genesis_block(), Epoch::new(1))),
    }));
    let persisted: Vec<Epoch> = receiver
        .try_iter()
        .filter_map(|event| match event {
            HostEvent::Shard(shard, ShardScopedInput::Protocol(event)) if shard == SHARD => {
                match *event {
                    ProtocolEvent::BeaconBlockPersisted { epoch, .. } => Some(epoch),
                    _ => None,
                }
            }
            _ => None,
        })
        .collect();
    assert_eq!(persisted, vec![Epoch::new(1)]);
}

/// Three registered chains on three shards, each with its own channel.
fn three_chains(host: &mut Host) -> Vec<(ChainRegistration, ShardId, Receiver<HostEvent>)> {
    [0, 1, 2]
        .into_iter()
        .map(|path| ShardId::leaf(2, path))
        .map(|shard| {
            let (sender, receiver) = unbounded();
            let registration = host.beacon.register(
                shard,
                LocalChainAnchors::GENESIS,
                BlockHeight::GENESIS,
                sender,
            );
            (registration.token, shard, receiver)
        })
        .collect()
}

/// The commit-proof asks each channel received, as `(source, height)`.
fn asks(receiver: &Receiver<HostEvent>) -> Vec<(ShardId, BlockHeight)> {
    receiver
        .try_iter()
        .filter_map(|event| match event {
            HostEvent::Shard(_, ShardScopedInput::Protocol(event)) => match *event {
                ProtocolEvent::CommitProofNeeded {
                    source_shard,
                    block_height,
                } => Some((source_shard, block_height)),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

fn ask_proof(host: &mut Host, source: ShardId, height: BlockHeight) {
    let unhandled = host.beacon.process_shared_action(
        participant(2),
        Action::Continuation(ProtocolEvent::CommitProofNeeded {
            source_shard: source,
            block_height: height,
        }),
    );
    assert!(unhandled.is_none());
}

/// A participant's ask for a hosted shard's commit proof goes to a
/// sibling loop: a loop never answers for its own shard.
#[test]
fn a_boundary_ask_for_a_hosted_shard_is_answered_by_a_sibling_loop() {
    let fix = Fixture::new();
    let (mut host, _events) = fix.host_over_history(advanced_history(&fix, 0), far_future());
    let chains = three_chains(&mut host);
    let (_, own, own_rx) = &chains[0];
    ask_proof(&mut host, *own, BlockHeight::new(4));
    assert!(
        asks(own_rx).is_empty(),
        "a loop never answers for its own shard"
    );
    assert_eq!(asks(&chains[1].2), vec![(*own, BlockHeight::new(4))]);
    assert!(asks(&chains[2].2).is_empty(), "the ask goes to one loop");
}

/// The loop an ask went to deregistering hands the ask to the next
/// eligible loop; one that answered is not asked again.
#[test]
fn a_boundary_ask_survives_its_loops_deregister() {
    let fix = Fixture::new();
    let (mut host, _events) = fix.host_over_history(advanced_history(&fix, 0), far_future());
    let chains = three_chains(&mut host);
    let source = chains[0].1;
    ask_proof(&mut host, source, BlockHeight::new(4));
    ask_proof(&mut host, source, BlockHeight::new(5));
    assert_eq!(asks(&chains[1].2).len(), 2);
    let proven = header_at(source, 5, 10_000);
    report(
        &mut host,
        chains[1].0,
        BeaconInput::CommitProven { header: proven },
    );

    host.beacon.deregister(chains[1].0);
    assert_eq!(
        asks(&chains[2].2),
        vec![(source, BlockHeight::new(4))],
        "the unanswered ask moves to the next loop",
    );
}

/// An ask no participant holds past the next adoption loses its
/// route: the loop it went to deregistering hands it to no one.
#[test]
fn an_unanswered_asks_route_is_dropped_at_the_next_adoption() {
    let fix = Fixture::new();
    let (mut host, _events) = fix.host_over_history(advanced_history(&fix, 0), far_future());
    let chains = three_chains(&mut host);
    let source = chains[0].1;
    ask_proof(&mut host, source, BlockHeight::new(4));
    assert_eq!(asks(&chains[1].2).len(), 1);
    let _ = host.step(fold_outcome(ProtocolEvent::BeaconBlockVerified {
        result: Ok(skip_block(&fix.genesis_block(), Epoch::new(1))),
    }));
    assert_eq!(host.beacon.fold().state().current_epoch, Epoch::new(1));

    host.beacon.deregister(chains[1].0);
    assert!(
        asks(&chains[2].2).is_empty(),
        "an ask the adoption retired is not handed on",
    );
}

/// A deregistered loop's late reports change nothing: a commit proof
/// it reports leaves the route another loop holds for the same ask,
/// and a source header it reports is not recorded.
#[test]
fn a_deregistered_loops_late_reports_change_nothing() {
    let fix = Fixture::new();
    let (mut host, _events) = fix.host_over_history(advanced_history(&fix, 0), far_future());
    let chains = three_chains(&mut host);
    let source = chains[0].1;
    let stale = chains[1].0;
    host.beacon.deregister(stale);
    ask_proof(&mut host, source, BlockHeight::new(4));
    assert_eq!(asks(&chains[2].2), vec![(source, BlockHeight::new(4))]);
    let (sender, rebuilt) = unbounded();
    let _ = host.beacon.register(
        chains[1].1,
        LocalChainAnchors::GENESIS,
        BlockHeight::GENESIS,
        sender,
    );

    report(
        &mut host,
        stale,
        BeaconInput::CommitProven {
            header: header_at(source, 4, 10_000),
        },
    );
    report(
        &mut host,
        stale,
        BeaconInput::SourceHeader {
            header: header_at(source, 5, 10_000),
        },
    );
    assert!(
        host.beacon
            .fold()
            .shard_source()
            .header(source, BlockHeight::new(5))
            .is_none(),
        "a closed loop's source header is not recorded",
    );
    host.beacon.deregister(chains[2].0);
    assert_eq!(
        asks(&rebuilt),
        vec![(source, BlockHeight::new(4))],
        "the ask's route outlived the closed loop's proof",
    );
}

/// The certified header of `shard`'s block at `height` over the block
/// `parent`, its parent's certificate dated `parent_ms`, committing
/// `leaf_count` witness leaves.
fn linked_header(
    shard: ShardId,
    height: u64,
    parent: BlockHash,
    parent_ms: u64,
    leaf_count: u64,
) -> Arc<Verified<CertifiedBlockHeader>> {
    let qc = |block, height, parent| {
        QuorumCertificate::new(
            block,
            shard,
            BlockHeight::new(height),
            parent,
            Round::INITIAL,
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(parent_ms),
        )
    };
    let header = BlockHeader::new(BlockHeaderParts {
        shard_id: shard,
        height: BlockHeight::new(height),
        parent_block_hash: parent,
        parent_qc: qc(parent, height.saturating_sub(1), BlockHash::ZERO).into(),
        round: Round::new(height),
        beacon_witness_root: BeaconWitnessRoot::from_raw(Hash::from_bytes(
            format!("bw-{height}").as_bytes(),
        )),
        beacon_witness_leaf_count: BeaconWitnessLeafCount::new(leaf_count),
        ..Default::default()
    });
    let certificate = qc(header.hash(), height, parent);
    Arc::new(Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
        header,
        certificate,
    )))
}

/// Adding the host's first participant on the beacon committee raises
/// the fold's committee flag, which fetches the witness chunk of a
/// crossing the fold already holds; removing it lowers the flag and
/// abandons the fetch.
#[test]
fn a_committee_participant_coming_and_going_starts_and_abandons_witness_fetches() {
    let fix = Fixture::new();
    let mut host = fix.host(BlockHeight::GENESIS);
    let chain = loop_of(&mut host).chain;
    let source = ShardId::ROOT;
    let b = linked_header(source, 5, BlockHash::ZERO, 1, 3);
    let c = linked_header(source, 6, b.block_hash(), 300_001, 3);
    let d = linked_header(source, 7, c.block_hash(), 300_001, 3);
    for header in [b, c, d] {
        report(&mut host, chain, BeaconInput::SourceHeader { header });
    }
    assert!(
        host.beacon.interest.witnesses.is_empty(),
        "off the committee the fold asks for no witness",
    );

    add(&mut host, &fix, 0);
    assert!(
        host.beacon
            .interest
            .witnesses
            .keys()
            .any(|run| run.0 == source),
        "the first committee participant starts the held crossing's fetch",
    );

    assert!(host.remove_participant(fix.committee.validator_id(0)));
    assert!(
        host.beacon.interest.witnesses.is_empty(),
        "the last committee participant leaving abandons it",
    );
}

/// The loop holds a commit proof one participant asked for and hands
/// that participant's awaiting proposal to its pool.
#[test]
#[allow(clippy::too_many_lines)] // one certified chain built and walked end to end
fn a_commit_proof_one_participant_asked_for_releases_its_proposal_on_the_loop() {
    let fix = Fixture::new();
    let (mut host, _events) =
        fix.host_over_history(advanced_history(&fix, 0), LocalTimestamp::ZERO);
    let shard = ShardId::ROOT;
    let (sender, _receiver) = unbounded();
    let chain = host
        .beacon
        .register(
            shard,
            LocalChainAnchors::GENESIS,
            BlockHeight::GENESIS,
            sender,
        )
        .token;
    add(&mut host, &fix, 0);
    let me = fix.committee.validator_id(0);
    let from = fix.committee.validator_id(1);
    let cut = fix.genesis_state().chain_config.epoch_duration_ms;
    let network = NetworkDefinition::simulator();

    let header = |height: u64, parent_qc: &QuorumCertificate| {
        BlockHeader::new(BlockHeaderParts {
            shard_id: shard,
            height: BlockHeight::new(height),
            parent_block_hash: parent_qc.block_hash(),
            parent_qc: parent_qc.clone().into(),
            round: Round::new(height),
            beacon_witness_root: BeaconWitnessRoot::from_raw(Hash::from_bytes(b"bw")),
            beacon_witness_leaf_count: BeaconWitnessLeafCount::new(3),
            ..Default::default()
        })
    };
    let qc_over = |header: &BlockHeader, wt: u64| {
        let votes: Vec<(usize, Verified<BlockVote>)> = (0..3)
            .map(|seat| {
                let vote = BlockVote::new(
                    &network,
                    header.hash(),
                    header.parent_block_hash(),
                    shard,
                    header.height(),
                    header.round(),
                    fix.committee.validator_id(seat),
                    fix.committee.signer(seat).as_ref(),
                    ProposerTimestamp::from_millis(wt),
                )
                .expect("vote signs");
                (seat, Verified::new_unchecked_for_test(vote))
            })
            .collect();
        Verified::<QuorumCertificate>::from_verified_votes(
            &BlsVerifier,
            header.hash(),
            shard,
            header.height(),
            header.round(),
            header.parent_block_hash(),
            header.parent_qc().weighted_timestamp(),
            &votes,
        )
        .expect("aggregates over a quorum")
        .into_inner()
    };
    let certified = |header: &BlockHeader, qc: &QuorumCertificate| {
        Arc::new(Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
            header.clone(),
            qc.clone(),
        )))
    };

    // `b` anchors short of the cut and is certified past it; `c`
    // embeds that certificate and `d` commits `c`.
    let below = QuorumCertificate::new(
        BlockHash::ZERO,
        shard,
        BlockHeight::new(3),
        BlockHash::ZERO,
        Round::INITIAL,
        SignerBitfield::new(4),
        AggregateSignature::ZERO,
        WeightedTimestamp::from_millis(cut - 2),
    );
    let a = header(4, &below);
    let a_qc = qc_over(&a, cut - 1);
    let b = header(5, &a_qc);
    let b_qc = qc_over(&b, cut + 1);
    let c = header(6, &b_qc);
    let c_qc = qc_over(&c, cut + 2);
    let d = header(7, &c_qc);
    let d_qc = qc_over(&d, cut + 3);

    let proposal = Verified::new_unchecked_for_test(BeaconProposal::new(
        std::iter::once((shard, Some(b_qc.clone()))).collect(),
        Vec::new(),
        BTreeMap::new(),
        Vec::new(),
        VrfProof::ZERO,
    ));
    report(
        &mut host,
        chain,
        BeaconInput::CertifiedHeader {
            header: certified(&a, &a_qc),
        },
    );
    let _ = host.step(HostEvent::Beacon(BeaconScopedInput::Protocol(Box::new(
        ProtocolEvent::BeaconProposalReceived {
            from,
            epoch: Epoch::GENESIS.next(),
            proposal: Arc::new(proposal),
        },
    ))));
    for (header, qc) in [(&b, &b_qc), (&c, &c_qc)] {
        report(
            &mut host,
            chain,
            BeaconInput::CertifiedHeader {
                header: certified(header, qc),
            },
        );
    }
    assert!(
        host.beacon
            .participant(me)
            .expect("runs")
            .proposal_pool()
            .get(from)
            .is_none(),
        "the boundary's dating child is only certified, so the proposal awaits",
    );
    let asked: Vec<_> = [(&b, &b_qc), (&c, &c_qc), (&d, &d_qc)]
        .into_iter()
        .filter(|(header, _)| {
            host.beacon
                .participant(me)
                .expect("runs")
                .asked(shard, header.height())
        })
        .collect();
    assert!(!asked.is_empty(), "the awaiting proposal asks for a proof");

    for (header, qc) in asked {
        report(
            &mut host,
            chain,
            BeaconInput::CommitProven {
                header: certified(header, qc),
            },
        );
    }
    assert!(
        host.beacon
            .participant(me)
            .expect("runs")
            .proposal_pool()
            .get(from)
            .is_some(),
        "the proven commit releases the asker's proposal into its pool",
    );
}

/// The states a merge into the root leaves: window 1 runs the root's
/// two children and window 2 the root alone, so each child's terminal
/// window is 1.
fn merged_history(fix: &Fixture) -> Vec<(Arc<Verified<CertifiedBeaconBlock>>, BeaconState)> {
    let genesis = fix.genesis_state();
    let mut split = genesis.clone();
    split.current_epoch = Epoch::new(1);
    let committee = split
        .shard_committees
        .remove(&ShardId::ROOT)
        .expect("genesis seats the root");
    let (left, right) = ShardId::ROOT.children();
    split.shard_committees = BTreeMap::from([(left, committee.clone()), (right, committee)]);
    split.next_shard_committees = split.shard_committees.clone();
    split.shard_consensus_members = split.ready_consensus_members(&split.shard_committees);
    let mut merged = genesis.clone();
    merged.current_epoch = Epoch::new(2);
    for boundary in merged.boundaries.values_mut() {
        boundary.last_live_epoch = Epoch::new(2);
    }
    let first = skip_block(&fix.genesis_block(), Epoch::new(1));
    let tip = skip_block(&first, Epoch::new(2));
    vec![
        (fix.genesis_block(), genesis.clone()),
        (first, split),
        (tip, merged),
    ]
}

/// A chain that committed past its terminal answers no commit-proof
/// ask: the ask goes to a live chain registered after it.
#[test]
fn a_boundary_ask_skips_a_chain_past_its_terminal() {
    let fix = Fixture::new();
    let (mut host, _events) = fix.host_over_history(merged_history(&fix), far_future());
    let (left, right) = ShardId::ROOT.children();
    let (terminated_tx, terminated_rx) = unbounded();
    let terminated = host
        .beacon
        .register(
            left,
            LocalChainAnchors {
                committee: in_epoch(&fix, 1),
                block: in_epoch(&fix, 2),
            },
            BlockHeight::new(4),
            terminated_tx,
        )
        .token;
    assert!(
        host.beacon
            .fold()
            .chain(terminated)
            .is_some_and(|chain| chain.terminal_committed),
        "the chain registers past its terminal",
    );
    let (live_tx, live_rx) = unbounded();
    let _ = host.beacon.register(
        ShardId::ROOT,
        LocalChainAnchors {
            committee: in_epoch(&fix, 2),
            block: in_epoch(&fix, 2),
        },
        BlockHeight::new(4),
        live_tx,
    );
    ask_proof(&mut host, right, BlockHeight::new(4));
    assert!(asks(&terminated_rx).is_empty());
    assert_eq!(asks(&live_rx), vec![(right, BlockHeight::new(4))]);
}

/// A shard loop on a thread of its own releases its chain's
/// registration as a panic unwinds the thread.
#[test]
fn a_panicking_shard_thread_deregisters_its_chain() {
    let fix = Fixture::new();
    let (host, events) = fix.host_with_events(BlockHeight::GENESIS);
    let (_process, mut shards, mut beacon) = host.into_parts();
    let shard_loop = shards.remove(&SHARD).expect("the fixture hosts SHARD");
    let chain = shard_loop.chain;
    let died = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _shard_loop = ThreadShardLoop::from(shard_loop);
        panic!("the shard loop dies");
    }));
    assert!(died.is_err());
    assert!(beacon.fold().chain(chain).is_some());
    for event in events.try_iter() {
        if let HostEvent::Beacon(input) = event {
            let _ = beacon.run_step(input);
        }
    }
    assert!(
        beacon.fold().chain(chain).is_none(),
        "the unwind deregistered the chain",
    );
}

/// A rebuilt chain registers again before its old loop deregisters;
/// the old loop's deregister and any commit it reports late touch
/// nothing of the new entry.
#[test]
fn a_rebuilt_loops_registration_survives_the_old_loops_deregister_and_late_commits() {
    let fix = Fixture::new();
    let (mut host, _events) = fix.host_over_history(advanced_history(&fix, 0), far_future());
    let register = |host: &mut Host, height| {
        let (sender, _receiver) = unbounded();
        host.beacon
            .register(
                SHARD,
                LocalChainAnchors::GENESIS,
                BlockHeight::new(height),
                sender,
            )
            .token
    };
    let old = register(&mut host, 3);
    let new = register(&mut host, 5);
    host.beacon.deregister(old);
    report(
        &mut host,
        old,
        BeaconInput::LocalCommit {
            header: header_at(SHARD, 6, 10_000),
        },
    );
    let chain = *host.beacon.fold().chain(new).expect("the new entry stands");
    assert_eq!(chain.height, BlockHeight::new(5));
    assert_eq!(chain.anchors, LocalChainAnchors::GENESIS);
    assert!(host.beacon.fold().chain(old).is_none());
}

/// Attaching a validator to another of its host's shards and leaving
/// the first touches neither its participant nor its attachment.
#[test]
fn a_seat_moving_between_shards_keeps_its_participant() {
    let fix = Fixture::new();
    let mut host = fix.host(BlockHeight::GENESIS);
    add(&mut host, &fix, 0);
    let before = attachment(&host, 0, &fix);
    let other = ShardId::leaf(1, 1);
    let (sender, _receiver) = unbounded();
    host.add_shard(
        &fix.replica_config(),
        HostedChain {
            shard: other,
            storage: SimShardStorage::new(shard_prefix_path(other)),
            recovered: &RecoveredState::default(),
            signers: vec![fix.identity(0)],
            inbox: sender.into(),
        },
    );
    assert!(host.remove_shard(SHARD).is_some());
    assert_eq!(attachment(&host, 0, &fix), before);
    assert!(
        host.beacon.participants[&fix.committee.validator_id(0)]
            .gate
            .enter()
            .is_some(),
        "its release gate stays open",
    );
}

/// Far enough past genesis that no beacon history is too young for
/// the retention horizon to keep.
fn far_future() -> LocalTimestamp {
    LocalTimestamp::from_millis(1 << 50)
}

/// A weighted timestamp inside `epoch`'s window.
fn in_epoch(fix: &Fixture, epoch: u64) -> WeightedTimestamp {
    WeightedTimestamp::from_millis(epoch * fix.genesis_state().chain_config.epoch_duration_ms + 1)
}

/// A host seated on no shard has no shard loop to gossip through, and
/// publishes its own submission straight to the shards it touches.
#[test]
fn a_host_seated_nowhere_publishes_its_own_submission() {
    let fix = Fixture::new();
    let (host, _events) = fix.host_over_history(advanced_history(&fix, 0), far_future());
    let _ = host.network().drain_outbox();
    let tx = Arc::new(test_transaction(1));
    assert!(host.process.submit_transaction(&tx));
    let sent = host.network().drain_outbox();
    assert!(
        sent.iter()
            .any(|entry| entry.message_type() == "transaction.gossip"
                && matches!(entry.target(), BroadcastTarget::Shard(_))),
        "{sent:?}"
    );
}

/// The beacon loop is the one writer of the process's topology, and
/// what it publishes releases the submissions parked while the host
/// seats a reshape successor: they route again against it.
#[test]
fn an_adoption_on_the_beacon_loop_releases_a_parked_submission() {
    let fix = Fixture::new();
    let (mut host, events) = fix.host_with_events(BlockHeight::GENESIS);
    let id = |idx| fix.committee.validator_id(idx);
    let seating = fix.topology_of(
        4,
        (0..4)
            .map(|path| {
                (
                    ShardId::leaf(2, path),
                    vec![id(usize::try_from(path).expect("small"))],
                )
            })
            .collect(),
    );
    assert!(seating.reshape_handoff_pending(SHARD));
    host.process.topology_snapshot.store(Arc::new(seating));
    let tx = Arc::new(test_transaction(1));
    assert!(host.process.submit_transaction(&tx));
    let routed = |events: &Receiver<HostEvent>| {
        events.try_iter().find_map(|event| match event {
            HostEvent::Shard(
                shard,
                ShardScopedInput::AdmitAndGossipTransaction { tx: held, .. },
            ) if held.hash() == tx.hash() => Some(shard),
            _ => None,
        })
    };
    assert_eq!(
        routed(&events),
        None,
        "the submission waits for the successor"
    );

    let live = fix.topology(BTreeMap::from([(SHARD, vec![id(0), id(1)])]));
    let (folded, held) = host.process.folded_schedule();
    let (_, newest) = held.retained_epochs().expect("the host holds a schedule");
    let epoch = folded.next();
    let unhandled = host.beacon.process_shared_action(
        BeaconOwner::Fold,
        Action::TopologyChanged {
            epoch,
            schedule: Arc::new(TopologySchedule::new(
                fix.genesis_state().chain_config.epoch_windows(),
                newest.next(),
                Arc::new(live),
            )),
        },
    );
    assert!(unhandled.is_none());
    assert_eq!(
        routed(&events),
        Some(SHARD),
        "the published topology releases the submission to the shard it routes to",
    );
}

/// A host seated nowhere holds a submission naming a record it lacks,
/// asks for the record, and publishes the submission once the record
/// lands: the wait is the host's, with no shard loop to hold it.
#[test]
fn a_host_seated_nowhere_holds_a_submission_until_its_record_arrives() {
    let fix = Fixture::new();
    let (mut host, _events) = fix.host_over_history(advanced_history(&fix, 0), far_future());
    let (instance, record) = record_on_shard(&host);
    let _ = host.network().drain_outbox();
    let tx = Arc::new(test_transaction(1));
    let _ = host.step(HostEvent::Beacon(
        BeaconScopedInput::SubmissionWantsRecords {
            deferred: DeferredTransaction::new(
                Arc::clone(&tx),
                Unresolved {
                    instances: vec![instance],
                    packages: Vec::new(),
                },
            ),
        },
    ));
    let published = |host: &Host| {
        host.network()
            .drain_outbox()
            .iter()
            .any(|entry| entry.message_type() == "transaction.gossip")
    };
    assert!(!published(&host), "the submission waits for its record");
    assert_eq!(records_asked(&host), vec![vec![instance]]);
    assert_eq!(
        host.beacon.interest.records[&instance],
        BTreeSet::from([BeaconOwner::Submissions]),
    );

    let _ = host.step(HostEvent::Beacon(
        BeaconScopedInput::InstanceRecordsFetched {
            records: vec![(instance, record)],
        },
    ));
    assert!(published(&host), "the arrival routes the submission");
    assert!(host.beacon.submissions.is_empty());
    assert_eq!(host.beacon.fetches.instance_record.pending_count(), 0);
}

/// A component record whose prefix `SHARD` owns, and its leaf bytes.
fn record_on_shard(host: &Host) -> (Address, Vec<u8>) {
    let topology = host.process.topology_snapshot.load();
    (0u8..=u8::MAX)
        .map(|salt| InstanceMeta {
            package: PackageHash(Hash32([7; 32])),
            config: Capped::empty(),
            salt: Hash32([salt; 32]),
        })
        .find_map(|meta| {
            let address = meta.address(&ProtocolHasher).address();
            (topology.shard_trie().shard_for_prefix(address) == SHARD)
                .then(|| (address, meta.leaf_bytes().expect("a record encodes")))
        })
        .expect("some salt lands on the shard")
}

/// Register another chain for `SHARD`, returning its token and the
/// channel the beacon loop sends it on.
fn chain_on_shard(host: &mut Host) -> (ChainRegistration, Receiver<HostEvent>) {
    let (sender, receiver) = unbounded();
    let token = host
        .beacon
        .register(
            SHARD,
            LocalChainAnchors::GENESIS,
            BlockHeight::GENESIS,
            sender,
        )
        .token;
    (token, receiver)
}

fn want_record(host: &mut Host, chain: ChainRegistration, instance: Address) {
    report(
        host,
        chain,
        BeaconInput::RecordsWanted {
            instances: vec![instance],
            packages: Vec::new(),
        },
    );
}

/// The records `chain`'s loop was told arrived, since the last call.
fn arrivals(receiver: &Receiver<HostEvent>) -> Vec<Address> {
    receiver
        .try_iter()
        .flat_map(|event| match event {
            HostEvent::Shard(_, ShardScopedInput::RecordsArrived { arrived }) => arrived,
            _ => Vec::new(),
        })
        .collect()
}

/// The record fetches `host` sent since the last call.
fn records_asked(host: &Host) -> Vec<Vec<Address>> {
    host.network()
        .drain_pending_requests()
        .iter()
        .filter_map(PendingRequest::request::<GetInstanceRecordsRequest>)
        .map(|request| request.instances.into_inner())
        .collect()
}

/// Two loops wanting one record cost the host one request, and both
/// stay askers of it.
#[test]
fn two_chains_wanting_one_record_ask_for_it_once() {
    let fix = Fixture::new();
    let mut host = fix.host(BlockHeight::GENESIS);
    let (instance, _) = record_on_shard(&host);
    let (first, _) = chain_on_shard(&mut host);
    let (second, _) = chain_on_shard(&mut host);
    let _ = records_asked(&host);
    want_record(&mut host, first, instance);
    want_record(&mut host, second, instance);
    assert_eq!(records_asked(&host), vec![vec![instance]]);
    assert_eq!(
        host.beacon.interest.records[&instance],
        BTreeSet::from([BeaconOwner::Chain(first), BeaconOwner::Chain(second)]),
    );
}

/// A loop that closes takes its interest with it, and the ask stands
/// while another loop still wants it. A rebuilt loop for the same
/// shard is another loop: the old one's late deregister leaves it be.
#[test]
fn a_closed_loops_record_interest_leaves_a_rebuilt_loops_standing() {
    let fix = Fixture::new();
    let mut host = fix.host(BlockHeight::GENESIS);
    let (instance, _) = record_on_shard(&host);
    let (old, _) = chain_on_shard(&mut host);
    let (rebuilt, _) = chain_on_shard(&mut host);
    want_record(&mut host, old, instance);
    want_record(&mut host, rebuilt, instance);
    host.beacon.deregister(old);
    assert_eq!(host.beacon.fetches.instance_record.pending_count(), 1);
    assert_eq!(
        host.beacon.interest.records[&instance],
        BTreeSet::from([BeaconOwner::Chain(rebuilt)]),
    );
    host.beacon.deregister(rebuilt);
    assert_eq!(
        host.beacon.fetches.instance_record.pending_count(),
        0,
        "nobody wants the record once the last asker closes",
    );
}

/// A record derivation already reads here is answered at once, with
/// no request: the ask was queued behind its own answer.
#[test]
fn a_record_the_host_holds_is_answered_without_a_request() {
    let fix = Fixture::new();
    let mut host = fix.host(BlockHeight::GENESIS);
    let (instance, record) = record_on_shard(&host);
    host.process
        .dispatch_handles
        .executor
        .install_instance(instance, &record);
    let (chain, receiver) = chain_on_shard(&mut host);
    let _ = records_asked(&host);
    want_record(&mut host, chain, instance);
    assert!(records_asked(&host).is_empty());
    assert_eq!(arrivals(&receiver), vec![instance]);
}

/// A wanted package is looked for in the stores this host serves off
/// the loop, once however often it is wanted meanwhile, and only what
/// none holds is asked of a peer.
#[test]
fn a_wanted_package_is_read_from_the_hosts_stores_once_off_the_loop() {
    let fix = Fixture::new();
    let jobs = Arc::new(DeferredJobs::new(ProcessingTimes::disk(7), 7));
    let (_wire, mut host, events) = wired(&fix, SyncDispatch::deferred(Arc::clone(&jobs)));
    let package = Hash::from_bytes(b"a package no store holds");
    let (first, _) = chain_on_shard(&mut host);
    let (second, _) = chain_on_shard(&mut host);
    for chain in [first, second] {
        host.beacon
            .want_records(BeaconOwner::Chain(chain), Vec::new(), vec![package]);
    }
    let queued = jobs.take();
    assert_eq!(queued.len(), 1, "one read covers both wants");
    assert_eq!(host.beacon.fetches.package_artifact.pending_count(), 0);

    for (_, job) in queued {
        job();
    }
    while let Ok(event) = events.try_recv() {
        let _ = host.step(event);
    }
    assert_eq!(
        host.beacon.fetches.package_artifact.pending_count(),
        1,
        "what no store holds is asked of a peer",
    );
    assert!(host.beacon.installing.is_empty());
}

/// Bytes that derive no record answer for nothing asked: the peer
/// that gave them is rejected, and the record asked for is asked of
/// another.
#[test]
fn record_bytes_deriving_nothing_reject_their_peer() {
    let fix = Fixture::new();
    let host = fix.host(BlockHeight::GENESIS);
    let (instance, _) = record_on_shard(&host);
    let (tx, events) = unbounded();
    let reply = BeaconReply::new(
        tx,
        ProposalKeys {
            topology: host.process.topology_snapshot.clone(),
            verifier: Arc::clone(&host.process.verifier),
            network: NetworkDefinition::simulator(),
        },
    );
    let garbage = GetInstanceRecordsResponse::new(
        Capped::new(vec![Bytes::new(vec![0xff; 4]).expect("bytes fit a cell")])
            .expect("one record"),
    );
    let verdict = settle_solicited::<InstanceRecordBinding, _>(vec![instance], Ok(garbage), &reply);
    assert!(matches!(verdict, ResponseVerdict::Reject));
    assert!(matches!(
        events.try_iter().collect::<Vec<_>>().as_slice(),
        [HostEvent::Beacon(BeaconScopedInput::FetchFailed(_))]
    ));
}

/// A peer's record lands in the registry and on disk, and the loop
/// that asked is told; one deriving another address seats nothing and
/// the ask stands for another try.
#[test]
fn a_fetched_record_is_seated_only_under_the_address_it_derives() {
    let fix = Fixture::new();
    let (mut wire, mut host, events) = wired(&fix, SyncDispatch::new());
    let (instance, record) = record_on_shard(&host);
    let (elsewhere, other) = {
        let meta = InstanceMeta {
            package: PackageHash(Hash32([8; 32])),
            config: Capped::empty(),
            salt: Hash32([1; 32]),
        };
        (
            meta.address(&ProtocolHasher).address(),
            meta.leaf_bytes().expect("a record encodes"),
        )
    };
    let honest = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let serving = Arc::clone(&honest);
    wire.peer
        .register_request_handler(SHARD, move |_: GetInstanceRecordsRequest| {
            let bytes = if serving.load(Ordering::SeqCst) {
                record.clone()
            } else {
                other.clone()
            };
            GetInstanceRecordsResponse::new(
                Capped::new(vec![Bytes::new(bytes).expect("a record fits a cell")])
                    .expect("one record"),
            )
        });
    let (chain, receiver) = chain_on_shard(&mut host);
    want_record(&mut host, chain, instance);
    wire.pump(&mut host, &events);
    let executor = Arc::clone(&host.process.dispatch_handles.executor);
    assert!(!executor.instance_known(instance));
    assert!(!executor.instance_known(elsewhere));
    assert!(arrivals(&receiver).is_empty());
    assert_eq!(host.beacon.fetches.instance_record.pending_count(), 1);

    honest.store(true, Ordering::SeqCst);
    let later = host.beacon.now.plus(Duration::from_secs(1));
    host.set_time(later);
    let _ = host.step(HostEvent::beacon_fetch_tick());
    wire.pump(&mut host, &events);
    assert!(executor.instance_known(instance));
    assert!(
        host.process
            .dispatch_handles
            .beacon_storage
            .fetched_instance(instance)
            .is_some(),
        "the record is kept on disk before it is seated",
    );
    assert_eq!(arrivals(&receiver), vec![instance]);
    assert_eq!(host.beacon.fetches.instance_record.pending_count(), 0);
}
