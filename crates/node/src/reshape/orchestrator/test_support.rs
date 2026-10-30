//! Fixtures the orchestrator's duty tests share.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use hyperscale_crypto_bls::BlsSigner;
use hyperscale_hbor::Capped;
use hyperscale_storage::test_helpers::make_test_block;
use hyperscale_types::network::request::GetBlockRequest;
use hyperscale_types::network::response::GetRemoteHeadersResponse;
use hyperscale_types::test_utils::{
    TestCommittee, install_stub_protocol_statics, stub_transaction,
};
use hyperscale_types::{
    BeaconWitnessLeafCount, Block, BlockHash, BlockHeight, CertifiedBlockHeader, Epoch,
    EpochWindows, Hash, LocalTimestamp, NetworkDefinition, PrincipalAddr, ReshapeSeat, ShardAnchor,
    ShardId, Signer, StateRoot, TimestampRange, TopologySchedule, TopologySnapshot, Transaction,
    ValidatorId, ValidatorInfo, ValidatorSet, Verifiable, WeightedTimestamp,
};

use super::io::{FetchKind, FetchedKind, ReshapeEvent, ReshapeRequest};
use super::keeper::KeeperDuty;
use super::observer_duty::{ObserverDuty, ObserverPhase};
use super::parent_half::{ParentHalfDuty, ParentHalfPhase};
use super::shared::{REFETCH_WAIT, SeatTail, StageQueue};
use super::*;
use crate::reshape::observer::ObserverTail;

pub fn insert_observer(orch: &mut ReshapeOrchestrator, child: ShardId, duty: ObserverDuty) {
    orch.duties.insert(child, Duty::Observer(duty));
}

pub fn insert_parent_half(orch: &mut ReshapeOrchestrator, child: ShardId, duty: ParentHalfDuty) {
    orch.duties.insert(child, Duty::ParentHalf(duty));
}

pub fn insert_keeper(orch: &mut ReshapeOrchestrator, parent: ShardId, duty: KeeperDuty) {
    orch.duties.insert(parent, Duty::Keeper(duty));
}

pub fn observer(orch: &ReshapeOrchestrator, child: ShardId) -> &ObserverDuty {
    match orch.duties.get(&child) {
        Some(Duty::Observer(duty)) => duty,
        _ => panic!("no observer duty for {child:?}"),
    }
}

pub fn parent_half(orch: &ReshapeOrchestrator, child: ShardId) -> &ParentHalfDuty {
    match orch.duties.get(&child) {
        Some(Duty::ParentHalf(duty)) => duty,
        _ => panic!("no parent-half duty for {child:?}"),
    }
}

pub fn keeper(orch: &ReshapeOrchestrator, parent: ShardId) -> &KeeperDuty {
    match orch.duties.get(&parent) {
        Some(Duty::Keeper(duty)) => duty,
        _ => panic!("no keeper duty for {parent:?}"),
    }
}

pub fn keeper_mut(orch: &mut ReshapeOrchestrator, parent: ShardId) -> &mut KeeperDuty {
    match orch.duties.get_mut(&parent) {
        Some(Duty::Keeper(duty)) => duty,
        _ => panic!("no keeper duty for {parent:?}"),
    }
}

pub fn vid(id: u64) -> ValidatorId {
    ValidatorId::new(id)
}

/// The orchestrator's local clock at `ms`. Only the ready-assertion
/// schedule reads it; every other step is clock independent, so tests
/// that aren't about pacing pump at a fixed instant.
pub fn at(ms: u64) -> LocalTimestamp {
    LocalTimestamp::from_millis(ms)
}

/// A non-zero anchor whose `prev` height is a valid terminal.
pub fn anchor() -> ShardAnchor {
    anchor_at(WeightedTimestamp::ZERO)
}

/// [`anchor`] windowed at `wt` — the value a ready signal cuts its
/// validity window from, and so what distinguishes one assertion from
/// a re-assertion of the same thing.
pub fn anchor_at(wt: WeightedTimestamp) -> ShardAnchor {
    ShardAnchor {
        state_root: StateRoot::ZERO,
        block_hash: BlockHash::from_raw(Hash::from_bytes(b"seeded-boundary")),
        height: BlockHeight::new(8),
        weighted_timestamp: wt,
        witness_base: BeaconWitnessLeafCount::ZERO,
        terminal_settled_txs: None,
        handoff_complete: None,
        terminal_epoch: None,
    }
}

/// A schedule headed by `snapshot`, cut into one-second windows.
pub fn windowed(snapshot: &TopologySnapshot) -> TopologySchedule {
    TopologySchedule::new(
        EpochWindows::new(0, 1_000),
        Epoch::GENESIS,
        Arc::new(snapshot.clone()),
    )
}

/// Project a snapshot with the given committees, observer cohort seats
/// `(parent, validator, child)` none of which the beacon has credited,
/// and seeded boundaries.
pub fn snapshot(
    committees: &[(ShardId, &[u64])],
    cohort: &[(ShardId, u64, ShardId)],
    seeded: &[ShardId],
) -> TopologySnapshot {
    snapshot_with_ready(committees, &uncredited(cohort), seeded)
}

/// [`snapshot`] with each observer seat's credited readiness spelled
/// out: `(parent, validator, child, ready)`.
pub fn snapshot_with_ready(
    committees: &[(ShardId, &[u64])],
    cohort: &[(ShardId, u64, ShardId, bool)],
    seeded: &[ShardId],
) -> TopologySnapshot {
    build(committees, cohort, &[], &[], seeded, anchor())
}

/// Project a snapshot with keeper cohort seats `(child, validator, parent)`.
pub fn snapshot_keepers(
    committees: &[(ShardId, &[u64])],
    keepers: &[(ShardId, u64, ShardId)],
    seeded: &[ShardId],
) -> TopologySnapshot {
    snapshot_keepers_with_ready(committees, &uncredited(keepers), seeded)
}

/// [`snapshot_keepers`] with each keeper seat's credited readiness
/// spelled out: `(child, validator, parent, ready)`.
pub fn snapshot_keepers_with_ready(
    committees: &[(ShardId, &[u64])],
    keepers: &[(ShardId, u64, ShardId, bool)],
    seeded: &[ShardId],
) -> TopologySnapshot {
    build(committees, &[], keepers, &[], seeded, anchor())
}

/// Seat triples as the beacon projects them before any `ReshapeReady`
/// has folded.
pub fn uncredited(seats: &[(ShardId, u64, ShardId)]) -> Vec<(ShardId, u64, ShardId, bool)> {
    seats.iter().map(|&(a, v, b)| (a, v, b, false)).collect()
}

/// Project a snapshot with parent-half cohort seats `(child, validator,
/// parent)`.
pub fn snapshot_parent_halves(
    committees: &[(ShardId, &[u64])],
    parent_halves: &[(ShardId, u64, ShardId)],
    seeded: &[ShardId],
) -> TopologySnapshot {
    build(committees, &[], &[], parent_halves, seeded, anchor())
}

pub fn build(
    committees: &[(ShardId, &[u64])],
    observers: &[(ShardId, u64, ShardId, bool)],
    keepers: &[(ShardId, u64, ShardId, bool)],
    parent_halves: &[(ShardId, u64, ShardId)],
    seeded: &[ShardId],
    boundary: ShardAnchor,
) -> TopologySnapshot {
    build_split_pending(
        committees,
        observers,
        keepers,
        parent_halves,
        seeded,
        boundary,
        &[],
    )
}

/// [`build`] with the shards whose admitted split has not executed.
pub fn build_split_pending(
    committees: &[(ShardId, &[u64])],
    observers: &[(ShardId, u64, ShardId, bool)],
    keepers: &[(ShardId, u64, ShardId, bool)],
    parent_halves: &[(ShardId, u64, ShardId)],
    seeded: &[ShardId],
    boundary: ShardAnchor,
    split_pending: &[ShardId],
) -> TopologySnapshot {
    let mut ids: BTreeSet<u64> = BTreeSet::new();
    for (_, members) in committees {
        ids.extend(members.iter().copied());
    }
    for (_, v, _, _) in observers.iter().chain(keepers) {
        ids.insert(*v);
    }
    for (_, v, _) in parent_halves {
        ids.insert(*v);
    }
    let validators: Vec<ValidatorInfo> = ids
        .iter()
        .map(|&id| ValidatorInfo {
            validator_id: vid(id),
            public_key: BlsSigner::generate().public_key(),
        })
        .collect();
    let committee_map: HashMap<ShardId, Vec<ValidatorId>> = committees
        .iter()
        .map(|(s, members)| (*s, members.iter().map(|&m| vid(m)).collect()))
        .collect();
    let mut observer_cohorts: BTreeMap<ShardId, BTreeMap<ValidatorId, ReshapeSeat>> =
        BTreeMap::new();
    for (parent, v, child, ready) in observers {
        observer_cohorts.entry(*parent).or_default().insert(
            vid(*v),
            ReshapeSeat {
                shard: *child,
                ready: *ready,
            },
        );
    }
    let mut keeper_cohorts: BTreeMap<ShardId, BTreeMap<ValidatorId, ReshapeSeat>> = BTreeMap::new();
    for (child, v, parent, ready) in keepers {
        keeper_cohorts.entry(*child).or_default().insert(
            vid(*v),
            ReshapeSeat {
                shard: *parent,
                ready: *ready,
            },
        );
    }
    let mut parent_half_cohorts: BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>> =
        BTreeMap::new();
    for (child, v, parent) in parent_halves {
        parent_half_cohorts
            .entry(*child)
            .or_default()
            .insert(vid(*v), *parent);
    }
    TopologySnapshot::from_explicit_committees(
        NetworkDefinition::simulator(),
        &ValidatorSet::new(validators),
        committee_map.clone(),
        committee_map,
        seeded.iter().map(|&s| (s, boundary)).collect(),
        HashMap::new(),
        observer_cohorts,
        keeper_cohorts,
        parent_half_cohorts,
        split_pending.iter().copied().collect(),
    )
}

pub fn observer_duty(
    parent: ShardId,
    child: ShardId,
    validator: u64,
    phase: ObserverPhase,
) -> ObserverDuty {
    ObserverDuty {
        parent,
        child,
        validators: vec![vid(validator)],
        phase,
        open_requested: true,
        store_opened: true,
        stages: StageQueue::default(),
        adopted_genesis: None,
        ready_asserts: BTreeMap::new(),
    }
}

pub fn following(tail: ObserverTail) -> ObserverPhase {
    ObserverPhase::Following(Box::new(tail))
}

/// The block fetch in `requests`, if any.
pub fn follow_fetch(requests: &[ReshapeRequest]) -> Option<BlockHeight> {
    requests.iter().find_map(|r| match r {
        ReshapeRequest::Fetch {
            kind: FetchKind::Block { request },
            ..
        } => Some(request.height),
        _ => None,
    })
}

/// The blocks `requests` asks the store to apply.
pub fn follow_applies(requests: &[ReshapeRequest]) -> Vec<BlockHash> {
    requests
        .iter()
        .filter_map(|r| match r {
            ReshapeRequest::ApplyFollow { block, .. } => Some(block.hash()),
            _ => None,
        })
        .collect()
}

/// A one-window schedule seating `committee` on `shard`, with the
/// observer cohort seats `(validator, child)` of `shard`'s pending
/// split. Every stamp a test signs below one second sits inside that
/// window.
pub fn committee_schedule(
    shard: ShardId,
    committee: &TestCommittee,
    observers: &[(u64, ShardId)],
) -> TopologySchedule {
    let validators: Vec<ValidatorInfo> = (0..committee.size())
        .map(|i| ValidatorInfo {
            validator_id: committee.validator_id(i),
            public_key: *committee.public_key(i),
        })
        .collect();
    let members: Vec<ValidatorId> = committee.validator_ids().to_vec();
    let snap = TopologySnapshot::from_explicit_committees(
        NetworkDefinition::simulator(),
        &ValidatorSet::new(validators),
        HashMap::from([(shard, members.clone())]),
        HashMap::from([(shard, members)]),
        BTreeMap::new(),
        HashMap::new(),
        BTreeMap::from([(
            shard,
            observers
                .iter()
                .map(|&(validator, child)| {
                    (
                        vid(validator),
                        ReshapeSeat {
                            shard: child,
                            ready: false,
                        },
                    )
                })
                .collect(),
        )]),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
    );
    windowed(&snap)
}

/// An unsigned block at height 1 and the attested anchor naming it.
pub fn anchored_block() -> (Block, ShardAnchor) {
    let block = make_test_block(BlockHeight::new(1));
    let anchor = ShardAnchor {
        block_hash: block.hash(),
        height: BlockHeight::new(1),
        ..anchor()
    };
    (block, anchor)
}

pub fn refetch_ms() -> u64 {
    u64::try_from(REFETCH_WAIT.as_millis()).expect("fits")
}

/// A transaction a block carries as decoded, with nothing derived.
pub fn carrying_an_underived_transaction(block: Block) -> Block {
    install_stub_protocol_statics();
    let payer = PrincipalAddr::new([0x11; 31]);
    let routed = stub_transaction(
        payer,
        &[payer.address()],
        1_000,
        TimestampRange::new(
            WeightedTimestamp::ZERO,
            WeightedTimestamp::from_millis(60_000),
        ),
    );
    let decoded = Transaction::new(routed.body().clone());
    assert!(!decoded.is_routed());
    let Block::Live {
        header,
        certificates,
        provisions,
        abandonment_records,
        state_claims,
        tick_manifest,
        terms,
        witness_sources,
        ..
    } = block
    else {
        unreachable!("the fixture builds a live block")
    };
    Block::Live {
        header,
        transactions: Arc::new(Capped::from_array([Arc::new(Verifiable::from(decoded))])),
        certificates,
        provisions,
        abandonment_records,
        state_claims,
        tick_manifest,
        terms,
        witness_sources,
    }
}

/// A parent half recognizing `parent`'s terminal above `anchor`,
/// the parent's cut published at 150ms.
pub fn recognizing_parent_half(
    parent: ShardId,
    child: ShardId,
    anchor: ShardAnchor,
) -> ReshapeOrchestrator {
    let mut tail = ObserverTail::recognizing(anchor, child);
    tail.set_terminal_cut(Some(WeightedTimestamp::from_millis(150)));
    let mut orch = ReshapeOrchestrator::new(vec![vid(50)]);
    insert_parent_half(
        &mut orch,
        child,
        ParentHalfDuty {
            parent,
            child,
            validators: vec![vid(50)],
            phase: ParentHalfPhase::Recognizing(Box::new(tail)),
            store_seeded: false,
        },
    );
    orch
}

/// The headers answer a recognizing walk of `parent` takes, each
/// header served with a quorum of `committee`'s QC over it.
pub fn walked(
    child: ShardId,
    parent: ShardId,
    committee: &TestCommittee,
    blocks: &[&Block],
) -> ReshapeEvent {
    let headers = blocks
        .iter()
        .map(|block| {
            CertifiedBlockHeader::new(
                block.header().clone(),
                committee.sign_qc(
                    block.header(),
                    &committee.quorum_indices(),
                    WeightedTimestamp::from_millis(900),
                ),
            )
        })
        .collect();
    ReshapeEvent::Fetched {
        duty: child,
        from: parent,
        kind: FetchedKind::Headers {
            response: Box::new(GetRemoteHeadersResponse::of(
                Capped::new(headers).expect("within one request"),
            )),
        },
    }
}

/// The first height of each header fetch in `requests`.
pub fn header_fetches_from(requests: &[ReshapeRequest]) -> Vec<BlockHeight> {
    requests
        .iter()
        .filter_map(|r| match r {
            ReshapeRequest::Fetch {
                kind: FetchKind::Headers { request },
                ..
            } => Some(request.from_height),
            _ => None,
        })
        .collect()
}

pub fn seeds_through(requests: &[ReshapeRequest]) -> Option<BlockHeight> {
    requests.iter().find_map(|r| match r {
        ReshapeRequest::SeedFromParent { through, .. } => Some(*through),
        _ => None,
    })
}

/// An observer duty in `Following`, ready to assert against `parent`.
pub fn following_observer(parent: ShardId, child: ShardId) -> ReshapeOrchestrator {
    let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
    insert_observer(
        &mut orch,
        child,
        observer_duty(
            parent,
            child,
            5,
            following(ObserverTail::new(anchor(), child)),
        ),
    );
    orch
}

/// The observed child of [`overtaken_follower`]: anchored at a height
/// the follow, still at the parent's anchor, has not reached.
pub fn overtaking_view(parent_halves: &[(ShardId, u64, ShardId)]) -> TopologySchedule {
    let parent = ShardId::ROOT;
    let (child, _) = parent.children();
    let child_anchor = ShardAnchor {
        height: BlockHeight::new(20),
        ..anchor()
    };
    let snap = build(
        &[(child, &[1, 5, 6])],
        &[],
        &[],
        parent_halves,
        &[],
        anchor(),
    )
    .with_boundaries(BTreeMap::from([(parent, anchor()), (child, child_anchor)]));
    windowed(&snap)
}

/// A host running `me` whose observer seat 5 follows ROOT's split into
/// its left child.
pub fn overtaken_follower(me: &[u64]) -> ReshapeOrchestrator {
    let parent = ShardId::ROOT;
    let (child, _) = parent.children();
    let mut orch = ReshapeOrchestrator::new(me.iter().map(|&id| vid(id)).collect());
    insert_observer(
        &mut orch,
        child,
        observer_duty(
            parent,
            child,
            5,
            following(ObserverTail::new(anchor(), child)),
        ),
    );
    orch
}

/// [`snapshot`] with `parent`'s split cut scheduled for the window
/// after genesis.
pub fn scheduled_split(
    committees: &[(ShardId, &[u64])],
    cohort: &[(ShardId, u64, ShardId)],
    seeded: &[ShardId],
    parent: ShardId,
) -> TopologySnapshot {
    let (observers, keepers) = (uncredited(cohort), Vec::new());
    build_split_pending(
        committees,
        &observers,
        &keepers,
        &[],
        seeded,
        anchor(),
        &[parent],
    )
    .with_scheduled_terminals(BTreeMap::from([(parent, Epoch::new(1))]))
}

/// A seated observer duty holding `adopted` as the genesis it flipped on.
pub fn adopted_duty(parent: ShardId, child: ShardId, adopted: BlockHash) -> ObserverDuty {
    ObserverDuty {
        adopted_genesis: Some(adopted),
        ..observer_duty(parent, child, 5, ObserverPhase::Seat(SeatTail::Seated))
    }
}

/// The block fetches a duty emitted from `from`, as their requests.
pub fn block_fetches(requests: &[ReshapeRequest], from_shard: ShardId) -> Vec<GetBlockRequest> {
    requests
        .iter()
        .filter_map(|r| match r {
            ReshapeRequest::Fetch {
                from,
                kind: FetchKind::Block { request },
                ..
            } if *from == from_shard => Some(request.clone()),
            _ => None,
        })
        .collect()
}
