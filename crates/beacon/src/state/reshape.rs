//! Split observer-cohort lifecycle: the admission-time draw, the
//! release that returns a cancelled reshape's cohort to the pool, and
//! the readiness-gated execution that mutates the shard trie.
//!
//! A pending split is staffed before it executes: admission draws a
//! committee-size cohort from the free pool, assigns each member the
//! child it will sync, and carries them on the splitting shard's
//! lookahead committee as `Observing` members — visible to serving and
//! gossip, never to the consensus subset, so the shard's quorum stays
//! at target size for the whole grow. The cut is scheduled at the first
//! fold where each child's ready membership — its parent half, computed
//! at that fold, plus its ready cohort — reaches quorum and the shard
//! has said no row of it hears, which it can say only once an earlier
//! such fold has latched its drain; the reshaped trie rides the lookahead
//! of the fold at the cut, so the children's committees are known a full
//! epoch before their window opens.

use std::collections::BTreeMap;

use blake3::Hasher;
use hyperscale_types::{
    BeaconState, BeaconWitnessLeafCount, BlockHash, BlockHeight, CohortSeat, DeclaredWork, Epoch,
    KeeperSeat, PendingReshape, Randomness, ScheduledSplit, ShardBoundary, ShardCommittee, ShardId,
    StateRoot, ValidatorId, ValidatorStatus, WeightedTimestamp, byzantine_threshold,
};
use rand::RngExt;
use rand_chacha::ChaCha20Rng;

use crate::sampling::prng_from;
use crate::state::committee::abort_rotations;

/// Domain tag for the cohort draw + child assignment seed. Distinct
/// from the parent-half and keeper tags so the reshape PRNG streams
/// never collide. The cohort stream seeds on the split's frozen
/// `cohort_seed` (not the running `(randomness, epoch)`), so a re-staff
/// after a lapse re-derives an identical cohort.
const DOMAIN_RESHAPE_COHORT: &[u8] = b"hyperscale-reshape-cohort-v1";

/// Domain tag for the execution-fold parent-half assignment seed.
const DOMAIN_RESHAPE_PARENT_HALF: &[u8] = b"hyperscale-reshape-parent-half-v1";

/// Domain tag for the pairing-time merge keeper draw seed.
const DOMAIN_RESHAPE_KEEPER: &[u8] = b"hyperscale-reshape-keeper-v1";

/// Draw a committee-size observer cohort for the pending split of
/// `target` from the free pool, assigning the first shuffled half to
/// the left child and the rest to the right.
///
/// The caller has already passed the pool gate (`drawable_pool_len(1) ≥
/// shard_size`). Each drawn validator becomes `Observing { shard: target }`
/// and joins the target's lookahead committee; the returned seats record
/// the child assignments with `ready: false`.
///
/// `cohort_seed` is the split's frozen entropy — the same value the
/// record carries for its whole life — so re-staffing a lapsed split
/// over an unchanged free pool reproduces the exact selection and child
/// assignment, leaving an observer's already-synced child in place.
pub(super) fn draw_split_cohort(
    state: &mut BeaconState,
    target: ShardId,
    cohort_seed: &Randomness,
) -> BTreeMap<ValidatorId, CohortSeat> {
    let mut pool = state.pooled_validators();
    let size = state.chain_config.shard_size as usize;
    debug_assert!(pool.len() >= size, "caller enforces the pool gate");

    let mut prng = cohort_prng(cohort_seed, target);
    shuffle(&mut pool, &mut prng);
    pool.truncate(size);

    let (left, right) = target.children();
    let mut cohort = BTreeMap::new();
    for (i, id) in pool.into_iter().enumerate() {
        let child = if i < size.div_ceil(2) { left } else { right };
        cohort.insert(
            id,
            CohortSeat {
                child,
                ready: false,
            },
        );
        state
            .validators
            .get_mut(&id)
            .expect("drawn from the derived pool, must be in validators")
            .status = ValidatorStatus::Observing {
            shard: target,
            placed_at_epoch: state.current_epoch,
        };
        state
            .next_shard_committees
            .entry(target)
            .or_default()
            .members
            .push(id);
    }
    cohort
}

/// Draw the keeper committee for a now-paired merge of `parent`'s two
/// children: half the merged committee from each child, preferring ready
/// members and backfilling from the not-yet-ready half, seeded like every
/// reshape draw.
///
/// Keepers stay `OnShard` on their child for the whole grow — they keep
/// running that chain and hard-link the merged store from it — so the
/// draw changes no statuses; it records seats the execution gate reads
/// and the shuffle pins. The non-keeper half of each child returns to
/// the pool at the boundary.
///
/// The left child contributes the larger half on an odd target size, so
/// the two halves total exactly the committee target.
pub(super) fn draw_merge_keepers(
    state: &BeaconState,
    parent: ShardId,
) -> BTreeMap<ValidatorId, KeeperSeat> {
    let size = state.chain_config.shard_size as usize;
    let (left, right) = parent.children();
    let mut keepers = BTreeMap::new();
    for (child, take) in [(left, size.div_ceil(2)), (right, size / 2)] {
        let on_child = |id: &ValidatorId, want_ready: bool| {
            matches!(
                state.validators.get(id).map(|r| r.status),
                Some(ValidatorStatus::OnShard { shard, ready, .. })
                    if shard == child && ready == want_ready
            )
        };
        let members = state
            .next_shard_committees
            .get(&child)
            .map_or(&[][..], |committee| committee.members.as_slice());
        let mut ready: Vec<ValidatorId> = members
            .iter()
            .copied()
            .filter(|id| on_child(id, true))
            .collect();
        let mut backfill: Vec<ValidatorId> = members
            .iter()
            .copied()
            .filter(|id| on_child(id, false))
            .collect();
        ready.sort_unstable();
        backfill.sort_unstable();
        let mut prng = reshape_prng(DOMAIN_RESHAPE_KEEPER, state, child);
        shuffle(&mut ready, &mut prng);
        shuffle(&mut backfill, &mut prng);
        // Prefer ready keepers — they hold a synced child half and can
        // hard-link the merged store at once — then fill any shortfall from
        // the not-yet-ready half so the reformed committee reaches `take`
        // even when a member's `Ready` witness has not folded by the pairing
        // fold. A backfilled keeper seats `OnShard` and completes via the
        // normal `Ready` path; the execution gate still holds the merge until
        // a `2f+1` keeper quorum is ready.
        let mut drawn = ready;
        drawn.truncate(take);
        if drawn.len() < take {
            drawn.extend(backfill.into_iter().take(take - drawn.len()));
        }
        for id in drawn {
            keepers.insert(
                id,
                KeeperSeat {
                    child,
                    ready: false,
                },
            );
        }
    }
    keepers
}

/// Return a split's `cohort` to the pool: each observer leaves the
/// target's lookahead committee and goes back to `Pooled`. Used both
/// when a split is abandoned (cohort dropped with the record) and when
/// it lapses (cohort emptied, record kept). A merge's keepers never
/// left their child committees, so a cancelled merge releases nothing.
pub(super) fn release_cohort(
    state: &mut BeaconState,
    target: ShardId,
    cohort: &BTreeMap<ValidatorId, CohortSeat>,
) {
    if let Some(committee) = state.next_shard_committees.get_mut(&target) {
        committee.members.retain(|m| !cohort.contains_key(m));
    }
    for id in cohort.keys() {
        let Some(rec) = state.validators.get_mut(id) else {
            continue;
        };
        if matches!(rec.status, ValidatorStatus::Observing { shard, .. } if shard == target) {
            rec.status = ValidatorStatus::Pooled;
        }
    }
}

/// Empty a lapsed split's cohort and return its observers to the pool,
/// keeping the record (and its frozen `cohort_seed`) so a re-assertion
/// before the readiness TTL re-staffs the identical cohort.
pub(super) fn lapse_split(state: &mut BeaconState, target: ShardId) {
    let Some(PendingReshape::Split { cohort, .. }) = state.pending_reshapes.get_mut(&target) else {
        return;
    };
    let drained = std::mem::take(cohort);
    release_cohort(state, target, &drained);
}

/// Schedule every pending split whose readiness gate is met, fixing the
/// cut one window out.
///
/// Per pending split, each fold: the parent half is computed here, over
/// the then-current consensus membership (shuffle, refill, and jail
/// replacement ran on the parent through the whole grow, so there are
/// no dangling assignments to repair), and the gate asks that each
/// child's ready membership — its parent half, ready by construction,
/// plus its ready cohort seats — reach `2f+1` of the committee target.
/// The first fold where both children pass latches the drain and
/// schedules nothing; on a later fold where both pass and the target has
/// said it is quiet, the carve and the cut are frozen onto the record and
/// the parent's boundary takes its terminal mark; [`apply_scheduled_splits`]
/// does the rest a window later.
///
/// The cut is the *next* window, never this one. A proposer decides
/// whether to stamp its boundary verdicts from its own window's frozen
/// projection, so a cut named for the window this fold opens would reach
/// that window's proposers only after they had already needed it — and
/// would land after the promotion freeze that window's schedule entry is
/// re-derived from.
///
/// Runs after the shuffle step so the assignment reads post-rotation
/// membership and the children first shuffle one epoch after they
/// form; reads the epoch's freshly rolled randomness.
pub(super) fn schedule_ready_splits(state: &mut BeaconState) {
    let targets: Vec<ShardId> = state
        .pending_reshapes
        .iter()
        .filter(|(_, r)| {
            matches!(r, PendingReshape::Split { .. }) && r.scheduled_terminal().is_none()
        })
        .map(|(target, _)| *target)
        .collect();
    for target in targets {
        // A rotation in flight holds a spare seat on the parent — its
        // entrant beside the victim it replaces — and a carve over both
        // seats a child one member more than its committee has seats,
        // with no rotation left to retire either. Cancel
        // the rotation rather than wait it out: a split's readiness TTL
        // is far shorter than the sync window a rotation may run for, so
        // holding the gate would abandon the split and re-draw its cohort
        // on a loop until the seat swap finished. The entrant gives up a
        // partial sync of a committee that is about to be re-carved
        // anyway.
        abort_rotations(state, target);
        try_schedule_split(state, target);
    }
}

/// Apply every scheduled split whose cut has arrived, mutating the trie
/// into the lookahead committee set.
///
/// The parent's lookahead committee is replaced by the two children's:
/// parent-half members keep their ready flag and placement epoch under
/// the new shard, cohort members are placed with the readiness their
/// `ReshapeReady` folded (stragglers complete via the normal `Ready` path
/// after the boundary). The children gain pending placeholder boundary
/// records — the beacon cannot derive child state roots (`r_p` is a
/// one-way hash of them), so the records fill from the parent's
/// final-epoch `split_child_roots` delivery; until then they don't
/// project as snap-sync anchors. The parent's boundary record stays for
/// its terminal-epoch contribution and witness drain.
///
/// This fold owns the parent's final window, so the children enter the
/// lookahead for the window that opens at the parent's cut.
pub(super) fn apply_scheduled_splits(state: &mut BeaconState) {
    let due: Vec<ShardId> = state
        .pending_reshapes
        .iter()
        .filter(|(_, r)| {
            matches!(r, PendingReshape::Split { .. })
                && r.scheduled_terminal()
                    .is_some_and(|terminal| terminal <= state.current_epoch)
        })
        .map(|(target, _)| *target)
        .collect();
    for target in due {
        apply_scheduled_split(state, target);
    }
}

/// The zero-hash placeholder a reshape leaves on a not-yet-live shard's
/// boundary — a split child or a composing merge parent. The zero block hash
/// keeps it from projecting as a snap-sync anchor until the shard's genesis
/// lands: a split child's seed from the parent's terminal, or a merge
/// parent's composition from both children's terminals.
///
/// `begins_above` is the highest height recorded for the shards the
/// reshape ends. The successor's chain continues their height line from
/// their terminals, so every block of it sits above that height, and the
/// record takes no block at or below it.
///
/// `epoch` is the applying fold's, whose lookahead is the first window to
/// run the successor, so the record names the next epoch as its
/// formation.
const fn pending_placeholder_boundary(epoch: Epoch, begins_above: BlockHeight) -> ShardBoundary {
    ShardBoundary {
        boundary_qc: None,
        state_root: StateRoot::ZERO,
        block_hash: BlockHash::ZERO,
        height: begins_above,
        weighted_timestamp: WeightedTimestamp::ZERO,
        witness_leaf_count: BeaconWitnessLeafCount::ZERO,
        witness_base: BeaconWitnessLeafCount::ZERO,
        cumulative_fees: 0,
        used: DeclaredWork::ZERO,
        blocks: 0,
        substate_bytes: 0,
        formed: epoch.next(),
        last_live_epoch: epoch,
        consecutive_misses: 0,
        terminal_epoch: None,
        handoff_complete: None,
        terminal_delivered: false,
        terminal_settled_txs: None,
        reshape_admitted_epoch: None,
    }
}

fn try_schedule_split(state: &mut BeaconState, target: ShardId) {
    let Some(PendingReshape::Split { cohort, .. }) = state.pending_reshapes.get(&target) else {
        return;
    };
    let (left, right) = target.children();
    debug_assert!(
        !state.terminal_record_stands(left) && !state.terminal_record_stands(right),
        "a split was admitted onto a child id whose terminal record stands",
    );

    // The parent half, assigned over the consensus membership as it
    // stands at this fold — observers are not parent members.
    let mut parent_members: Vec<ValidatorId> = state
        .next_shard_committees
        .get(&target)
        .map_or_default(|committee| {
            committee
                .members
                .iter()
                .copied()
                .filter(|id| {
                    matches!(
                        state.validators.get(id).map(|r| r.status),
                        Some(ValidatorStatus::OnShard { shard, .. }) if shard == target
                    )
                })
                .collect()
        });
    parent_members.sort_unstable();
    let mut prng = reshape_prng(DOMAIN_RESHAPE_PARENT_HALF, state, target);
    shuffle(&mut parent_members, &mut prng);
    let (left_half, right_half) = parent_members.split_at(parent_members.len().div_ceil(2));

    // The gate: the parent half's ready members (a ready parent member
    // holds the parent's state, the same liveness trust the beacon
    // extends to any committee it forms) plus ready cohort seats, at
    // 2f+1 of the committee target per child. An unready parent member —
    // a refill or a straggler still syncing the parent — rides the carve
    // but counts toward no child's quorum.
    let quorum = 2 * byzantine_threshold(state.chain_config.shard_size as usize) + 1;
    let ready_seats = |child: ShardId| {
        cohort
            .values()
            .filter(|seat| seat.child == child && seat.ready)
            .count()
    };
    let ready_half = |half: &[ValidatorId]| {
        half.iter()
            .filter(|id| {
                matches!(
                    state.validators.get(id).map(|r| r.status),
                    Some(ValidatorStatus::OnShard { ready: true, .. })
                )
            })
            .count()
    };
    if ready_half(left_half) + ready_seats(left) < quorum
        || ready_half(right_half) + ready_seats(right) < quorum
    {
        return;
    }
    let halves = BTreeMap::from([(left, left_half.to_vec()), (right, right_half.to_vec())]);
    if !drained(state, target) {
        return;
    }
    let terminal = state.current_epoch.next();
    tracing::info!(
        shard = ?target,
        terminal = terminal.inner(),
        "Shard split readiness gate met; scheduling the cut"
    );

    let Some(PendingReshape::Split {
        scheduled,
        admitted,
        ..
    }) = state.pending_reshapes.get_mut(&target)
    else {
        unreachable!("pending split read above");
    };
    let admitted_at = admitted.at;
    *scheduled = Some(ScheduledSplit { terminal, halves });

    // The parent's chain terminates at `terminal`'s cut and the children
    // take over from the lookahead. The mark keeps the boundary record
    // sourced (for the terminal contribution that seeds the children, and
    // the witness drain) without counting the dead chain as missing — and
    // it is what the window projection freezes for the parent's proposers
    // to stamp their boundary verdicts from.
    let boundary = state
        .boundaries
        .get_mut(&target)
        .expect("a shard asserts its split in a crossing folded under its record");
    boundary.terminal_epoch = Some(terminal);
    boundary.reshape_admitted_epoch = Some(admitted_at);
}

/// Whether the pending reshape of `target`, whose readiness gate passed
/// in this fold, may schedule its cut: its drain has latched and its
/// shard, or both of a merge's children, asserted quiet under it.
///
/// The first fold whose gate passes latches the drain instead, setting
/// the deadline [`reshape_drain_epochs`] out, and schedules nothing: the
/// windows that show the latch pause intake toward the shard, and only
/// an assertion made under one of them may say it is quiet. A latched
/// record whose gate stops passing waits, and cancels at its deadline.
///
/// [`reshape_drain_epochs`]: hyperscale_types::BeaconChainConfig::reshape_drain_epochs
fn drained(state: &mut BeaconState, target: ShardId) -> bool {
    let drain_by = state
        .current_epoch
        .saturating_add(state.chain_config.reshape_drain_epochs());
    let (admitted, quiet) = match state.pending_reshapes.get_mut(&target) {
        Some(PendingReshape::Split {
            admitted, quiet, ..
        }) => (admitted, *quiet),
        Some(PendingReshape::Merge {
            admitted: Some(admitted),
            halves,
            ..
        }) => (
            admitted,
            halves.len() == 2 && halves.values().all(|half| half.quiet),
        ),
        Some(PendingReshape::Merge { admitted: None, .. }) | None => return false,
    };
    if admitted.drain_by.is_none() {
        admitted.drain_by = Some(drain_by);
        tracing::info!(
            ?target,
            drain_by = drain_by.inner(),
            "Reshape readiness gate met; draining until its shard asserts quiet"
        );
        return false;
    }
    quiet
}

fn apply_scheduled_split(state: &mut BeaconState, target: ShardId) {
    let Some(PendingReshape::Split {
        cohort,
        scheduled: Some(ScheduledSplit { halves, .. }),
        ..
    }) = state.pending_reshapes.remove(&target)
    else {
        unreachable!("scheduled split read above");
    };
    tracing::info!(shard = ?target, "Shard split cut reached; reshaping the trie");
    state.next_shard_committees.remove(&target);
    // The parent's seats are re-carved between its children, so a pair
    // naming one of them has nothing left to retire.
    state.pending_rotations.remove(&target);
    // The parent's record stands from the fold that scheduled the cut
    // until its children are live.
    let begins_above = state.boundaries[&target].height;

    for (child, half) in halves {
        // Child committee: the parent half in assignment order, then
        // the cohort half in id order. A half member jailed or withdrawn
        // since the carve was frozen is dropped here rather than moved —
        // the schedule cannot be retracted to re-gate around it, so the
        // child seats short and `top_up_committees` backfills it from the
        // pool past the recovery reserve, waiting while the reserve is at
        // least the pool.
        let assigned: Vec<ValidatorId> = half
            .into_iter()
            .chain(
                cohort
                    .iter()
                    .filter(|(_, seat)| seat.child == child)
                    .map(|(id, _)| *id),
            )
            .collect();

        let mut members: Vec<ValidatorId> = Vec::with_capacity(assigned.len());
        for id in assigned {
            // A cohort seat carries the readiness its `ReshapeReady` folded;
            // a parent-half member is ready by construction and holds none.
            // The two sets are disjoint — halves are filtered to the parent's
            // `OnShard` members and the cohort is drawn from the free pool —
            // so a half member reaching the observing arm has no seat to read,
            // and is dropped like any other drift rather than indexed for.
            let seat_ready = cohort.get(&id).map(|seat| seat.ready);
            let rec = state
                .validators
                .get_mut(&id)
                .expect("members come from committee/cohort state, must be in validators");
            rec.status = match (rec.status, seat_ready) {
                (
                    ValidatorStatus::OnShard {
                        shard,
                        ready,
                        placed_at_epoch,
                    },
                    _,
                ) if shard == target => ValidatorStatus::OnShard {
                    shard: child,
                    ready,
                    placed_at_epoch,
                },
                (ValidatorStatus::Observing { .. }, Some(ready)) => ValidatorStatus::OnShard {
                    shard: child,
                    ready,
                    placed_at_epoch: state.current_epoch,
                },
                // Jailed, withdrawn, or rotated away since the carve was
                // frozen, or returned to the pool by a recovery of the
                // target. The schedule cannot be retracted to re-gate
                // around it, so the child seats short and
                // `top_up_committees` backfills it once the pool holds
                // members past the recovery reserve.
                _ => continue,
            };
            members.push(id);
            // Placement changed: the per-placement miss scope ends here.
            state.miss_counters.remove(&id);
        }

        state
            .next_shard_committees
            .insert(child, ShardCommittee { members });

        state.boundaries.insert(
            child,
            pending_placeholder_boundary(state.current_epoch, begins_above),
        );
    }
}

/// Schedule every paired merge whose readiness gate is met, fixing the
/// cut one window out.
///
/// Symmetric to [`schedule_ready_splits`], inverted: a merge keeps no
/// committee-liveness half — every keeper must sync the sibling half — so
/// the gate is simply the merged committee's ready keepers reaching
/// `2f+1` of the target. The first fold that passes latches the drain;
/// on a later fold that passes with both children quiet, both children's
/// boundaries take the same terminal mark, so they leave the trie on one
/// cut; [`apply_scheduled_merges`] does the rest a window later.
///
/// Only the cut is frozen here. A split must also freeze its carve, but a
/// merge's keepers were drawn when the halves paired and already live on
/// the record, and rotation skips them until the merge applies.
pub(super) fn schedule_ready_merges(state: &mut BeaconState) {
    let targets: Vec<ShardId> = state
        .pending_reshapes
        .iter()
        .filter(|(_, r)| {
            matches!(
                r,
                PendingReshape::Merge {
                    admitted: Some(_),
                    scheduled_terminal: None,
                    ..
                }
            )
        })
        .map(|(target, _)| *target)
        .collect();
    for target in targets {
        try_schedule_merge(state, target);
    }
}

/// Apply every scheduled merge whose cut has arrived, mutating the trie
/// into the lookahead committee set.
///
/// The parent's two children leave the lookahead and the parent takes
/// their place: keepers flip `OnShard` onto the parent with the readiness
/// their `ReshapeReady` folded (stragglers complete via the normal
/// `Ready` path), and the non-keeper half of each child returns to the
/// pool. The parent gains a pending placeholder until the beacon composes
/// its anchor from both children's terminal contributions.
pub(super) fn apply_scheduled_merges(state: &mut BeaconState) {
    let due: Vec<ShardId> = state
        .pending_reshapes
        .iter()
        .filter(|(_, r)| {
            matches!(r, PendingReshape::Merge { .. })
                && r.scheduled_terminal()
                    .is_some_and(|terminal| terminal <= state.current_epoch)
        })
        .map(|(target, _)| *target)
        .collect();
    for target in due {
        apply_scheduled_merge(state, target);
    }
}

fn try_schedule_merge(state: &mut BeaconState, parent: ShardId) {
    let Some(PendingReshape::Merge { keepers, .. }) = state.pending_reshapes.get(&parent) else {
        return;
    };
    debug_assert!(
        !state.terminal_record_stands(parent),
        "a merge was admitted onto a parent id whose terminal record stands",
    );
    let quorum = 2 * byzantine_threshold(state.chain_config.shard_size as usize) + 1;
    if keepers.values().filter(|seat| seat.ready).count() < quorum || !drained(state, parent) {
        return;
    }
    let terminal = state.current_epoch.next();
    tracing::info!(
        ?parent,
        terminal = terminal.inner(),
        "Shard merge readiness gate met; scheduling the cut"
    );

    let Some(PendingReshape::Merge {
        scheduled_terminal,
        admitted,
        ..
    }) = state.pending_reshapes.get_mut(&parent)
    else {
        unreachable!("pending merge read above");
    };
    let admitted_at = admitted.map(|admission| admission.at);
    *scheduled_terminal = Some(terminal);

    // Both children terminate on the same cut. The mark keeps each
    // boundary record sourced (for the contribution the beacon composes
    // into the parent anchor and the witness drain) without counting the
    // dead chain as missing, and is what each child's proposers read to
    // stamp their boundary verdicts.
    let children: [ShardId; 2] = parent.children().into();
    for child in children {
        let boundary = state
            .boundaries
            .get_mut(&child)
            .expect("a child asserts its half of a merge in a crossing folded under its record");
        boundary.terminal_epoch = Some(terminal);
        boundary.reshape_admitted_epoch = admitted_at;
    }
}

fn apply_scheduled_merge(state: &mut BeaconState, parent: ShardId) {
    let Some(PendingReshape::Merge { keepers, .. }) = state.pending_reshapes.remove(&parent) else {
        unreachable!("scheduled merge read above");
    };
    tracing::info!(?parent, "Shard merge cut reached; reshaping the trie");

    // Drop the children from the lookahead: keepers move to the parent
    // below, the rest return to the pool. The children's chains keep
    // running their in-flight window from the frozen active committee
    // until their terminal block.
    let children: [ShardId; 2] = parent.children().into();
    for child in children {
        // Keepers move to the parent and everyone else pools, so both
        // parties of any rotation on this child land in a placement of
        // their own and the pair has nothing left to say.
        state.pending_rotations.remove(&child);
        if let Some(committee) = state.next_shard_committees.remove(&child) {
            for id in committee.members {
                if keepers.contains_key(&id) {
                    continue;
                }
                if let Some(rec) = state.validators.get_mut(&id) {
                    rec.status = ValidatorStatus::Pooled;
                }
                state.miss_counters.remove(&id);
            }
        }
    }

    // The merged committee, keepers in id order, each now `OnShard` on
    // the parent carrying the readiness its `ReshapeReady` folded. A
    // keeper jailed, withdrawn, or rotated off its child since the cut was
    // scheduled is dropped rather than moved — the schedule cannot be
    // retracted to re-gate around it, so the parent seats short and
    // `top_up_committees` backfills it once the pool holds members past
    // the recovery reserve.
    let mut members: Vec<ValidatorId> = Vec::with_capacity(keepers.len());
    for (id, seat) in &keepers {
        let rec = state
            .validators
            .get_mut(id)
            .expect("keepers come from committee state, must be in validators");
        // Keepers keep their original placement epoch across the move —
        // they have been serving their child all along — so the parent's
        // pending placeholder doesn't exclude them from the beacon
        // committee (the `beacon_eligible` pending-anchor rule), which
        // would otherwise strand the beacon with no eligible signers the
        // moment every member left the children.
        let ValidatorStatus::OnShard {
            shard,
            placed_at_epoch,
            ..
        } = rec.status
        else {
            continue;
        };
        // The keeper must still be on one of the merging children. Moving a
        // validator that has rotated elsewhere would seat it on the parent
        // while its own shard still counts it.
        if !children.contains(&shard) {
            continue;
        }
        rec.status = ValidatorStatus::OnShard {
            shard: parent,
            ready: seat.ready,
            placed_at_epoch,
        };
        members.push(*id);
        // Placement changed: the per-placement miss scope ends here.
        state.miss_counters.remove(id);
    }
    state
        .next_shard_committees
        .insert(parent, ShardCommittee { members });

    // The parent's `r_p` is composed from the two terminal child anchors
    // once they fold; until then a zero block hash keeps the placeholder
    // from projecting as a snap-sync anchor. Both children's records stand
    // from the fold that scheduled the cut until the parent is live.
    let [left, right] = children.map(|child| state.boundaries[&child].height);
    let begins_above = left.max(right);
    state.boundaries.insert(
        parent,
        pending_placeholder_boundary(state.current_epoch, begins_above),
    );
}

/// PRNG bound to `(domain, randomness, epoch, shard)` — the seeding
/// discipline the parent-half and keeper draws share.
fn reshape_prng(domain: &[u8], state: &BeaconState, shard: ShardId) -> ChaCha20Rng {
    let mut h = Hasher::new();
    h.update(domain);
    h.update(state.randomness.as_bytes());
    h.update(&state.current_epoch.inner().to_le_bytes());
    h.update(&shard.inner().to_le_bytes());
    prng_from(h.finalize().as_bytes())
}

/// PRNG for the cohort draw, bound to `(cohort_seed, shard)` only — no
/// epoch — so re-staffing a lapsed split re-derives the identical
/// cohort. `cohort_seed` is the beacon randomness frozen at the split's
/// first admission, so the draw stays unbiasable while idempotent.
fn cohort_prng(cohort_seed: &Randomness, shard: ShardId) -> ChaCha20Rng {
    let mut h = Hasher::new();
    h.update(DOMAIN_RESHAPE_COHORT);
    h.update(cohort_seed.as_bytes());
    h.update(&shard.inner().to_le_bytes());
    prng_from(h.finalize().as_bytes())
}

/// Deterministic Fisher–Yates over `ids` driven by `prng`.
fn shuffle(ids: &mut [ValidatorId], prng: &mut ChaCha20Rng) {
    for i in (1..ids.len()).rev() {
        let j = prng.random_range(0..=i);
        ids.swap(i, j);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::ops::Range;
    use std::sync::Arc;

    use hyperscale_crypto_bls::BlsVerifier;
    use hyperscale_types::test_utils::test_pool;
    use hyperscale_types::{
        Address, AddressClass, Admission, Block, BlockHeader, BlockHeaderParts, Epoch,
        EpochWindows, Evidence, Formed, HALT_THRESHOLD_EPOCHS, Hash, RecoveryBinding,
        RecoveryCause, ReshapeKind, SettledTxsRoot, Settling, ShardFullness, ShardWitnessPayload,
        SplitChildRoots, Stake, StakePoolId, TERMINAL_EVIDENCE_EPOCHS, TopologySchedule,
        partner_evidence,
    };

    use super::*;
    use crate::state::committee::{recover_committees, top_up_committees};
    use crate::state::test_fixtures::{
        apply_next_epoch, apply_witness_chunk, assert_quiet, block_carrying, empty_state,
        fold_blocks, net, quiet_assertions, single_pool_state_at_genesis, validator_record,
    };
    use crate::state::witness::{apply_shard_payload, defer_reshape_ttls, prune_stale_reshapes};

    /// `single_pool_state_at_genesis(4)` — four ready members on
    /// `leaf(1, 0)`, promoted into the active slot too — plus `pooled`
    /// free validators, with a committee target of 4 (quorum 3).
    fn grow_state(pooled: u64) -> BeaconState {
        let mut state = single_pool_state_at_genesis(4);
        state.current_epoch = Epoch::new(5);
        state.chain_config.shard_size = 4;
        state.shard_committees = state.next_shard_committees.clone();
        for i in 0..pooled {
            let id = 1000 + i;
            state.validators.insert(
                ValidatorId::new(id),
                validator_record(id, 0, ValidatorStatus::Pooled),
            );
        }
        state
    }

    fn cohort_of(state: &BeaconState, target: ShardId) -> &BTreeMap<ValidatorId, CohortSeat> {
        let Some(PendingReshape::Split { cohort, .. }) = state.pending_reshapes.get(&target) else {
            panic!("no pending split for {target:?}");
        };
        cohort
    }

    /// An observer from the pending split's cohort assigned to `child`.
    fn observer_for(state: &BeaconState, target: ShardId, child: ShardId) -> ValidatorId {
        *cohort_of(state, target)
            .iter()
            .find(|(_, seat)| seat.child == child)
            .map(|(id, _)| id)
            .expect("cohort halves cover both children")
    }

    /// Drive a split through both of its folds: the readiness gate at the
    /// current epoch, then the trie change at the cut it schedules one
    /// window out. The epoch advances between them, as it does in
    /// `apply_epoch`, so a gate that holds simply leaves the record
    /// untouched and a gate that passes lands its reshape here.
    fn fold_split(state: &mut BeaconState) {
        schedule_quiet_splits(state);
        if advance_to_scheduled_cut(state) {
            apply_scheduled_splits(state);
        }
    }

    /// The merge counterpart of [`fold_split`].
    fn fold_merge(state: &mut BeaconState) {
        schedule_quiet_merges(state);
        if advance_to_scheduled_cut(state) {
            apply_scheduled_merges(state);
        }
    }

    /// The split schedulers a cut takes once its gate passes: the one
    /// that latches the drain, and, once the target has said it is quiet,
    /// the one that schedules the cut.
    fn schedule_quiet_splits(state: &mut BeaconState) {
        schedule_ready_splits(state);
        assert_quiet(state);
        schedule_ready_splits(state);
    }

    /// The merge counterpart of [`schedule_quiet_splits`].
    fn schedule_quiet_merges(state: &mut BeaconState) {
        schedule_ready_merges(state);
        assert_quiet(state);
        schedule_ready_merges(state);
    }

    /// Step to the cut a reshape just scheduled, reporting whether there
    /// was one. A gate that held schedules nothing and leaves the epoch
    /// where it was, so repeated folds don't drift it.
    fn advance_to_scheduled_cut(state: &mut BeaconState) -> bool {
        let Some(cut) = state
            .pending_reshapes
            .values()
            .filter_map(PendingReshape::scheduled_terminal)
            .max()
        else {
            return false;
        };
        state.current_epoch = cut;
        true
    }

    fn mark_ready(state: &mut BeaconState, target: ShardId, observer: ValidatorId) {
        let child = cohort_of(state, target)[&observer].child;
        apply_shard_payload(
            &BlsVerifier,
            state,
            &net(),
            target,
            &ShardWitnessPayload::ReshapeReady {
                validator: observer,
                child,
            },
        );
    }

    /// The gate holds until *each* child's parent half plus ready
    /// cohort reaches 2f+1 of the committee target; the first fold
    /// where both pass replaces the parent's lookahead committee with
    /// the two children's, partitions the parent membership, seats the
    /// cohort with its folded readiness, and creates pending
    /// placeholder boundary records.
    #[test]
    fn split_executes_only_when_each_child_reaches_quorum() {
        let p = ShardId::leaf(1, 0);
        let (left, right) = p.children();
        let mut state = grow_state(4);
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            p,
            &ShardWitnessPayload::ScheduleSplit {
                shard: p,
                epoch: Epoch::GENESIS,
                settling: None,
            },
        );
        let parent_members: BTreeSet<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let cohort: BTreeMap<ValidatorId, CohortSeat> = cohort_of(&state, p).clone();
        state.miss_counters.insert(ValidatorId::new(0), 2);

        // Nobody ready: each child sees only its parent half (2 < 3).
        fold_split(&mut state);
        assert!(state.pending_reshapes.contains_key(&p));
        assert!(state.next_shard_committees.contains_key(&p));

        // One child at quorum, the other not: still held.
        let left_observer = observer_for(&state, p, left);
        mark_ready(&mut state, p, left_observer);
        fold_split(&mut state);
        assert!(state.pending_reshapes.contains_key(&p));

        // Both children at 2 + 1 = 3 of 4: the trie reshapes.
        let right_observer = observer_for(&state, p, right);
        mark_ready(&mut state, p, right_observer);
        fold_split(&mut state);

        assert!(state.pending_reshapes.is_empty());
        assert!(!state.next_shard_committees.contains_key(&p));
        let left_members = state.next_shard_committees[&left].members.clone();
        let right_members = state.next_shard_committees[&right].members.clone();
        assert_eq!(left_members.len(), 4);
        assert_eq!(right_members.len(), 4);

        // The parent membership partitions across the children —
        // disjoint, complete — and every mover's status follows its
        // committee. Parent halves keep their flags and placement
        // epoch; cohort seats land with their folded readiness, placed
        // at the execution epoch.
        let mut seen: BTreeSet<ValidatorId> = BTreeSet::new();
        for (child, members) in [(left, &left_members), (right, &right_members)] {
            for id in members {
                assert!(seen.insert(*id), "{id:?} appears in both children");
                let status = state.validators[id].status;
                if parent_members.contains(id) {
                    assert_eq!(
                        status,
                        ValidatorStatus::OnShard {
                            shard: child,
                            ready: true,
                            placed_at_epoch: Epoch::GENESIS,
                        },
                    );
                } else {
                    let seat = cohort[id];
                    assert_eq!(seat.child, child);
                    assert_eq!(
                        status,
                        ValidatorStatus::OnShard {
                            shard: child,
                            ready: id == &left_observer || id == &right_observer,
                            placed_at_epoch: Epoch::new(6),
                        },
                    );
                }
            }
        }
        assert_eq!(seen.len(), 8);

        // Movers shed their per-placement miss scope; the children gain
        // pending placeholders that can't project as snap-sync anchors.
        assert!(!state.miss_counters.contains_key(&ValidatorId::new(0)));
        for child in [left, right] {
            let boundary = state.boundaries[&child].clone();
            assert_eq!(boundary.block_hash, BlockHash::ZERO);
            assert_eq!(boundary.last_live_epoch, Epoch::new(6));
        }
    }

    /// A not-yet-ready parent member counts toward the gate (ready by
    /// construction — committee-liveness trust) but carries its real
    /// flag onto the child, completing sync via the normal Ready path.
    /// The execution stamps the reshape's admission epoch onto the
    /// terminating parent's boundary record, and the live settled-window
    /// floor projection carries the parent across the whole lifecycle:
    /// from the pending record at admission, then from the boundary stamp
    /// once the record is consumed (the coast).
    /// A gate met inside a window schedules the terminal for the next
    /// one, after that window's projection was published, so the
    /// projection carries no terminal where the fold carries one — a
    /// reader keyed on `scheduled_terminal` answers differently from the
    /// two copies. The trie has no such gap: the cut lands a whole window
    /// after the gate, and every projection of the children's window is
    /// published after the gate has seated them.
    #[test]
    fn a_terminal_scheduled_inside_a_window_is_absent_from_that_windows_projection() {
        let p = ShardId::leaf(1, 0);
        let (left, right) = p.children();
        let mut state = grow_state(4);
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            p,
            &ShardWitnessPayload::ScheduleSplit {
                shard: p,
                epoch: Epoch::GENESIS,
                settling: None,
            },
        );
        let gate_epoch = state.current_epoch;
        // The next window's projection as the fold before the gate
        // published it.
        let published_before_the_gate = state.derive_next_topology_snapshot(net());
        let left_observer = observer_for(&state, p, left);
        mark_ready(&mut state, p, left_observer);
        let right_observer = observer_for(&state, p, right);
        mark_ready(&mut state, p, right_observer);
        schedule_quiet_splits(&mut state);
        let terminal = state
            .pending_reshapes
            .get(&p)
            .and_then(PendingReshape::scheduled_terminal)
            .expect("the gate schedules the cut");
        assert_eq!(
            terminal,
            gate_epoch.next(),
            "the parent's final window is the next one"
        );
        // What the fold into that window freezes: the live window as the
        // gate left it.
        let frozen_at_the_fold = state.derive_next_topology_snapshot(net());
        assert_eq!(published_before_the_gate.scheduled_terminal(p), None);
        assert_eq!(frozen_at_the_fold.scheduled_terminal(p), Some(terminal));
        assert_eq!(
            published_before_the_gate
                .shard_trie()
                .leaves()
                .collect::<Vec<_>>(),
            frozen_at_the_fold.shard_trie().leaves().collect::<Vec<_>>(),
            "the final window's trie still carries the parent in both copies",
        );
        // The children's window: projected at the final window's fold,
        // after the gate, so the children are already in its trie.
        assert!(advance_to_scheduled_cut(&mut state));
        apply_scheduled_splits(&mut state);
        let children = state.derive_next_topology_snapshot(net());
        assert!(children.shard_trie().contains(left) && children.shard_trie().contains(right));
        assert!(!children.shard_trie().contains(p));
    }

    #[test]
    fn execution_stamps_the_admission_epoch_on_the_terminal_boundary() {
        use hyperscale_types::RETENTION_HORIZON;

        let p = ShardId::leaf(1, 0);
        let (left, right) = p.children();
        let mut state = grow_state(4);
        state.chain_config.epoch_duration_ms = 400_000;
        state.boundaries.insert(
            p,
            ShardBoundary {
                boundary_qc: None,
                state_root: StateRoot::ZERO,
                block_hash: BlockHash::ZERO,
                height: BlockHeight::new(10),
                weighted_timestamp: WeightedTimestamp::ZERO,
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                witness_base: BeaconWitnessLeafCount::ZERO,
                cumulative_fees: 0,
                used: DeclaredWork::ZERO,
                blocks: 0,
                substate_bytes: 0,
                formed: Epoch::GENESIS,
                last_live_epoch: Epoch::new(5),
                consecutive_misses: 0,
                terminal_epoch: None,
                handoff_complete: None,
                terminal_delivered: false,
                terminal_settled_txs: None,
                reshape_admitted_epoch: None,
            },
        );
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            p,
            &ShardWitnessPayload::ScheduleSplit {
                shard: p,
                epoch: Epoch::GENESIS,
                settling: None,
            },
        );
        let admitted = state.current_epoch;
        let floor = WeightedTimestamp::from_millis(
            admitted.inner() * 400_000 - RETENTION_HORIZON.as_secs() * 1000,
        );
        assert_eq!(
            state.live_settled_window_floors().get(&p),
            Some(&floor),
            "the pending record projects the floor from admission",
        );

        let left_observer = observer_for(&state, p, left);
        mark_ready(&mut state, p, left_observer);
        let right_observer = observer_for(&state, p, right);
        mark_ready(&mut state, p, right_observer);
        fold_split(&mut state);

        assert!(state.pending_reshapes.is_empty());
        assert_eq!(
            state.boundaries[&p].reshape_admitted_epoch,
            Some(admitted),
            "the execution stamps the admission onto the terminal boundary",
        );
        assert_eq!(
            state.live_settled_window_floors().get(&p),
            Some(&floor),
            "the boundary stamp keeps projecting the floor through the coast",
        );
    }

    /// The floor is the admission epoch however many Skip folds follow
    /// it: a stall moves the readiness deadline, and the settled window
    /// keeps reaching back to the fold the counterpart fences armed at.
    #[test]
    fn the_settled_floor_ignores_skip_epochs() {
        use hyperscale_types::RETENTION_HORIZON;

        const EPOCH_MS: u64 = 400_000;
        let floor_of = |admitted: Epoch| {
            WeightedTimestamp::from_millis(
                admitted.inner() * EPOCH_MS - RETENTION_HORIZON.as_secs() * 1000,
            )
        };
        // The fold's Skip arm: the epoch advances and the deadlines move.
        let skip = |state: &mut BeaconState| {
            state.current_epoch = state.current_epoch.next();
            defer_reshape_ttls(state);
        };

        let p = ShardId::leaf(1, 0);
        let (left, right) = p.children();
        let mut state = grow_state(4);
        state.chain_config.epoch_duration_ms = EPOCH_MS;
        state.boundaries.insert(
            p,
            ShardBoundary {
                boundary_qc: None,
                state_root: StateRoot::ZERO,
                block_hash: BlockHash::ZERO,
                height: BlockHeight::new(10),
                weighted_timestamp: WeightedTimestamp::ZERO,
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                witness_base: BeaconWitnessLeafCount::ZERO,
                cumulative_fees: 0,
                used: DeclaredWork::ZERO,
                blocks: 0,
                substate_bytes: 0,
                formed: Epoch::GENESIS,
                last_live_epoch: Epoch::new(5),
                consecutive_misses: 0,
                terminal_epoch: None,
                handoff_complete: None,
                terminal_delivered: false,
                terminal_settled_txs: None,
                reshape_admitted_epoch: None,
            },
        );
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            p,
            &ShardWitnessPayload::ScheduleSplit {
                shard: p,
                epoch: Epoch::GENESIS,
                settling: None,
            },
        );
        let admitted = state.current_epoch;
        skip(&mut state);
        skip(&mut state);
        assert_eq!(
            state.live_settled_window_floors().get(&p),
            Some(&floor_of(admitted)),
            "the pending record floors on the admission, two skips later",
        );

        let left_observer = observer_for(&state, p, left);
        mark_ready(&mut state, p, left_observer);
        let right_observer = observer_for(&state, p, right);
        mark_ready(&mut state, p, right_observer);
        schedule_quiet_splits(&mut state);
        assert!(
            state.pending_reshapes[&p].scheduled_terminal().is_some(),
            "the gate schedules the cut",
        );
        assert_eq!(
            state.live_settled_window_floors().get(&p),
            Some(&floor_of(admitted)),
            "the scheduled record floors on the admission",
        );

        assert!(advance_to_scheduled_cut(&mut state));
        apply_scheduled_splits(&mut state);
        assert!(state.pending_reshapes.is_empty());
        assert_eq!(state.boundaries[&p].reshape_admitted_epoch, Some(admitted));
        assert_eq!(
            state.live_settled_window_floors().get(&p),
            Some(&floor_of(admitted)),
            "the boundary stamp floors on the admission",
        );

        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let mut state = merge_grow_state(0);
        state.chain_config.epoch_duration_ms = EPOCH_MS;
        let merge = merge_assertion(parent);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), right, &merge);
        let paired = state.current_epoch;
        skip(&mut state);
        skip(&mut state);
        let floors = state.live_settled_window_floors();
        assert_eq!(
            (floors.get(&left), floors.get(&right)),
            (Some(&floor_of(paired)), Some(&floor_of(paired))),
            "both children floor on the pairing, two skips later",
        );
    }

    /// An unready parent member rides the carve to a child with its flag
    /// and placement epoch; the gate passes on the ready members beside it.
    #[test]
    fn unready_parent_member_rides_the_carve_and_keeps_its_flag() {
        let p = ShardId::leaf(1, 0);
        let straggler = ValidatorId::new(3);
        let mut state = grow_state(4);
        state.validators.get_mut(&straggler).unwrap().status = ValidatorStatus::OnShard {
            shard: p,
            ready: false,
            placed_at_epoch: Epoch::new(4),
        };
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            p,
            &ShardWitnessPayload::ScheduleSplit {
                shard: p,
                epoch: Epoch::GENESIS,
                settling: None,
            },
        );
        let observers: Vec<ValidatorId> = cohort_of(&state, p).keys().copied().collect();
        for observer in observers {
            mark_ready(&mut state, p, observer);
        }

        fold_split(&mut state);

        assert!(state.pending_reshapes.is_empty());
        let ValidatorStatus::OnShard {
            shard,
            ready,
            placed_at_epoch,
        } = state.validators[&straggler].status
        else {
            panic!("straggler must stay placed");
        };
        assert_eq!(shard.parent(), Some(p));
        assert!(!ready);
        assert_eq!(placed_at_epoch, Epoch::new(4));
    }

    /// Two replicas with byte-identical state execute byte-identically
    /// — the parent-half assignment is seeded, not incidental.
    #[test]
    fn execution_is_deterministic_across_replicas() {
        let p = ShardId::leaf(1, 0);
        let mut a = grow_state(4);
        let mut b = grow_state(4);
        for state in [&mut a, &mut b] {
            apply_shard_payload(
                &BlsVerifier,
                state,
                &net(),
                p,
                &ShardWitnessPayload::ScheduleSplit {
                    shard: p,
                    epoch: Epoch::GENESIS,
                    settling: None,
                },
            );
            let observers: Vec<ValidatorId> = cohort_of(state, p).keys().copied().collect();
            for observer in observers {
                mark_ready(state, p, observer);
            }
            fold_split(state);
        }
        assert_eq!(a.next_shard_committees, b.next_shard_committees);
        assert_eq!(a.validators, b.validators);
        assert_eq!(a.boundaries, b.boundaries);
    }

    /// The fold surfaces cohort-seat changes through `SlotEffects`:
    /// the admission draw with its child assignments, the lapse sweep's
    /// release, and silence at execution — consumed seats land on their
    /// children through the committee transitions instead.
    #[test]
    fn slot_effects_surface_seat_draws_and_releases() {
        use hyperscale_types::RESHAPE_TRIGGER_TTL_EPOCHS;

        let p = ShardId::leaf(1, 0);
        let split = ShardWitnessPayload::ScheduleSplit {
            shard: p,
            epoch: Epoch::GENESIS,
            settling: None,
        };

        // Admission: the draw surfaces with assignments.
        let mut state = grow_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let effects = apply_witness_chunk(&mut state, 0, vec![split.clone()]);
        assert_eq!(effects.observers_drawn.len(), 4);
        assert!(
            effects
                .observers_drawn
                .iter()
                .all(|seat| seat.shard == p && seat.child.parent() == Some(p)),
        );
        assert!(effects.observers_released.is_empty());
        let drawn: BTreeSet<ValidatorId> = effects
            .observers_drawn
            .iter()
            .map(|seat| seat.validator)
            .collect();

        // The trigger goes quiet; the staleness sweep *lapses* the split,
        // releasing every seat once but keeping the record for a re-staff.
        let mut released = Vec::new();
        for _ in 0..RESHAPE_TRIGGER_TTL_EPOCHS {
            let effects = apply_next_epoch(&mut state, &[]);
            assert!(effects.observers_drawn.is_empty());
            released.extend(effects.observers_released);
        }
        assert!(
            state.pending_reshapes.contains_key(&p),
            "the lapse keeps the record",
        );
        assert!(
            cohort_of(&state, p).is_empty(),
            "the lapse empties the cohort"
        );
        assert_eq!(
            released
                .iter()
                .map(|seat| seat.validator)
                .collect::<BTreeSet<_>>(),
            drawn,
        );
        assert!(released.iter().all(|seat| seat.shard == p));

        // Execution: seats are consumed, not released — the epoch's
        // committee transitions carry the children instead.
        let mut state = grow_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        apply_witness_chunk(&mut state, 0, vec![split]);
        let ready_leaves: Vec<ShardWitnessPayload> = cohort_of(&state, p)
            .iter()
            .map(|(v, seat)| ShardWitnessPayload::ReshapeReady {
                validator: *v,
                child: seat.child,
            })
            .collect();
        let effects = apply_witness_chunk(&mut state, 0, ready_leaves);
        assert!(drain_latched(&state, p), "the gate must fire");
        assert!(effects.observers_released.is_empty());
        let quiet = quiet_payloads(&state);
        let effects = apply_witness_chunk(&mut state, 0, quiet);
        assert!(
            state.pending_reshapes[&p].scheduled_terminal().is_some(),
            "the quiet target must be scheduled"
        );
        assert!(effects.observers_released.is_empty());

        // The cut lands at the next fold: the record clears and the
        // children ride that fold's lookahead. The seats were consumed
        // there, not released.
        let effects = apply_witness_chunk(&mut state, 0, Vec::new());
        assert!(state.pending_reshapes.is_empty(), "the cut must apply");
        assert!(effects.observers_released.is_empty());
        let (left, right) = p.children();
        assert!(effects.shard_committee_transitions.contains_key(&left));
        assert!(effects.shard_committee_transitions.contains_key(&right));
    }

    /// The grow pipeline end to end: after the fold that meets the gate,
    /// the epoch in flight still resolves routing against the parent while
    /// the lookahead resolves the two-child partition; the in-flight
    /// window's frozen consensus subset is untouched; the promotion one
    /// epoch later activates both children at full consensus strength.
    #[test]
    fn lookahead_resolves_children_while_active_resolves_parent() {
        let p = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let (left, right) = p.children();
        let mut state = grow_state(4);
        // Staff the sibling so both tries are prefix-complete.
        let mut sibling_members = Vec::new();
        for i in 100..104u64 {
            let id = ValidatorId::new(i);
            sibling_members.push(id);
            state.validators.insert(
                id,
                validator_record(
                    i,
                    0,
                    ValidatorStatus::OnShard {
                        shard: sibling,
                        ready: true,
                        placed_at_epoch: Epoch::GENESIS,
                    },
                ),
            );
        }
        state.next_shard_committees.insert(
            sibling,
            ShardCommittee {
                members: sibling_members,
            },
        );
        state.shard_committees = state.next_shard_committees.clone();
        state.committee = (0u64..4).map(ValidatorId::new).collect();

        // One epoch folds the trigger; admission draws the cohort.
        apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::ScheduleSplit {
                shard: p,
                epoch: Epoch::GENESIS,
                settling: None,
            }],
        );
        assert!(state.pending_reshapes.contains_key(&p));
        let consensus_during_grow = state.shard_consensus_members.clone();

        // The next epoch folds every observer's ReshapeReady; the gate
        // fires inside that apply and latches the drain, and the one
        // after folds the target's quiet and schedules the cut a window
        // out. The fold at the cut is the one whose lookahead carries the
        // children.
        let ready_leaves: Vec<ShardWitnessPayload> = cohort_of(&state, p)
            .iter()
            .map(|(v, seat)| ShardWitnessPayload::ReshapeReady {
                validator: *v,
                child: seat.child,
            })
            .collect();
        apply_witness_chunk(&mut state, 0, ready_leaves);
        assert!(drain_latched(&state, p));
        let quiet = quiet_payloads(&state);
        apply_witness_chunk(&mut state, 0, quiet);
        assert!(state.pending_reshapes[&p].scheduled_terminal().is_some());
        apply_witness_chunk(&mut state, 0, Vec::new());
        assert!(state.pending_reshapes.is_empty());

        let active = state.derive_topology_snapshot(net());
        let lookahead = state.derive_next_topology_snapshot(net());
        for seed in 0..32u8 {
            let owner = Address::new([seed; 31], AddressClass::Component);
            let now = active.shard_for_prefix(owner);
            let next = lookahead.shard_for_prefix(owner);
            if now == p {
                // The parent's traffic remaps to exactly its children.
                assert_eq!(next.parent(), Some(p), "{owner:?} routed to {next:?}");
            } else {
                // Anything outside the split is untouched.
                assert_eq!(now, sibling);
                assert_eq!(next, sibling);
            }
            // Re-derivation is deterministic on both sides.
            assert_eq!(
                state
                    .derive_topology_snapshot(net())
                    .shard_for_prefix(owner),
                now
            );
            assert_eq!(
                state
                    .derive_next_topology_snapshot(net())
                    .shard_for_prefix(owner),
                next
            );
        }
        // The in-flight window still runs the parent: its promotion-
        // frozen consensus subset is exactly what the grow froze.
        assert_eq!(state.shard_consensus_members, consensus_during_grow);
        // Pending child placeholders never project as snap-sync anchors.
        assert!(lookahead.boundary(left).is_none());
        assert!(lookahead.boundary(right).is_none());

        // The promotion one epoch later activates both children at
        // full consensus strength: the parent half plus the readied
        // cohort half.
        apply_next_epoch(&mut state, &[]);
        assert!(!state.shard_committees.contains_key(&p));
        for child in [left, right] {
            assert_eq!(state.shard_committees[&child].members.len(), 4);
            assert_eq!(state.shard_consensus_members[&child].len(), 4);
        }
    }

    // ─── merge keeper lifecycle ──────────────────────────────────────────

    /// Parent `leaf(1, 0)`'s two children, each a four-member committee
    /// of ready `OnShard` validators, plus `pooled` free validators with
    /// a stake-backed pool so the shuffle can refill. `current_epoch =
    /// 5`, committee target 4.
    fn merge_grow_state(pooled: u64) -> BeaconState {
        use hyperscale_types::{MIN_STAKE_FLOOR, Stake, StakePool};

        let mut state = empty_state();
        state.current_epoch = Epoch::new(5);
        state.chain_config.shard_size = 4;
        let children: [ShardId; 2] = ShardId::leaf(1, 0).children().into();
        let mut validators = BTreeSet::new();
        let mut next = 0u64;
        for child in children {
            let mut members = Vec::new();
            for _ in 0..4 {
                let id = ValidatorId::new(next);
                members.push(id);
                validators.insert(id);
                state.validators.insert(
                    id,
                    validator_record(
                        next,
                        0,
                        ValidatorStatus::OnShard {
                            shard: child,
                            ready: true,
                            placed_at_epoch: Epoch::GENESIS,
                        },
                    ),
                );
                next += 1;
            }
            state.shard_committees.insert(
                child,
                ShardCommittee {
                    members: members.clone(),
                },
            );
            state
                .next_shard_committees
                .insert(child, ShardCommittee { members });
            state.boundaries.insert(
                child,
                ShardBoundary {
                    boundary_qc: None,
                    state_root: StateRoot::ZERO,
                    block_hash: BlockHash::ZERO,
                    height: BlockHeight::new(10),
                    weighted_timestamp: WeightedTimestamp::ZERO,
                    witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                    witness_base: BeaconWitnessLeafCount::ZERO,
                    cumulative_fees: 0,
                    used: DeclaredWork::ZERO,
                    blocks: 0,
                    substate_bytes: 0,
                    formed: Epoch::GENESIS,
                    last_live_epoch: Epoch::new(5),
                    consecutive_misses: 0,
                    terminal_epoch: None,
                    handoff_complete: None,
                    terminal_delivered: false,
                    terminal_settled_txs: None,
                    reshape_admitted_epoch: None,
                },
            );
        }
        for i in 0..pooled {
            let id = ValidatorId::new(1000 + i);
            validators.insert(id);
            state
                .validators
                .insert(id, validator_record(1000 + i, 0, ValidatorStatus::Pooled));
        }
        let count = 8 + u128::from(pooled);
        state.pools.insert(
            test_pool(0),
            StakePool {
                id: test_pool(0),
                total_stake: Stake::from_quanta(count * MIN_STAKE_FLOOR.quanta()),
                validators,
                pending_withdrawals: Vec::new(),
                released_cumulative: Stake::ZERO,
                conviction: None,
            },
        );
        state
    }

    fn keepers_of(state: &BeaconState, parent: ShardId) -> BTreeMap<ValidatorId, KeeperSeat> {
        let Some(PendingReshape::Merge { keepers, .. }) = state.pending_reshapes.get(&parent)
        else {
            panic!("no pending merge for {parent:?}");
        };
        keepers.clone()
    }

    /// Both halves pairing draws the keeper committee — half the target
    /// from each child, each seat a member of the child it runs, none
    /// ready — and stamps the readiness clock.
    #[test]
    fn merge_pairing_draws_keepers_from_each_child() {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let mut state = merge_grow_state(0);
        let merge = merge_assertion(parent);

        // The first half waits: no keepers, no readiness clock.
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
        let Some(PendingReshape::Merge {
            keepers, admitted, ..
        }) = state.pending_reshapes.get(&parent)
        else {
            panic!("merge half not recorded");
        };
        assert!(keepers.is_empty());
        assert!(admitted.is_none());

        // The sibling pairs it: keepers drawn on the spot.
        apply_shard_payload(&BlsVerifier, &mut state, &net(), right, &merge);
        let keepers = keepers_of(&state, parent);
        let Some(PendingReshape::Merge { admitted, .. }) = state.pending_reshapes.get(&parent)
        else {
            unreachable!()
        };
        assert_eq!(admitted.map(|admission| admission.at), Some(Epoch::new(5)));
        assert_eq!(keepers.len(), 4);
        let from_left = keepers.values().filter(|s| s.child == left).count();
        let from_right = keepers.values().filter(|s| s.child == right).count();
        assert_eq!((from_left, from_right), (2, 2));
        for (id, seat) in &keepers {
            assert!(!seat.ready);
            assert!(
                state.next_shard_committees[&seat.child]
                    .members
                    .contains(id)
            );
        }
    }

    /// A child short on ready members at the pairing fold still yields
    /// `take` keepers: the draw backfills the shortfall from the not-yet-ready
    /// `OnShard` half, so the reformed committee reaches full strength even
    /// when a member's `Ready` witness has not folded by then.
    #[test]
    fn merge_pairing_backfills_keepers_when_a_child_is_short_on_ready() {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let mut state = merge_grow_state(0);

        // Leave the left child with a single ready member; the rest stay
        // `OnShard` on the left but their readiness has not folded.
        let short: Vec<ValidatorId> = state.next_shard_committees[&left]
            .members
            .iter()
            .copied()
            .skip(1)
            .collect();
        for id in short {
            if let Some(rec) = state.validators.get_mut(&id)
                && let ValidatorStatus::OnShard { ready, .. } = &mut rec.status
            {
                *ready = false;
            }
        }

        let merge = merge_assertion(parent);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), right, &merge);

        let keepers = keepers_of(&state, parent);
        assert_eq!(
            keepers.len(),
            4,
            "backfill must reach full keeper strength when a child is short on ready members",
        );
        let from_left = keepers.values().filter(|s| s.child == left).count();
        let from_right = keepers.values().filter(|s| s.child == right).count();
        assert_eq!((from_left, from_right), (2, 2));
    }

    /// A paired merge projects its keepers into the lookahead topology
    /// snapshot, keyed by the child each runs, so that child's runtime
    /// classifies their ready signals as `ReshapeReady`. Under the freeze
    /// discipline the active snapshot picks them up only at the next
    /// promotion, so a fresh pairing is not yet visible there.
    #[test]
    fn merge_pairing_projects_keepers_into_the_snapshot() {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let mut state = merge_grow_state(0);
        let merge = merge_assertion(parent);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), right, &merge);
        let keepers = keepers_of(&state, parent);

        let lookahead = state.derive_next_topology_snapshot(net());
        let active = state.derive_topology_snapshot(net());
        for (id, seat) in &keepers {
            assert_eq!(
                lookahead.reshape_keeper_parent(seat.child, *id),
                Some(parent)
            );
            // A keeper of one child isn't projected onto the sibling.
            let sibling = if seat.child == left { right } else { left };
            assert_eq!(lookahead.reshape_keeper_parent(sibling, *id), None);
            // Frozen out of the active window until the next promotion.
            assert_eq!(active.reshape_keeper_parent(seat.child, *id), None);
        }
    }

    /// A keeper's `ReshapeReady` rides its own child's chain and marks
    /// only its own seat; the same signal arriving via the sibling
    /// chain is dropped (source pinning).
    #[test]
    fn keeper_reshape_ready_marks_only_its_own_seat() {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let mut state = merge_grow_state(0);
        let merge = merge_assertion(parent);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), right, &merge);

        let keeper = *keepers_of(&state, parent)
            .iter()
            .find(|(_, seat)| seat.child == left)
            .map(|(id, _)| id)
            .expect("left contributes keepers");
        let ready = ShardWitnessPayload::ReshapeReady {
            validator: keeper,
            child: left,
        };

        // Wrong chain: a left keeper's signal arriving on the right is
        // ignored.
        apply_shard_payload(&BlsVerifier, &mut state, &net(), right, &ready);
        assert!(!keepers_of(&state, parent)[&keeper].ready);

        // Own chain: the seat flips.
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &ready);
        assert!(keepers_of(&state, parent)[&keeper].ready);
    }

    /// A pending merge's keepers are pinned on their child: the trickle
    /// shuffle rotates only non-keeper members.
    #[test]
    fn merge_keepers_are_pinned_against_rotation() {
        use crate::state::committee::run_shuffle_step;

        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let mut state = merge_grow_state(4);
        state.current_epoch = Epoch::new(state.chain_config.shuffle_interval_epochs());
        let merge = merge_assertion(parent);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), right, &merge);
        let keepers = keepers_of(&state, parent);

        run_shuffle_step(&mut state);

        // Every keeper still runs its child, and no keeper is the member
        // either child's rotation is waiting to retire.
        for (id, seat) in &keepers {
            assert_eq!(
                state.validators[id].status,
                ValidatorStatus::OnShard {
                    shard: seat.child,
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
            );
            assert!(
                state.next_shard_committees[&seat.child]
                    .members
                    .contains(id)
            );
        }
        // The shuffle wasn't a no-op: both children opened a rotation, and
        // each named a non-keeper as its victim.
        for child in [left, right] {
            let victim = *state.pending_rotations[&child]
                .keys()
                .next()
                .expect("the child opened a rotation");
            assert!(!keepers.contains_key(&victim), "a keeper was named victim");
            assert_eq!(state.next_shard_committees[&child].members.len(), 5);
        }
    }

    /// A rotation's victim is the head of the shard's rotation order on the
    /// state the shuffle reads. Each exclusion is placed at genesis, so it
    /// would head the order but for what excludes it: a merge keeper, the
    /// victim of a rotation already open, and an unready member.
    #[test]
    fn the_shuffle_retires_the_head_of_the_rotation_order() {
        use hyperscale_types::PendingRotation;

        use crate::state::committee::run_shuffle_step;

        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let mut state = merge_grow_state(4);
        let boundary = Epoch::new(state.chain_config.shuffle_interval_epochs());
        let merge = merge_assertion(parent);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), right, &merge);
        let keepers: Vec<ValidatorId> = keepers_of(&state, parent)
            .into_iter()
            .filter(|(_, seat)| seat.child == left)
            .map(|(id, _)| id)
            .collect();
        let others: Vec<ValidatorId> = state.next_shard_committees[&left]
            .members
            .iter()
            .copied()
            .filter(|id| !keepers.contains(id))
            .collect();
        let [spoken_for, unready] = others[..] else {
            panic!("two of the left child's four members are keepers");
        };

        // Two later members: the head, placed at epoch 1, and the open
        // rotation's entrant, placed at epoch 2 and readied, so the open
        // rotation leaves the shard under its in-flight cap.
        let (head, entrant) = (ValidatorId::new(200), ValidatorId::new(201));
        for (id, placed) in [(head, 1), (entrant, 2)] {
            state.validators.insert(
                id,
                validator_record(
                    id.inner(),
                    0,
                    ValidatorStatus::OnShard {
                        shard: left,
                        ready: true,
                        placed_at_epoch: Epoch::new(placed),
                    },
                ),
            );
            state
                .next_shard_committees
                .get_mut(&left)
                .unwrap()
                .members
                .push(id);
        }
        state.pending_rotations.entry(left).or_default().insert(
            spoken_for,
            PendingRotation {
                entrant,
                opened_at: Epoch::GENESIS,
            },
        );
        let ValidatorStatus::OnShard { ready, .. } =
            &mut state.validators.get_mut(&unready).unwrap().status
        else {
            unreachable!("a member of the left child");
        };
        *ready = false;
        state.current_epoch = boundary;

        let order = state.rotation_order(left);
        assert_eq!(order, vec![head, entrant]);

        run_shuffle_step(&mut state);

        let opened: Vec<ValidatorId> = state.pending_rotations[&left]
            .iter()
            .filter(|(_, rotation)| rotation.opened_at == boundary)
            .map(|(victim, _)| *victim)
            .collect();
        assert_eq!(opened, vec![order[0]]);
    }

    /// Pairing draws the keepers, and the draw prefers ready members —
    /// which is exactly what a rotation's victim is. Cancel first, so no
    /// keeper seat is handed to a member on its way out and both children
    /// read at full strength, every member ready.
    #[test]
    fn merge_pairing_cancels_its_children_rotations() {
        use crate::state::committee::run_shuffle_step;

        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let mut state = merge_grow_state(4);
        state.current_epoch = Epoch::new(state.chain_config.shuffle_interval_epochs());
        run_shuffle_step(&mut state);
        let parties: Vec<(ValidatorId, ValidatorId)> = state
            .pending_rotations
            .values()
            .flat_map(|rotations| rotations.iter().map(|(v, rot)| (*v, rot.entrant)))
            .collect();
        assert_eq!(parties.len(), 2, "both children rotate");

        let merge = merge_assertion(parent);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), right, &merge);

        assert!(state.pending_rotations.is_empty(), "pairing cancels both");
        let keepers = keepers_of(&state, parent);
        for (victim, entrant) in parties {
            assert!(
                !keepers.contains_key(&entrant),
                "a cancelled entrant was drawn as a keeper",
            );
            assert_eq!(
                state.validators[&entrant].status,
                ValidatorStatus::Pooled,
                "a cancelled entrant returns to the pool",
            );
            // The victim keeps the seat it never gave up, so it is a
            // legitimate keeper candidate like any other member.
            assert!(matches!(
                state.validators[&victim].status,
                ValidatorStatus::OnShard { ready: true, .. },
            ));
        }
        for child in [left, right] {
            let members = &state.next_shard_committees[&child].members;
            assert_eq!(members.len(), 4, "the child reads at full strength");
            assert_eq!(
                state.ready_consensus_members(&state.next_shard_committees)[&child].len(),
                4,
                "every member the keeper draw sees is ready",
            );
        }
    }

    /// The shuffle exempts keepers but not the rest of a merging child, so
    /// a rotation can still open after pairing. The cut re-carves both
    /// children wholesale — keepers onto the parent, everyone else into
    /// the pool — so that rotation is dropped rather than left holding a
    /// seat that no longer exists, and both parties land in a placement of
    /// their own.
    #[test]
    fn a_merge_drops_a_rotation_opened_after_pairing() {
        use crate::state::committee::run_shuffle_step;

        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let mut state = merge_grow_state(4);

        let merge = merge_assertion(parent);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), right, &merge);

        state.current_epoch = Epoch::new(state.chain_config.shuffle_interval_epochs());
        run_shuffle_step(&mut state);
        let parties: Vec<ValidatorId> = state
            .pending_rotations
            .values()
            .flat_map(|rotations| {
                rotations
                    .iter()
                    .flat_map(|(victim, rotation)| [*victim, rotation.entrant])
            })
            .collect();
        assert_eq!(parties.len(), 4, "both children rotate past the pairing");

        for (id, seat) in keepers_of(&state, parent) {
            apply_shard_payload(
                &BlsVerifier,
                &mut state,
                &net(),
                seat.child,
                &ShardWitnessPayload::ReshapeReady {
                    validator: id,
                    child: seat.child,
                },
            );
        }
        fold_merge(&mut state);

        assert!(state.pending_rotations.is_empty());
        assert_eq!(state.next_shard_committees[&parent].members.len(), 4);
        for id in parties {
            let status = state.validators[&id].status;
            assert!(
                matches!(status, ValidatorStatus::OnShard { shard, .. } if shard == parent)
                    || matches!(status, ValidatorStatus::Pooled),
                "{id:?} was left at {status:?} by the merge",
            );
        }
    }

    /// A merge that pairs mid-rotation seats its parent at full strength,
    /// whichever members the draw happens to pick. Left to resolve, a
    /// rotation retires a member the keeper draw had already seated: that
    /// keeper can neither signal ready from a child it has left nor reach
    /// the keeper move, so the gate loses it and the parent seats short —
    /// or, once two are lost, never executes at all.
    #[test]
    fn a_merge_mid_rotation_seats_the_parent_at_full_strength() {
        use hyperscale_types::Randomness;

        use crate::state::committee::{resolve_pending_rotations, run_shuffle_step};

        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        for seed in 0u8..40 {
            let mut state = merge_grow_state(4);
            state.randomness = Randomness::new([seed; 32]);
            state.current_epoch = Epoch::new(state.chain_config.shuffle_interval_epochs());
            run_shuffle_step(&mut state);

            let merge = ShardWitnessPayload::ScheduleMerge {
                parent,
                epoch: Epoch::GENESIS,
                settling: None,
            };
            apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
            apply_shard_payload(&BlsVerifier, &mut state, &net(), right, &merge);

            // Any entrant that outlived the pairing would ready here and
            // retire its victim out from under the keeper draw.
            for rec in state.validators.values_mut() {
                if let ValidatorStatus::OnShard { ready, .. } = &mut rec.status {
                    *ready = true;
                }
            }
            resolve_pending_rotations(&mut state);

            // Only a keeper still seated on its child can emit a
            // ReshapeReady leaf through that child's chain.
            for (id, seat) in keepers_of(&state, parent) {
                if !matches!(
                    state.validators[&id].status,
                    ValidatorStatus::OnShard { shard, .. } if shard == seat.child
                ) {
                    continue;
                }
                apply_shard_payload(
                    &BlsVerifier,
                    &mut state,
                    &net(),
                    seat.child,
                    &ShardWitnessPayload::ReshapeReady {
                        validator: id,
                        child: seat.child,
                    },
                );
            }
            fold_merge(&mut state);

            assert!(
                !state.pending_reshapes.contains_key(&parent),
                "seed {seed}: the merge gate never met its keeper quorum",
            );
            assert_eq!(
                state.next_shard_committees[&parent].members.len(),
                4,
                "seed {seed}: the merged parent seated short",
            );
            assert_eq!(
                state.ready_consensus_members(&state.next_shard_committees)[&parent].len(),
                4,
                "seed {seed}: the merged parent opened below full consensus strength",
            );
        }
    }

    /// Once paired, a required half going quiet cancels the merge and
    /// un-pins the keepers — unlike a lone half, which simply waits.
    #[test]
    fn paired_merge_cancels_when_a_required_half_goes_quiet() {
        use hyperscale_types::RESHAPE_TRIGGER_TTL_EPOCHS;

        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let mut state = merge_grow_state(0);
        let merge = merge_assertion(parent);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), right, &merge);
        assert!(state.pending_reshapes.contains_key(&parent));

        // Only the left half keeps re-asserting; the right goes quiet.
        for epoch in 6..(5 + RESHAPE_TRIGGER_TTL_EPOCHS) {
            state.current_epoch = Epoch::new(epoch);
            apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
            prune_stale_reshapes(&mut state);
            assert!(
                state.pending_reshapes.contains_key(&parent),
                "cancelled early at epoch {epoch}",
            );
        }
        state.current_epoch = Epoch::new(5 + RESHAPE_TRIGGER_TTL_EPOCHS);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
        prune_stale_reshapes(&mut state);
        assert!(state.pending_reshapes.is_empty());
        // Keepers returned to ordinary rotation: still OnShard, no longer pinned.
        assert!(!state.is_merge_keeper(left, ValidatorId::new(0)));
    }

    // ─── placement drift across the scheduled window ────────────────────

    /// A carve member whose placement moves between the gate and the cut is
    /// dropped rather than seated.
    ///
    /// The carve is frozen when the gate fires and there is no second gate
    /// to re-approve a different one, so the applying fold a window later
    /// meets whatever the intervening window did. A parent half found in
    /// any state but `OnShard` on the splitting parent holds no cohort seat
    /// to read a readiness from — the two sets are disjoint by
    /// construction — so it is dropped, the child seats short, and the
    /// top-up backfills it in the same fold.
    #[test]
    fn a_split_carve_member_that_moved_is_dropped_not_seated() {
        let p = ShardId::leaf(1, 0);
        let children: [ShardId; 2] = p.children().into();
        let mut state = grow_state(4);
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            p,
            &ShardWitnessPayload::ScheduleSplit {
                shard: p,
                epoch: Epoch::GENESIS,
                settling: None,
            },
        );
        // Collected first: marking readiness borrows the state mutably.
        let observers: Vec<ValidatorId> = cohort_of(&state, p).keys().copied().collect();
        for observer in observers {
            mark_ready(&mut state, p, observer);
        }
        schedule_quiet_splits(&mut state);
        let scheduled = state.pending_reshapes[&p]
            .scheduled_terminal()
            .expect("the gate fires");

        // A parent half is drawn into another split's cohort in the window
        // between the gate and the cut — the one shape that would index a
        // cohort seat it does not hold.
        let half = *state.next_shard_committees[&p]
            .members
            .iter()
            .find(|id| !cohort_of(&state, p).contains_key(id))
            .expect("the carve holds parent-half members");
        state.validators.get_mut(&half).expect("seated").status = ValidatorStatus::Observing {
            shard: ShardId::leaf(1, 1),
            placed_at_epoch: state.current_epoch,
        };

        state.current_epoch = scheduled;
        apply_scheduled_splits(&mut state);

        assert!(state.pending_reshapes.is_empty(), "the cut applied");
        assert!(
            !children
                .iter()
                .any(|c| state.next_shard_committees[c].members.contains(&half)),
            "a member that moved must not be seated on a child",
        );
    }

    /// A keeper that rotated off its child between the gate and the cut is
    /// dropped rather than moved onto the merged parent, which would seat it
    /// there while its own shard still counted it.
    #[test]
    fn a_merge_keeper_that_rotated_away_is_dropped_not_moved() {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let mut state = merge_grow_state(0);
        let merge = merge_assertion(parent);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), right, &merge);
        let keepers = keepers_of(&state, parent);
        for (id, seat) in &keepers {
            apply_shard_payload(
                &BlsVerifier,
                &mut state,
                &net(),
                seat.child,
                &ShardWitnessPayload::ReshapeReady {
                    validator: *id,
                    child: seat.child,
                },
            );
        }
        schedule_quiet_merges(&mut state);
        let scheduled = state.pending_reshapes[&parent]
            .scheduled_terminal()
            .expect("the gate fires");

        // One keeper rotates onto an unrelated shard before the cut.
        let strayed = *keepers.keys().next().expect("keepers drawn");
        state.validators.get_mut(&strayed).expect("seated").status = ValidatorStatus::OnShard {
            shard: ShardId::leaf(1, 1),
            ready: true,
            placed_at_epoch: state.current_epoch,
        };

        state.current_epoch = scheduled;
        apply_scheduled_merges(&mut state);

        assert!(state.pending_reshapes.is_empty(), "the cut applied");
        assert!(
            !state.next_shard_committees[&parent]
                .members
                .contains(&strayed),
            "a keeper that rotated away must not be seated on the merged parent",
        );
    }

    // ─── admission against a terminating shard ──────────────────────────

    /// A boundary record for a shard that has produced — the shape every
    /// live leaf carries.
    fn live_boundary() -> ShardBoundary {
        ShardBoundary {
            boundary_qc: None,
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"live")),
            height: BlockHeight::new(4),
            weighted_timestamp: WeightedTimestamp::ZERO,
            witness_leaf_count: BeaconWitnessLeafCount::ZERO,
            witness_base: BeaconWitnessLeafCount::ZERO,
            used: DeclaredWork::ZERO,
            blocks: 0,
            cumulative_fees: 0,
            substate_bytes: 0,
            formed: Epoch::GENESIS,
            last_live_epoch: Epoch::GENESIS,
            consecutive_misses: 0,
            terminal_epoch: None,
            handoff_complete: None,
            terminal_delivered: false,
            terminal_settled_txs: None,
            reshape_admitted_epoch: None,
        }
    }

    /// A shard re-asserting its trigger inside its own final window admits
    /// nothing.
    ///
    /// The applying fold consumes the reshape record at the top of that
    /// window, but the shard keeps its committee and keeps producing to its
    /// terminal — and the witness window that suppresses a duplicate trigger
    /// leaf is deliberately shorter than a reshape's life, so it re-asserts.
    /// Admitting there would draw a fresh cohort out of the pool onto a
    /// shard about to leave the trie.
    #[test]
    fn a_terminating_split_target_admits_no_further_reshape() {
        let p = ShardId::leaf(1, 0);
        let mut state = grow_state(8);
        // A live shard always carries a boundary record; the terminal mark
        // the schedule stamps lands on it.
        state.boundaries.insert(p, live_boundary());
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            p,
            &ShardWitnessPayload::ScheduleSplit {
                shard: p,
                epoch: Epoch::GENESIS,
                settling: None,
            },
        );
        let observers: Vec<ValidatorId> = cohort_of(&state, p).keys().copied().collect();
        for observer in observers {
            mark_ready(&mut state, p, observer);
        }
        schedule_quiet_splits(&mut state);
        let cut = state.pending_reshapes[&p]
            .scheduled_terminal()
            .expect("the gate fires");
        state.current_epoch = cut;
        apply_scheduled_splits(&mut state);
        assert!(state.pending_reshapes.is_empty(), "the record is consumed");
        assert!(
            state.shard_committees.contains_key(&p),
            "the parent is live through its final window",
        );

        // The parent re-asserts inside that window.
        let pooled_before = state.pooled_validators().len();
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            p,
            &ShardWitnessPayload::ScheduleSplit {
                shard: p,
                epoch: Epoch::GENESIS,
                settling: None,
            },
        );

        assert!(
            state.pending_reshapes.is_empty(),
            "a terminating shard must admit no further reshape",
        );
        assert_eq!(
            state.pooled_validators().len(),
            pooled_before,
            "no cohort may be drawn onto a shard about to leave the trie",
        );
    }

    /// The same for a merge child, whose final-window assertion would
    /// otherwise record a fresh half against its parent.
    #[test]
    fn a_terminating_merge_child_admits_no_further_reshape() {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let mut state = merge_grow_state(0);
        let merge = merge_assertion(parent);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), right, &merge);
        for (id, seat) in keepers_of(&state, parent) {
            apply_shard_payload(
                &BlsVerifier,
                &mut state,
                &net(),
                seat.child,
                &ShardWitnessPayload::ReshapeReady {
                    validator: id,
                    child: seat.child,
                },
            );
        }
        schedule_quiet_merges(&mut state);
        let cut = state.pending_reshapes[&parent]
            .scheduled_terminal()
            .expect("the gate fires");
        state.current_epoch = cut;
        apply_scheduled_merges(&mut state);
        assert!(state.pending_reshapes.is_empty(), "the record is consumed");

        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);

        assert!(
            state.pending_reshapes.is_empty(),
            "a terminating child must record no further merge half",
        );
    }

    /// A re-assertion arriving after the cut is scheduled refreshes the
    /// trigger clock but never re-staffs the cohort.
    ///
    /// The gate approved one specific cohort and froze the carve beside
    /// it; there is no second gate to approve another. A re-staff there
    /// would seat the children from a cohort no gate ever passed, every
    /// seat unready.
    #[test]
    fn a_scheduled_split_never_restaffs_its_cohort() {
        let p = ShardId::leaf(1, 0);
        let mut state = grow_state(8);
        state.boundaries.insert(p, live_boundary());
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            p,
            &ShardWitnessPayload::ScheduleSplit {
                shard: p,
                epoch: Epoch::GENESIS,
                settling: None,
            },
        );
        let observers: Vec<ValidatorId> = cohort_of(&state, p).keys().copied().collect();
        for observer in &observers {
            mark_ready(&mut state, p, *observer);
        }
        schedule_quiet_splits(&mut state);
        assert!(state.pending_reshapes[&p].scheduled_terminal().is_some());
        let approved = cohort_of(&state, p).clone();

        // Empty the cohort the way only a lapse could, then re-assert with a
        // pool deep enough to draw a fresh one. The carve must not move.
        let PendingReshape::Split { cohort, .. } =
            state.pending_reshapes.get_mut(&p).expect("scheduled split")
        else {
            panic!("a split was admitted");
        };
        cohort.clear();
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            p,
            &ShardWitnessPayload::ScheduleSplit {
                shard: p,
                epoch: Epoch::GENESIS,
                settling: None,
            },
        );

        assert!(
            cohort_of(&state, p).is_empty(),
            "a scheduled record must not re-staff: the approved cohort was {approved:?}",
        );
    }

    /// A split admitted onto a rotating shard cancels the rotation
    /// instead of scheduling around it. The parent half is assigned over
    /// every `OnShard` member with no ready filter, so carving
    /// mid-rotation would put the unready entrant in a child's half and
    /// let it count toward the 2f+1 the gate trusts as ready by
    /// construction.
    #[test]
    fn a_split_cancels_a_rotation_on_its_target() {
        use crate::state::committee::run_shuffle_step;

        let p = ShardId::leaf(1, 0);
        let (left, right) = p.children();
        let mut state = grow_state(8);
        // Ready members on an uncommitteed shard, so `beacon_eligible`
        // clears the shuffle's floor without adding a shard to rotate.
        for i in 500u64..504 {
            state.validators.insert(
                ValidatorId::new(i),
                validator_record(
                    i,
                    0,
                    ValidatorStatus::OnShard {
                        shard: ShardId::leaf(1, 1),
                        ready: true,
                        placed_at_epoch: Epoch::GENESIS,
                    },
                ),
            );
        }
        state.current_epoch = Epoch::new(state.chain_config.shuffle_interval_epochs());
        run_shuffle_step(&mut state);
        let entrant = state.pending_rotations[&p]
            .values()
            .next()
            .expect("the shuffle opened a rotation")
            .entrant;

        // Admit the split and ready its whole cohort: the only thing left
        // between it and its cut is the rotation.
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            p,
            &ShardWitnessPayload::ScheduleSplit {
                shard: p,
                epoch: Epoch::GENESIS,
                settling: None,
            },
        );
        for child in [left, right] {
            let observer = observer_for(&state, p, child);
            mark_ready(&mut state, p, observer);
        }

        fold_split(&mut state);

        // The rotation is gone, its entrant back in the pool, and the
        // split carved a committee of ready members only.
        assert!(state.pending_rotations.is_empty());
        assert!(matches!(
            state.validators[&entrant].status,
            ValidatorStatus::Pooled,
        ));
        assert!(!state.next_shard_committees.contains_key(&p));
        for child in [left, right] {
            let members = &state.next_shard_committees[&child].members;
            assert_eq!(members.len(), 4);
            assert!(
                !members.contains(&entrant),
                "a cancelled entrant must not ride the carve into a child",
            );
        }
    }

    // ─── merge execution gate ────────────────────────────────────────────

    /// The gate holds until the merged committee's ready keepers reach
    /// 2f+1 of the target; the first fold that passes drops both children
    /// from the lookahead, seats the keepers on the parent with their
    /// folded readiness, returns the non-keepers to the pool, marks the
    /// children terminal, and leaves the parent a pending placeholder.
    #[test]
    fn merge_executes_only_when_keepers_reach_quorum() {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let mut state = merge_grow_state(0);
        let merge = merge_assertion(parent);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), right, &merge);
        let keepers = keepers_of(&state, parent);
        let keeper_ids: Vec<ValidatorId> = keepers.keys().copied().collect();
        let non_keepers: Vec<ValidatorId> = (0u64..8)
            .map(ValidatorId::new)
            .filter(|id| !keepers.contains_key(id))
            .collect();
        state.miss_counters.insert(keeper_ids[0], 2);

        // Quorum is 2f+1 = 3 of the four-member target. Two ready: held.
        let quorum = 3;
        for id in &keeper_ids[..quorum - 1] {
            let child = keepers[id].child;
            apply_shard_payload(
                &BlsVerifier,
                &mut state,
                &net(),
                child,
                &ShardWitnessPayload::ReshapeReady {
                    validator: *id,
                    child,
                },
            );
        }
        fold_merge(&mut state);
        assert!(state.pending_reshapes.contains_key(&parent));
        assert!(state.next_shard_committees.contains_key(&left));

        // The third keeper readies: the trie collapses, the fourth a
        // straggler.
        let third = keeper_ids[quorum - 1];
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            keepers[&third].child,
            &ShardWitnessPayload::ReshapeReady {
                validator: third,
                child: keepers[&third].child,
            },
        );
        fold_merge(&mut state);

        assert!(state.pending_reshapes.is_empty());
        assert!(!state.next_shard_committees.contains_key(&left));
        assert!(!state.next_shard_committees.contains_key(&right));
        let merged = state.next_shard_committees[&parent].members.clone();
        assert_eq!(merged.len(), 4);

        // Each keeper seated on the parent: the three readied carry
        // `ready: true`, the straggler `false` (it completes via the
        // normal `Ready` path), each keeping its original placement epoch
        // so the parent's pending placeholder doesn't bar it from the
        // beacon committee.
        for kid in &keeper_ids {
            let ready = keeper_ids[..quorum].contains(kid);
            assert_eq!(
                state.validators[kid].status,
                ValidatorStatus::OnShard {
                    shard: parent,
                    ready,
                    placed_at_epoch: Epoch::GENESIS,
                },
            );
            assert!(merged.contains(kid));
        }
        // Non-keepers returned to the pool.
        for id in &non_keepers {
            assert_eq!(state.validators[id].status, ValidatorStatus::Pooled);
        }
        // Both children terminal; the parent is a pending placeholder
        // that can't project as a snap-sync anchor.
        assert_eq!(state.boundaries[&left].terminal_epoch, Some(Epoch::new(6)));
        assert_eq!(state.boundaries[&right].terminal_epoch, Some(Epoch::new(6)));
        assert_eq!(state.boundaries[&parent].block_hash, BlockHash::ZERO);
        assert_eq!(state.boundaries[&parent].last_live_epoch, Epoch::new(6));
        // The mover shed its per-placement miss scope.
        assert!(!state.miss_counters.contains_key(&keeper_ids[0]));
    }

    /// Jailing a parent member of a splitting shard refills its seat from
    /// the pool, unready. The refill rides the carve but counts toward no
    /// child's quorum until it readies, and the ready timeout that
    /// readies it runs on every fold, skip folds included — so a jail
    /// that takes the beacon-eligible set below
    /// `MIN_BEACON_COMMITTEE_SIZE` restores it, where a seat held open
    /// until the split executed would keep the beacon on skip folds,
    /// which fold no witness the split could execute on.
    #[test]
    fn a_jailed_parent_member_of_a_splitting_shard_is_refilled() {
        use hyperscale_types::{JailReason, MIN_BEACON_COMMITTEE_SIZE};

        use crate::state::lifecycle::auto_ready_timeout;
        use crate::state::vrf::jail_validator;

        let p = ShardId::leaf(1, 0);
        let (left, right) = p.children();
        let mut state = grow_state(6);
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            p,
            &ShardWitnessPayload::ScheduleSplit {
                shard: p,
                epoch: Epoch::GENESIS,
                settling: None,
            },
        );
        assert_eq!(state.pooled_validators().len(), 2);
        assert_eq!(state.beacon_eligible().len(), MIN_BEACON_COMMITTEE_SIZE);

        jail_validator(
            &mut state,
            ValidatorId::new(0),
            JailReason::Performance,
            Epoch::new(5),
        );

        // The seat refilled from the pool, unready.
        let members = state.next_shard_committees[&p].members.clone();
        assert_eq!(members.len(), 8);
        assert!(!members.contains(&ValidatorId::new(0)));
        assert_eq!(state.pooled_validators().len(), 1);
        let refill = *members
            .iter()
            .find(|id| id.inner() >= 1000 && !cohort_of(&state, p).contains_key(id))
            .expect("a pool validator refilled the seat");
        assert!(matches!(
            state.validators[&refill].status,
            ValidatorStatus::OnShard { shard, ready: false, .. } if shard == p
        ));
        assert_eq!(state.beacon_eligible().len(), MIN_BEACON_COMMITTEE_SIZE - 1);

        // The ready timeout readies the refill and restores the set.
        state.current_epoch =
            Epoch::new(state.current_epoch.inner() + state.chain_config.ready_timeout_epochs);
        assert_eq!(auto_ready_timeout(&mut state), vec![refill]);
        assert_eq!(state.beacon_eligible().len(), MIN_BEACON_COMMITTEE_SIZE);

        // Every parent member, the refill included, rides the carve.
        let observers: Vec<ValidatorId> = cohort_of(&state, p).keys().copied().collect();
        for id in observers {
            mark_ready(&mut state, p, id);
        }
        fold_split(&mut state);
        assert!(state.pending_reshapes.is_empty());
        assert_eq!(
            state.next_shard_committees[&left].members.len()
                + state.next_shard_committees[&right].members.len(),
            8,
        );
    }

    /// A refill still syncing the parent counts toward no child's quorum:
    /// the half it lands in clears the gate only on the ready members
    /// beside it.
    #[test]
    fn an_unready_refill_does_not_carry_a_child_over_the_gate() {
        use hyperscale_types::JailReason;

        use crate::state::vrf::jail_validator;

        let p = ShardId::leaf(1, 0);
        let mut state = grow_state(6);
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            p,
            &ShardWitnessPayload::ScheduleSplit {
                shard: p,
                epoch: Epoch::GENESIS,
                settling: None,
            },
        );
        // Two parent members leave; their refills seat unready, so two of
        // the four parent members the carve splits are unready.
        for id in [0, 1] {
            jail_validator(
                &mut state,
                ValidatorId::new(id),
                JailReason::Performance,
                Epoch::new(5),
            );
        }
        // One ready cohort seat per child: a child whose half is one
        // ready member and one refill stands at 2 of the 3 it needs.
        let children: [ShardId; 2] = p.children().into();
        for child in children {
            let observer = observer_for(&state, p, child);
            mark_ready(&mut state, p, observer);
        }
        schedule_quiet_splits(&mut state);
        let scheduled = state
            .pending_reshapes
            .get(&p)
            .is_some_and(|reshape| reshape.scheduled_terminal().is_some());
        assert!(
            !scheduled,
            "two ready parent members and one ready seat per child cannot clear 2f+1 = 3 \
             on both children",
        );
    }

    /// Jailing a keeper sheds its seat from the pending merge, so the
    /// dead seat neither counts toward the readiness quorum nor reaches
    /// the keeper move when the merge executes.
    #[test]
    fn jailed_keeper_sheds_its_seat_and_the_merge_executes_past_it() {
        use hyperscale_types::JailReason;

        use crate::state::vrf::jail_validator;

        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let mut state = merge_grow_state(0);
        let merge = merge_assertion(parent);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), right, &merge);
        let keepers = keepers_of(&state, parent);
        let keeper_ids: Vec<ValidatorId> = keepers.keys().copied().collect();

        let jailed = keeper_ids[0];
        let jailed_child = keepers[&jailed].child;
        jail_validator(&mut state, jailed, JailReason::Performance, Epoch::new(5));

        // The seat is gone and the child committee no longer lists the
        // keeper.
        let remaining = keepers_of(&state, parent);
        assert_eq!(remaining.len(), 3);
        assert!(!remaining.contains_key(&jailed));
        assert!(
            !state.next_shard_committees[&jailed_child]
                .members
                .contains(&jailed)
        );

        // The three surviving keepers ready up: quorum is 2f+1 = 3, met
        // without the dead seat, and the move walks only live keepers.
        for id in &keeper_ids[1..] {
            let child = remaining[id].child;
            apply_shard_payload(
                &BlsVerifier,
                &mut state,
                &net(),
                child,
                &ShardWitnessPayload::ReshapeReady {
                    validator: *id,
                    child,
                },
            );
        }
        fold_merge(&mut state);

        assert!(state.pending_reshapes.is_empty());
        let merged = state.next_shard_committees[&parent].members.clone();
        assert_eq!(merged.len(), 3);
        assert!(!merged.contains(&jailed));
        for id in &keeper_ids[1..] {
            assert!(merged.contains(id));
        }
        assert_eq!(
            state.validators[&jailed].status,
            ValidatorStatus::Jailed {
                since_epoch: Epoch::new(5),
                reason: JailReason::Performance,
            },
        );
    }

    /// Two replicas with byte-identical state execute byte-identically —
    /// the keeper draw and the merged committee are seeded, not
    /// incidental.
    #[test]
    fn merge_execution_is_deterministic_across_replicas() {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let merge = merge_assertion(parent);
        let mut a = merge_grow_state(0);
        let mut b = merge_grow_state(0);
        for state in [&mut a, &mut b] {
            apply_shard_payload(&BlsVerifier, state, &net(), left, &merge);
            apply_shard_payload(&BlsVerifier, state, &net(), right, &merge);
            for (id, seat) in keepers_of(state, parent) {
                apply_shard_payload(
                    &BlsVerifier,
                    state,
                    &net(),
                    seat.child,
                    &ShardWitnessPayload::ReshapeReady {
                        validator: id,
                        child: seat.child,
                    },
                );
            }
            fold_merge(state);
        }
        assert_eq!(a.next_shard_committees, b.next_shard_committees);
        assert_eq!(a.validators, b.validators);
        assert_eq!(a.boundaries, b.boundaries);
    }

    /// The merge pipeline end to end, the grow case inverted: after the
    /// gate fires, the epoch in flight still resolves routing against the
    /// two children while the lookahead resolves the reunified parent, and
    /// the merged committee starts at full ready strength.
    #[test]
    fn merge_lookahead_resolves_parent_while_active_resolves_children() {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let sibling = ShardId::leaf(1, 1);
        let mut state = merge_grow_state(0);
        // Staff the sibling so both tries are prefix-complete.
        let mut sibling_members = Vec::new();
        for i in 100..104u64 {
            let id = ValidatorId::new(i);
            sibling_members.push(id);
            state.validators.insert(
                id,
                validator_record(
                    i,
                    0,
                    ValidatorStatus::OnShard {
                        shard: sibling,
                        ready: true,
                        placed_at_epoch: Epoch::GENESIS,
                    },
                ),
            );
        }
        state.shard_committees.insert(
            sibling,
            ShardCommittee {
                members: sibling_members.clone(),
            },
        );
        state.next_shard_committees.insert(
            sibling,
            ShardCommittee {
                members: sibling_members,
            },
        );

        let merge = merge_assertion(parent);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), right, &merge);
        for (id, seat) in keepers_of(&state, parent) {
            apply_shard_payload(
                &BlsVerifier,
                &mut state,
                &net(),
                seat.child,
                &ShardWitnessPayload::ReshapeReady {
                    validator: id,
                    child: seat.child,
                },
            );
        }
        fold_merge(&mut state);
        assert!(state.pending_reshapes.is_empty());

        let active = state.derive_topology_snapshot(net());
        let lookahead = state.derive_next_topology_snapshot(net());
        for seed in 0..32u8 {
            let owner = Address::new([seed; 31], AddressClass::Component);
            let now = active.shard_for_prefix(owner);
            let next = lookahead.shard_for_prefix(owner);
            if now == left || now == right {
                // The children's traffic remaps to their reunified parent.
                assert_eq!(next, parent, "{owner:?} routed to {next:?}");
            } else {
                // Anything outside the merge is untouched.
                assert_eq!(now, sibling);
                assert_eq!(next, sibling);
            }
        }
        // The merged committee starts at full ready strength.
        assert_eq!(state.next_shard_committees[&parent].members.len(), 4);
        let ready = state.ready_consensus_members(&state.next_shard_committees);
        assert_eq!(ready[&parent].len(), 4);
        // The pending placeholder never projects as a snap-sync anchor.
        assert!(lookahead.boundary(parent).is_none());
    }

    /// A merge assertion under `parent`, in the epoch these tests date
    /// every assertion to.
    fn merge_assertion(parent: ShardId) -> ShardWitnessPayload {
        ShardWitnessPayload::ScheduleMerge {
            parent,
            epoch: Epoch::GENESIS,
            settling: None,
        }
    }

    /// `routing_committees()` resolves a dissolved merging child to the
    /// frozen committee that ran it to its terminal crossing — its own
    /// serving members — never the keeper mix nor the reunified parent.
    ///
    /// This is the property a merge keeper relies on to snap-sync the
    /// sibling child it does not co-host: the committee routing resolves
    /// must be the one still subscribed and serving that child through the
    /// drain. Drives the real merge fold and reads back through the same
    /// schedule path production routes on.
    #[test]
    fn routing_committees_resolves_a_merging_child_to_its_own_terminal_committee() {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let sibling = ShardId::leaf(1, 1);
        let mut state = merge_grow_state(0);
        // Staff the sibling so both tries are prefix-complete.
        let mut sibling_members = Vec::new();
        for i in 100..104u64 {
            let id = ValidatorId::new(i);
            sibling_members.push(id);
            state.validators.insert(
                id,
                validator_record(
                    i,
                    0,
                    ValidatorStatus::OnShard {
                        shard: sibling,
                        ready: true,
                        placed_at_epoch: Epoch::GENESIS,
                    },
                ),
            );
        }
        state.shard_committees.insert(
            sibling,
            ShardCommittee {
                members: sibling_members.clone(),
            },
        );
        state.next_shard_committees.insert(
            sibling,
            ShardCommittee {
                members: sibling_members,
            },
        );

        // The frozen active committees that keep serving each child through
        // its terminal crossing — the set a keeper's fetch must reach. The
        // merge mutates `next_shard_committees` only, so these stay put.
        let serving = |state: &BeaconState, shard| -> BTreeSet<ValidatorId> {
            state.shard_committees[&shard]
                .members
                .iter()
                .copied()
                .collect()
        };
        let left_serving = serving(&state, left);
        let right_serving = serving(&state, right);

        // Drive the merge to execution.
        let merge = merge_assertion(parent);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), right, &merge);
        for (id, seat) in keepers_of(&state, parent) {
            apply_shard_payload(
                &BlsVerifier,
                &mut state,
                &net(),
                seat.child,
                &ShardWitnessPayload::ReshapeReady {
                    validator: id,
                    child: seat.child,
                },
            );
        }
        fold_merge(&mut state);
        assert!(state.pending_reshapes.is_empty());

        // The keeper committee seated on the reunified parent — a 2+2 mix
        // of both children's validators, so it is neither child's serving
        // set: the wrong answer a keeper fetch would route to.
        let keepers: BTreeSet<ValidatorId> = state.next_shard_committees[&parent]
            .members
            .iter()
            .copied()
            .collect();

        // The schedule the beacon holds at the merge-execution commit: the
        // in-flight window still carries the children; the lookahead carries
        // the reunified parent.
        let active = Arc::new(state.derive_topology_snapshot(net()));
        let lookahead = Arc::new(state.derive_next_topology_snapshot(net()));
        let mut schedule = TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(5), active);
        schedule.insert_lookahead(Epoch::new(6), lookahead);
        let routing = schedule.routing_committees();

        let route = |shard| -> BTreeSet<ValidatorId> {
            routing.get(&shard).into_iter().flatten().copied().collect()
        };
        // Each dissolved child routes to its own frozen serving committee.
        assert_eq!(
            route(left),
            left_serving,
            "the left child must route to its own serving committee",
        );
        assert_eq!(
            route(right),
            right_serving,
            "the right child must route to its own serving committee",
        );
        // And never to the keeper mix — the failure the prod merge hit.
        assert_ne!(
            route(left),
            keepers,
            "the left child must not route to the keeper committee",
        );
        assert_ne!(
            route(right),
            keepers,
            "the right child must not route to the keeper committee",
        );
        // The reunified parent routes to its keeper committee.
        assert_eq!(
            route(parent),
            keepers,
            "the reunified parent must route to its keeper committee",
        );
    }

    // ─── an id is taken up only once its previous life has left ─────────

    /// The record a shard leaves behind once its chain has ended at
    /// `terminal`, its handoff stamped complete in `handoff_complete`.
    fn departed_boundary(terminal: Epoch, handoff_complete: Epoch) -> ShardBoundary {
        ShardBoundary {
            terminal_epoch: Some(terminal),
            handoff_complete: Some(handoff_complete),
            ..live_boundary()
        }
    }

    /// Leave under `shard` what a chain that ran there kept beside its
    /// boundary record: its produced mark, a fullness mean off idle and
    /// a completed recovery.
    fn having_run(state: &mut BeaconState, shard: ShardId) {
        state.advanced.insert(shard);
        state.fullness.insert(
            shard,
            ShardFullness {
                compute: 9_000,
                ..ShardFullness::IDLE
            },
        );
        state.recoveries.insert(
            shard,
            vec![RecoveryBinding {
                rotated_at: Epoch::new(2),
                attested_frontier: BlockHeight::new(3),
                completed: true,
            }],
        );
    }

    /// Whether `shard` carries nothing a chain that ran there kept.
    fn starts_afresh(state: &BeaconState, shard: ShardId) -> bool {
        !state.advanced.contains(&shard)
            && !state.recoveries.contains_key(&shard)
            && !state.pending_recoveries.contains_key(&shard)
            && state
                .fullness
                .get(&shard)
                .is_none_or(|mean| *mean == ShardFullness::IDLE)
    }

    /// The fold that drops a terminal record stamped in `stamp`: the
    /// first whose window opens past the record's evidence expiry.
    fn dropping_fold(stamp: Epoch) -> Epoch {
        Epoch::new(stamp.inner() + TERMINAL_EVIDENCE_EPOCHS + 2)
    }

    /// The assertions a reshape's sources make of it in every window
    /// their load holds.
    type Triggers = Vec<(ShardId, ShardWitnessPayload)>;

    /// The quiet assertions of every latched reshape, for a chunk from the
    /// one shard the fixture contributes for.
    fn quiet_payloads(state: &BeaconState) -> Vec<ShardWitnessPayload> {
        quiet_assertions(state)
            .into_iter()
            .map(|(_, payload)| payload)
            .collect()
    }

    /// Whether `target`'s pending reshape has latched its drain and is
    /// not yet scheduled.
    fn drain_latched(state: &BeaconState, target: ShardId) -> bool {
        let reshape = &state.pending_reshapes[&target];
        let admitted = match reshape {
            PendingReshape::Split { admitted, .. } => Some(*admitted),
            PendingReshape::Merge { admitted, .. } => *admitted,
        };
        reshape.scheduled_terminal().is_none()
            && admitted.is_some_and(|admitted| admitted.drain_by.is_some())
    }

    /// Fold each of `triggers` from its source.
    fn assert_triggers(state: &mut BeaconState, triggers: &[(ShardId, ShardWitnessPayload)]) {
        for (source, trigger) in triggers {
            apply_shard_payload(&BlsVerifier, state, &net(), *source, trigger);
        }
    }

    /// Mark every seat of every pending reshape ready, each through the
    /// chain its holder signals on.
    fn ready_every_seat(state: &mut BeaconState) {
        let seats: Vec<(ShardId, ValidatorId, ShardId)> = state
            .pending_reshapes
            .iter()
            .flat_map(|(target, reshape)| match reshape {
                PendingReshape::Split { cohort, .. } => cohort
                    .iter()
                    .map(|(id, seat)| (*target, *id, seat.child))
                    .collect::<Vec<_>>(),
                PendingReshape::Merge { keepers, .. } => keepers
                    .iter()
                    .map(|(id, seat)| (seat.child, *id, seat.child))
                    .collect(),
            })
            .collect();
        for (source, validator, child) in seats {
            apply_shard_payload(
                &BlsVerifier,
                state,
                &net(),
                source,
                &ShardWitnessPayload::ReshapeReady { validator, child },
            );
        }
    }

    /// One whole fold of the next epoch: each of `triggers` asserted by
    /// its source, as a trigger that still holds is in every window, and
    /// every seat an admission drew marked ready in the same fold, which
    /// no cohort syncs faster than. The fold applies a window's witnesses
    /// before it drops any record, so the assertions made here read the
    /// records the fold before left standing.
    fn fold_asserting(state: &mut BeaconState, triggers: &[(ShardId, ShardWitnessPayload)]) {
        assert_triggers(state, triggers);
        assert_quiet(state);
        ready_every_seat(state);
        apply_next_epoch(state, &[]);
    }

    /// [`merge_grow_state`] on a one-second grid, beside the parent
    /// `leaf(1, 0)` its children merge under and the assertions both
    /// make of the merge.
    fn merge_asserted() -> (BeaconState, ShardId, Triggers) {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let mut state = merge_grow_state(0);
        state.chain_config.epoch_duration_ms = 1_000;
        let triggers = vec![
            (left, merge_assertion(parent)),
            (right, merge_assertion(parent)),
        ];
        (state, parent, triggers)
    }

    /// [`merge_asserted`] where the parent's own chain ended at a split
    /// and both children produced past genesis in the current epoch, the
    /// earliest fold either can assert the merge in: the parent's
    /// terminal record stands, stamped there.
    fn merge_over_a_departed_parent() -> (BeaconState, ShardId, Triggers) {
        let (mut state, parent, triggers) = merge_asserted();
        state.boundaries.insert(
            parent,
            departed_boundary(Epoch::new(3), state.current_epoch),
        );
        having_run(&mut state, parent);
        state
            .advanced
            .extend(<[ShardId; 2]>::from(parent.children()));
        (state, parent, triggers)
    }

    /// [`grow_state`] on a one-second grid, beside the shard
    /// `leaf(1, 0)` and the assertion it makes of its split.
    fn split_asserted() -> (BeaconState, ShardId, Triggers) {
        let p = ShardId::leaf(1, 0);
        let mut state = grow_state(4);
        state.chain_config.epoch_duration_ms = 1_000;
        state.boundaries.insert(p, live_boundary());
        let triggers = vec![(
            p,
            ShardWitnessPayload::ScheduleSplit {
                shard: p,
                epoch: Epoch::GENESIS,
                settling: None,
            },
        )];
        (state, p, triggers)
    }

    /// [`split_asserted`] where each of `held` is a child whose own
    /// chain ended at a merge into the target, which produced past
    /// genesis in the current epoch, the earliest fold it can assert its
    /// split in: each one's terminal record stands, stamped there.
    fn split_over_departed_children(held: &[ShardId]) -> (BeaconState, ShardId, Triggers) {
        let (mut state, p, triggers) = split_asserted();
        for child in held {
            state.boundaries.insert(
                *child,
                departed_boundary(Epoch::new(3), state.current_epoch),
            );
            having_run(&mut state, *child);
        }
        state.advanced.insert(p);
        (state, p, triggers)
    }

    /// Whether nothing an admitted reshape arms is armed for `leaves`,
    /// the shards a reshape keyed by `target` would end: no record
    /// pends, no observer is out of the pool and no keeper is pinned,
    /// and the window the state would publish next shows none of the
    /// leaves pending, floors none of their settled windows and reads
    /// none as scheduled to terminate.
    fn nothing_is_armed(state: &BeaconState, target: ShardId, leaves: &[ShardId]) -> bool {
        let floors = state.live_settled_window_floors();
        let published = state.derive_next_topology_snapshot(net());
        let next = state.current_epoch.next();
        let opening = state.chain_config.epoch_windows().window_of(next).start;
        let mut schedule = TopologySchedule::new(
            state.chain_config.epoch_windows(),
            next,
            Arc::new(published.clone()),
        );
        schedule.insert_lookahead(next, Arc::new(published.clone()));
        let unseated = state.validators.iter().all(|(id, record)| {
            !matches!(record.status, ValidatorStatus::Observing { .. })
                && leaves.iter().all(|leaf| {
                    !state.is_merge_keeper(*leaf, *id)
                        && published.reshape_keeper_parent(*leaf, *id).is_none()
                        && published.reshape_observer_child(*leaf, *id).is_none()
                })
        });
        !state.pending_reshapes.contains_key(&target)
            && unseated
            && leaves.iter().all(|leaf| {
                !state.reshape_involves(*leaf)
                    && !floors.contains_key(leaf)
                    && !published.split_pending(*leaf)
                    && published.settled_window_floor(*leaf).is_none()
                    && !schedule.termination_scheduled(*leaf, opening)
                    && partner_evidence(&schedule, *leaf, opening)
                        == Evidence::Live { terminating: false }
            })
    }

    /// A merge whose parent id still carries the terminal record of the
    /// parent's own chain is not admitted, fold after fold: neither half
    /// is recorded, no keeper is drawn and no window shows either child
    /// pending. The assertions the fold that drops the record carries
    /// are read while it stands, so the next fold's are the first
    /// admitted: both halves pair there, and with every keeper ready in
    /// that fold the cut is the window after and the fold at it seats
    /// the parent on a placeholder.
    #[test]
    fn a_merge_is_not_admitted_while_its_parents_terminal_record_stands() {
        let (mut state, parent, triggers) = merge_over_a_departed_parent();
        let children: [ShardId; 2] = parent.children().into();
        let members = state.next_shard_committees.clone();
        let drops = dropping_fold(state.current_epoch);

        while state.current_epoch < drops {
            assert!(state.terminal_record_stands(parent));
            fold_asserting(&mut state, &triggers);
            assert!(
                nothing_is_armed(&state, parent, &children),
                "admitted at the fold of {:?} over a standing record",
                state.current_epoch,
            );
            for child in children {
                assert_eq!(state.boundaries[&child].terminal_epoch, None);
                assert_eq!(state.next_shard_committees[&child], members[&child]);
            }
        }
        assert_eq!(state.current_epoch, drops);
        assert!(!state.boundaries.contains_key(&parent));

        assert_triggers(&mut state, &triggers);
        let PendingReshape::Merge {
            halves,
            keepers,
            admitted,
            scheduled_terminal,
        } = &state.pending_reshapes[&parent]
        else {
            panic!("the fold after the record drops admits the merge");
        };
        assert_eq!(halves.len(), 2);
        assert_eq!(keepers.len(), 4);
        assert!(admitted.is_some());
        assert_eq!(*scheduled_terminal, None);

        fold_asserting(&mut state, &triggers);
        assert!(drain_latched(&state, parent));
        fold_asserting(&mut state, &triggers);
        assert_eq!(
            state.pending_reshapes[&parent].scheduled_terminal(),
            Some(drops.next().next().next()),
        );

        fold_asserting(&mut state, &triggers);
        assert!(state.pending_reshapes.is_empty());
        assert!(state.next_shard_committees.contains_key(&parent));
        assert_eq!(state.boundaries[&parent].block_hash, BlockHash::ZERO);
        assert_eq!(state.boundaries[&parent].terminal_epoch, None);
    }

    /// A split is not admitted while either child id still carries the
    /// terminal record of that child's own chain: no cohort leaves the
    /// pool and no window shows the shard pending. The fold after the
    /// one that drops the last such record admits it and draws its
    /// cohort.
    #[test]
    fn a_split_is_not_admitted_while_a_childs_terminal_record_stands() {
        let p = ShardId::leaf(1, 0);
        let (left, right) = p.children();
        for held in [vec![left], vec![right], vec![left, right]] {
            let (mut state, p, triggers) = split_over_departed_children(&held);
            let pooled = state.pooled_validators();
            let members = state.next_shard_committees[&p].clone();
            let drops = dropping_fold(state.current_epoch);

            while state.current_epoch < drops {
                for child in &held {
                    assert!(state.terminal_record_stands(*child));
                }
                fold_asserting(&mut state, &triggers);
                assert!(
                    nothing_is_armed(&state, p, &[p]),
                    "admitted at the fold of {:?} over the standing records of {held:?}",
                    state.current_epoch,
                );
                assert_eq!(state.pooled_validators(), pooled);
                assert_eq!(state.next_shard_committees[&p], members);
                assert_eq!(state.boundaries[&p].terminal_epoch, None);
            }
            assert_eq!(state.current_epoch, drops);
            for child in &held {
                assert!(!state.boundaries.contains_key(child));
            }

            assert_triggers(&mut state, &triggers);
            assert_eq!(
                cohort_of(&state, p).len(),
                4,
                "the fold after the records of {held:?} drop admits the split",
            );
            assert!(state.pooled_validators().is_empty());

            fold_asserting(&mut state, &triggers);
            assert!(drain_latched(&state, p));
            fold_asserting(&mut state, &triggers);
            assert_eq!(
                state.pending_reshapes[&p].scheduled_terminal(),
                Some(drops.next().next().next()),
            );

            fold_asserting(&mut state, &triggers);
            assert!(state.pending_reshapes.is_empty());
            for child in [left, right] {
                assert!(state.next_shard_committees.contains_key(&child));
                assert_eq!(state.boundaries[&child].block_hash, BlockHash::ZERO);
                assert_eq!(state.boundaries[&child].terminal_epoch, None);
            }
        }
    }

    /// A merge whose parent id carries no record, and a split whose
    /// child ids carry none, are admitted by the first assertion, latch
    /// their drain at the fold that finds them ready, and are scheduled
    /// by the fold after it, which folds their shards' quiet.
    #[test]
    fn a_reshape_onto_ids_carrying_no_record_is_admitted_at_once() {
        let (mut state, parent, triggers) = merge_asserted();
        let asserted_at = state.current_epoch;
        assert_triggers(&mut state, &triggers);
        assert_eq!(keepers_of(&state, parent).len(), 4);
        fold_asserting(&mut state, &triggers);
        assert!(drain_latched(&state, parent));
        fold_asserting(&mut state, &triggers);
        assert_eq!(
            state.pending_reshapes[&parent].scheduled_terminal(),
            Some(asserted_at.next().next().next()),
        );

        let (mut state, p, triggers) = split_asserted();
        let asserted_at = state.current_epoch;
        assert_triggers(&mut state, &triggers);
        assert_eq!(cohort_of(&state, p).len(), 4);
        fold_asserting(&mut state, &triggers);
        assert!(drain_latched(&state, p));
        fold_asserting(&mut state, &triggers);
        assert_eq!(
            state.pending_reshapes[&p].scheduled_terminal(),
            Some(asserted_at.next().next().next()),
        );
    }

    /// A parent reformed on an id it held before does not read as having
    /// produced on the strength of its earlier chain: the produced mark
    /// leaves with the terminal record, so the merging children's
    /// handoff stays unstamped once the parent is seated and has
    /// committed nothing. The earlier chain's fullness mean and recovery
    /// history leave with it too, so the parent starts idle and
    /// unrecovered.
    #[test]
    fn a_reformed_parent_does_not_read_live_off_its_previous_life() {
        let (mut state, parent, triggers) = merge_over_a_departed_parent();
        let children: [ShardId; 2] = parent.children().into();
        let bound = dropping_fold(state.current_epoch).inner() + 5;

        while !state.shard_committees.contains_key(&parent) {
            assert!(state.current_epoch.inner() < bound, "the merge never ran");
            fold_asserting(&mut state, &triggers);
        }

        for child in children {
            assert!(state.boundaries[&child].terminal_epoch.is_some());
            assert_eq!(
                state.boundaries[&child].handoff_complete, None,
                "{child:?} is stamped handed off to a parent that has committed nothing",
            );
        }
        assert!(starts_afresh(&state, parent));
    }

    /// The same for split children formed on ids they held before: the
    /// splitting parent's handoff stays unstamped while neither child
    /// has committed anything.
    #[test]
    fn a_reformed_child_does_not_read_live_off_its_previous_life() {
        let p = ShardId::leaf(1, 0);
        let (left, right) = p.children();
        let (mut state, p, triggers) = split_over_departed_children(&[left, right]);
        let bound = dropping_fold(state.current_epoch).inner() + 5;

        while !state.shard_committees.contains_key(&left) {
            assert!(state.current_epoch.inner() < bound, "the split never ran");
            fold_asserting(&mut state, &triggers);
        }

        assert!(state.boundaries[&p].terminal_epoch.is_some());
        assert_eq!(
            state.boundaries[&p].handoff_complete, None,
            "the parent is stamped handed off to children that have committed nothing",
        );
        for child in [left, right] {
            assert!(starts_afresh(&state, child));
        }
    }

    /// What each published window says of `shard`'s evidence at its
    /// opening instant and at its last, from the window the next fold
    /// publishes to the first that runs `shard`.
    fn evidence_until_live(
        mut state: BeaconState,
        shard: ShardId,
        triggers: &[(ShardId, ShardWitnessPayload)],
    ) -> Vec<(Epoch, Evidence, Evidence)> {
        let windows = state.chain_config.epoch_windows();
        let bound = dropping_fold(state.current_epoch).inner() + 5;
        let mut schedule = TopologySchedule::new(
            windows,
            state.current_epoch,
            Arc::new(state.derive_topology_snapshot(net())),
        );
        let mut read = Vec::new();
        loop {
            assert!(
                state.current_epoch.inner() < bound,
                "the id never ran again"
            );
            fold_asserting(&mut state, triggers);
            let window = state.current_epoch.next();
            schedule.insert(window, Arc::new(state.derive_next_topology_snapshot(net())));
            let span = windows.window_of(window);
            let last = WeightedTimestamp::from_millis(span.end.as_millis() - 1);
            let at = |anchor| partner_evidence(&schedule, shard, anchor);
            read.push((window, at(span.start), at(last)));
            if matches!(at(last), Evidence::Live { .. }) {
                return read;
            }
        }
    }

    /// What [`evidence_until_live`] reads of an id whose terminal record
    /// is stamped in `stamp` and which the first fold allowed takes up
    /// again, its cohort ready in the fold that admits it and its shards
    /// quiet in the fold after the one that latches its drain: readable
    /// to the opening instant of the window its evidence expires at,
    /// unreadable from there through the four whole windows after, and
    /// live in the next. Each further fold a cohort takes to sync, or a
    /// shard to quiet, adds a whole unreadable window.
    fn readable_then_unreadable_then_live(stamp: Epoch) -> Vec<(Epoch, Evidence, Evidence)> {
        let expires_at = stamp.inner() + TERMINAL_EVIDENCE_EPOCHS + 1;
        let live = Evidence::Live { terminating: false };
        (stamp.inner() + 2..expires_at)
            .map(|window| (window, Evidence::Readable, Evidence::Readable))
            .chain([
                (expires_at, Evidence::Readable, Evidence::Unreadable),
                (expires_at + 1, Evidence::Unreadable, Evidence::Unreadable),
                (expires_at + 2, Evidence::Unreadable, Evidence::Unreadable),
                (expires_at + 3, Evidence::Unreadable, Evidence::Unreadable),
                (expires_at + 4, Evidence::Unreadable, Evidence::Unreadable),
                (expires_at + 5, live, live),
            ])
            .map(|(window, opening, last)| (Epoch::new(window), opening, last))
            .collect()
    }

    /// How many of the windows `read` covers say unreadable from their
    /// opening instant to their last.
    fn unreadable_windows(read: &[(Epoch, Evidence, Evidence)]) -> usize {
        read.iter()
            .filter(|(_, opening, last)| {
                (*opening, *last) == (Evidence::Unreadable, Evidence::Unreadable)
            })
            .count()
    }

    /// No published window runs a merge's parent id until the terminal
    /// evidence of the parent's own chain has read unreadable through
    /// three whole windows and the rest of a fourth, taking the merge up
    /// at the first fold allowed.
    #[test]
    fn a_merged_parent_runs_only_windows_after_its_old_evidence_stops_reading() {
        let (state, parent, triggers) = merge_over_a_departed_parent();
        let stamp = state.current_epoch;
        let read = evidence_until_live(state, parent, &triggers);
        assert_eq!(read, readable_then_unreadable_then_live(stamp));
        assert!(unreadable_windows(&read) >= 3);
    }

    /// The same for each child id of a split.
    #[test]
    fn a_split_child_runs_only_windows_after_its_old_evidence_stops_reading() {
        let p = ShardId::leaf(1, 0);
        let (left, right) = p.children();
        for child in [left, right] {
            let (state, _, triggers) = split_over_departed_children(&[left, right]);
            let stamp = state.current_epoch;
            let read = evidence_until_live(state, child, &triggers);
            assert_eq!(read, readable_then_unreadable_then_live(stamp));
            assert!(unreadable_windows(&read) >= 3);
        }
    }

    // ─── a reformed id takes no crossing of its previous life ───────────

    /// A block and the witness chunk a fold takes from it.
    type Contribution = (BlockHeader, Vec<ShardWitnessPayload>, Vec<Hash>);

    /// The pool a crossing's one witness leaf deposits into.
    const DEPOSITED: StakePoolId = test_pool(200);

    /// The instant [`crossing_of_the_previous_life`] is certified at.
    const OLD_CERTIFIED: u64 = 1_500;

    /// A crossing a chain that ran under `shard` made in its first
    /// windows, genuine and committed: height 20, anchored at 900 and
    /// certified at [`OLD_CERTIFIED`], carrying one deposit as the first
    /// leaf of its witness window.
    fn crossing_of_the_previous_life(shard: ShardId) -> Contribution {
        block_carrying(
            shard,
            20,
            900,
            vec![ShardWitnessPayload::StakeDeposit {
                pool_id: DEPOSITED,
                amount: Stake::from_whole_tokens(1),
            }],
            BlockHeaderParts::default(),
        )
    }

    /// The first instant past the cut `shard`'s chain ends at, where its
    /// terminal anchors.
    fn past_the_cut(state: &BeaconState, shard: ShardId) -> u64 {
        let terminal = state.boundaries[&shard]
            .terminal_epoch
            .expect("the shard is scheduled to end");
        let cut = state.chain_config.epoch_windows().window_of(terminal).end;
        cut.as_millis() + 100
    }

    /// The terminal of a chain ending at `height`, anchored at `anchor_ms`
    /// and carrying `rest`.
    fn terminal_at(
        shard: ShardId,
        height: u64,
        anchor_ms: u64,
        rest: BlockHeaderParts,
    ) -> Contribution {
        block_carrying(
            shard,
            height,
            anchor_ms,
            Vec::new(),
            BlockHeaderParts {
                terminal_settled_txs: Some(SettledTxsRoot::ZERO),
                ..rest
            },
        )
    }

    /// A crossing of `shard` at `height` and the instant it is certified
    /// at: anchored short of the second cut after `past_ms` and certified
    /// past it, carrying no witness.
    fn crossing_after(shard: ShardId, height: u64, past_ms: u64) -> (Contribution, u64) {
        let cut = (past_ms / 1_000 + 2) * 1_000;
        let block = block_carrying(
            shard,
            height,
            cut - 100,
            Vec::new(),
            BlockHeaderParts::default(),
        );
        (block, cut + 500)
    }

    /// Whether `shard` still stands on the placeholder its reshape left,
    /// with nothing of a chain's production under it.
    fn awaits_its_genesis(state: &BeaconState, shard: ShardId) -> bool {
        state.boundaries[&shard].block_hash == BlockHash::ZERO
            && state.boundaries[&shard].boundary_qc.is_none()
            && state.fold_watermark(shard) == 0
            && !state.advanced.contains(&shard)
            && !state.pools.contains_key(&DEPOSITED)
    }

    /// The parent recorded at `height` and split, by the first reshape
    /// admitted once the records of the chains that ran under its child
    /// ids have dropped, into children seated on placeholders. The parent
    /// formed when those chains merged, so its height line runs on above
    /// their terminals.
    fn split_reforming_its_children(height: u64) -> (BeaconState, ShardId) {
        let p = ShardId::leaf(1, 0);
        let (left, right) = p.children();
        let (mut state, p, triggers) = split_over_departed_children(&[left, right]);
        state
            .boundaries
            .get_mut(&p)
            .expect("the splitting parent is recorded")
            .height = BlockHeight::new(height);
        let bound = dropping_fold(state.current_epoch).inner() + 5;
        while !state.next_shard_committees.contains_key(&left) {
            assert!(state.current_epoch.inner() < bound, "the split never ran");
            fold_asserting(&mut state, &triggers);
        }
        for child in [left, right] {
            assert!(awaits_its_genesis(&state, child));
        }
        (state, p)
    }

    /// The children recorded at `heights` and merged, by the first
    /// reshape admitted once the record of the chain that ran under their
    /// parent's id has dropped, into a parent seated on a placeholder.
    /// The children formed when that chain split, so their height lines
    /// run on above its terminal.
    fn merge_reforming_its_parent(heights: [u64; 2]) -> (BeaconState, ShardId) {
        let (mut state, parent, triggers) = merge_over_a_departed_parent();
        let children: [ShardId; 2] = parent.children().into();
        for (child, height) in children.into_iter().zip(heights) {
            state
                .boundaries
                .get_mut(&child)
                .expect("each merging child is recorded")
                .height = BlockHeight::new(height);
        }
        let bound = dropping_fold(state.current_epoch).inner() + 5;
        while !state.next_shard_committees.contains_key(&parent) {
            assert!(state.current_epoch.inner() < bound, "the merge never ran");
            fold_asserting(&mut state, &triggers);
        }
        assert!(awaits_its_genesis(&state, parent));
        (state, parent)
    }

    /// The schedule an applying fold publishes: the window it freezes,
    /// and the lookahead it publishes for the window after.
    fn published_by(state: &BeaconState) -> TopologySchedule {
        let epoch = state.current_epoch;
        let frozen = Arc::new(state.derive_topology_snapshot(net()));
        let mut schedule = TopologySchedule::new(
            state.chain_config.epoch_windows(),
            epoch,
            Arc::clone(&frozen),
        );
        schedule.insert(epoch, frozen);
        schedule.insert_lookahead(
            epoch.next(),
            Arc::new(state.derive_next_topology_snapshot(net())),
        );
        schedule
    }

    /// Fold `triggers` until the reshape they assert applies, the fold
    /// that seats `successor` in the lookahead committee.
    fn applying(
        (mut state, target, triggers): (BeaconState, ShardId, Triggers),
        successor: ShardId,
    ) -> (BeaconState, ShardId) {
        let bound = state.current_epoch.inner() + 8;
        while !state.next_shard_committees.contains_key(&successor) {
            assert!(state.current_epoch.inner() < bound, "the reshape never ran");
            fold_asserting(&mut state, &triggers);
        }
        (state, target)
    }

    /// A reshape's successors form at the window the applying fold's
    /// lookahead opens: that window runs them, from the epoch their
    /// records name, while the window the fold freezes still runs their
    /// predecessors and carries the successors' records without running
    /// them.
    #[test]
    fn a_reshape_stamps_its_successors_formed_at_the_first_window_running_them() {
        let split = split_asserted();
        let left = split.1.children().0;
        let (split, p) = applying(split, left);
        let merge = merge_asserted();
        let reformed = merge.1;
        let (merge, parent) = applying(merge, reformed);
        let cases: [(BeaconState, Vec<ShardId>, Vec<ShardId>); 2] = [
            (split, <[ShardId; 2]>::from(p.children()).to_vec(), vec![p]),
            (
                merge,
                vec![parent],
                <[ShardId; 2]>::from(parent.children()).to_vec(),
            ),
        ];
        for (state, successors, predecessors) in cases {
            let schedule = published_by(&state);
            let windows = state.chain_config.epoch_windows();
            let first = state.current_epoch.next();
            let opens = windows.window_of(first).start;
            let frozen = schedule
                .at(windows.window_of(state.current_epoch).start)
                .expect("the frozen window is held");
            let lookahead = schedule.at(opens).expect("the lookahead is held");
            for successor in successors {
                assert_eq!(state.boundaries[&successor].formed, first);
                assert_eq!(lookahead.life(successor), Some(first));
                assert_eq!(frozen.life(successor), None);
                assert_eq!(frozen.formed(successor), Some(first));
                assert_eq!(
                    schedule.formed(successor, opens),
                    Some(Formed {
                        epoch: first,
                        opens
                    })
                );
            }
            for predecessor in predecessors {
                assert!(frozen.life(predecessor).is_some());
                assert_eq!(lookahead.life(predecessor), None);
            }
        }
    }

    /// An id seated again after the chain that ran under it ended names a
    /// later formation than that chain's: the successor forms past the
    /// fold that dropped the earlier chain's record, and so past its
    /// terminal and its own formation. While that record stands, the
    /// window carries its formation and runs no chain under the id.
    #[test]
    fn a_reseated_id_names_a_later_formation_than_its_previous_life() {
        let p = ShardId::leaf(1, 0);
        let children: [ShardId; 2] = p.children().into();
        let (before, _, _) = split_over_departed_children(&children);
        let (state, _) = split_reforming_its_children(40);
        let (before_merge, _, _) = merge_over_a_departed_parent();
        let (merged, _) = merge_reforming_its_parent([30, 34]);
        let cases = [
            (&before, &state, children.to_vec()),
            (&before_merge, &merged, vec![p]),
        ];
        for (before, after, reseated) in cases {
            let schedule = published_by(before);
            let windows = before.chain_config.epoch_windows();
            let window = schedule
                .at(windows.window_of(before.current_epoch).start)
                .expect("the frozen window is held");
            for id in reseated {
                let previous = &before.boundaries[&id];
                assert_eq!(window.formed(id), Some(previous.formed));
                assert_eq!(window.life(id), None, "{id:?} runs no chain here");
                let terminal = previous.terminal_epoch.expect("the earlier chain ended");
                let stamp = previous.handoff_complete.expect("its handoff completed");
                let formed = after.boundaries[&id].formed;
                assert_eq!(formed, after.current_epoch.next());
                assert!(formed > dropping_fold(stamp), "{id:?} formed at {formed:?}");
                assert!(formed > terminal);
                assert!(formed > previous.formed);
            }
        }
    }

    /// A split child formed on an id a chain ran under before takes no
    /// crossing of that chain. The crossing is genuine, and folded over
    /// the child's placeholder it would stand as the child's record, mark
    /// the child produced with nothing committed, leave the parent's
    /// terminal no pending child to seed, and apply its witness window
    /// over from the first leaf. The fold takes nothing from it, so the
    /// parent's terminal seeds the child and the child's own first
    /// crossing, above its genesis, is the first to record.
    #[test]
    fn a_reformed_split_child_takes_no_crossing_of_its_previous_life() {
        let (mut state, p) = split_reforming_its_children(40);
        let (left, right) = p.children();
        let halves = state.reshape_parent_halves.clone();
        assert!(halves.contains_key(&left));

        fold_blocks(
            &mut state,
            OLD_CERTIFIED,
            vec![crossing_of_the_previous_life(left)],
        );

        assert!(awaits_its_genesis(&state, left));
        assert_eq!(state.boundaries[&p].handoff_complete, None);
        assert_eq!(state.reshape_parent_halves, halves);

        let pair = SplitChildRoots {
            left: StateRoot::from_raw(Hash::from_bytes(b"left subtree")),
            right: StateRoot::from_raw(Hash::from_bytes(b"right subtree")),
        };
        let anchor = past_the_cut(&state, p);
        let terminal = terminal_at(
            p,
            41,
            anchor,
            BlockHeaderParts {
                state_root: pair.composed_root(),
                split_child_roots: Some(pair),
                ..BlockHeaderParts::default()
            },
        );
        let genesis = |child| {
            Block::split_child_genesis_from_terminal(child, &terminal.0)
                .expect("the pair composes to the terminal's root")
                .0
        };
        let seeds = [(left, genesis(left)), (right, genesis(right))];
        fold_blocks(&mut state, anchor + 400, vec![terminal]);
        for (child, genesis) in &seeds {
            assert_eq!(state.boundaries[child].block_hash, genesis.hash());
            assert_eq!(state.boundaries[child].height, BlockHeight::new(42));
            assert!(!state.advanced.contains(child));
        }

        let (first, certified) = crossing_after(left, 43, anchor);
        let first_hash = first.0.hash();
        fold_blocks(&mut state, certified, vec![first]);
        assert_eq!(state.boundaries[&left].block_hash, first_hash);
        assert!(state.advanced.contains(&left));
        assert!(!state.reshape_parent_halves.contains_key(&left));
    }

    /// A split child whose genesis the fold never seeded records its own
    /// first crossing over the placeholder: its chain begins above its
    /// parent's terminal, and so above the height the placeholder holds.
    #[test]
    fn an_unseeded_split_childs_first_crossing_lands_over_its_placeholder() {
        let (mut state, p) = split_reforming_its_children(40);
        let (left, _) = p.children();
        let anchor = past_the_cut(&state, p);

        let (first, certified) = crossing_after(left, 43, anchor);
        let first_hash = first.0.hash();
        fold_blocks(&mut state, certified, vec![first]);

        assert_eq!(state.boundaries[&left].block_hash, first_hash);
        assert_eq!(state.boundaries[&left].height, BlockHeight::new(43));
        assert!(state.advanced.contains(&left));
    }

    /// A merge parent formed on an id a chain ran under before takes no
    /// crossing of that chain: its placeholder stands, so the two
    /// children's terminals compose its genesis and its own first
    /// crossing, above that genesis, is the first to record.
    #[test]
    fn a_reformed_merge_parent_takes_no_crossing_of_its_previous_life() {
        let (mut state, parent) = merge_reforming_its_parent([30, 34]);
        let (left, right) = parent.children();

        fold_blocks(
            &mut state,
            OLD_CERTIFIED,
            vec![crossing_of_the_previous_life(parent)],
        );

        assert!(awaits_its_genesis(&state, parent));
        for child in [left, right] {
            assert_eq!(state.boundaries[&child].handoff_complete, None);
        }

        let anchor = past_the_cut(&state, left);
        let root = |tag: &[u8]| BlockHeaderParts {
            state_root: StateRoot::from_raw(Hash::from_bytes(tag)),
            ..BlockHeaderParts::default()
        };
        fold_blocks(
            &mut state,
            anchor + 400,
            vec![
                terminal_at(left, 35, anchor, root(b"left terminal root")),
                terminal_at(right, 36, anchor, root(b"right terminal root")),
            ],
        );
        assert_ne!(state.boundaries[&parent].block_hash, BlockHash::ZERO);
        assert_eq!(state.boundaries[&parent].height, BlockHeight::new(37));
        assert!(!state.advanced.contains(&parent));

        let (first, certified) = crossing_after(parent, 38, anchor);
        let first_hash = first.0.hash();
        fold_blocks(&mut state, certified, vec![first]);
        assert_eq!(state.boundaries[&parent].block_hash, first_hash);
        assert!(state.advanced.contains(&parent));
    }

    /// A merge parent whose keepers produce before the fold composes its
    /// genesis records its own first crossing over the placeholder: its
    /// chain begins above both children's terminals, and so above the
    /// height the placeholder holds.
    #[test]
    fn an_uncomposed_merge_parents_first_crossing_lands_over_its_placeholder() {
        let (mut state, parent) = merge_reforming_its_parent([30, 34]);
        let (left, _) = parent.children();
        let anchor = past_the_cut(&state, left);

        let (first, certified) = crossing_after(parent, 38, anchor);
        let first_hash = first.0.hash();
        fold_blocks(&mut state, certified, vec![first]);

        assert_eq!(state.boundaries[&parent].block_hash, first_hash);
        assert_eq!(state.boundaries[&parent].height, BlockHeight::new(38));
        assert!(state.advanced.contains(&parent));
    }

    // ─── recovery ahead of the reshape draws ────────────────────────────

    /// A halt-threshold miss count, as the boundary record stores it.
    fn halt_misses() -> u32 {
        u32::try_from(HALT_THRESHOLD_EPOCHS).expect("fits u32")
    }

    /// Seat `leaf(1, 1)` beside the split target with four ready members
    /// and a live record at `misses`, returning it.
    fn seat_sibling(state: &mut BeaconState, misses: u32) -> ShardId {
        let sibling = ShardId::leaf(1, 1);
        let members: Vec<ValidatorId> = (2000u64..2004).map(ValidatorId::new).collect();
        for id in &members {
            state.validators.insert(
                *id,
                validator_record(
                    id.inner(),
                    0,
                    ValidatorStatus::OnShard {
                        shard: sibling,
                        ready: true,
                        placed_at_epoch: Epoch::GENESIS,
                    },
                ),
            );
        }
        let committee = ShardCommittee { members };
        state
            .next_shard_committees
            .insert(sibling, committee.clone());
        state.shard_committees.insert(sibling, committee);
        state.boundaries.insert(
            sibling,
            ShardBoundary {
                consecutive_misses: misses,
                ..live_boundary()
            },
        );
        sibling
    }

    fn add_pooled(state: &mut BeaconState, ids: Range<u64>) {
        for id in ids {
            state.validators.insert(
                ValidatorId::new(id),
                validator_record(id, 0, ValidatorStatus::Pooled),
            );
        }
    }

    fn assert_split(state: &mut BeaconState, target: ShardId) {
        apply_shard_payload(
            &BlsVerifier,
            state,
            &net(),
            target,
            &ShardWitnessPayload::ScheduleSplit {
                shard: target,
                epoch: Epoch::GENESIS,
                settling: None,
            },
        );
    }

    /// `grow_state(pooled)` with the target on a live record, its split
    /// admitted and both children's observers ready, then gated: the cut
    /// stands scheduled for the window after the current one.
    fn split_scheduled(pooled: u64) -> (BeaconState, ShardId) {
        let p = ShardId::leaf(1, 0);
        let mut state = grow_state(pooled);
        state.boundaries.insert(p, live_boundary());
        assert_split(&mut state, p);
        for child in <[ShardId; 2]>::from(p.children()) {
            let observer = observer_for(&state, p, child);
            mark_ready(&mut state, p, observer);
        }
        schedule_quiet_splits(&mut state);
        assert_eq!(
            state
                .pending_reshapes
                .get(&p)
                .and_then(PendingReshape::scheduled_terminal),
            Some(state.current_epoch.next()),
        );
        (state, p)
    }

    /// A fork-flagged target whose cut applies at this fold is outside
    /// recovery demand: the recovery leaves it to the apply, which carries
    /// its committee into the children, and the flag drops with the seat.
    #[test]
    fn a_fork_flagged_shard_whose_cut_applies_this_fold_is_left_to_its_cut() {
        let (mut state, p) = split_scheduled(8);
        let parent: BTreeSet<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        assert!(advance_to_scheduled_cut(&mut state));
        state.fork_flagged.insert(p, BlockHeight::new(3));

        assert!(!state.recovery_demand(0).contains(&p));
        recover_committees(&mut state);
        assert!(!state.pending_recoveries.contains_key(&p));
        assert!(state.fork_flagged.contains_key(&p));

        apply_scheduled_splits(&mut state);
        let seated: BTreeSet<ValidatorId> = <[ShardId; 2]>::from(p.children())
            .iter()
            .flat_map(|child| state.next_shard_committees[child].members.iter().copied())
            .collect();
        assert!(parent.is_subset(&seated), "the cut seats the committee");

        apply_next_epoch(&mut state, &[]);
        assert!(
            !state.fork_flagged.contains_key(&p),
            "the flag drops with the seat",
        );
    }

    /// A fork-flagged target whose cut is a window out is in demand and is
    /// re-drawn before its apply. The forked members return to the pool,
    /// and the apply drops them from the frozen halves, so no forked
    /// member is seated on a child.
    #[test]
    fn a_fork_flagged_target_scheduled_a_window_out_is_redrawn_before_its_apply() {
        let (mut state, p) = split_scheduled(8);
        let forked: BTreeSet<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        state.fork_flagged.insert(p, BlockHeight::new(3));

        assert!(state.recovery_demand(0).contains(&p));
        recover_committees(&mut state);
        assert_eq!(state.pending_recoveries[&p].cause, RecoveryCause::Fork);
        assert!(!state.fork_flagged.contains_key(&p));

        assert!(advance_to_scheduled_cut(&mut state));
        apply_scheduled_splits(&mut state);
        for child in <[ShardId; 2]>::from(p.children()) {
            assert!(
                state.next_shard_committees[&child]
                    .members
                    .iter()
                    .all(|id| !forked.contains(id)),
                "a forked member is seated on {child:?}",
            );
        }
    }

    /// The witness fold runs before this fold's miss bump, so a sibling one
    /// miss short of the halt threshold is reserved there: the split it
    /// would starve is refused, and admitted once the pool funds both.
    #[test]
    fn a_shard_crossing_the_halt_threshold_this_fold_is_reserved_in_its_witness_fold() {
        let p = ShardId::leaf(1, 0);
        let mut state = grow_state(4);
        let sibling = seat_sibling(&mut state, halt_misses());
        assert!(state.halted_shards().is_empty());
        assert!(state.recovery_demand(0).is_empty());
        assert_eq!(state.recovery_demand(1), BTreeSet::from([sibling]));
        assert_eq!(state.drawable_pool_len(1), 0);

        assert_split(&mut state, p);
        assert!(!state.pending_reshapes.contains_key(&p));
        assert_eq!(state.pooled_validators().len(), 4);

        add_pooled(&mut state, 2100..2104);
        assert_split(&mut state, p);
        assert!(state.pending_reshapes.contains_key(&p));
        assert_eq!(state.pooled_validators().len(), 4, "the reserve stands");
    }

    /// Under a whole fold, the target's split contribution folds before the
    /// miss bump that takes the silent sibling past the threshold: the
    /// split is refused, and the same fold's recovery re-draws the sibling
    /// from the pool the refusal kept.
    #[test]
    fn a_split_witnessed_in_the_fold_its_sibling_halts_is_refused_for_the_recovery() {
        let p = ShardId::leaf(1, 0);
        let mut state = grow_state(4);
        let sibling = seat_sibling(&mut state, halt_misses());
        assert!(state.halted_shards().is_empty());

        apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::ScheduleSplit {
                shard: p,
                epoch: Epoch::GENESIS,
                settling: None,
            }],
        );

        assert!(!state.pending_reshapes.contains_key(&p));
        assert_eq!(
            state.pending_recoveries[&sibling].cause,
            RecoveryCause::Halt
        );
    }

    /// Split admission, cohort re-staff and top-up each leave a full
    /// committee per unfunded recovery in the pool.
    #[test]
    fn reshape_draws_and_top_up_leave_the_recovery_reserve_in_the_pool() {
        let p = ShardId::leaf(1, 0);
        let mut state = grow_state(4);
        state.boundaries.insert(p, live_boundary());
        seat_sibling(&mut state, halt_misses() + 1);
        assert_eq!(state.recovery_demand(0).len(), 1);

        // Admission: the pool holds only the reserve.
        assert_split(&mut state, p);
        assert!(!state.pending_reshapes.contains_key(&p));

        // Admission once the pool funds the cohort past the reserve.
        add_pooled(&mut state, 2100..2104);
        assert_split(&mut state, p);
        assert_eq!(cohort_of(&state, p).len(), 4);
        assert_eq!(state.pooled_validators().len(), 4);

        // Re-staff: a lapse returns the cohort, and with one pooled
        // validator gone the pool past the reserve no longer staffs it.
        lapse_split(&mut state, p);
        let pooled = state.pooled_validators()[0];
        revoke(&mut state, pooled);
        assert_split(&mut state, p);
        assert!(cohort_of(&state, p).is_empty(), "the re-staff waits");
        assert_eq!(state.pooled_validators().len(), 7);

        // Top-up: a short committee is backfilled only from the pool past
        // the reserve.
        state.pending_reshapes.remove(&p);
        let pooled = state.pooled_validators()[0];
        revoke(&mut state, pooled);
        shorten_by_two(&mut state, p);
        assert_eq!(state.drawable_pool_len(0), 2);
        top_up_committees(&mut state);
        assert_eq!(state.next_shard_committees[&p].members.len(), 4);
        assert_eq!(state.pooled_validators().len(), 4, "the reserve stands");

        shorten_by_two(&mut state, p);
        top_up_committees(&mut state);
        assert_eq!(
            state.next_shard_committees[&p].members.len(),
            2,
            "a pool at the reserve backfills nothing",
        );
        assert_eq!(state.pooled_validators().len(), 4);
    }

    fn revoke(state: &mut BeaconState, id: ValidatorId) {
        state.validators.get_mut(&id).expect("registered").status = ValidatorStatus::Revoked {
            at_epoch: state.current_epoch,
        };
    }

    /// Revoke the last two members `shard` seats, leaving it short.
    fn shorten_by_two(state: &mut BeaconState, shard: ShardId) {
        let members = state.next_shard_committees[&shard].members.clone();
        let (kept, dropped) = members.split_at(members.len() - 2);
        for id in dropped {
            revoke(state, *id);
        }
        state
            .next_shard_committees
            .get_mut(&shard)
            .expect("seated")
            .members = kept.to_vec();
    }

    /// The halted set reads the same on either side of the reshape folds:
    /// a target due to apply is reshape-involved before the apply and
    /// terminal after it, and the children's placeholders are exempt.
    #[test]
    fn the_halted_set_is_the_same_before_and_after_the_reshape_folds() {
        let (mut state, p) = split_scheduled(4);
        assert!(advance_to_scheduled_cut(&mut state));
        state
            .boundaries
            .get_mut(&p)
            .expect("live record")
            .consecutive_misses = halt_misses() + 1;
        let sibling = seat_sibling(&mut state, halt_misses() + 1);

        let before = state.halted_shards();
        apply_scheduled_splits(&mut state);
        schedule_quiet_splits(&mut state);
        apply_scheduled_merges(&mut state);
        schedule_quiet_merges(&mut state);
        let after = state.halted_shards();

        assert!(
            !state.next_shard_committees.contains_key(&p),
            "the cut applied"
        );
        assert_eq!(before, BTreeSet::from([sibling]));
        assert_eq!(after, before);
    }

    /// The merge half of the same claim: the children are reshape-involved
    /// before the apply and terminal after it, and the parent's placeholder
    /// is exempt as a never-produced successor.
    #[test]
    fn the_halted_set_is_the_same_before_and_after_a_merge_applies() {
        let parent = ShardId::leaf(1, 0);
        let children: [ShardId; 2] = parent.children().into();
        let mut state = merge_grow_state(0);
        let merge = merge_assertion(parent);
        for child in children {
            apply_shard_payload(&BlsVerifier, &mut state, &net(), child, &merge);
        }
        for (id, seat) in keepers_of(&state, parent) {
            apply_shard_payload(
                &BlsVerifier,
                &mut state,
                &net(),
                seat.child,
                &ShardWitnessPayload::ReshapeReady {
                    validator: id,
                    child: seat.child,
                },
            );
        }
        schedule_quiet_merges(&mut state);
        assert!(advance_to_scheduled_cut(&mut state));
        for child in children {
            state
                .boundaries
                .get_mut(&child)
                .expect("live record")
                .consecutive_misses = halt_misses() + 1;
        }
        let sibling = seat_sibling(&mut state, halt_misses() + 1);

        let before = (state.halted_shards(), state.recovery_demand(0));
        apply_scheduled_splits(&mut state);
        schedule_quiet_splits(&mut state);
        apply_scheduled_merges(&mut state);
        schedule_quiet_merges(&mut state);
        let after = (state.halted_shards(), state.recovery_demand(0));

        assert!(
            state.next_shard_committees.contains_key(&parent),
            "the cut applied"
        );
        assert_eq!(before.0, BTreeSet::from([sibling]));
        assert_eq!(before.1, BTreeSet::from([sibling]));
        assert_eq!(after, before);
    }

    // ─── the quiet gate ─────────────────────────────────────────────────

    /// [`grow_state`] with `leaf(1, 0)`'s split admitted at epoch 5 and
    /// every observer ready, so the readiness gate passes at every fold.
    fn split_ready() -> (BeaconState, ShardId) {
        let p = ShardId::leaf(1, 0);
        let mut state = grow_state(4);
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            p,
            &ShardWitnessPayload::ScheduleSplit {
                shard: p,
                epoch: Epoch::GENESIS,
                settling: None,
            },
        );
        let observers: Vec<ValidatorId> = cohort_of(&state, p).keys().copied().collect();
        for observer in observers {
            mark_ready(&mut state, p, observer);
        }
        (state, p)
    }

    /// `target`'s pending admission.
    fn admission_of(state: &BeaconState, target: ShardId) -> Admission {
        match &state.pending_reshapes[&target] {
            PendingReshape::Split { admitted, .. } => *admitted,
            PendingReshape::Merge { admitted, .. } => admitted.expect("a paired merge"),
        }
    }

    /// Whether `target`'s pending split carries its quiet bit.
    fn split_quiet(state: &BeaconState, target: ShardId) -> bool {
        matches!(
            state.pending_reshapes.get(&target),
            Some(PendingReshape::Split { quiet: true, .. })
        )
    }

    /// Fold `target`'s split settling, naming the admission at `admitted`.
    fn settle_split(state: &mut BeaconState, target: ShardId, admitted: Epoch, quiet: bool) {
        apply_shard_payload(
            &BlsVerifier,
            state,
            &net(),
            target,
            &ShardWitnessPayload::ScheduleSplit {
                shard: target,
                epoch: state.current_epoch,
                settling: Some(Settling { admitted, quiet }),
            },
        );
    }

    /// Fold `child`'s settling of the merge under `parent`, naming the
    /// admission at `admitted`.
    fn settle_half(
        state: &mut BeaconState,
        parent: ShardId,
        child: ShardId,
        admitted: Epoch,
        quiet: bool,
    ) {
        apply_shard_payload(
            &BlsVerifier,
            state,
            &net(),
            child,
            &ShardWitnessPayload::ScheduleMerge {
                parent,
                epoch: state.current_epoch,
                settling: Some(Settling { admitted, quiet }),
            },
        );
    }

    /// The fold's reshape steps in its order: the witnesses already
    /// applied, the prune, then the schedulers.
    fn prune_and_schedule(state: &mut BeaconState) {
        prune_stale_reshapes(state);
        schedule_ready_splits(state);
        schedule_ready_merges(state);
    }

    /// The first fold whose readiness gate passes latches the drain, a
    /// deadline the configured drain span out, and schedules nothing: no
    /// terminal is stamped, and the next window shows the target draining
    /// under its admission. A further fold without a quiet bit schedules
    /// nothing and leaves the deadline where it was.
    #[test]
    fn a_passing_gate_latches_the_drain_and_schedules_nothing_that_fold() {
        let (mut state, p) = split_ready();
        assert!(!state.derive_next_topology_snapshot(net()).draining(p));

        schedule_ready_splits(&mut state);
        let admitted = admission_of(&state, p);
        let drain_by = state
            .current_epoch
            .saturating_add(state.chain_config.reshape_drain_epochs());
        assert_eq!(admitted.drain_by, Some(drain_by));
        assert_eq!(state.pending_reshapes[&p].scheduled_terminal(), None);
        assert_eq!(state.boundaries[&p].terminal_epoch, None);
        assert_eq!(
            state
                .derive_next_topology_snapshot(net())
                .draining_admission(p),
            Some((ReshapeKind::Split, admitted.at)),
        );

        schedule_ready_splits(&mut state);
        assert_eq!(state.pending_reshapes[&p].scheduled_terminal(), None);
        assert_eq!(admission_of(&state, p).drain_by, Some(drain_by));
    }

    /// A latched split whose gate passes waits for its quiet bit: an
    /// unquiet settling refreshes it and schedules nothing, and the quiet
    /// one schedules the cut in the same fold.
    #[test]
    fn a_split_whose_gate_passes_waits_for_its_quiet_bit() {
        let (mut state, p) = split_ready();
        schedule_ready_splits(&mut state);
        let at = admission_of(&state, p).at;

        settle_split(&mut state, p, at, false);
        prune_and_schedule(&mut state);
        assert!(!split_quiet(&state, p));
        assert_eq!(state.pending_reshapes[&p].scheduled_terminal(), None);

        settle_split(&mut state, p, at, true);
        prune_and_schedule(&mut state);
        assert_eq!(
            state.pending_reshapes[&p].scheduled_terminal(),
            Some(state.current_epoch.next()),
        );
    }

    /// A latched record is cancelled at its drain deadline, its cohort
    /// back in the pool, and not at its readiness deadline: on a chain of
    /// short epochs the drain deadline lies past it.
    #[test]
    fn a_latched_record_cancels_at_drain_by() {
        let (mut state, p) = split_ready();
        state.chain_config.epoch_duration_ms = 30_000;
        let pooled = state.pooled_validators().len();
        schedule_ready_splits(&mut state);
        let admitted = admission_of(&state, p);
        let drain_by = admitted.drain_by.expect("latched");
        assert!(drain_by > admitted.ready_by);

        let at = admitted.at;
        for epoch in admitted.ready_by.inner()..drain_by.inner() {
            state.current_epoch = Epoch::new(epoch);
            settle_split(&mut state, p, at, false);
            prune_and_schedule(&mut state);
            assert!(state.pending_reshapes.contains_key(&p), "kept at {epoch}");
        }
        state.current_epoch = drain_by;
        settle_split(&mut state, p, at, false);
        prune_and_schedule(&mut state);
        assert!(!state.pending_reshapes.contains_key(&p));
        assert_eq!(state.pooled_validators().len(), pooled + 4);
    }

    /// A quiet leaf folded the fold before the drain deadline schedules
    /// the cut.
    #[test]
    fn a_quiet_leaf_folded_the_fold_before_drain_by_schedules_the_cut() {
        let (mut state, p) = split_ready();
        schedule_ready_splits(&mut state);
        let admitted = admission_of(&state, p);
        let drain_by = admitted.drain_by.expect("latched");

        state.current_epoch = Epoch::new(drain_by.inner() - 1);
        settle_split(&mut state, p, admitted.at, true);
        prune_and_schedule(&mut state);
        assert_eq!(
            state.pending_reshapes[&p].scheduled_terminal(),
            Some(drain_by)
        );
    }

    /// A quiet leaf folded at the drain deadline schedules nothing: the
    /// prune cancels the record before the schedulers read the fold.
    #[test]
    fn a_quiet_leaf_folded_at_drain_by_schedules_nothing() {
        let (mut state, p) = split_ready();
        schedule_ready_splits(&mut state);
        let admitted = admission_of(&state, p);

        state.current_epoch = admitted.drain_by.expect("latched");
        settle_split(&mut state, p, admitted.at, true);
        assert!(split_quiet(&state, p), "the leaf folds");
        prune_and_schedule(&mut state);
        assert!(!state.pending_reshapes.contains_key(&p));
        assert_eq!(state.boundaries[&p].terminal_epoch, None);
    }

    /// A latched split whose trigger goes silent lapses its cohort as any
    /// split does, and keeps its drain deadline: the next window still
    /// shows the target draining.
    #[test]
    fn the_drain_latch_survives_a_cohort_lapse() {
        use hyperscale_types::RESHAPE_TRIGGER_TTL_EPOCHS;

        let (mut state, p) = split_ready();
        state.chain_config.epoch_duration_ms = 30_000;
        schedule_ready_splits(&mut state);
        let admitted = admission_of(&state, p);

        state.current_epoch = state
            .current_epoch
            .saturating_add(RESHAPE_TRIGGER_TTL_EPOCHS);
        prune_and_schedule(&mut state);
        assert!(cohort_of(&state, p).is_empty(), "the cohort lapses");
        assert_eq!(admission_of(&state, p), admitted, "the latch stands");
        assert!(state.derive_next_topology_snapshot(net()).draining(p));
        assert_eq!(state.pending_reshapes[&p].scheduled_terminal(), None);
    }

    /// A settling assertion re-staffs a lapsed, latched split from its
    /// frozen seed, as an assertion on load does, and raises its quiet
    /// bit beside.
    #[test]
    fn a_lapsed_cohort_is_restaffed_by_a_settling_assertion() {
        use hyperscale_types::RESHAPE_TRIGGER_TTL_EPOCHS;

        let (mut state, p) = split_ready();
        state.chain_config.epoch_duration_ms = 30_000;
        let drawn: BTreeSet<ValidatorId> = cohort_of(&state, p).keys().copied().collect();
        schedule_ready_splits(&mut state);
        let at = admission_of(&state, p).at;
        state.current_epoch = state
            .current_epoch
            .saturating_add(RESHAPE_TRIGGER_TTL_EPOCHS);
        prune_and_schedule(&mut state);
        assert!(cohort_of(&state, p).is_empty());

        settle_split(&mut state, p, at, true);
        assert_eq!(
            cohort_of(&state, p)
                .keys()
                .copied()
                .collect::<BTreeSet<_>>(),
            drawn,
            "the same cohort, drawn again from the seed",
        );
        assert!(split_quiet(&state, p));
    }

    /// A settling assertion on a record that has not latched its drain
    /// sets nothing: neither the quiet bit nor the trigger clock.
    #[test]
    fn a_settling_assertion_on_an_unlatched_record_sets_nothing() {
        let (mut state, p) = split_ready();
        let before = state.pending_reshapes[&p].clone();
        state.current_epoch = state.current_epoch.next();
        let at = admission_of(&state, p).at;
        settle_split(&mut state, p, at, true);
        assert_eq!(state.pending_reshapes[&p], before);
    }

    /// A settling assertion folded after its record was cancelled admits
    /// nothing: no record, and no cohort leaves the pool.
    #[test]
    fn a_settling_assertion_after_cancellation_admits_nothing() {
        let (mut state, p) = split_ready();
        schedule_ready_splits(&mut state);
        let admitted = admission_of(&state, p);
        state.current_epoch = admitted.drain_by.expect("latched");
        prune_and_schedule(&mut state);
        assert!(state.pending_reshapes.is_empty());
        let pooled = state.pooled_validators();

        settle_split(&mut state, p, admitted.at, true);
        assert!(state.pending_reshapes.is_empty());
        assert_eq!(state.pooled_validators(), pooled);
    }

    /// An assertion from an anchor that predates a cancel names the
    /// cancelled admission. Folded against the re-admission that followed
    /// it, past whose own latch the fold epoch lies, it sets nothing.
    #[test]
    fn a_settling_assertion_naming_a_cancelled_admission_sets_nothing() {
        let (mut state, p) = split_ready();
        schedule_ready_splits(&mut state);
        let first = admission_of(&state, p);
        state.current_epoch = first.drain_by.expect("latched");
        prune_and_schedule(&mut state);
        assert!(state.pending_reshapes.is_empty());

        state.current_epoch = state.current_epoch.next();
        let epoch = state.current_epoch;
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            p,
            &ShardWitnessPayload::ScheduleSplit {
                shard: p,
                epoch,
                settling: None,
            },
        );
        let observers: Vec<ValidatorId> = cohort_of(&state, p).keys().copied().collect();
        for observer in observers {
            mark_ready(&mut state, p, observer);
        }
        schedule_ready_splits(&mut state);
        let second = admission_of(&state, p);
        assert!(second.at > first.at && second.drain_by.is_some());
        state.current_epoch = state.current_epoch.next();
        let before = state.pending_reshapes[&p].clone();

        settle_split(&mut state, p, first.at, true);
        assert_eq!(state.pending_reshapes[&p], before);
        prune_and_schedule(&mut state);
        assert_eq!(state.pending_reshapes[&p].scheduled_terminal(), None);
    }

    /// A quiet bit is sticky: an unquiet leaf folded after it, as a stale
    /// replica's might be, leaves it standing, for a split and for a
    /// merge's half.
    #[test]
    fn a_later_unquiet_leaf_does_not_clear_the_quiet_bit() {
        let (mut state, p) = split_ready();
        schedule_ready_splits(&mut state);
        let at = admission_of(&state, p).at;
        settle_split(&mut state, p, at, true);
        settle_split(&mut state, p, at, false);
        assert!(split_quiet(&state, p));

        let (mut state, parent) = merge_ready();
        schedule_ready_merges(&mut state);
        let at = admission_of(&state, parent).at;
        let (left, _) = parent.children();
        settle_half(&mut state, parent, left, at, true);
        settle_half(&mut state, parent, left, at, false);
        let Some(PendingReshape::Merge { halves, .. }) = state.pending_reshapes.get(&parent) else {
            panic!("the merge stands");
        };
        assert!(halves[&left].quiet);
    }

    /// [`merge_grow_state`] with the merge under `leaf(1, 0)` paired and
    /// every keeper ready, so the readiness gate passes at every fold.
    fn merge_ready() -> (BeaconState, ShardId) {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let mut state = merge_grow_state(0);
        let merge = merge_assertion(parent);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), left, &merge);
        apply_shard_payload(&BlsVerifier, &mut state, &net(), right, &merge);
        for (keeper, seat) in keepers_of(&state, parent) {
            apply_shard_payload(
                &BlsVerifier,
                &mut state,
                &net(),
                seat.child,
                &ShardWitnessPayload::ReshapeReady {
                    validator: keeper,
                    child: seat.child,
                },
            );
        }
        (state, parent)
    }

    /// A latched merge waits for both children to say they are quiet:
    /// one quiet half schedules nothing, and the second schedules the
    /// cut.
    #[test]
    fn a_merge_waits_for_both_children_quiet() {
        let (mut state, parent) = merge_ready();
        let (left, right) = parent.children();
        schedule_ready_merges(&mut state);
        let at = admission_of(&state, parent).at;
        assert_eq!(state.pending_reshapes[&parent].scheduled_terminal(), None);

        settle_half(&mut state, parent, left, at, true);
        settle_half(&mut state, parent, right, at, false);
        prune_and_schedule(&mut state);
        assert_eq!(state.pending_reshapes[&parent].scheduled_terminal(), None);

        settle_half(&mut state, parent, right, at, true);
        prune_and_schedule(&mut state);
        assert_eq!(
            state.pending_reshapes[&parent].scheduled_terminal(),
            Some(state.current_epoch.next()),
        );
    }

    /// The draining view is keyed from the record, not its seats: a
    /// child every keeper of which has dropped still reads draining under
    /// the merge's admission.
    #[test]
    fn a_merge_whose_keepers_on_one_child_dropped_still_reads_that_child_draining() {
        let (mut state, parent) = merge_ready();
        let (left, right) = parent.children();
        schedule_ready_merges(&mut state);
        let at = admission_of(&state, parent).at;
        let Some(PendingReshape::Merge { keepers, .. }) = state.pending_reshapes.get_mut(&parent)
        else {
            panic!("the merge stands");
        };
        keepers.retain(|_, seat| seat.child != left);

        let lookahead = state.derive_next_topology_snapshot(net());
        for child in [left, right] {
            assert_eq!(
                lookahead.draining_admission(child),
                Some((ReshapeKind::Merge, at)),
                "{child:?}",
            );
        }
    }
}
