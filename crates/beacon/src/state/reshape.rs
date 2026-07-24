//! Split observer-cohort lifecycle: the admission-time draw, the
//! release that returns a cancelled reshape's cohort to the pool, and
//! the readiness-gated execution that mutates the shard trie.
//!
//! A pending split is staffed before it executes: admission draws a
//! committee-size cohort from the free pool, assigns each member the
//! child it will sync, and carries them on the splitting shard's
//! lookahead committee as `Observing` members — visible to serving and
//! gossip, never to the consensus subset, so the shard's quorum stays
//! at target size for the whole grow. The trie mutates at the first
//! fold where each child's ready membership — its parent half,
//! computed at that fold, plus its ready cohort — reaches quorum; the
//! reshaped trie rides that fold's lookahead, so the children's
//! committees are known a full epoch before their window opens.

use std::collections::BTreeMap;

use blake3::Hasher;
use hyperscale_types::{
    BeaconState, BeaconWitnessLeafCount, BlockHash, BlockHeight, CohortSeat, Epoch, KeeperSeat,
    PendingReshape, Randomness, ShardBoundary, ShardCommittee, ShardId, StateRoot, ValidatorId,
    ValidatorStatus, WeightedTimestamp, byzantine_threshold,
};
use rand::RngExt;
use rand_chacha::ChaCha20Rng;

use crate::sampling::prng_from;

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
/// The caller has already passed the pool gate (`pooled_validators() ≥
/// shard_size`). Each drawn validator becomes `Observing { shard:
/// target }` and joins the target's lookahead committee; the returned
/// seats record the child assignments with `ready: false`.
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

/// Execute every pending split whose readiness gate is met, mutating
/// the trie into the lookahead committee set.
///
/// Per pending split, each fold: the parent half is computed here, over
/// the then-current consensus membership (shuffle, refill, and jail
/// replacement ran on the parent through the whole grow, so there are
/// no dangling assignments to repair), and the gate asks that each
/// child's ready membership — its parent half, ready by construction,
/// plus its ready cohort seats — reach `2f+1` of the committee target.
/// On the first fold where both children pass, the parent's lookahead
/// committee is replaced by the two children's: parent-half members
/// keep their ready flag and placement epoch under the new shard,
/// cohort members are placed with the readiness their `ReshapeReady`
/// folded (stragglers complete via the normal `Ready` path after the
/// boundary). The children gain pending placeholder boundary records —
/// the beacon cannot derive child state roots (`r_p` is a one-way hash
/// of them), so the records fill from the parent's final-epoch
/// `split_child_roots` delivery; until then they don't project as
/// snap-sync anchors. The parent's boundary record stays for its
/// terminal-epoch contribution and witness drain.
///
/// Runs after the shuffle step so the assignment reads post-rotation
/// membership and the children first shuffle one epoch after they
/// form; reads the epoch's freshly rolled randomness.
pub(super) fn execute_ready_splits(state: &mut BeaconState) {
    let targets: Vec<ShardId> = state
        .pending_reshapes
        .iter()
        .filter(|(_, r)| matches!(r, PendingReshape::Split { .. }))
        .map(|(target, _)| *target)
        .collect();
    for target in targets {
        try_execute_split(state, target);
    }
}

/// The zero-hash placeholder a reshape leaves on a not-yet-live shard's
/// boundary — a split child or a composing merge parent. The zero block hash
/// keeps it from projecting as a snap-sync anchor until the shard's genesis
/// lands: a split child's seed from the parent's terminal, or a merge
/// parent's composition from both children's terminals.
const fn pending_placeholder_boundary(epoch: Epoch) -> ShardBoundary {
    ShardBoundary {
        state_root: StateRoot::ZERO,
        block_hash: BlockHash::ZERO,
        height: BlockHeight::GENESIS,
        weighted_timestamp: WeightedTimestamp::ZERO,
        witness_leaf_count: BeaconWitnessLeafCount::ZERO,
        witness_base: BeaconWitnessLeafCount::ZERO,
        last_live_epoch: epoch,
        consecutive_misses: 0,
        terminal_epoch: None,
        terminal_qc_wt: None,
        settled_waves_root: None,
        reshape_admitted_epoch: None,
        reveals_fenced_below: None,
    }
}

fn try_execute_split(state: &mut BeaconState, target: ShardId) {
    let Some(PendingReshape::Split { cohort, .. }) = state.pending_reshapes.get(&target) else {
        return;
    };

    // The parent half, assigned over the consensus membership as it
    // stands at this fold — observers are not parent members.
    let mut parent_members: Vec<ValidatorId> = state
        .next_shard_committees
        .get(&target)
        .map(|committee| {
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
        })
        .unwrap_or_default();
    parent_members.sort_unstable();
    let mut prng = reshape_prng(DOMAIN_RESHAPE_PARENT_HALF, state, target);
    shuffle(&mut parent_members, &mut prng);
    let (left_half, right_half) = parent_members.split_at(parent_members.len().div_ceil(2));

    // The gate: parent half (ready by construction — the same liveness
    // trust the beacon extends to any committee it forms) plus ready
    // cohort seats, at 2f+1 of the committee target per child.
    let (left, right) = target.children();
    let quorum = 2 * byzantine_threshold(state.chain_config.shard_size as usize) + 1;
    let ready_seats = |child: ShardId| {
        cohort
            .values()
            .filter(|seat| seat.child == child && seat.ready)
            .count()
    };
    if left_half.len() + ready_seats(left) < quorum
        || right_half.len() + ready_seats(right) < quorum
    {
        return;
    }
    tracing::info!(shard = ?target, "Shard split readiness gate met; reshaping the trie");

    let halves = [(left, left_half.to_vec()), (right, right_half.to_vec())];
    let Some(PendingReshape::Split {
        cohort,
        admitted_at,
        ..
    }) = state.pending_reshapes.remove(&target)
    else {
        unreachable!("pending split read above");
    };
    state.next_shard_committees.remove(&target);

    // The epoch this fold starts is the parent's final one: its chain
    // terminates at the epoch's cut and the children take over from the
    // lookahead. The terminal mark keeps the boundary record sourced
    // (for the terminal contribution that seeds the children, and the
    // witness drain) without counting the dead chain as missing.
    if let Some(boundary) = state.boundaries.get_mut(&target) {
        boundary.terminal_epoch = Some(state.current_epoch);
        boundary.reshape_admitted_epoch = Some(admitted_at);
    } else {
        tracing::warn!(
            shard = ?target,
            "splitting shard has no boundary record; children must seed from their own contributions"
        );
    }

    for (child, half) in halves {
        // Child committee: the parent half in assignment order, then
        // the cohort half in id order.
        let mut members = half;
        for (id, seat) in &cohort {
            if seat.child == child {
                members.push(*id);
            }
        }

        for id in &members {
            let rec = state
                .validators
                .get_mut(id)
                .expect("members come from committee/cohort state, must be in validators");
            rec.status = match rec.status {
                ValidatorStatus::OnShard {
                    ready,
                    placed_at_epoch,
                    ..
                } => ValidatorStatus::OnShard {
                    shard: child,
                    ready,
                    placed_at_epoch,
                },
                ValidatorStatus::Observing { .. } => ValidatorStatus::OnShard {
                    shard: child,
                    ready: cohort[id].ready,
                    placed_at_epoch: state.current_epoch,
                },
                other => unreachable!("split moved a {other:?} validator"),
            };
            // Placement changed: the per-placement miss scope ends here.
            state.miss_counters.remove(id);
        }

        state
            .next_shard_committees
            .insert(child, ShardCommittee { members });

        state
            .boundaries
            .insert(child, pending_placeholder_boundary(state.current_epoch));
    }
}

/// Execute every paired merge whose readiness gate is met, mutating the
/// trie into the lookahead committee set.
///
/// Symmetric to [`execute_ready_splits`], inverted: a merge keeps no
/// committee-liveness half — every keeper must sync the sibling half — so
/// the gate is simply the merged committee's ready keepers reaching
/// `2f+1` of the target. On the first fold that passes, the parent's two
/// children leave the lookahead and the parent takes their place: keepers
/// flip `OnShard` onto the parent with the readiness their `ReshapeReady`
/// folded (stragglers complete via the normal `Ready` path), and the
/// non-keeper half of each child returns to the pool. Both children's
/// boundary records are marked terminal so their chains drain and the
/// beacon composes the parent anchor from them; the parent gains a
/// pending placeholder until that composition lands.
pub(super) fn execute_ready_merges(state: &mut BeaconState) {
    let targets: Vec<ShardId> = state
        .pending_reshapes
        .iter()
        .filter(|(_, r)| {
            matches!(
                r,
                PendingReshape::Merge {
                    admitted_at: Some(_),
                    ..
                }
            )
        })
        .map(|(target, _)| *target)
        .collect();
    for target in targets {
        try_execute_merge(state, target);
    }
}

fn try_execute_merge(state: &mut BeaconState, parent: ShardId) {
    let Some(PendingReshape::Merge { keepers, .. }) = state.pending_reshapes.get(&parent) else {
        return;
    };
    let quorum = 2 * byzantine_threshold(state.chain_config.shard_size as usize) + 1;
    if keepers.values().filter(|seat| seat.ready).count() < quorum {
        return;
    }
    tracing::info!(
        ?parent,
        "Shard merge readiness gate met; reshaping the trie"
    );

    let Some(PendingReshape::Merge {
        keepers,
        admitted_at,
        ..
    }) = state.pending_reshapes.remove(&parent)
    else {
        unreachable!("pending merge read above");
    };

    // Drop the children from the lookahead: keepers move to the parent
    // below, the rest return to the pool. The children's chains keep
    // running their in-flight window from the frozen active committee
    // until their terminal block — the terminal mark keeps each boundary
    // record sourced (for the contribution the beacon composes into the
    // parent anchor and the witness drain) without counting the dead
    // chain as missing.
    let children: [ShardId; 2] = parent.children().into();
    for child in children {
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
        if let Some(boundary) = state.boundaries.get_mut(&child) {
            boundary.terminal_epoch = Some(state.current_epoch);
            boundary.reshape_admitted_epoch = admitted_at;
        } else {
            tracing::warn!(
                shard = ?child,
                "merging child has no boundary record; the parent must seed from its own contribution"
            );
        }
    }

    // The merged committee, keepers in id order, each now `OnShard` on
    // the parent carrying the readiness its `ReshapeReady` folded.
    let members: Vec<ValidatorId> = keepers.keys().copied().collect();
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
        let placed_at_epoch = match rec.status {
            ValidatorStatus::OnShard {
                placed_at_epoch, ..
            } => placed_at_epoch,
            other => unreachable!("merge moved a {other:?} validator"),
        };
        rec.status = ValidatorStatus::OnShard {
            shard: parent,
            ready: seat.ready,
            placed_at_epoch,
        };
        // Placement changed: the per-placement miss scope ends here.
        state.miss_counters.remove(id);
    }
    state
        .next_shard_committees
        .insert(parent, ShardCommittee { members });

    // The parent's `r_p` is composed from the two terminal child anchors
    // once they fold; until then a zero block hash keeps the placeholder
    // from projecting as a snap-sync anchor.
    state
        .boundaries
        .insert(parent, pending_placeholder_boundary(state.current_epoch));
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

    use hyperscale_types::{Epoch, NodeId, ShardWitnessPayload};

    use super::*;
    use crate::state::test_fixtures::{
        apply_next_epoch, apply_witness_chunk, empty_state, net, single_pool_state,
        validator_record,
    };
    use crate::state::witness::{apply_shard_payload, prune_stale_reshapes};

    /// `single_pool_state(4)` — four ready members on `leaf(1, 0)`,
    /// promoted into the active slot too — plus `pooled` free
    /// validators, with a committee target of 4 (quorum 3).
    fn grow_state(pooled: u64) -> BeaconState {
        let mut state = single_pool_state(4);
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

    fn mark_ready(state: &mut BeaconState, target: ShardId, observer: ValidatorId) {
        let child = cohort_of(state, target)[&observer].child;
        apply_shard_payload(
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
            &mut state,
            &net(),
            p,
            &ShardWitnessPayload::ScheduleSplit { shard: p },
        );
        let parent_members: BTreeSet<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let cohort: BTreeMap<ValidatorId, CohortSeat> = cohort_of(&state, p).clone();
        state.miss_counters.insert(ValidatorId::new(0), 2);

        // Nobody ready: each child sees only its parent half (2 < 3).
        execute_ready_splits(&mut state);
        assert!(state.pending_reshapes.contains_key(&p));
        assert!(state.next_shard_committees.contains_key(&p));

        // One child at quorum, the other not: still held.
        let left_observer = observer_for(&state, p, left);
        mark_ready(&mut state, p, left_observer);
        execute_ready_splits(&mut state);
        assert!(state.pending_reshapes.contains_key(&p));

        // Both children at 2 + 1 = 3 of 4: the trie reshapes.
        let right_observer = observer_for(&state, p, right);
        mark_ready(&mut state, p, right_observer);
        execute_ready_splits(&mut state);

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
                            placed_at_epoch: Epoch::new(5),
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
            let boundary = state.boundaries[&child];
            assert_eq!(boundary.block_hash, BlockHash::ZERO);
            assert_eq!(boundary.last_live_epoch, Epoch::new(5));
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
                state_root: StateRoot::ZERO,
                block_hash: BlockHash::ZERO,
                height: BlockHeight::new(10),
                weighted_timestamp: WeightedTimestamp::ZERO,
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                witness_base: BeaconWitnessLeafCount::ZERO,
                last_live_epoch: Epoch::new(5),
                consecutive_misses: 0,
                terminal_epoch: None,
                terminal_qc_wt: None,
                settled_waves_root: None,
                reshape_admitted_epoch: None,
                reveals_fenced_below: None,
            },
        );
        apply_shard_payload(
            &mut state,
            &net(),
            p,
            &ShardWitnessPayload::ScheduleSplit { shard: p },
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
        execute_ready_splits(&mut state);

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

    #[test]
    fn unready_parent_member_counts_toward_gate_but_keeps_its_flag() {
        let p = ShardId::leaf(1, 0);
        let straggler = ValidatorId::new(3);
        let mut state = grow_state(4);
        state.validators.get_mut(&straggler).unwrap().status = ValidatorStatus::OnShard {
            shard: p,
            ready: false,
            placed_at_epoch: Epoch::new(4),
        };
        apply_shard_payload(
            &mut state,
            &net(),
            p,
            &ShardWitnessPayload::ScheduleSplit { shard: p },
        );
        let observers: Vec<ValidatorId> = cohort_of(&state, p).keys().copied().collect();
        for observer in observers {
            mark_ready(&mut state, p, observer);
        }

        execute_ready_splits(&mut state);

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
                state,
                &net(),
                p,
                &ShardWitnessPayload::ScheduleSplit { shard: p },
            );
            let observers: Vec<ValidatorId> = cohort_of(state, p).keys().copied().collect();
            for observer in observers {
                mark_ready(state, p, observer);
            }
            execute_ready_splits(state);
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
        let split = ShardWitnessPayload::ScheduleSplit { shard: p };

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
        assert!(state.pending_reshapes.is_empty(), "the gate must fire");
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
            vec![ShardWitnessPayload::ScheduleSplit { shard: p }],
        );
        assert!(state.pending_reshapes.contains_key(&p));
        let consensus_during_grow = state.shard_consensus_members.clone();

        // The next epoch folds every observer's ReshapeReady; the gate
        // fires inside the same apply and the children ride this
        // fold's lookahead.
        let ready_leaves: Vec<ShardWitnessPayload> = cohort_of(&state, p)
            .iter()
            .map(|(v, seat)| ShardWitnessPayload::ReshapeReady {
                validator: *v,
                child: seat.child,
            })
            .collect();
        apply_witness_chunk(&mut state, 0, ready_leaves);
        assert!(state.pending_reshapes.is_empty());

        let active = state.derive_topology_snapshot(net());
        let lookahead = state.derive_next_topology_snapshot(net());
        for seed in 0..32u8 {
            let node = NodeId([seed; 30]);
            let now = active.shard_for_node_id(&node);
            let next = lookahead.shard_for_node_id(&node);
            if now == p {
                // The parent's traffic remaps to exactly its children.
                assert_eq!(next.parent(), Some(p), "{node:?} routed to {next:?}");
            } else {
                // Anything outside the split is untouched.
                assert_eq!(now, sibling);
                assert_eq!(next, sibling);
            }
            // Re-derivation is deterministic on both sides.
            assert_eq!(
                state
                    .derive_topology_snapshot(net())
                    .shard_for_node_id(&node),
                now
            );
            assert_eq!(
                state
                    .derive_next_topology_snapshot(net())
                    .shard_for_node_id(&node),
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
        use hyperscale_types::{MIN_STAKE_FLOOR, Stake, StakePool, StakePoolId};

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
                    state_root: StateRoot::ZERO,
                    block_hash: BlockHash::ZERO,
                    height: BlockHeight::new(10),
                    weighted_timestamp: WeightedTimestamp::ZERO,
                    witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                    witness_base: BeaconWitnessLeafCount::ZERO,
                    last_live_epoch: Epoch::new(5),
                    consecutive_misses: 0,
                    terminal_epoch: None,
                    terminal_qc_wt: None,
                    settled_waves_root: None,
                    reshape_admitted_epoch: None,
                    reveals_fenced_below: None,
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
            StakePoolId::new(0),
            StakePool {
                id: StakePoolId::new(0),
                total_stake: Stake::from_attos(count * MIN_STAKE_FLOOR.attos()),
                validators,
                pending_withdrawals: Vec::new(),
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
        let merge = ShardWitnessPayload::ScheduleMerge { parent };

        // The first half waits: no keepers, no readiness clock.
        apply_shard_payload(&mut state, &net(), left, &merge);
        let Some(PendingReshape::Merge {
            keepers,
            admitted_at,
            ..
        }) = state.pending_reshapes.get(&parent)
        else {
            panic!("merge half not recorded");
        };
        assert!(keepers.is_empty());
        assert!(admitted_at.is_none());

        // The sibling pairs it: keepers drawn on the spot.
        apply_shard_payload(&mut state, &net(), right, &merge);
        let keepers = keepers_of(&state, parent);
        let Some(PendingReshape::Merge { admitted_at, .. }) = state.pending_reshapes.get(&parent)
        else {
            unreachable!()
        };
        assert_eq!(*admitted_at, Some(Epoch::new(5)));
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

        let merge = ShardWitnessPayload::ScheduleMerge { parent };
        apply_shard_payload(&mut state, &net(), left, &merge);
        apply_shard_payload(&mut state, &net(), right, &merge);

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
        let merge = ShardWitnessPayload::ScheduleMerge { parent };
        apply_shard_payload(&mut state, &net(), left, &merge);
        apply_shard_payload(&mut state, &net(), right, &merge);
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
        let merge = ShardWitnessPayload::ScheduleMerge { parent };
        apply_shard_payload(&mut state, &net(), left, &merge);
        apply_shard_payload(&mut state, &net(), right, &merge);

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
        apply_shard_payload(&mut state, &net(), right, &ready);
        assert!(!keepers_of(&state, parent)[&keeper].ready);

        // Own chain: the seat flips.
        apply_shard_payload(&mut state, &net(), left, &ready);
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
        let merge = ShardWitnessPayload::ScheduleMerge { parent };
        apply_shard_payload(&mut state, &net(), left, &merge);
        apply_shard_payload(&mut state, &net(), right, &merge);
        let keepers = keepers_of(&state, parent);

        run_shuffle_step(&mut state);

        // Every keeper still runs its child; a non-keeper rotated in its
        // place on each child (the pool refilled the freed slot).
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
        assert_eq!(state.next_shard_committees[&left].members.len(), 4);
        assert_eq!(state.next_shard_committees[&right].members.len(), 4);
        // A non-keeper got rotated out — the shuffle wasn't a no-op.
        assert!(
            state
                .pooled_validators()
                .iter()
                .any(|id| !keepers.contains_key(id) && id.inner() < 8),
        );
    }

    /// Once paired, a required half going quiet cancels the merge and
    /// un-pins the keepers — unlike a lone half, which simply waits.
    #[test]
    fn paired_merge_cancels_when_a_required_half_goes_quiet() {
        use hyperscale_types::RESHAPE_TRIGGER_TTL_EPOCHS;

        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let mut state = merge_grow_state(0);
        let merge = ShardWitnessPayload::ScheduleMerge { parent };
        apply_shard_payload(&mut state, &net(), left, &merge);
        apply_shard_payload(&mut state, &net(), right, &merge);
        assert!(state.pending_reshapes.contains_key(&parent));

        // Only the left half keeps re-asserting; the right goes quiet.
        for epoch in 6..(5 + RESHAPE_TRIGGER_TTL_EPOCHS) {
            state.current_epoch = Epoch::new(epoch);
            apply_shard_payload(&mut state, &net(), left, &merge);
            prune_stale_reshapes(&mut state);
            assert!(
                state.pending_reshapes.contains_key(&parent),
                "cancelled early at epoch {epoch}",
            );
        }
        state.current_epoch = Epoch::new(5 + RESHAPE_TRIGGER_TTL_EPOCHS);
        apply_shard_payload(&mut state, &net(), left, &merge);
        prune_stale_reshapes(&mut state);
        assert!(state.pending_reshapes.is_empty());
        // Keepers returned to ordinary rotation: still OnShard, no longer pinned.
        assert!(!state.is_merge_keeper(left, ValidatorId::new(0)));
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
        let merge = ShardWitnessPayload::ScheduleMerge { parent };
        apply_shard_payload(&mut state, &net(), left, &merge);
        apply_shard_payload(&mut state, &net(), right, &merge);
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
                &mut state,
                &net(),
                child,
                &ShardWitnessPayload::ReshapeReady {
                    validator: *id,
                    child,
                },
            );
        }
        execute_ready_merges(&mut state);
        assert!(state.pending_reshapes.contains_key(&parent));
        assert!(state.next_shard_committees.contains_key(&left));

        // The third keeper readies: the trie collapses, the fourth a
        // straggler.
        let third = keeper_ids[quorum - 1];
        apply_shard_payload(
            &mut state,
            &net(),
            keepers[&third].child,
            &ShardWitnessPayload::ReshapeReady {
                validator: third,
                child: keepers[&third].child,
            },
        );
        execute_ready_merges(&mut state);

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
        assert_eq!(state.boundaries[&left].terminal_epoch, Some(Epoch::new(5)));
        assert_eq!(state.boundaries[&right].terminal_epoch, Some(Epoch::new(5)));
        assert_eq!(state.boundaries[&parent].block_hash, BlockHash::ZERO);
        assert_eq!(state.boundaries[&parent].last_live_epoch, Epoch::new(5));
        // The mover shed its per-placement miss scope.
        assert!(!state.miss_counters.contains_key(&keeper_ids[0]));
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
        let merge = ShardWitnessPayload::ScheduleMerge { parent };
        apply_shard_payload(&mut state, &net(), left, &merge);
        apply_shard_payload(&mut state, &net(), right, &merge);
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
                &mut state,
                &net(),
                child,
                &ShardWitnessPayload::ReshapeReady {
                    validator: *id,
                    child,
                },
            );
        }
        execute_ready_merges(&mut state);

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
        let merge = ShardWitnessPayload::ScheduleMerge { parent };
        let mut a = merge_grow_state(0);
        let mut b = merge_grow_state(0);
        for state in [&mut a, &mut b] {
            apply_shard_payload(state, &net(), left, &merge);
            apply_shard_payload(state, &net(), right, &merge);
            for (id, seat) in keepers_of(state, parent) {
                apply_shard_payload(
                    state,
                    &net(),
                    seat.child,
                    &ShardWitnessPayload::ReshapeReady {
                        validator: id,
                        child: seat.child,
                    },
                );
            }
            execute_ready_merges(state);
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

        let merge = ShardWitnessPayload::ScheduleMerge { parent };
        apply_shard_payload(&mut state, &net(), left, &merge);
        apply_shard_payload(&mut state, &net(), right, &merge);
        for (id, seat) in keepers_of(&state, parent) {
            apply_shard_payload(
                &mut state,
                &net(),
                seat.child,
                &ShardWitnessPayload::ReshapeReady {
                    validator: id,
                    child: seat.child,
                },
            );
        }
        execute_ready_merges(&mut state);
        assert!(state.pending_reshapes.is_empty());

        let active = state.derive_topology_snapshot(net());
        let lookahead = state.derive_next_topology_snapshot(net());
        for seed in 0..32u8 {
            let node = NodeId([seed; 30]);
            let now = active.shard_for_node_id(&node);
            let next = lookahead.shard_for_node_id(&node);
            if now == left || now == right {
                // The children's traffic remaps to their reunified parent.
                assert_eq!(next, parent, "{node:?} routed to {next:?}");
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
        use std::sync::Arc;

        use hyperscale_types::TopologySchedule;

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
        let merge = ShardWitnessPayload::ScheduleMerge { parent };
        apply_shard_payload(&mut state, &net(), left, &merge);
        apply_shard_payload(&mut state, &net(), right, &merge);
        for (id, seat) in keepers_of(&state, parent) {
            apply_shard_payload(
                &mut state,
                &net(),
                seat.child,
                &ShardWitnessPayload::ReshapeReady {
                    validator: id,
                    child: seat.child,
                },
            );
        }
        execute_ready_merges(&mut state);
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
        let mut schedule = TopologySchedule::new(1000, Epoch::new(5), active);
        schedule.insert(Epoch::new(6), lookahead);
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
}
