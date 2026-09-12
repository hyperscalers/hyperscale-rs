//! Shuffle step, beacon-committee resample, and per-shard membership
//! diff.

use std::collections::{BTreeMap, BTreeSet};

use blake3::Hasher;
use hyperscale_types::{
    BeaconState, BlockHash, BlockHeight, CommitteeTransition, Epoch, MIN_BEACON_COMMITTEE_SIZE,
    PendingReshape, PendingRotation, RecoveryCause, ShardCommittee, ShardId, ShardRecovery,
    TransitionCause, ValidatorId, ValidatorStatus,
};

use crate::sampling::{sample_committee, sample_committee_weighted};
use crate::state::pool::pool_draw;

/// Domain tag for the shard recovery draw seed. Distinct from
/// [`crate::sampling`]'s pool-draw tag so the full-committee re-draw
/// never shares a PRNG stream with a same-epoch pool refill on the same
/// `(randomness, epoch, shard)` input.
const DOMAIN_SHARD_RECOVERY: &[u8] = b"hyperscale-shard-recovery-v1";

/// Retire the victim of every rotation whose entrant has readied.
///
/// The break half of the make-before-break rotation [`run_shuffle_step`]
/// opens. The entrant is now `OnShard { ready: true }`, so it counts
/// toward the shard's consensus subset and the victim's seat can go.
/// Deferring the removal to here rather than taking it at the opening
/// fold is the whole point: the consensus subset holds at `shard_size`
/// across the entrant's sync window, so the quorum denominator — and
/// with it the fault tolerance the shard actually runs at — never moves.
///
/// Runs behind the shuffle, so a victim is `OnShard` — and therefore
/// outside the derived pool — for every draw of the step that retires
/// it. A rotation opened by that same step seats an unready entrant, so
/// no fold both opens and resolves a rotation either.
pub(super) fn resolve_pending_rotations(state: &mut BeaconState) {
    let resolved: Vec<(ShardId, ValidatorId)> = state
        .pending_rotations
        .iter()
        .flat_map(|(shard, rotations)| rotations.iter().map(move |entry| (*shard, entry)))
        .filter(|(shard, (_, rotation))| {
            matches!(
                state.validators.get(&rotation.entrant).map(|r| r.status),
                Some(ValidatorStatus::OnShard { shard: s, ready: true, .. }) if s == *shard
            )
        })
        .map(|(shard, (victim, _))| (shard, *victim))
        .collect();
    for (shard, victim) in resolved {
        if let Some(rotations) = state.pending_rotations.get_mut(&shard) {
            rotations.remove(&victim);
            if rotations.is_empty() {
                state.pending_rotations.remove(&shard);
            }
        }
        if let Some(committee) = state.next_shard_committees.get_mut(&shard) {
            committee.members.retain(|v| *v != victim);
        }
        // Guarded like the recovery's replaced set: only pool a victim
        // still seated where the rotation left it, so a validator some
        // other transition has moved on is never dragged back.
        if let Some(rec) = state.validators.get_mut(&victim)
            && matches!(rec.status, ValidatorStatus::OnShard { shard: s, .. } if s == shard)
        {
            rec.status = ValidatorStatus::Pooled;
        }
    }
}

/// Cancel every rotation `shard` holds open: each entrant returns to the
/// pool and each victim keeps the seat it never gave up, leaving the
/// committee at `shard_size` with every member ready.
///
/// A rotation is a promise to swap a seat over a sync window. A caller
/// that needs the committee settled inside that window breaks the
/// promise instead of waiting it out, at the cost of the entrants'
/// partial syncs.
pub(super) fn abort_rotations(state: &mut BeaconState, shard: ShardId) {
    let Some(rotations) = state.pending_rotations.remove(&shard) else {
        return;
    };
    for rotation in rotations.values() {
        if let Some(committee) = state.next_shard_committees.get_mut(&shard) {
            committee.members.retain(|v| *v != rotation.entrant);
        }
        if let Some(rec) = state.validators.get_mut(&rotation.entrant)
            && matches!(rec.status, ValidatorStatus::OnShard { shard: s, .. } if s == shard)
        {
            rec.status = ValidatorStatus::Pooled;
        }
        state.miss_counters.remove(&rotation.entrant);
    }
}

/// Trickled committee rotation, make before break. When
/// `state.current_epoch` lands on a shuffle-interval boundary (and
/// `epoch > 0`), each shard seats an entrant from the pool via
/// [`pool_draw`] and records it against its longest-tenured ready member
/// in [`BeaconState::pending_rotations`]. The victim keeps its seat and
/// its `OnShard` status; [`resolve_pending_rotations`] retires it once
/// the entrant is ready. The system-wide rotation rate is one validator
/// per shard per interval, keeping per-shard composition churn uniform
/// and bounded; the interval itself derives from the chain config
/// ([`BeaconChainConfig::shuffle_interval_epochs`](hyperscale_types::BeaconChainConfig::shuffle_interval_epochs)),
/// which is sized so the open window is a bounded fraction of it.
///
/// Shards iterate in sorted [`ShardId`] order; the victim within each
/// shard is its longest-tenured ready member — the smallest
/// `(placed_at_epoch, ValidatorId)`, the id breaking ties within a
/// cohort placed together. The fixed tenure is load-bearing: a victim
/// drawn from `state.randomness` hands a randomness grinder a lever to
/// steer eviction away from corrupt seats every interval, marching a
/// targeted shard's corrupt count monotonically; on a tenure clock
/// every seat ages out on schedule, so the count settles at the entrant
/// draw's equilibrium instead. The entrant stays a seeded [`pool_draw`]
/// — a deterministic entrant would make each shard's next placement
/// predictable far ahead, handing an adaptive adversary a cheap target.
/// Shards with no eligible victim are skipped.
///
/// Self-replacement is impossible by construction — pinned by
/// `shuffle_avoids_self_replacement`. Derivation makes "in the pool"
/// mean "status == Pooled", and the victim holds `OnShard` from the
/// opening fold through the resolving one, so no draw in that span can
/// pick it. That span also fixes when a rotated-out validator becomes
/// drawable elsewhere: not in the step that rotates it out, but from the
/// fold that resolves its rotation onward.
pub(super) fn run_shuffle_step(state: &mut BeaconState) {
    let epoch = state.current_epoch;
    let interval = state.chain_config.shuffle_interval_epochs();
    if epoch.inner() == 0 || !epoch.inner().is_multiple_of(interval) {
        return;
    }
    // An entrant seats unready, so it is no use to the beacon until its
    // Ready folds, and while a rotation is open the shard carries no
    // ready spare to absorb attrition. At the BFT minimum the eligible
    // set has none of that slack to give, and a skip epoch folds no
    // Ready witness to recover it, so hold rotation network-wide until
    // it does. Opening a rotation moves nobody in or out of the eligible
    // set, so one reading covers the whole step.
    if state.beacon_eligible_count() <= MIN_BEACON_COMMITTEE_SIZE {
        return;
    }
    let shard_ids: Vec<ShardId> = state.next_shard_committees.keys().copied().collect();
    for shard in shard_ids {
        // A pending split's parent members all carry over to its children
        // as parent halves, ready by construction — the readiness the
        // split gate trusts. Rotating one out and refilling with a
        // not-yet-ready pool draw would seat a child below its ready
        // quorum, wedging it. Skip the splitting shard's rotation until it
        // executes (next epoch), the symmetric guard to the merge-keeper
        // skip below.
        if matches!(
            state.pending_reshapes.get(&shard),
            Some(PendingReshape::Split { .. })
        ) {
            continue;
        }
        // A recovering shard's fresh committee is pinned the same way: it
        // hasn't produced yet, so a rotated-in draw could never fold its
        // Ready witness — each rotation would shrink the consensus subset
        // toward a quorum the remaining members can't reach, re-wedging
        // the shard the recovery just re-seated. Rotation resumes once
        // the first crossing clears the recovery.
        if state.pending_recoveries.contains_key(&shard) {
            continue;
        }
        // Rotations run concurrently — one opens per interval and each
        // stays open for its entrant's sync — so a shard carries
        // `⌈sync / interval⌉` of them. The cap bounds committee size at
        // that; it never throttles the opening rate, which is what
        // tenure is derived from.
        //
        // Count only the entrants still syncing, which is what the cap
        // measures. An entrant whose readiness folded earlier this epoch
        // is not competing for sync headroom: [`resolve_pending_rotations`]
        // retires its victim later in this same fold, and the seat it
        // leaves is the one a rotation opened here would fill. Counting
        // it would cost the shard the whole boundary whenever a
        // resolution lands on one — every interval at which the derived
        // cadence divides the sync time, which is the common case, not
        // the corner.
        let in_flight = state.pending_rotations.get(&shard).map_or(0, |rotations| {
            rotations
                .values()
                .filter(|rotation| {
                    !matches!(
                        state.validators.get(&rotation.entrant).map(|r| r.status),
                        Some(ValidatorStatus::OnShard { ready: true, .. })
                    )
                })
                .count() as u64
        });
        if in_flight >= state.chain_config.max_rotations_in_flight() {
            continue;
        }
        // Bind the candidate set to validators whose status records
        // *this* shard. The global invariant `members ⇔ status ==
        // OnShard { shard: s, .. }` holds today; matching the shard
        // here means a future bug that drops a transition site (a
        // stale `members` entry pointing at a different shard) fails
        // to a skipped shuffle rather than picking from the wrong
        // shard.
        let victim = state
            .next_shard_committees
            .get(&shard)
            .expect("just iterated")
            .members
            .iter()
            .filter_map(|id| match state.validators.get(id).map(|r| r.status) {
                Some(ValidatorStatus::OnShard {
                    shard: s,
                    ready: true,
                    placed_at_epoch,
                }) if s == shard => Some((placed_at_epoch, *id)),
                _ => None,
            })
            // A pending merge's keepers must hold their child until they
            // sync the sibling half, so rotation skips them — their
            // departure would strand the merged committee below quorum.
            .filter(|(_, id)| !state.is_merge_keeper(shard, *id))
            // A member already named by an open rotation is spoken for.
            // Without this the same longest-tenured member would be named
            // again every interval, seating entrant after entrant against
            // one seat while the rest of the committee never aged.
            .filter(|(_, id)| {
                !state
                    .pending_rotations
                    .get(&shard)
                    .is_some_and(|rotations| rotations.contains_key(id))
            })
            .min();
        let Some((_, victim)) = victim else {
            continue;
        };
        // An empty pool leaves the rotation unopened rather than half
        // done: the victim keeps its seat until an interval whose pool
        // has stock, and the committee is never carrying a promise to
        // retire a member it has no replacement for.
        let Some(entrant) = pool_draw(state, shard) else {
            continue;
        };
        state.pending_rotations.entry(shard).or_default().insert(
            victim,
            PendingRotation {
                entrant,
                opened_at: epoch,
            },
        );
    }
}

/// Re-draw the entire committee of every halted shard from the free
/// pool — the f+1 liveness recovery.
///
/// A shard marches to a halt only by concentrating corrupt members; a
/// **full** fresh draw flushes that foothold, and unlike the one-seat
/// trickle it cannot be steered — reaching f+1 corrupt in one
/// hypergeometric draw is a negligible tail even against a seed grinder.
/// A partial re-seed would reopen the incremental march, so the re-draw
/// is all-or-nothing: a pool short of a full committee defers the
/// recovery (the shard stays flagged and retries each fold as the pool
/// refills).
///
/// The fresh members seat `OnShard { ready: true }` directly. The normal
/// readiness attestation rides the joined shard's own chain, and a
/// halted chain folds nothing — gating the cutover on a witness that can
/// never arrive would wedge the recovery. Seating ready extends the same
/// trust as the ready timeout, all at once: the lookahead epoch is the
/// sync window, and once the shard produces again its miss counters
/// catch any member that never caught up. The replaced committee returns
/// to the pool, excluded from its own replacement draw (its members are
/// still `OnShard` when the pool derives), and is retained in the
/// shard's routing view via [`ShardRecovery`] so the incomers can fetch
/// the halted tip from nodes that hold it.
pub(super) fn recover_committees(state: &mut BeaconState, halted: &BTreeSet<ShardId>) {
    // Fork-flagged shards re-draw under `Fork` provenance; a shard that
    // both forked and halted recovers once, as a fork. The flag is the
    // durable trigger: it clears only when the re-draw actually stamps a
    // pending recovery, so a fold that declines (short pool) retries on
    // every later fold, Skip epochs included.
    let forked: BTreeSet<ShardId> = state.fork_flagged.keys().copied().collect();
    for &shard in &forked {
        if recover_committee(state, shard, RecoveryCause::Fork) {
            state.fork_flagged.remove(&shard);
        }
    }
    for &shard in halted {
        if forked.contains(&shard) {
            continue;
        }
        recover_committee(state, shard, RecoveryCause::Halt);
    }
}

/// Whether the re-draw stamped a pending recovery for `shard`. `false`
/// when it declined — no attested anchor, or a free pool short of a full
/// committee — in which case the caller's trigger stays armed.
fn recover_committee(
    state: &mut BeaconState,
    shard: ShardId,
    requested_cause: RecoveryCause,
) -> bool {
    let size = state.chain_config.shard_size as usize;
    // A genesis-born shard that never produced still carries its ZERO
    // placeholder, which the topology snapshot omits — so a fresh committee
    // would have no attested anchor to seat against and the chain would
    // stay dead. Skip the redraw: it could only churn the pool. The halt
    // flag keeps standing, and a shard that never launched needs an
    // operator, not a rotation.
    if state
        .boundaries
        .get(&shard)
        .is_some_and(|b| b.block_hash == BlockHash::ZERO)
    {
        tracing::warn!(
            ?shard,
            "halted shard never produced: no attested anchor to recover against, redraw skipped"
        );
        return false;
    }
    // The beacon-authenticated frontier: the last boundary height folded
    // for the shard. A halted shard folds no new crossing, so this is
    // fixed for the halt's duration and equal across a stalled recovery's
    // successors. A shard reaching recovery always has a boundary record
    // (detection reads it); the default only guards a logically dead path.
    let attested_frontier = state
        .boundaries
        .get(&shard)
        .map_or(BlockHeight::GENESIS, |b| b.height);
    let pool = state.pooled_validators();
    if pool.len() < size {
        tracing::warn!(
            ?shard,
            pooled = pool.len(),
            committee_size = size,
            "halted shard awaits recovery: free pool below a full committee"
        );
        return false;
    }
    let mut h = Hasher::new();
    h.update(DOMAIN_SHARD_RECOVERY);
    h.update(state.randomness.as_bytes());
    h.update(&state.current_epoch.inner().to_le_bytes());
    h.update(&shard.inner().to_le_bytes());
    let fresh = sample_committee(&pool, h.finalize().as_bytes(), size);

    let replaced = state
        .next_shard_committees
        .insert(
            shard,
            ShardCommittee {
                members: fresh.clone(),
            },
        )
        .map(|committee| committee.members)
        .unwrap_or_default();
    for id in &fresh {
        state
            .validators
            .get_mut(id)
            .expect("drawn from the derived pool, must be in validators")
            .status = ValidatorStatus::OnShard {
            shard,
            ready: true,
            placed_at_epoch: state.current_epoch,
        };
        state.miss_counters.remove(id);
    }
    for id in &replaced {
        if let Some(rec) = state.validators.get_mut(id)
            && matches!(rec.status, ValidatorStatus::OnShard { shard: s, .. } if s == shard)
        {
            rec.status = ValidatorStatus::Pooled;
        }
        state.miss_counters.remove(id);
    }
    // The whole committee is replaced, victim and entrant with it, so a
    // rotation the shuffle had open on this shard names two validators
    // that no longer sit here.
    state.pending_rotations.remove(&shard);

    // The recovery resets the shard's miss count: the fresh committee
    // gets a full threshold of observed folds to sync and produce before
    // the shard re-flags and re-draws.
    if let Some(boundary) = state.boundaries.get_mut(&shard) {
        boundary.consecutive_misses = 0;
    }

    // A recovery that itself stalled folds its retention into the new
    // record: every committee that might hold the halted tip stays
    // routable until the shard commits again. Fork provenance is sticky —
    // a fork recovery that re-stalls and re-draws under a halt trigger
    // keeps its `Fork` cause, so a proven fork is never downgraded.
    let mut retained = replaced;
    let mut cause = requested_cause;
    if let Some(prior) = state.pending_recoveries.remove(&shard) {
        retained.extend(prior.retained);
        if prior.cause == RecoveryCause::Fork {
            cause = RecoveryCause::Fork;
        }
    }
    retained.sort_unstable();
    retained.dedup();
    tracing::info!(
        ?shard,
        fresh = ?fresh,
        ?cause,
        "shard committee fully re-drawn from the pool"
    );
    state.pending_recoveries.insert(
        shard,
        ShardRecovery {
            cause,
            rotated_at: state.current_epoch,
            retained,
            attested_frontier,
        },
    );
    true
}

/// Fill any live shard committee below `shard_size` from the pool.
///
/// [`run_shuffle_step`] maintains a committee's size — rotate one out, draw one
/// in — but never grows it. A committee drawn short — a split cohort drawn
/// against a pool the predecessors' make-before-break coast had momentarily
/// depleted — would otherwise stay under `shard_size` for life, tightening its
/// quorum toward all-of-N and missing the full-strength target a grow must
/// reach. Once those predecessors dissolve and return their members to the
/// pool, top each short committee back up; a member placed here syncs in via
/// the normal `Ready` path like any pool refill. Skips a shard mid-reshape — a
/// splitting parent's members carry to its children, a merge target's are its
/// keepers — matching the shuffle's guards.
pub(super) fn top_up_committees(state: &mut BeaconState) {
    // Only a split can seat a committee short — its cohort drawn against a pool
    // the make-before-break coast had depleted — and a split always leaves the
    // topology with both children, so at least two shards. A merge draws a full
    // keeper committee and genesis seats `shard_size`, so a lone shard is always
    // at strength. Skipping the single-shard case keeps top-up from churning a
    // pristine genesis committee (and the under-quorum committees small unit
    // fixtures construct in isolation).
    if state.next_shard_committees.len() <= 1 {
        return;
    }
    let shard_size = state.chain_config.shard_size as usize;
    let shard_ids: Vec<ShardId> = state.next_shard_committees.keys().copied().collect();
    for shard in shard_ids {
        if state.pending_reshapes.contains_key(&shard) {
            continue;
        }
        while state
            .next_shard_committees
            .get(&shard)
            .is_some_and(|committee| committee.members.len() < shard_size)
        {
            if pool_draw(state, shard).is_none() {
                break;
            }
        }
    }
}

/// Resample `state.committee` from [`beacon_eligible`] using
/// `state.randomness`, returning the resulting handover.
///
/// Runs every epoch — the slot-equals-epoch model makes every
/// `apply_epoch` a beacon-committee boundary, so the runner gets a
/// fresh SPC instance per epoch regardless of whether the resampled
/// set differs from the prior one.
///
/// Reads the post-shuffle eligible set: validators rotated to `Pooled`
/// by [`run_shuffle_step`] are excluded from this resample's input.
/// Order matters — putting the resample before the shuffle would feed
/// stale `OnShard { ready: true }` ids into the sampler.
///
/// `excluded` is the validator set the sampler must skip on top of the
/// natural [`beacon_eligible`] filter — empty under both the natural
/// resample and the skip path; carried so future schedulers that
/// want to exclude additional validators (e.g. operator-driven
/// quarantine) have a single seam to plumb through. `cause` tags the
/// resulting transition.
///
/// The draw is recency-weighted: each eligible member's weight ramps
/// from low right after it serves to full over `cooldown = eligible /
/// committee_size` epochs — one full committee turnover — recovering by
/// one per epoch. A grinder steering the seed can bias which committee
/// forms, but a corrupt member it just seated is down-weighted for the
/// cooldown, so it cannot keep re-seating the same set; the sustained
/// foothold caps near the natural `β · committee_size`. A never-served
/// member's baseline is its `registered_at_epoch`, so a fresh registrant
/// ramps in from low weight — the register-to-reset dodge buys nothing,
/// and ids are never reused. After the draw the drawn members'
/// [`BeaconState::last_beacon_service`] is stamped to this epoch.
pub(super) fn resample_beacon_committee(
    state: &mut BeaconState,
    excluded: &BTreeSet<ValidatorId>,
    cause: TransitionCause,
) -> CommitteeTransition {
    let prior = std::mem::take(&mut state.committee);
    let all_eligible = state.beacon_eligible();
    // The period counts the full eligible set, not the excluded-filtered
    // draw pool.
    let cooldown = state.recency_period_for(all_eligible.len());
    let eligible: Vec<ValidatorId> = all_eligible
        .into_iter()
        .filter(|id| !excluded.contains(id))
        .collect();
    let committee_size = state.chain_config.beacon_committee_size as usize;
    let now = state.current_epoch.inner();
    let weighted: Vec<(ValidatorId, u64)> = eligible
        .iter()
        .map(|id| {
            let baseline = state
                .last_beacon_service
                .get(id)
                .copied()
                .or_else(|| state.validators.get(id).map(|r| r.registered_at_epoch))
                .unwrap_or(Epoch::GENESIS)
                .inner();
            (*id, now.saturating_sub(baseline).min(cooldown))
        })
        .collect();
    state.committee =
        sample_committee_weighted(&weighted, state.randomness.as_bytes(), committee_size);
    for id in &state.committee {
        state.last_beacon_service.insert(*id, state.current_epoch);
    }
    CommitteeTransition {
        from: prior,
        to: state.committee.clone(),
        cause,
        at_slot: state.current_epoch,
    }
}

/// Compare each shard's current `members` against the epoch-start
/// snapshot and emit one [`CommitteeTransition`] per shard whose
/// membership *set* changed. Members are compared as sets, so a no-op
/// churn (e.g. jail one validator, [`pool_draw`] refills with the same
/// one) doesn't register as a transition.
///
/// The cause is shared across all transitions emitted in one epoch:
///
/// - [`TransitionCause::NaturalShuffle`] when the epoch landed on a
///   shuffle interval boundary (the dominant cadence on those epochs).
/// - [`TransitionCause::MembershipChange`] otherwise — irregular events
///   like jail, deactivate, or withdrawal-completion auto-deactivation
///   drove the change.
///
/// Shards present in the snapshot but missing from the current state
/// (or vice versa) aren't normal under a stable shard count, but the
/// diff is robust to either case by treating the missing side as an
/// empty member list.
pub(super) fn diff_shard_committees(
    state: &BeaconState,
    pre_shard_members: &BTreeMap<ShardId, Vec<ValidatorId>>,
) -> BTreeMap<ShardId, CommitteeTransition> {
    let epoch = state.current_epoch;
    let interval = state.chain_config.shuffle_interval_epochs();
    let cause = if epoch.inner() > 0 && epoch.inner().is_multiple_of(interval) {
        TransitionCause::NaturalShuffle
    } else {
        TransitionCause::MembershipChange
    };
    let mut shard_ids: BTreeSet<ShardId> = pre_shard_members.keys().copied().collect();
    shard_ids.extend(state.next_shard_committees.keys().copied());
    let mut transitions = BTreeMap::new();
    for shard in shard_ids {
        let prior = pre_shard_members.get(&shard).cloned().unwrap_or_default();
        let current = state
            .next_shard_committees
            .get(&shard)
            .map(|c| c.members.clone())
            .unwrap_or_default();
        let prior_set: BTreeSet<ValidatorId> = prior.iter().copied().collect();
        let current_set: BTreeSet<ValidatorId> = current.iter().copied().collect();
        if prior_set != current_set {
            transitions.insert(
                shard,
                CommitteeTransition {
                    from: prior,
                    to: current,
                    cause,
                    at_slot: epoch,
                },
            );
        }
    }
    transitions
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use hyperscale_types::{
        BEACON_SIGNER_COUNT, BeaconState, BeaconWitnessLeafCount, BlockHash, BlockHeight,
        DeclaredWork, Epoch, HALT_THRESHOLD_EPOCHS, Hash, JailReason, MIN_STAKE_FLOOR,
        PendingReshape, Randomness, RecoveryCause, ShardBoundary, ShardCommittee, ShardId,
        ShardWitnessPayload, Stake, StakePool, StakePoolId, StateRoot, TransitionCause,
        ValidatorId, ValidatorStatus, WeightedTimestamp,
    };

    use super::{
        recover_committee, recover_committees, resample_beacon_committee,
        resolve_pending_rotations, run_shuffle_step,
    };
    use crate::state::test_fixtures::{
        apply_next_epoch, apply_witness_chunk, empty_state, possession_proof, single_pool_state,
        validator_record,
    };
    use crate::state::vrf::jail_validator;
    // ─── run_shuffle_step + shard_committee_transitions diff ─────────────

    /// The shuffle interval the fixture states derive — all of them run
    /// under the dev-default `BeaconChainConfig`.
    fn shuffle_interval() -> u64 {
        empty_state().chain_config.shuffle_interval_epochs()
    }

    /// Seat four ready validators on an untracked sibling shard so
    /// `beacon_eligible` has slack past the rotation guard. The sibling
    /// carries no committee entry, so the shuffle itself never touches
    /// them and every per-shard assertion stays undisturbed.
    fn add_eligible_slack(state: &mut BeaconState) {
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
    }

    /// The shard's sole open rotation, as `(victim, entrant)`. Fixtures
    /// here run at `shard_size = 4`, where `max_rotations_in_flight` is
    /// one, so a shard mid-rotation holds exactly one pair.
    fn sole_rotation(state: &BeaconState, shard: ShardId) -> (ValidatorId, ValidatorId) {
        let rotations = &state.pending_rotations[&shard];
        assert_eq!(rotations.len(), 1, "one rotation in flight at shard_size 4");
        let (victim, rotation) = rotations.iter().next().expect("just checked");
        (*victim, rotation.entrant)
    }

    /// Flip a seated validator's `OnShard` status to ready, standing in
    /// for the `Ready` witness that resolves a rotation.
    fn mark_ready(state: &mut BeaconState, id: ValidatorId) {
        let status = &mut state.validators.get_mut(&id).expect("seated").status;
        let ValidatorStatus::OnShard { ready, .. } = status else {
            panic!("{id:?} is not seated on a shard");
        };
        *ready = true;
    }

    /// Ready every open rotation's entrant, then fold — the break half of
    /// every make-before-break rotation currently in flight.
    fn resolve_open_rotations(state: &mut BeaconState) {
        let entrants: Vec<ValidatorId> = state
            .pending_rotations
            .values()
            .flat_map(|rotations| rotations.values().map(|rotation| rotation.entrant))
            .collect();
        for entrant in entrants {
            mark_ready(state, entrant);
        }
        apply_next_epoch(state, &[]);
    }

    /// Two shards, `per_shard` ready members each, `pool_extras`
    /// `Pooled` validators kept in reserve so refills have stock.
    /// Pool stake is sized generously to keep `min_stake` at the floor.
    fn multi_shard_state(shard_count: u64, per_shard: u64, pool_extras: u64) -> BeaconState {
        let mut state = empty_state();
        let pool_id = StakePoolId::new(0);
        let total = shard_count * per_shard + pool_extras;
        let mut pool_validators = BTreeSet::new();
        let mut next_id = 0u64;
        for s in 0..shard_count {
            let shard = ShardId::leaf(1, s);
            let mut members = Vec::new();
            for _ in 0..per_shard {
                let id = ValidatorId::new(next_id);
                pool_validators.insert(id);
                members.push(id);
                state.validators.insert(
                    id,
                    validator_record(
                        next_id,
                        0,
                        ValidatorStatus::OnShard {
                            shard,
                            ready: true,
                            placed_at_epoch: Epoch::GENESIS,
                        },
                    ),
                );
                next_id += 1;
            }
            state
                .next_shard_committees
                .insert(shard, ShardCommittee { members });
        }
        for _ in 0..pool_extras {
            let id = ValidatorId::new(next_id);
            pool_validators.insert(id);
            state
                .validators
                .insert(id, validator_record(next_id, 0, ValidatorStatus::Pooled));
            next_id += 1;
        }
        state.pools.insert(
            pool_id,
            StakePool {
                id: pool_id,
                // Generous stake so `min_stake` stays clamped at the
                // floor and no admission gate trips during the test.
                total_stake: Stake::from_quanta(u128::from(total) * MIN_STAKE_FLOOR.quanta() * 4),
                validators: pool_validators,
                pending_withdrawals: Vec::new(),
                released_cumulative: Stake::ZERO,
                conviction: None,
            },
        );
        state
    }

    /// Off-interval epoch: shard committees and the pool stay
    /// byte-identical; no transition emitted.
    #[test]
    fn shuffle_doesnt_fire_off_interval() {
        // Land at epoch 1 — not a shuffle-interval multiple.
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Park a Pooled extra so a hypothetical refill would have stock.
        state.validators.insert(
            ValidatorId::new(99),
            validator_record(99, 0, ValidatorStatus::Pooled),
        );
        state
            .pools
            .get_mut(&StakePoolId::new(0))
            .unwrap()
            .validators
            .insert(ValidatorId::new(99));
        state
            .pools
            .get_mut(&StakePoolId::new(0))
            .unwrap()
            .total_stake = Stake::from_quanta(10 * MIN_STAKE_FLOOR.quanta());
        let initial_members = state.next_shard_committees[&ShardId::leaf(1, 0)]
            .members
            .clone();
        let initial_pool = state.pooled_validators();

        let effects = apply_next_epoch(&mut state, &[]);

        assert_eq!(
            state.next_shard_committees[&ShardId::leaf(1, 0)].members,
            initial_members
        );
        assert_eq!(state.pooled_validators(), initial_pool);
        assert!(effects.shard_committee_transitions.is_empty());
    }

    /// `top_up_committees` fills a committee drawn below `shard_size` from the
    /// pool — the heal a short split cohort needs once predecessors free their
    /// members — and is a no-op once the pool is spent.
    #[test]
    fn top_up_fills_short_committees_from_the_pool() {
        // Two shards at 3 of 4 ready members, two pooled spares.
        let mut state = multi_shard_state(2, 3, 2);
        assert_eq!(state.chain_config.shard_size, 4);

        super::top_up_committees(&mut state);

        for s in 0..2 {
            assert_eq!(
                state.next_shard_committees[&ShardId::leaf(1, s)]
                    .members
                    .len(),
                4,
                "a short committee is topped up to shard_size",
            );
        }
        assert!(
            state.pooled_validators().is_empty(),
            "both spares were drawn into the short committees",
        );

        // Idempotent: at strength with an empty pool, a second pass changes
        // nothing.
        super::top_up_committees(&mut state);
        for s in 0..2 {
            assert_eq!(
                state.next_shard_committees[&ShardId::leaf(1, s)]
                    .members
                    .len(),
                4,
            );
        }
    }

    /// A shard mid-split is skipped while its sibling is topped up: a splitting
    /// shard's members carry to its children as ready parent halves, so a
    /// not-yet-ready pool draw must not join it.
    #[test]
    fn top_up_skips_a_splitting_shard() {
        // Two short shards (so the multi-shard gate passes) and two spares.
        let mut state = multi_shard_state(2, 3, 2);
        let splitting = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        state.pending_reshapes.insert(
            splitting,
            PendingReshape::Split {
                last_asserted: Epoch::GENESIS,
                admitted_at: Epoch::GENESIS,
                cohort: BTreeMap::new(),
                cohort_seed: state.randomness,
                scheduled: None,
            },
        );

        super::top_up_committees(&mut state);

        assert_eq!(
            state.next_shard_committees[&splitting].members.len(),
            3,
            "a splitting shard is not topped up",
        );
        assert_eq!(
            state.next_shard_committees[&sibling].members.len(),
            4,
            "a non-splitting sibling is still topped up from the pool",
        );
    }

    /// On a shuffle-interval boundary, each shard seats one entrant from
    /// the pool beside its longest-tenured ready member. The member keeps
    /// its seat until the entrant readies, and only then retires to the
    /// pool.
    #[test]
    fn shuffle_rotates_one_validator_per_shard_at_interval() {
        // 2 shards × 4 ready actives + 2 pool extras = 10 validators.
        let mut state = multi_shard_state(2, 4, 2);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(shuffle_interval() - 1);

        let shards = [ShardId::leaf(1, 0), ShardId::leaf(1, 1)];
        let initial: Vec<Vec<ValidatorId>> = shards
            .iter()
            .map(|shard| state.next_shard_committees[shard].members.clone())
            .collect();

        apply_next_epoch(&mut state, &[]);

        // The genesis cohorts share a placement epoch, so tenure ties
        // break by id: each shard names its smallest member id as victim.
        for (i, (shard, expected_victim)) in shards.iter().zip([0u64, 4]).enumerate() {
            let members = &state.next_shard_committees[shard].members;
            let (victim, entrant) = sole_rotation(&state, *shard);
            assert_eq!(
                victim,
                ValidatorId::new(expected_victim),
                "tenure names the longest-tenured member as victim",
            );
            assert_eq!(
                state.pending_rotations[shard][&victim].opened_at,
                state.current_epoch,
            );
            assert_eq!(
                members.len(),
                5,
                "the entrant seats beside a committee still at full strength",
            );
            assert!(
                members.contains(&victim),
                "the victim holds its seat until the entrant readies",
            );
            assert!(
                !initial[i].contains(&entrant),
                "the entrant comes from the pool",
            );
            assert_eq!(
                state.ready_consensus_members(&state.next_shard_committees)[shard].len(),
                4,
                "the consensus subset never dips through the window",
            );
        }

        resolve_open_rotations(&mut state);

        for (shard, victim) in shards.iter().zip([0u64, 4]) {
            let members = &state.next_shard_committees[shard].members;
            let victim = ValidatorId::new(victim);
            assert_eq!(members.len(), 4, "the committee is back to capacity");
            assert!(
                !members.contains(&victim),
                "the victim retires on resolution"
            );
            assert!(matches!(
                state.validators[&victim].status,
                ValidatorStatus::Pooled,
            ));
            assert_eq!(
                state.ready_consensus_members(&state.next_shard_committees)[shard].len(),
                4,
            );
        }
        assert!(state.pending_rotations.is_empty());
    }

    /// Not-ready members are ineligible to be rotated out — only
    /// `OnShard { ready: true }` validators are picked.
    #[test]
    fn shuffle_picks_only_from_ready_members() {
        let shard = ShardId::leaf(1, 0);
        let mut state = single_pool_state(4);
        add_eligible_slack(&mut state);
        // Mark validators 2 and 3 as not-yet-ready.
        for id in [2u64, 3] {
            state
                .validators
                .get_mut(&ValidatorId::new(id))
                .unwrap()
                .status = ValidatorStatus::OnShard {
                shard,
                ready: false,
                placed_at_epoch: Epoch::GENESIS,
            };
        }
        state.committee = vec![ValidatorId::new(0), ValidatorId::new(1)];
        // Pool extra and headroom so refill has stock and admission
        // gates stay clear.
        state.validators.insert(
            ValidatorId::new(99),
            validator_record(99, 0, ValidatorStatus::Pooled),
        );
        let pool = state.pools.get_mut(&StakePoolId::new(0)).unwrap();
        pool.validators.insert(ValidatorId::new(99));
        pool.total_stake = Stake::from_quanta(10 * MIN_STAKE_FLOOR.quanta());
        state.current_epoch = Epoch::new(shuffle_interval() - 1);

        let initial_members = state.next_shard_committees[&shard].members.clone();
        apply_next_epoch(&mut state, &[]);

        // The victim is the longer-tenured of the two ready members —
        // 0 over 1, equal epochs falling to the smaller id.
        assert_eq!(
            sole_rotation(&state, shard).0,
            ValidatorId::new(0),
            "only a ready member can be named victim",
        );

        resolve_open_rotations(&mut state);

        // Not-ready validators must still be on the shard.
        for not_ready_id in [2u64, 3] {
            assert!(
                state.next_shard_committees[&shard]
                    .members
                    .contains(&ValidatorId::new(not_ready_id)),
                "not-ready validator {not_ready_id} got shuffled out"
            );
        }
        let rotated = initial_members
            .iter()
            .filter(|id| !state.next_shard_committees[&shard].members.contains(id))
            .count();
        assert_eq!(rotated, 1, "exactly one ready member rotates out");
        assert!(
            !state.next_shard_committees[&shard]
                .members
                .contains(&ValidatorId::new(0)),
            "the longest-tenured ready member is the victim",
        );
    }

    /// The per-shard `pool_draw` must not pick the shard's own victim.
    /// The victim holds `OnShard` from the opening fold to the resolving
    /// one, so a pool holding exactly one spare must always seat the
    /// spare — never the validator on its way out.
    #[test]
    fn shuffle_avoids_self_replacement() {
        let shard = ShardId::leaf(1, 0);
        let mut state = single_pool_state(4);
        add_eligible_slack(&mut state);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let spare = ValidatorId::new(99);
        state
            .validators
            .insert(spare, validator_record(99, 0, ValidatorStatus::Pooled));
        let pool = state.pools.get_mut(&StakePoolId::new(0)).unwrap();
        pool.validators.insert(spare);
        pool.total_stake = Stake::from_quanta(10 * MIN_STAKE_FLOOR.quanta());
        state.current_epoch = Epoch::new(shuffle_interval() - 1);

        let initial_members = state.next_shard_committees[&shard].members.clone();
        apply_next_epoch(&mut state, &[]);

        let (victim, entrant) = sole_rotation(&state, shard);
        assert_eq!(entrant, spare, "the lone spare must be the entrant");
        assert_eq!(
            victim,
            ValidatorId::new(0),
            "tenure picks the victim: equal epochs fall to the smallest id",
        );
        assert!(initial_members.contains(&victim));
        // The victim is out of the pool for the whole open window, so no
        // later draw anywhere can pick it back up.
        assert!(state.pooled_validators().is_empty());

        resolve_open_rotations(&mut state);

        let members = state.next_shard_committees[&shard].members.clone();
        assert_eq!(members.len(), 4);
        assert!(members.contains(&spare));
        assert!(!members.contains(&victim), "victim must not be re-drawn");
        assert_eq!(state.pooled_validators(), vec![victim]);
        assert!(matches!(
            state.validators[&victim].status,
            ValidatorStatus::Pooled,
        ));
    }

    /// The victim is the longest-tenured ready member — the smallest
    /// `(placed_at_epoch, ValidatorId)` — so eviction rides a tenure
    /// clock the folded randomness cannot steer, and members placed
    /// together drain in id order.
    #[test]
    fn shuffle_evicts_the_longest_tenured_ready_member() {
        let shard = ShardId::leaf(1, 0);
        let mut state = single_pool_state(4);
        add_eligible_slack(&mut state);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Distinct tenures, with ids 1 and 3 sharing the oldest epoch:
        // the smaller id breaks the tie.
        for (id, placed) in [(0u64, 9u64), (1, 3), (2, 7), (3, 3)] {
            state
                .validators
                .get_mut(&ValidatorId::new(id))
                .unwrap()
                .status = ValidatorStatus::OnShard {
                shard,
                ready: true,
                placed_at_epoch: Epoch::new(placed),
            };
        }
        let spare = ValidatorId::new(99);
        state
            .validators
            .insert(spare, validator_record(99, 0, ValidatorStatus::Pooled));
        let pool = state.pools.get_mut(&StakePoolId::new(0)).unwrap();
        pool.validators.insert(spare);
        pool.total_stake = Stake::from_quanta(10 * MIN_STAKE_FLOOR.quanta());
        state.current_epoch = Epoch::new(shuffle_interval() - 1);

        apply_next_epoch(&mut state, &[]);

        assert_eq!(
            sole_rotation(&state, shard).0,
            ValidatorId::new(1),
            "the oldest tenure with the smallest id is named victim",
        );

        resolve_open_rotations(&mut state);

        let members = &state.next_shard_committees[&shard].members;
        assert!(
            !members.contains(&ValidatorId::new(1)),
            "the oldest tenure with the smallest id is evicted",
        );
        for kept in [0u64, 2, 3] {
            assert!(
                members.contains(&ValidatorId::new(kept)),
                "member {kept} outranks the victim's tenure order",
            );
        }
        assert!(matches!(
            state.validators[&ValidatorId::new(1)].status,
            ValidatorStatus::Pooled,
        ));
    }

    /// With nobody `Pooled` to seat as entrant, the shuffle leaves the
    /// rotation unopened: the committee never carries a promise to retire
    /// a member it has no replacement for.
    #[test]
    fn shuffle_skips_rotation_when_pool_cannot_refill() {
        let shard = ShardId::leaf(1, 0);
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(shuffle_interval() - 1);
        assert!(state.pooled_validators().is_empty());

        let initial_members = state.next_shard_committees[&shard].members.clone();
        let effects = apply_next_epoch(&mut state, &[]);

        assert_eq!(
            state.next_shard_committees[&shard].members, initial_members,
            "an unrefillable rotation must not run",
        );
        assert!(state.pooled_validators().is_empty());
        assert!(state.pending_rotations.is_empty());
        assert!(effects.shard_committee_transitions.is_empty());
    }

    /// With `beacon_eligible` at the BFT minimum, rotation is held: an
    /// entrant seats unready, so it is no use to the beacon until its
    /// Ready folds, and a skip epoch folds no Ready witness to recover
    /// the eligible set if attrition takes it below the floor.
    #[test]
    fn shuffle_holds_rotation_at_the_beacon_eligible_floor() {
        let shard = ShardId::leaf(1, 0);
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.validators.insert(
            ValidatorId::new(99),
            validator_record(99, 0, ValidatorStatus::Pooled),
        );
        let pool = state.pools.get_mut(&StakePoolId::new(0)).unwrap();
        pool.validators.insert(ValidatorId::new(99));
        pool.total_stake = Stake::from_quanta(10 * MIN_STAKE_FLOOR.quanta());
        state.current_epoch = Epoch::new(shuffle_interval() - 1);
        assert_eq!(state.beacon_eligible().len(), 4);

        let initial_members = state.next_shard_committees[&shard].members.clone();
        apply_next_epoch(&mut state, &[]);

        assert_eq!(
            state.next_shard_committees[&shard].members, initial_members,
            "rotation at the eligible floor must hold",
        );
        assert!(state.pending_rotations.is_empty());
    }

    /// A shard at its rotation cap is skipped by the next interval's
    /// shuffle. At `shard_size = 4` the cap is one, so a single open
    /// rotation holds the shard.
    #[test]
    fn shuffle_holds_a_shard_at_its_rotation_cap() {
        let shard = ShardId::leaf(1, 0);
        let mut state = multi_shard_state(1, 4, 3);
        add_eligible_slack(&mut state);
        state.current_epoch = Epoch::new(shuffle_interval());

        run_shuffle_step(&mut state);
        let opened = state.pending_rotations[&shard].clone();
        let members = state.next_shard_committees[&shard].members.clone();
        let pool = state.pooled_validators();

        run_shuffle_step(&mut state);

        assert_eq!(
            state.pending_rotations[&shard], opened,
            "the open rotation is the one that resolves",
        );
        assert_eq!(
            state.next_shard_committees[&shard].members, members,
            "a second entrant must not seat on a rotating shard",
        );
        assert_eq!(state.pooled_validators(), pool);
    }

    /// Jailing the victim mid-rotation drops the pair and takes the
    /// refill with it: the entrant already seated is the replacement, and
    /// a second draw would leave the committee one over strength with
    /// nothing left to retire it — `top_up_committees` only grows.
    #[test]
    fn jailing_the_victim_mid_rotation_leaves_the_committee_at_strength() {
        let shard = ShardId::leaf(1, 0);
        let mut state = multi_shard_state(1, 4, 3);
        add_eligible_slack(&mut state);
        state.current_epoch = Epoch::new(shuffle_interval());
        run_shuffle_step(&mut state);
        let (victim, entrant) = sole_rotation(&state, shard);
        assert_eq!(state.next_shard_committees[&shard].members.len(), 5);

        let epoch = state.current_epoch;
        jail_validator(&mut state, victim, JailReason::Performance, epoch);

        assert!(state.pending_rotations.is_empty(), "the pair dies with it");
        let members = &state.next_shard_committees[&shard].members;
        assert_eq!(members.len(), 4, "the entrant is the replacement");
        assert!(members.contains(&entrant));
        assert!(!members.contains(&victim));
    }

    /// Jailing the entrant mid-rotation aborts the rotation: the victim
    /// keeps the seat it never gave up, so the committee is already at
    /// strength and needs no refill either.
    #[test]
    fn jailing_the_entrant_mid_rotation_leaves_the_victim_seated() {
        let shard = ShardId::leaf(1, 0);
        let mut state = multi_shard_state(1, 4, 3);
        add_eligible_slack(&mut state);
        state.current_epoch = Epoch::new(shuffle_interval());
        run_shuffle_step(&mut state);
        let (victim, entrant) = sole_rotation(&state, shard);

        let epoch = state.current_epoch;
        jail_validator(&mut state, entrant, JailReason::Performance, epoch);

        assert!(state.pending_rotations.is_empty());
        let members = &state.next_shard_committees[&shard].members;
        assert_eq!(members.len(), 4);
        assert!(members.contains(&victim), "the victim holds its seat");
        assert!(!members.contains(&entrant));
        assert_eq!(
            state.ready_consensus_members(&state.next_shard_committees)[&shard].len(),
            4,
        );
    }

    /// Attrition elsewhere on a rotating shard still refills: the lost
    /// member is neither the seat the entrant syncs into nor the one the
    /// victim holds, so without a draw the shard would settle one short
    /// when the rotation resolves.
    #[test]
    fn jailing_a_bystander_mid_rotation_still_refills() {
        let shard = ShardId::leaf(1, 0);
        let mut state = multi_shard_state(1, 4, 3);
        add_eligible_slack(&mut state);
        state.current_epoch = Epoch::new(shuffle_interval());
        run_shuffle_step(&mut state);
        let (victim, entrant) = sole_rotation(&state, shard);
        let opened = state.pending_rotations[&shard].clone();
        let bystander = *state.next_shard_committees[&shard]
            .members
            .iter()
            .find(|id| **id != victim && **id != entrant)
            .expect("a rotating committee has bystanders");

        let epoch = state.current_epoch;
        jail_validator(&mut state, bystander, JailReason::Performance, epoch);

        assert_eq!(
            state.pending_rotations[&shard], opened,
            "a bystander's departure leaves the rotation standing",
        );
        assert_eq!(
            state.next_shard_committees[&shard].members.len(),
            5,
            "the refill keeps the shard whole for the resolution",
        );
    }

    /// A recovery re-draws the whole committee, victim and entrant with
    /// it, so the rotation naming them is dropped rather than left to
    /// retire a validator the fresh committee never seated.
    #[test]
    fn recovery_drops_the_shards_rotation() {
        let shard = ShardId::leaf(1, 0);
        let mut state = multi_shard_state(1, 4, 8);
        add_eligible_slack(&mut state);
        state.current_epoch = Epoch::new(shuffle_interval());
        run_shuffle_step(&mut state);
        let (victim, entrant) = sole_rotation(&state, shard);

        assert!(recover_committee(&mut state, shard, RecoveryCause::Halt));

        assert!(state.pending_rotations.is_empty());
        let members = &state.next_shard_committees[&shard].members;
        assert_eq!(members.len(), 4, "a fresh committee, at strength");
        assert!(!members.contains(&victim));
        assert!(!members.contains(&entrant));
    }

    /// Rotations run concurrently, up to what the cadence opens against
    /// the sync window. A shard limited to one open rotation would rotate
    /// once per sync window instead of once per interval, stretching
    /// per-seat tenure by that same ratio and weakening the
    /// adaptive-corruption defense the cadence exists for.
    ///
    /// Run at 16 and at 12. Twelve is the case a cap read off the
    /// mid-sync fraction `⌊n / SHUFFLE_SYNC_HEADROOM⌋` gets wrong,
    /// holding the shard at one rotation where its own cadence opens two.
    #[test]
    fn a_shard_holds_concurrent_rotations_up_to_the_cap() {
        for shard_size in [16usize, 12] {
            let seats = u64::try_from(shard_size).expect("test sizes fit a u64");
            let shard = ShardId::leaf(1, 0);
            let mut state = multi_shard_state(1, seats, 8);
            state.chain_config.shard_size =
                u32::try_from(shard_size).expect("test sizes fit a u32");
            let interval = state.chain_config.shuffle_interval_epochs();
            assert_eq!(state.chain_config.max_rotations_in_flight(), 2);

            // Three intervals with no entrant readying: two rotations
            // open, the third is held at the cap.
            for i in 1..=3 {
                state.current_epoch = Epoch::new(interval * i);
                run_shuffle_step(&mut state);
            }

            let rotations = &state.pending_rotations[&shard];
            assert_eq!(
                rotations.len(),
                2,
                "shard_size {shard_size}: the cap bounds what is open at once",
            );
            assert_eq!(
                rotations.keys().collect::<BTreeSet<_>>().len(),
                2,
                "shard_size {shard_size}: a member already named is not named again",
            );
            assert_eq!(
                state.next_shard_committees[&shard].members.len(),
                shard_size + 2,
                "shard_size {shard_size}: each open rotation carries one entrant above strength",
            );
            assert_eq!(
                state.ready_consensus_members(&state.next_shard_committees)[&shard].len(),
                shard_size,
                "shard_size {shard_size}: concurrent entrants cost the quorum denominator nothing",
            );
        }
    }

    /// A resolution landing on a shuffle boundary must not cost the shard
    /// that boundary. The entrant's readiness folds before the shuffle
    /// runs and its victim retires after, so a shard at the cap on such
    /// an epoch is at the cap only for the width of one fold — counting
    /// the resolving rotation would skip the opening and drop the shard
    /// to a fraction of its cadence, stretching tenure by the reciprocal.
    #[test]
    fn a_resolution_on_a_shuffle_boundary_still_opens_a_rotation() {
        let shard = ShardId::leaf(1, 0);
        let mut state = multi_shard_state(1, 16, 8);
        state.chain_config.shard_size = 16;
        let interval = state.chain_config.shuffle_interval_epochs();
        assert_eq!(state.chain_config.max_rotations_in_flight(), 2);

        // Fill the shard to its cap, then ready the older entrant — the
        // shape `auto_ready_timeout` leaves when a sync budget expires on
        // a shuffle epoch.
        for i in 1..=2 {
            state.current_epoch = Epoch::new(interval * i);
            run_shuffle_step(&mut state);
        }
        let at_cap = state.pending_rotations[&shard].clone();
        assert_eq!(at_cap.len(), 2);
        let (resolving_victim, resolving) = at_cap
            .iter()
            .min_by_key(|(_, rotation)| rotation.opened_at)
            .expect("two rotations open");
        mark_ready(&mut state, resolving.entrant);

        state.current_epoch = Epoch::new(interval * 3);
        run_shuffle_step(&mut state);

        assert_eq!(
            state.pending_rotations[&shard].len(),
            3,
            "the boundary opened against a rotation that is on its way out",
        );
        // And the fold's own ordering completes the swap, so the shard
        // ends the epoch back at the cap rather than above it.
        resolve_pending_rotations(&mut state);
        let open = &state.pending_rotations[&shard];
        assert_eq!(open.len(), 2, "the resolving rotation retired this fold");
        assert!(!open.contains_key(resolving_victim));
        assert_eq!(
            state.next_shard_committees[&shard].members.len(),
            18,
            "one entrant per open rotation, above a committee at strength",
        );
        assert_eq!(
            state.ready_consensus_members(&state.next_shard_committees)[&shard].len(),
            16,
            "the consensus subset never moved",
        );
    }

    /// The consensus subset holds at `shard_size` for every fold of a
    /// rotation's window — the whole point of deferring the victim's
    /// retirement. A dip tightens `quorum_threshold` toward all-of-N and
    /// costs a view-change timeout at each end of the window.
    #[test]
    fn rotation_holds_the_consensus_subset_at_full_strength() {
        let mut state = multi_shard_state(2, 4, 2);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(shuffle_interval() - 1);

        // Two full intervals: rotations open, coast unready until the
        // ready timeout backstops them, resolve, and open again.
        for _ in 0..(2 * shuffle_interval()) {
            apply_next_epoch(&mut state, &[]);
            for (shard, members) in &state.next_shard_committees {
                assert_eq!(
                    state.ready_consensus_members(&state.next_shard_committees)[shard].len(),
                    4,
                    "consensus subset dipped at epoch {:?}",
                    state.current_epoch,
                );
                assert!(
                    members.members.len() <= 5,
                    "a rotation adds at most one member",
                );
            }
        }
    }

    /// A shard mid-split is exempt from rotation. Its members all carry
    /// over to the children as parent halves, ready by construction — the
    /// readiness the split gate trusts — so rotating one out and refilling
    /// with a not-yet-ready pool draw would seat a child below its ready
    /// quorum and wedge it. The pool has stock, so the only thing keeping
    /// the committee intact is the pending-split skip.
    #[test]
    fn shuffle_skips_a_shard_with_a_pending_split() {
        let splitting = ShardId::leaf(1, 0);
        // Two shards × 4 ready + 2 pool extras, so a rotation would have
        // stock to refill with.
        let mut state = multi_shard_state(2, 4, 2);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(shuffle_interval() - 1);
        // Arm a pending split with an empty cohort: the readiness gate
        // can't pass (no cohort seats), so the split won't execute this
        // epoch and the shard stays in the lookahead to inspect.
        state.pending_reshapes.insert(
            splitting,
            PendingReshape::Split {
                last_asserted: Epoch::new(shuffle_interval()),
                admitted_at: Epoch::new(shuffle_interval()),
                cohort: BTreeMap::new(),
                cohort_seed: state.randomness,
                scheduled: None,
            },
        );
        let before = state.next_shard_committees[&splitting].members.clone();

        apply_next_epoch(&mut state, &[]);

        // No victim rotated out, no not-yet-ready pool draw rotated in.
        assert_eq!(
            state.next_shard_committees[&splitting].members, before,
            "a shard mid-split must not rotate at the shuffle boundary",
        );
        for id in &state.next_shard_committees[&splitting].members {
            assert!(
                matches!(
                    state.validators[id].status,
                    ValidatorStatus::OnShard { shard, ready: true, .. } if shard == splitting
                ),
                "every member of a splitting shard stays a ready parent half",
            );
        }
    }

    /// On a shuffle-boundary epoch, any shard membership change is
    /// attributed to `NaturalShuffle` (the dominant cause on those
    /// epochs).
    #[test]
    fn shuffle_emits_shard_committee_transition_with_natural_shuffle_cause() {
        let mut state = single_pool_state(4);
        add_eligible_slack(&mut state);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Pool extra so the rotation swaps in a fresh validator
        // rather than just shrinking the shard.
        state.validators.insert(
            ValidatorId::new(99),
            validator_record(99, 0, ValidatorStatus::Pooled),
        );
        let pool = state.pools.get_mut(&StakePoolId::new(0)).unwrap();
        pool.validators.insert(ValidatorId::new(99));
        pool.total_stake = Stake::from_quanta(10 * MIN_STAKE_FLOOR.quanta());
        state.current_epoch = Epoch::new(shuffle_interval() - 1);

        let effects = apply_next_epoch(&mut state, &[]);
        let transition = effects
            .shard_committee_transitions
            .get(&ShardId::leaf(1, 0))
            .expect("shuffle on shard 0 emits a transition");
        assert_eq!(transition.cause, TransitionCause::NaturalShuffle);
        assert_eq!(transition.at_slot, Epoch::new(shuffle_interval()));
    }

    /// Empty epoch with no witnesses and no shuffle boundary leaves
    /// shard committees untouched and emits no transitions.
    #[test]
    fn no_membership_change_emits_no_transition() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let effects = apply_next_epoch(&mut state, &[]);
        assert!(effects.shard_committee_transitions.is_empty());
    }

    /// The lookahead committee finalized at epoch `E`
    /// (`next_shard_committees`) becomes the active committee
    /// (`shard_committees`) at epoch `E + 1` — the one-epoch promotion
    /// that lets every shard hold its committee before the window opens.
    /// Checked across a shuffle boundary so the committee provably
    /// changes between epochs; otherwise active and lookahead coincide
    /// and the promotion proves nothing.
    #[test]
    fn next_shard_committee_promotes_to_active_one_epoch_later() {
        // 2 shards × 4 ready + 2 pool extras so the shuffle swaps rather
        // than shrinks, making the lookahead differ from the active.
        let mut state = multi_shard_state(2, 4, 2);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(shuffle_interval() - 1);

        // Boundary epoch: the pipeline rotates `next_shard_committees`
        // (the lookahead governing the following window); the active
        // committee is the pre-rotation set promoted in at the top of
        // `apply_epoch`.
        apply_next_epoch(&mut state, &[]);
        let lookahead = state.next_shard_committees.clone();
        assert_ne!(
            state.shard_committees, lookahead,
            "shuffle must change the lookahead so the promotion is observable"
        );

        // The following epoch promotes that lookahead into the active slot.
        apply_next_epoch(&mut state, &[]);
        assert_eq!(
            state.shard_committees, lookahead,
            "epoch E's next_shard_committees becomes epoch E+1's shard_committees"
        );
    }

    // ─── beacon_eligible + resample_beacon_committee ─────────────────────

    /// `beacon_eligible` returns exactly the `OnShard { ready: true }`
    /// validators; `Pooled`, `Jailed`, `Revoked`, `InsufficientStake`, and
    /// not-yet-ready `OnShard` validators are all excluded.
    #[test]
    fn beacon_eligible_filters_to_on_shard_ready() {
        let shard = ShardId::leaf(1, 0);
        let mut state = empty_state();
        let ready_id = ValidatorId::new(1);
        state.validators.insert(
            ready_id,
            validator_record(
                1,
                0,
                ValidatorStatus::OnShard {
                    shard,
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
            ),
        );
        state.validators.insert(
            ValidatorId::new(2),
            validator_record(
                2,
                0,
                ValidatorStatus::OnShard {
                    shard,
                    ready: false,
                    placed_at_epoch: Epoch::GENESIS,
                },
            ),
        );
        state.validators.insert(
            ValidatorId::new(3),
            validator_record(3, 0, ValidatorStatus::Pooled),
        );
        state.validators.insert(
            ValidatorId::new(4),
            validator_record(
                4,
                0,
                ValidatorStatus::Jailed {
                    since_epoch: Epoch::GENESIS,
                    reason: JailReason::Performance,
                },
            ),
        );
        state.validators.insert(
            ValidatorId::new(5),
            validator_record(5, 0, ValidatorStatus::InsufficientStake),
        );

        assert_eq!(state.beacon_eligible(), vec![ready_id]);
    }

    /// `apply_epoch` always populates `committee_changed = true` and a
    /// `beacon_committee_transition` with `NaturalShuffle` cause anchored
    /// at the applied epoch.
    #[test]
    fn apply_epoch_populates_committee_changed_and_transition() {
        let mut state = single_pool_state(4);
        state.committee = vec![]; // start empty to make the handover visible

        let effects = apply_next_epoch(&mut state, &[]);

        assert!(effects.committee_changed);
        let transition = effects
            .beacon_committee_transition
            .expect("resample populates the transition");
        assert_eq!(transition.from, vec![]);
        assert_eq!(
            transition.to,
            (0u64..4).map(ValidatorId::new).collect::<Vec<_>>()
        );
        assert_eq!(transition.cause, TransitionCause::NaturalShuffle);
        assert_eq!(transition.at_slot, Epoch::new(1));
        // State carries the resampled committee.
        assert_eq!(state.committee, transition.to);
    }

    /// When `beacon_eligible` exceeds `BEACON_SIGNER_COUNT`, the
    /// resample returns exactly `BEACON_SIGNER_COUNT` validators, all
    /// drawn from the eligible set.
    #[test]
    fn resample_picks_subset_when_eligible_oversize() {
        // 2 shards × 4 ready actives = 8 eligible, BEACON_SIGNER_COUNT = 4.
        let mut state = multi_shard_state(2, 4, 0);
        let eligible: BTreeSet<ValidatorId> = state.beacon_eligible().into_iter().collect();
        assert!(eligible.len() > BEACON_SIGNER_COUNT);

        apply_next_epoch(&mut state, &[]);

        assert_eq!(state.committee.len(), BEACON_SIGNER_COUNT);
        for id in &state.committee {
            assert!(eligible.contains(id), "{id:?} not in eligible set");
        }
        // Sorted output (sample_committee's contract).
        let mut sorted = state.committee.clone();
        sorted.sort();
        assert_eq!(state.committee, sorted);
    }

    /// Two states with byte-identical inputs (validators, pools,
    /// randomness, `current_epoch`) produce byte-identical committees
    /// after `apply_epoch`. Pins the cross-replica determinism property
    /// the resample relies on.
    #[test]
    fn resample_is_deterministic_across_replicas() {
        let mut a = multi_shard_state(2, 4, 0);
        let mut b = multi_shard_state(2, 4, 0);
        // Same non-zero seed on both — the Fisher–Yates path activates
        // only when the eligible set exceeds `BEACON_SIGNER_COUNT`,
        // which is true here (8 > 4).
        a.randomness = Randomness::new([0x5A; 32]);
        b.randomness = Randomness::new([0x5A; 32]);

        apply_next_epoch(&mut a, &[]);
        apply_next_epoch(&mut b, &[]);

        assert_eq!(a.committee, b.committee);
        assert_eq!(a.randomness, b.randomness);
    }

    /// A validator jailed during the epoch must not appear in the
    /// resampled committee — the resample reads the post-pipeline
    /// `beacon_eligible` set.
    #[test]
    fn resample_excludes_jailed_validators() {
        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        // Pre-jail validator 0 — `beacon_eligible` excludes them on the
        // next apply.
        state
            .validators
            .get_mut(&ValidatorId::new(0))
            .unwrap()
            .status = ValidatorStatus::Jailed {
            since_epoch: Epoch::GENESIS,
            reason: JailReason::Performance,
        };
        // Drop validator 0 from the shard committee too, matching the
        // global invariant.
        state
            .next_shard_committees
            .get_mut(&ShardId::leaf(1, 0))
            .unwrap()
            .members
            .retain(|v| *v != ValidatorId::new(0));

        apply_next_epoch(&mut state, &[]);

        assert!(!state.committee.contains(&ValidatorId::new(0)));
        assert_eq!(
            state.committee,
            vec![
                ValidatorId::new(1),
                ValidatorId::new(2),
                ValidatorId::new(3),
            ]
        );
    }

    // ─── recency-weighted resample ───────────────────────────────────────

    /// After a resample, every drawn member's `last_beacon_service` is
    /// stamped to the current epoch, and members not drawn keep their
    /// prior stamp — the record the next resample down-weights against.
    #[test]
    fn resample_stamps_service_epoch_on_drawn_members() {
        let mut state = multi_shard_state(2, 8, 0);
        state.current_epoch = Epoch::new(50);
        // Pre-stamp an idle member at an old epoch to prove non-members
        // keep their stamp.
        let idle = ValidatorId::new(15);
        state.last_beacon_service.insert(idle, Epoch::new(3));

        resample_beacon_committee(
            &mut state,
            &BTreeSet::new(),
            TransitionCause::NaturalShuffle,
        );

        assert_eq!(state.committee.len(), BEACON_SIGNER_COUNT);
        for id in &state.committee {
            assert_eq!(
                state.last_beacon_service.get(id),
                Some(&Epoch::new(50)),
                "a drawn member is stamped at the current epoch",
            );
        }
        if !state.committee.contains(&idle) {
            assert_eq!(
                state.last_beacon_service.get(&idle),
                Some(&Epoch::new(3)),
                "an undrawn member keeps its prior stamp",
            );
        }
    }

    /// A member that served this epoch has weight zero and is excluded
    /// from the draw as long as enough recovered members remain to fill
    /// the committee — the rate limit that denies a grinder a repeat
    /// seat.
    #[test]
    fn recency_excludes_just_served_members() {
        let mut state = multi_shard_state(2, 8, 0);
        state.current_epoch = Epoch::new(100);
        // Four members "served" this very epoch — weight zero. The other
        // twelve are genesis-registered and long idle — full weight.
        let just_served: Vec<ValidatorId> = (0u64..4).map(ValidatorId::new).collect();
        for id in &just_served {
            state.last_beacon_service.insert(*id, Epoch::new(100));
        }

        resample_beacon_committee(
            &mut state,
            &BTreeSet::new(),
            TransitionCause::NaturalShuffle,
        );

        assert_eq!(state.committee.len(), BEACON_SIGNER_COUNT);
        for id in &just_served {
            assert!(
                !state.committee.contains(id),
                "a zero-weight just-served member must not be drawn while idle members remain",
            );
        }
    }

    /// A freshly registered validator (registration epoch = now, never
    /// served) enters at zero weight, ramping in like a just-served
    /// member — so the register-to-reset dodge buys no immediate seat.
    #[test]
    fn recency_excludes_fresh_registrants() {
        let mut state = multi_shard_state(2, 8, 0);
        state.current_epoch = Epoch::new(100);
        // Mark four members as freshly registered this epoch.
        let fresh: Vec<ValidatorId> = (0u64..4).map(ValidatorId::new).collect();
        for id in &fresh {
            state.validators.get_mut(id).unwrap().registered_at_epoch = Epoch::new(100);
        }

        resample_beacon_committee(
            &mut state,
            &BTreeSet::new(),
            TransitionCause::NaturalShuffle,
        );

        for id in &fresh {
            assert!(
                !state.committee.contains(id),
                "a fresh registrant enters at zero weight and is not drawn while idle members remain",
            );
        }
    }

    /// A member recovers its full weight once a cooldown has elapsed
    /// since it served: with only recovered members carrying weight, the
    /// draw fills from them and skips the still-cooling ones.
    #[test]
    fn recency_recovers_over_the_cooldown() {
        let mut state = multi_shard_state(2, 8, 0);
        state.current_epoch = Epoch::new(100);
        // cooldown = eligible / committee = 16 / 4 = 4. Four members
        // served five epochs ago — past the cooldown, fully recovered.
        let recovered: Vec<ValidatorId> = (0u64..4).map(ValidatorId::new).collect();
        for id in &recovered {
            state.last_beacon_service.insert(*id, Epoch::new(95));
        }
        // The other twelve served this epoch — weight zero.
        for id in (4u64..16).map(ValidatorId::new) {
            state.last_beacon_service.insert(id, Epoch::new(100));
        }

        resample_beacon_committee(
            &mut state,
            &BTreeSet::new(),
            TransitionCause::NaturalShuffle,
        );

        let drawn: BTreeSet<ValidatorId> = state.committee.iter().copied().collect();
        assert_eq!(
            drawn,
            recovered.iter().copied().collect::<BTreeSet<_>>(),
            "the committee fills from the recovered members, skipping the cooling ones",
        );
    }

    /// Two replicas with byte-identical state — including the recency map
    /// — resample byte-identical committees and stamp the same service
    /// epochs. The recency-weighted draw is a pure function of state.
    #[test]
    fn recency_resample_is_deterministic_across_replicas() {
        let build = || {
            let mut state = multi_shard_state(2, 8, 0);
            state.current_epoch = Epoch::new(100);
            state.randomness = Randomness::new([0x5A; 32]);
            for id in (0u64..6).map(ValidatorId::new) {
                state.last_beacon_service.insert(id, Epoch::new(98));
            }
            state
        };
        let mut a = build();
        let mut b = build();

        resample_beacon_committee(&mut a, &BTreeSet::new(), TransitionCause::NaturalShuffle);
        resample_beacon_committee(&mut b, &BTreeSet::new(), TransitionCause::NaturalShuffle);

        assert_eq!(a.committee, b.committee);
        assert_eq!(a.last_beacon_service, b.last_beacon_service);
    }

    /// The recency map rides validator churn deterministically: two
    /// replicas that register a new validator and then fold several
    /// epochs land on byte-identical state, recency map included. The
    /// register-to-reset dodge cannot fork consensus.
    #[test]
    fn recency_survives_registration_churn() {
        let build = || {
            let mut state = single_pool_state(4);
            state.committee = (0u64..4).map(ValidatorId::new).collect();
            state
        };
        let run = |state: &mut BeaconState| {
            // A stake deposit funds a pool, then a registration adds a
            // fresh validator id mid-run.
            apply_witness_chunk(
                state,
                0,
                vec![ShardWitnessPayload::StakeDeposit {
                    pool_id: StakePoolId::new(0),
                    amount: Stake::from_whole_tokens(1_000),
                }],
            );
            apply_witness_chunk(
                state,
                0,
                vec![ShardWitnessPayload::RegisterValidator {
                    pool_id: StakePoolId::new(0),
                    validator_id: ValidatorId::new(77),
                    pubkey: state.validators[&ValidatorId::new(0)].pubkey,
                    possession_proof: possession_proof(0, ValidatorId::new(77)),
                }],
            );
            for _ in 0..4 {
                apply_next_epoch(state, &[]);
            }
        };

        let mut a = build();
        let mut b = build();
        run(&mut a);
        run(&mut b);

        assert_eq!(a, b, "churn must leave two replicas byte-identical");
        assert_eq!(a.last_beacon_service, b.last_beacon_service);
    }

    // ─── halted-shard recovery ───────────────────────────────────────────

    /// A live boundary record the fold has observed missing for
    /// `misses` consecutive folds.
    fn live_boundary(misses: u32) -> ShardBoundary {
        ShardBoundary {
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"live")),
            height: BlockHeight::new(5),
            weighted_timestamp: WeightedTimestamp::ZERO,
            witness_leaf_count: BeaconWitnessLeafCount::ZERO,
            witness_base: BeaconWitnessLeafCount::ZERO,
            used: DeclaredWork::ZERO,
            attested_work: 0,
            substate_bytes: 0,
            last_live_epoch: Epoch::new(1),
            consecutive_misses: misses,
            terminal_epoch: None,
            handoff_complete: None,
            terminal_delivered: false,
            terminal_roots: None,
            reshape_admitted_epoch: None,
        }
    }

    /// One more miss than the halt threshold tolerates.
    fn over_threshold() -> u32 {
        u32::try_from(HALT_THRESHOLD_EPOCHS).expect("fits u32") + 1
    }

    /// A genesis-born placeholder the fold has never observed producing.
    fn never_produced_boundary(misses: u32) -> ShardBoundary {
        ShardBoundary {
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::ZERO,
            height: BlockHeight::GENESIS,
            weighted_timestamp: WeightedTimestamp::ZERO,
            witness_leaf_count: BeaconWitnessLeafCount::ZERO,
            witness_base: BeaconWitnessLeafCount::ZERO,
            used: DeclaredWork::ZERO,
            attested_work: 0,
            substate_bytes: 0,
            last_live_epoch: Epoch::GENESIS,
            consecutive_misses: misses,
            terminal_epoch: None,
            handoff_complete: None,
            terminal_delivered: false,
            terminal_roots: None,
            reshape_admitted_epoch: None,
        }
    }

    /// A halted shard's committee is re-drawn whole from the pool: the
    /// fresh members seat ready at the fold's epoch, the replaced members
    /// return to the pool, the recovery record retains them for routing,
    /// and the healthy sibling is untouched. The full swap surfaces as a
    /// committee transition for the runner.
    #[test]
    fn halted_committee_is_redrawn_whole_from_the_pool() {
        let s0 = ShardId::leaf(1, 0);
        let s1 = ShardId::leaf(1, 1);
        let mut state = multi_shard_state(2, 4, 4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(HALT_THRESHOLD_EPOCHS + 1);
        state.boundaries.insert(s0, live_boundary(over_threshold()));
        state.boundaries.insert(s1, live_boundary(0));
        let old: BTreeSet<ValidatorId> = state.next_shard_committees[&s0]
            .members
            .iter()
            .copied()
            .collect();
        let pooled: BTreeSet<ValidatorId> = state.pooled_validators().into_iter().collect();

        let effects = apply_next_epoch(&mut state, &[]);

        assert_eq!(effects.halted_shards, BTreeSet::from([s0]));
        let fresh: BTreeSet<ValidatorId> = state.next_shard_committees[&s0]
            .members
            .iter()
            .copied()
            .collect();
        assert_eq!(
            fresh, pooled,
            "the four pooled spares seat the fresh committee"
        );
        assert!(fresh.is_disjoint(&old), "the foothold is flushed");
        for id in &fresh {
            assert_eq!(
                state.validators[id].status,
                ValidatorStatus::OnShard {
                    shard: s0,
                    ready: true,
                    placed_at_epoch: state.current_epoch,
                },
            );
        }
        for id in &old {
            assert_eq!(state.validators[id].status, ValidatorStatus::Pooled);
        }
        let recovery = &state.pending_recoveries[&s0];
        assert_eq!(recovery.rotated_at, state.current_epoch);
        assert_eq!(
            recovery.retained.iter().copied().collect::<BTreeSet<_>>(),
            old,
        );
        assert_eq!(
            recovery.attested_frontier,
            BlockHeight::new(5),
            "the freeze records the last folded boundary height as the \
             frontier below which the old committee's history is legitimate",
        );
        assert_eq!(
            state.boundaries[&s0].consecutive_misses, 0,
            "the recovery resets the miss count for a fresh threshold",
        );
        // The unproven fresh committee sits out beacon eligibility until
        // the shard's first crossing clears the recovery.
        for id in &fresh {
            assert!(!state.beacon_eligible().contains(id));
        }
        assert!(effects.shard_committee_transitions.contains_key(&s0));
        assert!(!state.pending_recoveries.contains_key(&s1));
        assert!(!effects.shard_committee_transitions.contains_key(&s1));
    }

    /// A genesis-born shard that never produced has no attested anchor for
    /// a fresh committee to seat against: the redraw is skipped — no pool
    /// churn, no retention record, seated members untouched — while the
    /// halt flag keeps standing for the operator, fold after fold.
    #[test]
    fn never_produced_shard_is_flagged_but_not_redrawn() {
        let s0 = ShardId::leaf(1, 0);
        let s1 = ShardId::leaf(1, 1);
        let mut state = multi_shard_state(2, 4, 4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(HALT_THRESHOLD_EPOCHS + 1);
        state
            .boundaries
            .insert(s0, never_produced_boundary(over_threshold()));
        state.boundaries.insert(s1, live_boundary(0));
        let old: BTreeSet<ValidatorId> = state.next_shard_committees[&s0]
            .members
            .iter()
            .copied()
            .collect();

        for _ in 0..2 {
            let effects = apply_next_epoch(&mut state, &[]);
            assert_eq!(effects.halted_shards, BTreeSet::from([s0]), "flagged");
            assert_eq!(
                state.next_shard_committees[&s0]
                    .members
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>(),
                old,
                "no redraw without an attested anchor",
            );
            assert!(state.pending_recoveries.is_empty());
            assert!(!effects.shard_committee_transitions.contains_key(&s0));
            for id in &old {
                assert!(matches!(
                    state.validators[id].status,
                    ValidatorStatus::OnShard { shard, .. } if shard == s0,
                ));
            }
        }
    }

    /// A pool short of a full committee defers the recovery — a partial
    /// re-seed would reopen the incremental march — and the shard stays
    /// flagged until the pool refills, then recovers.
    #[test]
    fn recovery_defers_until_the_pool_holds_a_full_committee() {
        let s0 = ShardId::leaf(1, 0);
        let s1 = ShardId::leaf(1, 1);
        let mut state = multi_shard_state(2, 4, 2);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(HALT_THRESHOLD_EPOCHS + 1);
        state.boundaries.insert(s0, live_boundary(over_threshold()));
        state.boundaries.insert(s1, live_boundary(0));
        let old: BTreeSet<ValidatorId> = state.next_shard_committees[&s0]
            .members
            .iter()
            .copied()
            .collect();

        let effects = apply_next_epoch(&mut state, &[]);
        assert_eq!(effects.halted_shards, BTreeSet::from([s0]), "flagged");
        assert_eq!(
            state.next_shard_committees[&s0]
                .members
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            old,
            "two pooled spares cannot seat a committee of four",
        );
        assert!(state.pending_recoveries.is_empty());

        // The pool refills; the still-flagged shard recovers on the next fold.
        for i in 100..102u64 {
            state.validators.insert(
                ValidatorId::new(i),
                validator_record(i, 0, ValidatorStatus::Pooled),
            );
        }
        let effects = apply_next_epoch(&mut state, &[]);
        assert_eq!(effects.halted_shards, BTreeSet::from([s0]));
        assert!(state.pending_recoveries.contains_key(&s0));
        let fresh: BTreeSet<ValidatorId> = state.next_shard_committees[&s0]
            .members
            .iter()
            .copied()
            .collect();
        assert!(fresh.is_disjoint(&old));
    }

    /// A recovery whose fresh committee also stalls re-draws, and the
    /// successor record folds the prior retention forward: every committee
    /// that might hold the halted tip stays routable.
    #[test]
    fn stalled_recovery_folds_retention_forward() {
        let s0 = ShardId::leaf(1, 0);
        let mut state = multi_shard_state(1, 4, 4);
        state.current_epoch = Epoch::new(20);
        let old: BTreeSet<ValidatorId> = state.next_shard_committees[&s0]
            .members
            .iter()
            .copied()
            .collect();

        recover_committees(&mut state, &BTreeSet::from([s0]));
        let fresh1: BTreeSet<ValidatorId> = state.next_shard_committees[&s0]
            .members
            .iter()
            .copied()
            .collect();
        assert!(fresh1.is_disjoint(&old));

        state.current_epoch = Epoch::new(40);
        recover_committees(&mut state, &BTreeSet::from([s0]));
        let recovery = &state.pending_recoveries[&s0];
        assert_eq!(recovery.rotated_at, Epoch::new(40));
        assert_eq!(
            recovery.retained.iter().copied().collect::<BTreeSet<_>>(),
            old.union(&fresh1).copied().collect::<BTreeSet<_>>(),
        );
        assert_eq!(recovery.retained.len(), 8, "retention holds no duplicates");
    }

    /// The shard's next observed crossing completes the recovery: the
    /// retained committee is released from the routing view, and the
    /// seating epoch moves to the permanent completed record so the
    /// bridge band keeps resolving the fresh committee.
    #[test]
    fn recovery_clears_when_the_shard_commits_again() {
        use hyperscale_types::{CompletedRecovery, RecoveryCause, ShardRecovery};

        let mut state = single_pool_state(4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        let rotated_at = Epoch::GENESIS;
        state.pending_recoveries.insert(
            ShardId::leaf(1, 0),
            ShardRecovery {
                cause: RecoveryCause::Halt,
                rotated_at,
                retained: vec![ValidatorId::new(9)],
                attested_frontier: BlockHeight::GENESIS,
            },
        );

        apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(200),
                amount: Stake::from_whole_tokens(1),
            }],
        );

        assert!(state.pending_recoveries.is_empty());
        assert_eq!(
            state.completed_recoveries.get(&ShardId::leaf(1, 0)),
            Some(&CompletedRecovery {
                rotated_at,
                attested_frontier: BlockHeight::GENESIS,
            }),
        );
    }

    /// Two replicas with byte-identical state recover byte-identically —
    /// the fresh draw is seeded, not incidental.
    #[test]
    fn recovery_is_deterministic_across_replicas() {
        let s0 = ShardId::leaf(1, 0);
        let s1 = ShardId::leaf(1, 1);
        let mut a = multi_shard_state(2, 4, 4);
        let mut b = multi_shard_state(2, 4, 4);
        for state in [&mut a, &mut b] {
            state.committee = (0u64..4).map(ValidatorId::new).collect();
            state.current_epoch = Epoch::new(HALT_THRESHOLD_EPOCHS + 1);
            state.boundaries.insert(s0, live_boundary(over_threshold()));
            state.boundaries.insert(s1, live_boundary(0));
            apply_next_epoch(state, &[]);
        }
        assert_eq!(a, b);
    }

    // ─── fork-caused recovery ───────────────────────────────────────────────

    /// A fork that folds while the free pool is short of a full committee
    /// is not dropped: the durable flag survives the declined re-draw and
    /// the next pass stamps the recovery once the pool refills.
    #[test]
    fn fork_flag_defers_on_a_short_pool_and_retries_when_it_refills() {
        use hyperscale_types::RecoveryCause;

        let s0 = ShardId::leaf(1, 0);
        // One 4-member committee, no pool surplus: the re-draw must decline.
        let mut state = multi_shard_state(1, 4, 0);
        state.current_epoch = Epoch::new(10);
        state.boundaries.insert(s0, live_boundary(0));
        state.fork_flagged.insert(s0, BlockHeight::new(6));

        recover_committees(&mut state, &BTreeSet::new());
        assert!(
            state.pending_recoveries.is_empty(),
            "a short pool defers the re-draw",
        );
        assert!(
            state.fork_flagged.contains_key(&s0),
            "the flag survives the declined fold",
        );

        // The pool refills; the standing flag re-draws on the next pass.
        for i in 100..104u64 {
            state.validators.insert(
                ValidatorId::new(i),
                validator_record(i, 0, ValidatorStatus::Pooled),
            );
        }
        state.current_epoch = Epoch::new(11);
        recover_committees(&mut state, &BTreeSet::new());
        assert_eq!(state.pending_recoveries[&s0].cause, RecoveryCause::Fork);
        assert!(!state.fork_flagged.contains_key(&s0));
    }

    /// A fork-caused recovery re-draws the committee under `Fork`
    /// provenance, retains the replaced committee for routing, and fences at
    /// the last folded boundary height.
    #[test]
    fn fork_recovery_stamps_fork_cause_and_retains_committee() {
        use hyperscale_types::RecoveryCause;

        let s0 = ShardId::leaf(1, 0);
        let mut state = multi_shard_state(1, 4, 4);
        state.current_epoch = Epoch::new(10);
        state.boundaries.insert(s0, live_boundary(0));
        let old: BTreeSet<ValidatorId> = state.next_shard_committees[&s0]
            .members
            .iter()
            .copied()
            .collect();

        state.fork_flagged.insert(s0, BlockHeight::new(6));
        recover_committees(&mut state, &BTreeSet::new());

        assert!(
            !state.fork_flagged.contains_key(&s0),
            "a stamped fork recovery clears the durable flag",
        );
        let recovery = &state.pending_recoveries[&s0];
        assert_eq!(recovery.cause, RecoveryCause::Fork);
        // `live_boundary` sits at height 5 — the last folded boundary.
        assert_eq!(recovery.attested_frontier, BlockHeight::new(5));
        assert_eq!(
            recovery.retained.iter().copied().collect::<BTreeSet<_>>(),
            old,
        );
        let fresh: BTreeSet<ValidatorId> = state.next_shard_committees[&s0]
            .members
            .iter()
            .copied()
            .collect();
        assert!(fresh.is_disjoint(&old));
    }

    /// A shard that both forked and halted this pass recovers once, as a
    /// fork: the fork loop re-draws it and the halt loop skips it.
    #[test]
    fn fork_recovery_takes_precedence_over_a_simultaneous_halt() {
        use hyperscale_types::RecoveryCause;

        let s0 = ShardId::leaf(1, 0);
        let mut state = multi_shard_state(1, 4, 4);
        state.current_epoch = Epoch::new(10);
        state.boundaries.insert(s0, live_boundary(0));
        let old: BTreeSet<ValidatorId> = state.next_shard_committees[&s0]
            .members
            .iter()
            .copied()
            .collect();

        state.fork_flagged.insert(s0, BlockHeight::new(6));
        recover_committees(&mut state, &BTreeSet::from([s0]));

        assert_eq!(state.pending_recoveries[&s0].cause, RecoveryCause::Fork);
        // A single re-draw: retention holds exactly the one replaced committee.
        assert_eq!(
            state.pending_recoveries[&s0]
                .retained
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            old,
        );
    }

    /// A fork recovery that itself stalls and re-draws under a halt trigger
    /// keeps its `Fork` provenance — a proven fork is never downgraded.
    #[test]
    fn fork_cause_survives_a_stalled_halt_redraw() {
        use hyperscale_types::RecoveryCause;

        let s0 = ShardId::leaf(1, 0);
        let mut state = multi_shard_state(1, 4, 4);
        state.current_epoch = Epoch::new(10);
        state.boundaries.insert(s0, live_boundary(0));

        state.fork_flagged.insert(s0, BlockHeight::new(6));
        recover_committees(&mut state, &BTreeSet::new());
        assert_eq!(state.pending_recoveries[&s0].cause, RecoveryCause::Fork);

        // Refill the pool so the stalled recovery can re-draw again.
        for i in 100..104u64 {
            state.validators.insert(
                ValidatorId::new(i),
                validator_record(i, 0, ValidatorStatus::Pooled),
            );
        }
        state.current_epoch = Epoch::new(20);
        recover_committees(&mut state, &BTreeSet::from([s0]));
        assert_eq!(
            state.pending_recoveries[&s0].cause,
            RecoveryCause::Fork,
            "fork provenance is sticky across a stalled halt re-draw",
        );
    }

    /// Two replicas fold the same committed fork proof into byte-identical
    /// fork recoveries.
    #[test]
    fn fork_recovery_is_deterministic_across_replicas() {
        use hyperscale_types::test_utils::{TestCommittee, shard_fork_proof};
        use hyperscale_types::{BeaconProposal, RecoveryCause, VrfProof};

        let s0 = ShardId::leaf(1, 0);
        let committee = TestCommittee::new(4, 1);
        let proof = shard_fork_proof(&committee, s0, BlockHeight::new(5));
        let proposal = BeaconProposal::new(
            BTreeMap::new(),
            Vec::new(),
            std::iter::once((s0, proof)).collect(),
            Vec::new(),
            VrfProof::ZERO,
        );
        let proposals = [(ValidatorId::new(0), proposal)];

        let mut a = multi_shard_state(1, 4, 8);
        let mut b = multi_shard_state(1, 4, 8);
        for state in [&mut a, &mut b] {
            state.current_epoch = Epoch::new(10);
            state.boundaries.insert(s0, live_boundary(0));
            apply_next_epoch(state, &proposals);
        }
        assert_eq!(a, b);
        assert_eq!(a.pending_recoveries[&s0].cause, RecoveryCause::Fork);
    }
}
