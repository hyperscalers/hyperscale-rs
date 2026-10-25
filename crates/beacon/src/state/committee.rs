//! Shuffle step, beacon-committee resample, and per-shard membership
//! diff.

use std::collections::{BTreeMap, BTreeSet};

use blake3::Hasher;
use hyperscale_types::{
    BeaconState, BlockHeight, CommitteeTransition, Epoch, MIN_BEACON_COMMITTEE_SIZE,
    PendingReshape, PendingRotation, RecoveryCause, ShardCommittee, ShardId, ShardRecovery,
    TransitionCause, ValidatorId, ValidatorStatus, byzantine_threshold,
};

use crate::sampling::{sample_committee, sample_committee_weighted};
use crate::state::pool::pool_draw;

/// Domain tag for the shard recovery draw seed. Distinct from
/// [`crate::sampling`]'s pool-draw tag so the full-committee re-draw
/// never shares a PRNG stream with a same-epoch pool refill on the same
/// `(randomness, epoch, shard)` input.
const DOMAIN_SHARD_RECOVERY: &[u8] = b"hyperscale-shard-recovery-v1";

/// Domain tag for the pending-anchor observer draft seed, keeping the
/// draft's PRNG stream apart from the committee draw it tops up, which
/// reads `state.randomness` untagged.
const DOMAIN_PENDING_ANCHOR_DRAFT: &[u8] = b"hyperscale-pending-anchor-draft-v1";

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
///
/// A victim retires only from a committee that stays at `shard_size`
/// without it. A shard that lost a bystander to an empty pool sits a
/// seat short, and the readied entrant fills that seat instead: the
/// rotation closes with both members seated. Retiring the victim there
/// would hand the top-up a vacancy to fill with an unready draw — the
/// victim itself, when it is all the pool holds — trading a ready member
/// of the consensus subset for one that has yet to sync.
pub(super) fn resolve_pending_rotations(state: &mut BeaconState) {
    let shard_size = state.chain_config.shard_size as usize;
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
        let mut still_open = 0;
        if let Some(rotations) = state.pending_rotations.get_mut(&shard) {
            rotations.remove(&victim);
            still_open = rotations.len();
            if rotations.is_empty() {
                state.pending_rotations.remove(&shard);
            }
        }
        // Every rotation still open carries one spare member above the
        // shard's seats; anything at or under that is a seat the entrant
        // fills.
        if state
            .next_shard_committees
            .get(&shard)
            .is_some_and(|committee| committee.members.len() <= shard_size + still_open)
        {
            continue;
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
/// shard is the head of its [`rotation_order`](BeaconState::rotation_order), its longest-tenured
/// ready member that no merge holds and no open rotation names — the smallest
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
        let Some(&victim) = state.rotation_order(shard).first() else {
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

/// Re-draw the entire committee of every shard in
/// [`BeaconState::recovery_demand`], fork-flagged or halted, from the free
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
pub(super) fn recover_committees(state: &mut BeaconState) {
    // Fork-flagged shards re-draw first, under `Fork` provenance; a shard
    // that both forked and halted recovers once, as a fork. The flag is
    // the durable trigger: a re-draw that stamps a pending recovery
    // clears it, so a fold that declines (short pool) retries on every
    // later fold, Skip epochs included.
    let (forked, halted): (Vec<ShardId>, Vec<ShardId>) = state
        .recovery_demand(0)
        .into_iter()
        .partition(|shard| state.fork_flagged.contains_key(shard));
    for shard in forked {
        if recover_committee(state, shard, RecoveryCause::Fork) {
            state.fork_flagged.remove(&shard);
        }
    }
    for shard in halted {
        recover_committee(state, shard, RecoveryCause::Halt);
    }
}

/// Whether the re-draw stamped a pending recovery for `shard`, a member
/// of [`BeaconState::recovery_demand`]. `false` when the free pool is
/// short of a full committee, in which case the caller's trigger stays
/// armed.
fn recover_committee(
    state: &mut BeaconState,
    shard: ShardId,
    requested_cause: RecoveryCause,
) -> bool {
    let size = state.chain_config.shard_size as usize;
    // The beacon-authenticated frontier: the last boundary height folded
    // for the shard. A halted shard folds no new crossing, so this is
    // fixed for the halt's duration and equal across a stalled recovery's
    // successors. A halted shard always has a boundary record; a
    // fork-flagged shard without one falls back to the genesis frontier.
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
        .map_or_default(|committee| committee.members);
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
    state.record_recovery(shard, state.current_epoch, attested_frontier);
    true
}

/// Fill any live shard committee below `shard_size` from the pool, short of
/// the recovery reserve.
///
/// [`run_shuffle_step`] maintains a committee's size — rotate one out, draw one
/// in — but never grows it. A committee drawn short — a split cohort drawn
/// against a pool the predecessors' make-before-break coast had momentarily
/// depleted, or a split child whose half member was jailed or withdrawn since
/// the carve — would otherwise stay under `shard_size` for life, tightening
/// its quorum toward all-of-N and missing the full-strength target a grow must
/// reach. Once the pool holds members past the reserve
/// ([`BeaconState::drawable_pool_len`]), top each short committee back up; a
/// member placed here syncs in via the normal `Ready` path like any pool
/// refill. A recovery the pool cannot fund yet outranks a short committee, so
/// while the reserve is at least the pool, the backfill waits. Skips a shard
/// mid-reshape — a splitting parent's members carry to its children, a merge
/// target's are its keepers — matching the shuffle's guards.
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
            if state.drawable_pool_len(0) == 0 || pool_draw(state, shard).is_none() {
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
/// and ids are never reused. A draw short of [`MIN_BEACON_COMMITTEE_SIZE`]
/// tops up with pending-anchor observers
/// ([`draft_pending_anchor_observers`]). After the draw every seated
/// member's [`BeaconState::last_beacon_service`] is stamped to this epoch.
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
    let mut committee =
        sample_committee_weighted(&weighted, state.randomness.as_bytes(), committee_size);
    committee.extend(draft_pending_anchor_observers(
        state,
        excluded,
        committee.len(),
    ));
    committee.sort_unstable();
    state.committee = committee;
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

/// Pending-anchor observers seated to lift a proven draw of `proven`
/// members to [`MIN_BEACON_COMMITTEE_SIZE`].
///
/// Below the floor the SPC driver declines to bootstrap, every epoch
/// folds as a skip, and a skip folds no boundary QC — so a split whose
/// child anchors are still pending would never seed them, and the
/// observers they gate would never turn eligible to lift the count. The
/// observers break that cycle: each follows the beacon and can propose
/// and vote, but holds no shard headers and abstains from every proposal
/// carrying a boundary QC. Seating at most `f` of them, for the floor's
/// own `f`, leaves `n − f` synced members to carry every QC-bearing
/// proposal and fill the withholding sweep's `n − f` presence bar, so no
/// honest proposer is refused or jailed on an observer's abstention.
///
/// Empty when the proven draw already meets the floor, or when closing
/// the gap would take more than `f` observers — a committee that could
/// not carry a boundary QC could not seed the anchors either. The draw
/// is uniform under a domain-tagged seed over the fold's randomness and
/// epoch, so every replica seats the same observers; the next fold
/// redraws, so an observer gives way the moment its anchor seeds or the
/// proven set recovers.
fn draft_pending_anchor_observers(
    state: &BeaconState,
    excluded: &BTreeSet<ValidatorId>,
    proven: usize,
) -> Vec<ValidatorId> {
    let needed = MIN_BEACON_COMMITTEE_SIZE.saturating_sub(proven);
    if needed == 0 || needed > byzantine_threshold(MIN_BEACON_COMMITTEE_SIZE) {
        return Vec::new();
    }
    let observers: Vec<ValidatorId> = state
        .pending_anchor_observers()
        .into_iter()
        .filter(|id| !excluded.contains(id))
        .collect();
    let mut h = Hasher::new();
    h.update(DOMAIN_PENDING_ANCHOR_DRAFT);
    h.update(state.randomness.as_bytes());
    h.update(&state.current_epoch.inner().to_le_bytes());
    sample_committee(&observers, h.finalize().as_bytes(), needed)
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
            .map_or_default(|c| c.members.clone());
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

    use hyperscale_crypto_bls::BlsVerifier;
    use hyperscale_types::{
        Admission, BEACON_SIGNER_COUNT, BeaconState, BeaconWitnessLeafCount, BlockHash,
        BlockHeight, DeclaredWork, Epoch, HALT_THRESHOLD_EPOCHS, Hash, JailReason,
        MIN_BEACON_COMMITTEE_SIZE, MIN_STAKE_FLOOR, PendingReshape, RESHAPE_READY_TTL_EPOCHS,
        Randomness, RecoveryCause, Settling, ShardBoundary, ShardCommittee, ShardId,
        ShardWitnessPayload, Stake, StakePool, StakePoolId, StateRoot, TransitionCause,
        ValidatorId, ValidatorStatus, WeightedTimestamp, byzantine_threshold,
    };

    use super::{
        recover_committee, recover_committees, resample_beacon_committee,
        resolve_pending_rotations, run_shuffle_step,
    };
    use crate::state::reshape::schedule_ready_splits;
    use crate::state::test_fixtures::{
        apply_next_epoch, apply_witness_chunk, empty_state, live_boundary, net, possession_proof,
        single_pool_state, validator_record,
    };
    use crate::state::vrf::jail_validator;
    use crate::state::witness::apply_shard_payload;
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
                admitted: Admission::new(Epoch::GENESIS),
                cohort: BTreeMap::new(),
                cohort_seed: state.randomness,
                scheduled: None,
                quiet: false,
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

    /// A bystander lost to an empty pool leaves the shard a seat short,
    /// and the entrant fills it when it readies: the victim keeps the seat
    /// it holds. Retiring it would pool the only stock the top-up has, and
    /// the same fold would seat it straight back unready, swapping a ready
    /// member of the consensus subset for one that counts for nothing.
    #[test]
    fn a_rotation_on_a_short_committee_closes_with_the_victim_seated() {
        let shard = ShardId::leaf(1, 0);
        let mut state = multi_shard_state(2, 4, 1);
        state.current_epoch = Epoch::new(shuffle_interval());
        run_shuffle_step(&mut state);
        let (victim, entrant) = sole_rotation(&state, shard);
        let bystander = *state.next_shard_committees[&shard]
            .members
            .iter()
            .find(|id| **id != victim && **id != entrant)
            .expect("a rotating committee has bystanders");
        let epoch = state.current_epoch;
        jail_validator(&mut state, bystander, JailReason::Performance, epoch);
        assert_eq!(
            state.next_shard_committees[&shard].members.len(),
            4,
            "the pool had nothing to refill the bystander's seat with",
        );

        mark_ready(&mut state, entrant);
        state.current_epoch = Epoch::new(shuffle_interval() + 1);
        resolve_pending_rotations(&mut state);
        super::top_up_committees(&mut state);

        assert!(state.pending_rotations.is_empty(), "the rotation closed");
        let members = &state.next_shard_committees[&shard].members;
        assert_eq!(members.len(), 4);
        assert!(members.contains(&entrant));
        assert_eq!(
            state.validators[&victim].status,
            ValidatorStatus::OnShard {
                shard,
                ready: true,
                placed_at_epoch: Epoch::GENESIS,
            },
            "the victim holds its seat, ready, on the tenure it had",
        );
        assert_eq!(
            state.ready_consensus_members(&state.next_shard_committees)[&shard].len(),
            4,
            "the consensus subset is back at strength",
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
                admitted: Admission::new(Epoch::new(shuffle_interval())),
                cohort: BTreeMap::new(),
                cohort_seed: state.randomness,
                scheduled: None,
                quiet: false,
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

    // ─── pending-anchor observer draft ───────────────────────────────────

    /// A split whose children's anchors are still pending: `proven`
    /// parent halves (placed before the split, so eligible) and
    /// `observers` consumed observers (placed at the children's creation,
    /// so held out until the anchors seed), alternating across the two
    /// children. Parent halves take ids from 0, observers from 100.
    fn pending_split_state(proven: u64, observers: u64) -> BeaconState {
        let mut state = empty_state();
        state.current_epoch = Epoch::new(6);
        state.randomness = Randomness::new([0x3C; 32]);
        let created = Epoch::new(4);
        let (left, right) = ShardId::ROOT.children();
        for child in [left, right] {
            let mut pending = live_boundary(0);
            pending.block_hash = BlockHash::ZERO;
            pending.last_live_epoch = created;
            state.boundaries.insert(child, pending);
        }
        let mut seat = |id: u64, placed_at_epoch: Epoch| {
            let shard = if id.is_multiple_of(2) { left } else { right };
            state.validators.insert(
                ValidatorId::new(id),
                validator_record(
                    id,
                    0,
                    ValidatorStatus::OnShard {
                        shard,
                        ready: true,
                        placed_at_epoch,
                    },
                ),
            );
            state
                .next_shard_committees
                .entry(shard)
                .or_insert_with(|| ShardCommittee { members: vec![] })
                .members
                .push(ValidatorId::new(id));
        };
        for id in 0..proven {
            seat(id, Epoch::new(1));
        }
        for id in 100..100 + observers {
            seat(id, created);
        }
        state
    }

    fn resample(state: &mut BeaconState) {
        resample_beacon_committee(state, &BTreeSet::new(), TransitionCause::NaturalShuffle);
    }

    /// Proven members one short of the floor: the committee reaches the
    /// floor with a single pending-anchor observer, within the floor's
    /// fault bound, and keeps every proven member.
    #[test]
    fn a_short_draw_tops_up_to_the_floor_with_at_most_f_observers() {
        let mut state = pending_split_state(3, 4);
        assert_eq!(state.beacon_eligible().len(), 3);

        resample(&mut state);

        assert_eq!(state.committee.len(), MIN_BEACON_COMMITTEE_SIZE);
        let observers: BTreeSet<ValidatorId> =
            state.pending_anchor_observers().into_iter().collect();
        let drafted = state
            .committee
            .iter()
            .filter(|id| observers.contains(id))
            .count();
        assert_eq!(drafted, 1);
        assert!(drafted <= byzantine_threshold(state.committee.len()));
        for id in state.beacon_eligible() {
            assert!(state.committee.contains(&id), "{id:?} left off the draw");
        }
        let mut sorted = state.committee.clone();
        sorted.sort();
        assert_eq!(state.committee, sorted);
        // A drafted observer served, so its recency weight resets too.
        for id in &state.committee {
            assert_eq!(
                state.last_beacon_service.get(id),
                Some(&state.current_epoch)
            );
        }
    }

    /// Proven members at the floor: no observer is drafted.
    #[test]
    fn a_draw_at_the_floor_drafts_no_observer() {
        let mut state = pending_split_state(4, 4);

        resample(&mut state);

        let eligible: BTreeSet<ValidatorId> = state.beacon_eligible().into_iter().collect();
        assert_eq!(state.committee.len(), MIN_BEACON_COMMITTEE_SIZE);
        assert!(state.committee.iter().all(|id| eligible.contains(id)));
    }

    /// A gap wider than the floor's fault bound drafts nobody: a
    /// committee with more than `f` members abstaining on boundary QCs
    /// could not seed the anchors either.
    #[test]
    fn a_gap_beyond_f_drafts_no_observer() {
        let mut state = pending_split_state(2, 4);

        resample(&mut state);

        assert_eq!(
            state.committee,
            vec![ValidatorId::new(0), ValidatorId::new(1)]
        );
    }

    /// Replicas folding identical states seat identical observers.
    #[test]
    fn the_observer_draft_is_deterministic() {
        let mut a = pending_split_state(3, 6);
        let mut b = pending_split_state(3, 6);

        resample(&mut a);
        resample(&mut b);

        assert_eq!(a.committee, b.committee);
    }

    /// Once the anchors seed, the observers are proven members and the
    /// draft stands down: the next draw seats from the eligible set alone.
    #[test]
    fn drafted_observers_give_way_once_the_anchor_seeds() {
        let mut state = pending_split_state(3, 4);
        resample(&mut state);
        assert!(
            state.committee.iter().any(|id| id.inner() >= 100),
            "the short draw drafts an observer",
        );

        for boundary in state.boundaries.values_mut() {
            boundary.block_hash = BlockHash::from_raw(Hash::from_bytes(b"seeded"));
        }
        state.current_epoch = Epoch::new(7);
        resample(&mut state);

        assert!(state.pending_anchor_observers().is_empty());
        let eligible: BTreeSet<ValidatorId> = state.beacon_eligible().into_iter().collect();
        assert_eq!(eligible.len(), 7);
        assert_eq!(state.committee.len(), MIN_BEACON_COMMITTEE_SIZE);
        assert!(state.committee.iter().all(|id| eligible.contains(id)));
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
    /// One more miss than the halt threshold tolerates.
    fn over_threshold() -> u32 {
        u32::try_from(HALT_THRESHOLD_EPOCHS).expect("fits u32") + 1
    }

    /// Put `shard` past the halt threshold, seeding a live record where
    /// it has none.
    fn halt(state: &mut BeaconState, shard: ShardId) {
        state
            .boundaries
            .entry(shard)
            .or_insert_with(|| live_boundary(0))
            .consecutive_misses = over_threshold();
    }

    /// A genesis-born placeholder the fold has never observed producing.
    fn never_produced_boundary(misses: u32) -> ShardBoundary {
        ShardBoundary {
            boundary_qc: None,
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::ZERO,
            height: BlockHeight::GENESIS,
            weighted_timestamp: WeightedTimestamp::ZERO,
            witness_leaf_count: BeaconWitnessLeafCount::ZERO,
            witness_base: BeaconWitnessLeafCount::ZERO,
            used: DeclaredWork::ZERO,
            blocks: 0,
            cumulative_fees: 0,
            substate_bytes: 0,
            formed: Epoch::GENESIS,
            last_live_epoch: Epoch::GENESIS,
            consecutive_misses: misses,
            terminal_epoch: None,
            handoff_complete: None,
            terminal_delivered: false,
            terminal_settled_txs: None,
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

        halt(&mut state, s0);
        recover_committees(&mut state);
        let fresh1: BTreeSet<ValidatorId> = state.next_shard_committees[&s0]
            .members
            .iter()
            .copied()
            .collect();
        assert!(fresh1.is_disjoint(&old));

        state.current_epoch = Epoch::new(40);
        halt(&mut state, s0);
        recover_committees(&mut state);
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
    /// recovery's binding stays in the shard's history, marked completed.
    #[test]
    fn recovery_clears_when_the_shard_commits_again() {
        use hyperscale_types::{RecoveryBinding, RecoveryCause, ShardRecovery};

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
        state.record_recovery(ShardId::leaf(1, 0), rotated_at, BlockHeight::GENESIS);

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
            state.latest_completed_recovery(ShardId::leaf(1, 0)),
            Some(RecoveryBinding {
                rotated_at,
                attested_frontier: BlockHeight::GENESIS,
                completed: true,
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

        recover_committees(&mut state);
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
        recover_committees(&mut state);
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
        recover_committees(&mut state);

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
        halt(&mut state, s0);
        recover_committees(&mut state);

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
        recover_committees(&mut state);
        assert_eq!(state.pending_recoveries[&s0].cause, RecoveryCause::Fork);

        // Refill the pool so the stalled recovery can re-draw again.
        for i in 100..104u64 {
            state.validators.insert(
                ValidatorId::new(i),
                validator_record(i, 0, ValidatorStatus::Pooled),
            );
        }
        state.current_epoch = Epoch::new(20);
        halt(&mut state, s0);
        recover_committees(&mut state);
        assert_eq!(
            state.pending_recoveries[&s0].cause,
            RecoveryCause::Fork,
            "fork provenance is sticky across a stalled halt re-draw",
        );
    }

    /// Two live leaves beside the standing terminal records of
    /// `leaf(1, 0)`'s children, whose chains ended at the merge that
    /// reformed it. Returns the state and the left child.
    fn beside_departed_children() -> (BeaconState, ShardId) {
        let reformed = ShardId::leaf(1, 0);
        let (departed, sibling) = reformed.children();
        let mut state = multi_shard_state(2, 4, 4);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(10);
        for leaf in [reformed, ShardId::leaf(1, 1)] {
            state.boundaries.insert(leaf, live_boundary(0));
        }
        for child in [departed, sibling] {
            state.boundaries.insert(
                child,
                ShardBoundary {
                    terminal_epoch: Some(Epoch::new(8)),
                    handoff_complete: Some(Epoch::new(9)),
                    ..live_boundary(0)
                },
            );
        }
        (state, departed)
    }

    /// Whether no shard `committees` seats covers another's range.
    fn seats_no_overlap(committees: &BTreeMap<ShardId, ShardCommittee>) -> bool {
        committees.keys().all(|leaf| {
            std::iter::successors(leaf.parent(), |above| above.parent())
                .all(|above| !committees.contains_key(&above))
        })
    }

    /// A fork flag on a shard the lookahead does not seat re-draws no
    /// committee. The shard has left the trie and a live leaf covers its
    /// range, so seating it would publish a trie holding both. The fold
    /// drops the flag, draws nothing from the pool and stamps no
    /// recovery.
    #[test]
    fn a_fork_flag_on_a_departed_shard_seats_no_committee() {
        let (mut state, departed) = beside_departed_children();
        let seated = state.next_shard_committees.clone();
        let pooled = state.pooled_validators();
        state.fork_flagged.insert(departed, BlockHeight::new(6));

        apply_next_epoch(&mut state, &[]);

        assert!(state.terminal_record_stands(departed));
        assert!(!state.next_shard_committees.contains_key(&departed));
        assert!(seats_no_overlap(&state.next_shard_committees));
        assert_eq!(state.next_shard_committees, seated);
        assert_eq!(state.pooled_validators(), pooled);
        assert!(!state.fork_flagged.contains_key(&departed));
        assert!(!state.pending_recoveries.contains_key(&departed));
        let published = state.derive_next_topology_snapshot(net());
        assert!(!published.shard_trie().contains(departed));
        assert!(published.shard_trie().contains(ShardId::leaf(1, 0)));
    }

    // ─── recovery demand ───────────────────────────────────────────────

    /// A recovery that stalled past a further halt threshold is in demand
    /// beside its pending record: the record is the stalled recovery, not
    /// a reason to stop reserving for it.
    #[test]
    fn a_restalled_recovery_is_in_demand() {
        let s0 = ShardId::leaf(1, 0);
        let mut state = multi_shard_state(1, 4, 8);
        state.current_epoch = Epoch::new(10);
        halt(&mut state, s0);
        recover_committees(&mut state);
        assert!(state.pending_recoveries.contains_key(&s0));
        assert!(state.recovery_demand(0).is_empty());

        halt(&mut state, s0);
        assert_eq!(state.recovery_demand(0), BTreeSet::from([s0]));
        assert_eq!(
            state.drawable_pool_len(0),
            state.pooled_validators().len() - 4
        );
    }

    /// A seated fork-flagged shard is in demand though the fork fence
    /// keeps it out of the halted set.
    #[test]
    fn a_fork_flagged_sibling_is_in_demand() {
        let (s0, s1) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
        let mut state = multi_shard_state(2, 4, 4);
        for shard in [s0, s1] {
            state.boundaries.insert(shard, live_boundary(0));
        }
        state.fork_flagged.insert(s1, BlockHeight::new(3));

        assert!(state.halted_shards().is_empty());
        assert_eq!(state.recovery_demand(0), BTreeSet::from([s1]));
        assert_eq!(state.drawable_pool_len(0), 0);
    }

    /// A genesis shard that never produced is halted but not in demand: no
    /// recovery can seat against it, so it reserves nothing from the pool.
    #[test]
    fn a_never_produced_genesis_shard_reserves_nothing() {
        let (s0, s1) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
        let mut state = multi_shard_state(2, 4, 4);
        state
            .boundaries
            .insert(s0, never_produced_boundary(over_threshold()));
        state.boundaries.insert(s1, live_boundary(0));

        assert_eq!(state.halted_shards(), BTreeSet::from([s0]));
        assert!(state.recovery_demand(1).is_empty());
        assert_eq!(state.drawable_pool_len(1), 4);
    }

    /// A split cancelled at its readiness deadline returns its cohort in
    /// the prune, and the recovery draws it ahead of the shuffle: the
    /// halted sibling is re-drawn from the returned cohort, and the
    /// shuffle still opens its rotation from what the recovery returned.
    #[test]
    fn a_cancelled_cohort_reaches_the_recovery_before_the_shuffle() {
        let (halted, target) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
        let mut state = multi_shard_state(2, 4, 5);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.shard_committees = state.next_shard_committees.clone();
        add_eligible_slack(&mut state);
        for shard in [halted, target] {
            state.boundaries.insert(shard, live_boundary(0));
        }
        let interval = shuffle_interval();
        let fold = interval * (RESHAPE_READY_TTL_EPOCHS / interval + 1);
        state.current_epoch = Epoch::new(fold - RESHAPE_READY_TTL_EPOCHS);
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            target,
            &ShardWitnessPayload::ScheduleSplit {
                shard: target,
                epoch: Epoch::GENESIS,
                settling: None,
            },
        );
        let Some(PendingReshape::Split { cohort, .. }) = state.pending_reshapes.get(&target) else {
            panic!("the split is admitted");
        };
        let mut returned: BTreeSet<ValidatorId> = cohort.keys().copied().collect();
        returned.extend(state.pooled_validators());
        assert_eq!(state.pooled_validators().len(), 1);

        halt(&mut state, halted);
        state.current_epoch = Epoch::new(fold - 1);
        apply_next_epoch(&mut state, &[]);

        assert!(!state.pending_reshapes.contains_key(&target), "cancelled");
        let recovery = &state.pending_recoveries[&halted];
        assert_eq!(recovery.rotated_at, Epoch::new(fold));
        assert!(
            state.next_shard_committees[&halted]
                .members
                .iter()
                .all(|id| returned.contains(id)),
            "the fresh committee is drawn from the returned cohort",
        );
        let (_, entrant) = sole_rotation(&state, target);
        assert!(
            state.next_shard_committees[&target]
                .members
                .contains(&entrant)
        );
    }

    /// A split whose target never says it is quiet is cancelled at its
    /// drain deadline, and the same fold's recovery draws the returned
    /// cohort for the halted sibling the target's rows wait on.
    #[test]
    fn an_unquiet_split_is_cancelled_and_its_cohort_drawn_by_the_recovery() {
        let (halted, target) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
        let mut state = multi_shard_state(2, 4, 5);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.shard_committees = state.next_shard_committees.clone();
        add_eligible_slack(&mut state);
        for shard in [halted, target] {
            state.boundaries.insert(shard, live_boundary(0));
        }
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            target,
            &ShardWitnessPayload::ScheduleSplit {
                shard: target,
                epoch: Epoch::GENESIS,
                settling: None,
            },
        );
        let Some(PendingReshape::Split { cohort, .. }) = state.pending_reshapes.get(&target) else {
            panic!("the split is admitted");
        };
        let seats: Vec<(ValidatorId, ShardId)> =
            cohort.iter().map(|(id, seat)| (*id, seat.child)).collect();
        let mut returned: BTreeSet<ValidatorId> = seats.iter().map(|(id, _)| *id).collect();
        returned.extend(state.pooled_validators());
        for (validator, child) in seats {
            apply_shard_payload(
                &BlsVerifier,
                &mut state,
                &net(),
                target,
                &ShardWitnessPayload::ReshapeReady { validator, child },
            );
        }
        schedule_ready_splits(&mut state);
        let Some(PendingReshape::Split { admitted, .. }) = state.pending_reshapes.get(&target)
        else {
            panic!("the split stands");
        };
        let (at, drain_by) = (admitted.at, admitted.drain_by.expect("the gate latched"));

        halt(&mut state, halted);
        state.current_epoch = Epoch::new(drain_by.inner() - 1);
        apply_shard_payload(
            &BlsVerifier,
            &mut state,
            &net(),
            target,
            &ShardWitnessPayload::ScheduleSplit {
                shard: target,
                epoch: Epoch::new(drain_by.inner() - 1),
                settling: Some(Settling {
                    admitted: at,
                    quiet: false,
                }),
            },
        );
        apply_next_epoch(&mut state, &[]);

        assert_eq!(state.current_epoch, drain_by);
        assert!(!state.pending_reshapes.contains_key(&target), "cancelled");
        assert_eq!(
            state.boundaries[&target].terminal_epoch, None,
            "nothing cut"
        );
        assert_eq!(state.pending_recoveries[&halted].rotated_at, drain_by);
        assert!(
            state.next_shard_committees[&halted]
                .members
                .iter()
                .all(|id| returned.contains(id)),
            "the fresh committee is drawn from the returned cohort",
        );
    }

    /// A halted shard the pool cannot fund leaves rotation running on its
    /// siblings: the shuffle's entrant is not gated on the reserve.
    #[test]
    fn a_halted_shard_the_pool_cannot_fund_does_not_stop_rotation() {
        let (halted, live) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
        let mut state = multi_shard_state(2, 4, 2);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state
            .boundaries
            .insert(halted, live_boundary(over_threshold()));
        state.boundaries.insert(live, live_boundary(0));
        state.current_epoch = Epoch::new(shuffle_interval() - 1);

        apply_next_epoch(&mut state, &[]);

        assert!(state.recovery_demand(0).contains(&halted));
        assert!(!state.pending_recoveries.contains_key(&halted));
        let (_, entrant) = sole_rotation(&state, live);
        assert!(
            state.next_shard_committees[&live]
                .members
                .contains(&entrant)
        );
    }

    /// A shard the lookahead does not seat is never in recovery demand,
    /// whichever trigger names it, so the recovery draws nothing for it.
    #[test]
    fn a_shard_the_lookahead_does_not_seat_is_not_in_demand() {
        let (mut state, departed) = beside_departed_children();
        state.fork_flagged.insert(departed, BlockHeight::new(6));
        halt(&mut state, departed);
        state
            .boundaries
            .get_mut(&departed)
            .expect("seeded")
            .terminal_epoch = None;
        assert!(!state.recovery_demand(0).contains(&departed));
        let before = state.clone();
        recover_committees(&mut state);
        assert_eq!(state, before);
    }

    /// A recovery that stalls and is re-drawn keeps its binding beside its
    /// successor's, oldest first: the fresh committee it seated certified
    /// blocks that still resolve through it. Neither crossed, so neither
    /// is completed.
    #[test]
    fn a_chained_recovery_keeps_both_bindings() {
        let s0 = ShardId::leaf(1, 0);
        let mut state = multi_shard_state(1, 4, 8);
        state.current_epoch = Epoch::new(10);
        state.boundaries.insert(s0, live_boundary(0));
        halt(&mut state, s0);
        recover_committees(&mut state);
        state.current_epoch = Epoch::new(20);
        halt(&mut state, s0);
        recover_committees(&mut state);

        let history: Vec<_> = state.recoveries[&s0]
            .iter()
            .map(|binding| (binding.rotated_at, binding.completed))
            .collect();
        assert_eq!(
            history,
            vec![(Epoch::new(10), false), (Epoch::new(20), false)]
        );
        assert_eq!(state.latest_completed_recovery(s0), None);
    }

    /// The fold stamps a second recovery over a first whose fresh
    /// committee's crossing never folded: the first stamping resets the
    /// miss count, more than the halt threshold of folds without a
    /// crossing re-flags the shard, and the second recovery keeps the
    /// first's frontier, since no record moved between them.
    #[test]
    fn a_second_recovery_is_stamped_while_the_first_committee_never_folded() {
        let s0 = ShardId::leaf(1, 0);
        let mut state = multi_shard_state(1, 4, 8);
        state.committee = (4u64..8).map(ValidatorId::new).collect();
        let over = u32::try_from(HALT_THRESHOLD_EPOCHS).expect("fits u32") + 1;
        state.boundaries.insert(s0, live_boundary(over));

        apply_next_epoch(&mut state, &[]);
        let first = state.pending_recoveries[&s0].clone();
        assert_eq!(first.attested_frontier, BlockHeight::new(5));
        assert_eq!(state.boundaries[&s0].consecutive_misses, 0);

        for _ in 0..HALT_THRESHOLD_EPOCHS {
            apply_next_epoch(&mut state, &[]);
            assert_eq!(state.pending_recoveries[&s0].rotated_at, first.rotated_at);
        }
        apply_next_epoch(&mut state, &[]);
        let second = &state.pending_recoveries[&s0];
        assert_eq!(
            second.rotated_at.inner(),
            first.rotated_at.inner() + HALT_THRESHOLD_EPOCHS + 1,
        );
        assert_eq!(second.attested_frontier, first.attested_frontier);
        let history: Vec<_> = state.recoveries[&s0]
            .iter()
            .map(|binding| (binding.rotated_at, binding.completed))
            .collect();
        assert_eq!(
            history,
            vec![(first.rotated_at, false), (second.rotated_at, false)]
        );
    }

    /// The history keeps the newest [`RECOVERY_HISTORY_DEPTH`] bindings of
    /// a shard, and completing one marks only that one.
    #[test]
    fn the_recovery_history_keeps_the_newest_bindings() {
        use hyperscale_types::RECOVERY_HISTORY_DEPTH;

        let s0 = ShardId::leaf(1, 0);
        let mut state = single_pool_state(4);
        let depth = u64::try_from(RECOVERY_HISTORY_DEPTH).expect("depth fits u64");
        for epoch in 0..=depth {
            state.record_recovery(s0, Epoch::new(epoch), BlockHeight::new(epoch));
        }
        let kept: Vec<_> = state.recoveries[&s0]
            .iter()
            .map(|binding| binding.rotated_at.inner())
            .collect();
        assert_eq!(kept, (1..=depth).collect::<Vec<_>>());

        state.complete_recovery(s0, Epoch::new(2));
        assert_eq!(
            state
                .latest_completed_recovery(s0)
                .map(|binding| binding.rotated_at),
            Some(Epoch::new(2)),
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
