//! Shuffle step, beacon-committee resample, and per-shard membership
//! diff.

use std::collections::{BTreeMap, BTreeSet};

use blake3::Hasher;
use hyperscale_types::{
    BeaconState, BlockHash, BlockHeight, CommitteeTransition, Epoch, MIN_BEACON_COMMITTEE_SIZE,
    PendingReshape, RecoveryCause, ShardCommittee, ShardId, ShardRecovery, TransitionCause,
    ValidatorId, ValidatorStatus,
};

use crate::sampling::{sample_committee, sample_committee_weighted};
use crate::state::pool::pool_draw;

/// Domain tag for the shard recovery draw seed. Distinct from
/// [`crate::sampling`]'s pool-draw tag so the full-committee re-draw
/// never shares a PRNG stream with a same-epoch pool refill on the same
/// `(randomness, epoch, shard)` input.
const DOMAIN_SHARD_RECOVERY: &[u8] = b"hyperscale-shard-recovery-v1";

/// Trickled committee rotation. When `state.current_epoch` lands on a
/// shuffle-interval boundary (and `epoch > 0`), each shard rotates one
/// of its ready `OnShard` validators back to `Pooled` and immediately
/// refills the freed slot via [`pool_draw`]. The system-wide rotation
/// rate is one validator per shard per interval, keeping per-shard
/// composition churn uniform and bounded; the interval itself derives
/// from the chain config
/// ([`BeaconChainConfig::shuffle_interval_epochs`](hyperscale_types::BeaconChainConfig::shuffle_interval_epochs)).
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
/// Ordering invariant — pinned by `shuffle_avoids_self_replacement`:
///
/// 1. Remove the victim from the shard committee.
/// 2. [`pool_draw`] to refill — the derived pool excludes the victim
///    because their status is still `OnShard` here.
/// 3. Flip the victim's status to `Pooled`.
///
/// Flipping status *after* the draw is what prevents self-replacement:
/// derivation makes "in the pool" mean "status == Pooled", so flipping
/// early would put the victim in the pool just in time for the same
/// draw to pick them. A later shard's draw in the same step may pick
/// the victim and place them on a different shard — a legitimate
/// cross-shard reassignment.
pub(super) fn run_shuffle_step(state: &mut BeaconState) {
    let epoch = state.current_epoch;
    let interval = state.chain_config.shuffle_interval_epochs();
    if epoch.inner() == 0 || !epoch.inner().is_multiple_of(interval) {
        return;
    }
    let shard_ids: Vec<ShardId> = state.next_shard_committees.keys().copied().collect();
    let mut eligible_count = state.beacon_eligible_count();
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
            .min();
        let Some((_, victim)) = victim else {
            continue;
        };
        // Rotation must never shrink a committee: with nobody `Pooled` to
        // refill the freed slot, removing the victim would permanently drop
        // the committee below `shard_size` — and below the BFT minimum at
        // small validator counts, parking the beacon on the skip path and
        // tightening the shard quorum toward all-of-N. Skip this shard's
        // rotation until the pool recovers. An earlier shard's victim in
        // the same step is already `Pooled` here, so it still backfills a
        // later shard (the legitimate cross-shard reassignment).
        if state.pooled_validators().is_empty() {
            continue;
        }
        // Rotation also thins `beacon_eligible` by one until the drawn
        // joiner's Ready folds — the victim pools, the draw seats unready.
        // At the BFT minimum that dip parks the beacon on the skip path,
        // and a skip epoch folds no Ready witness, so the dip sustains
        // itself until the ready timeout clears it. Hold rotation until
        // the eligible set has slack to give. The count is cached across
        // shards — only a completed rotation mutates eligibility — and
        // recomputed after each one.
        if eligible_count <= MIN_BEACON_COMMITTEE_SIZE {
            break;
        }

        state
            .next_shard_committees
            .get_mut(&shard)
            .expect("present")
            .members
            .retain(|v| *v != victim);
        pool_draw(state, shard);
        state
            .validators
            .get_mut(&victim)
            .expect("victim is in state.validators")
            .status = ValidatorStatus::Pooled;
        eligible_count = state.beacon_eligible_count();
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
        BEACON_SIGNER_COUNT, BeaconState, BeaconWitnessLeafCount, BlockHash, BlockHeight, Epoch,
        HALT_THRESHOLD_EPOCHS, Hash, JailReason, MIN_STAKE_FLOOR, PendingReshape, Randomness,
        ShardBoundary, ShardCommittee, ShardId, ShardWitnessPayload, Stake, StakePool, StakePoolId,
        StateRoot, TransitionCause, ValidatorId, ValidatorStatus, WeightedTimestamp,
    };

    use super::{recover_committees, resample_beacon_committee};
    use crate::state::test_fixtures::{
        apply_next_epoch, apply_witness_chunk, empty_state, possession_proof, single_pool_state,
        validator_record,
    };
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
                total_stake: Stake::from_attos(u128::from(total) * MIN_STAKE_FLOOR.attos() * 4),
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
            .total_stake = Stake::from_attos(10 * MIN_STAKE_FLOOR.attos());
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

    /// On a shuffle-interval boundary, each shard rotates one
    /// of its ready `OnShard` validators back to `Pooled` and refills
    /// the freed slot via `pool_draw`.
    #[test]
    fn shuffle_rotates_one_validator_per_shard_at_interval() {
        // 2 shards × 4 ready actives + 2 pool extras = 10 validators.
        let mut state = multi_shard_state(2, 4, 2);
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(shuffle_interval() - 1);

        let initial_shard_0 = state.next_shard_committees[&ShardId::leaf(1, 0)]
            .members
            .clone();
        let initial_shard_1 = state.next_shard_committees[&ShardId::leaf(1, 1)]
            .members
            .clone();

        apply_next_epoch(&mut state, &[]);

        let final_shard_0 = state.next_shard_committees[&ShardId::leaf(1, 0)]
            .members
            .clone();
        let final_shard_1 = state.next_shard_committees[&ShardId::leaf(1, 1)]
            .members
            .clone();

        // Capacity preserved.
        assert_eq!(final_shard_0.len(), 4);
        assert_eq!(final_shard_1.len(), 4);
        // Each shard saw at most one membership change (zero is
        // possible if a cross-shard rotation lands the same set
        // back).
        let shard_0_diff = final_shard_0
            .iter()
            .filter(|id| !initial_shard_0.contains(id))
            .count();
        let shard_1_diff = final_shard_1
            .iter()
            .filter(|id| !initial_shard_1.contains(id))
            .count();
        assert!(shard_0_diff <= 1, "shard 0 churned by {shard_0_diff}");
        assert!(shard_1_diff <= 1, "shard 1 churned by {shard_1_diff}");
        // The genesis cohorts share a placement epoch, so tenure ties
        // break by id: each shard rotates out its smallest member id.
        assert!(
            !final_shard_0.contains(&ValidatorId::new(0)),
            "shard 0 evicts its longest-tenured member",
        );
        assert!(
            !final_shard_1.contains(&ValidatorId::new(4)),
            "shard 1 evicts its longest-tenured member",
        );
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
        pool.total_stake = Stake::from_attos(10 * MIN_STAKE_FLOOR.attos());
        state.current_epoch = Epoch::new(shuffle_interval() - 1);

        let initial_members = state.next_shard_committees[&shard].members.clone();
        apply_next_epoch(&mut state, &[]);

        // Not-ready validators must still be on the shard.
        for not_ready_id in [2u64, 3] {
            assert!(
                state.next_shard_committees[&shard]
                    .members
                    .contains(&ValidatorId::new(not_ready_id)),
                "not-ready validator {not_ready_id} got shuffled out"
            );
        }
        // Exactly one of the ready members (0 or 1) was rotated out —
        // the longer-tenured 0 (equal epochs, id breaks the tie).
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

    /// The per-shard `pool_draw` must not pick the just-rotated victim
    /// and restore them. Victim flips to `Pooled` *after* the draw, so a
    /// pool holding exactly one spare must always refill with the spare —
    /// never the victim.
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
        pool.total_stake = Stake::from_attos(10 * MIN_STAKE_FLOOR.attos());
        state.current_epoch = Epoch::new(shuffle_interval() - 1);

        let initial_members = state.next_shard_committees[&shard].members.clone();
        apply_next_epoch(&mut state, &[]);

        // Capacity preserved: the spare filled the freed slot.
        let members = state.next_shard_committees[&shard].members.clone();
        assert_eq!(members.len(), 4);
        assert!(members.contains(&spare), "the lone spare must refill");
        // Exactly one original member rotated out, into the pool.
        let pool_now = state.pooled_validators();
        assert_eq!(pool_now.len(), 1);
        let victim = pool_now[0];
        assert_eq!(
            victim,
            ValidatorId::new(0),
            "tenure picks the victim: equal epochs fall to the smallest id",
        );
        assert!(initial_members.contains(&victim));
        assert!(!members.contains(&victim), "victim must not be re-drawn");
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
        pool.total_stake = Stake::from_attos(10 * MIN_STAKE_FLOOR.attos());
        state.current_epoch = Epoch::new(shuffle_interval() - 1);

        apply_next_epoch(&mut state, &[]);

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

    /// With nobody `Pooled` to refill the freed slot, the shuffle skips
    /// the shard's rotation entirely: removing a member without a
    /// replacement would permanently shrink the committee — below the
    /// BFT minimum at small validator counts.
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
        assert!(effects.shard_committee_transitions.is_empty());
    }

    /// With `beacon_eligible` at the BFT minimum, rotation is held: the
    /// victim pools and the draw seats unready, so the swap would thin
    /// the eligible set below what SPC bootstrap requires — and a skip
    /// epoch folds no Ready witness to recover it.
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
        pool.total_stake = Stake::from_attos(10 * MIN_STAKE_FLOOR.attos());
        state.current_epoch = Epoch::new(shuffle_interval() - 1);
        assert_eq!(state.beacon_eligible().len(), 4);

        let initial_members = state.next_shard_committees[&shard].members.clone();
        apply_next_epoch(&mut state, &[]);

        assert_eq!(
            state.next_shard_committees[&shard].members, initial_members,
            "rotation at the eligible floor must hold",
        );
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
        pool.total_stake = Stake::from_attos(10 * MIN_STAKE_FLOOR.attos());
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
            last_live_epoch: Epoch::new(1),
            consecutive_misses: misses,
            terminal_epoch: None,
            terminal_qc_wt: None,
            settled_waves_root: None,
            reshape_admitted_epoch: None,
            reveals_fenced_below: None,
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
            last_live_epoch: Epoch::GENESIS,
            consecutive_misses: misses,
            terminal_epoch: None,
            terminal_qc_wt: None,
            settled_waves_root: None,
            reshape_admitted_epoch: None,
            reveals_fenced_below: None,
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
