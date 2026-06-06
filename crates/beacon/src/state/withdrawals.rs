//! Pending-withdrawal maturation, plus the shared
//! [`deactivate_to_insufficient_stake`] cascade primitive.

use hyperscale_types::{
    BeaconState, Stake, StakePoolId, UNBONDING_WINDOW_EPOCHS, ValidatorId, ValidatorStatus,
};

use crate::state::pool::pool_draw;

/// Transition `victim_id` to `InsufficientStake` with the standard
/// `OnShard` cascade (remove from shard committee + `pool_draw`
/// refill). Other statuses (`Pooled`, fault-cause `Jailed`) flip in
/// place. Already-`InsufficientStake` and already-permanent
/// `Jailed { Equivocation }` callers should not invoke this — there's
/// no transition to make. Callers gate on those cases at the variant
/// dispatch level (see `DeactivateValidator`).
pub(super) fn deactivate_to_insufficient_stake(state: &mut BeaconState, victim_id: ValidatorId) {
    let Some(rec) = state.validators.get_mut(&victim_id) else {
        return;
    };
    let prior_status = rec.status;
    rec.status = ValidatorStatus::InsufficientStake;
    if let ValidatorStatus::OnShard { shard, .. } = prior_status {
        if let Some(committee) = state.next_shard_committees.get_mut(&shard) {
            committee.members.retain(|v| *v != victim_id);
        }
        pool_draw(state, shard);
    }
    // Miss counters are scoped to the validator's current `OnShard`
    // placement; any transition out clears them.
    state.miss_counters.remove(&victim_id);
}

/// Outcome of [`complete_pending_withdrawals`].
#[derive(Default)]
pub(super) struct WithdrawalOutcome {
    /// Validators auto-deactivated to `InsufficientStake` because
    /// their pool's released amount left it over `max_active_count`.
    /// Listed in deactivation order: per-pool by `StakePoolId`
    /// ascending, then highest-`ValidatorId` first within each pool.
    pub(super) deactivated: Vec<ValidatorId>,
}

/// Mature any [`PendingWithdrawal`](hyperscale_types::PendingWithdrawal)
/// whose unbonding window has elapsed
/// (`current_epoch − initiated_at_epoch ≥ UNBONDING_WINDOW_EPOCHS`),
/// subtract the released amount from each affected pool's
/// `total_stake`, and auto-deactivate the pool's highest-id active
/// validators if the release leaves
/// `current_active_count > max_active_count` at the resulting dynamic
/// `min_stake`.
///
/// Per-pool batching: all matured withdrawals on a pool release
/// together. The cumulative `effective_stake` after batch release is
/// identical to processing them one-by-one, and batch avoids
/// spurious intermediate `min_stake` evaluations.
///
/// Cross-pool side effect: this pool's deactivations can raise
/// network-wide `min_stake` (the deactivating pool's `e/k` rises as
/// `k` drops), which in turn lowers every pool's `max_active_count`.
/// Other pools may end up temporarily over-committed as a result.
/// The design explicitly forbids retroactive ejections from a rising
/// `min_stake`; those pools stay over-committed until their own
/// withdrawal or operator action reconciles them.
///
/// Termination: each iteration of the inner loop strictly decreases
/// `current_active_count(pool)` by 1 (the victim flips from
/// `Pooled|OnShard` to `InsufficientStake`; the refill `pool_draw`
/// inside `deactivate_to_insufficient_stake` runs `Pooled → OnShard`
/// and both statuses count). The loop terminates in at most `cur`
/// iterations per over-committed pool.
pub(super) fn complete_pending_withdrawals(state: &mut BeaconState) -> WithdrawalOutcome {
    let mut outcome = WithdrawalOutcome::default();
    let current_epoch = state.current_epoch.inner();
    let pool_ids: Vec<StakePoolId> = state.pools.keys().copied().collect();
    for pool_id in pool_ids {
        let released = {
            let pool = state.pools.get_mut(&pool_id).expect("just iterated");
            let mut sum = Stake::ZERO;
            pool.pending_withdrawals.retain(|w| {
                if current_epoch.saturating_sub(w.initiated_at_epoch.inner())
                    >= UNBONDING_WINDOW_EPOCHS
                {
                    sum = sum.saturating_add(w.amount);
                    false
                } else {
                    true
                }
            });
            sum
        };
        if released == Stake::ZERO {
            continue;
        }
        {
            let pool = state.pools.get_mut(&pool_id).expect("present");
            pool.total_stake = pool.total_stake.saturating_sub(released);
        }
        // Auto-deactivate highest-id active validators until balanced.
        // `min_stake` is re-evaluated each iteration because dropping
        // this pool's active count by 1 raises its `e/k` contribution
        // to `t_no_eject`, weakly raising `min_stake` and weakly
        // shrinking `max_active_count`. The loop only shrinks the
        // budget — never grows it.
        loop {
            let (cur, max) = {
                let pool = state.pools.get(&pool_id).expect("present");
                (
                    pool.current_active_count(state),
                    pool.max_active_count(state),
                )
            };
            if cur <= max {
                break;
            }
            let victim = {
                let pool = state.pools.get(&pool_id).expect("present");
                pool.validators
                    .iter()
                    .rev()
                    .find(|id| {
                        matches!(
                            state.validators.get(id).map(|r| &r.status),
                            Some(ValidatorStatus::Pooled | ValidatorStatus::OnShard { .. })
                        )
                    })
                    .copied()
            };
            let Some(victim_id) = victim else {
                break;
            };
            deactivate_to_insufficient_stake(state, victim_id);
            outcome.deactivated.push(victim_id);
        }
    }
    outcome
}

#[cfg(test)]
mod tests {

    use hyperscale_types::{
        EMISSIONS_PER_EPOCH, Epoch, MIN_STAKE_FLOOR, PendingWithdrawal, ShardId, Stake,
        StakePoolId, UNBONDING_WINDOW_EPOCHS, ValidatorId, ValidatorStatus,
    };

    use super::super::test_fixtures::{apply_next_epoch, state_with_pending_withdrawal};
    // ─── complete_pending_withdrawals ────────────────────────────────────

    /// A withdrawal still within the unbonding window stays pending —
    /// `total_stake` unchanged, no deactivation.
    #[test]
    fn unmatured_withdrawal_stays_pending() {
        let initiated = Epoch::new(2);
        // current_epoch two short of maturity — apply_next_epoch
        // advances by 1 and the check runs at the still-unmature value.
        let current = Epoch::new(initiated.inner() + UNBONDING_WINDOW_EPOCHS - 2);
        let mut state = state_with_pending_withdrawal(
            4,
            Stake::from_attos(4 * MIN_STAKE_FLOOR.attos()),
            Stake::from_whole_tokens(100),
            initiated,
            current,
        );
        let pre_total = state.pools[&StakePoolId::new(0)].total_stake;

        let effects = apply_next_epoch(&mut state, &[]);

        assert!(effects.deactivated.is_empty());
        let pool = &state.pools[&StakePoolId::new(0)];
        // Unmatured withdrawal leaves total_stake alone; the only
        // delta is the epoch emission credit.
        assert_eq!(
            pool.total_stake,
            pre_total.saturating_add(EMISSIONS_PER_EPOCH)
        );
        assert_eq!(pool.pending_withdrawals.len(), 1);
    }

    /// A withdrawal whose unbonding window has elapsed releases its
    /// amount from `total_stake` and clears the `pending_withdrawals`
    /// entry. With no over-commitment, no auto-deactivation.
    #[test]
    fn matured_withdrawal_releases_amount_without_deactivation() {
        let initiated = Epoch::new(2);
        let current = Epoch::new(initiated.inner() + UNBONDING_WINDOW_EPOCHS);
        // Pool over-staked relative to the active set — even after a
        // small release, capacity comfortably covers the actives.
        let mut state = state_with_pending_withdrawal(
            4,
            Stake::from_attos(100 * MIN_STAKE_FLOOR.attos()),
            MIN_STAKE_FLOOR, // small release
            initiated,
            current,
        );

        let effects = apply_next_epoch(&mut state, &[]);

        assert!(effects.deactivated.is_empty());
        let pool = &state.pools[&StakePoolId::new(0)];
        // 99 × FLOOR after release, plus the epoch emission credit.
        assert_eq!(
            pool.total_stake,
            Stake::from_attos(100 * MIN_STAKE_FLOOR.attos() - MIN_STAKE_FLOOR.attos())
                .saturating_add(EMISSIONS_PER_EPOCH),
        );
        assert!(pool.pending_withdrawals.is_empty());
    }

    /// Multiple matured withdrawals release in a single batch — sum
    /// hits `total_stake` once, all matured entries drop from the
    /// pending list.
    #[test]
    fn multiple_matured_withdrawals_batch() {
        let initiated_a = Epoch::new(2);
        let initiated_b = Epoch::new(3);
        // Set `current` one epoch before maturity so apply_next_epoch's
        // advance lands exactly at the maturity boundary for `initiated_b`.
        let current = Epoch::new(initiated_b.inner() + UNBONDING_WINDOW_EPOCHS - 1);
        let mut state = state_with_pending_withdrawal(
            4,
            Stake::from_attos(100 * MIN_STAKE_FLOOR.attos()),
            MIN_STAKE_FLOOR, // first one already in the fixture
            initiated_a,
            current,
        );
        // Add a second matured + a third unmatured.
        let pool = state.pools.get_mut(&StakePoolId::new(0)).unwrap();
        pool.pending_withdrawals.push(PendingWithdrawal {
            amount: Stake::from_attos(2 * MIN_STAKE_FLOOR.attos()),
            initiated_at_epoch: initiated_b,
        });
        // still-pending withdrawal initiated late enough that
        // post-apply current_epoch - still_pending < WINDOW.
        let still_pending_epoch =
            Epoch::new(current.inner().saturating_sub(UNBONDING_WINDOW_EPOCHS - 2));
        pool.pending_withdrawals.push(PendingWithdrawal {
            amount: Stake::from_whole_tokens(7),
            initiated_at_epoch: still_pending_epoch,
        });

        let pre_total = state.pools[&StakePoolId::new(0)].total_stake;

        apply_next_epoch(&mut state, &[]);

        let pool = &state.pools[&StakePoolId::new(0)];
        // Released = MIN_STAKE_FLOOR + 2 * MIN_STAKE_FLOOR; epoch
        // emission credit goes back on top.
        assert_eq!(
            pool.total_stake,
            pre_total
                .saturating_sub(Stake::from_attos(3 * MIN_STAKE_FLOOR.attos()))
                .saturating_add(EMISSIONS_PER_EPOCH),
        );
        // One pending entry remains.
        assert_eq!(pool.pending_withdrawals.len(), 1);
        assert_eq!(
            pool.pending_withdrawals[0].initiated_at_epoch,
            still_pending_epoch,
        );
    }

    /// Release that over-commits the pool deactivates the highest-id
    /// active validator (here 4 validators, stake drops to support
    /// 3 → validator 3 flips to `InsufficientStake`).
    #[test]
    fn matured_withdrawal_overcommits_deactivates_highest_id() {
        let initiated = Epoch::new(2);
        let current = Epoch::new(initiated.inner() + UNBONDING_WINDOW_EPOCHS);
        // Pool stake exactly covers 4 actives; release MIN_STAKE_FLOOR
        // leaves capacity for 3.
        let mut state = state_with_pending_withdrawal(
            4,
            Stake::from_attos(4 * MIN_STAKE_FLOOR.attos()),
            MIN_STAKE_FLOOR,
            initiated,
            current,
        );

        let effects = apply_next_epoch(&mut state, &[]);

        assert_eq!(effects.deactivated, vec![ValidatorId::new(3)]);
        // Validator 3 transitioned to InsufficientStake.
        assert_eq!(
            state.validators.get(&ValidatorId::new(3)).unwrap().status,
            ValidatorStatus::InsufficientStake,
        );
        // Shard committee shrank (the only pool has no Pooled validators
        // to refill from, so `pool_draw` returns None and the committee
        // stays at 3).
        let members = &state.next_shard_committees[&ShardId::leaf(1, 0)].members;
        assert_eq!(members.len(), 3);
        assert!(!members.contains(&ValidatorId::new(3)));
    }

    /// A release that requires multiple deactivations runs the loop
    /// to fixed point — validators flip highest-id first until
    /// `current_active_count ≤ max_active_count`.
    #[test]
    fn over_commitment_loop_runs_to_fixed_point() {
        let initiated = Epoch::new(2);
        let current = Epoch::new(initiated.inner() + UNBONDING_WINDOW_EPOCHS);
        // Start with 4 actives at exactly 4 * MIN_STAKE_FLOOR. Release
        // 3 * MIN_STAKE_FLOOR — only 1 active can be supported.
        let mut state = state_with_pending_withdrawal(
            4,
            Stake::from_attos(4 * MIN_STAKE_FLOOR.attos()),
            Stake::from_attos(3 * MIN_STAKE_FLOOR.attos()),
            initiated,
            current,
        );

        let effects = apply_next_epoch(&mut state, &[]);

        // 3 highest-id validators flipped to InsufficientStake.
        assert_eq!(
            effects.deactivated,
            vec![
                ValidatorId::new(3),
                ValidatorId::new(2),
                ValidatorId::new(1),
            ],
        );
        for id in [3u64, 2, 1].map(ValidatorId::new) {
            assert_eq!(
                state.validators.get(&id).unwrap().status,
                ValidatorStatus::InsufficientStake,
            );
        }
        // Validator 0 still OnShard.
        assert!(matches!(
            state.validators.get(&ValidatorId::new(0)).unwrap().status,
            ValidatorStatus::OnShard { .. },
        ));
    }
}
