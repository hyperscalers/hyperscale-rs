//! Pending-withdrawal maturation, plus the shared
//! [`deactivate_to_insufficient_stake`] cascade primitive.

use hyperscale_types::{BeaconState, Stake, StakePoolId, ValidatorId, ValidatorStatus};

use crate::constants::UNBONDING_WINDOW_EPOCHS;
use crate::state::derived::{current_active_count, max_active_count};
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
        if let Some(committee) = state.shard_committees.get_mut(&shard) {
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
                    current_active_count(pool, state),
                    max_active_count(pool, state),
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
