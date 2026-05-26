//! Per-epoch lifecycle steps: auto-reactivation, reward distribution,
//! auto-ready timeout.

use std::collections::BTreeMap;

use hyperscale_types::{BeaconState, Stake, StakePoolId, ValidatorId, ValidatorStatus};

use crate::constants::{EMISSIONS_PER_EPOCH, READY_TIMEOUT_EPOCHS};
use crate::state::derived::{current_active_count, max_active_count};

/// Promote `InsufficientStake` validators back to `Pooled` for every
/// pool that has newly-available capacity, looping until no pool can
/// reactivate further.
///
/// Capacity becomes available when a `StakeDeposit` arrives or when
/// any pool's reactivation lowers network-wide `min_stake` (each
/// reactivation drops the pool's contribution to `t_no_eject` from
/// `e/cur` to `e/(cur + 1)`, weakly smaller). The downstream effect
/// is that every pool's `max_active_count` is weakly non-decreasing
/// through the loop, so reactivation in pool A can unlock further
/// reactivations in pool B.
///
/// Per-iteration progress: each successful flip removes one validator
/// from the `InsufficientStake` set, which monotonically shrinks
/// since the only way to *enter* `InsufficientStake` is via
/// withdrawal completion or an explicit deactivation — neither of
/// which runs inside this loop. The loop terminates in O(N²) at
/// worst, in practice O(N).
///
/// The "doesn't immediately re-promote a just-deactivated validator"
/// property is provided by the gate: the pool that triggered the
/// deactivation in
/// [`complete_pending_withdrawals`](super::withdrawals::complete_pending_withdrawals)
/// now has `cur >= max` (the deactivation was *because* of
/// over-commitment), so this loop skips it.
pub(super) fn auto_reactivate(state: &mut BeaconState) -> Vec<ValidatorId> {
    let mut reactivated = Vec::new();
    loop {
        let mut did_any = false;
        let pool_ids: Vec<StakePoolId> = state.pools.keys().copied().collect();
        for pool_id in pool_ids {
            let (cur, max) = {
                let pool = state.pools.get(&pool_id).expect("just iterated");
                (
                    current_active_count(pool, state),
                    max_active_count(pool, state),
                )
            };
            if cur >= max {
                continue;
            }
            let candidate = {
                let pool = state.pools.get(&pool_id).expect("present");
                pool.validators
                    .iter()
                    .rev()
                    .find(|id| {
                        matches!(
                            state.validators.get(id).map(|r| &r.status),
                            Some(ValidatorStatus::InsufficientStake),
                        )
                    })
                    .copied()
            };
            let Some(rev_id) = candidate else {
                continue;
            };
            state
                .validators
                .get_mut(&rev_id)
                .expect("just found via the pool's validator set")
                .status = ValidatorStatus::Pooled;
            reactivated.push(rev_id);
            did_any = true;
        }
        if !did_any {
            break;
        }
    }
    reactivated
}

/// Credit one epoch's emissions across stake pools pro-rata to each
/// pool's count of `OnShard { ready: true }` validators.
///
/// Pure deterministic function of `(state)`. Returns the per-pool
/// credits actually applied; zero-share pools are omitted.
///
/// Integer-division rounding remainder is burned — the per-year
/// emission envelope
/// ([`TOKENS_PER_YEAR_TARGET`](crate::constants::TOKENS_PER_YEAR_TARGET))
/// is a sizing target, not a hard cap, so the per-epoch remainder
/// (at most `active_pools − 1` attos) drops on the floor rather than
/// accumulating in state.
/// Epochs where no pool has a ready `OnShard` validator return an
/// empty map without crediting — the whole epoch's emission burns.
///
/// `u128` intermediate arithmetic is overflow-safe for the full
/// `Stake` range: the multiplication is `emission × validators_in_pool`,
/// both bounded well below `u128::MAX / u128::MAX` headroom.
pub(super) fn distribute_epoch_rewards(state: &mut BeaconState) -> BTreeMap<StakePoolId, Stake> {
    let mut active_count: BTreeMap<StakePoolId, u64> = BTreeMap::new();
    for record in state.validators.values() {
        if matches!(record.status, ValidatorStatus::OnShard { ready: true, .. }) {
            *active_count.entry(record.pool).or_insert(0) += 1;
        }
    }
    let total_active: u64 = active_count.values().sum();
    if total_active == 0 {
        return BTreeMap::new();
    }
    let emission = EMISSIONS_PER_EPOCH.attos();
    let total = u128::from(total_active);
    let mut credited = BTreeMap::new();
    for (pool_id, n) in active_count {
        let share_attos = emission * u128::from(n) / total;
        if share_attos == 0 {
            continue;
        }
        let share = Stake::from_attos(share_attos);
        let pool = state
            .pools
            .get_mut(&pool_id)
            .expect("OnShard validator's pool must be present in state.pools");
        pool.total_stake = pool.total_stake.saturating_add(share);
        credited.insert(pool_id, share);
    }
    credited
}

/// Flip `OnShard { ready: false }` validators to `ready: true` once
/// `current_epoch − placed_at_epoch ≥ READY_TIMEOUT_EPOCHS`.
///
/// Backstop for the event-driven ready path: validators normally
/// signal sync-completion via a `Ready` shard witness; the timeout
/// catches the case where that signal never arrives. A validator
/// auto-readied while still mid-sync exposes themselves to a
/// `MissedProposal` jail cascade — they'll miss votes, accumulate
/// misses, and the threshold trips the normal performance jail.
///
/// Returns the ids that flipped this epoch, deterministic ascending
/// by `BTreeMap` iteration.
pub(super) fn auto_ready_timeout(state: &mut BeaconState) -> Vec<ValidatorId> {
    let current_epoch = state.current_epoch.inner();
    let mut readied = Vec::new();
    for (id, rec) in &mut state.validators {
        if let ValidatorStatus::OnShard {
            shard,
            ready: false,
            placed_at_epoch,
        } = rec.status
            && current_epoch.saturating_sub(placed_at_epoch.inner()) >= READY_TIMEOUT_EPOCHS
        {
            rec.status = ValidatorStatus::OnShard {
                shard,
                ready: true,
                placed_at_epoch,
            };
            readied.push(*id);
        }
    }
    readied
}
