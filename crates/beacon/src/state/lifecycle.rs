//! Per-epoch lifecycle steps: auto-reactivation, reward distribution,
//! auto-ready timeout.

use std::collections::BTreeMap;

use hyperscale_types::{
    BeaconState, EMISSIONS_PER_EPOCH, Stake, StakePoolId, ValidatorId, ValidatorStatus,
};

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
/// `min_stake` is global and shifts only when a flip changes some pool's
/// active count, so it's computed once and refreshed after each flip
/// rather than re-derived per pool — without that, every sweep would be
/// O(pools²), which a dust-deposit pool flood could inflate at will. An
/// empty `InsufficientStake` set (the common steady state) skips the
/// sweep outright.
///
/// The "doesn't immediately re-promote a just-deactivated validator"
/// property is provided by the gate: the pool that triggered the
/// deactivation in
/// [`complete_pending_withdrawals`](super::withdrawals::complete_pending_withdrawals)
/// now has `cur >= max` (the deactivation was *because* of
/// over-commitment), so this loop skips it.
pub(super) fn auto_reactivate(state: &mut BeaconState) -> Vec<ValidatorId> {
    let nothing_waiting = !state
        .validators
        .values()
        .any(|r| matches!(r.status, ValidatorStatus::InsufficientStake));
    if nothing_waiting {
        return Vec::new();
    }

    let mut reactivated = Vec::new();
    let mut min_stake = state.min_stake();
    loop {
        let mut did_any = false;
        let pool_ids: Vec<StakePoolId> = state.pools.keys().copied().collect();
        for pool_id in pool_ids {
            let (cur, max) = {
                let pool = state.pools.get(&pool_id).expect("just iterated");
                // A convicted pool never reactivates: its zero actives
                // against standing stake would otherwise pass the
                // capacity check and re-pool members the conviction
                // retired.
                if pool.conviction.is_some() {
                    continue;
                }
                (
                    pool.current_active_count(state),
                    pool.max_active_count_at(min_stake),
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
            // The flip raised this pool's active count, so `t_no_eject`
            // (and thus `min_stake`) may have moved; refresh before the
            // next pool reads it.
            min_stake = state.min_stake();
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
/// ([`TOKENS_PER_YEAR_TARGET`](hyperscale_types::TOKENS_PER_YEAR_TARGET))
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
/// `current_epoch − placed_at_epoch ≥ chain_config.ready_timeout_epochs`.
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
    let timeout = state.chain_config.ready_timeout_epochs;
    let mut readied = Vec::new();
    for (id, rec) in &mut state.validators {
        if let ValidatorStatus::OnShard {
            shard,
            ready: false,
            placed_at_epoch,
        } = rec.status
            && current_epoch.saturating_sub(placed_at_epoch.inner()) >= timeout
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_types::{
        BeaconState, Epoch, JailReason, MIN_STAKE_FLOOR, ShardCommittee, ShardId,
        ShardWitnessPayload, Stake, StakePool, StakePoolId, UNBONDING_WINDOW_EPOCHS, ValidatorId,
        ValidatorRecord, ValidatorStatus,
    };

    use super::distribute_epoch_rewards;
    use crate::state::test_fixtures::{
        apply_next_epoch, apply_witness_chunk, empty_state, pubkey, single_pool_state,
        state_with_pending_withdrawal, validator_record,
    };
    // ─── auto_reactivate ─────────────────────────────────────────────────

    /// Build a pool with `n_active` validators (`OnShard`) plus
    /// `insufficient` `InsufficientStake` validators in the same pool.
    /// Pool stake is `total_stake_attos` attos; caller picks it to
    /// engineer specific `max_active_count` outcomes.
    fn state_with_insufficient(
        n_active: u64,
        insufficient: &[u64],
        total_stake_attos: u128,
    ) -> BeaconState {
        let mut state = empty_state();
        let pool_id = StakePoolId::new(0);
        let shard = ShardId::leaf(1, 0);
        let mut pool_validators = BTreeSet::new();
        let mut members = Vec::new();
        for i in 0..n_active {
            let id = ValidatorId::new(i);
            pool_validators.insert(id);
            members.push(id);
            state.validators.insert(
                id,
                validator_record(
                    i,
                    0,
                    ValidatorStatus::OnShard {
                        shard,
                        ready: true,
                        placed_at_epoch: Epoch::GENESIS,
                    },
                ),
            );
        }
        for &id in insufficient {
            pool_validators.insert(ValidatorId::new(id));
            state.validators.insert(
                ValidatorId::new(id),
                validator_record(id, 0, ValidatorStatus::InsufficientStake),
            );
        }
        state.pools.insert(
            pool_id,
            StakePool {
                id: pool_id,
                total_stake: Stake::from_attos(total_stake_attos),
                validators: pool_validators,
                pending_withdrawals: Vec::new(),
                released_cumulative: Stake::ZERO,
                conviction: None,
            },
        );
        state
            .next_shard_committees
            .insert(shard, ShardCommittee { members });
        state.committee = (0..n_active).map(ValidatorId::new).collect();
        state
    }

    /// Pool with capacity for one more active and an
    /// `InsufficientStake` validator → that validator reactivates to
    /// `Pooled`.
    #[test]
    fn auto_reactivate_promotes_insufficient_when_capacity_available() {
        // 3 actives, 1 insufficient, stake covers 4. After
        // reactivation cur=4 ≤ max=4.
        let mut state = state_with_insufficient(3, &[5], 4 * MIN_STAKE_FLOOR.attos());

        let effects = apply_next_epoch(&mut state, &[]);

        assert_eq!(effects.reactivated, vec![ValidatorId::new(5)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(5)).unwrap().status,
            ValidatorStatus::Pooled,
        );
    }

    /// Pool with `InsufficientStake` validator but no capacity
    /// (cur >= max) → no reactivation.
    #[test]
    fn auto_reactivate_skips_pool_at_capacity() {
        // 4 actives, 1 insufficient, stake covers 4 only. cur=4, max=4
        // → no reactivation.
        let mut state = state_with_insufficient(4, &[5], 4 * MIN_STAKE_FLOOR.attos());

        let effects = apply_next_epoch(&mut state, &[]);

        assert!(effects.reactivated.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(5)).unwrap().status,
            ValidatorStatus::InsufficientStake,
        );
    }

    /// Pool with capacity but no `InsufficientStake` validators → no
    /// reactivation.
    #[test]
    fn auto_reactivate_noop_when_no_candidates() {
        let mut state = state_with_insufficient(3, &[], 10 * MIN_STAKE_FLOOR.attos());

        let effects = apply_next_epoch(&mut state, &[]);

        assert!(effects.reactivated.is_empty());
    }

    /// Multiple `InsufficientStake` candidates: highest-id picked
    /// first; subsequent iterations pick next-highest if capacity
    /// still allows.
    #[test]
    fn auto_reactivate_picks_highest_id_first() {
        // 1 active, 3 insufficient (ids 5, 7, 9), stake covers 3.
        // Each iteration adds one validator: iteration 1 adds 9
        // (cur=2), iteration 2 adds 7 (cur=3), iteration 3 sees
        // cur=3=max, no further picks.
        let mut state = state_with_insufficient(1, &[5, 7, 9], 3 * MIN_STAKE_FLOOR.attos());

        let effects = apply_next_epoch(&mut state, &[]);

        assert_eq!(
            effects.reactivated,
            vec![ValidatorId::new(9), ValidatorId::new(7)],
        );
        assert_eq!(
            state.validators.get(&ValidatorId::new(9)).unwrap().status,
            ValidatorStatus::Pooled,
        );
        assert_eq!(
            state.validators.get(&ValidatorId::new(7)).unwrap().status,
            ValidatorStatus::Pooled,
        );
        // Validator 5 stays insufficient — pool full.
        assert_eq!(
            state.validators.get(&ValidatorId::new(5)).unwrap().status,
            ValidatorStatus::InsufficientStake,
        );
    }

    /// Funded-but-empty "dust" pools don't change the reactivation
    /// outcome — exercises the cached-`min_stake` sweep under a pool
    /// flood and pins that it yields the same flips a clean state does.
    #[test]
    fn auto_reactivate_outcome_unaffected_by_dust_pools() {
        let base_attos = 3 * MIN_STAKE_FLOOR.attos();
        let mut baseline = state_with_insufficient(1, &[5, 7, 9], base_attos);
        let mut flooded = state_with_insufficient(1, &[5, 7, 9], base_attos);
        for i in 100u32..160 {
            flooded.pools.insert(
                StakePoolId::new(i),
                StakePool {
                    id: StakePoolId::new(i),
                    total_stake: Stake::from_attos(1),
                    validators: BTreeSet::new(),
                    pending_withdrawals: Vec::new(),
                    released_cumulative: Stake::ZERO,
                    conviction: None,
                },
            );
        }

        let base_effects = apply_next_epoch(&mut baseline, &[]);
        let flood_effects = apply_next_epoch(&mut flooded, &[]);

        assert_eq!(base_effects.reactivated, flood_effects.reactivated);
        assert_eq!(
            base_effects.reactivated,
            vec![ValidatorId::new(9), ValidatorId::new(7)],
        );
        for id in [5u64, 7, 9] {
            assert_eq!(
                baseline
                    .validators
                    .get(&ValidatorId::new(id))
                    .map(|r| r.status),
                flooded
                    .validators
                    .get(&ValidatorId::new(id))
                    .map(|r| r.status),
            );
        }
    }

    /// A validator just deactivated by `complete_pending_withdrawals`
    /// in the same epoch is NOT re-promoted: the pool that deactivated
    /// them has `cur = max` after the release, so the auto-reactivate
    /// gate skips it.
    #[test]
    fn auto_reactivate_does_not_unwind_same_slot_withdrawal_deactivation() {
        let initiated = Epoch::new(2);
        let current = Epoch::new(initiated.inner() + UNBONDING_WINDOW_EPOCHS);
        // 4 actives, stake covers 4 exactly. Release MIN_STAKE_FLOOR
        // — deactivates validator 3, leaves cur=3 max=3.
        let mut state = state_with_pending_withdrawal(
            4,
            Stake::from_attos(4 * MIN_STAKE_FLOOR.attos()),
            MIN_STAKE_FLOOR,
            initiated,
            current,
        );

        let effects = apply_next_epoch(&mut state, &[]);

        // Validator 3 was deactivated this epoch.
        assert_eq!(effects.deactivated, vec![ValidatorId::new(3)]);
        // …and NOT re-promoted.
        assert!(effects.reactivated.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(3)).unwrap().status,
            ValidatorStatus::InsufficientStake,
        );
    }

    // ─── distribute_epoch_rewards ────────────────────────────────────────

    use hyperscale_types::EMISSIONS_PER_EPOCH;

    /// State with no `OnShard { ready: true }` validators returns no
    /// credits — the whole epoch's emission burns.
    #[test]
    fn distribute_epoch_rewards_no_op_when_no_ready_actives() {
        let mut state = empty_state();
        // Empty pool entry so the function has something to iterate
        // over without hitting the no-active branch via empty
        // validators.
        state.pools.insert(
            StakePoolId::new(0),
            StakePool {
                id: StakePoolId::new(0),
                total_stake: Stake::from_whole_tokens(1_000_000),
                validators: BTreeSet::new(),
                pending_withdrawals: Vec::new(),
                released_cumulative: Stake::ZERO,
                conviction: None,
            },
        );
        let pre_total = state.pools[&StakePoolId::new(0)].total_stake;

        let credited = distribute_epoch_rewards(&mut state);

        assert!(credited.is_empty());
        assert_eq!(state.pools[&StakePoolId::new(0)].total_stake, pre_total);
    }

    /// Validators with `ready: false` don't count — pool with one
    /// ready + one not-ready credits as if it had one active.
    #[test]
    fn distribute_epoch_rewards_excludes_unready_validators() {
        let mut state = single_pool_state(0);
        let pool_id = StakePoolId::new(0);
        let shard = ShardId::leaf(1, 0);
        // Two validators: ready and not-ready, both OnShard.
        state.validators.insert(
            ValidatorId::new(0),
            validator_record(
                0,
                0,
                ValidatorStatus::OnShard {
                    shard,
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
            ),
        );
        state.validators.insert(
            ValidatorId::new(1),
            validator_record(
                1,
                0,
                ValidatorStatus::OnShard {
                    shard,
                    ready: false,
                    placed_at_epoch: Epoch::GENESIS,
                },
            ),
        );
        state
            .pools
            .get_mut(&pool_id)
            .unwrap()
            .validators
            .extend([ValidatorId::new(0), ValidatorId::new(1)]);
        let pre_total = state.pools[&pool_id].total_stake;

        let credited = distribute_epoch_rewards(&mut state);

        // One pool got credited (the only one with ready actives).
        assert_eq!(credited.len(), 1);
        let credit = credited[&pool_id];
        // Single-active-validator-only-pool case: the credit equals
        // the full epoch emission (no rounding remainder when total =
        // count = 1).
        assert_eq!(credit, EMISSIONS_PER_EPOCH);
        assert_eq!(
            state.pools[&pool_id].total_stake,
            pre_total.saturating_add(credit),
        );
    }

    /// Multi-pool distribution: pro-rata by ready-active count.
    /// Two pools with 1 vs 3 ready actives get 1/4 vs 3/4 of the
    /// emission respectively (integer-division remainder burned).
    #[test]
    fn distribute_epoch_rewards_splits_pro_rata_by_ready_count() {
        let mut state = empty_state();
        let pool_a = StakePoolId::new(1);
        let pool_b = StakePoolId::new(2);
        let shard = ShardId::leaf(1, 0);

        // Pool A: 1 ready active.
        state.pools.insert(
            pool_a,
            StakePool {
                id: pool_a,
                total_stake: Stake::from_whole_tokens(1_000),
                validators: std::iter::once(ValidatorId::new(10)).collect(),
                pending_withdrawals: Vec::new(),
                released_cumulative: Stake::ZERO,
                conviction: None,
            },
        );
        state.validators.insert(
            ValidatorId::new(10),
            ValidatorRecord {
                id: ValidatorId::new(10),
                pool: pool_a,
                status: ValidatorStatus::OnShard {
                    shard,
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
                registered_at_epoch: Epoch::GENESIS,
                pubkey: pubkey(10),
            },
        );

        // Pool B: 3 ready actives.
        state.pools.insert(
            pool_b,
            StakePool {
                id: pool_b,
                total_stake: Stake::from_whole_tokens(1_000),
                validators: (20u64..23).map(ValidatorId::new).collect(),
                pending_withdrawals: Vec::new(),
                released_cumulative: Stake::ZERO,
                conviction: None,
            },
        );
        for i in 20u64..23 {
            state.validators.insert(
                ValidatorId::new(i),
                ValidatorRecord {
                    id: ValidatorId::new(i),
                    pool: pool_b,
                    status: ValidatorStatus::OnShard {
                        shard,
                        ready: true,
                        placed_at_epoch: Epoch::GENESIS,
                    },
                    registered_at_epoch: Epoch::GENESIS,
                    pubkey: pubkey(i),
                },
            );
        }

        let credited = distribute_epoch_rewards(&mut state);

        // Pool A's share = EMISSIONS_PER_EPOCH * 1 / 4 (integer
        // div). Pool B's share = EMISSIONS_PER_EPOCH * 3 / 4.
        let total = 4u128;
        let expected_a = Stake::from_attos(EMISSIONS_PER_EPOCH.attos() / total);
        let expected_b = Stake::from_attos(EMISSIONS_PER_EPOCH.attos() * 3 / total);
        assert_eq!(credited[&pool_a], expected_a);
        assert_eq!(credited[&pool_b], expected_b);
        // Sum is at most EMISSIONS_PER_EPOCH (remainder burns at most
        // total_pools - 1 = 1 atto).
        let sum = credited[&pool_a].attos() + credited[&pool_b].attos();
        assert!(sum <= EMISSIONS_PER_EPOCH.attos());
        assert!(EMISSIONS_PER_EPOCH.attos() - sum < total);
    }

    /// Zero-share pools (in this case: pool with only `Pooled`
    /// validators, no `OnShard { ready: true }`) are omitted from
    /// the returned map.
    #[test]
    fn distribute_epoch_rewards_omits_zero_share_pools() {
        let mut state = empty_state();
        let pool_a = StakePoolId::new(1);
        let pool_b = StakePoolId::new(2);

        // Pool A: 1 ready active. Pool B: only a Pooled validator.
        state.pools.insert(
            pool_a,
            StakePool {
                id: pool_a,
                total_stake: Stake::from_whole_tokens(1_000),
                validators: std::iter::once(ValidatorId::new(10)).collect(),
                pending_withdrawals: Vec::new(),
                released_cumulative: Stake::ZERO,
                conviction: None,
            },
        );
        state.pools.insert(
            pool_b,
            StakePool {
                id: pool_b,
                total_stake: Stake::from_whole_tokens(1_000),
                validators: std::iter::once(ValidatorId::new(20)).collect(),
                pending_withdrawals: Vec::new(),
                released_cumulative: Stake::ZERO,
                conviction: None,
            },
        );
        state.validators.insert(
            ValidatorId::new(10),
            ValidatorRecord {
                id: ValidatorId::new(10),
                pool: pool_a,
                status: ValidatorStatus::OnShard {
                    shard: ShardId::leaf(1, 0),
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
                registered_at_epoch: Epoch::GENESIS,
                pubkey: pubkey(10),
            },
        );
        state.validators.insert(
            ValidatorId::new(20),
            validator_record(20, 2, ValidatorStatus::Pooled),
        );

        let credited = distribute_epoch_rewards(&mut state);

        // Only pool A credited.
        assert_eq!(credited.len(), 1);
        assert!(credited.contains_key(&pool_a));
        assert!(!credited.contains_key(&pool_b));
    }

    /// Deterministic: two states with byte-identical inputs produce
    /// byte-identical credits.
    #[test]
    fn distribute_epoch_rewards_is_deterministic() {
        let mut a = single_pool_state(4);
        let mut b = single_pool_state(4);
        let credits_a = distribute_epoch_rewards(&mut a);
        let credits_b = distribute_epoch_rewards(&mut b);
        assert_eq!(credits_a, credits_b);
        assert_eq!(a.pools, b.pools);
    }

    // ─── auto_ready_timeout ──────────────────────────────────────────────

    /// The ready timeout the fixture states run under — the dev-default
    /// `chain_config.ready_timeout_epochs`.
    fn ready_timeout() -> u64 {
        empty_state().chain_config.ready_timeout_epochs
    }

    /// Helper: place validator `id` on shard 0 at `placed_at_epoch`
    /// with `ready: false`. Inserts into pool 0's validator set so
    /// derived helpers see the pool correctly.
    fn insert_unready_on_shard(state: &mut BeaconState, id: u64, placed_at_epoch: Epoch) {
        let pool_id = StakePoolId::new(0);
        let shard = ShardId::leaf(1, 0);
        state
            .pools
            .entry(pool_id)
            .or_insert_with(|| StakePool {
                id: pool_id,
                total_stake: Stake::from_whole_tokens(1_000_000),
                validators: BTreeSet::new(),
                pending_withdrawals: Vec::new(),
                released_cumulative: Stake::ZERO,
                conviction: None,
            })
            .validators
            .insert(ValidatorId::new(id));
        state.validators.insert(
            ValidatorId::new(id),
            validator_record(
                id,
                0,
                ValidatorStatus::OnShard {
                    shard,
                    ready: false,
                    placed_at_epoch,
                },
            ),
        );
    }

    /// Validator placed `ready_timeout_epochs` epochs ago flips to
    /// `ready: true` (with `placed_at_epoch` preserved).
    #[test]
    fn auto_ready_timeout_flips_after_threshold() {
        let placed = Epoch::new(3);
        let current = Epoch::new(placed.inner() + ready_timeout());
        let mut state = empty_state();
        state.current_epoch = current;
        state.committee = vec![ValidatorId::new(0)];
        insert_unready_on_shard(&mut state, 0, placed);

        let effects = apply_next_epoch(&mut state, &[]);

        assert_eq!(effects.readied, vec![ValidatorId::new(0)]);
        assert_eq!(
            state.validators.get(&ValidatorId::new(0)).unwrap().status,
            ValidatorStatus::OnShard {
                shard: ShardId::leaf(1, 0),
                ready: true,
                placed_at_epoch: placed,
            },
        );
    }

    /// Validator placed just under the threshold stays `ready: false`.
    #[test]
    fn auto_ready_timeout_holds_before_threshold() {
        let placed = Epoch::new(3);
        // Two short of maturity — apply_next_epoch's advance lands at
        // (placed + THRESHOLD - 1), still under.
        let current = Epoch::new(placed.inner() + ready_timeout() - 2);
        let mut state = empty_state();
        state.current_epoch = current;
        state.committee = vec![ValidatorId::new(0)];
        insert_unready_on_shard(&mut state, 0, placed);

        let effects = apply_next_epoch(&mut state, &[]);

        assert!(effects.readied.is_empty());
        assert!(matches!(
            state.validators.get(&ValidatorId::new(0)).unwrap().status,
            ValidatorStatus::OnShard { ready: false, .. },
        ));
    }

    /// Validators in non-`OnShard{ready:false}` statuses are
    /// unchanged — `Pooled`, `Jailed`, already-ready `OnShard`,
    /// `InsufficientStake` all bypass the timeout.
    #[test]
    fn auto_ready_timeout_ignores_non_unready_on_shard() {
        let mut state = single_pool_state(4); // 4 ready OnShard
        state.committee = (0u64..4).map(ValidatorId::new).collect();
        state.current_epoch = Epoch::new(10 * ready_timeout());
        // Add a Pooled and a Jailed validator — neither should flip.
        state.validators.insert(
            ValidatorId::new(10),
            validator_record(10, 0, ValidatorStatus::Pooled),
        );
        state.validators.insert(
            ValidatorId::new(11),
            validator_record(
                11,
                0,
                ValidatorStatus::Jailed {
                    since_epoch: Epoch::GENESIS,
                    reason: JailReason::Performance,
                },
            ),
        );

        let effects = apply_next_epoch(&mut state, &[]);

        assert!(effects.readied.is_empty());
        assert_eq!(
            state.validators.get(&ValidatorId::new(10)).unwrap().status,
            ValidatorStatus::Pooled,
        );
        assert_eq!(
            state.validators.get(&ValidatorId::new(11)).unwrap().status,
            ValidatorStatus::Jailed {
                since_epoch: Epoch::GENESIS,
                reason: JailReason::Performance,
            },
        );
    }

    /// Multiple unready validators: only those past the threshold
    /// flip; the under-threshold ones stay.
    #[test]
    fn auto_ready_timeout_flips_selectively_by_placed_epoch() {
        let current = Epoch::new(2 * ready_timeout());
        let mut state = empty_state();
        state.current_epoch = current;
        // Three validators at distinct ages: 2T past, 1 under, exactly T past.
        insert_unready_on_shard(&mut state, 0, Epoch::GENESIS);
        insert_unready_on_shard(&mut state, 1, Epoch::new(current.inner() - 1));
        insert_unready_on_shard(&mut state, 2, Epoch::new(current.inner() - ready_timeout()));

        let effects = apply_next_epoch(&mut state, &[]);

        // Ids 0 and 2 flipped; 1 didn't.
        assert_eq!(
            effects.readied,
            vec![ValidatorId::new(0), ValidatorId::new(2)]
        );
        assert!(matches!(
            state.validators.get(&ValidatorId::new(0)).unwrap().status,
            ValidatorStatus::OnShard { ready: true, .. },
        ));
        assert!(matches!(
            state.validators.get(&ValidatorId::new(1)).unwrap().status,
            ValidatorStatus::OnShard { ready: false, .. },
        ));
        assert!(matches!(
            state.validators.get(&ValidatorId::new(2)).unwrap().status,
            ValidatorStatus::OnShard { ready: true, .. },
        ));
    }

    /// `Ready` witness this epoch and `auto_ready_timeout` flipping
    /// other validators both populate `SlotEffects.readied` —
    /// witness path first, timeout path appended. Pins the
    /// dual-source field semantics.
    #[test]
    fn readied_field_carries_both_witness_and_timeout_flips() {
        let mut state = empty_state();
        state.current_epoch = Epoch::new(5 * ready_timeout());
        state.committee = vec![ValidatorId::new(0)];

        // Validator 0: OnShard{ready:true} — needed to sign the
        // proposal.
        let pool_id = StakePoolId::new(0);
        state.pools.insert(
            pool_id,
            StakePool {
                id: pool_id,
                total_stake: Stake::from_whole_tokens(1_000_000),
                validators: [
                    ValidatorId::new(0),
                    ValidatorId::new(1),
                    ValidatorId::new(2),
                ]
                .into_iter()
                .collect(),
                pending_withdrawals: Vec::new(),
                released_cumulative: Stake::ZERO,
                conviction: None,
            },
        );
        state.validators.insert(
            ValidatorId::new(0),
            validator_record(
                0,
                0,
                ValidatorStatus::OnShard {
                    shard: ShardId::leaf(1, 0),
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
            ),
        );
        state
            .next_shard_committees
            .insert(ShardId::leaf(1, 0), ShardCommittee::default());
        state
            .next_shard_committees
            .get_mut(&ShardId::leaf(1, 0))
            .unwrap()
            .members
            .push(ValidatorId::new(0));

        // Validator 1: placed fresh (age 0, under the timeout
        // threshold) so it readies via the explicit Ready witness rather
        // than the timeout path.
        let fresh_epoch = state.current_epoch;
        insert_unready_on_shard(&mut state, 1, fresh_epoch);
        // Validator 2: placed in the distant past, so it readies via the
        // timeout path.
        insert_unready_on_shard(&mut state, 2, Epoch::new(0));

        let effects = apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::Ready {
                id: ValidatorId::new(1),
            }],
        );

        // Both ended up in readied: validator 1 via witness, validator
        // 2 via timeout. Order: witness path appends first, then
        // timeout.
        assert_eq!(
            effects.readied,
            vec![ValidatorId::new(1), ValidatorId::new(2)]
        );
    }
}
