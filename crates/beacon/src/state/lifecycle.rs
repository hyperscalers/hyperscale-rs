//! Per-epoch lifecycle steps: auto-reactivation, reward distribution,
//! auto-ready timeout.

use std::collections::BTreeMap;

use hyperscale_types::{
    BeaconState, EMISSION_PARTICIPATION_WEIGHT, EMISSION_STORAGE_WEIGHT, EMISSION_WORK_WEIGHT,
    EMISSIONS_PER_EPOCH, ShardId, Stake, StakePoolId, ValidatorId, ValidatorStatus,
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

/// One shard's emission weight per ready validator: a participation floor
/// plus its share of the epoch's attested work and of committed stored bytes.
///
/// Shares rather than rates, so the constants are dimensionless ratios
/// against the floor instead of guesses at what a work unit or a byte is
/// worth. A zero network total drops that term for everyone rather than
/// dividing by zero, which is what an epoch with no traffic — or a network
/// with no state yet — actually means.
///
/// The weight is per validator, so a shard's total scales with its
/// committee size. Committees are capped at one size by design, so this is
/// uniform scaling; it is not an attempt to price a seat.
fn shard_emission_weight(gas_delta: u64, gas_total: u128, bytes: u64, bytes_total: u128) -> u128 {
    // `checked_div` carries the zero-total case: a network that attested no
    // work, or holds no state yet, drops that term for everyone rather than
    // dividing by zero.
    let work = (u128::from(EMISSION_WORK_WEIGHT) * u128::from(gas_delta))
        .checked_div(gas_total)
        .unwrap_or(0);
    let storage = (u128::from(EMISSION_STORAGE_WEIGHT) * u128::from(bytes))
        .checked_div(bytes_total)
        .unwrap_or(0);
    u128::from(EMISSION_PARTICIPATION_WEIGHT) + work + storage
}

/// Credit one epoch's emissions across stake pools, weighting each ready
/// `OnShard` validator by what its shard attested this epoch.
///
/// `shard_work` is the epoch's attested work per shard — the difference
/// between each boundary record's mark and the one the previous crossing
/// left — and the stored-byte level comes off the records themselves. Both
/// are quorum-backed chain content by the time they reach here, so every
/// replica weights identically.
///
/// Pure deterministic function of `(state, shard_work)`. Returns the
/// per-pool credits actually applied; zero-share pools are omitted.
///
/// Integer-division rounding remainder is burned — the per-year
/// emission envelope
/// ([`TOKENS_PER_YEAR_TARGET`](hyperscale_types::TOKENS_PER_YEAR_TARGET))
/// is a sizing target, not a hard cap, so the per-epoch remainder
/// drops on the floor rather than accumulating in state.
/// Epochs where no pool has a ready `OnShard` validator return an
/// empty map without crediting — the whole epoch's emission burns.
///
/// `u128` intermediate arithmetic is overflow-safe for the full `Stake`
/// range: the multiplication is `emission × pool_weight`, and weights are
/// bounded by the three weight constants times the validator count.
pub(super) fn distribute_epoch_rewards(
    state: &mut BeaconState,
    shard_work: &BTreeMap<ShardId, u64>,
) -> BTreeMap<StakePoolId, Stake> {
    let gas_total: u128 = shard_work.values().map(|g| u128::from(*g)).sum();
    // Live records only: a reshape's lingering terminal record holds the
    // same bytes its successors' records carry — a splitting parent's
    // reappear on its children — so counting both would dilute every
    // live shard's storage share in exactly the reshape-adjacent epochs
    // the term exists to discriminate.
    let bytes_total: u128 = state
        .boundaries
        .values()
        .filter(|b| b.terminal_epoch.is_none())
        .map(|b| u128::from(b.substate_bytes))
        .sum();
    let weight_of = |shard: ShardId| -> u128 {
        shard_emission_weight(
            shard_work.get(&shard).copied().unwrap_or(0),
            gas_total,
            state
                .boundaries
                .get(&shard)
                .filter(|b| b.terminal_epoch.is_none())
                .map_or(0, |b| b.substate_bytes),
            bytes_total,
        )
    };

    let mut pool_weight: BTreeMap<StakePoolId, u128> = BTreeMap::new();
    for record in state.validators.values() {
        if let ValidatorStatus::OnShard {
            shard, ready: true, ..
        } = record.status
        {
            *pool_weight.entry(record.pool).or_insert(0) += weight_of(shard);
        }
    }
    let total: u128 = pool_weight.values().sum();
    if total == 0 {
        return BTreeMap::new();
    }
    let emission = EMISSIONS_PER_EPOCH.quanta();
    let mut credited = BTreeMap::new();
    for (pool_id, n) in pool_weight {
        let share_quanta = emission * n / total;
        if share_quanta == 0 {
            continue;
        }
        let share = Stake::from_quanta(share_quanta);
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
    use std::collections::{BTreeMap, BTreeSet};

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
    /// Pool stake is `total_stake_quanta` quanta; caller picks it to
    /// engineer specific `max_active_count` outcomes.
    fn state_with_insufficient(
        n_active: u64,
        insufficient: &[u64],
        total_stake_quanta: u128,
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
                total_stake: Stake::from_quanta(total_stake_quanta),
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
        let mut state = state_with_insufficient(3, &[5], 4 * MIN_STAKE_FLOOR.quanta());

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
        let mut state = state_with_insufficient(4, &[5], 4 * MIN_STAKE_FLOOR.quanta());

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
        let mut state = state_with_insufficient(3, &[], 10 * MIN_STAKE_FLOOR.quanta());

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
        let mut state = state_with_insufficient(1, &[5, 7, 9], 3 * MIN_STAKE_FLOOR.quanta());

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
        let base_quanta = 3 * MIN_STAKE_FLOOR.quanta();
        let mut baseline = state_with_insufficient(1, &[5, 7, 9], base_quanta);
        let mut flooded = state_with_insufficient(1, &[5, 7, 9], base_quanta);
        for i in 100u32..160 {
            flooded.pools.insert(
                StakePoolId::new(i),
                StakePool {
                    id: StakePoolId::new(i),
                    total_stake: Stake::from_quanta(1),
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
            Stake::from_quanta(4 * MIN_STAKE_FLOOR.quanta()),
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

        let credited = distribute_epoch_rewards(&mut state, &BTreeMap::new());

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

        let credited = distribute_epoch_rewards(&mut state, &BTreeMap::new());

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

        let credited = distribute_epoch_rewards(&mut state, &BTreeMap::new());

        // Pool A's share = EMISSIONS_PER_EPOCH * 1 / 4 (integer
        // div). Pool B's share = EMISSIONS_PER_EPOCH * 3 / 4.
        let total = 4u128;
        let expected_a = Stake::from_quanta(EMISSIONS_PER_EPOCH.quanta() / total);
        let expected_b = Stake::from_quanta(EMISSIONS_PER_EPOCH.quanta() * 3 / total);
        assert_eq!(credited[&pool_a], expected_a);
        assert_eq!(credited[&pool_b], expected_b);
        // Sum is at most EMISSIONS_PER_EPOCH (remainder burns at most
        // total_pools - 1 = 1 quantum).
        let sum = credited[&pool_a].quanta() + credited[&pool_b].quanta();
        assert!(sum <= EMISSIONS_PER_EPOCH.quanta());
        assert!(EMISSIONS_PER_EPOCH.quanta() - sum < total);
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

        let credited = distribute_epoch_rewards(&mut state, &BTreeMap::new());

        // Only pool A credited.
        assert_eq!(credited.len(), 1);
        assert!(credited.contains_key(&pool_a));
        assert!(!credited.contains_key(&pool_b));
    }

    /// Deterministic: two states with byte-identical inputs produce
    /// byte-identical credits.
    /// The weighting moves emission toward the shard that did the work,
    /// and with an empty work map and no recorded bytes only the
    /// participation floor applies, which is the
    /// pro-rata-by-ready-validator split.
    #[test]
    fn emission_weights_follow_attested_work_and_fall_back_to_participation() {
        use hyperscale_types::{
            BeaconWitnessLeafCount, BlockHash, BlockHeight, ShardBoundary, StateRoot,
            WeightedTimestamp,
        };

        // Two pools, one validator each, on two different shards.
        let mut state = single_pool_state(1);
        let busy = ShardId::leaf(1, 0);
        let quiet = ShardId::leaf(1, 1);
        let second = ValidatorId::new(1);
        let second_pool = StakePoolId::new(1);
        state.pools.insert(
            second_pool,
            StakePool {
                id: second_pool,
                total_stake: Stake::from_quanta(MIN_STAKE_FLOOR.quanta()),
                validators: std::iter::once(second).collect(),
                pending_withdrawals: Vec::new(),
                released_cumulative: Stake::ZERO,
                conviction: None,
            },
        );
        state.validators.insert(
            second,
            validator_record(
                1,
                1,
                ValidatorStatus::OnShard {
                    shard: quiet,
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
            ),
        );

        // No attested work anywhere: the floor alone, so the two pools
        // split evenly.
        let flat = distribute_epoch_rewards(&mut state, &BTreeMap::new());
        assert_eq!(flat[&StakePoolId::new(0)], flat[&second_pool]);

        // Now the busy shard attested every work unit of the epoch. Its
        // pool's share must exceed the quiet one's, and the emission is
        // still divided rather than inflated.
        let work = BTreeMap::from([(busy, 10_000u64), (quiet, 0u64)]);
        let weighted = distribute_epoch_rewards(&mut state, &work);
        assert!(
            weighted[&StakePoolId::new(0)] > weighted[&second_pool],
            "work should move emission: {weighted:?}"
        );
        let total: u128 = weighted.values().map(|s| s.quanta()).sum();
        assert!(total <= EMISSIONS_PER_EPOCH.quanta());

        // The quiet shard still earns: the floor is what keeps a secured but
        // idle shard fundable.
        assert!(weighted[&second_pool] > Stake::from_quanta(0));

        // Stored bytes weigh on the same footing. Giving the quiet shard the
        // network's whole byte level pulls its share back up.
        let record = ShardBoundary {
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::ZERO,
            height: BlockHeight::GENESIS,
            weighted_timestamp: WeightedTimestamp::ZERO,
            witness_leaf_count: BeaconWitnessLeafCount::ZERO,
            witness_base: BeaconWitnessLeafCount::ZERO,
            attested_work: 0,
            substate_bytes: 1_000_000,
            last_live_epoch: Epoch::GENESIS,
            consecutive_misses: 0,
            terminal_epoch: None,
            handoff_complete: None,
            terminal_delivered: false,
            terminal_roots: None,
            reshape_admitted_epoch: None,
        };
        state.boundaries.insert(quiet, record);
        let with_storage = distribute_epoch_rewards(&mut state, &work);
        assert!(
            with_storage[&second_pool] > weighted[&second_pool],
            "stored bytes should weigh: {with_storage:?}"
        );
    }

    /// A reshape's lingering terminal record neither earns nor dilutes
    /// the storage term: a splitting parent's bytes already reappear on
    /// its successors' records, so an epoch straddling the split
    /// credits them once — the live shards' shares are identical with
    /// and without the terminal record present.
    #[test]
    fn a_lingering_terminal_record_does_not_dilute_the_storage_term() {
        use hyperscale_types::{
            BeaconWitnessLeafCount, BlockHash, BlockHeight, ShardBoundary, StateRoot,
            WeightedTimestamp,
        };

        let record = |bytes: u64, terminal: Option<Epoch>| ShardBoundary {
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::ZERO,
            height: BlockHeight::GENESIS,
            weighted_timestamp: WeightedTimestamp::ZERO,
            witness_leaf_count: BeaconWitnessLeafCount::ZERO,
            witness_base: BeaconWitnessLeafCount::ZERO,
            attested_work: 0,
            substate_bytes: bytes,
            last_live_epoch: Epoch::GENESIS,
            consecutive_misses: 0,
            terminal_epoch: terminal,
            handoff_complete: None,
            terminal_delivered: false,
            terminal_roots: None,
            reshape_admitted_epoch: None,
        };

        // Two pools, one ready validator each, on the two children of a
        // split whose parent's record still lingers.
        let build = |with_terminal: bool| {
            let mut state = single_pool_state(1);
            let sibling = ShardId::leaf(1, 1);
            let second = ValidatorId::new(1);
            let second_pool = StakePoolId::new(1);
            state.pools.insert(
                second_pool,
                StakePool {
                    id: second_pool,
                    total_stake: Stake::from_quanta(MIN_STAKE_FLOOR.quanta()),
                    validators: std::iter::once(second).collect(),
                    pending_withdrawals: Vec::new(),
                    released_cumulative: Stake::ZERO,
                    conviction: None,
                },
            );
            state.validators.insert(
                second,
                validator_record(
                    1,
                    1,
                    ValidatorStatus::OnShard {
                        shard: sibling,
                        ready: true,
                        placed_at_epoch: Epoch::GENESIS,
                    },
                ),
            );
            state
                .boundaries
                .insert(ShardId::leaf(1, 0), record(1_000, None));
            state.boundaries.insert(sibling, record(3_000, None));
            if with_terminal {
                state
                    .boundaries
                    .insert(ShardId::ROOT, record(4_000, Some(Epoch::GENESIS)));
            }
            state
        };

        let work = BTreeMap::new();
        let without = distribute_epoch_rewards(&mut build(false), &work);
        let with = distribute_epoch_rewards(&mut build(true), &work);
        assert_eq!(
            with, without,
            "a terminal record must not move any live shard's share"
        );
    }

    #[test]
    fn distribute_epoch_rewards_is_deterministic() {
        let mut a = single_pool_state(4);
        let mut b = single_pool_state(4);
        let work = BTreeMap::new();
        let credits_a = distribute_epoch_rewards(&mut a, &work);
        let credits_b = distribute_epoch_rewards(&mut b, &work);
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
