//! Pure derived helpers over [`BeaconState`].
//!
//! Every helper re-derives its value from `state` — no caching, no
//! two-piece state to keep in sync. These functions live here because
//! they depend on beacon-side protocol constants
//! ([`MIN_STAKE_FLOOR`](crate::constants::MIN_STAKE_FLOOR),
//! [`POOL_BUFFER_TARGET`](crate::constants::POOL_BUFFER_TARGET),
//! [`SHARD_CAPACITY`](crate::constants::SHARD_CAPACITY)) the types crate
//! doesn't see.

use std::collections::HashMap;

use hyperscale_types::{
    BeaconCert, BeaconState, Bls12381G1PublicKey, CertifiedBeaconBlock, NetworkDefinition,
    ShardGroupId, Stake, StakePool, TopologySnapshot, ValidatorId, ValidatorInfo, ValidatorSet,
    ValidatorStatus, VotePower,
};

use crate::constants::{MIN_STAKE_FLOOR, POOL_BUFFER_TARGET, SHARD_CAPACITY};

/// Stake available to support active validators on this pool after
/// accounting for in-flight withdrawals.
///
/// Pending withdrawals reduce effective stake immediately even though
/// `total_stake` doesn't drop until the unbonding window completes —
/// this is what blocks new registrations that would have relied on the
/// withdrawn amount.
#[must_use]
pub fn effective_stake(pool: &StakePool) -> Stake {
    let pending = pool
        .pending_withdrawals
        .iter()
        .fold(Stake::ZERO, |acc, w| acc.saturating_add(w.amount));
    pool.total_stake.saturating_sub(pending)
}

/// How many of `pool`'s validators are currently consuming an
/// activation epoch.
///
/// Counts `Pooled` and `OnShard`; excludes `Jailed` (epoch may stay
/// jailed indefinitely; locking stake against an uncertain return is
/// wrong) and `InsufficientStake` (already represents "not consuming a
/// epoch").
#[must_use]
pub fn current_active_count(pool: &StakePool, state: &BeaconState) -> usize {
    pool.validators
        .iter()
        .filter(|id| {
            matches!(
                state.validators.get(id).map(|r| &r.status),
                Some(ValidatorStatus::Pooled | ValidatorStatus::OnShard { .. })
            )
        })
        .count()
}

/// Cap on how many of `pool`'s validators can be active at the current
/// dynamic [`min_stake`].
///
/// Equals `effective_stake(pool) / min_stake(state)`. The invariant
/// `current_active_count(pool) ≤ max_active_count(pool, state)` is
/// enforced at `RegisterValidator` and `Unjail` application.
#[must_use]
pub fn max_active_count(pool: &StakePool, state: &BeaconState) -> usize {
    let t = min_stake(state);
    if t == Stake::ZERO {
        return usize::MAX;
    }
    let e = effective_stake(pool).attos();
    (e / t.attos()) as usize
}

/// Validators currently waiting in the global pool.
///
/// Derived from `state.validators` rather than stored as a separate
/// field, so there's no two-piece state to keep in sync. Returned
/// sorted by `ValidatorId` for deterministic indexing inside pool draws.
///
/// Membership is exactly `status == Pooled`. A validator becomes
/// `Pooled` on registration, on `Unjail` after cooldown, on trickled
/// shuffle exit, and on auto-reactivation; they leave `Pooled` when a
/// pool draw flips them to `OnShard`, or when a witness moves them to
/// another status.
#[must_use]
pub fn pooled_validators(state: &BeaconState) -> Vec<ValidatorId> {
    state
        .validators
        .iter()
        .filter(|(_, r)| matches!(r.status, ValidatorStatus::Pooled))
        .map(|(id, _)| *id)
        .collect()
}

/// Validators eligible to serve on the beacon committee: status is
/// `OnShard { ready: true, .. }` on any shard.
///
/// Every beacon committee member is therefore a signer on some shard —
/// an offline validator can't escape detection by hiding in the beacon
/// set. Pooled, jailed, insufficient-stake, and not-yet-ready
/// validators are all excluded.
///
/// Returned sorted by `ValidatorId` (`BTreeMap` iteration order) for
/// deterministic Fisher–Yates input downstream.
#[must_use]
pub fn beacon_eligible(state: &BeaconState) -> Vec<ValidatorId> {
    state
        .validators
        .iter()
        .filter(|(_, r)| matches!(r.status, ValidatorStatus::OnShard { ready: true, .. }))
        .map(|(id, _)| *id)
        .collect()
}

/// Resolve the beacon committee from a [`BeaconState`] into
/// `(validator_id, pubkey)` pairs in committee-declaration order.
///
/// The order matches `state.committee` exactly, which is the same
/// positional enumeration `SignerBitfield` is indexed against. SPC
/// cert verifiers, beacon-block verifiers, and the SPC FSM all
/// consume this resolved form.
///
/// Validators present in `state.committee` but missing from
/// `state.validators` are silently dropped. The caller should treat
/// any length mismatch from `state.committee.len()` as a state
/// invariant violation; this function does not panic so callers can
/// make their own decision.
#[must_use]
pub fn derive_beacon_committee(state: &BeaconState) -> Vec<(ValidatorId, Bls12381G1PublicKey)> {
    state
        .committee
        .iter()
        .filter_map(|id| state.validators.get(id).map(|r| (*id, r.pubkey)))
        .collect()
}

/// Derive an immutable [`TopologySnapshot`] from a `BeaconState`.
///
/// The snapshot is the read-only consumer-facing view of validator
/// placement: shard committees, per-validator pubkeys, the local
/// vnode's shard, and the global validator set. Re-derived on every
/// epoch commit and shared via `ArcSwap` with the `io_loop`.
///
/// `local_shard` resolves from the local validator's
/// [`ValidatorStatus`]:
/// - `OnShard { shard, .. }` → that shard.
/// - any other status → `ShardGroupId::new(0)` as a placeholder. The
///   value is informational for off-shard vnodes (pooled, jailed,
///   etc.) — they don't participate in shard consensus and
///   downstream consumers ignore it.
///
/// All validators are assigned uniform [`VotePower::new(1)`] until
/// stake-weighted voting power lands.
#[must_use]
pub fn derive_topology_snapshot(
    state: &BeaconState,
    network: NetworkDefinition,
    local_validator_id: ValidatorId,
) -> TopologySnapshot {
    let validators: Vec<ValidatorInfo> = state
        .validators
        .values()
        .map(|r| ValidatorInfo {
            validator_id: r.id,
            public_key: r.pubkey,
            voting_power: VotePower::new(1),
        })
        .collect();
    let validator_set = ValidatorSet::new(validators);

    let shard_committees: HashMap<ShardGroupId, Vec<ValidatorId>> = state
        .shard_committees
        .iter()
        .map(|(sid, sc)| (*sid, sc.members.clone()))
        .collect();

    let local_shard = state
        .validators
        .get(&local_validator_id)
        .and_then(|r| match r.status {
            ValidatorStatus::OnShard { shard, .. } => Some(shard),
            _ => None,
        })
        .unwrap_or_else(|| ShardGroupId::new(0));

    let num_shards = u64::try_from(state.shard_committees.len()).unwrap_or(u64::MAX);

    TopologySnapshot::with_shard_committees(
        network,
        local_validator_id,
        local_shard,
        num_shards,
        &validator_set,
        shard_committees,
    )
}

/// Active-duty validator pool: every validator `OnShard { ready: true }`
/// on any shard, paired with their pubkey. Returned in `BTreeMap`
/// iteration order over `state.validators` (sorted by `ValidatorId`).
///
/// This is the quorum substrate for [skip](crate::skip):
/// [`SkipRequest`](hyperscale_types::SkipRequest)s are signed by
/// members of this pool and assembled into a
/// [`SkipEpochCert`](hyperscale_types::SkipEpochCert) whose `signers`
/// bitfield is positionally indexed against the same ordering.
#[must_use]
pub fn derive_active_pool(state: &BeaconState) -> Vec<(ValidatorId, Bls12381G1PublicKey)> {
    state
        .validators
        .iter()
        .filter(|(_, r)| matches!(r.status, ValidatorStatus::OnShard { ready: true, .. }))
        .map(|(id, r)| (*id, r.pubkey))
        .collect()
}

/// Pick the signer pool a certified block's cert verifies against.
///
/// Beacon committee for a Normal cert, active pool for a Skip cert.
/// Returns `None` for `BeaconCert::Genesis` — past-tip genesis blocks
/// have no signer pool to verify against.
#[must_use]
pub fn signer_pool_for(
    block: &CertifiedBeaconBlock,
    state: &BeaconState,
) -> Option<Vec<(ValidatorId, Bls12381G1PublicKey)>> {
    match block.cert() {
        BeaconCert::Normal(_) => Some(derive_beacon_committee(state)),
        BeaconCert::Skip(_) => Some(derive_active_pool(state)),
        BeaconCert::Genesis(_) => None,
    }
}

/// Dynamic per-validator minimum stake.
///
/// Pure function of state — no stored "current `min_stake`" field.
/// Evaluated fresh at every site that needs it (registration
/// validation, unjail validation, withdrawal-completion checks).
///
/// Three forces:
///   - `t_no_eject`: the highest level that wouldn't force any
///     currently-active validator into `InsufficientStake`. The
///     tightest pool's `effective_stake / current_active_count`.
///   - `t_admit`: the level low enough that pools collectively *could*
///     support the target validator population (one full shard
///     committee per shard plus [`POOL_BUFFER_TARGET`] reserves).
///   - [`MIN_STAKE_FLOOR`]: governance-set absolute minimum, Sybil
///     backstop.
///
/// Resolution: `min(t_no_eject, t_admit).max(MIN_STAKE_FLOOR)`.
/// `t_no_eject` is a ceiling, not a trigger — a rising `min_stake`
/// doesn't cause involuntary deactivations.
#[must_use]
pub fn min_stake(state: &BeaconState) -> Stake {
    let ne = t_no_eject(state);
    let ad = admit_threshold(state);
    Stake::from_attos(ne.attos().min(ad.attos()).max(MIN_STAKE_FLOOR.attos()))
}

/// Highest `min_stake` could be without forcing any active validator
/// into `InsufficientStake`.
///
/// Equals the minimum across pools (with at least one active
/// validator) of `effective_stake / current_active_count`.
/// [`Stake::MAX`] when no pool yet has an active validator (e.g. at
/// bootstrap).
pub(super) fn t_no_eject(state: &BeaconState) -> Stake {
    state
        .pools
        .values()
        .filter_map(|pool| {
            let active = current_active_count(pool, state);
            if active == 0 {
                None
            } else {
                Some(effective_stake(pool).attos() / active as u128)
            }
        })
        .min()
        .map_or(Stake::MAX, Stake::from_attos)
}

/// Marginal price at which exactly the target epoch count is offered
/// across all pools.
///
/// Each pool offers a descending sequence (`effective_stake / 1, / 2,
/// …`) — "if I had to support k validators, my budget per validator
/// would be e/k." Gather every pool's offerings, sort descending,
/// return the entry at position `target - 1`.
///
/// Target is `shard_count × SHARD_CAPACITY + POOL_BUFFER_TARGET`. The
/// shard count isn't a stored field — it's `state.shard_committees.len()`.
/// Returns [`Stake::MAX`] for a zero target; returns [`MIN_STAKE_FLOOR`]
/// when pools collectively can't fill the target even at floor pricing
/// (anything below the floor would be clamped away by `min_stake`'s
/// `.max(...)` anyway).
pub(super) fn admit_threshold(state: &BeaconState) -> Stake {
    let target = state.shard_committees.len() * SHARD_CAPACITY + POOL_BUFFER_TARGET;
    if target == 0 {
        return Stake::MAX;
    }

    let mut offerings: Vec<u128> = Vec::new();
    for pool in state.pools.values() {
        let e = effective_stake(pool).attos();
        if e == 0 {
            continue;
        }
        // Cap per-pool at `target`: a pool's k-th offering for
        // k > target can't enter the global top-`target`, because the
        // same pool already contributed k-1 higher offerings ranked
        // ahead of it. Also cap at `floor(e / MIN_STAKE_FLOOR)` since
        // offerings below the floor would be clamped away in
        // `min_stake` anyway.
        let floor_cap = if MIN_STAKE_FLOOR == Stake::ZERO {
            target
        } else {
            (e / MIN_STAKE_FLOOR.attos()) as usize
        };
        let k_max = floor_cap.min(target);
        for k in 1..=k_max {
            offerings.push(e / k as u128);
        }
    }

    if offerings.len() < target {
        return MIN_STAKE_FLOOR;
    }

    offerings.sort_unstable_by(|a, b| b.cmp(a));
    Stake::from_attos(offerings[target - 1])
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_types::{
        Epoch, JailReason, PendingWithdrawal, Stake, StakePool, StakePoolId, ValidatorId,
        ValidatorStatus,
    };

    use super::super::test_fixtures::{empty_state, single_pool_state, validator_record};
    use super::*;
    use crate::constants::MIN_STAKE_FLOOR;
    // ─── effective_stake ──────────────────────────────────────────────────

    #[test]
    fn effective_stake_subtracts_pending_withdrawals() {
        let pool = StakePool {
            id: StakePoolId::new(0),
            total_stake: Stake::from_whole_tokens(1_000),
            validators: BTreeSet::new(),
            pending_withdrawals: vec![
                PendingWithdrawal {
                    amount: Stake::from_whole_tokens(100),
                    initiated_at_epoch: Epoch::new(1),
                },
                PendingWithdrawal {
                    amount: Stake::from_whole_tokens(250),
                    initiated_at_epoch: Epoch::new(2),
                },
            ],
        };
        assert_eq!(effective_stake(&pool), Stake::from_whole_tokens(650));
    }

    /// Defense-in-depth: an over-withdrawal (bookkeeping drift, hostile
    /// shard) clamps `effective_stake` to zero rather than wrapping.
    #[test]
    fn effective_stake_saturates_when_pending_exceeds_total() {
        let pool = StakePool {
            id: StakePoolId::new(0),
            total_stake: Stake::from_whole_tokens(100),
            validators: BTreeSet::new(),
            pending_withdrawals: vec![PendingWithdrawal {
                amount: Stake::from_whole_tokens(500),
                initiated_at_epoch: Epoch::GENESIS,
            }],
        };
        assert_eq!(effective_stake(&pool), Stake::ZERO);
    }

    // ─── current_active_count ────────────────────────────────────────────

    #[test]
    fn current_active_count_includes_pooled_and_on_shard() {
        let state = single_pool_state(4);
        let pool = state.pools.get(&StakePoolId::new(0)).unwrap();
        assert_eq!(current_active_count(pool, &state), 4);
    }

    #[test]
    fn current_active_count_excludes_jailed_and_insufficient_stake() {
        let mut state = single_pool_state(4);
        // Jail one, mark another InsufficientStake — both must drop out.
        state
            .validators
            .get_mut(&ValidatorId::new(0))
            .unwrap()
            .status = ValidatorStatus::Jailed {
            since_epoch: Epoch::GENESIS,
            reason: JailReason::Performance,
        };
        state
            .validators
            .get_mut(&ValidatorId::new(1))
            .unwrap()
            .status = ValidatorStatus::InsufficientStake;
        let pool = state.pools.get(&StakePoolId::new(0)).unwrap();
        assert_eq!(current_active_count(pool, &state), 2);
    }

    // ─── pooled_validators ───────────────────────────────────────────────

    #[test]
    fn pooled_validators_returns_only_pooled_in_id_order() {
        let mut state = single_pool_state(0);
        // Insert out of id order to confirm BTreeMap iteration sorts.
        for id in [3u64, 0, 2, 1] {
            state.validators.insert(
                ValidatorId::new(id),
                validator_record(id, 0, ValidatorStatus::Pooled),
            );
        }
        // Insert a non-Pooled validator that must be filtered out.
        state.validators.insert(
            ValidatorId::new(99),
            validator_record(99, 0, ValidatorStatus::InsufficientStake),
        );
        assert_eq!(
            pooled_validators(&state),
            vec![
                ValidatorId::new(0),
                ValidatorId::new(1),
                ValidatorId::new(2),
                ValidatorId::new(3),
            ]
        );
    }

    // ─── min_stake ───────────────────────────────────────────────────────

    /// Empty state — no pools, no active validators. `t_no_eject` and
    /// `admit_threshold` both default high; `min_stake` clamps to
    /// `MIN_STAKE_FLOOR`.
    #[test]
    fn min_stake_floor_on_empty_state() {
        let state = empty_state();
        assert_eq!(min_stake(&state), MIN_STAKE_FLOOR);
    }

    /// One pool, four active validators, total stake exactly `4 ×
    /// MIN_STAKE_FLOOR`. `t_no_eject = MIN_STAKE_FLOOR` (tightest
    /// pool's ratio), so `min_stake` lands at the floor.
    #[test]
    fn min_stake_clamps_to_floor_at_tight_pool() {
        let state = single_pool_state(4);
        assert_eq!(min_stake(&state), MIN_STAKE_FLOOR);
    }

    // ─── max_active_count ────────────────────────────────────────────────

    #[test]
    fn max_active_count_equals_effective_over_min_stake() {
        let state = single_pool_state(4);
        let pool = state.pools.get(&StakePoolId::new(0)).unwrap();
        // 4 floors of stake, `min_stake = floor` ⇒ cap of 4.
        assert_eq!(max_active_count(pool, &state), 4);
    }

    /// A pending withdrawal that empties the pool's effective stake
    /// drops `max_active_count` to zero, even though `total_stake`
    /// remains funded.
    #[test]
    fn max_active_count_respects_pending_withdrawals() {
        let mut state = single_pool_state(4);
        let pool_mut = state.pools.get_mut(&StakePoolId::new(0)).unwrap();
        pool_mut.pending_withdrawals.push(PendingWithdrawal {
            amount: pool_mut.total_stake,
            initiated_at_epoch: Epoch::GENESIS,
        });
        let pool = state.pools.get(&StakePoolId::new(0)).unwrap();
        assert_eq!(max_active_count(pool, &state), 0);
    }

    // ─── miss counter sanity ──────────────────────────────────────────────

    /// Pins the `miss_counters` field shape (per-validator `u32`
    /// counter) so a future refactor that changes the value type is
    /// caught. The scoping invariants (per-epoch reset, status-
    /// transition reset) live with `apply_epoch`, not the type.
    #[test]
    fn miss_counters_field_is_per_validator_u32_map() {
        let mut state = empty_state();
        state.miss_counters.insert(ValidatorId::new(5), 3);
        state.miss_counters.insert(ValidatorId::new(7), 12);
        assert_eq!(state.miss_counters.get(&ValidatorId::new(5)), Some(&3));
        assert_eq!(state.miss_counters.get(&ValidatorId::new(7)), Some(&12));
    }
}
