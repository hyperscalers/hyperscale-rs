//! Pool-level byzantine conviction: the cascade that permanently
//! retires a stake pool when equivocation evidence lands on any of its
//! validators.

use hyperscale_types::{
    BeaconState, Epoch, PoolConviction, StakePoolId, ValidatorId, ValidatorStatus,
};

use crate::state::vrf::revoke_validator;

/// Convict `pool_id`: stamp the conviction record and revoke every
/// validator the pool operates, whatever their status — one operator
/// runs them all, so the pool is the attribution unit the evidence
/// reaches. `InsufficientStake` members are revoked too (the record
/// retention that exists exactly so late evidence can still apply);
/// placed members tear down through `revoke_validator`'s
/// `exit_placement` (committee removal, keeper and cohort seat
/// shedding, refill).
///
/// `lifts_at` is stamped from the live `impound_epochs` parameter, so a
/// later governance change never shortens an in-force impound.
///
/// Idempotent: a pool with a standing conviction is left untouched, so
/// evidence arriving through multiple channels folds to one conviction
/// and `lifts_at` never restamps. Returns the validators revoked by
/// this call (empty on replay or unknown pool).
pub(super) fn convict_pool(
    state: &mut BeaconState,
    pool_id: StakePoolId,
    epoch: Epoch,
) -> Vec<ValidatorId> {
    let lifts_at = Epoch::new(epoch.inner().saturating_add(state.params.impound_epochs));
    let Some(pool) = state.pools.get_mut(&pool_id) else {
        return Vec::new();
    };
    if pool.conviction.is_some() {
        return Vec::new();
    }
    pool.conviction = Some(PoolConviction {
        convicted_at: epoch,
        lifts_at,
    });
    // The pool's governance weight dies with it. Dropping the standing
    // vote here (not just gating new casts) matters for ordering: a
    // vote recorded earlier in this same fold would otherwise still
    // carry the impounded stake into this epoch's tally.
    state.param_votes.remove(&pool_id);
    let members: Vec<ValidatorId> = pool.validators.iter().copied().collect();
    let mut revoked = Vec::new();
    for id in members {
        if matches!(
            state.validators.get(&id).map(|r| r.status),
            Some(ValidatorStatus::Revoked { .. }) | None
        ) {
            continue;
        }
        revoke_validator(state, id, epoch);
        revoked.push(id);
    }
    revoked
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        BeaconState, EMISSIONS_PER_EPOCH, Epoch, JailReason, MIN_STAKE_FLOOR, NetworkParams,
        ParamProposal, PendingWithdrawal, ShardCommittee, ShardId, Stake, StakePool,
        UNBONDING_WINDOW_EPOCHS, ValidatorId,
    };

    use super::*;
    use crate::state::lifecycle::{auto_reactivate, distribute_epoch_rewards};
    use crate::state::test_fixtures::{empty_state, validator_record};
    use crate::state::withdrawals::complete_pending_withdrawals;

    /// Pool 0: validator 0 `OnShard`, 1 `Pooled`, 2 `Jailed`, 3
    /// `InsufficientStake`. Pool 1: validator 10 `OnShard`, 11 `Pooled`.
    fn two_pool_state() -> BeaconState {
        let shard = ShardId::leaf(1, 0);
        let mut state = empty_state();
        state.current_epoch = Epoch::new(7);
        let on_shard = ValidatorStatus::OnShard {
            shard,
            ready: true,
            placed_at_epoch: Epoch::GENESIS,
        };
        let statuses = [
            (0u64, 0u32, on_shard),
            (1, 0, ValidatorStatus::Pooled),
            (
                2,
                0,
                ValidatorStatus::Jailed {
                    since_epoch: Epoch::new(3),
                    reason: JailReason::Performance,
                },
            ),
            (3, 0, ValidatorStatus::InsufficientStake),
            (10, 1, on_shard),
            (11, 1, ValidatorStatus::Pooled),
        ];
        for (id, pool, status) in statuses {
            state
                .validators
                .insert(ValidatorId::new(id), validator_record(id, pool, status));
        }
        for (pool, ids, stake_multiple) in
            [(0u32, vec![0u64, 1, 2, 3], 4u128), (1, vec![10, 11], 2)]
        {
            let pool_id = StakePoolId::new(pool);
            state.pools.insert(
                pool_id,
                StakePool {
                    id: pool_id,
                    total_stake: Stake::from_attos(stake_multiple * MIN_STAKE_FLOOR.attos()),
                    validators: ids.into_iter().map(ValidatorId::new).collect(),
                    pending_withdrawals: Vec::new(),
                    released_cumulative: Stake::ZERO,
                    conviction: None,
                },
            );
        }
        state.next_shard_committees.insert(
            shard,
            ShardCommittee {
                members: vec![ValidatorId::new(0), ValidatorId::new(10)],
            },
        );
        state
    }

    /// The cascade revokes every member whatever its status, stamps the
    /// record from the live `impound_epochs`, tears the placed member
    /// off its committee, and leaves the other pool untouched.
    #[test]
    fn conviction_revokes_every_member_and_spares_other_pools() {
        let mut state = two_pool_state();
        let epoch = state.current_epoch;

        let revoked = convict_pool(&mut state, StakePoolId::new(0), epoch);

        assert_eq!(
            revoked,
            [0u64, 1, 2, 3].map(ValidatorId::new).to_vec(),
            "every status revokes: OnShard, Pooled, Jailed, InsufficientStake",
        );
        for id in [0u64, 1, 2, 3] {
            assert_eq!(
                state.validators[&ValidatorId::new(id)].status,
                ValidatorStatus::Revoked { at_epoch: epoch },
            );
        }
        let conviction = state.pools[&StakePoolId::new(0)]
            .conviction
            .expect("stamped");
        assert_eq!(conviction.convicted_at, epoch);
        assert_eq!(
            conviction.lifts_at,
            Epoch::new(epoch.inner() + state.params.impound_epochs),
        );
        // Validator 0 left the committee; the refill drew from the
        // surviving pool (validator 11, the only Pooled candidate).
        let members = &state.next_shard_committees[&ShardId::leaf(1, 0)].members;
        assert!(!members.contains(&ValidatorId::new(0)));
        assert!(members.contains(&ValidatorId::new(11)));
        // Pool 1 untouched: no conviction, statuses intact.
        assert!(state.pools[&StakePoolId::new(1)].conviction.is_none());
        assert!(matches!(
            state.validators[&ValidatorId::new(10)].status,
            ValidatorStatus::OnShard { .. },
        ));
        // Revoked members stay in the pool's validator set.
        assert_eq!(state.pools[&StakePoolId::new(0)].validators.len(), 4);
    }

    /// A second conviction is a no-op: no re-revocation, and `lifts_at`
    /// never restamps even if the parameter has changed since.
    #[test]
    fn conviction_is_idempotent_and_never_restamps() {
        let mut state = two_pool_state();
        let epoch = state.current_epoch;
        convict_pool(&mut state, StakePoolId::new(0), epoch);
        let stamped = state.pools[&StakePoolId::new(0)].conviction;

        state.params.impound_epochs *= 2;
        let replay = convict_pool(
            &mut state,
            StakePoolId::new(0),
            Epoch::new(epoch.inner() + 5),
        );

        assert!(replay.is_empty());
        assert_eq!(state.pools[&StakePoolId::new(0)].conviction, stamped);
    }

    /// An unknown pool convicts nothing.
    #[test]
    fn conviction_of_unknown_pool_is_a_no_op() {
        let mut state = two_pool_state();
        let epoch = state.current_epoch;
        assert!(convict_pool(&mut state, StakePoolId::new(9), epoch).is_empty());
    }

    /// The impound freezes maturation outright — a withdrawal whose
    /// unbonding window elapsed long ago still waits out the lift —
    /// and afterwards the stake exits whole through the normal path.
    /// `total_stake` moves only at maturation: conviction and the
    /// frozen span leave it byte-identical (nothing is slashed), and
    /// `released_cumulative` plateaus over the impound.
    #[test]
    fn impound_freezes_maturation_and_releases_whole_after_lift() {
        let mut state = two_pool_state();
        state.params.impound_epochs = UNBONDING_WINDOW_EPOCHS;
        let pool_id = StakePoolId::new(0);
        let amount = MIN_STAKE_FLOOR;
        state
            .pools
            .get_mut(&pool_id)
            .unwrap()
            .pending_withdrawals
            .push(PendingWithdrawal {
                amount,
                initiated_at_epoch: Epoch::new(0),
            });
        let epoch = state.current_epoch;
        let total_before = state.pools[&pool_id].total_stake;

        convict_pool(&mut state, pool_id, epoch);
        assert_eq!(state.pools[&pool_id].total_stake, total_before);
        let lifts_at = state.pools[&pool_id].conviction.unwrap().lifts_at;

        // Window long elapsed, impound in force: nothing matures.
        state.current_epoch = Epoch::new(lifts_at.inner() - 1);
        complete_pending_withdrawals(&mut state);
        let pool = &state.pools[&pool_id];
        assert_eq!(pool.total_stake, total_before);
        assert_eq!(pool.released_cumulative, Stake::ZERO);
        assert_eq!(pool.pending_withdrawals.len(), 1);

        // At the lift the frozen withdrawal releases in full.
        state.current_epoch = lifts_at;
        complete_pending_withdrawals(&mut state);
        let pool = &state.pools[&pool_id];
        assert_eq!(pool.total_stake, total_before.saturating_sub(amount));
        assert_eq!(pool.released_cumulative, amount);
        assert!(pool.pending_withdrawals.is_empty());
    }

    /// A convicted pool earns no emissions — it has no ready actives to
    /// key a share off — while live pools keep their full flow.
    #[test]
    fn convicted_pool_earns_no_emissions() {
        let mut state = two_pool_state();
        let epoch = state.current_epoch;
        convict_pool(&mut state, StakePoolId::new(0), epoch);
        let total0 = state.pools[&StakePoolId::new(0)].total_stake;

        let credits = distribute_epoch_rewards(&mut state);

        assert!(!credits.contains_key(&StakePoolId::new(0)));
        assert_eq!(
            credits.get(&StakePoolId::new(1)).copied(),
            Some(EMISSIONS_PER_EPOCH),
        );
        assert_eq!(state.pools[&StakePoolId::new(0)].total_stake, total0);
    }

    /// Conviction drops the pool's standing parameter vote — a vote
    /// recorded earlier in the same fold must not carry impounded
    /// stake into this epoch's tally.
    #[test]
    fn conviction_drops_the_standing_param_vote() {
        let mut state = two_pool_state();
        let epoch = state.current_epoch;
        state.param_votes.insert(
            StakePoolId::new(0),
            ParamProposal {
                params: NetworkParams::default(),
                activate_at: Epoch::new(epoch.inner() + 2),
            },
        );

        convict_pool(&mut state, StakePoolId::new(0), epoch);

        assert!(!state.param_votes.contains_key(&StakePoolId::new(0)));
    }

    /// The reactivation sweep never resurrects a convicted pool's
    /// members: zero actives against standing stake passes the capacity
    /// check, so only the conviction gate holds the line.
    #[test]
    fn convicted_pool_members_never_auto_reactivate() {
        let mut state = two_pool_state();
        let epoch = state.current_epoch;
        convict_pool(&mut state, StakePoolId::new(0), epoch);
        // Force the shape auto_reactivate keys on: an InsufficientStake
        // member of a pool with spare capacity.
        state
            .validators
            .get_mut(&ValidatorId::new(3))
            .unwrap()
            .status = ValidatorStatus::InsufficientStake;

        let reactivated = auto_reactivate(&mut state);

        assert!(reactivated.is_empty());
        assert_eq!(
            state.validators[&ValidatorId::new(3)].status,
            ValidatorStatus::InsufficientStake,
        );
    }
}
