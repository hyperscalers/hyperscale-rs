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
        BeaconState, Epoch, JailReason, MIN_STAKE_FLOOR, ShardCommittee, ShardId, Stake, StakePool,
        ValidatorId,
    };

    use super::*;
    use crate::state::lifecycle::auto_reactivate;
    use crate::state::test_fixtures::{empty_state, validator_record};

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
