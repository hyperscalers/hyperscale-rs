//! Pool-draw glue: pick one validator from the global `Pooled` set and
//! place them on a shard, plus the inverse [`exit_placement`] cascade
//! that tears a validator off their shard placement.

use hyperscale_types::{BeaconState, PendingReshape, ShardId, ValidatorId, ValidatorStatus};

use crate::sampling::draw_from_pool;

/// Draw one validator from the global pool and place them on `shard`
/// as `OnShard { ready: false, placed_at_epoch: state.current_epoch }`.
///
/// Returns the chosen validator id, or `None` when the pool is empty
/// (the epoch stays open and refills on the next pool draw against a
/// non-empty pool).
///
/// The pool is derived per-call via [`pooled_validators`] rather than
/// stored. Seeding binds to `(state.randomness, state.current_epoch,
/// shard)` so draws across shards within one epoch — and across slots
/// on one shard — use distinct PRNG streams.
///
/// Multiple draws on the same `(epoch, shard)` re-seed with the same
/// bytes, but each subsequent call sees a strictly smaller derived
/// pool: the previously-chosen validator's status is now `OnShard`,
/// excluding them from the next call's `pooled_validators`. Picks
/// remain distinct even when the raw PRNG index collides.
///
/// # Panics
///
/// Panics if the chosen validator id (which came from
/// [`pooled_validators`] filtering `state.validators` immediately
/// above) is absent from `state.validators`. Structurally
/// unreachable.
pub fn pool_draw(state: &mut BeaconState, shard: ShardId) -> Option<ValidatorId> {
    let pool = state.pooled_validators();
    let chosen = draw_from_pool(
        &pool,
        state.randomness.as_bytes(),
        state.current_epoch,
        shard,
    )?;
    state
        .validators
        .get_mut(&chosen)
        .expect("chosen comes from the derived pool, must be in validators")
        .status = ValidatorStatus::OnShard {
        shard,
        ready: false,
        placed_at_epoch: state.current_epoch,
    };
    state
        .next_shard_committees
        .entry(shard)
        .or_default()
        .members
        .push(chosen);
    Some(chosen)
}

/// Clean up after a validator leaves its prior placement: drop the
/// per-placement [`BeaconState::miss_counters`] entry and, when they
/// were `OnShard`, remove them from that shard's committee and draw a
/// pool refill onto it via [`pool_draw`].
///
/// The caller writes the validator's new status first and passes the
/// status it held immediately before as `prior`. An `OnShard`
/// validator on a merging child also sheds any keeper seat it holds
/// on the parent's pending merge — the merge absorbs the attrition
/// like a split cohort does (execution gate, staleness cancel,
/// readiness TTL), and a stale seat must never count toward the merge
/// quorum or reach the keeper move. An `Observing`
/// validator leaves the committee and sheds its cohort seat instead —
/// with no refill, since a cohort seat is not a committee slot;
/// attrition is absorbed by the execution gate, the staleness cancel,
/// or the readiness TTL. A validator that was neither only sheds its
/// (already-absent) miss counter, leaving committees untouched. The
/// miss-counter clear and the refill are independent — `pool_draw`
/// never reads `miss_counters` — so the caller-visible order between
/// them doesn't matter.
pub(super) fn exit_placement(
    state: &mut BeaconState,
    validator: ValidatorId,
    prior: ValidatorStatus,
) {
    state.miss_counters.remove(&validator);
    match prior {
        ValidatorStatus::OnShard { shard, .. } => {
            if let Some(committee) = state.next_shard_committees.get_mut(&shard) {
                committee.members.retain(|v| *v != validator);
            }
            if let Some(parent) = shard.parent()
                && let Some(PendingReshape::Merge { keepers, .. }) =
                    state.pending_reshapes.get_mut(&parent)
            {
                keepers.remove(&validator);
            }
            pool_draw(state, shard);
        }
        ValidatorStatus::Observing { shard, .. } => {
            if let Some(committee) = state.next_shard_committees.get_mut(&shard) {
                committee.members.retain(|v| *v != validator);
            }
            if let Some(PendingReshape::Split { cohort, .. }) =
                state.pending_reshapes.get_mut(&shard)
            {
                cohort.remove(&validator);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_types::{
        BeaconState, Epoch, MIN_STAKE_FLOOR, Randomness, ShardCommittee, ShardId, Stake, StakePool,
        StakePoolId, ValidatorId, ValidatorStatus,
    };

    use super::*;
    use crate::state::test_fixtures::{empty_state, validator_record};

    // ─── pool_draw ───────────────────────────────────────────────────────

    /// Build a state with `n` validators all sitting in the global pool
    /// (status `Pooled`), one empty shard, and the given randomness +
    /// `current_epoch`. `pool_draw` reads `state.randomness` and
    /// `state.current_epoch` so the caller sets them up explicitly.
    fn state_with_pool(n: u64, randomness: Randomness, current_epoch: Epoch) -> BeaconState {
        let mut state = empty_state();
        state.current_epoch = current_epoch;
        state.randomness = randomness;
        let pool_id = StakePoolId::new(0);
        let mut pool_validators = BTreeSet::new();
        for i in 0..n {
            let id = ValidatorId::new(i);
            pool_validators.insert(id);
            state
                .validators
                .insert(id, validator_record(i, 0, ValidatorStatus::Pooled));
        }
        state.pools.insert(
            pool_id,
            StakePool {
                id: pool_id,
                total_stake: Stake::from_attos(u128::from(n) * MIN_STAKE_FLOOR.attos()),
                validators: pool_validators,
                pending_withdrawals: Vec::new(),
            },
        );
        state
            .next_shard_committees
            .insert(ShardId::leaf(1, 0), ShardCommittee::default());
        state
    }

    #[test]
    fn pool_draw_returns_none_when_pool_empty() {
        let mut state = empty_state();
        state
            .next_shard_committees
            .insert(ShardId::leaf(1, 0), ShardCommittee::default());
        assert_eq!(pool_draw(&mut state, ShardId::leaf(1, 0)), None);
        assert!(
            state.next_shard_committees[&ShardId::leaf(1, 0)]
                .members
                .is_empty()
        );
    }

    /// Two states built from byte-identical inputs must produce the
    /// same pick. Determinism is what lets every honest replica
    /// converge after a pool-draw event.
    #[test]
    fn pool_draw_is_deterministic_across_replicas() {
        let mut a = state_with_pool(8, Randomness::new([0x5A; 32]), Epoch::new(1));
        let mut b = state_with_pool(8, Randomness::new([0x5A; 32]), Epoch::new(1));
        let pick_a = pool_draw(&mut a, ShardId::leaf(1, 0)).unwrap();
        let pick_b = pool_draw(&mut b, ShardId::leaf(1, 0)).unwrap();
        assert_eq!(pick_a, pick_b);
        assert_eq!(a.next_shard_committees, b.next_shard_committees);
        assert_eq!(a.pooled_validators(), b.pooled_validators());
    }

    /// Two draws at the same `(epoch, shard)` pick distinct validators
    /// even though the PRNG seed re-derives identically. The first
    /// draw flips its chosen validator to `OnShard`; the second draw's
    /// `pooled_validators` re-derivation excludes them, so the second
    /// draw indexes into a strictly smaller pool of different members.
    #[test]
    fn pool_draw_two_calls_same_slot_shard_pick_distinct_validators() {
        let mut state = state_with_pool(8, Randomness::new([0x42; 32]), Epoch::new(1));
        let first = pool_draw(&mut state, ShardId::leaf(1, 0)).unwrap();
        let second = pool_draw(&mut state, ShardId::leaf(1, 0)).unwrap();
        assert_ne!(first, second);
        let members = &state.next_shard_committees[&ShardId::leaf(1, 0)].members;
        assert_eq!(members.len(), 2);
        assert!(members.contains(&first));
        assert!(members.contains(&second));
        assert_eq!(state.pooled_validators().len(), 8 - 2);
    }

    /// Chosen validator transitions to `OnShard { ready: false }` with
    /// `placed_at_epoch` set to `state.current_epoch`.
    #[test]
    fn pool_draw_places_chosen_validator_with_current_epoch() {
        let placed_epoch = Epoch::new(5);
        let mut state = state_with_pool(4, Randomness::new([0x99; 32]), placed_epoch);
        let chosen = pool_draw(&mut state, ShardId::leaf(1, 0)).unwrap();
        let status = state.validators.get(&chosen).unwrap().status;
        assert_eq!(
            status,
            ValidatorStatus::OnShard {
                shard: ShardId::leaf(1, 0),
                ready: false,
                placed_at_epoch: placed_epoch,
            },
        );
    }

    /// Different shards within the same `(state, epoch)` use distinct
    /// PRNG streams. Across multiple randomness values at least one
    /// pair must differ — if the shard id were collapsed out of the
    /// seed, no pair would ever differ.
    #[test]
    fn pool_draw_across_shards_uses_distinct_seeds() {
        let any_differ = (0u8..16).any(|i| {
            let mut a = state_with_pool(8, Randomness::new([i; 32]), Epoch::GENESIS);
            // Add a second shard so the draw target exists.
            a.next_shard_committees
                .insert(ShardId::leaf(1, 1), ShardCommittee::default());
            let mut b = a.clone();
            let pick_a = pool_draw(&mut a, ShardId::leaf(1, 0)).unwrap();
            let pick_b = pool_draw(&mut b, ShardId::leaf(1, 1)).unwrap();
            pick_a != pick_b
        });
        assert!(any_differ);
    }
}
