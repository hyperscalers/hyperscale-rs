//! Pool-draw glue: pick one validator from the global `Pooled` set and
//! place them on a shard.

use hyperscale_types::{BeaconState, ShardGroupId, ValidatorId, ValidatorStatus};

use crate::sampling::draw_from_pool;
use crate::state::derived::pooled_validators;

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
pub fn pool_draw(state: &mut BeaconState, shard: ShardGroupId) -> Option<ValidatorId> {
    let pool = pooled_validators(state);
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
        .shard_committees
        .entry(shard)
        .or_default()
        .members
        .push(chosen);
    Some(chosen)
}
