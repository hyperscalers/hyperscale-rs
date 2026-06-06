//! Deterministic committee sampling and pool-draw primitives.
//!
//! Pure functions. Both operations are seeded from a 32-byte randomness
//! digest (the running [`BeaconState`] randomness in production, mixed
//! from VRF reveals each epoch). The PRNG is `ChaCha20Rng` — a
//! cryptographically uniform 32-byte-seeded stream, so unbiased bounded
//! draws need no hand-rolled rejection sampling.
//!
//! `BeaconState` glue (eligibility filters, state mutation) lives in
//! `crate::state` and calls these primitives.
//!
//! [`BeaconState`]: crate::state::BeaconState

use blake3::Hasher;
use hyperscale_types::{Epoch, ShardId, ValidatorId};
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Domain tag for the pool-draw seed. Binds the draw to "beacon
/// pool-draw v1" so PRNG output never collides with other beacon
/// randomness-derived draws (committee sampling uses
/// `state.randomness` directly with no domain tag — that's the
/// canonical untagged usage).
const POOL_DRAW_DOMAIN: &[u8] = b"hyperscale-pool-draw-v1";

/// Seed `ChaCha20Rng` from a 32-byte randomness digest. Public so the
/// state layer can derive purpose-bound seeds (committee draw,
/// pool draw, future per-shard randomness) the same way.
#[must_use]
pub fn prng_from(seed: &[u8; 32]) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(*seed)
}

/// Sample a beacon committee of up to `committee_size` from `eligible`,
/// seeded by `randomness`. Returns sorted validator ids for
/// deterministic hashing downstream.
///
/// Caller is responsible for filtering `eligible` to the right set
/// (e.g. `OnShard { ready: true }` under the current eligibility rule).
#[must_use]
pub fn sample_committee(
    eligible: &[ValidatorId],
    randomness: &[u8; 32],
    committee_size: usize,
) -> Vec<ValidatorId> {
    if eligible.len() <= committee_size {
        let mut out = eligible.to_vec();
        out.sort();
        return out;
    }

    // Deterministic Fisher–Yates seeded from beacon randomness.
    // ChaCha20 + `random_range` gives unbiased bounded draws.
    let mut prng = prng_from(randomness);
    let mut shuffled = eligible.to_vec();
    let n = shuffled.len();
    for i in (1..n).rev() {
        let j = prng.random_range(0..=i);
        shuffled.swap(i, j);
    }
    shuffled.truncate(committee_size);
    shuffled.sort();
    shuffled
}

/// Pick one validator from `pool` for placement on `shard` at `epoch`.
///
/// Uses `randomness` blended with `(epoch, shard)` so draws across
/// shards in an epoch and across epochs on one shard don't share a PRNG
/// stream. Returns `None` if the pool is empty.
///
/// Pure: the caller mutates `BeaconState` based on the returned id.
/// Re-calling on the same `(pool, randomness, epoch, shard)` returns
/// the same validator; callers that need multiple distinct picks
/// from the same `(epoch, shard)` must remove each pick from the pool
/// before the next call.
#[must_use]
pub fn draw_from_pool(
    pool: &[ValidatorId],
    randomness: &[u8; 32],
    epoch: Epoch,
    shard: ShardId,
) -> Option<ValidatorId> {
    if pool.is_empty() {
        return None;
    }

    let mut h = Hasher::new();
    h.update(POOL_DRAW_DOMAIN);
    h.update(randomness);
    h.update(&epoch.inner().to_le_bytes());
    h.update(&shard.inner().to_le_bytes());
    let seed = *h.finalize().as_bytes();

    let mut prng = prng_from(&seed);
    let idx = prng.random_range(0..pool.len());
    Some(pool[idx])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(range: std::ops::Range<u64>) -> Vec<ValidatorId> {
        range.map(ValidatorId::new).collect()
    }

    #[test]
    fn sample_committee_returns_all_when_eligible_fits() {
        let eligible = ids(0..4);
        let out = sample_committee(&eligible, &[0u8; 32], 8);
        assert_eq!(out.len(), 4);
        // Result is sorted regardless of input order.
        let mut expected = eligible;
        expected.sort();
        assert_eq!(out, expected);
    }

    #[test]
    fn sample_committee_deterministic_for_same_seed() {
        let eligible = ids(0..16);
        let a = sample_committee(&eligible, &[0xDE; 32], 4);
        let b = sample_committee(&eligible, &[0xDE; 32], 4);
        assert_eq!(a, b);
        assert_eq!(a.len(), 4);
    }

    #[test]
    fn sample_committee_differs_across_seeds() {
        // Different randomness must (with overwhelming probability for
        // a 16-element eligible set and committee of 4) produce
        // different committees.
        let eligible = ids(0..16);
        let a = sample_committee(&eligible, &[0xDE; 32], 4);
        let b = sample_committee(&eligible, &[0xCA; 32], 4);
        assert_ne!(a, b);
    }

    #[test]
    fn sample_committee_output_is_sorted() {
        let eligible = ids(0..16);
        let out = sample_committee(&eligible, &[0x42; 32], 5);
        let mut sorted = out.clone();
        sorted.sort();
        assert_eq!(out, sorted);
    }

    #[test]
    fn draw_from_pool_returns_none_when_empty() {
        assert_eq!(
            draw_from_pool(&[], &[0u8; 32], Epoch::new(1), ShardId::leaf(1, 0)),
            None
        );
    }

    #[test]
    fn draw_from_pool_deterministic_for_same_inputs() {
        let pool = ids(0..8);
        let a = draw_from_pool(&pool, &[0x5A; 32], Epoch::new(7), ShardId::leaf(1, 0));
        let b = draw_from_pool(&pool, &[0x5A; 32], Epoch::new(7), ShardId::leaf(1, 0));
        assert_eq!(a, b);
        assert!(a.is_some());
    }

    /// Same `(pool, randomness, epoch)` but different shards must use
    /// distinct PRNG streams. Across many randomness values at least
    /// one pair must differ — if the shard id were collapsed out of
    /// the seed, no pair would ever differ.
    #[test]
    fn draw_from_pool_across_shards_uses_distinct_seeds() {
        let pool = ids(0..8);
        let any_differ = (0u8..16).any(|i| {
            let a = draw_from_pool(&pool, &[i; 32], Epoch::new(5), ShardId::leaf(1, 0));
            let b = draw_from_pool(&pool, &[i; 32], Epoch::new(5), ShardId::leaf(1, 1));
            a != b
        });
        assert!(any_differ);
    }

    /// Same `(pool, randomness, shard)` but different slots must use
    /// distinct PRNG streams. Same logic as the across-shards test.
    #[test]
    fn draw_from_pool_across_slots_uses_distinct_seeds() {
        let pool = ids(0..8);
        let any_differ = (0u8..16).any(|i| {
            let a = draw_from_pool(&pool, &[i; 32], Epoch::new(5), ShardId::leaf(1, 0));
            let b = draw_from_pool(&pool, &[i; 32], Epoch::new(6), ShardId::leaf(1, 0));
            a != b
        });
        assert!(any_differ);
    }
}
