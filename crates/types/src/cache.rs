//! Bounded concurrent caches whose eviction is a function of their inputs.
//!
//! A [`BoundedCache`] picks its eviction victim from the key's hash and
//! the shard it lands in, so both are pinned here rather than left to
//! the cache library's defaults: a random per-process hasher and a shard
//! count derived from the machine's core count would make which entry a
//! full cache drops differ between two runs of the same simulation.
//!
//! Hashing is random per process unless [`pin_hashing`] has run, which
//! the simulation does before it builds any host. A production node
//! keeps random keys, so a peer cannot grind keys that collide inside
//! one shard of its caches.

use std::collections::hash_map::{DefaultHasher, RandomState};
use std::hash::{BuildHasher, Hash};
use std::sync::atomic::{AtomicBool, Ordering};

use quick_cache::sync::{Cache, DefaultLifecycle};
pub use quick_cache::sync::{EntryAction, EntryResult};
use quick_cache::{OptionsBuilder, UnitWeighter};

/// Shard count for every cache, fixed so eviction does not depend on
/// the host's core count.
const SHARDS: usize = 64;

static PINNED: AtomicBool = AtomicBool::new(false);

/// Make every cache built after this call hash with fixed keys. Called
/// by the simulation before it builds any host; a production build has
/// no way to call it.
#[cfg(any(test, feature = "test-utils"))]
pub fn pin_hashing() {
    PINNED.store(true, Ordering::Relaxed);
}

/// Hash state for a [`BoundedCache`]: std's hasher, randomly keyed per
/// cache unless [`pin_hashing`] has run.
#[derive(Clone, Debug)]
pub enum CacheHashState {
    /// Keys drawn per cache from the process's random source.
    Random(RandomState),
    /// std's fixed hasher keys, identical in every process.
    Pinned,
}

impl BuildHasher for CacheHashState {
    type Hasher = DefaultHasher;

    fn build_hasher(&self) -> DefaultHasher {
        match self {
            Self::Random(state) => state.build_hasher(),
            Self::Pinned => DefaultHasher::new(),
        }
    }
}

/// A concurrent cache holding up to a fixed number of entries.
pub type BoundedCache<K, V> = Cache<K, V, UnitWeighter, CacheHashState, DefaultLifecycle<K, V>>;

/// A cache holding roughly `capacity` entries.
///
/// # Panics
///
/// Never: the options it builds are always valid.
#[must_use]
pub fn bounded_cache<K: Eq + Hash, V: Clone>(capacity: usize) -> BoundedCache<K, V> {
    let hash_state = if PINNED.load(Ordering::Relaxed) {
        CacheHashState::Pinned
    } else {
        CacheHashState::Random(RandomState::new())
    };
    let options = OptionsBuilder::new()
        .estimated_items_capacity(capacity)
        .weight_capacity(capacity as u64)
        .shards(SHARDS)
        .build()
        .expect("capacity and shard count are always valid options");
    Cache::with_options(
        options,
        UnitWeighter,
        hash_state,
        DefaultLifecycle::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_hashing_is_the_same_across_caches() {
        let a = CacheHashState::Pinned;
        let b = CacheHashState::Pinned;
        assert_eq!(a.hash_one(42u64), b.hash_one(42u64));
    }

    #[test]
    fn a_cache_holds_what_it_was_given() {
        let cache: BoundedCache<u64, u64> = bounded_cache(128);
        cache.insert(1, 10);
        assert_eq!(cache.get(&1), Some(10));
    }
}
