//! The per-peer stream pools' backoff maps.
//!
//! Both the request streams and the notify actors gate reopening a stream
//! to a peer on [`StreamBackoff`], the policy every transport shares; this
//! module holds it in the concurrent maps they share, on the wall clock.

use std::hash::Hash;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use hyperscale_network::stream_backoff::{StreamBackoff, StreamFailure};

/// Per-key backoff state. Callers store this in a `DashMap` keyed by
/// whatever identifies the stream's target (peer and class for the notify
/// pool, peer and shard for requests) and clear the entry on a successful
/// open to reset the series.
pub type BackoffState = StreamBackoff<Instant>;

/// Apply (or escalate) backoff for `key` after `failure`, replacing any
/// existing entry.
pub fn apply_backoff<K>(backoff_map: &DashMap<K, BackoffState>, key: &K, failure: StreamFailure)
where
    K: Eq + Hash + Clone,
{
    let now = Instant::now();
    let state = BackoffState::after(backoff_map.get(key).as_deref(), failure, now);
    backoff_map.insert(key.clone(), state);
}

/// How much longer `key`'s stream stays in backoff, or `None` when it is
/// usable now.
pub fn backed_off_for<K>(backoff_map: &DashMap<K, BackoffState>, key: &K) -> Option<Duration>
where
    K: Eq + Hash,
{
    backoff_map
        .get(key)
        .and_then(|state| state.held_for(Instant::now()))
}

#[cfg(test)]
mod tests {
    use hyperscale_network::stream_backoff::{BACKOFF_MULTIPLIER, INITIAL_BACKOFF};
    use iroh::{EndpointId, SecretKey};

    use super::*;

    fn random_peer() -> EndpointId {
        SecretKey::generate().public()
    }

    #[test]
    fn the_first_failure_backs_the_peer_off_from_now() {
        let map = DashMap::new();
        let peer = random_peer();
        let before = Instant::now();
        apply_backoff(&map, &peer, StreamFailure::Transient);
        let next_attempt = map.get(&peer).unwrap().next_attempt();
        assert!(next_attempt >= before + INITIAL_BACKOFF);
        assert!(next_attempt <= Instant::now() + INITIAL_BACKOFF);
        assert!(backed_off_for(&map, &peer).is_some_and(|left| left <= INITIAL_BACKOFF));
    }

    #[test]
    fn a_lapsed_entry_no_longer_backs_off() {
        let map = DashMap::new();
        let peer = random_peer();
        let lapsed = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        map.insert(
            peer,
            BackoffState::after(None, StreamFailure::Transient, lapsed),
        );
        assert_eq!(backed_off_for(&map, &peer), None);
    }

    #[test]
    fn isolates_per_peer() {
        let map = DashMap::new();
        let a = random_peer();
        let b = random_peer();

        apply_backoff(&map, &a, StreamFailure::Transient);
        apply_backoff(&map, &a, StreamFailure::Transient);
        apply_backoff(&map, &b, StreamFailure::Transient);

        assert_eq!(
            map.get(&a).unwrap().current(),
            INITIAL_BACKOFF * BACKOFF_MULTIPLIER
        );
        assert_eq!(map.get(&b).unwrap().current(), INITIAL_BACKOFF);
    }
}
