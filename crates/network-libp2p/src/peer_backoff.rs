//! Shared exponential backoff for per-peer stream pools.
//!
//! Both [`RequestStreamPool`] and [`NotifyStreamPool`] gate reconnection
//! attempts to a peer with the same exponential backoff policy: 100ms
//! initial, doubling on each failure, capped at 5s. Centralising the policy
//! here keeps the two pools in lock step — when these constants lived in
//! both modules they could drift silently.
//!
//! [`RequestStreamPool`]: crate::RequestStreamPool
//! [`NotifyStreamPool`]: crate::notify_pool

use std::hash::Hash;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Initial reconnection backoff after the first stream failure.
pub const INITIAL_BACKOFF: Duration = Duration::from_millis(100);

/// Maximum reconnection backoff (cap for the geometric series).
pub const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Multiplier applied on each consecutive failure.
pub const BACKOFF_MULTIPLIER: u32 = 2;

/// Per-key backoff state. Callers store this in a `DashMap` keyed by
/// whatever identifies the connection target (`PeerId` for the notify
/// pool, `(PeerId, ShardId)` for the per-shard request pool) and
/// clear the entry on successful reconnect to reset the series.
pub struct BackoffState {
    pub next_attempt: Instant,
    pub current_backoff: Duration,
}

/// Apply (or escalate) backoff for `key`. The first call sets
/// [`INITIAL_BACKOFF`]; subsequent calls double the previous duration up to
/// [`MAX_BACKOFF`]. Replaces any existing entry.
pub fn apply_backoff<K>(backoff_map: &DashMap<K, BackoffState>, key: &K)
where
    K: Eq + Hash + Clone,
{
    let current_backoff = backoff_map.get(key).map_or(INITIAL_BACKOFF, |state| {
        (state.current_backoff * BACKOFF_MULTIPLIER).min(MAX_BACKOFF)
    });

    backoff_map.insert(
        key.clone(),
        BackoffState {
            next_attempt: Instant::now() + current_backoff,
            current_backoff,
        },
    );
}

#[cfg(test)]
mod tests {
    use libp2p::PeerId;

    use super::*;

    /// Snapshot the backoff entry's `(current_backoff, scheduled_delay)`
    /// where `scheduled_delay = next_attempt - sample_instant`. The instant
    /// is captured before reading the entry so the delay reflects the value
    /// `apply_backoff` set, not whatever has elapsed since.
    fn snapshot(map: &DashMap<PeerId, BackoffState>, peer: &PeerId) -> (Duration, Duration) {
        let sampled_at = Instant::now();
        let entry = map.get(peer).expect("backoff state inserted");
        let scheduled = entry.next_attempt.saturating_duration_since(sampled_at);
        (entry.current_backoff, scheduled)
    }

    #[tokio::test]
    async fn first_failure_schedules_initial_delay() {
        let map = DashMap::new();
        let peer = PeerId::random();
        let before = Instant::now();
        apply_backoff(&map, &peer);
        let (current, scheduled) = snapshot(&map, &peer);

        assert_eq!(current, INITIAL_BACKOFF);

        // next_attempt should be (apply-time + INITIAL_BACKOFF). Apply-time
        // sits between `before` and `now()`, so scheduled lands within
        // [INITIAL_BACKOFF - elapsed, INITIAL_BACKOFF]. The lower bound
        // catches a regression like `next_attempt = Instant::now()` (no
        // backoff at all).
        let max_elapsed = before.elapsed();
        assert!(
            scheduled <= INITIAL_BACKOFF,
            "scheduled {scheduled:?} exceeds INITIAL_BACKOFF {INITIAL_BACKOFF:?}"
        );
        assert!(
            scheduled + max_elapsed >= INITIAL_BACKOFF,
            "scheduled {scheduled:?} + elapsed {max_elapsed:?} < INITIAL_BACKOFF {INITIAL_BACKOFF:?} \
             — looks like backoff wasn't applied"
        );
    }

    #[tokio::test]
    async fn doubles_then_caps_at_max() {
        let map = DashMap::new();
        let peer = PeerId::random();

        // Walk the geometric series and assert each step matches the formula
        // exactly until it saturates. This catches off-by-one (cap reached
        // one step early/late) and stuck-at-initial regressions.
        let mut expected = INITIAL_BACKOFF;
        let mut steps = 0;
        loop {
            apply_backoff(&map, &peer);
            steps += 1;
            assert_eq!(
                map.get(&peer).unwrap().current_backoff,
                expected,
                "step {steps}: expected {expected:?}"
            );
            if expected == MAX_BACKOFF {
                break;
            }
            expected = (expected * BACKOFF_MULTIPLIER).min(MAX_BACKOFF);
            assert!(steps < 32, "backoff failed to saturate within 32 steps");
        }

        // Further failures stay pinned at MAX_BACKOFF, not above.
        for _ in 0..3 {
            apply_backoff(&map, &peer);
            assert_eq!(map.get(&peer).unwrap().current_backoff, MAX_BACKOFF);
        }
    }

    #[tokio::test]
    async fn isolates_per_peer() {
        let map = DashMap::new();
        let a = PeerId::random();
        let b = PeerId::random();

        apply_backoff(&map, &a);
        apply_backoff(&map, &a);
        apply_backoff(&map, &b);

        assert_eq!(
            map.get(&a).unwrap().current_backoff,
            INITIAL_BACKOFF * BACKOFF_MULTIPLIER
        );
        assert_eq!(map.get(&b).unwrap().current_backoff, INITIAL_BACKOFF);
    }
}
