//! Scope-keyed bundle fetch state machine.
//!
//! One in-flight slot per scope. The scope itself encodes everything the
//! responder needs (e.g. `(ShardGroupId, BlockHeight)` for a header fetch);
//! the protocol is payload-agnostic and only tracks rotation, retries, and
//! admission.
//!
//! Admission is the only completion signal: when the payload for a scope
//! lands via *any* path (fetch response, gossip, local production), the
//! caller emits [`ScopeFetchInput::Admitted`] and the protocol drops the
//! entry.

use super::peer_rotator::PeerRotator;
use super::slot_tracker::SlotTracker;
use hyperscale_types::ValidatorId;
use std::collections::BTreeMap;
use std::hash::Hash;
use std::time::Instant;
use tracing::{debug, trace};

/// Tunables for a `ScopeFetch` instance.
#[derive(Debug, Clone)]
pub struct ScopeFetchConfig {
    /// Maximum in-flight network requests at any time.
    pub max_concurrent: usize,
}

impl Default for ScopeFetchConfig {
    fn default() -> Self {
        Self { max_concurrent: 4 }
    }
}

/// Inputs to the protocol state machine.
#[derive(Debug)]
pub enum ScopeFetchInput<S> {
    /// Caller wants the bundle for `scope`. Idempotent: a duplicate request
    /// refreshes the peer pool and resets the rotation.
    Request { scope: S, peers: Vec<ValidatorId> },
    /// A network attempt for `scope` failed; rotate to the next peer on the
    /// next tick.
    Failed { scope: S },
    /// The payload for `scope` is no longer needed (it landed via fetch
    /// response, gossip, or any other path). Drops the entry. No-op for
    /// unknown scopes.
    Admitted { scope: S },
    /// Drive pending fetches: spawn requests up to `max_concurrent`, honour
    /// per-entry backoff.
    Tick { now: Instant },
}

/// Outputs from the protocol state machine.
#[derive(Debug)]
pub enum ScopeFetchOutput<S> {
    /// The runner should issue a network request for `scope` to `peer`.
    /// Translation to a wire request type is the caller's responsibility.
    Send { scope: S, peer: ValidatorId },
}

#[derive(Debug)]
struct ScopeEntry {
    rotator: PeerRotator,
}

/// Scope-keyed bundle fetch state machine.
#[derive(Debug)]
pub struct ScopeFetch<S: Eq + Hash + Ord + Clone> {
    pending: BTreeMap<S, ScopeEntry>,
    in_flight: SlotTracker<S>,
}

impl<S: Eq + Hash + Ord + Clone + std::fmt::Debug> ScopeFetch<S> {
    /// Create a new protocol instance with the given config.
    #[must_use]
    pub fn new(config: &ScopeFetchConfig) -> Self {
        Self {
            pending: BTreeMap::new(),
            in_flight: SlotTracker::new(config.max_concurrent),
        }
    }

    /// Process an input and return outputs.
    pub fn handle(&mut self, input: ScopeFetchInput<S>) -> Vec<ScopeFetchOutput<S>> {
        match input {
            ScopeFetchInput::Request { scope, peers } => self.handle_request(scope, peers),
            ScopeFetchInput::Failed { scope } => self.handle_failed(&scope),
            ScopeFetchInput::Admitted { scope } => self.handle_admitted(&scope),
            ScopeFetchInput::Tick { now } => self.spawn_pending_fetches(now),
        }
    }

    /// Whether any scope is currently pending or in flight.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Number of scopes with an in-flight network request.
    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.in_flight()
    }

    /// Number of scopes currently tracked (in-flight or awaiting a slot).
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Drop every scope for which `is_stale` returns `true`. Called by the
    /// instance from the tick handler with whatever state-machine read is
    /// relevant (committed height, etc.).
    pub fn evict_stale<F>(&mut self, mut is_stale: F)
    where
        F: FnMut(&S) -> bool,
    {
        self.pending.retain(|s, _| !is_stale(s));
        self.in_flight.retain(|s| !is_stale(s));
    }

    fn handle_request(&mut self, scope: S, peers: Vec<ValidatorId>) -> Vec<ScopeFetchOutput<S>> {
        if let Some(entry) = self.pending.get_mut(&scope) {
            entry.rotator.refresh(peers);
            trace!(?scope, "Refreshed peer list for pending scope fetch");
            return vec![];
        }

        debug!(?scope, peer_count = peers.len(), "Starting scope fetch");
        self.pending.insert(
            scope,
            ScopeEntry {
                rotator: PeerRotator::new(peers),
            },
        );
        vec![]
    }

    fn handle_failed(&mut self, scope: &S) -> Vec<ScopeFetchOutput<S>> {
        if self.in_flight.release(scope) {
            trace!(?scope, "Scope fetch attempt failed, will rotate");
        }
        vec![]
    }

    fn handle_admitted(&mut self, scope: &S) -> Vec<ScopeFetchOutput<S>> {
        let was_tracked = self.pending.remove(scope).is_some();
        self.in_flight.release(scope);
        if was_tracked {
            debug!(?scope, "Scope fetch admitted");
        }
        vec![]
    }

    fn spawn_pending_fetches(&mut self, now: Instant) -> Vec<ScopeFetchOutput<S>> {
        let mut outputs = Vec::new();

        for (scope, entry) in &mut self.pending {
            if !self.in_flight.has_capacity() {
                break;
            }
            if self.in_flight.contains(scope) {
                continue;
            }
            let Some(peer) = entry.rotator.next(now) else {
                continue;
            };

            self.in_flight.try_acquire(scope.clone());
            trace!(?scope, peer = peer.0, "Sending scope fetch");
            outputs.push(ScopeFetchOutput::Send {
                scope: scope.clone(),
                peer,
            });
        }

        outputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{BlockHeight, ShardGroupId};
    use std::time::Duration;

    type Scope = (ShardGroupId, BlockHeight);

    fn scope(s: u64, h: u64) -> Scope {
        (ShardGroupId(s), BlockHeight(h))
    }

    fn vid(n: u64) -> ValidatorId {
        ValidatorId(n)
    }

    fn config() -> ScopeFetchConfig {
        ScopeFetchConfig { max_concurrent: 4 }
    }

    #[test]
    fn request_then_tick_emits_send() {
        let mut p = ScopeFetch::<Scope>::new(&config());
        p.handle(ScopeFetchInput::Request {
            scope: scope(1, 10),
            peers: vec![vid(1), vid(2)],
        });
        let out = p.handle(ScopeFetchInput::Tick {
            now: Instant::now(),
        });
        assert_eq!(out.len(), 1);
        match &out[0] {
            ScopeFetchOutput::Send { scope: s, peer } => {
                assert_eq!(*s, scope(1, 10));
                assert_eq!(*peer, vid(1));
            }
        }
        assert_eq!(p.in_flight_count(), 1);
    }

    #[test]
    fn failed_releases_slot_and_rotates_next_tick() {
        let mut p = ScopeFetch::<Scope>::new(&config());
        p.handle(ScopeFetchInput::Request {
            scope: scope(1, 10),
            peers: vec![vid(1), vid(2)],
        });
        p.handle(ScopeFetchInput::Tick {
            now: Instant::now(),
        });
        p.handle(ScopeFetchInput::Failed {
            scope: scope(1, 10),
        });
        assert_eq!(p.in_flight_count(), 0);

        let out = p.handle(ScopeFetchInput::Tick {
            now: Instant::now(),
        });
        assert!(matches!(
            out.first(),
            Some(ScopeFetchOutput::Send { peer, .. }) if *peer == vid(2)
        ));
    }

    #[test]
    fn admitted_drops_entry() {
        let mut p = ScopeFetch::<Scope>::new(&config());
        p.handle(ScopeFetchInput::Request {
            scope: scope(1, 10),
            peers: vec![vid(1)],
        });
        p.handle(ScopeFetchInput::Tick {
            now: Instant::now(),
        });
        assert!(p.has_pending());

        p.handle(ScopeFetchInput::Admitted {
            scope: scope(1, 10),
        });
        assert!(!p.has_pending());
        assert_eq!(p.in_flight_count(), 0);
    }

    #[test]
    fn admitted_unknown_scope_is_silent_noop() {
        let mut p = ScopeFetch::<Scope>::new(&config());
        p.handle(ScopeFetchInput::Admitted {
            scope: scope(7, 99),
        });
        assert!(!p.has_pending());
    }

    #[test]
    fn duplicate_request_refreshes_peers() {
        let mut p = ScopeFetch::<Scope>::new(&config());
        p.handle(ScopeFetchInput::Request {
            scope: scope(1, 10),
            peers: vec![vid(1)],
        });
        p.handle(ScopeFetchInput::Tick {
            now: Instant::now(),
        });
        p.handle(ScopeFetchInput::Failed {
            scope: scope(1, 10),
        });

        // Refresh: peer pool now includes vid(2). Rotation resets.
        p.handle(ScopeFetchInput::Request {
            scope: scope(1, 10),
            peers: vec![vid(2)],
        });
        let out = p.handle(ScopeFetchInput::Tick {
            now: Instant::now(),
        });
        assert!(matches!(
            out.first(),
            Some(ScopeFetchOutput::Send { peer, .. }) if *peer == vid(2)
        ));
    }

    #[test]
    fn max_concurrent_bounds_in_flight() {
        let mut p = ScopeFetch::<Scope>::new(&ScopeFetchConfig { max_concurrent: 2 });
        for h in 10..15 {
            p.handle(ScopeFetchInput::Request {
                scope: scope(1, h),
                peers: vec![vid(1)],
            });
        }
        let out = p.handle(ScopeFetchInput::Tick {
            now: Instant::now(),
        });
        assert_eq!(out.len(), 2);
        assert_eq!(p.in_flight_count(), 2);
    }

    #[test]
    fn evict_stale_drops_matching_scopes() {
        let mut p = ScopeFetch::<Scope>::new(&config());
        for h in 1..=4 {
            p.handle(ScopeFetchInput::Request {
                scope: scope(1, h),
                peers: vec![vid(1)],
            });
        }
        p.handle(ScopeFetchInput::Tick {
            now: Instant::now(),
        });
        p.evict_stale(|s| s.1.0 <= 2);
        // Heights 1 and 2 drop from both maps; 3 and 4 remain in-flight.
        assert_eq!(p.pending_count(), 2);
        assert_eq!(p.in_flight_count(), 2);
    }

    #[test]
    fn exhausted_peers_back_off_then_retry() {
        let mut p = ScopeFetch::<Scope>::new(&config());
        let t0 = Instant::now();
        p.handle(ScopeFetchInput::Request {
            scope: scope(1, 10),
            peers: vec![vid(1)],
        });

        p.handle(ScopeFetchInput::Tick { now: t0 });
        p.handle(ScopeFetchInput::Failed {
            scope: scope(1, 10),
        });

        // Round exhausted on next tick — backoff begins.
        let out = p.handle(ScopeFetchInput::Tick { now: t0 });
        assert!(out.is_empty());

        // Within backoff: still no fetch.
        let out = p.handle(ScopeFetchInput::Tick {
            now: t0 + Duration::from_millis(500),
        });
        assert!(out.is_empty());

        // Past backoff: retry.
        let out = p.handle(ScopeFetchInput::Tick {
            now: t0 + Duration::from_millis(1100),
        });
        assert_eq!(out.len(), 1);
    }
}
