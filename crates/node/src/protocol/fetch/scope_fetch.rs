//! Scope-keyed bundle fetch state machine.
//!
//! One in-flight slot per scope. The scope itself encodes everything the
//! responder needs (e.g. `(ShardGroupId, BlockHeight)` for a header fetch);
//! the protocol is payload-agnostic. It does NO peer selection — every Tick
//! emits a `Send { scope, peers }` carrying the full peer pool, and the
//! output handler hands that pool to `Network::request` so the network's
//! health-weighted selector picks the actual target.
//!
//! Admission is the only completion signal: when the payload for a scope
//! lands via *any* path (fetch response, gossip, local production), the
//! caller emits [`ScopeFetchInput::Admitted`] and the protocol drops the
//! entry.

use super::slot_tracker::SlotTracker;
use hyperscale_core::FetchPeers;
use std::collections::BTreeMap;
use std::hash::Hash;
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
    /// refreshes the peer pool.
    Request {
        /// Scope key the bundle belongs to.
        scope: S,
        /// Peer pool / canonical-source hint for this scope.
        peers: FetchPeers,
    },
    /// A network attempt for `scope` failed; release its slot so the next
    /// tick can re-issue the request (network handles peer rotation).
    Failed {
        /// Scope whose attempt failed.
        scope: S,
    },
    /// The payload for `scope` is no longer needed (it landed via fetch
    /// response, gossip, or any other path). Drops the entry. No-op for
    /// unknown scopes.
    Admitted {
        /// Scope whose payload has been admitted.
        scope: S,
    },
    /// Drive pending fetches: spawn requests up to `max_concurrent`.
    Tick,
}

/// Outputs from the protocol state machine.
#[derive(Debug)]
pub enum ScopeFetchOutput<S> {
    /// The runner should issue a network request for `scope` against
    /// `peers`. Translation to a wire request type is the caller's
    /// responsibility.
    Send {
        /// Scope key.
        scope: S,
        /// Peer pool for the request.
        peers: FetchPeers,
    },
}

#[derive(Debug)]
struct ScopeEntry {
    peers: FetchPeers,
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
            ScopeFetchInput::Tick => self.spawn_pending_fetches(),
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

    /// Drop every scope for which `is_abandoned` returns `true`. Called by the
    /// instance from the tick handler with whatever state-machine read is
    /// relevant (committed height, etc.).
    pub fn evict_abandoned<F>(&mut self, mut is_abandoned: F)
    where
        F: FnMut(&S) -> bool,
    {
        self.pending.retain(|s, _| !is_abandoned(s));
        self.in_flight.retain(|s| !is_abandoned(s));
    }

    fn handle_request(&mut self, scope: S, peers: FetchPeers) -> Vec<ScopeFetchOutput<S>> {
        if let Some(entry) = self.pending.get_mut(&scope) {
            entry.peers = peers;
            trace!(?scope, "Refreshed peer pool for pending scope fetch");
            return vec![];
        }
        debug!(?scope, "Starting scope fetch");
        self.pending.insert(scope, ScopeEntry { peers });
        vec![]
    }

    fn handle_failed(&mut self, scope: &S) -> Vec<ScopeFetchOutput<S>> {
        if self.in_flight.release(scope) {
            trace!(
                ?scope,
                "Scope fetch attempt failed, will re-issue next tick"
            );
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

    fn spawn_pending_fetches(&mut self) -> Vec<ScopeFetchOutput<S>> {
        let mut outputs = Vec::new();

        for (scope, entry) in &self.pending {
            if !self.in_flight.has_capacity() {
                break;
            }
            if self.in_flight.contains(scope) {
                continue;
            }

            self.in_flight.try_acquire(scope.clone());
            trace!(?scope, "Sending scope fetch");
            outputs.push(ScopeFetchOutput::Send {
                scope: scope.clone(),
                peers: entry.peers.clone(),
            });
        }

        outputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{BlockHeight, ShardGroupId, ValidatorId};

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

    fn rotation(peers: Vec<ValidatorId>) -> FetchPeers {
        FetchPeers::rotation(peers)
    }

    #[test]
    fn request_then_tick_emits_send() {
        let mut p = ScopeFetch::<Scope>::new(&config());
        p.handle(ScopeFetchInput::Request {
            scope: scope(1, 10),
            peers: rotation(vec![vid(1), vid(2)]),
        });
        let out = p.handle(ScopeFetchInput::Tick);
        assert_eq!(out.len(), 1);
        match &out[0] {
            ScopeFetchOutput::Send { scope: s, peers } => {
                assert_eq!(*s, (ShardGroupId(1), BlockHeight(10)));
                assert_eq!(peers.peers, vec![vid(1), vid(2)]);
                assert_eq!(peers.preferred, None);
            }
        }
        assert_eq!(p.in_flight_count(), 1);
    }

    #[test]
    fn failed_releases_slot_for_re_issue() {
        let mut p = ScopeFetch::<Scope>::new(&config());
        p.handle(ScopeFetchInput::Request {
            scope: scope(1, 10),
            peers: rotation(vec![vid(1), vid(2)]),
        });
        p.handle(ScopeFetchInput::Tick);
        p.handle(ScopeFetchInput::Failed {
            scope: scope(1, 10),
        });
        assert_eq!(p.in_flight_count(), 0);

        let out = p.handle(ScopeFetchInput::Tick);
        assert_eq!(out.len(), 1, "next tick re-issues with the same peer pool");
    }

    #[test]
    fn admitted_drops_entry() {
        let mut p = ScopeFetch::<Scope>::new(&config());
        p.handle(ScopeFetchInput::Request {
            scope: scope(1, 10),
            peers: rotation(vec![vid(1)]),
        });
        p.handle(ScopeFetchInput::Tick);
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
            peers: rotation(vec![vid(1)]),
        });
        // Refresh: peer pool now includes vid(2).
        p.handle(ScopeFetchInput::Request {
            scope: scope(1, 10),
            peers: rotation(vec![vid(2)]),
        });
        let out = p.handle(ScopeFetchInput::Tick);
        match &out[0] {
            ScopeFetchOutput::Send { peers, .. } => {
                assert_eq!(peers.peers, vec![vid(2)]);
            }
        }
    }

    #[test]
    fn max_concurrent_bounds_in_flight() {
        let mut p = ScopeFetch::<Scope>::new(&ScopeFetchConfig { max_concurrent: 2 });
        for h in 10..15 {
            p.handle(ScopeFetchInput::Request {
                scope: scope(1, h),
                peers: rotation(vec![vid(1)]),
            });
        }
        let out = p.handle(ScopeFetchInput::Tick);
        assert_eq!(out.len(), 2);
        assert_eq!(p.in_flight_count(), 2);
    }

    #[test]
    fn evict_abandoned_drops_matching_scopes() {
        let mut p = ScopeFetch::<Scope>::new(&config());
        for h in 1..=4 {
            p.handle(ScopeFetchInput::Request {
                scope: scope(1, h),
                peers: rotation(vec![vid(1)]),
            });
        }
        p.handle(ScopeFetchInput::Tick);
        p.evict_abandoned(|s| s.1.0 <= 2);
        assert_eq!(p.pending_count(), 2);
        assert_eq!(p.in_flight_count(), 2);
    }
}
