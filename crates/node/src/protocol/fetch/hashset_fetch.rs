//! Hash-set fetch state machine with partial admission.
//!
//! Tracks a set of items per scope (e.g. tx hashes per block). Each `Send`
//! output covers a *chunk* of the missing set; the protocol limits both the
//! per-scope concurrency and the parallel-chunks-per-tick fan-out. The
//! scope's entry self-evicts when its missing set drains, either by direct
//! per-id admission or a scope-level admission signal.

use super::peer_rotator::PeerRotator;
use hyperscale_types::ValidatorId;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::Hash;
use std::time::Instant;
use tracing::{debug, trace};

/// Tunables for a `HashSetFetch` instance.
#[derive(Debug, Clone)]
pub struct HashSetFetchConfig {
    /// Maximum chunks (i.e. in-flight network requests) per scope.
    pub max_concurrent_per_scope: usize,
    /// Maximum ids in a single chunked request.
    pub max_ids_per_request: usize,
    /// Maximum chunks emitted from a single `Tick` per scope.
    pub parallel_chunks_per_tick: usize,
}

impl Default for HashSetFetchConfig {
    fn default() -> Self {
        Self {
            max_concurrent_per_scope: 8,
            max_ids_per_request: 50,
            parallel_chunks_per_tick: 4,
        }
    }
}

/// Peer-selection policy for a hash-set fetch.
#[derive(Debug, Clone)]
pub enum PeerSource {
    /// Pinned to a single peer for every chunk (no rotation).
    Pinned(ValidatorId),
    /// Walk through `preferred` first, then `rest`. Rotates on failure.
    Rotation {
        /// The peer tried first on each round.
        preferred: ValidatorId,
        /// Fallback peers, walked in order.
        rest: Vec<ValidatorId>,
    },
}

/// Inputs to the protocol state machine.
#[derive(Debug)]
pub enum HashSetFetchInput<S, Id> {
    /// Request `ids` for `scope`. Idempotent: a duplicate request merges new
    /// ids into the missing set without disturbing in-flight chunks.
    Request {
        /// Scope key the ids belong to.
        scope: S,
        /// Initial set of ids to fetch under this scope.
        ids: Vec<Id>,
        /// Peer pool / selection policy for this scope's network requests.
        peers: PeerSource,
    },
    /// A network attempt for `scope` failed (or returned an unusable
    /// response); reclaim its ids for retry.
    Failed {
        /// Scope whose chunk failed.
        scope: S,
        /// Ids that were in flight on the failed chunk.
        ids: Vec<Id>,
    },
    /// One or more ids landed via *any* path. Drains them from every scope
    /// waiting on them.
    Admitted {
        /// Ids whose payloads have been admitted to their canonical store.
        ids: Vec<Id>,
    },
    /// Scope-level admission: drop the scope entirely.
    AdmittedScope {
        /// Scope to evict.
        scope: S,
    },
    /// Drive pending fetches: emit chunks up to per-scope and per-tick caps.
    Tick,
}

/// Outputs from the protocol state machine.
#[derive(Debug)]
pub enum HashSetFetchOutput<S, Id> {
    /// Issue a network request for `ids` of `scope` to `peer`.
    Send {
        /// Scope the chunk belongs to.
        scope: S,
        /// Ids in this chunk.
        ids: Vec<Id>,
        /// Peer to issue the request against.
        peer: ValidatorId,
    },
    /// Every id in `scope` has been admitted; the scope's entry has self-evicted.
    ScopeComplete {
        /// Scope that just became complete.
        #[allow(dead_code)]
        // Consumed by hash-set-fetch instances once their callers wire it.
        scope: S,
    },
}

#[derive(Debug)]
struct ScopedSet<Id: Eq + Hash + Clone> {
    missing: HashSet<Id>,
    in_flight: HashSet<Id>,
    peers: PeerSource,
    rotator: Option<PeerRotator>,
}

impl<Id: Eq + Hash + Clone> ScopedSet<Id> {
    fn new(ids: Vec<Id>, peers: PeerSource) -> Self {
        let rotator = match &peers {
            PeerSource::Pinned(_) => None,
            PeerSource::Rotation { preferred, rest } => {
                let mut peer_list = Vec::with_capacity(1 + rest.len());
                peer_list.push(*preferred);
                peer_list.extend(rest.iter().filter(|p| *p != preferred).copied());
                Some(PeerRotator::new(peer_list))
            }
        };
        Self {
            missing: ids.into_iter().collect(),
            in_flight: HashSet::new(),
            peers,
            rotator,
        }
    }

    fn next_peer(&mut self, now: Instant) -> Option<ValidatorId> {
        match (&self.peers, self.rotator.as_mut()) {
            (PeerSource::Pinned(p), _) => Some(*p),
            (_, Some(rot)) => rot.next(now),
            _ => None,
        }
    }

    fn is_complete(&self) -> bool {
        self.missing.is_empty() && self.in_flight.is_empty()
    }
}

/// Hash-set fetch state machine.
pub struct HashSetFetch<S: Eq + Hash + Ord + Clone, Id: Eq + Hash + Clone> {
    config: HashSetFetchConfig,
    pending: BTreeMap<S, ScopedSet<Id>>,
    /// Reverse index: which scopes is this id missing in?
    id_to_scopes: HashMap<Id, Vec<S>>,
}

impl<S: Eq + Hash + Ord + Clone + std::fmt::Debug, Id: Eq + Hash + Clone + std::fmt::Debug>
    HashSetFetch<S, Id>
{
    /// Create a new protocol instance with the given config.
    #[must_use]
    pub fn new(config: HashSetFetchConfig) -> Self {
        Self {
            config,
            pending: BTreeMap::new(),
            id_to_scopes: HashMap::new(),
        }
    }

    /// Process an input and return outputs.
    pub fn handle(&mut self, input: HashSetFetchInput<S, Id>) -> Vec<HashSetFetchOutput<S, Id>> {
        match input {
            HashSetFetchInput::Request { scope, ids, peers } => {
                self.handle_request(scope, ids, peers)
            }
            HashSetFetchInput::Failed { scope, ids } => self.handle_failed(&scope, &ids),
            HashSetFetchInput::Admitted { ids } => self.handle_admitted(ids),
            HashSetFetchInput::AdmittedScope { scope } => self.handle_admitted_scope(&scope),
            HashSetFetchInput::Tick => self.spawn_pending_fetches(Instant::now()),
        }
    }

    /// Whether any scope is currently tracked.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Number of ids currently dispatched and not yet acknowledged.
    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.pending.values().map(|s| s.in_flight.len()).sum()
    }

    /// Number of scopes currently tracked.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Drop every scope for which `is_stale` returns `true` and prune the
    /// reverse index of the ids those scopes owned.
    pub fn evict_stale<F>(&mut self, mut is_stale: F)
    where
        F: FnMut(&S) -> bool,
    {
        let evicted: Vec<S> = self
            .pending
            .keys()
            .filter(|s| is_stale(s))
            .cloned()
            .collect();
        for scope in evicted {
            if let Some(set) = self.pending.remove(&scope) {
                for id in set.missing.iter().chain(set.in_flight.iter()) {
                    if let Some(scopes) = self.id_to_scopes.get_mut(id) {
                        scopes.retain(|s| s != &scope);
                        if scopes.is_empty() {
                            self.id_to_scopes.remove(id);
                        }
                    }
                }
            }
        }
    }

    fn handle_request(
        &mut self,
        scope: S,
        ids: Vec<Id>,
        peers: PeerSource,
    ) -> Vec<HashSetFetchOutput<S, Id>> {
        if ids.is_empty() {
            return vec![];
        }

        if let Some(set) = self.pending.get_mut(&scope) {
            for id in ids {
                if set.in_flight.contains(&id) {
                    continue;
                }
                if set.missing.insert(id.clone()) {
                    self.id_to_scopes.entry(id).or_default().push(scope.clone());
                }
            }
            return vec![];
        }

        debug!(?scope, count = ids.len(), "Starting hash-set fetch");
        for id in &ids {
            self.id_to_scopes
                .entry(id.clone())
                .or_default()
                .push(scope.clone());
        }
        self.pending.insert(scope, ScopedSet::new(ids, peers));
        vec![]
    }

    fn handle_failed(&mut self, scope: &S, ids: &[Id]) -> Vec<HashSetFetchOutput<S, Id>> {
        if let Some(set) = self.pending.get_mut(scope) {
            for id in ids {
                set.in_flight.remove(id);
            }
            trace!(?scope, count = ids.len(), "Hash-set fetch chunk failed");
        }
        vec![]
    }

    fn handle_admitted(&mut self, ids: Vec<Id>) -> Vec<HashSetFetchOutput<S, Id>> {
        let mut outputs = Vec::new();
        for id in ids {
            let Some(scopes) = self.id_to_scopes.remove(&id) else {
                continue;
            };
            for scope in scopes {
                if let Some(set) = self.pending.get_mut(&scope) {
                    set.missing.remove(&id);
                    set.in_flight.remove(&id);
                    if set.is_complete() {
                        self.pending.remove(&scope);
                        outputs.push(HashSetFetchOutput::ScopeComplete { scope });
                    }
                }
            }
        }
        outputs
    }

    fn handle_admitted_scope(&mut self, scope: &S) -> Vec<HashSetFetchOutput<S, Id>> {
        let Some(set) = self.pending.remove(scope) else {
            return vec![];
        };
        // Strip this scope from the reverse index for every id it owned.
        for id in set.missing.iter().chain(set.in_flight.iter()) {
            if let Some(scopes) = self.id_to_scopes.get_mut(id) {
                scopes.retain(|s| s != scope);
                if scopes.is_empty() {
                    self.id_to_scopes.remove(id);
                }
            }
        }
        debug!(?scope, "Scope-level admission; dropping fetch entry");
        vec![HashSetFetchOutput::ScopeComplete {
            scope: scope.clone(),
        }]
    }

    fn spawn_pending_fetches(&mut self, now: Instant) -> Vec<HashSetFetchOutput<S, Id>> {
        let mut outputs = Vec::new();
        let max_in_flight = self.config.max_concurrent_per_scope * self.config.max_ids_per_request;

        for (scope, set) in &mut self.pending {
            if set.in_flight.len() >= max_in_flight {
                continue;
            }

            // Hashes available to fetch this tick.
            let to_fetch: Vec<Id> = set
                .missing
                .iter()
                .filter(|id| !set.in_flight.contains(id))
                .cloned()
                .collect();
            if to_fetch.is_empty() {
                continue;
            }

            let slot_chunks =
                (max_in_flight - set.in_flight.len()).div_ceil(self.config.max_ids_per_request);
            let chunk_count = self.config.parallel_chunks_per_tick.min(slot_chunks);

            for chunk in to_fetch
                .chunks(self.config.max_ids_per_request)
                .take(chunk_count)
            {
                let Some(peer) = set.next_peer(now) else {
                    break;
                };
                for id in chunk {
                    set.in_flight.insert(id.clone());
                }
                outputs.push(HashSetFetchOutput::Send {
                    scope: scope.clone(),
                    ids: chunk.to_vec(),
                    peer,
                });
            }
        }

        outputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{BlockHash, Hash, TxHash};

    fn block(n: u8) -> BlockHash {
        BlockHash::from_raw(Hash::from_bytes(&[n; 32]))
    }

    fn tx(n: u8) -> TxHash {
        TxHash::from_raw(Hash::from_bytes(&[n; 32]))
    }

    fn vid(n: u64) -> ValidatorId {
        ValidatorId(n)
    }

    fn config() -> HashSetFetchConfig {
        HashSetFetchConfig {
            max_concurrent_per_scope: 4,
            max_ids_per_request: 2,
            parallel_chunks_per_tick: 4,
        }
    }

    #[test]
    fn request_then_tick_emits_chunked_sends() {
        let mut p = HashSetFetch::<BlockHash, TxHash>::new(config());
        p.handle(HashSetFetchInput::Request {
            scope: block(1),
            ids: vec![tx(1), tx(2), tx(3), tx(4), tx(5)],
            peers: PeerSource::Pinned(vid(1)),
        });

        let out = p.handle(HashSetFetchInput::Tick);
        // 5 ids @ 2/chunk = 3 chunks; capped by parallel_chunks_per_tick=4.
        assert_eq!(out.len(), 3);
        for o in &out {
            match o {
                HashSetFetchOutput::Send { peer, .. } => assert_eq!(*peer, vid(1)),
                HashSetFetchOutput::ScopeComplete { .. } => panic!("unexpected"),
            }
        }
        // All 5 ids dispatched across the 3 chunks.
        assert_eq!(p.in_flight_count(), 5);
    }

    #[test]
    fn failed_releases_chunk_for_retry() {
        let mut p = HashSetFetch::<BlockHash, TxHash>::new(config());
        p.handle(HashSetFetchInput::Request {
            scope: block(1),
            ids: vec![tx(1), tx(2)],
            peers: PeerSource::Pinned(vid(1)),
        });
        let out = p.handle(HashSetFetchInput::Tick);
        assert_eq!(out.len(), 1);
        let HashSetFetchOutput::Send { ids, .. } = &out[0] else {
            panic!()
        };
        let chunk_ids = ids.clone();

        p.handle(HashSetFetchInput::Failed {
            scope: block(1),
            ids: chunk_ids,
        });
        assert_eq!(p.in_flight_count(), 0);

        let out = p.handle(HashSetFetchInput::Tick);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn admitted_drains_ids_and_emits_scope_complete() {
        let mut p = HashSetFetch::<BlockHash, TxHash>::new(config());
        p.handle(HashSetFetchInput::Request {
            scope: block(1),
            ids: vec![tx(1), tx(2)],
            peers: PeerSource::Pinned(vid(1)),
        });
        p.handle(HashSetFetchInput::Tick);

        let out = p.handle(HashSetFetchInput::Admitted {
            ids: vec![tx(1), tx(2)],
        });
        assert_eq!(out.len(), 1);
        assert!(matches!(
            out[0],
            HashSetFetchOutput::ScopeComplete { scope } if scope == block(1)
        ));
        assert!(!p.has_pending());
    }

    #[test]
    fn admitted_drains_across_multiple_scopes() {
        let mut p = HashSetFetch::<BlockHash, TxHash>::new(config());
        p.handle(HashSetFetchInput::Request {
            scope: block(1),
            ids: vec![tx(1), tx(2)],
            peers: PeerSource::Pinned(vid(1)),
        });
        p.handle(HashSetFetchInput::Request {
            scope: block(2),
            ids: vec![tx(1), tx(3)],
            peers: PeerSource::Pinned(vid(1)),
        });

        // tx(1) lands; both scopes should drop it.
        p.handle(HashSetFetchInput::Admitted { ids: vec![tx(1)] });
        assert_eq!(p.pending_count(), 2);
    }

    #[test]
    fn admitted_scope_drops_the_entire_entry() {
        let mut p = HashSetFetch::<BlockHash, TxHash>::new(config());
        p.handle(HashSetFetchInput::Request {
            scope: block(1),
            ids: vec![tx(1), tx(2)],
            peers: PeerSource::Pinned(vid(1)),
        });

        let out = p.handle(HashSetFetchInput::AdmittedScope { scope: block(1) });
        assert_eq!(out.len(), 1);
        assert!(!p.has_pending());
    }

    #[test]
    fn admitted_unknown_id_is_silent_noop() {
        let mut p = HashSetFetch::<BlockHash, TxHash>::new(config());
        let out = p.handle(HashSetFetchInput::Admitted { ids: vec![tx(99)] });
        assert!(out.is_empty());
    }

    #[test]
    fn duplicate_request_merges_new_ids() {
        let mut p = HashSetFetch::<BlockHash, TxHash>::new(config());
        p.handle(HashSetFetchInput::Request {
            scope: block(1),
            ids: vec![tx(1)],
            peers: PeerSource::Pinned(vid(1)),
        });
        p.handle(HashSetFetchInput::Request {
            scope: block(1),
            ids: vec![tx(2)],
            peers: PeerSource::Pinned(vid(1)),
        });
        let out = p.handle(HashSetFetchInput::Tick);
        // Both ids would fit in one chunk (2/req), so 1 send.
        assert_eq!(out.len(), 1);
        let HashSetFetchOutput::Send { ids, .. } = &out[0] else {
            panic!()
        };
        assert_eq!(ids.len(), 2);
    }
}
