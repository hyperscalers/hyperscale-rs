//! Id-keyed fetch state machine with admission-driven completion.
//!
//! Tracks a set of pending ids. Each `Request` carries the peer pool the
//! ids should be fetched from; the protocol stores it as `Arc<FetchPeers>`
//! so siblings share state and group naturally at emit time. Each `Tick`
//! collects ids that aren't in flight, groups them by their peer-pool
//! identity, and emits chunked `Send`s up to per-tick and global concurrency
//! caps. The protocol does NO peer selection — it hands the full pool
//! through to the output handler, which calls `Network::request` and lets
//! the network's health-weighted selector pick.
//!
//! Entries self-evict on `Admitted`. There is no consumer-side `is_abandoned`
//! predicate — emitters that decide an id is no longer needed feed the id
//! back through `Admitted` to drop it.

use hyperscale_core::FetchPeers;
use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::sync::Arc;
use tracing::{debug, trace};

/// Tunables for an [`IdFetch`] instance.
#[derive(Debug, Clone)]
pub struct IdFetchConfig {
    /// Maximum ids in flight across all entries simultaneously.
    pub max_in_flight: usize,
    /// Maximum ids in a single chunked request.
    pub max_ids_per_request: usize,
    /// Maximum chunks emitted from a single `Tick`.
    pub parallel_chunks_per_tick: usize,
}

impl Default for IdFetchConfig {
    fn default() -> Self {
        Self {
            max_in_flight: 400,
            max_ids_per_request: 50,
            parallel_chunks_per_tick: 8,
        }
    }
}

/// Inputs to the protocol state machine.
#[derive(Debug)]
pub enum IdFetchInput<Id> {
    /// Request `ids` using `peers`. Idempotent: ids already pending keep
    /// their existing peer pool; new ids are added with the supplied one.
    Request {
        /// Ids to fetch.
        ids: Vec<Id>,
        /// Peer pool / canonical-source hint for these ids' network requests.
        peers: FetchPeers,
    },
    /// A network attempt for `ids` failed (or returned an unusable response);
    /// reclaim them for retry on the next tick.
    Failed {
        /// Ids that were in flight on the failed chunk.
        ids: Vec<Id>,
    },
    /// One or more ids landed via *any* path (fetch, gossip, local
    /// production). Drops them from the pending set. Doubles as the
    /// "no-longer-needed" signal — emitters that abandon a request feed
    /// the ids back here to drop them without a fetch ever returning.
    Admitted {
        /// Ids whose payloads have been admitted (or are no longer wanted).
        ids: Vec<Id>,
    },
    /// Drive pending fetches: emit chunks up to per-tick and global caps.
    Tick,
}

/// Outputs from the protocol state machine.
#[derive(Debug)]
pub enum IdFetchOutput<Id> {
    /// Issue a network request for `ids` against `peers`. The output handler
    /// translates this into `Network::request(&peers.peers, peers.preferred,
    /// ..)`. The network's health-weighted selector picks the actual target.
    Send {
        /// Ids in this chunk.
        ids: Vec<Id>,
        /// Peer pool for the request.
        peers: FetchPeers,
    },
}

#[derive(Debug)]
struct Entry {
    peers: Arc<FetchPeers>,
    in_flight: bool,
}

/// Id-keyed fetch state machine.
pub struct IdFetch<Id: Eq + Hash + Ord + Clone> {
    config: IdFetchConfig,
    /// `BTreeMap` for deterministic iteration order during chunk assembly.
    pending: BTreeMap<Id, Entry>,
}

impl<Id: Eq + Hash + Ord + Clone + std::fmt::Debug> IdFetch<Id> {
    /// Create a new protocol instance with the given config.
    #[must_use]
    pub const fn new(config: IdFetchConfig) -> Self {
        Self {
            config,
            pending: BTreeMap::new(),
        }
    }

    /// Process an input and return outputs.
    pub fn handle(&mut self, input: IdFetchInput<Id>) -> Vec<IdFetchOutput<Id>> {
        match input {
            IdFetchInput::Request { ids, peers } => self.handle_request(ids, peers),
            IdFetchInput::Failed { ids } => self.handle_failed(&ids),
            IdFetchInput::Admitted { ids } => self.handle_drop(&ids),
            IdFetchInput::Tick => self.spawn_pending_fetches(),
        }
    }

    /// Whether any id is currently tracked.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Number of ids currently dispatched and not yet acknowledged.
    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.pending.values().filter(|e| e.in_flight).count()
    }

    /// Total ids currently tracked (in-flight or awaiting dispatch).
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    fn handle_request(&mut self, ids: Vec<Id>, peers: FetchPeers) -> Vec<IdFetchOutput<Id>> {
        if ids.is_empty() {
            return vec![];
        }
        let shared = Arc::new(peers);
        let mut added = 0usize;
        for id in ids {
            self.pending.entry(id).or_insert_with(|| {
                added += 1;
                Entry {
                    peers: Arc::clone(&shared),
                    in_flight: false,
                }
            });
        }
        if added > 0 {
            debug!(count = added, "Started id fetch");
        }
        vec![]
    }

    fn handle_failed(&mut self, ids: &[Id]) -> Vec<IdFetchOutput<Id>> {
        let mut released = 0usize;
        for id in ids {
            if let Some(entry) = self.pending.get_mut(id)
                && entry.in_flight
            {
                entry.in_flight = false;
                released += 1;
            }
        }
        if released > 0 {
            trace!(count = released, "Id fetch chunk failed");
        }
        vec![]
    }

    fn handle_drop(&mut self, ids: &[Id]) -> Vec<IdFetchOutput<Id>> {
        for id in ids {
            self.pending.remove(id);
        }
        vec![]
    }

    fn spawn_pending_fetches(&mut self) -> Vec<IdFetchOutput<Id>> {
        let in_flight_now = self.in_flight_count();
        let global_room = self.config.max_in_flight.saturating_sub(in_flight_now);
        if global_room == 0 {
            return vec![];
        }

        // Group ready ids by their peer-pool identity (Arc pointer). Siblings
        // from the same `Request` share an Arc, so they coalesce into one
        // `Send` even when many ids share the same network target.
        let mut groups: HashMap<*const FetchPeers, (Arc<FetchPeers>, Vec<Id>)> = HashMap::new();
        let mut taken = 0usize;
        for (id, entry) in &self.pending {
            if taken >= global_room {
                break;
            }
            if entry.in_flight {
                continue;
            }
            let key = Arc::as_ptr(&entry.peers);
            groups
                .entry(key)
                .or_insert_with(|| (Arc::clone(&entry.peers), Vec::new()))
                .1
                .push(id.clone());
            taken += 1;
        }

        // Iterate groups by peer-pointer order for deterministic test output.
        let mut group_order: Vec<*const FetchPeers> = groups.keys().copied().collect();
        group_order.sort_unstable();

        let mut outputs = Vec::new();
        let mut chunks_emitted = 0usize;
        'outer: for key in group_order {
            let (peers, ids) = groups.remove(&key).expect("key just collected");
            for chunk in ids.chunks(self.config.max_ids_per_request) {
                if chunks_emitted >= self.config.parallel_chunks_per_tick {
                    break 'outer;
                }
                for id in chunk {
                    if let Some(entry) = self.pending.get_mut(id) {
                        entry.in_flight = true;
                    }
                }
                outputs.push(IdFetchOutput::Send {
                    ids: chunk.to_vec(),
                    peers: (*peers).clone(),
                });
                chunks_emitted += 1;
            }
        }
        outputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{Hash, TxHash, ValidatorId};

    fn tx(n: u8) -> TxHash {
        TxHash::from_raw(Hash::from_bytes(&[n; 32]))
    }

    fn vid(n: u64) -> ValidatorId {
        ValidatorId(n)
    }

    fn config() -> IdFetchConfig {
        IdFetchConfig {
            max_in_flight: 100,
            max_ids_per_request: 2,
            parallel_chunks_per_tick: 4,
        }
    }

    fn pinned(v: ValidatorId) -> FetchPeers {
        FetchPeers::with_preferred(v, vec![])
    }

    #[test]
    fn request_then_tick_emits_chunked_sends() {
        let mut p = IdFetch::<TxHash>::new(config());
        p.handle(IdFetchInput::Request {
            ids: vec![tx(1), tx(2), tx(3), tx(4), tx(5)],
            peers: pinned(vid(1)),
        });

        let out = p.handle(IdFetchInput::Tick);
        // 5 ids @ 2/chunk = 3 chunks, all carrying the same peer pool.
        assert_eq!(out.len(), 3);
        for o in &out {
            let IdFetchOutput::Send { peers, .. } = o;
            assert_eq!(peers.preferred, Some(vid(1)));
        }
        assert_eq!(p.in_flight_count(), 5);
    }

    #[test]
    fn failed_releases_chunk_for_retry() {
        let mut p = IdFetch::<TxHash>::new(config());
        p.handle(IdFetchInput::Request {
            ids: vec![tx(1), tx(2)],
            peers: pinned(vid(1)),
        });
        let out = p.handle(IdFetchInput::Tick);
        assert_eq!(out.len(), 1);
        let IdFetchOutput::Send { ids, .. } = &out[0];
        let chunk_ids = ids.clone();

        p.handle(IdFetchInput::Failed { ids: chunk_ids });
        assert_eq!(p.in_flight_count(), 0);

        let out = p.handle(IdFetchInput::Tick);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn admitted_drops_ids() {
        let mut p = IdFetch::<TxHash>::new(config());
        p.handle(IdFetchInput::Request {
            ids: vec![tx(1), tx(2)],
            peers: pinned(vid(1)),
        });
        p.handle(IdFetchInput::Tick);

        p.handle(IdFetchInput::Admitted {
            ids: vec![tx(1), tx(2)],
        });
        assert!(!p.has_pending());
    }

    #[test]
    fn admitted_unknown_id_is_silent_noop() {
        let mut p = IdFetch::<TxHash>::new(config());
        let out = p.handle(IdFetchInput::Admitted { ids: vec![tx(99)] });
        assert!(out.is_empty());
    }

    #[test]
    fn duplicate_request_keeps_existing_peers() {
        let mut p = IdFetch::<TxHash>::new(config());
        p.handle(IdFetchInput::Request {
            ids: vec![tx(1)],
            peers: pinned(vid(1)),
        });
        // Second request adds tx(2) under a fresh peer pool. tx(1) keeps its
        // existing pool; tx(2) gets the new one.
        p.handle(IdFetchInput::Request {
            ids: vec![tx(1), tx(2)],
            peers: pinned(vid(2)),
        });
        let out = p.handle(IdFetchInput::Tick);
        // Two distinct peer pools → two Sends.
        assert_eq!(out.len(), 2);
        let mut preferreds: Vec<_> = out
            .iter()
            .map(|o| match o {
                IdFetchOutput::Send { peers, .. } => peers.preferred.unwrap(),
            })
            .collect();
        preferreds.sort_by_key(|v| v.0);
        assert_eq!(preferreds, vec![vid(1), vid(2)]);
    }

    #[test]
    fn siblings_share_peer_pool_via_arc_grouping() {
        let mut p = IdFetch::<TxHash>::new(IdFetchConfig {
            max_in_flight: 100,
            max_ids_per_request: 50,
            parallel_chunks_per_tick: 8,
        });
        // 30 ids in one Request — should emit a single Send carrying all 30.
        p.handle(IdFetchInput::Request {
            ids: (0..30).map(tx).collect(),
            peers: pinned(vid(1)),
        });
        let out = p.handle(IdFetchInput::Tick);
        assert_eq!(out.len(), 1);
        let IdFetchOutput::Send { ids, .. } = &out[0];
        assert_eq!(ids.len(), 30);
    }

    #[test]
    fn global_in_flight_cap_bounds_emissions() {
        let mut p = IdFetch::<TxHash>::new(IdFetchConfig {
            max_in_flight: 3,
            max_ids_per_request: 10,
            parallel_chunks_per_tick: 4,
        });
        p.handle(IdFetchInput::Request {
            ids: (0..10).map(tx).collect(),
            peers: pinned(vid(1)),
        });
        p.handle(IdFetchInput::Tick);
        assert_eq!(p.in_flight_count(), 3, "global cap honoured");
    }
}
