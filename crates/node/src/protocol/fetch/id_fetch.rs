//! Id-keyed fetch state machine with admission-driven completion.
//!
//! Tracks a set of pending ids, each with its own peer-rotation state. Each
//! `Tick` collects ids that are ready to dispatch, groups them by the next
//! peer their rotator picks, and emits chunked `Send`s up to per-tick and
//! global concurrency caps. Entries self-evict when they're admitted via any
//! path (`Admitted`) or explicitly cancelled (`Cancel`).
//!
//! Unlike scope-keyed fetch, there is no consumer-side ownership concept and
//! no `is_abandoned` predicate — an entry's lifetime is bounded by admission
//! or an explicit cancel from its emitter. Two callers that request the same
//! id share the in-flight entry; the first request to land sets the peer
//! source, subsequent requests are no-ops.

use super::peer_rotator::PeerRotator;
use hyperscale_types::ValidatorId;
use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::time::Instant;
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

/// Peer-selection policy for a fetch entry.
///
/// Always rotates: walks `preferred` first (one canonical-source peer), then
/// `rest`, with backoff between full sweeps. A "pinned to one peer" effect
/// is just `Rotation { preferred, rest: vec![] }` — same shape, but with
/// backoff instead of a tight retry loop.
#[derive(Debug, Clone)]
pub enum PeerSource {
    /// Walk through `preferred` first, then `rest`. Rotates on failure with
    /// backoff between full sweeps.
    Rotation {
        /// The peer tried first on each round.
        preferred: ValidatorId,
        /// Fallback peers, walked in order.
        rest: Vec<ValidatorId>,
    },
}

/// Inputs to the protocol state machine.
#[derive(Debug)]
pub enum IdFetchInput<Id> {
    /// Request `ids` using `peers`. Idempotent: ids already pending keep
    /// their existing peer source; new ids are added with the supplied one.
    Request {
        /// Ids to fetch.
        ids: Vec<Id>,
        /// Peer pool / selection policy for these ids' network requests.
        peers: PeerSource,
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
    /// Issue a network request for `ids` to `peer`.
    Send {
        /// Ids in this chunk.
        ids: Vec<Id>,
        /// Peer to issue the request against.
        peer: ValidatorId,
    },
}

#[derive(Debug)]
struct Entry {
    rotator: PeerRotator,
    in_flight: bool,
}

impl Entry {
    fn new(peers: PeerSource) -> Self {
        let PeerSource::Rotation { preferred, rest } = peers;
        let mut peer_list = Vec::with_capacity(1 + rest.len());
        peer_list.push(preferred);
        peer_list.extend(rest.into_iter().filter(|p| *p != preferred));
        Self {
            rotator: PeerRotator::new(peer_list),
            in_flight: false,
        }
    }

    fn next_peer(&mut self, now: Instant) -> Option<ValidatorId> {
        self.rotator.next(now)
    }
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
            IdFetchInput::Request { ids, peers } => self.handle_request(ids, &peers),
            IdFetchInput::Failed { ids } => self.handle_failed(&ids),
            IdFetchInput::Admitted { ids } => self.handle_drop(&ids),
            IdFetchInput::Tick => self.spawn_pending_fetches(Instant::now()),
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

    fn handle_request(&mut self, ids: Vec<Id>, peers: &PeerSource) -> Vec<IdFetchOutput<Id>> {
        if ids.is_empty() {
            return vec![];
        }
        let mut added = 0usize;
        for id in ids {
            self.pending.entry(id).or_insert_with(|| {
                added += 1;
                Entry::new(peers.clone())
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

    fn spawn_pending_fetches(&mut self, now: Instant) -> Vec<IdFetchOutput<Id>> {
        let in_flight_now = self.in_flight_count();
        let global_room = self.config.max_in_flight.saturating_sub(in_flight_now);
        if global_room == 0 {
            return vec![];
        }

        // Group ready ids by the peer their rotator picks this tick. Rotators
        // sharing identical history pick the same peer, so siblings from one
        // request batch naturally coalesce into a single `Send`.
        let mut by_peer: HashMap<ValidatorId, Vec<Id>> = HashMap::new();
        let mut taken = 0usize;
        for (id, entry) in &mut self.pending {
            if taken >= global_room {
                break;
            }
            if entry.in_flight {
                continue;
            }
            let Some(peer) = entry.next_peer(now) else {
                continue;
            };
            by_peer.entry(peer).or_default().push(id.clone());
            taken += 1;
        }

        let mut outputs = Vec::new();
        let mut chunks_emitted = 0usize;
        // Iterate peer groups in deterministic ValidatorId order.
        let mut peer_order: Vec<ValidatorId> = by_peer.keys().copied().collect();
        peer_order.sort_by_key(|v| v.0);
        'outer: for peer in peer_order {
            let ids = by_peer.remove(&peer).unwrap_or_default();
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
                    peer,
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
    use hyperscale_types::{Hash, TxHash};

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

    #[test]
    fn request_then_tick_emits_chunked_sends() {
        let mut p = IdFetch::<TxHash>::new(config());
        p.handle(IdFetchInput::Request {
            ids: vec![tx(1), tx(2), tx(3), tx(4), tx(5)],
            peers: PeerSource::Rotation {
                preferred: vid(1),
                rest: vec![],
            },
        });

        let out = p.handle(IdFetchInput::Tick);
        // 5 ids @ 2/chunk = 3 chunks, all to vid(1).
        assert_eq!(out.len(), 3);
        for o in &out {
            let IdFetchOutput::Send { peer, .. } = o;
            assert_eq!(*peer, vid(1));
        }
        assert_eq!(p.in_flight_count(), 5);
    }

    #[test]
    fn failed_releases_chunk_for_retry() {
        let mut p = IdFetch::<TxHash>::new(config());
        // Two-peer rotation so retry-after-failure rotates without entering
        // backoff (single-peer rotation backs off between rounds).
        p.handle(IdFetchInput::Request {
            ids: vec![tx(1), tx(2)],
            peers: PeerSource::Rotation {
                preferred: vid(1),
                rest: vec![vid(2)],
            },
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
            peers: PeerSource::Rotation {
                preferred: vid(1),
                rest: vec![],
            },
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
    fn duplicate_request_keeps_existing_peer_source() {
        let mut p = IdFetch::<TxHash>::new(config());
        p.handle(IdFetchInput::Request {
            ids: vec![tx(1)],
            peers: PeerSource::Rotation {
                preferred: vid(1),
                rest: vec![],
            },
        });
        // Second request adds tx(2), keeps tx(1)'s existing peer source.
        p.handle(IdFetchInput::Request {
            ids: vec![tx(1), tx(2)],
            peers: PeerSource::Rotation {
                preferred: vid(2),
                rest: vec![],
            },
        });
        let out = p.handle(IdFetchInput::Tick);
        // tx(1) goes to vid(1), tx(2) goes to vid(2). Two sends.
        assert_eq!(out.len(), 2);
        let mut peers: Vec<_> = out
            .iter()
            .map(|o| match o {
                IdFetchOutput::Send { peer, .. } => *peer,
            })
            .collect();
        peers.sort_by_key(|v| v.0);
        assert_eq!(peers, vec![vid(1), vid(2)]);
    }

    #[test]
    fn rotation_advances_after_failure() {
        let mut p = IdFetch::<TxHash>::new(config());
        p.handle(IdFetchInput::Request {
            ids: vec![tx(1)],
            peers: PeerSource::Rotation {
                preferred: vid(1),
                rest: vec![vid(2)],
            },
        });
        let out = p.handle(IdFetchInput::Tick);
        let IdFetchOutput::Send { peer: first, .. } = &out[0];
        assert_eq!(*first, vid(1));

        p.handle(IdFetchInput::Failed { ids: vec![tx(1)] });
        let out = p.handle(IdFetchInput::Tick);
        let IdFetchOutput::Send { peer: second, .. } = &out[0];
        assert_eq!(*second, vid(2));
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
            peers: PeerSource::Rotation {
                preferred: vid(1),
                rest: vec![],
            },
        });
        p.handle(IdFetchInput::Tick);
        assert_eq!(p.in_flight_count(), 3, "global cap honoured");
    }
}
