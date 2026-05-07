//! Id-keyed fetch state machine plus per-payload bindings and inbound
//! request responders.
//!
//! - The generic [`Fetch`] state machine in this file owns scheduling
//!   only — pending sets, chunking, in-flight caps.
//! - [`binding`] provides per-payload glue: which `Fetch<Id>` instance on
//!   [`FetchHost`] backs each payload and the wire shape of each request.
//!   The `ProtocolEvent` → in-flight-drain mapping lives outside the
//!   binding, in `io_loop::drive_fetch_admission`.
//! - [`host`] bundles the per-payload `Fetch<Id>` instances owned by the
//!   I/O loop, plus metrics readouts.
//! - [`transaction_serve`] / [`provision_serve`] answer inbound requests
//!   for the fetch payloads that have a dedicated wire request type.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::sync::Arc;

use hyperscale_core::{FetchOrigin, FetchPeers};
use hyperscale_metrics::{
    record_fetch_abandoned, record_fetch_completed, record_fetch_retried, record_fetch_started,
};
use hyperscale_types::ValidatorId;
use tracing::{debug, trace};

pub mod binding;
pub mod host;
pub mod provision_serve;
pub mod transaction_serve;

pub use host::{FetchHost, FetchMetrics};

/// Tunables for a [`Fetch`] instance.
#[derive(Debug, Clone)]
pub struct FetchConfig {
    /// Maximum ids in flight across all entries simultaneously.
    pub max_in_flight: usize,
    /// Maximum ids in a single chunked request.
    pub max_ids_per_request: usize,
    /// Maximum chunks emitted from a single `Tick`.
    pub parallel_chunks_per_tick: usize,
}

impl Default for FetchConfig {
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
pub enum FetchInput<Id> {
    /// Request `ids` using `peers`. Idempotent: ids already pending keep
    /// their existing peer pool / origin; new ids are added with the supplied
    /// pair.
    Request {
        /// Ids to fetch.
        ids: Vec<Id>,
        /// Peer pool / canonical-source hint for these ids' network requests.
        peers: FetchPeers,
        /// Why the fetch is being issued. Drives the message-class override
        /// when the binding ultimately calls `Network::request`.
        origin: FetchOrigin,
    },
    /// A network attempt for `ids` failed (or returned an unusable response);
    /// reclaim them for retry on the next tick.
    Failed {
        /// Ids that were in flight on the failed chunk.
        ids: Vec<Id>,
    },
    /// Payload for `ids` landed via fetch response, gossip, or local
    /// production. Fed by `io_loop::drive_fetch_admission` on canonical
    /// admission `ProtocolEvent`s. Records `record_fetch_completed` per
    /// id removed.
    Admitted {
        /// Ids whose payloads have been admitted.
        ids: Vec<Id>,
    },
    /// Consumer coordinator dropped its expectation for `ids`. Fed by
    /// `io_loop`'s `Action::AbandonFetch` dispatcher. Records
    /// `record_fetch_abandoned` per id removed — distinct from `Admitted`
    /// so the two populations are observable separately.
    Abandoned {
        /// Ids whose fetch has been cancelled by the originating coordinator.
        ids: Vec<Id>,
    },
    /// Drive pending fetches: emit chunks up to per-tick and global caps.
    Tick,
}

/// Outputs from the protocol state machine.
#[derive(Debug)]
pub enum FetchOutput<Id> {
    /// Issue a network request for `ids` against `peers`. The output handler
    /// translates this into `Network::request(&peers.peers, peers.preferred,
    /// .., origin.class_override(), ..)`. The network's health-weighted
    /// selector picks the actual target.
    Send {
        /// Ids in this chunk.
        ids: Vec<Id>,
        /// Peer pool for the request.
        peers: FetchPeers,
        /// Origin shared by every id in this chunk; chunks are grouped by
        /// `(peers, origin)` so this is well-defined.
        origin: FetchOrigin,
    },
}

#[derive(Debug)]
struct Entry {
    peers: Arc<FetchPeers>,
    origin: FetchOrigin,
    in_flight: bool,
}

/// Why an id is being removed from the pending set — drives which counter
/// `handle_drop` increments.
#[derive(Debug, Clone, Copy)]
enum DropKind {
    Admitted,
    Abandoned,
}

/// Group key for ready ids during chunk assembly: same peer pool *and*
/// same origin coalesce; different origins emit separate `Send`s so they
/// can carry distinct `MessageClass` overrides downstream.
type GroupKey = (FetchPeers, FetchOrigin);

/// Group value: shared peer pool, the origin all ids in the group share,
/// and the ids themselves.
type GroupValue<Id> = (Arc<FetchPeers>, FetchOrigin, Vec<Id>);

/// Id-keyed fetch state machine.
pub struct Fetch<Id: Eq + Hash + Ord + Clone> {
    config: FetchConfig,
    /// Routed into the global metrics recorder as the `kind` label.
    kind: &'static str,
    /// `BTreeMap` for deterministic iteration order during chunk assembly.
    pending: BTreeMap<Id, Entry>,
}

impl<Id: Eq + Hash + Ord + Clone + std::fmt::Debug> Fetch<Id> {
    /// Create a new protocol instance with the given config.
    ///
    /// `kind` labels metrics emitted by this instance.
    #[must_use]
    pub const fn new(kind: &'static str, config: FetchConfig) -> Self {
        Self {
            config,
            kind,
            pending: BTreeMap::new(),
        }
    }

    /// Process an input and return outputs.
    pub fn handle(&mut self, input: FetchInput<Id>) -> Vec<FetchOutput<Id>> {
        match input {
            FetchInput::Request { ids, peers, origin } => self.handle_request(ids, peers, origin),
            FetchInput::Failed { ids } => self.handle_failed(&ids),
            FetchInput::Admitted { ids } => self.handle_drop(&ids, DropKind::Admitted),
            FetchInput::Abandoned { ids } => self.handle_drop(&ids, DropKind::Abandoned),
            FetchInput::Tick => self.spawn_pending_fetches(),
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

    fn handle_request(
        &mut self,
        ids: Vec<Id>,
        peers: FetchPeers,
        origin: FetchOrigin,
    ) -> Vec<FetchOutput<Id>> {
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
                    origin,
                    in_flight: false,
                }
            });
        }
        if added > 0 {
            for _ in 0..added {
                record_fetch_started(self.kind);
            }
            debug!(count = added, "Started id fetch");
        }
        self.spawn_pending_fetches()
    }

    fn handle_failed(&mut self, ids: &[Id]) -> Vec<FetchOutput<Id>> {
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
            for _ in 0..released {
                record_fetch_retried(self.kind);
            }
            trace!(count = released, "Id fetch chunk failed");
        }
        self.spawn_pending_fetches()
    }

    fn handle_drop(&mut self, ids: &[Id], kind: DropKind) -> Vec<FetchOutput<Id>> {
        for id in ids {
            if self.pending.remove(id).is_some() {
                match kind {
                    DropKind::Admitted => record_fetch_completed(self.kind),
                    DropKind::Abandoned => record_fetch_abandoned(self.kind),
                }
            }
        }
        // A drop frees a slot; surface any pending entries that were
        // waiting on capacity.
        self.spawn_pending_fetches()
    }

    fn spawn_pending_fetches(&mut self) -> Vec<FetchOutput<Id>> {
        let in_flight_now = self.in_flight_count();
        let global_room = self.config.max_in_flight.saturating_sub(in_flight_now);
        if global_room == 0 {
            return vec![];
        }

        // Group ready ids by `(peer-pool content, origin)`. Two `Request`
        // calls that carry identical `FetchPeers` end up with distinct `Arc`s
        // but should still coalesce into one `Send` — keying by Arc identity
        // defeats batching for callers that emit single-id Actions
        // (e.g. exec-cert, remote-provision). Origins differ in network
        // class, so two ids requested with the same peers but different
        // origins issue as separate `Send`s.
        let mut groups: HashMap<GroupKey, GroupValue<Id>> = HashMap::new();
        let mut taken = 0usize;
        for (id, entry) in &self.pending {
            if taken >= global_room {
                break;
            }
            if entry.in_flight {
                continue;
            }
            groups
                .entry(((*entry.peers).clone(), entry.origin))
                .or_insert_with(|| (Arc::clone(&entry.peers), entry.origin, Vec::new()))
                .2
                .push(id.clone());
            taken += 1;
        }

        // Iterate groups in sorted order for deterministic test output.
        let mut group_order: Vec<GroupKey> = groups.keys().cloned().collect();
        group_order.sort_unstable_by(|a, b| {
            a.0.preferred
                .map(ValidatorId::inner)
                .cmp(&b.0.preferred.map(ValidatorId::inner))
                .then_with(|| a.0.peers.cmp(&b.0.peers))
                .then_with(|| a.1.cmp(&b.1))
        });

        let mut outputs = Vec::new();
        let mut chunks_emitted = 0usize;
        'outer: for key in group_order {
            let (peers, origin, ids) = groups.remove(&key).expect("key just collected");
            for chunk in ids.chunks(self.config.max_ids_per_request) {
                if chunks_emitted >= self.config.parallel_chunks_per_tick {
                    break 'outer;
                }
                for id in chunk {
                    if let Some(entry) = self.pending.get_mut(id) {
                        entry.in_flight = true;
                    }
                }
                outputs.push(FetchOutput::Send {
                    ids: chunk.to_vec(),
                    peers: (*peers).clone(),
                    origin,
                });
                chunks_emitted += 1;
            }
        }
        outputs
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{Hash, TxHash, ValidatorId};

    use super::*;

    fn tx(n: u8) -> TxHash {
        TxHash::from_raw(Hash::from_bytes(&[n; 32]))
    }

    fn vid(n: u64) -> ValidatorId {
        ValidatorId::new(n)
    }

    fn config() -> FetchConfig {
        FetchConfig {
            max_in_flight: 100,
            max_ids_per_request: 2,
            parallel_chunks_per_tick: 4,
        }
    }

    fn pinned(v: ValidatorId) -> FetchPeers {
        FetchPeers::with_preferred(v, vec![])
    }

    #[test]
    fn request_emits_chunked_sends() {
        let mut p = Fetch::<TxHash>::new("test", config());
        let out = p.handle(FetchInput::Request {
            ids: vec![tx(1), tx(2), tx(3), tx(4), tx(5)],
            peers: pinned(vid(1)),
            origin: FetchOrigin::PendingBlock,
        });
        assert_eq!(out.len(), 3);
        for o in &out {
            let FetchOutput::Send { peers, .. } = o;
            assert_eq!(peers.preferred, Some(vid(1)));
        }
        assert_eq!(p.in_flight_count(), 5);
    }

    #[test]
    fn failed_releases_chunk_and_redispatches() {
        let mut p = Fetch::<TxHash>::new("test", config());
        let out = p.handle(FetchInput::Request {
            ids: vec![tx(1), tx(2)],
            peers: pinned(vid(1)),
            origin: FetchOrigin::PendingBlock,
        });
        assert_eq!(out.len(), 1);
        let FetchOutput::Send { ids, .. } = &out[0];
        let chunk_ids = ids.clone();

        // The new contract: handle(Failed) returns the re-dispatch Sends
        // directly. The 2-call pattern (Failed then Tick) the old contract
        // required is gone — input handlers spawn pending fetches inline.
        let retry_out = p.handle(FetchInput::Failed { ids: chunk_ids });
        assert_eq!(p.in_flight_count(), 2);
        assert_eq!(retry_out.len(), 1);
    }

    #[test]
    fn admitted_drops_ids() {
        let mut p = Fetch::<TxHash>::new("test", config());
        p.handle(FetchInput::Request {
            ids: vec![tx(1), tx(2)],
            peers: pinned(vid(1)),
            origin: FetchOrigin::PendingBlock,
        });
        p.handle(FetchInput::Tick);

        p.handle(FetchInput::Admitted {
            ids: vec![tx(1), tx(2)],
        });
        assert!(!p.has_pending());
    }

    #[test]
    fn admitted_unknown_id_is_silent_noop() {
        let mut p = Fetch::<TxHash>::new("test", config());
        let out = p.handle(FetchInput::Admitted { ids: vec![tx(99)] });
        assert!(out.is_empty());
    }

    #[test]
    fn abandoned_drops_ids_like_admitted() {
        let mut p = Fetch::<TxHash>::new("test", config());
        p.handle(FetchInput::Request {
            ids: vec![tx(1), tx(2)],
            peers: pinned(vid(1)),
            origin: FetchOrigin::PendingBlock,
        });
        p.handle(FetchInput::Tick);

        p.handle(FetchInput::Abandoned {
            ids: vec![tx(1), tx(2)],
        });
        assert!(!p.has_pending());
    }

    #[test]
    fn duplicate_request_keeps_existing_peers() {
        let mut p = Fetch::<TxHash>::new("test", config());
        let first = p.handle(FetchInput::Request {
            ids: vec![tx(1)],
            peers: pinned(vid(1)),
            origin: FetchOrigin::PendingBlock,
        });
        // First request marks tx(1) in_flight under vid(1) and emits its Send.
        assert_eq!(first.len(), 1);
        // Second Request adds tx(2) under vid(2); tx(1) keeps its original
        // peer pool because it's already in_flight and the entry is
        // preserved by `or_insert_with`.
        let second = p.handle(FetchInput::Request {
            ids: vec![tx(1), tx(2)],
            peers: pinned(vid(2)),
            origin: FetchOrigin::PendingBlock,
        });
        assert_eq!(second.len(), 1);
        let FetchOutput::Send { peers, ids, .. } = &second[0];
        assert_eq!(peers.preferred, Some(vid(2)));
        assert_eq!(ids, &vec![tx(2)]);
    }

    #[test]
    fn siblings_share_peer_pool_via_arc_grouping() {
        let mut p = Fetch::<TxHash>::new(
            "test",
            FetchConfig {
                max_in_flight: 100,
                max_ids_per_request: 50,
                parallel_chunks_per_tick: 8,
            },
        );
        let out = p.handle(FetchInput::Request {
            ids: (0..30).map(tx).collect(),
            peers: pinned(vid(1)),
            origin: FetchOrigin::PendingBlock,
        });
        assert_eq!(out.len(), 1);
        let FetchOutput::Send { ids, .. } = &out[0];
        assert_eq!(ids.len(), 30);
    }

    #[test]
    fn global_in_flight_cap_bounds_emissions() {
        let mut p = Fetch::<TxHash>::new(
            "test",
            FetchConfig {
                max_in_flight: 3,
                max_ids_per_request: 10,
                parallel_chunks_per_tick: 4,
            },
        );
        p.handle(FetchInput::Request {
            ids: (0..10).map(tx).collect(),
            peers: pinned(vid(1)),
            origin: FetchOrigin::PendingBlock,
        });
        p.handle(FetchInput::Tick);
        assert_eq!(p.in_flight_count(), 3, "global cap honoured");
    }
}
