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
use std::time::Instant;

use hyperscale_metrics::{
    record_fetch_abandoned, record_fetch_completed, record_fetch_retried, record_fetch_started,
};
use hyperscale_types::{MessageClass, ShardGroupId, ValidatorId};
use tracing::{debug, trace};

pub mod binding;
pub mod exec_cert_serve;
pub mod finalized_wave_serve;
pub mod host;
pub mod provision_serve;
pub mod transaction_serve;

pub use host::FetchHost;

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
    /// Request `ids` against `shard`'s committee with `preferred` as the
    /// canonical-source hint. Idempotent: ids already pending keep their
    /// existing `(shard, preferred, class)` triple; new ids are added
    /// with the supplied values.
    Request {
        /// Ids to fetch.
        ids: Vec<Id>,
        /// Shard whose committee answers — forwarded as the routing
        /// argument to `Network::request`.
        shard: ShardGroupId,
        /// Canonical-source hint passed to `Network::request`. `None` lets
        /// the network's health-weighted rotation pick freely.
        preferred: Option<ValidatorId>,
        /// Class override forwarded to `Network::request`.
        class: Option<MessageClass>,
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
    /// Issue a network request for `ids`. The output handler translates this
    /// into `Network::request(shard, preferred, .., class, ..)`.
    Send {
        /// Ids in this chunk.
        ids: Vec<Id>,
        /// Shard whose committee answers — forwarded as the routing
        /// argument to `Network::request`.
        shard: ShardGroupId,
        /// Canonical-source hint forwarded to the network layer.
        preferred: Option<ValidatorId>,
        /// Class override shared by every id in this chunk; chunks are
        /// grouped by `(shard, preferred, class)` so this is well-defined.
        class: Option<MessageClass>,
    },
}

#[derive(Debug)]
struct Entry {
    shard: ShardGroupId,
    preferred: Option<ValidatorId>,
    class: Option<MessageClass>,
    in_flight: bool,
    /// When the entry most recently transitioned to `in_flight=true`.
    /// `None` while the entry is awaiting dispatch. Wall-clock-derived
    /// (`Instant`) because this is observability-only: an alert on
    /// `oldest_in_flight_age_ms` fires when admission stops happening,
    /// catching novel pin scenarios the existing per-drop notifications
    /// haven't been wired for yet.
    dispatched_at: Option<Instant>,
}

/// Why an id is being removed from the pending set — drives which counter
/// `handle_drop` increments.
#[derive(Debug, Clone, Copy)]
enum DropKind {
    Admitted,
    Abandoned,
}

/// Group key for ready ids during chunk assembly: same `(shard, preferred,
/// class)` coalesce; chunks that differ on any of those three issue as
/// separate `Send`s (different shards route to different committees,
/// different preferreds bias different peers, different classes carry
/// different network urgencies).
type GroupKey = (ShardGroupId, Option<ValidatorId>, Option<MessageClass>);

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
            FetchInput::Request {
                ids,
                shard,
                preferred,
                class,
            } => self.handle_request(ids, shard, preferred, class),
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

    /// Age in milliseconds of the longest-running in-flight entry, or
    /// `0` if nothing is in flight. Surfaced through `FetchHost::metrics`
    /// so an alert on `> N` catches admission paths that silently dropped
    /// without notifying the FSM — the symptom that motivated the
    /// provision-fetch robustness work in the first place.
    #[must_use]
    pub fn oldest_in_flight_age_ms(&self) -> u64 {
        let oldest = self.pending.values().filter_map(|e| e.dispatched_at).min();
        oldest.map_or(0, |t| {
            u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX)
        })
    }

    fn handle_request(
        &mut self,
        ids: Vec<Id>,
        shard: ShardGroupId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
    ) -> Vec<FetchOutput<Id>> {
        if ids.is_empty() {
            return vec![];
        }
        let mut added = 0usize;
        for id in ids {
            self.pending.entry(id).or_insert_with(|| {
                added += 1;
                Entry {
                    shard,
                    preferred,
                    class,
                    in_flight: false,
                    dispatched_at: None,
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
                entry.dispatched_at = None;
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

        // Group ready ids by `(shard, preferred, class)`. Two ids with the
        // same shard+preferred but different classes issue as separate
        // `Send`s.
        let mut groups: HashMap<GroupKey, Vec<Id>> = HashMap::new();
        let mut taken = 0usize;
        for (id, entry) in &self.pending {
            if taken >= global_room {
                break;
            }
            if entry.in_flight {
                continue;
            }
            groups
                .entry((entry.shard, entry.preferred, entry.class))
                .or_default()
                .push(id.clone());
            taken += 1;
        }

        // Iterate groups in sorted order for deterministic test output.
        let mut group_order: Vec<GroupKey> = groups.keys().copied().collect();
        group_order.sort_unstable_by(|a, b| {
            a.0.inner()
                .cmp(&b.0.inner())
                .then_with(|| {
                    a.1.map(ValidatorId::inner)
                        .cmp(&b.1.map(ValidatorId::inner))
                })
                .then_with(|| a.2.cmp(&b.2))
        });

        let mut outputs = Vec::new();
        let mut chunks_emitted = 0usize;
        'outer: for key in group_order {
            let (shard, preferred, class) = key;
            let ids = groups.remove(&key).expect("key just collected");
            for chunk in ids.chunks(self.config.max_ids_per_request) {
                if chunks_emitted >= self.config.parallel_chunks_per_tick {
                    break 'outer;
                }
                let dispatched_at = Instant::now();
                for id in chunk {
                    if let Some(entry) = self.pending.get_mut(id) {
                        entry.in_flight = true;
                        entry.dispatched_at = Some(dispatched_at);
                    }
                }
                outputs.push(FetchOutput::Send {
                    ids: chunk.to_vec(),
                    shard,
                    preferred,
                    class,
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

    const SHARD: ShardGroupId = ShardGroupId::new(0);

    #[test]
    fn request_emits_chunked_sends() {
        let mut p = Fetch::<TxHash>::new("test", config());
        let out = p.handle(FetchInput::Request {
            ids: vec![tx(1), tx(2), tx(3), tx(4), tx(5)],
            shard: SHARD,
            preferred: Some(vid(1)),
            class: None,
        });
        assert_eq!(out.len(), 3);
        for o in &out {
            let FetchOutput::Send { preferred, .. } = o;
            assert_eq!(*preferred, Some(vid(1)));
        }
        assert_eq!(p.in_flight_count(), 5);
    }

    #[test]
    fn failed_releases_chunk_and_redispatches() {
        let mut p = Fetch::<TxHash>::new("test", config());
        let out = p.handle(FetchInput::Request {
            ids: vec![tx(1), tx(2)],
            shard: SHARD,
            preferred: Some(vid(1)),
            class: None,
        });
        assert_eq!(out.len(), 1);
        let FetchOutput::Send { ids, .. } = &out[0];
        let chunk_ids = ids.clone();

        // handle(Failed) re-dispatches inline — no separate Tick needed.
        let retry_out = p.handle(FetchInput::Failed { ids: chunk_ids });
        assert_eq!(p.in_flight_count(), 2);
        assert_eq!(retry_out.len(), 1);
    }

    #[test]
    fn admitted_drops_ids() {
        let mut p = Fetch::<TxHash>::new("test", config());
        p.handle(FetchInput::Request {
            ids: vec![tx(1), tx(2)],
            shard: SHARD,
            preferred: Some(vid(1)),
            class: None,
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
            shard: SHARD,
            preferred: Some(vid(1)),
            class: None,
        });
        p.handle(FetchInput::Tick);

        p.handle(FetchInput::Abandoned {
            ids: vec![tx(1), tx(2)],
        });
        assert!(!p.has_pending());
    }

    #[test]
    fn duplicate_request_keeps_existing_preferred() {
        let mut p = Fetch::<TxHash>::new("test", config());
        let first = p.handle(FetchInput::Request {
            ids: vec![tx(1)],
            shard: SHARD,
            preferred: Some(vid(1)),
            class: None,
        });
        // First request marks tx(1) in_flight under vid(1) and emits its Send.
        assert_eq!(first.len(), 1);
        // Second Request adds tx(2) under vid(2); tx(1) keeps its original
        // `preferred` because it's already in_flight and the entry is
        // preserved by `or_insert_with`.
        let second = p.handle(FetchInput::Request {
            ids: vec![tx(1), tx(2)],
            shard: SHARD,
            preferred: Some(vid(2)),
            class: None,
        });
        assert_eq!(second.len(), 1);
        let FetchOutput::Send { preferred, ids, .. } = &second[0];
        assert_eq!(*preferred, Some(vid(2)));
        assert_eq!(ids, &vec![tx(2)]);
    }

    #[test]
    fn siblings_with_same_preferred_coalesce_into_one_send() {
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
            shard: SHARD,
            preferred: Some(vid(1)),
            class: None,
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
            shard: SHARD,
            preferred: Some(vid(1)),
            class: None,
        });
        p.handle(FetchInput::Tick);
        assert_eq!(p.in_flight_count(), 3, "global cap honoured");
    }
}
