//! Id-keyed fetch state machine plus its per-payload binding trait — the
//! scope-agnostic fetch engine.
//!
//! - The generic [`Fetch`] state machine owns scheduling only — pending
//!   sets, chunking, in-flight caps.
//! - The [`FetchBinding`] trait is the per-payload contract — which
//!   `Fetch<Id>` instance backs each payload and the wire shape of each
//!   request. The concrete impls live with their subsystem state
//!   (`shard/{consensus,cross_shard,mempool}`, `beacon`); the `ProtocolEvent`
//!   → in-flight-drain mapping lives outside the binding, in
//!   `ShardLoop::drive_fetch_admission`.
//! - [`ScopedAnswer`] is the contract for a binding whose request names one
//!   scope and whose answer is checked against it; [`dispatch_scoped`] is
//!   the one response boundary those bindings share.
//! - [`SolicitedAnswer`] is the contract for a binding whose request is a
//!   bag of ids and whose answer a bag of items; [`dispatch_solicited`] is
//!   the response boundary those share, filtering through
//!   [`partition_solicited`].

use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::Hash;

use crossbeam::channel::Sender;
use hyperscale_core::{FetchIds, ProtocolEvent};
use hyperscale_metrics::{
    record_fetch_abandoned, record_fetch_completed, record_fetch_latency,
    record_fetch_response_refused, record_fetch_retried, record_fetch_started,
};
use hyperscale_network::{Answerers, Network, RequestError, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::Request;
use hyperscale_types::{MessageClass, ShardId, Stopwatch, ValidatorId};
use tracing::{debug, trace, warn};

use crate::event::{HostEvent, ShardScopedInput};
use crate::shard::{ShardIo, push_shard_input};

/// Tunables for a [`Fetch`] instance.
#[derive(Debug, Clone)]
pub struct FetchConfig {
    /// Maximum ids in flight across all entries simultaneously.
    pub(crate) max_in_flight: usize,
    /// Maximum ids in a single chunked request.
    pub(crate) max_ids_per_request: usize,
    /// Maximum chunks one dispatch emits — one input's worth of sends,
    /// whichever input freed the room.
    pub(crate) chunks_per_dispatch: usize,
}

impl FetchConfig {
    /// A fetch schedule with its limits: ids in flight across every
    /// entry, ids per request, and requests one dispatch may emit.
    ///
    /// # Panics
    ///
    /// Panics if any limit is zero: a zero limit never fetches.
    #[must_use]
    pub fn new(
        max_in_flight: usize,
        max_ids_per_request: usize,
        chunks_per_dispatch: usize,
    ) -> Self {
        assert!(
            max_in_flight > 0 && max_ids_per_request > 0 && chunks_per_dispatch > 0,
            "fetch limits must be positive",
        );
        Self {
            max_in_flight,
            max_ids_per_request,
            chunks_per_dispatch,
        }
    }
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            max_in_flight: 400,
            max_ids_per_request: 50,
            chunks_per_dispatch: 8,
        }
    }
}

/// Inputs to the protocol state machine.
#[derive(Debug)]
pub enum FetchInput<Id> {
    /// Request `ids` against `shard`'s committee with `preferred` as the
    /// canonical-source hint. Idempotent in the pending set — an id
    /// already tracked is not added twice — but the route it carries is
    /// the latest one asked for: an ask states where the answer is, and
    /// an id can have more than one asker saying it. Takes effect on the
    /// next dispatch, so a chunk already in flight is unaffected.
    Request {
        /// Ids to fetch.
        ids: Vec<Id>,
        /// Shard whose committee answers — forwarded as the routing
        /// argument to `Network::request`.
        shard: ShardId,
        /// Canonical-source hint passed to `Network::request`. `None` lets
        /// the network's health-weighted rotation pick freely.
        preferred: Option<ValidatorId>,
        /// Class override forwarded to `Network::request`.
        class: Option<MessageClass>,
    },
    /// A network attempt for `ids` failed (or returned an unusable response);
    /// reclaim them for retry, at once on the first failure since the last
    /// [`Self::Tick`] and on the tick after that.
    Failed {
        /// Ids that were in flight on the failed chunk.
        ids: Vec<Id>,
    },
    /// Payload for `ids` landed via fetch response, gossip, or local
    /// production. Fed by `ShardLoop::drive_fetch_admission` on canonical
    /// admission `ProtocolEvent`s. Records `record_fetch_completed` per
    /// id removed.
    Admitted {
        /// Ids whose payloads have been admitted.
        ids: Vec<Id>,
    },
    /// Consumer coordinator dropped its expectation for `ids`. Fed by
    /// the loop's `Action::AbandonFetch` dispatcher. Records
    /// `record_fetch_abandoned` per id removed — distinct from `Admitted`
    /// so the two populations are observable separately.
    Abandoned {
        /// Ids whose fetch has been cancelled by the originating coordinator.
        ids: Vec<Id>,
    },
    /// A chunk that never reached a peer: release the slots and leave
    /// the retry to [`Self::Tick`].
    Unroutable {
        /// Ids in the chunk.
        ids: Vec<Id>,
    },
    /// Drive pending fetches: emit chunks up to the per-dispatch and
    /// global caps.
    /// Every id's inline retry is restored first.
    Tick,
}

/// Outputs from the protocol state machine.
#[derive(Debug)]
pub enum FetchOutput<Id> {
    /// Issue a network request for `ids` along `route`.
    Send {
        /// Ids in this chunk.
        ids: Vec<Id>,
        /// Where the chunk is asked. Chunks are grouped by it, so every id
        /// in one shares it.
        route: Route,
    },
}

/// Where one chunk is asked. Chunks that differ on any field issue as
/// separate requests: different shards route to different committees,
/// different preferreds bias different peers, different classes carry
/// different network urgencies, and a chunk asked past the local seats
/// cannot ride with one that asks them first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Route {
    /// Shard whose committee answers.
    pub shard: ShardId,
    /// Canonical-source hint, when one exists.
    pub preferred: Option<ValidatorId>,
    /// Class override forwarded to the network layer.
    pub class: Option<MessageClass>,
    /// Who may answer. A failed attempt's retry asks whichever of this
    /// host's replica and the committee's other members the attempt did
    /// not, since this host's replica answers every retry the same way.
    pub answerers: Answerers,
}

impl Route {
    /// Send `request` along this route.
    pub fn request<N: Network, R: Request + Clone + 'static>(
        self,
        network: &N,
        request: R,
        on_response: Box<dyn FnOnce(Result<R::Response, RequestError>) -> ResponseVerdict + Send>,
    ) {
        network.request_from(
            self.shard,
            self.answerers,
            self.preferred,
            request,
            self.class,
            on_response,
        );
    }
}

#[derive(Debug)]
struct Entry {
    shard: ShardId,
    preferred: Option<ValidatorId>,
    class: Option<MessageClass>,
    in_flight: bool,
    /// The preferred peer the in-flight attempt went to. A re-ask may
    /// restate `preferred` while the attempt is out; only a failure of
    /// the peer actually asked drops the preference.
    asked: Option<ValidatorId>,
    /// When the entry most recently transitioned to `in_flight=true`.
    /// `None` while the entry is awaiting dispatch. Wall-clock-derived
    /// because this is observability-only: an alert on
    /// `oldest_in_flight_age_ms` fires when admission stops happening,
    /// catching an id pinned in flight by a path that releases nothing.
    dispatched_at: Option<Stopwatch>,
    /// Who the in-flight attempt asked, or who the next one asks. A
    /// failure flips it, so the local seats and the committee's other
    /// members take turns and neither is asked twice running between
    /// ticks; the tick resets it to [`Answerers::LocalFirst`] on every
    /// entry it may send. A peers-only instance keeps it at
    /// [`Answerers::PeersOnly`] throughout.
    answerers: Answerers,
    /// Failures since the last tick. The first retries at once; past it
    /// the id waits for the tick, since the same answer is coming back. A
    /// re-ask keeps the hold and only the tick lifts it: a consumer that
    /// re-asks on every failure would otherwise reopen the loop the hold
    /// closes. An unroutable chunk does not count, as it waits for the
    /// tick anyway.
    failures_since_tick: u8,
}

/// Why an id is being removed from the pending set — drives which counter
/// `handle_drop` increments.
#[derive(Debug, Clone, Copy)]
enum DropKind {
    Admitted,
    Abandoned,
}

/// Id-keyed fetch state machine.
pub struct Fetch<Id: Eq + Hash + Ord + Clone> {
    config: FetchConfig,
    /// Routed into the global metrics recorder as the `kind` label.
    kind: &'static str,
    /// `BTreeMap` for deterministic iteration order during chunk assembly.
    pending: BTreeMap<Id, Entry>,
    /// Every attempt asks past the local seats: an answer this host could
    /// give itself is one its own consumer already lacks.
    peers_only: bool,
}

impl<Id: Eq + Hash + Ord + Clone + std::fmt::Debug> Fetch<Id> {
    /// Create a new protocol instance with the given config.
    ///
    /// `kind` labels metrics emitted by this instance.
    #[must_use]
    pub(crate) const fn new(kind: &'static str, config: FetchConfig) -> Self {
        Self {
            config,
            kind,
            pending: BTreeMap::new(),
            peers_only: false,
        }
    }

    /// A protocol instance whose every attempt, first, retried or
    /// ticked, asks only the committee's members this host does not run.
    #[must_use]
    pub(crate) const fn peers_only(kind: &'static str, config: FetchConfig) -> Self {
        Self {
            config,
            kind,
            pending: BTreeMap::new(),
            peers_only: true,
        }
    }

    /// Who a new entry, or one the tick resets, asks first.
    const fn first_answerers(&self) -> Answerers {
        if self.peers_only {
            Answerers::PeersOnly
        } else {
            Answerers::LocalFirst
        }
    }

    /// Process an input and return outputs.
    pub(crate) fn handle(&mut self, input: FetchInput<Id>) -> Vec<FetchOutput<Id>> {
        match input {
            FetchInput::Request {
                ids,
                shard,
                preferred,
                class,
            } => self.handle_request(ids, shard, preferred, class),
            FetchInput::Failed { ids } => self.handle_failed(&ids, Respawn::Now),
            FetchInput::Unroutable { ids } => self.handle_failed(&ids, Respawn::OnTick),
            FetchInput::Admitted { ids } => self.handle_drop(&ids, DropKind::Admitted),
            FetchInput::Abandoned { ids } => self.handle_drop(&ids, DropKind::Abandoned),
            FetchInput::Tick => {
                let answerers = self.first_answerers();
                for entry in self.pending.values_mut() {
                    entry.failures_since_tick = 0;
                    if !entry.in_flight {
                        entry.answerers = answerers;
                    }
                }
                self.spawn_pending_fetches()
            }
        }
    }

    /// Whether any id is currently tracked.
    #[must_use]
    pub(crate) fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Number of ids currently dispatched and not yet acknowledged.
    #[must_use]
    pub(crate) fn in_flight_count(&self) -> usize {
        self.pending.values().filter(|e| e.in_flight).count()
    }

    /// Total ids currently tracked (in-flight or awaiting dispatch).
    #[must_use]
    pub(crate) fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Every id currently tracked, in sorted order. A driver whose
    /// consumer re-derives its wanted set each tick diffs against this to
    /// abandon what the consumer no longer asks for — without it an id
    /// nobody answers stays in the pending set for the process's life.
    pub(crate) fn pending_ids(&self) -> impl Iterator<Item = &Id> {
        self.pending.keys()
    }

    /// Age in milliseconds of the longest-running in-flight entry, or
    /// `0` if nothing is in flight. Surfaced through `ShardIo::fetch_metrics`
    /// so an alert on `> N` catches admission paths that silently dropped
    /// without notifying the FSM.
    #[must_use]
    pub(crate) fn oldest_in_flight_age_ms(&self) -> u64 {
        let oldest = self
            .pending
            .values()
            .filter_map(|e| e.dispatched_at.map(|t| t.elapsed()))
            .max();
        oldest.map_or(0, |age| u64::try_from(age.as_millis()).unwrap_or(u64::MAX))
    }

    fn handle_request(
        &mut self,
        ids: Vec<Id>,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
    ) -> Vec<FetchOutput<Id>> {
        if ids.is_empty() {
            return vec![];
        }
        let mut added = 0usize;
        let answerers = self.first_answerers();
        for id in ids {
            // Where an id is answerable from is what the asker just
            // said, not what the first asker once said. Two owners of
            // one id space route differently on purpose — a pending
            // block asks the proposer that provably holds the body, the
            // mempool asks the source shard — and both re-ask on their
            // own cadence, so holding the first route forever leaves one
            // of them asking a committee that may never answer.
            if let Some(entry) = self.pending.get_mut(&id) {
                entry.shard = shard;
                entry.preferred = preferred;
                entry.class = class;
            } else {
                added += 1;
                self.pending.insert(
                    id,
                    Entry {
                        shard,
                        preferred,
                        class,
                        in_flight: false,
                        asked: None,
                        dispatched_at: None,
                        answerers,
                        failures_since_tick: 0,
                    },
                );
            }
        }
        if added > 0 {
            for _ in 0..added {
                record_fetch_started(self.kind);
            }
            debug!(count = added, "Started id fetch");
        }
        self.spawn_pending_fetches()
    }

    /// Release a chunk's slots for retry. A chunk that reached its
    /// preferred peer and failed also drops the preference: the hint
    /// named where the answer should be, that peer has now been asked,
    /// and pinning every retry to it would let one peer that answers
    /// "not held" keep the requester from ever reaching the peers that
    /// do hold it.
    ///
    /// A failure's retry asks whoever the failed attempt did not: an
    /// answer served from this host's replica costs no round trip and comes
    /// back the same each time it is asked, so a failure after asking the
    /// replica goes to the committee's other members, and one after asking
    /// only them gives the replica, which may have caught up since, the
    /// next turn. Only the first failure since the tick retries
    /// at once. One from a committee that all answers alike comes back the
    /// same too, so a second failure before the tick waits for it. Where a
    /// round trip is a few milliseconds, as on a LAN or within one region,
    /// two failed sweeps of a small committee fit well inside one tick, so
    /// an id whose payload is still in gossip can wait up to a tick longer
    /// than it would by asking again at once.
    fn handle_failed(&mut self, ids: &[Id], respawn: Respawn) -> Vec<FetchOutput<Id>> {
        let mut released = 0usize;
        let peers_only = self.peers_only;
        for id in ids {
            if let Some(entry) = self.pending.get_mut(id)
                && entry.in_flight
            {
                entry.in_flight = false;
                entry.dispatched_at = None;
                let asked = entry.asked.take();
                if matches!(respawn, Respawn::Now) {
                    entry.failures_since_tick = entry.failures_since_tick.saturating_add(1);
                    entry.answerers = match entry.answerers {
                        _ if peers_only => Answerers::PeersOnly,
                        Answerers::LocalFirst => Answerers::PeersOnly,
                        Answerers::PeersOnly => Answerers::LocalFirst,
                    };
                    if asked == entry.preferred {
                        entry.preferred = None;
                    }
                }
                released += 1;
            }
        }
        if released > 0 {
            for _ in 0..released {
                record_fetch_retried(self.kind);
            }
            trace!(count = released, "Id fetch chunk failed");
        }
        match respawn {
            Respawn::Now => self.spawn_pending_fetches(),
            Respawn::OnTick => Vec::new(),
        }
    }

    fn handle_drop(&mut self, ids: &[Id], kind: DropKind) -> Vec<FetchOutput<Id>> {
        for id in ids {
            if let Some(entry) = self.pending.remove(id) {
                match kind {
                    DropKind::Admitted => {
                        record_fetch_completed(self.kind);
                        if let Some(dispatched_at) = entry.dispatched_at {
                            record_fetch_latency(self.kind, dispatched_at.elapsed().as_secs_f64());
                        }
                    }
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

        // Group ready ids by route.
        let mut groups: HashMap<Route, Vec<Id>> = HashMap::new();
        let mut taken = 0usize;
        for (id, entry) in &self.pending {
            if taken >= global_room {
                break;
            }
            if entry.in_flight || entry.failures_since_tick > 1 {
                continue;
            }
            groups
                .entry(Route {
                    shard: entry.shard,
                    preferred: entry.preferred,
                    class: entry.class,
                    answerers: entry.answerers,
                })
                .or_default()
                .push(id.clone());
            taken += 1;
        }

        // Iterate groups in sorted order for deterministic test output.
        let mut group_order: Vec<Route> = groups.keys().copied().collect();
        group_order.sort_unstable_by(|a, b| {
            a.shard
                .inner()
                .cmp(&b.shard.inner())
                .then_with(|| {
                    a.preferred
                        .map(ValidatorId::inner)
                        .cmp(&b.preferred.map(ValidatorId::inner))
                })
                .then_with(|| a.class.cmp(&b.class))
                .then_with(|| a.answerers.cmp(&b.answerers))
        });

        let mut outputs = Vec::new();
        let mut chunks_emitted = 0usize;
        'outer: for route in group_order {
            let ids = groups.remove(&route).expect("route just collected");
            for chunk in ids.chunks(self.config.max_ids_per_request) {
                if chunks_emitted >= self.config.chunks_per_dispatch {
                    break 'outer;
                }
                let dispatched_at = Stopwatch::start();
                for id in chunk {
                    if let Some(entry) = self.pending.get_mut(id) {
                        entry.in_flight = true;
                        entry.asked = route.preferred;
                        entry.dispatched_at = Some(dispatched_at);
                    }
                }
                outputs.push(FetchOutput::Send {
                    ids: chunk.to_vec(),
                    route,
                });
                chunks_emitted += 1;
            }
        }
        outputs
    }
}

// ─── Binding trait ─────────────────────────────────────────────────────

/// A per-payload binding of the generic [`Fetch`] state machine.
///
/// Each fetch payload (transactions, provisions, headers, …) gets one impl —
/// living with its subsystem state in `shard/{consensus,cross_shard,mempool}`
/// or `beacon` — that owns the `Id` type and the arm of its loop's id
/// family it rides in: [`FetchIds`] for a shard loop's,
/// [`BeaconFetchIds`](hyperscale_core::BeaconFetchIds) for the beacon
/// loop's. Which `Fetch<Id>` instance
/// backs it and the wire shape of its requests are [`FetchedBy`], per
/// loop that drives it.
pub trait FetchBinding: 'static {
    /// Id used to address payloads of this kind.
    type Id: Clone + Ord + Hash + std::fmt::Debug + Send + Sync + 'static;

    /// The id family of the loop that drives this binding.
    type Ids: Send + 'static;

    /// Stable identifier for this binding — used in dispatch tracing.
    const NAME: &'static str;

    /// One network request per id (vs. one batched request per chunk).
    /// Cross-shard fetches that target a single `(shard, height)` set this
    /// to `true`; bag-of-hashes fetches leave it `false`.
    const PER_ID: bool = false;

    /// The [`Self::Ids`] arm that carries this binding's ids — how a
    /// response boundary names the ids it failed or fulfilled, and the
    /// inverse of the one dispatcher that routes a batch back here.
    fn ids(ids: Vec<Self::Id>) -> Self::Ids;
}

/// A loop that owns fetch state: the shard loop's [`ShardIo`] or the
/// beacon loop's fetches.
pub trait FetchOwner {
    /// How an answer finds its way back to this loop.
    type Reply: FetchReply;
}

/// A binding as the fetch-state owner `O` drives it.
pub trait FetchedBy<O: FetchOwner>: FetchBinding<Ids = <O::Reply as FetchReply>::Ids> {
    /// Locate this binding's `Fetch<Id>` instance inside `O`.
    fn fetch_mut(owner: &mut O) -> &mut Fetch<Self::Id>;

    /// Send one request covering `ids` along `route` and route the
    /// response back through `reply`. For [`PER_ID`](FetchBinding::PER_ID)
    /// bindings the dispatcher pre-splits into single-element chunks
    /// before calling this.
    fn dispatch_chunk<N: Network>(ids: Vec<Self::Id>, route: Route, network: &N, reply: &O::Reply);
}

/// Where a fetch's outcome goes: the loop whose fetch state asked, so a
/// failure releases what it asked for and an answer reaches what wanted
/// it.
pub trait FetchReply: Clone + Send + 'static {
    /// The id family of the loop this reply reaches.
    type Ids;

    /// Release `ids` after a request that failed with `error`: on the
    /// tick when it never reached a peer, at once otherwise.
    fn failed(&self, ids: Self::Ids, error: &RequestError);

    /// Release `ids` for retry after an answer that did not settle them:
    /// one refused, or one that left them out.
    fn refused(&self, ids: Self::Ids);

    /// Retire `ids` and hand over the event their answer carries. The
    /// ids are released first, so the freed capacity is available if
    /// handling the event re-drives the fetch.
    fn answered(&self, ids: Self::Ids, event: ProtocolEvent);
}

/// A shard loop's reply handle: its event channel, with the hosted shard
/// that asked so the outcome reaches that shard's loop under
/// cross-shard hosting (distinct from `route.shard`, which selects the
/// target committee).
#[derive(Clone)]
pub struct ShardReply {
    pub(crate) shard: ShardId,
    pub(crate) sender: Sender<HostEvent>,
}

impl FetchReply for ShardReply {
    type Ids = FetchIds;

    fn failed(&self, ids: FetchIds, error: &RequestError) {
        let release = if defers_to_the_tick(error) {
            ShardScopedInput::FetchUnroutable(ids)
        } else {
            ShardScopedInput::FetchFailed(ids)
        };
        push_shard_input(&self.sender, self.shard, release);
    }

    fn refused(&self, ids: FetchIds) {
        push_shard_input(&self.sender, self.shard, ShardScopedInput::FetchFailed(ids));
    }

    fn answered(&self, ids: FetchIds, event: ProtocolEvent) {
        self.hand_over(Some(ids), vec![ShardScopedInput::Protocol(Box::new(event))]);
    }
}

impl HandsOver<ShardScopedInput> for ShardReply {
    fn hand_over(&self, fulfilled: Option<FetchIds>, inputs: Vec<ShardScopedInput>) {
        if let Some(ids) = fulfilled {
            push_shard_input(
                &self.sender,
                self.shard,
                ShardScopedInput::FetchFulfilled(ids),
            );
        }
        for input in inputs {
            push_shard_input(&self.sender, self.shard, input);
        }
    }
}

impl<S: ShardStorage> FetchOwner for ShardIo<S> {
    type Reply = ShardReply;
}

// ─── Scoped answers ────────────────────────────────────────────────────

/// A binding whose request names one scope and asks about keys under it,
/// and whose answer is checked against that scope before anything
/// downstream sees it: a committed-transaction query against a
/// predecessor's terminal, a state proof against an anchor's root, a
/// witness run against a committed block. [`dispatch_scoped`] is the one
/// response boundary these share; the impl is the pure part — how an id
/// splits, what the request looks like, and what the answer has to lift
/// to.
pub trait ScopedAnswer: FetchBinding {
    /// What one request is checked against. A chunk is grouped by
    /// `(shard, preferred, class)`, which does not separate two scopes of
    /// one shard, so the dispatcher splits a chunk by this before it
    /// issues anything.
    type Scope: Copy + Ord + std::fmt::Debug + Send + Sync + 'static;
    /// What is asked under a scope — `()` when the scope is the whole
    /// question.
    type Key: Copy + std::fmt::Debug + Send + Sync + 'static;
    /// The wire request one scope's keys ride in.
    type Request: Request + Clone + 'static;

    /// The id as its scope and key.
    fn split(id: Self::Id) -> (Self::Scope, Self::Key);

    /// The id a scope and key name.
    fn join(scope: Self::Scope, key: Self::Key) -> Self::Id;

    /// One request for `keys` under `scope`.
    fn request(scope: Self::Scope, keys: &[Self::Key]) -> Self::Request;

    /// Check a peer's answer against the scope and turn it into the
    /// event that carries it, or say why it is refused. The event is
    /// what every replica reads; nothing unverified reaches it.
    fn answer(
        scope: Self::Scope,
        keys: Vec<Self::Key>,
        response: <Self::Request as Request>::Response,
    ) -> Result<ProtocolEvent, Refusal>;
}

/// Why a scoped answer is refused at the response boundary. Either way
/// the ids are released for retry against another peer and the response
/// is rejected for peer scoring; an unusable one is also counted under
/// its reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The peer does not hold the scope — a pruned height, a terminal it
    /// never served.
    NotHeld,
    /// The peer answered, but with something that does not lift to the
    /// scope. The label is the metric reason.
    Unusable(&'static str),
}

/// What a refusal says about the peer that gave it.
///
/// Only one of the two is the peer's fault. A scope it does not hold is
/// an honest answer about a height it has pruned or a terminal it never
/// served, and every member of a committee asked below its own retention
/// floor gives the same one — so scoring it would deprioritize a whole
/// honest committee for answering correctly, and the requester would
/// rotate away from the only peers there are. An answer that does not
/// lift to the scope is the peer's fault and is scored.
///
/// `Accept` is not a reward: the transports act on `Reject` alone, so
/// this leaves an honest refusal costing a round trip and nothing else.
/// The ids release the same way either way.
pub const fn scored(refusal: Refusal) -> ResponseVerdict {
    match refusal {
        Refusal::NotHeld => ResponseVerdict::Accept,
        Refusal::Unusable(_) => ResponseVerdict::Reject,
    }
}

/// Whether a transport error leaves the retry to the tick.
///
/// Only an error that never reached a peer does: the peer set is the
/// reason, and re-dispatching into the same set inside the response
/// callback would spin — an empty committee stays empty, and a committee
/// whose every stream is backing off answers the same until the soonest
/// reopens, which the tick's cadence outlasts. Everything the transport
/// already answered — a timeout, an exhausted retry budget, a peer-level
/// error — has had per-peer and per-request backoff absorbed below this
/// seam already, so it retries inline against a rotated peer.
pub const fn defers_to_the_tick(error: &RequestError) -> bool {
    matches!(
        error,
        RequestError::NoPeers | RequestError::PeerUnreachable(_) | RequestError::BackingOff { .. }
    )
}

/// Issue one request per scope in `ids` and route each answer through
/// [`ScopedAnswer::answer`] to `reply`. A transport error releases the
/// ids without rejecting the response — the network already recorded
/// it — while an answer that is not an answer counts as a refusal.
pub fn dispatch_scoped<B: ScopedAnswer, N: Network, R: FetchReply<Ids = B::Ids>>(
    ids: Vec<B::Id>,
    route: Route,
    network: &N,
    reply: &R,
) {
    let mut by_scope: BTreeMap<B::Scope, Vec<B::Key>> = BTreeMap::new();
    for id in ids {
        let (scope, key) = B::split(id);
        by_scope.entry(scope).or_default().push(key);
    }
    for (scope, keys) in by_scope {
        let requested: Vec<B::Id> = keys.iter().map(|key| B::join(scope, *key)).collect();
        let reply = reply.clone();
        route.request(
            network,
            B::request(scope, &keys),
            Box::new(move |result| {
                let response = match result {
                    Ok(response) => response,
                    Err(error) => return transport_failed::<B, R>(requested, &error, &reply),
                };
                match B::answer(scope, keys, response) {
                    Ok(event) => {
                        reply.answered(B::ids(requested), event);
                        ResponseVerdict::Accept
                    }
                    Err(refusal) => {
                        if let Refusal::Unusable(reason) = refusal {
                            warn!(
                                binding = B::NAME,
                                scope = ?scope,
                                reason,
                                "Dropping fetch response: unusable answer"
                            );
                            record_fetch_response_refused(B::NAME, reason);
                        }
                        reply.refused(B::ids(requested));
                        scored(refusal)
                    }
                }
            }),
        );
    }
}

/// Release `requested` after a request that failed with `error`. The
/// network has already recorded the failure against its peer, so the
/// response is not rejected again here.
pub fn transport_failed<B: FetchBinding, R: FetchReply<Ids = B::Ids>>(
    requested: Vec<B::Id>,
    error: &RequestError,
    reply: &R,
) -> ResponseVerdict {
    if matches!(error, RequestError::PeerError(_)) {
        record_fetch_response_refused(B::NAME, "unusable_answer");
    }
    reply.failed(B::ids(requested), error);
    ResponseVerdict::Accept
}

// ─── Solicited answers ─────────────────────────────────────────────────

/// When a kept answer lets go of the ids it answers for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settles {
    /// The response boundary is the whole check, so a kept item retires
    /// its ids as it lands.
    OnAnswer,
    /// The asker finishes the check after the answer lands, against a
    /// header or a committee it may not hold yet, so the ids stay in
    /// flight until its verdict: an admission, or an abandon or failure
    /// naming them. Retiring them at the answer would let the asker's own
    /// re-ask fetch the answer again while the first copy is still being
    /// checked, and leave nothing to ask again when the check fails.
    OnVerdict,
}

/// A binding whose request names a bag of ids and whose answer is a bag
/// of items, each answering for the ids it names. [`dispatch_solicited`]
/// is the one response boundary these share, with one rule: a kept item
/// reaches the asker, a requested id nothing answered releases for retry
/// at no cost to the peer, since a peer trims its answer to a budget or
/// does not hold the item, and only an item answering for nothing asked
/// rejects the response.
pub trait SolicitedAnswer: FetchBinding {
    /// The wire request one chunk's ids ride in.
    type Request: Request + Clone + 'static;
    /// One item of an answer.
    type Item: Send + 'static;
    /// What kept items reach the asking loop as.
    type Input: Send + 'static;
    /// When a kept item's ids release.
    const SETTLES: Settles;

    /// One request for `ids`.
    fn request(ids: &[Self::Id]) -> Self::Request;

    /// The items an answer carries. One that carries nothing the asker
    /// can use is left out, which reads as the peer not holding it.
    fn items(response: <Self::Request as Request>::Response) -> Vec<Self::Item>;

    /// The ids `item` answers for. An item that answers for none asked
    /// is unsolicited.
    fn answers_for(item: &Self::Item) -> impl IntoIterator<Item = Self::Id> + use<Self>;

    /// What the kept items reach the asker as, in order.
    fn deliver(kept: Vec<Self::Item>) -> Vec<Self::Input>;
}

/// A reply that hands a binding's own loop input to the loop that asked:
/// what a [`SolicitedAnswer`]'s kept items reach it as.
pub trait HandsOver<Input>: FetchReply {
    /// Retire `fulfilled`, when given, then hand over `inputs` in order.
    fn hand_over(&self, fulfilled: Option<Self::Ids>, inputs: Vec<Input>);
}

/// Issue one request for `ids` and route its answer to `reply` under the
/// [`SolicitedAnswer`] rule.
pub fn dispatch_solicited<B, N, R>(ids: Vec<B::Id>, route: Route, network: &N, reply: &R)
where
    B: SolicitedAnswer,
    N: Network,
    R: HandsOver<B::Input> + FetchReply<Ids = B::Ids>,
{
    let request = B::request(&ids);
    let reply = reply.clone();
    route.request(
        network,
        request,
        Box::new(move |result| settle_solicited::<B, R>(ids, result, &reply)),
    );
}

/// The response boundary of [`dispatch_solicited`]: release and hand over
/// what `result` answers for `requested`, and say what it says of the peer.
pub fn settle_solicited<B, R>(
    requested: Vec<B::Id>,
    result: Result<<B::Request as Request>::Response, RequestError>,
    reply: &R,
) -> ResponseVerdict
where
    B: SolicitedAnswer,
    R: HandsOver<B::Input> + FetchReply<Ids = B::Ids>,
{
    let response = match result {
        Ok(response) => response,
        Err(error) => return transport_failed::<B, R>(requested, &error, reply),
    };
    let split = partition_solicited(B::items(response), &requested, B::answers_for);
    if !split.kept.is_empty() {
        let fulfilled = match B::SETTLES {
            Settles::OnAnswer => {
                let missing: HashSet<&B::Id> = split.missing.iter().collect();
                let kept: Vec<B::Id> = requested
                    .iter()
                    .filter(|id| !missing.contains(id))
                    .cloned()
                    .collect();
                Some(B::ids(kept))
            }
            Settles::OnVerdict => None,
        };
        reply.hand_over(fulfilled, B::deliver(split.kept));
    }
    if !split.missing.is_empty() {
        reply.refused(B::ids(split.missing));
    }
    if split.unsolicited > 0 {
        warn!(
            binding = B::NAME,
            unsolicited = split.unsolicited,
            "Dropping fetched items nobody asked for"
        );
        record_fetch_response_refused(B::NAME, "unsolicited");
        ResponseVerdict::Reject
    } else {
        ResponseVerdict::Accept
    }
}

/// Why a batch of ids leaves the in-flight set: the three id-carrying
/// [`FetchInput`]s, so one dispatcher can route a [`FetchIds`] batch to
/// its binding whichever way it is being released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Release {
    /// The attempt failed or went unanswered, whatever the reason; retry
    /// at once the first time since the tick, and on the tick after that.
    /// The retry asks whichever of the local seats and the committee's
    /// other members the failed attempt did not, so a refused local
    /// answer is not asked again before the tick. Peer selection is
    /// weighted, so a refused remote peer is penalised rather than
    /// excluded and may be chosen again.
    Failed,
    /// The request never reached a peer. Retry on the tick — see
    /// [`Respawn`].
    Unroutable,
    /// The payload landed; the ids are done.
    Admitted,
    /// The consumer no longer wants them.
    Abandoned,
}

impl Release {
    /// The [`FetchInput`] releasing `ids` this way.
    pub(crate) const fn input<Id>(self, ids: Vec<Id>) -> FetchInput<Id> {
        match self {
            Self::Failed => FetchInput::Failed { ids },
            Self::Unroutable => FetchInput::Unroutable { ids },
            Self::Admitted => FetchInput::Admitted { ids },
            Self::Abandoned => FetchInput::Abandoned { ids },
        }
    }
}

/// What to do with a batch of ids, erased over the id type.
///
/// The erasure is what keeps the one place a [`FetchIds`] arm is matched
/// back to its binding a flat match rather than one per intent: asking
/// and releasing differ in the [`FetchInput`] they build and in nothing
/// else.
///
/// [`FetchIds`]: hyperscale_core::FetchIds
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intent {
    /// Add the ids to the pending set, to be asked of `shard`'s
    /// committee. No `Send` goes out here — chunks fan out under the
    /// per-dispatch cap.
    Ask {
        /// Shard whose committee answers.
        shard: ShardId,
        /// Canonical-source hint, when one exists.
        preferred: Option<ValidatorId>,
        /// Class override forwarded to `Network::request`.
        class: Option<MessageClass>,
    },
    /// Take the ids back out of it, the way [`Release`] says.
    Let(Release),
}

impl Intent {
    /// The [`FetchInput`] this intent makes of `ids`.
    pub(crate) const fn input<Id>(self, ids: Vec<Id>) -> FetchInput<Id> {
        match self {
            Self::Ask {
                shard,
                preferred,
                class,
            } => FetchInput::Request {
                ids,
                shard,
                preferred,
                class,
            },
            Self::Let(how) => how.input(ids),
        }
    }
}

impl From<Release> for Intent {
    fn from(how: Release) -> Self {
        Self::Let(how)
    }
}

/// When a released chunk goes out again.
///
/// A request the transport answered — a timeout, an exhausted rotation,
/// a peer that held nothing, an answer this node could not use — leaves
/// again at once, once per tick, asking whoever the failed attempt did
/// not: a remote answer has cost a round trip and the retry rotates off
/// its peer, and a locally served answer would come back the same, so a
/// failure after asking the local seats goes to the committee's other
/// members. A request that never reached a peer has not been answered:
/// no committee resolves it, or none of its members is up, and it fails
/// again as fast as it is asked. Re-sending that here spins between this
/// thread and the transport for as long as the cause stands, which after
/// a restart is until the beacon folds a topology.
#[derive(Debug, Clone, Copy)]
enum Respawn {
    /// Send what the released slots make room for, now.
    Now,
    /// Leave it to the tick.
    OnTick,
}

/// Result of partitioning a fetch response against the requested set.
pub struct Partition<T, Id> {
    /// Items whose extracted id matched a requested id.
    pub(crate) kept: Vec<T>,
    /// Requested ids that didn't appear in the response.
    pub(crate) missing: Vec<Id>,
    /// Count of returned items whose id was NOT requested. A non-zero
    /// value indicates a buggy or malicious peer trying to inject items
    /// we never asked for.
    pub(crate) unsolicited: usize,
}

/// Split a fetch response into solicited / missing / unsolicited buckets.
///
/// Per-binding admit handlers downstream check binding-specific invariants
/// (mempool dedup + validity range for txs, signature quorum for ECs, merkle
/// proof for provisions) but none of them ask "did we request this?".
/// Filtering at the response boundary keeps unsolicited items from
/// reaching pre-verification state mutations and from racing the legitimate
/// fetch path.
///
/// `extract` yields every id a returned item answers for, which is one id
/// for most payloads and several for an execution certificate — a single
/// certificate covers every transaction of its tick, so it settles each
/// requested transaction it names at once. An item is kept when it answers
/// for at least one requested id, and unsolicited when it answers for none.
pub fn partition_solicited<T, Id, F, I>(
    returned: Vec<T>,
    requested: &[Id],
    extract: F,
) -> Partition<T, Id>
where
    Id: Clone + Eq + Hash,
    F: Fn(&T) -> I,
    I: IntoIterator<Item = Id>,
{
    let requested_set: HashSet<Id> = requested.iter().cloned().collect();
    let mut kept = Vec::with_capacity(returned.len().min(requested.len()));
    let mut delivered: HashSet<Id> = HashSet::with_capacity(requested.len());
    let mut unsolicited = 0usize;
    for item in returned {
        let mut answers_for_a_requested_id = false;
        for id in extract(&item) {
            if requested_set.contains(&id) {
                delivered.insert(id);
                answers_for_a_requested_id = true;
            }
        }
        if answers_for_a_requested_id {
            kept.push(item);
        } else {
            unsolicited += 1;
        }
    }
    let missing = requested
        .iter()
        .filter(|id| !delivered.contains(id))
        .cloned()
        .collect();
    Partition {
        kept,
        missing,
        unsolicited,
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{Hash, TxHash, ValidatorId};

    use super::*;

    fn tx(n: u8) -> TxHash {
        TxHash::from(Hash::from_bytes(&[n; 32]))
    }

    /// Only an error that never reached a peer defers to the tick.
    ///
    /// The distinction is load-bearing in both directions. Deferring
    /// what the transport already answered costs a whole tick of
    /// latency on every timeout; retrying inline on an empty peer set
    /// spins against nothing. The transport absorbs per-peer and
    /// per-request backoff below this seam, so an answered error has
    /// already waited.
    #[test]
    fn only_an_error_that_never_reached_a_peer_waits_for_the_tick() {
        assert!(defers_to_the_tick(&RequestError::NoPeers));
        assert!(defers_to_the_tick(&RequestError::PeerUnreachable(vid(3))));
        assert!(defers_to_the_tick(&RequestError::BackingOff {
            retry_in: std::time::Duration::from_millis(100),
        }));

        assert!(!defers_to_the_tick(&RequestError::Timeout));
        assert!(!defers_to_the_tick(&RequestError::Exhausted {
            attempts: 4
        }));
        assert!(!defers_to_the_tick(&RequestError::PeerError(
            "committee said no".into()
        )));
    }

    /// A peer that does not hold the scope is not the peer at fault.
    ///
    /// Every member of a committee asked about a height below its own
    /// retention floor answers the same way, so scoring it would
    /// deprioritize the whole committee for being honest and send the
    /// requester rotating away from the only peers that exist. An answer
    /// that does not lift to the scope is a different matter and is
    /// scored.
    #[test]
    fn only_an_unusable_answer_is_the_serving_peers_fault() {
        assert_eq!(scored(Refusal::NotHeld), ResponseVerdict::Accept);
        assert_eq!(
            scored(Refusal::Unusable("short list")),
            ResponseVerdict::Reject,
        );
    }

    fn vid(n: u64) -> ValidatorId {
        ValidatorId::new(n)
    }

    fn config() -> FetchConfig {
        FetchConfig {
            max_in_flight: 100,
            max_ids_per_request: 2,
            chunks_per_dispatch: 4,
        }
    }

    const SHARD: ShardId = ShardId::ROOT;

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
            let FetchOutput::Send { route, .. } = o;
            assert_eq!(route.preferred, Some(vid(1)));
        }
        assert_eq!(p.in_flight_count(), 5);
    }

    /// An id with two askers routes where the latest one says.
    ///
    /// The transactions id space has two owners with incompatible
    /// routes — a pending block asks the local shard with the proposer
    /// preferred, the mempool asks the source shard on the recovery
    /// class — and both re-ask on their own cadence. Holding whichever
    /// got there first would leave the other asking a committee that may
    /// never answer, for as long as the id is pending.
    #[test]
    fn a_re_ask_restates_where_the_answer_is() {
        let mut p = Fetch::<TxHash>::new("test", config());
        let source = ShardId::leaf(1, 1);
        p.handle(FetchInput::Request {
            ids: vec![tx(1)],
            shard: source,
            preferred: None,
            class: Some(MessageClass::Recovery),
        });
        // In flight under the first route; the second ask lands while it
        // is out, so it is the retry that takes the new route.
        p.handle(FetchInput::Request {
            ids: vec![tx(1)],
            shard: SHARD,
            preferred: Some(vid(7)),
            class: None,
        });
        assert_eq!(p.pending_count(), 1, "the id is tracked once");

        let retried = p.handle(FetchInput::Failed { ids: vec![tx(1)] });
        let [FetchOutput::Send { route, .. }] = retried.as_slice() else {
            panic!("one re-send, got {retried:?}");
        };
        assert_eq!(
            (route.shard, route.preferred, route.class),
            (SHARD, Some(vid(7)), None)
        );
    }

    /// A chunk the transport answered goes out again at once: the round
    /// trip is already spent, and the next attempt rotates to another
    /// peer.
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

        let retry_out = p.handle(FetchInput::Failed { ids: chunk_ids });
        assert_eq!(p.in_flight_count(), 2);
        assert_eq!(retry_out.len(), 1);
    }

    /// A preferred peer that was asked and failed is not asked first
    /// again: the retry goes to the network's rotation.
    #[test]
    fn a_failed_chunk_retries_without_its_preferred_peer() {
        let mut p = Fetch::<TxHash>::new("test", config());
        let out = p.handle(FetchInput::Request {
            ids: vec![tx(1)],
            shard: SHARD,
            preferred: Some(vid(1)),
            class: None,
        });
        let FetchOutput::Send { ids, route } = &out[0];
        assert_eq!(route.preferred, Some(vid(1)));

        let retried = p.handle(FetchInput::Failed { ids: ids.clone() });
        let FetchOutput::Send { route, .. } = &retried[0];
        assert_eq!(route.preferred, None);
    }

    /// An answer that fails the same way each time it is asked costs one
    /// inline retry, then waits for the tick: a locally served answer
    /// spends no round trip, so re-sending on every refusal would never let
    /// time pass.
    #[test]
    fn a_second_failure_before_the_tick_waits_for_the_tick() {
        let mut p = Fetch::<TxHash>::new("test", config());
        p.handle(FetchInput::Request {
            ids: vec![tx(1)],
            shard: SHARD,
            preferred: None,
            class: None,
        });
        assert_eq!(
            p.handle(FetchInput::Failed { ids: vec![tx(1)] }).len(),
            1,
            "the first failure retries at once"
        );
        assert!(
            p.handle(FetchInput::Failed { ids: vec![tx(1)] }).is_empty(),
            "the second waits for the tick"
        );
        // Another id's ask does not carry the held one out with it.
        let out = p.handle(FetchInput::Request {
            ids: vec![tx(2)],
            shard: SHARD,
            preferred: None,
            class: None,
        });
        let [FetchOutput::Send { ids, .. }] = out.as_slice() else {
            panic!("one send, got {out:?}");
        };
        assert_eq!(ids, &vec![tx(2)]);

        let out = p.handle(FetchInput::Tick);
        let [FetchOutput::Send { ids, .. }] = out.as_slice() else {
            panic!("one send, got {out:?}");
        };
        assert_eq!(ids, &vec![tx(1)]);
    }

    fn ask(p: &mut Fetch<TxHash>, id: TxHash, preferred: Option<ValidatorId>) -> Vec<TxHash> {
        p.handle(FetchInput::Request {
            ids: vec![id],
            shard: SHARD,
            preferred,
            class: None,
        })
        .into_iter()
        .flat_map(|FetchOutput::Send { ids, .. }| ids)
        .collect()
    }

    /// A re-ask restates where the answer is but keeps the hold: a
    /// consumer that re-asks on every failure would otherwise reopen the
    /// loop the hold closes. The tick sends it to the restated peer.
    #[test]
    fn a_re_ask_keeps_the_hold_until_the_tick() {
        let mut p = Fetch::<TxHash>::new("test", config());
        ask(&mut p, tx(1), None);
        p.handle(FetchInput::Failed { ids: vec![tx(1)] });
        assert!(p.handle(FetchInput::Failed { ids: vec![tx(1)] }).is_empty());

        assert!(
            ask(&mut p, tx(1), Some(vid(7))).is_empty(),
            "the re-ask does not lift the hold"
        );
        let out = p.handle(FetchInput::Tick);
        let [FetchOutput::Send { ids, route }] = out.as_slice() else {
            panic!("one send, got {out:?}");
        };
        assert_eq!(ids, &vec![tx(1)]);
        assert_eq!(route.preferred, Some(vid(7)));
    }

    /// A chunk that never reached a peer waits for the tick already, so
    /// it does not count toward the hold: the next failure that did reach
    /// one still retries at once.
    #[test]
    fn an_unroutable_chunk_does_not_count_toward_the_hold() {
        let mut p = Fetch::<TxHash>::new("test", config());
        ask(&mut p, tx(1), None);
        assert!(
            p.handle(FetchInput::Unroutable { ids: vec![tx(1)] })
                .is_empty()
        );
        // Another id's ask carries the released one out with it.
        assert_eq!(ask(&mut p, tx(2), None), vec![tx(1), tx(2)]);
        assert_eq!(
            p.handle(FetchInput::Failed { ids: vec![tx(1)] }).len(),
            1,
            "the first failure that reached a peer retries at once"
        );
    }

    /// A chunk in flight across a tick fails into a fresh count: the tick
    /// restores every id's inline retry, the ones in flight included.
    #[test]
    fn a_failure_after_the_tick_retries_at_once() {
        let mut p = Fetch::<TxHash>::new("test", config());
        ask(&mut p, tx(1), None);
        assert_eq!(p.handle(FetchInput::Failed { ids: vec![tx(1)] }).len(), 1);
        assert!(
            p.handle(FetchInput::Tick).is_empty(),
            "the retry is still in flight"
        );
        assert_eq!(
            p.handle(FetchInput::Failed { ids: vec![tx(1)] }).len(),
            1,
            "the failure after the tick retries at once"
        );
    }

    fn ask_out(p: &mut Fetch<TxHash>, id: TxHash) -> Vec<FetchOutput<TxHash>> {
        p.handle(FetchInput::Request {
            ids: vec![id],
            shard: SHARD,
            preferred: None,
            class: None,
        })
    }

    fn answerers(out: &[FetchOutput<TxHash>]) -> Vec<Answerers> {
        out.iter()
            .map(|FetchOutput::Send { route, .. }| route.answerers)
            .collect()
    }

    /// A failure's retry asks whoever the failed attempt did not: a seat
    /// this host runs answers every retry the same way, and the
    /// committee's other members may not. The second failure before the
    /// tick holds, and the tick asks the local seats first.
    #[test]
    fn a_failed_retry_takes_turns_with_the_local_seats() {
        let mut p = Fetch::<TxHash>::new("test", config());
        let out = ask_out(&mut p, tx(1));
        assert_eq!(answerers(&out), [Answerers::LocalFirst]);
        let out = p.handle(FetchInput::Failed { ids: vec![tx(1)] });
        assert_eq!(answerers(&out), [Answerers::PeersOnly]);
        assert!(p.handle(FetchInput::Failed { ids: vec![tx(1)] }).is_empty());
        let out = p.handle(FetchInput::Tick);
        assert_eq!(answerers(&out), [Answerers::LocalFirst]);
    }

    /// A peers-only instance asks past the host on the first attempt, on
    /// the retry after a failure, and after the tick, whose hold and
    /// release it keeps as any instance does.
    #[test]
    fn a_peers_only_fetch_never_asks_the_host_on_failure_or_tick() {
        let mut p = Fetch::<TxHash>::peers_only("test", config());
        let out = ask_out(&mut p, tx(1));
        assert_eq!(answerers(&out), [Answerers::PeersOnly]);
        let out = p.handle(FetchInput::Failed { ids: vec![tx(1)] });
        assert_eq!(answerers(&out), [Answerers::PeersOnly]);
        assert!(p.handle(FetchInput::Failed { ids: vec![tx(1)] }).is_empty());
        let out = p.handle(FetchInput::Tick);
        assert_eq!(answerers(&out), [Answerers::PeersOnly]);
        let out = p.handle(FetchInput::Failed { ids: vec![tx(1)] });
        assert_eq!(answerers(&out), [Answerers::PeersOnly]);
    }

    /// A peer round that outlasts the tick fails back to the local seats:
    /// the next answerers follow from what the failed attempt asked, not
    /// from a count the tick cleared while it was out.
    #[test]
    fn a_peer_round_failing_after_the_tick_asks_the_local_seats_next() {
        let mut p = Fetch::<TxHash>::new("test", config());
        let out = ask_out(&mut p, tx(1));
        assert_eq!(answerers(&out), [Answerers::LocalFirst]);
        let out = p.handle(FetchInput::Failed { ids: vec![tx(1)] });
        assert_eq!(answerers(&out), [Answerers::PeersOnly]);
        assert!(
            p.handle(FetchInput::Tick).is_empty(),
            "the peer round is still in flight"
        );
        let out = p.handle(FetchInput::Failed { ids: vec![tx(1)] });
        assert_eq!(answerers(&out), [Answerers::LocalFirst]);
        assert!(
            p.handle(FetchInput::Failed { ids: vec![tx(1)] }).is_empty(),
            "two failures since the tick hold"
        );
        let out = p.handle(FetchInput::Tick);
        assert_eq!(answerers(&out), [Answerers::LocalFirst]);
    }

    /// A chunk that never reached a peer asked no one, so it keeps its
    /// preferred peer for the tick's retry.
    #[test]
    fn an_unroutable_chunk_keeps_its_preferred_peer() {
        let mut p = Fetch::<TxHash>::new("test", config());
        let out = p.handle(FetchInput::Request {
            ids: vec![tx(1)],
            shard: SHARD,
            preferred: Some(vid(1)),
            class: None,
        });
        let FetchOutput::Send { ids, .. } = &out[0];
        p.handle(FetchInput::Unroutable { ids: ids.clone() });

        let retried = p.handle(FetchInput::Tick);
        let FetchOutput::Send { route, .. } = &retried[0];
        assert_eq!(route.preferred, Some(vid(1)));
    }

    /// A chunk that never reached a peer waits for the tick. Re-sending
    /// it here would meet the same wall in the same instant — an
    /// unresolved committee answers as fast as it is asked — so the
    /// slots are released, the ids stay owed, and the ticker carries it.
    #[test]
    fn an_unroutable_chunk_leaves_the_retry_to_the_tick() {
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

        assert!(
            p.handle(FetchInput::Unroutable { ids: chunk_ids })
                .is_empty(),
            "an unroutable chunk re-sends nothing"
        );
        assert_eq!(p.in_flight_count(), 0, "and holds no slot");
        assert!(p.has_pending(), "the ids are still owed");

        let retried = p.handle(FetchInput::Tick);
        assert_eq!(retried.len(), 1);
        assert_eq!(p.in_flight_count(), 2);
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

    /// A re-ask restates the route of an id already in flight without
    /// sending it again: the attempt out is unaffected, and the id's next
    /// attempt goes where the latest ask said.
    #[test]
    fn a_re_ask_restates_the_route_of_an_id_in_flight() {
        let mut p = Fetch::<TxHash>::new("test", config());
        let first = p.handle(FetchInput::Request {
            ids: vec![tx(1)],
            shard: SHARD,
            preferred: Some(vid(1)),
            class: None,
        });
        assert_eq!(first.len(), 1);
        let second = p.handle(FetchInput::Request {
            ids: vec![tx(1), tx(2)],
            shard: SHARD,
            preferred: Some(vid(2)),
            class: None,
        });
        assert_eq!(second.len(), 1);
        let FetchOutput::Send { route, ids } = &second[0];
        assert_eq!(route.preferred, Some(vid(2)));
        assert_eq!(ids, &vec![tx(2)], "the id in flight is not sent again");

        let retry = p.handle(FetchInput::Failed { ids: vec![tx(1)] });
        assert_eq!(retry.len(), 1);
        let FetchOutput::Send { route, ids } = &retry[0];
        assert_eq!(ids, &vec![tx(1)]);
        assert_eq!(
            route.preferred,
            Some(vid(2)),
            "the retry goes where the latest ask said"
        );
    }

    #[test]
    fn siblings_with_same_preferred_coalesce_into_one_send() {
        let mut p = Fetch::<TxHash>::new(
            "test",
            FetchConfig {
                max_in_flight: 100,
                max_ids_per_request: 50,
                chunks_per_dispatch: 8,
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

    /// An id stuck at the global cap dispatches as soon as an in-flight
    /// id is admitted — the freed slot is filled in the same call, not
    /// deferred to a later tick.
    #[test]
    fn admitted_frees_slot_for_queued_id() {
        let mut p = Fetch::<TxHash>::new(
            "test",
            FetchConfig {
                max_in_flight: 1,
                max_ids_per_request: 10,
                chunks_per_dispatch: 4,
            },
        );
        let out = p.handle(FetchInput::Request {
            ids: vec![tx(1), tx(2)],
            shard: SHARD,
            preferred: None,
            class: None,
        });
        assert_eq!(out.len(), 1);
        let FetchOutput::Send { ids, .. } = &out[0];
        assert_eq!(ids, &vec![tx(1)]);

        let out = p.handle(FetchInput::Admitted { ids: vec![tx(1)] });
        assert_eq!(out.len(), 1);
        let FetchOutput::Send { ids, .. } = &out[0];
        assert_eq!(ids, &vec![tx(2)]);
        assert_eq!(p.pending_count(), 1);
    }

    #[test]
    fn global_in_flight_cap_bounds_emissions() {
        let mut p = Fetch::<TxHash>::new(
            "test",
            FetchConfig {
                max_in_flight: 3,
                max_ids_per_request: 10,
                chunks_per_dispatch: 4,
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

#[cfg(test)]
mod partition_tests {
    use std::sync::Arc;

    use hyperscale_hbor::Capped;
    use hyperscale_types::test_utils::test_transaction;
    use hyperscale_types::{Transaction, TxHash};

    use super::*;

    fn tx_arc(seed: u8) -> Transaction {
        test_transaction(seed)
    }

    fn tx_hash(tx: &Transaction) -> [TxHash; 1] {
        [tx.hash()]
    }

    /// A returned item that answers for several ids at once, the way an
    /// execution certificate answers for every transaction of its batch.
    struct Cover(Vec<TxHash>);

    #[test]
    fn partition_keeps_only_solicited_and_flags_extras() {
        // Requested two known hashes; peer ships one we asked for plus one
        // we never asked for. The unsolicited tx must be dropped from the
        // delivery and counted in `unsolicited`.
        let asked = tx_arc(1);
        let asked_hash = asked.hash();
        let extra = tx_arc(99);
        let other_requested = tx_arc(2).hash();

        let split =
            partition_solicited(vec![asked, extra], &[asked_hash, other_requested], tx_hash);
        assert_eq!(split.kept.len(), 1);
        assert_eq!(split.kept[0].hash(), asked_hash);
        assert_eq!(split.unsolicited, 1);
        assert_eq!(split.missing, vec![other_requested]);
    }

    #[test]
    fn partition_full_delivery_yields_no_missing_no_unsolicited() {
        let a = tx_arc(1);
        let b = tx_arc(2);
        let split = partition_solicited(vec![a.clone(), b.clone()], &[a.hash(), b.hash()], tx_hash);
        assert_eq!(split.kept.len(), 2);
        assert!(split.missing.is_empty());
        assert_eq!(split.unsolicited, 0);
    }

    #[test]
    fn partition_only_unsolicited_yields_kept_empty_all_missing() {
        let bogus_a = tx_arc(50);
        let bogus_b = tx_arc(51);
        let wanted_1 = tx_arc(1).hash();
        let wanted_2 = tx_arc(2).hash();

        let split = partition_solicited(vec![bogus_a, bogus_b], &[wanted_1, wanted_2], tx_hash);
        assert!(split.kept.is_empty());
        assert_eq!(split.unsolicited, 2);
        assert_eq!(split.missing.len(), 2);
    }

    /// One returned item answering for several requested ids delivers all
    /// of them. An execution certificate covers every transaction of its
    /// tick, so a requester that asked for three of them and got one
    /// certificate is missing nothing.
    #[test]
    fn partition_credits_every_id_a_single_item_answers_for() {
        let a = tx_arc(1).hash();
        let b = tx_arc(2).hash();
        let c = tx_arc(3).hash();
        let split = partition_solicited(vec![Cover(vec![a, b, c])], &[a, b], |item| item.0.clone());
        assert_eq!(split.kept.len(), 1);
        assert!(split.missing.is_empty());
        assert_eq!(split.unsolicited, 0);
    }

    /// An item covering nothing we asked for is unsolicited, however many
    /// ids it answers for.
    #[test]
    fn partition_counts_a_multi_id_item_covering_nothing_requested() {
        let wanted = tx_arc(1).hash();
        let split = partition_solicited(
            vec![Cover(vec![tx_arc(50).hash(), tx_arc(51).hash()])],
            &[wanted],
            |item| item.0.clone(),
        );
        assert!(split.kept.is_empty());
        assert_eq!(split.unsolicited, 1);
        assert_eq!(split.missing, vec![wanted]);
    }

    #[test]
    fn partition_works_for_non_copy_id_via_clone() {
        // Sanity-check that the generic helper accepts a Clone (non-Copy)
        // id type; TickId is the production motivator here.
        #[derive(Clone, Eq, Hash, PartialEq, Debug)]
        struct CompoundId(String);
        struct Item(CompoundId);

        let a = Item(CompoundId("a".into()));
        let b = Item(CompoundId("b".into()));
        let split = partition_solicited(
            vec![a, b],
            &[CompoundId("a".into()), CompoundId("c".into())],
            |it| [it.0.clone()],
        );
        assert_eq!(split.kept.len(), 1);
        assert_eq!(split.unsolicited, 1);
        assert_eq!(split.missing, vec![CompoundId("c".into())]);
    }

    #[test]
    fn partition_filters_unsolicited_local_provisions() {
        // The LocalProvisionBinding admits each kept item as a separate
        // UnverifiedProvisionsReceived event, which buffers in the provision pipeline
        // before signature/merkle verification — so unsolicited deliveries
        // must be dropped at the response boundary.
        use hyperscale_types::{
            BlockHeight, Hash, MerkleInclusionProof, ProvisionEntry, Provisions, ShardId, TxHash,
            WeightedTimestamp,
        };
        let asked = Arc::new(Provisions::new(
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 2),
            BlockHeight::new(10),
            WeightedTimestamp::ZERO,
            MerkleInclusionProof::dummy(),
            Capped::from_array([ProvisionEntry::new(
                TxHash::from(Hash::from_bytes(b"asked")),
                Capped::empty(),
            )]),
        ));
        let extra = Arc::new(Provisions::new(
            ShardId::leaf(2, 3),
            ShardId::leaf(2, 2),
            BlockHeight::new(11),
            WeightedTimestamp::ZERO,
            MerkleInclusionProof::dummy(),
            Capped::from_array([ProvisionEntry::new(
                TxHash::from(Hash::from_bytes(b"extra")),
                Capped::empty(),
            )]),
        ));
        let asked_hash = asked.hash();
        let split = partition_solicited(vec![asked, extra], &[asked_hash], |p| [p.hash()]);
        assert_eq!(split.kept.len(), 1);
        assert_eq!(split.kept[0].hash(), asked_hash);
        assert_eq!(split.unsolicited, 1);
        assert!(split.missing.is_empty());
    }
}
