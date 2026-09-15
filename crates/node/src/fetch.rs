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
//!   `io_loop::drive_fetch_admission`.
//! - [`ScopedAnswer`] is the contract for a binding whose request names one
//!   scope and whose answer is checked against it; [`dispatch_scoped`] is
//!   the one response boundary those bindings share.
//! - [`partition_solicited`] is the shared response-boundary filter every
//!   bag-of-ids binding's admit handler runs.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::Hash;

use crossbeam::channel::Sender;
use hyperscale_core::{FetchIds, ProtocolEvent};
use hyperscale_metrics::{
    record_fetch_abandoned, record_fetch_completed, record_fetch_response_refused,
    record_fetch_retried, record_fetch_started,
};
use hyperscale_network::{Network, RequestError, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::Request;
use hyperscale_types::{MessageClass, ShardId, Stopwatch, ValidatorId};
use tracing::{debug, trace, warn};

use crate::shard::{HostEvent, ShardIo, ShardScopedInput, push_protocol_event, push_shard_input};

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
        shard: ShardId,
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
    /// A chunk that never reached a peer: release the slots and leave
    /// the retry to [`Self::Tick`].
    Unroutable {
        /// Ids in the chunk.
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
        shard: ShardId,
        /// Canonical-source hint forwarded to the network layer.
        preferred: Option<ValidatorId>,
        /// Class override shared by every id in this chunk; chunks are
        /// grouped by `(shard, preferred, class)` so this is well-defined.
        class: Option<MessageClass>,
    },
}

#[derive(Debug)]
struct Entry {
    shard: ShardId,
    preferred: Option<ValidatorId>,
    class: Option<MessageClass>,
    in_flight: bool,
    /// When the entry most recently transitioned to `in_flight=true`.
    /// `None` while the entry is awaiting dispatch. Wall-clock-derived
    /// because this is observability-only: an alert on
    /// `oldest_in_flight_age_ms` fires when admission stops happening,
    /// catching novel pin scenarios the existing per-drop notifications
    /// haven't been wired for yet.
    dispatched_at: Option<Stopwatch>,
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
type GroupKey = (ShardId, Option<ValidatorId>, Option<MessageClass>);

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
            FetchInput::Failed { ids } => self.handle_failed(&ids, Respawn::Now),
            FetchInput::Unroutable { ids } => self.handle_failed(&ids, Respawn::OnTick),
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

    /// Every id currently tracked, in sorted order. A driver whose
    /// consumer re-derives its wanted set each tick diffs against this to
    /// abandon what the consumer no longer asks for — without it an id
    /// nobody answers stays in the pending set for the process's life.
    pub fn pending_ids(&self) -> impl Iterator<Item = &Id> {
        self.pending.keys()
    }

    /// Age in milliseconds of the longest-running in-flight entry, or
    /// `0` if nothing is in flight. Surfaced through `ShardIo::fetch_metrics`
    /// so an alert on `> N` catches admission paths that silently dropped
    /// without notifying the FSM — the symptom that motivated the
    /// provision-fetch robustness work in the first place.
    #[must_use]
    pub fn oldest_in_flight_age_ms(&self) -> u64 {
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

    fn handle_failed(&mut self, ids: &[Id], respawn: Respawn) -> Vec<FetchOutput<Id>> {
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
        match respawn {
            Respawn::Now => self.spawn_pending_fetches(),
            Respawn::OnTick => Vec::new(),
        }
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
                let dispatched_at = Stopwatch::start();
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

// ─── Binding trait ─────────────────────────────────────────────────────

/// A per-payload binding of the generic [`Fetch`] state machine.
///
/// Each fetch payload (transactions, provisions, headers, …) gets one impl —
/// living with its subsystem state in `shard/{consensus,cross_shard,mempool}`
/// or `beacon` — that owns the `Id` type, which `Fetch<Id>` instance backs it
/// (via [`fetch_mut`](Self::fetch_mut)), and the wire request/response shape.
pub trait FetchBinding: 'static {
    /// Id used to address payloads of this kind.
    type Id: Clone + Ord + Hash + std::fmt::Debug + Send + Sync + 'static;

    /// Stable identifier for this binding — used in dispatch tracing.
    const NAME: &'static str;

    /// One network request per id (vs. one batched request per chunk).
    /// Cross-shard fetches that target a single `(shard, height)` set this
    /// to `true`; bag-of-hashes fetches leave it `false`.
    const PER_ID: bool = false;

    /// The [`FetchIds`] arm that carries this binding's ids — how a
    /// response boundary names the ids it failed or fulfilled, and the
    /// inverse of the one dispatcher that routes a batch back here.
    fn ids(ids: Vec<Self::Id>) -> FetchIds;

    /// Locate the `Fetch<Id>` instance for this binding inside `ShardIo` —
    /// each impl navigates to its own subsystem's state.
    fn fetch_mut<S: ShardStorage>(shard: &mut ShardIo<S>) -> &mut Fetch<Self::Id>;

    /// Send one request covering `ids` against `shard`'s committee and
    /// route the response back through the event sender. `class` flows
    /// down to `Network::request` as the per-call class override. For
    /// [`PER_ID`](Self::PER_ID) bindings the dispatcher pre-splits into
    /// single-element chunks before calling this.
    ///
    /// `local_shard` is the hosted shard that produced this request — it's
    /// threaded into the response callback so the resulting
    /// `ShardScopedInput::Protocol` and `*FetchFailed` events route to the right
    /// hosted shard under cross-shard hosting (distinct from `shard`,
    /// which selects the *target* committee).
    fn dispatch_chunk<N: Network>(
        ids: Vec<Self::Id>,
        local_shard: ShardId,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
        network: &N,
        sender: &Sender<HostEvent>,
    );
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
const fn scored(refusal: Refusal) -> ResponseVerdict {
    match refusal {
        Refusal::NotHeld => ResponseVerdict::Accept,
        Refusal::Unusable(_) => ResponseVerdict::Reject,
    }
}

/// Whether a transport error leaves the retry to the tick.
///
/// Only an error that never reached a peer does: the peer set is the
/// reason, and re-dispatching into the same empty set inside the
/// response callback would spin. Everything the transport already
/// answered — a timeout, an exhausted retry budget, a peer-level error —
/// has had per-peer and per-request backoff absorbed below this seam
/// already, so it retries inline against a rotated peer.
const fn defers_to_the_tick(error: &RequestError) -> bool {
    matches!(
        error,
        RequestError::NoPeers | RequestError::PeerUnreachable(_)
    )
}

/// Issue one request per scope in `ids` and route each answer through
/// [`ScopedAnswer::answer`]. The ids are released before the event goes
/// out, so the freed capacity is available if handling the delivery
/// re-drives the fetch. A transport error releases the ids without
/// rejecting the response — the network already recorded it — while an
/// answer that is not an answer counts as a refusal.
pub fn dispatch_scoped<B: ScopedAnswer, N: Network>(
    ids: Vec<B::Id>,
    local_shard: ShardId,
    shard: ShardId,
    preferred: Option<ValidatorId>,
    class: Option<MessageClass>,
    network: &N,
    sender: &Sender<HostEvent>,
) {
    let mut by_scope: BTreeMap<B::Scope, Vec<B::Key>> = BTreeMap::new();
    for id in ids {
        let (scope, key) = B::split(id);
        by_scope.entry(scope).or_default().push(key);
    }
    for (scope, keys) in by_scope {
        let requested: Vec<B::Id> = keys.iter().map(|key| B::join(scope, *key)).collect();
        let es = sender.clone();
        network.request(
            shard,
            preferred,
            B::request(scope, &keys),
            class,
            Box::new(move |result| {
                let response = match result {
                    Ok(response) => response,
                    Err(error) => {
                        if matches!(error, RequestError::PeerError(_)) {
                            record_fetch_response_refused(B::NAME, "unusable_answer");
                        }
                        let input = if defers_to_the_tick(&error) {
                            ShardScopedInput::FetchUnroutable(B::ids(requested))
                        } else {
                            ShardScopedInput::FetchFailed(B::ids(requested))
                        };
                        push_shard_input(&es, local_shard, input);
                        return ResponseVerdict::Accept;
                    }
                };
                match B::answer(scope, keys, response) {
                    Ok(event) => {
                        push_shard_input(
                            &es,
                            local_shard,
                            ShardScopedInput::FetchFulfilled(B::ids(requested)),
                        );
                        push_protocol_event(&es, local_shard, event);
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
                        push_shard_input(
                            &es,
                            local_shard,
                            ShardScopedInput::FetchFailed(B::ids(requested)),
                        );
                        scored(refusal)
                    }
                }
            }),
        );
    }
}

/// Why a batch of ids leaves the in-flight set: the three id-carrying
/// [`FetchInput`]s, so one dispatcher can route a [`FetchIds`] batch to
/// its binding whichever way it is being released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Release {
    /// The attempt failed or went unanswered; retry at once, since the
    /// transport already spent a round trip on it.
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
    pub const fn input<Id>(self, ids: Vec<Id>) -> FetchInput<Id> {
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
    /// per-tick cap.
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
    pub const fn input<Id>(self, ids: Vec<Id>) -> FetchInput<Id> {
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
/// a peer that held nothing, an answer this node could not use — has
/// already cost a round trip and its peer budget, so the next attempt
/// leaves at once. A request that never reached a peer has not: no
/// committee resolves it, or none of its members is up, and it fails
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
    pub kept: Vec<T>,
    /// Requested ids that didn't appear in the response.
    pub missing: Vec<Id>,
    /// Count of returned items whose id was NOT requested. A non-zero
    /// value indicates a buggy or malicious peer trying to inject items
    /// we never asked for.
    pub unsolicited: usize,
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
            parallel_chunks_per_tick: 4,
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
            let FetchOutput::Send { preferred, .. } = o;
            assert_eq!(*preferred, Some(vid(1)));
        }
        assert_eq!(p.in_flight_count(), 5);
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
                parallel_chunks_per_tick: 4,
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

#[cfg(test)]
mod partition_tests {
    use std::sync::Arc;

    use hyperscale_types::test_utils::test_transaction;
    use hyperscale_types::{Transaction, TxHash};

    use super::*;

    fn tx_arc(seed: u8) -> Arc<Transaction> {
        Arc::new(test_transaction(seed))
    }

    fn tx_hash(tx: &Arc<Transaction>) -> [TxHash; 1] {
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

        let split = partition_solicited(
            vec![Arc::clone(&asked), Arc::clone(&extra)],
            &[asked_hash, other_requested],
            tx_hash,
        );
        assert_eq!(split.kept.len(), 1);
        assert_eq!(split.kept[0].hash(), asked_hash);
        assert_eq!(split.unsolicited, 1);
        assert_eq!(split.missing, vec![other_requested]);
    }

    #[test]
    fn partition_full_delivery_yields_no_missing_no_unsolicited() {
        let a = tx_arc(1);
        let b = tx_arc(2);
        let split = partition_solicited(
            vec![Arc::clone(&a), Arc::clone(&b)],
            &[a.hash(), b.hash()],
            tx_hash,
        );
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
            vec![ProvisionEntry::new(
                TxHash::from(Hash::from_bytes(b"asked")),
                vec![],
            )],
        ));
        let extra = Arc::new(Provisions::new(
            ShardId::leaf(2, 3),
            ShardId::leaf(2, 2),
            BlockHeight::new(11),
            WeightedTimestamp::ZERO,
            MerkleInclusionProof::dummy(),
            vec![ProvisionEntry::new(
                TxHash::from(Hash::from_bytes(b"extra")),
                vec![],
            )],
        ));
        let asked_hash = asked.hash();
        let split = partition_solicited(
            vec![Arc::clone(&asked), Arc::clone(&extra)],
            &[asked_hash],
            |p| [p.hash()],
        );
        assert_eq!(split.kept.len(), 1);
        assert_eq!(split.kept[0].hash(), asked_hash);
        assert_eq!(split.unsolicited, 1);
        assert!(split.missing.is_empty());
    }
}
