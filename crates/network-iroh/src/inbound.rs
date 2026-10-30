//! Routes the streams a bound peer opens to per-type handlers.
//!
//! Every bound connection gets two accept loops, one per stream direction.
//! A stream's first byte names what it carries: a unidirectional stream of
//! notifications or of gossip, read frame by frame until the sender
//! finishes it; a unidirectional stream that subscribes the peer to global
//! gossip for as long as it stays open; or a bidirectional stream holding
//! one request, answered and finished.
//!
//! Requests are admitted against a global concurrency limit and a per-peer
//! one, so no single peer (or flood of peers) can exhaust handler capacity,
//! and the time a peer's handlers take is charged against a budget that
//! time pays down (see [`crate::serve_budget`]), so no peer can keep this
//! host busy for more than one core.
//! A peer's notifications are judged a few at a time, and each one its
//! handler does not take, but for one it had no room for, is charged
//! against the peer, as is each stream
//! that broke the protocol, in the budget the host's gossip shares (see
//! [`crate::cooldown`]). A request refused, for capacity or for its
//! budget, is answered as such rather than left to time out, and charged
//! the same way. A peer whose refused traffic costs more than its share is
//! cooled down: the streams it has open are stopped, and no new one is
//! taken up until the cooldown lapses. All of it is kept per principal (see
//! [`Peer`]).

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;
use std::{fmt, io};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use hyperscale_metrics::{record_network_bandwidth, set_inbound_streams_in_use};
use hyperscale_network::{HandlerRegistry, Verdict};
use hyperscale_types::{MessageClass, ShardId, ValidatorId};
use iroh::EndpointId;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use tokio::io::AsyncReadExt;
use tokio::spawn;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::spawn_blocking;
use tokio::time::{Instant, sleep_until, timeout};
use tracing::{debug, warn};

use crate::bind::{self, BindContext, BindError};
use crate::cooldown::{Cooldown, Refusal, refused_work};
use crate::fanout::Fanout;
use crate::fault_gate::FaultState;
use crate::framing::{self, FrameError, MAX_FRAME_SIZE};
use crate::path::PathPolicy;
use crate::peer::Peer;
use crate::protocol::{
    RESPONSE_BUSY, RESPONSE_OK, RESPONSE_RELAYED, RESPONSE_SHARD_UNSUPPORTED,
    RESPONSE_UNKNOWN_TYPE, SHARD_WIRE_LEN, STOP_REFUSED, STREAM_ATTEST, STREAM_GOSSIP,
    STREAM_NOTIFY, STREAM_REQUEST, STREAM_SUBSCRIBE, class_from_byte, class_priority, decode_shard,
};
use crate::serve_budget::{ServeBudget, processor_time};

/// Timeout for reading a stream's header and its request frame.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// The least time between two pulls a peer has this host answer: each
/// costs a signature per validator asked for, and an honest peer pulls
/// only when its topology learns a validator it was told of.
const MIN_PULL_INTERVAL: Duration = Duration::from_secs(1);

/// Timeout for writing a response. A response may be the largest frame the
/// protocol allows, and the requester's own timeout stops the stream sooner
/// when it has given up.
const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Work charged against a peer for a stream of its that broke the protocol
/// or stalled: the task, the reads, and the slot it held.
const FAILED_STREAM_WORK: Duration = Duration::from_millis(1);

/// Maximum number of inbound requests handled concurrently across all peers.
const MAX_INBOUND_CONCURRENT: usize = 128;

/// Maximum number of inbound requests handled concurrently for one peer.
const MAX_INBOUND_PER_PEER: usize = 32;

/// Notifications of one peer judged at once. A handler may check a
/// signature, and a verdict that cools a peer down stops only what is read
/// after it.
const NOTIFICATIONS_JUDGED_AT_ONCE: usize = 4;

/// Routes inbound streams to per-type handlers via the handler registry.
pub struct InboundRouter {
    registry: Arc<HandlerRegistry>,
    /// Shards this host serves requests for.
    local_shards: Arc<ArcSwap<HashSet<ShardId>>>,
    /// Global concurrency limiter. Each request in flight holds one permit.
    global_semaphore: Arc<Semaphore>,
    /// Per-principal count of requests in flight.
    per_peer: DashMap<ValidatorId, AtomicUsize>,
    /// What each principal's requests have cost this host's handlers.
    serve_budget: ServeBudget,
    /// Turns at judging each principal's notifications.
    judging: DashMap<ValidatorId, Arc<Semaphore>>,
    /// What each peer's refused traffic has cost this host, shared with
    /// the fan-out.
    failures: Arc<Cooldown>,
    /// Decides whether a response goes back over the requester's path.
    paths: Arc<PathPolicy>,
    /// The host's fault gate, which may rewrite what a handler answers.
    fault_gate: Arc<FaultState>,
    /// Where gossip and subscription streams go. Unset until the host's
    /// gossip is running; such streams are dropped unread before then.
    fanout: OnceLock<Weak<Fanout>>,
    /// What answers a pull: the identities this host signs as. Unset
    /// until the endpoint installs it; a pull is refused before then.
    attest: OnceLock<BindContext>,
    /// When each peer last had a pull answered, and whether one is being
    /// answered now.
    pulls: DashMap<EndpointId, PullTurn>,
}

/// A peer's turn at having this host answer a pull.
#[derive(Clone, Copy)]
struct PullTurn {
    at: Instant,
    open: bool,
}

impl InboundRouter {
    pub fn new(
        registry: Arc<HandlerRegistry>,
        local_shards: Arc<ArcSwap<HashSet<ShardId>>>,
        paths: Arc<PathPolicy>,
        fault_gate: Arc<FaultState>,
        failures: Arc<Cooldown>,
    ) -> Self {
        Self {
            registry,
            local_shards,
            paths,
            fault_gate,
            failures,
            global_semaphore: Arc::new(Semaphore::new(MAX_INBOUND_CONCURRENT)),
            per_peer: DashMap::new(),
            serve_budget: ServeBudget::default(),
            judging: DashMap::new(),
            fanout: OnceLock::new(),
            attest: OnceLock::new(),
            pulls: DashMap::new(),
        }
    }

    /// Answer pulls with `ctx`'s identities from now on.
    pub(crate) fn install_attest(&self, ctx: BindContext) {
        let _ = self.attest.set(ctx);
    }

    /// Route gossip and subscription streams to `fanout` from now on.
    pub fn install_fanout(&self, fanout: &Arc<Fanout>) {
        let _ = self.fanout.set(Arc::downgrade(fanout));
    }

    fn fanout(&self) -> Option<Arc<Fanout>> {
        self.fanout.get().and_then(Weak::upgrade)
    }

    /// Serve every stream the peer opens on `connection`, which bound as
    /// `principal` among others, until it closes.
    pub fn serve(self: &Arc<Self>, connection: &Connection, principal: ValidatorId) {
        let peer = Peer {
            endpoint: connection.remote_id(),
            principal,
        };
        if let Some(fanout) = self.fanout() {
            fanout.on_link(peer);
        }

        let router = Arc::clone(self);
        let streams = connection.clone();
        spawn(async move {
            loop {
                router.sit_out_cooldown(principal).await;
                let Ok(stream) = streams.accept_uni().await else {
                    break;
                };
                let router = Arc::clone(&router);
                spawn(async move {
                    let result = router.handle_uni(peer, stream).await;
                    router.record_outcome(peer, &result);
                });
            }
        });

        let router = Arc::clone(self);
        let streams = connection.clone();
        spawn(async move {
            loop {
                router.sit_out_cooldown(principal).await;
                let Ok((send, recv)) = streams.accept_bi().await else {
                    break;
                };
                let router = Arc::clone(&router);
                spawn(async move {
                    let result = router.handle_bi(peer, send, recv).await;
                    router.record_outcome(peer, &result);
                });
            }
        });
    }

    /// Wait out any cooldown `principal` is in. Its streams are not taken up
    /// meanwhile, so the transport's limit on a peer's open streams holds it
    /// to those already open, and refusing it costs this host nothing more
    /// however fast it asks.
    async fn sit_out_cooldown(&self, principal: ValidatorId) {
        while let Some(until) = self.failures.cooling_until(principal) {
            sleep_until(until).await;
        }
    }

    /// Charge `peer` for a stream that failed by its fault. A stream that
    /// succeeded earns nothing back: a peer can always open one that does.
    fn record_outcome(&self, peer: Peer, result: &Result<(), StreamError>) {
        if let Err(error) = result {
            debug!(peer = %peer.endpoint.fmt_short(), %error, "Inbound stream failed");
            if error.is_peers_fault() {
                self.charge(peer, FAILED_STREAM_WORK);
            }
        }
    }

    /// Charge `peer` for `work` its refused traffic cost this host.
    fn charge(&self, peer: Peer, work: Duration) {
        if let Some(cooldown) = self.failures.charge(peer.principal, work) {
            warn!(
                peer = %peer.endpoint.fmt_short(),
                validator = peer.principal.inner(),
                cooldown_secs = cooldown.as_secs_f32(),
                "Peer's traffic keeps being refused; refusing it for a while"
            );
        }
    }

    /// Try to admit an inbound request, checking per-peer and then global
    /// concurrency. Returns `Some(permit)` if admitted.
    fn try_admit(&self, peer: ValidatorId) -> Option<OwnedSemaphorePermit> {
        let counter = self
            .per_peer
            .entry(peer)
            .or_insert_with(|| AtomicUsize::new(0));
        let active = counter.fetch_add(1, Ordering::Relaxed);
        drop(counter);
        if active >= MAX_INBOUND_PER_PEER {
            self.release(peer);
            warn!(
                validator = peer.inner(),
                active,
                limit = MAX_INBOUND_PER_PEER,
                "Refusing inbound request: per-peer limit exceeded"
            );
            return None;
        }

        let Ok(permit) = Arc::clone(&self.global_semaphore).try_acquire_owned() else {
            self.release(peer);
            warn!(
                validator = peer.inner(),
                limit = MAX_INBOUND_CONCURRENT,
                "Refusing inbound request: global concurrency limit reached"
            );
            return None;
        };
        self.update_inbound_gauge();
        Some(permit)
    }

    /// Give back the per-peer slot an admitted (or just-refused) request
    /// took.
    fn release(&self, peer: ValidatorId) {
        if let Some(counter) = self.per_peer.get(&peer) {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
        self.update_inbound_gauge();
    }

    fn update_inbound_gauge(&self) {
        let in_use =
            MAX_INBOUND_CONCURRENT.saturating_sub(self.global_semaphore.available_permits());
        set_inbound_streams_in_use("all", in_use);
    }

    async fn handle_uni(
        self: &Arc<Self>,
        peer: Peer,
        mut recv: RecvStream,
    ) -> Result<(), StreamError> {
        if self.failures.cooling_down(peer.principal) {
            return Ok(());
        }
        // Every unidirectional stream opens with its kind and its class.
        let mut header = [0u8; 2];
        AsyncReadExt::read_exact(&mut recv, &mut header)
            .await
            .map_err(StreamError::Io)?;
        match header[0] {
            STREAM_NOTIFY => {
                let class = class_from_byte(header[1]).ok_or(StreamError::MalformedHeader)?;
                self.read_notifications(peer, class, recv).await
            }
            STREAM_GOSSIP => {
                let class = class_from_byte(header[1]).ok_or(StreamError::MalformedHeader)?;
                match self.fanout() {
                    Some(fanout) => fanout
                        .read_gossip(peer, class, recv)
                        .await
                        .map_err(StreamError::Frame),
                    None => Ok(()),
                }
            }
            STREAM_SUBSCRIBE => {
                if let Some(fanout) = self.fanout() {
                    fanout.hold_subscription(peer, recv).await;
                }
                Ok(())
            }
            _ => Err(StreamError::UnknownStreamKind),
        }
    }

    /// Dispatch every notification the peer writes to this stream, until it
    /// finishes the stream, the connection closes, or the peer is cooled
    /// down.
    async fn read_notifications(
        self: &Arc<Self>,
        peer: Peer,
        class: MessageClass,
        mut recv: RecvStream,
    ) -> Result<(), StreamError> {
        let turns = Arc::clone(
            &self
                .judging
                .entry(peer.principal)
                .or_insert_with(|| Arc::new(Semaphore::new(NOTIFICATIONS_JUDGED_AT_ONCE))),
        );
        loop {
            if self.failures.cooling_down(peer.principal) {
                let _ = recv.stop(STOP_REFUSED);
                return Ok(());
            }
            let (type_id, payload, wire_bytes) =
                match framing::read_typed_frame(&mut recv, MAX_FRAME_SIZE).await {
                    Ok(frame) => frame,
                    Err(FrameError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                        return Ok(());
                    }
                    Err(e) => return Err(StreamError::Frame(e)),
                };
            record_network_bandwidth(wire_bytes as u64, 0);
            if class == MessageClass::Consensus {
                self.paths.note_consensus(peer.endpoint);
            }

            let Some(handler) = self.registry.get_notification(&type_id) else {
                // The sender may follow with types this host does know.
                warn!(
                    peer = %peer.endpoint.fmt_short(),
                    type_id = %type_id,
                    "Unknown notification type"
                );
                continue;
            };
            // The peer's notifications are judged a few at a time, so it
            // cannot have more read than that before the verdicts that cool
            // it down.
            let turn = Arc::clone(&turns)
                .acquire_owned()
                .await
                .expect("the judging semaphore is never closed");
            // Checked again once a turn is in hand: the wait for it may have
            // begun before the cooldown did.
            if self.failures.cooling_down(peer.principal) {
                let _ = recv.stop(STOP_REFUSED);
                return Ok(());
            }
            let router = Arc::clone(self);
            spawn(async move {
                let bytes = payload.len();
                let verdict = handler(payload);
                drop(turn);
                router.conclude(peer, class, bytes, verdict);
            });
        }
    }

    /// Act on a handler's verdict on a notification of `bytes` from `peer`.
    /// Nothing that is not taken goes unpaid but what this host had no room
    /// for: a rejection is charged as the peer's fault, a notification this
    /// host could not judge at the work of reading it, and a deferred
    /// verdict when it settles.
    fn conclude(&self, peer: Peer, class: MessageClass, bytes: usize, verdict: Verdict) {
        match verdict {
            Verdict::Accept | Verdict::Busy => {}
            Verdict::Reject => self.charge(peer, refused_work(bytes, Refusal::Fault)),
            Verdict::Ignore => self.charge(peer, refused_work(bytes, Refusal::Unjudged)),
            Verdict::Defer(deferral) => match self.fanout() {
                Some(fanout) => fanout.await_notification_verdict(peer, class, &deferral, bytes),
                None => self.charge(peer, refused_work(bytes, Refusal::Unjudged)),
            },
        }
    }

    async fn handle_bi(
        &self,
        peer: Peer,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<(), StreamError> {
        if self.failures.cooling_down(peer.principal) {
            return Ok(());
        }
        let mut kind = [0u8; 1];
        timeout(
            REQUEST_READ_TIMEOUT,
            AsyncReadExt::read_exact(&mut recv, &mut kind),
        )
        .await
        .map_err(|_| StreamError::Timeout)?
        .map_err(StreamError::Io)?;
        if kind[0] == STREAM_ATTEST {
            return self.serve_pull(peer, send, recv).await;
        }
        if kind[0] != STREAM_REQUEST {
            return Err(StreamError::UnknownStreamKind);
        }

        let Some(permit) = self.try_admit(peer.principal) else {
            // Being refused costs a peer what refusing it costs this host,
            // so asking again and again while refused runs it into a
            // cooldown.
            self.charge(peer, refused_work(0, Refusal::Unjudged));
            return respond_status(&mut send, RESPONSE_BUSY).await;
        };
        let result = self.serve_request(peer, send, recv).await;
        drop(permit);
        self.release(peer.principal);
        result
    }

    /// Answer one pull: one at a time per peer, and none sooner than
    /// [`MIN_PULL_INTERVAL`] after its last. A pull outside its turn, or one
    /// naming nothing this host runs, costs the peer what refusing it cost.
    async fn serve_pull(
        &self,
        peer: Peer,
        send: SendStream,
        recv: RecvStream,
    ) -> Result<(), StreamError> {
        let Some(ctx) = self.attest.get() else {
            return Ok(());
        };
        let now = Instant::now();
        let taken = match self.pulls.entry(peer.endpoint) {
            Entry::Occupied(mut turn) => {
                let held = *turn.get();
                if held.open || now < held.at + MIN_PULL_INTERVAL {
                    false
                } else {
                    turn.insert(PullTurn {
                        at: now,
                        open: true,
                    });
                    true
                }
            }
            Entry::Vacant(turn) => {
                turn.insert(PullTurn {
                    at: now,
                    open: true,
                });
                true
            }
        };
        if !taken {
            self.charge(peer, refused_work(0, Refusal::Fault));
            return Ok(());
        }
        let answered = timeout(REQUEST_READ_TIMEOUT, bind::answer_pull(send, recv, ctx)).await;
        if let Some(mut turn) = self.pulls.get_mut(&peer.endpoint) {
            turn.open = false;
        }
        match answered {
            Err(_) => Err(StreamError::Timeout),
            Ok(Err(error)) => Err(StreamError::from(error)),
            Ok(Ok(0)) => {
                self.charge(peer, refused_work(0, Refusal::Fault));
                Ok(())
            }
            Ok(Ok(_)) => Ok(()),
        }
    }

    /// Read one request, run its handler, and write the response.
    async fn serve_request(
        &self,
        peer: Peer,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<(), StreamError> {
        let (class, shard, type_id, payload) = timeout(REQUEST_READ_TIMEOUT, async {
            let mut header = [0u8; 1 + SHARD_WIRE_LEN];
            AsyncReadExt::read_exact(&mut recv, &mut header)
                .await
                .map_err(StreamError::Io)?;
            let class = class_from_byte(header[0]).ok_or(StreamError::MalformedHeader)?;
            let mut shard_bytes = [0u8; SHARD_WIRE_LEN];
            shard_bytes.copy_from_slice(&header[1..]);
            let shard = decode_shard(shard_bytes).ok_or(StreamError::MalformedHeader)?;
            let (type_id, payload, wire_bytes) =
                framing::read_typed_frame(&mut recv, MAX_FRAME_SIZE)
                    .await
                    .map_err(StreamError::Frame)?;
            record_network_bandwidth((header.len() + wire_bytes) as u64, 0);
            Ok::<_, StreamError>((class, shard, type_id, payload))
        })
        .await
        .map_err(|_| StreamError::Timeout)??;

        // The response competes for the connection at its request's class.
        // The stream is ours alone and open, so this cannot fail.
        let _ = send.set_priority(class_priority(class));

        if !self.local_shards.load().contains(&shard) {
            return respond_status(&mut send, RESPONSE_SHARD_UNSUPPORTED).await;
        }
        // A relayed path takes no response of a class it does not carry;
        // saying so before the handler runs spares the work.
        if !self.paths.carries(peer.endpoint, class) {
            return respond_status(&mut send, RESPONSE_RELAYED).await;
        }
        let Some(handler) = self.registry.get_request(&type_id, shard) else {
            respond_status(&mut send, RESPONSE_UNKNOWN_TYPE).await?;
            return Err(StreamError::UnknownMessageType);
        };
        // A peer whose requests have cost this host its share is answered
        // busy before anything more is spent on it, and charged for the
        // refusal.
        if !self.serve_budget.admits(peer.principal) {
            self.charge(peer, refused_work(payload.len(), Refusal::Unjudged));
            return respond_status(&mut send, RESPONSE_BUSY).await;
        }

        // Handlers do heavy work (merkle proof generation) that would starve
        // the async runtime on a worker thread.
        let ((asked, answer), spent) = spawn_blocking(move || {
            processor_time(|| {
                let answer = handler(&payload);
                (payload, answer)
            })
        })
        .await
        .expect("request handler task panicked");
        self.serve_budget.charge(peer.principal, spent);
        let response = self
            .fault_gate
            .rewrite_response(peer.endpoint, &type_id, &asked, answer);
        drop(asked);

        if !self.paths.admit(peer.endpoint, class, response.len()) {
            return respond_status(&mut send, RESPONSE_RELAYED).await;
        }

        let wire_bytes = timeout(RESPONSE_WRITE_TIMEOUT, async {
            send.write_all(&[RESPONSE_OK])
                .await
                .map_err(StreamError::io)?;
            let wire_bytes = framing::write_frame(&mut send, &response)
                .await
                .map_err(StreamError::Io)?;
            send.finish().map_err(StreamError::io)?;
            // Hold the stream until the requester has the response or has
            // stopped reading; dropping it sooner would reset unsent data.
            let _ = send.stopped().await;
            Ok::<_, StreamError>(wire_bytes)
        })
        .await
        .map_err(|_| StreamError::Timeout)??;
        record_network_bandwidth(0, 1 + wire_bytes as u64);
        Ok(())
    }
}

/// Answer a request with a bare status and finish the stream.
async fn respond_status(send: &mut SendStream, status: u8) -> Result<(), StreamError> {
    send.write_all(&[status]).await.map_err(StreamError::io)?;
    send.finish().map_err(StreamError::io)?;
    let _ = timeout(REQUEST_READ_TIMEOUT, send.stopped()).await;
    Ok(())
}

/// Errors that can occur during stream handling.
#[derive(Debug)]
enum StreamError {
    Timeout,
    Io(io::Error),
    Frame(FrameError),
    UnknownStreamKind,
    MalformedHeader,
    UnknownMessageType,
}

impl From<BindError> for StreamError {
    fn from(error: BindError) -> Self {
        match error {
            BindError::Io(e) => Self::Io(e),
            BindError::Frame(e) => Self::Frame(e),
            _ => Self::MalformedHeader,
        }
    }
}

impl StreamError {
    fn io(error: impl Into<io::Error>) -> Self {
        Self::Io(error.into())
    }

    /// Whether the peer is to blame: it broke the protocol or stalled. A
    /// peer that closed or reset its stream abandoned it, as requesters do
    /// as a normal part of their retry strategy, and one that asked for a
    /// type this host does not know runs another version; neither is
    /// charged.
    fn is_peers_fault(&self) -> bool {
        !matches!(self, Self::UnknownMessageType) && !self.is_peer_abandonment()
    }

    /// Whether the error was caused by the peer closing or resetting the
    /// stream rather than a protocol violation or a local fault.
    fn is_peer_abandonment(&self) -> bool {
        let io_kind = match self {
            Self::Io(e) | Self::Frame(FrameError::Io(e)) => Some(e.kind()),
            _ => None,
        };
        matches!(
            io_kind,
            Some(
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::NotConnected
            )
        )
    }
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "stream timeout"),
            Self::Io(e) => write!(f, "stream I/O error: {e}"),
            Self::Frame(e) => write!(f, "stream frame error: {e}"),
            Self::UnknownStreamKind => write!(f, "unknown stream kind"),
            Self::MalformedHeader => write!(f, "malformed stream header"),
            Self::UnknownMessageType => write!(f, "unknown message type"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;

    use iroh::SecretKey;

    use super::*;

    fn random_peer() -> ValidatorId {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        ValidatorId::new(NEXT.fetch_add(1, Ordering::Relaxed))
    }

    fn make_router(global_cap: usize) -> InboundRouter {
        InboundRouter {
            global_semaphore: Arc::new(Semaphore::new(global_cap)),
            ..InboundRouter::new(
                Arc::new(HandlerRegistry::default()),
                Arc::new(ArcSwap::from_pointee(HashSet::new())),
                Arc::new(PathPolicy::default()),
                Arc::new(FaultState::new()),
                Arc::new(Cooldown::default()),
            )
        }
    }

    fn peer_count(router: &InboundRouter, peer: ValidatorId) -> usize {
        router
            .per_peer
            .get(&peer)
            .map_or(0, |c| c.load(Ordering::Relaxed))
    }

    #[tokio::test]
    async fn the_per_peer_cap_refuses_without_leaking_its_slot() {
        let router = make_router(MAX_INBOUND_PER_PEER * 2);
        let peer = random_peer();

        // Dropping a permit frees the global slot only, so the per-peer
        // count climbs as it would with every request still in flight.
        for _ in 0..MAX_INBOUND_PER_PEER {
            assert!(router.try_admit(peer).is_some(), "under cap");
        }
        assert!(router.try_admit(peer).is_none(), "at cap");
        assert_eq!(
            peer_count(&router, peer),
            MAX_INBOUND_PER_PEER,
            "a refusal rolls back its speculative increment"
        );

        router.release(peer);
        assert!(
            router.try_admit(peer).is_some(),
            "a finished request frees its slot"
        );
    }

    #[tokio::test]
    async fn one_saturated_peer_leaves_another_admittable() {
        let router = make_router(MAX_INBOUND_PER_PEER * 4);
        let a = random_peer();
        let b = random_peer();
        for _ in 0..MAX_INBOUND_PER_PEER {
            assert!(router.try_admit(a).is_some());
        }
        assert!(router.try_admit(a).is_none());
        assert!(router.try_admit(b).is_some());
    }

    #[tokio::test]
    async fn the_global_cap_refuses_without_charging_the_peer() {
        let router = make_router(2);
        let a = random_peer();
        let b = random_peer();
        let _p1 = router.try_admit(a).expect("first slot");
        let _p2 = router.try_admit(a).expect("second slot");

        assert!(router.try_admit(b).is_none(), "global cap refuses");
        assert_eq!(peer_count(&router, b), 0);
    }

    #[test]
    fn a_request_of_an_unknown_type_is_not_the_peers_fault() {
        assert!(!StreamError::UnknownMessageType.is_peers_fault());
        assert!(StreamError::MalformedHeader.is_peers_fault());
        assert!(StreamError::Timeout.is_peers_fault());
    }

    #[tokio::test(start_paused = true)]
    async fn successful_streams_do_not_buy_back_failed_ones() {
        let router = make_router(MAX_INBOUND_CONCURRENT);
        let peer = Peer {
            endpoint: SecretKey::generate().public(),
            principal: random_peer(),
        };
        let mut failed = 0;
        while !router.failures.cooling_down(peer.principal) {
            router.record_outcome(peer, &Err(StreamError::MalformedHeader));
            failed += 1;
            for _ in 0..7 {
                router.record_outcome(peer, &Ok(()));
            }
            assert!(
                failed <= 64,
                "a peer failing one stream in eight is cooled down"
            );
        }
    }

    #[test]
    fn a_stream_the_peer_abandoned_is_not_a_failure() {
        for kind in [
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::NotConnected,
        ] {
            assert!(StreamError::Io(io::Error::new(kind, "test")).is_peer_abandonment());
            assert!(
                StreamError::Frame(FrameError::Io(io::Error::new(kind, "test")))
                    .is_peer_abandonment()
            );
        }
        for error in [
            StreamError::Timeout,
            StreamError::UnknownStreamKind,
            StreamError::MalformedHeader,
            StreamError::UnknownMessageType,
            StreamError::Io(io::Error::new(io::ErrorKind::InvalidData, "test")),
            StreamError::Frame(FrameError::TooLarge(1_000_000)),
        ] {
            assert!(!error.is_peer_abandonment(), "{error:?} is a real failure");
        }
    }
}
