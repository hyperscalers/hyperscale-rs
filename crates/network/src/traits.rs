//! Network trait for typed message passing.
//!
//! Defines the `Network` interface implemented by both production (`network-libp2p`)
//! and simulation (`network-memory`) backends.
//!
//! Handler registration is fully typed: `register_gossip_handler<M>` accepts a
//! `GossipHandler<M>` and `register_request_handler<R>` accepts a `RequestHandler<R>`.
//! The `HandlerRegistry` owns wire serialization — `Network` impls just forward.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_hbor::{HborEncode, to_vec as hbor_to_vec};
// Re-export for back-compat call sites; the canonical definition lives in
// `hyperscale_types`.
pub use hyperscale_types::TopicScope;
use hyperscale_types::{
    ConsensusPublicKey, GossipMessage, Hash, MessageClass, NetworkMessage, Request,
    RoutingCommittees, ShardId, TopologySnapshot, ValidatorId,
};

/// Maps `ValidatorId` to consensus public key for identity verification (e.g. validator-bind).
///
/// Derived from the topology snapshot inside network impls when
/// [`Network::update_topology`] is called.
pub type ValidatorKeyMap = HashMap<ValidatorId, ConsensusPublicKey>;

/// Error returned when a network request fails.
#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    /// No response received within the configured timeout.
    #[error("Request timed out")]
    Timeout,
    /// The transport's request manager retried the request against rotated
    /// peers and exhausted its retry budget. The transport already absorbed
    /// per-peer + per-request backoff before surfacing this — callers
    /// should retry immediately rather than pile additional deferral on
    /// top.
    #[error("Request exhausted after {attempts} attempts")]
    Exhausted {
        /// Number of attempts the transport made.
        attempts: u32,
    },
    /// Network layer could not reach the named peer.
    #[error("Peer unreachable: {0}")]
    PeerUnreachable(ValidatorId),
    /// No peers available in the target pool.
    #[error("No peers available")]
    NoPeers,
    /// Every candidate's stream is backing off after a recent failure, and
    /// the soonest is usable again after `retry_in`. Unlike
    /// [`Self::NoPeers`] the committee is there: asking again before
    /// `retry_in` finds it in the same state, and asking after it finds a
    /// peer to send to.
    #[error("Every candidate is backing off for {retry_in:?}")]
    BackingOff {
        /// Until the soonest candidate's stream is usable again.
        retry_in: Duration,
    },
    /// Peer answered with an application-level error.
    #[error("Peer returned error: {0}")]
    PeerError(String),
    /// Network is shutting down; the request will not complete.
    #[error("Network shutting down")]
    Shutdown,
}

/// What a handler made of an inbound message.
///
/// Returned by [`GossipHandler::on_message`] and
/// [`NotificationHandler::on_notification`] to tell the network layer
/// whether a gossip message may travel on, and whose fault it is when a
/// message is refused. A transport that charges senders for refused traffic
/// charges [`Self::Reject`] as the sender's fault and [`Self::Ignore`] as no
/// one's.
///
/// A handler whose checks of the message finish only after it returns says
/// [`Self::Defer`], naming every check the message's validity rests on, and
/// each check settles its part through [`Network::settle`]. A transport that
/// forwards only what it has judged holds the message until then, so a host
/// never forwards a message whose check could still fail, and the sender
/// answers for it when it does. A notification is never forwarded, so it is
/// not held; its sender answers for it when the verdict comes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing here holds the message against its sender. A gossip
    /// message is valid and travels on; a notification was taken in, its
    /// claims checked here or left to a check the state machine bounds
    /// itself.
    Accept,
    /// Message is invalid, and no honest sender sends it: it does not
    /// decode, or what it claims is false by this host's own settled view.
    /// Dropped, and held against the sender.
    Reject,
    /// This host cannot judge the message now: it does not serve the
    /// shard the message is for yet, or its view of the chain does not
    /// reach what the message names. Dropped and not forwarded, but not the
    /// sender's fault; a host that is behind refuses honest messages this
    /// way.
    Ignore,
    /// The message is being checked, and the checks it names settle the
    /// verdict through [`Network::settle`].
    Defer(Deferral),
}

impl Verdict {
    /// Defer to the check that settles the item `key` names.
    #[must_use]
    pub fn defer(key: VerdictKey) -> Self {
        Self::Defer(Deferral(vec![key]))
    }

    /// Defer to every check that settles one of the items `keys` names.
    ///
    /// # Panics
    ///
    /// Panics if `keys` is empty: a message that waits on no check has
    /// a verdict already.
    #[must_use]
    pub fn defer_all(keys: impl IntoIterator<Item = VerdictKey>) -> Self {
        let mut keys: Vec<VerdictKey> = keys.into_iter().collect();
        keys.sort_unstable_by_key(|key| key.0);
        keys.dedup();
        assert!(!keys.is_empty(), "a deferred verdict waits on some check");
        Self::Defer(Deferral(keys))
    }
}

/// The checks a deferred verdict waits on. The message holds up when every
/// one of them settles [`Verdict::Accept`], and is refused as soon as one
/// settles anything else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deferral(Vec<VerdictKey>);

impl Deferral {
    /// The items whose checks the verdict waits on, at least one.
    #[must_use]
    pub fn keys(&self) -> &[VerdictKey] {
        &self.0
    }

    /// The checks both deferrals wait on.
    #[must_use]
    pub fn join(self, other: Self) -> Self {
        let Verdict::Defer(joined) = Verdict::defer_all(self.0.into_iter().chain(other.0)) else {
            unreachable!("deferring on two deferrals' checks defers");
        };
        joined
    }
}

/// Names an item whose verdict waits on a check, so that the check,
/// finishing elsewhere, can settle it.
///
/// Derived from the item's encoding, so that the handler that defers and the
/// check that settles name the same item from the value each holds, and two
/// copies that differ in any signed byte are two items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VerdictKey([u8; 32]);

impl VerdictKey {
    /// The key of `item`.
    ///
    /// # Panics
    ///
    /// Panics if `item` does not encode; every value that decoded from the
    /// wire does.
    #[must_use]
    pub fn of<T: HborEncode + ?Sized>(item: &T) -> Self {
        let bytes = hbor_to_vec(item).expect("a decoded item encodes");
        Self(*Hash::from_bytes(&bytes).as_bytes())
    }

    /// The key named by a digest the item computes itself, for an item
    /// whose encoding costs more than a digest of fields it already holds.
    #[must_use]
    pub const fn from_digest(digest: Hash) -> Self {
        Self(*digest.as_bytes())
    }
}

/// Result of request-response evaluation by the application callback.
///
/// Returned by the `on_response` closure passed to [`Network::request`] so
/// the network layer can feed app-level success/failure into the same
/// peer-health tracker that timeouts and connection errors already use.
/// Use `Reject` whenever the response decoded fine at the wire layer but
/// was unusable to the app (peer returned `None`/empty, scope mismatch,
/// partial response, malformed payload). This deprioritizes the peer for
/// future selection without any extra plumbing from the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseVerdict {
    /// Response was usable — record success.
    Accept,
    /// Response was unusable — penalize the serving peer.
    Reject,
}

/// Typed handler for a single gossip message type.
///
/// Called once per **target hosted shard** the framework decides this
/// message should land in:
///
/// - For [`TopicScope::Shard`] messages the target is the topic's shard
///   (filtered to the host's hosted shards).
/// - For [`TopicScope::Global`] messages the framework fans the message
///   out to every hosted shard except [`GossipMessage::source_shard`]
///   (which sees its own commits directly, not through gossip).
///
/// The handler closure therefore makes no routing decisions and never
/// inspects `hosted_shards` — it just translates "this decoded message
/// destined for shard S" into a `ShardScopedInput` or equivalent.
pub trait GossipHandler<M: GossipMessage>: Send + Sync + 'static {
    /// Process a decoded gossip message for `shard`; return whether to
    /// forward it.
    fn on_message(&self, message: M, shard: ShardId) -> Verdict;
}

/// Blanket impl: any `Fn(M, ShardId) -> Verdict` can serve as
/// a typed gossip handler.
impl<M, F> GossipHandler<M> for F
where
    M: GossipMessage,
    F: Fn(M, ShardId) -> Verdict + Send + Sync + 'static,
{
    fn on_message(&self, message: M, shard: ShardId) -> Verdict {
        (self)(message, shard)
    }
}

/// Typed handler for inbound notification messages (fire-and-forget unicast).
///
/// Called after the network layer decodes the raw payload into `M`.
/// Nothing is answered: notifications are one-way. The returned [`Verdict`]
/// says whether the sender is to blame for the message.
pub trait NotificationHandler<M: NetworkMessage>: Send + Sync + 'static {
    /// Process a decoded notification.
    fn on_notification(&self, message: M) -> Verdict;
}

/// Blanket impl: any `Fn(M) -> Verdict` can serve as a typed notification
/// handler.
impl<M, F> NotificationHandler<M> for F
where
    M: NetworkMessage,
    F: Fn(M) -> Verdict + Send + Sync + 'static,
{
    fn on_notification(&self, message: M) -> Verdict {
        (self)(message)
    }
}

/// Typed handler for a single request message type.
///
/// Called after the network layer decodes the raw request into `R`.
/// The returned `R::Response` is encoded by the network layer before
/// sending back to the requester.
pub trait RequestHandler<R: Request>: Send + Sync + 'static {
    /// Produce a response for a decoded request.
    fn handle_request(&self, request: R) -> R::Response;
}

/// Blanket impl: any `Fn(R) -> R::Response` can serve as a typed request handler.
impl<R: Request, F: Fn(R) -> R::Response + Send + Sync + 'static> RequestHandler<R> for F {
    fn handle_request(&self, request: R) -> R::Response {
        (self)(request)
    }
}

/// Network interface for sending typed messages and handling inbound traffic.
///
/// Generic methods make this NOT object-safe — use `N: Network` bounds.
/// This is consistent with how storage and the engine are already used:
/// `ActionContext<S: ShardStorage, E: Engine>`.
///
/// All sends are fire-and-forget. Responses to requests arrive via callback.
pub trait Network: Send + Sync + 'static {
    // ── Pub/sub messaging ──

    /// Broadcast a shard-scoped message to all peers subscribed to that shard's topic.
    fn broadcast_to_shard<M: GossipMessage + 'static>(&self, shard: ShardId, message: &M);

    /// Broadcast a message to all connected peers globally.
    fn broadcast_global<M: GossipMessage + 'static>(&self, message: &M);

    // ── Handler registration ──

    /// Register a typed gossip handler for a message type.
    ///
    /// The implementation decodes the raw network payload into `M` before
    /// calling the handler. Decode errors are logged and the message is dropped.
    ///
    /// In production, this also auto-subscribes to the corresponding
    /// gossipsub topic(s); the scope (shard / global) is read from
    /// [`GossipMessage::SCOPE`].
    ///
    /// Called during node initialization — once per message type.
    fn register_gossip_handler<M: GossipMessage + 'static>(&self, handler: impl GossipHandler<M>);

    /// Register a handler invoked once per host for a [`TopicScope::Global`],
    /// [`source_shard`](GossipMessage::source_shard) `None` gossip message,
    /// regardless of the hosted-shard set, so a shard-less host (the
    /// beacon-follower pool) still receives committed beacon blocks.
    /// Additive: the per-hosted-shard Global fan is unchanged.
    ///
    /// Invoked only on a host that runs a follower pool. A backend that
    /// doesn't serve shard-less hosts may leave it unimplemented.
    fn register_host_gossip_handler<M: GossipMessage + 'static>(
        &self,
        handler: impl Fn(M) + Send + Sync + 'static,
    );

    /// Register a typed request handler for a message type on `shard`.
    ///
    /// The `HandlerRegistry` decodes the raw request into `R` and encodes
    /// the `R::Response` before sending it back. Decode/encode errors are logged
    /// and an empty response is returned.
    ///
    /// Called during node initialization — once per `(type, hosted shard)` pair.
    /// A multi-shard host registers one handler per hosted shard so each
    /// closure can capture its own `ShardIo`'s storage.
    ///
    /// `R: Send` and `R::Response: Send` are required so the registry can
    /// also install a typed local-dispatch path — same-host requests
    /// bypass libp2p and preserve `Arc`-shared payloads on the response.
    fn register_request_handler<R: Request + Send + 'static>(
        &self,
        shard: ShardId,
        handler: impl RequestHandler<R>,
    ) where
        R::Response: Send + 'static;

    // ── Unicast notifications ──

    /// Send a typed notification directly to specific validators (fire-and-forget).
    ///
    /// No response is expected. TCP provides packet-level reliability;
    /// protocol-level timeouts handle the rest.
    fn notify<M: NetworkMessage + 'static>(&self, recipients: &[ValidatorId], message: &M);

    /// Register a handler for inbound notification messages (fire-and-forget unicast).
    ///
    /// Called during node initialization — once per notification type.
    fn register_notification_handler<M: NetworkMessage + Clone + 'static>(
        &self,
        handler: impl NotificationHandler<M>,
    );

    // ── Shard participation ──

    /// Begin serving `shard`: include it in gossip fan-out and accept
    /// per-shard request-handler registrations for it. Transports with
    /// per-shard wire state (gossipsub topics, request stream
    /// protocols) bring that up as well.
    fn subscribe_shard(&self, shard: ShardId);

    /// Stop serving `shard`: exclude it from gossip fan-out, drop every
    /// request handler registered for it (so a later
    /// [`Self::subscribe_shard`] can register afresh), and tear down
    /// per-shard wire state. Traffic already dispatched against the old
    /// hosted set completes against the handlers it resolved.
    fn unsubscribe_shard(&self, shard: ShardId);

    // ── Topology updates ──

    /// Update the topology snapshot used for peer selection and identity
    /// verification.
    ///
    /// Called by the `io_loop` when topology changes. The network impl reads
    /// shard committees, validator consensus pubkeys, and the local validator set
    /// from the snapshot — callers don't pass any of that explicitly.
    ///
    /// Default is a no-op (simulation impls without committee routing don't
    /// need it).
    fn update_topology(&self, _snapshot: Arc<TopologySnapshot>) {}

    /// Update the terminal-clamped per-shard routing committees, covering
    /// every shard the schedule still retains — including a split parent
    /// draining out of the head. Fetch routing keys on these rather than the
    /// head snapshot, so a request to a dissolved shard still reaches its
    /// draining members through the retention window.
    ///
    /// Default is a no-op — simulation impls route by subscription, not
    /// committee, so the head snapshot never strands a dissolved shard.
    fn update_routing_committees(&self, _committees: Arc<RoutingCommittees>) {}

    // ── Deferred verdicts ──

    /// Settle the part of a deferred verdict the item `key` names, once the
    /// check of that item has finished: [`Verdict::Accept`] when the item
    /// holds up, [`Verdict::Reject`] when it is false, [`Verdict::Ignore`]
    /// when this host could not finish judging it; a deferral here is taken
    /// as [`Verdict::Ignore`]. A check runs on every copy, wherever it came
    /// from, and may run before any handler defers on it; settling an item
    /// no handler deferred is harmless.
    ///
    /// Default is a no-op, for a backend that does not wait for deferred
    /// verdicts.
    fn settle(&self, _key: VerdictKey, _verdict: Verdict) {}

    // ── Request-response ──

    /// Send a typed request and receive the response via callback.
    ///
    /// * `shard` — the shard whose committee answers the request. The
    ///   network impl resolves `shard` to its committee using the current
    ///   topology snapshot and picks the actual peer(s) to try (filtering
    ///   out locally-hosted validator ids automatically).
    /// * `preferred_peer` — optional hint for which peer to try first
    ///   (e.g. the block proposer for fetch requests). `None` means the
    ///   network's health-weighted selection picks freely. If the
    ///   `preferred_peer` is not in `shard`'s committee, the hint is
    ///   ignored.
    ///
    /// The callback is called on a network thread when the response arrives,
    /// or with an error on timeout/failure. Compatible with sync main loops —
    /// the callback typically pushes into the main loop's event channel. The
    /// callback returns a [`ResponseVerdict`] so app-level rejections (peer
    /// returned `None`/empty/wrong-scope) feed back into the same peer-health
    /// tracker that timeouts use, deprioritizing the serving peer for future
    /// selection. Verdict is ignored on the `Err` path (the network already
    /// recorded the failure).
    ///
    /// `class_override` lets the caller demote (or, in principle, promote)
    /// the message class on a per-call basis. `None` uses the wire type's
    /// static [`NetworkMessage::class()`]. Bimodal types like
    /// `GetTransactionsRequest` use this to differentiate hot-path
    /// pending-block fetches from sync / DA-backfill fetches.
    ///
    /// A seat this process hosts on `shard` answers first, and the
    /// committee only when that answer is empty; see
    /// [`Answerers::LocalFirst`].
    fn request<R: Request + Clone + 'static>(
        &self,
        shard: ShardId,
        preferred_peer: Option<ValidatorId>,
        request: R,
        class_override: Option<MessageClass>,
        on_response: Box<dyn FnOnce(Result<R::Response, RequestError>) -> ResponseVerdict + Send>,
    ) {
        self.request_from(
            shard,
            Answerers::LocalFirst,
            preferred_peer,
            request,
            class_override,
            on_response,
        );
    }

    /// [`Self::request`], asked of `answerers`: with
    /// [`Answerers::PeersOnly`] no seat this process hosts answers, and
    /// the request goes to the committee's other members at once.
    fn request_from<R: Request + Clone + 'static>(
        &self,
        shard: ShardId,
        answerers: Answerers,
        preferred_peer: Option<ValidatorId>,
        request: R,
        class_override: Option<MessageClass>,
        on_response: Box<dyn FnOnce(Result<R::Response, RequestError>) -> ResponseVerdict + Send>,
    );
}

/// Who may answer a request.
///
/// A seat this process hosts answers at no cost and comes first. Its
/// answer is final unless it is empty, so a seat that answers with
/// something the requester refuses — a store on another branch at the
/// height asked, say — would answer every retry the same way and keep
/// the committee from ever being asked. A requester whose attempt failed
/// for any reason asks whichever of the two it did not ask last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Answerers {
    /// A seat this process hosts on the shard, then the committee's other
    /// members when that answer is empty.
    LocalFirst,
    /// The committee's other members only.
    PeersOnly,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_deferral_names_each_check_once() {
        let (a, b) = (VerdictKey::of(&1u8), VerdictKey::of(&2u8));
        assert_eq!(Verdict::defer_all([a, b, a]), Verdict::defer_all([b, a]));
        let Verdict::Defer(deferral) = Verdict::defer_all([a, b, a]) else {
            panic!("a deferral");
        };
        assert_eq!(deferral.keys().len(), 2);
        assert_eq!(
            Verdict::Defer(deferral.join(Deferral(vec![a]))),
            Verdict::defer_all([a, b])
        );
    }

    #[test]
    #[should_panic(expected = "waits on some check")]
    fn a_deferral_waits_on_some_check() {
        let _ = Verdict::defer_all([]);
    }

    // Verify that closures satisfy GossipHandler<M> via blanket impl.
    #[test]
    fn test_closure_gossip_handler() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use hyperscale_hbor::Hbor;
        use hyperscale_types::{GossipMessage, NetworkMessage, TopicScope};

        #[derive(Debug, Clone, Hbor)]
        struct TestMsg(u32);
        impl NetworkMessage for TestMsg {
            fn message_type_id() -> &'static str {
                "test.msg"
            }

            fn class() -> MessageClass {
                MessageClass::Recovery
            }
        }
        impl GossipMessage for TestMsg {
            const SCOPE: TopicScope = TopicScope::Shard;
        }

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let handler = move |_msg: TestMsg, _shard: ShardId| -> Verdict {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            Verdict::Accept
        };
        let verdict = handler.on_message(TestMsg(42), ShardId::ROOT);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(verdict, Verdict::Accept);
    }
}
