//! Gossip by fan-out to known sets.
//!
//! There is no overlay and no mesh. Every recipient of gossip is a
//! validator whose host this one is bound to, so a publisher sends straight
//! to an audience it works out from the committees:
//!
//! - **Shard scope.** The publisher sends to the destination committee: all
//!   of it when it has at most [`SHARD_FANOUT`] members besides the
//!   publisher, a uniform sample of that many otherwise. Nobody forwards. A
//!   member that misses an item fetches what it needs when a block names it.
//! - **Global scope.** The publisher sends to every member of the
//!   committees it sits in, to [`GLOBAL_SAMPLE`] more bound hosts drawn at
//!   random, and to its subscribers. A host that accepts an item forwards
//!   it once, to [`FORWARD_SAMPLE`] bound hosts drawn at random and to its
//!   subscribers. An item is recognised by the BLAKE3 hash of its scope,
//!   type, and payload, so each host handles and forwards it once however
//!   many copies arrive.
//!
//! A host that serves no shard sits in no committee and is sampled too
//! rarely to follow the chain, so it subscribes: it holds a stream open to
//! [`FOLLOWER_SUBSCRIPTIONS`] bound hosts, each of which then sends it every
//! global item it accepts.
//!
//! Samples are drawn only from hosts that proved, in the bind handshake,
//! that they carry a validator of the beacon derived set; nothing a peer
//! merely claims widens an audience. Each item a host refuses is charged
//! against its sender at about the work it took, and a sender whose refused
//! items cost more than its share is cooled down: its gossip streams are
//! stopped unread until the cooldown lapses.
//!
//! Discovery rides the same path. Each host announces its signed address
//! records at an interval, and hands a newly bound peer its own records and
//! every record in its book, so a host that knows one peer soon knows them
//! all.

use std::collections::{BTreeSet, HashSet};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use std::{io, mem};

use arc_swap::ArcSwap;
use blake3::Hasher;
use bytes::Bytes;
use dashmap::{DashMap, DashSet};
use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};
use hyperscale_metrics::{
    record_invalid_message, record_libp2p_bandwidth, record_network_message_received,
    record_network_message_sent,
};
use hyperscale_network::compression::{compress, decompress};
use hyperscale_network::{GossipVerdict, HandlerRegistry, RawGossipHandler, RawHostGossipHandler};
use hyperscale_types::network::gossip::ValidatorAddressGossip;
use hyperscale_types::{
    GossipMessage, MessageClass, NetworkMessage, RoutingCommittees, ShardId, TopologySnapshot,
    ValidatorId,
};
use iroh::EndpointId;
use iroh::endpoint::RecvStream;
use rand::{Rng, RngExt, rng};
use tokio::io::AsyncReadExt;
use tokio::runtime::Handle;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval, sleep};
use tracing::{debug, warn};

use crate::address_book::IngestOutcome;
use crate::cooldown::Cooldown;
use crate::endpoint::IrohAdapter;
use crate::framing::{self, FrameError, MAX_FRAME_SIZE};
use crate::notify::ClassStreams;
use crate::path::{PathKind, Readiness};
use crate::protocol::{
    SCOPE_GLOBAL, SCOPE_SHARD, SHARD_WIRE_LEN, STOP_GOSSIP_REFUSED, STOP_SUBSCRIBERS_FULL,
    STREAM_GOSSIP, STREAM_SUBSCRIBE, decode_shard, encode_shard,
};

/// Most members of a shard committee a publisher sends a shard scoped item
/// to.
pub const SHARD_FANOUT: usize = 16;

/// Bound hosts, beyond its own committees, a publisher sends a global item
/// to.
pub const GLOBAL_SAMPLE: usize = 8;

/// Bound hosts a host forwards an accepted global item to.
pub const FORWARD_SAMPLE: usize = 8;

/// Hosts a host that serves no shard subscribes to.
pub const FOLLOWER_SUBSCRIPTIONS: usize = 4;

/// Subscribers a host serves at once.
const MAX_SUBSCRIBERS: usize = 64;

/// Items remembered per generation of the seen set. Two generations are
/// held, so an item is recognised for at least this many items after it
/// arrived.
const SEEN_GENERATION: usize = 32_768;

/// Interval between validator address announcements. Also the worst-case
/// staleness a peer's book carries after this host changes addresses.
const ADDRESS_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(30);

/// Delay before the first address announcement, giving the endpoint time
/// to learn its own addresses and bind its bootstrap peers.
const FIRST_ANNOUNCE_DELAY: Duration = Duration::from_secs(1);

/// Interval at which a host that serves no shard tops up its subscriptions.
const SUBSCRIPTION_INTERVAL: Duration = Duration::from_secs(5);

/// Class address records travel at. A host that is reached only through a
/// relay still has to learn the book to find its committee, so records go
/// under the relayed budget rather than at the class of the bulk gossip
/// they are typed as, which a relayed path never carries.
const ADDRESS_RECORD_CLASS: MessageClass = MessageClass::CrossShardProgress;

/// Items of one peer judged at once. Judging (decompressing, decoding, and
/// for an address record checking a signature) runs off the read loop, and
/// a verdict that cools a peer down stops only what is read after it.
const JUDGED_AT_ONCE_PER_PEER: usize = 4;

/// Work charged against a peer for each of its gossip items this host
/// refuses: reading, hashing, and dispatching it.
const REFUSED_ITEM_WORK: Duration = Duration::from_micros(10);

/// Work charged for each KiB of a refused item, for decompressing and
/// decoding it.
const REFUSED_KIB_WORK: Duration = Duration::from_micros(1);

/// Work charged for a refused address record, whose signature this host
/// checks before it can refuse it. The other items the transport carries
/// fail, when they fail here, before any signature is checked.
const SIGNATURE_CHECK_WORK: Duration = Duration::from_millis(2);

/// The work charged for refusing an item of `bytes`.
fn refused_work(bytes: usize, signature_checked: bool) -> Duration {
    let kib = u32::try_from(bytes.div_ceil(1024)).unwrap_or(u32::MAX);
    let checked = if signature_checked {
        SIGNATURE_CHECK_WORK
    } else {
        Duration::ZERO
    };
    REFUSED_ITEM_WORK + REFUSED_KIB_WORK * kib + checked
}

/// Where a gossip item is addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Every host.
    Global,
    /// The hosts serving one shard.
    Shard(ShardId),
}

impl Scope {
    const fn shard(self) -> Option<ShardId> {
        match self {
            Self::Global => None,
            Self::Shard(shard) => Some(shard),
        }
    }

    /// The scope's bytes on the wire, which open every gossip frame.
    fn encode(self) -> Vec<u8> {
        match self {
            Self::Global => vec![SCOPE_GLOBAL],
            Self::Shard(shard) => {
                let mut bytes = Vec::with_capacity(1 + SHARD_WIRE_LEN);
                bytes.push(SCOPE_SHARD);
                bytes.extend_from_slice(&encode_shard(shard));
                bytes
            }
        }
    }
}

/// `limit` of `candidates` drawn uniformly, or all of them when there are
/// no more than that.
fn sample<T>(mut candidates: Vec<T>, limit: usize, rng: &mut (impl Rng + ?Sized)) -> Vec<T> {
    if candidates.len() <= limit {
        return candidates;
    }
    for chosen in 0..limit {
        let pick = rng.random_range(chosen..candidates.len());
        candidates.swap(chosen, pick);
    }
    candidates.truncate(limit);
    candidates
}

/// The validators a shard scoped item is sent to: the committee without
/// the publisher's own validators, sampled down to [`SHARD_FANOUT`].
fn shard_audience(
    committee: &[ValidatorId],
    own: &HashSet<ValidatorId>,
    rng: &mut (impl Rng + ?Sized),
) -> Vec<ValidatorId> {
    let others = committee
        .iter()
        .filter(|validator| !own.contains(validator))
        .copied()
        .collect();
    sample(others, SHARD_FANOUT, rng)
}

/// The hosts a published global item is sent to: every host carrying a
/// member of the publisher's own committees, [`GLOBAL_SAMPLE`] of the other
/// bound hosts, and every subscriber.
fn global_audience(
    committee_hosts: BTreeSet<EndpointId>,
    bound: &[EndpointId],
    subscribers: impl IntoIterator<Item = EndpointId>,
    rng: &mut (impl Rng + ?Sized),
) -> BTreeSet<EndpointId> {
    let others = bound
        .iter()
        .filter(|peer| !committee_hosts.contains(*peer))
        .copied()
        .collect();
    let mut audience = committee_hosts;
    audience.extend(sample(others, GLOBAL_SAMPLE, rng));
    audience.extend(subscribers);
    audience
}

/// The hosts an accepted global item is forwarded to: [`FORWARD_SAMPLE`] of
/// the bound hosts and every subscriber, never the host it came from.
fn forward_audience(
    sender: EndpointId,
    bound: &[EndpointId],
    subscribers: impl IntoIterator<Item = EndpointId>,
    rng: &mut (impl Rng + ?Sized),
) -> BTreeSet<EndpointId> {
    let others = bound
        .iter()
        .filter(|peer| **peer != sender)
        .copied()
        .collect();
    let mut audience: BTreeSet<EndpointId> =
        sample(others, FORWARD_SAMPLE, rng).into_iter().collect();
    audience.extend(subscribers);
    audience.remove(&sender);
    audience
}

/// What identifies a gossip item across every copy of it.
fn digest(scope: Scope, type_id: &str, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&scope.encode());
    hasher.update(&(type_id.len() as u64).to_le_bytes());
    hasher.update(type_id.as_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

/// The items this host has already handled, bounded by holding two
/// generations and discarding the older when the newer fills.
#[derive(Default)]
struct SeenSet {
    current: HashSet<[u8; 32]>,
    previous: HashSet<[u8; 32]>,
}

impl SeenSet {
    /// Remember `item`. Returns whether it is new.
    fn insert(&mut self, item: [u8; 32]) -> bool {
        if self.current.contains(&item) || self.previous.contains(&item) {
            return false;
        }
        if self.current.len() >= SEEN_GENERATION {
            self.previous = mem::take(&mut self.current);
        }
        self.current.insert(item)
    }
}

/// What decides whether a received item is accepted.
enum Judge {
    /// The transport's own address records: this host's address book, on
    /// every host whether or not it serves a shard, so a record is checked
    /// once and a forged one is refused wherever it lands.
    AddressBook,
    /// The handlers the node registered for the item's type.
    Registry {
        handler: Arc<RawGossipHandler>,
        host_handler: Option<Arc<RawHostGossipHandler>>,
    },
}

/// Encode one gossip frame: its scope, then a typed frame.
fn encode_frame(scope: Scope, type_id: &str, compressed: &[u8]) -> Result<Bytes, io::Error> {
    let mut frame = scope.encode();
    frame.extend_from_slice(&framing::encode_typed_frame(type_id, compressed)?);
    Ok(Bytes::from(frame))
}

/// Publishes, receives, and forwards gossip for one host.
pub struct Fanout {
    adapter: Arc<IrohAdapter>,
    registry: Arc<HandlerRegistry>,
    /// Outbound gossip streams, one per peer and class.
    streams: ClassStreams,
    seen: Mutex<SeenSet>,
    /// What each peer's refused items have cost this host.
    rejects: Cooldown,
    /// Turns at judging each peer's items.
    judging: DashMap<EndpointId, Arc<Semaphore>>,
    topology: Arc<ArcSwap<TopologySnapshot>>,
    routing_committees: Arc<ArcSwap<RoutingCommittees>>,
    /// Hosts that asked for every global item this host accepts.
    subscribers: DashSet<EndpointId>,
    /// Hosts this one holds a subscription stream to.
    subscriptions: Arc<DashSet<EndpointId>>,
    tokio_handle: Handle,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl Fanout {
    /// Start gossiping over `adapter`'s connections, dispatching what
    /// arrives through `registry`.
    pub fn spawn(
        adapter: Arc<IrohAdapter>,
        registry: Arc<HandlerRegistry>,
        topology: Arc<ArcSwap<TopologySnapshot>>,
        routing_committees: Arc<ArcSwap<RoutingCommittees>>,
        tokio_handle: Handle,
        latency: Duration,
    ) -> Arc<Self> {
        let fanout = Arc::new(Self {
            streams: ClassStreams::new(
                Arc::clone(&adapter),
                STREAM_GOSSIP,
                tokio_handle.clone(),
                latency,
            ),
            adapter,
            registry,
            seen: Mutex::new(SeenSet::default()),
            rejects: Cooldown::default(),
            judging: DashMap::new(),
            topology,
            routing_committees,
            subscribers: DashSet::new(),
            subscriptions: Arc::new(DashSet::new()),
            tokio_handle,
            tasks: Mutex::new(Vec::new()),
        });
        let tasks = vec![
            fanout
                .tokio_handle
                .spawn(announce_loop(Arc::downgrade(&fanout))),
            fanout
                .tokio_handle
                .spawn(subscription_loop(Arc::downgrade(&fanout))),
        ];
        *fanout.tasks.lock().expect("fanout tasks lock") = tasks;
        fanout
    }

    /// Publish `message` at `scope`: encode and compress it off the
    /// caller's thread, then send it to its audience.
    pub fn publish<M: GossipMessage + 'static>(self: &Arc<Self>, scope: Scope, message: M) {
        let fanout = Arc::clone(self);
        self.tokio_handle.spawn_blocking(move || {
            let payload = hbor_to_vec(&message).expect("wire encode failed");
            fanout.publish_encoded(scope, M::message_type_id(), M::class(), &payload);
        });
    }

    /// Send an encoded item this host originates to its audience.
    fn publish_encoded(&self, scope: Scope, type_id: &str, class: MessageClass, payload: &[u8]) {
        // The publisher has handled its own item already.
        self.seen
            .lock()
            .expect("seen set lock")
            .insert(digest(scope, type_id, payload));
        let frame = match encode_frame(scope, type_id, &compress(payload)) {
            Ok(frame) => frame,
            Err(error) => {
                warn!(type_id, %error, "Cannot frame gossip item");
                return;
            }
        };
        let audience = match scope {
            Scope::Shard(shard) => self.shard_hosts(shard),
            Scope::Global => global_audience(
                self.own_committee_hosts(),
                &self.adapter.connected_peers(),
                self.subscribers.iter().map(|peer| *peer),
                &mut rng(),
            ),
        };
        self.send(&audience, class, &frame);
    }

    fn send(&self, audience: &BTreeSet<EndpointId>, class: MessageClass, frame: &Bytes) {
        for peer in audience {
            self.streams.send(*peer, class, frame.clone());
            record_network_message_sent();
        }
    }

    /// The committee routed to `shard`.
    fn committee(&self, shard: ShardId) -> Vec<ValidatorId> {
        self.routing_committees.load().get(&shard).map_or_else(
            || self.topology.load().committee_for_shard(shard).to_vec(),
            Clone::clone,
        )
    }

    fn own_validators(&self) -> HashSet<ValidatorId> {
        self.adapter.local_validator_ids().iter().copied().collect()
    }

    /// The bound hosts behind `validators`.
    fn hosts_of(&self, validators: impl IntoIterator<Item = ValidatorId>) -> BTreeSet<EndpointId> {
        validators
            .into_iter()
            .filter_map(|validator| self.adapter.peer_for_validator(validator))
            .collect()
    }

    /// The hosts a shard scoped item for `shard` is sent to.
    fn shard_hosts(&self, shard: ShardId) -> BTreeSet<EndpointId> {
        let audience = shard_audience(&self.committee(shard), &self.own_validators(), &mut rng());
        self.hosts_of(audience)
    }

    /// The bound hosts carrying a member of a committee this host sits in.
    fn own_committee_hosts(&self) -> BTreeSet<EndpointId> {
        let own = self.own_validators();
        let members: BTreeSet<ValidatorId> = self
            .adapter
            .local_shards()
            .iter()
            .flat_map(|shard| self.committee(*shard))
            .filter(|validator| !own.contains(validator))
            .collect();
        self.hosts_of(members)
    }

    /// How this host reaches the other members of the committees it sits
    /// in.
    pub fn readiness(&self) -> Readiness {
        let own = self.own_validators();
        let members: BTreeSet<ValidatorId> = self
            .adapter
            .local_shards()
            .iter()
            .flat_map(|shard| self.committee(*shard))
            .filter(|validator| !own.contains(validator))
            .collect();
        let mut readiness = Readiness::default();
        for member in members {
            let kind = self
                .adapter
                .peer_for_validator(member)
                .map(|peer| self.adapter.paths().kind(peer));
            match kind {
                None => readiness.unbound += 1,
                Some(Some(PathKind::Relayed)) => readiness.relayed += 1,
                // A bound connection that has selected no path yet is
                // counted with the direct ones until it says otherwise.
                Some(Some(PathKind::Direct) | None) => readiness.direct += 1,
            }
        }
        readiness
    }

    /// Say so when too little of the committee is on a direct path.
    fn report_readiness(&self) {
        let readiness = self.readiness();
        if readiness.degraded() {
            warn!(
                direct = readiness.direct,
                relayed = readiness.relayed,
                unbound = readiness.unbound,
                "Fewer than two thirds of the committee are on a direct path; \
                 forward this host's port or give it an external address"
            );
        }
    }

    /// Read every gossip frame `peer` writes to this stream of `class`,
    /// until it finishes the stream, the connection closes, or the peer is
    /// cooled down.
    pub async fn read_gossip(
        self: &Arc<Self>,
        peer: EndpointId,
        class: MessageClass,
        mut recv: RecvStream,
    ) -> Result<(), FrameError> {
        loop {
            if self.rejects.cooling_down(peer) {
                let _ = recv.stop(STOP_GOSSIP_REFUSED);
                return Ok(());
            }
            let mut scope_byte = [0u8; 1];
            match AsyncReadExt::read_exact(&mut recv, &mut scope_byte).await {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(FrameError::Io(e)),
            }
            let scope = match scope_byte[0] {
                SCOPE_GLOBAL => Scope::Global,
                SCOPE_SHARD => {
                    let mut shard = [0u8; SHARD_WIRE_LEN];
                    AsyncReadExt::read_exact(&mut recv, &mut shard).await?;
                    Scope::Shard(decode_shard(shard).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "gossip frame names no shard")
                    })?)
                }
                _ => {
                    return Err(FrameError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unknown gossip scope",
                    )));
                }
            };
            let (type_id, compressed, wire_bytes) =
                framing::read_typed_frame_compressed(&mut recv, MAX_FRAME_SIZE).await?;
            record_libp2p_bandwidth((scope.encode().len() + wire_bytes) as u64, 0);
            // The peer's items are judged a few at a time, so it cannot have
            // more read than that before the verdicts that cool it down.
            let turns = Arc::clone(
                &self
                    .judging
                    .entry(peer)
                    .or_insert_with(|| Arc::new(Semaphore::new(JUDGED_AT_ONCE_PER_PEER))),
            );
            let turn = turns
                .acquire_owned()
                .await
                .expect("the judging semaphore is never closed");
            // Checked again once the frame and a turn are in hand: the wait
            // for them may have begun before the cooldown did.
            if self.rejects.cooling_down(peer) {
                let _ = recv.stop(STOP_GOSSIP_REFUSED);
                return Ok(());
            }
            self.receive(peer, class, scope, &type_id, &compressed, turn);
        }
    }

    /// Handle one gossip item from `sender`: deliver it once to this host's
    /// handlers and, when a global item is accepted, forward it once.
    fn receive(
        self: &Arc<Self>,
        sender: EndpointId,
        class: MessageClass,
        scope: Scope,
        type_id: &str,
        compressed: &[u8],
        turn: OwnedSemaphorePermit,
    ) {
        // Fault gate: a matching drop rule or a partition against the
        // sender suppresses both local delivery and forwarding.
        if self
            .adapter
            .fault_gate()
            .drop_inbound_gossip(sender, type_id)
        {
            return;
        }
        // A shard scoped item is for the hosts serving that shard.
        if let Scope::Shard(shard) = scope
            && !self.adapter.local_shards().contains(&shard)
        {
            debug!(
                peer = %sender.fmt_short(),
                shard = shard.inner(),
                type_id,
                "Dropping gossip for a shard this host does not serve"
            );
            return;
        }
        let judge =
            if scope == Scope::Global && type_id == ValidatorAddressGossip::message_type_id() {
                Judge::AddressBook
            } else if let Some(handler) = self.registry.get_gossip(type_id) {
                // A global item also reaches a host that serves no shard,
                // through the host level handler.
                let host_handler = match scope {
                    Scope::Global => self.registry.get_host_gossip(type_id),
                    Scope::Shard(_) => None,
                };
                Judge::Registry {
                    handler,
                    host_handler,
                }
            } else {
                // No handler is not the sender's fault.
                debug!(type_id, "No gossip handler registered for message type");
                return;
            };
        let payload = match decompress(compressed) {
            Ok(payload) => payload,
            Err(error) => {
                warn!(peer = %sender.fmt_short(), %error, "Failed to decompress gossip item");
                record_invalid_message();
                self.note_reject(sender, refused_work(compressed.len(), false));
                return;
            }
        };
        if !self
            .seen
            .lock()
            .expect("seen set lock")
            .insert(digest(scope, type_id, &payload))
        {
            return;
        }
        let forward = match scope {
            Scope::Global => encode_frame(scope, type_id, compressed).ok(),
            Scope::Shard(_) => None,
        };

        let refused = refused_work(payload.len(), matches!(judge, Judge::AddressBook));
        let fanout = Arc::clone(self);
        self.tokio_handle.spawn(async move {
            let _turn = turn;
            let verdict = match judge {
                Judge::AddressBook => fanout.ingest_address_record(&payload),
                Judge::Registry {
                    handler,
                    host_handler,
                } => {
                    if let Some(host_handler) = host_handler {
                        host_handler(payload.clone());
                    }
                    handler(payload, scope.shard())
                }
            };
            match verdict {
                GossipVerdict::Accept => {
                    record_network_message_received();
                    if let Some(frame) = forward {
                        let audience = forward_audience(
                            sender,
                            &fanout.adapter.connected_peers(),
                            fanout.subscribers.iter().map(|peer| *peer),
                            &mut rng(),
                        );
                        fanout.send(&audience, class, &frame);
                    }
                }
                GossipVerdict::Reject => {
                    record_invalid_message();
                    fanout.note_reject(sender, refused);
                }
            }
        });
    }

    /// Verify an address record and store it if it is the newest for its
    /// validator. Only a record that cannot be right is refused: one whose
    /// validator this host does not know yet, or that it holds a newer
    /// record for, is still news to others.
    fn ingest_address_record(&self, payload: &[u8]) -> GossipVerdict {
        let Ok(record) = hbor_from_slice::<ValidatorAddressGossip>(payload) else {
            return GossipVerdict::Reject;
        };
        match self.adapter.ingest_validator_address(&record) {
            IngestOutcome::Invalid => GossipVerdict::Reject,
            IngestOutcome::Recorded | IngestOutcome::Stale | IngestOutcome::UnknownValidator => {
                GossipVerdict::Accept
            }
        }
    }

    fn note_reject(&self, sender: EndpointId, work: Duration) {
        if let Some(cooldown) = self.rejects.charge(sender, work) {
            warn!(
                peer = %sender.fmt_short(),
                cooldown_secs = cooldown.as_secs_f32(),
                "Peer's gossip keeps being rejected; refusing it for a while"
            );
        }
    }

    /// Serve `peer`'s subscription for as long as it holds this stream
    /// open.
    pub async fn hold_subscription(&self, peer: EndpointId, mut recv: RecvStream) {
        if self.subscribers.len() >= MAX_SUBSCRIBERS && !self.subscribers.contains(&peer) {
            let _ = recv.stop(STOP_SUBSCRIBERS_FULL);
            return;
        }
        self.subscribers.insert(peer);
        // The stream carries nothing; it ends when the subscriber finishes
        // it or the connection closes.
        let mut sink = [0u8; 64];
        while matches!(recv.read(&mut sink).await, Ok(Some(_))) {}
        self.subscribers.remove(&peer);
    }

    /// Give a newly bound `peer` this host's own address records and every
    /// record in its book.
    pub fn on_link(&self, peer: EndpointId) {
        let mut records = self.adapter.address_records();
        records.extend(self.adapter.book_records());
        let type_id = ValidatorAddressGossip::message_type_id();
        for record in records {
            let Ok(payload) = hbor_to_vec(&record) else {
                continue;
            };
            if let Ok(frame) = encode_frame(Scope::Global, type_id, &compress(&payload)) {
                self.streams.send(peer, ADDRESS_RECORD_CLASS, frame);
            }
        }
    }

    /// Announce this host's address records to its global audience.
    fn announce_addresses(&self) {
        for record in self.adapter.address_records() {
            match hbor_to_vec(&record) {
                Ok(payload) => self.publish_encoded(
                    Scope::Global,
                    ValidatorAddressGossip::message_type_id(),
                    ADDRESS_RECORD_CLASS,
                    &payload,
                ),
                Err(error) => {
                    warn!(error = ?error, "Failed to encode validator address announcement");
                }
            }
        }
    }

    /// While this host serves no shard, hold subscriptions to
    /// [`FOLLOWER_SUBSCRIPTIONS`] bound hosts, dialing recorded validators
    /// when too few are bound.
    fn top_up_subscriptions(&self) {
        if !self.adapter.local_shards().is_empty() {
            return;
        }
        let wanted = FOLLOWER_SUBSCRIPTIONS.saturating_sub(self.subscriptions.len());
        let candidates: Vec<EndpointId> = self
            .adapter
            .connected_peers()
            .into_iter()
            .filter(|peer| !self.subscriptions.contains(peer))
            .collect();
        if candidates.len() < wanted {
            self.adapter.dial_recorded(wanted - candidates.len());
        }
        for peer in sample(candidates, wanted, &mut rng()) {
            self.subscriptions.insert(peer);
            let adapter = Arc::clone(&self.adapter);
            let subscriptions = Arc::clone(&self.subscriptions);
            self.tokio_handle.spawn(async move {
                if let Ok(mut stream) = adapter.open_uni(peer).await
                    && stream.write_all(&[STREAM_SUBSCRIBE, 0]).await.is_ok()
                {
                    // Resolves when the peer stops the stream or the
                    // connection closes: the subscription is over.
                    let _ = stream.stopped().await;
                }
                subscriptions.remove(&peer);
            });
        }
    }
}

impl Drop for Fanout {
    fn drop(&mut self) {
        for task in self.tasks.lock().expect("fanout tasks lock").iter() {
            task.abort();
        }
    }
}

async fn announce_loop(fanout: Weak<Fanout>) {
    sleep(FIRST_ANNOUNCE_DELAY).await;
    let mut tick = interval(ADDRESS_ANNOUNCE_INTERVAL);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        let Some(fanout) = fanout.upgrade() else {
            return;
        };
        fanout.announce_addresses();
        fanout.report_readiness();
    }
}

async fn subscription_loop(fanout: Weak<Fanout>) {
    let mut tick = interval(SUBSCRIPTION_INTERVAL);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        let Some(fanout) = fanout.upgrade() else {
            return;
        };
        fanout.top_up_subscriptions();
    }
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;

    fn seeded() -> ChaCha8Rng {
        ChaCha8Rng::seed_from_u64(7)
    }

    fn peers(count: usize) -> Vec<EndpointId> {
        (0..count).map(|_| SecretKey::generate().public()).collect()
    }

    fn validators(range: std::ops::Range<u64>) -> Vec<ValidatorId> {
        range.map(ValidatorId::new).collect()
    }

    #[test]
    fn a_small_committee_hears_a_shard_item_in_full_bar_the_publisher() {
        let committee = validators(0..SHARD_FANOUT as u64 + 1);
        let own = HashSet::from([ValidatorId::new(3)]);

        let audience = shard_audience(&committee, &own, &mut seeded());
        assert_eq!(audience.len(), SHARD_FANOUT);
        assert!(!audience.contains(&ValidatorId::new(3)));
    }

    #[test]
    fn a_large_committee_hears_a_shard_item_through_a_sample() {
        let committee = validators(0..128);
        let own = HashSet::from([ValidatorId::new(0)]);

        let audience = shard_audience(&committee, &own, &mut seeded());
        assert_eq!(audience.len(), SHARD_FANOUT);
        let distinct: HashSet<_> = audience.iter().collect();
        assert_eq!(distinct.len(), SHARD_FANOUT, "no member is drawn twice");
        assert!(audience.iter().all(|v| committee.contains(v)));
        assert!(!audience.contains(&ValidatorId::new(0)));

        let again = shard_audience(&committee, &own, &mut ChaCha8Rng::seed_from_u64(8));
        assert_ne!(audience, again, "the sample is drawn afresh each time");
    }

    #[test]
    fn a_global_item_goes_to_own_committees_a_sample_and_subscribers() {
        let bound = peers(40);
        let committee_hosts: BTreeSet<EndpointId> = bound[..5].iter().copied().collect();
        let subscriber = SecretKey::generate().public();

        let audience =
            global_audience(committee_hosts.clone(), &bound, [subscriber], &mut seeded());
        assert!(audience.is_superset(&committee_hosts));
        assert!(audience.contains(&subscriber));
        assert_eq!(audience.len(), 5 + GLOBAL_SAMPLE + 1);
    }

    #[test]
    fn a_host_bound_to_few_sends_a_global_item_to_all_of_them() {
        let bound = peers(3);
        let audience = global_audience(BTreeSet::new(), &bound, [], &mut seeded());
        assert_eq!(audience, bound.iter().copied().collect());
    }

    #[test]
    fn a_forward_skips_its_sender_and_reaches_every_subscriber() {
        let bound = peers(40);
        let sender = bound[0];
        let subscribers = [bound[1], sender, SecretKey::generate().public()];

        let audience = forward_audience(sender, &bound, subscribers, &mut seeded());
        assert!(
            !audience.contains(&sender),
            "nothing goes back where it came from"
        );
        assert!(audience.contains(&subscribers[0]));
        assert!(audience.contains(&subscribers[2]));
        assert!(audience.len() <= FORWARD_SAMPLE + 2);
        assert!(audience.len() >= FORWARD_SAMPLE);
    }

    #[test]
    fn an_item_is_new_once() {
        let mut seen = SeenSet::default();
        let item = digest(Scope::Global, "beacon.block", b"payload");
        assert!(seen.insert(item));
        assert!(!seen.insert(item));
    }

    #[test]
    fn the_seen_set_stays_within_two_generations() {
        let mut seen = SeenSet::default();
        let item = |i: usize| digest(Scope::Global, "t", &i.to_le_bytes());
        for i in 0..SEEN_GENERATION * 3 {
            assert!(seen.insert(item(i)));
        }
        assert!(seen.current.len() + seen.previous.len() <= SEEN_GENERATION * 2);
        assert!(
            !seen.insert(item(SEEN_GENERATION * 3 - 1)),
            "a recent item is still recognised"
        );
        assert!(seen.insert(item(0)), "the oldest generation was let go");
    }

    #[test]
    fn scope_and_type_are_part_of_what_an_item_is() {
        let global = digest(Scope::Global, "a", b"x");
        assert_ne!(global, digest(Scope::Shard(ShardId::ROOT), "a", b"x"));
        assert_ne!(global, digest(Scope::Global, "b", b"x"));
        assert_ne!(
            digest(Scope::Shard(ShardId::leaf(1, 0)), "a", b"x"),
            digest(Scope::Shard(ShardId::leaf(1, 1)), "a", b"x")
        );
        // A type id cannot borrow bytes from the payload.
        assert_ne!(
            digest(Scope::Global, "ab", b"c"),
            digest(Scope::Global, "a", b"bc")
        );
    }

    #[test]
    fn a_frame_opens_with_its_scope() {
        let global = encode_frame(Scope::Global, "t", b"z").unwrap();
        assert_eq!(global[0], SCOPE_GLOBAL);

        let shard = ShardId::leaf(2, 3);
        let framed = encode_frame(Scope::Shard(shard), "t", b"z").unwrap();
        assert_eq!(framed[0], SCOPE_SHARD);
        let mut id = [0u8; SHARD_WIRE_LEN];
        id.copy_from_slice(&framed[1..=SHARD_WIRE_LEN]);
        assert_eq!(decode_shard(id), Some(shard));
        assert_eq!(framed.len(), global.len() + SHARD_WIRE_LEN);
    }
}
