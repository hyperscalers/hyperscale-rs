//! Beacon gossip handler registration.
//!
//! A free function rather than a `ProcessIo` method: the handler closures
//! capture only the shard senders, the pool's beacon channel, and the
//! route-active gate — never the single `Network` owner — so they register
//! without fighting that ownership. `process::network_handlers` calls this
//! from `register_gossip_handlers`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crossbeam::channel::Sender;
use hyperscale_core::ProtocolEvent;
use hyperscale_network::{Network, Verdict, VerdictKey};
use hyperscale_types::ShardId;
use hyperscale_types::network::gossip::beacon::{
    BeaconBlockGossip, BeaconCandidateGossip, RatifyVoteGossip,
};
use tracing::warn;

use crate::event::HostEvent;
use crate::process::SharedShardSenders;
use crate::shard::push_protocol_event;

/// Register the beacon gossip handlers on `network`.
///
/// - `beacon.block` fans out per hosted shard (the framework's Global topic
///   reaches every hosted shard), each routed to that shard's vnodes.
/// - An additive host-level `beacon.block` handler routes the committed block
///   to the follower pool's beacon channel, but only while a pool is draining
///   it (`route_active`) — so a host with no live pool neither drops the
///   registration nor backs the channel up.
/// - `beacon.candidate` and `beacon.ratify_vote` route to the named
///   shard's consensus.
///
/// Each defers its gossip verdict to the coordinator's signature checks,
/// whose action handlers settle them, so the transport forwards a beacon
/// item only once it holds up. An item the coordinator drops unchecked
/// because it cannot place it is never settled and so never forwarded from
/// here; one it holds already was settled when it was first checked.
pub fn register_beacon_gossip_handlers<N: Network>(
    network: &N,
    senders: &SharedShardSenders,
    beacon_sender: &Sender<HostEvent>,
    route_active: &Arc<AtomicBool>,
) {
    // ── beacon.block → ProtocolEvent::BeaconBlockReceived ───────
    //
    // Each shard's vnodes process the gossip independently through
    // `handle_beacon` — the coordinator dedups verification by block hash
    // and ignores blocks at or behind its tip.
    let s = senders.clone();
    network.register_gossip_handler::<BeaconBlockGossip>(
        move |gossip: BeaconBlockGossip, target_shard: ShardId| -> Verdict {
            let senders = s.load();
            let Some(tx) = senders.get(&target_shard) else {
                warn!(
                    target_shard = target_shard.inner(),
                    "Dropping beacon block gossip: shard not hosted"
                );
                return Verdict::Ignore;
            };
            let key = VerdictKey::of(gossip.block());
            push_protocol_event(
                tx,
                target_shard,
                ProtocolEvent::BeaconBlockReceived {
                    block: gossip.block,
                },
            );
            Verdict::defer(key)
        },
    );

    // ── beacon.block → pool follower (additive, shard-less hosts) ──
    //
    // The per-hosted-shard Global fan above never reaches a host with no
    // hosted shards. This additive host-level handler routes the committed
    // block to the pool's beacon channel while a pool drains it.
    let bs = beacon_sender.clone();
    let ra = Arc::clone(route_active);
    network.register_host_gossip_handler::<BeaconBlockGossip>(move |gossip: BeaconBlockGossip| {
        if !ra.load(Ordering::Acquire) {
            return;
        }
        let _ = bs.send(HostEvent::beacon(ProtocolEvent::BeaconBlockReceived {
            block: gossip.block,
        }));
    });

    // ── beacon.candidate → ProtocolEvent::BeaconCandidateReceived ──
    let s = senders.clone();
    network.register_gossip_handler::<BeaconCandidateGossip>(
        move |gossip: BeaconCandidateGossip, target_shard: ShardId| -> Verdict {
            let senders = s.load();
            let Some(tx) = senders.get(&target_shard) else {
                return Verdict::Ignore;
            };
            let key = VerdictKey::of(gossip.candidate());
            push_protocol_event(
                tx,
                target_shard,
                ProtocolEvent::BeaconCandidateReceived {
                    candidate: gossip.candidate,
                },
            );
            Verdict::defer(key)
        },
    );

    // ── beacon.candidate → pool follower (additive) ────────────────
    //
    // A pooled validator can sit in the epoch's ratify pool (its seat
    // pending — a placement onto a halted shard, a draw not yet
    // bootstrapped); without the candidate it can only ever prevote the
    // skip hash and a follower-heavy pool degrades every epoch to skip.
    let bs = beacon_sender.clone();
    let ra = Arc::clone(route_active);
    network.register_host_gossip_handler::<BeaconCandidateGossip>(
        move |gossip: BeaconCandidateGossip| {
            if !ra.load(Ordering::Acquire) {
                return;
            }
            let _ = bs.send(HostEvent::beacon(ProtocolEvent::BeaconCandidateReceived {
                candidate: gossip.candidate,
            }));
        },
    );

    // ── beacon.ratify_vote → ProtocolEvent::UnverifiedRatifyVoteReceived ──
    //
    // One event per vote the message carries — the sender's own and each
    // proof vote — so every one is gated, verified, and pooled on its own
    // merits.
    let s = senders.clone();
    network.register_gossip_handler::<RatifyVoteGossip>(
        move |gossip: RatifyVoteGossip, target_shard: ShardId| -> Verdict {
            let senders = s.load();
            let Some(tx) = senders.get(&target_shard) else {
                return Verdict::Ignore;
            };
            // Every vote the message carries is judged as it would be
            // alone, and the message travels on only once all of them hold.
            // A proof vote this host pooled already is not checked again;
            // the check that pooled it settled it.
            let checks: Vec<VerdictKey> = std::iter::once(gossip.vote())
                .chain(gossip.proof.iter().map(|vote| vote.as_unverified()))
                .map(VerdictKey::of)
                .collect();
            for vote in gossip.into_votes() {
                push_protocol_event(
                    tx,
                    target_shard,
                    ProtocolEvent::UnverifiedRatifyVoteReceived { vote },
                );
            }
            Verdict::defer_all(checks)
        },
    );

    // ── beacon.ratify_vote → pool follower (additive) ──────────────
    //
    // A ratify voter precommits only when it observes a prevote quorum,
    // so a pooled pool member must see its peers' votes or its weight
    // can never reach a commit certificate.
    let bs = beacon_sender.clone();
    let ra = Arc::clone(route_active);
    network.register_host_gossip_handler::<RatifyVoteGossip>(move |gossip: RatifyVoteGossip| {
        if !ra.load(Ordering::Acquire) {
            return;
        }
        for vote in gossip.into_votes() {
            let _ = bs.send(HostEvent::beacon(
                ProtocolEvent::UnverifiedRatifyVoteReceived { vote },
            ));
        }
    });
}
