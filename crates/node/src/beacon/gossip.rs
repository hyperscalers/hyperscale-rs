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
use hyperscale_network::{GossipVerdict, Network};
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
        move |gossip: BeaconBlockGossip, target_shard: ShardId| -> GossipVerdict {
            let senders = s.load();
            let Some(tx) = senders.get(&target_shard) else {
                warn!(
                    target_shard = target_shard.inner(),
                    "Dropping beacon block gossip: shard not hosted"
                );
                return GossipVerdict::Reject;
            };
            push_protocol_event(
                tx,
                target_shard,
                ProtocolEvent::BeaconBlockReceived {
                    block: gossip.block,
                },
            );
            GossipVerdict::Accept
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
        move |gossip: BeaconCandidateGossip, target_shard: ShardId| -> GossipVerdict {
            let senders = s.load();
            let Some(tx) = senders.get(&target_shard) else {
                return GossipVerdict::Reject;
            };
            push_protocol_event(
                tx,
                target_shard,
                ProtocolEvent::BeaconCandidateReceived {
                    candidate: gossip.candidate,
                },
            );
            GossipVerdict::Accept
        },
    );

    // ── beacon.ratify_vote → ProtocolEvent::UnverifiedRatifyVoteReceived ──
    let s = senders.clone();
    network.register_gossip_handler::<RatifyVoteGossip>(
        move |gossip: RatifyVoteGossip, target_shard: ShardId| -> GossipVerdict {
            let senders = s.load();
            let Some(tx) = senders.get(&target_shard) else {
                return GossipVerdict::Reject;
            };
            push_protocol_event(
                tx,
                target_shard,
                ProtocolEvent::UnverifiedRatifyVoteReceived { vote: gossip.vote },
            );
            GossipVerdict::Accept
        },
    );
}
