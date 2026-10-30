//! Beacon gossip handler registration.
//!
//! A free function rather than a `ProcessIo` method: the handler closures
//! capture only the shard senders and the beacon loop's channel — never
//! the single `Network` owner — so they register without fighting that
//! ownership. `process::network_handlers` calls this from
//! `register_gossip_handlers`.

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

/// Register the beacon gossip handlers on `network`.
///
/// - A host-level handler runs once per host, a shard-less one included,
///   and is the one that feeds the host's beacon loop.
/// - A per-shard handler runs once per hosted shard (the framework's
///   Global topic reaches every hosted shard) and forwards nothing: it
///   holds the item's gossip verdict for the beacon loop's checks, whose
///   action handlers settle it, so the transport forwards a beacon item
///   only once it holds up. An item the loop drops unchecked because it
///   cannot place it is never settled and so never forwarded from here;
///   one it holds already was settled when it was first checked.
///
/// Both check the same item, so the loop's check of the host-level copy
/// settles the verdict the per-shard handlers hold.
pub fn register_beacon_gossip_handlers<N: Network>(
    network: &N,
    senders: &SharedShardSenders,
    beacon_sender: &Sender<HostEvent>,
) {
    // ── beacon.block → ProtocolEvent::BeaconBlockReceived ───────
    //
    // The fold dedups verification by block hash and ignores blocks at
    // or behind its tip.
    let s = senders.clone();
    network.register_gossip_handler::<BeaconBlockGossip>(
        move |gossip: BeaconBlockGossip, target_shard: ShardId| -> Verdict {
            if !s.load().contains_key(&target_shard) {
                warn!(
                    target_shard = target_shard.inner(),
                    "Dropping beacon block gossip: shard not hosted"
                );
                return Verdict::Ignore;
            }
            Verdict::defer(VerdictKey::of(gossip.block()))
        },
    );
    let bs = beacon_sender.clone();
    network.register_host_gossip_handler::<BeaconBlockGossip>(move |gossip: BeaconBlockGossip| {
        let _ = bs.send(HostEvent::beacon(ProtocolEvent::BeaconBlockReceived {
            block: gossip.block,
        }));
    });

    // ── beacon.candidate → ProtocolEvent::BeaconCandidateReceived ──
    //
    // Every participant in the epoch's ratify pool needs the candidate:
    // without it a member can only ever prevote the skip hash.
    let s = senders.clone();
    network.register_gossip_handler::<BeaconCandidateGossip>(
        move |gossip: BeaconCandidateGossip, target_shard: ShardId| -> Verdict {
            if !s.load().contains_key(&target_shard) {
                return Verdict::Ignore;
            }
            Verdict::defer(VerdictKey::of(gossip.candidate()))
        },
    );
    let bs = beacon_sender.clone();
    network.register_host_gossip_handler::<BeaconCandidateGossip>(
        move |gossip: BeaconCandidateGossip| {
            let _ = bs.send(HostEvent::beacon(ProtocolEvent::BeaconCandidateReceived {
                candidate: gossip.candidate,
            }));
        },
    );

    // ── beacon.ratify_vote → ProtocolEvent::UnverifiedRatifyVoteReceived ──
    //
    // One event per vote the message carries — the sender's own and each
    // proof vote — so every one is gated, verified, and pooled on its own
    // merits. A ratify voter precommits only on a prevote quorum it
    // observes, so every participant must see its peers' votes.
    let s = senders.clone();
    network.register_gossip_handler::<RatifyVoteGossip>(
        move |gossip: RatifyVoteGossip, target_shard: ShardId| -> Verdict {
            if !s.load().contains_key(&target_shard) {
                return Verdict::Ignore;
            }
            // Every vote the message carries is judged as it would be
            // alone, and the message travels on only once all of them hold.
            // A proof vote this host pooled already is not checked again;
            // the check that pooled it settled it.
            Verdict::defer_all(
                std::iter::once(gossip.vote())
                    .chain(gossip.proof.iter().map(|vote| vote.as_unverified()))
                    .map(VerdictKey::of),
            )
        },
    );
    let bs = beacon_sender.clone();
    network.register_host_gossip_handler::<RatifyVoteGossip>(move |gossip: RatifyVoteGossip| {
        for vote in gossip.into_votes() {
            let _ = bs.send(HostEvent::beacon(
                ProtocolEvent::UnverifiedRatifyVoteReceived { vote },
            ));
        }
    });
}
