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

/// Register the beacon gossip handlers on `network`. Every handler feeds
/// the host's beacon loop.
///
/// - A per-shard handler runs once per hosted shard (the framework's
///   Global topic reaches every hosted shard). It defers its gossip
///   verdict to the beacon loop's checks, whose action handlers settle
///   them, so the transport forwards a beacon item only once it holds up.
///   An item the loop drops unchecked because it cannot place it is never
///   settled and so never forwarded from here; one it holds already was
///   settled when it was first checked.
/// - A host-level handler runs on every host, a shard-less one included,
///   and carries no verdict.
///
/// A host with N hosted shards therefore feeds the loop N + 1 copies of
/// an item; the fold's block dedup and the participants' pools absorb
/// every copy after the first.
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
    let bs = beacon_sender.clone();
    network.register_gossip_handler::<BeaconBlockGossip>(
        move |gossip: BeaconBlockGossip, target_shard: ShardId| -> Verdict {
            if !s.load().contains_key(&target_shard) {
                warn!(
                    target_shard = target_shard.inner(),
                    "Dropping beacon block gossip: shard not hosted"
                );
                return Verdict::Ignore;
            }
            let key = VerdictKey::of(gossip.block());
            let _ = bs.send(HostEvent::beacon(ProtocolEvent::BeaconBlockReceived {
                block: gossip.block,
            }));
            Verdict::defer(key)
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
    let bs = beacon_sender.clone();
    network.register_gossip_handler::<BeaconCandidateGossip>(
        move |gossip: BeaconCandidateGossip, target_shard: ShardId| -> Verdict {
            if !s.load().contains_key(&target_shard) {
                return Verdict::Ignore;
            }
            let key = VerdictKey::of(gossip.candidate());
            let _ = bs.send(HostEvent::beacon(ProtocolEvent::BeaconCandidateReceived {
                candidate: gossip.candidate,
            }));
            Verdict::defer(key)
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
    let bs = beacon_sender.clone();
    network.register_gossip_handler::<RatifyVoteGossip>(
        move |gossip: RatifyVoteGossip, target_shard: ShardId| -> Verdict {
            if !s.load().contains_key(&target_shard) {
                return Verdict::Ignore;
            }
            // Every vote the message carries is judged as it would be
            // alone, and the message travels on only once all of them hold.
            // A proof vote this host pooled already is not checked again;
            // the check that pooled it settled it.
            let checks: Vec<VerdictKey> = std::iter::once(gossip.vote())
                .chain(gossip.proof.iter().map(|vote| vote.as_unverified()))
                .map(VerdictKey::of)
                .collect();
            for vote in gossip.into_votes() {
                let _ = bs.send(HostEvent::beacon(
                    ProtocolEvent::UnverifiedRatifyVoteReceived { vote },
                ));
            }
            Verdict::defer_all(checks)
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
