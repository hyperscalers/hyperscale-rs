//! A beacon committee member that crashes after signing a PC vote and
//! restarts in the same instance signs nothing that contradicts it.
//!
//! The sign handlers hold no state of their own; the process's beacon
//! store is all that survives a crash, so a restart is the same handler
//! run against the same store with nothing else carried over.

use std::sync::{Arc, Mutex};

use hyperscale_beacon::action_handlers::handle_action;
use hyperscale_core::{Action, BeaconActionContext, ProtocolEvent};
use hyperscale_crypto_bls::BlsVerifier;
use hyperscale_network::{
    GossipHandler, Network, NotificationHandler, RequestError, RequestHandler, ResponseVerdict,
};
use hyperscale_storage_memory::SimBeaconStorage;
use hyperscale_types::test_utils::TestCommittee;
use hyperscale_types::{
    Epoch, GossipMessage, MessageClass, NetworkMessage, PcValueElement, PcVector, Request,
    RoutingCommittees, ShardId, SpcView, TopologySnapshot, ValidatorId,
};

/// A network that counts the notifications it is asked to send.
#[derive(Default)]
struct Outbox {
    notified: Mutex<usize>,
}

impl Network for Outbox {
    fn broadcast_to_shard<M: GossipMessage + 'static>(&self, _: ShardId, _: &M) {}
    fn broadcast_global<M: GossipMessage + 'static>(&self, _: &M) {}
    fn register_gossip_handler<M: GossipMessage + 'static>(&self, _: impl GossipHandler<M>) {}
    fn register_host_gossip_handler<M: GossipMessage + 'static>(
        &self,
        _: impl Fn(M) + Send + Sync + 'static,
    ) {
    }
    fn register_request_handler<R: Request + Send + 'static>(
        &self,
        _: ShardId,
        _: impl RequestHandler<R>,
    ) where
        R::Response: Send + 'static,
    {
    }
    fn notify<M: NetworkMessage + 'static>(&self, _: &[ValidatorId], _: &M) {
        *self.notified.lock().expect("outbox lock") += 1;
    }
    fn register_notification_handler<M: NetworkMessage + Clone + 'static>(
        &self,
        _: impl NotificationHandler<M>,
    ) {
    }
    fn subscribe_shard(&self, _: ShardId) {}
    fn unsubscribe_shard(&self, _: ShardId) {}
    fn update_topology(&self, _: Arc<TopologySnapshot>) {}
    fn update_routing_committees(&self, _: Arc<RoutingCommittees>) {}
    fn request<R: Request + Clone + 'static>(
        &self,
        _: ShardId,
        _: Option<ValidatorId>,
        _: R,
        _: Option<MessageClass>,
        _: Box<dyn FnOnce(Result<R::Response, RequestError>) -> ResponseVerdict + Send>,
    ) {
    }
}

/// One process lifetime of a committee member: the handlers' context
/// over `storage`, and what they signed and sent.
struct Member {
    committee: TestCommittee,
    topology: TopologySnapshot,
    network: Arc<Outbox>,
    signed: Arc<Mutex<Vec<PcVector>>>,
}

impl Member {
    fn start() -> Self {
        let committee = TestCommittee::new(4, 7);
        let topology = committee.topology_snapshot(1);
        Self {
            committee,
            topology,
            network: Arc::new(Outbox::default()),
            signed: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Run `SignAndBroadcastPcVote1` for `v_in` at view 1 of epoch 3.
    fn vote1(&self, storage: &SimBeaconStorage, v_in: &PcVector) {
        let sink = Arc::clone(&self.signed);
        let notify: Arc<dyn Fn(ProtocolEvent) + Send + Sync> = Arc::new(move |event| {
            if let ProtocolEvent::VerifiedPcVote1Received { vote, .. } = event {
                sink.lock().expect("signed lock").push(vote.v_in().clone());
            }
        });
        let key = self.committee.signer(0);
        let ctx = BeaconActionContext {
            topology_snapshot: &self.topology,
            me: self.committee.validator_id(0),
            ratify_registers: storage,
            beacon_vote_registers: storage,
            network: &self.network,
            signer: &key,
            verifier: &BlsVerifier,
            notify,
            cache_beacon_proposal: &|_, _, _| {},
            cache_beacon_candidate: &|_| {},
        };
        handle_action(
            Action::SignAndBroadcastPcVote1 {
                epoch: Epoch::new(3),
                view: SpcView::new(1),
                v_in: v_in.clone(),
                recipients: self.committee.validator_ids().to_vec(),
            },
            &ctx,
        );
    }

    fn signed(&self) -> Vec<PcVector> {
        self.signed.lock().expect("signed lock").clone()
    }

    fn notified(&self) -> usize {
        *self.network.notified.lock().expect("outbox lock")
    }
}

fn vector(tag: u8) -> PcVector {
    PcVector::new([PcValueElement::new([tag; 32]), PcValueElement::BOTTOM])
}

#[test]
fn a_restarted_member_does_not_sign_a_conflicting_vote1() {
    let storage = SimBeaconStorage::new();
    let before = Member::start();
    before.vote1(&storage, &vector(1));
    assert_eq!(before.signed(), vec![vector(1)]);
    assert_eq!(before.notified(), 1);

    // The process dies and the machine loses every unsynced write; the
    // restarted member pooled other proposals, so its view-1 input
    // differs.
    drop(before);
    storage.lose_unsynced();
    let after = Member::start();
    after.vote1(&storage, &vector(2));
    after.vote1(&storage, &PcVector::new([PcValueElement::new([1; 32])]));
    assert!(
        after.signed().is_empty(),
        "neither a different vector nor a prefix of the signed one is signed"
    );
    assert_eq!(after.notified(), 0, "nothing reaches the network");

    // The vector it signed before the crash is still its vote: re-signing
    // it is a retransmission, not a second vote.
    after.vote1(&storage, &vector(1));
    assert_eq!(after.signed(), vec![vector(1)]);
    assert_eq!(after.notified(), 1);
}
