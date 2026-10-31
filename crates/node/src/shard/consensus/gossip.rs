//! Committed-block-gossip step handlers.
//!
//! A peer's committed block header goes through a sender-signature
//! verification pass before reaching the state machine; the host's own
//! broadcast reaches it from the inbound handler. The flow is:
//!
//! 1. `CommittedBlockGossipReceived` — the inbound handler closure has
//!    already verified the sender's committee membership and resolved the
//!    public key. The header is queued in a batch accumulator so one
//!    dispatched task checks a batch of sender signatures, each on its own.
//! 2. `flush_certified_header_verifications` — fires when the batch fills
//!    or its window expires. The items are queued on the throughput pool
//!    for envelope signature verification; on success they emit as
//!    `ProtocolEvent::UnverifiedRemoteHeaderReceived` (the marker tracks
//!    the QC predicate, which the envelope check doesn't establish), and
//!    the state machine still dispatches `Action::VerifyRemoteHeaderQc`
//!    against them. The check settles the gossip verdict the inbound
//!    handler deferred to it, so the transport forwards a header only once
//!    its sender signature holds up, and charges the peer that delivered
//!    one that does not.

use std::sync::Arc;

use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_metrics::{
    record_signature_verification_failure, record_signature_verification_latency,
};
use hyperscale_network::{Network, Verdict, VerdictKey};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::gossip::CertifiedBlockHeaderGossip;
use hyperscale_types::{
    CertifiedBlockHeader, ConsensusPublicKey, ConsensusSignature, HeaderSource, ShardForkProof,
    Signed, SignedContext, Stopwatch, ValidatorId, Verifiable,
};

use super::CertifiedHeaderVerificationItem;
use crate::shard::{ShardLoop, push_protocol_event};

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Inbound handler closure already verified sender's committee
    /// membership and resolved the public key. Queue it for the next
    /// verification task; fires `flush_certified_header_verifications` when
    /// full.
    pub(crate) fn handle_committed_block_gossip_received(
        &mut self,
        certified_header: Verifiable<CertifiedBlockHeader>,
        sender: ValidatorId,
        public_key: ConsensusPublicKey,
        sender_signature: ConsensusSignature,
    ) {
        let item: CertifiedHeaderVerificationItem =
            (certified_header, sender, public_key, sender_signature);
        let now = self.now;
        if self.io.consensus.certified_header_batch.push(item, now) {
            self.flush_certified_header_verifications();
        }
    }

    /// A self-authenticating fork proof arrived over gossip. No sender
    /// signature to batch — hand the proof straight to the state machine,
    /// which re-verifies it against the local topology and fences.
    pub(crate) fn handle_shard_fork_proof_gossip_received(&self, proof: &ShardForkProof) {
        push_protocol_event(
            self.event_sender(),
            self.shard,
            ProtocolEvent::UnverifiedShardForkProofReceived {
                proof: Box::new(proof.clone()),
            },
        );
    }

    /// Flush accumulated certified header sender-signature verifications.
    ///
    /// Every item is a peer's copy: the host's own broadcast reaches the
    /// state machine from the inbound handler. One throughput-pool task
    /// checks each sender signature in turn; valid ones emit as
    /// `UnverifiedRemoteHeaderReceived`, invalid ones are warn-dropped.
    pub(crate) fn flush_certified_header_verifications(&mut self) {
        let items = self.io.consensus.certified_header_batch.take();
        if items.is_empty() {
            return;
        }

        let shard = self.shard;
        let event_tx = self.event_sender().clone();
        let topology_snapshot = self.process.topology_snapshot.clone();
        let verifier = Arc::clone(&self.process.verifier);
        let network = Arc::clone(&self.process.network);
        self.process
            .dispatch
            .spawn(DispatchPool::Throughput, move || {
                let topo = topology_snapshot.load();
                for (certified_header, sender, public_key, sender_signature) in items {
                    let gossip = CertifiedBlockHeaderGossip {
                        certified_header,
                        sender,
                        sender_signature,
                    };
                    let start = Stopwatch::start();
                    let valid = gossip
                        .verify_signature(&SignedContext {
                            network: topo.network(),
                            public_key: &public_key,
                            verifier: verifier.as_ref(),
                        })
                        .is_ok();
                    record_signature_verification_latency(
                        "certified_header",
                        start.elapsed().as_secs_f64(),
                    );
                    network.settle(
                        VerdictKey::from_digest(gossip.copy_digest()),
                        if valid {
                            Verdict::Accept
                        } else {
                            Verdict::Reject
                        },
                    );
                    if valid {
                        let raw = gossip.certified_header.into_unverified();
                        push_protocol_event(
                            &event_tx,
                            shard,
                            ProtocolEvent::UnverifiedRemoteHeaderReceived {
                                certified_header: raw,
                                source: HeaderSource::Gossip(gossip.sender),
                            },
                        );
                    } else {
                        record_signature_verification_failure("certified_header");
                        tracing::warn!(
                            sender = gossip.sender.inner(),
                            height = gossip.certified_header.header().height().inner(),
                            "Certified header sender signature verification failed"
                        );
                    }
                }
            });
    }
}
