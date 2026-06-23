//! Committed-block-gossip step handlers.
//!
//! Gossip-delivered committed block headers go through a sender-signature
//! BLS verification pass before reaching the state machine. The flow is:
//!
//! 1. `CommittedBlockGossipReceived` — the inbound handler closure has
//!    already verified the sender's committee membership and resolved the
//!    public key. The header is queued in a batch accumulator for amortized
//!    BLS verification.
//! 2. `flush_certified_header_verifications` — fires when the batch fills
//!    or its window expires. Verified-marked items (local-dispatched from
//!    a colocated proposer) emit directly as
//!    `ProtocolEvent::VerifiedRemoteHeaderReceived` — the typestate
//!    marker rides through. Unverified items are queued on the crypto
//!    pool for envelope BLS verification; on success they emit as
//!    `ProtocolEvent::UnverifiedRemoteHeaderReceived` (the marker tracks
//!    the QC predicate, which the envelope check doesn't establish), and
//!    the state machine still dispatches `Action::VerifyRemoteHeaderQc`
//!    against them.

use std::sync::Arc;

use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_metrics::record_signature_verification_latency;
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::gossip::CertifiedBlockHeaderGossip;
use hyperscale_types::{
    Bls12381G1PublicKey, Bls12381G2Signature, CertifiedBlockHeader, Signed, SignedContext,
    ValidatorId, Verifiable,
};

use super::CertifiedHeaderVerificationItem;
use crate::shard_loop::{ShardLoop, push_protocol_event};

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Inbound handler closure already verified sender's committee
    /// membership and resolved the public key. Queue for batched BLS
    /// verification; fires `flush_certified_header_verifications` when full.
    pub(crate) fn handle_committed_block_gossip_received(
        &mut self,
        certified_header: Arc<Verifiable<CertifiedBlockHeader>>,
        sender: ValidatorId,
        public_key: Bls12381G1PublicKey,
        sender_signature: Bls12381G2Signature,
    ) {
        let item: CertifiedHeaderVerificationItem =
            (certified_header, sender, public_key, sender_signature);
        let now = self.now;
        if self.io.consensus.certified_header_batch.push(item, now) {
            self.flush_certified_header_verifications();
        }
    }

    /// Flush accumulated certified header sender-signature verifications.
    ///
    /// Partitions the batch on `is_verified()`: verified items
    /// (local-dispatched from a colocated proposer) emit directly as
    /// `VerifiedRemoteHeaderReceived`, skipping the envelope BLS check.
    /// Unverified items go to the crypto pool for batched signature
    /// verification; valid ones emit as `UnverifiedRemoteHeaderReceived`,
    /// invalid ones are warn-dropped.
    pub(crate) fn flush_certified_header_verifications(&mut self) {
        let items = self.io.consensus.certified_header_batch.take();
        if items.is_empty() {
            return;
        }

        let mut verified = Vec::new();
        let mut unverified = Vec::new();
        for item in items {
            if item.0.is_verified() {
                verified.push(item);
            } else {
                unverified.push(item);
            }
        }

        let shard = self.shard;

        // Fast path: emit verified items synchronously — no BLS work.
        for (certified_header, sender, _public_key, _sender_signature) in verified {
            let verified_header = Arc::unwrap_or_clone(certified_header)
                .into_verified()
                .unwrap_or_else(|_| unreachable!("is_verified() guards the verified partition"));
            push_protocol_event(
                self.event_sender(),
                shard,
                ProtocolEvent::VerifiedRemoteHeaderReceived {
                    certified_header: Arc::new(verified_header),
                    sender,
                },
            );
        }

        if unverified.is_empty() {
            return;
        }

        let event_tx = self.event_sender().clone();
        let topology = self.process.topology_snapshot.clone();
        self.process
            .dispatch
            .spawn(DispatchPool::Throughput, move || {
                let topo = topology.load();
                for (certified_header, sender, public_key, sender_signature) in unverified {
                    let gossip = CertifiedBlockHeaderGossip {
                        certified_header,
                        sender,
                        sender_signature,
                    };
                    let start = std::time::Instant::now();
                    let valid = gossip
                        .verify_signature(&SignedContext {
                            network: topo.network(),
                            public_key: &public_key,
                        })
                        .is_ok();
                    record_signature_verification_latency(
                        "certified_header",
                        start.elapsed().as_secs_f64(),
                    );
                    if valid {
                        let raw = Arc::unwrap_or_clone(gossip.certified_header).into_unverified();
                        push_protocol_event(
                            &event_tx,
                            shard,
                            ProtocolEvent::UnverifiedRemoteHeaderReceived {
                                certified_header: Arc::new(raw),
                                sender: gossip.sender,
                            },
                        );
                    } else {
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
