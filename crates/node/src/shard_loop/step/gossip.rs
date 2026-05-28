//! Committed-block-gossip step handlers.
//!
//! Gossip-delivered committed block headers go through a sender-signature
//! BLS verification pass before reaching the state machine. The flow is:
//!
//! 1. `CommittedBlockGossipReceived` — the inbound handler closure has
//!    already verified the sender's committee membership and resolved the
//!    public key. The header is queued in a batch accumulator for amortized
//!    BLS verification.
//! 2. `flush_committed_header_verifications` — fires when the batch fills
//!    or its window expires. Spawns one closure on the crypto pool that
//!    verifies each sender's BLS signature. Valid headers are emitted
//!    directly as `ProtocolEvent::RemoteHeaderReceived` for the state
//!    machine to dispatch QC verification.

use std::sync::Arc;

use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_metrics::record_signature_verification_latency;
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::gossip::CommittedBlockHeaderGossip;
use hyperscale_types::{
    Bls12381G1PublicKey, Bls12381G2Signature, CommittedBlockHeader, Signed, SignedContext,
    ValidatorId,
};

use crate::shard_io::CommittedHeaderVerificationItem;
use crate::shard_loop::{ShardLoop, push_protocol_event};

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Inbound handler closure already verified sender's committee
    /// membership and resolved the public key. Queue for batched BLS
    /// verification; fires `flush_committed_header_verifications` when full.
    pub(in crate::shard_loop) fn handle_committed_block_gossip_received(
        &mut self,
        committed_header: Arc<CommittedBlockHeader>,
        sender: ValidatorId,
        public_key: Bls12381G1PublicKey,
        sender_signature: Bls12381G2Signature,
    ) {
        let item: CommittedHeaderVerificationItem =
            (committed_header, sender, public_key, sender_signature);
        let now = self.now;
        if self.io.committed_header_batch.push(item, now) {
            self.flush_committed_header_verifications();
        }
    }

    /// Flush accumulated committed-header sender-signature verifications.
    ///
    /// Spawns one closure on the crypto pool that verifies each sender's
    /// BLS signature. Valid headers are emitted directly as
    /// `ProtocolEvent::RemoteHeaderReceived` for state-machine ingestion;
    /// invalid items are warn-dropped (byzantine peer; no cleanup needed).
    pub(crate) fn flush_committed_header_verifications(&mut self) {
        let items = self.io.committed_header_batch.take();
        if items.is_empty() {
            return;
        }

        let shard = self.shard;
        let event_tx = self.event_sender().clone();
        let topology = self.process.topology_snapshot.clone();
        self.process
            .dispatch
            .spawn(DispatchPool::Throughput, move || {
                let topo = topology.load();
                for (committed_header, sender, public_key, sender_signature) in items {
                    let gossip = CommittedBlockHeaderGossip {
                        committed_header,
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
                        "committed_header",
                        start.elapsed().as_secs_f64(),
                    );
                    if valid {
                        push_protocol_event(
                            &event_tx,
                            shard,
                            ProtocolEvent::RemoteHeaderReceived {
                                committed_header: gossip.committed_header,
                                sender: gossip.sender,
                            },
                        );
                    } else {
                        tracing::warn!(
                            sender = gossip.sender.inner(),
                            height = gossip.committed_header.header().height().inner(),
                            "Committed header sender signature verification failed"
                        );
                    }
                }
            });
    }
}
