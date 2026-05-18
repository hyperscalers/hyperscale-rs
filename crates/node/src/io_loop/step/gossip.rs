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
use hyperscale_engine::Engine;
use hyperscale_network::Network;
use hyperscale_storage::Storage;
use hyperscale_types::{
    Bls12381G1PublicKey, Bls12381G2Signature, CommittedBlockHeader, ShardGroupId, ValidatorId,
    committed_block_header_message,
};

use crate::io_loop::{IoLoop, ShardEvent};
use crate::shard::CommittedHeaderVerificationItem;
use crate::shard::verify::verify_bls_with_metrics;

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Inbound handler closure already verified sender's committee
    /// membership and resolved the public key. Queue for batched BLS
    /// verification; fires `flush_committed_header_verifications` when full.
    pub(in crate::io_loop) fn handle_committed_block_gossip_received(
        &mut self,
        shard: ShardGroupId,
        committed_header: Arc<CommittedBlockHeader>,
        sender: ValidatorId,
        public_key: Bls12381G1PublicKey,
        sender_signature: Bls12381G2Signature,
    ) {
        let item: CommittedHeaderVerificationItem =
            (committed_header, sender, public_key, sender_signature);
        let now = self.now();
        if self
            .shard_io_mut(shard)
            .committed_header_batch
            .push(item, now)
        {
            self.flush_committed_header_verifications(shard);
        }
    }

    /// Flush accumulated committed-header sender-signature verifications
    /// for `shard`.
    ///
    /// Spawns one closure on the crypto pool that verifies each sender's
    /// BLS signature. Valid headers are emitted directly as
    /// `ProtocolEvent::RemoteHeaderReceived` for state-machine ingestion;
    /// invalid items are warn-dropped (byzantine peer; no `IoLoop`
    /// cleanup needed). See `IoLoop::event_sender` for the off-thread
    /// → pinned-thread routing convention.
    pub(in crate::io_loop) fn flush_committed_header_verifications(&mut self, shard: ShardGroupId) {
        let items = self.shard_io_mut(shard).committed_header_batch.take();
        if items.is_empty() {
            return;
        }

        let event_tx = self.event_sender.clone();
        self.dispatch.spawn(DispatchPool::Crypto, move || {
            for (committed_header, sender, public_key, sender_signature) in items {
                let msg = committed_block_header_message(
                    committed_header.header().shard_group_id(),
                    committed_header.header().height(),
                    &committed_header.header().hash(),
                );
                let valid = verify_bls_with_metrics(
                    &msg,
                    &public_key,
                    &sender_signature,
                    "committed_header",
                );
                if valid {
                    let _ = event_tx.send(ShardEvent::protocol(
                        shard,
                        ProtocolEvent::RemoteHeaderReceived {
                            committed_header,
                            sender,
                        },
                    ));
                } else {
                    tracing::warn!(
                        sender = sender.inner(),
                        height = committed_header.header().height().inner(),
                        "Committed header sender signature verification failed"
                    );
                }
            }
        });
    }
}
