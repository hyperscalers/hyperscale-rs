//! Batch flushing for committed-header BLS verification.
//!
//! The transaction-validation batch lives with the tx-validation step
//! handlers in [`super::step`]; this file is now committed-header only.

use super::IoLoop;
use super::verify::verify_bls_with_metrics;
use hyperscale_core::NodeInput;
use hyperscale_dispatch::{Dispatch, DispatchPool};
use hyperscale_engine::Engine;
use hyperscale_network::Network;
use hyperscale_storage::Storage;

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Flush accumulated committed header sender-signature verifications.
    ///
    /// Spawns one closure on the crypto pool that verifies each sender's BLS
    /// signature. Valid headers are sent back as `CommittedHeaderValidated`.
    pub(super) fn flush_committed_header_verifications(&mut self) {
        let items = self.committed_header_batch.take();
        if items.is_empty() {
            return;
        }

        let event_tx = self.event_sender.clone();
        self.dispatch.spawn(DispatchPool::Crypto, move || {
            for (committed_header, sender, public_key, sender_signature) in items {
                let msg = hyperscale_types::committed_block_header_message(
                    committed_header.header.shard_group_id,
                    committed_header.header.height,
                    &committed_header.header.hash(),
                );
                let valid = verify_bls_with_metrics(
                    &msg,
                    &public_key,
                    &sender_signature,
                    "committed_header",
                );
                if valid {
                    let _ = event_tx.send(NodeInput::CommittedHeaderValidated {
                        committed_header,
                        sender,
                    });
                } else {
                    tracing::warn!(
                        sender = sender.0,
                        height = committed_header.header.height.0,
                        "Committed header sender signature verification failed"
                    );
                }
            }
        });
    }
}
