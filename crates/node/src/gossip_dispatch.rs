//! Gossip message dispatch: topic → typed message → NodeInput conversion.
//!
//! [`register_gossip_handlers`] registers typed handlers on a [`HandlerRegistry`]
//! during setup. Both production and simulation use this function to set up gossip
//! dispatch through `HandlerRegistry::dispatch_gossip()`, ensuring the same
//! decode/dispatch code path is exercised in both environments.

use hyperscale_core::{NodeInput, ProtocolEvent};
use hyperscale_messages::gossip::{
    BlockHeaderGossip, BlockVoteGossip, StateCertificateBatch, StateProvisionBatch, StateVoteBatch,
    TransactionCertificateGossip, TransactionGossip,
};
use hyperscale_network::HandlerRegistry;

/// Register all gossip message handlers on a [`HandlerRegistry`].
///
/// Each handler decodes the typed gossip message, converts it to one or more
/// [`NodeInput`] variants, and sends them through the provided channel. Called
/// during both production and simulation setup.
pub fn register_gossip_handlers(
    registry: &HandlerRegistry,
    event_tx: crossbeam::channel::Sender<NodeInput>,
) {
    // BlockHeaderGossip → ProtocolEvent::BlockHeaderReceived
    let tx = event_tx.clone();
    registry.register::<BlockHeaderGossip>(Box::new(move |_sender, gossip| {
        let _ = tx.send(NodeInput::Protocol(ProtocolEvent::BlockHeaderReceived {
            header: gossip.header,
            retry_hashes: gossip.retry_hashes,
            priority_hashes: gossip.priority_hashes,
            tx_hashes: gossip.transaction_hashes,
            cert_hashes: gossip.certificate_hashes,
            deferred: gossip.deferred,
            aborted: gossip.aborted,
            commitment_proofs: gossip.commitment_proofs,
        }));
    }));

    // BlockVoteGossip → ProtocolEvent::BlockVoteReceived
    let tx = event_tx.clone();
    registry.register::<BlockVoteGossip>(Box::new(move |_sender, gossip| {
        let _ = tx.send(NodeInput::Protocol(ProtocolEvent::BlockVoteReceived {
            vote: gossip.vote,
        }));
    }));

    // StateProvisionBatch → ProtocolEvent::StateProvisionReceived (one per provision)
    let tx = event_tx.clone();
    registry.register::<StateProvisionBatch>(Box::new(move |_sender, batch| {
        for provision in batch.into_provisions() {
            let _ = tx.send(NodeInput::Protocol(ProtocolEvent::StateProvisionReceived {
                provision,
            }));
        }
    }));

    // StateVoteBatch → ProtocolEvent::StateVoteReceived (one per vote)
    let tx = event_tx.clone();
    registry.register::<StateVoteBatch>(Box::new(move |_sender, batch| {
        for vote in batch.into_votes() {
            let _ = tx.send(NodeInput::Protocol(ProtocolEvent::StateVoteReceived {
                vote,
            }));
        }
    }));

    // StateCertificateBatch → ProtocolEvent::StateCertificateReceived (one per cert)
    let tx = event_tx.clone();
    registry.register::<StateCertificateBatch>(Box::new(move |_sender, batch| {
        for cert in batch.into_certificates() {
            let _ = tx.send(NodeInput::Protocol(
                ProtocolEvent::StateCertificateReceived { cert },
            ));
        }
    }));

    // TransactionGossip → ProtocolEvent::TransactionGossipReceived
    let tx = event_tx.clone();
    registry.register::<TransactionGossip>(Box::new(move |_sender, gossip| {
        let _ = tx.send(NodeInput::Protocol(
            ProtocolEvent::TransactionGossipReceived {
                tx: gossip.transaction,
                submitted_locally: false,
            },
        ));
    }));

    // TransactionCertificateGossip → NodeInput::TransactionCertificateReceived
    let tx = event_tx;
    registry.register::<TransactionCertificateGossip>(Box::new(move |_sender, gossip| {
        let _ = tx.send(NodeInput::TransactionCertificateReceived {
            certificate: gossip.into_certificate(),
        });
    }));
}
