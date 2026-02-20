//! Gossip message dispatch: topic → typed message → Event conversion.
//!
//! This module contains the application-level logic for converting wire-encoded
//! gossip messages into [`Event`] variants. It is used by:
//!
//! - **Production**: [`register_gossip_handlers`] registers typed handlers on a
//!   [`HandlerRegistry`] during setup. The codec pool dispatches incoming gossip
//!   through the registry, and handlers construct Events and send them via channel.
//!
//! - **Simulation**: [`decode_gossip_to_events`] decodes wire bytes directly into
//!   Events for the simulation harness to schedule with latency/partitions.

use hyperscale_core::Event;
use hyperscale_messages::gossip::{
    BlockHeaderGossip, BlockVoteGossip, StateCertificateBatch, StateProvisionBatch, StateVoteBatch,
    TransactionCertificateGossip, TransactionGossip,
};
use hyperscale_network::{decode_from_wire, CodecError, HandlerRegistry, Topic};

/// Register all gossip message handlers on a [`HandlerRegistry`].
///
/// Each handler decodes the typed gossip message, converts it to one or more
/// [`Event`] variants, and sends them through the provided channel. Called
/// during production setup before the network event loop starts.
pub fn register_gossip_handlers(
    registry: &HandlerRegistry,
    event_tx: crossbeam::channel::Sender<Event>,
) {
    // BlockHeaderGossip → Event::BlockHeaderReceived
    let tx = event_tx.clone();
    registry.register::<BlockHeaderGossip>(Box::new(move |_sender, gossip| {
        let _ = tx.send(Event::BlockHeaderReceived {
            header: gossip.header,
            retry_hashes: gossip.retry_hashes,
            priority_hashes: gossip.priority_hashes,
            tx_hashes: gossip.transaction_hashes,
            cert_hashes: gossip.certificate_hashes,
            deferred: gossip.deferred,
            aborted: gossip.aborted,
            commitment_proofs: gossip.commitment_proofs,
        });
    }));

    // BlockVoteGossip → Event::BlockVoteReceived
    let tx = event_tx.clone();
    registry.register::<BlockVoteGossip>(Box::new(move |_sender, gossip| {
        let _ = tx.send(Event::BlockVoteReceived { vote: gossip.vote });
    }));

    // StateProvisionBatch → Event::StateProvisionReceived (one per provision)
    let tx = event_tx.clone();
    registry.register::<StateProvisionBatch>(Box::new(move |_sender, batch| {
        for provision in batch.into_provisions() {
            let _ = tx.send(Event::StateProvisionReceived { provision });
        }
    }));

    // StateVoteBatch → Event::StateVoteReceived (one per vote)
    let tx = event_tx.clone();
    registry.register::<StateVoteBatch>(Box::new(move |_sender, batch| {
        for vote in batch.into_votes() {
            let _ = tx.send(Event::StateVoteReceived { vote });
        }
    }));

    // StateCertificateBatch → Event::StateCertificateReceived (one per cert)
    let tx = event_tx.clone();
    registry.register::<StateCertificateBatch>(Box::new(move |_sender, batch| {
        for cert in batch.into_certificates() {
            let _ = tx.send(Event::StateCertificateReceived { cert });
        }
    }));

    // TransactionGossip → Event::TransactionGossipReceived
    let tx = event_tx.clone();
    registry.register::<TransactionGossip>(Box::new(move |_sender, gossip| {
        let _ = tx.send(Event::TransactionGossipReceived {
            tx: gossip.transaction,
            submitted_locally: false,
        });
    }));

    // TransactionCertificateGossip → Event::TransactionCertificateReceived
    let tx = event_tx;
    registry.register::<TransactionCertificateGossip>(Box::new(move |_sender, gossip| {
        let _ = tx.send(Event::TransactionCertificateReceived {
            certificate: gossip.into_certificate(),
        });
    }));
}

/// Decode wire-encoded gossip bytes into Events based on topic.
///
/// Used by the simulation harness, which needs decoded Events (not handler dispatch)
/// so it can apply latency and partitions before scheduling delivery.
pub fn decode_gossip_to_events(topic: &Topic, data: &[u8]) -> Result<Vec<Event>, CodecError> {
    let msg_type = topic.message_type();

    match msg_type {
        "block.header" => {
            let gossip: BlockHeaderGossip = decode_from_wire(data)?;
            Ok(vec![Event::BlockHeaderReceived {
                header: gossip.header,
                retry_hashes: gossip.retry_hashes,
                priority_hashes: gossip.priority_hashes,
                tx_hashes: gossip.transaction_hashes,
                cert_hashes: gossip.certificate_hashes,
                deferred: gossip.deferred,
                aborted: gossip.aborted,
                commitment_proofs: gossip.commitment_proofs,
            }])
        }
        "block.vote" => {
            let gossip: BlockVoteGossip = decode_from_wire(data)?;
            Ok(vec![Event::BlockVoteReceived { vote: gossip.vote }])
        }
        "state.provision.batch" => {
            let batch: StateProvisionBatch = decode_from_wire(data)?;
            Ok(batch
                .into_provisions()
                .into_iter()
                .map(|provision| Event::StateProvisionReceived { provision })
                .collect())
        }
        "state.vote.batch" => {
            let batch: StateVoteBatch = decode_from_wire(data)?;
            Ok(batch
                .into_votes()
                .into_iter()
                .map(|vote| Event::StateVoteReceived { vote })
                .collect())
        }
        "state.certificate.batch" => {
            let batch: StateCertificateBatch = decode_from_wire(data)?;
            Ok(batch
                .into_certificates()
                .into_iter()
                .map(|cert| Event::StateCertificateReceived { cert })
                .collect())
        }
        "transaction.gossip" => {
            let gossip: TransactionGossip = decode_from_wire(data)?;
            Ok(vec![Event::TransactionGossipReceived {
                tx: gossip.transaction,
                submitted_locally: false,
            }])
        }
        "transaction.certificate" => {
            let gossip: TransactionCertificateGossip = decode_from_wire(data)?;
            Ok(vec![Event::TransactionCertificateReceived {
                certificate: gossip.into_certificate(),
            }])
        }
        _ => Err(CodecError::UnknownTopic(topic.to_string())),
    }
}
