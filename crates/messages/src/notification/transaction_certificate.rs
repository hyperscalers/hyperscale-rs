//! TransactionCertificate notification message.

use hyperscale_types::{
    Bls12381G2Signature, MessagePriority, NetworkMessage, TransactionCertificate, ValidatorId,
};
use sbor::prelude::BasicSbor;

/// Notification of a finalized transaction certificate.
///
/// When a transaction certificate is finalized (all shard proofs collected), it is
/// sent to same-shard peers so they can persist it before the proposer includes
/// it in a block. This ensures certificates are available for fetch requests when
/// other validators receive the block header.
///
/// The sender signature authenticates the message, allowing receivers to reject
/// forged certificate notifications before processing.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct TransactionCertificateNotification {
    /// The finalized transaction certificate.
    pub certificate: TransactionCertificate,
    /// The validator who sent this notification.
    pub sender: ValidatorId,
    /// BLS signature over the domain-separated signing message, by the sender.
    pub sender_signature: Bls12381G2Signature,
}

impl TransactionCertificateNotification {
    /// Create a new signed transaction certificate notification message.
    pub fn new(
        certificate: TransactionCertificate,
        sender: ValidatorId,
        sender_signature: Bls12381G2Signature,
    ) -> Self {
        Self {
            certificate,
            sender,
            sender_signature,
        }
    }

    /// Build the canonical signing message for this notification.
    pub fn signing_message(&self, shard: hyperscale_types::ShardGroupId) -> Vec<u8> {
        hyperscale_types::tx_cert_gossip_message(shard, &self.certificate.transaction_hash)
    }

    /// Get the certificate.
    pub fn certificate(&self) -> &TransactionCertificate {
        &self.certificate
    }

    /// Consume and return the certificate.
    pub fn into_certificate(self) -> TransactionCertificate {
        self.certificate
    }
}

impl NetworkMessage for TransactionCertificateNotification {
    fn message_type_id() -> &'static str {
        "transaction.certificate"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Finalization
    }
}
