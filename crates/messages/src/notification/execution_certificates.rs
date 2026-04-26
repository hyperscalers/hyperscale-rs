//! `ExecutionCertificatesNotification` message.

use hyperscale_types::{
    Bls12381G2Signature, ExecutionCertificate, MessagePriority, NetworkMessage, ShardGroupId,
    ValidatorId,
};
use sbor::prelude::BasicSbor;

/// Batched execution certificates proving quorum for execution waves.
///
/// Each certificate covers all transactions in a deterministic wave
/// partition of a block. Contains per-tx outcomes so remote shards can
/// extract individual transaction results for cross-shard finalization.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ExecutionCertificatesNotification {
    /// The execution certificates being sent.
    pub certificates: Vec<ExecutionCertificate>,
    /// The validator who sent this batch.
    pub sender: ValidatorId,
    /// BLS signature over the domain-separated signing message, by the sender.
    pub sender_signature: Bls12381G2Signature,
}

impl ExecutionCertificatesNotification {
    /// Create a new signed execution certificate batch.
    #[must_use]
    pub fn new(
        certificates: Vec<ExecutionCertificate>,
        sender: ValidatorId,
        sender_signature: Bls12381G2Signature,
    ) -> Self {
        Self {
            certificates,
            sender,
            sender_signature,
        }
    }

    /// Build the canonical signing message for this batch.
    #[must_use]
    pub fn signing_message(&self, shard: ShardGroupId) -> Vec<u8> {
        hyperscale_types::exec_cert_batch_message(shard, &self.certificates)
    }

    /// Get the certificates.
    #[must_use]
    pub fn certificates(&self) -> &[ExecutionCertificate] {
        &self.certificates
    }

    /// Consume and return the certificates.
    #[must_use]
    pub fn into_certificates(self) -> Vec<ExecutionCertificate> {
        self.certificates
    }

    /// Check if the batch is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// Get the number of certificates in the batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.certificates.len()
    }
}

impl NetworkMessage for ExecutionCertificatesNotification {
    fn message_type_id() -> &'static str {
        "execution.cert.batch"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}
