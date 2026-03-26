//! ExecutionWaveCertificatesNotification message.

use hyperscale_types::{
    Bls12381G2Signature, ExecutionWaveCertificate, MessagePriority, NetworkMessage, ShardGroupId,
    ValidatorId,
};
use sbor::prelude::BasicSbor;

/// Batched wave certificates proving execution quorum for entire waves.
///
/// Each wave certificate covers all transactions in a deterministic wave
/// partition of a block. Contains per-tx outcomes so remote shards can
/// extract individual transaction results for cross-shard finalization.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ExecutionWaveCertificatesNotification {
    /// The execution wave certificates being sent.
    pub certificates: Vec<ExecutionWaveCertificate>,
    /// The validator who sent this batch.
    pub sender: ValidatorId,
    /// BLS signature over the domain-separated signing message, by the sender.
    pub sender_signature: Bls12381G2Signature,
}

impl ExecutionWaveCertificatesNotification {
    /// Create a new signed execution wave certificate batch.
    pub fn new(
        certificates: Vec<ExecutionWaveCertificate>,
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
    pub fn signing_message(&self, shard: ShardGroupId) -> Vec<u8> {
        hyperscale_types::exec_wave_cert_batch_message(shard, &self.certificates)
    }

    /// Get the certificates.
    pub fn certificates(&self) -> &[ExecutionWaveCertificate] {
        &self.certificates
    }

    /// Consume and return the certificates.
    pub fn into_certificates(self) -> Vec<ExecutionWaveCertificate> {
        self.certificates
    }

    /// Check if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// Get the number of certificates in the batch.
    pub fn len(&self) -> usize {
        self.certificates.len()
    }
}

impl NetworkMessage for ExecutionWaveCertificatesNotification {
    fn message_type_id() -> &'static str {
        "execution.wave_cert.batch"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}
