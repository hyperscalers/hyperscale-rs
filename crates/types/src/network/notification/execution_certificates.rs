//! `ExecutionCertificatesNotification` message.

use sbor::prelude::BasicSbor;

use crate::{
    Bls12381G2Signature, ExecutionCertificate, MessageClass, NetworkDefinition, NetworkMessage,
    ShardGroupId, Signed, ValidatorId, exec_cert_batch_message,
};

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
    pub const fn new(
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
    pub const fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// Get the number of certificates in the batch.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.certificates.len()
    }
}

impl Signed for ExecutionCertificatesNotification {
    fn signer(&self) -> ValidatorId {
        self.sender
    }

    fn signature(&self) -> &Bls12381G2Signature {
        &self.sender_signature
    }

    /// Derives the batch's shard from `certificates[0]`. Empty batches use
    /// a sentinel shard so the resulting message can never match a real
    /// signature; the `IoLoop` also early-drops empty batches before
    /// verification, so this branch is defensive only.
    fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        let shard = self
            .certificates
            .first()
            .map_or(ShardGroupId::ROOT, ExecutionCertificate::shard_group_id);
        exec_cert_batch_message(network, shard, &self.certificates)
    }
}

impl NetworkMessage for ExecutionCertificatesNotification {
    fn message_type_id() -> &'static str {
        "execution.cert.batch"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}
