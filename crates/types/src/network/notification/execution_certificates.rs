//! `ExecutionCertificatesNotification` message.

use hyperscale_hbor::Hbor;

use crate::{
    ConsensusSignature, ExecutionCertificate, ExecutionCertificatesSenderMessage,
    MAX_TXS_PER_BLOCK, MessageClass, NetworkDefinition, NetworkMessage, ShardId, Signed,
    ValidatorId, signed_bytes,
};

/// Batched execution certificates proving quorum for execution ticks.
///
/// Each certificate covers all transactions in a deterministic tick
/// partition of a block. Contains per-tx outcomes so remote shards can
/// extract individual transaction results for cross-shard finalization.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct ExecutionCertificatesNotification {
    /// The execution certificates being sent.
    ///
    /// One per tick of a block, and a tick is a partition of the block's
    /// transactions, so the block's own transaction cap bounds them —
    /// the same ceiling [`GetExecutionCertsRequest`] asks under.
    ///
    /// [`GetExecutionCertsRequest`]: crate::network::request::GetExecutionCertsRequest
    #[hbor(max = MAX_TXS_PER_BLOCK)]
    pub certificates: Vec<ExecutionCertificate>,
    /// The validator who sent this batch.
    pub sender: ValidatorId,
    /// Signature over the domain-separated signing message, by the sender.
    pub(crate) sender_signature: ConsensusSignature,
}

impl ExecutionCertificatesNotification {
    /// Create a new signed execution certificate batch.
    #[must_use]
    pub const fn new(
        certificates: Vec<ExecutionCertificate>,
        sender: ValidatorId,
        sender_signature: ConsensusSignature,
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

    fn signature(&self) -> &ConsensusSignature {
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
            .map_or(ShardId::ROOT, ExecutionCertificate::shard_id);
        signed_bytes(
            &ExecutionCertificatesSenderMessage::new(shard, &self.certificates),
            network,
        )
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
