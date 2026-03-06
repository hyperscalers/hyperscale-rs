//! ExecutionCertificatesNotification message.

use crate::trace_context::TraceContext;
use hyperscale_types::{
    Bls12381G2Signature, ExecutionCertificate, MessagePriority, NetworkMessage, ValidatorId,
};
use sbor::prelude::BasicSbor;

/// Batched certificates proving execution quorum.
///
/// Contains full state data. Once all shards' certificates collected, transaction is finalized.
/// The sender signature authenticates the batch, allowing receivers to reject forged
/// certificate batches before doing expensive aggregated BLS signature verification.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ExecutionCertificatesNotification {
    /// The execution certificates being sent.
    pub certificates: Vec<ExecutionCertificate>,
    /// The validator who sent this batch.
    pub sender: ValidatorId,
    /// BLS signature over the domain-separated signing message, by the sender.
    pub sender_signature: Bls12381G2Signature,
    /// Trace context for distributed tracing (empty when feature disabled).
    pub trace_context: TraceContext,
}

impl ExecutionCertificatesNotification {
    /// Create a new signed execution certificate batch.
    pub fn new(
        certificates: Vec<ExecutionCertificate>,
        sender: ValidatorId,
        sender_signature: Bls12381G2Signature,
    ) -> Self {
        Self {
            certificates,
            sender,
            sender_signature,
            trace_context: TraceContext::default(),
        }
    }

    /// Build the canonical signing message for this batch.
    pub fn signing_message(&self, shard: hyperscale_types::ShardGroupId) -> Vec<u8> {
        hyperscale_types::exec_cert_batch_message(shard, &self.certificates)
    }

    /// Create a batch from a single certificate.
    pub fn single(
        certificate: ExecutionCertificate,
        sender: ValidatorId,
        sender_signature: Bls12381G2Signature,
    ) -> Self {
        Self::new(vec![certificate], sender, sender_signature)
    }

    /// Create a new signed execution certificate batch with trace context from current span.
    pub fn with_trace_context(
        certificates: Vec<ExecutionCertificate>,
        sender: ValidatorId,
        sender_signature: Bls12381G2Signature,
    ) -> Self {
        Self {
            certificates,
            sender,
            sender_signature,
            trace_context: TraceContext::from_current(),
        }
    }

    /// Get the certificates.
    pub fn certificates(&self) -> &[ExecutionCertificate] {
        &self.certificates
    }

    /// Consume and return the certificates.
    pub fn into_certificates(self) -> Vec<ExecutionCertificate> {
        self.certificates
    }

    /// Get the trace context.
    pub fn trace_context(&self) -> &TraceContext {
        &self.trace_context
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

impl NetworkMessage for ExecutionCertificatesNotification {
    fn message_type_id() -> &'static str {
        "execution.certificate.batch"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{zero_bls_signature, Hash, ShardGroupId, SignerBitfield, ValidatorId};

    fn make_cert() -> ExecutionCertificate {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);

        ExecutionCertificate {
            transaction_hash: Hash::from_bytes(b"tx"),
            shard_group_id: ShardGroupId(0),
            read_nodes: vec![],
            state_writes: vec![],
            writes_commitment: Hash::from_bytes(b"commitment"),
            success: true,
            aggregated_signature: zero_bls_signature(),
            signers,
        }
    }

    #[test]
    fn test_execution_certificate_batch() {
        let cert = make_cert();

        let batch = ExecutionCertificatesNotification::single(
            cert.clone(),
            ValidatorId(0),
            zero_bls_signature(),
        );
        assert_eq!(batch.len(), 1);
        assert!(!batch.is_empty());
        assert_eq!(batch.certificates()[0], cert);

        let extracted = batch.into_certificates();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0], cert);
    }

    #[test]
    fn test_empty_batch() {
        let certs =
            ExecutionCertificatesNotification::new(vec![], ValidatorId(0), zero_bls_signature());
        assert!(certs.is_empty());
        assert_eq!(certs.len(), 0);
    }

    #[test]
    fn test_message_type_id() {
        assert_eq!(
            ExecutionCertificatesNotification::message_type_id(),
            "execution.certificate.batch"
        );
    }

    #[test]
    fn test_trace_context() {
        let cert = make_cert();

        // new() should have empty trace context
        let batch = ExecutionCertificatesNotification::single(
            cert.clone(),
            ValidatorId(0),
            zero_bls_signature(),
        );
        assert!(!batch.trace_context().has_trace());

        // with_trace_context() without active span should also be empty
        let batch_with_ctx = ExecutionCertificatesNotification::with_trace_context(
            vec![cert],
            ValidatorId(0),
            zero_bls_signature(),
        );
        assert!(!batch_with_ctx.trace_context().has_trace() || TraceContext::is_enabled());
    }
}
