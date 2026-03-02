//! State-related gossip messages for cross-shard transactions.
//!
//! All state messages use batching to reduce network overhead.
//! The runner accumulates individual items and flushes them periodically.

use crate::trace_context::TraceContext;
use hyperscale_types::{
    ExecutionCertificate, ExecutionVote, MessagePriority, NetworkMessage, ShardMessage,
    StateProvision, TransactionCertificate,
};
use sbor::prelude::BasicSbor;

/// Batched state provisions for cross-shard transactions.
///
/// Broadcasts state from owning shard to executing shard.
/// Target shard waits for 2f+1 matching provisions before marking as "provisioned".
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct StateProvisionBatch {
    /// The state provisions being broadcast
    pub provisions: Vec<StateProvision>,
    /// Trace context for distributed tracing (empty when feature disabled).
    pub trace_context: TraceContext,
}

impl StateProvisionBatch {
    /// Create a new state provision batch.
    pub fn new(provisions: Vec<StateProvision>) -> Self {
        Self {
            provisions,
            trace_context: TraceContext::default(),
        }
    }

    /// Create a batch from a single provision.
    pub fn single(provision: StateProvision) -> Self {
        Self::new(vec![provision])
    }

    /// Create a new state provision batch with trace context from current span.
    pub fn with_trace_context(provisions: Vec<StateProvision>) -> Self {
        Self {
            provisions,
            trace_context: TraceContext::from_current(),
        }
    }

    /// Get the provisions.
    pub fn provisions(&self) -> &[StateProvision] {
        &self.provisions
    }

    /// Consume and return the provisions.
    pub fn into_provisions(self) -> Vec<StateProvision> {
        self.provisions
    }

    /// Get the trace context.
    pub fn trace_context(&self) -> &TraceContext {
        &self.trace_context
    }

    /// Check if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.provisions.is_empty()
    }

    /// Get the number of provisions in the batch.
    pub fn len(&self) -> usize {
        self.provisions.len()
    }
}

impl NetworkMessage for StateProvisionBatch {
    fn message_type_id() -> &'static str {
        "state.provision.batch"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}

impl ShardMessage for StateProvisionBatch {}

/// Batched votes on transaction execution results within a shard.
///
/// 2f+1 matching votes create an ExecutionCertificate with aggregated BLS signature.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ExecutionVoteBatch {
    /// The execution votes being gossiped
    pub votes: Vec<ExecutionVote>,
}

impl ExecutionVoteBatch {
    /// Create a new execution vote batch.
    pub fn new(votes: Vec<ExecutionVote>) -> Self {
        Self { votes }
    }

    /// Create a batch from a single vote.
    pub fn single(vote: ExecutionVote) -> Self {
        Self::new(vec![vote])
    }

    /// Get the votes.
    pub fn votes(&self) -> &[ExecutionVote] {
        &self.votes
    }

    /// Consume and return the votes.
    pub fn into_votes(self) -> Vec<ExecutionVote> {
        self.votes
    }

    /// Check if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.votes.is_empty()
    }

    /// Get the number of votes in the batch.
    pub fn len(&self) -> usize {
        self.votes.len()
    }
}

impl NetworkMessage for ExecutionVoteBatch {
    fn message_type_id() -> &'static str {
        "execution.vote.batch"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}

impl ShardMessage for ExecutionVoteBatch {}

/// Batched certificates proving execution quorum.
///
/// Contains full state data. Once all shards' certificates collected, transaction is finalized.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ExecutionCertificateBatch {
    /// The execution certificates being gossiped
    pub certificates: Vec<ExecutionCertificate>,
    /// Trace context for distributed tracing (empty when feature disabled).
    pub trace_context: TraceContext,
}

impl ExecutionCertificateBatch {
    /// Create a new execution certificate batch.
    pub fn new(certificates: Vec<ExecutionCertificate>) -> Self {
        Self {
            certificates,
            trace_context: TraceContext::default(),
        }
    }

    /// Create a batch from a single certificate.
    pub fn single(certificate: ExecutionCertificate) -> Self {
        Self::new(vec![certificate])
    }

    /// Create a new execution certificate batch with trace context from current span.
    pub fn with_trace_context(certificates: Vec<ExecutionCertificate>) -> Self {
        Self {
            certificates,
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

impl NetworkMessage for ExecutionCertificateBatch {
    fn message_type_id() -> &'static str {
        "execution.certificate.batch"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Coordination
    }
}

impl ShardMessage for ExecutionCertificateBatch {}

/// Gossip message for a finalized transaction certificate.
///
/// When a transaction certificate is finalized (all shard proofs collected), it is
/// gossiped to same-shard peers so they can persist it before the proposer includes
/// it in a block. This ensures certificates are available for fetch requests when
/// other validators receive the block header.
///
/// Unlike batched messages, this uses individual gossip to enable better deduplication
/// by gossipsub - the message hash is based on the certificate content, so identical
/// certificates are naturally deduplicated across the network.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct TransactionCertificateGossip {
    /// The finalized transaction certificate being gossiped
    pub certificate: TransactionCertificate,
}

impl TransactionCertificateGossip {
    /// Create a new transaction certificate gossip message.
    pub fn new(certificate: TransactionCertificate) -> Self {
        Self { certificate }
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

impl NetworkMessage for TransactionCertificateGossip {
    fn message_type_id() -> &'static str {
        "transaction.certificate"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Finalization
    }
}

impl ShardMessage for TransactionCertificateGossip {}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        zero_bls_signature, BlockHeight, Hash, ShardGroupId, SignerBitfield, ValidatorId,
    };
    use std::sync::Arc;

    #[test]
    fn test_state_provision_batch() {
        let provision = StateProvision {
            transaction_hash: Hash::from_bytes(b"tx"),
            target_shard: ShardGroupId(1),
            source_shard: ShardGroupId(0),
            block_height: BlockHeight(10),
            block_timestamp: 1000,
            entries: Arc::new(vec![]),
            validator_id: ValidatorId(0),
            signature: zero_bls_signature(),
        };

        let batch = StateProvisionBatch::single(provision.clone());
        assert_eq!(batch.len(), 1);
        assert!(!batch.is_empty());
        assert_eq!(batch.provisions()[0], provision);

        let extracted = batch.into_provisions();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0], provision);
    }

    #[test]
    fn test_execution_vote_batch() {
        let vote = ExecutionVote {
            transaction_hash: Hash::from_bytes(b"tx"),
            shard_group_id: ShardGroupId(0),
            writes_commitment: Hash::from_bytes(b"commitment"),
            success: true,
            state_writes: vec![],
            validator: ValidatorId(0),
            signature: zero_bls_signature(),
        };

        let batch = ExecutionVoteBatch::single(vote.clone());
        assert_eq!(batch.len(), 1);
        assert!(!batch.is_empty());
        assert_eq!(batch.votes()[0], vote);

        let extracted = batch.into_votes();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0], vote);
    }

    #[test]
    fn test_execution_certificate_batch() {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);

        let cert = ExecutionCertificate {
            transaction_hash: Hash::from_bytes(b"tx"),
            shard_group_id: ShardGroupId(0),
            read_nodes: vec![],
            state_writes: vec![],
            writes_commitment: Hash::from_bytes(b"commitment"),
            success: true,
            aggregated_signature: zero_bls_signature(),
            signers,
            voting_power: 3,
        };

        let batch = ExecutionCertificateBatch::single(cert.clone());
        assert_eq!(batch.len(), 1);
        assert!(!batch.is_empty());
        assert_eq!(batch.certificates()[0], cert);

        let extracted = batch.into_certificates();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0], cert);
    }

    #[test]
    fn test_message_type_ids() {
        assert_eq!(
            StateProvisionBatch::message_type_id(),
            "state.provision.batch"
        );
        assert_eq!(
            ExecutionVoteBatch::message_type_id(),
            "execution.vote.batch"
        );
        assert_eq!(
            ExecutionCertificateBatch::message_type_id(),
            "execution.certificate.batch"
        );
    }

    #[test]
    fn test_empty_batches() {
        let provisions: StateProvisionBatch = StateProvisionBatch::new(vec![]);
        assert!(provisions.is_empty());
        assert_eq!(provisions.len(), 0);

        let votes = ExecutionVoteBatch::new(vec![]);
        assert!(votes.is_empty());
        assert_eq!(votes.len(), 0);

        let certs = ExecutionCertificateBatch::new(vec![]);
        assert!(certs.is_empty());
        assert_eq!(certs.len(), 0);
    }

    #[test]
    fn test_state_provision_trace_context() {
        let provision = StateProvision {
            transaction_hash: Hash::from_bytes(b"tx"),
            target_shard: ShardGroupId(1),
            source_shard: ShardGroupId(0),
            block_height: BlockHeight(10),
            block_timestamp: 1000,
            entries: Arc::new(vec![]),
            validator_id: ValidatorId(0),
            signature: zero_bls_signature(),
        };

        // new() should have empty trace context
        let batch = StateProvisionBatch::single(provision.clone());
        assert!(!batch.trace_context().has_trace());

        // with_trace_context() without active span should also be empty
        let batch_with_ctx = StateProvisionBatch::with_trace_context(vec![provision]);
        assert!(!batch_with_ctx.trace_context().has_trace() || TraceContext::is_enabled());
    }

    #[test]
    fn test_execution_certificate_trace_context() {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);

        let cert = ExecutionCertificate {
            transaction_hash: Hash::from_bytes(b"tx"),
            shard_group_id: ShardGroupId(0),
            read_nodes: vec![],
            state_writes: vec![],
            writes_commitment: Hash::from_bytes(b"commitment"),
            success: true,
            aggregated_signature: zero_bls_signature(),
            signers,
            voting_power: 3,
        };

        // new() should have empty trace context
        let batch = ExecutionCertificateBatch::single(cert.clone());
        assert!(!batch.trace_context().has_trace());

        // with_trace_context() without active span should also be empty
        let batch_with_ctx = ExecutionCertificateBatch::with_trace_context(vec![cert]);
        assert!(!batch_with_ctx.trace_context().has_trace() || TraceContext::is_enabled());
    }
}
