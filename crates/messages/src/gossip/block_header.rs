//! BlockHeader gossip message.

use hyperscale_types::{
    BlockHeader, CommitmentProof, Hash, MessagePriority, NetworkMessage, ShardMessage,
    TransactionAbort, TransactionDefer,
};
use sbor::prelude::BasicSbor;
use std::collections::HashMap;

/// Gossips a block proposal (header only, not full block).
/// Validators construct the full Block locally from header + mempool transactions.
///
/// Transaction hashes are split into three priority sections:
/// 1. **retry_hashes**: Retry transactions (highest priority, critical for liveness)
/// 2. **priority_hashes**: Cross-shard transactions with commitment proofs
/// 3. **transaction_hashes**: All other transactions
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BlockHeaderGossip {
    /// The block header being gossiped
    pub header: BlockHeader,

    /// Retry transaction hashes (highest priority).
    ///
    /// These are transactions that were previously deferred due to cross-shard
    /// cycles and are being retried. Critical for liveness.
    pub retry_hashes: Vec<Hash>,

    /// Priority transaction hashes (cross-shard with commitment proofs).
    ///
    /// These are cross-shard transactions where other shards have already
    /// committed and are waiting for us.
    pub priority_hashes: Vec<Hash>,

    /// Other transaction hashes (normal priority).
    ///
    /// Fresh transactions with no special priority.
    pub transaction_hashes: Vec<Hash>,

    /// Transaction certificate hashes included in this block (finalized cross-shard transactions)
    /// (needed for non-proposers to assemble the block)
    ///
    /// These are the transaction hashes of TransactionCertificates that have been finalized
    /// and are being committed in this block.
    pub certificate_hashes: Vec<Hash>,

    /// Deferred transactions in this block (livelock prevention).
    ///
    /// These are transactions that lost a cross-shard cycle and are being deferred.
    /// Voters can validate these independently.
    pub deferred: Vec<TransactionDefer>,

    /// Aborted transactions in this block.
    ///
    /// These are transactions that timed out or exceeded retry limits.
    pub aborted: Vec<TransactionAbort>,

    /// Commitment proofs for priority transaction ordering.
    ///
    /// Maps transaction hash to its CommitmentProof. Transactions with proofs
    /// are ordered before transactions without proofs in the block.
    /// This makes the block self-contained for ordering validation.
    pub commitment_proofs: HashMap<Hash, CommitmentProof>,
}

impl BlockHeaderGossip {
    /// Create a new block header gossip message with all sections.
    pub fn new(
        header: BlockHeader,
        retry_hashes: Vec<Hash>,
        priority_hashes: Vec<Hash>,
        transaction_hashes: Vec<Hash>,
    ) -> Self {
        Self {
            header,
            retry_hashes,
            priority_hashes,
            transaction_hashes,
            certificate_hashes: vec![],
            deferred: vec![],
            aborted: vec![],
            commitment_proofs: HashMap::new(),
        }
    }

    /// Create a new block header gossip message with certificates.
    pub fn with_certificates(
        header: BlockHeader,
        retry_hashes: Vec<Hash>,
        priority_hashes: Vec<Hash>,
        transaction_hashes: Vec<Hash>,
        certificate_hashes: Vec<Hash>,
    ) -> Self {
        Self {
            header,
            retry_hashes,
            priority_hashes,
            transaction_hashes,
            certificate_hashes,
            deferred: vec![],
            aborted: vec![],
            commitment_proofs: HashMap::new(),
        }
    }

    /// Create a new block header gossip message with all fields.
    #[allow(clippy::too_many_arguments)]
    pub fn full(
        header: BlockHeader,
        retry_hashes: Vec<Hash>,
        priority_hashes: Vec<Hash>,
        transaction_hashes: Vec<Hash>,
        certificate_hashes: Vec<Hash>,
        deferred: Vec<TransactionDefer>,
        aborted: Vec<TransactionAbort>,
        commitment_proofs: HashMap<Hash, CommitmentProof>,
    ) -> Self {
        Self {
            header,
            retry_hashes,
            priority_hashes,
            transaction_hashes,
            certificate_hashes,
            deferred,
            aborted,
            commitment_proofs,
        }
    }

    /// Get the inner block header.
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// Get the retry transaction hashes.
    pub fn retry_hashes(&self) -> &[Hash] {
        &self.retry_hashes
    }

    /// Get the priority transaction hashes.
    pub fn priority_hashes(&self) -> &[Hash] {
        &self.priority_hashes
    }

    /// Get the other transaction hashes.
    pub fn transaction_hashes(&self) -> &[Hash] {
        &self.transaction_hashes
    }

    /// Get total transaction count across all sections.
    pub fn transaction_count(&self) -> usize {
        self.retry_hashes.len() + self.priority_hashes.len() + self.transaction_hashes.len()
    }

    /// Iterate all transaction hashes in priority order.
    pub fn all_transaction_hashes(&self) -> impl Iterator<Item = &Hash> {
        self.retry_hashes
            .iter()
            .chain(self.priority_hashes.iter())
            .chain(self.transaction_hashes.iter())
    }

    /// Get the certificate hashes.
    pub fn certificate_hashes(&self) -> &[Hash] {
        &self.certificate_hashes
    }

    /// Get the deferred transactions.
    pub fn deferred(&self) -> &[TransactionDefer] {
        &self.deferred
    }

    /// Get the aborted transactions.
    pub fn aborted(&self) -> &[TransactionAbort] {
        &self.aborted
    }

    /// Get the commitment proofs.
    pub fn commitment_proofs(&self) -> &HashMap<Hash, CommitmentProof> {
        &self.commitment_proofs
    }

    /// Consume and return the inner block header.
    pub fn into_header(self) -> BlockHeader {
        self.header
    }

    /// Consume and return all components.
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        BlockHeader,
        Vec<Hash>,
        Vec<Hash>,
        Vec<Hash>,
        Vec<Hash>,
        Vec<TransactionDefer>,
        Vec<TransactionAbort>,
        HashMap<Hash, CommitmentProof>,
    ) {
        (
            self.header,
            self.retry_hashes,
            self.priority_hashes,
            self.transaction_hashes,
            self.certificate_hashes,
            self.deferred,
            self.aborted,
            self.commitment_proofs,
        )
    }
}

// Network message implementation
impl NetworkMessage for BlockHeaderGossip {
    fn message_type_id() -> &'static str {
        "block.header"
    }

    fn priority() -> MessagePriority {
        MessagePriority::Critical
    }
}

impl ShardMessage for BlockHeaderGossip {}

#[cfg(test)]
mod tests {
    use hyperscale_types::{BlockHeight, QuorumCertificate, ValidatorId};

    use super::*;

    #[test]
    fn test_block_header_gossip_creation() {
        let header = BlockHeader {
            height: BlockHeight(1),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: 1234567890,
            round: 0,
            is_fallback: false,
        };
        let retry_hashes = vec![Hash::from_bytes(b"retry1")];
        let priority_hashes = vec![Hash::from_bytes(b"priority1")];
        let transaction_hashes = vec![Hash::from_bytes(b"tx1"), Hash::from_bytes(b"tx2")];

        let gossip = BlockHeaderGossip::new(
            header.clone(),
            retry_hashes.clone(),
            priority_hashes.clone(),
            transaction_hashes.clone(),
        );
        assert_eq!(gossip.header(), &header);
        assert_eq!(gossip.retry_hashes(), &retry_hashes[..]);
        assert_eq!(gossip.priority_hashes(), &priority_hashes[..]);
        assert_eq!(gossip.transaction_hashes(), &transaction_hashes[..]);
        assert_eq!(gossip.transaction_count(), 4);
    }

    #[test]
    fn test_block_header_gossip_into_header() {
        let header = BlockHeader {
            height: BlockHeight(5),
            parent_hash: Hash::from_bytes(b"block4"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(1),
            timestamp: 9876543210,
            round: 0,
            is_fallback: false,
        };
        let transaction_hashes = vec![Hash::from_bytes(b"tx1")];

        let gossip = BlockHeaderGossip::new(header.clone(), vec![], vec![], transaction_hashes);
        let extracted = gossip.into_header();
        assert_eq!(extracted, header);
    }

    #[test]
    fn test_block_header_gossip_all_transaction_hashes() {
        let header = BlockHeader {
            height: BlockHeight(1),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: 0,
            round: 0,
            is_fallback: false,
        };
        let retry = Hash::from_bytes(b"retry");
        let priority = Hash::from_bytes(b"priority");
        let other = Hash::from_bytes(b"other");

        let gossip = BlockHeaderGossip::new(header, vec![retry], vec![priority], vec![other]);

        let all: Vec<Hash> = gossip.all_transaction_hashes().copied().collect();
        assert_eq!(all, vec![retry, priority, other]);
    }
}
