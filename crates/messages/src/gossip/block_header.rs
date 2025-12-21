//! BlockHeader gossip message.

use hyperscale_types::{
    BlockHeader, CommitmentProof, Hash, NetworkMessage, ShardMessage, TransactionAbort,
    TransactionDefer,
};
use sbor::prelude::BasicSbor;
use std::collections::HashMap;

/// Gossips a block proposal (header only, not full block).
/// Validators construct the full Block locally from header + mempool transactions.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BlockHeaderGossip {
    /// The block header being gossiped
    pub header: BlockHeader,

    /// Transaction hashes included in this block
    /// (needed for non-proposers to assemble the block)
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
    /// Create a new block header gossip message (no certificates, deferrals, or aborts).
    pub fn new(header: BlockHeader, transaction_hashes: Vec<Hash>) -> Self {
        Self {
            header,
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
        transaction_hashes: Vec<Hash>,
        certificate_hashes: Vec<Hash>,
    ) -> Self {
        Self {
            header,
            transaction_hashes,
            certificate_hashes,
            deferred: vec![],
            aborted: vec![],
            commitment_proofs: HashMap::new(),
        }
    }

    /// Create a new block header gossip message with all fields.
    pub fn full(
        header: BlockHeader,
        transaction_hashes: Vec<Hash>,
        certificate_hashes: Vec<Hash>,
        deferred: Vec<TransactionDefer>,
        aborted: Vec<TransactionAbort>,
        commitment_proofs: HashMap<Hash, CommitmentProof>,
    ) -> Self {
        Self {
            header,
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

    /// Get the transaction hashes.
    pub fn transaction_hashes(&self) -> &[Hash] {
        &self.transaction_hashes
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
        Vec<TransactionDefer>,
        Vec<TransactionAbort>,
        HashMap<Hash, CommitmentProof>,
    ) {
        (
            self.header,
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
        let transaction_hashes = vec![Hash::from_bytes(b"atom1"), Hash::from_bytes(b"atom2")];

        let gossip = BlockHeaderGossip::new(header.clone(), transaction_hashes.clone());
        assert_eq!(gossip.header(), &header);
        assert_eq!(gossip.transaction_hashes(), &transaction_hashes[..]);
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
        let transaction_hashes = vec![Hash::from_bytes(b"atom1")];

        let gossip = BlockHeaderGossip::new(header.clone(), transaction_hashes);
        let extracted = gossip.into_header();
        assert_eq!(extracted, header);
    }
}
