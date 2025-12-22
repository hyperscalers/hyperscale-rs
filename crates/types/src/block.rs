//! Block and BlockHeader types for consensus.

use crate::{
    BlockHeight, CommitmentProof, Hash, QuorumCertificate, RoutableTransaction, TransactionAbort,
    TransactionCertificate, TransactionDefer, ValidatorId,
};
use sbor::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;

/// Block header containing consensus metadata.
///
/// The header is what validators vote on. It contains:
/// - Chain position (height, parent hash)
/// - Proposer identity
/// - Proof of parent commitment (parent QC)
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BlockHeader {
    /// Block height in the chain (genesis = 0).
    pub height: BlockHeight,

    /// Hash of parent block.
    pub parent_hash: Hash,

    /// Quorum certificate proving parent block was committed.
    pub parent_qc: QuorumCertificate,

    /// Validator that proposed this block.
    pub proposer: ValidatorId,

    /// Unix timestamp (milliseconds) when block was proposed.
    pub timestamp: u64,

    /// View/round number for view change protocol.
    pub round: u64,

    /// Whether this block was created as a fallback when leader timed out.
    pub is_fallback: bool,
}

impl BlockHeader {
    /// Compute hash of this block header.
    pub fn hash(&self) -> Hash {
        let bytes = basic_encode(self).expect("BlockHeader serialization should never fail");
        Hash::from_bytes(&bytes)
    }

    /// Check if this is the genesis block header.
    pub fn is_genesis(&self) -> bool {
        self.height.0 == 0
    }

    /// Get the expected proposer for this height (round-robin).
    pub fn expected_proposer(&self, num_validators: u64) -> ValidatorId {
        ValidatorId((self.height.0 + self.round) % num_validators)
    }
}

/// Complete block with header and transaction data.
///
/// Blocks can contain four types of transaction-related items:
/// 1. **transactions**: New transactions being committed for the first time
/// 2. **committed_certificates**: Finalized transaction certificates (Accept/Reject decisions)
/// 3. **deferred**: Transactions deferred due to cross-shard cycles (livelock prevention)
/// 4. **aborted**: Transactions aborted due to timeout or rejection
///
/// Transactions and certificates are stored as `Arc` for efficient cloning
/// and sharing across the system. When serialized (for storage or network),
/// the underlying data is written directly.
#[derive(Debug, Clone)]
pub struct Block {
    /// Block header with consensus metadata.
    pub header: BlockHeader,

    /// Transactions included in this block.
    pub transactions: Vec<Arc<RoutableTransaction>>,

    /// Transaction certificates for finalized transactions.
    pub committed_certificates: Vec<Arc<TransactionCertificate>>,

    /// Transactions deferred due to cross-shard livelock cycles.
    ///
    /// When cycle detection identifies a bidirectional cycle, the losing
    /// transaction (higher hash) is deferred. This releases its locks and
    /// queues it for retry after the winner completes.
    pub deferred: Vec<TransactionDefer>,

    /// Transactions aborted due to timeout or explicit rejection.
    ///
    /// Aborts are terminal - the transaction will not be retried. This is
    /// used for N-way cycles that cannot be resolved via simple deferral,
    /// or for transactions that explicitly failed during execution.
    pub aborted: Vec<TransactionAbort>,

    /// Commitment proofs for priority transaction ordering.
    ///
    /// Maps transaction hash to its CommitmentProof. Transactions with proofs
    /// are ordered before transactions without proofs in the block.
    ///
    /// This makes the block self-contained: validators can verify the ordering
    /// is correct without needing to have received the same provisions.
    pub commitment_proofs: HashMap<Hash, CommitmentProof>,
}

// Manual PartialEq - compare transaction/certificate content, not Arc pointers
impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header
            && self.transactions.len() == other.transactions.len()
            && self
                .transactions
                .iter()
                .zip(other.transactions.iter())
                .all(|(a, b)| a.hash() == b.hash())
            && self.committed_certificates.len() == other.committed_certificates.len()
            && self
                .committed_certificates
                .iter()
                .zip(other.committed_certificates.iter())
                .all(|(a, b)| a.as_ref() == b.as_ref())
            && self.deferred == other.deferred
            && self.aborted == other.aborted
            && self.commitment_proofs == other.commitment_proofs
    }
}

impl Eq for Block {}

// ============================================================================
// Manual SBOR implementation (since Arc doesn't derive BasicSbor)
// We serialize/deserialize the inner RoutableTransaction directly.
// ============================================================================

impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E> for Block {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(6)?;
        encoder.encode(&self.header)?;
        // Transactions (manual encoding to unwrap Arc)
        encoder.write_value_kind(sbor::ValueKind::Array)?;
        encoder.write_value_kind(sbor::ValueKind::Tuple)?;
        encoder.write_size(self.transactions.len())?;
        for tx in &self.transactions {
            encoder.encode_deeper_body(tx.as_ref())?;
        }
        // Certificates (manual encoding to unwrap Arc)
        encoder.write_value_kind(sbor::ValueKind::Array)?;
        encoder.write_value_kind(sbor::ValueKind::Tuple)?;
        encoder.write_size(self.committed_certificates.len())?;
        for cert in &self.committed_certificates {
            encoder.encode_deeper_body(cert.as_ref())?;
        }
        encoder.encode(&self.deferred)?;
        encoder.encode(&self.aborted)?;
        // Commitment proofs (HashMap<Hash, CommitmentProof>)
        // Encode as array of (key, value) pairs for determinism
        encoder.write_value_kind(sbor::ValueKind::Array)?;
        encoder.write_value_kind(sbor::ValueKind::Tuple)?;
        encoder.write_size(self.commitment_proofs.len())?;
        // Sort by hash for deterministic encoding
        let mut proofs: Vec<_> = self.commitment_proofs.iter().collect();
        proofs.sort_by_key(|(k, _)| *k);
        for (tx_hash, proof) in proofs {
            encoder.encode(tx_hash)?;
            encoder.encode(proof)?;
        }
        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D> for Block {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;

        if length != 6 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 6,
                actual: length,
            });
        }

        let header: BlockHeader = decoder.decode()?;

        // Transactions (manual decoding to wrap in Arc)
        decoder.read_and_check_value_kind(sbor::ValueKind::Array)?;
        decoder.read_and_check_value_kind(sbor::ValueKind::Tuple)?;
        let tx_count = decoder.read_size()?;
        let mut transactions = Vec::with_capacity(tx_count);
        for _ in 0..tx_count {
            let tx: RoutableTransaction =
                decoder.decode_deeper_body_with_value_kind(sbor::ValueKind::Tuple)?;
            transactions.push(Arc::new(tx));
        }

        // Certificates (manual decoding to wrap in Arc)
        decoder.read_and_check_value_kind(sbor::ValueKind::Array)?;
        decoder.read_and_check_value_kind(sbor::ValueKind::Tuple)?;
        let cert_count = decoder.read_size()?;
        let mut committed_certificates = Vec::with_capacity(cert_count);
        for _ in 0..cert_count {
            let cert: TransactionCertificate =
                decoder.decode_deeper_body_with_value_kind(sbor::ValueKind::Tuple)?;
            committed_certificates.push(Arc::new(cert));
        }

        let deferred: Vec<TransactionDefer> = decoder.decode()?;
        let aborted: Vec<TransactionAbort> = decoder.decode()?;

        // Commitment proofs (array of (Hash, CommitmentProof) pairs)
        decoder.read_and_check_value_kind(sbor::ValueKind::Array)?;
        decoder.read_and_check_value_kind(sbor::ValueKind::Tuple)?;
        let proof_count = decoder.read_size()?;
        let mut commitment_proofs = HashMap::with_capacity(proof_count);
        for _ in 0..proof_count {
            let tx_hash: Hash = decoder.decode()?;
            let proof: CommitmentProof = decoder.decode()?;
            commitment_proofs.insert(tx_hash, proof);
        }

        Ok(Self {
            header,
            transactions,
            committed_certificates,
            deferred,
            aborted,
            commitment_proofs,
        })
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for Block {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for Block {
    const TYPE_ID: sbor::RustTypeId = sbor::RustTypeId::novel_with_code("Block", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

impl Block {
    /// Compute hash of this block (hashes the header).
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// Get block height.
    pub fn height(&self) -> BlockHeight {
        self.header.height
    }

    /// Get number of transactions in this block.
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Check if this block contains a specific transaction by hash.
    pub fn contains_transaction(&self, tx_hash: &Hash) -> bool {
        self.transactions.iter().any(|tx| tx.hash() == *tx_hash)
    }

    /// Get transaction hashes for gossip messages.
    pub fn transaction_hashes(&self) -> Vec<Hash> {
        self.transactions.iter().map(|tx| tx.hash()).collect()
    }

    /// Check if this is the genesis block.
    pub fn is_genesis(&self) -> bool {
        self.header.is_genesis()
    }

    /// Create a genesis block.
    pub fn genesis(genesis_qc: QuorumCertificate) -> Self {
        Self {
            header: BlockHeader {
                height: BlockHeight(0),
                parent_hash: Hash::ZERO,
                parent_qc: genesis_qc,
                proposer: ValidatorId(0),
                timestamp: 0,
                round: 0,
                is_fallback: false,
            },
            transactions: vec![],
            committed_certificates: vec![],
            deferred: vec![],
            aborted: vec![],
            commitment_proofs: HashMap::new(),
        }
    }

    /// Check if a transaction has a commitment proof in this block.
    pub fn has_commitment_proof(&self, tx_hash: &Hash) -> bool {
        self.commitment_proofs.contains_key(tx_hash)
    }

    /// Get the commitment proof for a transaction, if present.
    pub fn get_commitment_proof(&self, tx_hash: &Hash) -> Option<&CommitmentProof> {
        self.commitment_proofs.get(tx_hash)
    }

    /// Get number of committed certificates in this block.
    pub fn certificate_count(&self) -> usize {
        self.committed_certificates.len()
    }

    /// Get transaction hashes from committed certificates.
    pub fn committed_transaction_hashes(&self) -> Vec<Hash> {
        self.committed_certificates
            .iter()
            .map(|cert| cert.transaction_hash)
            .collect()
    }

    /// Check if this block contains a certificate for a specific transaction.
    pub fn contains_certificate(&self, tx_hash: &Hash) -> bool {
        self.committed_certificates
            .iter()
            .any(|cert| &cert.transaction_hash == tx_hash)
    }

    /// Get number of deferred transactions in this block.
    pub fn deferred_count(&self) -> usize {
        self.deferred.len()
    }

    /// Get transaction hashes of deferred transactions.
    pub fn deferred_transaction_hashes(&self) -> Vec<Hash> {
        self.deferred.iter().map(|d| d.tx_hash).collect()
    }

    /// Check if this block contains a deferral for a specific transaction.
    pub fn contains_deferral(&self, tx_hash: &Hash) -> bool {
        self.deferred.iter().any(|d| &d.tx_hash == tx_hash)
    }

    /// Get number of aborted transactions in this block.
    pub fn aborted_count(&self) -> usize {
        self.aborted.len()
    }

    /// Get transaction hashes of aborted transactions.
    pub fn aborted_transaction_hashes(&self) -> Vec<Hash> {
        self.aborted.iter().map(|a| a.tx_hash).collect()
    }

    /// Check if this block contains an abort for a specific transaction.
    pub fn contains_abort(&self, tx_hash: &Hash) -> bool {
        self.aborted.iter().any(|a| &a.tx_hash == tx_hash)
    }

    /// Check if this block has any livelock-related content.
    pub fn has_livelock_content(&self) -> bool {
        !self.deferred.is_empty() || !self.aborted.is_empty()
    }
}

// ============================================================================
// BlockMetadata - Denormalized storage format
// ============================================================================

/// Denormalized block metadata for efficient storage.
///
/// Unlike `Block`, this stores only hashes for transactions and certificates,
/// which are stored separately in their own column families. This eliminates
/// duplication and enables direct lookups.
///
/// # Storage Layout
///
/// - `"blocks"` CF: `BlockMetadata` (this struct) keyed by height
/// - `"transactions"` CF: `RoutableTransaction` keyed by tx_hash
/// - `"certificates"` CF: `TransactionCertificate` keyed by tx_hash
///
/// To reconstruct a full `Block`, fetch the metadata, then batch-fetch
/// transactions and certificates using the stored hashes.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BlockMetadata {
    /// Block header (contains height, parent hash, proposer, etc.)
    pub header: BlockHeader,

    /// Transaction hashes in block order.
    /// Actual transactions stored in "transactions" CF.
    pub tx_hashes: Vec<Hash>,

    /// Certificate hashes in block order.
    /// Actual certificates stored in "certificates" CF.
    pub cert_hashes: Vec<Hash>,

    /// Deferred transactions (small, stored inline).
    pub deferred: Vec<TransactionDefer>,

    /// Aborted transactions (small, stored inline).
    pub aborted: Vec<TransactionAbort>,

    /// Commitment proofs for priority ordering (stored inline).
    pub commitment_proofs: HashMap<Hash, CommitmentProof>,

    /// Quorum certificate that commits this block.
    pub qc: QuorumCertificate,
}

impl BlockMetadata {
    /// Create metadata from a full block and QC.
    pub fn from_block(block: &Block, qc: QuorumCertificate) -> Self {
        Self {
            header: block.header.clone(),
            tx_hashes: block.transactions.iter().map(|tx| tx.hash()).collect(),
            cert_hashes: block
                .committed_certificates
                .iter()
                .map(|c| c.transaction_hash)
                .collect(),
            deferred: block.deferred.clone(),
            aborted: block.aborted.clone(),
            commitment_proofs: block.commitment_proofs.clone(),
            qc,
        }
    }

    /// Get block height.
    pub fn height(&self) -> BlockHeight {
        self.header.height
    }

    /// Compute hash of this block (hashes the header).
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_header_hash_deterministic() {
        let header = BlockHeader {
            height: BlockHeight(1),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: 1234567890,
            round: 0,
            is_fallback: false,
        };

        let hash1 = header.hash();
        let hash2 = header.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_genesis_block() {
        let genesis_qc = QuorumCertificate::genesis();
        let genesis = Block::genesis(genesis_qc);

        assert!(genesis.is_genesis());
        assert_eq!(genesis.height(), BlockHeight(0));
        assert_eq!(genesis.transaction_count(), 0);
    }
}
