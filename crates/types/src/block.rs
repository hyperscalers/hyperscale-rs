//! Block and BlockHeader types for consensus.

use crate::{
    compute_merkle_root, BlockHeight, CommitmentProof, Hash, QuorumCertificate,
    RoutableTransaction, TransactionAbort, TransactionCertificate, TransactionDefer, ValidatorId,
};
use sbor::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;

/// Tag prefixes for transaction slot provability in merkle tree.
/// Each transaction's leaf hash is `hash(TAG || tx_hash)`, allowing
/// merkle proofs to prove both inclusion AND which slot the tx belongs to.
const RETRY_TAG: &[u8] = b"RETRY";
const PRIORITY_TAG: &[u8] = b"PRIORITY";
const NORMAL_TAG: &[u8] = b"NORMAL";

/// Compute the transaction merkle root for a block.
///
/// Transactions are organized into three sections with tagged leaf hashes:
/// - Retry transactions: `hash(RETRY || tx_hash)`
/// - Priority transactions: `hash(PRIORITY || tx_hash)`
/// - Normal transactions: `hash(NORMAL || tx_hash)`
///
/// The root is computed over the concatenation of all tagged hashes in order.
/// Returns `Hash::ZERO` if all sections are empty.
pub fn compute_transaction_root(
    retry_transactions: &[Arc<RoutableTransaction>],
    priority_transactions: &[Arc<RoutableTransaction>],
    transactions: &[Arc<RoutableTransaction>],
) -> Hash {
    let total_count = retry_transactions.len() + priority_transactions.len() + transactions.len();

    if total_count == 0 {
        return Hash::ZERO;
    }

    let mut leaves = Vec::with_capacity(total_count);

    // Add retry transaction leaves
    for tx in retry_transactions {
        leaves.push(Hash::from_parts(&[RETRY_TAG, tx.hash().as_bytes()]));
    }

    // Add priority transaction leaves
    for tx in priority_transactions {
        leaves.push(Hash::from_parts(&[PRIORITY_TAG, tx.hash().as_bytes()]));
    }

    // Add normal transaction leaves
    for tx in transactions {
        leaves.push(Hash::from_parts(&[NORMAL_TAG, tx.hash().as_bytes()]));
    }

    compute_merkle_root(&leaves)
}

/// Block header containing consensus metadata.
///
/// The header is what validators vote on. It contains:
/// - Chain position (height, parent hash)
/// - Proposer identity
/// - Proof of parent commitment (parent QC)
/// - State commitment (JMT root after applying committed certificates)
/// - Transaction commitment (merkle root of all transactions in the block)
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

    /// JMT state root hash after applying all certificates in this block.
    pub state_root: Hash,

    /// JMT version corresponding to state_root. Increments by 1 per certificate with state writes.
    pub state_version: u64,

    /// Merkle root of all transactions in this block.
    ///
    /// Computed over tagged transaction hashes from all three sections in order:
    /// `[RETRY || hash, ...] ++ [PRIORITY || hash, ...] ++ [NORMAL || hash, ...]`
    ///
    /// This enables:
    /// - Proving a transaction is in the block (merkle inclusion proof)
    /// - Proving which slot a transaction belongs to (via tag prefix)
    /// - Proving transaction ordering (via merkle path position)
    ///
    /// For empty blocks (fallback, sync), this is `Hash::ZERO`.
    pub transaction_root: Hash,
}

impl BlockHeader {
    /// Create a genesis block header (height 0) with the given proposer and JMT state.
    pub fn genesis(proposer: ValidatorId, state_root: Hash, state_version: u64) -> Self {
        Self {
            height: BlockHeight(0),
            parent_hash: Hash::from_bytes(&[0u8; 32]),
            parent_qc: QuorumCertificate::genesis(),
            proposer,
            timestamp: 0,
            round: 0,
            is_fallback: false,
            state_root,
            state_version,
            transaction_root: Hash::ZERO,
        }
    }

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
/// Blocks contain transactions in three priority sections:
/// 1. **retry_transactions**: Retry transactions (highest priority, critical for liveness)
/// 2. **priority_transactions**: Cross-shard transactions with commitment proofs
/// 3. **transactions**: All other transactions
///
/// Additional block contents:
/// - **certificates**: Finalized transaction certificates (Accept/Reject decisions)
/// - **deferred**: Transactions deferred due to cross-shard cycles (livelock prevention)
/// - **aborted**: Transactions aborted due to timeout or rejection
///
/// Each section is sorted by transaction hash for deterministic ordering.
/// Transactions and certificates are stored as `Arc` for efficient cloning
/// and sharing across the system. When serialized (for storage or network),
/// the underlying data is written directly.
#[derive(Debug, Clone)]
pub struct Block {
    /// Block header with consensus metadata.
    pub header: BlockHeader,

    /// Retry transactions (highest priority).
    ///
    /// These are transactions that were previously deferred due to cross-shard
    /// cycles and are being retried. They bypass backpressure limits because
    /// completing them is critical for liveness.
    pub retry_transactions: Vec<Arc<RoutableTransaction>>,

    /// Priority transactions (cross-shard with commitment proofs).
    ///
    /// These are cross-shard transactions where other shards have already
    /// committed and are waiting for us. They bypass soft backpressure limits.
    pub priority_transactions: Vec<Arc<RoutableTransaction>>,

    /// Other transactions (normal priority).
    ///
    /// Fresh transactions with no special priority. Subject to backpressure limits.
    pub transactions: Vec<Arc<RoutableTransaction>>,

    /// Transaction certificates for finalized transactions.
    pub certificates: Vec<Arc<TransactionCertificate>>,

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
    /// Maps transaction hash to its CommitmentProof. These proofs justify
    /// why transactions are in the priority section.
    pub commitment_proofs: HashMap<Hash, CommitmentProof>,
}

// Manual PartialEq - compare transaction/certificate content, not Arc pointers
impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        fn tx_lists_equal(a: &[Arc<RoutableTransaction>], b: &[Arc<RoutableTransaction>]) -> bool {
            a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.hash() == y.hash())
        }

        self.header == other.header
            && tx_lists_equal(&self.retry_transactions, &other.retry_transactions)
            && tx_lists_equal(&self.priority_transactions, &other.priority_transactions)
            && tx_lists_equal(&self.transactions, &other.transactions)
            && self.certificates.len() == other.certificates.len()
            && self
                .certificates
                .iter()
                .zip(other.certificates.iter())
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

/// Helper to encode a Vec<Arc<RoutableTransaction>> as an SBOR array.
fn encode_tx_vec<E: sbor::Encoder<sbor::NoCustomValueKind>>(
    encoder: &mut E,
    txs: &[Arc<RoutableTransaction>],
) -> Result<(), sbor::EncodeError> {
    encoder.write_value_kind(sbor::ValueKind::Array)?;
    encoder.write_value_kind(sbor::ValueKind::Tuple)?;
    encoder.write_size(txs.len())?;
    for tx in txs {
        encoder.encode_deeper_body(tx.as_ref())?;
    }
    Ok(())
}

impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E> for Block {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(8)?;
        encoder.encode(&self.header)?;
        // Retry transactions
        encode_tx_vec(encoder, &self.retry_transactions)?;
        // Priority transactions
        encode_tx_vec(encoder, &self.priority_transactions)?;
        // Other transactions
        encode_tx_vec(encoder, &self.transactions)?;
        // Certificates (manual encoding to unwrap Arc)
        encoder.write_value_kind(sbor::ValueKind::Array)?;
        encoder.write_value_kind(sbor::ValueKind::Tuple)?;
        encoder.write_size(self.certificates.len())?;
        for cert in &self.certificates {
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

/// Helper to decode a Vec<Arc<RoutableTransaction>> from an SBOR array.
fn decode_tx_vec<D: sbor::Decoder<sbor::NoCustomValueKind>>(
    decoder: &mut D,
) -> Result<Vec<Arc<RoutableTransaction>>, sbor::DecodeError> {
    decoder.read_and_check_value_kind(sbor::ValueKind::Array)?;
    decoder.read_and_check_value_kind(sbor::ValueKind::Tuple)?;
    let count = decoder.read_size()?;
    let mut txs = Vec::with_capacity(count);
    for _ in 0..count {
        let tx: RoutableTransaction =
            decoder.decode_deeper_body_with_value_kind(sbor::ValueKind::Tuple)?;
        txs.push(Arc::new(tx));
    }
    Ok(txs)
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D> for Block {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;

        if length != 8 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 8,
                actual: length,
            });
        }

        let header: BlockHeader = decoder.decode()?;

        // Transaction sections
        let retry_transactions = decode_tx_vec(decoder)?;
        let priority_transactions = decode_tx_vec(decoder)?;
        let transactions = decode_tx_vec(decoder)?;

        // Certificates (manual decoding to wrap in Arc)
        decoder.read_and_check_value_kind(sbor::ValueKind::Array)?;
        decoder.read_and_check_value_kind(sbor::ValueKind::Tuple)?;
        let cert_count = decoder.read_size()?;
        let mut certificates = Vec::with_capacity(cert_count);
        for _ in 0..cert_count {
            let cert: TransactionCertificate =
                decoder.decode_deeper_body_with_value_kind(sbor::ValueKind::Tuple)?;
            certificates.push(Arc::new(cert));
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
            retry_transactions,
            priority_transactions,
            transactions,
            certificates,
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
    /// Create an empty genesis block with the given proposer and JMT state.
    pub fn genesis(proposer: ValidatorId, state_root: Hash, state_version: u64) -> Self {
        Self {
            header: BlockHeader::genesis(proposer, state_root, state_version),
            retry_transactions: vec![],
            priority_transactions: vec![],
            transactions: vec![],
            certificates: vec![],
            deferred: vec![],
            aborted: vec![],
            commitment_proofs: HashMap::new(),
        }
    }

    /// Compute hash of this block (hashes the header).
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// Get block height.
    pub fn height(&self) -> BlockHeight {
        self.header.height
    }

    /// Get total number of transactions across all sections.
    pub fn transaction_count(&self) -> usize {
        self.retry_transactions.len() + self.priority_transactions.len() + self.transactions.len()
    }

    /// Iterate all transactions in priority order (retries, priority, others).
    pub fn all_transactions(&self) -> impl Iterator<Item = &Arc<RoutableTransaction>> {
        self.retry_transactions
            .iter()
            .chain(self.priority_transactions.iter())
            .chain(self.transactions.iter())
    }

    /// Check if this block contains a specific transaction by hash.
    pub fn contains_transaction(&self, tx_hash: &Hash) -> bool {
        self.all_transactions().any(|tx| tx.hash() == *tx_hash)
    }

    /// Get all transaction hashes in priority order.
    pub fn all_transaction_hashes(&self) -> Vec<Hash> {
        self.all_transactions().map(|tx| tx.hash()).collect()
    }

    /// Get retry transaction hashes.
    pub fn retry_hashes(&self) -> Vec<Hash> {
        self.retry_transactions.iter().map(|tx| tx.hash()).collect()
    }

    /// Get priority transaction hashes.
    pub fn priority_hashes(&self) -> Vec<Hash> {
        self.priority_transactions
            .iter()
            .map(|tx| tx.hash())
            .collect()
    }

    /// Get other transaction hashes.
    pub fn transaction_hashes(&self) -> Vec<Hash> {
        self.transactions.iter().map(|tx| tx.hash()).collect()
    }

    /// Check if this is the genesis block.
    pub fn is_genesis(&self) -> bool {
        self.header.is_genesis()
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
        self.certificates.len()
    }

    /// Get transaction hashes from committed certificates.
    pub fn committed_transaction_hashes(&self) -> Vec<Hash> {
        self.certificates
            .iter()
            .map(|cert| cert.transaction_hash)
            .collect()
    }

    /// Check if this block contains a certificate for a specific transaction.
    pub fn contains_certificate(&self, tx_hash: &Hash) -> bool {
        self.certificates
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

    /// Retry transaction hashes (highest priority section).
    pub retry_hashes: Vec<Hash>,

    /// Priority transaction hashes (cross-shard with proofs).
    pub priority_hashes: Vec<Hash>,

    /// Other transaction hashes (normal priority section).
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
            retry_hashes: block
                .retry_transactions
                .iter()
                .map(|tx| tx.hash())
                .collect(),
            priority_hashes: block
                .priority_transactions
                .iter()
                .map(|tx| tx.hash())
                .collect(),
            tx_hashes: block.transactions.iter().map(|tx| tx.hash()).collect(),
            cert_hashes: block
                .certificates
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

    /// Get total transaction count across all sections.
    pub fn transaction_count(&self) -> usize {
        self.retry_hashes.len() + self.priority_hashes.len() + self.tx_hashes.len()
    }

    /// Iterate all transaction hashes in priority order.
    pub fn all_tx_hashes(&self) -> impl Iterator<Item = &Hash> {
        self.retry_hashes
            .iter()
            .chain(self.priority_hashes.iter())
            .chain(self.tx_hashes.iter())
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
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };

        let hash1 = header.hash();
        let hash2 = header.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_genesis_block() {
        let genesis = Block::genesis(ValidatorId(0), Hash::ZERO, 0);

        assert!(genesis.is_genesis());
        assert_eq!(genesis.height(), BlockHeight(0));
        assert_eq!(genesis.transaction_count(), 0);
        assert_eq!(genesis.header.transaction_root, Hash::ZERO);
        assert_eq!(genesis.header.parent_qc, QuorumCertificate::genesis());
    }

    #[test]
    fn test_compute_transaction_root_empty() {
        let root = compute_transaction_root(&[], &[], &[]);
        assert_eq!(root, Hash::ZERO);
    }

    #[test]
    fn test_compute_transaction_root_deterministic() {
        use radix_common::network::NetworkDefinition;
        use radix_transactions::builder::ManifestBuilder;

        // Create a simple transaction for testing
        let manifest = ManifestBuilder::new().drop_all_proofs().build();
        let network = NetworkDefinition::simulator();
        let key = crate::generate_ed25519_keypair();
        let notarized = crate::sign_and_notarize(manifest, &network, 1, &key).unwrap();
        let tx = Arc::new(RoutableTransaction::try_from(notarized).unwrap());

        let root1 = compute_transaction_root(&[], &[], &[tx.clone()]);
        let root2 = compute_transaction_root(&[], &[], &[tx.clone()]);
        assert_eq!(root1, root2);
        assert_ne!(root1, Hash::ZERO);
    }

    #[test]
    fn test_compute_transaction_root_slot_affects_hash() {
        use radix_common::network::NetworkDefinition;
        use radix_transactions::builder::ManifestBuilder;

        // Create a transaction
        let manifest = ManifestBuilder::new().drop_all_proofs().build();
        let network = NetworkDefinition::simulator();
        let key = crate::generate_ed25519_keypair();
        let notarized = crate::sign_and_notarize(manifest, &network, 1, &key).unwrap();
        let tx = Arc::new(RoutableTransaction::try_from(notarized).unwrap());

        // Same tx in different slots should produce different roots
        let root_retry = compute_transaction_root(&[tx.clone()], &[], &[]);
        let root_priority = compute_transaction_root(&[], &[tx.clone()], &[]);
        let root_normal = compute_transaction_root(&[], &[], &[tx.clone()]);

        assert_ne!(root_retry, root_priority);
        assert_ne!(root_priority, root_normal);
        assert_ne!(root_retry, root_normal);
    }
}
