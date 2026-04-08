//! Block and BlockHeader types for consensus.

use crate::{
    compute_merkle_root, compute_merkle_root_with_proof, compute_padded_merkle_root,
    decode_wave_cert_vec, encode_wave_cert_vec, AbortIntent, BlockHeight, Hash, QuorumCertificate,
    RoutableTransaction, ShardGroupId, TransactionInclusionProof, ValidatorId, WaveCertificate,
    WaveId,
};
use sbor::prelude::*;
use std::sync::Arc;

/// Compute the receipt merkle root for a block's wave certificates.
///
/// Each wave certificate's `receipt_hash` becomes a leaf.
/// Returns `Hash::ZERO` if there are no certificates.
pub fn compute_certificate_root(certificates: &[Arc<WaveCertificate>]) -> Hash {
    if certificates.is_empty() {
        return Hash::ZERO;
    }

    let leaves: Vec<Hash> = certificates.iter().map(|c| c.receipt_hash()).collect();
    compute_merkle_root(&leaves)
}

/// Compute the transaction merkle root for a block.
///
/// Each transaction's hash becomes a leaf directly. Returns `Hash::ZERO` if empty.
pub fn compute_transaction_root(transactions: &[Arc<RoutableTransaction>]) -> Hash {
    if transactions.is_empty() {
        return Hash::ZERO;
    }

    let leaves: Vec<Hash> = transactions.iter().map(|tx| tx.hash()).collect();

    // Use padded merkle root (power-of-2 padding with Hash::ZERO) so that
    // merkle inclusion proofs can be generated and verified for any leaf.
    compute_padded_merkle_root(&leaves)
}

/// Compute a transaction inclusion proof for a specific transaction in a block.
///
/// Reconstructs the leaf list in the same order as `compute_transaction_root`,
/// finds the leaf matching `tx_hash`, and returns a merkle inclusion proof.
///
/// Returns `None` if the transaction is not in the block.
pub fn tx_inclusion_proof(block: &Block, tx_hash: &Hash) -> Option<TransactionInclusionProof> {
    if block.transactions.is_empty() {
        return None;
    }

    let leaves: Vec<Hash> = block.transactions.iter().map(|tx| tx.hash()).collect();

    let index = leaves.iter().position(|leaf| leaf == tx_hash)?;

    let (_root, proof) = compute_merkle_root_with_proof(&leaves, index);
    Some(proof)
}

/// Batch version of [`tx_inclusion_proof`] — generates proofs for multiple
/// transactions from the same block, building the leaf list only once.
pub fn tx_inclusion_proofs(
    block: &Block,
    tx_hashes: &[Hash],
) -> Vec<(Hash, Option<TransactionInclusionProof>)> {
    if block.transactions.is_empty() {
        return tx_hashes.iter().map(|h| (*h, None)).collect();
    }

    let leaves: Vec<Hash> = block.transactions.iter().map(|tx| tx.hash()).collect();

    tx_hashes
        .iter()
        .map(|tx_hash| {
            let index = leaves.iter().position(|leaf| leaf == tx_hash);

            match index {
                Some(idx) => {
                    let (_root, proof) = compute_merkle_root_with_proof(&leaves, idx);
                    (*tx_hash, Some(proof))
                }
                None => (*tx_hash, None),
            }
        })
        .collect()
}

/// Block header containing consensus metadata.
///
/// The header is what validators vote on. It contains:
/// - Chain position (height, parent hash)
/// - Proposer identity
/// - Proof of parent commitment (parent QC)
/// - State commitment (JVT root after applying committed certificates)
/// - Transaction commitment (merkle root of all transactions in the block)
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BlockHeader {
    /// Shard group this block belongs to.
    ///
    /// Makes headers self-describing for cross-shard verification. A remote shard
    /// needs to know which shard's committee to verify the QC against.
    pub shard_group_id: ShardGroupId,

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

    /// JVT state root hash after applying all certificates in this block.
    pub state_root: Hash,

    /// Merkle root of all transactions in this block.
    ///
    /// Each transaction's hash is a leaf in a padded binary merkle tree.
    /// For empty blocks (fallback, sync), this is `Hash::ZERO`.
    pub transaction_root: Hash,

    /// Merkle root of all certificate receipt hashes in this block.
    ///
    /// Each certificate's `receipt_hash` (hash of outcome + event_root) is a leaf
    /// in a binary merkle tree. This enables light-client proof of "did transaction
    /// X succeed/fail in block N?" without replaying the block.
    ///
    /// For empty blocks (genesis, fallback, no certificates), this is `Hash::ZERO`.
    pub certificate_root: Hash,

    /// Merkle root of per-tx `LocalReceipt` hashes for all transactions
    /// covered by this block's wave certificates.
    ///
    /// Commits to the specific per-tx state deltas (shard-filtered DatabaseUpdates)
    /// that were applied to produce `state_root`. Enables per-tx delta attribution
    /// and receipt integrity verification by sync nodes.
    ///
    /// For empty blocks (genesis, fallback, no certificates), this is `Hash::ZERO`.
    pub local_receipt_root: Hash,

    /// Cross-shard execution waves in this block.
    ///
    /// Each `WaveId` is the set of remote shards that a group of transactions
    /// depends on for provisions. Transactions with identical remote shard sets
    /// share a wave. Wave-zero (single-shard txs) is excluded.
    ///
    /// This is QC-attested (covered by the block hash), so a byzantine proposer
    /// cannot forge it without the block being rejected by honest validators.
    ///
    /// Used by remote shards to:
    /// 1. Detect missing provisions (derive provision targets from wave union)
    /// 2. Detect missing execution certificates (know which certs to expect)
    /// 3. Assign wave leaders per wave
    ///
    /// Empty for genesis, fallback, and sync blocks (no transactions).
    pub waves: Vec<WaveId>,
}

impl BlockHeader {
    /// Create a genesis block header (height 0) with the given proposer and JVT state.
    pub fn genesis(shard_group_id: ShardGroupId, proposer: ValidatorId, state_root: Hash) -> Self {
        Self {
            shard_group_id,
            height: BlockHeight(0),
            parent_hash: Hash::from_bytes(&[0u8; 32]),
            parent_qc: QuorumCertificate::genesis(),
            proposer,
            timestamp: 0,
            round: 0,
            is_fallback: false,
            state_root,
            transaction_root: Hash::ZERO,
            certificate_root: Hash::ZERO,
            local_receipt_root: Hash::ZERO,
            waves: vec![],
        }
    }

    /// Derive provision targets from waves (union of all shards across all waves).
    ///
    /// Returns the sorted set of all remote shards that need provisions from this block.
    pub fn provision_targets(&self) -> Vec<ShardGroupId> {
        let mut set = std::collections::BTreeSet::new();
        for wave in &self.waves {
            set.extend(wave.remote_shards.iter().copied());
        }
        set.into_iter().collect()
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
/// Transactions are stored in a single flat list, sorted by hash for deterministic ordering.
///
/// Additional block contents:
/// - **certificates**: Wave certificates (per-wave finalization proofs)
/// - **abort_intents**: Proposals to abort transactions (timeout, livelock cycle)
///
/// Transactions and certificates are stored as `Arc` for efficient cloning
/// and sharing across the system. When serialized (for storage or network),
/// the underlying data is written directly.
#[derive(Debug, Clone)]
pub struct Block {
    /// Block header with consensus metadata.
    pub header: BlockHeader,

    /// All transactions in this block, sorted by hash.
    pub transactions: Vec<Arc<RoutableTransaction>>,

    /// Wave certificates for finalized waves.
    pub certificates: Vec<Arc<WaveCertificate>>,

    /// Abort intents — proposals to the execution voting process.
    pub abort_intents: Vec<AbortIntent>,
}

// Manual PartialEq - compare transaction/certificate content, not Arc pointers
impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        fn tx_lists_equal(a: &[Arc<RoutableTransaction>], b: &[Arc<RoutableTransaction>]) -> bool {
            a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.hash() == y.hash())
        }

        self.header == other.header
            && tx_lists_equal(&self.transactions, &other.transactions)
            && self.certificates.len() == other.certificates.len()
            && self
                .certificates
                .iter()
                .zip(other.certificates.iter())
                .all(|(a, b)| a.as_ref() == b.as_ref())
            && self.abort_intents == other.abort_intents
    }
}

impl Eq for Block {}

// ============================================================================
// Manual SBOR implementation (since Arc doesn't derive BasicSbor)
// We serialize/deserialize the inner types directly.
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
        encoder.write_size(4)?;
        encoder.encode(&self.header)?;
        encode_tx_vec(encoder, &self.transactions)?;
        encode_wave_cert_vec(encoder, &self.certificates)?;
        encoder.encode(&self.abort_intents)?;
        Ok(())
    }
}

/// Maximum items in a single collection during SBOR decoding.
///
/// Prevents allocation bombs where a crafted SBOR payload claims millions of
/// items, causing multi-GB `Vec::with_capacity()` pre-allocations. This limit
/// is generous enough for any legitimate block content while blocking malicious
/// payloads. Applied to transaction arrays, certificate arrays, and commitment
/// proof maps.
const MAX_SBOR_COLLECTION_SIZE: usize = 10_000;

/// Helper to decode a Vec<Arc<RoutableTransaction>> from an SBOR array.
fn decode_tx_vec<D: sbor::Decoder<sbor::NoCustomValueKind>>(
    decoder: &mut D,
) -> Result<Vec<Arc<RoutableTransaction>>, sbor::DecodeError> {
    decoder.read_and_check_value_kind(sbor::ValueKind::Array)?;
    decoder.read_and_check_value_kind(sbor::ValueKind::Tuple)?;
    let count = decoder.read_size()?;
    if count > MAX_SBOR_COLLECTION_SIZE {
        return Err(sbor::DecodeError::UnexpectedSize {
            expected: MAX_SBOR_COLLECTION_SIZE,
            actual: count,
        });
    }
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

        if length != 4 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 4,
                actual: length,
            });
        }

        let header: BlockHeader = decoder.decode()?;
        let transactions = decode_tx_vec(decoder)?;
        let certificates = decode_wave_cert_vec(decoder, MAX_SBOR_COLLECTION_SIZE)?;
        let abort_intents: Vec<AbortIntent> = decoder.decode()?;

        Ok(Self {
            header,
            transactions,
            certificates,
            abort_intents,
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
    /// Create an empty genesis block with the given proposer and JVT state.
    pub fn genesis(shard_group_id: ShardGroupId, proposer: ValidatorId, state_root: Hash) -> Self {
        Self {
            header: BlockHeader::genesis(shard_group_id, proposer, state_root),
            transactions: vec![],
            certificates: vec![],
            abort_intents: vec![],
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

    /// Get total number of transactions.
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Check if this block contains a specific transaction by hash.
    pub fn contains_transaction(&self, tx_hash: &Hash) -> bool {
        self.transactions.iter().any(|tx| tx.hash() == *tx_hash)
    }

    /// Get all transaction hashes.
    pub fn transaction_hashes(&self) -> Vec<Hash> {
        self.transactions.iter().map(|tx| tx.hash()).collect()
    }

    /// Check if this is the genesis block.
    pub fn is_genesis(&self) -> bool {
        self.header.is_genesis()
    }

    /// Get number of wave certificates in this block.
    pub fn certificate_count(&self) -> usize {
        self.certificates.len()
    }

    /// Get number of abort intents in this block.
    pub fn abort_intent_count(&self) -> usize {
        self.abort_intents.len()
    }

    /// Get transaction hashes of abort intents.
    pub fn abort_intent_hashes(&self) -> Vec<Hash> {
        self.abort_intents.iter().map(|a| a.tx_hash).collect()
    }

    /// Check if this block contains an abort intent for a specific transaction.
    pub fn contains_abort_intent(&self, tx_hash: &Hash) -> bool {
        self.abort_intents.iter().any(|a| &a.tx_hash == tx_hash)
    }

    /// Check if this block has any livelock-related content.
    pub fn has_livelock_content(&self) -> bool {
        !self.abort_intents.is_empty()
    }
}

// ============================================================================
// BlockManifest - Hash-level block contents
// ============================================================================

/// Hash-level description of a block's contents (transactions, certificates,
/// and abort intents).
///
/// This is the common denominator shared by `BlockHeaderNotification`, `BlockMetadata`,
/// and `ProtocolEvent::BlockHeaderReceived`. Extracting it into a standalone type
/// eliminates copy-paste across those sites.
#[derive(Debug, Clone, Default, PartialEq, Eq, BasicSbor)]
pub struct BlockManifest {
    /// Transaction hashes in block order.
    pub tx_hashes: Vec<Hash>,

    /// Certificate hashes (wave_id hashes) in block order.
    /// Validators use these to match against their locally finalized waves.
    pub cert_hashes: Vec<Hash>,

    /// Abort intents (small, stored inline).
    pub abort_intents: Vec<AbortIntent>,
}

impl BlockManifest {
    /// Get total transaction count.
    pub fn transaction_count(&self) -> usize {
        self.tx_hashes.len()
    }

    /// Build a manifest from a full block (extracting hashes).
    ///
    /// `cert_hashes` uses wave_id identity hashes (computable without EC knowledge).
    pub fn from_block(block: &Block) -> Self {
        Self {
            tx_hashes: block.transactions.iter().map(|tx| tx.hash()).collect(),
            cert_hashes: block
                .certificates
                .iter()
                .map(|c| c.wave_id.hash())
                .collect(),
            abort_intents: block.abort_intents.clone(),
        }
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
/// - `"wave_certificates"` CF: `WaveCertificate` keyed by wave_id hash
///
/// To reconstruct a full `Block`, fetch the metadata, then batch-fetch
/// transactions and certificates using the stored hashes.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BlockMetadata {
    /// Block header (contains height, parent hash, proposer, etc.)
    pub header: BlockHeader,

    /// Block contents (transaction hashes, certificates, deferrals, etc.)
    pub manifest: BlockManifest,

    /// Quorum certificate that commits this block.
    pub qc: QuorumCertificate,
}

impl BlockMetadata {
    /// Create metadata from a full block and QC.
    pub fn from_block(block: &Block, qc: QuorumCertificate) -> Self {
        Self {
            header: block.header.clone(),
            manifest: BlockManifest::from_block(block),
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

    /// Get total transaction count.
    pub fn transaction_count(&self) -> usize {
        self.manifest.transaction_count()
    }
}

// ============================================================================
// CommittedBlockHeader - Cross-shard trust attestation
// ============================================================================

/// A block header paired with the QC that committed it.
///
/// This is the minimal cross-shard trust attestation: given a `CommittedBlockHeader`,
/// a remote shard can verify the QC against the source shard's validator public keys
/// (from topology), confirm the `block_hash` matches `hash(header)`, and then trust
/// the `state_root` in the header for merkle inclusion proof verification.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct CommittedBlockHeader {
    /// The block header.
    pub header: BlockHeader,

    /// The quorum certificate that committed this block.
    pub qc: QuorumCertificate,
}

impl CommittedBlockHeader {
    /// Create a new committed block header.
    pub fn new(header: BlockHeader, qc: QuorumCertificate) -> Self {
        Self { header, qc }
    }

    /// Compute the block hash (hashes the header).
    pub fn block_hash(&self) -> Hash {
        self.header.hash()
    }

    /// Get the block height.
    pub fn height(&self) -> BlockHeight {
        self.header.height
    }

    /// Get the shard group this block belongs to.
    pub fn shard_group_id(&self) -> ShardGroupId {
        self.header.shard_group_id
    }

    /// Get the state root committed by this block.
    pub fn state_root(&self) -> Hash {
        self.header.state_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_header_hash_deterministic() {
        let header = BlockHeader {
            shard_group_id: ShardGroupId(0),
            height: BlockHeight(1),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: 1234567890,
            round: 0,
            is_fallback: false,
            state_root: Hash::ZERO,
            transaction_root: Hash::ZERO,
            certificate_root: Hash::ZERO,
            local_receipt_root: Hash::ZERO,
            waves: vec![],
        };

        let hash1 = header.hash();
        let hash2 = header.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_genesis_block() {
        let genesis = Block::genesis(ShardGroupId(0), ValidatorId(0), Hash::ZERO);

        assert!(genesis.is_genesis());
        assert_eq!(genesis.height(), BlockHeight(0));
        assert_eq!(genesis.transaction_count(), 0);
        assert_eq!(genesis.header.transaction_root, Hash::ZERO);
        assert_eq!(genesis.header.parent_qc, QuorumCertificate::genesis());
    }

    #[test]
    fn test_compute_transaction_root_empty() {
        let root = compute_transaction_root(&[]);
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

        let root1 = compute_transaction_root(std::slice::from_ref(&tx));
        let root2 = compute_transaction_root(std::slice::from_ref(&tx));
        assert_eq!(root1, root2);
        assert_ne!(root1, Hash::ZERO);
    }

    #[test]
    fn test_compute_certificate_root_empty() {
        let root = compute_certificate_root(&[]);
        assert_eq!(root, Hash::ZERO);
    }

    #[test]
    fn test_compute_certificate_root_deterministic() {
        use crate::{
            Bls12381G2Signature, ShardAttestation, ShardGroupId, SignerBitfield, WaveCertificate,
            WaveId, WaveResolution,
        };
        use std::collections::BTreeSet;

        let make_wave_cert = |seed: u8| -> Arc<WaveCertificate> {
            Arc::new(WaveCertificate {
                wave_id: WaveId {
                    shard_group_id: ShardGroupId(0),
                    block_height: 10,
                    remote_shards: BTreeSet::from([ShardGroupId(1)]),
                },
                resolution: WaveResolution::Completed {
                    attestations: vec![ShardAttestation {
                        shard_group_id: ShardGroupId(0),
                        ec_hash: Hash::from_bytes(&[seed; 4]),
                        vote_height: 11,
                        global_receipt_root: Hash::from_bytes(&[seed + 100; 4]),
                        aggregated_signature: Bls12381G2Signature([0u8; 96]),
                        signers: SignerBitfield::new(4),
                    }],
                },
            })
        };

        let certs = vec![make_wave_cert(1), make_wave_cert(2)];
        let root1 = compute_certificate_root(&certs);
        let root2 = compute_certificate_root(&certs);
        assert_eq!(root1, root2);
        assert_ne!(root1, Hash::ZERO);
    }

    #[test]
    fn test_compute_certificate_root_single_cert() {
        use crate::{
            Bls12381G2Signature, ShardAttestation, ShardGroupId, SignerBitfield, WaveCertificate,
            WaveId, WaveResolution,
        };
        use std::collections::BTreeSet;

        let cert = Arc::new(WaveCertificate {
            wave_id: WaveId {
                shard_group_id: ShardGroupId(0),
                block_height: 10,
                remote_shards: BTreeSet::new(),
            },
            resolution: WaveResolution::Completed {
                attestations: vec![ShardAttestation {
                    shard_group_id: ShardGroupId(0),
                    ec_hash: Hash::from_bytes(b"ec1"),
                    vote_height: 11,
                    global_receipt_root: Hash::from_bytes(b"receipt"),
                    aggregated_signature: Bls12381G2Signature([0u8; 96]),
                    signers: SignerBitfield::new(4),
                }],
            },
        });

        let root = compute_certificate_root(std::slice::from_ref(&cert));
        // Single cert: certificate_root should equal the cert's receipt_hash
        assert_eq!(root, cert.receipt_hash());
    }

    #[test]
    fn test_genesis_certificate_root_is_zero() {
        let genesis = Block::genesis(ShardGroupId(0), ValidatorId(0), Hash::ZERO);
        assert_eq!(genesis.header.certificate_root, Hash::ZERO);
    }
}
