//! Block and BlockHeader types for consensus.

#[cfg(test)]
use crate::GlobalReceiptHash;
use crate::{
    block_vote_message, compute_merkle_root, compute_padded_merkle_root, decode_finalized_wave_vec,
    encode_finalized_wave_vec, BlockHash, BlockHeight, Bls12381G1PrivateKey, Bls12381G2Signature,
    CertificateRoot, FinalizedWave, Hash, LocalReceiptRoot, ProposerTimestamp, ProvisionHash,
    ProvisionTxRoot, Provisions, ProvisionsRoot, QuorumCertificate, ReceiptBundle, Round,
    RoutableTransaction, ShardGroupId, StateRoot, TransactionRoot, TxHash, ValidatorId, WaveId,
    WaveIdHash,
};
use sbor::prelude::*;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Compute the receipt merkle root for a block's finalized waves.
///
/// Each underlying wave certificate's `receipt_hash` becomes a leaf.
/// Returns `Hash::ZERO` if there are no certificates.
pub fn compute_certificate_root(certificates: &[Arc<FinalizedWave>]) -> CertificateRoot {
    if certificates.is_empty() {
        return CertificateRoot::ZERO;
    }

    let leaves: Vec<Hash> = certificates
        .iter()
        .map(|fw| fw.certificate.receipt_hash().into_raw())
        .collect();
    CertificateRoot::from_raw(compute_merkle_root(&leaves))
}

/// Compute the local receipt merkle root for a block's receipts.
///
/// Each receipt's `receipt_hash()` (includes outcome + events + database_updates)
/// becomes a leaf. Receipts are sorted by `tx_hash` before computing the root
/// to ensure determinism regardless of collection order (e.g. HashMap iteration).
/// Returns `Hash::ZERO` if there are no receipts.
pub fn compute_local_receipt_root(receipts: &[ReceiptBundle]) -> LocalReceiptRoot {
    if receipts.is_empty() {
        return LocalReceiptRoot::ZERO;
    }

    // Sort by tx_hash for deterministic ordering across validators.
    let mut sorted: Vec<_> = receipts
        .iter()
        .map(|b| (b.tx_hash, b.local_receipt.receipt_hash()))
        .collect();
    sorted.sort_by_key(|(tx_hash, _)| *tx_hash);

    let leaves: Vec<Hash> = sorted
        .into_iter()
        .map(|(_, receipt_hash)| receipt_hash)
        .collect();
    LocalReceiptRoot::from_raw(compute_merkle_root(&leaves))
}

/// Compute the provisions merkle root for a block.
///
/// Each provisions' hash becomes a leaf. Returns `Hash::ZERO` if empty.
pub fn compute_provision_root(batch_hashes: &[Hash]) -> ProvisionsRoot {
    if batch_hashes.is_empty() {
        return ProvisionsRoot::ZERO;
    }
    ProvisionsRoot::from_raw(compute_padded_merkle_root(batch_hashes))
}

/// Compute the transaction merkle root for a block.
///
/// Each transaction's hash becomes a leaf directly. Returns `Hash::ZERO` if empty.
pub fn compute_transaction_root(transactions: &[Arc<RoutableTransaction>]) -> TransactionRoot {
    if transactions.is_empty() {
        return TransactionRoot::ZERO;
    }

    let leaves: Vec<Hash> = transactions.iter().map(|tx| tx.hash().into_raw()).collect();

    // Use padded merkle root (power-of-2 padding with Hash::ZERO) so that
    // merkle inclusion proofs can be generated and verified for any leaf.
    TransactionRoot::from_raw(compute_padded_merkle_root(&leaves))
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
    /// Shard group this block belongs to.
    ///
    /// Makes headers self-describing for cross-shard verification. A remote shard
    /// needs to know which shard's committee to verify the QC against.
    pub shard_group_id: ShardGroupId,

    /// Block height in the chain (genesis = 0).
    pub height: BlockHeight,

    /// Hash of parent block.
    pub parent_hash: BlockHash,

    /// Quorum certificate proving parent block was committed.
    pub parent_qc: QuorumCertificate,

    /// Validator that proposed this block.
    pub proposer: ValidatorId,

    /// Proposer's local wall-clock when this block was proposed.
    ///
    /// **Not** BFT-authenticated. Used only for BFT liveness bounds (rejecting
    /// rushed/stale proposals against the local validator's clock) and local
    /// latency metrics. Never anchor a deterministic timeout on this — use
    /// `qc.weighted_timestamp` / `ts_ms` fields derived from it instead.
    pub timestamp: ProposerTimestamp,

    /// View/round number for view change protocol.
    pub round: Round,

    /// Whether this block was created as a fallback when leader timed out.
    pub is_fallback: bool,

    /// JMT state root hash after applying all certificates in this block.
    pub state_root: StateRoot,

    /// Merkle root of all transactions in this block.
    ///
    /// Each transaction's hash is a leaf in a padded binary merkle tree.
    /// For empty blocks (fallback, sync), this is `TransactionRoot::ZERO`.
    pub transaction_root: TransactionRoot,

    /// Merkle root of all certificate receipt hashes in this block.
    ///
    /// Each certificate's `receipt_hash` (hash of outcome + event_root) is a leaf
    /// in a binary merkle tree. This enables light-client proof of "did transaction
    /// X succeed/fail in block N?" without replaying the block.
    ///
    /// For empty blocks (genesis, fallback, no certificates), this is `CertificateRoot::ZERO`.
    pub certificate_root: CertificateRoot,

    /// Merkle root of per-tx `LocalReceipt` hashes for all transactions
    /// covered by this block's wave certificates.
    ///
    /// Commits to the specific per-tx state deltas (shard-filtered DatabaseUpdates)
    /// that were applied to produce `state_root`. Enables per-tx delta attribution
    /// and receipt integrity verification by sync nodes.
    ///
    /// For empty blocks (genesis, fallback, no certificates), this is `LocalReceiptRoot::ZERO`.
    pub local_receipt_root: LocalReceiptRoot,

    /// Merkle root of provisions included in this block.
    ///
    /// Commits to which remote-shard provisions are available at this height.
    /// Validators who voted for the BFT proposal have this data locally.
    /// `ProvisionsRoot::ZERO` when no provisions are included (single-shard or empty block).
    pub provision_root: ProvisionsRoot,

    /// Cross-shard execution waves in this block.
    ///
    /// Each `WaveId` is the set of remote shards that a group of transactions
    /// depends on for provisions. Transactions with identical remote shard sets
    /// share a wave. Wave-zero (single-shard txs) is excluded.
    ///
    /// QC-attested (covered by the block hash), so a byzantine proposer
    /// cannot forge it without the block being rejected by honest validators —
    /// `validate_waves` recomputes this from `transactions` and compares.
    ///
    /// Used by remote shards to know which execution certificates to expect.
    /// Provisions completeness is handled separately via
    /// [`BlockHeader::provision_tx_roots`]. Empty for genesis, fallback, and
    /// sync blocks.
    pub waves: Vec<WaveId>,

    /// Per-target-shard merkle commitment over the tx hashes a target shard
    /// should receive provisions for from this block.
    ///
    /// Key = target shard; value = `compute_padded_merkle_root` over the
    /// ordered tx hashes destined for that target (block order, already
    /// hash-ascending). Lets the target verify a received `Provisions`
    /// contains the full set it was meant to receive — catches silently
    /// dropped txs on the broadcast path.
    ///
    /// Entries only exist for targets with ≥1 tx. Empty for genesis,
    /// single-shard-only blocks, and empty blocks.
    pub provision_tx_roots: BTreeMap<ShardGroupId, ProvisionTxRoot>,

    /// Approximate number of in-flight transactions on this shard at proposal time.
    ///
    /// "In-flight" = committed + executed transactions in the proposer's mempool,
    /// i.e. transactions actively holding state locks. Gossiped cross-shard via
    /// `CommittedBlockHeaderGossip` so RPC nodes can reject transactions targeting
    /// congested remote shards.
    ///
    /// BFT-verified within tolerance (validators may differ slightly due to
    /// execution timing). Zero for genesis, fallback, and sync blocks.
    pub in_flight: u32,
}

impl BlockHeader {
    /// Create a genesis block header (height 0) with the given proposer and JMT state.
    pub fn genesis(
        shard_group_id: ShardGroupId,
        proposer: ValidatorId,
        state_root: StateRoot,
    ) -> Self {
        Self {
            shard_group_id,
            height: BlockHeight(0),
            parent_hash: BlockHash::from_raw(Hash::from_bytes(&[0u8; 32])),
            parent_qc: QuorumCertificate::genesis(),
            proposer,
            timestamp: ProposerTimestamp::ZERO,
            round: Round::INITIAL,
            is_fallback: false,
            state_root,
            transaction_root: TransactionRoot::ZERO,
            certificate_root: CertificateRoot::ZERO,
            local_receipt_root: LocalReceiptRoot::ZERO,
            provision_root: ProvisionsRoot::ZERO,
            waves: vec![],
            provision_tx_roots: BTreeMap::new(),
            in_flight: 0,
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
    pub fn hash(&self) -> BlockHash {
        let bytes = basic_encode(self).expect("BlockHeader serialization should never fail");
        BlockHash::from_raw(Hash::from_bytes(&bytes))
    }

    /// Check if this is the genesis block header.
    pub fn is_genesis(&self) -> bool {
        self.height.0 == 0
    }

    /// Get the expected proposer for this height (round-robin).
    pub fn expected_proposer(&self, num_validators: u64) -> ValidatorId {
        ValidatorId((self.height.0 + self.round.0) % num_validators)
    }
}

/// Complete block with header and transaction data.
///
/// Transactions are stored in a single flat list, sorted by hash for deterministic ordering.
///
/// Blocks have two variants reflecting their temporal lifecycle:
/// - **`Live`**: within the cross-shard execution window. Carries the
///   provisions needed to execute cross-shard waves locally.
/// - **`Sealed`**: past the execution window (at least `WAVE_TIMEOUT` of
///   wall-clock behind the local committed tip). Waves are finalized from
///   certs + receipts alone, so provisions are no longer needed and are
///   dropped from memory. The on-disk / storage shape is always `Sealed`.
///
/// The header's `provision_root` commits to the original provision set, so
/// `Sealed` is self-consistent — a `Live` block matches its `Sealed` form
/// modulo the provision payload.
#[derive(Debug, Clone)]
pub enum Block {
    Live {
        header: BlockHeader,
        transactions: Vec<Arc<RoutableTransaction>>,
        certificates: Vec<Arc<FinalizedWave>>,
        provisions: Vec<Arc<Provisions>>,
    },
    Sealed {
        header: BlockHeader,
        transactions: Vec<Arc<RoutableTransaction>>,
        certificates: Vec<Arc<FinalizedWave>>,
    },
}

// Manual PartialEq - compare transaction/certificate content, not Arc pointers.
// Provisions are excluded from equality: the header's `provision_root` already
// commits to them, and a Live and Sealed form of the same block should compare
// equal for content purposes.
impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        fn tx_lists_equal(a: &[Arc<RoutableTransaction>], b: &[Arc<RoutableTransaction>]) -> bool {
            a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.hash() == y.hash())
        }
        fn cert_lists_equal(a: &[Arc<FinalizedWave>], b: &[Arc<FinalizedWave>]) -> bool {
            a.len() == b.len()
                && a.iter()
                    .zip(b.iter())
                    .all(|(x, y)| x.as_ref() == y.as_ref())
        }

        self.header() == other.header()
            && tx_lists_equal(self.transactions(), other.transactions())
            && cert_lists_equal(self.certificates(), other.certificates())
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

/// Helper to encode a Vec<Arc<Provision>> as an SBOR array. Mirrors the
/// transaction / finalized-wave helpers.
fn encode_provision_vec<E: sbor::Encoder<sbor::NoCustomValueKind>>(
    encoder: &mut E,
    provisions: &[Arc<Provisions>],
) -> Result<(), sbor::EncodeError> {
    encoder.write_value_kind(sbor::ValueKind::Array)?;
    encoder.write_value_kind(sbor::ValueKind::Tuple)?;
    encoder.write_size(provisions.len())?;
    for p in provisions {
        encoder.encode_deeper_body(p.as_ref())?;
    }
    Ok(())
}

// Variant tag bytes for SBOR encoding. Explicit rather than relying on
// derive so future additions don't renumber existing variants silently.
const BLOCK_VARIANT_LIVE: u8 = 0;
const BLOCK_VARIANT_SEALED: u8 = 1;

impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E> for Block {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Enum)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        match self {
            Block::Live {
                header,
                transactions,
                certificates,
                provisions,
            } => {
                encoder.write_discriminator(BLOCK_VARIANT_LIVE)?;
                encoder.write_size(4)?;
                encoder.encode(header)?;
                encode_tx_vec(encoder, transactions)?;
                encode_finalized_wave_vec(encoder, certificates)?;
                encode_provision_vec(encoder, provisions)?;
            }
            Block::Sealed {
                header,
                transactions,
                certificates,
            } => {
                encoder.write_discriminator(BLOCK_VARIANT_SEALED)?;
                encoder.write_size(3)?;
                encoder.encode(header)?;
                encode_tx_vec(encoder, transactions)?;
                encode_finalized_wave_vec(encoder, certificates)?;
            }
        }
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

/// Helper to decode a Vec<Arc<Provision>> from an SBOR array.
fn decode_provision_vec<D: sbor::Decoder<sbor::NoCustomValueKind>>(
    decoder: &mut D,
) -> Result<Vec<Arc<Provisions>>, sbor::DecodeError> {
    decoder.read_and_check_value_kind(sbor::ValueKind::Array)?;
    decoder.read_and_check_value_kind(sbor::ValueKind::Tuple)?;
    let count = decoder.read_size()?;
    if count > MAX_SBOR_COLLECTION_SIZE {
        return Err(sbor::DecodeError::UnexpectedSize {
            expected: MAX_SBOR_COLLECTION_SIZE,
            actual: count,
        });
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let p: Provisions = decoder.decode_deeper_body_with_value_kind(sbor::ValueKind::Tuple)?;
        out.push(Arc::new(p));
    }
    Ok(out)
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D> for Block {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Enum)?;
        let discriminator = decoder.read_discriminator()?;
        let length = decoder.read_size()?;

        match discriminator {
            BLOCK_VARIANT_LIVE => {
                if length != 4 {
                    return Err(sbor::DecodeError::UnexpectedSize {
                        expected: 4,
                        actual: length,
                    });
                }
                let header: BlockHeader = decoder.decode()?;
                let transactions = decode_tx_vec(decoder)?;
                let certificates = decode_finalized_wave_vec(decoder, MAX_SBOR_COLLECTION_SIZE)?;
                let provisions = decode_provision_vec(decoder)?;
                Ok(Block::Live {
                    header,
                    transactions,
                    certificates,
                    provisions,
                })
            }
            BLOCK_VARIANT_SEALED => {
                if length != 3 {
                    return Err(sbor::DecodeError::UnexpectedSize {
                        expected: 3,
                        actual: length,
                    });
                }
                let header: BlockHeader = decoder.decode()?;
                let transactions = decode_tx_vec(decoder)?;
                let certificates = decode_finalized_wave_vec(decoder, MAX_SBOR_COLLECTION_SIZE)?;
                Ok(Block::Sealed {
                    header,
                    transactions,
                    certificates,
                })
            }
            other => Err(sbor::DecodeError::UnknownDiscriminator(other)),
        }
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for Block {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Enum
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
    ///
    /// Genesis is born `Live` with no provisions — the temporality machinery
    /// activates only once there are cross-shard waves in flight.
    pub fn genesis(
        shard_group_id: ShardGroupId,
        proposer: ValidatorId,
        state_root: StateRoot,
    ) -> Self {
        Block::Live {
            header: BlockHeader::genesis(shard_group_id, proposer, state_root),
            transactions: vec![],
            certificates: vec![],
            provisions: vec![],
        }
    }

    /// Block header — present in both variants.
    pub fn header(&self) -> &BlockHeader {
        match self {
            Block::Live { header, .. } | Block::Sealed { header, .. } => header,
        }
    }

    /// Transactions in the block — present in both variants.
    pub fn transactions(&self) -> &[Arc<RoutableTransaction>] {
        match self {
            Block::Live { transactions, .. } | Block::Sealed { transactions, .. } => transactions,
        }
    }

    /// Finalized waves (certificates) in the block — present in both variants.
    pub fn certificates(&self) -> &[Arc<FinalizedWave>] {
        match self {
            Block::Live { certificates, .. } | Block::Sealed { certificates, .. } => certificates,
        }
    }

    /// Provisions. Non-empty only for `Live`; `Sealed` blocks have
    /// dropped their provisions because the cross-shard execution window
    /// they served has passed. Use `is_live()` when the variant itself
    /// matters — this accessor flattens both cases to a slice.
    pub fn provisions(&self) -> &[Arc<Provisions>] {
        match self {
            Block::Live { provisions, .. } => provisions,
            Block::Sealed { .. } => &[],
        }
    }

    /// True if this block is still in its `Live` variant.
    pub fn is_live(&self) -> bool {
        matches!(self, Block::Live { .. })
    }

    /// Convert to `Sealed` by dropping provisions. Identity on an already-
    /// sealed block. This is the canonical persisted shape; sync-serving
    /// glue re-attaches provisions (via `into_live`) when the requester
    /// needs them.
    pub fn into_sealed(self) -> Block {
        match self {
            Block::Live {
                header,
                transactions,
                certificates,
                ..
            } => Block::Sealed {
                header,
                transactions,
                certificates,
            },
            sealed @ Block::Sealed { .. } => sealed,
        }
    }

    /// Attach provisions, promoting `Sealed` → `Live`. Used by sync-serving
    /// to upgrade a persisted block when the requester is still inside the
    /// cross-shard execution window. Panics if invoked on a `Live` block —
    /// that would silently discard the existing provision set.
    pub fn into_live(self, provisions: Vec<Arc<Provisions>>) -> Block {
        match self {
            Block::Sealed {
                header,
                transactions,
                certificates,
            } => Block::Live {
                header,
                transactions,
                certificates,
                provisions,
            },
            Block::Live { .. } => {
                panic!("into_live called on an already-Live block")
            }
        }
    }

    /// Compute hash of this block (hashes the header).
    pub fn hash(&self) -> BlockHash {
        self.header().hash()
    }

    /// Get block height.
    pub fn height(&self) -> BlockHeight {
        self.header().height
    }

    /// Get total number of transactions.
    pub fn transaction_count(&self) -> usize {
        self.transactions().len()
    }

    /// Check if this block contains a specific transaction by hash.
    pub fn contains_transaction(&self, tx_hash: &TxHash) -> bool {
        self.transactions().iter().any(|tx| tx.hash() == *tx_hash)
    }

    /// Get all transaction hashes.
    pub fn transaction_hashes(&self) -> Vec<TxHash> {
        self.transactions().iter().map(|tx| tx.hash()).collect()
    }

    /// Check if this is the genesis block.
    pub fn is_genesis(&self) -> bool {
        self.header().is_genesis()
    }

    /// Get number of wave certificates in this block.
    pub fn certificate_count(&self) -> usize {
        self.certificates().len()
    }
}

// ============================================================================
// BlockManifest - Hash-level block contents
// ============================================================================

/// Hash-level description of a block's contents (transactions and certificates).
///
/// This is the common denominator shared by `BlockHeaderNotification`, `BlockMetadata`,
/// and `ProtocolEvent::BlockHeaderReceived`. Extracting it into a standalone type
/// eliminates copy-paste across those sites.
#[derive(Debug, Clone, Default, PartialEq, Eq, BasicSbor)]
pub struct BlockManifest {
    /// Transaction hashes in block order.
    pub tx_hashes: Vec<TxHash>,

    /// Certificate hashes (wave_id hashes) in block order.
    /// Validators use these to match against their locally finalized waves.
    pub cert_hashes: Vec<WaveIdHash>,

    /// Hashes of provisions included in this block.
    /// Used for provision data availability — validators fetch missing batches by hash.
    pub provision_hashes: Vec<ProvisionHash>,
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
            tx_hashes: block.transactions().iter().map(|tx| tx.hash()).collect(),
            cert_hashes: block
                .certificates()
                .iter()
                .map(|c| c.wave_id().hash())
                .collect(),
            provision_hashes: vec![],
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
            header: block.header().clone(),
            manifest: BlockManifest::from_block(block),
            qc,
        }
    }

    /// Get block height.
    pub fn height(&self) -> BlockHeight {
        self.header.height
    }

    /// Compute hash of this block (hashes the header).
    pub fn hash(&self) -> BlockHash {
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
    pub fn block_hash(&self) -> BlockHash {
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
    pub fn state_root(&self) -> StateRoot {
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
            parent_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: ProposerTimestamp(1234567890),
            round: Round::INITIAL,
            is_fallback: false,
            state_root: StateRoot::ZERO,
            transaction_root: TransactionRoot::ZERO,
            certificate_root: CertificateRoot::ZERO,
            local_receipt_root: LocalReceiptRoot::ZERO,
            provision_root: ProvisionsRoot::ZERO,
            waves: vec![],
            provision_tx_roots: BTreeMap::new(),
            in_flight: 0,
        };

        let hash1 = header.hash();
        let hash2 = header.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_genesis_block() {
        let genesis = Block::genesis(ShardGroupId(0), ValidatorId(0), StateRoot::ZERO);

        assert!(genesis.is_genesis());
        assert_eq!(genesis.height(), BlockHeight(0));
        assert_eq!(genesis.transaction_count(), 0);
        assert_eq!(genesis.header().transaction_root, TransactionRoot::ZERO);
        assert_eq!(genesis.header().parent_qc, QuorumCertificate::genesis());
    }

    #[test]
    fn test_compute_transaction_root_empty() {
        let root = compute_transaction_root(&[]);
        assert_eq!(root, TransactionRoot::ZERO);
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
        let tx = Arc::new(
            crate::routable_from_notarized_v1(notarized, crate::test_utils::test_validity_range())
                .unwrap(),
        );

        let root1 = compute_transaction_root(std::slice::from_ref(&tx));
        let root2 = compute_transaction_root(std::slice::from_ref(&tx));
        assert_eq!(root1, root2);
        assert_ne!(root1, TransactionRoot::ZERO);
    }

    #[test]
    fn test_compute_certificate_root_empty() {
        let root = compute_certificate_root(&[]);
        assert_eq!(root, CertificateRoot::ZERO);
    }

    #[test]
    fn test_compute_certificate_root_deterministic() {
        use crate::{
            Bls12381G2Signature, ExecutionCertificate, ExecutionOutcome, ShardGroupId,
            SignerBitfield, TxOutcome, WaveCertificate, WaveId,
        };
        use std::collections::BTreeSet;

        let make_fw = |seed: u8| -> Arc<FinalizedWave> {
            let ec = Arc::new(ExecutionCertificate::new(
                WaveId::new(
                    ShardGroupId(0),
                    BlockHeight(10),
                    BTreeSet::from([ShardGroupId(1)]),
                ),
                crate::WeightedTimestamp(11),
                crate::GlobalReceiptRoot::from_raw(Hash::from_bytes(&[seed + 100; 4])),
                vec![TxOutcome {
                    tx_hash: TxHash::from_raw(Hash::from_bytes(&[seed; 4])),
                    outcome: ExecutionOutcome::Executed {
                        receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(
                            &[seed + 50; 4],
                        )),
                        success: true,
                    },
                }],
                Bls12381G2Signature([0u8; 96]),
                SignerBitfield::new(4),
            ));
            Arc::new(FinalizedWave {
                certificate: Arc::new(WaveCertificate {
                    wave_id: WaveId::new(
                        ShardGroupId(0),
                        BlockHeight(10),
                        BTreeSet::from([ShardGroupId(1)]),
                    ),
                    execution_certificates: vec![ec],
                }),
                receipts: vec![],
            })
        };

        let certs = vec![make_fw(1), make_fw(2)];
        let root1 = compute_certificate_root(&certs);
        let root2 = compute_certificate_root(&certs);
        assert_eq!(root1, root2);
        assert_ne!(root1, CertificateRoot::ZERO);
    }

    #[test]
    fn test_compute_certificate_root_single_cert() {
        use crate::{
            Bls12381G2Signature, ExecutionCertificate, ExecutionOutcome, ShardGroupId,
            SignerBitfield, TxOutcome, WaveCertificate, WaveId,
        };
        use std::collections::BTreeSet;

        let ec = Arc::new(ExecutionCertificate::new(
            WaveId::new(ShardGroupId(0), BlockHeight(10), BTreeSet::new()),
            crate::WeightedTimestamp(11),
            crate::GlobalReceiptRoot::from_raw(Hash::from_bytes(b"receipt")),
            vec![TxOutcome {
                tx_hash: TxHash::from_raw(Hash::from_bytes(b"tx1")),
                outcome: ExecutionOutcome::Executed {
                    receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(b"rh")),
                    success: true,
                },
            }],
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        ));
        let cert = Arc::new(WaveCertificate {
            wave_id: WaveId::new(ShardGroupId(0), BlockHeight(10), BTreeSet::new()),
            execution_certificates: vec![ec],
        });
        let expected_receipt_hash = cert.receipt_hash();
        let fw = Arc::new(FinalizedWave {
            certificate: cert,
            receipts: vec![],
        });

        let root = compute_certificate_root(std::slice::from_ref(&fw));
        // Single cert: certificate_root should equal the cert's receipt_hash
        assert_eq!(root.into_raw(), expected_receipt_hash.into_raw());
    }

    #[test]
    fn test_genesis_certificate_root_is_zero() {
        let genesis = Block::genesis(ShardGroupId(0), ValidatorId(0), StateRoot::ZERO);
        assert_eq!(genesis.header().certificate_root, CertificateRoot::ZERO);
    }
}

// ============================================================================
// BlockVote
// ============================================================================

/// Block vote for BFT consensus.
#[derive(Debug, Clone, PartialEq, Eq, sbor::prelude::BasicSbor)]
pub struct BlockVote {
    /// Hash of the block being voted on.
    pub block_hash: BlockHash,
    /// Shard group this vote belongs to (prevents cross-shard replay).
    pub shard_group_id: ShardGroupId,
    /// Height of the block.
    pub height: BlockHeight,
    /// Round number (for view change).
    pub round: Round,
    /// Validator who cast this vote.
    pub voter: ValidatorId,
    /// BLS signature over the domain-separated signing message.
    pub signature: Bls12381G2Signature,
    /// Voter's local wall-clock when this vote was created. Stake-weighted
    /// into the QC's `weighted_timestamp` once 2f+1 votes are aggregated.
    pub timestamp: ProposerTimestamp,
}

impl BlockVote {
    /// Create a new block vote with domain-separated signing.
    pub fn new(
        block_hash: BlockHash,
        shard_group_id: ShardGroupId,
        height: BlockHeight,
        round: Round,
        voter: ValidatorId,
        signing_key: &Bls12381G1PrivateKey,
        timestamp: ProposerTimestamp,
    ) -> Self {
        let message = block_vote_message(shard_group_id, height, round, &block_hash);
        let signature = signing_key.sign_v1(&message);
        Self {
            block_hash,
            shard_group_id,
            height,
            round,
            voter,
            signature,
            timestamp,
        }
    }

    /// Build the canonical signing message for this vote.
    ///
    /// Uses `DOMAIN_BLOCK_VOTE` tag for domain separation.
    /// This is the same message used for QC aggregated signature verification.
    pub fn signing_message(&self) -> Vec<u8> {
        block_vote_message(
            self.shard_group_id,
            self.height,
            self.round,
            &self.block_hash,
        )
    }
}
