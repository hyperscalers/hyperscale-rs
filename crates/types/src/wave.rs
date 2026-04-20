//! Wave types and utilities for cross-shard execution.
//!
//! Transactions in a block are partitioned into waves by their provision
//! dependency set (the set of remote shards they need provisions from).
//! All validators compute identical wave assignments from block contents,
//! enabling wave-level BLS signature aggregation instead of per-transaction
//! signatures.
//!
//! # Wave Assignment
//!
//! - **Wave ∅** (ZERO): Single-shard txs — no provisions needed
//! - **Wave {B}**: Txs needing provisions only from shard B
//! - **Wave {B,C}**: Txs needing provisions from both B and C
//!
//! Tx ordering within a wave preserves block ordering (stable partition).
//!
//! # Wave Lifecycle
//!
//! 1. [`WaveId`] — identity, computed from block contents
//! 2. [`ExecutionVote`] — per-validator BLS vote on wave outcomes
//! 3. [`ExecutionCertificate`] — aggregated 2f+1 shard-local certificate
//! 4. [`WaveCertificate`] — cross-shard proof of finalization (holds ECs directly)
//! 5. [`FinalizedWave`] — all data needed for block commit

use crate::{
    compute_padded_merkle_root, Bls12381G2Signature, Hash, LocalReceipt, ReceiptBundle,
    RoutableTransaction, ShardGroupId, SignerBitfield, TopologySnapshot, TransactionDecision,
    TransactionOutcome, ValidatorId,
};
use sbor::prelude::*;
use std::collections::BTreeSet;
use std::sync::Arc;

// ============================================================================
// WaveId
// ============================================================================

/// Self-contained wave identifier.
///
/// Globally unique: includes the local shard, block height, and the provision
/// dependency set (remote shards). This eliminates composite `(block_hash, wave_id)`
/// keys throughout the codebase.
///
/// The provision dependency set for a transaction is the set of remote shards
/// it needs state provisions from before execution. Transactions with identical
/// dependency sets belong to the same wave and can be voted on together.
///
/// A wave with empty `remote_shards` represents single-shard transactions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, BasicSbor)]
pub struct WaveId {
    /// The shard that committed the block containing this wave's transactions.
    pub shard_group_id: ShardGroupId,
    /// Block height at which the wave's transactions were committed.
    pub block_height: u64,
    /// Set of remote shards the transactions depend on (empty for single-shard waves).
    pub remote_shards: BTreeSet<ShardGroupId>,
}

impl WaveId {
    /// Create a new WaveId.
    pub fn new(
        shard_group_id: ShardGroupId,
        block_height: u64,
        remote_shards: BTreeSet<ShardGroupId>,
    ) -> Self {
        Self {
            shard_group_id,
            block_height,
            remote_shards,
        }
    }

    /// Whether this is a single-shard wave (no remote dependencies).
    pub fn is_zero(&self) -> bool {
        self.remote_shards.is_empty()
    }

    /// Number of provision source shards.
    pub fn dependency_count(&self) -> usize {
        self.remote_shards.len()
    }

    /// Compute a deterministic identity hash for this wave.
    ///
    /// Used for: BlockManifest cert_hashes, PendingBlock matching, storage keys,
    /// wave cert fetch requests. Computable without knowing EC content.
    pub fn hash(&self) -> Hash {
        let bytes = basic_encode(self).expect("WaveId serialization should never fail");
        Hash::from_bytes(&bytes)
    }
}

impl std::fmt::Display for WaveId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_zero() {
            write!(
                f,
                "Wave(shard={}, h={}, ∅)",
                self.shard_group_id.0, self.block_height
            )
        } else {
            write!(
                f,
                "Wave(shard={}, h={}, {{",
                self.shard_group_id.0, self.block_height
            )?;
            for (i, shard) in self.remote_shards.iter().enumerate() {
                if i > 0 {
                    write!(f, ",")?;
                }
                write!(f, "{}", shard.0)?;
            }
            write!(f, "}})")
        }
    }
}

// ============================================================================
// Wave Computation
// ============================================================================

/// Compute the set of cross-shard waves for a block's transactions.
///
/// Each transaction's remote shard set (shards it touches minus local shard)
/// defines its wave. Transactions with identical remote shard sets belong to
/// the same wave. Wave-zero (single-shard txs) is excluded.
///
/// Returns a sorted `Vec<WaveId>` with fully populated shard + height fields.
/// (Deterministic via BTreeSet ordering.)
/// Used in both block proposal (to populate `BlockHeader::waves`) and
/// validation (to verify the header's waves field).
pub fn compute_waves(
    topology: &TopologySnapshot,
    block_height: u64,
    transactions: &[Arc<RoutableTransaction>],
) -> Vec<WaveId> {
    let local_shard = topology.local_shard();
    let mut remote_shard_sets: BTreeSet<BTreeSet<ShardGroupId>> = BTreeSet::new();

    for tx in transactions {
        if topology.is_single_shard_transaction(tx) {
            continue;
        }
        let remote_shards: BTreeSet<ShardGroupId> = topology
            .all_shards_for_transaction(tx)
            .into_iter()
            .filter(|&s| s != local_shard)
            .collect();
        if !remote_shards.is_empty() {
            remote_shard_sets.insert(remote_shards);
        }
    }

    remote_shard_sets
        .into_iter()
        .map(|remote_shards| WaveId {
            shard_group_id: local_shard,
            block_height,
            remote_shards,
        })
        .collect()
}

/// Deterministically select the wave leader for a wave (attempt 0).
///
/// The wave leader collects execution votes, aggregates the EC, and
/// broadcasts it to local peers and remote shards. Convenience wrapper
/// for `wave_leader_at(wave_id, 0, committee)`.
pub fn wave_leader(wave_id: &WaveId, committee: &[ValidatorId]) -> ValidatorId {
    wave_leader_at(wave_id, 0, committee)
}

/// Deterministically select the wave leader with rotation for fallback.
///
/// Each `attempt` selects a different validator from the committee, enabling
/// leader rotation when the primary leader (attempt=0) fails. Validators
/// re-send their vote to `wave_leader_at(wave_id, attempt+1, committee)`
/// after a timeout.
///
/// Uses `Hash(sbor_encode(wave_id) ++ attempt.to_le_bytes()) % committee_size`
/// for deterministic selection. All validators compute the same result.
pub fn wave_leader_at(wave_id: &WaveId, attempt: u32, committee: &[ValidatorId]) -> ValidatorId {
    assert!(!committee.is_empty(), "committee must not be empty");
    let mut buf = basic_encode(wave_id).expect("WaveId serialization should never fail");
    buf.extend_from_slice(&attempt.to_le_bytes());
    let selection_hash = Hash::from_bytes(&buf);
    let bytes = selection_hash.as_bytes();
    let index_val = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    let index = (index_val as usize) % committee.len();
    committee[index]
}

// ============================================================================
// ExecutionOutcome / TxOutcome
// ============================================================================

/// Per-transaction execution outcome within a wave.
///
/// Carried inside execution certificates so remote shards can extract
/// individual transaction results for cross-shard finalization.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct TxOutcome {
    /// Transaction hash.
    pub tx_hash: Hash,
    /// The execution outcome for this transaction.
    pub outcome: ExecutionOutcome,
}

impl TxOutcome {
    /// Whether this outcome is an abort.
    pub fn is_aborted(&self) -> bool {
        matches!(self.outcome, ExecutionOutcome::Aborted)
    }
}

/// The outcome of executing a transaction on a single shard.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub enum ExecutionOutcome {
    /// Transaction executed. `receipt_hash` is the hash of the execution receipt.
    /// `success=true` means the transaction's logic succeeded (writes applied).
    /// `success=false` means the transaction's logic failed (no writes).
    Executed { receipt_hash: Hash, success: bool },
    /// Transaction aborted before execution could complete.
    Aborted,
}

impl ExecutionOutcome {
    /// Whether execution succeeded (executed with success=true).
    pub fn is_success(&self) -> bool {
        matches!(self, ExecutionOutcome::Executed { success: true, .. })
    }

    /// Whether the transaction was aborted.
    pub fn is_aborted(&self) -> bool {
        matches!(self, ExecutionOutcome::Aborted)
    }

    /// Get the receipt hash, or `Hash::ZERO` for aborted outcomes.
    pub fn receipt_hash_or_zero(&self) -> Hash {
        match self {
            ExecutionOutcome::Executed { receipt_hash, .. } => *receipt_hash,
            ExecutionOutcome::Aborted => Hash::ZERO,
        }
    }
}

// ============================================================================
// ExecutionVote
// ============================================================================

/// A validator's vote on all transactions in an execution wave.
///
/// One vote covers all transactions sharing the same provision dependency set,
/// with `global_receipt_root` being a padded merkle root over per-tx leaf hashes
/// where each leaf = H(tx_hash || receipt_hash || success_byte).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ExecutionVote {
    /// Block this wave belongs to.
    pub block_hash: Hash,
    /// Block height (the block containing the wave's transactions).
    pub block_height: u64,
    /// Consensus height at which this vote was cast.
    ///
    /// Validators vote at each block commit where the wave is complete.
    /// Including `vote_height` in the BLS-signed message prevents
    /// cross-height aggregation, ensuring that if an abort intent changes
    /// the global_receipt_root between heights, stale votes cannot combine.
    pub vote_height: u64,
    /// Which wave within the block.
    pub wave_id: WaveId,
    /// Which shard produced this vote.
    pub shard_group_id: ShardGroupId,
    /// Merkle root over per-tx outcome leaves.
    pub global_receipt_root: Hash,
    /// Number of transactions in this wave.
    pub tx_count: u32,
    /// Per-tx execution outcomes in wave order.
    ///
    /// Carried alongside the vote so any aggregator can extract tx_outcomes
    /// directly from quorum votes when building the EC. Not included in the
    /// BLS-signed message (global_receipt_root already commits to the content).
    /// This avoids relying on each aggregator's local accumulator, which may
    /// have diverged due to different abort timing.
    pub tx_outcomes: Vec<TxOutcome>,
    /// Validator who cast this vote.
    pub validator: ValidatorId,
    /// BLS signature over the vote signing message.
    pub signature: Bls12381G2Signature,
}

// ============================================================================
// ExecutionCertificate
// ============================================================================

/// Aggregated certificate for an execution wave.
///
/// Contains the BLS aggregated signature from 2f+1 validators plus per-tx
/// outcomes so remote shards can extract individual transaction results.
pub struct ExecutionCertificate {
    /// Self-contained wave identifier (shard + height + remote dependencies).
    pub wave_id: WaveId,
    /// Consensus height at which quorum was reached.
    ///
    /// Must match the `vote_height` in the aggregated votes. Needed to
    /// reconstruct the BLS signing message for signature verification.
    pub vote_height: u64,
    /// Merkle root over per-tx outcome leaves.
    pub global_receipt_root: Hash,
    /// Per-transaction outcomes (in wave order = block order).
    pub tx_outcomes: Vec<TxOutcome>,
    /// BLS aggregated signature from 2f+1 validators.
    pub aggregated_signature: Bls12381G2Signature,
    /// Which validators signed (bitfield indexed by committee position).
    pub signers: SignerBitfield,
    /// Cached canonical hash, computed eagerly at construction and on deserialization.
    canonical_hash: Hash,
    /// Cached SBOR-encoded bytes. Populated at construction or after
    /// deserialization to avoid re-serialization on storage writes.
    cached_sbor: Option<Vec<u8>>,
}

impl std::fmt::Debug for ExecutionCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionCertificate")
            .field("wave_id", &self.wave_id)
            .field("vote_height", &self.vote_height)
            .field("global_receipt_root", &self.global_receipt_root)
            .field("tx_outcomes", &self.tx_outcomes)
            .field("aggregated_signature", &self.aggregated_signature)
            .field("signers", &self.signers)
            .field("canonical_hash", &self.canonical_hash)
            .finish()
    }
}

impl Clone for ExecutionCertificate {
    fn clone(&self) -> Self {
        Self {
            wave_id: self.wave_id.clone(),
            vote_height: self.vote_height,
            global_receipt_root: self.global_receipt_root,
            tx_outcomes: self.tx_outcomes.clone(),
            aggregated_signature: self.aggregated_signature,
            signers: self.signers.clone(),
            canonical_hash: self.canonical_hash,
            cached_sbor: self.cached_sbor.clone(),
        }
    }
}

impl PartialEq for ExecutionCertificate {
    fn eq(&self, other: &Self) -> bool {
        self.canonical_hash == other.canonical_hash
            && self.wave_id == other.wave_id
            && self.vote_height == other.vote_height
            && self.global_receipt_root == other.global_receipt_root
            && self.tx_outcomes == other.tx_outcomes
            && self.aggregated_signature == other.aggregated_signature
            && self.signers == other.signers
    }
}

impl Eq for ExecutionCertificate {}

// Manual SBOR: cached_sbor and canonical_hash are derived, not serialized.
impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for ExecutionCertificate
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(6)?;
        encoder.encode(&self.wave_id)?;
        encoder.encode(&self.vote_height)?;
        encoder.encode(&self.global_receipt_root)?;
        encoder.encode(&self.tx_outcomes)?;
        encoder.encode(&self.aggregated_signature)?;
        encoder.encode(&self.signers)?;
        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for ExecutionCertificate
{
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
        let wave_id: WaveId = decoder.decode()?;
        let vote_height: u64 = decoder.decode()?;
        let global_receipt_root: Hash = decoder.decode()?;
        let tx_outcomes: Vec<TxOutcome> = decoder.decode()?;
        let aggregated_signature: Bls12381G2Signature = decoder.decode()?;
        let signers: SignerBitfield = decoder.decode()?;
        let canonical_hash =
            Self::compute_canonical_hash(&wave_id, vote_height, &global_receipt_root, &tx_outcomes);
        let mut ec = Self {
            wave_id,
            vote_height,
            global_receipt_root,
            tx_outcomes,
            aggregated_signature,
            signers,
            canonical_hash,
            cached_sbor: None,
        };
        ec.populate_cached_sbor();
        Ok(ec)
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for ExecutionCertificate {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for ExecutionCertificate {
    const TYPE_ID: sbor::RustTypeId =
        sbor::RustTypeId::novel_with_code("ExecutionCertificate", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

impl ExecutionCertificate {
    /// Create a new execution certificate, computing the canonical hash eagerly.
    pub fn new(
        wave_id: WaveId,
        vote_height: u64,
        global_receipt_root: Hash,
        tx_outcomes: Vec<TxOutcome>,
        aggregated_signature: Bls12381G2Signature,
        signers: SignerBitfield,
    ) -> Self {
        let canonical_hash =
            Self::compute_canonical_hash(&wave_id, vote_height, &global_receipt_root, &tx_outcomes);
        let mut ec = Self {
            wave_id,
            vote_height,
            global_receipt_root,
            tx_outcomes,
            aggregated_signature,
            signers,
            canonical_hash,
            cached_sbor: None,
        };
        ec.populate_cached_sbor();
        ec
    }

    /// The shard that produced this certificate.
    pub fn shard_group_id(&self) -> ShardGroupId {
        self.wave_id.shard_group_id
    }

    /// Block height (the block containing the wave's transactions).
    pub fn block_height(&self) -> u64 {
        self.wave_id.block_height
    }

    /// Return the cached canonical hash.
    ///
    /// Hashes only the deterministic execution-result fields, **excluding**
    /// `aggregated_signature` and `signers`. Different validators aggregate
    /// different 2f+1 subsets of votes, producing different signatures for the
    /// same wave — the canonical hash identifies the *logical* EC so that any
    /// valid aggregation resolves to the same hash.
    pub fn canonical_hash(&self) -> Hash {
        self.canonical_hash
    }

    /// Pre-serialized SBOR bytes, if available.
    pub fn cached_sbor_bytes(&self) -> Option<&[u8]> {
        self.cached_sbor.as_deref()
    }

    fn populate_cached_sbor(&mut self) {
        self.cached_sbor = Some(basic_encode(self).expect("EC SBOR encoding must succeed"));
    }

    fn compute_canonical_hash(
        wave_id: &WaveId,
        vote_height: u64,
        global_receipt_root: &Hash,
        tx_outcomes: &[TxOutcome],
    ) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&basic_encode(wave_id).unwrap());
        hasher.update(&vote_height.to_le_bytes());
        hasher.update(global_receipt_root.as_bytes());
        hasher.update(&basic_encode(tx_outcomes).unwrap());
        Hash::from_hash_bytes(hasher.finalize().as_bytes())
    }
}

// ============================================================================
// Receipt Tree Utilities
// ============================================================================

/// Compute the leaf hash for a transaction outcome in the receipt tree.
///
/// For executed outcomes: Leaf = H(tx_hash || receipt_hash || success_byte)
/// For aborted outcomes: Leaf = H(tx_hash || "ABORTED:" || sbor_encode(reason))
///
/// The domain tag `b"ABORTED:"` ensures abort leaves can never collide with
/// executed leaves.
pub fn tx_outcome_leaf(outcome: &TxOutcome) -> Hash {
    match &outcome.outcome {
        ExecutionOutcome::Executed {
            receipt_hash,
            success,
            ..
        } => Hash::from_parts(&[
            outcome.tx_hash.as_bytes(),
            receipt_hash.as_bytes(),
            &[if *success { 1u8 } else { 0u8 }],
        ]),
        ExecutionOutcome::Aborted => Hash::from_parts(&[outcome.tx_hash.as_bytes(), b"ABORTED:"]),
    }
}

/// Compute the receipt root from a list of transaction outcomes.
///
/// Uses padded merkle tree (power-of-2 padding with Hash::ZERO) so that
/// merkle inclusion proofs have a fixed `ceil(log2(N))` siblings.
///
/// Outcomes must be in wave order (= block order within the wave).
pub fn compute_global_receipt_root(outcomes: &[TxOutcome]) -> Hash {
    let leaves: Vec<Hash> = outcomes.iter().map(tx_outcome_leaf).collect();
    compute_padded_merkle_root(&leaves)
}

/// Compute receipt root and a merkle inclusion proof for a specific tx.
///
/// Returns `(root, proof_siblings, leaf_index, leaf_hash)`.
///
/// # Panics
///
/// Panics if `tx_index >= outcomes.len()` or `outcomes` is empty.
pub fn compute_global_receipt_root_with_proof(
    outcomes: &[TxOutcome],
    tx_index: usize,
) -> (Hash, Vec<Hash>, u32, Hash) {
    let leaves: Vec<Hash> = outcomes.iter().map(tx_outcome_leaf).collect();

    let leaf_hash = leaves[tx_index];
    let (root, siblings, leaf_index) = crate::compute_merkle_root_with_proof(&leaves, tx_index);
    (root, siblings, leaf_index, leaf_hash)
}

// ============================================================================
// WaveCertificate
// ============================================================================

/// Wave certificate — proof of execution finalization for a wave.
///
/// Contains the execution certificates from all participating shards.
/// Per-tx decisions (Accept/Reject/Aborted) are derived from the ECs.
/// Every wave resolves through the EC path — there is no all-abort fallback.
///
/// # Invariant (well-formed WC)
///
/// A well-formed WaveCertificate always contains the **local EC** — the EC
/// where `ec.wave_id == wc.wave_id`. The local EC is the authoritative source
/// for the wave's tx set and canonical (block) ordering. Remote ECs attest
/// against their own wave decompositions and may cover only subsets.
///
/// Enforced by `WaveCertificateTracker::create_wave_certificate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaveCertificate {
    /// Self-contained wave identifier (shard + height + remote dependencies).
    /// Globally unique. `hash(wave_id)` = identity key for manifest/storage.
    pub wave_id: WaveId,
    /// Execution certificates from all participating shards.
    /// Always includes the local EC (see invariant above).
    /// May contain multiple ECs from the same remote shard — this happens when
    /// a remote shard committed this wave's transactions across multiple blocks,
    /// producing separate ECs.
    /// Sorted by (shard_group_id, canonical_hash) for deterministic receipt_hash.
    pub execution_certificates: Vec<Arc<ExecutionCertificate>>,
}

impl WaveCertificate {
    /// Compute the receipt hash for this wave certificate.
    ///
    /// Hashes sorted (shard_group_id, canonical_hash) pairs. The vec is
    /// pre-sorted at construction time for deterministic ordering.
    /// canonical_hash already encodes the WaveId, vote_height,
    /// global_receipt_root, and all tx_outcomes — so this commits to
    /// the full content of every contributing EC.
    pub fn receipt_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        for ec in &self.execution_certificates {
            hasher.update(&basic_encode(&ec.shard_group_id()).unwrap());
            hasher.update(ec.canonical_hash().as_bytes());
        }
        Hash::from_hash_bytes(hasher.finalize().as_bytes())
    }

    /// Get the execution certificates.
    pub fn execution_certificates(&self) -> &[Arc<ExecutionCertificate>] {
        &self.execution_certificates
    }
}

// Manual SBOR implementation (since we need stable encoding)

impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for WaveCertificate
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(2)?;
        encoder.encode(&self.wave_id)?;
        // Encode Vec<Arc<ExecutionCertificate>> as Vec<ExecutionCertificate>
        encoder.write_value_kind(sbor::ValueKind::Array)?;
        encoder.write_value_kind(sbor::ValueKind::Tuple)?;
        encoder.write_size(self.execution_certificates.len())?;
        for ec in &self.execution_certificates {
            encoder.encode_deeper_body(ec.as_ref())?;
        }
        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for WaveCertificate
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 2 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 2,
                actual: length,
            });
        }
        let wave_id: WaveId = decoder.decode()?;
        // Decode Vec<ExecutionCertificate> into Vec<Arc<ExecutionCertificate>>
        decoder.read_and_check_value_kind(sbor::ValueKind::Array)?;
        decoder.read_and_check_value_kind(sbor::ValueKind::Tuple)?;
        let count = decoder.read_size()?;
        let mut execution_certificates = Vec::with_capacity(count);
        for _ in 0..count {
            let ec: ExecutionCertificate =
                decoder.decode_deeper_body_with_value_kind(sbor::ValueKind::Tuple)?;
            execution_certificates.push(Arc::new(ec));
        }
        Ok(Self {
            wave_id,
            execution_certificates,
        })
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for WaveCertificate {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for WaveCertificate {
    const TYPE_ID: sbor::RustTypeId =
        sbor::RustTypeId::novel_with_code("WaveCertificate", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

/// Encode a `Vec<Arc<WaveCertificate>>` as an SBOR array.
pub fn encode_wave_cert_vec<E: sbor::Encoder<sbor::NoCustomValueKind>>(
    encoder: &mut E,
    certs: &[Arc<WaveCertificate>],
) -> Result<(), sbor::EncodeError> {
    encoder.write_value_kind(sbor::ValueKind::Array)?;
    encoder.write_value_kind(sbor::ValueKind::Tuple)?;
    encoder.write_size(certs.len())?;
    for cert in certs {
        encoder.encode_deeper_body(cert.as_ref())?;
    }
    Ok(())
}

/// Decode a `Vec<Arc<WaveCertificate>>` from an SBOR array.
pub fn decode_wave_cert_vec<D: sbor::Decoder<sbor::NoCustomValueKind>>(
    decoder: &mut D,
    max_size: usize,
) -> Result<Vec<Arc<WaveCertificate>>, sbor::DecodeError> {
    decoder.read_and_check_value_kind(sbor::ValueKind::Array)?;
    decoder.read_and_check_value_kind(sbor::ValueKind::Tuple)?;
    let count = decoder.read_size()?;
    if count > max_size {
        return Err(sbor::DecodeError::UnexpectedSize {
            expected: max_size,
            actual: count,
        });
    }
    let mut certs = Vec::with_capacity(count);
    for _ in 0..count {
        let cert: WaveCertificate =
            decoder.decode_deeper_body_with_value_kind(sbor::ValueKind::Tuple)?;
        certs.push(Arc::new(cert));
    }
    Ok(certs)
}

/// Encode a `Vec<Arc<FinalizedWave>>` as an SBOR array.
pub fn encode_finalized_wave_vec<E: sbor::Encoder<sbor::NoCustomValueKind>>(
    encoder: &mut E,
    waves: &[Arc<FinalizedWave>],
) -> Result<(), sbor::EncodeError> {
    encoder.write_value_kind(sbor::ValueKind::Array)?;
    encoder.write_value_kind(sbor::ValueKind::Tuple)?;
    encoder.write_size(waves.len())?;
    for wave in waves {
        encoder.encode_deeper_body(wave.as_ref())?;
    }
    Ok(())
}

/// Decode a `Vec<Arc<FinalizedWave>>` from an SBOR array.
pub fn decode_finalized_wave_vec<D: sbor::Decoder<sbor::NoCustomValueKind>>(
    decoder: &mut D,
    max_size: usize,
) -> Result<Vec<Arc<FinalizedWave>>, sbor::DecodeError> {
    decoder.read_and_check_value_kind(sbor::ValueKind::Array)?;
    decoder.read_and_check_value_kind(sbor::ValueKind::Tuple)?;
    let count = decoder.read_size()?;
    if count > max_size {
        return Err(sbor::DecodeError::UnexpectedSize {
            expected: max_size,
            actual: count,
        });
    }
    let mut waves = Vec::with_capacity(count);
    for _ in 0..count {
        let wave: FinalizedWave =
            decoder.decode_deeper_body_with_value_kind(sbor::ValueKind::Tuple)?;
        waves.push(Arc::new(wave));
    }
    Ok(waves)
}

// ============================================================================
// FinalizedWave
// ============================================================================

/// A finalized wave — all participating shards have reported, WaveCertificate created.
///
/// Holds the wave certificate (which contains the execution certificates) plus the
/// receipt bundles produced by local execution. Receipts are written atomically
/// with the block at commit time (not fire-and-forget).
///
/// # Derived views
///
/// The wave's canonical tx list, ordering, and per-tx decisions are all **derived**
/// from the WaveCertificate, not stored alongside it. See:
/// - [`FinalizedWave::local_ec`] — the authoritative EC (where `ec.wave_id == wc.wave_id`)
/// - [`FinalizedWave::tx_hashes`] — iterator over the wave's tx hashes in block order
/// - [`FinalizedWave::tx_decisions`] — aggregated (Aborted > Reject > Accept) per tx
///
/// `receipts` contains only txs that actually executed (sparse subset of
/// `tx_hashes()`, same block order). Aborted txs produce no receipt.
///
/// Shared via `Arc` across the system — flows from execution state through
/// pending blocks, actions, and into the commit path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedWave {
    pub certificate: Arc<WaveCertificate>,
    /// Receipt bundles for txs that executed. Aborted txs are absent —
    /// `receipts.len() <= tx_count()`. Preserves canonical block order.
    /// Held in-memory until block commit, then written atomically with block metadata.
    pub receipts: Vec<ReceiptBundle>,
}

/// Reason a `FinalizedWave`'s receipts don't agree with its own EC.
/// Returned by [`FinalizedWave::validate_receipts_against_ec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptValidationError {
    /// The WaveCertificate has no EC whose `wave_id == wc.wave_id`.
    /// Every committed WC carries exactly one such "local" EC per the
    /// `create_wave_certificate` invariant; this indicates a malformed
    /// or tampered certificate.
    MissingLocalEc,
    /// A non-aborted `tx_outcome` has no corresponding receipt.
    MissingReceipt { tx_hash: Hash },
    /// A receipt's `tx_hash` doesn't match the expected position in
    /// canonical order.
    TxHashMismatch { expected: Hash, actual: Hash },
    /// A receipt's outcome (Success/Failure) disagrees with the EC's
    /// attested outcome for that tx.
    OutcomeMismatch {
        tx_hash: Hash,
        expected: TransactionOutcome,
        actual: TransactionOutcome,
    },
    /// More receipts than non-aborted outcomes.
    ExtraReceipt { tx_hash: Hash },
}

impl FinalizedWave {
    /// Get the wave ID from the certificate.
    pub fn wave_id(&self) -> &WaveId {
        &self.certificate.wave_id
    }

    /// Get the wave ID hash (used as key in pending block tracking).
    pub fn wave_id_hash(&self) -> Hash {
        self.certificate.wave_id.hash()
    }

    /// Get the execution certificates (from the wave certificate).
    pub fn execution_certificates(&self) -> &[Arc<ExecutionCertificate>] {
        &self.certificate.execution_certificates
    }

    /// The local shard's EC — authoritative for wave membership and ordering.
    ///
    /// A well-formed WaveCertificate has exactly one EC with `ec.wave_id == wc.wave_id`
    /// (invariant established by `WaveCertificateTracker::create_wave_certificate`
    /// and the endorsement + convergence gate).
    pub fn local_ec(&self) -> &ExecutionCertificate {
        self.certificate
            .execution_certificates
            .iter()
            .find(|ec| ec.wave_id == self.certificate.wave_id)
            .expect("WaveCertificate invariant: local EC must be present")
    }

    /// Number of transactions in this wave.
    pub fn tx_count(&self) -> usize {
        self.local_ec().tx_outcomes.len()
    }

    /// Iterator over the wave's tx hashes in canonical block order.
    pub fn tx_hashes(&self) -> impl Iterator<Item = Hash> + '_ {
        self.local_ec().tx_outcomes.iter().map(|o| o.tx_hash)
    }

    /// Whether the wave contains a given tx.
    pub fn contains_tx(&self, tx_hash: &Hash) -> bool {
        self.local_ec()
            .tx_outcomes
            .iter()
            .any(|o| &o.tx_hash == tx_hash)
    }

    /// Reconstruct a `FinalizedWave` from a `WaveCertificate` and a receipt lookup.
    ///
    /// Used on the storage/sync serving side to rebuild the in-memory shape
    /// from committed state. Walks the local EC's `tx_outcomes` (canonical block
    /// order) and fetches each receipt via `lookup`. Aborted txs are skipped —
    /// they produce no receipt (matches the shape in `execution::finalize_wave`).
    ///
    /// Returns `None` if:
    /// - The WaveCertificate lacks a local EC (malformed — should not happen
    ///   for a committed WC per the `create_wave_certificate` invariant).
    /// - Any non-aborted tx's receipt is missing from the lookup (peer/storage
    ///   has incomplete state — syncing peer should try a different source).
    pub fn reconstruct<F>(certificate: Arc<WaveCertificate>, mut lookup: F) -> Option<Self>
    where
        F: FnMut(&Hash) -> Option<Arc<LocalReceipt>>,
    {
        let local_ec = certificate
            .execution_certificates
            .iter()
            .find(|ec| ec.wave_id == certificate.wave_id)?;

        let mut receipts: Vec<ReceiptBundle> = Vec::with_capacity(local_ec.tx_outcomes.len());
        for outcome in &local_ec.tx_outcomes {
            match lookup(&outcome.tx_hash) {
                Some(receipt) => receipts.push(ReceiptBundle {
                    tx_hash: outcome.tx_hash,
                    local_receipt: receipt,
                    execution_output: None,
                }),
                None if outcome.is_aborted() => {}
                None => return None,
            }
        }

        Some(FinalizedWave {
            certificate,
            receipts,
        })
    }

    /// Validate that `receipts` are consistent with the local EC's
    /// `tx_outcomes`: exactly one receipt per non-aborted outcome, in
    /// tx_outcomes canonical order, with matching tx_hash and matching
    /// success/failure outcome.
    ///
    /// This does **not** verify `database_updates` or `writes_root` —
    /// `LocalReceipt` carries only shard-filtered writes, so the global
    /// `writes_root` the EC commits to can't be reconstructed from a
    /// local receipt alone. Use to catch gross drift (wrong tx, wrong
    /// success/fail, missing or surplus receipts) at peer-wave ingress.
    pub fn validate_receipts_against_ec(&self) -> Result<(), ReceiptValidationError> {
        let local_ec = self
            .certificate
            .execution_certificates
            .iter()
            .find(|ec| ec.wave_id == self.certificate.wave_id)
            .ok_or(ReceiptValidationError::MissingLocalEc)?;

        let mut receipt_iter = self.receipts.iter();
        for outcome in &local_ec.tx_outcomes {
            match outcome.outcome {
                ExecutionOutcome::Aborted => {
                    // Aborted outcomes carry no local receipt; skip.
                }
                ExecutionOutcome::Executed { success, .. } => {
                    let receipt =
                        receipt_iter
                            .next()
                            .ok_or(ReceiptValidationError::MissingReceipt {
                                tx_hash: outcome.tx_hash,
                            })?;
                    if receipt.tx_hash != outcome.tx_hash {
                        return Err(ReceiptValidationError::TxHashMismatch {
                            expected: outcome.tx_hash,
                            actual: receipt.tx_hash,
                        });
                    }
                    let expected = if success {
                        TransactionOutcome::Success
                    } else {
                        TransactionOutcome::Failure
                    };
                    if receipt.local_receipt.outcome != expected {
                        return Err(ReceiptValidationError::OutcomeMismatch {
                            tx_hash: outcome.tx_hash,
                            expected,
                            actual: receipt.local_receipt.outcome,
                        });
                    }
                }
            }
        }
        if let Some(extra) = receipt_iter.next() {
            return Err(ReceiptValidationError::ExtraReceipt {
                tx_hash: extra.tx_hash,
            });
        }
        Ok(())
    }

    /// Aggregate per-tx decisions across all ECs (Aborted > Reject > Accept).
    ///
    /// Iteration order follows the local EC's canonical (block) order.
    pub fn tx_decisions(&self) -> Vec<(Hash, TransactionDecision)> {
        let mut aborted: std::collections::HashSet<Hash> = std::collections::HashSet::new();
        let mut failure: std::collections::HashSet<Hash> = std::collections::HashSet::new();
        for ec in &self.certificate.execution_certificates {
            for outcome in &ec.tx_outcomes {
                if outcome.is_aborted() {
                    aborted.insert(outcome.tx_hash);
                }
                if !matches!(
                    outcome.outcome,
                    ExecutionOutcome::Executed { success: true, .. }
                ) {
                    failure.insert(outcome.tx_hash);
                }
            }
        }
        self.tx_hashes()
            .map(|h| {
                let d = if aborted.contains(&h) {
                    TransactionDecision::Aborted
                } else if failure.contains(&h) {
                    TransactionDecision::Reject
                } else {
                    TransactionDecision::Accept
                };
                (h, d)
            })
            .collect()
    }
}

// Manual SBOR implementation for FinalizedWave (Arc fields prevent BasicSbor derive).
// Encodes Arc<T> as T, decodes T and wraps in Arc.

impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for FinalizedWave
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(2)?;
        encoder.encode(self.certificate.as_ref())?;
        encoder.encode(&self.receipts)?;
        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for FinalizedWave
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 2 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 2,
                actual: length,
            });
        }
        let certificate: WaveCertificate = decoder.decode()?;
        let receipts: Vec<ReceiptBundle> = decoder.decode()?;
        Ok(Self {
            certificate: Arc::new(certificate),
            receipts,
        })
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for FinalizedWave {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for FinalizedWave {
    const TYPE_ID: sbor::RustTypeId = sbor::RustTypeId::novel_with_code("FinalizedWave", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_outcome(seed: u8) -> TxOutcome {
        TxOutcome {
            tx_hash: Hash::from_bytes(&[seed; 4]),
            outcome: ExecutionOutcome::Executed {
                receipt_hash: Hash::from_bytes(&[seed + 100; 4]),
                success: true,
            },
        }
    }

    fn make_wave_id(shard: u64, height: u64, remote: &[u64]) -> WaveId {
        WaveId {
            shard_group_id: ShardGroupId(shard),
            block_height: height,
            remote_shards: remote.iter().map(|&s| ShardGroupId(s)).collect(),
        }
    }

    #[test]
    fn test_wave_id_display() {
        let zero = make_wave_id(0, 42, &[]);
        assert_eq!(zero.to_string(), "Wave(shard=0, h=42, ∅)");

        let wave = make_wave_id(0, 42, &[2, 5]);
        assert_eq!(wave.to_string(), "Wave(shard=0, h=42, {2,5})");
    }

    #[test]
    fn test_wave_id_ordering() {
        let zero = make_wave_id(0, 42, &[]);
        let wave_a = make_wave_id(0, 42, &[1]);
        let wave_b = make_wave_id(0, 42, &[2]);
        let wave_ab = make_wave_id(0, 42, &[1, 2]);

        assert!(zero < wave_a);
        assert!(wave_a < wave_b);
        assert!(wave_a < wave_ab);
    }

    #[test]
    fn test_wave_id_hash_deterministic() {
        let w1 = make_wave_id(0, 42, &[1]);
        let w2 = make_wave_id(0, 42, &[1]);
        assert_eq!(w1.hash(), w2.hash());
        assert_ne!(w1.hash(), Hash::ZERO);
    }

    #[test]
    fn test_wave_id_hash_differs_by_height() {
        let w1 = make_wave_id(0, 42, &[1]);
        let w2 = make_wave_id(0, 43, &[1]);
        assert_ne!(w1.hash(), w2.hash());
    }

    #[test]
    fn test_global_receipt_root_deterministic() {
        let outcomes = vec![make_outcome(1), make_outcome(2), make_outcome(3)];
        let root1 = compute_global_receipt_root(&outcomes);
        let root2 = compute_global_receipt_root(&outcomes);
        assert_eq!(root1, root2);
        assert_ne!(root1, Hash::ZERO);
    }

    #[test]
    fn test_global_receipt_root_single_tx() {
        let outcomes = vec![make_outcome(1)];
        let root = compute_global_receipt_root(&outcomes);
        let expected = tx_outcome_leaf(&outcomes[0]);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_global_receipt_root_empty() {
        let root = compute_global_receipt_root(&[]);
        assert_eq!(root, Hash::ZERO);
    }

    #[test]
    fn test_global_receipt_root_order_matters() {
        let o1 = make_outcome(1);
        let o2 = make_outcome(2);

        let root_12 = compute_global_receipt_root(&[o1.clone(), o2.clone()]);
        let root_21 = compute_global_receipt_root(&[o2, o1]);
        assert_ne!(root_12, root_21);
    }

    #[test]
    fn test_merkle_proof_roundtrip() {
        let outcomes = vec![
            make_outcome(1),
            make_outcome(2),
            make_outcome(3),
            make_outcome(4),
            make_outcome(5),
        ];

        let root = compute_global_receipt_root(&outcomes);

        for i in 0..outcomes.len() {
            let (proof_root, siblings, leaf_index, leaf_hash) =
                compute_global_receipt_root_with_proof(&outcomes, i);

            assert_eq!(proof_root, root, "Root mismatch for index {i}");

            let expected_leaf = tx_outcome_leaf(&outcomes[i]);
            assert_eq!(leaf_hash, expected_leaf, "Leaf hash mismatch for index {i}");

            assert!(
                crate::verify_merkle_inclusion(root, leaf_hash, &siblings, leaf_index),
                "Proof failed for index {i}"
            );
        }
    }

    #[test]
    fn test_tx_outcome_leaf_success_matters() {
        let success = TxOutcome {
            tx_hash: Hash::from_bytes(b"tx"),
            outcome: ExecutionOutcome::Executed {
                receipt_hash: Hash::from_bytes(b"receipt"),
                success: true,
            },
        };
        let failure = TxOutcome {
            tx_hash: Hash::from_bytes(b"tx"),
            outcome: ExecutionOutcome::Executed {
                receipt_hash: Hash::from_bytes(b"receipt"),
                success: false,
            },
        };
        assert_ne!(tx_outcome_leaf(&success), tx_outcome_leaf(&failure));
    }

    #[test]
    fn test_tx_outcome_leaf_aborted_differs_from_executed() {
        let executed = TxOutcome {
            tx_hash: Hash::from_bytes(b"tx"),
            outcome: ExecutionOutcome::Executed {
                receipt_hash: Hash::from_bytes(b"receipt"),
                success: true,
            },
        };
        let aborted = TxOutcome {
            tx_hash: Hash::from_bytes(b"tx"),
            outcome: ExecutionOutcome::Aborted,
        };
        assert_ne!(tx_outcome_leaf(&executed), tx_outcome_leaf(&aborted));
    }

    fn make_test_ec(
        signers: SignerBitfield,
        signature: Bls12381G2Signature,
    ) -> ExecutionCertificate {
        ExecutionCertificate::new(
            make_wave_id(0, 10, &[1]),
            11,
            Hash::from_bytes(b"global_receipt_root"),
            vec![make_outcome(1), make_outcome(2)],
            signature,
            signers,
        )
    }

    #[test]
    fn test_canonical_hash_deterministic() {
        let signers = SignerBitfield::new(4);
        let sig = Bls12381G2Signature([0u8; 96]);
        let ec1 = make_test_ec(signers.clone(), sig);
        let ec2 = make_test_ec(signers, sig);
        assert_eq!(ec1.canonical_hash(), ec2.canonical_hash());
        assert_ne!(ec1.canonical_hash(), Hash::ZERO);
    }

    #[test]
    fn test_canonical_hash_signer_independent() {
        let mut signers_a = SignerBitfield::new(4);
        signers_a.set(0);
        signers_a.set(1);
        let sig_a = Bls12381G2Signature([1u8; 96]);

        let mut signers_b = SignerBitfield::new(4);
        signers_b.set(2);
        signers_b.set(3);
        let sig_b = Bls12381G2Signature([2u8; 96]);

        let ec_a = make_test_ec(signers_a, sig_a);
        let ec_b = make_test_ec(signers_b, sig_b);

        // Different signers + signatures → same canonical hash
        assert_eq!(ec_a.canonical_hash(), ec_b.canonical_hash());
    }

    fn make_test_wave_ec(shard: u64, seed: u8) -> Arc<ExecutionCertificate> {
        Arc::new(ExecutionCertificate::new(
            make_wave_id(shard, 42, &[1]),
            43,
            Hash::from_bytes(&[seed + 100; 4]),
            vec![make_outcome(seed)],
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        ))
    }

    #[test]
    fn test_receipt_hash_deterministic() {
        let wc = WaveCertificate {
            wave_id: make_wave_id(0, 42, &[1]),
            execution_certificates: vec![make_test_wave_ec(0, 1), make_test_wave_ec(1, 2)],
        };
        assert_eq!(wc.receipt_hash(), wc.receipt_hash());
        assert_ne!(wc.receipt_hash(), Hash::ZERO);
    }

    #[test]
    fn test_receipt_hash_changes_with_ec() {
        let wave_id = make_wave_id(0, 42, &[1]);
        let wc1 = WaveCertificate {
            wave_id: wave_id.clone(),
            execution_certificates: vec![make_test_wave_ec(0, 1)],
        };
        let wc2 = WaveCertificate {
            wave_id,
            execution_certificates: vec![make_test_wave_ec(0, 2)],
        };
        assert_ne!(wc1.receipt_hash(), wc2.receipt_hash());
    }

    #[test]
    fn test_wave_cert_sbor_roundtrip() {
        let wc = WaveCertificate {
            wave_id: make_wave_id(0, 42, &[1]),
            execution_certificates: vec![make_test_wave_ec(0, 1), make_test_wave_ec(1, 2)],
        };
        let encoded = basic_encode(&wc).unwrap();
        let decoded: WaveCertificate = basic_decode(&encoded).unwrap();
        assert_eq!(wc, decoded);
    }

    #[test]
    fn test_arc_vec_sbor_roundtrip() {
        let certs = vec![
            Arc::new(WaveCertificate {
                wave_id: make_wave_id(0, 42, &[1]),
                execution_certificates: vec![make_test_wave_ec(0, 1)],
            }),
            Arc::new(WaveCertificate {
                wave_id: WaveId {
                    shard_group_id: ShardGroupId(0),
                    block_height: 42,
                    remote_shards: BTreeSet::new(),
                },
                execution_certificates: vec![make_test_wave_ec(1, 3)],
            }),
        ];

        // Encode
        let mut buf = Vec::new();
        let mut encoder = sbor::BasicEncoder::new(&mut buf, sbor::BASIC_SBOR_V1_MAX_DEPTH);
        encode_wave_cert_vec(&mut encoder, &certs).unwrap();

        // Decode
        let mut decoder = sbor::BasicDecoder::new(&buf, sbor::BASIC_SBOR_V1_MAX_DEPTH);
        let decoded = decode_wave_cert_vec(&mut decoder, 100).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].as_ref(), certs[0].as_ref());
        assert_eq!(decoded[1].as_ref(), certs[1].as_ref());
    }

    #[test]
    fn test_wave_leader_is_attempt_zero() {
        let committee = vec![
            ValidatorId(1),
            ValidatorId(2),
            ValidatorId(3),
            ValidatorId(4),
        ];
        let wave_id = make_wave_id(0, 100, &[1]);
        assert_eq!(
            wave_leader(&wave_id, &committee),
            wave_leader_at(&wave_id, 0, &committee)
        );
    }

    #[test]
    fn test_wave_leader_at_rotates() {
        let committee = vec![
            ValidatorId(1),
            ValidatorId(2),
            ValidatorId(3),
            ValidatorId(4),
        ];
        let wave_id = make_wave_id(0, 100, &[1]);
        let mut leaders: std::collections::HashSet<ValidatorId> = std::collections::HashSet::new();
        for attempt in 0..4 {
            leaders.insert(wave_leader_at(&wave_id, attempt, &committee));
        }
        // With 4 attempts and 4 committee members, we should get multiple distinct leaders.
        // (Not guaranteed to be all 4 due to hash collisions, but at least 2.)
        assert!(
            leaders.len() >= 2,
            "Expected rotation to produce distinct leaders"
        );
    }

    #[test]
    fn test_wave_leader_at_wraps() {
        let committee = vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)];
        let wave_id = make_wave_id(0, 100, &[1]);
        // Large attempt values should not panic — they wrap via modulo.
        let _ = wave_leader_at(&wave_id, 1000, &committee);
    }

    #[test]
    fn test_wave_leader_deterministic() {
        let committee = vec![
            ValidatorId(1),
            ValidatorId(2),
            ValidatorId(3),
            ValidatorId(4),
        ];
        let wave_id = make_wave_id(0, 100, &[1]);
        let leader1 = wave_leader_at(&wave_id, 2, &committee);
        let leader2 = wave_leader_at(&wave_id, 2, &committee);
        assert_eq!(leader1, leader2);
    }

    // ─── FinalizedWave::reconstruct ────────────────────────────────────

    fn make_local_ec(wave_id: &WaveId, outcomes: Vec<TxOutcome>) -> Arc<ExecutionCertificate> {
        Arc::new(ExecutionCertificate::new(
            wave_id.clone(),
            wave_id.block_height + 1,
            compute_global_receipt_root(&outcomes),
            outcomes,
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        ))
    }

    fn make_success_receipt() -> Arc<LocalReceipt> {
        Arc::new(LocalReceipt {
            outcome: crate::TransactionOutcome::Success,
            database_updates: Default::default(),
            application_events: vec![],
        })
    }

    #[test]
    fn reconstruct_from_all_success_outcomes() {
        let wave_id = make_wave_id(0, 42, &[1]);
        let tx_a = Hash::from_bytes(b"tx_a");
        let tx_b = Hash::from_bytes(b"tx_b");

        let outcomes = vec![
            TxOutcome {
                tx_hash: tx_a,
                outcome: ExecutionOutcome::Executed {
                    receipt_hash: Hash::from_bytes(b"r_a"),
                    success: true,
                },
            },
            TxOutcome {
                tx_hash: tx_b,
                outcome: ExecutionOutcome::Executed {
                    receipt_hash: Hash::from_bytes(b"r_b"),
                    success: true,
                },
            },
        ];
        let wc = Arc::new(WaveCertificate {
            wave_id: wave_id.clone(),
            execution_certificates: vec![make_local_ec(&wave_id, outcomes)],
        });

        let fw = FinalizedWave::reconstruct(wc, |_| Some(make_success_receipt()))
            .expect("reconstruction should succeed");
        assert_eq!(fw.tx_count(), 2);
        let hashes: Vec<Hash> = fw.tx_hashes().collect();
        assert_eq!(hashes, vec![tx_a, tx_b]);
        assert_eq!(fw.receipts.len(), 2);
        assert_eq!(fw.receipts[0].tx_hash, tx_a);
        assert_eq!(fw.receipts[1].tx_hash, tx_b);
    }

    #[test]
    fn reconstruct_skips_aborted_tx_without_receipt() {
        let wave_id = make_wave_id(0, 42, &[1]);
        let tx_a = Hash::from_bytes(b"tx_a");
        let tx_b = Hash::from_bytes(b"tx_b_aborted");

        let outcomes = vec![
            TxOutcome {
                tx_hash: tx_a,
                outcome: ExecutionOutcome::Executed {
                    receipt_hash: Hash::from_bytes(b"r_a"),
                    success: true,
                },
            },
            TxOutcome {
                tx_hash: tx_b,
                outcome: ExecutionOutcome::Aborted,
            },
        ];
        let wc = Arc::new(WaveCertificate {
            wave_id: wave_id.clone(),
            execution_certificates: vec![make_local_ec(&wave_id, outcomes)],
        });

        // Lookup returns Some for tx_a, None for tx_b (never persisted — pure abort).
        let fw = FinalizedWave::reconstruct(wc, |h| {
            if *h == tx_a {
                Some(make_success_receipt())
            } else {
                None
            }
        })
        .expect("aborted tx without receipt should be skipped, not fail");

        assert_eq!(fw.tx_count(), 2);
        assert_eq!(fw.receipts.len(), 1);
        assert_eq!(fw.receipts[0].tx_hash, tx_a);
    }

    #[test]
    fn reconstruct_fails_when_non_aborted_receipt_missing() {
        let wave_id = make_wave_id(0, 42, &[1]);
        let tx_a = Hash::from_bytes(b"tx_a");

        let outcomes = vec![TxOutcome {
            tx_hash: tx_a,
            outcome: ExecutionOutcome::Executed {
                receipt_hash: Hash::from_bytes(b"r_a"),
                success: true,
            },
        }];
        let wc = Arc::new(WaveCertificate {
            wave_id: wave_id.clone(),
            execution_certificates: vec![make_local_ec(&wave_id, outcomes)],
        });

        // Lookup always returns None — but tx is not aborted, so failure synthesis
        // is not allowed.
        let fw = FinalizedWave::reconstruct(wc, |_| None);
        assert!(
            fw.is_none(),
            "reconstruction should fail when non-aborted receipt is missing"
        );
    }

    #[test]
    fn reconstruct_fails_when_local_ec_missing() {
        let wave_id = make_wave_id(0, 42, &[1]);
        // Only a remote EC (shard 1), no local EC matching wc.wave_id.
        let remote_wave_id = make_wave_id(1, 42, &[0]);
        let remote_ec = make_local_ec(
            &remote_wave_id,
            vec![TxOutcome {
                tx_hash: Hash::from_bytes(b"tx"),
                outcome: ExecutionOutcome::Aborted,
            }],
        );
        let wc = Arc::new(WaveCertificate {
            wave_id,
            execution_certificates: vec![remote_ec],
        });

        let fw = FinalizedWave::reconstruct(wc, |_| Some(make_success_receipt()));
        assert!(fw.is_none(), "reconstruction requires the local EC");
    }

    // ─── validate_receipts_against_ec ──────────────────────────────────────

    fn make_failure_receipt() -> Arc<LocalReceipt> {
        Arc::new(LocalReceipt {
            outcome: crate::TransactionOutcome::Failure,
            database_updates: Default::default(),
            application_events: vec![],
        })
    }

    #[test]
    fn validate_accepts_receipts_matching_outcomes() {
        let wave_id = make_wave_id(0, 42, &[1]);
        let tx_a = Hash::from_bytes(b"tx_a");
        let tx_b = Hash::from_bytes(b"tx_b_aborted");
        let tx_c = Hash::from_bytes(b"tx_c_fail");

        let outcomes = vec![
            TxOutcome {
                tx_hash: tx_a,
                outcome: ExecutionOutcome::Executed {
                    receipt_hash: Hash::ZERO,
                    success: true,
                },
            },
            TxOutcome {
                tx_hash: tx_b,
                outcome: ExecutionOutcome::Aborted,
            },
            TxOutcome {
                tx_hash: tx_c,
                outcome: ExecutionOutcome::Executed {
                    receipt_hash: Hash::ZERO,
                    success: false,
                },
            },
        ];
        let fw = FinalizedWave {
            certificate: Arc::new(WaveCertificate {
                wave_id: wave_id.clone(),
                execution_certificates: vec![make_local_ec(&wave_id, outcomes)],
            }),
            receipts: vec![
                ReceiptBundle {
                    tx_hash: tx_a,
                    local_receipt: make_success_receipt(),
                    execution_output: None,
                },
                ReceiptBundle {
                    tx_hash: tx_c,
                    local_receipt: make_failure_receipt(),
                    execution_output: None,
                },
            ],
        };
        assert_eq!(fw.validate_receipts_against_ec(), Ok(()));
    }

    #[test]
    fn validate_rejects_outcome_flip() {
        let wave_id = make_wave_id(0, 42, &[1]);
        let tx_a = Hash::from_bytes(b"tx_a");
        let outcomes = vec![TxOutcome {
            tx_hash: tx_a,
            outcome: ExecutionOutcome::Executed {
                receipt_hash: Hash::ZERO,
                success: true,
            },
        }];
        // EC says success but the receipt claims failure.
        let fw = FinalizedWave {
            certificate: Arc::new(WaveCertificate {
                wave_id: wave_id.clone(),
                execution_certificates: vec![make_local_ec(&wave_id, outcomes)],
            }),
            receipts: vec![ReceiptBundle {
                tx_hash: tx_a,
                local_receipt: make_failure_receipt(),
                execution_output: None,
            }],
        };
        assert!(matches!(
            fw.validate_receipts_against_ec(),
            Err(ReceiptValidationError::OutcomeMismatch { .. })
        ));
    }

    #[test]
    fn validate_rejects_missing_receipt() {
        let wave_id = make_wave_id(0, 42, &[1]);
        let tx_a = Hash::from_bytes(b"tx_a");
        let outcomes = vec![TxOutcome {
            tx_hash: tx_a,
            outcome: ExecutionOutcome::Executed {
                receipt_hash: Hash::ZERO,
                success: true,
            },
        }];
        let fw = FinalizedWave {
            certificate: Arc::new(WaveCertificate {
                wave_id: wave_id.clone(),
                execution_certificates: vec![make_local_ec(&wave_id, outcomes)],
            }),
            receipts: vec![], // non-aborted outcome without a receipt
        };
        assert!(matches!(
            fw.validate_receipts_against_ec(),
            Err(ReceiptValidationError::MissingReceipt { .. })
        ));
    }

    #[test]
    fn validate_rejects_extra_receipt() {
        let wave_id = make_wave_id(0, 42, &[1]);
        let tx_a = Hash::from_bytes(b"tx_a");
        let outcomes = vec![TxOutcome {
            tx_hash: tx_a,
            outcome: ExecutionOutcome::Aborted,
        }];
        let fw = FinalizedWave {
            certificate: Arc::new(WaveCertificate {
                wave_id: wave_id.clone(),
                execution_certificates: vec![make_local_ec(&wave_id, outcomes)],
            }),
            receipts: vec![ReceiptBundle {
                tx_hash: tx_a,
                local_receipt: make_success_receipt(),
                execution_output: None,
            }],
        };
        assert!(matches!(
            fw.validate_receipts_against_ec(),
            Err(ReceiptValidationError::ExtraReceipt { .. })
        ));
    }

    #[test]
    fn validate_rejects_tx_hash_mismatch() {
        let wave_id = make_wave_id(0, 42, &[1]);
        let tx_a = Hash::from_bytes(b"tx_a");
        let tx_b = Hash::from_bytes(b"tx_b");
        let outcomes = vec![TxOutcome {
            tx_hash: tx_a,
            outcome: ExecutionOutcome::Executed {
                receipt_hash: Hash::ZERO,
                success: true,
            },
        }];
        let fw = FinalizedWave {
            certificate: Arc::new(WaveCertificate {
                wave_id: wave_id.clone(),
                execution_certificates: vec![make_local_ec(&wave_id, outcomes)],
            }),
            receipts: vec![ReceiptBundle {
                tx_hash: tx_b, // wrong tx for this outcome slot
                local_receipt: make_success_receipt(),
                execution_output: None,
            }],
        };
        assert!(matches!(
            fw.validate_receipts_against_ec(),
            Err(ReceiptValidationError::TxHashMismatch { .. })
        ));
    }

    #[test]
    fn validate_rejects_missing_local_ec() {
        let wave_id = make_wave_id(0, 42, &[1]);
        let remote_wave_id = make_wave_id(1, 42, &[0]);
        let remote_ec = make_local_ec(&remote_wave_id, vec![]);
        let fw = FinalizedWave {
            certificate: Arc::new(WaveCertificate {
                wave_id, // differs from any EC's wave_id
                execution_certificates: vec![remote_ec],
            }),
            receipts: vec![],
        };
        assert_eq!(
            fw.validate_receipts_against_ec(),
            Err(ReceiptValidationError::MissingLocalEc)
        );
    }

    #[test]
    fn validate_all_aborted_wave_with_empty_receipts_passes() {
        let wave_id = make_wave_id(0, 42, &[1]);
        let outcomes = vec![TxOutcome {
            tx_hash: Hash::from_bytes(b"aborted"),
            outcome: ExecutionOutcome::Aborted,
        }];
        let fw = FinalizedWave {
            certificate: Arc::new(WaveCertificate {
                wave_id: wave_id.clone(),
                execution_certificates: vec![make_local_ec(&wave_id, outcomes)],
            }),
            receipts: vec![],
        };
        assert_eq!(fw.validate_receipts_against_ec(), Ok(()));
    }
}
