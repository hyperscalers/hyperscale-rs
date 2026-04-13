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
//! 4. [`ShardAttestation`] / [`WaveCertificate`] — cross-shard proof of finalization
//! 5. [`FinalizedWave`] — all data needed for block commit

use crate::{
    compute_padded_merkle_root, Bls12381G2Signature, Hash, ReceiptBundle, RoutableTransaction,
    ShardGroupId, SignerBitfield, TopologySnapshot, TransactionDecision, ValidatorId,
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

/// Derive the transaction hashes belonging to a wave, given the source block's transactions.
///
/// This is the inverse of `compute_waves`: given a `WaveId` and the block's transactions,
/// return the tx_hashes that belong to that wave. Deterministic — any node with the
/// source block can re-derive the same result.
///
/// The WaveId is self-contained (`shard_group_id` + `block_height` + `remote_shards`),
/// so no separate block hash is needed. The caller is responsible for providing the
/// correct block's transactions (the block at `wave_id.block_height` on
/// `wave_id.shard_group_id`'s chain).
pub fn derive_wave_tx_hashes(
    topology: &TopologySnapshot,
    wave_id: &WaveId,
    transactions: &[Arc<RoutableTransaction>],
) -> Vec<Hash> {
    let local_shard = wave_id.shard_group_id;
    transactions
        .iter()
        .filter(|tx| {
            let remote_shards: BTreeSet<ShardGroupId> = topology
                .all_shards_for_transaction(tx)
                .into_iter()
                .filter(|&s| s != local_shard)
                .collect();
            remote_shards == wave_id.remote_shards
        })
        .map(|tx| tx.hash())
        .collect()
}

/// Deterministically select the designated broadcaster for a wave.
///
/// The designated broadcaster sends the aggregated EC to remote shards.
/// Uses `Hash(sbor_encode(wave_id)) % committee_size` to pick one
/// validator. All validators compute the same result from the same inputs.
///
/// Since WaveId is self-contained (includes shard + height + remote shards),
/// no separate block_hash is needed.
pub fn designated_broadcaster(wave_id: &WaveId, committee: &[ValidatorId]) -> ValidatorId {
    assert!(!committee.is_empty(), "committee must not be empty");
    let wave_bytes = basic_encode(wave_id).expect("WaveId serialization should never fail");
    let selection_hash = Hash::from_bytes(&wave_bytes);
    // Use first 8 bytes as u64 for index selection
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
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
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
}

impl ExecutionCertificate {
    /// The shard that produced this certificate.
    pub fn shard_group_id(&self) -> ShardGroupId {
        self.wave_id.shard_group_id
    }

    /// Block height (the block containing the wave's transactions).
    pub fn block_height(&self) -> u64 {
        self.wave_id.block_height
    }

    /// Compute the canonical hash of this certificate.
    ///
    /// Hashes only the deterministic execution-result fields, **excluding**
    /// `aggregated_signature` and `signers`. Different validators aggregate
    /// different 2f+1 subsets of votes, producing different signatures for the
    /// same wave — the canonical hash identifies the *logical* EC so that any
    /// valid aggregation resolves to the same hash.
    pub fn canonical_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&basic_encode(&self.wave_id).unwrap());
        hasher.update(&self.vote_height.to_le_bytes());
        hasher.update(self.global_receipt_root.as_bytes());
        hasher.update(&basic_encode(&self.tx_outcomes).unwrap());
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
/// Contains only shard attestations (proof half). Per-tx decisions
/// (Accept/Reject/Aborted) are derived from the ECs referenced by
/// the attestations. Every wave resolves through the EC path — there
/// is no all-abort fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaveCertificate {
    /// Self-contained wave identifier (shard + height + remote dependencies).
    /// Globally unique. `hash(wave_id)` = identity key for manifest/storage.
    pub wave_id: WaveId,
    /// Shard attestations proving execution finalization.
    /// May contain multiple attestations from the same shard — this happens when
    /// a remote shard committed this wave's transactions across multiple blocks,
    /// producing separate ECs.
    /// Sorted by (shard_group_id, ec_hash) for deterministic receipt_hash.
    pub attestations: Vec<ShardAttestation>,
}

/// Proof half of an execution certificate from a single shard.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ShardAttestation {
    /// Which shard produced this EC.
    pub shard_group_id: ShardGroupId,
    /// Canonical hash of the EC this attestation came from.
    pub ec_hash: Hash,
    /// Vote height at which the EC was aggregated.
    pub vote_height: u64,
    /// Merkle root over per-tx outcome leaves in the EC.
    pub global_receipt_root: Hash,
    /// BLS aggregated signature from 2f+1 validators on this shard.
    pub aggregated_signature: Bls12381G2Signature,
    /// Which validators signed (bitfield indexed by committee position).
    pub signers: SignerBitfield,
}

impl WaveCertificate {
    /// Compute the receipt hash for this wave certificate.
    ///
    /// Hashes sorted (shard_group_id, ec_hash) pairs. The vec is pre-sorted
    /// at construction time for deterministic ordering. ec_hash already encodes
    /// the WaveId, vote_height, global_receipt_root, and all tx_outcomes — so
    /// this commits to the full content of every contributing EC.
    pub fn receipt_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        for att in &self.attestations {
            hasher.update(&basic_encode(&att.shard_group_id).unwrap());
            hasher.update(att.ec_hash.as_bytes());
        }
        Hash::from_hash_bytes(hasher.finalize().as_bytes())
    }

    /// Get attestations.
    pub fn attestations(&self) -> &[ShardAttestation] {
        &self.attestations
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
        encoder.encode(&self.attestations)?;
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
        let attestations: Vec<ShardAttestation> = decoder.decode()?;
        Ok(Self {
            wave_id,
            attestations,
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

// ============================================================================
// FinalizedWave
// ============================================================================

/// A finalized wave — all participating shards have reported, WaveCertificate created.
///
/// Holds all data needed for block commit: the wave certificate, execution certificates,
/// per-tx decisions, and receipt bundles. Receipts are written atomically with the
/// block at commit time (not fire-and-forget).
///
/// Shared via `Arc` across the system — flows from execution state through
/// pending blocks, actions, and into the commit path.
#[derive(Debug, Clone)]
pub struct FinalizedWave {
    pub certificate: Arc<WaveCertificate>,
    pub tx_hashes: Vec<Hash>,
    pub execution_certificates: Vec<Arc<ExecutionCertificate>>,
    /// Per-transaction decisions: (tx_hash, decision).
    pub tx_decisions: Vec<(Hash, TransactionDecision)>,
    /// Receipt bundles for all transactions in this wave.
    /// Held in-memory until block commit, then written atomically with block metadata.
    pub receipts: Vec<ReceiptBundle>,
    pub finalized_height: u64,
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
        encoder.write_size(6)?;
        encoder.encode(self.certificate.as_ref())?;
        encoder.encode(&self.tx_hashes)?;
        // Encode Vec<Arc<ExecutionCertificate>> as Vec<ExecutionCertificate>
        encoder.encode(&self.execution_certificates.len())?;
        for ec in &self.execution_certificates {
            encoder.encode(ec.as_ref())?;
        }
        encoder.encode(&self.tx_decisions)?;
        encoder.encode(&self.receipts)?;
        encoder.encode(&self.finalized_height)?;
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
        if length != 6 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 6,
                actual: length,
            });
        }
        let certificate: WaveCertificate = decoder.decode()?;
        let tx_hashes: Vec<Hash> = decoder.decode()?;
        let ec_count: usize = decoder.decode()?;
        let mut execution_certificates = Vec::with_capacity(ec_count);
        for _ in 0..ec_count {
            let ec: ExecutionCertificate = decoder.decode()?;
            execution_certificates.push(Arc::new(ec));
        }
        let tx_decisions: Vec<(Hash, TransactionDecision)> = decoder.decode()?;
        let receipts: Vec<ReceiptBundle> = decoder.decode()?;
        let finalized_height: u64 = decoder.decode()?;
        Ok(Self {
            certificate: Arc::new(certificate),
            tx_hashes,
            execution_certificates,
            tx_decisions,
            receipts,
            finalized_height,
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
        ExecutionCertificate {
            wave_id: make_wave_id(0, 10, &[1]),
            vote_height: 11,
            global_receipt_root: Hash::from_bytes(b"global_receipt_root"),
            tx_outcomes: vec![make_outcome(1), make_outcome(2)],
            aggregated_signature: signature,
            signers,
        }
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

    fn make_test_attestation(shard: u64, ec_hash_seed: u8) -> ShardAttestation {
        ShardAttestation {
            shard_group_id: ShardGroupId(shard),
            ec_hash: Hash::from_bytes(&[ec_hash_seed; 4]),
            vote_height: 43,
            global_receipt_root: Hash::from_bytes(&[ec_hash_seed + 100; 4]),
            aggregated_signature: Bls12381G2Signature([0u8; 96]),
            signers: SignerBitfield::new(4),
        }
    }

    #[test]
    fn test_receipt_hash_deterministic() {
        let wc = WaveCertificate {
            wave_id: make_wave_id(0, 42, &[1]),
            attestations: vec![make_test_attestation(0, 1), make_test_attestation(1, 2)],
        };
        assert_eq!(wc.receipt_hash(), wc.receipt_hash());
        assert_ne!(wc.receipt_hash(), Hash::ZERO);
    }

    #[test]
    fn test_receipt_hash_changes_with_ec_hash() {
        let wave_id = make_wave_id(0, 42, &[1]);
        let wc1 = WaveCertificate {
            wave_id: wave_id.clone(),
            attestations: vec![make_test_attestation(0, 1)],
        };
        let wc2 = WaveCertificate {
            wave_id,
            attestations: vec![make_test_attestation(0, 2)],
        };
        assert_ne!(wc1.receipt_hash(), wc2.receipt_hash());
    }

    #[test]
    fn test_wave_cert_sbor_roundtrip() {
        let wc = WaveCertificate {
            wave_id: make_wave_id(0, 42, &[1]),
            attestations: vec![make_test_attestation(0, 1), make_test_attestation(1, 2)],
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
                attestations: vec![make_test_attestation(0, 1)],
            }),
            Arc::new(WaveCertificate {
                wave_id: WaveId {
                    shard_group_id: ShardGroupId(0),
                    block_height: 42,
                    remote_shards: BTreeSet::new(),
                },
                attestations: vec![make_test_attestation(1, 3)],
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
}
