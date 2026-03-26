//! Wave-based execution voting types and utilities.
//!
//! Waves are deterministic partitions of a block's transactions by their
//! provision dependency set (the set of remote shards they need provisions from).
//! All validators compute identical wave assignments from block contents, enabling
//! wave-level BLS signature aggregation instead of per-transaction signatures.
//!
//! # Wave Assignment
//!
//! - **Wave ∅** (ZERO): Single-shard txs — no provisions needed
//! - **Wave {B}**: Txs needing provisions only from shard B
//! - **Wave {B,C}**: Txs needing provisions from both B and C
//!
//! Tx ordering within a wave preserves block ordering (stable partition).

use crate::{
    compute_padded_merkle_root, Bls12381G2Signature, Hash, NodeId, ShardGroupId, SignerBitfield,
    ValidatorId,
};
use sbor::prelude::*;
use std::collections::BTreeSet;

// ============================================================================
// WaveId
// ============================================================================

/// Deterministic wave identifier = frozen provision dependency set.
///
/// The provision dependency set for a transaction is the set of remote shards
/// it needs state provisions from before execution. Transactions with identical
/// dependency sets belong to the same wave and can be voted on together.
///
/// `WaveId::ZERO` (empty set) represents single-shard transactions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, BasicSbor)]
pub struct WaveId(pub BTreeSet<ShardGroupId>);

impl WaveId {
    /// Wave zero: single-shard transactions with no provision dependencies.
    pub fn zero() -> Self {
        Self(BTreeSet::new())
    }

    /// Whether this is wave zero (single-shard, no provisions).
    pub fn is_zero(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of provision source shards.
    pub fn dependency_count(&self) -> usize {
        self.0.len()
    }
}

impl std::fmt::Display for WaveId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_zero() {
            write!(f, "Wave(∅)")
        } else {
            write!(f, "Wave{{")?;
            for (i, shard) in self.0.iter().enumerate() {
                if i > 0 {
                    write!(f, ",")?;
                }
                write!(f, "{}", shard.0)?;
            }
            write!(f, "}}")
        }
    }
}

// ============================================================================
// Wave Tx Outcome
// ============================================================================

/// Per-transaction execution outcome within a wave.
///
/// Carried inside wave certificates so remote shards can extract
/// individual transaction results for cross-shard finalization.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct WaveTxOutcome {
    /// Transaction hash.
    pub tx_hash: Hash,
    /// Receipt hash (hash of ConsensusReceipt).
    pub receipt_hash: Hash,
    /// Whether execution succeeded.
    pub success: bool,
    /// NodeIds written by this transaction (for speculative invalidation).
    pub write_nodes: Vec<NodeId>,
}

// ============================================================================
// Execution Wave Vote
// ============================================================================

/// A validator's vote on an entire execution wave.
///
/// Replaces per-transaction `ExecutionVote`. One wave vote covers all
/// transactions in the wave, reducing message count from O(txs) to O(waves).
/// The `wave_receipt_root` is a padded merkle root over per-tx leaf hashes,
/// where each leaf = H(tx_hash || receipt_hash || success_byte).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ExecutionWaveVote {
    /// Block this wave belongs to.
    pub block_hash: Hash,
    /// Block height.
    pub block_height: u64,
    /// Which wave within the block.
    pub wave_id: WaveId,
    /// Which shard produced this vote.
    pub shard_group_id: ShardGroupId,
    /// Merkle root over per-tx outcome leaves.
    pub wave_receipt_root: Hash,
    /// Number of transactions in this wave.
    pub tx_count: u32,
    /// Validator who cast this vote.
    pub validator: ValidatorId,
    /// BLS signature over the wave vote signing message.
    pub signature: Bls12381G2Signature,
}

// ============================================================================
// Execution Wave Certificate
// ============================================================================

/// Aggregated certificate for an entire execution wave.
///
/// Replaces per-transaction `ExecutionCertificate`. Contains the BLS
/// aggregated signature from 2f+1 validators plus per-tx outcomes so
/// remote shards can extract individual transaction results.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ExecutionWaveCertificate {
    /// Block this wave belongs to.
    pub block_hash: Hash,
    /// Block height.
    pub block_height: u64,
    /// Which wave within the block.
    pub wave_id: WaveId,
    /// Which shard produced this certificate.
    pub shard_group_id: ShardGroupId,
    /// Merkle root over per-tx outcome leaves.
    pub wave_receipt_root: Hash,
    /// Per-transaction outcomes (in wave order = block order).
    pub tx_outcomes: Vec<WaveTxOutcome>,
    /// BLS aggregated signature from 2f+1 validators.
    pub aggregated_signature: Bls12381G2Signature,
    /// Which validators signed (bitfield indexed by committee position).
    pub signers: SignerBitfield,
}

// ============================================================================
// TxWaveProof
// ============================================================================

/// Per-transaction proof extracted from a wave certificate.
///
/// Replaces `ExecutionCertificate` in `TransactionCertificate.shard_proofs`.
/// Contains a merkle inclusion proof linking the individual tx's outcome
/// to the wave's signed receipt root.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct TxWaveProof {
    /// Which shard produced this proof.
    pub shard_group_id: ShardGroupId,
    /// Receipt hash for this specific transaction.
    pub receipt_hash: Hash,
    /// Whether this transaction succeeded.
    pub success: bool,
    /// NodeIds written by this transaction.
    pub write_nodes: Vec<NodeId>,
    /// The wave's receipt root (what was actually signed).
    pub wave_receipt_root: Hash,
    /// Merkle inclusion proof: siblings from leaf to root.
    pub merkle_proof: Vec<Hash>,
    /// Leaf index in the padded merkle tree.
    pub leaf_index: u32,
    /// BLS aggregated signature over the wave vote message.
    pub aggregated_signature: Bls12381G2Signature,
    /// Which validators signed.
    pub signers: SignerBitfield,
}

// ============================================================================
// Wave Receipt Tree Utilities
// ============================================================================

/// Compute the leaf hash for a transaction outcome in the wave receipt tree.
///
/// Leaf = H(tx_hash || receipt_hash || success_byte)
pub fn wave_outcome_leaf(tx_hash: &Hash, receipt_hash: &Hash, success: bool) -> Hash {
    Hash::from_parts(&[
        tx_hash.as_bytes(),
        receipt_hash.as_bytes(),
        &[if success { 1u8 } else { 0u8 }],
    ])
}

/// Compute the wave receipt root from a list of transaction outcomes.
///
/// Uses padded merkle tree (power-of-2 padding with Hash::ZERO) so that
/// merkle inclusion proofs have a fixed `ceil(log2(N))` siblings.
///
/// Outcomes must be in wave order (= block order within the wave).
pub fn compute_wave_receipt_root(outcomes: &[WaveTxOutcome]) -> Hash {
    let leaves: Vec<Hash> = outcomes
        .iter()
        .map(|o| wave_outcome_leaf(&o.tx_hash, &o.receipt_hash, o.success))
        .collect();
    compute_padded_merkle_root(&leaves)
}

/// Compute wave receipt root and a merkle inclusion proof for a specific tx.
///
/// Returns `(root, proof_siblings, leaf_index, leaf_hash)`.
///
/// # Panics
///
/// Panics if `tx_index >= outcomes.len()` or `outcomes` is empty.
pub fn compute_wave_receipt_root_with_proof(
    outcomes: &[WaveTxOutcome],
    tx_index: usize,
) -> (Hash, Vec<Hash>, u32, Hash) {
    let leaves: Vec<Hash> = outcomes
        .iter()
        .map(|o| wave_outcome_leaf(&o.tx_hash, &o.receipt_hash, o.success))
        .collect();

    let (root, proof) = crate::compute_merkle_root_with_proof(&leaves, tx_index);
    (root, proof.siblings, proof.leaf_index, proof.leaf_hash)
}

/// Extract a `TxWaveProof` for a specific transaction from a wave certificate.
///
/// Computes the merkle inclusion proof from the wave's tx_outcomes.
///
/// # Panics
///
/// Panics if `tx_index >= cert.tx_outcomes.len()`.
pub fn extract_tx_wave_proof(cert: &ExecutionWaveCertificate, tx_index: usize) -> TxWaveProof {
    let outcome = &cert.tx_outcomes[tx_index];
    let (_root, siblings, leaf_index, _leaf_hash) =
        compute_wave_receipt_root_with_proof(&cert.tx_outcomes, tx_index);

    TxWaveProof {
        shard_group_id: cert.shard_group_id,
        receipt_hash: outcome.receipt_hash,
        success: outcome.success,
        write_nodes: outcome.write_nodes.clone(),
        wave_receipt_root: cert.wave_receipt_root,
        merkle_proof: siblings,
        leaf_index,
        aggregated_signature: cert.aggregated_signature,
        signers: cert.signers.clone(),
    }
}

/// Verify a `TxWaveProof` against the wave receipt root.
///
/// Reconstructs the merkle path from the leaf (computed from receipt_hash)
/// using the proof siblings, and checks it matches `wave_receipt_root`.
pub fn verify_tx_wave_proof(proof: &TxWaveProof, tx_hash: &Hash) -> bool {
    let leaf_hash = wave_outcome_leaf(tx_hash, &proof.receipt_hash, proof.success);
    let inclusion = crate::TransactionInclusionProof {
        siblings: proof.merkle_proof.clone(),
        leaf_index: proof.leaf_index,
        leaf_hash,
    };
    crate::verify_merkle_inclusion(proof.wave_receipt_root, &inclusion)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zero_bls_signature;

    fn make_outcome(seed: u8) -> WaveTxOutcome {
        WaveTxOutcome {
            tx_hash: Hash::from_bytes(&[seed; 4]),
            receipt_hash: Hash::from_bytes(&[seed + 100; 4]),
            success: true,
            write_nodes: vec![],
        }
    }

    #[test]
    fn test_wave_id_display() {
        assert_eq!(WaveId::zero().to_string(), "Wave(∅)");

        let wave = WaveId(BTreeSet::from([ShardGroupId(2), ShardGroupId(5)]));
        assert_eq!(wave.to_string(), "Wave{2,5}");
    }

    #[test]
    fn test_wave_id_ordering() {
        let zero = WaveId::zero();
        let wave_a = WaveId(BTreeSet::from([ShardGroupId(1)]));
        let wave_b = WaveId(BTreeSet::from([ShardGroupId(2)]));
        let wave_ab = WaveId(BTreeSet::from([ShardGroupId(1), ShardGroupId(2)]));

        assert!(zero < wave_a);
        assert!(wave_a < wave_b);
        assert!(wave_a < wave_ab);
    }

    #[test]
    fn test_wave_receipt_root_deterministic() {
        let outcomes = vec![make_outcome(1), make_outcome(2), make_outcome(3)];
        let root1 = compute_wave_receipt_root(&outcomes);
        let root2 = compute_wave_receipt_root(&outcomes);
        assert_eq!(root1, root2);
        assert_ne!(root1, Hash::ZERO);
    }

    #[test]
    fn test_wave_receipt_root_single_tx() {
        let outcomes = vec![make_outcome(1)];
        let root = compute_wave_receipt_root(&outcomes);
        // Single leaf: root should be the leaf hash itself
        let expected = wave_outcome_leaf(
            &outcomes[0].tx_hash,
            &outcomes[0].receipt_hash,
            outcomes[0].success,
        );
        assert_eq!(root, expected);
    }

    #[test]
    fn test_wave_receipt_root_empty() {
        let root = compute_wave_receipt_root(&[]);
        assert_eq!(root, Hash::ZERO);
    }

    #[test]
    fn test_wave_receipt_root_order_matters() {
        let o1 = make_outcome(1);
        let o2 = make_outcome(2);

        let root_12 = compute_wave_receipt_root(&[o1.clone(), o2.clone()]);
        let root_21 = compute_wave_receipt_root(&[o2, o1]);
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

        let root = compute_wave_receipt_root(&outcomes);

        // Verify proof for each tx
        for i in 0..outcomes.len() {
            let (proof_root, siblings, leaf_index, leaf_hash) =
                compute_wave_receipt_root_with_proof(&outcomes, i);

            assert_eq!(proof_root, root, "Root mismatch for index {i}");

            let expected_leaf = wave_outcome_leaf(
                &outcomes[i].tx_hash,
                &outcomes[i].receipt_hash,
                outcomes[i].success,
            );
            assert_eq!(leaf_hash, expected_leaf, "Leaf hash mismatch for index {i}");

            // Verify via inclusion proof
            let inclusion = crate::TransactionInclusionProof {
                siblings,
                leaf_index,
                leaf_hash,
            };
            assert!(
                crate::verify_merkle_inclusion(root, &inclusion),
                "Proof failed for index {i}"
            );
        }
    }

    #[test]
    fn test_extract_and_verify_tx_wave_proof() {
        let outcomes = vec![make_outcome(1), make_outcome(2), make_outcome(3)];
        let root = compute_wave_receipt_root(&outcomes);

        let cert = ExecutionWaveCertificate {
            block_hash: Hash::from_bytes(b"block"),
            block_height: 10,
            wave_id: WaveId::zero(),
            shard_group_id: ShardGroupId(0),
            wave_receipt_root: root,
            tx_outcomes: outcomes.clone(),
            aggregated_signature: zero_bls_signature(),
            signers: SignerBitfield::new(4),
        };

        for i in 0..outcomes.len() {
            let proof = extract_tx_wave_proof(&cert, i);
            assert_eq!(proof.receipt_hash, outcomes[i].receipt_hash);
            assert_eq!(proof.wave_receipt_root, root);
            assert!(verify_tx_wave_proof(&proof, &outcomes[i].tx_hash));
        }
    }

    #[test]
    fn test_tx_wave_proof_wrong_tx_hash_fails() {
        let outcomes = vec![make_outcome(1), make_outcome(2)];
        let root = compute_wave_receipt_root(&outcomes);

        let cert = ExecutionWaveCertificate {
            block_hash: Hash::from_bytes(b"block"),
            block_height: 10,
            wave_id: WaveId::zero(),
            shard_group_id: ShardGroupId(0),
            wave_receipt_root: root,
            tx_outcomes: outcomes,
            aggregated_signature: zero_bls_signature(),
            signers: SignerBitfield::new(4),
        };

        let proof = extract_tx_wave_proof(&cert, 0);
        // Verify with wrong tx_hash should fail
        let wrong_hash = Hash::from_bytes(b"wrong");
        assert!(!verify_tx_wave_proof(&proof, &wrong_hash));
    }

    #[test]
    fn test_wave_outcome_leaf_success_matters() {
        let tx = Hash::from_bytes(b"tx");
        let receipt = Hash::from_bytes(b"receipt");

        let leaf_true = wave_outcome_leaf(&tx, &receipt, true);
        let leaf_false = wave_outcome_leaf(&tx, &receipt, false);
        assert_ne!(leaf_true, leaf_false);
    }
}
