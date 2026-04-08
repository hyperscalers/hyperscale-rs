//! Execution voting types and utilities.
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

use crate::{
    compute_padded_merkle_root, AbortReason, Bls12381G2Signature, Hash, NodeId,
    RoutableTransaction, ShardGroupId, SignerBitfield, TopologySnapshot, ValidatorId,
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

/// Deterministically select the wave leader for a wave.
///
/// The wave leader is the sole aggregator of execution votes into an EC.
/// Uses `Hash(sbor_encode(wave_id)) % committee_size` to pick one
/// validator. All validators compute the same result from the same inputs.
///
/// Since WaveId is self-contained (includes shard + height + remote shards),
/// no separate block_hash is needed.
pub fn wave_leader(wave_id: &WaveId, committee: &[ValidatorId]) -> ValidatorId {
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
// TxOutcome
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
    pub outcome: TxExecutionOutcome,
}

impl TxOutcome {
    /// Whether this outcome is an abort.
    pub fn is_aborted(&self) -> bool {
        matches!(self.outcome, TxExecutionOutcome::Aborted { .. })
    }
}

/// The outcome of executing a transaction on a single shard.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub enum TxExecutionOutcome {
    /// Transaction executed. `receipt_hash` is the hash of the execution receipt.
    /// `success=true` means the transaction's logic succeeded (writes applied).
    /// `success=false` means the transaction's logic failed (no writes).
    Executed {
        receipt_hash: Hash,
        success: bool,
        write_nodes: Vec<NodeId>,
    },
    /// Transaction aborted before execution could complete.
    /// Carries the reason so the TC can propagate it to all shards.
    Aborted { reason: AbortReason },
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
    /// Carried alongside the vote so the wave leader can extract tx_outcomes
    /// directly from quorum votes when building the EC. Not included in the
    /// BLS-signed message (global_receipt_root already commits to the content).
    /// This avoids relying on the wave leader's local accumulator, which may
    /// have diverged due to different abort intent timing.
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
        TxExecutionOutcome::Executed {
            receipt_hash,
            success,
            ..
        } => Hash::from_parts(&[
            outcome.tx_hash.as_bytes(),
            receipt_hash.as_bytes(),
            &[if *success { 1u8 } else { 0u8 }],
        ]),
        TxExecutionOutcome::Aborted { reason } => {
            let reason_bytes = basic_encode(reason).expect("SBOR encode of AbortReason");
            let mut parts =
                Vec::with_capacity(outcome.tx_hash.as_bytes().len() + 8 + reason_bytes.len());
            parts.extend_from_slice(outcome.tx_hash.as_bytes());
            parts.extend_from_slice(b"ABORTED:");
            parts.extend_from_slice(&reason_bytes);
            Hash::from_bytes(&parts)
        }
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
    let (root, proof) = crate::compute_merkle_root_with_proof(&leaves, tx_index);
    (root, proof.siblings, proof.leaf_index, leaf_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn make_outcome(seed: u8) -> TxOutcome {
        TxOutcome {
            tx_hash: Hash::from_bytes(&[seed; 4]),
            outcome: TxExecutionOutcome::Executed {
                receipt_hash: Hash::from_bytes(&[seed + 100; 4]),
                success: true,
                write_nodes: vec![],
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

            let inclusion = crate::TransactionInclusionProof {
                siblings,
                leaf_index,
            };
            assert!(
                crate::verify_merkle_inclusion(root, leaf_hash, &inclusion),
                "Proof failed for index {i}"
            );
        }
    }

    #[test]
    fn test_tx_outcome_leaf_success_matters() {
        let success = TxOutcome {
            tx_hash: Hash::from_bytes(b"tx"),
            outcome: TxExecutionOutcome::Executed {
                receipt_hash: Hash::from_bytes(b"receipt"),
                success: true,
                write_nodes: vec![],
            },
        };
        let failure = TxOutcome {
            tx_hash: Hash::from_bytes(b"tx"),
            outcome: TxExecutionOutcome::Executed {
                receipt_hash: Hash::from_bytes(b"receipt"),
                success: false,
                write_nodes: vec![],
            },
        };
        assert_ne!(tx_outcome_leaf(&success), tx_outcome_leaf(&failure));
    }

    #[test]
    fn test_tx_outcome_leaf_aborted_differs_from_executed() {
        let executed = TxOutcome {
            tx_hash: Hash::from_bytes(b"tx"),
            outcome: TxExecutionOutcome::Executed {
                receipt_hash: Hash::from_bytes(b"receipt"),
                success: true,
                write_nodes: vec![],
            },
        };
        let aborted = TxOutcome {
            tx_hash: Hash::from_bytes(b"tx"),
            outcome: TxExecutionOutcome::Aborted {
                reason: crate::AbortReason::ExecutionTimeout {
                    committed_at: crate::BlockHeight(10),
                },
            },
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
}
