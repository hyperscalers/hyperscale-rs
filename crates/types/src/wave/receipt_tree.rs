//! Receipt tree leaves and `global_receipt_root` computation/proof helpers.

use crate::{
    ExecutionOutcome, GlobalReceiptRoot, Hash, TxOutcome, compute_merkle_root,
    compute_merkle_root_with_proof,
};

/// Compute the leaf hash for a transaction outcome in the receipt tree.
///
/// - `Succeeded`: `H(tx_hash || receipt_hash)`
/// - `Failed`:    `H(tx_hash || b"FAILED:")` (domain-tagged; canonical hash is implicit)
/// - `Aborted`:   `H(tx_hash || b"ABORTED:")`
///
/// The domain tags ensure the three variants can never collide.
#[must_use]
pub fn tx_outcome_leaf(outcome: &TxOutcome) -> Hash {
    match outcome.outcome() {
        ExecutionOutcome::Succeeded { receipt_hash } => {
            Hash::from_parts(&[outcome.tx_hash().as_bytes(), receipt_hash.as_bytes()])
        }
        ExecutionOutcome::Failed => Hash::from_parts(&[outcome.tx_hash().as_bytes(), b"FAILED:"]),
        ExecutionOutcome::Aborted => Hash::from_parts(&[outcome.tx_hash().as_bytes(), b"ABORTED:"]),
    }
}

/// Compute the receipt root from a list of transaction outcomes.
///
/// Uses padded merkle tree (power-of-2 padding with `Hash::ZERO`) so that
/// merkle inclusion proofs have a fixed `ceil(log2(N))` siblings.
///
/// Outcomes must be in wave order (= block order within the wave).
pub fn compute_global_receipt_root(outcomes: &[TxOutcome]) -> GlobalReceiptRoot {
    let leaves: Vec<Hash> = outcomes.iter().map(tx_outcome_leaf).collect();
    GlobalReceiptRoot::from_raw(compute_merkle_root(&leaves))
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
    let (root, siblings, leaf_index) = compute_merkle_root_with_proof(&leaves, tx_index);
    (root, siblings, leaf_index, leaf_hash)
}
