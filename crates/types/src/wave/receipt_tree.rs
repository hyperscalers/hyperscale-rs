//! Receipt tree leaves and `global_receipt_root` computation/proof helpers.

use crate::{ExecutionOutcome, GlobalReceiptRoot, Hash, TxOutcome, compute_padded_merkle_root};

/// Compute the leaf hash for a transaction outcome in the receipt tree.
///
/// For executed outcomes: Leaf = `H(tx_hash` || `receipt_hash` || `success_byte`)
/// For aborted outcomes: Leaf = `H(tx_hash` || "ABORTED:" || `sbor_encode(reason)`)
///
/// The domain tag `b"ABORTED:"` ensures abort leaves can never collide with
/// executed leaves.
#[must_use]
pub fn tx_outcome_leaf(outcome: &TxOutcome) -> Hash {
    match &outcome.outcome {
        ExecutionOutcome::Executed {
            receipt_hash,
            success,
            ..
        } => Hash::from_parts(&[
            outcome.tx_hash.as_bytes(),
            receipt_hash.as_bytes(),
            &[u8::from(*success)],
        ]),
        ExecutionOutcome::Aborted => Hash::from_parts(&[outcome.tx_hash.as_bytes(), b"ABORTED:"]),
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
    GlobalReceiptRoot::from_raw(compute_padded_merkle_root(&leaves))
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
