//! Merkle root computation helpers for the per-block fields in [`BlockHeader`].

use crate::{
    CertificateRoot, FinalizedWave, Hash, LocalReceiptRoot, ProvisionsRoot, ReceiptBundle,
    RoutableTransaction, TransactionRoot, compute_merkle_root, compute_padded_merkle_root,
};
use std::sync::Arc;

/// Compute the receipt merkle root for a block's finalized waves.
///
/// Each underlying wave certificate's `receipt_hash` becomes a leaf.
/// Returns `Hash::ZERO` if there are no certificates.
#[must_use]
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
/// Each receipt's `receipt_hash()` (includes outcome + events + `database_updates`)
/// becomes a leaf. Receipts are sorted by `tx_hash` before computing the root
/// to ensure determinism regardless of collection order (e.g. `HashMap` iteration).
/// Returns `Hash::ZERO` if there are no receipts.
#[must_use]
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
#[must_use]
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
