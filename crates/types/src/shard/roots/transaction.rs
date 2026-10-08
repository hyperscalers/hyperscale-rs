//! [`TransactionRoot`]: the padded merkle root over a block's
//! transactions, one leaf per transaction hash.

use std::sync::Arc;

use crate::{Hash, Transaction, TransactionRoot, Verifiable, Verified, compute_merkle_root};

impl Verified<TransactionRoot> {
    /// Compute the transaction root from `transactions`. Verified by
    /// construction.
    #[must_use]
    pub fn compute(transactions: &[Arc<Verifiable<Transaction>>]) -> Self {
        if transactions.is_empty() {
            return Self::new_unchecked(TransactionRoot::ZERO);
        }
        let leaves: Vec<Hash> = transactions
            .iter()
            .map(|tx| Hash::from(tx.hash()))
            .collect();
        // Use padded merkle root (power-of-2 padding with Hash::ZERO) so that
        // merkle inclusion proofs can be generated and verified for any leaf.
        Self::new_unchecked(TransactionRoot::from_raw(compute_merkle_root(&leaves)))
    }
}
