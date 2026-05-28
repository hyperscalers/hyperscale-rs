//! [`TransactionRoot`] verification.

use std::sync::Arc;

use thiserror::Error;

use crate::{
    Hash, RoutableTransaction, TransactionRoot, TxHash, Verified, Verify, WeightedTimestamp,
    compute_merkle_root,
};

/// Inputs the [`TransactionRoot`] verifier reads against.
#[derive(Debug, Clone, Copy)]
pub struct TransactionRootContext<'a> {
    /// The block's transactions — each contributes one leaf (its
    /// content hash) to the recomputed root.
    pub transactions: &'a [Arc<RoutableTransaction>],
    /// Parent QC's `weighted_timestamp` — the shard-consensus-authenticated
    /// clock for this block, used as the anchor every tx's `validity_range`
    /// must enclose. An honest cluster never sees a window mismatch here
    /// because the proposer applied the same check during transaction
    /// selection.
    pub validity_anchor: WeightedTimestamp,
}

/// Failure modes of [`TransactionRoot`] verification.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum TxRootVerifyError {
    /// The root computed from the supplied transactions does not match
    /// the claimed root.
    #[error("computed transaction root {computed:?} ≠ claimed {expected:?}")]
    Mismatch {
        /// Header's claimed root.
        expected: TransactionRoot,
        /// Root computed from the supplied transactions.
        computed: TransactionRoot,
    },
    /// A transaction's `validity_range` either was malformed or did not
    /// contain the parent QC's weighted timestamp.
    #[error(
        "tx {tx_hash:?} validity window {start_ms}..{end_ms} \
         does not contain anchor {anchor_ms}"
    )]
    ValidityWindowExpired {
        /// Hash of the offending transaction.
        tx_hash: TxHash,
        /// Anchor (parent QC's weighted timestamp) in millis.
        anchor_ms: u64,
        /// Start of the tx's validity window in millis (inclusive).
        start_ms: u64,
        /// End of the tx's validity window in millis (exclusive).
        end_ms: u64,
    },
}

impl Verified<TransactionRoot> {
    /// Pipeline-attestation gate for slot prefill. The trust source is
    /// the verification pipeline's per-root tracking: either the block
    /// carries no transactions (empty-input compute trivially matches
    /// `root`) or an earlier verifier run already accepted `root`.
    #[must_use]
    pub const fn from_pipeline_attestation(root: TransactionRoot) -> Self {
        Self::new_unchecked(root)
    }

    /// Compute the transaction root from `transactions`. Verified by
    /// construction.
    #[must_use]
    pub fn compute(transactions: &[Arc<RoutableTransaction>]) -> Self {
        if transactions.is_empty() {
            return Self::new_unchecked(TransactionRoot::ZERO);
        }
        let leaves: Vec<Hash> = transactions.iter().map(|tx| tx.hash().into_raw()).collect();
        // Use padded merkle root (power-of-2 padding with Hash::ZERO) so that
        // merkle inclusion proofs can be generated and verified for any leaf.
        Self::new_unchecked(TransactionRoot::from_raw(compute_merkle_root(&leaves)))
    }
}

/// Construction asserts both:
///
/// 1. The wrapped [`TransactionRoot`] equals `compute_merkle_root` of
///    each transaction's hash, in block order (already hash-ascending).
/// 2. Every transaction's `validity_range` is well-formed against and
///    contains the block's `validity_anchor` (the parent QC's
///    weighted timestamp).
impl Verify<&TransactionRootContext<'_>> for TransactionRoot {
    type Augment = ();
    type Error = TxRootVerifyError;

    fn verify(&self, ctx: &TransactionRootContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let computed = *Verified::<Self>::compute(ctx.transactions).as_ref();
        if computed != *self {
            return Err(TxRootVerifyError::Mismatch {
                expected: *self,
                computed,
            });
        }
        for tx in ctx.transactions {
            let range = tx.validity_range();
            if !range.is_well_formed(ctx.validity_anchor) || !range.contains(ctx.validity_anchor) {
                return Err(TxRootVerifyError::ValidityWindowExpired {
                    tx_hash: tx.hash(),
                    anchor_ms: ctx.validity_anchor.as_millis(),
                    start_ms: range.start_timestamp_inclusive.as_millis(),
                    end_ms: range.end_timestamp_exclusive.as_millis(),
                });
            }
        }
        Ok(Verified::new_unchecked(*self))
    }
}
