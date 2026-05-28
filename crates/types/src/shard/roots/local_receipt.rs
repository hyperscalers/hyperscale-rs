//! [`LocalReceiptRoot`] verification.

use thiserror::Error;

use crate::{Hash, LocalReceiptRoot, StoredReceipt, Verified, Verify, compute_merkle_root};

/// Inputs the [`LocalReceiptRoot`] verifier reads against.
#[derive(Debug, Clone, Copy)]
pub struct LocalReceiptRootContext<'a> {
    /// The block's stored receipts — each contributes one leaf
    /// (`local_receipt_hash`) to the recomputed root.
    pub receipts: &'a [StoredReceipt],
}

/// Failure modes of [`LocalReceiptRoot`] verification.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum LocalReceiptRootVerifyError {
    /// The root computed from the supplied receipts does not match the
    /// claimed root.
    #[error("computed local receipt root {computed:?} ≠ claimed {expected:?}")]
    Mismatch {
        /// Header's claimed root.
        expected: LocalReceiptRoot,
        /// Root computed from the supplied receipts.
        computed: LocalReceiptRoot,
    },
}

impl Verified<LocalReceiptRoot> {
    /// Pipeline-attestation gate for slot prefill. The trust source is
    /// the verification pipeline's per-root tracking: either the block
    /// carries no certificates (empty-input compute trivially matches
    /// `root`) or an earlier verifier run already accepted `root`.
    #[must_use]
    pub const fn from_pipeline_attestation(root: LocalReceiptRoot) -> Self {
        Self::new_unchecked(root)
    }

    /// Compute the local-receipt root from `receipts`. Verified by
    /// construction.
    #[must_use]
    pub fn compute(receipts: &[StoredReceipt]) -> Self {
        if receipts.is_empty() {
            return Self::new_unchecked(LocalReceiptRoot::ZERO);
        }
        let leaves: Vec<Hash> = receipts
            .iter()
            .map(|r| r.consensus.local_receipt_hash())
            .collect();
        Self::new_unchecked(LocalReceiptRoot::from_raw(compute_merkle_root(&leaves)))
    }
}

/// Construction asserts: the wrapped [`LocalReceiptRoot`] equals
/// `compute_merkle_root` of each receipt's `local_receipt_hash`, in
/// block order.
impl Verify<&LocalReceiptRootContext<'_>> for LocalReceiptRoot {
    type Augment = ();
    type Error = LocalReceiptRootVerifyError;

    fn verify(&self, ctx: &LocalReceiptRootContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let computed = *Verified::<Self>::compute(ctx.receipts).as_ref();
        if computed != *self {
            return Err(LocalReceiptRootVerifyError::Mismatch {
                expected: *self,
                computed,
            });
        }
        Ok(Verified::new_unchecked(*self))
    }
}
