//! [`ProvisionsRoot`] verification.

use thiserror::Error;

use crate::{Hash, ProvisionsRoot, Verified, Verify, compute_merkle_root};

/// Inputs the [`ProvisionsRoot`] verifier reads against.
#[derive(Debug, Clone, Copy)]
pub struct ProvisionsRootContext<'a> {
    /// Provision-batch hashes in block order — each contributes one
    /// leaf to the recomputed root.
    pub batch_hashes: &'a [Hash],
}

/// Failure modes of [`ProvisionsRoot`] verification.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum ProvisionRootVerifyError {
    /// The root computed from the supplied provision-batch hashes does
    /// not match the claimed root.
    #[error("computed provision root {computed:?} ≠ claimed {expected:?}")]
    Mismatch {
        /// Header's claimed root.
        expected: ProvisionsRoot,
        /// Root computed from the supplied batch hashes.
        computed: ProvisionsRoot,
    },
}

impl Verified<ProvisionsRoot> {
    /// Pipeline-attestation gate for slot prefill. The trust source is
    /// the verification pipeline's per-root tracking: either the block
    /// carries no provisions (header claims `ProvisionsRoot::ZERO`) or
    /// an earlier verifier run already accepted `root`.
    #[must_use]
    pub const fn from_pipeline_attestation(root: ProvisionsRoot) -> Self {
        Self::new_unchecked(root)
    }

    /// Compute the provisions root from `batch_hashes`. Verified by
    /// construction.
    #[must_use]
    pub fn compute(batch_hashes: &[Hash]) -> Self {
        if batch_hashes.is_empty() {
            return Self::new_unchecked(ProvisionsRoot::ZERO);
        }
        Self::new_unchecked(ProvisionsRoot::from_raw(compute_merkle_root(batch_hashes)))
    }
}

/// Construction asserts: the wrapped [`ProvisionsRoot`] equals
/// `compute_merkle_root` of the batch hashes in block order.
impl Verify<&ProvisionsRootContext<'_>> for ProvisionsRoot {
    type Augment = ();
    type Error = ProvisionRootVerifyError;

    fn verify(&self, ctx: &ProvisionsRootContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let computed = *Verified::<Self>::compute(ctx.batch_hashes).as_ref();
        if computed != *self {
            return Err(ProvisionRootVerifyError::Mismatch {
                expected: *self,
                computed,
            });
        }
        Ok(Verified::new_unchecked(*self))
    }
}
