//! [`CertificateRoot`] verification.

use std::sync::Arc;

use thiserror::Error;

use crate::{
    CertificateRoot, FinalizedWave, Hash, Verifiable, Verified, Verify, compute_merkle_root,
};

/// Inputs the [`CertificateRoot`] verifier reads against.
#[derive(Debug, Clone, Copy)]
pub struct CertificateRootContext<'a> {
    /// The block's finalized wave certificates — each contributes one
    /// leaf (its `receipt_hash`) to the recomputed root.
    pub certificates: &'a [Arc<Verifiable<FinalizedWave>>],
}

/// Failure modes of [`CertificateRoot`] verification.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum CertRootVerifyError {
    /// The root computed from the supplied certificates does not match
    /// the claimed root.
    #[error("computed certificate root {computed:?} ≠ claimed {expected:?}")]
    Mismatch {
        /// Header's claimed root.
        expected: CertificateRoot,
        /// Root computed from the supplied certificates.
        computed: CertificateRoot,
    },
}

impl Verified<CertificateRoot> {
    /// Compute the certificate root from `certificates`. Verified by
    /// construction. Reads each wave's `receipt_hash` via the
    /// [`Verifiable`] `Deref` impl so callers can pass the
    /// `Block::Live.certificates` slice without unwrapping.
    #[must_use]
    pub fn compute(certificates: &[Arc<Verifiable<FinalizedWave>>]) -> Self {
        if certificates.is_empty() {
            return Self::new_unchecked(CertificateRoot::ZERO);
        }
        let leaves: Vec<Hash> = certificates
            .iter()
            .map(|fw| fw.certificate().receipt_hash().into_raw())
            .collect();
        Self::new_unchecked(CertificateRoot::from_raw(compute_merkle_root(&leaves)))
    }

    /// Pipeline-attestation gate for slot prefill. The trust source is
    /// the verification pipeline's per-root tracking: either the block
    /// carries no certificates (empty-input compute trivially matches
    /// `root`) or an earlier verifier run already accepted `root`.
    #[must_use]
    pub const fn from_pipeline_attestation(root: CertificateRoot) -> Self {
        Self::new_unchecked(root)
    }
}

/// Construction asserts: the wrapped [`CertificateRoot`] equals
/// `compute_merkle_root` of each underlying wave certificate's
/// `receipt_hash`, in block order.
impl Verify<&CertificateRootContext<'_>> for CertificateRoot {
    type Error = CertRootVerifyError;

    fn verify(&self, ctx: &CertificateRootContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let computed = *Verified::<Self>::compute(ctx.certificates).as_ref();
        if computed != *self {
            return Err(CertRootVerifyError::Mismatch {
                expected: *self,
                computed,
            });
        }
        Ok(Verified::new_unchecked(*self))
    }
}
