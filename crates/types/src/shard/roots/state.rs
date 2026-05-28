//! State-root verification typestate.
//!
//! [`StateRoot`] is verified by replaying a block's finalized waves
//! against the JMT rooted at the parent's state root and comparing the
//! resulting root against the header's claim. The JMT replay itself
//! happens inside the storage backend's `prepare_block_commit`; the
//! verifier here is a thin equality check that wraps the byproduct —
//! the prepared-commit closure — into the augment slot.
//!
//! Its verified form is `Verified<StateRoot, PreparedCommit>` — holding
//! one is type-level proof that the JMT was actually replayed, not just
//! that the claim was trusted. Predicate at
//! [`impl Verify<StateRootContext>`](Verify::verify) below.
//!
//! [`StateRoot`]: crate::StateRoot
//! [`PreparedCommit`]: crate::PreparedCommit

use thiserror::Error;

use crate::{PreparedCommit, StateRoot, Verified, Verify};

/// Inputs the [`StateRoot`] verifier checks against.
///
/// Built by the action handler after calling the backend's
/// `prepare_block_commit` — that call computes both the speculative
/// root and the [`PreparedCommit`] closure; the handler packs them in
/// here so the verifier can return either an error or the typed
/// `Verified<StateRoot, PreparedCommit>` augment.
///
/// [`StateRoot`]: crate::StateRoot
pub struct StateRootContext {
    /// Root produced by replaying the block's finalized waves against
    /// the JMT.
    pub computed_root: StateRoot,
    /// Closure carrying the precomputed commit work. Moves into the
    /// augment slot on success; the action handler hands it to the
    /// commit pipeline.
    pub prepared: PreparedCommit,
}

/// Failure modes of [`StateRoot`] verification.
///
/// [`StateRoot`]: crate::StateRoot
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum StateRootVerifyError {
    /// JMT replay computed a different root than the header claimed.
    /// Distinguishes a Byzantine proposer from an honest one; the
    /// receipt-root pre-flight check (run before this verifier on the
    /// shared dispatch path) already eliminates the
    /// receipts-don't-match case.
    #[error("computed state root {computed:?} ≠ claimed {expected:?}")]
    Mismatch {
        /// Header's claimed state root.
        expected: StateRoot,
        /// Root produced by replaying receipts against the JMT.
        computed: StateRoot,
    },
}

/// Construction asserts: the supplied `computed_root` (produced by
/// replaying the block's finalized waves against the JMT rooted at the
/// parent's state root) equals the wrapped [`StateRoot`]. The augment
/// carries the [`PreparedCommit`] closure from that replay, ready for
/// the commit pipeline to invoke without recomputing.
impl Verify<StateRootContext> for StateRoot {
    type Augment = PreparedCommit;
    type Error = StateRootVerifyError;

    fn verify(&self, ctx: StateRootContext) -> Result<Verified<Self, Self::Augment>, Self::Error> {
        if ctx.computed_root != *self {
            return Err(StateRootVerifyError::Mismatch {
                expected: *self,
                computed: ctx.computed_root,
            });
        }
        Ok(Verified::new_unchecked_with(*self, ctx.prepared))
    }
}
