//! State-root verification typestate.
//!
//! [`StateRoot`] is verified by replaying a block's finalized waves
//! against the JMT rooted at the parent's state root and comparing the
//! resulting root against the header's claim. The verification reads
//! from storage (via [`ShardChainWriter::prepare_block_commit`]) and
//! produces a side artifact — the prepared-commit handle — that the
//! commit pipeline reuses so it doesn't have to redo the JMT replay.
//!
//! Its verified form is `Verified<StateRoot, S::PreparedCommit>` —
//! holding one is type-level proof that the JMT was actually replayed,
//! not just that the claim was trusted. The prepared-commit handle
//! rides in the augment slot. Predicate at
//! [`impl Verify<&StateRootContext<'_, S>>`](Verify::verify) below.

use std::sync::Arc;

use hyperscale_types::{BlockHeight, FinalizedWave, StateRoot, Verified, Verify};
use thiserror::Error;

use crate::shard::pending_chain::BaseReadCache;
use crate::tree::JmtSnapshot;
use crate::{ShardChainWriter, SubstateStore};

/// Inputs the [`StateRoot`] verifier reads against.
pub struct StateRootContext<'a, S> {
    /// Storage backend exposing [`ShardChainWriter::prepare_block_commit`].
    pub storage: &'a S,
    /// State root committed by the parent block — anchors the JMT
    /// replay.
    pub parent_state_root: StateRoot,
    /// Parent block's height — stable JMT version (`storage.jmt_height()`
    /// is racy under concurrent commits).
    pub parent_block_height: BlockHeight,
    /// Finalized wave certificates whose receipts drive the JMT writes.
    pub finalized_waves: &'a [Arc<FinalizedWave>],
    /// Height of the block being verified.
    pub block_height: BlockHeight,
    /// JMT snapshots from prior unpersisted commits — let the verifier
    /// chain on top of speculative state.
    pub pending_snapshots: &'a [Arc<JmtSnapshot>],
    /// Optional base-reads cache produced during execution; a
    /// [`SubstateView`](crate::store::SubstateStore) storage backend
    /// drains it inside `prepare_block_commit`.
    pub base_reads: Option<&'a BaseReadCache>,
}

/// Failure modes of [`StateRoot`] verification.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum StateRootVerifyError {
    /// The JMT-replay computed a different root than the header
    /// claimed. Distinguishes a Byzantine proposer from an honest one;
    /// the receipt-root pre-flight check (run before this verifier on
    /// the shared dispatch path) already eliminates the
    /// receipts-don't-match case.
    #[error("computed state root {computed:?} ≠ claimed {expected:?}")]
    Mismatch {
        /// Header's claimed state root.
        expected: StateRoot,
        /// Root computed by replaying receipts against the JMT.
        computed: StateRoot,
    },
}

/// Construction asserts: replaying the supplied finalized waves against
/// the JMT rooted at the parent's state root produces a root that
/// equals the wrapped [`StateRoot`]. The augment carries the JMT write
/// batch from that replay (`S::PreparedCommit`), ready for the commit
/// pipeline to apply without recomputing.
///
/// Construction goes through one of two gates:
///
/// - [`<StateRoot as Verify>::verify`](Verify::verify) — runs the JMT
///   replay against [`StateRootContext::storage`] and compares.
/// - [`Verified::<StateRoot, _>::new_unchecked_with`] — re-wraps a
///   root whose predicate already held via an out-of-band trust
///   source (storage-recovery, where the root was verified before
///   persistence and the prepared-commit handle has been re-derived
///   from the persisted JMT). Every call site documents the trust
///   source with a `// SAFETY:` comment.
impl<S: ShardChainWriter + SubstateStore> Verify<&StateRootContext<'_, S>> for StateRoot {
    type Augment = S::PreparedCommit;
    type Error = StateRootVerifyError;

    fn verify(
        &self,
        ctx: &StateRootContext<'_, S>,
    ) -> Result<Verified<Self, Self::Augment>, Self::Error> {
        let (computed, prepared) = ctx.storage.prepare_block_commit(
            ctx.parent_state_root,
            ctx.parent_block_height,
            ctx.finalized_waves,
            ctx.block_height,
            ctx.pending_snapshots,
            ctx.base_reads,
        );
        if computed != *self {
            return Err(StateRootVerifyError::Mismatch {
                expected: *self,
                computed,
            });
        }
        Ok(Verified::new_unchecked_with(*self, prepared))
    }
}
