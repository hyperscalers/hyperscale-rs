//! State-root verification typestate.
//!
//! [`StateRoot`] is verified by replaying a block's finalized waves
//! against the JMT rooted at the parent's state root and comparing the
//! resulting root against the header's claim. The verification reads
//! from storage (via [`ShardChainWriter::prepare_block_commit`]) and
//! produces a side artifact — the prepared-commit handle — that the
//! commit pipeline reuses so it doesn't have to redo the JMT replay.
//!
//! [`VerifiedStateRoot<P>`] carries both the verified root and the
//! prepared-commit handle. Holding one is type-level proof that the
//! JMT was actually replayed, not just that the claim was trusted.

use std::sync::Arc;

use hyperscale_types::{BlockHeight, FinalizedWave, StateRoot, Verify};
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

/// Verified state root paired with its prepared-commit handle.
///
/// Construction asserts: replaying the supplied finalized waves against
/// the JMT rooted at the parent's state root produces a root that
/// equals the wrapped [`StateRoot`]. The `prepared_commit` is the JMT
/// write batch from that replay, ready for the commit pipeline to apply
/// without recomputing.
///
/// Construction goes through one of two gates:
///
/// - [`<StateRoot as Verify>::verify`](Verify::verify) — runs the JMT
///   replay against [`StateRootContext::storage`] and compares.
/// - [`Self::new_unchecked`] — audit point. Used at storage-recovery
///   sites where the root was verified before persistence and the
///   prepared-commit handle has been re-derived from the persisted JMT.
///   Every call site documents the trust source with a `// SAFETY:`
///   comment.
pub struct VerifiedStateRoot<P> {
    root: StateRoot,
    prepared_commit: P,
}

impl<P> VerifiedStateRoot<P> {
    /// Audit-point constructor. Skips the predicate.
    #[must_use]
    pub const fn new_unchecked(root: StateRoot, prepared_commit: P) -> Self {
        Self {
            root,
            prepared_commit,
        }
    }

    /// The verified state root.
    #[must_use]
    pub const fn root(&self) -> StateRoot {
        self.root
    }

    /// The prepared-commit handle from the JMT replay. The commit
    /// pipeline applies this directly when the block commits, avoiding
    /// a second replay.
    #[must_use]
    pub const fn prepared_commit(&self) -> &P {
        &self.prepared_commit
    }

    /// Consume the wrapper and return both halves.
    #[must_use]
    pub fn into_parts(self) -> (StateRoot, P) {
        (self.root, self.prepared_commit)
    }
}

impl<P> AsRef<StateRoot> for VerifiedStateRoot<P> {
    fn as_ref(&self) -> &StateRoot {
        &self.root
    }
}

impl<S: ShardChainWriter + SubstateStore> Verify<&StateRootContext<'_, S>> for StateRoot {
    type Verified = VerifiedStateRoot<S::PreparedCommit>;
    type Error = StateRootVerifyError;

    fn verify(&self, ctx: &StateRootContext<'_, S>) -> Result<Self::Verified, Self::Error> {
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
        Ok(VerifiedStateRoot::new_unchecked(*self, prepared))
    }
}
