//! State-root verification typestate.
//!
//! [`StateRoot`] is verified by replaying a block's finalized waves
//! against the JMT rooted at the parent's state root and comparing the
//! resulting root against the header's claim. The JMT replay itself
//! happens inside the storage backend's `prepare_block_commit`; the
//! verifier here is a thin equality check.
//!
//! The replay's other byproduct — the [`PreparedCommit`] closure — is
//! orthogonal `IoLoop` pipeline data, not part of the verification
//! predicate. The action handler routes it through `commit_prepared`
//! separately from the verified handle. Predicate at
//! [`impl Verify<StateRootContext>`](Verify::verify) below.
//!
//! [`StateRoot`]: crate::StateRoot
//! [`PreparedCommit`]: crate::PreparedCommit

use hyperscale_jmt::{Blake3Hasher, Hasher};
use sbor::prelude::*;
use thiserror::Error;

use crate::{Hash, SettledWavesRoot, StateRoot, Verified, Verify};

/// The two child hashes of the JMT root node behind a header's
/// `state_root` — `r_p0` / `r_p1` for a shard whose split executes at the
/// next epoch boundary.
///
/// Carried on every header of the split-pending shard's final epoch, so
/// whichever block terminates the chain delivers the children of exactly
/// the root the beacon anchors. `StateRoot::ZERO` marks an absent side
/// (the JMT hashes absent children as the empty hash).
///
/// Verified beside the state root: `hash_internal(left, right)` must
/// equal the recomputed root, which pins the pair by collision
/// resistance. A ≤1-key tree has a leaf root, and leaf/internal hashing
/// is domain-separated, so no pair verifies against it — the check fails
/// closed on the degenerate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BasicSbor)]
pub struct SplitChildRoots {
    /// Subtree root at the left child's prefix (`path‖0`).
    pub left: StateRoot,
    /// Subtree root at the right child's prefix (`path‖1`).
    pub right: StateRoot,
}

impl SplitChildRoots {
    /// The internal-node hash the pair composes to —
    /// `hash_internal(left, right)`.
    #[must_use]
    pub fn composed_root(&self) -> StateRoot {
        StateRoot::from_raw(Hash::from_hash_bytes(&Blake3Hasher::hash_internal(&[
            *self.left.as_bytes(),
            *self.right.as_bytes(),
        ])))
    }

    /// Whether `hash_internal(left, right)` reproduces `root` — the pair
    /// is exactly the two children of the internal node behind `root`.
    #[must_use]
    pub fn composes_to(&self, root: StateRoot) -> bool {
        self.composed_root() == root
    }
}

/// Inputs the [`StateRoot`] verifier checks against.
///
/// [`StateRoot`]: crate::StateRoot
pub struct StateRootContext<'a> {
    /// Root produced by replaying the block's finalized waves against
    /// the JMT.
    pub computed_root: &'a StateRoot,
    /// The header's `split_child_roots` claim.
    pub claimed_split_child_roots: Option<SplitChildRoots>,
    /// Whether the block's window requires the claim — true exactly when
    /// the next epoch's trie replaces the shard with its two children
    /// (the split-pending shard's final epoch).
    pub split_child_roots_required: bool,
    /// The header's `settled_waves_root` claim.
    pub claimed_settled_waves_root: Option<SettledWavesRoot>,
    /// Root recomputed by walking the committed retention window, present
    /// exactly when [`Self::settled_waves_root_required`] is set.
    pub computed_settled_waves_root: Option<SettledWavesRoot>,
    /// Whether the block's window requires the settled-waves claim — set
    /// on a terminating shard's boundary header.
    pub settled_waves_root_required: bool,
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

    /// The block's window is the split-pending shard's final epoch, but
    /// the header carries no `split_child_roots`.
    #[error("split child roots required in the final epoch but absent")]
    MissingSplitChildRoots,

    /// The header carries `split_child_roots` outside a split-pending
    /// shard's final epoch.
    #[error("split child roots carried outside a split-pending final epoch")]
    UnexpectedSplitChildRoots,

    /// The claimed pair does not compose to the computed root —
    /// `hash_internal(left, right) ≠ computed_root`. Also the fail-closed
    /// path for a ≤1-key tree, whose root is a leaf no pair composes to.
    #[error("split child roots {left:?}/{right:?} do not compose to {computed:?}")]
    SplitChildRootsMismatch {
        /// Claimed left child subtree root.
        left: StateRoot,
        /// Claimed right child subtree root.
        right: StateRoot,
        /// Root produced by replaying receipts against the JMT.
        computed: StateRoot,
    },

    /// The block terminates the shard at a boundary but the header carries
    /// no `settled_waves_root`.
    #[error("settled waves root required at a terminating boundary but absent")]
    MissingSettledWavesRoot,

    /// The header carries `settled_waves_root` outside a terminating
    /// boundary header.
    #[error("settled waves root carried outside a terminating boundary")]
    UnexpectedSettledWavesRoot,

    /// The claimed settled-waves root differs from the root recomputed
    /// over the committed retention window.
    #[error("settled waves root {claimed:?} ≠ recomputed {computed:?}")]
    SettledWavesRootMismatch {
        /// Header's claimed settled-waves root.
        claimed: SettledWavesRoot,
        /// Root recomputed by walking the committed retention window.
        computed: Option<SettledWavesRoot>,
    },
}

impl Verified<StateRoot> {
    /// Pipeline-attestation gate for slot prefill. The trust source is
    /// the verification pipeline's per-root tracking: an earlier verifier
    /// run already accepted `root` (success path of
    /// [`<StateRoot as Verify>::verify`](Verify::verify)).
    #[must_use]
    pub const fn from_pipeline_attestation(root: StateRoot) -> Self {
        Self::new_unchecked(root)
    }
}

/// Construction asserts: the supplied `computed_root` (produced by
/// replaying the block's finalized waves against the JMT rooted at the
/// parent's state root) equals the wrapped [`StateRoot`], and the
/// header's `split_child_roots` claim is present exactly when the window
/// requires it and composes to the computed root.
impl Verify<&StateRootContext<'_>> for StateRoot {
    type Error = StateRootVerifyError;

    fn verify(&self, ctx: &StateRootContext<'_>) -> Result<Verified<Self>, Self::Error> {
        if *ctx.computed_root != *self {
            return Err(StateRootVerifyError::Mismatch {
                expected: *self,
                computed: *ctx.computed_root,
            });
        }
        match (
            ctx.split_child_roots_required,
            ctx.claimed_split_child_roots,
        ) {
            (true, None) => return Err(StateRootVerifyError::MissingSplitChildRoots),
            (false, Some(_)) => return Err(StateRootVerifyError::UnexpectedSplitChildRoots),
            (true, Some(claimed)) if !claimed.composes_to(*ctx.computed_root) => {
                return Err(StateRootVerifyError::SplitChildRootsMismatch {
                    left: claimed.left,
                    right: claimed.right,
                    computed: *ctx.computed_root,
                });
            }
            _ => {}
        }
        match (
            ctx.settled_waves_root_required,
            ctx.claimed_settled_waves_root,
        ) {
            (true, None) => return Err(StateRootVerifyError::MissingSettledWavesRoot),
            (false, Some(_)) => return Err(StateRootVerifyError::UnexpectedSettledWavesRoot),
            (true, Some(claimed)) if Some(claimed) != ctx.computed_settled_waves_root => {
                return Err(StateRootVerifyError::SettledWavesRootMismatch {
                    claimed,
                    computed: ctx.computed_settled_waves_root,
                });
            }
            _ => {}
        }
        Ok(Verified::new_unchecked(*self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash;

    fn composing_pair() -> (SplitChildRoots, StateRoot) {
        let left = StateRoot::from_raw(Hash::from_bytes(b"left subtree"));
        let right = StateRoot::from_raw(Hash::from_bytes(b"right subtree"));
        let root = StateRoot::from_raw(Hash::from_hash_bytes(&Blake3Hasher::hash_internal(&[
            *left.as_bytes(),
            *right.as_bytes(),
        ])));
        (SplitChildRoots { left, right }, root)
    }

    #[test]
    fn final_epoch_pair_composing_to_the_root_verifies() {
        let (pair, root) = composing_pair();
        assert!(
            root.verify(&StateRootContext {
                computed_root: &root,
                claimed_split_child_roots: Some(pair),
                split_child_roots_required: true,
                claimed_settled_waves_root: None,
                computed_settled_waves_root: None,
                settled_waves_root_required: false,
            })
            .is_ok()
        );
    }

    #[test]
    fn missing_pair_in_the_final_epoch_is_rejected() {
        let (_, root) = composing_pair();
        assert_eq!(
            root.verify(&StateRootContext {
                computed_root: &root,
                claimed_split_child_roots: None,
                split_child_roots_required: true,
                claimed_settled_waves_root: None,
                computed_settled_waves_root: None,
                settled_waves_root_required: false,
            })
            .unwrap_err(),
            StateRootVerifyError::MissingSplitChildRoots,
        );
    }

    #[test]
    fn pair_outside_the_final_epoch_is_rejected() {
        let (pair, root) = composing_pair();
        assert_eq!(
            root.verify(&StateRootContext {
                computed_root: &root,
                claimed_split_child_roots: Some(pair),
                split_child_roots_required: false,
                claimed_settled_waves_root: None,
                computed_settled_waves_root: None,
                settled_waves_root_required: false,
            })
            .unwrap_err(),
            StateRootVerifyError::UnexpectedSplitChildRoots,
        );
    }

    #[test]
    fn non_composing_pair_is_rejected() {
        let (pair, root) = composing_pair();
        let forged = SplitChildRoots {
            left: StateRoot::from_raw(Hash::from_bytes(b"forged")),
            right: pair.right,
        };
        assert_eq!(
            root.verify(&StateRootContext {
                computed_root: &root,
                claimed_split_child_roots: Some(forged),
                split_child_roots_required: true,
                claimed_settled_waves_root: None,
                computed_settled_waves_root: None,
                settled_waves_root_required: false,
            })
            .unwrap_err(),
            StateRootVerifyError::SplitChildRootsMismatch {
                left: forged.left,
                right: forged.right,
                computed: root,
            },
        );
    }

    #[test]
    fn root_mismatch_is_reported_before_the_pair_check() {
        let (pair, root) = composing_pair();
        let other = StateRoot::from_raw(Hash::from_bytes(b"other"));
        assert!(matches!(
            other
                .verify(&StateRootContext {
                    computed_root: &root,
                    claimed_split_child_roots: Some(pair),
                    split_child_roots_required: true,
                    claimed_settled_waves_root: None,
                    computed_settled_waves_root: None,
                    settled_waves_root_required: false,
                })
                .unwrap_err(),
            StateRootVerifyError::Mismatch { .. },
        ));
    }

    /// A context isolating the settled-waves checks: the state root matches
    /// and no split-child-roots claim is in play.
    fn settled_ctx(
        root: &StateRoot,
        claimed: Option<SettledWavesRoot>,
        computed: Option<SettledWavesRoot>,
        required: bool,
    ) -> StateRootContext<'_> {
        StateRootContext {
            computed_root: root,
            claimed_split_child_roots: None,
            split_child_roots_required: false,
            claimed_settled_waves_root: claimed,
            computed_settled_waves_root: computed,
            settled_waves_root_required: required,
        }
    }

    #[test]
    fn settled_waves_root_matching_the_recompute_verifies() {
        let root = StateRoot::from_raw(Hash::from_bytes(b"state"));
        let settled = SettledWavesRoot::from_raw(Hash::from_bytes(b"settled"));
        assert!(
            root.verify(&settled_ctx(&root, Some(settled), Some(settled), true))
                .is_ok()
        );
    }

    #[test]
    fn missing_settled_waves_root_at_a_boundary_is_rejected() {
        let root = StateRoot::from_raw(Hash::from_bytes(b"state"));
        let recomputed = SettledWavesRoot::from_raw(Hash::from_bytes(b"settled"));
        assert_eq!(
            root.verify(&settled_ctx(&root, None, Some(recomputed), true))
                .unwrap_err(),
            StateRootVerifyError::MissingSettledWavesRoot,
        );
    }

    #[test]
    fn settled_waves_root_outside_a_boundary_is_rejected() {
        let root = StateRoot::from_raw(Hash::from_bytes(b"state"));
        let settled = SettledWavesRoot::from_raw(Hash::from_bytes(b"settled"));
        assert_eq!(
            root.verify(&settled_ctx(&root, Some(settled), None, false))
                .unwrap_err(),
            StateRootVerifyError::UnexpectedSettledWavesRoot,
        );
    }

    #[test]
    fn settled_waves_root_diverging_from_the_recompute_is_rejected() {
        let root = StateRoot::from_raw(Hash::from_bytes(b"state"));
        let claimed = SettledWavesRoot::from_raw(Hash::from_bytes(b"claimed"));
        let computed = SettledWavesRoot::from_raw(Hash::from_bytes(b"computed"));
        assert_eq!(
            root.verify(&settled_ctx(&root, Some(claimed), Some(computed), true))
                .unwrap_err(),
            StateRootVerifyError::SettledWavesRootMismatch {
                claimed,
                computed: Some(computed),
            },
        );
    }
}
