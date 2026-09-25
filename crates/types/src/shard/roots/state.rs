//! State-root verification typestate.
//!
//! [`StateRoot`] is verified by replaying a block's finalizations
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

use hyperscale_hbor::Hbor;
use hyperscale_jmt::{Blake3Hasher, Hasher};
use thiserror::Error;

use crate::{Hash, SettledTxsRoot, StateRoot, SweepFrontier, Verified, Verify};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
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
    /// Root produced by replaying the block's finalizations against
    /// the JMT.
    pub computed_root: &'a StateRoot,
    /// The header's `split_child_roots` claim.
    pub claimed_split_child_roots: Option<SplitChildRoots>,
    /// Whether the block's window requires the claim — true exactly when
    /// the next epoch's trie replaces the shard with its two children
    /// (the split-pending shard's final epoch).
    pub split_child_roots_required: bool,
    /// The header's terminal settled-transaction root claim.
    pub claimed_terminal_settled_txs: Option<SettledTxsRoot>,
    /// The root recomputed by walking the committed retention window,
    /// present exactly when [`Self::terminal_settled_txs_required`] is set.
    pub computed_terminal_settled_txs: Option<SettledTxsRoot>,
    /// Whether the block's window requires the claim — set on a
    /// terminating shard's boundary header.
    pub terminal_settled_txs_required: bool,
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

    /// The header's sweep frontier is not the one the block's own
    /// interval produces.
    ///
    /// Short of it is a sweep the proposer declined to finish, which is
    /// the equilibrium the obligation exists to break — a removal earns
    /// no fee and costs block space. Past it reaches cells the block's
    /// clock does not yet allow.
    #[error("computed sweep frontier {computed:?} ≠ claimed {expected:?}")]
    SweepFrontierMismatch {
        /// Header's claimed frontier.
        expected: SweepFrontier,
        /// Frontier the walk over the block's own interval lands on.
        computed: SweepFrontier,
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
    /// no terminal settled root.
    #[error("terminal settled root required at a terminating boundary but absent")]
    MissingTerminalSettledTxs,

    /// The header carries a terminal settled root outside a terminating boundary
    /// header.
    #[error("terminal settled root carried outside a terminating boundary")]
    UnexpectedTerminalSettledTxs,

    /// The claimed terminal settled root differs from the one recomputed
    /// over the committed retention window.
    #[error("terminal settled root {claimed:?} ≠ recomputed {computed:?}")]
    TerminalSettledTxsMismatch {
        /// Header's claimed root.
        claimed: SettledTxsRoot,
        /// Pair recomputed by walking the committed retention window.
        computed: Option<SettledTxsRoot>,
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
/// replaying the block's finalizations against the JMT rooted at the
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
            ctx.terminal_settled_txs_required,
            ctx.claimed_terminal_settled_txs,
        ) {
            (true, None) => return Err(StateRootVerifyError::MissingTerminalSettledTxs),
            (false, Some(_)) => return Err(StateRootVerifyError::UnexpectedTerminalSettledTxs),
            (true, Some(claimed)) if Some(claimed) != ctx.computed_terminal_settled_txs => {
                return Err(StateRootVerifyError::TerminalSettledTxsMismatch {
                    claimed,
                    computed: ctx.computed_terminal_settled_txs,
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
                claimed_terminal_settled_txs: None,
                computed_terminal_settled_txs: None,
                terminal_settled_txs_required: false,
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
                claimed_terminal_settled_txs: None,
                computed_terminal_settled_txs: None,
                terminal_settled_txs_required: false,
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
                claimed_terminal_settled_txs: None,
                computed_terminal_settled_txs: None,
                terminal_settled_txs_required: false,
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
                claimed_terminal_settled_txs: None,
                computed_terminal_settled_txs: None,
                terminal_settled_txs_required: false,
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
                    claimed_terminal_settled_txs: None,
                    computed_terminal_settled_txs: None,
                    terminal_settled_txs_required: false,
                })
                .unwrap_err(),
            StateRootVerifyError::Mismatch { .. },
        ));
    }

    /// A context isolating the terminal settled root checks: the state root
    /// matches and no split-child-roots claim is in play.
    fn terminal_ctx(
        root: &StateRoot,
        claimed: Option<SettledTxsRoot>,
        computed: Option<SettledTxsRoot>,
        required: bool,
    ) -> StateRootContext<'_> {
        StateRootContext {
            computed_root: root,
            claimed_split_child_roots: None,
            split_child_roots_required: false,
            claimed_terminal_settled_txs: claimed,
            computed_terminal_settled_txs: computed,
            terminal_settled_txs_required: required,
        }
    }

    fn settled(tag: &[u8]) -> SettledTxsRoot {
        SettledTxsRoot::from_raw(Hash::from_bytes(tag))
    }

    #[test]
    fn terminal_settled_txs_matching_the_recompute_verify() {
        let root = StateRoot::from_raw(Hash::from_bytes(b"state"));
        let claimed = settled(b"settled");
        assert!(
            root.verify(&terminal_ctx(&root, Some(claimed), Some(claimed), true))
                .is_ok()
        );
    }

    #[test]
    fn missing_terminal_settled_txs_at_a_boundary_is_rejected() {
        let root = StateRoot::from_raw(Hash::from_bytes(b"state"));
        let recomputed = settled(b"settled");
        assert_eq!(
            root.verify(&terminal_ctx(&root, None, Some(recomputed), true))
                .unwrap_err(),
            StateRootVerifyError::MissingTerminalSettledTxs,
        );
    }

    #[test]
    fn terminal_settled_txs_outside_a_boundary_are_rejected() {
        let root = StateRoot::from_raw(Hash::from_bytes(b"state"));
        assert_eq!(
            root.verify(&terminal_ctx(&root, Some(settled(b"settled")), None, false))
                .unwrap_err(),
            StateRootVerifyError::UnexpectedTerminalSettledTxs,
        );
    }

    #[test]
    fn a_root_diverging_from_the_recompute_is_rejected() {
        let root = StateRoot::from_raw(Hash::from_bytes(b"state"));
        let computed = settled(b"settled");
        let claimed = settled(b"other settled");
        assert_eq!(
            root.verify(&terminal_ctx(&root, Some(claimed), Some(computed), true))
                .unwrap_err(),
            StateRootVerifyError::TerminalSettledTxsMismatch {
                claimed,
                computed: Some(computed),
            },
        );
    }
}
