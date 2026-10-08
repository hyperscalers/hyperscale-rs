//! What a block demands be checked before a vote, and how one check
//! ends.
//!
//! A block makes claims its header commits — roots over its sections, a
//! state root, reservations its payers can cover, resolutions of
//! transactions it names, proofs of counterparts' cells — and every
//! claim it makes is checked off the main loop before a vote. Which
//! claims a block makes is a fact of the block, derived here once;
//! every reader of the pipeline — what to dispatch, whether a vote may
//! proceed, what to log when it cannot, what the assembled block
//! witnesses — asks this rather than restating the rule.

use std::collections::BTreeSet;

use crate::{Block, TxHash, Verified};

/// One check the pipeline runs on a block before voting on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerificationKind {
    /// State root computed by replaying the block's database updates
    /// against the JMT.
    StateRoot,
    /// The body root over every section's root, plus the per-tx
    /// validity-window check.
    BodyRoot,
    /// Per-target-shard provision-tx merkle roots map.
    ProvisionTxRoots,
    /// Merkle root over the per-shard beacon-witness accumulator after
    /// this block's appended leaves.
    BeaconWitnessRoot,
    /// The block's resolutions against the committed transactions they
    /// name: the figures its records restate, and the deliveries its
    /// finalizations carry, held short of the lapse.
    Resolutions,
}

/// The checks a block demands before a vote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Demands(BTreeSet<VerificationKind>);

impl Demands {
    /// Every check the block's own content asks for.
    ///
    /// The state, body and beacon-witness roots are always demanded:
    /// every block replays to a state root, commits a body (if only the
    /// empty one) and appends to the witness accumulator.
    #[must_use]
    pub(crate) fn of(block: &Block) -> Self {
        let h = block.header();
        let mut demanded = BTreeSet::from([
            VerificationKind::StateRoot,
            VerificationKind::BodyRoot,
            VerificationKind::BeaconWitnessRoot,
        ]);
        if !h.provision_tx_roots().is_empty() {
            demanded.insert(VerificationKind::ProvisionTxRoots);
        }
        if block.resolves_anything() {
            demanded.insert(VerificationKind::Resolutions);
        }
        Self(demanded)
    }

    /// Whether `kind` is demanded.
    #[must_use]
    pub fn contains(&self, kind: VerificationKind) -> bool {
        self.0.contains(&kind)
    }

    /// Every demanded kind, in a fixed order.
    pub fn iter(&self) -> impl Iterator<Item = VerificationKind> + '_ {
        self.0.iter().copied()
    }

    /// The demanded kinds `checked` does not answer.
    #[must_use]
    pub fn outstanding(
        &self,
        checked: impl Fn(VerificationKind) -> bool,
    ) -> BTreeSet<VerificationKind> {
        self.iter().filter(|&kind| !checked(kind)).collect()
    }
}

impl Verified<Demands> {
    /// Re-wrap demands the verification pipeline has seen every one of
    /// answered.
    #[must_use]
    pub const fn from_pipeline_attestation(demands: Demands) -> Self {
        Self::new_unchecked(demands)
    }
}

/// How one check on a block ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    /// The block's claim holds. The state root's replay also measures
    /// the net substate byte change the block makes, which reshape
    /// predicates read; no other check measures anything.
    Checked {
        /// The net substate byte change the check measured.
        bytes_delta: i64,
    },
    /// The block's claim does not hold; the block never gets a vote.
    Refused,
    /// The check could not be answered here yet. The block stays
    /// pending and the check is dispatched again when the vote is
    /// re-driven.
    Deferred(DeferOn),
}

/// What a deferred check waits on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeferOn {
    /// Transactions the block names that this validator's store does
    /// not hold.
    Bodies(Vec<TxHash>),
}
