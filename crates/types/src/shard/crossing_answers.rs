//! [`CrossingAnswers`]: what this shard has answered about the crossings
//! handed to it, and what it might still answer.
//!
//! A block's declines are judged against two facts, and both are folds
//! the execution side keeps: whether this shard already holds an answer
//! for a crossing, and whether a tick or a candidate here still holds a
//! member that could write one. Neither is a counterpart's word and
//! neither is per-validator evidence — every replica at one frontier
//! holds the same pair, which is what lets the decline rule be a content
//! rule rather than a fence.
//!
//! Shared rather than copied, and the two halves are maintained
//! differently because they are sized differently. The answers this
//! shard holds grow with every crossing it ever answered and shrink only
//! when one is reclaimed, so they are edited where they change; the
//! members it still holds are bounded by what the chain has in flight,
//! so they are rewritten whole at each commit.

use std::collections::BTreeSet;
use std::sync::{PoisonError, RwLock};

use crate::{SubstateKey, TxHash};

/// The answering side of a crossing, as a block's declines are judged
/// against it.
#[derive(Debug, Default)]
pub struct CrossingAnswers {
    answered: RwLock<BTreeSet<SubstateKey>>,
    holding: RwLock<BTreeSet<TxHash>>,
}

impl CrossingAnswers {
    /// An empty pair: a seat that has answered nothing and holds no
    /// member.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed the answered set from the leaves a seat starts holding,
    /// replacing whatever was there.
    pub fn seed_answered(&self, records: impl IntoIterator<Item = SubstateKey>) {
        let mut guard = self
            .answered
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        *guard = records.into_iter().collect();
    }

    /// Record that this shard now holds an answer for the crossing
    /// `record` names.
    pub fn answered(&self, record: SubstateKey) {
        self.answered
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(record);
    }

    /// Record that the answer for `record` is gone, so the crossing is
    /// one this shard could answer again.
    pub fn unanswered(&self, record: &SubstateKey) {
        self.answered
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(record);
    }

    /// Whether this shard holds an answer for the crossing `record`
    /// names.
    #[must_use]
    pub fn holds_answer(&self, record: &SubstateKey) -> bool {
        self.answered
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(record)
    }

    /// Replace the transactions a tick or a candidate here still holds a
    /// member for.
    ///
    /// Whole rather than edited, because the set is bounded by what the
    /// chain has in flight and its membership changes at more sites than
    /// it is worth threading an edit through.
    pub fn hold_members_for(&self, txs: impl IntoIterator<Item = TxHash>) {
        let mut guard = self.holding.write().unwrap_or_else(PoisonError::into_inner);
        *guard = txs.into_iter().collect();
    }

    /// Whether a tick or a candidate here still holds a member for
    /// `tx_hash`, so an execution that would write a claim may yet run.
    #[must_use]
    pub fn holds_member_for(&self, tx_hash: &TxHash) -> bool {
        self.holding
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(tx_hash)
    }
}
