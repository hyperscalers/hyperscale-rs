//! What a successor knows about the chains that ran before it.
//!
//! A reshape successor holds no record of what its predecessor
//! committed, so it refuses every transaction whose validity window
//! opened before its own origin. That refusal is a superset of the real
//! hazard — a transaction submitted before the cut and never committed is
//! harmless there, and landing it here is its first commit — and this is
//! what narrows it: per-predecessor answers, each proven against a
//! `committed_txs_root` the successor commit-proved.
//!
//! Nothing here applies to a chain older than `MAX_VALIDITY_RANGE`. That
//! is the widest a validity window gets, so no transaction a chain of
//! that age can be offered opens before its origin.

use std::collections::HashMap;

use hyperscale_types::{PredecessorTerminal, ShardId, TxHash};

/// What a successor knows about one transaction across every chain it
/// succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrecutStatus {
    /// Proven absent from every predecessor's committed set — the
    /// transaction is admissible, and landing it here is its first
    /// commit.
    Absent,
    /// Some predecessor committed it. Admitting it would be the second
    /// commit of one transaction across the boundary.
    Committed,
    /// At least one predecessor has not answered yet. Indistinguishable
    /// from `Committed` for admission purposes, but not for votes: an
    /// answer is still coming, so the vote waits rather than refusing.
    Unresolved,
}

/// The chains this one succeeds, and what they have answered about
/// transactions that predate it.
///
/// The two travel together everywhere: an answer means nothing without the
/// predecessor whose root it was proven against, and a predecessor is only
/// consulted through its answers. Answers are keyed by predecessor as well
/// as transaction because a merged parent succeeds two children and a
/// transaction is only admissible when it is absent from **both** — an
/// absence proof against one child's root says nothing about what the
/// other committed.
#[derive(Debug, Clone, Default)]
pub struct Precut {
    /// One entry for a split child, two for a merged parent, empty for a
    /// chain born at network genesis or for a seat that missed the flip.
    predecessors: Vec<PredecessorTerminal>,
    /// `true` where the named predecessor proved the transaction absent
    /// from its committed set, `false` where it reported committing it.
    answers: HashMap<(ShardId, TxHash), bool>,
}

impl Precut {
    /// The chains this one succeeds, with nothing answered yet.
    #[must_use]
    pub(crate) fn succeeding(predecessors: Vec<PredecessorTerminal>) -> Self {
        Self {
            predecessors,
            answers: HashMap::new(),
        }
    }

    /// The chains this one succeeds.
    #[must_use]
    pub(crate) fn predecessors(&self) -> &[PredecessorTerminal] {
        &self.predecessors
    }

    /// Whether any predecessor is on hand to answer at all.
    #[must_use]
    pub(crate) const fn has_predecessors(&self) -> bool {
        !self.predecessors.is_empty()
    }

    /// Drop everything held for a rule that no longer applies.
    ///
    /// Called once the chain has outlived its origin by
    /// `MAX_VALIDITY_RANGE`: nothing on offer can open before the cut from
    /// there on, so no answer will be consulted again and the map would
    /// otherwise be held for the coordinator's life.
    pub(crate) fn retire(&mut self) {
        self.predecessors = Vec::new();
        self.answers = HashMap::new();
    }

    /// Whether anything is still held — what a caller retiring the rule
    /// checks before doing the work of retiring it.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.predecessors.is_empty() && self.answers.is_empty()
    }

    /// Record one predecessor's answer.
    ///
    /// The caller has already verified an `absent` answer against that
    /// predecessor's attested root; a `committed` answer needs no proof,
    /// because it leaves the standing refusal in place.
    pub(crate) fn record(&mut self, predecessor: ShardId, tx_hash: TxHash, absent: bool) {
        self.answers.insert((predecessor, tx_hash), absent);
    }

    /// What is known about `tx_hash` across every predecessor.
    ///
    /// A chain with no predecessors resolves nothing: it either has none
    /// (born at network genesis, where no transaction predates it) or has
    /// not been handed them yet, and both cases keep the strict rule.
    #[must_use]
    pub(crate) fn status(&self, tx_hash: &TxHash) -> PrecutStatus {
        if self.predecessors.is_empty() {
            return PrecutStatus::Unresolved;
        }
        let mut all_answered = true;
        for predecessor in &self.predecessors {
            match self.answers.get(&(predecessor.shard, *tx_hash)) {
                // One predecessor committing it settles the question; no
                // other answer can make it admissible.
                Some(false) => return PrecutStatus::Committed,
                Some(true) => {}
                None => all_answered = false,
            }
        }
        if all_answered {
            PrecutStatus::Absent
        } else {
            PrecutStatus::Unresolved
        }
    }

    /// Whether `tx_hash` may be offered despite opening before this chain
    /// did — proven absent from every predecessor's committed set.
    #[must_use]
    pub(crate) fn admissible(&self, tx_hash: &TxHash) -> bool {
        self.status(tx_hash) == PrecutStatus::Absent
    }

    /// The `(predecessor, transaction)` pairs still owed an answer — what
    /// a driver turns into queries.
    ///
    /// The predecessor rides out whole rather than as its shard id: a
    /// query names the terminal block it resolves against, and the
    /// absence proof that comes back is checked against that terminal's
    /// root.
    #[must_use]
    pub(crate) fn outstanding(
        &self,
        tx_hashes: impl IntoIterator<Item = TxHash>,
    ) -> Vec<(PredecessorTerminal, TxHash)> {
        let mut out = Vec::new();
        for tx_hash in tx_hashes {
            for predecessor in &self.predecessors {
                if !self.answers.contains_key(&(predecessor.shard, tx_hash)) {
                    out.push((*predecessor, tx_hash));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{BlockHash, BlockHeight, CommittedTxsRoot, Hash};

    use super::*;

    fn tx(seed: u8) -> TxHash {
        TxHash::from(Hash::from_bytes(&[seed]))
    }

    fn predecessor(shard: ShardId) -> PredecessorTerminal {
        PredecessorTerminal {
            shard,
            height: BlockHeight::new(9),
            block_hash: BlockHash::ZERO,
            committed_txs_root: CommittedTxsRoot::ZERO,
        }
    }

    fn one() -> Precut {
        Precut::succeeding(vec![predecessor(ShardId::leaf(1, 0))])
    }

    fn two() -> Precut {
        Precut::succeeding(vec![
            predecessor(ShardId::leaf(2, 0)),
            predecessor(ShardId::leaf(2, 1)),
        ])
    }

    /// The two shards `two()` succeeds, in the order it holds them.
    fn both(precut: &Precut) -> (ShardId, ShardId) {
        (
            precut.predecessors()[0].shard,
            precut.predecessors()[1].shard,
        )
    }

    #[test]
    fn an_unanswered_transaction_is_unresolved() {
        assert_eq!(one().status(&tx(1)), PrecutStatus::Unresolved);
    }

    #[test]
    fn a_single_predecessors_answers_settle_it() {
        let mut precut = one();
        let shard = precut.predecessors()[0].shard;

        precut.record(shard, tx(1), true);
        precut.record(shard, tx(2), false);
        assert_eq!(precut.status(&tx(1)), PrecutStatus::Absent);
        assert!(precut.admissible(&tx(1)));
        assert_eq!(precut.status(&tx(2)), PrecutStatus::Committed);
        assert!(!precut.admissible(&tx(2)));
    }

    /// A merged parent succeeds both children, so one absence proof is
    /// not enough — the transaction stays unresolved until the second
    /// child answers, and a single `committed` settles it against
    /// admission however the other answers.
    #[test]
    fn a_merged_parent_needs_both_children() {
        let mut precut = two();
        let (left, right) = both(&precut);

        precut.record(left, tx(1), true);
        assert_eq!(
            precut.status(&tx(1)),
            PrecutStatus::Unresolved,
            "one child's absence proof settles nothing on its own"
        );
        precut.record(right, tx(1), true);
        assert_eq!(precut.status(&tx(1)), PrecutStatus::Absent);

        // The other child committed it: absent from one, committed by the
        // other, and inadmissible.
        let mut mixed = two();
        mixed.record(left, tx(2), true);
        mixed.record(right, tx(2), false);
        assert_eq!(mixed.status(&tx(2)), PrecutStatus::Committed);
    }

    /// A `committed` answer settles the question before every predecessor
    /// has spoken — nothing a later answer says can make it admissible.
    #[test]
    fn one_committed_answer_settles_it_early() {
        let mut precut = two();
        let (left, _) = both(&precut);
        precut.record(left, tx(1), false);
        assert_eq!(precut.status(&tx(1)), PrecutStatus::Committed);
    }

    /// With no predecessors on hand nothing resolves, so the strict rule
    /// stands. This is the seat that missed the flip, not a chain born at
    /// genesis — that one never asks, because nothing predates it.
    #[test]
    fn no_predecessors_resolves_nothing() {
        let mut precut = Precut::default();
        precut.record(ShardId::leaf(1, 0), tx(1), true);
        assert_eq!(precut.status(&tx(1)), PrecutStatus::Unresolved);
        assert!(!precut.has_predecessors());
    }

    /// Outstanding pairs are exactly what has not been answered, per
    /// predecessor — a merged parent owes two answers per transaction.
    #[test]
    fn outstanding_names_every_unanswered_pair() {
        let mut precut = two();
        let (left, right) = both(&precut);
        precut.record(left, tx(1), true);

        let outstanding: Vec<(ShardId, TxHash)> = precut
            .outstanding([tx(1), tx(2)])
            .into_iter()
            .map(|(predecessor, tx_hash)| (predecessor.shard, tx_hash))
            .collect();
        assert_eq!(
            outstanding,
            vec![(right, tx(1)), (left, tx(2)), (right, tx(2))]
        );

        assert!(precut.outstanding(std::iter::empty()).is_empty());
    }

    /// Retiring drops both halves, so a chain that has outlived its origin
    /// stops holding answers nothing will consult again.
    #[test]
    fn retiring_drops_the_predecessors_and_their_answers() {
        let mut precut = two();
        let (left, _) = both(&precut);
        precut.record(left, tx(1), true);
        assert!(!precut.is_empty());

        precut.retire();
        assert!(precut.is_empty());
        assert!(!precut.has_predecessors());
        assert_eq!(
            precut.status(&tx(1)),
            PrecutStatus::Unresolved,
            "a retired answer is gone, not remembered as absent"
        );
        assert!(precut.outstanding([tx(1)]).is_empty());
    }
}
