//! What a successor knows about transactions that predate it.
//!
//! "Did a chain in this lineage commit T" is answered by T's committed
//! marker, read from state. A left child holds its parent's markers
//! under its own owner, and a merged parent holds both predecessors'
//! markers in its own state, so both read the answer where they read
//! their own. Only a split's right child holds none of its parent's
//! markers — they sit under the parent's owner, in the left half — and it
//! asks for each one by a state proof against the parent's terminal
//! root.
//!
//! Nothing here applies to a block anchored `MAX_VALIDITY_RANGE` or more
//! past its chain's origin. That is the widest a validity window gets, so
//! no transaction such a block can carry opens before the origin. Which
//! side of the line a block sits on is its own anchor's to say. How a
//! block below the line is judged is this node's: a right child keeps
//! asking until its committed block anchors past the line, and defers on
//! a pre-cut transaction after that. No block extending the committed
//! one anchors below the line by then, so the deferral never holds up a
//! block that can become canonical.
//!
//! One level of asking is enough. The beacon's scheduling rule puts two
//! cuts on one lineage at least `MAX_VALIDITY_RANGE` apart on the epoch
//! grid, so a transaction a successor can be offered opens after its
//! parent's own origin, and only the parent can have committed it.

use std::collections::HashMap;

use hyperscale_storage::committed_tx_cell_key;
use hyperscale_types::{Anchor, ShardId, SubstateKey, TxHash, WeightedTimestamp};

/// What a successor knows about one transaction that predates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrecutStatus {
    /// Nothing outside this chain's own state is left to ask: the
    /// transaction passes here, and the marker rule judges it against
    /// the parent state.
    Absent,
    /// The parent's terminal state holds its marker. Admitting it would
    /// be the second commit of one transaction across the boundary.
    Committed,
    /// Not known yet. Not proposed, and a vote on a block carrying it
    /// waits rather than refusing: an answer is still coming.
    Unresolved,
}

/// Where this chain reads the answer for a transaction older than it.
#[derive(Debug, Clone, Default)]
pub enum Precut {
    /// Nothing answers for a transaction older than the chain: the
    /// chains this one succeeds are not yet known here, or a right child
    /// has stopped asking its parent. Such a transaction is not proposed
    /// and a vote on one defers. A chain born at network genesis sits
    /// here for good, and nothing is older than it.
    #[default]
    Unanswered,
    /// Every predecessor's markers are in this chain's own state: a left
    /// child's and a merged parent's.
    Local,
    /// A split's right child, asking the parent's terminal state.
    Remote {
        /// The parent's terminal, whose state root a proof is checked
        /// against.
        terminal: Anchor,
        /// Each marker key asked about and answered: `true` where the
        /// terminal state holds it.
        answers: HashMap<SubstateKey, bool>,
    },
}

impl Precut {
    /// The rule for `local_shard` succeeding `predecessors`.
    ///
    /// `Remote` only for a split's right child: its one predecessor is
    /// the parent whose right child it is. Any other set of predecessors
    /// wrote under owners this chain's state holds.
    #[must_use]
    pub(crate) fn adopted(local_shard: ShardId, predecessors: &[Anchor]) -> Self {
        match predecessors {
            [] => Self::Unanswered,
            [parent] if parent.shard.children().1 == local_shard => Self::Remote {
                terminal: *parent,
                answers: HashMap::new(),
            },
            _ => Self::Local,
        }
    }

    /// Whether nothing answers here yet.
    #[must_use]
    pub(crate) const fn is_unanswered(&self) -> bool {
        matches!(self, Self::Unanswered)
    }

    /// The terminal a right child asks, while it still asks.
    #[must_use]
    pub(crate) const fn terminal(&self) -> Option<Anchor> {
        match self {
            Self::Remote { terminal, .. } => Some(*terminal),
            Self::Unanswered | Self::Local => None,
        }
    }

    /// Stop asking and drop the answers. A right child's state still
    /// holds none of the parent's markers, so a pre-cut transaction it
    /// meets afterwards, which only a block anchored below the line can
    /// carry, defers rather than passes.
    pub(crate) fn retire(&mut self) {
        *self = Self::Unanswered;
    }

    /// Record what a proof against `terminal` says of `key`. Ignored
    /// unless `terminal` is the one this chain asks.
    pub(crate) fn record(&mut self, terminal: Anchor, key: SubstateKey, present: bool) {
        if let Self::Remote {
            terminal: asked,
            answers,
        } = self
            && *asked == terminal
        {
            answers.insert(key, present);
        }
    }

    /// What is known about the transaction `tx_hash`, whose range ends at
    /// `validity_end`.
    #[must_use]
    pub(crate) fn status(&self, tx_hash: TxHash, validity_end: WeightedTimestamp) -> PrecutStatus {
        match self {
            Self::Unanswered => PrecutStatus::Unresolved,
            Self::Local => PrecutStatus::Absent,
            Self::Remote { terminal, answers } => {
                match answers.get(&committed_tx_cell_key(
                    terminal.shard,
                    tx_hash,
                    validity_end,
                )) {
                    Some(false) => PrecutStatus::Absent,
                    Some(true) => PrecutStatus::Committed,
                    None => PrecutStatus::Unresolved,
                }
            }
        }
    }

    /// Whether the transaction may be offered despite opening before
    /// this chain did.
    #[must_use]
    pub(crate) fn admissible(&self, tx_hash: TxHash, validity_end: WeightedTimestamp) -> bool {
        self.status(tx_hash, validity_end) == PrecutStatus::Absent
    }

    /// The marker keys still owed an answer among `candidates`, each a
    /// transaction and the end of its range — what a driver asks the
    /// terminal for. Empty unless this chain asks.
    #[must_use]
    pub(crate) fn outstanding(
        &self,
        candidates: impl IntoIterator<Item = (TxHash, WeightedTimestamp)>,
    ) -> Vec<SubstateKey> {
        let Self::Remote { terminal, answers } = self else {
            return Vec::new();
        };
        let mut keys: Vec<SubstateKey> = candidates
            .into_iter()
            .map(|(tx_hash, validity_end)| {
                committed_tx_cell_key(terminal.shard, tx_hash, validity_end)
            })
            .filter(|key| !answers.contains_key(key))
            .collect();
        keys.sort_unstable();
        keys.dedup();
        keys
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::install_stub_protocol_statics;
    use hyperscale_types::{BlockHeight, Hash, StateRoot};

    use super::*;

    const END: WeightedTimestamp = WeightedTimestamp::from_millis(60_000);

    fn tx(seed: u8) -> TxHash {
        TxHash::from(Hash::from_bytes(&[seed]))
    }

    fn terminal(shard: ShardId) -> Anchor {
        Anchor {
            shard,
            height: BlockHeight::new(9),
            state_root: StateRoot::from_raw(Hash::from_bytes(b"terminal")),
            ts: WeightedTimestamp::from_millis(1_000),
        }
    }

    fn right_child() -> (Anchor, Precut) {
        install_stub_protocol_statics();
        let parent = ShardId::leaf(1, 0);
        let terminal = terminal(parent);
        (terminal, Precut::adopted(parent.children().1, &[terminal]))
    }

    /// Only a split's right child asks: a left child and a merged parent
    /// hold every predecessor's markers in their own state.
    #[test]
    fn adoption_asks_only_for_a_right_child() {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        assert!(
            Precut::adopted(right, &[terminal(parent)])
                .terminal()
                .is_some()
        );
        assert!(matches!(
            Precut::adopted(left, &[terminal(parent)]),
            Precut::Local
        ));
        assert!(matches!(
            Precut::adopted(parent, &[terminal(left), terminal(right)]),
            Precut::Local
        ));
        assert!(Precut::adopted(right, &[]).is_unanswered());
    }

    /// Unanswered resolves nothing; Local passes everything on to the
    /// marker rule.
    #[test]
    fn unanswered_defers_and_local_passes() {
        assert_eq!(
            Precut::Unanswered.status(tx(1), END),
            PrecutStatus::Unresolved
        );
        assert_eq!(Precut::Local.status(tx(1), END), PrecutStatus::Absent);
    }

    /// A right child's answers are the terminal's markers: present
    /// refuses, absent passes, unasked defers.
    #[test]
    fn a_right_childs_answers_settle_it() {
        let (terminal, mut precut) = right_child();
        let present = committed_tx_cell_key(terminal.shard, tx(1), END);
        let absent = committed_tx_cell_key(terminal.shard, tx(2), END);
        precut.record(terminal, present, true);
        precut.record(terminal, absent, false);

        assert_eq!(precut.status(tx(1), END), PrecutStatus::Committed);
        assert_eq!(precut.status(tx(2), END), PrecutStatus::Absent);
        assert!(precut.admissible(tx(2), END));
        assert_eq!(precut.status(tx(3), END), PrecutStatus::Unresolved);
    }

    /// A proof against any other anchor answers nothing here.
    #[test]
    fn a_proof_against_another_anchor_is_ignored() {
        let (terminal, mut precut) = right_child();
        let key = committed_tx_cell_key(terminal.shard, tx(1), END);
        precut.record(
            Anchor {
                height: BlockHeight::new(10),
                ..terminal
            },
            key,
            false,
        );
        assert_eq!(precut.status(tx(1), END), PrecutStatus::Unresolved);
    }

    /// Outstanding keys are exactly the unanswered ones, once each.
    #[test]
    fn outstanding_names_every_unanswered_key() {
        let (terminal, mut precut) = right_child();
        precut.record(
            terminal,
            committed_tx_cell_key(terminal.shard, tx(1), END),
            false,
        );
        let owed = precut.outstanding([(tx(1), END), (tx(2), END), (tx(2), END)]);
        assert_eq!(
            owed,
            vec![committed_tx_cell_key(terminal.shard, tx(2), END)]
        );
        assert!(Precut::Local.outstanding([(tx(2), END)]).is_empty());
    }

    /// Retiring stops the asking and forgets the answers, including one
    /// that refused: the right child's own state never held the parent's
    /// markers, so what it meets afterwards defers.
    #[test]
    fn retiring_forgets_the_answers_and_defers() {
        let (terminal, mut precut) = right_child();
        precut.record(
            terminal,
            committed_tx_cell_key(terminal.shard, tx(1), END),
            true,
        );
        precut.retire();
        assert!(precut.terminal().is_none());
        assert_eq!(precut.status(tx(1), END), PrecutStatus::Unresolved);
        assert!(!precut.admissible(tx(1), END));
    }
}
