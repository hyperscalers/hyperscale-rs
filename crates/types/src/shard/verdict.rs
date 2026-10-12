//! What a member row has heard of its siblings' verdicts.
//!
//! A shard learns a sibling's verdict on a member they share only from
//! the sibling's committed state, through a state claim a block carries.
//! Each reading is kept on the member's row beside the mark of the
//! anchor it was taken at, one entry per sibling, and the newest reading
//! stands: an entry is replaced only by a reading at a strictly higher
//! mark, whatever either says.
//!
//! What an entry is worth is judged where the schedule is in hand, and
//! never by the fold that keeps it. [`source_of`] reads from the trie of
//! the anchor's window whether a sibling still runs, and [`asks`] says
//! from the sibling's entry and what the schedule says of it whether the
//! sibling is still asked. Each is a function of its arguments alone.

use hyperscale_hbor::{Capped, Hbor};

use crate::{
    Epoch, Hash, Inclusion, MAX_PREFIXES_PER_TX, ReadMark, RecoveryBinding, ShardId, SubstateKey,
    TxHash, Unpublished, WeightedTimestamp, WindowView,
};

/// What a sibling's committed state says of a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub enum Said {
    /// Its certificate succeeded for the member, among the shards the
    /// reader's own row shares the verdict with.
    Yes,
    /// It applied the member's effects, among those same shards.
    Accepted,
    /// Its verdict cell holds anything else, or it holds no row for the
    /// member and can commit none.
    Left,
}

/// One sibling's newest reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub struct Heard {
    /// The sibling read.
    pub shard: ShardId,
    /// The anchor the reading was taken at.
    pub mark: ReadMark,
    /// What it said there; `None` where it had stated nothing and could
    /// still commit the member.
    pub said: Option<Said>,
}

/// What a row has heard, at most one entry per sibling its settlement
/// awaits, ascending by shard.
pub type Hearing = Capped<Vec<Heard>, MAX_PREFIXES_PER_TX>;

/// Where a sibling's verdict is read from, chosen from the trie of the
/// anchor's window before any entry is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The trie runs the sibling: its verdict is the row's entry.
    Live,
    /// The trie no longer runs it, and it is asked nothing.
    Gone,
}

/// The source `sibling`'s verdict is read from under `window`, the
/// window the judging anchor falls in; `None` where that window is not
/// held, which gives no source at all.
#[must_use]
pub fn source_of(window: Option<WindowView<'_>>, sibling: ShardId) -> Option<Source> {
    let window = window?;
    Some(if window.shard_trie().contains(sibling) {
        Source::Live
    } else {
        Source::Gone
    })
}

/// What the schedule says of one sibling at a judging anchor, beside the
/// row's entry for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiblingView {
    /// The epoch the anchor's clock falls in, on the grid readings are
    /// marked on.
    pub epoch: Epoch,
    /// The newest recovery recorded for the sibling in the anchor's
    /// window as it was first published.
    pub recovery: Result<Option<RecoveryBinding>, Unpublished>,
}

/// Whether `entry` is an entry at all under `view`.
///
/// It is one where it is marked no earlier than the bridge of the
/// sibling's newest recovery the published window records, and no later
/// than the anchor's own epoch. An entry that is not counted stands on
/// the row until a reading at a higher mark replaces it.
#[must_use]
pub fn counts(entry: &Heard, view: &SiblingView) -> bool {
    let bridged = view
        .recovery
        .ok()
        .flatten()
        .is_none_or(|recovery| entry.mark.epoch >= recovery.bridge());
    bridged && entry.mark.epoch <= view.epoch
}

/// One question a hearing row puts to a sibling that still runs: what
/// does its committed state say of the member?
///
/// It carries everything a reading of the sibling's cells is classified
/// by, so whoever fetches the reading needs no row: the two values the
/// sibling's verdict cell can hold that mean a yes and an accept among
/// the shards this row shares the verdict with, and the signed end the
/// sibling's committed marker is keyed by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerdictQuestion {
    /// The sibling asked.
    pub sibling: ShardId,
    /// The member asked about.
    pub tx: TxHash,
    /// The end of the transaction's signed validity range.
    pub validity_end: WeightedTimestamp,
    /// The value hash of the sibling's verdict cell where it says yes.
    pub yes: Hash,
    /// The value hash of that cell where it says accepted.
    pub accepted: Hash,
    /// What the row has heard of the sibling so far.
    pub entry: Option<Heard>,
    /// Whether that entry counts under the window the question was put
    /// in: one that does not is replaced by whatever is read next.
    pub counted: bool,
}

impl VerdictQuestion {
    /// Whether a reading of the sibling at `mark` saying `said` is worth
    /// a block's bytes: it is newer than the row's entry, and it either
    /// says something else, replaces an entry that does not count, or
    /// renews a yes read in an earlier epoch, which the row counts only
    /// while it is recent. A row with no entry is offered only a reading
    /// that says something, and a newer mark on any other unchanged
    /// answer that counts is not offered at all.
    #[must_use]
    pub fn offers(&self, mark: ReadMark, said: Option<Said>) -> bool {
        let Some(entry) = self.entry else {
            return said.is_some();
        };
        mark > entry.mark
            && (said != entry.said
                || !self.counted
                || (said == Some(Said::Yes) && mark.epoch > entry.mark.epoch))
    }
}

/// The three cells a verdict question reads on its sibling at one
/// anchor: the verdict leaf, and the member row and committed marker an
/// absent leaf is judged with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerdictCells {
    /// The sibling's verdict cell for the member.
    pub leaf: SubstateKey,
    /// The sibling's member row.
    pub row: SubstateKey,
    /// The sibling's committed marker for the transaction.
    pub marker: SubstateKey,
}

impl VerdictCells {
    /// The three keys, the leaf first.
    #[must_use]
    pub const fn keys(&self) -> [SubstateKey; 3] {
        [self.leaf, self.row, self.marker]
    }
}

/// Whether a hearing row puts a question to a sibling read from `source`
/// whose entry is `entry` under `view`.
///
/// Only a sibling that still runs is asked, and only until its entry
/// says it accepted or left, which no later reading of a running sibling
/// takes back. The entry says so only where it counts under a published
/// window that is held: an entry marked in an epoch below the bridge of
/// the sibling's newest recorded recovery was read off a chain the
/// recovery replaced, one marked past the anchor's own epoch off a
/// header the anchor's window does not yet seat, and under a window not
/// held nothing is taken as said.
#[must_use]
pub fn asks(entry: Option<&Heard>, source: Option<Source>, view: &SiblingView) -> bool {
    let settled = view.recovery.is_ok()
        && entry
            .filter(|heard| counts(heard, view))
            .is_some_and(|heard| matches!(heard.said, Some(Said::Accepted | Said::Left)));
    source == Some(Source::Live) && !settled
}

/// What a sibling's cells at one anchor say of a member.
///
/// The reader's row would hash the sibling's yes as `yes` and its accept
/// as `accepted`, and its transaction's signed validity ends at
/// `validity_end`.
///
/// `leaf` is the sibling's verdict cell, `beside` its member row and
/// committed marker where both were read at the same anchor, and `clock`
/// the anchor's. A verdict cell read present says yes or accepted where
/// it holds that hash, and left for any other value, a verdict shared
/// among other shards included. Read absent, it is judged with the row
/// and the marker: left where the row is absent and the marker present
/// or the clock at or past the validity end, since the sibling then
/// holds no row and can commit none; and not stated, `Some(None)`, in
/// every other case, where it may still commit or state.
///
/// `None` where the cells prove nothing: the verdict cell is absent and
/// the row and marker were not both read beside it.
#[must_use]
pub fn said_at(
    leaf: Inclusion,
    beside: Option<(Inclusion, Inclusion)>,
    clock: WeightedTimestamp,
    validity_end: WeightedTimestamp,
    yes: Hash,
    accepted: Hash,
) -> Option<Option<Said>> {
    match leaf {
        Inclusion::Present(held) => {
            let held = Hash::from_hash_bytes(&held);
            Some(Some(if held == yes {
                Said::Yes
            } else if held == accepted {
                Said::Accepted
            } else {
                Said::Left
            }))
        }
        Inclusion::Absent => {
            let (row, marker) = beside?;
            let exited = row == Inclusion::Absent && (marker.is_present() || clock >= validity_end);
            Some(exited.then_some(Said::Left))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_utils::TestCommittee;
    use crate::{BlockHeight, TopologySchedule};

    fn heard(epoch: u64, said: Option<Said>) -> Heard {
        Heard {
            shard: ShardId::leaf(1, 1),
            mark: ReadMark {
                epoch: Epoch::new(epoch),
                height: BlockHeight::new(7),
            },
            said,
        }
    }

    /// A sibling with no recovery recorded, judged in epoch `epoch`.
    fn view(epoch: u64) -> SiblingView {
        SiblingView {
            epoch: Epoch::new(epoch),
            recovery: Ok(None),
        }
    }

    fn recovered_at(rotated_at: u64) -> RecoveryBinding {
        RecoveryBinding {
            rotated_at: Epoch::new(rotated_at),
            attested_frontier: BlockHeight::new(3),
            completed: true,
        }
    }

    fn two_shards() -> TopologySchedule {
        TopologySchedule::single(Arc::new(TestCommittee::new(4, 7).topology_snapshot(2)))
    }

    const LIVE: Option<Source> = Some(Source::Live);
    const GONE: Option<Source> = Some(Source::Gone);

    #[test]
    fn a_sibling_the_trie_runs_is_read_live() {
        let schedule = two_shards();
        let window = schedule.at(WeightedTimestamp::ZERO);
        assert_eq!(source_of(window, ShardId::leaf(1, 1)), Some(Source::Live));
    }

    #[test]
    fn a_sibling_the_trie_does_not_run_is_read_gone() {
        let schedule = two_shards();
        let window = schedule.at(WeightedTimestamp::ZERO);
        assert_eq!(source_of(window, ShardId::leaf(2, 3)), Some(Source::Gone));
        assert_eq!(source_of(window, ShardId::ROOT), Some(Source::Gone));
    }

    #[test]
    fn an_evicted_window_decides_nothing() {
        let schedule = TopologySchedule::new(
            1_000,
            Epoch::new(4),
            Arc::new(TestCommittee::new(4, 7).topology_snapshot(1)),
        );
        let evicted = schedule.at(WeightedTimestamp::from_millis(1_500));
        assert!(evicted.is_none());
        assert_eq!(source_of(evicted, ShardId::ROOT), None);
    }

    /// A sibling is asked only while the trie runs it, and only until
    /// what it said can no longer change: a gone sibling is asked
    /// nothing, and no window is no source at all.
    #[test]
    fn a_sibling_is_asked_only_while_it_runs_and_has_not_settled() {
        for entry in [None, Some(heard(5, None)), Some(heard(5, Some(Said::Yes)))] {
            assert!(asks(entry.as_ref(), LIVE, &view(5)));
            assert!(!asks(entry.as_ref(), GONE, &view(5)));
            assert!(!asks(entry.as_ref(), None, &view(5)));
        }
        for said in [Said::Accepted, Said::Left] {
            assert!(!asks(Some(&heard(5, Some(said))), LIVE, &view(5)));
            assert!(!asks(Some(&heard(5, Some(said))), GONE, &view(5)));
        }
        // An entry the window does not count is no answer yet.
        assert!(asks(Some(&heard(6, Some(Said::Left))), LIVE, &view(5)));
    }

    /// Under a window not held as published nothing is taken as said, so
    /// a running sibling is asked whatever its entry holds.
    #[test]
    fn a_sibling_is_asked_while_the_published_window_is_not_held() {
        let unpublished = SiblingView {
            recovery: Err(Unpublished),
            ..view(5)
        };
        for said in [Said::Yes, Said::Accepted, Said::Left] {
            let entry = heard(5, Some(said));
            assert!(asks(Some(&entry), LIVE, &unpublished));
            assert!(!asks(Some(&entry), GONE, &unpublished));
        }
    }

    /// A reading is offered where it would change what the row holds,
    /// or renew its yes in a later epoch, and never at or below the mark
    /// already held.
    #[test]
    fn a_reading_is_offered_only_where_it_changes_or_renews_the_entry() {
        let mark = |epoch: u64, height: u64| ReadMark {
            epoch: Epoch::new(epoch),
            height: BlockHeight::new(height),
        };
        let question = |entry| VerdictQuestion {
            sibling: ShardId::leaf(1, 1),
            tx: TxHash::from(Hash::from_bytes(b"member")),
            validity_end: WeightedTimestamp::ZERO,
            yes: Hash::from_bytes(b"yes"),
            accepted: Hash::from_bytes(b"accepted"),
            entry,
            counted: true,
        };
        let unheard = question(None);
        assert!(!unheard.offers(mark(5, 9), None));
        assert!(unheard.offers(mark(5, 9), Some(Said::Yes)));

        let yes = question(Some(heard(5, Some(Said::Yes))));
        assert!(
            !yes.offers(mark(5, 9), Some(Said::Yes)),
            "a newer mark alone"
        );
        assert!(yes.offers(mark(5, 9), Some(Said::Accepted)));
        assert!(yes.offers(mark(5, 9), None), "a yes that is gone");
        assert!(
            !yes.offers(mark(5, 7), Some(Said::Accepted)),
            "at the mark held"
        );
        assert!(
            !yes.offers(mark(4, 9), Some(Said::Left)),
            "below the mark held"
        );
        assert!(yes.offers(mark(6, 1), Some(Said::Yes)), "a yes an epoch on");

        let left = question(Some(heard(5, Some(Said::Left))));
        assert!(!left.offers(mark(6, 1), Some(Said::Left)));
    }

    /// An entry the window does not count is no answer, so the same
    /// answer read again above it is offered: it is what replaces the
    /// entry, and until it does the sibling is asked without end.
    #[test]
    fn a_reading_over_an_entry_that_does_not_count_is_offered() {
        let entry = heard(4, Some(Said::Left));
        let recovered = SiblingView {
            recovery: Ok(Some(recovered_at(4))),
            ..view(5)
        };
        assert!(!counts(&entry, &recovered), "below the bridge");
        assert!(
            !counts(&heard(6, Some(Said::Left)), &view(5)),
            "past the anchor"
        );
        assert!(counts(&heard(5, Some(Said::Left)), &recovered));
        assert!(
            asks(Some(&entry), LIVE, &recovered),
            "so the sibling is asked"
        );

        let question = |counted| VerdictQuestion {
            sibling: ShardId::leaf(1, 1),
            tx: TxHash::from(Hash::from_bytes(b"member")),
            validity_end: WeightedTimestamp::ZERO,
            yes: Hash::from_bytes(b"yes"),
            accepted: Hash::from_bytes(b"accepted"),
            entry: Some(entry),
            counted,
        };
        let fresh = ReadMark {
            epoch: Epoch::new(5),
            height: BlockHeight::new(9),
        };
        assert!(question(false).offers(fresh, Some(Said::Left)));
        assert!(!question(true).offers(fresh, Some(Said::Left)));
    }
}
