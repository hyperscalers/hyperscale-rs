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
//! the anchor's window whether a sibling still runs, [`value_of`] turns
//! the sibling's entry and what the schedule says of it into one
//! [`Value`], [`asks`] says from that value whether the sibling is still
//! asked, and [`decide`] reads a row's values into what the row may do.
//! Each is a function of its arguments alone.

use hyperscale_hbor::{Capped, Hbor};

use crate::{
    Epoch, Evidence, Formed, Hash, Inclusion, MAX_PREFIXES_PER_TX, ReadMark, RecoveryBinding,
    ShardId, SubstateKey, TxHash, Unpublished, WeightedTimestamp, WindowView,
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
    /// The trie no longer runs it: its verdict is an accepted entry, or
    /// else the names its terminal block ended.
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

/// What one sibling's verdict counts as at a judging anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    /// It accepted.
    A,
    /// It left without accepting.
    L,
    /// It says yes, read recently enough to count.
    Y,
    /// Nothing countable yet, which every replica computes alike from
    /// the committed row and the published window: a reading or a beacon
    /// fold changes it.
    W,
    /// Nothing countable here, for want of something this replica alone
    /// lacks: the anchor's window as first published, or a departed
    /// sibling's ended names while its evidence can still be read.
    N,
    /// It is gone and its evidence can no longer be read, which every
    /// replica computes alike from the published window, whatever names
    /// each holds.
    U,
}

/// What the schedule and the mirror say of one sibling at a judging
/// anchor, beside the row's entry for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiblingView {
    /// The epoch the anchor's clock falls in, on the grid readings are
    /// marked on.
    pub epoch: Epoch,
    /// Whether the sibling leaves the trie at the end of the anchor's
    /// own window; `None` where that window is not held.
    pub terminating: Option<bool>,
    /// The newest recovery recorded for the sibling in the anchor's
    /// window as it was first published.
    pub recovery: Result<Option<RecoveryBinding>, Unpublished>,
    /// The sibling's evidence in that same published window.
    pub evidence: Result<Evidence, Unpublished>,
    /// Where the chain that same published window names under the
    /// sibling's id formed: the one it runs, or a departed one while its
    /// record stands. `None` where the window carries no record of it.
    pub formed: Result<Option<Formed>, Unpublished>,
    /// Whether the names the sibling's terminal block ended hold the
    /// transaction; `None` where those names are not held. Read only
    /// while the evidence is readable.
    pub ended: Option<bool>,
}

/// What `entry`, the row's reading of one sibling, counts as where the
/// sibling is read from `source` and the schedule says `view` of it, for
/// a row committed at `committed`.
///
/// No source counts as nothing yet, and a published window, or a
/// formation in it, not held is this replica's lack. An entry marked in
/// an epoch below the bridge of the sibling's newest recorded recovery,
/// or past the anchor's own epoch, is no entry: the first was read off a
/// chain the recovery replaced, and the second off a header the anchor's
/// window does not yet seat.
///
/// A row committed before the chain the window names under the
/// sibling's id formed awaited an earlier chain under that id, which
/// nothing the window says of the later one answers for. It counts an
/// accepted entry marked before the later chain formed, which is the
/// earlier chain's, and is unreadable otherwise, wherever the sibling is
/// read from: the earlier chain's evidence expired before the later one
/// formed. The window's recovery is the later chain's and bridges no
/// entry of the earlier.
///
/// Otherwise a live sibling counts by its entry: accepted, left, or a
/// yes while it is not terminating and the reading is no older than the
/// epoch before the anchor's. A gone sibling counts an accepted entry
/// and no other. Failing that it is unreadable where its published
/// evidence says so, whether or not the names its terminal ended are
/// held: the names are this replica's alone and can no longer be
/// fetched, so a value read from them there would be one a replica
/// without them cannot reach. While the evidence is readable it counts
/// by those names where they are held, and is this replica's lack where
/// they are not.
#[must_use]
pub fn value_of(
    entry: Option<&Heard>,
    source: Option<Source>,
    view: &SiblingView,
    committed: WeightedTimestamp,
) -> Value {
    let Some(source) = source else {
        return Value::W;
    };
    let (Ok(_), Ok(evidence), Ok(_)) = (view.recovery, view.evidence, view.formed) else {
        return Value::N;
    };
    let said = entry
        .filter(|heard| counts(heard, view, committed))
        .and_then(|heard| heard.said.map(|said| (said, heard.mark.epoch)));
    if predated(view, committed).is_some() {
        return match said {
            Some((Said::Accepted, _)) => Value::A,
            _ => Value::U,
        };
    }
    match source {
        Source::Live => match said {
            Some((Said::Accepted, _)) => Value::A,
            Some((Said::Left, _)) => Value::L,
            Some((Said::Yes, read))
                if view.terminating == Some(false) && read.next() >= view.epoch =>
            {
                Value::Y
            }
            Some((Said::Yes, _)) | None => Value::W,
        },
        Source::Gone => match (said, view.ended) {
            (Some((Said::Accepted, _)), _) => Value::A,
            _ if evidence == Evidence::Unreadable => Value::U,
            (_, Some(true)) => Value::A,
            (_, Some(false)) => Value::L,
            (_, None) => Value::N,
        },
    }
}

/// The formation of the chain `view` names under the sibling's id, where
/// a row committed at `committed` predates it.
fn predated(view: &SiblingView, committed: WeightedTimestamp) -> Option<Formed> {
    view.formed
        .ok()
        .flatten()
        .filter(|formed| formed.predates(committed))
}

/// How a row that hears stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hears {
    /// It has said yes and not accepted.
    Stated,
    /// It has accepted.
    Accepted,
}

/// What a row that hears may do on its siblings' values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// A stated row accepts.
    Accept,
    /// A stated row is refused: a sibling left without accepting.
    Refuse,
    /// Nothing yet.
    Wait,
    /// Nothing this replica can say: a sibling is judged on something
    /// only this replica lacks, and what it lacks could change the
    /// decision.
    Lacking,
    /// A stated row is let go: no sibling refused, none can still be
    /// waited on, and one can never be read.
    LetGo,
    /// An accepted row ends: no sibling can still ask about it.
    End,
}

/// What a row standing as `state` may do where its siblings count as
/// `values`, one per shard it awaits.
///
/// A stated row accepts on any sibling's accept, which decides alone;
/// failing that it is lacking while any sibling is this replica's lack,
/// since what it lacks may be an accept, then it is refused on any
/// sibling's leaving, accepts on a yes from every sibling, waits while
/// any sibling counts as nothing yet, and is let go otherwise, which
/// leaves an unreadable sibling. A stated row given no value at
/// all waits: nobody has said yes. An accepted row ends once every
/// sibling has accepted, left or become unreadable, waits while any says
/// yes or counts as nothing yet, and is lacking otherwise.
#[must_use]
pub fn decide(state: Hears, values: &[Value]) -> Decision {
    let any = |value| values.contains(&value);
    match state {
        Hears::Stated if values.is_empty() => Decision::Wait,
        Hears::Stated if any(Value::A) => Decision::Accept,
        Hears::Stated if any(Value::N) => Decision::Lacking,
        Hears::Stated if any(Value::L) => Decision::Refuse,
        Hears::Stated if values.iter().all(|value| *value == Value::Y) => Decision::Accept,
        Hears::Stated if any(Value::W) => Decision::Wait,
        Hears::Stated => Decision::LetGo,
        Hears::Accepted if any(Value::Y) || any(Value::W) => Decision::Wait,
        Hears::Accepted if any(Value::N) => Decision::Lacking,
        Hears::Accepted => Decision::End,
    }
}

/// Whether `entry` is an entry at all under `view`, for a row committed
/// at `committed`.
///
/// It is one where it is marked no later than the anchor's own epoch,
/// and either before the chain the window names under the sibling's id
/// formed, where the row predates that chain, or else no earlier than
/// the bridge of the sibling's newest recovery the published window
/// records. An entry that is not counted stands on the row until a
/// reading at a higher mark replaces it.
#[must_use]
pub fn counts(entry: &Heard, view: &SiblingView, committed: WeightedTimestamp) -> bool {
    let read = entry.mark.epoch;
    let of_its_chain = predated(view, committed).map_or_else(
        || {
            view.recovery
                .ok()
                .flatten()
                .is_none_or(|recovery| read >= recovery.bridge())
        },
        |formed| read < formed.epoch,
    );
    of_its_chain && read <= view.epoch
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

/// Whether a hearing row committed at `committed` puts a question to a
/// sibling read from `source` whose entry is `entry` under `view`.
///
/// Only a sibling that still runs is asked, and only until its value is
/// an accept or a leaving, which no later reading of a running sibling
/// takes back, and never where it is unreadable, which a running sibling
/// is only to a row predating its chain and which no reading moves.
#[must_use]
pub fn asks(
    entry: Option<&Heard>,
    source: Option<Source>,
    view: &SiblingView,
    committed: WeightedTimestamp,
) -> bool {
    source == Some(Source::Live)
        && !matches!(
            value_of(entry, source, view, committed),
            Value::A | Value::L | Value::U
        )
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

    /// The clock the row judged below was committed at: in epoch 1 of
    /// a one-second grid.
    const COMMITTED: WeightedTimestamp = WeightedTimestamp::from_millis(1_500);

    /// A chain formed in `epoch` of a one-second grid.
    fn formed_in(epoch: u64) -> Formed {
        Formed {
            epoch: Epoch::new(epoch),
            opens: WeightedTimestamp::from_millis(epoch * 1_000),
        }
    }

    /// A sibling that runs, formed at genesis, is not terminating, has no
    /// recovery recorded and whose departed names nobody holds, judged in
    /// epoch `epoch`.
    fn view(epoch: u64) -> SiblingView {
        SiblingView {
            epoch: Epoch::new(epoch),
            terminating: Some(false),
            recovery: Ok(None),
            evidence: Ok(Evidence::Live { terminating: false }),
            formed: Ok(Some(formed_in(0))),
            ended: None,
        }
    }

    fn gone(evidence: Evidence) -> SiblingView {
        SiblingView {
            evidence: Ok(evidence),
            ..view(5)
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
        let source = source_of(evicted, ShardId::ROOT);
        assert_eq!(source, None);
        for said in [Said::Yes, Said::Accepted, Said::Left] {
            assert_eq!(
                value_of(Some(&heard(1, Some(said))), source, &view(1), COMMITTED),
                Value::W
            );
        }
    }

    #[test]
    fn a_live_accepted_entry_is_an_accept() {
        let entry = heard(5, Some(Said::Accepted));
        assert_eq!(value_of(Some(&entry), LIVE, &view(5), COMMITTED), Value::A);
    }

    #[test]
    fn a_live_left_entry_is_a_leaving() {
        let entry = heard(5, Some(Said::Left));
        assert_eq!(value_of(Some(&entry), LIVE, &view(5), COMMITTED), Value::L);
    }

    #[test]
    fn a_live_yes_read_this_epoch_or_the_last_is_a_yes() {
        for read in [4, 5] {
            let entry = heard(read, Some(Said::Yes));
            assert_eq!(value_of(Some(&entry), LIVE, &view(5), COMMITTED), Value::Y);
        }
    }

    #[test]
    fn a_yes_two_epochs_old_is_not_read() {
        let entry = heard(3, Some(Said::Yes));
        assert_eq!(value_of(Some(&entry), LIVE, &view(5), COMMITTED), Value::W);
    }

    #[test]
    fn a_yes_of_a_terminating_sibling_waits() {
        let entry = heard(5, Some(Said::Yes));
        for terminating in [Some(true), None] {
            let view = SiblingView {
                terminating,
                ..view(5)
            };
            assert_eq!(value_of(Some(&entry), LIVE, &view, COMMITTED), Value::W);
        }
        let leaving = SiblingView {
            terminating: Some(true),
            ..view(5)
        };
        assert_eq!(
            value_of(
                Some(&heard(5, Some(Said::Accepted))),
                LIVE,
                &leaving,
                COMMITTED
            ),
            Value::A
        );
        assert_eq!(
            value_of(Some(&heard(5, Some(Said::Left))), LIVE, &leaving, COMMITTED),
            Value::L
        );
    }

    #[test]
    fn a_live_sibling_not_stated_or_unread_waits() {
        assert_eq!(
            value_of(Some(&heard(5, None)), LIVE, &view(5), COMMITTED),
            Value::W
        );
        assert_eq!(value_of(None, LIVE, &view(5), COMMITTED), Value::W);
    }

    #[test]
    fn an_entry_past_the_anchors_epoch_is_not_read() {
        for said in [Said::Yes, Said::Accepted, Said::Left] {
            let entry = heard(6, Some(said));
            assert_eq!(value_of(Some(&entry), LIVE, &view(5), COMMITTED), Value::W);
        }
        let entry = heard(6, Some(Said::Accepted));
        assert_eq!(
            value_of(Some(&entry), GONE, &gone(Evidence::Readable), COMMITTED),
            Value::N
        );
    }

    #[test]
    fn an_entry_below_a_recorded_bridge_is_not_read() {
        let recovered = SiblingView {
            recovery: Ok(Some(recovered_at(4))),
            ..view(5)
        };
        for said in [Said::Yes, Said::Accepted, Said::Left] {
            let before = heard(4, Some(said));
            assert_eq!(
                value_of(Some(&before), LIVE, &recovered, COMMITTED),
                Value::W
            );
        }
        let after = heard(5, Some(Said::Accepted));
        assert_eq!(
            value_of(Some(&after), LIVE, &recovered, COMMITTED),
            Value::A
        );
    }

    /// A window not held as published is this replica's lack, whatever
    /// the entry says and wherever the sibling is read from.
    #[test]
    fn an_unpublished_window_is_this_replicas_lack() {
        let entry = heard(5, Some(Said::Accepted));
        let no_recovery = SiblingView {
            recovery: Err(Unpublished),
            ..view(5)
        };
        let no_evidence = SiblingView {
            evidence: Err(Unpublished),
            ..view(5)
        };
        for view in [no_recovery, no_evidence] {
            assert_eq!(value_of(Some(&entry), LIVE, &view, COMMITTED), Value::N);
            assert_eq!(value_of(Some(&entry), GONE, &view, COMMITTED), Value::N);
        }
    }

    #[test]
    fn a_gone_siblings_accepted_entry_is_an_accept() {
        let entry = heard(5, Some(Said::Accepted));
        assert_eq!(
            value_of(Some(&entry), GONE, &gone(Evidence::Readable), COMMITTED),
            Value::A
        );
    }

    #[test]
    fn a_left_entry_is_not_read_for_a_gone_sibling() {
        for said in [Said::Left, Said::Yes] {
            let entry = heard(5, Some(said));
            assert_eq!(
                value_of(Some(&entry), GONE, &gone(Evidence::Readable), COMMITTED),
                Value::N
            );
            let named = SiblingView {
                ended: Some(true),
                ..gone(Evidence::Readable)
            };
            assert_eq!(value_of(Some(&entry), GONE, &named, COMMITTED), Value::A);
        }
    }

    #[test]
    fn a_gone_siblings_names_holding_the_member_are_an_accept() {
        let named = SiblingView {
            ended: Some(true),
            ..gone(Evidence::Readable)
        };
        assert_eq!(value_of(None, GONE, &named, COMMITTED), Value::A);
    }

    #[test]
    fn a_gone_siblings_names_without_the_member_are_a_leaving() {
        let unnamed = SiblingView {
            ended: Some(false),
            ..gone(Evidence::Readable)
        };
        assert_eq!(value_of(None, GONE, &unnamed, COMMITTED), Value::L);
        let entry = heard(5, Some(Said::Accepted));
        assert_eq!(value_of(Some(&entry), GONE, &unnamed, COMMITTED), Value::A);
    }

    /// The names may still arrive while the evidence can be read, so
    /// their absence here is this replica's lack and no verdict.
    #[test]
    fn a_gone_sibling_without_names_waits() {
        for evidence in [
            Evidence::Readable,
            Evidence::Unknown,
            Evidence::Live { terminating: true },
        ] {
            assert_eq!(value_of(None, GONE, &gone(evidence), COMMITTED), Value::N);
        }
    }

    #[test]
    fn a_gone_sibling_without_names_past_its_evidence_is_unreadable() {
        assert_eq!(
            value_of(None, GONE, &gone(Evidence::Unreadable), COMMITTED),
            Value::U
        );
    }

    /// Past its evidence a gone sibling is one value on every replica:
    /// names held, holding the member or not, count as names not held,
    /// and so does any entry but an accepted one. An accepted entry is
    /// on the committed row, which every replica reads alike.
    #[test]
    fn a_gone_sibling_past_its_evidence_is_unreadable_whatever_names_are_held() {
        for ended in [Some(true), Some(false), None] {
            let view = SiblingView {
                ended,
                ..gone(Evidence::Unreadable)
            };
            assert_eq!(value_of(None, GONE, &view, COMMITTED), Value::U);
            for said in [Said::Yes, Said::Left] {
                let entry = heard(5, Some(said));
                assert_eq!(value_of(Some(&entry), GONE, &view, COMMITTED), Value::U);
            }
            let accepted = heard(5, Some(Said::Accepted));
            assert_eq!(value_of(Some(&accepted), GONE, &view, COMMITTED), Value::A);
        }
    }

    /// While the evidence is not unreadable the names decide wherever
    /// they are held, whatever else the evidence reads.
    #[test]
    fn a_gone_siblings_names_are_read_while_its_evidence_is_readable() {
        for evidence in [
            Evidence::Readable,
            Evidence::Unknown,
            Evidence::Live { terminating: true },
        ] {
            for (ended, value) in [(true, Value::A), (false, Value::L)] {
                let view = SiblingView {
                    ended: Some(ended),
                    ..gone(evidence)
                };
                assert_eq!(value_of(None, GONE, &view, COMMITTED), value);
            }
        }
    }

    /// A sibling is asked only while the trie runs it, and only until
    /// what it said can no longer change: a gone sibling is read from
    /// its terminal's names, and no window is no source at all.
    #[test]
    fn a_sibling_is_asked_only_while_it_runs_and_has_not_settled() {
        for entry in [None, Some(heard(5, None)), Some(heard(5, Some(Said::Yes)))] {
            assert!(asks(entry.as_ref(), LIVE, &view(5), COMMITTED));
            assert!(!asks(
                entry.as_ref(),
                GONE,
                &gone(Evidence::Readable),
                COMMITTED
            ));
            assert!(!asks(entry.as_ref(), None, &view(5), COMMITTED));
        }
        for said in [Said::Accepted, Said::Left] {
            assert!(!asks(
                Some(&heard(5, Some(said))),
                LIVE,
                &view(5),
                COMMITTED
            ));
        }
        // An entry the window does not count is no answer yet.
        assert!(asks(
            Some(&heard(6, Some(Said::Left))),
            LIVE,
            &view(5),
            COMMITTED
        ));
    }

    /// Under a window not held as published nothing is taken as said, so
    /// a running sibling is asked whatever its entry holds.
    #[test]
    fn a_sibling_is_asked_while_the_published_window_is_not_held() {
        let no_recovery = SiblingView {
            recovery: Err(Unpublished),
            ..view(5)
        };
        let no_evidence = SiblingView {
            evidence: Err(Unpublished),
            ..view(5)
        };
        for unpublished in [no_recovery, no_evidence] {
            for said in [Said::Yes, Said::Accepted, Said::Left] {
                let entry = heard(5, Some(said));
                assert!(asks(Some(&entry), LIVE, &unpublished, COMMITTED));
                assert!(!asks(Some(&entry), GONE, &unpublished, COMMITTED));
            }
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
        assert!(!counts(&entry, &recovered, COMMITTED), "below the bridge");
        assert!(
            !counts(&heard(6, Some(Said::Left)), &view(5), COMMITTED),
            "past the anchor"
        );
        assert!(counts(&heard(5, Some(Said::Left)), &recovered, COMMITTED));
        assert!(
            asks(Some(&entry), LIVE, &recovered, COMMITTED),
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

    #[test]
    fn a_stated_row_accepts_on_any_accept() {
        for rest in [Value::L, Value::Y, Value::W, Value::U] {
            assert_eq!(decide(Hears::Stated, &[rest, Value::A]), Decision::Accept);
        }
    }

    #[test]
    fn a_stated_row_is_refused_on_a_leaving_with_no_accept() {
        for rest in [Value::Y, Value::W, Value::U] {
            assert_eq!(decide(Hears::Stated, &[rest, Value::L]), Decision::Refuse);
        }
    }

    #[test]
    fn a_stated_row_accepts_on_a_yes_from_every_sibling() {
        assert_eq!(
            decide(Hears::Stated, &[Value::Y, Value::Y]),
            Decision::Accept
        );
    }

    #[test]
    fn a_stated_row_with_no_sibling_read_waits() {
        assert_eq!(decide(Hears::Stated, &[]), Decision::Wait);
    }

    #[test]
    fn a_stated_row_waits_while_a_sibling_is_unread() {
        for rest in [Value::Y, Value::U] {
            assert_eq!(decide(Hears::Stated, &[rest, Value::W]), Decision::Wait);
        }
    }

    #[test]
    fn a_stated_row_beside_an_unreadable_sibling_is_let_go() {
        assert_eq!(
            decide(Hears::Stated, &[Value::Y, Value::U]),
            Decision::LetGo
        );
        assert_eq!(decide(Hears::Stated, &[Value::U]), Decision::LetGo);
    }

    #[test]
    fn a_stated_row_is_lacking_where_no_sibling_accepted_and_one_is_unjudged() {
        for rest in [Value::L, Value::Y, Value::W, Value::U] {
            assert_eq!(decide(Hears::Stated, &[rest, Value::N]), Decision::Lacking);
        }
        assert_eq!(
            decide(Hears::Stated, &[Value::N, Value::A]),
            Decision::Accept
        );
    }

    #[test]
    fn an_accepted_row_is_lacking_where_nothing_waits_and_a_sibling_is_unjudged() {
        for rest in [Value::A, Value::L, Value::U] {
            assert_eq!(
                decide(Hears::Accepted, &[rest, Value::N]),
                Decision::Lacking
            );
        }
        for waits in [Value::Y, Value::W] {
            assert_eq!(decide(Hears::Accepted, &[waits, Value::N]), Decision::Wait);
        }
    }

    #[test]
    fn an_accepted_row_ends_once_no_sibling_can_still_ask() {
        assert_eq!(
            decide(Hears::Accepted, &[Value::A, Value::L, Value::U]),
            Decision::End
        );
        for pending in [Value::Y, Value::W] {
            assert_eq!(
                decide(Hears::Accepted, &[Value::A, pending]),
                Decision::Wait
            );
        }
    }

    #[test]
    fn an_unread_window_decides_to_wait() {
        assert_eq!(decide(Hears::Stated, &[Value::W]), Decision::Wait);
        assert_eq!(decide(Hears::Accepted, &[Value::W]), Decision::Wait);
    }

    /// A sibling whose id runs, at the anchor, a chain formed in epoch 3,
    /// judged in epoch 5 for a row committed in epoch 1.
    fn predated(source_evidence: Evidence) -> SiblingView {
        SiblingView {
            evidence: Ok(source_evidence),
            formed: Ok(Some(formed_in(3))),
            ..view(5)
        }
    }

    /// Every evidence a window can give a sibling.
    const EVIDENCE: [Evidence; 5] = [
        Evidence::Live { terminating: false },
        Evidence::Live { terminating: true },
        Evidence::Readable,
        Evidence::Unknown,
        Evidence::Unreadable,
    ];

    /// A row committed before the chain its sibling's id names at the
    /// anchor formed awaited an earlier chain, which no reading of the
    /// later one and nothing the window says of it can answer for: short
    /// of an accept of the earlier chain the sibling reads unreadable,
    /// whether the trie runs it, it is gone with its evidence readable,
    /// or its names are held. An accept marked in the later chain's
    /// epochs is the later chain's, and counts no more than its yes.
    #[test]
    fn a_predated_sibling_reads_unreadable() {
        let entries = [
            None,
            Some(heard(1, None)),
            Some(heard(1, Some(Said::Yes))),
            Some(heard(1, Some(Said::Left))),
            Some(heard(5, Some(Said::Yes))),
            Some(heard(4, Some(Said::Left))),
            Some(heard(3, Some(Said::Accepted))),
            Some(heard(5, Some(Said::Accepted))),
        ];
        for evidence in EVIDENCE {
            for ended in [Some(true), Some(false), None] {
                let view = SiblingView {
                    ended,
                    ..predated(evidence)
                };
                for source in [LIVE, GONE] {
                    for entry in &entries {
                        assert_eq!(
                            value_of(entry.as_ref(), source, &view, COMMITTED),
                            Value::U,
                            "{source:?}, {evidence:?}, {ended:?}, {entry:?}",
                        );
                    }
                }
            }
        }
        assert_eq!(decide(Hears::Stated, &[Value::U]), Decision::LetGo);
        assert_eq!(decide(Hears::Accepted, &[Value::U]), Decision::End);
    }

    /// The earlier chain's accept, marked before the later chain formed,
    /// is what the row awaited, and counts however the window reads the
    /// id now.
    #[test]
    fn a_predated_siblings_earlier_accept_still_counts() {
        for evidence in EVIDENCE {
            for source in [LIVE, GONE] {
                for epoch in [1, 2] {
                    let entry = heard(epoch, Some(Said::Accepted));
                    assert_eq!(
                        value_of(Some(&entry), source, &predated(evidence), COMMITTED),
                        Value::A,
                        "{source:?}, {evidence:?}, marked in {epoch}",
                    );
                }
            }
        }
    }

    /// A recovery the window records for the id is the later chain's,
    /// whose bridge says nothing of what the earlier chain committed: an
    /// accept of the earlier chain below it still counts, where the same
    /// bridge on the chain the row awaited would leave it unread.
    #[test]
    fn a_later_lifes_recovery_bridges_no_entry_of_the_earlier() {
        let entry = heard(2, Some(Said::Accepted));
        let later = SiblingView {
            recovery: Ok(Some(recovered_at(4))),
            ..predated(Evidence::Live { terminating: false })
        };
        assert!(entry.mark.epoch < recovered_at(4).bridge());
        assert!(counts(&entry, &later, COMMITTED));
        assert_eq!(value_of(Some(&entry), LIVE, &later, COMMITTED), Value::A);

        let awaited = SiblingView {
            formed: Ok(Some(formed_in(0))),
            ..later
        };
        assert!(!counts(&entry, &awaited, COMMITTED));
        assert_eq!(value_of(Some(&entry), LIVE, &awaited, COMMITTED), Value::W);
    }

    /// A row committed at or after the opening of the window its sibling's
    /// chain first ran in awaited that chain, and reads it as any other: a
    /// row committed the instant before predates it. A window carrying no
    /// record of the sibling predates nothing.
    #[test]
    fn a_row_committed_in_its_siblings_first_window_reads_it_live() {
        let formed = SiblingView {
            formed: Ok(Some(formed_in(1))),
            ..view(5)
        };
        let opens = formed_in(1).opens;
        let before = WeightedTimestamp::from_millis(opens.as_millis() - 1);
        for committed in [opens, COMMITTED] {
            for (entry, value) in [
                (heard(5, Some(Said::Yes)), Value::Y),
                (heard(5, Some(Said::Left)), Value::L),
                (heard(2, Some(Said::Accepted)), Value::A),
                (heard(5, None), Value::W),
            ] {
                assert_eq!(
                    value_of(Some(&entry), LIVE, &formed, committed),
                    value,
                    "committed at {committed:?}, {entry:?}",
                );
            }
        }
        assert_eq!(
            value_of(Some(&heard(5, Some(Said::Yes))), LIVE, &formed, before),
            Value::U,
        );

        let unrecorded = SiblingView {
            formed: Ok(None),
            ..gone(Evidence::Unreadable)
        };
        assert_eq!(value_of(None, GONE, &unrecorded, COMMITTED), Value::U);
        let named = SiblingView {
            ended: Some(false),
            ..SiblingView {
                formed: Ok(None),
                ..gone(Evidence::Readable)
            }
        };
        assert_eq!(value_of(None, GONE, &named, COMMITTED), Value::L);
    }

    /// A formation not held as published is this replica's lack, whatever
    /// the entry says and wherever the sibling is read from, and a running
    /// sibling is asked.
    #[test]
    fn an_unpublished_formation_is_this_replicas_lack() {
        let unpublished = SiblingView {
            formed: Err(Unpublished),
            ..view(5)
        };
        for entry in [
            None,
            Some(heard(2, Some(Said::Accepted))),
            Some(heard(5, Some(Said::Yes))),
            Some(heard(5, Some(Said::Left))),
        ] {
            for source in [LIVE, GONE] {
                assert_eq!(
                    value_of(entry.as_ref(), source, &unpublished, COMMITTED),
                    Value::N,
                    "{source:?}, {entry:?}",
                );
            }
            assert!(asks(entry.as_ref(), LIVE, &unpublished, COMMITTED));
        }
    }

    /// A running sibling whose chain the row predates is asked nothing:
    /// no reading of it can move the row's value.
    #[test]
    fn a_predated_sibling_is_not_asked() {
        let running = predated(Evidence::Live { terminating: false });
        for entry in [
            None,
            Some(heard(5, None)),
            Some(heard(5, Some(Said::Yes))),
            Some(heard(1, Some(Said::Yes))),
            Some(heard(5, Some(Said::Left))),
            Some(heard(2, Some(Said::Accepted))),
            Some(heard(5, Some(Said::Accepted))),
        ] {
            assert!(
                !asks(entry.as_ref(), LIVE, &running, COMMITTED),
                "{entry:?}",
            );
        }
    }
}
