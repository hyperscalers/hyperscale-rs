//! The read frontier: how far along each producer's chain this shard
//! has read, committed as state, and what it refuses.
//!
//! Each consuming shard keeps, per producer [`ShardId`], the highest
//! anchor of that producer its blocks have carried a state claim at. A
//! crossing record read present below that frontier is refused, so an
//! absence of the record at or above it comes after every presence this
//! chain ever committed, and licenses deleting the answer with no grace
//! and no clock. Every claim a block carries raises its producer's
//! entry, and only block content does: an absence is a hash key with
//! no bytes, so no voter can tell a deleting absence from any other, and
//! the raise has to be the same rule for every reading.
//!
//! A mark is `(epoch, height)`, epoch first. Heights alone do not order
//! a lineage: a halt recovery rebinds the chain to a fresh committee at
//! a later epoch, so a mark taken after the bridge orders above every
//! mark taken before it even where heights repeat, and an entry a
//! replaced committee's forged suffix raised delays the recovered
//! chain's readings by at most one epoch and never wedges them. A split
//! child starts above its parent's terminal and a merged parent above
//! the larger child terminal, so marks rise across every reshape too.
//!
//! An entry outlives the readings that raised it by at most
//! [`RETENTION_HORIZON`] past its epoch's window: a claim anchored more
//! than a horizon before the block is refused on its age, so an entry
//! that old could refuse nothing the age bound does not and is dropped.

use std::collections::BTreeMap;
use std::fmt;

use hyperscale_hbor::Hbor;

use crate::{
    Anchor, Block, BlockHeight, Epoch, EpochWindows, RETENTION_HORIZON, ShardId, StateClaim,
    SubstateKey, TxHash, WeightedTimestamp,
};

/// Where an anchor sits in its producer's lineage: the epoch whose
/// committee certified the anchor's header, then its height.
///
/// The epoch is read off the anchor's own clock, the header's parent-QC
/// weighted timestamp, so it is the one the schedule seats that
/// committee in; nothing about the reader's head enters it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub struct ReadMark {
    /// The epoch the anchor's clock falls in.
    pub epoch: Epoch,
    /// The anchor's height.
    pub height: BlockHeight,
}

impl ReadMark {
    /// The mark of `anchor` on the `windows` grid.
    #[must_use]
    pub const fn of(anchor: &Anchor, windows: EpochWindows) -> Self {
        Self {
            epoch: windows.epoch_for(anchor.ts),
            height: anchor.height,
        }
    }
}

/// The highest mark each producer has been read at, at most one entry
/// per producer [`ShardId`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadFrontier {
    entries: BTreeMap<ShardId, ReadMark>,
}

impl ReadFrontier {
    /// A table over `entries`, keeping the highest mark where a shard
    /// is named twice.
    pub fn from_entries(entries: impl IntoIterator<Item = (ShardId, ReadMark)>) -> Self {
        let mut table = Self::default();
        for (shard, mark) in entries {
            table.raise(shard, mark);
        }
        table
    }

    /// Every entry, by producer.
    pub fn entries(&self) -> impl Iterator<Item = (ShardId, ReadMark)> + '_ {
        self.entries.iter().map(|(shard, mark)| (*shard, *mark))
    }

    /// Whether the table holds no entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry for `shard` itself, if one stands.
    #[must_use]
    pub fn entry(&self, shard: ShardId) -> Option<ReadMark> {
        self.entries.get(&shard).copied()
    }

    /// The floor a reading of `shard` must meet: the highest entry over
    /// its lineage, the shard itself, its ancestors and its descendants,
    /// and never a sibling or a sibling's descendant.
    ///
    /// Ancestors cost nothing, since their marks sit below any anchor of
    /// the shard. Descendants are the entries that matter: once a split
    /// child of the shard has been read, a stale anchor of the
    /// terminated parent that still shows a record is refused. Siblings
    /// are kept apart because their heights are unrelated, and a floor
    /// that mixed them would refuse a slower sibling for good.
    #[must_use]
    pub fn floor(&self, shard: ShardId) -> Option<ReadMark> {
        self.entries
            .iter()
            .filter(|(entry, _)| overlaps(**entry, shard))
            .map(|(_, mark)| *mark)
            .max()
    }

    /// Whether a reading of `shard` at `mark` sits below the floor.
    #[must_use]
    pub fn refuses(&self, shard: ShardId, mark: ReadMark) -> bool {
        self.floor(shard).is_some_and(|floor| mark < floor)
    }

    /// Raise `shard`'s entry to `mark` where it is higher, saying whether
    /// anything changed.
    pub fn raise(&mut self, shard: ShardId, mark: ReadMark) -> bool {
        match self.entries.get(&shard) {
            Some(held) if *held >= mark => false,
            _ => {
                self.entries.insert(shard, mark);
                true
            }
        }
    }

    /// Take the pointwise maximum with `other`.
    pub fn fold_max(&mut self, other: &Self) {
        for (shard, mark) in other.entries() {
            self.raise(shard, mark);
        }
    }

    /// What one block does to the table: the prunes, then the raises.
    ///
    /// An entry `(E, h)` refuses only readings anchored in `E`'s window
    /// or an earlier one, and a claim anchored more than
    /// [`RETENTION_HORIZON`] before the block is refused on its age
    /// wherever its mark sits. So once the block's anchor is a horizon
    /// past the close of `E`'s window the entry can refuse nothing the
    /// age bound does not, and it is dropped. The rule reads the block's
    /// anchor, the entry and a constant, so every replica prunes alike,
    /// and a departed producer's entry follows its last anchor out one
    /// horizon later with no departure record read. A grid of one window
    /// closes no epoch, so nothing is pruned on it.
    pub fn advance(&mut self, inputs: &FrontierInputs) {
        if inputs.windows.epoch_duration_ms() != 0 {
            self.entries.retain(|_, mark| {
                inputs
                    .anchor
                    .elapsed_since(inputs.windows.window_of(mark.epoch).end)
                    <= RETENTION_HORIZON
            });
        }
        for (shard, mark) in &inputs.marks {
            self.raise(*shard, *mark);
        }
    }
}

/// Whether two shards share a lineage: one is the other, an ancestor of
/// it or a descendant of it.
const fn overlaps(a: ShardId, b: ShardId) -> bool {
    a.is_ancestor_of(b) || b.is_ancestor_of(a)
}

/// What a block does to the read frontier.
///
/// A function of the block's content, its anchor and the epoch grid
/// alone: nothing node-local and nothing off a beacon fold enters it,
/// so two replicas that have folded different beacon heights write one
/// `state_root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontierInputs {
    /// The shard whose table the block advances.
    pub local: ShardId,
    /// The block's own anchor: its parent QC's weighted timestamp.
    pub anchor: WeightedTimestamp,
    /// The epoch grid marks are read on.
    pub windows: EpochWindows,
    /// The highest mark per producer among the block's claims.
    pub marks: BTreeMap<ShardId, ReadMark>,
}

impl FrontierInputs {
    /// The inputs of a block carrying `claims` at `anchor`.
    #[must_use]
    pub fn for_block(
        claims: &[StateClaim],
        windows: EpochWindows,
        anchor: WeightedTimestamp,
        local: ShardId,
    ) -> Self {
        let mut marks: BTreeMap<ShardId, ReadMark> = BTreeMap::new();
        for claim in claims {
            let mark = ReadMark::of(&claim.anchor, windows);
            marks
                .entry(claim.anchor.shard)
                .and_modify(|held| *held = (*held).max(mark))
                .or_insert(mark);
        }
        Self {
            local,
            anchor,
            windows,
            marks,
        }
    }

    /// The inputs of `block`, read off its claims, its parent QC's clock
    /// and its shard.
    #[must_use]
    pub fn of_block(block: &Block, windows: EpochWindows) -> Self {
        Self::for_block(
            block.state_claims(),
            windows,
            block.header().parent_qc().weighted_timestamp(),
            block.header().shard_id(),
        )
    }

    /// The inputs of a block carrying no claim, on a grid of one window:
    /// what a fixture hands a commit that raises nothing.
    #[must_use]
    pub fn still(local: ShardId) -> Self {
        Self::for_block(&[], EpochWindows::new(0), WeightedTimestamp::ZERO, local)
    }
}

/// One fenced reading a block carries: the key, the producer it was
/// read from and the mark it was read at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    /// The cell read.
    pub key: SubstateKey,
    /// The shard the claim's anchor belongs to.
    pub shard: ShardId,
    /// The claim's anchor, as a mark.
    pub mark: ReadMark,
}

/// What the read frontier fences in a block beyond its raises: the
/// record presences its claims carry, the absences beside them, and the
/// answer cells its late deliveries would have to find gone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadFence {
    /// Every held reading whose bytes decode as a crossing record.
    pub presences: Vec<Reading>,
    /// Every absent reading the block carries, whichever key.
    pub absences: Vec<Reading>,
    /// For each transaction carried past its validity end on a record
    /// presence, the answer cells of every crossing it consumes here.
    /// While either answer stands the delivery is a replay of one this
    /// shard already answered, and is refused.
    pub late_answers: BTreeMap<TxHash, Vec<SubstateKey>>,
}

/// Why the read frontier refuses a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontierRefusal {
    /// A record presence read below the floor the parent state left for
    /// its producer's lineage.
    BelowFloor {
        /// The reading refused.
        reading: Reading,
        /// The floor it fell below.
        floor: ReadMark,
    },
    /// A record presence read below an absence of the same key the block
    /// carries from the same lineage.
    BelowAbsence {
        /// The reading refused.
        reading: Reading,
        /// The absence above it.
        absence: Reading,
    },
    /// A late delivery whose crossing this shard has already answered.
    AnswerStands {
        /// The delivery refused.
        tx: TxHash,
        /// The answer cell standing.
        answer: SubstateKey,
    },
}

impl fmt::Display for FrontierRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BelowFloor { reading, floor } => write!(
                f,
                "record {:?} read present on {:?} at epoch {} height {}, below the read \
                 frontier's floor of epoch {} height {}",
                reading.key,
                reading.shard,
                reading.mark.epoch.inner(),
                reading.mark.height.inner(),
                floor.epoch.inner(),
                floor.height.inner(),
            ),
            Self::BelowAbsence { reading, absence } => write!(
                f,
                "record {:?} read present on {:?} at epoch {} height {}, below the same \
                 block's absence of it on {:?} at epoch {} height {}",
                reading.key,
                reading.shard,
                reading.mark.epoch.inner(),
                reading.mark.height.inner(),
                absence.shard,
                absence.mark.epoch.inner(),
                absence.mark.height.inner(),
            ),
            Self::AnswerStands { tx, answer } => write!(
                f,
                "late delivery {tx:?} consumes a crossing whose answer {answer:?} stands",
            ),
        }
    }
}

/// What the fence refuses of a block, for a proposer to drop before
/// building.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Refused {
    /// The record presences refused.
    pub readings: Vec<Reading>,
    /// The late deliveries refused.
    pub deliveries: Vec<TxHash>,
}

impl ReadFence {
    /// Judge the block against `parent`, the table as the parent state
    /// left it, and `standing`, whether an answer cell is present in the
    /// parent state or written by the block's own finalizations.
    ///
    /// # Errors
    ///
    /// The first refusal found: a presence below its lineage's floor, a
    /// presence below a same-block absence of its key, or a late
    /// delivery either of whose answers stands.
    pub fn check(
        &self,
        parent: &ReadFrontier,
        standing: impl Fn(SubstateKey) -> bool,
    ) -> Result<(), Box<FrontierRefusal>> {
        for reading in &self.presences {
            if let Some(refusal) = self.refuses_presence(parent, *reading) {
                return Err(Box::new(refusal));
            }
        }
        for (tx, answers) in &self.late_answers {
            if let Some(answer) = answers.iter().copied().find(|answer| standing(*answer)) {
                return Err(Box::new(FrontierRefusal::AnswerStands { tx: *tx, answer }));
            }
        }
        Ok(())
    }

    /// Everything [`check`](Self::check) would refuse, all of it.
    #[must_use]
    pub fn refused(
        &self,
        parent: &ReadFrontier,
        standing: impl Fn(SubstateKey) -> bool,
    ) -> Refused {
        Refused {
            readings: self
                .presences
                .iter()
                .copied()
                .filter(|reading| self.refuses_presence(parent, *reading).is_some())
                .collect(),
            deliveries: self
                .late_answers
                .iter()
                .filter(|(_, answers)| answers.iter().any(|answer| standing(*answer)))
                .map(|(tx, _)| *tx)
                .collect(),
        }
    }

    fn refuses_presence(&self, parent: &ReadFrontier, reading: Reading) -> Option<FrontierRefusal> {
        if let Some(floor) = parent
            .floor(reading.shard)
            .filter(|floor| reading.mark < *floor)
        {
            return Some(FrontierRefusal::BelowFloor { reading, floor });
        }
        self.absences
            .iter()
            .copied()
            .find(|absence| {
                absence.key == reading.key
                    && overlaps(absence.shard, reading.shard)
                    && reading.mark < absence.mark
            })
            .map(|absence| FrontierRefusal::BelowAbsence { reading, absence })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::test_utils::test_key;
    use crate::{Hash, StateRoot};

    const WINDOW_MS: u64 = 1_000_000;

    fn windows() -> EpochWindows {
        EpochWindows::new(WINDOW_MS)
    }

    fn mark(epoch: u64, height: u64) -> ReadMark {
        ReadMark {
            epoch: Epoch::new(epoch),
            height: BlockHeight::new(height),
        }
    }

    fn anchor(shard: ShardId, epoch: u64, height: u64) -> Anchor {
        Anchor {
            shard,
            height: BlockHeight::new(height),
            state_root: StateRoot::from_raw(Hash::ZERO),
            ts: WeightedTimestamp::from_millis(epoch * WINDOW_MS + 1),
        }
    }

    fn inputs(local: ShardId, anchor_ms: u64, marks: &[(ShardId, ReadMark)]) -> FrontierInputs {
        FrontierInputs {
            local,
            anchor: WeightedTimestamp::from_millis(anchor_ms),
            windows: windows(),
            marks: marks.iter().copied().collect(),
        }
    }

    /// The floor over a lineage takes the shard, its ancestors and its
    /// descendants, and never a sibling: a reading at a split parent's
    /// anchor is refused once either child has an entry, and a
    /// sibling's high entry refuses nothing.
    #[test]
    fn the_floor_is_the_lineages_and_never_a_siblings() {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let sibling = ShardId::leaf(1, 1);
        let table = ReadFrontier::from_entries([
            (parent, mark(3, 100)),
            (left, mark(4, 110)),
            (sibling, mark(9, 900)),
        ]);
        assert_eq!(
            table.floor(parent),
            Some(mark(4, 110)),
            "the child's entry floors the parent"
        );
        assert_eq!(table.floor(left), Some(mark(4, 110)));
        assert_eq!(
            table.floor(right),
            Some(mark(3, 100)),
            "the sibling child is floored by the parent alone"
        );
        assert!(
            table.refuses(parent, mark(3, 101)),
            "a stale anchor of the terminated parent is refused"
        );
        assert!(
            !table.refuses(right, mark(4, 105)),
            "a sibling's higher entry refuses nothing"
        );
        assert_eq!(
            ReadFrontier::from_entries([(parent, mark(3, 100))]).floor(sibling),
            None,
            "and a shard outside every entry's lineage has no floor",
        );
    }

    /// Marks order across a split, a merge and a recovery bridge:
    /// epoch first, so a fresh committee at a later epoch orders above
    /// every mark of the halted chain even where heights repeat.
    #[test]
    fn marks_order_by_epoch_before_height() {
        assert!(mark(5, 1) > mark(4, 1_000_000));
        assert!(mark(4, 11) > mark(4, 10));
        let shard = ShardId::leaf(1, 0);
        assert_eq!(ReadMark::of(&anchor(shard, 7, 42), windows()), mark(7, 42));
    }

    /// The bridge: with an entry of P at `(E, H)` for any `H`, a reading
    /// of P at `(E + 1, 1)` passes and one at `(E, H − 1)` is refused; an
    /// entry raised before a recovery at an epoch below the seating
    /// epoch refuses no reading at it.
    #[test]
    fn a_forged_entry_delays_one_epoch_and_never_wedges() {
        let producer = ShardId::leaf(1, 0);
        let forged = ReadFrontier::from_entries([(producer, mark(6, 5_000_000))]);
        assert!(forged.refuses(producer, mark(6, 4_999_999)));
        assert!(!forged.refuses(producer, mark(7, 1)));
        let before = ReadFrontier::from_entries([(producer, mark(5, 400))]);
        assert!(
            !before.refuses(producer, mark(6, 1)),
            "a pre-recovery entry refuses nothing at the seating epoch"
        );
    }

    /// Advancing is monotone apart from the prune, applying the same
    /// inputs twice changes nothing, and an entry one horizon past its
    /// window's close is dropped while one a millisecond inside stands.
    #[test]
    fn advance_is_idempotent_and_prunes_one_horizon_past_the_window() {
        let local = ShardId::ROOT;
        let producer = ShardId::leaf(1, 0);
        let other = ShardId::leaf(1, 1);
        let mut table = ReadFrontier::from_entries([(producer, mark(2, 10))]);
        let raise = inputs(
            local,
            2 * WINDOW_MS + 500,
            &[(producer, mark(2, 12)), (other, mark(2, 3))],
        );
        table.advance(&raise);
        let once = table.clone();
        table.advance(&raise);
        assert_eq!(table, once, "the same inputs twice change nothing");
        assert_eq!(table.entry(producer), Some(mark(2, 12)));
        let lower = inputs(local, 2 * WINDOW_MS + 600, &[(producer, mark(2, 11))]);
        table.advance(&lower);
        assert_eq!(
            table.entry(producer),
            Some(mark(2, 12)),
            "a lower mark lowers nothing"
        );

        let close = windows().window_of(Epoch::new(2)).end;
        let inside = close.plus(RETENTION_HORIZON);
        table.advance(&inputs(local, inside.as_millis(), &[]));
        assert_eq!(
            table.entry(producer),
            Some(mark(2, 12)),
            "at the horizon the entry stands"
        );
        table.advance(&inputs(
            local,
            inside.plus(Duration::from_millis(1)).as_millis(),
            &[],
        ));
        assert_eq!(
            table.entry(producer),
            None,
            "a millisecond past it the entry is dropped"
        );
        assert_eq!(table.entry(other), None);
    }

    /// A grid of one window closes no epoch, so it prunes nothing.
    #[test]
    fn a_single_window_grid_prunes_nothing() {
        let producer = ShardId::leaf(1, 0);
        let mut table = ReadFrontier::from_entries([(producer, mark(0, 10))]);
        table.advance(&FrontierInputs {
            local: ShardId::ROOT,
            anchor: WeightedTimestamp::from_millis(u64::MAX / 2),
            windows: EpochWindows::new(0),
            marks: BTreeMap::new(),
        });
        assert_eq!(table.entry(producer), Some(mark(0, 10)));
    }

    /// The fence refuses a presence below the floor, a presence below a
    /// same-block absence of its key from the same lineage, and a late
    /// delivery whose answer stands; and passes everything else.
    #[test]
    fn the_fence_refuses_the_three_cases_and_passes_the_rest() {
        let producer = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let record = test_key(0x10);
        let parent = ReadFrontier::from_entries([(producer, mark(3, 50))]);
        let reading = |shard, epoch, height| Reading {
            key: record,
            shard,
            mark: mark(epoch, height),
        };
        let none = |_| false;

        let below = ReadFence {
            presences: vec![reading(producer, 3, 49)],
            ..ReadFence::default()
        };
        assert!(matches!(
            below.check(&parent, none).err().map(|refusal| *refusal),
            Some(FrontierRefusal::BelowFloor { .. })
        ));

        let at = ReadFence {
            presences: vec![reading(producer, 3, 50)],
            ..ReadFence::default()
        };
        assert_eq!(
            at.check(&parent, none),
            Ok(()),
            "at the floor a presence passes"
        );

        let under_absence = ReadFence {
            presences: vec![reading(producer, 3, 60)],
            absences: vec![reading(producer, 3, 61)],
            ..ReadFence::default()
        };
        assert!(matches!(
            under_absence
                .check(&parent, none)
                .err()
                .map(|refusal| *refusal),
            Some(FrontierRefusal::BelowAbsence { .. })
        ));

        let sibling_absence = ReadFence {
            presences: vec![reading(producer, 3, 60)],
            absences: vec![reading(sibling, 9, 900)],
            ..ReadFence::default()
        };
        assert_eq!(
            sibling_absence.check(&parent, none),
            Ok(()),
            "an absence from an unrelated lineage orders nothing",
        );

        let tx = TxHash::from(Hash::from_bytes(b"late"));
        let answer = test_key(0x20);
        let late = ReadFence {
            late_answers: BTreeMap::from([(tx, vec![test_key(0x21), answer])]),
            ..ReadFence::default()
        };
        assert_eq!(late.check(&parent, none), Ok(()));
        assert_eq!(
            late.check(&parent, |key| key == answer),
            Err(Box::new(FrontierRefusal::AnswerStands { tx, answer })),
        );

        let everything = ReadFence {
            presences: vec![reading(producer, 3, 49), reading(producer, 3, 60)],
            absences: vec![reading(producer, 3, 61)],
            late_answers: late.late_answers,
        };
        let refused = everything.refused(&parent, |key| key == answer);
        assert_eq!(
            refused.readings,
            vec![reading(producer, 3, 49), reading(producer, 3, 60)]
        );
        assert_eq!(refused.deliveries, vec![tx]);
    }
}
