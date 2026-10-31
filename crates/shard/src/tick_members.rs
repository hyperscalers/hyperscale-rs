//! What a block's member lines are judged over: tick membership at the
//! block's parent, and what committed content up to the parent says each
//! member it may name has in hand.
//!
//! A proposer and a voter stand at different committed tips, so both read
//! the chain up to the parent as the committed tier plus each pending
//! ancestor's content, and so read one input.

use std::collections::{BTreeSet, HashSet};

use hyperscale_engine::tick_select::{
    CommittedSets, Judged, ManifestBudget, SiblingViews, Unlicensed, accepting, ends_stand,
    legs_stand, terms_of,
};
use hyperscale_storage::{MemberIndex, MemberInputs, MemberRow, RowState, record_arrivals};
use hyperscale_types::{
    Block, BlockHeight, Engagement, EpochWindows, Finalization, MemberTerms, Reshaping, Settlement,
    ShardId, SiblingView, Source, StatedTerms, SubstateKey, TickHalf, TickLine, TopologySchedule,
    TopologySnapshot, Transaction, TxHash, Verifiable, WeightedTimestamp, partner_evidence,
    source_of,
};

use crate::commit_dedup::CommitDedupIndex;
use crate::fence::Withheld;

/// The terms each of `transactions` stands on, in their order, derived
/// under `committee`, the committee their block is classified under.
/// Every one must be routed and within the declared-access cap.
pub fn derived_terms<'a>(
    committee: &TopologySnapshot,
    local: ShardId,
    transactions: impl IntoIterator<Item = &'a Transaction>,
) -> Vec<StatedTerms> {
    transactions
        .into_iter()
        .map(|tx| StatedTerms {
            tx: tx.hash(),
            terms: terms_of(tx, committee, local),
        })
        .collect()
}

/// The terms section of a block whose transactions derive `derived` and
/// whose manifest is `lines`, in the block's transaction order: the
/// entry of every transaction no line names to run, and of every one a
/// line runs whose terms carry crossings, which its row owes from the
/// block that commits it.
pub fn stated_terms(mut derived: Vec<StatedTerms>, lines: &[TickLine]) -> Vec<StatedTerms> {
    let run = run_by(lines);
    derived.retain(|entry| states_entry(run.contains(&entry.tx), &entry.terms));
    derived
}

/// Whether a block keeps the terms entry of a transaction it commits:
/// always where no line of it `runs` the transaction, and otherwise
/// exactly where the terms carry crossings.
#[must_use]
pub fn states_entry(runs: bool, terms: &MemberTerms) -> bool {
    !runs || !terms.crossings.is_empty()
}

/// The transactions `lines` name to run.
#[must_use]
pub fn run_by(lines: &[TickLine]) -> BTreeSet<TxHash> {
    lines
        .iter()
        .filter_map(|line| match line {
            TickLine::Member { tx, joins, .. } => joins.dispatched().then_some(*tx),
            TickLine::Fate { .. } | TickLine::Discard { .. } | TickLine::End { .. } => None,
        })
        .collect()
}

/// The chain between the committed tip and a block's parent: tick
/// membership at the parent, and what those pending ancestors engaged
/// and read.
pub struct Ancestry {
    /// Tick membership at the parent.
    pub rows: MemberIndex,
    engaged: BTreeSet<(ShardId, TxHash)>,
    arrived: Vec<(SubstateKey, TxHash, BlockHeight)>,
}

impl Ancestry {
    /// `committed` advanced over `ancestors`, the pending blocks from the
    /// tip's child to the parent, in height order, each folded on the
    /// `windows` grid.
    pub fn over<'a>(
        committed: &MemberIndex,
        ancestors: impl IntoIterator<Item = &'a Block>,
        windows: EpochWindows,
    ) -> Self {
        let mut rows = committed.clone();
        let mut engaged = BTreeSet::new();
        let mut arrived = Vec::new();
        for block in ancestors {
            rows.advance(&MemberInputs::of(block, windows));
            engaged.extend(
                block
                    .engagements()
                    .iter()
                    .map(|engagement| (engagement.source, engagement.tx_hash)),
            );
            arrived.extend(
                record_arrivals(block.state_claims())
                    .into_iter()
                    .map(|(key, tx)| (key, tx, block.height())),
            );
        }
        Self {
            rows,
            engaged,
            arrived,
        }
    }
}

/// What a block's own content adds: the bundles it carries and the
/// records its claims read.
#[derive(Debug, Default)]
pub struct OwnContent {
    engaged: BTreeSet<(ShardId, TxHash)>,
    arrived: BTreeSet<(SubstateKey, TxHash)>,
}

impl OwnContent {
    /// What `engagements` and `claims_read` add.
    pub fn of(
        engagements: &BTreeSet<Engagement>,
        claims_read: BTreeSet<(SubstateKey, TxHash)>,
    ) -> Self {
        Self {
            engaged: engagements
                .iter()
                .map(|engagement| (engagement.source, engagement.tx_hash))
                .collect(),
            arrived: claims_read,
        }
    }
}

/// Where `sibling`'s verdict is read from and what the schedule says of
/// it at `anchor`: the source off the trie of the anchor's window, the
/// recovery and the formation off that window as it was first published.
pub fn sibling_view(
    schedule: &TopologySchedule,
    sibling: ShardId,
    anchor: WeightedTimestamp,
) -> (Option<Source>, SiblingView) {
    (
        source_of(schedule.at(anchor), sibling),
        SiblingView {
            epoch: schedule.epoch_for(anchor),
            recovery: schedule.recovery_as_published(sibling, anchor),
            formed: schedule.formed_as_published(sibling, anchor),
        },
    )
}

/// The rows of `rows` that hear their siblings, stated or accepted: the
/// ones a block's legs halves, exits of stated rows and `End` lines turn
/// on.
pub fn hearing_rows(rows: &MemberIndex) -> impl Iterator<Item = &MemberRow> {
    rows.members.values().filter(|row| row.state.hears())
}

/// Whether `ended`, the end lines closing the manifest of a block, are
/// lines the chain licenses: each for a row accepted at `parent` that no
/// sibling can still ask about, judged under `views` over `rows`, the
/// parent's advanced by the block, within `budget`, what the block's
/// other lines left.
///
/// # Errors
///
/// Refused for a line no replica licenses; deferred where this one
/// lacks the block's window as it was published, which a line turns on.
pub fn ends_licensed(
    ended: &[TickLine],
    rows: &MemberIndex,
    parent: &MemberIndex,
    views: &SiblingViews,
    budget: ManifestBudget,
) -> Result<(), Withheld> {
    let ended: Vec<TxHash> = ended
        .iter()
        .filter_map(|line| match line {
            TickLine::End { tx } => Some(*tx),
            TickLine::Member { .. } | TickLine::Fate { .. } | TickLine::Discard { .. } => None,
        })
        .collect();
    ends_stand(&ended, rows, parent, views, budget).map_err(|unlicensed| match unlicensed {
        Unlicensed::Refused(why) => Withheld::Refused(why),
        Unlicensed::Lacking(tx) => Withheld::deferred(format!(
            "what the end line of {tx:?} is judged on is not held here"
        )),
    })
}

/// Whether the names of every legs half among `certificates` accept on
/// what their siblings' state says, under `views`, over `parent`'s rows
/// as the block's claims in `pending` leave them and before any
/// finalization of the block settles.
///
/// # Errors
///
/// Refused for a name over a row that does not accept; deferred where
/// this replica cannot judge one.
pub fn legs_licensed(
    parent: &MemberIndex,
    pending: &MemberInputs,
    certificates: &[Verifiable<Finalization>],
    views: &SiblingViews,
) -> Result<(), Withheld> {
    let legs: Vec<TxHash> = certificates
        .iter()
        .filter(|fw| fw.half() == TickHalf::Legs)
        .flat_map(|fw| fw.tx_hashes())
        .collect();
    if legs.is_empty() {
        return Ok(());
    }
    let rows = heard_named(parent, pending, &legs);
    legs_stand(legs, &rows, views).map_err(|unlicensed| match unlicensed {
        Unlicensed::Refused(why) => Withheld::Refused(why),
        Unlicensed::Lacking(tx) => Withheld::deferred(format!(
            "what the legs half naming {tx:?} is judged on is not held here"
        )),
    })
}

/// The finalizations a proposer offers in a block, and the legs halves
/// among them it cut, which no other replica holds and which voters
/// fetch.
pub struct OfferedLegs {
    pub offered: Vec<Verifiable<Finalization>>,
    pub cut: Vec<Verifiable<Finalization>>,
}

/// `finalizations` as a proposer offers them in a block over `parent`'s
/// rows: each legs half cut to the names whose siblings' state accepts
/// them under `views`, judged over the rows as the block's claims in
/// `pending` leave them, and dropped where it is left naming nobody. A
/// name this replica cannot judge is cut too: a voter lacking what it
/// turns on would defer the block.
pub fn legs_that_stand(
    finalizations: Vec<Verifiable<Finalization>>,
    parent: &MemberIndex,
    pending: &MemberInputs,
    views: &SiblingViews,
) -> OfferedLegs {
    let mut cut = Vec::new();
    let offered = finalizations
        .into_iter()
        .filter_map(|fw| {
            if fw.half() != TickHalf::Legs {
                return Some(fw);
            }
            let names: Vec<TxHash> = fw.tx_hashes().collect();
            let standing = accepting(&heard_named(parent, pending, &names), views);
            if names.iter().all(|tx| standing.contains(tx)) {
                return Some(fw);
            }
            let kept: HashSet<TxHash> = names
                .into_iter()
                .filter(|tx| standing.contains(tx))
                .collect();
            if kept.is_empty() {
                return None;
            }
            let narrowed = Verifiable::from(fw.as_unverified().clone().naming(&kept));
            cut.push(narrowed.clone());
            Some(narrowed)
        })
        .collect();
    OfferedLegs { offered, cut }
}

/// The rows of `parent` named by `names`, each as it stands once the
/// claims of `pending` are heard and before anything else of the block
/// is folded.
pub fn heard_named(parent: &MemberIndex, pending: &MemberInputs, names: &[TxHash]) -> MemberIndex {
    let heard = parent.heard_rows(pending);
    let mut rows = MemberIndex::empty(parent.shard());
    for tx in names {
        if let Some(row) = heard.get(tx).or_else(|| parent.members.get(tx)) {
            rows.members.insert(*tx, row.clone());
        }
    }
    rows
}

/// What the schedule says at `anchor` of each shard one of `rows`
/// awaits.
pub fn sibling_views<'r>(
    rows: impl IntoIterator<Item = &'r MemberRow>,
    schedule: &TopologySchedule,
    anchor: WeightedTimestamp,
) -> SiblingViews {
    let mut views = SiblingViews::default();
    for row in rows {
        for &sibling in row.awaits.iter() {
            views
                .shards
                .entry(sibling)
                .or_insert_with(|| sibling_view(schedule, sibling, anchor));
        }
    }
    views
}

/// What committed content up to the parent, and the block's own, says
/// each `Pending` row of `rows` has in hand, which of them await a verdict
/// across a shard reshaping at `anchor`, and what each shard says of
/// its evidence, and where its chain formed, that a row in flight or
/// stated reaches, or a released one a counterpart settles against:
/// judged at `anchor` under `committee`, the block's. What is said of
/// the siblings of the rows accepted at the parent is
/// [`sibling_views`]', gathered apart.
pub fn committed_sets(
    rows: &MemberIndex,
    ancestry: &Ancestry,
    own: &OwnContent,
    dedup: &CommitDedupIndex,
    anchor: WeightedTimestamp,
    committee: &TopologySnapshot,
    schedule: &TopologySchedule,
) -> CommittedSets {
    let mut sets = CommittedSets::default();
    let reshaping = schedule.reshaping_at(anchor).unwrap_or(Reshaping::UNHELD);
    for row in rows.members.values() {
        if matches!(
            row.state,
            RowState::InFlight { .. }
                | RowState::Stated { .. }
                | RowState::Released {
                    settlement: Settlement::Shared
                }
        ) {
            for &shard in row.reach.iter() {
                sets.evidence
                    .entry(shard)
                    .or_insert_with(|| partner_evidence(schedule, shard, anchor));
                if let Some(formed) = schedule.formed(shard, anchor) {
                    sets.formed.insert(shard, formed);
                }
            }
        }
        if row.state != RowState::Pending {
            continue;
        }
        let shared = row
            .waiting
            .as_ref()
            .is_some_and(|waiting| waiting.settlement == Settlement::Shared);
        if shared
            && std::iter::once(rows.shard())
                .chain(row.awaits.iter().copied())
                .any(|shard| reshaping.contains(shard))
        {
            sets.reshaping.insert(row.tx);
        }
        let judged = Judged::of_row(row);
        for source in judged.sources() {
            let engaged = own.engaged.contains(&(source, row.tx))
                || ancestry.engaged.contains(&(source, row.tx))
                || dedup.engaged(source, row.tx, anchor, committee);
            if engaged {
                sets.engaged.insert((source, row.tx));
            }
        }
        for key in judged.records() {
            let arrived = own.arrived.contains(&(key, row.tx))
                || ancestry.arrived.iter().any(|(read, tx, height)| {
                    *read == key && *tx == row.tx && *height >= row.height
                })
                || dedup.arrived(key, row.tx, row.height, anchor);
            if arrived {
                sets.arrived.insert((key, row.tx));
            }
        }
    }
    sets
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::Capped;
    use hyperscale_types::test_utils::{stub_abort_charge, stub_stated_terms};
    use hyperscale_types::{Deadline, Hash, Joins, Settlement, WeightedTimestamp};

    use super::*;

    fn tx(seed: u8) -> TxHash {
        TxHash::from(Hash::from_bytes(&[seed; 32]))
    }

    fn line(seed: u8, joins: Joins) -> TickLine {
        TickLine::Member {
            staged: 0,
            tx: tx(seed),
            joins,
            settlement: Settlement::Alone,
            holds: Capped::empty(),
            reach: Capped::empty(),
            awaits: Capped::empty(),
            charge: stub_abort_charge(seed),
            share: 0,
            reserves: Capped::empty(),
            deadline: Deadline::of(WeightedTimestamp::from_millis(90_000)),
            crossings: Capped::empty(),
        }
    }

    /// A block keeps the entry of every transaction no line of it runs,
    /// and of one a line runs only where its terms carry crossings, in
    /// the order derived.
    #[test]
    fn a_run_transaction_keeps_its_terms_entry_only_with_crossings() {
        let entry = |seed: u8, crossings: bool| {
            let mut entry = stub_stated_terms(tx(seed), seed);
            if !crossings {
                entry.terms.crossings = Capped::empty();
            }
            entry
        };
        let derived = vec![
            entry(1, true),
            entry(2, false),
            entry(3, true),
            entry(4, false),
            entry(5, false),
            entry(6, true),
        ];
        let lines = [
            line(3, Joins::Executes),
            line(4, Joins::Executes),
            line(5, Joins::Aborted),
            line(6, Joins::ExecutesAborted),
        ];
        let kept: Vec<TxHash> = stated_terms(derived, &lines)
            .into_iter()
            .map(|entry| entry.tx)
            .collect();
        assert_eq!(kept, [tx(1), tx(2), tx(3), tx(5), tx(6)]);
    }
}
