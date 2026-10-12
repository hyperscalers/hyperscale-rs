//! What a block's member lines are judged over: tick membership at the
//! block's parent, and what committed content up to the parent says each
//! member it may name has in hand.
//!
//! A proposer and a voter stand at different committed tips, so both read
//! the chain up to the parent as the committed tier plus each pending
//! ancestor's content, and so read one input.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_engine::tick_select::{CommittedSets, Judged, SiblingViews, terms_of};
use hyperscale_storage::{MemberIndex, MemberInputs, MemberRow, RowState, record_arrivals};
use hyperscale_types::{
    Block, BlockHash, BlockHeight, CounterpartMirror, Decision, Engagement, EpochWindows, Hears,
    Joins, Settlement, ShardId, SiblingView, Source, StatedTerms, SubstateKey, TickHalf, TickLine,
    TopologySchedule, TopologySnapshot, Transaction, TxHash, WeightedTimestamp, decide,
    partner_evidence, source_of,
};

use crate::commit_dedup::CommitDedupIndex;

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
/// whose manifest is `lines`: the entry of every transaction no line
/// names to run, in the block's transaction order.
pub fn stated_terms(mut derived: Vec<StatedTerms>, lines: &[TickLine]) -> Vec<StatedTerms> {
    let run: BTreeSet<TxHash> = lines
        .iter()
        .filter_map(|line| match line {
            TickLine::Member { tx, joins, .. } => joins.dispatched().then_some(*tx),
            TickLine::Fate { .. } | TickLine::Discard { .. } | TickLine::End { .. } => None,
        })
        .collect();
    derived.retain(|entry| !run.contains(&entry.tx));
    derived
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
/// recovery and the evidence off that window as it was first published.
/// Whether a departed sibling's terminal ended a transaction is the
/// mirror's to add, per transaction.
pub fn sibling_view(
    schedule: &TopologySchedule,
    sibling: ShardId,
    anchor: WeightedTimestamp,
) -> (Option<Source>, SiblingView) {
    (
        source_of(schedule.at(anchor), sibling),
        SiblingView {
            epoch: schedule.epoch_for(anchor),
            terminating: schedule.terminates_at_next_boundary(sibling, anchor),
            recovery: schedule.recovery_as_published(sibling, anchor),
            evidence: schedule.evidence_as_published(sibling, anchor),
            ended: None,
        },
    )
}

/// The rows of `rows` standing accepted: the ones an `End` line may
/// name in a block built on them.
pub fn accepted_rows(rows: &MemberIndex) -> impl Iterator<Item = &MemberRow> {
    rows.members
        .values()
        .filter(|row| row.state == RowState::Accepted)
}

/// What the schedule and `mirror` say at `anchor` of each shard one of
/// `rows` awaits. A departed sibling's ended names are the ones held for
/// the terminal the anchor's published window records for it, so every
/// replica asks the mirror about one terminal.
pub fn sibling_views<'r>(
    rows: impl IntoIterator<Item = &'r MemberRow>,
    schedule: &TopologySchedule,
    mirror: &CounterpartMirror,
    anchor: WeightedTimestamp,
) -> SiblingViews {
    let mut views = SiblingViews::default();
    let mut terminals: BTreeMap<ShardId, Option<BlockHash>> = BTreeMap::new();
    for row in rows {
        for &sibling in row.awaits.iter() {
            let (source, _) = *views
                .shards
                .entry(sibling)
                .or_insert_with(|| sibling_view(schedule, sibling, anchor));
            if source != Some(Source::Gone) {
                continue;
            }
            let terminal = *terminals.entry(sibling).or_insert_with(|| {
                schedule
                    .terminal_as_published(sibling, anchor)
                    .ok()
                    .flatten()
            });
            if let Some(ended) =
                terminal.and_then(|terminal| mirror.ended(sibling, terminal, row.tx))
            {
                views.ended.insert((sibling, row.tx), ended);
            }
        }
    }
    views
}

/// How [`decide`], had it judged a row while it stood stated, compares
/// with what a committed block did with the row on its certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agreement {
    /// The two match.
    Agree,
    /// `decide` waits, and a legs half settled the member.
    AfterLocalSettle,
    /// `decide` refuses a member the legs half accepted, on a sibling's
    /// leaf shared among other shards than the row's own.
    AwaitedSetStricter,
    /// `decide` waits or accepts, and a line aborted the member under a
    /// record or its deadline.
    RecordAbort,
    /// `decide` accepts, and the certificates refused: on a shard whose
    /// verdict no core leaf states.
    LegSibling,
    /// `decide` lacks the published window or a departed sibling's
    /// names.
    NoView,
    /// Anything else.
    Other,
}

impl Agreement {
    /// The label the sample is counted under: where the block settled
    /// the row, or under `ended`, where it ended a row that had
    /// accepted.
    #[must_use]
    pub const fn label(self, ended: bool) -> &'static str {
        match (self, ended) {
            (Self::Agree, false) => "agree",
            (Self::AfterLocalSettle, false) => "after_local_settle",
            (Self::AwaitedSetStricter, false) => "awaited_set_stricter",
            (Self::RecordAbort, false) => "record_abort",
            (Self::LegSibling, false) => "leg_sibling",
            (Self::NoView, false) => "no_view",
            (Self::Other, false) => "other",
            (Self::Agree, true) => "end_agree",
            (Self::AfterLocalSettle, true) => "end_after_local_settle",
            (Self::AwaitedSetStricter, true) => "end_awaited_set_stricter",
            (Self::RecordAbort, true) => "end_record_abort",
            (Self::LegSibling, true) => "end_leg_sibling",
            (Self::NoView, true) => "end_no_view",
            (Self::Other, true) => "end_other",
        }
    }
}

/// What a block did with a row that stood stated at its parent, or with
/// one that stood accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Did {
    /// A legs half accepted it.
    Accepted,
    /// A legs half settled its refusal.
    Refused,
    /// A line aborted it.
    Aborted,
    /// A fate ended it.
    Fated,
    /// An end line ended it, accepted earlier.
    Ended,
}

/// For each row a block of `inputs` takes out of `Stated`, and each
/// accepted row it ends, how [`decide`] over the row as a stated one
/// compares with what the block did, beside whether the sample is of an
/// ended row. `parent` holds the rows at the block's parent, judged
/// once the block's claims are heard, at `anchor`; `other_shaped` names
/// the rows a sibling's leaf of another shape was read for.
pub fn agreements(
    parent: &MemberIndex,
    inputs: &MemberInputs,
    other_shaped: &BTreeSet<TxHash>,
    schedule: &TopologySchedule,
    mirror: &CounterpartMirror,
    anchor: WeightedTimestamp,
) -> Vec<(bool, Agreement)> {
    let mut did: BTreeMap<TxHash, Did> = BTreeMap::new();
    for half in inputs
        .settled
        .iter()
        .filter(|half| half.half == TickHalf::Legs)
    {
        did.extend(half.deleted.iter().map(|tx| (*tx, Did::Refused)));
        did.extend(half.accepted.iter().map(|tx| (*tx, Did::Accepted)));
    }
    for line in inputs.manifest.iter() {
        match line {
            TickLine::Member { tx, joins, .. } if *joins == Joins::Aborted => {
                did.insert(*tx, Did::Aborted);
            }
            TickLine::Fate { tx, .. } => {
                did.insert(*tx, Did::Fated);
            }
            TickLine::End { tx } => {
                did.insert(*tx, Did::Ended);
            }
            TickLine::Member { .. } | TickLine::Discard { .. } => {}
        }
    }
    did.retain(|tx, did| {
        parent.members.get(tx).is_some_and(|row| match did {
            Did::Ended => row.state == RowState::Accepted,
            Did::Accepted | Did::Refused | Did::Aborted | Did::Fated => {
                matches!(row.state, RowState::Stated { .. })
            }
        })
    });
    if did.is_empty() {
        return Vec::new();
    }
    let heard = parent.heard_rows(inputs);
    let rows: Vec<&MemberRow> = did
        .keys()
        .filter_map(|tx| heard.get(tx).or_else(|| parent.members.get(tx)))
        .collect();
    let views = sibling_views(rows.iter().copied(), schedule, mirror, anchor);
    rows.into_iter()
        .map(|row| {
            let did = did[&row.tx];
            let decision = decide(Hears::Stated, &views.values(row));
            let settled = if did == Did::Ended {
                Did::Accepted
            } else {
                did
            };
            let agreement = match (decision, settled) {
                (Decision::Lacking, _) => Agreement::NoView,
                (Decision::Accept, Did::Accepted)
                | (Decision::Refuse, Did::Refused | Did::Aborted)
                | (Decision::LetGo, Did::Fated) => Agreement::Agree,
                (Decision::Wait, Did::Accepted | Did::Refused) => Agreement::AfterLocalSettle,
                (Decision::Refuse, Did::Accepted) if other_shaped.contains(&row.tx) => {
                    Agreement::AwaitedSetStricter
                }
                (Decision::Wait | Decision::Accept, Did::Aborted) => Agreement::RecordAbort,
                (Decision::Accept, Did::Refused) => Agreement::LegSibling,
                _ => Agreement::Other,
            };
            (did == Did::Ended, agreement)
        })
        .collect()
}

/// What committed content up to the parent, and the block's own, says
/// each `Pending` row of `rows` has in hand, and what each shard says of
/// its evidence that a row in flight or stated reaches, or a released
/// one a counterpart settles against: judged at `anchor` under `committee`,
/// the block's. What is said of the siblings of the rows accepted at
/// the parent is [`sibling_views`]', gathered apart.
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
            }
        }
        if row.state != RowState::Pending {
            continue;
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
