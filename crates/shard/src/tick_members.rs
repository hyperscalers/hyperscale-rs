//! What a block's member lines are judged over: tick membership at the
//! block's parent, and what committed content up to the parent says each
//! member it may name has in hand.
//!
//! A proposer and a voter stand at different committed tips, so both read
//! the chain up to the parent as the committed tier plus each pending
//! ancestor's content, and so read one input.

use std::collections::BTreeSet;

use hyperscale_engine::tick_select::{CommittedSets, Judged, terms_of};
use hyperscale_storage::{MemberIndex, MemberInputs, RowState, record_arrivals};
use hyperscale_types::{
    Block, BlockHeight, Engagement, ShardId, StatedTerms, SubstateKey, TickLine, TopologySchedule,
    TopologySnapshot, Transaction, TxHash, WeightedTimestamp, partner_evidence,
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
            TickLine::Member { tx, joins, .. } if joins.dispatched() => Some(*tx),
            _ => None,
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
    /// tip's child to the parent, in height order.
    pub fn over<'a>(
        committed: &MemberIndex,
        ancestors: impl IntoIterator<Item = &'a Block>,
    ) -> Self {
        let mut rows = committed.clone();
        let mut engaged = BTreeSet::new();
        let mut arrived = Vec::new();
        for block in ancestors {
            rows.advance(&MemberInputs::of(block));
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

/// What committed content up to the parent, and the block's own, says
/// each `Pending` row of `rows` has in hand, and what each shard an
/// in-flight row reaches says of its evidence: judged at `anchor` under
/// `committee`, the block's.
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
        if matches!(row.state, RowState::InFlight { .. }) {
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
