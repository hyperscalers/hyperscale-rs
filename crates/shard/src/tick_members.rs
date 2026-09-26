//! What a block's member lines are judged over: tick membership at the
//! block's parent, the facts of each member it may name, and what
//! committed content up to the parent says each has in hand.
//!
//! A proposer and a voter stand at different committed tips, so both read
//! the chain up to the parent as the committed tier plus each pending
//! ancestor's content, and so read one input.

use std::collections::{BTreeSet, HashMap};

use hyperscale_engine::tick_select::{CommittedSets, EngagementWait, MemberFacts, Requirement};
use hyperscale_storage::{MemberIndex, MemberInputs, RowState, record_arrivals};
use hyperscale_types::{
    Block, BlockHeight, Deadline, Engagement, ShardId, SubstateKey, TopologySchedule,
    TopologySnapshot, Transaction, TxHash, WeightedTimestamp, partner_evidence,
};

use crate::commit_dedup::CommitDedupIndex;

/// Each transaction's member facts, classified where a body was first
/// held, `None` for one this node cannot route; kept while the
/// transaction can still be named.
#[derive(Debug, Default)]
pub struct FactsCache {
    entries: HashMap<TxHash, (Option<MemberFacts>, Deadline)>,
}

impl FactsCache {
    /// Classify each of `transactions` not yet held, under `committee`,
    /// the committee its including block is classified under.
    pub fn classify<'a>(
        &mut self,
        committee: &TopologySnapshot,
        local: ShardId,
        transactions: impl IntoIterator<Item = &'a Transaction>,
    ) {
        for tx in transactions {
            self.entries.entry(tx.hash()).or_insert_with(|| {
                (
                    tx.is_routed()
                        .then(|| MemberFacts::of(tx, committee, local)),
                    Deadline::of_transaction(tx),
                )
            });
        }
    }

    /// The facts of `tx`, where this node could classify it.
    pub fn get(&self, tx: TxHash) -> Option<&MemberFacts> {
        self.entries.get(&tx).and_then(|(facts, _)| facts.as_ref())
    }

    /// Keep what `rows` still stands for, or what has not passed its
    /// deadline at `anchor`: a transaction in a block not yet committed
    /// may still be.
    pub fn retain(&mut self, rows: &MemberIndex, anchor: WeightedTimestamp) {
        self.entries
            .retain(|tx, (_, deadline)| rows.members.contains_key(tx) || !deadline.passed(anchor));
    }
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
/// each `Pending` row of `rows` has in hand, for the rows whose facts are
/// held, and what each shard an in-flight row reaches says of its
/// evidence: judged at `anchor` under `committee`, the block's.
#[allow(clippy::too_many_arguments)] // the tier, the ancestry and the block's own content, each judged at one anchor
pub fn committed_sets(
    rows: &MemberIndex,
    facts: &FactsCache,
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
        let Some(known) = facts.get(row.tx) else {
            continue;
        };
        let counterparts = known
            .engagement
            .iter()
            .flat_map(|EngagementWait { counterparts, .. }| counterparts.iter().copied());
        let sources = known
            .requires
            .iter()
            .filter_map(|requirement| match requirement {
                Requirement::CommittedState(shard) => Some(*shard),
                Requirement::Crossing { .. } => None,
            })
            .chain(counterparts);
        for source in sources {
            let engaged = own.engaged.contains(&(source, row.tx))
                || ancestry.engaged.contains(&(source, row.tx))
                || dedup.engaged(source, row.tx, anchor, committee);
            if engaged {
                sets.engaged.insert((source, row.tx));
            }
        }
        for requirement in &known.requires {
            let Requirement::Crossing { key } = requirement else {
                continue;
            };
            let arrived = own.arrived.contains(&(*key, row.tx))
                || ancestry.arrived.iter().any(|(read, tx, height)| {
                    *read == *key && *tx == row.tx && *height >= row.height
                })
                || dedup.arrived(*key, row.tx, row.height, anchor);
            if arrived {
                sets.arrived.insert((*key, row.tx));
            }
        }
    }
    sets
}
