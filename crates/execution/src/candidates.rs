//! Committed transactions waiting to join a tick.
//!
//! A block commits transactions; a tick executes them. The two are not
//! the same set — a cross-shard leg waits for its counterparts'
//! provisions, a payer's leg waits for their engagement echoes, and a
//! member whose declared cells another leg holds provisionally waits for
//! that leg's fate. This is where they wait, and it is per transaction
//! because every one of those waits is.
//!
//! What leaves is what the tick attests. Nothing here has an outcome:
//! a candidate that cannot join a tick has said nothing and owes nothing,
//! so it is free to wait as long as its own deadline allows, and the
//! `ledger` is what ends that wait.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_core::CrossShardExecutionRequest;
use hyperscale_engine::legs::{Classified, Member, Runs};
use hyperscale_engine::tick_select::{
    CommittedInputs, ManifestBudget, MemberFacts, Nameable, ProvisionalCells, Standing,
    select_members,
};
use hyperscale_types::{
    Deadline, EscrowedValue, Joins, PriceTable, ShardId, ShardTrie, SubstateKey, TickLine,
    Transaction, TxHash, Verified, WeightedTimestamp,
};
use hyperscale_vm_effects::Kind;
use hyperscale_vm_types::ProtocolHasher;

use crate::provisioning::ProvisioningTracker;
use crate::tick_state::Membership;

/// One committed transaction awaiting a tick.
#[derive(Debug)]
struct Candidate {
    tx: Arc<Verified<Transaction>>,
    /// This shard's member of it, derived once at registration: the
    /// frozen classification, where it runs, which of its shard's legs it
    /// takes and what the transaction reaches. Every per-member question
    /// below is asked of this and none is re-derived beside it.
    member: Member,
    /// The committing block's weighted timestamp — the clock a member
    /// executes under when no payer bundle names another. It stays the
    /// committing block's however many ticks later the member runs: the
    /// transaction was admitted against that clock.
    committed_ts: WeightedTimestamp,
    /// The table the committing block's own committee named, which
    /// prices this shard's share of the transaction.
    ///
    /// Carried rather than resolved again at composition: the block that
    /// committed the member is what froze its abandonment's figures, and
    /// a member that reaches an engine has to attest what a member that
    /// never does would have restated.
    committed_prices: PriceTable,
}

/// What committed claims attested for the escrowed edges `tx`'s legs on
/// `local` consume: each crossing landing here, with the value its
/// record cell says left. An owed crossing is credited by the commit
/// fold and never arrives in a member.
///
/// A divided member only. The cell was proven against the producer's
/// committed root by the claim that carried it, and its bytes are the
/// kernel's own record, so what it says left is what the consumer
/// claims, read off the arrival the fold indexed by the record's key.
/// An edge whose record has not arrived is left out, and the planner
/// refuses the member for it rather than running short.
fn arrivals_for(
    classified: &Classified,
    provisioning: &ProvisioningTracker,
    local: ShardId,
) -> Vec<EscrowedValue> {
    if !classified.decomposed() {
        return Vec::new();
    }
    classified
        .edges()
        .iter()
        .filter(|edge| edge.to.contains(&local) && edge.crossing.kind == Kind::Escrowed)
        .filter_map(|edge| {
            let key = edge.crossing.id.record_key(&ProtocolHasher);
            let record = provisioning.arrived().get(&key)?.cell;
            Some(EscrowedValue {
                node: edge.producer,
                output: edge.output,
                resource: record.resource,
                amount: record.amount,
                record: key,
            })
        })
        .collect()
}

/// This node's absorbed bundles and arrived crossings, read as the
/// committed inputs a member waits on.
struct Absorbed<'a>(&'a ProvisioningTracker);

impl CommittedInputs for Absorbed<'_> {
    fn engaged(&self, source: ShardId, tx: TxHash) -> bool {
        self.0.has_received_from(tx, source)
    }

    fn arrived(&self, key: SubstateKey, tx: TxHash) -> bool {
        self.0
            .arrived()
            .get(&key)
            .is_some_and(|arrival| arrival.cell.tx == tx)
    }
}

/// The committed transactions no tick has taken yet.
#[derive(Debug)]
pub struct TickCandidates {
    local_shard: ShardId,
    /// Keyed and iterated in hash order so composition is a function of
    /// the candidate set and nothing about arrival.
    candidates: BTreeMap<TxHash, Candidate>,
}

/// One member's admission to the tick being composed.
pub struct Admitted {
    /// The request the engine runs.
    pub request: CrossShardExecutionRequest,
    /// Whose certificate its settlement waits on, and who its own is
    /// owed to.
    pub membership: Membership,
    /// The terms it joins on. Everything composition admits runs; the
    /// payer's leg whose counterparts never engaged runs and is attested
    /// `Aborted` regardless.
    pub joins: Joins,
    /// The table the block that committed this member named.
    ///
    /// What its own share is priced at: the abandonment of a member that
    /// never reaches an engine restates the figure its committing block
    /// froze, so a member that does reach one attests the same figure.
    /// The clock the request carries is the payer's and prices the burn;
    /// this is this chain's and prices what it attests.
    pub committed_prices: PriceTable,
}

impl Admitted {
    /// Every shard the member's transaction reaches — what a second
    /// member of it on this shard is registered as participating with.
    #[must_use]
    pub fn membership_reach(&self) -> BTreeSet<ShardId> {
        self.membership.reach().clone()
    }
}

impl TickCandidates {
    /// An empty pool for `local_shard`.
    #[must_use]
    pub const fn new(local_shard: ShardId) -> Self {
        Self {
            local_shard,
            candidates: BTreeMap::new(),
        }
    }

    /// Record a transaction the committing block puts in flight.
    ///
    /// Idempotent: a re-registered hash keeps the anchors it was admitted
    /// under, which is what makes composition identical on a replica that
    /// sees the block once and one that replays it.
    pub fn register(
        &mut self,
        tx: Arc<Verified<Transaction>>,
        participating: BTreeSet<ShardId>,
        committed_ts: WeightedTimestamp,
        committed_prices: PriceTable,
        classified: Classified,
    ) {
        let member = Member::of(classified, self.local_shard, participating);
        self.register_member(tx, member, committed_ts, committed_prices);
    }

    /// Record `member` of `tx` as a candidate, under the clock of the
    /// block that committed it.
    pub fn register_member(
        &mut self,
        tx: Arc<Verified<Transaction>>,
        member: Member,
        committed_ts: WeightedTimestamp,
        committed_prices: PriceTable,
    ) {
        self.candidates.entry(tx.hash()).or_insert(Candidate {
            tx,
            member,
            committed_ts,
            committed_prices,
        });
    }

    /// The member lines this node's own committed inputs name at `now`:
    /// every candidate [`select_members`] admits under `held`, in
    /// canonical order. What a block's manifest names where this node's
    /// inputs are the chain's, which is what a fixture building a block
    /// stands in for.
    #[must_use]
    pub fn named(
        &self,
        trie: &ShardTrie,
        provisioning: &ProvisioningTracker,
        held: &mut ProvisionalCells,
        now: WeightedTimestamp,
    ) -> Vec<TickLine> {
        let facts: Vec<(TxHash, MemberFacts, Deadline)> = self
            .candidates
            .iter()
            .map(|(tx_hash, candidate)| {
                (
                    *tx_hash,
                    MemberFacts::of_member(&candidate.member, &candidate.tx, trie),
                    Deadline::of_transaction(&candidate.tx),
                )
            })
            .collect();
        select_members(
            now,
            facts.iter().map(|(tx_hash, facts, deadline)| Nameable {
                tx: *tx_hash,
                deadline: *deadline,
                standing: Standing::Pending(facts),
            }),
            &Absorbed(provisioning),
            held,
            &mut ManifestBudget::default(),
        )
    }

    /// Take the members a committed manifest names to run, in its order,
    /// each on the terms its line gives. A member named `Aborted` runs
    /// nothing, and is seated by its abandonment instead.
    ///
    /// The line is the decision: this node seats what the chain named
    /// whatever its own inputs would have said. A line naming a
    /// transaction this node holds no candidate for — one it could not
    /// route — seats nothing here.
    pub fn take_named(
        &mut self,
        lines: &[TickLine],
        provisioning: &ProvisioningTracker,
    ) -> Vec<Admitted> {
        let local = self.local_shard;
        let mut admitted = Vec::new();
        for line in lines {
            let TickLine::Member {
                tx: tx_hash, joins, ..
            } = line
            else {
                continue;
            };
            if !joins.dispatched() {
                continue;
            }
            let Some(candidate) = self.candidates.remove(tx_hash) else {
                continue;
            };
            let reaches_beyond = candidate.member.reaches_beyond();
            // What arrived for the edges this member's legs consume, read
            // off the record cells the committed claims proved.
            let arrivals = arrivals_for(candidate.member.classified(), provisioning, local);
            // A remote-payer leg executes under the anchor its payer
            // bundle carried; every other member under its own committing
            // block's.
            let anchor = provisioning.payer_anchor(*tx_hash);
            admitted.push(Admitted {
                request: CrossShardExecutionRequest {
                    tx_hash: *tx_hash,
                    transaction: Some(Arc::clone(&candidate.tx)),
                    provisions: if reaches_beyond {
                        provisioning.provisions_for(*tx_hash)
                    } else {
                        Vec::new()
                    },
                    clock: anchor.map_or(candidate.committed_ts, |a| a.clock),
                    // Resolved against that clock once the schedule is
                    // in hand, where the member is seated.
                    prices: PriceTable::GENESIS,
                    runs: Runs::Shape(candidate.member.clone()),
                    arrivals,
                },
                membership: Membership::of(&candidate.member),
                joins: *joins,
                committed_prices: candidate.committed_prices,
            });
        }
        admitted
    }

    /// Drop a candidate no tick will take — abandoned at its deadline, or
    /// dropped with the chain at a reshape terminal.
    pub fn remove(&mut self, tx_hash: TxHash) {
        self.candidates.remove(&tx_hash);
    }

    /// Whether a transaction is still waiting for a tick.
    #[must_use]
    pub fn contains(&self, tx_hash: TxHash) -> bool {
        self.candidates.contains_key(&tx_hash)
    }

    /// Every transaction still waiting for a tick, in hash order.
    pub fn tx_hashes(&self) -> impl Iterator<Item = TxHash> + '_ {
        self.candidates.keys().copied()
    }

    /// Drop every candidate. Called when the local chain terminates: a
    /// tick is a block's, and a terminated chain commits no further block.
    pub fn clear(&mut self) {
        self.candidates.clear();
    }

    /// How many transactions are waiting.
    #[must_use]
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    /// Whether nothing is waiting.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::Capped;
    use hyperscale_types::test_utils::{test_prefix, test_transaction_with_prefixes};
    use hyperscale_types::{Settlement, WeightedTimestamp};

    use super::*;

    const LOCAL: ShardId = ShardId::ROOT;

    fn tx(seed: u8) -> Arc<Verified<Transaction>> {
        Arc::new(Verified::new_unchecked_for_test(
            test_transaction_with_prefixes(
                &[seed, seed + 1, seed + 2],
                &[test_prefix(seed)],
                &[test_prefix(seed.wrapping_add(10))],
            ),
        ))
    }

    fn ms(v: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(v)
    }

    fn local_only(candidates: &mut TickCandidates, tx: Arc<Verified<Transaction>>) -> TxHash {
        let hash = tx.hash();
        candidates.register(
            tx,
            BTreeSet::from([LOCAL]),
            ms(1_000),
            PriceTable::GENESIS,
            Classified::whole(),
        );
        hash
    }

    /// The line is the decision: a named candidate leaves the pool and
    /// is seated on the terms its line gives, under the table its own
    /// committing block named.
    #[test]
    fn a_named_candidate_is_seated_on_its_lines_terms() {
        let mut candidates = TickCandidates::new(LOCAL);
        let moved = PriceTable {
            compute: 7,
            ..PriceTable::GENESIS
        };
        let tx = tx(1);
        let hash = tx.hash();
        candidates.register(
            tx,
            BTreeSet::from([LOCAL]),
            ms(1_000),
            moved,
            Classified::whole(),
        );

        let admitted = candidates.take_named(
            &[TickLine::Member {
                tx: hash,
                joins: Joins::ExecutesAborted,
                settlement: Settlement::Alone,
                holds: Capped::empty(),
                reach: Capped::empty(),
            }],
            &ProvisioningTracker::new(),
        );
        assert_eq!(admitted.len(), 1);
        assert_eq!(admitted[0].request.tx_hash, hash);
        assert_eq!(admitted[0].joins, Joins::ExecutesAborted);
        assert_eq!(
            admitted[0].committed_prices, moved,
            "the committing block's table, not the composing tick's"
        );
        assert!(candidates.is_empty(), "and leaves the pool with the tick");
    }

    /// A line naming a transaction this node holds no candidate for seats
    /// nothing here, and a candidate no line names stays.
    #[test]
    fn only_a_named_candidate_is_seated() {
        let mut candidates = TickCandidates::new(LOCAL);
        let waiting = local_only(&mut candidates, tx(2));
        let admitted = candidates.take_named(
            &[TickLine::Member {
                tx: tx(3).hash(),
                joins: Joins::Executes,
                settlement: Settlement::Alone,
                holds: Capped::empty(),
                reach: Capped::empty(),
            }],
            &ProvisioningTracker::new(),
        );
        assert!(admitted.is_empty());
        assert!(candidates.contains(waiting));
    }

    /// A divided member is seated on the membership its frozen
    /// classification implies, not on the participant set it was
    /// registered with: a leg awaits itself and reaches every
    /// participant.
    #[test]
    fn a_divided_member_is_seated_on_its_classified_membership() {
        use crate::fixtures::{leaf, payer, swap, trie};

        let trie = trie();
        let (local, venue) = (leaf(0), leaf(1));
        let classified = Classified::freeze(&swap(), payer(), &[], &trie);
        assert!(classified.decomposed());

        let mut candidates = TickCandidates::new(local);
        let tx = tx(5);
        let hash = tx.hash();
        candidates.register(
            tx,
            BTreeSet::from([local, venue]),
            ms(1_000),
            PriceTable::GENESIS,
            classified,
        );
        let admitted = candidates.take_named(
            &[TickLine::Member {
                tx: hash,
                joins: Joins::Executes,
                settlement: Settlement::Awaited,
                holds: Capped::empty(),
                reach: Capped::empty(),
            }],
            &ProvisioningTracker::new(),
        );
        assert_eq!(admitted.len(), 1);
        assert_eq!(admitted[0].membership.awaited(), &BTreeSet::from([local]));
        assert_eq!(
            admitted[0].membership.reach(),
            &BTreeSet::from([local, venue])
        );
        assert!(
            admitted[0].request.runs.reaches_beyond(),
            "reach is what the request carries"
        );
    }

    /// What this node's own inputs name is [`select_members`] over its
    /// candidates: a local member at once, and one whose declared cells
    /// a provisional leg holds not at all.
    #[test]
    fn a_node_names_what_the_one_rule_admits() {
        let mut candidates = TickCandidates::new(LOCAL);
        let contender = tx(5);
        let hash = local_only(&mut candidates, Arc::clone(&contender));
        let trie = ShardTrie::single();

        let named = candidates.named(
            &trie,
            &ProvisioningTracker::new(),
            &mut ProvisionalCells::default(),
            ms(1_000),
        );
        assert!(matches!(
            named.as_slice(),
            [TickLine::Member { tx, joins: Joins::Executes, .. }] if *tx == hash
        ));

        let mut held = ProvisionalCells::default();
        held.claim(&contender.routing().declared_modes);
        assert!(
            candidates
                .named(&trie, &ProvisioningTracker::new(), &mut held, ms(1_000))
                .is_empty(),
            "the cell is spoken for",
        );
    }
}
