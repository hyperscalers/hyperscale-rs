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
//! [`ledger`](crate::unresolved) is what ends that wait.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_core::CrossShardExecutionRequest;
use hyperscale_engine::legs::{Classified, Member, Runs, Side};
use hyperscale_types::{
    Deadline, EscrowedValue, PriceTable, ShardId, Transaction, TxHash, Verified, WeightedTimestamp,
    Window,
};
use hyperscale_vm_effects::CrossingCell;

use crate::provisional::ProvisionalCells;
use crate::provisioning::ProvisioningTracker;
use crate::tick_state::{Admission, Membership};

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
    /// Counterpart shards whose engagement echo this shard, as the fee
    /// payer, still waits for. Empty for every other transaction.
    engagement_pending: BTreeSet<ShardId>,
    /// The moment past which the payer stops waiting for those echoes and
    /// executes anyway, to be attested `Aborted` by the tick that runs it.
    /// `None` when nothing is engagement-gated.
    engagement_deadline: Option<WeightedTimestamp>,
}

impl Candidate {
    /// Whether the payer's wait for engagement echoes is over, either
    /// covered or past its deadline.
    fn engagement_settled(&self, now: WeightedTimestamp) -> bool {
        self.engagement_pending.is_empty()
            || self
                .engagement_deadline
                .is_some_and(|deadline| now >= deadline)
    }
}

/// What committed bundles attested for the edges `tx`'s legs on `local`
/// consume: each crossing landing here, with the value its record cell
/// says left.
///
/// A divided member only. The cell was proven against the producer's
/// committed root when its bundle was absorbed, and its bytes are the
/// kernel's own record, so what it says left is what the consumer
/// claims — read from that bundle and no other, since a bundle from any
/// other shard carrying the key proves nothing about a cell it does not
/// own. An edge whose cell is missing or unreadable is left out, and
/// the planner refuses the member for it rather than running short.
fn arrivals_for(
    tx: &Transaction,
    classified: &Classified,
    provisioning: &ProvisioningTracker,
    local: ShardId,
    side: Side,
) -> Vec<EscrowedValue> {
    if !classified.decomposed() {
        return Vec::new();
    }
    classified
        .edges()
        .iter()
        .filter(|edge| edge.to.contains(&local) && edge.delivers == (side == Side::Delivering))
        .filter_map(|edge| {
            let key = edge.record.key();
            let bytes = provisioning.present_cell(tx.hash(), edge.from, key)?;
            let record = CrossingCell::from_bytes(bytes)?;
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
    pub admission: Admission,
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
        let side = classified.first_side_at(self.local_shard);
        let member = Member::of(classified, self.local_shard, side, participating);
        self.register_member(tx, member, committed_ts, committed_prices);
    }

    /// Record `member` of `tx` as a candidate, under the clock of the
    /// block that committed it.
    ///
    /// A mixed shard's delivering member arrives here once a tick has
    /// taken its issuing one: this shard runs outbound legs beside the
    /// inbound ones, and they wait on what the core returns. It waits on
    /// no engagement — the issuing member settled that — and runs under
    /// the same committing block's clock.
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
            engagement_pending: BTreeSet::new(),
            engagement_deadline: None,
        });
    }

    /// Record that this shard, as `tx_hash`'s fee payer, waits for
    /// `counterparts` to echo their engagement before executing it.
    /// `validity_end` is the signed window end the wait is bounded by.
    pub fn record_engagement_wait(
        &mut self,
        tx_hash: TxHash,
        counterparts: BTreeSet<ShardId>,
        deadline: WeightedTimestamp,
    ) {
        if counterparts.is_empty() {
            return;
        }
        if let Some(candidate) = self.candidates.get_mut(&tx_hash) {
            candidate.engagement_pending = counterparts;
            candidate.engagement_deadline = Some(deadline);
        }
    }

    /// Drain engagement coverage from committed provisions: a bundle from
    /// a counterpart names the transaction only because that shard's block
    /// committed it, so absorption is the engagement evidence.
    pub fn absorb_engagement_evidence(&mut self, provisioning: &ProvisioningTracker) {
        for (tx_hash, candidate) in &mut self.candidates {
            candidate
                .engagement_pending
                .retain(|shard| !provisioning.has_received_from(*tx_hash, *shard));
        }
    }

    /// Take the members that can execute at this commit, in hash order.
    ///
    /// A member joins when it has everything it needs to reach its final
    /// outcome in this tick: its counterparts' provisions, its payer
    /// engagement settled one way or the other, and no cell another
    /// provisional leg is holding. `held` carries in what earlier ticks
    /// claim and leaves with what this one adds, so a member of this very
    /// batch can be what keeps the next one out — a batch is one overlay,
    /// and a leg reading what another left would carry writes an abort
    /// retracts.
    ///
    /// Cross-shard members are offered first for the same reason: theirs
    /// are the provisional writes everything else has to be compatible
    /// with, and a determined member is the cheaper of the two to defer.
    pub fn compose(
        &mut self,
        provisioning: &ProvisioningTracker,
        held: &mut ProvisionalCells,
        now: WeightedTimestamp,
    ) -> Vec<Admitted> {
        let local = self.local_shard;
        let mut ordered: Vec<TxHash> = self.candidates.keys().copied().collect();
        ordered.sort_by_key(|tx_hash| {
            let reaches_beyond = self.candidates[tx_hash].member.reaches_beyond();
            (!reaches_beyond, *tx_hash)
        });

        let mut taken: Vec<TxHash> = Vec::new();
        let mut admitted: Vec<Admitted> = Vec::with_capacity(ordered.len());
        for tx_hash in ordered {
            let candidate = &self.candidates[&tx_hash];
            let reaches_beyond = candidate.member.reaches_beyond();
            // A transaction reaching no further than this shard needs no
            // provisions; one that does waits for every shard it named.
            if reaches_beyond && !provisioning.is_fully_provisioned(tx_hash) {
                continue;
            }
            if !candidate.engagement_settled(now) {
                continue;
            }
            let membership = Membership::of(&candidate.member);
            // A member whose effects a counterpart's verdict can still
            // discard: its writes stay provisional, and its declaration
            // is a claim the members after it must compose with. One
            // that awaits nobody but this shard holds nothing back —
            // its writes are determined at once, and the kernel's own
            // conflict groups sequence its batch-mates against it.
            let abortable = candidate.member.abortable();
            let declared = &candidate.tx.routing().declared_modes;
            if !held.is_empty() && held.blocks(declared) {
                continue;
            }
            // After the test, never before: a transaction is not what
            // keeps itself out.
            if abortable {
                held.claim(declared);
            }

            // What arrived for the edges this member's legs consume, read
            // off the record cells the committed bundles proved. Every
            // requirement is met, so every edge has its cell.
            let arrivals = arrivals_for(
                &candidate.tx,
                candidate.member.classified(),
                provisioning,
                local,
                candidate.member.side(),
            );
            // A remote-payer leg executes under the anchor its payer
            // bundle carried; every other member under its own committing
            // block's.
            let anchor = provisioning.payer_anchor(tx_hash);
            admitted.push(Admitted {
                request: CrossShardExecutionRequest {
                    tx_hash,
                    transaction: Some(Arc::clone(&candidate.tx)),
                    provisions: if reaches_beyond {
                        provisioning.provisions_for(tx_hash)
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
                membership,
                admission: if candidate.engagement_pending.is_empty() {
                    Admission::Executes
                } else {
                    Admission::ExecutesAborted
                },
                committed_prices: candidate.committed_prices,
            });
            taken.push(tx_hash);
        }

        for tx_hash in taken {
            self.candidates.remove(&tx_hash);
        }
        admitted
    }

    /// Drop a candidate no tick will take — abandoned at its deadline, or
    /// dropped with the chain at a reshape terminal.
    pub fn remove(&mut self, tx_hash: TxHash) {
        self.candidates.remove(&tx_hash);
    }

    /// Drop every delivering candidate the delivery window has closed on.
    ///
    /// A delivery is admissible to the window's close and no later: past
    /// it the crossing lapses and its issuer may reclaim on a proof the
    /// claim is absent, so a delivery composed past the close would
    /// claim what a reclaim may already have taken back. Run before
    /// every composition under the same clock, so [`Self::compose`]
    /// never sees one. Returns the hashes dropped.
    ///
    /// A mixed shard's delivering member is the one that reaches this:
    /// registered beside its issuing member, and removed by nothing else,
    /// since its ledger entry is the leg's and a leg is never abandoned.
    pub fn drop_closed_deliveries(&mut self, now: WeightedTimestamp) -> Vec<TxHash> {
        let closed: Vec<TxHash> = self
            .candidates
            .iter()
            .filter(|(_, candidate)| {
                candidate.member.side() == Side::Delivering
                    && now
                        >= Window::Delivery
                            .of(Deadline::of_transaction(&candidate.tx))
                            .end
            })
            .map(|(tx_hash, _)| *tx_hash)
            .collect();
        for tx_hash in &closed {
            self.candidates.remove(tx_hash);
        }
        closed
    }

    /// Whether a transaction is still waiting for a tick.
    #[must_use]
    pub fn contains(&self, tx_hash: TxHash) -> bool {
        self.candidates.contains_key(&tx_hash)
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
    use hyperscale_types::WeightedTimestamp;
    use hyperscale_types::test_utils::{test_prefix, test_transaction_with_prefixes};

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

    /// A transaction reaching no further than this shard needs nothing
    /// from anyone, so it joins the first tick composed after its commit.
    #[test]
    fn a_local_transaction_joins_at_once() {
        let mut candidates = TickCandidates::new(LOCAL);
        let hash = local_only(&mut candidates, tx(1));

        let admitted = candidates.compose(
            &ProvisioningTracker::new(),
            &mut ProvisionalCells::default(),
            ms(1_000),
        );
        assert_eq!(admitted.len(), 1);
        assert_eq!(admitted[0].request.tx_hash, hash);
        assert!(!admitted[0].request.runs.reaches_beyond());
        assert!(candidates.is_empty(), "and leaves the pool with the tick");
    }

    /// A member is composed under the table its committing block named,
    /// however far the schedule has moved since.
    ///
    /// What a shard attests it charged is the figure its own block
    /// froze — the one an abandonment of the same member would restate —
    /// so the table travels with the candidate rather than being
    /// resolved again where the tick composes.
    #[test]
    fn a_member_carries_the_table_its_committing_block_named() {
        let mut candidates = TickCandidates::new(LOCAL);
        let moved = PriceTable {
            compute: PriceTable::GENESIS.compute * 2,
            ..PriceTable::GENESIS
        };
        candidates.register(
            tx(1),
            BTreeSet::from([LOCAL]),
            ms(1_000),
            moved,
            Classified::whole(),
        );
        let admitted = candidates.compose(
            &ProvisioningTracker::new(),
            &mut ProvisionalCells::default(),
            ms(9_000),
        );
        assert_eq!(admitted.len(), 1);
        assert_eq!(
            admitted[0].committed_prices, moved,
            "the committing block's table, not the composing tick's"
        );
    }

    /// A cross-shard member waits for the provisions its counterparts owe
    /// it, and waiting costs it nothing but latency — it has said nothing.
    #[test]
    fn a_cross_shard_member_waits_for_its_provisions() {
        let mut candidates = TickCandidates::new(LOCAL);
        let remote = ShardId::leaf(1, 1);
        let tx = tx(2);
        let hash = tx.hash();
        candidates.register(
            tx,
            BTreeSet::from([LOCAL, remote]),
            ms(1_000),
            PriceTable::GENESIS,
            Classified::whole(),
        );

        let mut provisioning = ProvisioningTracker::new();
        assert!(
            candidates
                .compose(&provisioning, &mut ProvisionalCells::default(), ms(1_000),)
                .is_empty(),
            "nothing has arrived for it",
        );
        assert!(candidates.contains(hash), "so it is still waiting");

        provisioning.record_required(hash, BTreeSet::new());
        let admitted =
            candidates.compose(&provisioning, &mut ProvisionalCells::default(), ms(1_000));
        assert_eq!(admitted.len(), 1);
        assert!(admitted[0].request.runs.reaches_beyond());
    }

    /// A delivering candidate the window has closed on is dropped, not
    /// merely skipped: no tick can take it again, and the shard holding
    /// it holds the transaction's body and walks it once per block.
    #[test]
    fn a_delivering_candidate_goes_when_its_window_closes() {
        let mut candidates = TickCandidates::new(LOCAL);
        let remote = ShardId::leaf(1, 1);
        let delivery = tx(6);
        let delivered = delivery.hash();
        let end = delivery.validity_range().end_timestamp_exclusive;
        candidates.register_member(
            delivery,
            Member::of(
                Classified::whole(),
                LOCAL,
                Side::Delivering,
                BTreeSet::from([LOCAL, remote]),
            ),
            ms(1_000),
            PriceTable::GENESIS,
        );
        let issuing = local_only(&mut candidates, tx(7));

        assert!(
            candidates
                .drop_closed_deliveries(
                    Window::Delivery
                        .of(Deadline::of(end))
                        .end
                        .minus(std::time::Duration::from_millis(1))
                )
                .is_empty(),
            "short of the close the delivery may still be admitted",
        );

        assert_eq!(
            candidates.drop_closed_deliveries(Window::Delivery.of(Deadline::of(end)).end),
            vec![delivered],
        );
        assert!(!candidates.contains(delivered));
        assert!(
            candidates.contains(issuing),
            "an issuing candidate is on its own clock",
        );
    }

    /// The payer's leg does not execute until its counterparts have
    /// engaged: the tick that runs it is the tick that attests it, so it
    /// must not run before it knows which verdict it owes.
    #[test]
    fn the_payer_leg_waits_for_the_echoes_its_verdict_turns_on() {
        let mut candidates = TickCandidates::new(LOCAL);
        let remote = ShardId::leaf(1, 1);
        let tx = tx(3);
        let hash = tx.hash();
        candidates.register(
            tx,
            BTreeSet::from([LOCAL, remote]),
            ms(1_000),
            PriceTable::GENESIS,
            Classified::whole(),
        );
        candidates.record_engagement_wait(hash, BTreeSet::from([remote]), ms(60_000));

        let mut provisioning = ProvisioningTracker::new();
        provisioning.record_required(hash, BTreeSet::new());

        assert!(
            candidates
                .compose(&provisioning, &mut ProvisionalCells::default(), ms(1_000),)
                .is_empty(),
            "the payer holds while a counterpart has not engaged",
        );
    }

    /// Past its deadline the payer stops waiting and runs anyway, marked
    /// for the abort its tick attests — the charge that abort settles is
    /// what the execution builds, so it cannot be skipped.
    #[test]
    fn the_payer_leg_runs_at_its_deadline_to_be_aborted() {
        let mut candidates = TickCandidates::new(LOCAL);
        let remote = ShardId::leaf(1, 1);
        let tx = tx(4);
        let hash = tx.hash();
        candidates.register(
            tx,
            BTreeSet::from([LOCAL, remote]),
            ms(1_000),
            PriceTable::GENESIS,
            Classified::whole(),
        );
        candidates.record_engagement_wait(hash, BTreeSet::from([remote]), ms(60_000));

        let mut provisioning = ProvisioningTracker::new();
        provisioning.record_required(hash, BTreeSet::new());

        let admitted =
            candidates.compose(&provisioning, &mut ProvisionalCells::default(), ms(60_000));
        assert_eq!(admitted.len(), 1);
        assert_eq!(
            admitted[0].admission,
            Admission::ExecutesAborted,
            "it executes to build the charge, and is attested aborted",
        );
    }

    /// A member whose declared cells a provisional leg holds waits for
    /// that leg's fate rather than reading what it left.
    #[test]
    fn a_member_waits_on_a_cell_a_provisional_leg_holds() {
        let mut candidates = TickCandidates::new(LOCAL);
        let contender = tx(5);
        let hash = local_only(&mut candidates, Arc::clone(&contender));

        let mut held = ProvisionalCells::default();
        held.claim(&contender.routing().declared_modes);

        assert!(
            candidates
                .compose(&ProvisioningTracker::new(), &mut held, ms(1_000),)
                .is_empty(),
            "the cell is spoken for",
        );
        assert!(candidates.contains(hash));
    }

    /// A divided member joins on the membership its frozen
    /// classification implies, not on the participant set it was
    /// registered with: a leg awaits itself and reaches every
    /// participant.
    #[test]
    fn a_divided_member_joins_on_its_classified_membership() {
        use crate::fixtures::{leaf, swap, trie};

        let trie = trie();
        let (local, venue) = (leaf(0), leaf(1));
        let classified = Classified::freeze(&swap(), &[], &trie);
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
        let mut provisioning = ProvisioningTracker::new();
        provisioning.record_required(hash, BTreeSet::new());

        let admitted =
            candidates.compose(&provisioning, &mut ProvisionalCells::default(), ms(1_000));
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

    /// The claim exists for a member a counterpart can still retract.
    /// Two whole cross-shard members writing one cell take turns — the
    /// first claims it and the second waits for the first's fate. Two
    /// divided members of a single-shard core writing the same cell are
    /// admitted together: nothing retracts either, so the kernel's own
    /// conflict groups sequence them, and a contended core clears its
    /// queue in one tick rather than one member per tick.
    #[test]
    fn a_member_nothing_can_retract_takes_no_provisional_claim() {
        use crate::fixtures::{leaf, swap, trie};

        let trie = trie();
        let (caller, venue) = (leaf(0), leaf(1));
        let participating = BTreeSet::from([caller, venue]);
        // Two transactions distinct by hash, both writing one pool cell.
        let contending = |seed: u8| {
            Arc::new(Verified::new_unchecked_for_test(
                test_transaction_with_prefixes(
                    &[seed, seed + 1, seed + 2],
                    &[],
                    &[test_prefix(99)],
                ),
            ))
        };

        let mut whole = TickCandidates::new(venue);
        let mut provisioning = ProvisioningTracker::new();
        for seed in [1, 2] {
            let tx = contending(seed);
            provisioning.record_required(tx.hash(), BTreeSet::new());
            whole.register(
                tx,
                participating.clone(),
                ms(1_000),
                PriceTable::GENESIS,
                Classified::whole(),
            );
        }
        let mut held = ProvisionalCells::default();
        let admitted = whole.compose(&provisioning, &mut held, ms(1_000));
        assert_eq!(admitted.len(), 1, "a whole member claims the cell");
        assert!(admitted[0].request.runs.abortable());
        assert_eq!(whole.len(), 1, "and the other waits on its fate");

        let classified = Classified::freeze(&swap(), &[], &trie);
        assert_eq!(classified.core(), &BTreeSet::from([venue]));
        let mut divided = TickCandidates::new(venue);
        for seed in [1, 2] {
            let tx = contending(seed);
            divided.register(
                tx,
                participating.clone(),
                ms(1_000),
                PriceTable::GENESIS,
                classified.clone(),
            );
        }
        let mut held = ProvisionalCells::default();
        let admitted = divided.compose(&provisioning, &mut held, ms(1_000));
        assert_eq!(admitted.len(), 2, "both core members clear in one tick");
        assert!(
            admitted
                .iter()
                .all(|member| !member.request.runs.abortable())
        );
        assert!(held.is_empty(), "and neither claimed anything");
        assert!(divided.is_empty());
    }
}
