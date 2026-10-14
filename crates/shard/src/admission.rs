//! What a block's sections are admitted against, and the one rule per
//! section that admits an item.
//!
//! A proposer selects what its block carries and every voter checks
//! what a block carries, and the two must agree: a proposer offering
//! what its own voters refuse spends a round and offers it again. So
//! each section has one predicate, [`Section::admit`], read against one
//! [`Committed`] context — the chain behind the block's parent and the
//! window it is anchored in — with a running [`Section::Fold`] for the
//! rules that hold across the section. The proposer filters its
//! candidates on it; the voter runs it over the block and refuses on the
//! first item it refuses.
//!
//! Only what is deterministic over the block and the committed chain
//! lives here. What a validator can only hold to its own evidence — a
//! settled set, a counterpart's word, a proven anchor, a predecessor's
//! answer — is the vote fence's, and what a delegated verifier
//! recomputes — a root, a validity window, a reservation — is the
//! pipeline's.

use std::collections::{BTreeSet, HashSet};
use std::marker::PhantomData;
use std::ops::Bound;
use std::sync::Arc;

use hyperscale_engine::tick_select::{awaited_core, member_of};
use hyperscale_storage::{MemberIndex, RowState};
use hyperscale_types::{
    AbandonmentRecord, Anchor, BlockHash, BlockHeight, DeclaredWork, Engagement, EpochWindows,
    Finalization, FinalizationHash, MAX_CLAIMS_BYTES, MAX_ENGAGEMENTS_PER_BLOCK,
    MAX_FINALIZED_TX_PER_BLOCK, MAX_HELD_VALUE_BYTES, MAX_HOLDS_PER_MEMBER,
    MAX_PROPOSAL_EVIDENCE_BYTES, MAX_STANDING_TOWARD_SHARD, MAX_STATE_CLAIMS_BYTES,
    MAX_STATE_CLAIMS_PER_BLOCK, MAX_UNSETTLED_PER_BLOCK, ProvisionHash, Provisions, Settlement,
    ShardId, StandingToward, StateClaim, SubstateKey, TickHalf, TopologySchedule, TopologySnapshot,
    Transaction, TxHash, TxOutcome, Verifiable, WeightedTimestamp, WindowView, budget_admits_block,
    caps_admit_transaction, claims_admit_block, evidence_admits_block, state_claims_admit_block,
    sweep_admits_block,
};
use hyperscale_vm_effects::{CROSSING_CELL_BYTES, CrossingLeaf, ProtocolHasher, Terms};

use crate::chain_view::ChainView;
use crate::commit_dedup::CommitDedupIndex;

/// What the QC chain's uncommitted ancestors already carry, from a
/// parent back to committed height, gathered in one walk.
///
/// Transactions, provisions and certificate identities are read off each
/// ancestor's manifest, which names them whether or not the body has
/// assembled here; the transactions those certificates decide are read
/// off the finalizations themselves, so an ancestor whose finalizations
/// this node is still fetching contributes none — a node that
/// under-reports can only fail to refuse, and the rule needs a quorum of
/// enforcers rather than every node. The just-committed block is
/// covered by the [`CommitDedupIndex`] instead.
#[derive(Debug, Default)]
pub(crate) struct QcChainSets {
    /// Transactions an ancestor carries.
    pub(crate) txs: HashSet<TxHash>,
    /// Provision batches an ancestor carries.
    pub(crate) provisions: HashSet<ProvisionHash>,
    /// Transactions an ancestor's finalizations decided.
    pub(crate) resolved: HashSet<TxHash>,
    /// Finalizations an ancestor carries.
    pub(crate) finalizations: HashSet<FinalizationHash>,
}

impl QcChainSets {
    /// What the chain above `parent_block_hash` carries, walked once.
    #[must_use]
    pub(crate) fn behind(chain: &ChainView<'_>, parent_block_hash: BlockHash) -> Self {
        let mut sets = Self::default();
        let mut current_hash = parent_block_hash;
        // Headers, not pending entries: a block admitted through sync is
        // certified without ever being constructed as pending, and a
        // halt recovery's fresh committee extends exactly such a block
        // as its proposal parent. Walking `pending` alone stops at it
        // and reads nothing of the chain above the committed tip, so a
        // name it already carries is refused by nothing — the dedup
        // index covers the committed window, and this covers the
        // uncommitted prefix, leaving no gap between them.
        while let Some(header) = chain.get_header(current_hash) {
            if header.height() <= chain.committed_height() {
                break;
            }
            // A pending block carries its manifest before its body
            // assembles, which is the whole point of reading it there;
            // a certified one carries the body and nothing else.
            if let Some(pending) = chain.get_pending(current_hash) {
                let manifest = pending.manifest();
                sets.txs.extend(manifest.tx_hashes().iter().copied());
                sets.provisions
                    .extend(manifest.provision_hashes().iter().copied());
                sets.finalizations
                    .extend(manifest.cert_ids().iter().copied());
                for fw in pending.finalizations() {
                    sets.resolved.extend(fw.deciding_tx_hashes());
                }
            } else if let Some(block) = chain.get_block(current_hash) {
                sets.txs
                    .extend(block.transactions().iter().map(|tx| tx.hash()));
                sets.provisions.extend(block.provision_hashes());
                for fw in block.certificates().iter() {
                    sets.finalizations.insert(fw.receipt_hash());
                    sets.resolved.extend(fw.deciding_tx_hashes());
                }
            }
            current_hash = header.parent_block_hash();
        }
        sets
    }
}

/// What a block is admitted against: the committed view at the block's
/// two anchors.
///
/// Every input is the block, its parent's header, the committee at the
/// parent's anchor, the window at the block's own anchor, or a tier
/// folded from committed blocks and read at that anchor — so two
/// replicas at different tips, clocks or head epochs answer alike.
/// Execution's report beside the rows' owed ticks is the one node-local
/// input, and it only refuses.
#[derive(Clone, Copy)]
pub(crate) struct Committed<'a> {
    /// The committee the block is classified under: the one its parent's
    /// anchor resolves. Classification, payer routing and the recovery
    /// fences read it; every time comparison reads [`Self::anchor`]. The
    /// two anchors straddle an epoch cut once per window.
    pub(crate) snapshot: &'a TopologySnapshot,
    /// The window at the block's own anchor, whose boundary records say
    /// which shards have departed and where each chain ended.
    pub(crate) window: WindowView<'a>,
    /// The epoch grid the windows sit on.
    pub(crate) windows: EpochWindows,
    /// The schedule, read only for the window a state claim's own anchor
    /// lies in, which is at most a retention horizon before the block's.
    pub(crate) schedule: &'a TopologySchedule,
    /// The shard the block is on.
    pub(crate) local_shard: ShardId,
    /// The block's own anchor: its parent QC's weighted timestamp.
    pub(crate) anchor: WeightedTimestamp,
    /// The block's parent as an anchor: this shard, the parent's height
    /// and state root, at the block's own clock. The one anchor a
    /// crossing whose two ends route here is read at, with the empty
    /// proof, since every voter reads that state through its own
    /// anchored view.
    pub(crate) parent: Anchor,
    /// Where this chain began; content anchored before it belongs to a
    /// predecessor.
    pub(crate) chain_origin: WeightedTimestamp,
    /// What the QC chain above the parent carries.
    pub(crate) chain: &'a QcChainSets,
    /// What committed blocks within the retention window carry.
    pub(crate) dedup: &'a CommitDedupIndex,
    /// Tick membership at the parent: which tick holds each member, and
    /// in which half.
    pub(crate) members: &'a MemberIndex,
    /// The settlement frontier the parent left, which a determined half
    /// must settle above. `None` where the parent is pruned, which
    /// leaves the order unjudged here: such a block is verified but not
    /// voted on.
    pub(crate) parent_settled_frontier: Option<BlockHeight>,
    /// Ticks whose determined half this chain still owes, by height: the
    /// member rows' flags at the parent, which a proposer and every voter
    /// read alike, beside execution's report for the ticks that run
    /// nothing but reclaims, which no row names. A half may not settle
    /// past one of these.
    ///
    /// The report is the one node-local input, and so it may only
    /// refuse: a validator that never composed a reclaim tick holds it in
    /// no set and enforces nothing, so it refuses only what a composing
    /// quorum would refuse anyway.
    pub(crate) owed_determined: &'a BTreeSet<BlockHeight>,
}

/// One section of a block, and the rule that admits an item to it.
pub(crate) trait Section {
    /// What the section holds.
    type Item: ?Sized;
    /// What the rule carries across the section.
    type Fold;

    /// Admit `item` after everything the fold has admitted, advancing
    /// the fold on success and leaving it untouched on refusal, so a
    /// proposer filtering a candidate list and a voter walking a block
    /// fold the same admitted items the same way.
    ///
    /// # Errors
    ///
    /// Why the item is refused, for the voter's log.
    fn admit(ctx: &Committed<'_>, fold: &mut Self::Fold, item: &Self::Item) -> Result<(), String>;
}

/// The block's provisions.
pub(crate) struct ProvisionsSection;

/// What the provisions admitted so far amount to.
#[derive(Debug, Default)]
pub(crate) struct ProvisionsFold {
    /// Transactions the admitted batches provision, against the block's
    /// cap on them.
    pub(crate) tx_count: usize,
    /// What the admitted batches engage — what the transactions section
    /// reads to engage a cross-shard transaction in the same block.
    pub(crate) engaged: BTreeSet<Engagement>,
}

impl ProvisionsFold {
    /// Whether an admitted batch from `source` names `tx_hash`, at any
    /// source height.
    pub(crate) fn engages(&self, source: ShardId, tx_hash: TxHash) -> bool {
        let at = |source_height| Engagement {
            source,
            tx_hash,
            source_height,
        };
        self.engaged
            .range(at(BlockHeight::GENESIS)..=at(BlockHeight::new(u64::MAX)))
            .next()
            .is_some()
    }
}

impl Section for ProvisionsSection {
    type Item = Provisions;
    type Fold = ProvisionsFold;

    /// A batch the chain does not already carry, from a shard whose
    /// recovery does not fence it, within the block's transaction cap.
    ///
    /// Content from a recovering shard above its attested frontier is
    /// refused network-wide, and folding the check into admission keeps
    /// every replica's verdict a pure function of the block's own
    /// anchor: a block anchored before the recovery folded resolves a
    /// snapshot without the record and stays valid.
    fn admit(ctx: &Committed<'_>, fold: &mut Self::Fold, batch: &Provisions) -> Result<(), String> {
        let provision_hash = batch.hash();
        if ctx.chain.provisions.contains(&provision_hash) {
            return Err(format!(
                "provisions batch {provision_hash:?} already in QC chain ancestor"
            ));
        }
        if ctx.dedup.contains_provision(&provision_hash, ctx.anchor) {
            return Err(format!(
                "provisions batch {provision_hash:?} already committed within its retention window"
            ));
        }
        let source_shard = batch.source_shard();
        if ctx
            .snapshot
            .recovery_fences(source_shard, batch.block_height())
        {
            return Err(format!(
                "provisions batch {provision_hash:?} from recovering shard {source_shard:?} above \
                 the attested frontier"
            ));
        }
        let tx_count = fold.tx_count.saturating_add(batch.transactions().len());
        if tx_count > MAX_ENGAGEMENTS_PER_BLOCK {
            return Err(format!(
                "provisions batch {provision_hash:?} carries the block past \
                 {MAX_ENGAGEMENTS_PER_BLOCK} provisioned transactions"
            ));
        }
        fold.tx_count = tx_count;
        fold.engaged.extend(Engagement::of_batch(batch));
        Ok(())
    }
}

/// The block's transactions, admitted beside the provisions that
/// engage them.
pub(crate) struct TransactionsSection<'p>(PhantomData<&'p ProvisionsFold>);

/// What the transactions admitted so far amount to.
#[derive(Debug)]
pub(crate) struct TransactionsFold<'a> {
    /// The sweepable cells the admitted transactions create on this
    /// shard, against the per-block creation cap.
    pub(crate) sweepable: usize,
    /// What the admitted transactions declare against this shard between
    /// them — each one's share under the block's placement — against the
    /// per-block caps.
    pub(crate) budget: DeclaredWork,
    /// The provisions admitted beside them, which engage a cross-shard
    /// transaction's payer.
    pub(crate) provisions: &'a ProvisionsFold,
    /// The rows standing toward each shard: those at the parent, and one
    /// for each admitted transaction whose member here awaits it. Read
    /// off the parent's rows by the first transaction that awaits a
    /// shard, so a section admitting none walks no row.
    standing: Option<StandingToward>,
}

impl<'a> TransactionsFold<'a> {
    /// A fold beside the admitted `provisions`.
    #[must_use]
    pub(crate) const fn beside(provisions: &'a ProvisionsFold) -> Self {
        Self {
            sweepable: 0,
            budget: DeclaredWork::ZERO,
            provisions,
            standing: None,
        }
    }

    /// The rows standing toward each shard after the transactions
    /// admitted so far.
    fn standing(&mut self, ctx: &Committed<'_>) -> &mut StandingToward {
        self.standing
            .get_or_insert_with(|| standing_toward(ctx.members))
    }
}

/// The rows of `rows` standing toward each shard: every row, in whatever
/// state, counted once for each shard its settlement awaits.
pub(crate) fn standing_toward(rows: &MemberIndex) -> StandingToward {
    StandingToward::over(rows.members.values().map(|row| row.awaits.as_slice()))
}

impl<'p> Section for TransactionsSection<'p> {
    type Item = Transaction;
    type Fold = TransactionsFold<'p>;

    /// A transaction the chain does not already carry and this shard
    /// commits, engaged by its payer bundle where its payer is
    /// elsewhere, under its own ceilings in every dimension, and fitting
    /// the block's sweepable-cell cap and its per-dimension caps over
    /// the share this shard bears, and awaiting no shard that
    /// [`MAX_STANDING_TOWARD_SHARD`] rows already stand toward.
    ///
    /// **The cap on rows standing toward one shard.** A core or whole
    /// member reaching beyond this shard stands until every shard it
    /// awaits answers, on no clock of its own, so a sibling that stops
    /// answering pins every row awaiting it. Such a transaction is
    /// refused where the rows at the parent awaiting one of its awaited
    /// shards, with the ones this block has already admitted, number the
    /// cap. Counted off the parent's rows and the block alone, so a
    /// proposer and every voter count alike, and under the trie the
    /// block's terms are derived under, so what is counted for an
    /// admitted transaction is what its row records.
    ///
    /// Nothing here asks about the code a transaction runs. A node that
    /// cannot resolve a package never derives the transaction at all, so
    /// it never reaches this gate — and one that did derive it holds the
    /// metadata, which is what admission reads. A shard that only takes
    /// delivery of the transaction's owed crossings never includes it:
    /// its commit fold credits them off the records' readings. Engagement
    /// demands the transaction commit proof — the payer bundle — ride in
    /// the same block or a committed one, which closes the
    /// Byzantine-proposer path to engaging counterpart locks before the
    /// payer shard commits. The sweep cap bounds how
    /// fast a shard can be made to owe cells, counted off the
    /// derivations for this shard plus the one committed cell the chain
    /// writes for every transaction it carries; a transaction that does
    /// not fit is refused on its own, so a large composition never
    /// starves the small ones behind it.
    fn admit(ctx: &Committed<'_>, fold: &mut Self::Fold, tx: &Transaction) -> Result<(), String> {
        let tx_hash = tx.hash();
        if ctx.chain.txs.contains(&tx_hash) {
            return Err(format!(
                "transaction {tx_hash} already in QC chain ancestor"
            ));
        }
        let trie = ctx.snapshot.shard_trie();
        let member = member_of(tx, trie, ctx.local_shard);
        let classified = member.classified();
        if !classified.commits_at(ctx.local_shard) {
            return Err(format!(
                "transaction {tx_hash} only delivers here, which its commit fold credits"
            ));
        }
        // The block that commits a transaction states what it declared,
        // on its terms entry or on the line that runs it, and its row
        // holds that: one declaring more than either carries is never
        // carried.
        if tx.routing().declared_modes.len() > MAX_HOLDS_PER_MEMBER {
            return Err(format!(
                "transaction {tx_hash} declares more accesses than a member's terms carry"
            ));
        }
        let awaited = awaited_core(&member);
        if !awaited.is_empty()
            && let Some(shard) = fold.standing(ctx).capped(&awaited)
        {
            return Err(format!(
                "transaction {tx_hash} awaits {shard:?}, which {MAX_STANDING_TOWARD_SHARD} rows \
                 already stand toward"
            ));
        }

        let payer_shard = trie.shard_for_prefix(tx.fee_payer());
        if !ctx.snapshot.is_single_shard_transaction(tx)
            && payer_shard != ctx.local_shard
            && !fold.provisions.engages(payer_shard, tx_hash)
            && !ctx
                .dedup
                .engaged(payer_shard, tx_hash, ctx.anchor, ctx.snapshot)
        {
            return Err(format!(
                "cross-shard VM transaction {tx_hash} lacks its payer bundle from \
                 {payer_shard:?}"
            ));
        }
        // The committed cell is one per transaction, so the term is a
        // constant rather than a reading of where the shape sits.
        let sweepable = fold
            .sweepable
            .saturating_add(tx.sweepable_writes_on(trie, ctx.local_shard) + 1);
        if !sweep_admits_block(sweepable) {
            return Err(format!(
                "transaction {tx_hash} carries the block past the per-block cap on sweepable cells"
            ));
        }
        // The signed ceiling covers the price at the table this block's
        // anchor names. Judged here rather than at the signature,
        // because the price is the window's and a signature check holds
        // no window: a transaction admissible before a fold that raised
        // the table is one its own ceiling no longer covers.
        //
        // By the shard holding the payer's vault and by no other. Fees
        // never move cross-shard, so that shard is where the ceiling is
        // spent and where the table that prices it is resolved — and two
        // shards whose blocks sit either side of a fold name two tables,
        // so a guard every participant applied would admit a straddling
        // transaction on one shard and refuse it on another.
        if payer_shard == ctx.local_shard {
            let price = tx.price(&ctx.snapshot.prices());
            if price > tx.terms().max_fee {
                return Err(format!(
                    "transaction {tx_hash} signs a ceiling of {} and prices at {price}",
                    tx.terms().max_fee
                ));
            }
        }
        // The declared vector, held to the transaction's own ceilings
        // whole and to the block's caps over this shard's share: what
        // the block reserves is what its transactions may consume here,
        // judged from the block alone.
        if !caps_admit_transaction(tx.work()) {
            return Err(format!(
                "transaction {tx_hash} declares more than the protocol admits of one transaction"
            ));
        }
        let budget = fold
            .budget
            .saturating_add(classified.local_work(tx, ctx.local_shard));
        if !budget_admits_block(&budget) {
            return Err(format!(
                "transaction {tx_hash} carries the block past a per-block cap on this shard"
            ));
        }
        fold.sweepable = sweepable;
        fold.budget = budget;
        if !awaited.is_empty() {
            fold.standing(ctx).add(&awaited);
        }
        Ok(())
    }
}

/// The block's finalizations.
pub(crate) struct FinalizationsSection;

/// What the finalizations admitted so far amount to.
#[derive(Debug)]
pub(crate) struct FinalizationsFold {
    /// Every name an admitted finalization carries, deciding or not.
    pub(crate) resolved_here: HashSet<TxHash>,
    /// Every admitted certificate's identity.
    pub(crate) carried_here: HashSet<FinalizationHash>,
    /// Where the determined halves admitted so far end, starting at the
    /// parent's frontier. `None` where the parent is pruned and the
    /// order is not judged.
    pub(crate) frontier: Option<BlockHeight>,
    /// Transactions the admitted finalizations carry, against the
    /// block's cap: the ones each settles, and the ones a stating half
    /// states.
    pub(crate) tx_count: usize,
    /// The ticks an admitted stating half belongs to.
    pub(crate) stated_here: HashSet<BlockHeight>,
}

impl FinalizationsFold {
    /// A fold starting at the parent's settlement frontier.
    #[must_use]
    pub(crate) fn from(ctx: &Committed<'_>) -> Self {
        Self {
            resolved_here: HashSet::new(),
            carried_here: HashSet::new(),
            frontier: ctx.parent_settled_frontier,
            tx_count: 0,
            stated_here: HashSet::new(),
        }
    }
}

impl Section for FinalizationsSection {
    type Item = Finalization;
    type Fold = FinalizationsFold;

    /// A certificate of one of this chain's own ticks, anchored on this
    /// chain, that the chain does not already carry, whose names the
    /// chain has not already resolved, whose determined half settles
    /// above the frontier, whose other half settles behind every
    /// determined half owed up to its tick, within the block's cap on
    /// finalized transactions.
    ///
    /// A finalization's names are the members it settles: every member
    /// of a determined half, the ones a stating half's certificate
    /// refused, and the ones a legs half lists. A tick's legs settle by
    /// member, so a block may carry several legs halves of one tick,
    /// each naming members no other names and each counted against the
    /// cap for its own names alone.
    ///
    /// Every half is judged against the parent's rows, and which half
    /// may touch a row is read from where the row stands: the determined
    /// half a row in flight that it alone settles, the stating half any
    /// other row in flight, a legs half a row stated. So a legs half
    /// rides a later block than the stating half of its members, and one
    /// offered first is refused.
    ///
    /// **A determined half is whole over its tick's rows.** Its reserved
    /// outcomes are over distinct rows and number the rows its tick
    /// holds in flight for the determined half alone, so a proposer
    /// cannot settle part of them under the tick's certificate projected
    /// to that part, carry the frontier to the tick, and leave the rest
    /// where no determined half reaches them again. A reclaim holds no
    /// row and is counted by none.
    ///
    /// **A stating half is whole and single.** Every outcome of its
    /// certificate, one it settles or one it states, is over a distinct
    /// row its tick holds in flight outside the determined half, a
    /// reserved one, and a stated yes over a row a counterpart shares
    /// the verdict on, which is the only row a stating half moves and
    /// does not delete. They number the rows the tick holds so, so a
    /// proposer cannot state part of a tick and leave the rest with no
    /// half that could ever touch them; and a block carries one stating
    /// half of a tick, since two copies attested at different anchors
    /// both read the parent's rows as theirs. Each outcome counts
    /// against the cap, since each moves a row. A stated name joins no
    /// resolved set: the legs half that settles it comes later.
    ///
    /// **The name rule is what makes settlement and abandonment
    /// exclusive.** A shard abandons a transaction its counterpart left
    /// in flight, and settles one whose coverage completed; both are
    /// verdicts, and a transaction that took two of them would be
    /// settled on one reading of the chain and aborted on another. One
    /// rule covers both directions because it asks about the
    /// transaction rather than about which kind of verdict each
    /// certificate carried: every name is held to once per block, and
    /// only a deciding one against what the chain already resolved,
    /// since a leg's finalization resolves nothing and the reclaim's
    /// may follow it. The identity rule beside it is the same rule at a
    /// coarser key, for the case the fine key cannot reach: a
    /// certificate whose members reach no verdict names nothing the
    /// per-transaction rule can hold it to, so without it the same
    /// certificate rides every block.
    ///
    /// A certificate anchored before the chain's origin names a tick on
    /// a predecessor, resolves transactions this chain never committed,
    /// and carries receipts computed against a state this genesis never
    /// held; there is no harmless subset to separate out.
    ///
    /// A certificate of another shard's tick is the same hazard without
    /// the clock to catch it: that shard's committee certified it over
    /// receipts this chain never executed, no row of this chain holds its
    /// members, and settling it would write another chain's state here.
    /// Every finalization admitted therefore names a tick of this shard,
    /// which is what the member and frontier rules below read it as.
    ///
    /// The order its tick settles in is [`settles_in_order`]'s.
    fn admit(ctx: &Committed<'_>, fold: &mut Self::Fold, fw: &Finalization) -> Result<(), String> {
        if fw.local_ec().vote_anchor_ts() < ctx.chain_origin {
            return Err(format!(
                "certificate for tick {:?} predates this chain's origin",
                fw.tick_id()
            ));
        }
        if fw.tick_id().shard_id() != ctx.local_shard {
            return Err(format!(
                "finalization for tick {:?} names a tick of another shard",
                fw.tick_id()
            ));
        }
        let receipt_hash = fw.receipt_hash();
        if fold.carried_here.contains(&receipt_hash) {
            return Err(format!(
                "finalization {receipt_hash:?} appears twice in the same block"
            ));
        }
        if ctx.chain.finalizations.contains(&receipt_hash) {
            return Err(format!(
                "finalization {receipt_hash:?} is already carried by a QC chain ancestor"
            ));
        }
        if ctx.dedup.contains_finalization(&receipt_hash, ctx.anchor) {
            return Err(format!(
                "finalization {receipt_hash:?} was already committed within its retention window"
            ));
        }
        let stating = fw.half() == TickHalf::Stated;
        for outcome in fw.settled_outcomes() {
            let tx_hash = outcome.tx_hash();
            // A half settles only members its tick holds for that half: a
            // discarded one is released or gone, one an earlier legs half
            // of the tick named is deleted, and a later finalization of
            // either is refused. A member no committing block reserved a
            // place for, a reclaim, has no row to hold it, and is no
            // member a stating half speaks for.
            if (outcome.reserved() || stating) && !held_for(ctx.members, fw, tx_hash) {
                return Err(format!(
                    "finalization {receipt_hash:?} settles transaction {tx_hash}, which tick {} \
                     does not hold for its {:?} half",
                    fw.tick_id(),
                    fw.half(),
                ));
            }
            if fold.resolved_here.contains(&tx_hash) {
                return Err(format!(
                    "transaction {tx_hash} resolved twice within the same block"
                ));
            }
            if outcome.decides() {
                already_resolved(ctx, tx_hash)?;
            }
        }
        let stated = match fw.half() {
            TickHalf::Determined => {
                settles_its_rows_whole(ctx.members, fw)?;
                0
            }
            TickHalf::Stated => states_its_tick_whole(ctx.members, fold, fw)?,
            TickHalf::Legs => 0,
        };
        let frontier = settles_in_order(ctx, fold.frontier, fw)?;
        let tx_count = fold
            .tx_count
            .saturating_add(fw.tx_count())
            .saturating_add(stated);
        if tx_count > MAX_FINALIZED_TX_PER_BLOCK {
            return Err(format!(
                "finalization {receipt_hash:?} carries the block past {MAX_FINALIZED_TX_PER_BLOCK} \
                 finalized transactions"
            ));
        }
        fold.carried_here.insert(receipt_hash);
        fold.resolved_here.extend(fw.tx_hashes());
        fold.frontier = frontier;
        fold.tx_count = tx_count;
        if stating {
            fold.stated_here.insert(fw.tick_id().block_height());
        }
        Ok(())
    }
}

/// How many members `fw`, a stating half, states a yes for, where it
/// states its tick whole and is the block's one stating half of it; a
/// refusal otherwise.
///
/// Its settled outcomes are held to their rows by the caller. Here each
/// yes is held to a row its tick holds in flight on terms a counterpart
/// shares, every outcome to a reserved place and to a row of its own,
/// and the outcomes together to the count of rows the tick holds outside
/// its determined half.
fn states_its_tick_whole(
    members: &MemberIndex,
    fold: &FinalizationsFold,
    fw: &Finalization,
) -> Result<usize, String> {
    let tick = fw.tick_id().block_height();
    let receipt_hash = fw.receipt_hash();
    if fold.stated_here.contains(&tick) {
        return Err(format!(
            "finalization {receipt_hash:?} is a second stating half of tick {} in the same block",
            tick.inner()
        ));
    }
    let mut stated = 0usize;
    for outcome in fw.stated_outcomes() {
        let tx_hash = outcome.tx_hash();
        let shared = members.members.get(&tx_hash).is_some_and(|row| {
            matches!(
                row.state,
                RowState::InFlight {
                    tick: held,
                    settlement: Settlement::Shared,
                    ..
                } if held == tick
            )
        });
        if !shared {
            return Err(format!(
                "finalization {receipt_hash:?} states transaction {tx_hash}, which tick {} does \
                 not hold in flight beside a counterpart",
                tick.inner()
            ));
        }
        stated += 1;
    }
    let outcomes: Vec<&TxOutcome> = fw.settled_outcomes().chain(fw.stated_outcomes()).collect();
    if let Some(unreserved) = outcomes.iter().find(|outcome| !outcome.reserved()) {
        return Err(format!(
            "finalization {receipt_hash:?} states transaction {}, which no committing block \
             reserved a place for",
            unreserved.tx_hash()
        ));
    }
    if outcomes.is_empty() {
        return Err(format!(
            "finalization {receipt_hash:?} states no member of tick {}",
            tick.inner()
        ));
    }
    let awaiting = members.ticks.get(&tick).map_or(0, |row| row.awaiting);
    covers_its_rows(fw, &outcomes, awaiting as usize)?;
    Ok(stated)
}

/// A refusal unless `fw`, a determined half, settles every row its tick
/// holds for one.
///
/// Its reserved outcomes are held to their rows by the caller, each to
/// one in flight in the tick that the determined half alone settles.
/// Here they are held to rows of their own and to the count of such
/// rows the tick's own row lists. A tick's certificate projects to any
/// of its outcomes under one root and one signature, so a half over
/// some of those rows is as well formed as the half over all of them;
/// and a tick takes one determined half, since the frontier it carries
/// refuses a second. One settling part of the rows would leave the rest
/// in flight behind a frontier no half of theirs settles above.
///
/// A member no committing block reserved a place for holds no row, and
/// the count says nothing of it: a tick of nothing but such members
/// holds no row for the half, and its half is admitted over none.
fn settles_its_rows_whole(members: &MemberIndex, fw: &Finalization) -> Result<(), String> {
    let reserved: Vec<&TxOutcome> = fw
        .settled_outcomes()
        .filter(|outcome| outcome.reserved())
        .collect();
    let listed: BTreeSet<TxHash> = members
        .ticks
        .get(&fw.tick_id().block_height())
        .map_or_else(BTreeSet::new, |row| row.members.iter().copied().collect());
    let held = listed
        .into_iter()
        .filter(|&tx_hash| held_for(members, fw, tx_hash))
        .count();
    covers_its_rows(fw, &reserved, held)
}

/// A refusal unless `outcomes`, the ones of `fw` that each stand over a
/// row its tick holds for a half of `fw`'s kind, are over distinct rows
/// and number `held`, the rows the tick holds so. A half whole over its
/// tick leaves no row behind that only a half of its kind could touch.
fn covers_its_rows(fw: &Finalization, outcomes: &[&TxOutcome], held: usize) -> Result<(), String> {
    let distinct: HashSet<TxHash> = outcomes.iter().map(|outcome| outcome.tx_hash()).collect();
    if distinct.len() != outcomes.len() || outcomes.len() != held {
        return Err(format!(
            "finalization {:?} covers {} members of tick {}, which holds {held} for its {:?} half",
            fw.receipt_hash(),
            distinct.len(),
            fw.tick_id().block_height().inner(),
            fw.half(),
        ));
    }
    Ok(())
}

/// Where the determined halves admitted end once `fw` is, given that
/// they end at `frontier` before it; a refusal where `fw` would settle
/// out of order. `None` in is `None` out, and judges nothing.
///
/// A receipt states an absolute computed from its tick's baseline and
/// settlement is last writer per cell, so an earlier tick's determined
/// half landing after a later one's reverts a write later ticks have
/// already read — every replica would then agree on the wrong state,
/// which is why the order is refused up front rather than detected.
///
/// Any other half waits for the determined halves the chain owes between
/// the running frontier and its own tick, that tick's included. Its
/// members were judged over a baseline that folds the unsettled
/// determined output of every tick up to theirs, so a debit one of them
/// makes may be covered by a credit only that output holds, and settling
/// the debit first runs it past what state holds. The running frontier
/// rises with each determined half the block admits, so the block that
/// settles the owed half carries the waiting one behind it. A half at or
/// below the frontier waits on nothing: every determined half up to its
/// tick has settled.
fn settles_in_order(
    ctx: &Committed<'_>,
    frontier: Option<BlockHeight>,
    fw: &Finalization,
) -> Result<Option<BlockHeight>, String> {
    let Some(settled) = frontier else {
        return Ok(None);
    };
    let tick = fw.tick_id().block_height();
    if !fw.is_determined() {
        // A tick at or below the frontier leaves no range to read.
        if tick > settled
            && let Some(owed) = ctx
                .owed_determined
                .range((Bound::Excluded(settled), Bound::Included(tick)))
                .next()
        {
            return Err(format!(
                "{:?} half of tick {} settles ahead of tick {}, whose determined half the chain \
                 still owes",
                fw.half(),
                tick.inner(),
                owed.inner()
            ));
        }
        return Ok(frontier);
    }
    if tick <= settled {
        return Err(format!(
            "determined half of tick {} settles at or below the frontier {} it would settle under",
            tick.inner(),
            settled.inner()
        ));
    }
    // Nothing between the running frontier and this half may still owe
    // one of its own. Admitting it would carry the frontier past a tick
    // whose half is refused for good the moment its certificate lands,
    // leaving its members committed and never finalized.
    if let Some(skipped) = ctx
        .owed_determined
        .range((Bound::Excluded(settled), Bound::Excluded(tick)))
        .next()
    {
        return Err(format!(
            "determined half of tick {} settles past tick {}, whose own determined half the \
             chain still owes",
            tick.inner(),
            skipped.inner()
        ));
    }
    Ok(Some(tick))
}

/// Whether `members` holds `tx_hash` in `fw`'s tick where a half of
/// `fw`'s kind may touch it: in flight and settled by the determined
/// half alone for a determined half, in flight on any other terms for a
/// stating half, and stated for a legs half. An accepted row is in no
/// tick, and no half may touch it.
fn held_for(members: &MemberIndex, fw: &Finalization, tx_hash: TxHash) -> bool {
    let height = fw.tick_id().block_height();
    members
        .members
        .get(&tx_hash)
        .is_some_and(|row| match (fw.half(), row.state) {
            (
                TickHalf::Determined,
                RowState::InFlight {
                    tick, settlement, ..
                },
            ) => tick == height && settlement.alone(),
            (
                TickHalf::Stated,
                RowState::InFlight {
                    tick, settlement, ..
                },
            ) => tick == height && !settlement.alone(),
            (TickHalf::Legs, RowState::Stated { tick, .. }) => tick == height,
            (
                _,
                RowState::Pending
                | RowState::InFlight { .. }
                | RowState::Stated { .. }
                | RowState::Released { .. }
                | RowState::Accepted,
            ) => false,
        })
}

/// Refuse `tx_hash` if the chain has already reached a verdict on it —
/// by an ancestor above committed height, or by a committed block within
/// the retention window.
fn already_resolved(ctx: &Committed<'_>, tx_hash: TxHash) -> Result<(), String> {
    if ctx.chain.resolved.contains(&tx_hash) {
        return Err(format!(
            "transaction {tx_hash} already resolved by a QC chain ancestor"
        ));
    }
    if ctx.dedup.contains_resolved_tx(&tx_hash, ctx.anchor) {
        return Err(format!(
            "transaction {tx_hash} already resolved within its retention window"
        ));
    }
    Ok(())
}

/// Whether a voter on `local` admits `fw` in a block whose parent left
/// `rows` and the settlement frontier `frontier`.
///
/// The finalization section's own rule under `snapshot` spanning every
/// anchor, for a test in another crate that builds the half and the rows
/// it is judged against from one manifest.
///
/// # Errors
///
/// The refusal admission gives.
///
/// # Panics
///
/// Never: the one window spans every anchor.
#[cfg(feature = "test-utils")]
pub fn admit_finalization_over(
    snapshot: &TopologySnapshot,
    local: ShardId,
    rows: &MemberIndex,
    frontier: BlockHeight,
    fw: &Finalization,
) -> Result<(), String> {
    use hyperscale_types::{Epoch, StateRoot, WindowLookup};

    let schedule = TopologySchedule::new(u64::MAX / 2, Epoch::GENESIS, Arc::new(snapshot.clone()));
    let WindowLookup::Window(window) = schedule.lookup(WeightedTimestamp::ZERO) else {
        panic!("the one window spans every anchor");
    };
    let (chain, dedup) = (QcChainSets::default(), CommitDedupIndex::new());
    let owed_determined = rows.owed_determined();
    let ctx = Committed {
        snapshot,
        window,
        windows: schedule.windows(),
        schedule: &schedule,
        local_shard: local,
        anchor: WeightedTimestamp::ZERO,
        parent: Anchor {
            shard: local,
            height: BlockHeight::GENESIS,
            state_root: StateRoot::ZERO,
            ts: WeightedTimestamp::ZERO,
        },
        chain_origin: WeightedTimestamp::ZERO,
        chain: &chain,
        dedup: &dedup,
        parent_settled_frontier: Some(frontier),
        members: rows,
        owed_determined: &owed_determined,
    };
    FinalizationsSection::admit(&ctx, &mut FinalizationsFold::from(&ctx), fw)
}

/// The block's abandonment records, admitted after the finalizations
/// whose names they may not repeat.
pub(crate) struct RecordsSection<'f>(PhantomData<&'f FinalizationsFold>);

/// What the records admitted so far amount to, beside the finalizations
/// admitted before them.
#[derive(Debug)]
pub(crate) struct RecordsFold<'a> {
    /// The finalizations the block carries, whose names no record may
    /// repeat.
    pub(crate) finalizations: &'a FinalizationsFold,
    /// The last admitted record's shard, which the next must follow.
    pub(crate) previous: Option<ShardId>,
    /// Names the admitted records carry, against the drain's own bound.
    pub(crate) named: usize,
    /// Bytes the admitted records weigh, against the section's budget.
    pub(crate) weight: usize,
}

impl<'a> RecordsFold<'a> {
    /// A fold after the block's `finalizations`.
    #[must_use]
    pub(crate) const fn after(finalizations: &'a FinalizationsFold) -> Self {
        Self {
            finalizations,
            previous: None,
            named: 0,
            weight: 0,
        }
    }
}

impl RecordsSection<'_> {
    /// Whether a record may name `tx_hash`: not one a finalization in
    /// the same block resolves, and not one the chain already resolved.
    ///
    /// A record is a request for a second verdict, and one every replica
    /// would honour, since a replica reconstructs the entry from the
    /// record precisely when it cannot check the name against an account
    /// of its own. The proposer trims a record to the names that stand
    /// and offers what is left; the voter refuses a record naming one
    /// that does not.
    ///
    /// # Errors
    ///
    /// Why the name is refused.
    pub(crate) fn name_stands(
        ctx: &Committed<'_>,
        fold: &RecordsFold<'_>,
        tx_hash: TxHash,
    ) -> Result<(), String> {
        if fold.finalizations.resolved_here.contains(&tx_hash) {
            return Err(format!(
                "abandonment record names {tx_hash}, which the same block resolves"
            ));
        }
        already_resolved(ctx, tx_hash)
    }

    /// Whether every name a record carries is one the departed shard was
    /// party to, by [`UnsettledTx::party`]: it held one of the name's
    /// remote routes when the transaction committed, and left afterwards.
    /// A crossing named off its leaf is held to
    /// [`UnclaimedCrossing::party`](hyperscale_types::UnclaimedCrossing::party):
    /// the departed shard was the only one that could have taken it.
    ///
    /// A stranger to the departed shard is absent from its settled set
    /// trivially, and abandoning it would charge a payer for a
    /// transaction a live counterpart can still settle. Judged from the
    /// figures the record restates and the departures the window at the
    /// block's anchor attests, so every replica answers alike —
    /// including one holding no entry for the name, which rebuilds the
    /// entry from the record precisely because it cannot check the name
    /// against an account of its own.
    fn parties_stand(ctx: &Committed<'_>, record: &AbandonmentRecord) -> Result<(), String> {
        let departures: Vec<(ShardId, WeightedTimestamp)> =
            ctx.window.departures(ctx.windows).collect();
        for entry in record.unsettled() {
            if !entry.party(
                ctx.local_shard,
                record.shard(),
                record.terminal_wt(),
                &departures,
            ) {
                return Err(format!(
                    "abandonment record names {}, which the departed shard {:?} was not party to",
                    entry.tx_hash,
                    record.shard()
                ));
            }
        }
        for crossing in record.unclaimed() {
            if !crossing.party(
                ctx.local_shard,
                record.shard(),
                record.terminal_wt(),
                &departures,
            ) {
                return Err(format!(
                    "abandonment record names the crossing at {:?}, which the departed shard {:?} \
                     was not the one to take",
                    crossing.record,
                    record.shard()
                ));
            }
        }
        Ok(())
    }

    /// Whether a record's departure is one the window at the block's
    /// anchor attests: the cut it names is the departed shard's, and its
    /// boundary record is still readable there. A record anchored after
    /// the beacon closed and swept the departure claims what nobody can
    /// check.
    fn evidence_stands(ctx: &Committed<'_>, verdict: &AbandonmentRecord) -> Result<(), String> {
        let terminal_wt = verdict.terminal_wt();
        let shard = verdict.shard();
        let scheduled = ctx.window.terminal_cut(shard, ctx.windows);
        if scheduled != Some(terminal_wt) {
            return Err(format!(
                "abandonment record names a departure of {shard:?} at {terminal_wt:?} the \
                 schedule does not attest ({scheduled:?})"
            ));
        }
        if !ctx.window.evidence_readable(shard, ctx.anchor, ctx.windows) {
            return Err(format!(
                "abandonment record names a departure of {shard:?} whose evidence window has \
                 closed"
            ));
        }
        Ok(())
    }
}

impl<'f> Section for RecordsSection<'f> {
    type Item = AbandonmentRecord;
    type Fold = RecordsFold<'f>;

    /// A well-formed record, in its place in the section's order, under
    /// a departure the anchored window attests, naming only what the departed
    /// shard was party to and what stands, within the budget the records
    /// share.
    ///
    /// The order is ascending by shard, which gives uniqueness and one
    /// encoding per claim set together — two records for one shard
    /// would leave which answer counts to the reader, and a reordering
    /// would be a second form of the same block. Both budgets are sums
    /// across every record, because the per-record decode cap alone
    /// would let a block spend either once per record.
    ///
    /// The byte budget is what bounds the block, since a name's cost
    /// varies with its reach and a count cannot see that. At the
    /// figures both stand at, the bytes are reached first for a section
    /// of any shape — the drain's count of names costs three frames at
    /// the narrowest reach there is — so the count is checked for the
    /// question it answers rather than for the blocks it turns away:
    /// how many transactions the drain can have owed at once, which
    /// binds again the moment a name gets cheaper.
    fn admit(
        ctx: &Committed<'_>,
        fold: &mut Self::Fold,
        verdict: &AbandonmentRecord,
    ) -> Result<(), String> {
        if !verdict.is_well_formed() {
            return Err(format!(
                "abandonment record for {:?} is empty, over its cap, or out of order",
                verdict.shard()
            ));
        }
        let position = verdict.shard();
        if fold.previous.is_some_and(|previous| previous >= position) {
            return Err(format!(
                "abandonment record for {:?} repeats or precedes the one before it",
                verdict.shard()
            ));
        }
        Self::evidence_stands(ctx, verdict)?;
        Self::parties_stand(ctx, verdict)?;
        for tx_hash in verdict.tx_hashes() {
            Self::name_stands(ctx, fold, tx_hash)?;
        }
        let named = fold.named.saturating_add(verdict.names());
        if named > MAX_UNSETTLED_PER_BLOCK {
            return Err(format!(
                "abandonment records name {named} transactions, over the drain's own bound of \
                 {MAX_UNSETTLED_PER_BLOCK}"
            ));
        }
        let weight = fold.weight.saturating_add(verdict.wire_weight());
        if !evidence_admits_block(weight) {
            return Err(format!(
                "abandonment records weigh {weight} bytes, over the section's budget of \
                 {MAX_PROPOSAL_EVIDENCE_BYTES}"
            ));
        }
        fold.previous = Some(position);
        fold.named = named;
        fold.weight = weight;
        Ok(())
    }
}

/// The block's state claims.
pub(crate) struct StateClaimsSection;

/// The one value a reading carries is a crossing record, so the widest
/// held value is the record cell's own width.
const _: () = assert!(MAX_HELD_VALUE_BYTES == CROSSING_CELL_BYTES as usize);

/// What the claims admitted so far amount to.
#[derive(Debug, Default)]
pub(crate) struct StateClaimsFold {
    /// The last admitted claim's anchor and its last key, which the
    /// next claim must follow.
    pub(crate) previous: Option<(Anchor, SubstateKey)>,
    /// The bytes admitted so far of every claim but the verdict
    /// claims, against their budget.
    pub(crate) weight: usize,
    /// The bytes admitted so far of verdict claims, which spend what
    /// the other claims leave of the section's budget.
    pub(crate) verdict_weight: usize,
    /// How many claims but the verdict claims are admitted so far,
    /// against their count.
    pub(crate) count: usize,
}

impl StateClaimsFold {
    /// Whether `claim` follows what the fold has admitted, by the
    /// section's order rule: claims ascend by anchor, and claims at one
    /// anchor carry disjoint keys in ascending order. One anchor's
    /// readings are one sorted key list cut into claims, so no key is
    /// read twice at one anchor and no proof is orphaned or duplicated.
    pub(crate) fn in_order(&self, claim: &StateClaim) -> bool {
        let Some((anchor, last)) = self.previous else {
            return true;
        };
        let first = claim.cells.first().map(|(key, _)| *key);
        anchor < claim.anchor || (anchor == claim.anchor && first.is_some_and(|key| last < key))
    }

    /// Charge `claim` to the section, by its kind: every claim to the
    /// section's bytes, and a claim that is not a verdict claim, as
    /// [`StateClaim::is_verdict_claim`] tells one, to the bytes and the
    /// count such claims are held to inside it. So the verdict claims
    /// spend what the others leave, and the others never spend the
    /// bytes or the places left to the verdict claims. The kind is read
    /// off the claim alone, so every replica charges a block's claims
    /// alike.
    fn charge(&mut self, claim: &StateClaim) -> Result<(), String> {
        let bytes = claim.wire_weight();
        let verdict = claim.is_verdict_claim();
        let (weight, verdict_weight) = if verdict {
            (self.weight, self.verdict_weight.saturating_add(bytes))
        } else {
            (self.weight.saturating_add(bytes), self.verdict_weight)
        };
        if !verdict && self.count >= MAX_STATE_CLAIMS_PER_BLOCK {
            return Err(format!(
                "more state claims than the {MAX_STATE_CLAIMS_PER_BLOCK} that are not verdict \
                 claims a block carries"
            ));
        }
        if !state_claims_admit_block(weight) {
            return Err(format!(
                "state claims that are not verdict claims weigh {weight} bytes, over the \
                 section's budget of {MAX_STATE_CLAIMS_BYTES} for them"
            ));
        }
        let section = weight.saturating_add(verdict_weight);
        if !claims_admit_block(section) {
            return Err(format!(
                "state claims weigh {section} bytes, over the section's budget of \
                 {MAX_CLAIMS_BYTES}"
            ));
        }
        self.weight = weight;
        self.verdict_weight = verdict_weight;
        self.count += usize::from(!verdict);
        Ok(())
    }
}

impl Section for StateClaimsSection {
    type Item = StateClaim;
    type Fold = StateClaimsFold;

    /// A well-formed claim whose proof bears out every reading, at an
    /// anchor no recovery fences and no older than one retention
    /// horizon before the block's own clock unless it is a boundary
    /// claim, in its place in the section's order, within the section's
    /// budget and what its kind is held to inside it — and, where it
    /// carries a value, on the shard that owned the cell at the
    /// anchor's clock.
    ///
    /// A claim anchored at the block's own parent carries the empty
    /// proof and reads only keys the block's trie routes here: the
    /// verifier re-reads each one from its own parent view. A crossing
    /// reading of a locally routed key at any other anchor is refused,
    /// as is any other anchor of this shard's, which no voter could
    /// hold a commit-proven header for.
    ///
    /// The proof is walked here, so a bad one refuses the block on
    /// every replica alike: every rule is a pure function of the block
    /// and its anchor, nothing this validator fetched. Whether the
    /// anchor is a header this validator commit-proved is the vote
    /// fence's question. The order rule gives one set of answers one
    /// encoding, and the budget is spent by the byte, proof and values
    /// included: every claim but the verdict claims spends no more than
    /// its own share of it and takes no more than its own count of
    /// places, and the verdict claims spend what those leave.
    ///
    /// The age bound is the one any voter can still prove: a proof
    /// stands for a horizon, so a claim older than that is one no
    /// voter could check. Stated at the block's own clock, it is the
    /// exact complement of the read frontier's prune, which drops an
    /// entry once every presence it could refuse is one this bound
    /// refuses.
    ///
    /// One class of claim is admitted past the bound, the boundary
    /// claim: anchored on another shard more than a horizon before the
    /// block ([`StateClaim::at_boundary`]), naming no member, holding no
    /// value and reading nothing present under a crossing it names
    /// ([`StateClaim::reads_as_a_boundary`]). It is the reading a commit
    /// fold deletes an answer on, and the anchor it names is one the
    /// vote fence holds to the boundaries the beacon recorded, which
    /// every voter has without a header. The class is told from the
    /// claim and the block's anchor, so proposer and voter sort one
    /// claim alike. A claim of this shard's own, anchored at the parent,
    /// is no boundary claim however old the parent: after a stall longer
    /// than a horizon the block reads nothing at its parent. A cell the
    /// claim names nothing for is opaque here and licenses nothing: the
    /// one other reader of an unnamed reading, a seat question, is
    /// answered by nothing older than a horizon, which is the validity
    /// range plus the finalization delay. Which presences the frontier
    /// itself refuses is judged where the parent state is read. The
    /// owner is read off the global schedule at the anchor's own clock,
    /// never the head, so a split parent's coast anchor owns nothing;
    /// the fold reads the committed fact and never re-resolves.
    fn admit(ctx: &Committed<'_>, fold: &mut Self::Fold, claim: &StateClaim) -> Result<(), String> {
        let at = || {
            format!(
                "state claim on {:?} at height {}",
                claim.anchor.shard,
                claim.anchor.height.inner()
            )
        };
        if !claim.is_well_formed() {
            return Err(format!(
                "{} is empty, over its cap, or out of order, or names a member beside a \
                 crossing or a value",
                at()
            ));
        }
        let trie = ctx.snapshot.shard_trie();
        let routed_here = |key: &SubstateKey| trie.shard_for_prefix(key.owner) == ctx.local_shard;
        if claim.anchor == ctx.parent {
            if !claim.proof.as_bytes().is_empty() {
                return Err(format!("{} at the parent carries a proof", at()));
            }
            if !claim.keys().iter().all(routed_here) {
                return Err(format!(
                    "{} at the parent reads a key this shard does not hold",
                    at()
                ));
            }
        } else {
            if claim.anchor.shard == ctx.local_shard {
                return Err(format!("{} is anchored on this shard off its parent", at()));
            }
            if claim.crossings.iter().any(|(key, _)| routed_here(key)) {
                return Err(format!(
                    "{} reads a crossing of this shard's away from the parent",
                    at()
                ));
            }
            claim
                .verify()
                .map_err(|err| format!("{} does not prove its readings: {err}", at()))?;
            if ctx
                .snapshot
                .recovery_fences(claim.anchor.shard, claim.anchor.height)
            {
                return Err(format!(
                    "{} is at a height the shard's recovery fences",
                    at()
                ));
            }
        }
        if claim.at_boundary(ctx.anchor)
            && (claim.anchor.shard == ctx.local_shard || !claim.reads_as_a_boundary())
        {
            return Err(format!(
                "{} is anchored more than a retention horizon before the block and is no \
                 boundary reading of another shard",
                at()
            ));
        }
        if claim.holds_a_value() {
            let Some(window) = ctx.schedule.at(claim.anchor.ts) else {
                return Err(format!(
                    "{} carries a value at an anchor no schedule window covers",
                    at()
                ));
            };
            let trie = window.shard_trie();
            if claim
                .cells
                .iter()
                .filter(|(_, stated)| stated.held().is_some())
                .any(|(key, _)| trie.shard_for_prefix(key.owner) != claim.anchor.shard)
            {
                return Err(format!(
                    "{} carries the value of a cell its anchor's shard did not own at the \
                     anchor's clock",
                    at()
                ));
            }
            if owed_elsewhere(ctx, claim) {
                return Err(format!(
                    "{} carries an owed record whose consumer this shard does not hold",
                    at()
                ));
            }
        }
        if !fold.in_order(claim) {
            return Err(format!("{} repeats or precedes the one before it", at()));
        }
        fold.charge(claim)?;
        let last = claim
            .cells
            .last()
            .map(|(key, _)| *key)
            .expect("a well-formed claim names a cell");
        fold.previous = Some((claim.anchor, last));
        Ok(())
    }
}

/// Whether `claim` carries the value of an owed record whose consumer
/// this shard does not hold.
///
/// An owed record's value is the credit this shard's fold lands, so it
/// is carried only where its consumer routes. Anywhere else it licenses
/// nothing and spends the budget.
fn owed_elsewhere(ctx: &Committed<'_>, claim: &StateClaim) -> bool {
    claim.cells.iter().any(|(key, stated)| {
        stated.held().is_some_and(|bytes| {
            matches!(
                CrossingLeaf::read(&ProtocolHasher, *key, bytes),
                Some(CrossingLeaf::Record { cell, .. })
                    if cell.terms == Terms::Owed
                        && ctx.snapshot.shard_trie().shard_for_prefix(cell.consumer)
                            != ctx.local_shard
            )
        })
    })
}

/// Run `S::admit` over `items` in order, refusing on the first item it
/// refuses — the voter's walk over a section.
///
/// # Errors
///
/// The first refusal.
pub(crate) fn admit_all<'i, S: Section>(
    ctx: &Committed<'_>,
    fold: &mut S::Fold,
    items: impl IntoIterator<Item = &'i S::Item>,
) -> Result<(), String>
where
    S::Item: 'i,
{
    items
        .into_iter()
        .try_for_each(|item| S::admit(ctx, fold, item))
}

/// Keep the items `S::admit` admits, in order, folding each admitted
/// one — the proposer's filter over its candidates. Returns what was
/// kept and how many were refused.
pub(crate) fn admit_each<S: Section, T>(
    ctx: &Committed<'_>,
    fold: &mut S::Fold,
    items: Vec<T>,
    item: impl Fn(&T) -> &S::Item,
) -> (Vec<T>, usize) {
    let mut refused = 0usize;
    let kept = items
        .into_iter()
        .filter(|candidate| {
            let admitted = S::admit(ctx, fold, item(candidate)).is_ok();
            if !admitted {
                refused += 1;
            }
            admitted
        })
        .collect();
    (kept, refused)
}

/// The shared shape of a section's items behind an `Arc<Verifiable<_>>`.
pub(crate) fn unwrapped<T>(item: &Arc<Verifiable<T>>) -> &T {
    item
}

#[cfg(test)]
pub(crate) mod fixtures {
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::sync::Arc;

    use hyperscale_storage::MemberIndex;
    use hyperscale_types::{
        Anchor, BeaconWitnessLeafCount, BlockHash, BlockHeight, Epoch, Hash, NetworkDefinition,
        ShardAnchor, ShardId, StateRoot, TopologySchedule, TopologySnapshot, ValidatorSet,
        WeightedTimestamp, WindowLookup,
    };

    use super::{Committed, QcChainSets};
    use crate::commit_dedup::CommitDedupIndex;

    /// What a test block is admitted against: one window, with nothing
    /// behind the parent and nothing committed unless a test puts it
    /// there.
    pub struct Against {
        pub(crate) snapshot: TopologySnapshot,
        pub(crate) schedule: TopologySchedule,
        pub(crate) local_shard: ShardId,
        pub(crate) anchor: WeightedTimestamp,
        pub(crate) parent: Anchor,
        pub(crate) chain_origin: WeightedTimestamp,
        pub(crate) chain: QcChainSets,
        pub(crate) dedup: CommitDedupIndex,
        pub(crate) parent_settled_frontier: Option<BlockHeight>,
        pub(crate) members: MemberIndex,
        pub(crate) owed_determined: BTreeSet<BlockHeight>,
    }

    impl Against {
        /// Admission under `snapshot`, whose one window spans every
        /// anchor a test sets.
        pub fn window(snapshot: TopologySnapshot) -> Self {
            let schedule =
                TopologySchedule::new(u64::MAX / 2, Epoch::GENESIS, Arc::new(snapshot.clone()));
            Self::schedule(snapshot, schedule)
        }

        /// Admission under `schedule`, classified under `snapshot`.
        pub(crate) fn schedule(snapshot: TopologySnapshot, schedule: TopologySchedule) -> Self {
            Self {
                snapshot,
                schedule,
                local_shard: ShardId::ROOT,
                anchor: WeightedTimestamp::ZERO,
                parent: Anchor {
                    shard: ShardId::ROOT,
                    height: BlockHeight::GENESIS,
                    state_root: StateRoot::ZERO,
                    ts: WeightedTimestamp::ZERO,
                },
                chain_origin: WeightedTimestamp::ZERO,
                chain: QcChainSets::default(),
                dedup: CommitDedupIndex::new(),
                parent_settled_frontier: Some(BlockHeight::GENESIS),
                members: MemberIndex::empty(ShardId::ROOT),
                owed_determined: BTreeSet::new(),
            }
        }

        /// # Panics
        ///
        /// If the fixture's anchor lies outside every window its schedule
        /// holds, which no test means.
        pub(crate) fn ctx(&self) -> Committed<'_> {
            let WindowLookup::Window(window) = self.schedule.lookup(self.anchor) else {
                panic!("a fixture anchors inside its own schedule");
            };
            Committed {
                snapshot: &self.snapshot,
                window,
                windows: self.schedule.windows(),
                schedule: &self.schedule,
                local_shard: self.local_shard,
                anchor: self.anchor,
                parent: self.parent,
                chain_origin: self.chain_origin,
                chain: &self.chain,
                dedup: &self.dedup,
                parent_settled_frontier: self.parent_settled_frontier,
                members: &self.members,
                owed_determined: &self.owed_determined,
            }
        }
    }

    /// The cut every departure the fixtures schedule ends at: the end of
    /// the first window, which is the last to carry the departed shards.
    pub const DEPARTURE_CUT_MS: u64 = 1_000;

    /// A schedule whose first window carries every shard of `departed`
    /// and whose every later window carries `survivors` instead, with
    /// each departure's boundary record at [`DEPARTURE_CUT_MS`] and its
    /// handoff stamped complete at `handoff_complete` or still open.
    pub fn departures(
        departed: &[ShardId],
        survivors: &[ShardId],
        handoff_complete: Option<Epoch>,
    ) -> TopologySchedule {
        departures_cut_at(DEPARTURE_CUT_MS, departed, survivors, handoff_complete)
    }

    /// [`departures`], with every window `cut_ms` long, so the cut falls
    /// at `cut_ms`.
    pub fn departures_cut_at(
        cut_ms: u64,
        departed: &[ShardId],
        survivors: &[ShardId],
        handoff_complete: Option<Epoch>,
    ) -> TopologySchedule {
        let window = |shards: &[ShardId], boundaries: BTreeMap<ShardId, ShardAnchor>| {
            Arc::new(TopologySnapshot::from_explicit_committees(
                NetworkDefinition::simulator(),
                &ValidatorSet::new(Vec::new()),
                shards.iter().map(|&shard| (shard, Vec::new())).collect(),
                HashMap::new(),
                boundaries,
                HashMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeSet::new(),
            ))
        };
        let boundaries: BTreeMap<ShardId, ShardAnchor> = departed
            .iter()
            .map(|&shard| {
                (
                    shard,
                    ShardAnchor {
                        state_root: StateRoot::ZERO,
                        block_hash: BlockHash::from_raw(Hash::from_bytes(b"terminal")),
                        height: BlockHeight::new(9),
                        weighted_timestamp: WeightedTimestamp::from_millis(cut_ms),
                        witness_base: BeaconWitnessLeafCount::ZERO,
                        terminal_settled_txs: None,
                        handoff_complete,
                        terminal_epoch: Some(Epoch::new(0)),
                    },
                )
            })
            .collect();
        let after = window(survivors, boundaries);
        let mut sched =
            TopologySchedule::new(cut_ms, Epoch::new(0), window(departed, BTreeMap::new()));
        for epoch in 1..=20u64 {
            sched.insert(Epoch::new(epoch), Arc::clone(&after));
        }
        sched.set_head(after);
        sched
    }
}

#[cfg(test)]
mod state_claim_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use hyperscale_hbor::Bytes;
    use hyperscale_storage::{committed_tx_cell_key, member_row_leaf};
    use hyperscale_types::test_utils::{
        proven_claim, state_and_proof, state_and_proof_holding, test_key,
    };
    use hyperscale_types::{
        Address, AddressClass, Anchor, BlockHeight, Epoch, Hash, Inclusion, MerkleInclusionProof,
        NetworkDefinition, RETENTION_HORIZON, ShardId, StateClaim, Stated, SubstateKey,
        TopologySnapshot, TxHash, ValidatorSet, WeightedTimestamp, verdict_leaf,
    };
    use hyperscale_vm_effects::{CrossingId, Hash32, IntentHash, ProtocolHasher, Terms};
    use hyperscale_vm_types::{ResourceAddr, TxHash as VmTxHash};

    use super::fixtures::{Against, DEPARTURE_CUT_MS, departures};
    use super::{Section, StateClaimsFold, StateClaimsSection};

    const PRODUCER: ShardId = ShardId::leaf(1, 0);

    /// A window carrying the producer up to the cut, and the root alone
    /// past it: past the cut every owner routes to the root, and the
    /// producer's anchors there own nothing.
    fn against(block_anchor: WeightedTimestamp) -> Against {
        let mut schedule = departures(&[PRODUCER, ShardId::leaf(1, 1)], &[ShardId::ROOT], None);
        // The block is judged in the window its own anchor lies in, which
        // the schedule has committed however far past the cut it is.
        let head = Arc::clone(schedule.head());
        let block_epoch = schedule.epoch_for(block_anchor);
        if schedule.at(block_anchor).is_none() {
            schedule.insert(block_epoch, head);
        }
        let snapshot = (**schedule.head()).clone();
        let mut against = Against::schedule(snapshot, schedule);
        against.anchor = block_anchor;
        against
    }

    /// A key the producer's prefix owns.
    fn producer_key() -> SubstateKey {
        test_key(0x10)
    }

    /// A claim on `shard` at `ts` holding `key`'s value, as the fixture
    /// tree stores it: the key's own bytes.
    fn held(shard: ShardId, ts: WeightedTimestamp, key: SubstateKey) -> StateClaim {
        let (state_root, proof) = state_and_proof(shard, &[key], &[key]);
        StateClaim::new(
            Anchor {
                shard,
                height: BlockHeight::new(9),
                state_root,
                ts,
            },
            [(
                key,
                Stated::Held(Bytes::new(key.to_bytes().to_vec()).unwrap()),
            )],
            proof,
        )
    }

    fn admit(against: &Against, claim: &StateClaim) -> Result<(), String> {
        let mut fold = StateClaimsFold::default();
        StateClaimsSection::admit(&against.ctx(), &mut fold, claim)
    }

    /// A crossing whose record sits under the producer's prefix.
    fn crossing() -> CrossingId {
        CrossingId {
            producer: producer_key().owner,
            consumer: test_key(0x12).owner,
            intent: IntentHash(Hash32([0x77; 32])),
            local: 0,
            output: 0,
        }
    }

    /// A crossing read at the block's parent, absent, with the empty
    /// proof, as the proposer reads one whose ends share its shard.
    fn read_at_the_parent(against: &Against) -> StateClaim {
        let record = crossing().record_key(&ProtocolHasher);
        StateClaim::new(
            against.parent,
            [(record, Inclusion::Absent)],
            MerkleInclusionProof::new(Vec::new()),
        )
        .naming([(record, crossing())])
    }

    /// A crossing whose two ends route here is read at the block's own
    /// parent with the empty proof, and nowhere else: a parent-anchored
    /// claim carrying a proof, one reading a key this shard does not
    /// hold, another anchor of this shard's, and a crossing reading of a
    /// key routed here at a counterpart's anchor are each refused.
    #[test]
    fn a_local_crossing_is_read_only_at_the_parent() {
        // Past the cut every key routes to the root, this shard.
        let against = against(WeightedTimestamp::from_millis(DEPARTURE_CUT_MS + 9_000));
        assert_eq!(admit(&against, &read_at_the_parent(&against)), Ok(()));

        let mut proven = read_at_the_parent(&against);
        proven.proof = MerkleInclusionProof::new(vec![0]);
        assert!(
            admit(&against, &proven)
                .expect_err("a parent-anchored claim carries no proof")
                .contains("carries a proof"),
        );

        let mut off_parent = read_at_the_parent(&against);
        off_parent.anchor.height = BlockHeight::new(3);
        assert!(
            admit(&against, &off_parent)
                .expect_err("only the parent anchors a claim of this shard's")
                .contains("off its parent"),
        );

        let record = crossing().record_key(&ProtocolHasher);
        let remote = proven_claim(PRODUCER, 9, &[], &[record]);
        assert_eq!(
            admit(&against, &remote),
            Ok(()),
            "a bare reading of the key at a counterpart's anchor is admitted",
        );
        assert!(
            admit(&against, &remote.naming([(record, crossing())]))
                .expect_err("a crossing of this shard's is read at the parent alone")
                .contains("away from the parent"),
        );

        // A shard holding no prefix reads nothing of its own at the
        // parent.
        let elsewhere = Against::window(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            2,
            ValidatorSet::new(Vec::new()),
        ));
        assert!(
            admit(&elsewhere, &read_at_the_parent(&elsewhere))
                .expect_err("the key routes to a child, not to the root")
                .contains("does not hold"),
        );
    }

    /// A claim carrying a value is admitted at exactly one retention
    /// horizon before the block and refused a millisecond past it: the
    /// bound is the proof's life, and a value is no boundary reading.
    #[test]
    fn a_claim_older_than_the_horizon_is_refused() {
        let read_at = WeightedTimestamp::from_millis(500);
        let claim = held(PRODUCER, read_at, producer_key());
        let at_the_horizon = read_at.plus(RETENTION_HORIZON);
        assert_eq!(admit(&against(at_the_horizon), &claim), Ok(()));
        let past = at_the_horizon.plus(Duration::from_millis(1));
        assert!(
            admit(&against(past), &claim)
                .is_err_and(|err| err.contains("more than a retention horizon")),
        );
    }

    /// Admission on the second of two shards, at `block_anchor`, with
    /// the first as the counterpart every claim reads.
    fn beside_a_counterpart(block_anchor: WeightedTimestamp) -> (Against, ShardId) {
        let (counterpart, local) = ShardId::ROOT.children();
        let mut against = Against::window(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            2,
            ValidatorSet::new(Vec::new()),
        ));
        against.local_shard = local;
        against.anchor = block_anchor;
        (against, counterpart)
    }

    /// Past the retention horizon a claim on another shard is admitted
    /// only as a boundary claim: one that names no member, holds no
    /// value and reads nothing present under a crossing it names. A
    /// record read absent under its crossing's name, with its producing
    /// member's row and committed marker unnamed beside it, is the
    /// reading an answer is deleted on, and is admitted at any age. The
    /// same readings a millisecond younger are fresh claims, and every
    /// one of them is admitted.
    #[test]
    fn a_boundary_claim_holds_no_value_names_no_member_and_reads_no_crossing_present() {
        let (_, counterpart) = beside_a_counterpart(WeightedTimestamp::ZERO);
        let component = |byte: u8| Address::new([byte; 31], AddressClass::Component);
        let id = CrossingId {
            producer: component(0x10),
            consumer: component(0x90),
            intent: IntentHash(Hash32([0x5D; 32])),
            local: 0,
            output: 0,
        };
        let record = id.record_key(&ProtocolHasher);
        let tx = TxHash::from(Hash::from_bytes(b"a producing member"));
        let row = member_row_leaf(counterpart, tx);
        let marker = committed_tx_cell_key(counterpart, tx, WeightedTimestamp::from_millis(60_000));
        let leaf = verdict_leaf(counterpart, tx);

        let deleting =
            proven_claim(counterpart, 9, &[marker], &[record, row, marker]).naming([(record, id)]);
        assert_eq!(deleting.reading(record), Some(Inclusion::Absent));
        assert_eq!(deleting.reading(row), Some(Inclusion::Absent));
        assert!(deleting.reads_as_a_boundary());
        let bare = proven_claim(counterpart, 9, &[marker], &[row, marker]);
        let named_present =
            proven_claim(counterpart, 9, &[record], &[record]).naming([(record, id)]);
        let naming_a_member = proven_claim(counterpart, 9, &[leaf], &[leaf]).hearing([tx]);
        assert!(naming_a_member.is_well_formed());
        let value = id
            .cell(
                VmTxHash(Hash32([0xC3; 32])),
                ResourceAddr::new([0xE1; 31]),
                40,
                60_000,
                Terms::Escrowed {
                    credit: test_key(0x21),
                },
            )
            .to_bytes();
        let (state_root, proof) =
            state_and_proof_holding(counterpart, &[(record, value.clone())], &[record]);
        let holding = StateClaim::new(
            Anchor {
                state_root,
                ..deleting.anchor
            },
            [(record, Stated::Held(Bytes::new(value).unwrap()))],
            proof,
        )
        .naming([(record, id)]);

        let at_the_horizon = deleting.anchor.ts.plus(RETENTION_HORIZON);
        let (fresh, _) = beside_a_counterpart(at_the_horizon);
        for claim in [&deleting, &bare, &named_present, &naming_a_member, &holding] {
            assert!(!claim.at_boundary(at_the_horizon));
            assert_eq!(admit(&fresh, claim), Ok(()), "a fresh claim is admitted");
        }

        let past = at_the_horizon.plus(Duration::from_millis(1));
        let (boundary, _) = beside_a_counterpart(past);
        assert!(deleting.at_boundary(past));
        assert_eq!(admit(&boundary, &deleting), Ok(()));
        assert_eq!(
            admit(&boundary, &bare),
            Ok(()),
            "cells that name nothing are opaque, and license nothing alone",
        );
        for (claim, why) in [
            (&named_present, "a crossing read present"),
            (&naming_a_member, "a member named"),
            (&holding, "a value held"),
        ] {
            assert!(
                admit(&boundary, claim)
                    .is_err_and(|err| err.contains("no boundary reading of another shard")),
                "{why} is no boundary reading",
            );
        }
        let far = past.plus(RETENTION_HORIZON).plus(RETENTION_HORIZON);
        assert_eq!(
            admit(&beside_a_counterpart(far).0, &deleting),
            Ok(()),
            "a boundary claim has no age bound",
        );
    }

    /// A claim anchored at the block's own parent is no boundary claim,
    /// however long the chain stalled: one read at a parent more than a
    /// retention horizon before the block is refused, a record absence
    /// naming its crossing included, so no block's own parent reading
    /// is one its voters hold to a boundary.
    #[test]
    fn a_parent_claim_past_the_horizon_is_no_boundary_claim() {
        let at_the_horizon = WeightedTimestamp::ZERO.plus(RETENTION_HORIZON);
        let before = against(at_the_horizon);
        let claim = read_at_the_parent(&before);
        assert!(claim.reads_as_a_boundary());
        assert_eq!(admit(&before, &claim), Ok(()));

        let stalled = against(at_the_horizon.plus(Duration::from_millis(1)));
        let claim = read_at_the_parent(&stalled);
        assert!(claim.at_boundary(stalled.anchor));
        assert!(
            admit(&stalled, &claim)
                .is_err_and(|err| err.contains("no boundary reading of another shard")),
        );
    }

    /// An owed record's value is carried only where its consumer routes,
    /// since that shard's fold is the one it credits; an escrowed
    /// record's is carried wherever it is read.
    #[test]
    fn an_owed_record_is_carried_only_where_its_consumer_routes() {
        let (producer_shard, local) = ShardId::ROOT.children();
        let mut against = Against::window(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            2,
            ValidatorSet::new(Vec::new()),
        ));
        against.local_shard = local;
        against.anchor = WeightedTimestamp::from_millis(900);

        let component = |byte: u8| Address::new([byte; 31], AddressClass::Component);
        let carrying = |consumer: u8, terms: Terms| {
            let id = CrossingId {
                producer: component(0x10),
                consumer: component(consumer),
                intent: IntentHash(Hash32([0x5C; 32])),
                local: 0,
                output: 0,
            };
            let record = id.record_key(&ProtocolHasher);
            let value = id
                .cell(
                    VmTxHash(Hash32([0xC3; 32])),
                    ResourceAddr::new([0xE1; 31]),
                    40,
                    60_000,
                    terms,
                )
                .to_bytes();
            let (state_root, proof) =
                state_and_proof_holding(producer_shard, &[(record, value.clone())], &[record]);
            StateClaim::new(
                Anchor {
                    shard: producer_shard,
                    height: BlockHeight::new(9),
                    state_root,
                    ts: WeightedTimestamp::from_millis(500),
                },
                [(record, Stated::Held(Bytes::new(value).unwrap()))],
                proof,
            )
            .naming([(record, id)])
        };
        let (here, elsewhere) = (0x90, 0x20);

        assert_eq!(
            admit(&against, &carrying(here, Terms::Owed)),
            Ok(()),
            "an owed record whose consumer routes here is the credit this fold lands",
        );
        assert!(
            admit(&against, &carrying(elsewhere, Terms::Owed))
                .expect_err("an owed record credits only where its consumer is")
                .contains("owed record whose consumer this shard does not hold"),
        );
        assert_eq!(
            admit(
                &against,
                &carrying(
                    elsewhere,
                    Terms::Escrowed {
                        credit: test_key(0x21),
                    }
                )
            ),
            Ok(()),
            "an escrowed record is read wherever its consumer runs",
        );
    }

    #[test]
    fn a_held_reading_is_owned_by_its_anchors_shard_at_the_anchors_clock() {
        let block_anchor = WeightedTimestamp::from_millis(DEPARTURE_CUT_MS + 500);
        let key = producer_key();
        assert_eq!(
            admit(
                &against(block_anchor),
                &held(PRODUCER, WeightedTimestamp::from_millis(500), key)
            ),
            Ok(()),
            "before the cut the producer owns the cell",
        );
        assert!(
            admit(
                &against(block_anchor),
                &held(
                    PRODUCER,
                    WeightedTimestamp::from_millis(DEPARTURE_CUT_MS + 100),
                    key
                )
            )
            .is_err_and(|err| err.contains("did not own")),
            "a coast anchor of the departed producer owns nothing",
        );
        // Judged from a shard the root is a counterpart of: a shard
        // carries no claim anchored on itself but at its parent.
        let mut from_elsewhere = against(block_anchor);
        from_elsewhere.local_shard = ShardId::leaf(1, 1);
        assert_eq!(
            admit(
                &from_elsewhere,
                &held(
                    ShardId::ROOT,
                    WeightedTimestamp::from_millis(DEPARTURE_CUT_MS + 100),
                    key
                )
            ),
            Ok(()),
            "the successor's reading past the cut is admitted",
        );
        // A claim anchored in a window this replica has evicted carries a
        // value no window here can place.
        let mut evicted = against(block_anchor);
        evicted.schedule.evict_below(Epoch::new(1));
        evicted.local_shard = ShardId::leaf(1, 1);
        assert!(
            admit(
                &evicted,
                &held(ShardId::ROOT, WeightedTimestamp::from_millis(500), key)
            )
            .is_err_and(|err| err.contains("no schedule window covers")),
        );
    }
}
