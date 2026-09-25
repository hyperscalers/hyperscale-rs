//! What a block's sections are admitted against, and the one rule per
//! section that admits an item.
//!
//! A proposer selects what its block carries and every voter checks
//! what a block carries, and the two must agree: a proposer offering
//! what its own voters refuse spends a round and offers it again. So
//! each section has one predicate, [`Section::admit`], read against one
//! [`Admission`] context — the chain behind the block's parent and the
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

use hyperscale_engine::legs::Classified;
use hyperscale_types::{
    AbandonmentRecord, Anchor, BlockHash, BlockHeight, DeclaredWork, Finalization,
    FinalizationHash, MAX_FINALIZED_TX_PER_BLOCK, MAX_HELD_VALUE_BYTES,
    MAX_PROPOSAL_EVIDENCE_BYTES, MAX_STATE_CLAIMS_BYTES, MAX_TXS_PER_BLOCK,
    MAX_UNSETTLED_PER_BLOCK, ProvisionHash, Provisions, RETENTION_HORIZON, ShardId, StateClaim,
    SubstateKey, TopologySchedule, TopologySnapshot, Transaction, TxHash, Verifiable,
    WeightedTimestamp, budget_admits_block, caps_admit_transaction, evidence_admits_block,
    state_claims_admit_block, sweep_admits_block,
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

/// What a block is admitted against.
#[derive(Clone, Copy)]
pub(crate) struct Admission<'a> {
    /// The committee the block is classified under.
    pub(crate) snapshot: &'a TopologySnapshot,
    /// The schedule, for the departures a record may name.
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
    /// The settlement frontier the parent left, which a determined half
    /// must settle above. `None` where the parent is pruned, which
    /// leaves the order unjudged here: such a block is verified but not
    /// voted on.
    pub(crate) parent_settled_frontier: Option<BlockHeight>,
    /// Ticks whose determined half this chain still owes, by height —
    /// the fold's answer, which a proposer and every voter reach
    /// independently over the same committed blocks. A half may not
    /// settle past one of these; a validator that never composed the
    /// tick holds it in no set and enforces nothing, so the rule refuses
    /// only what a composing quorum would refuse anyway.
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
    fn admit(ctx: &Admission<'_>, fold: &mut Self::Fold, item: &Self::Item) -> Result<(), String>;
}

/// The block's provisions.
pub(crate) struct ProvisionsSection;

/// What the provisions admitted so far amount to.
#[derive(Debug, Default)]
pub(crate) struct ProvisionsFold {
    /// Transactions the admitted batches provision, against the block's
    /// cap on them.
    pub(crate) tx_count: usize,
    /// Which transactions each admitted batch provisions, by payer
    /// shard — what the transactions section reads to engage a
    /// cross-shard transaction.
    pub(crate) provisioned: HashSet<(ShardId, TxHash)>,
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
    fn admit(ctx: &Admission<'_>, fold: &mut Self::Fold, batch: &Provisions) -> Result<(), String> {
        let provision_hash = batch.hash();
        if ctx.chain.provisions.contains(&provision_hash) {
            return Err(format!(
                "provisions batch {provision_hash:?} already in QC chain ancestor"
            ));
        }
        if ctx.dedup.contains_provision(&provision_hash) {
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
        if tx_count > MAX_TXS_PER_BLOCK {
            return Err(format!(
                "provisions batch {provision_hash:?} carries the block past {MAX_TXS_PER_BLOCK} \
                 provisioned transactions"
            ));
        }
        fold.tx_count = tx_count;
        fold.provisioned.extend(
            batch
                .transactions()
                .iter()
                .map(|entry| (source_shard, entry.tx_hash)),
        );
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
}

impl<'a> TransactionsFold<'a> {
    /// A fold beside the admitted `provisions`.
    #[must_use]
    pub(crate) const fn beside(provisions: &'a ProvisionsFold) -> Self {
        Self {
            sweepable: 0,
            budget: DeclaredWork::ZERO,
            provisions,
        }
    }
}

impl<'p> Section for TransactionsSection<'p> {
    type Item = Transaction;
    type Fold = TransactionsFold<'p>;

    /// A transaction the chain does not already carry and this shard
    /// commits, engaged by its payer bundle where its payer is
    /// elsewhere, under its own ceilings in every dimension, and fitting
    /// the block's sweepable-cell cap and its per-dimension caps over
    /// the share this shard bears.
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
    fn admit(ctx: &Admission<'_>, fold: &mut Self::Fold, tx: &Transaction) -> Result<(), String> {
        let tx_hash = tx.hash();
        if ctx.chain.txs.contains(&tx_hash) {
            return Err(format!(
                "transaction {tx_hash} already in QC chain ancestor"
            ));
        }
        if ctx.dedup.contains_tx(&tx_hash) {
            return Err(format!(
                "transaction {tx_hash} already committed within its validity window"
            ));
        }
        let trie = ctx.snapshot.shard_trie();
        let classified = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), trie);
        if !classified.commits_at(ctx.local_shard) {
            return Err(format!(
                "transaction {tx_hash} only delivers here, which its commit fold credits"
            ));
        }
        let payer_shard = trie.shard_for_prefix(tx.fee_payer());
        if !ctx.snapshot.is_single_shard_transaction(tx)
            && payer_shard != ctx.local_shard
            && !fold
                .provisions
                .provisioned
                .contains(&(payer_shard, tx_hash))
            && !ctx.dedup.contains_provision_tx(payer_shard, tx_hash)
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
    /// block's cap.
    pub(crate) tx_count: usize,
}

impl FinalizationsFold {
    /// A fold starting at the parent's settlement frontier.
    #[must_use]
    pub(crate) fn from(ctx: &Admission<'_>) -> Self {
        Self {
            resolved_here: HashSet::new(),
            carried_here: HashSet::new(),
            frontier: ctx.parent_settled_frontier,
            tx_count: 0,
        }
    }
}

impl Section for FinalizationsSection {
    type Item = Finalization;
    type Fold = FinalizationsFold;

    /// A certificate anchored on this chain, that the chain does not
    /// already carry, whose names the chain has not already resolved,
    /// whose determined half settles above the frontier, within the
    /// block's cap on finalized transactions.
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
    /// The order rule: a receipt states an absolute computed from its
    /// tick's baseline and settlement is last writer per cell, so an
    /// earlier tick's determined half landing after a later one's
    /// reverts a write later ticks have already read — every replica
    /// would then agree on the wrong state, which is why the order is
    /// refused up front rather than detected. Legs halves are not
    /// constrained: a leg's declared cells are claimed against every
    /// later tick from the moment it executes, so it has nothing to
    /// invert against.
    fn admit(ctx: &Admission<'_>, fold: &mut Self::Fold, fw: &Finalization) -> Result<(), String> {
        if fw.local_ec().vote_anchor_ts() < ctx.chain_origin {
            return Err(format!(
                "certificate for tick {:?} predates this chain's origin",
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
        if ctx.dedup.contains_finalization(&receipt_hash) {
            return Err(format!(
                "finalization {receipt_hash:?} was already committed within its retention window"
            ));
        }
        for outcome in fw.local_ec().tx_outcomes() {
            let tx_hash = outcome.tx_hash();
            if fold.resolved_here.contains(&tx_hash) {
                return Err(format!(
                    "transaction {tx_hash} resolved twice within the same block"
                ));
            }
            if outcome.decides() {
                already_resolved(ctx, tx_hash)?;
            }
        }
        let mut frontier = fold.frontier;
        if fw.is_determined()
            && let Some(parent_frontier) = frontier
        {
            let tick = fw.tick_id().block_height();
            if tick <= parent_frontier {
                return Err(format!(
                    "determined half of tick {} settles at or below the frontier {} it would \
                     settle under",
                    tick.inner(),
                    parent_frontier.inner()
                ));
            }
            // Nothing between the running frontier and this half may
            // still owe one of its own. Admitting it would carry the
            // frontier past a tick whose half is refused for good the
            // moment its certificate lands, leaving its members
            // committed and never finalized.
            if let Some(skipped) = ctx
                .owed_determined
                .range((Bound::Excluded(parent_frontier), Bound::Excluded(tick)))
                .next()
            {
                return Err(format!(
                    "determined half of tick {} settles past tick {}, whose own determined half \
                     the chain still owes",
                    tick.inner(),
                    skipped.inner()
                ));
            }
            frontier = Some(tick);
        }
        let tx_count = fold.tx_count.saturating_add(fw.tx_count());
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
        Ok(())
    }
}

/// Refuse `tx_hash` if the chain has already reached a verdict on it —
/// by an ancestor above committed height, or by a committed block within
/// the retention window.
fn already_resolved(ctx: &Admission<'_>, tx_hash: TxHash) -> Result<(), String> {
    if ctx.chain.resolved.contains(&tx_hash) {
        return Err(format!(
            "transaction {tx_hash} already resolved by a QC chain ancestor"
        ));
    }
    if ctx.dedup.contains_resolved_tx(&tx_hash) {
        return Err(format!(
            "transaction {tx_hash} already resolved within its retention window"
        ));
    }
    Ok(())
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
        ctx: &Admission<'_>,
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
    /// figures the record restates and the departures the schedule
    /// attests at the block's anchor, so every replica answers alike —
    /// including one holding no entry for the name, which rebuilds the
    /// entry from the record precisely because it cannot check the name
    /// against an account of its own.
    fn parties_stand(ctx: &Admission<'_>, record: &AbandonmentRecord) -> Result<(), String> {
        let departures: Vec<(ShardId, WeightedTimestamp)> =
            ctx.schedule.departures_at(ctx.anchor).collect();
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

    /// Whether a record's departure is one the schedule attests at the
    /// block's anchor: the cut it names is the departed shard's, and its
    /// boundary record is still readable. A record anchored after the
    /// beacon closed and swept the departure claims what nobody can
    /// check.
    fn evidence_stands(ctx: &Admission<'_>, verdict: &AbandonmentRecord) -> Result<(), String> {
        let terminal_wt = verdict.terminal_wt();
        let shard = verdict.shard();
        let scheduled = ctx.schedule.terminal_cut_for_shard(shard, ctx.anchor);
        if scheduled != Some(terminal_wt) {
            return Err(format!(
                "abandonment record names a departure of {shard:?} at {terminal_wt:?} the \
                 schedule does not attest ({scheduled:?})"
            ));
        }
        if !ctx.schedule.terminal_evidence_readable(shard, ctx.anchor) {
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
    /// a departure the schedule attests, naming only what the departed
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
        ctx: &Admission<'_>,
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
    /// The bytes admitted so far, against the section's budget.
    pub(crate) weight: usize,
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
}

impl Section for StateClaimsSection {
    type Item = StateClaim;
    type Fold = StateClaimsFold;

    /// A well-formed claim whose proof bears out every reading, at an
    /// anchor no recovery fences and no older than one retention
    /// horizon before the block's own clock, in its place in the
    /// section's order, within the section's budget — and, where it
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
    /// included, so the decode cap on the count never binds first.
    ///
    /// The age bound is the one any voter can still prove: a proof
    /// stands for a horizon, so a claim older than that is one no
    /// voter could check. Stated at the block's own clock, it is the
    /// exact complement of the read frontier's prune, which drops an
    /// entry once every presence it could refuse is one this bound
    /// refuses. Which presences the frontier itself refuses is judged
    /// where the parent state is read. The owner is read off the global
    /// schedule at the anchor's own clock, never the head, so a split
    /// parent's coast anchor owns nothing; the fold reads the committed
    /// fact and never re-resolves.
    fn admit(ctx: &Admission<'_>, fold: &mut Self::Fold, claim: &StateClaim) -> Result<(), String> {
        let at = || {
            format!(
                "state claim on {:?} at height {}",
                claim.anchor.shard,
                claim.anchor.height.inner()
            )
        };
        if !claim.is_well_formed() {
            return Err(format!("{} is empty, over its cap, or out of order", at()));
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
        if ctx.anchor.elapsed_since(claim.anchor.ts) > RETENTION_HORIZON {
            return Err(format!(
                "{} is anchored more than a retention horizon before the block",
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
        let weight = fold.weight.saturating_add(claim.wire_weight());
        if !state_claims_admit_block(weight) {
            return Err(format!(
                "state claims weigh {weight} bytes, over the section's budget of \
                 {MAX_STATE_CLAIMS_BYTES}"
            ));
        }
        let last = claim
            .cells
            .last()
            .map(|(key, _)| *key)
            .expect("a well-formed claim names a cell");
        fold.previous = Some((claim.anchor, last));
        fold.weight = weight;
        Ok(())
    }
}

/// Whether `claim` carries the value of an owed record whose consumer
/// this shard does not hold.
///
/// An owed record's value is the credit this shard's fold lands, so it
/// is carried only where its consumer routes. Anywhere else it licenses
/// nothing and spends the budget.
fn owed_elsewhere(ctx: &Admission<'_>, claim: &StateClaim) -> bool {
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
    ctx: &Admission<'_>,
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
    ctx: &Admission<'_>,
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

    use hyperscale_types::{
        Anchor, BeaconWitnessLeafCount, BlockHash, BlockHeight, Epoch, Hash, NetworkDefinition,
        ShardAnchor, ShardId, StateRoot, TopologySchedule, TopologySnapshot, ValidatorSet,
        WeightedTimestamp,
    };

    use super::{Admission, QcChainSets};
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
        pub(crate) owed_determined: BTreeSet<BlockHeight>,
    }

    impl Against {
        /// Admission under `snapshot`, which is every window of the
        /// schedule too.
        pub fn window(snapshot: TopologySnapshot) -> Self {
            let schedule = TopologySchedule::new(1_000, Epoch::GENESIS, Arc::new(snapshot.clone()));
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
                owed_determined: BTreeSet::new(),
            }
        }

        pub(crate) fn ctx(&self) -> Admission<'_> {
            Admission {
                snapshot: &self.snapshot,
                schedule: &self.schedule,
                local_shard: self.local_shard,
                anchor: self.anchor,
                parent: self.parent,
                chain_origin: self.chain_origin,
                chain: &self.chain,
                dedup: &self.dedup,
                parent_settled_frontier: self.parent_settled_frontier,
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
        let window = |shards: &[ShardId], boundaries: HashMap<ShardId, ShardAnchor>| {
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
        let boundaries: HashMap<ShardId, ShardAnchor> = departed
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
                        terminal_roots: None,
                        handoff_complete,
                    },
                )
            })
            .collect();
        let after = window(survivors, boundaries);
        let mut sched =
            TopologySchedule::new(cut_ms, Epoch::new(0), window(departed, HashMap::new()));
        for epoch in 1..=20u64 {
            sched.insert(Epoch::new(epoch), Arc::clone(&after));
        }
        sched.set_head(after);
        sched
    }
}

#[cfg(test)]
mod state_claim_tests {
    use std::time::Duration;

    use hyperscale_hbor::Bytes;
    use hyperscale_types::test_utils::{proven_claim, state_and_proof, test_key};
    use hyperscale_types::{
        Anchor, BlockHeight, Inclusion, MerkleInclusionProof, NetworkDefinition, RETENTION_HORIZON,
        ShardId, StateClaim, Stated, SubstateKey, TopologySnapshot, ValidatorSet,
        WeightedTimestamp,
    };
    use hyperscale_vm_effects::{CrossingId, Hash32, IntentHash, ProtocolHasher};

    use super::fixtures::{Against, DEPARTURE_CUT_MS, departures};
    use super::{Section, StateClaimsFold, StateClaimsSection};

    const PRODUCER: ShardId = ShardId::leaf(1, 0);

    /// A window carrying the producer up to the cut, and the root alone
    /// past it: past the cut every owner routes to the root, and the
    /// producer's anchors there own nothing.
    fn against(block_anchor: WeightedTimestamp) -> Against {
        let schedule = departures(&[PRODUCER, ShardId::leaf(1, 1)], &[ShardId::ROOT], None);
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

    /// A claim is admitted at exactly one retention horizon before the
    /// block and refused a millisecond past it, whether or not it
    /// carries a value: the bound is the proof's life, not the
    /// reading's.
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
        let bare = proven_claim(PRODUCER, 9, &[producer_key()], &[producer_key()]);
        let bare = StateClaim::new(
            Anchor {
                ts: read_at,
                ..bare.anchor
            },
            bare.cells.iter().cloned(),
            bare.proof.clone(),
        );
        assert_eq!(admit(&against(at_the_horizon), &bare), Ok(()));
        assert!(
            admit(&against(past), &bare)
                .is_err_and(|err| err.contains("more than a retention horizon")),
            "the bound binds a bare reading too",
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
        let unscheduled = WeightedTimestamp::from_millis(1_000_000_000);
        let mut past_the_schedule = against(unscheduled);
        past_the_schedule.local_shard = ShardId::leaf(1, 1);
        assert!(
            admit(&past_the_schedule, &held(ShardId::ROOT, unscheduled, key))
                .is_err_and(|err| err.contains("no schedule window covers")),
        );
    }
}
