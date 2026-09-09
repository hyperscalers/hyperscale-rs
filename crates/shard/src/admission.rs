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

use hyperscale_types::{
    AbandonmentRecord, BlockHash, BlockHeight, CounterpartEvidence, Finalization, FinalizationHash,
    MAX_FINALIZED_TX_PER_BLOCK, MAX_PROPOSAL_EVIDENCE_BYTES, MAX_STATE_CLAIMS_PER_BLOCK,
    MAX_TXS_PER_BLOCK, MAX_UNSETTLED_PER_BLOCK, ProvisionHash, Provisions, ShardId, StateClaim,
    TopologySchedule, TopologySnapshot, Transaction, TxHash, Verifiable, WeightedTimestamp,
    evidence_admits_block, sweep_admits_block,
};

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
pub struct QcChainSets {
    /// Transactions an ancestor carries.
    pub txs: HashSet<TxHash>,
    /// Provision batches an ancestor carries.
    pub provisions: HashSet<ProvisionHash>,
    /// Transactions an ancestor's finalizations decided.
    pub resolved: HashSet<TxHash>,
    /// Finalizations an ancestor carries.
    pub finalizations: HashSet<FinalizationHash>,
}

impl QcChainSets {
    /// What the chain above `parent_block_hash` carries, walked once.
    #[must_use]
    pub fn behind(chain: &ChainView<'_>, parent_block_hash: BlockHash) -> Self {
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
pub struct Admission<'a> {
    /// The committee the block is classified under.
    pub snapshot: &'a TopologySnapshot,
    /// The schedule, for the departures a record may name.
    pub schedule: &'a TopologySchedule,
    /// The shard the block is on.
    pub local_shard: ShardId,
    /// The block's own anchor: its parent QC's weighted timestamp.
    pub anchor: WeightedTimestamp,
    /// Where this chain began; content anchored before it belongs to a
    /// predecessor.
    pub chain_origin: WeightedTimestamp,
    /// What the QC chain above the parent carries.
    pub chain: &'a QcChainSets,
    /// What committed blocks within the retention window carry.
    pub dedup: &'a CommitDedupIndex,
    /// The settlement frontier the parent left, which a determined half
    /// must settle above. `None` where the parent is pruned, which
    /// leaves the order unjudged here: such a block is verified but not
    /// voted on.
    pub parent_settled_frontier: Option<BlockHeight>,
    /// Ticks whose determined half this chain still owes, by height —
    /// the fold's answer, which a proposer and every voter reach
    /// independently over the same committed blocks. A half may not
    /// settle past one of these; a validator that never composed the
    /// tick holds it in no set and enforces nothing, so the rule refuses
    /// only what a composing quorum would refuse anyway.
    pub owed_determined: &'a BTreeSet<BlockHeight>,
}

/// One section of a block, and the rule that admits an item to it.
pub trait Section {
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
pub struct ProvisionsSection;

/// What the provisions admitted so far amount to.
#[derive(Debug, Default)]
pub struct ProvisionsFold {
    /// Transactions the admitted batches provision, against the block's
    /// cap on them.
    pub tx_count: usize,
    /// Which transactions each admitted batch provisions, by payer
    /// shard — what the transactions section reads to engage a
    /// cross-shard transaction.
    pub provisioned: HashSet<(ShardId, TxHash)>,
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
pub struct TransactionsSection<'p>(PhantomData<&'p ProvisionsFold>);

/// What the transactions admitted so far amount to.
#[derive(Debug)]
pub struct TransactionsFold<'a> {
    /// The sweepable cells the admitted transactions create on this
    /// shard, against the per-block creation cap.
    pub sweepable: usize,
    /// The provisions admitted beside them, which engage a cross-shard
    /// transaction's payer.
    pub provisions: &'a ProvisionsFold,
}

impl<'a> TransactionsFold<'a> {
    /// A fold beside the admitted `provisions`.
    #[must_use]
    pub const fn beside(provisions: &'a ProvisionsFold) -> Self {
        Self {
            sweepable: 0,
            provisions,
        }
    }
}

impl<'p> Section for TransactionsSection<'p> {
    type Item = Transaction;
    type Fold = TransactionsFold<'p>;

    /// A transaction the chain does not already carry, naming packages
    /// this window can run, engaged by its payer bundle where its payer
    /// is elsewhere, and fitting the block's sweepable-cell cap.
    ///
    /// The package rule is stated as the permission rather than the
    /// refusal: every package a transaction names must be registered
    /// past its maturity window or born with the chain, so by the time
    /// a transaction can run, the code it runs is code the whole
    /// committee holds. Engagement demands the transaction commit proof
    /// — the payer bundle — ride in the same block or a committed one,
    /// which closes the Byzantine-proposer path to engaging counterpart
    /// locks before the payer shard commits. The sweep cap bounds how
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
        if let Some(package) = ctx.snapshot.unusable_package_of(tx) {
            return Err(format!(
                "transaction {tx_hash} names package {package}, which this window cannot run"
            ));
        }
        let trie = ctx.snapshot.shard_trie();
        if !ctx.snapshot.is_single_shard_transaction(tx) {
            let payer_shard = trie.shard_for_prefix(tx.body().fee_payer);
            if payer_shard != ctx.local_shard
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
        fold.sweepable = sweepable;
        Ok(())
    }
}

/// The block's finalizations.
pub struct FinalizationsSection;

/// What the finalizations admitted so far amount to.
#[derive(Debug)]
pub struct FinalizationsFold {
    /// Every name an admitted finalization carries, deciding or not.
    pub resolved_here: HashSet<TxHash>,
    /// Every admitted certificate's identity.
    pub carried_here: HashSet<FinalizationHash>,
    /// Where the determined halves admitted so far end, starting at the
    /// parent's frontier. `None` where the parent is pruned and the
    /// order is not judged.
    pub frontier: Option<BlockHeight>,
    /// Transactions the admitted finalizations carry, against the
    /// block's cap.
    pub tx_count: usize,
}

impl FinalizationsFold {
    /// A fold starting at the parent's settlement frontier.
    #[must_use]
    pub fn from(ctx: &Admission<'_>) -> Self {
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
pub struct RecordsSection<'f>(PhantomData<&'f FinalizationsFold>);

/// What the records admitted so far amount to, beside the finalizations
/// admitted before them.
#[derive(Debug)]
pub struct RecordsFold<'a> {
    /// The finalizations the block carries, whose names no record may
    /// repeat.
    pub finalizations: &'a FinalizationsFold,
    /// The last admitted record's position, which the next must follow.
    pub previous: Option<(ShardId, CounterpartEvidence)>,
    /// Names the admitted records carry, against the drain's own bound.
    pub named: usize,
    /// Bytes the admitted records weigh, against the section's budget.
    pub weight: usize,
}

impl<'a> RecordsFold<'a> {
    /// A fold after the block's `finalizations`.
    #[must_use]
    pub const fn after(finalizations: &'a FinalizationsFold) -> Self {
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
    pub fn name_stands(
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

    /// Whether a departure record's evidence is one the schedule
    /// attests at the block's anchor: the cut it names is the departed
    /// shard's, and its boundary record is still readable. A record
    /// anchored after the beacon closed and swept the departure claims
    /// what nobody can check. A refusal names a live shard and is held
    /// to no window.
    fn evidence_stands(ctx: &Admission<'_>, verdict: &AbandonmentRecord) -> Result<(), String> {
        let CounterpartEvidence::Departed { terminal_wt } = verdict.evidence() else {
            return Ok(());
        };
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
    /// evidence the schedule attests, naming only what stands, within
    /// the budget the records share.
    ///
    /// The order is ascending by shard and then by arm, which gives
    /// uniqueness and one encoding per claim set together — two records
    /// for one shard under one arm would leave which answer counts to
    /// the reader, and a reordering would be a second form of the same
    /// block. One shard may carry several arms: what it refused and
    /// what it never took are different transactions. Both budgets
    /// are sums across every record, because the per-record decode cap
    /// alone would let a block spend either once per record.
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
        let position = (verdict.shard(), verdict.evidence());
        if fold.previous.is_some_and(|previous| previous >= position) {
            return Err(format!(
                "abandonment record for {:?} repeats or precedes the one before it",
                verdict.shard()
            ));
        }
        Self::evidence_stands(ctx, verdict)?;
        for tx_hash in verdict.tx_hashes() {
            Self::name_stands(ctx, fold, tx_hash)?;
        }
        let named = fold.named.saturating_add(verdict.unsettled().len());
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
pub struct StateClaimsSection;

/// What the claims admitted so far amount to.
#[derive(Debug, Default)]
pub struct StateClaimsFold {
    /// The last admitted claim, which the next must follow.
    pub previous: Option<StateClaim>,
    /// How many have been admitted, against the block's cap.
    pub count: usize,
}

impl Section for StateClaimsSection {
    type Item = StateClaim;
    type Fold = StateClaimsFold;

    /// A well-formed claim, in its place in the section's ascending
    /// order without repeats, within the block's cap.
    ///
    /// The canonical order — within each claim and across them — means
    /// one set of answers has one encoding; a claim naming no cell
    /// answers nothing, so the cap is spent on answers a record can be
    /// offered from. Whether the anchor and each reading are ones this
    /// validator took for itself is the vote fence's question, not this
    /// one: a claim carries nothing checkable in isolation.
    fn admit(
        _ctx: &Admission<'_>,
        fold: &mut Self::Fold,
        claim: &StateClaim,
    ) -> Result<(), String> {
        if !claim.is_well_formed() {
            return Err(format!(
                "state claim {} is empty, over its cap, or out of order",
                fold.count
            ));
        }
        if fold
            .previous
            .as_ref()
            .is_some_and(|previous| previous >= claim)
        {
            return Err(format!(
                "state claim {} repeats or precedes the one before it",
                fold.count
            ));
        }
        if fold.count >= MAX_STATE_CLAIMS_PER_BLOCK {
            return Err(format!(
                "block carries more than {MAX_STATE_CLAIMS_PER_BLOCK} state claims"
            ));
        }
        fold.previous = Some(claim.clone());
        fold.count += 1;
        Ok(())
    }
}

/// Run `S::admit` over `items` in order, refusing on the first item it
/// refuses — the voter's walk over a section.
///
/// # Errors
///
/// The first refusal.
pub fn admit_all<'i, S: Section>(
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
pub fn admit_each<S: Section, T>(
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
pub fn unwrapped<T>(item: &Arc<Verifiable<T>>) -> &T {
    item
}

#[cfg(test)]
pub(crate) mod fixtures {
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::sync::Arc;

    use hyperscale_types::{
        BeaconWitnessLeafCount, BlockHash, BlockHeight, Epoch, Hash, NetworkDefinition,
        ShardAnchor, ShardId, StateRoot, TopologySchedule, TopologySnapshot, ValidatorSet,
        WeightedTimestamp,
    };

    use super::{Admission, QcChainSets};
    use crate::commit_dedup::CommitDedupIndex;

    /// What a test block is admitted against: one window, with nothing
    /// behind the parent and nothing committed unless a test puts it
    /// there.
    pub struct Against {
        pub snapshot: TopologySnapshot,
        pub schedule: TopologySchedule,
        pub local_shard: ShardId,
        pub anchor: WeightedTimestamp,
        pub chain_origin: WeightedTimestamp,
        pub chain: QcChainSets,
        pub dedup: CommitDedupIndex,
        pub parent_settled_frontier: Option<BlockHeight>,
        pub owed_determined: BTreeSet<BlockHeight>,
    }

    impl Against {
        /// Admission under `snapshot`, which is every window of the
        /// schedule too.
        pub fn window(snapshot: TopologySnapshot) -> Self {
            let schedule = TopologySchedule::new(1_000, Epoch::GENESIS, Arc::new(snapshot.clone()));
            Self::schedule(snapshot, schedule)
        }

        /// Admission under `schedule`, classified under `snapshot`.
        pub fn schedule(snapshot: TopologySnapshot, schedule: TopologySchedule) -> Self {
            Self {
                snapshot,
                schedule,
                local_shard: ShardId::ROOT,
                anchor: WeightedTimestamp::ZERO,
                chain_origin: WeightedTimestamp::ZERO,
                chain: QcChainSets::default(),
                dedup: CommitDedupIndex::new(),
                parent_settled_frontier: Some(BlockHeight::GENESIS),
                owed_determined: BTreeSet::new(),
            }
        }

        pub fn ctx(&self) -> Admission<'_> {
            Admission {
                snapshot: &self.snapshot,
                schedule: &self.schedule,
                local_shard: self.local_shard,
                anchor: self.anchor,
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
                        weighted_timestamp: WeightedTimestamp::from_millis(DEPARTURE_CUT_MS),
                        witness_base: BeaconWitnessLeafCount::ZERO,
                        terminal_roots: None,
                        handoff_complete,
                    },
                )
            })
            .collect();
        let after = window(survivors, boundaries);
        let mut sched = TopologySchedule::new(
            DEPARTURE_CUT_MS,
            Epoch::new(0),
            window(departed, HashMap::new()),
        );
        for epoch in 1..=20u64 {
            sched.insert(Epoch::new(epoch), Arc::clone(&after));
        }
        sched.set_head(after);
        sched
    }
}
