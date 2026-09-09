//! Per-tick attestation state.
//!
//! One `TickState` owns what a tick attests, from the moment its batch
//! is composed to the moment its finalization is handed off: the local
//! execution results, the vote this validator casts over them, and the
//! awaited shards' certificates that complete each member's coverage.
//!
//! ## What a tick holds
//!
//! A tick's *membership* is what it answers for; its *batch* is the
//! subset the VM runs. The two differ by one case: a member past the
//! deadline that bounds it joins undispatched and is attested `Aborted`
//! without executing, because a certificate is execution's statement
//! about its members rather than about its batch.
//!
//! Membership is decided at composition — a member that could not reach
//! its outcome in this tick is not in it, it is still waiting in
//! [`TickCandidates`](crate::candidates::TickCandidates) — so a tick has
//! an outcome for every member the moment its batch returns, and no
//! member of it waits on another.
//!
//! ## Lifecycle
//!
//! 1. **Composed** at a block commit, from the candidates that could
//!    execute there. The block is the tick's own: its hash, its weighted
//!    timestamp, and the committee seated at it.
//! 2. **Executes** as one batch. Results land via
//!    `record_execution_result`.
//! 3. **Votes** once every dispatched member has a result. The vote is
//!    one-shot.
//! 4. **Collects certificates** from the shards its members await via
//!    `add_execution_certificate`. When every member is covered (or
//!    aborted, which is terminal-covered), the tick is complete and ready
//!    for finalization.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_engine::legs::Member;
use hyperscale_types::{
    BlockHash, BlockHeight, ExecutionCertificate, ExecutionOutcome, Finalization,
    GlobalReceiptRoot, MAX_FINALIZATION_DELAY, Role, Settles, ShardId, StoredReceipt, SubstateKey,
    TickHalf, TickId, TxHash, TxOutcome, Verified, WeightedTimestamp, compute_global_receipt_root,
    refused_transactions, settles,
};

/// A tick whose local execution disagreed with the quorum's.
///
/// The receipt root the validator voted against the one its committee
/// certified: direct proof that this node's execution produced different
/// writes from the same committed chain.
#[derive(Debug, Clone)]
pub struct Divergence {
    /// The tick whose roots disagreed.
    pub tick_id: TickId,
    /// The hash of the block whose commit composed it.
    pub block_hash: BlockHash,
    /// The root this validator voted.
    pub local_root: GlobalReceiptRoot,
    /// The root its committee certified.
    pub ec_root: GlobalReceiptRoot,
}

/// The two shard sets a member joins under, kept apart because each
/// answers a different question.
///
/// **Awaited** is whose certificate settlement waits on. A member of the
/// core set awaits the whole core set: the core is one atomic unit, and
/// its members agree or the transaction aborts. Any other member awaits
/// itself: its legs are inbound escrows or outbound deliveries, and
/// neither is anyone else's business to confirm. A whole shape awaits
/// every participant, since every one of them runs it. Two cases and no
/// third; a shape needing one is a shape the classifier should refuse.
///
/// **Reach** is every shard the transaction touches — who this tick's
/// certificate is owed to, because any of them may need what a member
/// escrowed. Waiting on reach would hold a leg behind the core it feeds;
/// routing on awaited would withhold a crossing from the shard that
/// claims it.
///
/// Both include this shard, and awaited is a subset of reach.
///
/// Beside them, whether this shard's certificate **decides** the
/// transaction: it does unless the member is a leg, whose transaction
/// its core decides. Not a third awaited case — a leg and a single-shard
/// core await the same set — but the one fact the wire cannot derive
/// from that set. And whether the member only **delivers**: a leg that
/// failed is the transaction's end on its shard, since it could not
/// issue, but a delivery that failed decides nothing either way — the
/// value it claims stays in its cell for a later claim. And whether the
/// member **executes** the transaction or settles what an execution left:
/// a reclaim, an abandonment, an inherited record's member or a
/// retirement runs no execution of the transaction's own, and the
/// deadline holds only what does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    awaited: BTreeSet<ShardId>,
    reach: BTreeSet<ShardId>,
    role: Role,
}

impl Membership {
    /// The two sets and the role `member` answers — a cache of its
    /// derivation, in the shape a tick carries.
    ///
    /// Classifies **one member**, and so reads the side it runs on. Not
    /// the same question as [`Part::of`](crate::ledger::Part), which
    /// classifies a shard's one ledger entry and reads
    /// [`Classified::only_delivers_at`]: the branches look alike and
    /// answer differently for a shard with legs on both sides of the
    /// core, whose delivering member is a `Delivery` here and whose
    /// single entry is a leg there. Folding either into the other reads
    /// a delivery's verdict off an entry that bears one.
    ///
    /// [`Classified::only_delivers_at`]: hyperscale_engine::legs::Classified::only_delivers_at
    #[must_use]
    pub fn of(member: &Member) -> Self {
        let awaited = member.awaited();
        debug_assert!(
            awaited.is_subset(member.reach()),
            "a member awaits only shards the transaction reaches"
        );
        Self {
            awaited,
            reach: member.reach().clone(),
            role: member.role(),
        }
    }

    /// A whole shape on every participant: one set answers both
    /// questions, and the certificate decides.
    #[must_use]
    pub fn whole(participating: BTreeSet<ShardId>) -> Self {
        Self {
            awaited: participating.clone(),
            reach: participating,
            role: Role::Whole,
        }
    }

    /// A member that settles nothing about the transaction: a retirement,
    /// deleting records whose claims committed elsewhere. Awaits nobody,
    /// decides nothing — the verdict was reached where the claims were,
    /// and a name that decided here would be a second verdict on a chain
    /// that may already hold the first — and executes nothing.
    #[must_use]
    pub fn housekeeping(local: ShardId) -> Self {
        Self {
            awaited: BTreeSet::from([local]),
            reach: BTreeSet::from([local]),
            role: Role::Retiring,
        }
    }

    /// This membership for a member that settles what an execution left
    /// rather than executing the transaction: a reclaim, an abandonment,
    /// an inherited record's. The awaited set stays as stated; the
    /// member decides and executes nothing.
    #[must_use]
    pub const fn settling(mut self) -> Self {
        self.role = Role::Settling;
        self
    }

    /// What this shard is to the transaction.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// The shards whose certificates settlement waits on, this one
    /// included.
    #[must_use]
    pub const fn awaited(&self) -> &BTreeSet<ShardId> {
        &self.awaited
    }

    /// Every shard the transaction touches, this one included.
    #[must_use]
    pub const fn reach(&self) -> &BTreeSet<ShardId> {
        &self.reach
    }

    /// Whether a counterpart's verdict can still discard this member's
    /// effects — off what it awaits, which is what puts it in the legs
    /// half of a tick rather than the determined.
    #[must_use]
    pub fn abortable(&self, local: ShardId) -> bool {
        self.awaited.iter().any(|&shard| shard != local)
    }

    /// Whether the transaction touches a shard besides this one — off
    /// what it reaches, never off what this member awaits. A leg of a
    /// divided transaction reaches beyond and awaits only itself.
    #[must_use]
    pub fn reaches_beyond(&self, local: ShardId) -> bool {
        self.reach.iter().any(|&shard| shard != local)
    }
}

/// How a member joins its tick.
///
/// The three cases are the whole of it: what the tick answers for is its
/// membership, and what the VM runs is its batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// In the batch, attested with whatever execution returns.
    Executes,
    /// In the batch and attested `Aborted` whatever it returns — the
    /// payer's leg whose counterparts never engaged. It still executes,
    /// because the charge that abort settles is what the execution
    /// builds.
    ExecutesAborted,
    /// Not in the batch. Past the deadline that bounds it, so no
    /// execution here can reach an outcome, and the tick attests
    /// `Aborted` on nothing but the hash and the reservation its
    /// committing block took.
    Aborted,
}

impl Admission {
    /// Whether the member goes to the engine, and so whether the tick
    /// waits for a result before it can vote.
    const fn dispatched(self) -> bool {
        matches!(self, Self::Executes | Self::ExecutesAborted)
    }

    /// Whether the tick attests `Aborted` whatever execution says.
    const fn aborts(self) -> bool {
        matches!(self, Self::ExecutesAborted | Self::Aborted)
    }
}

/// Age at which a still-unresolved tick emits a single diagnostic warning.
///
/// Every committed transaction is supposed to reach a certificate — its
/// tick's, or the later tick that abandons it at its deadline. The
/// threshold sits past the deadline so a tick resolving through either
/// path passes silently. A firing means the post-inclusion termination
/// guarantee has failed, so the dump is invariant-violation diagnostics
/// rather than routine load noise.
pub const TICK_OVERDUE_WARN: Duration = Duration::from_secs(MAX_FINALIZATION_DELAY.as_secs() * 2);

/// One member's seat in its tick: the terms it joined on, and everything
/// the tick has learned about it since — from the engine, from the
/// certificates that cover it, and from the chain that settles it.
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)] // independent lifecycle flags, not config knobs
struct Seat {
    /// Whose certificate its settlement waits on, and who its own is
    /// owed to.
    membership: Membership,
    /// The reservation its committing block took against the drain.
    /// Carried apart from the transaction because an abandoned member
    /// has no body here and still has to release exactly what was taken.
    reserved_work: u64,
    /// Dispatched to the engine and still owing a result. A tick is
    /// votable once no seat is.
    awaiting_result: bool,
    /// Attested `Aborted` whatever its execution said: a payer's leg
    /// whose counterparts never engaged, or a member past its own
    /// deadline that never ran.
    aborted: bool,
    /// This tick *is* the member's abandonment — it was seated past the
    /// window that bounds it, running nothing. Kept apart from
    /// [`Self::aborted`], which a member that ran can also carry, because
    /// what it answers is whether abandoning the member again would
    /// discard the abort already waiting to be certified.
    abandons: bool,
    /// The engine's outcome.
    result: Option<ExecutionOutcome>,
    /// The engine's local receipt, drained into the `Finalization` at
    /// finalization. Scoped to the tick rather than a process-wide cache
    /// so a receipt from a locally-executed transaction cannot leak into
    /// a `Finalization` whose certificate attests it `Aborted`.
    receipt: Option<StoredReceipt>,
    /// The fee receipt the engine built alongside the execution receipt,
    /// for a cross-shard transaction this shard pays for. An abort
    /// settles it: the transaction's own effects are discarded, the
    /// payer's floor is not.
    fee_receipt: Option<StoredReceipt>,
    /// What this shard attests it did for the member, carried from
    /// execution onto the outcome it votes.
    attested_work: u64,
    /// What the member's execution escrowed out, carried from execution
    /// onto the outcome it votes.
    escrowed: Vec<SubstateKey>,
    /// The shards the member's crossings land on, read off the frozen
    /// classification at admission. Attested on the outcome only where
    /// the execution escrowed something.
    crossing_targets: BTreeSet<ShardId>,
    /// The committed cell this shard wrote at the member's inclusion,
    /// for a member of the core. Attested on the outcome only where the
    /// member refuses: the settling block deletes it, and a leg probing
    /// the core reads the refusal as the absence it is.
    committed_cell: Option<SubstateKey>,
    /// Which shards have reported on the member via a certificate.
    covered_by: BTreeSet<ShardId>,
    /// A certificate reported abort. Terminal — an aborted transaction
    /// needs no further coverage.
    aborted_anywhere: bool,
    /// A committed finalization resolved the member. The tick's
    /// certificate and tracking state drop once every seat is — which is
    /// later than the halves being emitted, since a handed-off
    /// finalization still has to reach a block.
    settled: bool,
}

impl Seat {
    /// A seat on the terms `admission` names.
    const fn new(membership: Membership, reserved_work: u64, admission: Admission) -> Self {
        Self {
            membership,
            reserved_work,
            awaiting_result: admission.dispatched(),
            aborted: admission.aborts(),
            abandons: matches!(admission, Admission::Aborted),
            result: None,
            receipt: None,
            fee_receipt: None,
            attested_work: 0,
            escrowed: Vec::new(),
            crossing_targets: BTreeSet::new(),
            committed_cell: None,
            covered_by: BTreeSet::new(),
            aborted_anywhere: false,
            settled: false,
        }
    }

    /// Whether the member has the verdict its settlement needs: an
    /// abort anywhere is terminal, and anything else waits for every
    /// awaited shard to have certified it.
    fn is_covered(&self) -> bool {
        self.aborted_anywhere || self.membership.awaited().is_subset(&self.covered_by)
    }
}

/// Per-tick state from composition through finalization.
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)] // independent lifecycle flags, not config knobs
pub struct TickState {
    // ── Identity ────────────────────────────────────────────────────────
    tick_id: TickId,
    block_hash: BlockHash,
    /// The tick's own block's BFT-authenticated weighted timestamp: the
    /// vote anchor, and so the committee that attests.
    tick_ts: WeightedTimestamp,

    // ── Members ─────────────────────────────────────────────────────────
    /// Members, in composition order.
    order: Vec<TxHash>,
    /// Each member's seat.
    seats: HashMap<TxHash, Seat>,

    // ── Local vote and certificate ──────────────────────────────────────
    /// Whether the local vote has been emitted (`build_vote_data` called once).
    voted: bool,
    /// `global_receipt_root` carried on this validator's own emitted vote.
    /// Reconciled against `admitted_local_ec_root` to detect divergence.
    local_vote_global_receipt_root: Option<GlobalReceiptRoot>,
    /// `global_receipt_root` from the admitted local certificate. May
    /// arrive before the local vote, when peers aggregate it before this
    /// validator's engine finishes.
    admitted_local_ec_root: Option<GlobalReceiptRoot>,
    /// Set when the admitted local certificate's `global_receipt_root`
    /// disagreed with `local_vote_global_receipt_root`. Bars the tick from
    /// finalizing locally so divergent receipts cannot enter the
    /// `finalized` store, propagate via `cert_bloom`, or be re-served on
    /// sync — which matters for the window before the coordinator
    /// escalates, not as an outcome. There is no recovery from here: a
    /// wrong tick output is the baseline every later tick reads.
    locally_divergent: bool,
    /// The mismatch behind the latch, until the coordinator reports it.
    divergence: Option<Divergence>,
    /// Whether the determined half's finalization has been handed off.
    determined_emitted: bool,
    /// Whether the legs half's finalization has been handed off.
    legs_emitted: bool,
    /// Whether the local certificate has been added to
    /// `execution_certificates`. Gates completion. Independent of the
    /// canonical-root reconciliation — `locally_divergent` carries the
    /// divergence verdict separately.
    local_ec_emitted: bool,
    /// Latches `log_if_overdue`: fires once per tick after crossing the
    /// `TICK_OVERDUE_WARN` threshold. Under ts-based ages we can't rely on
    /// exact equality (commits can skip over any given ms value).
    overdue_warned: bool,
    /// All collected certificates (local + remote).
    execution_certificates: Vec<Arc<Verified<ExecutionCertificate>>>,
}

impl TickState {
    /// An empty tick at `tick_id`, anchored on the block whose commit
    /// composed it. Members join through [`admit`](Self::admit), which is
    /// the only way in.
    #[must_use]
    pub fn new(tick_id: TickId, block_hash: BlockHash, tick_ts: WeightedTimestamp) -> Self {
        Self {
            tick_id,
            block_hash,
            tick_ts,
            order: Vec::new(),
            seats: HashMap::new(),
            voted: false,
            local_vote_global_receipt_root: None,
            admitted_local_ec_root: None,
            locally_divergent: false,
            divergence: None,
            determined_emitted: false,
            legs_emitted: false,
            local_ec_emitted: false,
            overdue_warned: false,
            execution_certificates: Vec::new(),
        }
    }

    /// Admit a member, on the terms `admission` names.
    ///
    /// One entry point for all three, because they differ only in what
    /// the tick waits for and what it will say. An
    /// [`Aborted`](Admission::Aborted) member joins with no body at all:
    /// the ledger names it by hash, by the shards party to it, and by the
    /// work its committing block reserved, which is everything an abort
    /// has to state. A member the tick already holds keeps the terms it
    /// joined under.
    pub fn admit(
        &mut self,
        tx_hash: TxHash,
        membership: Membership,
        reserved_work: u64,
        admission: Admission,
    ) {
        if self.seats.contains_key(&tx_hash) {
            return;
        }
        self.order.push(tx_hash);
        self.seats
            .insert(tx_hash, Seat::new(membership, reserved_work, admission));
    }

    // ── Identity getters ────────────────────────────────────────────────

    /// The tick's identity.
    #[must_use]
    pub const fn tick_id(&self) -> &TickId {
        &self.tick_id
    }

    /// Hash of the block whose commit composed this tick.
    #[must_use]
    pub const fn block_hash(&self) -> BlockHash {
        self.block_hash
    }

    /// Height of that block (mirrors `tick_id.block_height`).
    #[must_use]
    pub const fn block_height(&self) -> BlockHeight {
        self.tick_id.block_height()
    }

    /// Members, in composition order.
    #[must_use]
    pub fn tx_hashes(&self) -> &[TxHash] {
        &self.order
    }

    /// Whether the tick holds no members at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// The subset of [`Self::tx_hashes`] whose settlement waits on a
    /// counterpart.
    pub fn awaiting_tx_hashes(&self) -> impl Iterator<Item = TxHash> + '_ {
        self.order
            .iter()
            .copied()
            .filter(|&tx_hash| self.awaits_beyond(tx_hash))
    }

    /// Whether the local certificate has been fed into this tick (via
    /// `add_execution_certificate` with `ec.tick_id() == &self.tick_id`).
    #[must_use]
    pub const fn local_ec_emitted(&self) -> bool {
        self.local_ec_emitted
    }

    /// Whether `tx_hash`'s settlement waits on a shard other than this
    /// one — what puts it in the legs half rather than the determined.
    fn awaits_beyond(&self, tx_hash: TxHash) -> bool {
        let local = self.tick_id.shard_id();
        self.seats
            .get(&tx_hash)
            .is_some_and(|seat| seat.membership.abortable(local))
    }

    /// Whether `outcome`, attested by `shard`, covers its member here: the
    /// member awaits `shard`, and a success counts only if the
    /// counterpart awaited this shard for it — ran the shape that has
    /// this shard in it. Two shards freeze a member's shape each at its
    /// own anchor, and one that froze it divided while this one froze it
    /// whole attests a leg that awaited nobody; settling a whole shape on
    /// that would credit here what the leg escrowed there, and the
    /// escrow's reclaim then pays it a second time. An abort settles
    /// nothing and is terminal whoever speaks it, and the tick's own
    /// certificate is what it awaited of itself.
    fn covers(&self, outcome: &TxOutcome, shard: ShardId, is_local: bool) -> bool {
        self.awaits(outcome.tx_hash(), shard)
            && (is_local
                || outcome.is_aborted()
                || outcome.counterparts().contains(&self.tick_id.shard_id()))
    }

    /// Whether `tx_hash`'s settlement waits on `shard`'s certificate.
    fn awaits(&self, tx_hash: TxHash, shard: ShardId) -> bool {
        self.seats
            .get(&tx_hash)
            .is_some_and(|seat| seat.membership.awaited().contains(&shard))
    }

    /// The shards other than this one that the tick's members reach —
    /// who its certificate is owed to. Reach rather than awaited: a
    /// shard this tick waits on nothing from may still need what a
    /// member escrowed.
    #[must_use]
    pub fn counterpart_shards(&self) -> Vec<ShardId> {
        let local = self.tick_id.shard_id();
        self.seats
            .values()
            .flat_map(|seat| seat.membership.reach())
            .copied()
            .filter(|&s| s != local)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Every counterpart certificate this tick's members wait on, as
    /// `(member, shard)` pairs — the coverage [`Self::is_covered`] asks
    /// for, stated as the certificates that would supply it.
    ///
    /// A member admitted as an abort names none: the tick's own
    /// certificate carries its verdict, and no counterpart owes one for a
    /// transaction that reached no outcome anywhere.
    pub fn awaited_counterparts(&self) -> impl Iterator<Item = (TxHash, ShardId)> + '_ {
        let local = self.tick_id.shard_id();
        self.seats
            .iter()
            .filter(|(_, seat)| !seat.aborted)
            .flat_map(move |(&tx_hash, seat)| {
                seat.membership
                    .awaited()
                    .iter()
                    .filter(move |&&shard| shard != local)
                    .map(move |&shard| (tx_hash, shard))
            })
    }

    /// Whether this tick is `tx_hash`'s abandonment rather than a tick
    /// that merely holds it.
    ///
    /// Such a tick waits on nothing and can never fail to close its
    /// coverage, so a later commit that abandoned the member again would
    /// discard the abort this one is carrying and compose an identical
    /// one, every block, for as long as the entry stands.
    #[must_use]
    pub fn abandons(&self, tx_hash: TxHash) -> bool {
        self.seats.get(&tx_hash).is_some_and(|seat| seat.abandons)
    }

    /// Whether a success this tick attests for `tx_hash` is one no block
    /// will carry past the transaction's deadline.
    ///
    /// The three terms the deadline fence reads, off the membership the
    /// outcome's own are derived from: the success bears the verdict, it
    /// is this shard's execution of the transaction rather than a member
    /// settling what one left, and it waits on nobody — so no
    /// counterpart's certificate is coming to close its coverage either.
    #[must_use]
    pub fn decided_alone(&self, tx_hash: TxHash) -> bool {
        self.seats.get(&tx_hash).is_some_and(|seat| {
            let role = seat.membership.role();
            role.success_decides()
                && role.executes()
                && !seat.membership.abortable(self.tick_id.shard_id())
        })
    }

    /// The tick's members whose settlement waits on `shard` — what this
    /// tick is waiting on that shard for.
    pub fn txs_awaiting(&self, shard: ShardId) -> impl Iterator<Item = TxHash> + '_ {
        self.order
            .iter()
            .copied()
            .filter(move |&tx_hash| self.awaits(tx_hash, shard))
    }

    /// The tick's members `shard` is party to — what its copy of this
    /// tick's certificate carries.
    pub fn txs_reaching(&self, shard: ShardId) -> impl Iterator<Item = TxHash> + '_ {
        self.order.iter().copied().filter(move |tx_hash| {
            self.seats
                .get(tx_hash)
                .is_some_and(|seat| seat.membership.reach().contains(&shard))
        })
    }

    // ── Local execution bookkeeping ─────────────────────────────────────

    /// Record an execution outcome from the engine. First-write-wins.
    pub fn record_execution_result(&mut self, tx_hash: TxHash, outcome: ExecutionOutcome) {
        if let Some(seat) = self.seats.get_mut(&tx_hash) {
            seat.result.get_or_insert(outcome);
            seat.awaiting_result = false;
        }
    }

    /// Record a local receipt from the engine. First-write-wins.
    ///
    /// Paired with `record_execution_result`: both flow from the same
    /// `ExecutionBatchCompleted` event and are scoped to this tick.
    /// Receipts for transactions not in it are silently dropped.
    pub fn record_receipt(&mut self, receipt: StoredReceipt) {
        if let Some(seat) = self.seats.get_mut(&receipt.tx_hash) {
            seat.receipt.get_or_insert(receipt);
        }
    }

    /// Record what this shard attested it did for a member.
    pub fn record_attested_work(&mut self, tx_hash: TxHash, work: u64) {
        if let Some(seat) = self.seats.get_mut(&tx_hash) {
            seat.attested_work = work;
        }
    }

    /// Record what a member's execution escrowed out.
    pub fn record_escrowed(&mut self, tx_hash: TxHash, escrowed: Vec<SubstateKey>) {
        if let Some(seat) = self.seats.get_mut(&tx_hash) {
            seat.escrowed = escrowed;
        }
    }

    /// Record the shards a member's crossings land on.
    pub fn record_crossing_targets(&mut self, tx_hash: TxHash, targets: BTreeSet<ShardId>) {
        if let Some(seat) = self.seats.get_mut(&tx_hash) {
            seat.crossing_targets = targets;
        }
    }

    /// Record the committed cell this shard wrote at a core member's
    /// inclusion, which its refusal retracts.
    pub fn record_committed_cell(&mut self, tx_hash: TxHash, cell: SubstateKey) {
        if let Some(seat) = self.seats.get_mut(&tx_hash) {
            seat.committed_cell = Some(cell);
        }
    }

    /// Record the fee receipt the engine built beside a member's
    /// execution receipt: what the payer owes if the transaction aborts.
    pub fn record_fee_receipt(&mut self, receipt: StoredReceipt) {
        if let Some(seat) = self.seats.get_mut(&receipt.tx_hash) {
            seat.fee_receipt.get_or_insert(receipt);
        }
    }

    /// Number of receipts currently held. Exposed for memory stats;
    /// receipts drain at finalization.
    #[must_use]
    pub fn receipt_count(&self) -> usize {
        self.seats
            .values()
            .filter(|seat| seat.receipt.is_some())
            .count()
    }

    /// Take the receipt for a member, removing it. Used internally by
    /// [`Self::into_finalization`] to drain receipts in canonical order.
    fn take_receipt(&mut self, tx_hash: TxHash) -> Option<StoredReceipt> {
        self.seats.get_mut(&tx_hash)?.receipt.take()
    }

    /// Whether this validator holds a local receipt for every member of
    /// `members` the local certificate attests as executed. Aborted
    /// outcomes need no receipt.
    ///
    /// Gates each half so it can't produce a [`Finalization`] that fails
    /// [`Finalization::validate_against_certificates`]. The check mirrors
    /// that invariant: a receipt is needed exactly for the outcomes the
    /// certificate attests as `Executed`. When this validator's local
    /// decision disagrees with the quorum's, the gate blocks here rather
    /// than synthesizing a `Finalization` with missing receipts. Recovery
    /// flows through the existing peer-fetch path.
    ///
    /// **Scoped to one half, because each half drains its own receipts.**
    /// A tick-wide check would pass before the first half settles and
    /// fail afterwards, wedging the second on receipts the first
    /// legitimately consumed.
    ///
    /// Returns false if the local certificate hasn't arrived yet;
    /// `local_ec_emitted` is checked separately for the same reason.
    ///
    /// [`Finalization`]: hyperscale_types::Finalization
    /// [`Finalization::validate_against_certificates`]:
    ///     hyperscale_types::Finalization::validate_against_certificates
    fn has_local_receipts_for(&self, members: &[TxHash]) -> bool {
        let Some(local_ec) = self.local_certificate() else {
            return false;
        };
        local_ec
            .tx_outcomes()
            .iter()
            .filter(|outcome| members.contains(&outcome.tx_hash()))
            .all(|outcome| {
                outcome.is_aborted()
                    || self
                        .seats
                        .get(&outcome.tx_hash())
                        .is_some_and(|seat| seat.receipt.is_some())
            })
    }

    /// This tick's own certificate, in the copy that carries the whole
    /// batch.
    ///
    /// The store can hold more than one copy of a tick — a broadcast and
    /// a narrower fetch answer both land, and the retention rule keeps
    /// whichever covers something new — so the first match is not
    /// necessarily the complete one. Projecting a half needs sibling
    /// nodes from the whole receipt tree, which only the complete copy
    /// carries, and a shard sends its own peers exactly that.
    fn local_certificate(&self) -> Option<&Arc<Verified<ExecutionCertificate>>> {
        self.execution_certificates
            .iter()
            .filter(|ec| ec.tick_id() == &self.tick_id)
            .find(|ec| ec.is_complete())
    }

    // ── Vote emission ───────────────────────────────────────────────────

    /// Vote anchor timestamp: the tick's own block's BFT-authenticated
    /// weighted timestamp.
    ///
    /// This rides the vote payload and the certificate's canonical hash,
    /// and [`VoteTracker`] groups votes by it, so every validator must
    /// derive the same value or agreeing votes never aggregate. Only
    /// committed chain content carries that guarantee, and the block that
    /// composed the tick is exactly that — identical on every replica,
    /// and already in the past when the vote is built, so the committee it
    /// resolves is available at once.
    ///
    /// It is also the right committee on the merits: the one seated at the
    /// tick is the one that holds the state and ran the batch, which is
    /// not always the one that committed the transactions.
    ///
    /// [`VoteTracker`]: crate::vote_tracker::VoteTracker
    #[must_use]
    pub const fn vote_anchor_ts(&self) -> WeightedTimestamp {
        self.tick_ts
    }

    /// Whether the local vote can be emitted.
    ///
    /// One condition, because composition established the rest: every
    /// member the batch was given has come back. A member that could not
    /// reach its outcome here was never admitted, so nothing in a tick
    /// waits on anything outside it.
    #[must_use]
    pub fn can_emit_vote(&self) -> bool {
        !self.voted && self.seats.values().all(|seat| !seat.awaiting_result)
    }

    /// Build the vote payload, consuming the one-shot vote.
    ///
    /// Returns `(vote_anchor_ts, global_receipt_root, tx_outcomes)`, or
    /// `None` if [`Self::can_emit_vote`] is false.
    ///
    /// # Panics
    ///
    /// Panics if a member has neither a decided abort nor an execution
    /// result. `can_emit_vote` guards against this; a panic here would
    /// indicate a bug in the gating.
    pub fn build_vote_data(
        &mut self,
    ) -> Option<(WeightedTimestamp, GlobalReceiptRoot, Vec<TxOutcome>)> {
        if !self.can_emit_vote() {
            return None;
        }

        let local = self.tick_id.shard_id();
        let outcomes: Vec<TxOutcome> = self
            .order
            .iter()
            .map(|tx_hash| {
                let seat = self
                    .seats
                    .get(tx_hash)
                    .expect("a tick seats every member it names");
                let outcome = if seat.aborted {
                    ExecutionOutcome::Aborted
                } else {
                    seat.result
                        .clone()
                        .expect("a votable tick holds a result for every member it ran")
                };
                // Who the settlement waits on, stated so a peer reading
                // the certificate can tell a complete set of them from
                // one a proposer thinned. This shard is not among them:
                // this certificate is its report.
                let counterparts = seat
                    .membership
                    .awaited()
                    .iter()
                    .copied()
                    .filter(|&shard| shard != local);
                // The charge this shard holds against the transaction, if
                // the engine built one. Named whatever the local outcome
                // was, because the local outcome is not what decides
                // whether it is owed: a leg that completed here still
                // owes the floor if a counterpart refuses it, and a
                // charge nobody named is a charge nothing can settle.
                let charge = seat
                    .fee_receipt
                    .as_ref()
                    .map(|fee| fee.consensus.receipt_hash());
                // What left, and where it lands. The targets are attested
                // only beside something escrowed: a member that issued
                // nothing promises no bundle to anyone.
                let targets = if seat.escrowed.is_empty() {
                    BTreeSet::new()
                } else {
                    seat.crossing_targets.clone()
                };
                // A core member's refusal retracts the committed cell
                // its inclusion wrote: the settling block deletes it,
                // so a leg probing the core reads the refusal as an
                // absence, the same one a core that never included the
                // transaction leaves.
                let retracts = seat
                    .committed_cell
                    .filter(|_| !matches!(outcome, ExecutionOutcome::Succeeded { .. }));
                match charge {
                    Some(fee) => TxOutcome::with_fee(*tx_hash, outcome, fee, seat.attested_work),
                    None => TxOutcome::attesting(*tx_hash, outcome, seat.attested_work),
                }
                // What the transaction reserved when its block committed
                // it, carried so the settling block can release exactly
                // that.
                .reserving(seat.reserved_work)
                .awaiting(counterparts)
                .escrowing(seat.escrowed.clone())
                .crossing_to(targets)
                .retracting(retracts)
                .as_role(seat.membership.role())
            })
            .collect();

        let root = compute_global_receipt_root(&outcomes);
        self.voted = true;
        self.local_vote_global_receipt_root = Some(root);
        self.reconcile_local_ec_root();
        Some((self.tick_ts, root, outcomes))
    }

    // ── Cross-shard certificate collection ──────────────────────────────

    /// Feed a certificate into the tick: update per-member coverage, track
    /// aborts and failures, and keep it. For our own local certificate
    /// (`ec.tick_id() == &self.tick_id`), records the admitted root and
    /// reconciles against the local vote when both are known. The local
    /// certificate may arrive before the local vote when peers aggregate
    /// it before this validator's engine finishes; the reconciliation runs
    /// again from `build_vote_data` once the local vote lands.
    ///
    /// **A certificate is kept exactly when it covers something this tick
    /// does not already have covered.** A certificate carries the outcomes
    /// naming its holder, so two copies of one tick can differ — the
    /// broadcast a shard sends and a narrower one a fetch answered with —
    /// and dropping the second because its tick is familiar would leave
    /// this tick believing a transaction covered by an outcome it does not
    /// hold. That is not a missing optimisation but a hole: the outcome it
    /// would have dropped could be the counterpart's abort, and settling
    /// its sibling without it moves value one-sidedly.
    ///
    /// The same test is the bound. A peer can synthesise arbitrarily many
    /// valid narrower copies of one tick, so keeping every distinct copy
    /// would be unbounded; keeping only those that cover something new
    /// caps the collection at one certificate per transaction.
    ///
    /// **An outcome from a shard the member does not await is not
    /// coverage.** A leg that certifies alone owes nothing to the core's
    /// certificate, and reading a verdict off one would discard an
    /// escrow that is only ever reclaimed on evidence. Such a certificate
    /// covers nothing here and is not kept.
    ///
    /// Readiness is the caller's next question — a certificate can make
    /// either half settleable, or neither.
    pub fn add_execution_certificate(&mut self, ec: Arc<Verified<ExecutionCertificate>>) {
        let shard = ec.shard_id();
        let is_local = ec.tick_id() == &self.tick_id;

        let covers_something_new = ec.tx_outcomes().iter().any(|outcome| {
            self.covers(outcome, shard, is_local)
                && self
                    .seats
                    .get(&outcome.tx_hash())
                    .is_some_and(|seat| !seat.covered_by.contains(&shard))
        });
        // An empty tick's own certificate covers nothing yet still has to
        // land: both halves gate on having emitted it.
        let first_local = is_local && !self.local_ec_emitted;
        if !covers_something_new && !first_local {
            return;
        }

        for outcome in ec.tx_outcomes() {
            let tx_hash = outcome.tx_hash();
            if !self.covers(outcome, shard, is_local) {
                continue;
            }
            if let Some(seat) = self.seats.get_mut(&tx_hash) {
                seat.covered_by.insert(shard);
                if outcome.is_aborted() {
                    seat.aborted_anywhere = true;
                }
            }
        }

        if is_local {
            self.admitted_local_ec_root = Some(ec.global_receipt_root());
            self.local_ec_emitted = true;
            self.reconcile_local_ec_root();
        }

        self.execution_certificates.push(ec);
    }

    /// Compare `local_vote_global_receipt_root` against
    /// `admitted_local_ec_root` once both are known. Run from both sites
    /// that can supply the second half of the pair: `build_vote_data` and
    /// `add_execution_certificate`.
    fn reconcile_local_ec_root(&mut self) {
        let (Some(local), Some(admitted)) = (
            self.local_vote_global_receipt_root,
            self.admitted_local_ec_root,
        ) else {
            return;
        };
        if local == admitted || self.locally_divergent {
            return;
        }
        self.locally_divergent = true;
        self.divergence = Some(Divergence {
            tick_id: self.tick_id,
            block_hash: self.block_hash,
            local_root: local,
            ec_root: admitted,
        });
    }

    /// Take the latched divergence, if any, for the coordinator to report.
    pub const fn take_divergence(&mut self) -> Option<Divergence> {
        self.divergence.take()
    }

    /// Whether this validator's execution disagreed with its committee's.
    #[must_use]
    pub const fn is_locally_divergent(&self) -> bool {
        self.locally_divergent
    }

    /// The members whose settlement needs no shard but this one — the
    /// single-shard transactions, the legs that certify alone, and the
    /// ones this tick abandons. Their outcome is decided by the tick's
    /// own certificate, so nothing a counterpart does can hold them.
    #[must_use]
    pub fn determined_members(&self) -> Vec<TxHash> {
        self.order
            .iter()
            .copied()
            .filter(|&tx_hash| !self.awaits_beyond(tx_hash))
            .collect()
    }

    /// The members whose settlement waits on a counterpart — the legs
    /// half.
    #[must_use]
    pub fn leg_members(&self) -> Vec<TxHash> {
        self.awaiting_tx_hashes().collect()
    }

    /// Conditions both halves share: the certificate exists and this
    /// validator agreed with it. Receipts are checked per half, since
    /// each drains its own.
    const fn attestable(&self) -> bool {
        self.local_ec_emitted && !self.locally_divergent
    }

    /// Whether `tx_hash` has the verdict its settlement needs.
    fn is_covered(&self, tx_hash: TxHash) -> bool {
        self.seats.get(&tx_hash).is_some_and(Seat::is_covered)
    }

    /// Whether the determined half can settle now.
    ///
    /// It needs no coverage beyond the tick's own certificate, which is
    /// the whole point: a leg waiting on a counterpart that never comes
    /// cannot hold these members, and the settlement frontier they
    /// advance therefore cannot wedge.
    #[must_use]
    pub fn determined_ready(&self) -> bool {
        let members = self.determined_members();
        !self.determined_emitted
            && self.attestable()
            && !members.is_empty()
            && self.has_local_receipts_for(&members)
    }

    /// Whether the legs half can settle now: every leg has its verdict,
    /// and this validator holds the receipts they settle.
    ///
    /// It does not wait on the determined half. The two cannot produce
    /// conflicting absolutes, because composition claims a leg's declared
    /// access before testing any determined member: the pair is admitted
    /// together only where both reach the cell commutatively, and
    /// movements compose in any order. Waiting would only mean a
    /// determined member missing a receipt could hold legs that are ready
    /// — the same hostage-taking the halves exist to end, pointing the
    /// other way.
    #[must_use]
    pub fn legs_ready(&self) -> bool {
        let legs = self.leg_members();
        !self.legs_emitted
            && self.attestable()
            && !legs.is_empty()
            && self.has_local_receipts_for(&legs)
            && legs.iter().all(|&tx_hash| self.is_covered(tx_hash))
    }

    /// Whether the determined half is still owed here: the tick holds
    /// members that await nobody but this shard, none of them settled by
    /// a committed block, and their finalization has not been taken.
    #[must_use]
    pub fn determined_pending(&self) -> bool {
        !self.determined_emitted && self.determined_unsettled()
    }

    /// Whether the *chain* still owes this tick's determined half: the
    /// tick holds members that await nobody but this shard and no
    /// committed block has settled them.
    ///
    /// Wider than [`Self::determined_pending`], which also asks whether
    /// this validator has yet to hand the half off. Settlement order is
    /// measured over what the chain carries, so a half already emitted
    /// and not yet committed is one a later half must not settle past.
    #[must_use]
    pub fn determined_unsettled(&self) -> bool {
        self.determined_members()
            .iter()
            .any(|tx_hash| self.seats.get(tx_hash).is_some_and(|seat| !seat.settled))
    }

    /// Whether the determined half is out of the way — emitted, or never
    /// existed because the tick ran nothing but legs.
    fn determined_emitted_or_absent(&self) -> bool {
        self.determined_emitted || self.determined_members().is_empty()
    }

    /// Whether this tick has said everything it will say.
    #[must_use]
    pub fn has_spoken(&self) -> bool {
        self.determined_emitted_or_absent() && (self.legs_emitted || self.leg_members().is_empty())
    }

    /// Record that a committed finalization resolved these members.
    /// Returns whether every member of the tick is now settled, which is
    /// when its certificate and tracking state can be dropped.
    pub fn record_settled(&mut self, tx_hashes: impl IntoIterator<Item = TxHash>) -> bool {
        for tx_hash in tx_hashes {
            if let Some(seat) = self.seats.get_mut(&tx_hash) {
                seat.settled = true;
            }
        }
        self.seats.values().all(|seat| seat.settled)
    }

    /// Emit a `warn!` log exactly once, when the tick reaches
    /// `TICK_OVERDUE_WARN` of age without completing. A firing is an
    /// invariant violation — every member is supposed to terminate with a
    /// `Finalization` — so the dump captures enough state to diagnose
    /// where the post-inclusion termination guarantee broke. Latched at
    /// the first crossing so it fires once per stuck tick, not once per
    /// surviving commit.
    pub fn log_if_overdue(&mut self, committed_ts: WeightedTimestamp) {
        if self.overdue_warned {
            return;
        }
        let age = committed_ts.elapsed_since(self.tick_ts);
        if age < TICK_OVERDUE_WARN {
            return;
        }
        self.overdue_warned = true;

        let total = self.order.len();

        let mut missing_coverage: Vec<String> = Vec::new();
        for tx_hash in &self.order {
            let Some(seat) = self.seats.get(tx_hash) else {
                continue;
            };
            if seat.aborted_anywhere {
                continue;
            }
            let missing: BTreeSet<ShardId> = seat
                .membership
                .awaited()
                .difference(&seat.covered_by)
                .copied()
                .collect();
            if !missing.is_empty() {
                let missing_list: Vec<String> =
                    missing.iter().map(|s| s.inner().to_string()).collect();
                missing_coverage.push(format!("{:?}→[{}]", tx_hash, missing_list.join(",")));
            }
        }

        let local_receipts_ready = self.has_local_receipts_for(&self.order);

        tracing::warn!(
            tick = %self.tick_id,
            block_hash = ?self.block_hash,
            block_height = self.tick_id.block_height().inner(),
            tick_ts = self.tick_ts.as_millis(),
            committed_ts = committed_ts.as_millis(),
            age_ms = u64::try_from(age.as_millis()).unwrap_or(u64::MAX),
            num_txs = total,
            awaiting_results = self.seats.values().filter(|seat| seat.awaiting_result).count(),
            voted = self.voted,
            local_ec_emitted = self.local_ec_emitted,
            local_receipts_ready,
            execution_results = self.seats.values().filter(|seat| seat.result.is_some()).count(),
            aborted = self.seats.values().filter(|seat| seat.aborted).count(),
            aborted_anywhere = self.seats.values().filter(|seat| seat.aborted_anywhere).count(),
            ecs_collected = self.execution_certificates.len(),
            determined_ready = self.determined_ready(),
            legs_ready = self.legs_ready(),
            determined_emitted = self.determined_emitted,
            legs_emitted = self.legs_emitted,
            missing_coverage = missing_coverage.join(" "),
            "Tick overdue: unresolved past the deadline that bounds every member"
        );
    }

    /// Build one half's attestation: the tick's own certificate
    /// projected to `members`, plus the counterpart certificates those
    /// members still need a verdict from.
    ///
    /// **The projection is what makes each half account for itself.**
    /// `tx_hashes`, `tx_count` and `declared_work` all read the local
    /// certificate, so projecting it to this half's members is what makes
    /// the half name exactly its own transactions and release exactly
    /// their reservations — no new field, and the drain term stays
    /// readable off the block. Both projections verify under the same
    /// signed root and signature as the copy they came from.
    ///
    /// A remote certificate is included when it comes from a shard a
    /// member of this half awaits and covers a member this half still
    /// needs a verdict on, or when it is the certificate carrying that
    /// member's abort. That second clause is what keeps the two
    /// sides of a settlement in agreement. `tracker_aborted` is fed by
    /// the very certificates being filtered here — a remote abort lands
    /// as coverage *and* as an entry in that set — so pruning on
    /// `tracker_aborted` alone discards the only artifact carrying that
    /// verdict. Every downstream reader derives the outcome from the
    /// certificate and nothing else ([`Finalization::tx_decisions`]), so
    /// what that drops is not merely redundant: the local certificate's
    /// success stands unopposed and this shard commits an accept against
    /// the counterparty's abort.
    ///
    /// Returns `None` when this half has no members, or when the local
    /// certificate has not landed yet.
    #[must_use]
    fn attestation_for(&self, half: TickHalf, members: &HashSet<TxHash>) -> Option<Finalization> {
        let local = self.local_certificate()?;
        // What the local certificate says on its own. A member it already
        // reports as aborted needs no remote to corroborate it.
        let locally_aborted: HashSet<TxHash> = local
            .tx_outcomes()
            .iter()
            .filter(|outcome| outcome.is_aborted())
            .map(TxOutcome::tx_hash)
            .collect();

        let projected = local.project_to(members)?;

        let required_remote_tick_ids: HashSet<TickId> = self
            .execution_certificates
            .iter()
            .filter(|ec| ec.tick_id() != &self.tick_id)
            .filter(|ec| {
                let shard = ec.shard_id();
                ec.tx_outcomes().iter().any(|outcome| {
                    let tx_hash = outcome.tx_hash();
                    if !members.contains(&tx_hash) || !self.awaits(tx_hash, shard) {
                        return false;
                    }
                    // Still awaiting a verdict, or holding the only one that
                    // says abort.
                    !self
                        .seats
                        .get(&tx_hash)
                        .is_some_and(|seat| seat.aborted_anywhere)
                        || (outcome.is_aborted() && !locally_aborted.contains(&tx_hash))
                })
            })
            .map(|ec| *ec.tick_id())
            .collect();

        let mut ecs: Vec<Verified<ExecutionCertificate>> = std::iter::once(projected)
            .chain(
                self.execution_certificates
                    .iter()
                    .filter(|ec| required_remote_tick_ids.contains(ec.tick_id()))
                    .map(|verified| (**verified).clone()),
            )
            .collect();
        ecs.sort_by(|a, b| (&a.shard_id(), a.tick_id()).cmp(&(&b.shard_id(), b.tick_id())));

        Some(Finalization::from_verified_ecs(self.tick_id, half, ecs))
    }

    /// Drain one stored receipt per outcome of `attestation` that settles
    /// anything, in the certificate's canonical order.
    ///
    /// Which side of an outcome settles is [`settles`]'s question, read
    /// against the whole certificate rather than against this shard's own
    /// verdict: a leg that completed here and was refused by a counterpart
    /// settles its charge, not its effects. Peers re-derive the same rule
    /// through `validate_against_certificates` at ingress.
    fn with_drained_receipts(&mut self, attestation: Finalization) -> Finalization {
        let local_ec = attestation
            .execution_certificates()
            .iter()
            .find(|ec| ec.tick_id() == attestation.tick_id())
            .expect("a half carries the projection of its own tick's certificate")
            .clone();
        let refused = refused_transactions(attestation.execution_certificates());
        let mut receipts: Vec<StoredReceipt> = Vec::with_capacity(local_ec.tx_outcomes().len());
        for outcome in local_ec.tx_outcomes() {
            let drained = match settles(outcome, &refused) {
                // The charge stands in for whatever the transaction did:
                // a `Failed` receipt carries nothing, and a completed
                // leg's effects are discarded by the refusal. Either way
                // the pairing stays one receipt per outcome.
                Settles::Charge(_) => {
                    self.take_receipt(outcome.tx_hash());
                    self.seats
                        .get_mut(&outcome.tx_hash())
                        .and_then(|seat| seat.fee_receipt.take())
                }
                Settles::Effects(_) | Settles::Failure => self.take_receipt(outcome.tx_hash()),
                Settles::Nothing => continue,
            };
            if let Some(receipt) = drained {
                receipts.push(receipt);
            } else {
                tracing::error!(
                    tick = %self.tick_id,
                    tx_hash = ?outcome.tx_hash(),
                    "an outcome that settles something is missing its stored receipt \
                     (readiness gate bypassed)"
                );
            }
        }
        attestation.with_receipts(receipts)
    }

    /// Take the determined half's finalization, if it is ready.
    ///
    /// Settles on the tick's own certificate alone, so a leg waiting on a
    /// counterpart cannot hold it — which is what keeps the settlement
    /// frontier advancing whatever a counterpart does.
    pub fn take_determined_finalization(&mut self) -> Option<Finalization> {
        if !self.determined_ready() {
            return None;
        }
        let members: HashSet<TxHash> = self.determined_members().into_iter().collect();
        let attestation = self.attestation_for(TickHalf::Determined, &members)?;
        self.determined_emitted = true;
        Some(self.with_drained_receipts(attestation))
    }

    /// Take the legs half's finalization, if it is ready.
    pub fn take_legs_finalization(&mut self) -> Option<Finalization> {
        if !self.legs_ready() {
            return None;
        }
        let members: HashSet<TxHash> = self.leg_members().into_iter().collect();
        let attestation = self.attestation_for(TickHalf::Legs, &members)?;
        self.legs_emitted = true;
        Some(self.with_drained_receipts(attestation))
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_engine::legs::{Classified, Side};
    use hyperscale_types::{
        AggregateSignature, ConsensusReceipt, GlobalReceiptHash, Hash, SignerBitfield,
    };

    use super::*;

    fn tx(seed: u8) -> TxHash {
        TxHash::from(Hash::from_bytes(&[seed; 32]))
    }

    fn receipt(tx_hash: TxHash) -> StoredReceipt {
        StoredReceipt {
            tx_hash,
            consensus: Arc::new(ConsensusReceipt::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
                #[allow(clippy::default_trait_access)]
                writes: Default::default(),
                beacon_witness_events: Vec::new(),
                events: Vec::new(),
            }),
            metadata: None,
        }
    }

    fn shard(index: u64) -> ShardId {
        ShardId::leaf(1, index)
    }

    /// A core member's refusal retracts the committed cell its inclusion
    /// wrote, and its success does not: the settling block deletes the
    /// cell of a refused transaction, so a leg probing the core reads
    /// the refusal as the absence a core that never included it leaves.
    #[test]
    fn a_core_members_refusal_retracts_its_committed_cell() {
        use hyperscale_types::test_utils::test_key;

        let local = shard(0);
        let (refused, accepted) = (tx(1), tx(2));
        let mut tick = TickState::new(
            TickId::new(local, BlockHeight::new(1)),
            BlockHash::ZERO,
            WeightedTimestamp::from_millis(1_000),
        );
        for (tx_hash, cell) in [(refused, test_key(1)), (accepted, test_key(2))] {
            tick.admit(
                tx_hash,
                Membership::whole(BTreeSet::from([local, shard(1)])),
                10,
                Admission::Executes,
            );
            tick.record_committed_cell(tx_hash, cell);
        }
        tick.record_execution_result(refused, ExecutionOutcome::Failed);
        tick.record_execution_result(
            accepted,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        );
        let (_, _, outcomes) = tick.build_vote_data().expect("every member came back");
        let retracts = |tx_hash: TxHash| {
            outcomes
                .iter()
                .find(|outcome| outcome.tx_hash() == tx_hash)
                .expect("the tick votes every member")
                .retracts()
        };
        assert_eq!(
            retracts(refused),
            Some(test_key(1)),
            "the refusal names the cell the settling block deletes"
        );
        assert_eq!(
            retracts(accepted),
            None,
            "a success leaves its cell standing"
        );
    }

    /// A tick at `shard(0)` running one single-shard member and one leg
    /// bound to `shard(1)`, both executed and both holding a receipt.
    fn mixed_tick() -> (TickState, TxHash, TxHash) {
        let local = shard(0);
        let (determined, leg) = (tx(1), tx(2));
        let mut tick = TickState::new(
            TickId::new(local, BlockHeight::new(1)),
            BlockHash::ZERO,
            WeightedTimestamp::from_millis(1_000),
        );
        tick.admit(
            determined,
            Membership::whole(BTreeSet::from([local])),
            10,
            Admission::Executes,
        );
        tick.admit(
            leg,
            Membership::whole(BTreeSet::from([local, shard(1)])),
            20,
            Admission::Executes,
        );
        for tx_hash in [determined, leg] {
            tick.record_execution_result(
                tx_hash,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            );
            tick.record_receipt(receipt(tx_hash));
        }
        let (_, root, outcomes) = tick.build_vote_data().expect("every member came back");
        tick.add_execution_certificate(Arc::new(Verified::new_unchecked_for_test(
            ExecutionCertificate::new(
                *tick.tick_id(),
                tick.vote_anchor_ts(),
                root,
                outcomes,
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ),
        )));
        (tick, determined, leg)
    }

    /// A counterpart that ran the member as a leg awaited nobody, and its
    /// certificate is not the counterpart a whole shape here waits on:
    /// the member stays uncovered until a certificate whose outcome
    /// awaited this shard arrives.
    #[test]
    fn a_counterpart_that_awaited_nobody_does_not_cover_a_whole_shape() {
        let (local, peer) = (shard(0), shard(1));
        let member = tx(3);
        let mut tick = TickState::new(
            TickId::new(local, BlockHeight::new(1)),
            BlockHash::ZERO,
            WeightedTimestamp::from_millis(1_000),
        );
        tick.admit(
            member,
            Membership::whole(BTreeSet::from([local, peer])),
            10,
            Admission::Executes,
        );
        let from_peer = |counterparts: Vec<ShardId>| {
            Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
                TickId::new(peer, BlockHeight::new(7)),
                WeightedTimestamp::from_millis(1_000),
                GlobalReceiptRoot::ZERO,
                vec![
                    TxOutcome::attesting(
                        member,
                        ExecutionOutcome::Succeeded {
                            receipt_hash: GlobalReceiptHash::ZERO,
                        },
                        1,
                    )
                    .awaiting(counterparts),
                ],
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            )))
        };

        tick.add_execution_certificate(from_peer(Vec::new()));
        assert!(
            !tick.seats[&member].covered_by.contains(&peer),
            "a leg's certificate awaited nobody and covers nothing here"
        );
        tick.add_execution_certificate(from_peer(vec![local]));
        assert!(
            tick.seats[&member].covered_by.contains(&peer),
            "a certificate whose outcome awaited this shard is the counterpart"
        );
    }

    /// The hostage-taking runs both ways, and neither is allowed.
    ///
    /// A determined member this validator holds no receipt for cannot
    /// settle, and must not hold the legs beside it. Nothing is lost by
    /// letting them go first: composition claims a leg's declared access
    /// before testing any determined member, so the two are admitted
    /// together only where both reach the cell commutatively, and
    /// movements compose in any order.
    #[test]
    fn a_determined_member_without_its_receipt_does_not_hold_the_legs() {
        let local = shard(0);
        let (determined, leg) = (tx(1), tx(2));
        let mut tick = TickState::new(
            TickId::new(local, BlockHeight::new(1)),
            BlockHash::ZERO,
            WeightedTimestamp::from_millis(1_000),
        );
        tick.admit(
            determined,
            Membership::whole(BTreeSet::from([local])),
            10,
            Admission::Executes,
        );
        tick.admit(
            leg,
            Membership::whole(BTreeSet::from([local, shard(1)])),
            20,
            Admission::Executes,
        );
        for tx_hash in [determined, leg] {
            tick.record_execution_result(
                tx_hash,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            );
        }
        // Only the leg's receipt lands.
        tick.record_receipt(receipt(leg));
        let (_, root, outcomes) = tick.build_vote_data().expect("every member came back");
        tick.add_execution_certificate(Arc::new(Verified::new_unchecked_for_test(
            ExecutionCertificate::new(
                *tick.tick_id(),
                tick.vote_anchor_ts(),
                root,
                outcomes,
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ),
        )));
        tick.add_execution_certificate(Arc::new(Verified::new_unchecked_for_test(
            ExecutionCertificate::new(
                TickId::new(shard(1), BlockHeight::new(4)),
                WeightedTimestamp::from_millis(1_000),
                GlobalReceiptRoot::ZERO,
                vec![
                    TxOutcome::new(
                        leg,
                        ExecutionOutcome::Succeeded {
                            receipt_hash: GlobalReceiptHash::ZERO,
                        },
                    )
                    .awaiting([local]),
                ],
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ),
        )));

        assert!(
            !tick.determined_ready(),
            "the determined half is missing the receipt it would settle",
        );
        assert!(tick.legs_ready(), "and the legs are ready regardless");
        let half = tick
            .take_legs_finalization()
            .expect("covered and receipted");
        assert_eq!(half.tx_hashes().collect::<Vec<_>>(), vec![leg]);
        assert_eq!(half.half(), TickHalf::Legs);
    }

    /// The milestone's whole point: a leg whose counterpart never
    /// certifies does not hold its tick-mates. The determined half
    /// settles on the tick's own certificate, names only its own member,
    /// and releases only that member's reservation.
    #[test]
    fn a_stranded_leg_does_not_hold_its_tick_mates() {
        let (mut tick, determined, leg) = mixed_tick();

        assert!(tick.determined_ready());
        assert!(!tick.legs_ready(), "the counterpart has not certified");

        let half = tick
            .take_determined_finalization()
            .expect("settles on the tick's own certificate");
        assert_eq!(
            half.tx_hashes().collect::<Vec<_>>(),
            vec![determined],
            "the half names its own members and no others",
        );
        assert_eq!(
            half.declared_work(),
            10,
            "and releases only what those members reserved",
        );
        assert!(!tick.has_spoken(), "the leg is still owed a verdict");

        // The counterpart still never certifies.
        assert!(!tick.legs_ready());
        assert!(tick.take_legs_finalization().is_none());
        assert!(!tick.determined_ready(), "the determined half is one-shot");
        let _ = leg;
    }

    /// Once the counterpart certifies, the legs half follows and the tick
    /// has said everything it will say.
    #[test]
    fn the_legs_half_follows_its_counterpart() {
        let (mut tick, _determined, leg) = mixed_tick();
        tick.take_determined_finalization().expect("ready");

        tick.add_execution_certificate(Arc::new(Verified::new_unchecked_for_test(
            ExecutionCertificate::new(
                TickId::new(shard(1), BlockHeight::new(4)),
                WeightedTimestamp::from_millis(1_000),
                GlobalReceiptRoot::ZERO,
                vec![
                    TxOutcome::new(
                        leg,
                        ExecutionOutcome::Succeeded {
                            receipt_hash: GlobalReceiptHash::ZERO,
                        },
                    )
                    .awaiting([shard(0)]),
                ],
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ),
        )));

        assert!(tick.legs_ready());
        let half = tick.take_legs_finalization().expect("covered");
        assert_eq!(half.tx_hashes().collect::<Vec<_>>(), vec![leg]);
        assert_eq!(half.declared_work(), 20);
        assert!(tick.has_spoken());
    }

    /// A tick with nothing but single-shard members has no legs half at
    /// all, so it is done the moment its own certificate lands.
    #[test]
    fn a_purely_local_tick_has_one_half() {
        let local = shard(0);
        let mut tick = TickState::new(
            TickId::new(local, BlockHeight::new(1)),
            BlockHash::ZERO,
            WeightedTimestamp::from_millis(1_000),
        );
        tick.admit(
            tx(1),
            Membership::whole(BTreeSet::from([local])),
            10,
            Admission::Executes,
        );
        tick.record_execution_result(
            tx(1),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        );
        tick.record_receipt(receipt(tx(1)));
        let (_, root, outcomes) = tick.build_vote_data().expect("came back");
        tick.add_execution_certificate(Arc::new(Verified::new_unchecked_for_test(
            ExecutionCertificate::new(
                *tick.tick_id(),
                tick.vote_anchor_ts(),
                root,
                outcomes,
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ),
        )));

        assert!(tick.take_determined_finalization().is_some());
        assert!(tick.leg_members().is_empty());
        assert!(tick.has_spoken());
    }

    /// The awaited set has two cases and no third. A member of the core
    /// set awaits the whole core set; any other member awaits itself; and
    /// a whole shape awaits every participant. Reach is every participant
    /// whatever the case.
    #[test]
    fn membership_follows_the_two_case_rule() {
        use crate::fixtures::{leaf, route, swap, trie};

        let trie = trie();
        let (low, high, third) = (leaf(0), leaf(1), leaf(2));

        let swap = Classified::freeze(&swap(), &[], &trie);
        assert!(swap.decomposed());
        let participating = BTreeSet::from([low, high]);
        let member_of = |classified: &Classified, local, participating: &BTreeSet<ShardId>| {
            Member::of(
                classified.clone(),
                local,
                Side::Issuing,
                participating.clone(),
            )
        };
        let caller = Membership::of(&member_of(&swap, low, &participating));
        assert_eq!(
            caller.awaited(),
            &BTreeSet::from([low]),
            "a leg awaits itself"
        );
        assert_eq!(caller.reach(), &participating);
        assert_eq!(
            caller.role(),
            Role::Leg,
            "and its core decides the transaction"
        );
        let venue = Membership::of(&member_of(&swap, high, &participating));
        assert_eq!(
            venue.awaited(),
            &BTreeSet::from([high]),
            "a single-shard core awaits itself"
        );
        assert_eq!(venue.reach(), &participating);
        assert_eq!(venue.role(), Role::Core, "and decides");

        let route = Classified::freeze(&route(), &[], &trie);
        let participating = BTreeSet::from([low, high, third]);
        let core_member = Membership::of(&member_of(&route, high, &participating));
        assert_eq!(
            core_member.awaited(),
            &BTreeSet::from([high, third]),
            "a core member awaits the core set"
        );
        assert_eq!(core_member.reach(), &participating);
        let feeder = Membership::of(&member_of(&route, low, &participating));
        assert_eq!(feeder.awaited(), &BTreeSet::from([low]));

        let whole = Membership::of(&member_of(&Classified::whole(), low, &participating));
        assert_eq!(whole, Membership::whole(participating));
    }

    /// A shard outside the core whose every leg is a delivery is frozen
    /// as delivering; one that also issues is not, and neither is the
    /// core. A delivering member decides nothing whichever way it went —
    /// its failure leaves the value in the cell — where a leg that
    /// failed to issue is the transaction's end on its shard.
    #[test]
    fn a_delivering_member_never_decides() {
        use hyperscale_types::BlockHeight;
        use hyperscale_vm_types::LegRole;

        use crate::fixtures::{leaf, leg, swap, trie};

        let trie = trie();
        let placement = &trie;
        let (sender, recipient) = (leaf(0), leaf(1));

        let transfer = Classified::freeze(
            &[
                leg(0, LegRole::Core, &[]),
                leg(1, LegRole::Outbound, &[(0, 0)]),
            ],
            &[],
            placement,
        );
        assert!(transfer.decomposed());
        assert!(transfer.only_delivers_at(recipient));
        assert!(
            !transfer.only_delivers_at(sender),
            "the core bears the verdict"
        );
        let swap = Classified::freeze(&swap(), &[], placement);
        assert!(
            !swap.only_delivers_at(leaf(0)),
            "a shard that also issues runs on the transaction's window"
        );

        let mut tick = TickState::new(
            TickId::new(recipient, BlockHeight::new(1)),
            BlockHash::ZERO,
            WeightedTimestamp::from_millis(1_000),
        );
        let participating = BTreeSet::from([sender, recipient]);
        let delivery = tx(1);
        let membership = Membership::of(&Member::of(
            transfer,
            recipient,
            Side::Delivering,
            participating.clone(),
        ));
        assert!(membership.role().delivers());
        assert_eq!(membership.role(), Role::Delivery);
        tick.admit(delivery, membership, 10, Admission::Executes);
        let issuer = tx(2);
        tick.admit(
            issuer,
            Membership::of(&Member::of(swap, leaf(0), Side::Issuing, participating)),
            10,
            Admission::Executes,
        );
        tick.record_execution_result(delivery, ExecutionOutcome::Failed);
        tick.record_execution_result(issuer, ExecutionOutcome::Failed);
        let (_, _, outcomes) = tick.build_vote_data().expect("both settle alone");
        let decides = |hash: TxHash| {
            outcomes
                .iter()
                .find(|outcome| outcome.tx_hash() == hash)
                .expect("attested")
                .decides()
        };
        assert!(!decides(delivery), "a failed delivery decides nothing");
        assert!(
            decides(issuer),
            "a failed issue is the transaction's end here"
        );
    }

    /// A leg awaiting nobody but itself settles in the determined half on
    /// the tick's own certificate, while that certificate is still owed
    /// to every shard the transaction reaches. A certificate from one of
    /// those shards is neither coverage for the leg nor part of its
    /// finalization: its verdict is not the leg's to apply.
    #[test]
    fn a_leg_certifies_alone_and_is_still_routed_to_its_reach() {
        use hyperscale_types::BlockHeight;

        use crate::fixtures::{leaf, swap, trie};

        let trie = trie();
        let (local, venue) = (leaf(0), leaf(1));
        let classified = Classified::freeze(&swap(), &[], &trie);
        let leg = tx(1);
        let mut tick = TickState::new(
            TickId::new(local, BlockHeight::new(1)),
            BlockHash::ZERO,
            WeightedTimestamp::from_millis(1_000),
        );
        tick.admit(
            leg,
            Membership::of(&Member::of(
                classified,
                local,
                Side::Issuing,
                BTreeSet::from([local, venue]),
            )),
            10,
            Admission::Executes,
        );

        assert_eq!(tick.determined_members(), vec![leg], "it settles alone");
        assert!(tick.leg_members().is_empty());
        assert_eq!(
            tick.awaited_counterparts().count(),
            0,
            "and expects no certificate"
        );
        assert_eq!(
            tick.counterpart_shards(),
            vec![venue],
            "yet its own is owed to the venue"
        );
        assert_eq!(tick.txs_reaching(venue).collect::<Vec<_>>(), vec![leg]);
        assert_eq!(tick.txs_awaiting(venue).count(), 0);

        tick.record_execution_result(
            leg,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        );
        tick.record_receipt(receipt(leg));
        let (_, root, outcomes) = tick.build_vote_data().expect("came back");
        assert!(
            outcomes[0].counterparts().is_empty(),
            "the outcome names no counterpart, so the finalization is complete on its own"
        );
        assert!(
            !outcomes[0].decides(),
            "and decides nothing: the venue's verdict is the transaction's"
        );

        // The venue's refusal lands before this shard's own certificate.
        // It is not the leg's verdict.
        tick.add_execution_certificate(Arc::new(Verified::new_unchecked_for_test(
            ExecutionCertificate::new(
                TickId::new(venue, BlockHeight::new(1)),
                WeightedTimestamp::from_millis(1_000),
                GlobalReceiptRoot::ZERO,
                vec![TxOutcome::new(leg, ExecutionOutcome::Aborted)],
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ),
        )));
        assert!(
            !tick.determined_ready(),
            "nothing settles before the local certificate"
        );
        assert!(
            !tick.seats[&leg].aborted_anywhere && tick.seats[&leg].covered_by.is_empty(),
            "a shard the leg does not await decides nothing for it"
        );

        tick.add_execution_certificate(Arc::new(Verified::new_unchecked_for_test(
            ExecutionCertificate::new(
                *tick.tick_id(),
                tick.vote_anchor_ts(),
                root,
                outcomes,
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ),
        )));
        let half = tick
            .take_determined_finalization()
            .expect("the local certificate is all it needed");
        assert_eq!(half.execution_certificates().len(), 1, "and all it carries");
        assert!(tick.has_spoken());
    }
}
