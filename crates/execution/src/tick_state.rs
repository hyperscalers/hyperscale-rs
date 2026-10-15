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
//! 4. **States** what its own certificate reached for every member
//!    awaiting another shard, once and whole: the stating half settles
//!    the ones it refused and states a yes for the rest.
//! 5. **Collects certificates** from the shards its members await via
//!    `add_execution_certificate`. A stated member is ready for
//!    finalization once every shard it awaits has covered it (or one
//!    has aborted it, which is terminal-covered), whatever its
//!    tick-mates still wait for.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_engine::legs::Member;
use hyperscale_hbor::Capped;
use hyperscale_types::{
    BlockHash, BlockHeight, ExecutionCertificate, ExecutionOutcome, Finalization,
    GlobalReceiptRoot, Joins, MAX_EXECUTION_CERTIFICATES_PER_TICK, MAX_FINALIZATION_DELAY, Role,
    Settles, ShardId, StoredReceipt, TickHalf, TickId, TxClaim, TxHash, TxOutcome, Verified,
    WeightedTimestamp, compute_global_receipt_root, refused_transactions, settles,
};

/// What a finalization claims of its counterparts' settled sets.
pub(crate) type Claims = Vec<(ShardId, TxHash, TxClaim)>;

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
/// **Reach** is every shard the transaction touches. Who this tick's
/// certificate is owed to is [`Membership::owes_certificate_to`]'s
/// question, asked of reach: waiting on reach would hold a leg behind the
/// core it feeds.
///
/// Both include this shard, and awaited is a subset of reach.
///
/// Beside them, whether this shard's certificate **decides** the
/// transaction: it does unless the member is a leg, whose transaction
/// its core decides. Not a third awaited case — a leg and a single-shard
/// core await the same set — but the one fact the wire cannot derive
/// from that set. And whether the member **executes** the transaction or settles what an execution left:
/// a reclaim, an abandonment, a held record's disposal or a retirement
/// runs no execution of the transaction's own, and the deadline holds
/// only what does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    awaited: BTreeSet<ShardId>,
    reach: BTreeSet<ShardId>,
    role: Role,
}

impl Membership {
    /// The two sets and the role `member` answers — a cache of its
    /// derivation, in the shape a tick carries.
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

    /// This membership for a member that settles what an execution left
    /// rather than executing the transaction: a reclaim, an abandonment,
    /// a held record's disposal. The awaited set stays as stated; the
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

    /// Whether `shard` is owed this member's outcome: every other shard
    /// the transaction reaches, unless the member is a leg. One awaiting
    /// this shard's certificate settles on it, and one consuming a record
    /// the member issued arms its read of the record off it.
    ///
    /// A leg's outcome is owed nowhere: a core awaits the core alone,
    /// and a leg speaks no verdict a producer or sibling reads. A
    /// consumer reads a leg's crossing off the record it pushed, never
    /// off its certificate, so a leg's certificate stays home.
    #[must_use]
    pub fn owes_certificate_to(&self, shard: ShardId, local: ShardId) -> bool {
        shard != local && self.reach.contains(&shard) && self.role != Role::Leg
    }

    /// Whether the transaction touches a shard besides this one — off
    /// what it reaches, never off what this member awaits. A leg of a
    /// divided transaction reaches beyond and awaits only itself.
    #[must_use]
    pub fn reaches_beyond(&self, local: ShardId) -> bool {
        self.reach.iter().any(|&shard| shard != local)
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

/// Where a tick's stating half stands: the one finalization saying what
/// the tick's own certificate reached for every member awaiting another
/// shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stating {
    /// Not handed off, or handed off over members a release has since
    /// taken out of the tick: built once the tick's certificate is
    /// complete, over the awaiting members that stand.
    Owed,
    /// Handed off, and not yet committed.
    Offered,
    /// A committed block carried it. Nothing leaves this: a tick states
    /// once, and its legs settle only from here.
    Committed,
}

/// One member's seat in its tick: the terms it joined on, and everything
/// the tick has learned about it since — from the engine, from the
/// certificates that cover it, and from the chain that settles it.
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)] // independent lifecycle flags, not config knobs
struct Seat {
    /// Whose certificate its settlement waits on, and who its own is
    /// owed to.
    membership: Membership,
    /// What the member was charged, where its tick holds the row its
    /// committing block wrote for it — `None` for a member settling what
    /// an execution left, which its tick holds no row for. Carried apart
    /// from the transaction because an abandoned member has no body here
    /// and still has to attest exactly what was priced.
    charged: Option<u128>,
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
    /// The engine's local receipt, carried by the `Finalization` that
    /// settles the member and dropped once a committed block has.
    /// Scoped to the tick rather than a process-wide cache so a receipt
    /// from a locally-executed transaction cannot leak into a
    /// `Finalization` whose certificate attests it `Aborted`.
    receipt: Option<StoredReceipt>,
    /// The refusal receipt the engine built alongside the execution
    /// receipt: the payer's floor where this shard holds the vault, and
    /// the `Never` answers of a consumer that can be refused. A refusal
    /// settles it: the transaction's own effects are discarded, the
    /// floor and the answers are not.
    refusal_receipt: Option<StoredReceipt>,
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
    /// The tick has stopped speaking for the member: a partner past its
    /// terminal never settled it, so no finalization may name it, and
    /// its deadline is what ends it.
    withdrawn: bool,
}

impl Seat {
    /// A seat on the terms `joins` names.
    const fn new(membership: Membership, charged: Option<u128>, joins: Joins) -> Self {
        Self {
            membership,
            charged,
            awaiting_result: joins.dispatched(),
            aborted: joins.aborts(),
            abandons: matches!(joins, Joins::Aborted),
            result: None,
            receipt: None,
            refusal_receipt: None,
            covered_by: BTreeSet::new(),
            aborted_anywhere: false,
            settled: false,
            withdrawn: false,
        }
    }

    /// Whether the member has the verdict its settlement needs: an
    /// abort anywhere is terminal, and anything else waits for every
    /// awaited shard to have certified it.
    fn is_covered(&self) -> bool {
        self.aborted_anywhere || self.membership.awaited().is_subset(&self.covered_by)
    }

    /// Whether a counterpart shares the verdict on this member: a whole
    /// shape or a core member awaiting a shard other than `local`, which
    /// settles the member against this shard's certificate.
    ///
    /// Read off committed membership alone, never off whether this
    /// replica has handed its own certificate off, so every replica
    /// answers alike on the same commit.
    fn shares_verdict(&self, local: ShardId) -> bool {
        matches!(self.membership.role(), Role::Whole | Role::Core)
            && self.membership.abortable(local)
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
    /// Whether this validator's own outcomes for the tick are fixed:
    /// every dispatched seat came back and `build_vote_data` took the
    /// root over them, to send as its vote or, where the tick's
    /// certificate landed first, only to reconcile against it.
    voted: bool,
    /// The latest anchor this validator re-signed the tick's vote at,
    /// past its own: the tick's committee could not certify it, or the
    /// certificate it held lapsed while the tick was still owed, and a
    /// later committee is attesting it instead.
    reanchored: Option<WeightedTimestamp>,
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
    /// Where the stating half stands.
    stating: Stating,
    /// The members the legs half last handed off names, in the order
    /// the tick's own certificate attests them; empty where none is out.
    /// A legs half is handed off again only where the members it would
    /// name differ from these.
    legs_offered: Vec<TxHash>,
    /// The legs that could settle when the half was last handed off and
    /// were left out of it, each with the claims on its counterparts'
    /// settled sets that were held back. They are not built into a half
    /// again until one of those claims is answered.
    legs_deferred: BTreeMap<TxHash, Claims>,
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
            reanchored: None,
            local_vote_global_receipt_root: None,
            admitted_local_ec_root: None,
            locally_divergent: false,
            divergence: None,
            determined_emitted: false,
            stating: Stating::Owed,
            legs_offered: Vec::new(),
            legs_deferred: BTreeMap::new(),
            local_ec_emitted: false,
            overdue_warned: false,
            execution_certificates: Vec::new(),
        }
    }

    /// Admit a member, on the terms `joins` names.
    ///
    /// One entry point for all three, because they differ only in what
    /// the tick waits for and what it will say. An
    /// [`Aborted`](Joins::Aborted) member joins with no body at all:
    /// its line names it by hash, by the shards party to it, and by the
    /// share its committing block priced, which is everything an abort
    /// has to state. A member the tick already holds keeps the terms it
    /// joined under.
    pub fn admit(
        &mut self,
        tx_hash: TxHash,
        membership: Membership,
        charged: Option<u128>,
        joins: Joins,
    ) {
        if self.seats.contains_key(&tx_hash) {
            return;
        }
        self.order.push(tx_hash);
        self.seats
            .insert(tx_hash, Seat::new(membership, charged, joins));
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

    /// The shards other than this one that some member owes its
    /// outcome to — who this tick's certificate is projected to.
    #[must_use]
    pub fn counterpart_shards(&self) -> Vec<ShardId> {
        let local = self.tick_id.shard_id();
        self.seats
            .values()
            .flat_map(|seat| {
                seat.membership
                    .reach()
                    .iter()
                    .copied()
                    .filter(|&shard| seat.membership.owes_certificate_to(shard, local))
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Every counterpart certificate this tick's members wait on, as
    /// `(member, shard)` pairs — the coverage [`Self::covered_legs`] asks
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

    /// The tick's members whose settlement waits on `shard` — what this
    /// tick is waiting on that shard for.
    pub fn txs_awaiting(&self, shard: ShardId) -> impl Iterator<Item = TxHash> + '_ {
        self.order
            .iter()
            .copied()
            .filter(move |&tx_hash| self.awaits(tx_hash, shard))
    }

    /// The tick's members that owe `shard` their outcome — what its copy
    /// of this tick's certificate carries.
    pub fn txs_reaching(&self, shard: ShardId) -> impl Iterator<Item = TxHash> + '_ {
        let local = self.tick_id.shard_id();
        self.order.iter().copied().filter(move |tx_hash| {
            self.seats
                .get(tx_hash)
                .is_some_and(|seat| seat.membership.owes_certificate_to(shard, local))
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

    /// Record the refusal receipt the engine built beside a member's
    /// execution receipt: what the payer owes and what the consumer
    /// answers if the transaction is refused.
    pub fn record_refusal_receipt(&mut self, receipt: StoredReceipt) {
        if let Some(seat) = self.seats.get_mut(&receipt.tx_hash) {
            seat.refusal_receipt.get_or_insert(receipt);
        }
    }

    /// Number of receipts currently held. Exposed for memory stats; a
    /// member's receipts go once a committed block settles it.
    #[must_use]
    pub fn receipt_count(&self) -> usize {
        self.seats
            .values()
            .filter(|seat| seat.receipt.is_some())
            .count()
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
    /// **Scoped to the members asked about**, since a half carries the
    /// receipts of its own members alone: one missing a receipt holds
    /// only the half that settles it.
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
        let outcomes = self.outcomes();
        let root = compute_global_receipt_root(&outcomes);
        self.voted = true;
        self.local_vote_global_receipt_root = Some(root);
        self.reconcile_local_ec_root();
        Some((self.tick_ts, root, outcomes))
    }

    /// Fix this validator's own outcomes against the tick's complete
    /// certificate where that landed before any vote was built, and
    /// reconcile their root with it. The payload is a vote nobody needs:
    /// the certificate is the committee's answer.
    ///
    /// Only where the seats held are exactly the members the certificate
    /// attests. A replica that seated fewer, one member being a
    /// transaction it could not route, did not run the tick whole: a
    /// root over its subset says nothing about its execution, so it
    /// reconciles nothing and stays unable to state the tick.
    pub(crate) fn reconcile_with_certificate(&mut self) {
        if !self.can_emit_vote() {
            return;
        }
        if self.seats_the_certified_tick() {
            let _ = self.build_vote_data();
        }
    }

    /// Whether the seats held are exactly the members the tick's
    /// complete certificate attests. False until that certificate lands,
    /// on a replica that seated fewer, one member being a transaction it
    /// could not route, and once a release has let seats go.
    fn seats_the_certified_tick(&self) -> bool {
        self.local_certificate().is_some_and(|local| {
            local.tx_outcomes().len() == self.order.len()
                && local
                    .tx_outcomes()
                    .iter()
                    .all(|outcome| self.seats.contains_key(&outcome.tx_hash()))
        })
    }

    /// Re-sign the tick's vote at `anchor`, a later anchor than its own,
    /// for the committee seated there.
    ///
    /// Only once this validator has voted, which means it ran the tick:
    /// the outcomes are the ones it already signed, and the root is the
    /// one its committee would have certified. Once per anchor, and
    /// never at or below the anchor of the local certificate held: a
    /// certificate the tick holds lapses at its own anchor's step like
    /// any other, and a half still owed then needs a later one.
    pub fn revote_at(
        &mut self,
        anchor: WeightedTimestamp,
    ) -> Option<(WeightedTimestamp, GlobalReceiptRoot, Vec<TxOutcome>)> {
        if !self.voted
            || anchor <= self.reanchored.unwrap_or(self.tick_ts)
            || self
                .local_certificate()
                .is_some_and(|held| held.vote_anchor_ts() >= anchor)
        {
            return None;
        }
        let outcomes = self.outcomes();
        let root = compute_global_receipt_root(&outcomes);
        debug_assert_eq!(
            Some(root),
            self.local_vote_global_receipt_root,
            "a re-signed vote restates the vote this validator cast"
        );
        self.reanchored = Some(anchor);
        Some((anchor, root, outcomes))
    }

    /// The outcome each member's vote attests, in composition order.
    ///
    /// # Panics
    ///
    /// If a member has neither a decided abort nor an execution result,
    /// which [`Self::can_emit_vote`] rules out.
    fn outcomes(&self) -> Vec<TxOutcome> {
        let local = self.tick_id.shard_id();
        self.order
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
                let refusal = seat
                    .refusal_receipt
                    .as_ref()
                    .map(|fee| fee.consensus.receipt_hash());
                let attested = match refusal {
                    Some(receipt) => TxOutcome::with_refusal(*tx_hash, outcome, receipt),
                    None => TxOutcome::new(*tx_hash, outcome),
                };
                // What the transaction was charged when its block
                // committed it, and that its row is the one this
                // certificate's finalization deletes.
                match seat.charged {
                    Some(charged) => attested.reserving(charged),
                    None => attested,
                }
                .awaiting(counterparts)
                .as_role(seat.membership.role())
            })
            .collect()
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

    /// Hold `ec`, the tick's own complete certificate signed at a later
    /// anchor than the one held, in that one's place. Returns whether it
    /// did.
    ///
    /// A later committee re-attests a tick whose certificate lapsed while
    /// its half was still owed. The outcomes and root are the held
    /// copy's, so coverage, reconciliation and readiness stand as they
    /// are; only the certificate a half is built from changes, to the one
    /// verifiers still resolve a committee for.
    pub fn adopt_later_certificate(&mut self, ec: &Arc<Verified<ExecutionCertificate>>) -> bool {
        if ec.tick_id() != &self.tick_id || !ec.is_complete() {
            return false;
        }
        let Some(held) = self
            .execution_certificates
            .iter_mut()
            .filter(|held| held.tick_id() == &self.tick_id)
            .find(|held| held.is_complete())
        else {
            return false;
        };
        if ec.vote_anchor_ts() <= held.vote_anchor_ts()
            || ec.global_receipt_root() != held.global_receipt_root()
            || ec.tx_outcomes() != held.tx_outcomes()
        {
            return false;
        }
        *held = Arc::clone(ec);
        true
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

    /// The receipt root this validator's own vote carries, once its run
    /// of the tick has produced one.
    #[must_use]
    pub const fn voted_receipt_root(&self) -> Option<GlobalReceiptRoot> {
        self.local_vote_global_receipt_root
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
    /// validator agreed with it. Receipts are checked per member, since
    /// a half carries only its own.
    const fn attestable(&self) -> bool {
        self.local_ec_emitted && !self.locally_divergent
    }

    /// Whether the determined half can settle now.
    ///
    /// It needs no coverage beyond the tick's own certificate, which is
    /// the whole point: a leg waiting on a counterpart that never comes
    /// cannot hold these members, and the settlement frontier they
    /// advance therefore cannot wedge.
    ///
    /// It needs the seats held to be exactly the members the certificate
    /// attests. A replica that seated fewer still receives the
    /// certificate by broadcast, and its projection to the determined
    /// seats held would settle part of the rows the tick holds for this
    /// half, which no block admits. It does not need this validator to
    /// have run the tick: one that seated it whole and ran none of it
    /// holds every later tick behind this half, and builds the half its
    /// seats alone carry, which is one of nothing but aborts.
    ///
    /// Once a release has let seats go the tick holds no determined
    /// member, so the seats falling short of the certificate then
    /// refuses nothing that could be built.
    #[must_use]
    pub fn determined_ready(&self) -> bool {
        if self.determined_emitted || !self.attestable() || !self.seats_the_certified_tick() {
            return false;
        }
        let members = self.determined_members();
        !members.is_empty() && self.has_local_receipts_for(&members)
    }

    /// The members the stating half speaks for, in composition order:
    /// every one awaiting another shard that no committed block has
    /// settled.
    fn stating_members(&self) -> Vec<TxHash> {
        self.awaiting_tx_hashes()
            .filter(|tx_hash| self.seats.get(tx_hash).is_some_and(|seat| !seat.settled))
            .collect()
    }

    /// Whether this validator holds the receipt each of `members` the
    /// local certificate refused settles in a stating half: the refusal
    /// receipt its outcome names, or its failure record. A member the
    /// certificate succeeded for carries nothing there.
    fn holds_stating_receipts(&self, local: &ExecutionCertificate, members: &[TxHash]) -> bool {
        let stated: Vec<&TxOutcome> = local
            .tx_outcomes()
            .iter()
            .filter(|outcome| members.contains(&outcome.tx_hash()))
            .collect();
        let refused: BTreeSet<TxHash> = stated
            .iter()
            .filter(|outcome| !matches!(outcome.outcome(), ExecutionOutcome::Succeeded { .. }))
            .map(|outcome| outcome.tx_hash())
            .collect();
        stated.into_iter().all(|outcome| {
            let seat = self.seats.get(&outcome.tx_hash());
            match settles(outcome, &refused) {
                Settles::Refusal(_) => seat.is_some_and(|seat| seat.refusal_receipt.is_some()),
                Settles::Failure => seat.is_some_and(|seat| seat.receipt.is_some()),
                Settles::Effects(_) | Settles::Nothing => true,
            }
        })
    }

    /// Whether the stating half can be handed off now: it is owed, this
    /// validator ran every seat of the tick and fixed its own outcomes,
    /// the tick's complete certificate is in hand and its root is the
    /// one over those outcomes, a member awaiting another shard stands,
    /// and this validator holds what the half carries.
    ///
    /// The agreeing root is what says the seats held are the tick's
    /// members. A replica that seated fewer, or ran none of them, still
    /// receives the certificate by broadcast, and its projection to the
    /// seats held would state part of the tick, which no block admits.
    ///
    /// It waits on no counterpart and on no other half of its tick; the
    /// order it settles in beside the determined halves owed up to its
    /// tick is admission's.
    #[must_use]
    pub fn stating_ready(&self) -> bool {
        let members = self.stating_members();
        self.stating == Stating::Owed
            && self.voted
            && self.attestable()
            && !members.is_empty()
            && self
                .local_certificate()
                .is_some_and(|local| self.holds_stating_receipts(local, &members))
    }

    /// Whether the stating half is owed here: never handed off, or
    /// handed off over members a release took out of the tick, so that
    /// no copy held for a block states the tick as it stands.
    #[must_use]
    pub(crate) fn stating_owed(&self) -> bool {
        self.stating == Stating::Owed
    }

    /// Record that a committed block carried this tick's stating half.
    /// The tick states nothing more, and its legs may settle.
    pub(crate) const fn stating_committed(&mut self) {
        self.stating = Stating::Committed;
    }

    /// The legs a half can settle now, in the order the tick's own
    /// certificate attests them: the tick's stating half has committed,
    /// each has its verdict, this validator holds the receipt it
    /// settles, no committed block has settled it, and the tick has not
    /// stopped speaking for it. A leg still waiting on a counterpart is
    /// not among them, and holds none of its tick-mates. A member the
    /// certificate refused is none: the stating half's commit settled
    /// it.
    ///
    /// Their certificate does not wait on the determined half's. The two
    /// cannot produce conflicting absolutes, because composition claims a
    /// leg's declared access before testing any determined member: the
    /// pair is admitted together only where both reach the cell
    /// commutatively. A leg's debit may still rest on a determined
    /// member's credit, so a block carries a legs half only behind the
    /// determined halves the chain owes up to this tick; that order is
    /// admission's, and the half is ready to be offered without it.
    #[must_use]
    fn covered_legs(&self) -> Vec<TxHash> {
        let Some(local_ec) = self
            .local_certificate()
            .filter(|_| self.attestable() && self.stating == Stating::Committed)
        else {
            return Vec::new();
        };
        local_ec
            .tx_outcomes()
            .iter()
            .filter(|outcome| {
                self.awaits_beyond(outcome.tx_hash())
                    && self.seats.get(&outcome.tx_hash()).is_some_and(|seat| {
                        !seat.settled
                            && !seat.withdrawn
                            && seat.is_covered()
                            && (outcome.is_aborted() || seat.receipt.is_some())
                    })
            })
            .inspect(|outcome| {
                debug_assert!(
                    matches!(outcome.outcome(), ExecutionOutcome::Succeeded { .. }),
                    "a legs half names only members the committed stating half stated"
                );
            })
            .map(TxOutcome::tx_hash)
            .collect()
    }

    /// Whether the legs half is due: the legs that can settle now are
    /// not exactly the ones the half last handed off names and the ones
    /// it left out.
    #[must_use]
    pub fn legs_ready(&self) -> bool {
        let covered = self.covered_legs();
        let asked: HashSet<&TxHash> = self
            .legs_offered
            .iter()
            .chain(self.legs_deferred.keys())
            .collect();
        covered.len() != asked.len() || covered.iter().any(|tx_hash| !asked.contains(tx_hash))
    }

    /// Record that the legs half handed off names `names`, leaving out
    /// `deferred`, legs that could settle but for the claims given.
    /// Returns whether `names` differ from those of the half handed off
    /// before it, which it then replaces.
    pub(crate) fn offer_legs(
        &mut self,
        names: Vec<TxHash>,
        deferred: BTreeMap<TxHash, Claims>,
    ) -> bool {
        self.legs_deferred = deferred;
        if names == self.legs_offered {
            return false;
        }
        self.legs_offered = names;
        true
    }

    /// The legs left out of the half last handed off, each with the
    /// claims held back.
    pub(crate) const fn deferred_legs(&self) -> &BTreeMap<TxHash, Claims> {
        &self.legs_deferred
    }

    /// Ask about `tx_hash` again: a claim that held it back has an
    /// answer, so the next legs half is built with it.
    pub(crate) fn reask_leg(&mut self, tx_hash: TxHash) {
        self.legs_deferred.remove(&tx_hash);
    }

    /// Stop speaking for `names`: no legs half names them again.
    pub(crate) fn withdraw_legs(&mut self, names: &[TxHash]) {
        for tx_hash in names {
            if let Some(seat) = self.seats.get_mut(tx_hash) {
                seat.withdrawn = true;
            }
            self.legs_deferred.remove(tx_hash);
        }
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

    /// The anchor whose committee would have to attest this tick.
    #[must_use]
    pub const fn anchor(&self) -> WeightedTimestamp {
        self.tick_ts
    }

    /// Whether the determined half is out of the way — emitted, or never
    /// existed because the tick ran nothing but legs.
    fn determined_emitted_or_absent(&self) -> bool {
        self.determined_emitted || self.determined_members().is_empty()
    }

    /// Whether the tick's own certificate refused `tx_hash`: the stating
    /// half is all the tick says of such a member.
    fn refused_here(&self, tx_hash: TxHash) -> bool {
        self.local_certificate().is_some_and(|local| {
            local.tx_outcomes().iter().any(|outcome| {
                outcome.tx_hash() == tx_hash
                    && !matches!(outcome.outcome(), ExecutionOutcome::Succeeded { .. })
            })
        })
    }

    /// Whether this tick has said everything it will say: its
    /// determined half is out of the way, its stating half is handed
    /// off or has no member left to state, and every member awaiting
    /// another shard is one its certificate refused, or is settled,
    /// withdrawn, or named by the legs half handed off.
    #[must_use]
    pub fn has_spoken(&self) -> bool {
        self.determined_emitted_or_absent()
            && (self.stating != Stating::Owed || self.stating_members().is_empty())
            && self.awaiting_tx_hashes().all(|tx_hash| {
                self.legs_offered.contains(&tx_hash)
                    || self.refused_here(tx_hash)
                    || self
                        .seats
                        .get(&tx_hash)
                        .is_some_and(|seat| seat.settled || seat.withdrawn)
            })
    }

    /// Record that a committed finalization resolved these members, and
    /// let go of the receipts it carried for them. Returns whether every
    /// member of the tick is now settled, which is when its certificate
    /// and tracking state can be dropped.
    ///
    /// A legs half handed off that names one of them settles nothing
    /// more: a block naming a settled member is refused, so the half is
    /// due again for the legs it named that still stand.
    pub fn record_settled(&mut self, tx_hashes: impl IntoIterator<Item = TxHash>) -> bool {
        for tx_hash in tx_hashes {
            if let Some(seat) = self.seats.get_mut(&tx_hash) {
                seat.settled = true;
                seat.receipt = None;
                seat.refusal_receipt = None;
                self.legs_deferred.remove(&tx_hash);
                if self.legs_offered.contains(&tx_hash) {
                    self.legs_offered.clear();
                }
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
            stating_ready = self.stating_ready(),
            legs_ready = self.legs_ready(),
            determined_emitted = self.determined_emitted,
            stating = ?self.stating,
            legs_offered = self.legs_offered.len(),
            missing_coverage = missing_coverage.join(" "),
            "Tick overdue: unresolved past the deadline that bounds every member"
        );
    }

    /// Build one half's attestation: the tick's own certificate
    /// projected to `members`, plus the counterpart certificates those
    /// members still need a verdict from.
    ///
    /// **The projection is what makes each half account for itself.**
    /// The certificate a half carries attests exactly `members`, which
    /// are the transactions it names and the rows it deletes: every
    /// member of the determined half, and the legs a legs half settles
    /// now. Every projection verifies under the same signed root and
    /// signature as the copy it came from.
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
    /// Returns `None` when this half has no members, when the local
    /// certificate has not landed yet, or when the certificates the half
    /// needs outgrow what one finalization carries.
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

        // The certificates are the proof, so a shorter list proves less
        // than the members need and truncating one would assert a
        // verdict nothing carries. A half whose evidence outgrows what a
        // finalization holds is one this node cannot attest to, and
        // declining leaves the half for the next pass — the caller marks
        // it emitted only on a `Some`.
        let carried = ecs.len();
        let Ok(ecs) = Capped::new(ecs) else {
            tracing::error!(
                tick = %self.tick_id,
                ?half,
                carried,
                cap = MAX_EXECUTION_CERTIFICATES_PER_TICK,
                "a half's certificates outgrow one finalization; not attesting to it"
            );
            return None;
        };

        Some(Finalization::from_verified_ecs(self.tick_id, half, &ecs))
    }

    /// `attestation` carrying one stored receipt per outcome it settles
    /// anything of, in the certificate's canonical order.
    ///
    /// Which side of an outcome settles is [`settles`]'s question, read
    /// against the whole certificate rather than against this shard's own
    /// verdict: a leg that completed here and was refused by a counterpart
    /// settles its charge, not its effects. Peers re-derive the same rule
    /// through `validate_against_certificates` at ingress.
    ///
    /// The seats keep their receipts until a committed block settles
    /// them: a legs half is built again as the legs it can name change,
    /// and each one carries the receipts of every member it names.
    fn with_receipts(&self, attestation: Finalization) -> Finalization {
        let refused = refused_transactions(attestation.execution_certificates());
        let mut receipts: Vec<StoredReceipt> = Vec::with_capacity(attestation.tx_count());
        for outcome in attestation.settled_outcomes() {
            let seat = self.seats.get(&outcome.tx_hash());
            let held = match settles(outcome, &refused) {
                // The charge stands in for whatever the transaction did:
                // a `Failed` receipt carries nothing, and a completed
                // leg's effects are discarded by the refusal. Either way
                // the pairing stays one receipt per outcome.
                Settles::Refusal(_) => seat.and_then(|seat| seat.refusal_receipt.clone()),
                Settles::Effects(_) | Settles::Failure => {
                    seat.and_then(|seat| seat.receipt.clone())
                }
                Settles::Nothing => continue,
            };
            if let Some(receipt) = held {
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
        attestation.with_receipts(
            Capped::new(receipts).expect("a list under the cap its source already met"),
        )
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
        Some(self.with_receipts(attestation))
    }

    /// Take the stating half's finalization, if it is ready: the tick's
    /// own certificate projected to the members awaiting another shard
    /// that stand unsettled, carrying no counterpart's certificate, with
    /// the receipt each refused member settles.
    ///
    /// It states every such member or none, since a block admits only a
    /// stating half that accounts for every row its tick holds outside
    /// the determined half. A release that takes one of them out of the
    /// tick owes the half again, built over the members that remain.
    pub fn take_stating_finalization(&mut self) -> Option<Finalization> {
        if !self.stating_ready() {
            return None;
        }
        let members: HashSet<TxHash> = self.stating_members().into_iter().collect();
        let projected = self.local_certificate()?.project_to(&members)?;
        let attestation = Finalization::from_verified_ecs(
            self.tick_id,
            TickHalf::Stated,
            &Capped::from_array([projected]),
        );
        self.stating = Stating::Offered;
        Some(self.with_receipts(attestation))
    }

    /// A legs half naming every leg that can settle now, where there is
    /// one.
    ///
    /// Building it hands nothing off: the caller narrows it to the
    /// members it may offer and records them through
    /// [`Self::offer_legs`], and the half then replaces the one handed
    /// off before, which named other legs or one a committed block has
    /// since settled.
    #[must_use]
    pub(crate) fn legs_half(&self) -> Option<Finalization> {
        let names = self.covered_legs();
        if names.is_empty() {
            return None;
        }
        let members: HashSet<TxHash> = names.into_iter().collect();
        let attestation = self.attestation_for(TickHalf::Legs, &members)?;
        Some(self.with_receipts(attestation))
    }

    /// Release every member sharing no verdict with a counterpart, and
    /// `abandoned` whatever it shares. Returns the released members and
    /// the kept ones, each in composition order.
    ///
    /// What stays is a member a counterpart can settle against this
    /// shard's certificate, which outlives the tick: dropped here,
    /// nothing would settle it, and its entry being certified, nothing
    /// would abandon it. Every determined seat goes, so the tick owes no
    /// determined half afterwards; the legs half is owed again for the
    /// kept legs, since one handed off before may name a released
    /// member. A stating half handed off and not yet committed is owed
    /// again: a release takes at least the member it abandons, which the
    /// half states, and no block admits a half stating a member its tick
    /// no longer holds, so the half is built once more over the members
    /// kept. A committed one stands.
    pub fn release(&mut self, abandoned: Option<TxHash>) -> (Vec<TxHash>, Vec<TxHash>) {
        let local = self.tick_id.shard_id();
        let (kept, released): (Vec<TxHash>, Vec<TxHash>) =
            self.order.iter().copied().partition(|&tx_hash| {
                Some(tx_hash) != abandoned
                    && self
                        .seats
                        .get(&tx_hash)
                        .is_some_and(|seat| seat.shares_verdict(local))
            });
        if self.stating == Stating::Offered {
            self.stating = Stating::Owed;
        }
        for tx_hash in &released {
            self.seats.remove(tx_hash);
        }
        self.order.clone_from(&kept);
        self.legs_offered.clear();
        self.legs_deferred.clear();
        (released, kept)
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_engine::legs::Classified;
    use hyperscale_types::{
        AggregateSignature, ConsensusReceipt, GlobalReceiptHash, Hash, SignerBitfield,
    };

    use super::*;

    /// Two replicas, one with its own certificate in hand and one
    /// without, release the same members on the same commit: what stays
    /// is read off committed membership alone.
    #[test]
    fn a_release_reads_committed_membership_alone() {
        let local = ShardId::leaf(1, 0);
        let peer = ShardId::leaf(1, 1);
        let tick_id = TickId::new(local, BlockHeight::new(1));
        let shared = TxHash::from(Hash::from_bytes(&[1; 32]));
        let alone = TxHash::from(Hash::from_bytes(&[2; 32]));
        let holding = || {
            let mut tick = TickState::new(tick_id, BlockHash::ZERO, WeightedTimestamp::ZERO);
            tick.admit(
                shared,
                Membership::whole(BTreeSet::from([local, peer])),
                None,
                Joins::Executes,
            );
            tick.admit(
                alone,
                Membership::whole(BTreeSet::from([local])),
                None,
                Joins::Executes,
            );
            tick
        };
        let mut emitted = holding();
        emitted.add_execution_certificate(Arc::new(Verified::new_unchecked_for_test(
            ExecutionCertificate::new(
                tick_id,
                WeightedTimestamp::ZERO,
                GlobalReceiptRoot::ZERO,
                Capped::from_array([
                    TxOutcome::new(shared, ExecutionOutcome::Aborted),
                    TxOutcome::new(alone, ExecutionOutcome::Aborted),
                ]),
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ),
        )));
        assert!(emitted.local_ec_emitted());
        let mut pending = holding();
        assert!(!pending.local_ec_emitted());

        assert_eq!(emitted.release(None), (vec![alone], vec![shared]));
        assert_eq!(pending.release(None), (vec![alone], vec![shared]));
        assert_eq!(emitted.tx_hashes(), &[shared]);
        assert!(
            !emitted.determined_unsettled(),
            "a kept tick owes no determined half",
        );
        assert_eq!(
            holding().release(Some(shared)),
            (vec![shared, alone], vec![]),
            "the abandoned member goes whatever it shares",
        );
    }

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
                beacon_witness_events: Capped::empty(),
                events: Capped::empty(),
            }),
        }
    }

    fn shard(index: u64) -> ShardId {
        ShardId::leaf(1, index)
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
            Some(10),
            Joins::Executes,
        );
        tick.admit(
            leg,
            Membership::whole(BTreeSet::from([local, shard(1)])),
            Some(20),
            Joins::Executes,
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
                Capped::new(outcomes).expect("a list written out in a test"),
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
            Some(10),
            Joins::Executes,
        );
        let from_peer = |counterparts: Vec<ShardId>| {
            Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
                TickId::new(peer, BlockHeight::new(7)),
                WeightedTimestamp::from_millis(1_000),
                GlobalReceiptRoot::ZERO,
                Capped::from_array([TxOutcome::new(
                    member,
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                )
                .awaiting(counterparts)]),
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
            Some(10),
            Joins::Executes,
        );
        tick.admit(
            leg,
            Membership::whole(BTreeSet::from([local, shard(1)])),
            Some(20),
            Joins::Executes,
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
                Capped::new(outcomes).expect("a list written out in a test"),
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ),
        )));
        tick.add_execution_certificate(Arc::new(Verified::new_unchecked_for_test(
            ExecutionCertificate::new(
                TickId::new(shard(1), BlockHeight::new(4)),
                WeightedTimestamp::from_millis(1_000),
                GlobalReceiptRoot::ZERO,
                Capped::from_array([TxOutcome::new(
                    leg,
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                )
                .awaiting([local])]),
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ),
        )));

        assert!(
            !tick.determined_ready(),
            "the determined half is missing the receipt it would settle",
        );
        assert!(
            !tick.legs_ready(),
            "no leg settles before the tick's stating half commits",
        );
        let stated = state(&mut tick);
        assert_eq!(
            stated
                .stated_outcomes()
                .map(TxOutcome::tx_hash)
                .collect::<Vec<_>>(),
            vec![leg],
            "the stating half waits on the determined receipt no more than the legs do",
        );
        assert!(tick.legs_ready(), "and the legs are ready regardless");
        let half = take_legs(&mut tick).expect("covered and receipted");
        assert_eq!(half.tx_hashes().collect::<Vec<_>>(), vec![leg]);
        assert_eq!(half.half(), TickHalf::Legs);
    }

    /// Hand off the tick's stating half and commit it, as the block that
    /// carries it does: the members it refused are settled, and the
    /// tick's legs may follow.
    fn state(tick: &mut TickState) -> Finalization {
        let half = tick
            .take_stating_finalization()
            .expect("the tick's own certificate is all its stating half needs");
        assert_eq!(half.half(), TickHalf::Stated);
        assert_eq!(half.validate_against_certificates(), Ok(()));
        assert_eq!(
            half.execution_certificates().len(),
            1,
            "a stating half carries no counterpart's certificate",
        );
        tick.stating_committed();
        tick.record_settled(half.tx_hashes());
        half
    }

    /// Hand off the legs half as a caller that narrows nothing does.
    fn take_legs(tick: &mut TickState) -> Option<Finalization> {
        let half = tick.legs_ready().then(|| tick.legs_half()).flatten()?;
        tick.offer_legs(half.tx_hashes().collect(), BTreeMap::new());
        Some(half)
    }

    /// How many of the half's outcomes name a row their finalization
    /// deletes.
    fn reserved_in(half: &Finalization) -> usize {
        half.local_ec()
            .tx_outcomes()
            .iter()
            .filter(|outcome| outcome.reserved())
            .count()
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
            (reserved_in(&half), half.charged()),
            (1, 10),
            "and settles only what those members reserved",
        );
        assert!(!tick.has_spoken(), "the leg is still owed a verdict");

        // The counterpart still never certifies.
        assert!(!tick.legs_ready());
        assert!(take_legs(&mut tick).is_none());
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
                Capped::from_array([TxOutcome::new(
                    leg,
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                )
                .awaiting([shard(0)])]),
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ),
        )));

        assert!(
            !tick.legs_ready() && !tick.has_spoken(),
            "covered, and still behind the stating half",
        );
        let stated = state(&mut tick);
        assert_eq!(
            (stated.tx_count(), stated.charged()),
            (0, 20),
            "the stating half settles nothing of a yes and is where it is charged",
        );

        assert!(tick.legs_ready());
        let half = take_legs(&mut tick).expect("covered");
        assert_eq!(half.tx_hashes().collect::<Vec<_>>(), vec![leg]);
        assert_eq!(
            (reserved_in(&half), half.charged()),
            (1, 0),
            "the legs half charges nothing: the stating half counted the member",
        );
        assert!(tick.has_spoken());
    }

    /// A core member this shard's own run refused settles in the stating
    /// half, on its refusal receipt and on no counterpart's certificate,
    /// beside a tick-mate the half states a yes for. No legs half ever
    /// names it, whatever its counterpart then certifies.
    #[test]
    fn a_member_refused_locally_settles_in_its_stating_block() {
        let local = shard(0);
        let (accepted, refused) = (tx(1), tx(2));
        let refusal = receipt(refused);
        let running = |holds_refusal: bool| {
            let mut tick = TickState::new(
                TickId::new(local, BlockHeight::new(1)),
                BlockHash::ZERO,
                WeightedTimestamp::from_millis(1_000),
            );
            for (tx_hash, charged) in [(accepted, 10), (refused, 20)] {
                tick.admit(
                    tx_hash,
                    Membership::whole(BTreeSet::from([local, shard(1)])),
                    Some(charged),
                    Joins::Executes,
                );
            }
            tick.record_execution_result(
                accepted,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            );
            tick.record_receipt(receipt(accepted));
            tick.record_execution_result(refused, ExecutionOutcome::Failed);
            tick.record_refusal_receipt(refusal.clone());
            let (_, root, outcomes) = tick.build_vote_data().expect("every member came back");
            if !holds_refusal {
                tick.seats
                    .get_mut(&refused)
                    .expect("seated above")
                    .refusal_receipt = None;
            }
            tick.add_execution_certificate(Arc::new(Verified::new_unchecked_for_test(
                ExecutionCertificate::new(
                    *tick.tick_id(),
                    tick.vote_anchor_ts(),
                    root,
                    Capped::new(outcomes).expect("a list written out in a test"),
                    AggregateSignature::ZERO,
                    SignerBitfield::new(4),
                ),
            )));
            tick
        };

        let mut short = running(false);
        assert!(
            !short.stating_ready() && short.take_stating_finalization().is_none(),
            "a validator without the refusal receipt hands off no stating half",
        );

        let mut tick = running(true);
        // The counterpart certifies both before the tick has stated.
        for (height, tx_hash) in [(4, accepted), (5, refused)] {
            tick.add_execution_certificate(counterpart(height, tx_hash));
        }
        assert!(tick.stating_ready() && !tick.legs_ready());
        let half = state(&mut tick);
        assert_eq!(half.tx_hashes().collect::<Vec<_>>(), vec![refused]);
        assert_eq!(half.receipts(), &vec![refusal]);
        assert_eq!(half.settling_receipts().len(), 1);
        assert_eq!(
            half.stated_outcomes()
                .map(TxOutcome::tx_hash)
                .collect::<Vec<_>>(),
            vec![accepted],
        );
        assert_eq!((half.tx_count(), half.charged()), (1, 30));
        assert!(
            tick.seats[&refused].settled && !tick.seats[&accepted].settled,
            "the refusal settled in the stating block, and the yes waits",
        );
        assert!(
            !tick.stating_ready() && tick.take_stating_finalization().is_none(),
            "a tick states once",
        );

        let legs = take_legs(&mut tick).expect("the yes is covered");
        assert_eq!(legs.tx_hashes().collect::<Vec<_>>(), vec![accepted]);
        assert!(tick.has_spoken());
        assert!(tick.record_settled([accepted]), "and the tick is done");
    }

    /// An abort with a reach, seated from its line and never run, awaits
    /// shards beyond this one and settles in the stating half on its
    /// refusal receipt: the tick's own certificate is its verdict. It
    /// states no yes, owes no legs half, and the tick is done once the
    /// stating half commits.
    #[test]
    fn an_abort_with_a_reach_settles_in_the_stating_half() {
        let local = shard(0);
        let aborted = tx(1);
        let mut tick = TickState::new(
            TickId::new(local, BlockHeight::new(1)),
            BlockHash::ZERO,
            WeightedTimestamp::from_millis(1_000),
        );
        tick.admit(
            aborted,
            Membership::whole(BTreeSet::from([local, shard(1)])).settling(),
            Some(7),
            Joins::Aborted,
        );
        let charge = receipt(aborted);
        tick.record_refusal_receipt(charge.clone());
        assert!(tick.determined_members().is_empty());
        let (_, root, outcomes) = tick.build_vote_data().expect("an abort waits on no engine");
        assert!(outcomes[0].is_aborted() && outcomes[0].reserved());
        tick.add_execution_certificate(Arc::new(Verified::new_unchecked_for_test(
            ExecutionCertificate::new(
                *tick.tick_id(),
                tick.vote_anchor_ts(),
                root,
                Capped::new(outcomes).expect("a list written out in a test"),
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ),
        )));

        assert!(
            !tick.legs_ready() && !tick.has_spoken(),
            "no legs half names an abort, and the tick has yet to state it",
        );
        let half = tick
            .take_stating_finalization()
            .expect("the abort is the tick's own to state");
        assert!(
            tick.has_spoken(),
            "handed off, the tick has said all it will"
        );
        assert_eq!(half.tx_hashes().collect::<Vec<_>>(), vec![aborted]);
        assert_eq!(half.stated_outcomes().count(), 0);
        assert_eq!(half.receipts(), &vec![charge]);
        assert_eq!(half.validate_against_certificates(), Ok(()));
        assert_eq!((half.tx_count(), half.charged()), (1, 7));

        tick.stating_committed();
        assert!(
            tick.record_settled(half.tx_hashes()),
            "the stating half's commit resolves the whole tick",
        );
        assert!(!tick.legs_ready());
    }

    /// A release owes a handed-off stating half again, over the members
    /// kept, and nothing reopens a stating half a block has committed.
    #[test]
    fn a_release_owes_the_stating_half_again_until_it_commits() {
        let (mut tick, near, far) = two_leg_tick();
        let first = tick.take_stating_finalization().expect("ready");
        assert_eq!(first.stated_outcomes().count(), 2);
        assert!(!tick.stating_owed() && !tick.stating_ready());

        assert_eq!(tick.release(Some(far)), (vec![far], vec![near]));
        assert!(tick.stating_owed() && tick.stating_ready());
        let again = tick.take_stating_finalization().expect("owed again");
        assert_eq!(
            again
                .stated_outcomes()
                .map(TxOutcome::tx_hash)
                .collect::<Vec<_>>(),
            vec![near],
            "built over the member the release kept",
        );
        assert_ne!(again.receipt_hash(), first.receipt_hash());

        let (mut committed, near, far) = two_leg_tick();
        state(&mut committed);
        assert_eq!(committed.release(Some(far)), (vec![far], vec![near]));
        assert!(
            !committed.stating_owed() && committed.take_stating_finalization().is_none(),
            "a tick states once, whatever a later discard takes",
        );
        committed.add_execution_certificate(counterpart(4, near));
        let legs = take_legs(&mut committed).expect("the kept member's legs half follows");
        assert_eq!(legs.tx_hashes().collect::<Vec<_>>(), vec![near]);
    }

    /// A replica hands off a stating half only for a tick it ran and
    /// voted as its committee certified it. One that seated a strict
    /// subset of the tick's members, or seated them all and never ran
    /// them, still receives the tick's complete certificate by
    /// broadcast: projecting it to the seats held would state part of
    /// the tick, which no block admits, and latch the half as handed
    /// off.
    #[test]
    fn a_replica_that_did_not_vote_the_tick_states_nothing() {
        let local = shard(0);
        let (voter, near, far) = two_leg_tick();
        let certificate = Arc::clone(voter.local_certificate().expect("certified"));
        let succeeded = ExecutionOutcome::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
        };
        let seating = |members: &[TxHash]| {
            let mut tick = TickState::new(
                TickId::new(local, BlockHeight::new(1)),
                BlockHash::ZERO,
                WeightedTimestamp::from_millis(1_000),
            );
            for &tx_hash in members {
                tick.admit(
                    tx_hash,
                    Membership::whole(BTreeSet::from([local, shard(1)])),
                    Some(10),
                    Joins::Executes,
                );
            }
            tick
        };
        let states_nothing = |tick: &mut TickState, replica: &str| {
            assert!(tick.local_ec_emitted(), "{replica}: the certificate landed");
            assert!(
                !tick.stating_ready() && tick.take_stating_finalization().is_none(),
                "{replica}: no stating half is handed off",
            );
            assert!(tick.stating_owed(), "{replica}: and none is latched");
        };

        let mut subset = seating(&[near]);
        subset.record_execution_result(near, succeeded.clone());
        subset.record_receipt(receipt(near));
        subset.add_execution_certificate(Arc::clone(&certificate));
        states_nothing(&mut subset, "a strict subset, unvoted");

        let mut disagreeing = seating(&[near]);
        disagreeing.record_execution_result(near, succeeded);
        disagreeing.record_receipt(receipt(near));
        disagreeing
            .build_vote_data()
            .expect("its one seat came back");
        disagreeing.add_execution_certificate(Arc::clone(&certificate));
        states_nothing(&mut disagreeing, "a strict subset, voted on another root");

        let mut idle = seating(&[near, far]);
        idle.add_execution_certificate(certificate);
        states_nothing(&mut idle, "every seat, never run");
    }

    /// A replica hands off a determined half only over every member its
    /// tick settles in one. One that seated the tick without a member it
    /// could not route runs none of it and casts no vote, and still
    /// receives the tick's complete certificate by broadcast: where every
    /// determined member it did seat is an abort, which needs no receipt,
    /// the certificate projected to the seats held settles part of the
    /// tick's determined half and leaves the unseated member out.
    #[test]
    fn a_replica_seating_part_of_a_tick_hands_off_no_determined_half() {
        let local = shard(0);
        let (unrouted, aborted, shared) = (tx(1), tx(2), tx(3));
        let succeeded = || ExecutionOutcome::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
        };
        let seating = |members: &[TxHash]| {
            let mut tick = TickState::new(
                TickId::new(local, BlockHeight::new(1)),
                BlockHash::ZERO,
                WeightedTimestamp::from_millis(1_000),
            );
            for &tx_hash in members {
                if tx_hash == aborted {
                    tick.admit(
                        tx_hash,
                        Membership::whole(BTreeSet::from([local])).settling(),
                        Some(5),
                        Joins::Aborted,
                    );
                } else {
                    let awaited = if tx_hash == shared {
                        BTreeSet::from([local, shard(1)])
                    } else {
                        BTreeSet::from([local])
                    };
                    tick.admit(
                        tx_hash,
                        Membership::whole(awaited),
                        Some(10),
                        Joins::Executes,
                    );
                }
            }
            tick
        };

        let mut voter = seating(&[unrouted, aborted, shared]);
        for tx_hash in [unrouted, shared] {
            voter.record_execution_result(tx_hash, succeeded());
            voter.record_receipt(receipt(tx_hash));
        }
        let (_, root, outcomes) = voter.build_vote_data().expect("every member came back");
        let certificate = Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
            *voter.tick_id(),
            voter.vote_anchor_ts(),
            root,
            Capped::new(outcomes).expect("a list written out in a test"),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        )));
        voter.add_execution_certificate(Arc::clone(&certificate));
        let whole = voter
            .take_determined_finalization()
            .expect("the voter settles its determined half");
        assert_eq!(
            whole.tx_hashes().collect::<Vec<_>>(),
            vec![unrouted, aborted]
        );

        let mut subset = seating(&[aborted, shared]);
        assert!(!subset.can_emit_vote(), "its one run seat never came back");
        subset.add_execution_certificate(Arc::clone(&certificate));
        assert!(subset.local_ec_emitted() && !subset.is_locally_divergent());
        let half = subset.take_determined_finalization();
        assert_eq!(
            half.as_ref().map(|half| (
                half.tx_hashes().collect::<Vec<_>>(),
                half.validate_against_certificates(),
            )),
            None,
            "a replica seating part of the tick hands off a determined half over part of {:?}",
            whole.tx_hashes().collect::<Vec<_>>(),
        );
        assert!(subset.determined_pending(), "and none is latched");

        // A replica whose batch came back after the certificate landed
        // casts no vote, and builds the whole half over outcomes fixed
        // against the certificate.
        let mut late = seating(&[unrouted, aborted, shared]);
        late.add_execution_certificate(certificate);
        for tx_hash in [unrouted, shared] {
            late.record_execution_result(tx_hash, succeeded());
            late.record_receipt(receipt(tx_hash));
        }
        late.reconcile_with_certificate();
        assert!(!late.is_locally_divergent());
        let reconciled = late
            .take_determined_finalization()
            .expect("the seats held are the tick's members");
        assert_eq!(reconciled.receipt_hash(), whole.receipt_hash());
    }

    /// A replica that seated a tick whole and ran none of it hands off
    /// the determined half its seats alone can build: one whose every
    /// member is an abort, settled on the refusal receipt its seating
    /// built. Such a replica holds dispatch of every later tick behind
    /// this one's determined half, so where no replica that ran the tick
    /// still holds it, this is the half the chain waits on.
    #[test]
    fn a_replica_that_seated_a_tick_whole_and_never_ran_it_settles_its_aborts() {
        let local = shard(0);
        let (aborted, shared) = (tx(1), tx(2));
        let seating = || {
            let mut tick = TickState::new(
                TickId::new(local, BlockHeight::new(1)),
                BlockHash::ZERO,
                WeightedTimestamp::from_millis(1_000),
            );
            tick.admit(
                aborted,
                Membership::whole(BTreeSet::from([local])).settling(),
                Some(5),
                Joins::Aborted,
            );
            tick.record_refusal_receipt(receipt(aborted));
            tick.admit(
                shared,
                Membership::whole(BTreeSet::from([local, shard(1)])),
                Some(10),
                Joins::Executes,
            );
            tick
        };

        let mut voter = seating();
        voter.record_execution_result(
            shared,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        );
        voter.record_receipt(receipt(shared));
        let (_, root, outcomes) = voter.build_vote_data().expect("every member came back");
        let certificate = Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
            *voter.tick_id(),
            voter.vote_anchor_ts(),
            root,
            Capped::new(outcomes).expect("a list written out in a test"),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        )));
        voter.add_execution_certificate(Arc::clone(&certificate));
        let whole = voter
            .take_determined_finalization()
            .expect("the voter settles its determined half");

        let mut held = seating();
        assert!(!held.can_emit_vote(), "its run seat never came back");
        held.add_execution_certificate(certificate);
        let half = held
            .take_determined_finalization()
            .expect("the seats held are the tick's members, and its aborts need no run");
        assert_eq!(half.tx_hashes().collect::<Vec<_>>(), vec![aborted]);
        assert_eq!(half.validate_against_certificates(), Ok(()));
        assert_eq!(half.receipt_hash(), whole.receipt_hash());
        assert!(
            !held.stating_ready(),
            "it states nothing of a member it never ran",
        );
    }

    /// A tick whose every member reaches no engine is voted by every
    /// replica seating it, each of which hands off its determined half:
    /// a tick of nothing but aborts, which waits on no batch.
    #[test]
    fn a_tick_of_nothing_but_aborts_hands_off_its_determined_half() {
        let local = shard(0);
        let mut tick = TickState::new(
            TickId::new(local, BlockHeight::new(1)),
            BlockHash::ZERO,
            WeightedTimestamp::from_millis(1_000),
        );
        for tx_hash in [tx(1), tx(2)] {
            tick.admit(
                tx_hash,
                Membership::whole(BTreeSet::from([local])).settling(),
                Some(5),
                Joins::Aborted,
            );
        }
        let (_, root, outcomes) = tick.build_vote_data().expect("an abort waits on no engine");
        tick.add_execution_certificate(Arc::new(Verified::new_unchecked_for_test(
            ExecutionCertificate::new(
                *tick.tick_id(),
                tick.vote_anchor_ts(),
                root,
                Capped::new(outcomes).expect("a list written out in a test"),
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ),
        )));
        let half = tick
            .take_determined_finalization()
            .expect("a replica that voted the tick settles it");
        assert_eq!(half.tx_hashes().collect::<Vec<_>>(), vec![tx(1), tx(2)]);
        assert_eq!(half.validate_against_certificates(), Ok(()));
    }

    /// A tick at `shard(0)` running two members `shard(1)` shares the
    /// verdict on, both executed, both holding a receipt, its own
    /// certificate in hand.
    fn two_leg_tick() -> (TickState, TxHash, TxHash) {
        let local = shard(0);
        let (near, far) = (tx(1), tx(2));
        let mut tick = TickState::new(
            TickId::new(local, BlockHeight::new(1)),
            BlockHash::ZERO,
            WeightedTimestamp::from_millis(1_000),
        );
        for (tx_hash, charged) in [(near, 10), (far, 20)] {
            tick.admit(
                tx_hash,
                Membership::whole(BTreeSet::from([local, shard(1)])),
                Some(charged),
                Joins::Executes,
            );
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
                Capped::new(outcomes).expect("a list written out in a test"),
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ),
        )));
        (tick, near, far)
    }

    /// `shard(1)`'s certificate of its tick at `height`, attesting
    /// `tx_hash` succeeded there awaiting `shard(0)`.
    fn counterpart(height: u64, tx_hash: TxHash) -> Arc<Verified<ExecutionCertificate>> {
        Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
            TickId::new(shard(1), BlockHeight::new(height)),
            WeightedTimestamp::from_millis(1_000),
            GlobalReceiptRoot::ZERO,
            Capped::from_array([TxOutcome::new(
                tx_hash,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            )
            .awaiting([shard(0)])]),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        )))
    }

    /// A leg whose counterpart has certified is offered while its
    /// tick-mate still waits. The half offered names every covered leg
    /// no committed block has settled, so it is taken again exactly when
    /// those names change: as coverage grows, and as a block settles one.
    #[test]
    fn a_covered_leg_is_offered_beside_an_uncovered_tick_mate() {
        let (mut tick, near, far) = two_leg_tick();
        assert!(take_legs(&mut tick).is_none(), "neither is covered");
        let stated = state(&mut tick);
        assert_eq!((stated.tx_count(), stated.charged()), (0, 30));
        assert!(
            take_legs(&mut tick).is_none(),
            "stated, and neither covered"
        );

        tick.add_execution_certificate(counterpart(4, near));
        let half = take_legs(&mut tick).expect("the covered leg does not wait for its tick-mate");
        assert_eq!(half.tx_hashes().collect::<Vec<_>>(), vec![near]);
        assert_eq!(half.validate_against_certificates(), Ok(()));
        assert_eq!(
            (half.tx_count(), half.charged()),
            (1, 0),
            "a legs half charges nothing",
        );
        assert!(!tick.has_spoken(), "the other leg is still owed a verdict");
        assert!(
            take_legs(&mut tick).is_none(),
            "the same names are offered once",
        );

        tick.add_execution_certificate(counterpart(5, far));
        let both = take_legs(&mut tick).expect("the names grew with the coverage");
        assert_eq!(both.tx_hashes().collect::<Vec<_>>(), vec![near, far]);
        assert_eq!(both.validate_against_certificates(), Ok(()));
        assert_ne!(both.receipt_hash(), half.receipt_hash());
        assert!(tick.has_spoken());

        assert!(!tick.record_settled([near]), "the other leg still stands");
        let rest = take_legs(&mut tick).expect("the half out names a member a block has settled");
        assert_eq!(rest.tx_hashes().collect::<Vec<_>>(), vec![far]);
        assert_eq!(rest.validate_against_certificates(), Ok(()));
        assert!(tick.record_settled([far]));
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
            Some(10),
            Joins::Executes,
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
                Capped::new(outcomes).expect("a list written out in a test"),
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
        use crate::fixtures::{leaf, payer, route, swap, trie};

        let trie = trie();
        let (low, high, third) = (leaf(0), leaf(1), leaf(2));

        let swap = Classified::freeze(&swap(), payer(), &[], &trie);
        assert!(swap.decomposed());
        let participating = BTreeSet::from([low, high]);
        let member_of = |classified: &Classified, local, participating: &BTreeSet<ShardId>| {
            Member::of(classified.clone(), local, participating.clone())
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

        let route = Classified::freeze(&route(), payer(), &[], &trie);
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

    /// A membership stated outright, for the routing pins.
    fn membership(
        awaited: impl IntoIterator<Item = ShardId>,
        reach: impl IntoIterator<Item = ShardId>,
        role: Role,
    ) -> Membership {
        Membership {
            awaited: awaited.into_iter().collect(),
            reach: reach.into_iter().collect(),
            role,
        }
    }

    /// A tick holding a leg and a core member routes per member: the
    /// venue's copy carries the core outcome it awaits and leaves out the
    /// leg beside it.
    #[test]
    fn a_mixed_tick_routes_its_core_outcome_and_withholds_its_leg() {
        use hyperscale_types::BlockHeight;

        use crate::fixtures::leaf;

        let (local, venue) = (leaf(0), leaf(1));
        let (leg, core) = (tx(1), tx(2));
        let mut tick = TickState::new(
            TickId::new(local, BlockHeight::new(1)),
            BlockHash::ZERO,
            WeightedTimestamp::from_millis(1_000),
        );
        tick.admit(
            leg,
            membership([local], [local, venue], Role::Leg),
            Some(10),
            Joins::Executes,
        );
        tick.admit(
            core,
            membership([local, venue], [local, venue], Role::Core),
            Some(10),
            Joins::Executes,
        );

        assert_eq!(tick.counterpart_shards(), vec![venue]);
        assert_eq!(tick.txs_reaching(venue).collect::<Vec<_>>(), vec![core]);
    }

    /// A core member owes its outcome to every shard its transaction
    /// reaches, a leg's producer among them; the leg owes its own to
    /// nobody.
    #[test]
    fn a_core_outcome_is_owed_to_its_leg_producer() {
        use crate::fixtures::leaf;

        let (local, producer) = (leaf(1), leaf(0));
        let core = membership([local], [local, producer], Role::Core);
        assert!(core.owes_certificate_to(producer, local));
        assert!(!core.owes_certificate_to(local, local));
        let leg = membership([producer], [local, producer], Role::Leg);
        assert!(!leg.owes_certificate_to(local, producer));
    }

    /// A leg awaiting nobody but itself settles in the determined half on
    /// the tick's own certificate, and owes that certificate to nobody:
    /// the venue reads the leg's crossing off the record it was pushed.
    /// A certificate from the venue is neither coverage for the leg nor
    /// part of its finalization: its verdict is not the leg's to apply.
    #[test]
    fn a_leg_certifies_alone_and_owes_its_certificate_to_nobody() {
        use hyperscale_types::BlockHeight;

        use crate::fixtures::{leaf, payer, swap, trie};

        let trie = trie();
        let (local, venue) = (leaf(0), leaf(1));
        let classified = Classified::freeze(&swap(), payer(), &[], &trie);
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
                BTreeSet::from([local, venue]),
            )),
            Some(10),
            Joins::Executes,
        );

        assert_eq!(tick.determined_members(), vec![leg], "it settles alone");
        assert!(tick.leg_members().is_empty());
        assert_eq!(
            tick.awaited_counterparts().count(),
            0,
            "and expects no certificate"
        );
        assert!(
            tick.counterpart_shards().is_empty(),
            "and owes its own to nobody"
        );
        assert_eq!(tick.txs_reaching(venue).count(), 0);
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
                Capped::from_array([TxOutcome::new(leg, ExecutionOutcome::Aborted)]),
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
                Capped::new(outcomes).expect("a list written out in a test"),
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

    /// A half needing more certificates than one finalization carries is
    /// declined, not fatal.
    ///
    /// The wire holds [`MAX_EXECUTION_CERTIFICATES_PER_TICK`] of them and
    /// nothing holds this node's collection to that figure: a member
    /// awaiting many counterparts takes one certificate from each, and
    /// each is one the tick keeps because it covers a seat nothing else
    /// does. So the list the half needs can outgrow what it fits in, and
    /// what that must not do is take the node down with it.
    #[test]
    fn a_half_whose_certificates_outgrow_one_finalization_is_declined() {
        // A trie deep enough to name every counterpart apart, which the
        // two-shard helper above is not.
        let at = |path: u64| ShardId::leaf(11, path);
        let local = at(0);
        let member = tx(3);
        // One counterpart per certificate the wire holds: with the local
        // projection beside them the half needs one more than it fits.
        let peers: BTreeSet<ShardId> = (1..=MAX_EXECUTION_CERTIFICATES_PER_TICK as u64)
            .map(at)
            .collect();
        let mut participating = peers.clone();
        participating.insert(local);

        let mut tick = TickState::new(
            TickId::new(local, BlockHeight::new(1)),
            BlockHash::ZERO,
            WeightedTimestamp::from_millis(1_000),
        );
        tick.admit(
            member,
            Membership::whole(participating),
            Some(10),
            Joins::Executes,
        );
        tick.record_execution_result(
            member,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        );
        tick.record_receipt(receipt(member));
        let (_, root, outcomes) = tick.build_vote_data().expect("the member came back");
        tick.add_execution_certificate(Arc::new(Verified::new_unchecked_for_test(
            ExecutionCertificate::new(
                *tick.tick_id(),
                tick.vote_anchor_ts(),
                root,
                Capped::new(outcomes).expect("a list written out in a test"),
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ),
        )));

        // One certificate per counterpart, each awaiting this shard for
        // the member, so each covers a seat the others do not.
        for peer in &peers {
            tick.add_execution_certificate(Arc::new(Verified::new_unchecked_for_test(
                ExecutionCertificate::new(
                    TickId::new(*peer, BlockHeight::new(7)),
                    WeightedTimestamp::from_millis(1_000),
                    GlobalReceiptRoot::ZERO,
                    Capped::from_array([TxOutcome::new(
                        member,
                        ExecutionOutcome::Succeeded {
                            receipt_hash: GlobalReceiptHash::ZERO,
                        },
                    )
                    .awaiting(vec![local])]),
                    AggregateSignature::ZERO,
                    SignerBitfield::new(4),
                ),
            )));
        }

        let members = HashSet::from([member]);
        assert!(
            tick.attestation_for(TickHalf::Determined, &members)
                .is_none(),
            "a half that does not fit one finalization is one this node declines"
        );
    }

    /// A counterpart whose tick stated a shared member holds the replaced
    /// committee's yes for it, verified before it folded the recovered
    /// shard's binding, when the fresh committee's abort of the released
    /// member verifies at it. The legs half it builds is the one its
    /// first certificate covered: the abort covers nothing new and is not
    /// kept, so the counterpart accepts what the recovered shard aborts.
    /// The same two in the other order settle the abort. Which one a
    /// counterpart settles turns on the order they reached it, and the
    /// band refuses the replaced yes only where it arrives after the
    /// fold.
    #[test]
    fn a_stated_counterpart_holding_a_replaced_yes_meets_a_fresh_abort() {
        use hyperscale_types::{Role, TransactionDecision};

        let abort = |height: u64, tx_hash: TxHash| {
            Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
                TickId::new(shard(1), BlockHeight::new(height)),
                WeightedTimestamp::from_millis(9_000),
                GlobalReceiptRoot::ZERO,
                Capped::from_array([TxOutcome::new(tx_hash, ExecutionOutcome::Aborted)
                    .reserving(10)
                    .awaiting([shard(0)])
                    .as_role(Role::Settling)]),
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            )))
        };
        let decided = |half: &Finalization, tx_hash: TxHash| {
            half.tx_decisions()
                .into_iter()
                .find(|(named, _)| *named == tx_hash)
                .map(|(_, decision)| decision)
        };
        let from_counterpart = |half: &Finalization| {
            half.execution_certificates()
                .iter()
                .filter(|ec| ec.shard_id() == shard(1))
                .map(|ec| ec.tick_id().block_height().inner())
                .collect::<Vec<_>>()
        };

        let (mut tick, near, _) = two_leg_tick();
        state(&mut tick);
        tick.add_execution_certificate(counterpart(4, near));
        tick.add_execution_certificate(abort(9, near));
        let half = tick.legs_half().expect("covered");
        assert_eq!(decided(&half, near), Some(TransactionDecision::Accept));
        assert_eq!(from_counterpart(&half), vec![4], "the abort is not kept");

        let (mut tick, near, _) = two_leg_tick();
        state(&mut tick);
        tick.add_execution_certificate(abort(9, near));
        tick.add_execution_certificate(counterpart(4, near));
        let half = tick.legs_half().expect("covered");
        assert_eq!(decided(&half, near), Some(TransactionDecision::Aborted));
        assert_eq!(from_counterpart(&half), vec![9]);
    }
}
