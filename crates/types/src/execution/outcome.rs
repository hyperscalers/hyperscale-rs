//! Per-tx execution outcome ([`TxOutcome`]) and the [`ExecutionOutcome`] enum
//! carried inside execution certificates.

use hyperscale_hbor::Hbor;
use hyperscale_vm_types::{MAX_CROSSINGS_PER_TX, ResourceAddr, SubstateKey};

use crate::{GlobalReceiptHash, MAX_PROVISION_TARGET_SHARDS, ShardId, TxHash};

/// What one value edge escrowed out of this shard's execution.
///
/// Per edge, not per resource: a sum over the outcome would leave two
/// edges carrying one resource with no way to say which value fed which
/// consumer, and the consuming shard claims its own argument rather than
/// a share of a total.
///
/// Self-describing: the record cell rides the entry, so a validator
/// holding the certificate and not the transaction can build, serve and
/// match the bundle that proves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub struct EscrowedValue {
    /// The producing node.
    pub node: u32,
    /// Which of its outputs left.
    pub output: u32,
    /// The resource that left.
    pub resource: ResourceAddr,
    /// How much of it.
    pub amount: u128,
    /// The record cell the value left into, under the producing node's
    /// target — what the bundle carrying it proves, and what the
    /// consumer's requirement names.
    pub record: SubstateKey,
}

/// Per-transaction execution outcome within a tick.
///
/// What the attesting shard was to a transaction, as its certificate
/// says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub enum Role {
    /// The whole shape: a transaction on one shard, or a participant of
    /// one that runs undivided across several.
    Whole,
    /// A member of a divided transaction's core, whose certificate is a
    /// share of the verdict.
    Core,
    /// A leg outside the core: its success is its own part and the core
    /// decides, but a leg that could not issue is the transaction's end
    /// on its shard.
    Leg,
    /// A delivery: claims what crossed to it and decides nothing either
    /// way, since a delivery that failed leaves the value in its cell
    /// for a later claim.
    Delivery,
    /// A member settling what an execution left, with a verdict of its
    /// own: a reclaim, an abandonment, an inherited record's member.
    Settling,
    /// Housekeeping deciding nothing: a retirement, deleting records
    /// whose claims committed elsewhere, where a verdict here would be a
    /// second one on a chain that may already hold the first.
    Retiring,
}

impl Role {
    /// Whether an outcome with this role and `outcome` bears the verdict
    /// on the transaction for the certifying shard.
    #[must_use]
    pub const fn decides(self, outcome: &ExecutionOutcome) -> bool {
        match outcome {
            ExecutionOutcome::Succeeded { .. } => self.success_decides(),
            // A member that could not do its part ends the transaction
            // on this shard whatever its role, except where the role
            // bears no verdict at all.
            _ => !matches!(self, Self::Delivery | Self::Retiring),
        }
    }

    /// Whether a *success* in this role bears the verdict.
    ///
    /// The population a deadline refuses: such a success committed past
    /// the transaction's deadline is one a leg may already have
    /// reclaimed against, so no block carries it and the tick holding
    /// one has nothing left to say.
    #[must_use]
    pub const fn success_decides(self) -> bool {
        matches!(self, Self::Whole | Self::Core | Self::Settling)
    }

    /// Whether the outcome is the transaction's own execution, rather
    /// than a member settling what one left.
    #[must_use]
    pub const fn executes(self) -> bool {
        matches!(self, Self::Whole | Self::Core | Self::Leg | Self::Delivery)
    }

    /// Whether the member only delivers.
    #[must_use]
    pub const fn delivers(self) -> bool {
        matches!(self, Self::Delivery)
    }

    /// Whether a *success* in this role claims what crossed to it.
    ///
    /// What an issuer's record is held for is the claim, and only a
    /// member that ran the consuming side makes one: a delivery, or a
    /// core member, or an undivided participant. A leg's success says
    /// its own side went through and nothing about anyone else's, so an
    /// issuer reading it as a claim would retire a record before the
    /// value it stands for has been taken — which on a shard that is
    /// both a caller and a recipient is every swap.
    #[must_use]
    pub const fn success_claims(self) -> bool {
        matches!(self, Self::Whole | Self::Core | Self::Delivery)
    }
}

/// Carried inside execution certificates so remote shards can extract
/// individual transaction results for cross-shard finalization.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct TxOutcome {
    tx_hash: TxHash,
    outcome: ExecutionOutcome,
    /// Set when this shard charges a transaction it pays for without
    /// applying its effects: the hash of the receipt carrying that charge.
    ///
    /// An aborted transaction's own effects never apply — that is what
    /// makes a cross-shard abort atomic — and a failed one produced none
    /// to apply. Either way the payer still owes for the work the attempt
    /// consumed, and state moves only through receipts. The fee receipt is
    /// the reconciliation: it carries that debit and nothing else, and
    /// naming its hash here puts it under the signed receipt root like any
    /// other receipt's content.
    ///
    /// A failure that settles one takes the place of the `Failed` receipt
    /// it would otherwise store, so the one-receipt-per-outcome pairing is
    /// unchanged.
    fee_receipt: Option<GlobalReceiptHash>,
    /// What this shard attests it did for the transaction, under the
    /// engine's schedule.
    ///
    /// Beside the outcome rather than inside the receipt, and the
    /// distinction is load-bearing. A receipt is the effect record every
    /// participant of a cross-shard transaction derives identically —
    /// locality decides what is *applied* from it, never what it *says*.
    /// Work is the opposite kind of quantity: this shard's own share,
    /// which the participants are meant to differ on. It also covers every
    /// verdict, where a receipt covers only the outcomes that produced
    /// one, so an attempt that failed or aborted still reports the
    /// declaration work it really did.
    attested_work: u64,
    /// What carrying this transaction cost a block, in work units — the
    /// quantity admission reserved against the drain budget.
    ///
    /// The mirror image of [`TxOutcome::attested_work`]. That is this
    /// shard's own share of what the transaction *cost*, which
    /// participants are meant to differ on; this is what it *reserved*,
    /// derived from the whole declaration and therefore identical on
    /// every participant.
    ///
    /// Attested rather than re-derived because release has to work
    /// without the transaction. A block settling a tick releases the
    /// reservation its committing block took, and a validator holding
    /// the certificate but not the transactions — a node that snap-synced
    /// past them — still has to reach the same total. Reserving one
    /// number and releasing another leaves the running total drifting
    /// upward and never returning to zero.
    declared_work: u64,
    /// The other shards party to the transaction — the ones whose
    /// certificates its settlement waits on. Ascending and distinct;
    /// empty for a transaction reaching no further than this shard.
    ///
    /// A function of the declaration and the topology that committed it,
    /// so every participant derives the same set. The certifying shard is
    /// left out: the certificate carrying this outcome is its report.
    ///
    /// Attested rather than re-derived for the reason
    /// [`TxOutcome::declared_work`] is — a validator holding the
    /// certificate but not the transaction still has to reach the same
    /// answer — and it is what lets a set of certificates state how
    /// complete it needs to be. Without it the rule discarding a refused
    /// transaction's effects is read over whichever certificates the set
    /// happens to carry, and a set with the refusal dropped reads as
    /// unanimous.
    #[hbor(max = MAX_PROVISION_TARGET_SHARDS)]
    counterparts: Vec<ShardId>,
    /// The record cell this shard's execution wrote for each value edge
    /// it escrowed out. Ascending and distinct.
    ///
    /// The cell and not what is in it: a claiming shard reads the
    /// crossing's resource and amount off the record itself, which
    /// arrives under a provisions root that authenticates it. What this
    /// names is which cells to ask for, which the certificate carries a
    /// block earlier than the bundle answering them.
    #[hbor(max = MAX_CROSSINGS_PER_TX)]
    escrowed: Vec<SubstateKey>,
    /// The shards those crossings land on. Ascending and distinct.
    ///
    /// Derivable from `escrowed` and the trie, and attested anyway: the
    /// shard promising a bundle reads this a block earlier than it can
    /// resolve the trie the issuer used.
    #[hbor(max = MAX_PROVISION_TARGET_SHARDS)]
    crossing_targets: Vec<ShardId>,
    /// The committed cell this shard wrote at the transaction's inclusion
    /// and this outcome retracts: a core member that refused or aborted
    /// the transaction, whose settling block deletes the cell so a leg
    /// probing it reads the same absence a core that never included the
    /// transaction leaves. A core's verdict is then a fact about its
    /// state, like its inclusion and its claim.
    ///
    /// Attested rather than derived because the key carries the
    /// transaction's validity end, and a validator holding the
    /// certificate but not the transaction — one that synced past its
    /// block — still has to delete the same cell or its root forks.
    retracts: Option<SubstateKey>,
    /// What the attesting shard was to the transaction: the one fact
    /// that says whether this outcome bears the verdict, whether it is
    /// the transaction's own execution, and whether a counterpart could
    /// ask about it.
    ///
    /// Attested rather than derived because it cannot be: a leg and a
    /// single-shard core both await nobody and both may escrow, a
    /// reclaim and a single-shard core both decide and both succeed, and
    /// only the classification the certifying shard froze and the tick
    /// that admitted the member tell them apart.
    role: Role,
}

impl TxOutcome {
    /// Create a new `TxOutcome` settling no fee receipt.
    #[must_use]
    pub const fn new(tx_hash: TxHash, outcome: ExecutionOutcome) -> Self {
        Self::attesting(tx_hash, outcome, 0)
    }

    /// A `TxOutcome` attesting `work`, settling no fee receipt.
    #[must_use]
    pub const fn attesting(tx_hash: TxHash, outcome: ExecutionOutcome, work: u64) -> Self {
        Self {
            attested_work: work,
            declared_work: 0,
            tx_hash,
            outcome,
            fee_receipt: None,
            counterparts: Vec::new(),
            escrowed: Vec::new(),
            crossing_targets: Vec::new(),
            retracts: None,
            role: Role::Whole,
        }
    }

    /// Bind the committed cell this outcome retracts, if it refuses the
    /// transaction a core member here was written one for.
    #[must_use]
    pub const fn retracting(mut self, cell: Option<SubstateKey>) -> Self {
        self.retracts = cell;
        self
    }

    /// Bind what this transaction reserved against the drain budget.
    #[must_use]
    pub const fn reserving(mut self, declared_work: u64) -> Self {
        self.declared_work = declared_work;
        self
    }

    /// Bind the shards this transaction's settlement waits on, in the one
    /// form the set may take: ascending, distinct, and without the shard
    /// whose certificate carries the outcome.
    #[must_use]
    pub fn awaiting(mut self, counterparts: impl IntoIterator<Item = ShardId>) -> Self {
        let mut counterparts: Vec<ShardId> = counterparts.into_iter().collect();
        counterparts.sort_unstable();
        counterparts.dedup();
        self.counterparts = counterparts;
        self
    }

    /// Bind what this execution escrowed out, in its one form: sorted on
    /// the whole entry, one per edge.
    #[must_use]
    pub fn escrowing(mut self, escrowed: impl IntoIterator<Item = SubstateKey>) -> Self {
        let mut escrowed: Vec<SubstateKey> = escrowed.into_iter().collect();
        escrowed.sort_unstable();
        escrowed.dedup();
        self.escrowed = escrowed;
        self
    }

    /// Bind the shards this execution's crossings land on, in the one
    /// form the set may take: ascending and distinct.
    #[must_use]
    pub fn crossing_to(mut self, targets: impl IntoIterator<Item = ShardId>) -> Self {
        let mut targets: Vec<ShardId> = targets.into_iter().collect();
        targets.sort_unstable();
        targets.dedup();
        self.crossing_targets = targets;
        self
    }

    /// Bind what the attesting shard was to the transaction.
    #[must_use]
    pub const fn as_role(mut self, role: Role) -> Self {
        self.role = role;
        self
    }

    /// What the attesting shard was to the transaction.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Whether the transaction reaches a shard other than the attesting
    /// one — whether any counterpart could ask about this verdict. A
    /// divided transaction's members reach beyond by construction; a
    /// whole shape or a settling member reaches exactly the shards its
    /// settlement waits on.
    #[must_use]
    pub const fn reaches_beyond(&self) -> bool {
        match self.role {
            Role::Core | Role::Leg | Role::Delivery => true,
            Role::Whole | Role::Settling => !self.counterparts.is_empty(),
            Role::Retiring => false,
        }
    }

    /// Whether this outcome bears the verdict on the transaction for the
    /// certifying shard — what lets its finalization resolve the hash.
    #[must_use]
    pub const fn decides(&self) -> bool {
        self.role.decides(&self.outcome)
    }

    /// Whether this outcome is the transaction's own execution, rather
    /// than a member settling what one left.
    #[must_use]
    pub const fn executes(&self) -> bool {
        self.role.executes()
    }

    /// Create a `TxOutcome` that settles the payer's charge through the
    /// named fee receipt.
    ///
    /// Both outcomes that owe a charge without applying the transaction's
    /// own effects use this: an abort, whose effects are discarded to keep
    /// the cross-shard settlement atomic, and a failure, whose effects the
    /// engine never produced. In either case the transaction did work its
    /// payer owes for, and the receipt named here is the only thing that
    /// moves that charge.
    #[must_use]
    pub const fn with_fee(
        tx_hash: TxHash,
        outcome: ExecutionOutcome,
        fee_receipt: GlobalReceiptHash,
        work: u64,
    ) -> Self {
        Self {
            attested_work: work,
            declared_work: 0,
            tx_hash,
            outcome,
            fee_receipt: Some(fee_receipt),
            counterparts: Vec::new(),
            escrowed: Vec::new(),
            crossing_targets: Vec::new(),
            retracts: None,
            role: Role::Whole,
        }
    }

    /// The committed cell this outcome retracts, where it refuses a
    /// transaction a core member here was written one for.
    #[must_use]
    pub const fn retracts(&self) -> Option<SubstateKey> {
        self.retracts
    }

    /// What this shard attests it did for the transaction.
    #[must_use]
    pub const fn attested_work(&self) -> u64 {
        self.attested_work
    }

    /// What carrying this transaction reserved against the drain budget.
    #[must_use]
    pub const fn declared_work(&self) -> u64 {
        self.declared_work
    }

    /// The fee receipt this outcome settles, if any.
    #[must_use]
    pub const fn fee_receipt(&self) -> Option<GlobalReceiptHash> {
        self.fee_receipt
    }

    /// The shards this transaction's settlement waits on, besides the one
    /// certifying this outcome.
    #[must_use]
    pub fn counterparts(&self) -> &[ShardId] {
        &self.counterparts
    }

    /// What this shard's execution escrowed out, one entry per edge.
    #[must_use]
    pub fn escrowed(&self) -> &[SubstateKey] {
        &self.escrowed
    }

    /// The shards this execution's crossings land on.
    #[must_use]
    pub fn crossing_targets(&self) -> &[ShardId] {
        &self.crossing_targets
    }

    /// Transaction hash.
    #[must_use]
    pub const fn tx_hash(&self) -> TxHash {
        self.tx_hash
    }

    /// The execution outcome for this transaction.
    #[must_use]
    pub const fn outcome(&self) -> &ExecutionOutcome {
        &self.outcome
    }

    /// Consume the outcome and return its parts.
    #[must_use]
    pub fn into_parts(self) -> (TxHash, ExecutionOutcome) {
        (self.tx_hash, self.outcome)
    }

    /// Whether this outcome is an abort.
    #[must_use]
    pub const fn is_aborted(&self) -> bool {
        matches!(self.outcome, ExecutionOutcome::Aborted)
    }
}

/// The outcome of executing a transaction on a single shard.
///
/// The variant tag IS the outcome — there is no separate `success: bool`
/// flag. Failed transactions carry no `receipt_hash` on the wire (the
/// canonical [`FAILED_RECEIPT_HASH`](crate::FAILED_RECEIPT_HASH) is
/// derivable at hash time).
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub enum ExecutionOutcome {
    /// Engine committed the transaction; state changes applied.
    Succeeded {
        /// Hash of the global receipt produced by this execution.
        receipt_hash: GlobalReceiptHash,
    },
    /// Engine rejected the transaction; no state changes applied.
    /// Carries no payload — every failure is consensus-equivalent.
    Failed,
    /// Transaction aborted before execution could complete.
    Aborted,
}

impl ExecutionOutcome {
    /// Whether the transaction was aborted.
    #[must_use]
    pub const fn is_aborted(&self) -> bool {
        matches!(self, Self::Aborted)
    }
}
