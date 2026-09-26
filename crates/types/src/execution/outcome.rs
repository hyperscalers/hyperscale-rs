//! Per-tx execution outcome ([`TxOutcome`]) and the [`ExecutionOutcome`] enum
//! carried inside execution certificates.

use hyperscale_hbor::{Capped, Hbor};

use crate::{GlobalReceiptHash, MAX_PROVISION_TARGET_SHARDS, ShardId, TxHash};

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
    /// A member settling what an execution left, with a verdict of its
    /// own: a reclaim, an abandonment, an inherited record's member.
    Settling,
}

impl Role {
    /// Whether an outcome with this role and `outcome` bears the verdict
    /// on the transaction for the certifying shard.
    #[must_use]
    pub(crate) const fn decides(self, outcome: &ExecutionOutcome) -> bool {
        match outcome {
            ExecutionOutcome::Succeeded { .. } => self.success_decides(),
            // A member that could not do its part ends the transaction
            // on this shard whatever its role.
            _ => true,
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
        matches!(self, Self::Whole | Self::Core | Self::Leg)
    }
}

/// Carried inside execution certificates so remote shards can extract
/// individual transaction results for cross-shard finalization.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct TxOutcome {
    tx_hash: TxHash,
    outcome: ExecutionOutcome,
    /// Set when this shard settles something apart from the
    /// transaction's own effects: the hash of the refusal receipt
    /// carrying the payer's charge, where this shard holds the vault,
    /// and the `Never` answers of every refusable crossing the member
    /// consumed, where it was refused.
    ///
    /// An aborted transaction's own effects never apply — that is what
    /// makes a cross-shard abort atomic — and a failed one produced none
    /// to apply. Either way the payer still owes for the work the attempt
    /// consumed, the consumer owes its producers one answer, and state
    /// moves only through receipts. The refusal receipt is the
    /// reconciliation: it carries the debit and the answers and nothing
    /// else, and naming its hash here puts it under the signed receipt
    /// root like any other receipt's content.
    ///
    /// A failure that settles one takes the place of the `Failed` receipt
    /// it would otherwise store, so the one-receipt-per-outcome pairing is
    /// unchanged.
    refusal_receipt: Option<GlobalReceiptHash>,
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
    /// What this shard attests it charged, in quanta: the price of its
    /// own share of the declared vector, at the table in force at its
    /// block's anchor, raised by the signed priority.
    ///
    /// The share, not the whole: the payer burns the whole price once,
    /// on its own shard, while this is what the beacon weighs this
    /// shard's emission by — so it has to say what this shard did, and
    /// the shares of a cross-shard transaction sum past the whole by
    /// what every participant repeats.
    ///
    /// Attested rather than re-derived because a validator holding the
    /// certificate but not the transaction — a node that snap-synced
    /// past it — still has to reach the same figure, and because the
    /// beacon weighs a shard's emission by what its certificates settled.
    /// Zero for a member whose shard charged the transaction already.
    charged: u128,
    /// Whether the block that committed this member took a place in the
    /// drain for it, which its settlement gives back.
    ///
    /// False for a member no committing block took a place for: a
    /// reclaim, or any other member settling what an execution left, so
    /// it releases nothing. Attested for the reason `charged` is: the
    /// settling block counts what it releases with no history behind it.
    reserved: bool,
    /// The other shards party to the transaction — the ones whose
    /// certificates its settlement waits on. Ascending and distinct;
    /// empty for a transaction reaching no further than this shard.
    ///
    /// A function of the declaration and the topology that committed it,
    /// so every participant derives the same set. The certifying shard is
    /// left out: the certificate carrying this outcome is its report.
    ///
    /// Attested rather than re-derived for the reason
    /// [`TxOutcome::charged`] is — a validator holding the
    /// certificate but not the transaction still has to reach the same
    /// answer — and it is what lets a set of certificates state how
    /// complete it needs to be. Without it the rule discarding a refused
    /// transaction's effects is read over whichever certificates the set
    /// happens to carry, and a set with the refusal dropped reads as
    /// unanimous.
    counterparts: Capped<Vec<ShardId>, MAX_PROVISION_TARGET_SHARDS>,
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
    /// Create a new `TxOutcome` settling no refusal receipt.
    #[must_use]
    pub const fn new(tx_hash: TxHash, outcome: ExecutionOutcome) -> Self {
        Self {
            charged: 0,
            reserved: false,
            tx_hash,
            outcome,
            refusal_receipt: None,
            counterparts: Capped::empty(),
            role: Role::Whole,
        }
    }

    /// Bind what this transaction was charged, and that its committing
    /// block took a place in the drain for it.
    #[must_use]
    pub const fn reserving(mut self, charged: u128) -> Self {
        self.charged = charged;
        self.reserved = true;
        self
    }

    /// Bind the shards this transaction's settlement waits on, in the one
    /// form the set may take: ascending, distinct, and without the shard
    /// whose certificate carries the outcome.
    ///
    /// # Panics
    ///
    /// If a list runs past the cap its type states, which a committee's own vote cannot.
    #[must_use]
    pub fn awaiting(mut self, counterparts: impl IntoIterator<Item = ShardId>) -> Self {
        let mut counterparts: Vec<ShardId> = counterparts.into_iter().collect();
        counterparts.sort_unstable();
        counterparts.dedup();
        self.counterparts =
            Capped::new(counterparts).expect("a list under the cap its source already met");
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
    pub fn reaches_beyond(&self) -> bool {
        match self.role {
            Role::Core | Role::Leg => true,
            Role::Whole | Role::Settling => !self.counterparts.is_empty(),
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

    /// Create a `TxOutcome` that settles what it owes apart from the
    /// transaction's own effects through the named refusal receipt.
    ///
    /// Every outcome that owes something without applying the
    /// transaction's own effects uses this: an abort, whose effects are
    /// discarded to keep the cross-shard settlement atomic, and a
    /// failure, whose effects the engine never produced. In either case
    /// the transaction did work its payer owes for and consumed
    /// crossings its producers are owed an answer for, and the receipt
    /// named here is the only thing that moves either.
    #[must_use]
    pub const fn with_refusal(
        tx_hash: TxHash,
        outcome: ExecutionOutcome,
        refusal_receipt: GlobalReceiptHash,
    ) -> Self {
        Self {
            charged: 0,
            reserved: false,
            tx_hash,
            outcome,
            refusal_receipt: Some(refusal_receipt),
            counterparts: Capped::empty(),
            role: Role::Whole,
        }
    }

    /// What this transaction was charged, in quanta.
    #[must_use]
    pub const fn charged(&self) -> u128 {
        self.charged
    }

    /// Whether this member's committing block took a place in the drain
    /// for it, which its settlement gives back.
    #[must_use]
    pub(crate) const fn reserved(&self) -> bool {
        self.reserved
    }

    /// The refusal receipt this outcome settles, if any.
    #[must_use]
    pub const fn refusal_receipt(&self) -> Option<GlobalReceiptHash> {
        self.refusal_receipt
    }

    /// The shards this transaction's settlement waits on, besides the one
    /// certifying this outcome.
    #[must_use]
    pub fn counterparts(&self) -> &[ShardId] {
        &self.counterparts
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
