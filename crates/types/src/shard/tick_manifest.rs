//! [`TickLine`]: one line of a block's tick manifest, the section in
//! which a proposer names what the block's tick holds and what it lets
//! go.

use hyperscale_hbor::{Capped, Hbor};
use hyperscale_vm_types::{MAX_CROSSINGS_PER_TX, Mode};

use crate::{
    DeclaredKey, ESCROWED_RECORD_BYTES, MAX_HOLDS_PER_MEMBER, MAX_TICK_LINES_PER_BLOCK,
    SubstateKey, TICK_HOLD_BYTES, TICK_LINE_BYTES, TickId, TxHash,
};

/// How a member joins its tick: the terms a
/// [`TickLine::Member`] names it on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Hbor)]
pub enum Joins {
    /// In the batch, attested on what execution says.
    Executes,
    /// In the batch, attested `Aborted` whatever it says: the payer's
    /// leg whose counterparts never engaged. It still executes, because
    /// the charge that abort settles is what the execution builds.
    ExecutesAborted,
    /// Not in the batch. Past the deadline that bounds it, so no
    /// execution here can reach an outcome, and the tick attests
    /// `Aborted` on nothing but the hash and the reservation its
    /// committing block took.
    Aborted,
}

impl Joins {
    /// Whether the member goes to the engine, and so whether the tick
    /// waits for a result before it can vote.
    #[must_use]
    pub const fn dispatched(self) -> bool {
        matches!(self, Self::Executes | Self::ExecutesAborted)
    }

    /// Whether the tick attests `Aborted` whatever execution says.
    #[must_use]
    pub const fn aborts(self) -> bool {
        matches!(self, Self::ExecutesAborted | Self::Aborted)
    }
}

/// Why a committed tick lets its members go.
///
/// A discard names a cause and never members: each replica derives the
/// members it releases from the tick's own rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Hbor)]
pub enum DiscardCause {
    /// The tick holds the transaction, and the same block aborts it at
    /// its deadline.
    Abandoned(TxHash),
    /// Every counterpart the transaction reaches has departed, and no
    /// settled set that could speak for it is still read.
    Unanswerable(TxHash),
    /// A departed partner's settled set does not hold the tick's legs
    /// half.
    Rejected,
    /// The tick sits at or below a halt recovery's attested frontier,
    /// and the block is the first the fresh committee certified.
    Recovery,
}

/// What an abortable member holds provisionally while its tick is in
/// flight: its declared accesses, each under the mode it takes.
pub type Holds = Capped<Vec<(DeclaredKey, Mode)>, MAX_HOLDS_PER_MEMBER>;

/// One line of a block's tick manifest.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub enum TickLine {
    /// A transaction this chain committed joins the block's tick.
    ///
    /// `holds` is what the member claims while its tick is in flight:
    /// its declared accesses when a counterpart's verdict can still
    /// discard its writes, and nothing otherwise. It rides the line
    /// because every replica folds it and only a replica that can route
    /// the transaction can derive it.
    Member {
        /// The transaction, which this chain committed and has not
        /// resolved.
        tx: TxHash,
        /// The terms it joins on.
        joins: Joins,
        /// What it holds while the tick is in flight.
        holds: Holds,
    },
    /// The block's tick takes back what the records name, under `name`:
    /// a leg entry's own transaction, or the records' disposal name.
    Reclaim {
        /// The member's name on the tick.
        name: TxHash,
        /// The records it takes back, at most one transaction's worth.
        records: Capped<Vec<SubstateKey>, MAX_CROSSINGS_PER_TX>,
    },
    /// An earlier tick lets go of the members `cause` releases.
    Discard {
        /// The tick, which committed on this chain.
        tick: TickId,
        /// What licenses the release.
        cause: DiscardCause,
    },
}

impl TickLine {
    /// An upper bound on what this line costs the block that carries
    /// it, so a composer spends the section's budget as it fills it and
    /// a voter checks the same figure without re-encoding what it
    /// decoded. Everything but the holds and the records is fixed width.
    #[must_use]
    pub fn wire_weight(&self) -> usize {
        TICK_LINE_BYTES
            + match self {
                Self::Member { holds, .. } => holds.len() * TICK_HOLD_BYTES,
                Self::Reclaim { records, .. } => records.len() * ESCROWED_RECORD_BYTES,
                Self::Discard { .. } => 0,
            }
    }
}

/// A block's tick manifest, in the order its lines are charged and
/// applied.
pub type TickManifest = Capped<Vec<TickLine>, MAX_TICK_LINES_PER_BLOCK>;
