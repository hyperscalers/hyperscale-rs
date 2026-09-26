//! [`TickLine`]: one line of a block's tick manifest, the section in
//! which a proposer names what the block's tick holds and what it lets
//! go.

use hyperscale_hbor::{Capped, Hbor};
use hyperscale_vm_types::Mode;

use crate::{
    DeclaredKey, MAX_HOLDS_PER_MEMBER, MAX_PREFIXES_PER_TX, MAX_TICK_LINES_PER_BLOCK, ShardId,
    TICK_HOLD_BYTES, TICK_LINE_BYTES, TICK_REACH_BYTES, TickHalf, TickId, TxHash,
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

/// How a member's settlement stands to its counterparts: which half of
/// its tick settles it, and whether a discard keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Hbor)]
pub enum Settlement {
    /// On this shard's certificate alone: the determined half.
    Alone,
    /// The legs half, and a counterpart settles it against this shard's
    /// certificate, which may already be out: a whole or core member. A
    /// discard keeps it.
    Shared,
    /// The legs half, awaiting counterparts that settle nothing against
    /// this shard's certificate: a leg, or a member this tick settles
    /// rather than runs. A discard releases it.
    Awaited,
}

impl Settlement {
    /// The finalization half that settles a member of this kind.
    #[must_use]
    pub const fn half(self) -> TickHalf {
        match self {
            Self::Alone => TickHalf::Determined,
            Self::Shared | Self::Awaited => TickHalf::Legs,
        }
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

/// The remote shards a member's transaction reaches, as its committing
/// block's committee placed them.
pub type Reach = Capped<Vec<ShardId>, MAX_PREFIXES_PER_TX>;

/// One line of a block's tick manifest.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub enum TickLine {
    /// A transaction this chain committed joins the block's tick.
    ///
    /// `holds` is what the member claims while its tick is in flight:
    /// its declared accesses when a counterpart's verdict can still
    /// discard its writes, and nothing otherwise. It and `reach` ride
    /// the line because every replica folds them and only a replica that
    /// can route the transaction can derive them: what a row is judged
    /// on after naming is what its line named.
    Member {
        /// The transaction, which this chain committed and has not
        /// resolved.
        tx: TxHash,
        /// The terms it joins on.
        joins: Joins,
        /// Which half settles it, and whether a discard keeps it.
        settlement: Settlement,
        /// What it holds while the tick is in flight.
        holds: Holds,
        /// The remote shards it reaches.
        reach: Reach,
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
    /// decoded. Everything but the holds and the reach is fixed width.
    #[must_use]
    pub fn wire_weight(&self) -> usize {
        TICK_LINE_BYTES
            + match self {
                Self::Member { holds, reach, .. } => {
                    holds.len() * TICK_HOLD_BYTES + reach.len() * TICK_REACH_BYTES
                }
                Self::Discard { .. } => 0,
            }
    }
}

/// A block's tick manifest, in the order its lines are charged and
/// applied.
pub type TickManifest = Capped<Vec<TickLine>, MAX_TICK_LINES_PER_BLOCK>;
