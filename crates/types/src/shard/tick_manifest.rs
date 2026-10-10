//! [`TickLine`]: one line of a block's tick manifest, the section in
//! which a proposer names what the block's tick holds and what it lets
//! go. [`StatedTerms`]: one entry of a block's terms section, the
//! section in which a block states the terms a transaction it commits
//! stands on.

use hyperscale_hbor::{Capped, Hbor};
use hyperscale_vm_effects::CrossingId;
use hyperscale_vm_types::{MAX_CROSSINGS_PER_TX, Mode};

use crate::{
    AbortCharge, DeclaredKey, MAX_HOLDS_PER_MEMBER, MAX_PREFIXES_PER_TX, MAX_TICK_LINES_PER_BLOCK,
    MAX_TXS_PER_BLOCK, ShardId, SubstateKey, TICK_CROSSING_BYTES, TICK_HOLD_BYTES, TICK_LINE_BYTES,
    TICK_REACH_BYTES, TICK_RESERVE_BYTES, TICK_TERMS_BYTES, TickHalf, TickId, TxHash,
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
    /// Not in the batch. Past the deadline that bounds it, or the
    /// victim of a hold cycle the block proves, so no execution here
    /// reaches an outcome, and the tick attests `Aborted` on nothing but
    /// the hash and the reservation its committing block took.
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

/// What a member's declared reservations promise of the vaults its
/// shard charges fees to: each vault once, in key order, at the sum of
/// the amounts reserved on it.
pub type Reserves = Capped<Vec<(SubstateKey, u128)>, MAX_HOLDS_PER_MEMBER>;

/// One line of a block's tick manifest.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub enum TickLine {
    /// A transaction this chain committed joins the block's tick.
    ///
    /// `holds` is what the member claims while its tick is in flight:
    /// its declared accesses when a counterpart's verdict can still
    /// discard its writes, and nothing otherwise. It, `reach` and
    /// `awaits` ride the line because every replica folds them and only a replica that
    /// can route the transaction can derive them: what a row is judged
    /// on after naming is what its line named. So is `charge`, the
    /// floor an abort of the member burns, priced where the line is
    /// named: a terminal fates the member off its row alone. `share` and
    /// `reserves` ride it for the member a line names in the block that
    /// commits it, whose row the line alone writes.
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
        /// The remote shards whose certificates its settlement awaits:
        /// where a core or whole member's siblings run, each holding a
        /// seat while its own tick is in flight. Empty for a member that
        /// awaits nobody, and for an abort, which seats nothing.
        awaits: Reach,
        /// What an abort of it burns, out of whose vault.
        charge: AbortCharge,
        /// The price this shard attests for it, in quanta.
        share: u128,
        /// What its declared reservations promise of this shard's fee
        /// vaults.
        reserves: Reserves,
    },
    /// The chain's terminal lets a member go with an abort: its row
    /// leaves the family, and its charge is burned where its vault lies.
    /// The terminal names one for every row it inherits, and no other
    /// block names any.
    Fate {
        /// The transaction, whose row the chain still holds.
        tx: TxHash,
        /// What its abort burns, out of whose vault.
        charge: AbortCharge,
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
    /// decoded. Everything but the holds, the reach and the reserves is
    /// fixed width.
    #[must_use]
    pub fn wire_weight(&self) -> usize {
        TICK_LINE_BYTES
            + match self {
                Self::Member {
                    holds,
                    reach,
                    awaits,
                    reserves,
                    ..
                } => {
                    holds.len() * TICK_HOLD_BYTES
                        + (reach.len() + awaits.len()) * TICK_REACH_BYTES
                        + reserves.len() * TICK_RESERVE_BYTES
                }
                Self::Fate { .. } | Self::Discard { .. } => 0,
            }
    }
}

/// A block's tick manifest, in the order its lines are charged and
/// applied.
pub type TickManifest = Capped<Vec<TickLine>, MAX_TICK_LINES_PER_BLOCK>;

/// The terms a transaction stands on from the block that commits it:
/// everything a replica reads to judge the member that only a replica
/// able to route the transaction can derive.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct MemberTerms {
    /// Whether this shard runs a leg of the transaction and not its
    /// core.
    pub leg: bool,
    /// Which half settles it, and whether a discard keeps it.
    pub settlement: Settlement,
    /// Its declared accesses, each under the mode it takes.
    pub declared: Holds,
    /// The remote shards it reaches.
    pub reach: Reach,
    /// The remote shards whose certificates its settlement awaits.
    pub awaits: Reach,
    /// The remote shards whose committed bundle it requires before it
    /// runs.
    pub engages: Reach,
    /// The escrowed crossings it consumes.
    pub crossings: Capped<Vec<CrossingId>, MAX_CROSSINGS_PER_TX>,
    /// Whether it is the payer's leg, which waits for every shard it
    /// reaches to engage.
    pub waits: bool,
    /// What an abort of it burns, out of whose vault.
    pub charge: AbortCharge,
    /// The price this shard attests for it, in quanta.
    pub share: u128,
    /// What its declared reservations promise of this shard's fee
    /// vaults.
    pub reserves: Reserves,
}

impl MemberTerms {
    /// An upper bound on what the entry stating these terms costs the
    /// block that carries it, its transaction's hash included, so the
    /// section's budget is checked without re-encoding what was decoded.
    /// Everything but the five lists is fixed width.
    #[must_use]
    pub fn wire_weight(&self) -> usize {
        TICK_TERMS_BYTES
            + self.declared.len() * TICK_HOLD_BYTES
            + (self.reach.len() + self.awaits.len() + self.engages.len()) * TICK_REACH_BYTES
            + self.crossings.len() * TICK_CROSSING_BYTES
            + self.reserves.len() * TICK_RESERVE_BYTES
    }
}

/// One entry of a block's terms section.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct StatedTerms {
    /// The transaction, which the block commits.
    pub tx: TxHash,
    /// The terms it stands on.
    pub terms: MemberTerms,
}

/// A block's terms section, in the block's transaction order.
pub type TermsSection = Capped<Vec<StatedTerms>, MAX_TXS_PER_BLOCK>;
