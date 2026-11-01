//! [`Engagement`]: a transaction a block's provisions name, from the
//! shard and height that sent them.

use std::collections::BTreeSet;
use std::ops::RangeInclusive;

use hyperscale_hbor::{Capped, Hbor};

use crate::{
    BlockHeight, EpochWindows, MAX_ENGAGEMENTS_PER_BLOCK, Provision, ShardId, TopologySnapshot,
    TxHash, Verifiable, WeightedTimestamp,
};

/// One transaction a committed provision batch names: the evidence that
/// `source` committed `tx_hash` at `source_height`.
///
/// The field order is the sort order, so every entry for one
/// `(source, tx_hash)` pair is adjacent and a range answers the pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub struct Engagement {
    /// The shard whose committed block sent the batch.
    pub source: ShardId,
    /// The transaction the batch names.
    pub tx_hash: TxHash,
    /// The height of the source block the batch was read at.
    pub source_height: BlockHeight,
    /// The source block's anchor, its parent-QC weighted timestamp
    /// ([`Provision::source_block_ts`]): what places the entry inside
    /// or outside a recovery's band once the recovery is no longer
    /// pending.
    pub source_anchor: WeightedTimestamp,
}

/// The engagements a sealed block keeps of the provisions it dropped,
/// strictly ascending, so one set has one encoding.
pub type Engagements = Capped<Vec<Engagement>, MAX_ENGAGEMENTS_PER_BLOCK>;

impl Engagement {
    /// The entry `part` names, an empty part included: a payer holding
    /// none of a transaction's reads sends an empty one, and it is still
    /// the payer's word that the transaction committed.
    #[must_use]
    pub fn of_part(part: &Provision) -> Self {
        Self {
            source: part.source_shard(),
            tx_hash: part.tx_hash(),
            source_height: part.block_height(),
            source_anchor: part.source_block_ts(),
        }
    }

    /// The set a block's provisions engage, whatever order they ride in.
    #[must_use]
    pub fn of_provisions(parts: &[Verifiable<Provision>]) -> BTreeSet<Self> {
        parts.iter().map(|part| Self::of_part(part)).collect()
    }

    /// Every entry of `set` naming `tx_hash` from `source`, whatever
    /// source block sent it.
    pub fn of_pair(
        set: &BTreeSet<Self>,
        source: ShardId,
        tx_hash: TxHash,
    ) -> impl Iterator<Item = &Self> {
        set.range(Self::pair_range(source, tx_hash))
    }

    /// The span of the sort order holding every entry naming `tx_hash`
    /// from `source`.
    #[must_use]
    pub const fn pair_range(source: ShardId, tx_hash: TxHash) -> RangeInclusive<Self> {
        Self {
            source,
            tx_hash,
            source_height: BlockHeight::GENESIS,
            source_anchor: WeightedTimestamp::ZERO,
        }..=Self {
            source,
            tx_hash,
            source_height: BlockHeight::new(u64::MAX),
            source_anchor: WeightedTimestamp::from_millis(u64::MAX),
        }
    }

    /// Whether the source still vouches for this entry under `snapshot`,
    /// on the epoch grid `windows`: no recovery pending there fences its
    /// height ([`TopologySnapshot::recovery_fences`]), and no recovery it
    /// records, pending or completed, holds its block in the band the
    /// recovered chain lets go of at its crossing block
    /// ([`TopologySnapshot::recovery_orphaned`]).
    ///
    /// The one rule every engagement answers to, committed or riding a
    /// block above the committed tip: the recovery record is committed
    /// beacon state, so the answer is a function of the judging anchor's
    /// snapshot, and a voter that has committed the carrying block
    /// answers as one that has not.
    #[must_use]
    pub fn stands_under(&self, snapshot: &TopologySnapshot, windows: EpochWindows) -> bool {
        !snapshot.recovery_fences(self.source, self.source_height)
            && !snapshot.recovery_orphaned(
                windows,
                self.source,
                self.source_anchor,
                self.source_height,
            )
    }
}
