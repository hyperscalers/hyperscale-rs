//! [`Engagement`]: a transaction a block's provisions name, from the
//! shard and height that sent them.

use std::collections::BTreeSet;
use std::sync::Arc;

use hyperscale_hbor::{Capped, Hbor};

use crate::{BlockHeight, MAX_ENGAGEMENTS_PER_BLOCK, Provisions, ShardId, TxHash, Verifiable};

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
}

/// The engagements a sealed block keeps of the provisions it dropped,
/// strictly ascending, so one set has one encoding.
pub type Engagements = Capped<Vec<Engagement>, MAX_ENGAGEMENTS_PER_BLOCK>;

impl Engagement {
    /// One entry per transaction `batch` names, empty entries included:
    /// a payer holding none of a transaction's reads sends an empty one,
    /// and it is still the payer's word that the transaction committed.
    pub fn of_batch(batch: &Provisions) -> impl Iterator<Item = Self> + '_ {
        let source = batch.source_shard();
        let source_height = batch.block_height();
        batch.transactions().iter().map(move |entry| Self {
            source,
            tx_hash: entry.tx_hash,
            source_height,
        })
    }

    /// The set a block's provisions engage, whatever order they ride in.
    #[must_use]
    pub fn of_provisions(batches: &[Arc<Verifiable<Provisions>>]) -> BTreeSet<Self> {
        batches
            .iter()
            .flat_map(|batch| Self::of_batch(batch))
            .collect()
    }
}
