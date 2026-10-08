//! Every block a run committed, kept for the questions a scenario asks of
//! a chain's whole history.
//!
//! A replica keeps its chain only down to its chain floor, so a scenario
//! asking where a transaction committed hours of simulated time ago asks
//! a store that has pruned the answer. The archive holds one copy of each
//! committed block per shard, encoded, taken from whichever replica
//! committed it first and walked often enough that every height is taken
//! before any replica's floor passes it.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_hbor::{from_slice, to_vec};
use hyperscale_storage::ShardChainReader;
use hyperscale_types::{BlockHeight, CertifiedBlock, ShardId, Verified};

use super::SimulationRunner;
use crate::NodeIndex;

/// One encoded block per committed `(shard, height)`.
#[derive(Default)]
pub struct ChainArchive {
    blocks: BTreeMap<ShardId, BTreeMap<BlockHeight, Arc<[u8]>>>,
    /// Highest height walked per `(host, shard)` store.
    walked: BTreeMap<(NodeIndex, ShardId), BlockHeight>,
}

impl ChainArchive {
    /// Take every height each store committed since the last walk.
    pub(super) fn record(&mut self, runner: &SimulationRunner) {
        for host in 0..runner.num_hosts() {
            for shard in runner.hosted_shards_of(host) {
                let Some(store) = runner.hosts_shard(host, shard) else {
                    continue;
                };
                let committed = store.committed_height();
                let walked = self.walked.entry((host, shard)).or_default();
                // A store replaced under the host restarts below where the
                // last one stood; walk it from its own head on.
                if committed < *walked {
                    *walked = committed;
                }
                let from = walked.next().max(store.chain_floor());
                *walked = committed;
                let archived = self.blocks.entry(shard).or_default();
                let mut height = from;
                while height <= committed {
                    if !archived.contains_key(&height)
                        && let Some(certified) = store.get_block(height)
                    {
                        let bytes = to_vec(&*certified).expect("a committed block encodes");
                        archived.insert(height, Arc::from(bytes));
                    }
                    height = height.next();
                }
            }
        }
    }

    /// `shard`'s archived chain.
    #[must_use]
    pub fn chain(&self, shard: ShardId) -> ArchivedChain<'_> {
        ArchivedChain {
            blocks: self.blocks.get(&shard),
        }
    }
}

/// One shard's archived blocks.
pub struct ArchivedChain<'a> {
    blocks: Option<&'a BTreeMap<BlockHeight, Arc<[u8]>>>,
}

impl ArchivedChain<'_> {
    /// The highest archived height.
    #[must_use]
    pub fn tip(&self) -> BlockHeight {
        self.blocks
            .and_then(|blocks| blocks.keys().next_back().copied())
            .unwrap_or(BlockHeight::GENESIS)
    }

    /// The lowest archived height.
    #[must_use]
    pub fn first(&self) -> BlockHeight {
        self.blocks
            .and_then(|blocks| blocks.keys().next().copied())
            .unwrap_or(BlockHeight::GENESIS)
    }

    /// The block committed at `height`, if archived.
    ///
    /// # Panics
    ///
    /// If an archived block no longer decodes.
    #[must_use]
    pub fn block(&self, height: BlockHeight) -> Option<Verified<CertifiedBlock>> {
        let bytes = self.blocks?.get(&height)?;
        let certified: CertifiedBlock = from_slice(bytes).expect("an archived block decodes");
        Some(Verified::<CertifiedBlock>::from_persisted(certified))
    }
}
