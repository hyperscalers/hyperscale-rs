//! Every block a run committed, kept for the questions a scenario asks of
//! a chain's whole history.
//!
//! A replica keeps its chain only down to its chain floor, so a scenario
//! asking where a transaction committed hours of simulated time ago asks
//! a store that has pruned the answer. The archive holds one copy of each
//! committed block per shard, decoded, taken from whichever replica
//! committed it first and walked often enough that every height is taken
//! before any replica's floor passes it.
//!
//! In a run that permits forks, a replica that commits a different block
//! at an archived height replaces it, once. A halt recovery's fresh
//! committee builds above the tip it harvested, at heights where the
//! replaced committee committed a tail nobody served it, and the shard's
//! chain is the one that goes on. A replica committing yet another block
//! at a height already replaced holds a tail the chain left behind, and
//! is abandoned rather than flipping the height back. A run that does not
//! permit forks panics on a differing block instead.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use hyperscale_storage::ShardChainReader;
use hyperscale_types::{BlockHash, BlockHeight, CertifiedBlock, ShardId, Verified};

use super::SimulationRunner;
use crate::NodeIndex;

/// One archived block, keyed by its hash for the fork check. A block's
/// sections are shared, so the archive costs little beyond the stores' own
/// copies, and a chain walk reads blocks without decoding or rehashing them.
type Archived = (BlockHash, Verified<CertifiedBlock>);

/// One block per committed `(shard, height)`.
#[derive(Default)]
pub struct ChainArchive {
    blocks: BTreeMap<ShardId, BTreeMap<BlockHeight, Archived>>,
    /// Highest height walked per `(host, shard)` store.
    walked: BTreeMap<(NodeIndex, ShardId), BlockHeight>,
    /// The heights whose first archived block the shard's chain replaced.
    replaced: BTreeSet<(ShardId, BlockHeight)>,
    /// The `(host, shard)` stores holding a block the shard's chain
    /// replaced.
    abandoned: BTreeSet<(NodeIndex, ShardId)>,
}

impl ChainArchive {
    /// Take every height each store committed since the last walk.
    ///
    /// # Panics
    ///
    /// If a store committed a block differing from the archived one at a
    /// height, in a run that does not permit forks.
    pub(super) fn record(&mut self, runner: &SimulationRunner) {
        let forks_permitted = runner.invariants.forks_permitted();
        let mut replaced = Vec::new();
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
                // Heights below the chain's origin are its predecessor's,
                // whose own stores archive them.
                let from = walked
                    .next()
                    .max(store.chain_floor())
                    .max(store.genesis_height());
                *walked = committed;
                let archived = self.blocks.entry(shard).or_default();
                let mut height = from;
                while height <= committed {
                    let hash = store
                        .get_block_metadata(height)
                        .map(|meta| meta.header().hash());
                    let stale = match archived.entry(height) {
                        Entry::Vacant(_) => true,
                        Entry::Occupied(slot) => {
                            let kept = slot.get().0;
                            match hash {
                                Some(hash) if hash != kept => {
                                    assert!(
                                        forks_permitted,
                                        "host {host} committed {shard:?} at {height:?} as \
                                         {hash:?}, but the archive holds {kept:?}"
                                    );
                                    if self.replaced.insert((shard, height)) {
                                        replaced.push((shard, height, kept));
                                        true
                                    } else {
                                        self.abandoned.insert((host, shard));
                                        false
                                    }
                                }
                                _ => false,
                            }
                        }
                    };
                    if stale {
                        let certified = store.get_block(height).unwrap_or_else(|| {
                            panic!(
                                "host {host} committed {shard:?} at {height:?}, at or above its \
                                 chain floor, and cannot rebuild the block"
                            )
                        });
                        archived.insert(height, (certified.block().hash(), certified));
                    }
                    height = height.next();
                }
            }
        }
        for (shard, height, kept) in replaced {
            for host in 0..runner.num_hosts() {
                let held = runner
                    .hosts_shard(host, shard)
                    .and_then(|store| store.get_block_metadata(height))
                    .map(|meta| meta.header().hash());
                if held == Some(kept) {
                    self.abandoned.insert((host, shard));
                }
            }
        }
    }

    /// Whether `host`'s store of `shard` committed a block the shard's
    /// chain replaced: a replica of a committee a halt recovery replaced,
    /// holding a tail the fresh committee never harvested.
    #[must_use]
    pub fn abandoned(&self, host: NodeIndex, shard: ShardId) -> bool {
        self.abandoned.contains(&(host, shard))
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
    blocks: Option<&'a BTreeMap<BlockHeight, Archived>>,
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
    #[must_use]
    pub fn block(&self, height: BlockHeight) -> Option<Verified<CertifiedBlock>> {
        self.blocks?
            .get(&height)
            .map(|(_, certified)| certified.clone())
    }
}
