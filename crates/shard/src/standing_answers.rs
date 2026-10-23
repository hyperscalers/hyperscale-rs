//! The answers a voter holds its consumer chain to, per producer route:
//! a count at a committed height, the deltas of the committed blocks no
//! persist has reached, and the deltas of the pending ones.
//!
//! Nothing attests the count in a header, so the count behind a block
//! is rebuilt from the frontier over every delta between them. A block
//! whose delta this voter never measured, a sync commit or one that
//! committed on its certificate before its check here completed, leaves
//! a hole the frontier cannot pass. A persist carrying the count its
//! shard loop read at a block this voter committed re-bases the frontier
//! on it, which closes a hole and re-anchors the count on the store.
//!
//! A count never honestly falls below zero: every delta is measured
//! against the parent its block commits on, and every frontier is read
//! off the store or folded from one. Where one would, the frontier is
//! wrong; a build with debug assertions fails on it, and a release build
//! warns and lets the frontier go.

use std::collections::{BTreeMap, HashMap};

use hyperscale_types::{AnswerAdditions, AnswerDelta, BlockHash, BlockHeight, StandingAnswers};
use tracing::warn;

/// A voter's hold on the answers its chain stands at.
#[derive(Debug, Default)]
pub struct HeldAnswers {
    /// The count at a committed height.
    frontier: Option<(BlockHeight, StandingAnswers)>,
    /// The delta each pending block measured, and what it adds, by
    /// block.
    pending: HashMap<BlockHash, (AnswerDelta, AnswerAdditions)>,
    /// The committed blocks above the newest persist and above the
    /// newest count the frontier re-based on, each with its delta where
    /// this voter measured one. The frontier folds over them without taking them,
    /// so a count read at one of them re-bases it.
    committed: BTreeMap<BlockHeight, (BlockHash, Option<AnswerDelta>)>,
    /// The newest height a persist reported.
    persisted: BlockHeight,
    /// How many times a count read off the store has been taken: a vote
    /// held for want of a count is re-driven when it moves.
    adopted: u64,
}

impl HeldAnswers {
    /// Hold `delta`, what `block`'s writes do to the answers its parent
    /// stands at, and `additions`, what it adds to them and to the
    /// crossings the chain's rows owe.
    pub fn measured(&mut self, block: BlockHash, delta: AnswerDelta, additions: AnswerAdditions) {
        self.pending.insert(block, (delta, additions));
    }

    /// What pending `block` adds, where this voter measured it.
    pub fn additions(&self, block: BlockHash) -> Option<&AnswerAdditions> {
        self.pending.get(&block).map(|(_, additions)| additions)
    }

    /// Keep the pending deltas of the blocks `keep` names.
    pub fn retain_pending(&mut self, keep: impl Fn(BlockHash) -> bool) {
        self.pending.retain(|block, _| keep(*block));
    }

    /// `block` committed at `height`, with the delta held for it.
    ///
    /// A commit at or below the newest persist is not recorded: that
    /// persist's count already covers it, so a frontier standing below it
    /// can go no further.
    pub fn committed(&mut self, height: BlockHeight, block: BlockHash) {
        let delta = self.pending.remove(&block).map(|(delta, _)| delta);
        if height <= self.persisted {
            if self.frontier.as_ref().is_some_and(|(at, _)| *at < height) {
                self.frontier = None;
            }
            return;
        }
        self.committed.insert(height, (block, delta));
        self.fold();
    }

    /// A persist reached `height`, carrying the count its loop read at
    /// a block, where it read one.
    ///
    /// Where this voter committed that block, the frontier re-bases on
    /// the count and folds again over the deltas above it, wherever it
    /// stood. A frontier it already held at or above the block is the
    /// one the re-base reaches; a build with debug assertions checks it.
    /// A count at a block this voter did not commit is not adopted, and
    /// a frontier below it goes. Either way nothing committed at or below
    /// `height` is held after, nor a frontier below it.
    pub fn persisted(
        &mut self,
        height: BlockHeight,
        count: Option<(BlockHeight, BlockHash, StandingAnswers)>,
    ) {
        self.persisted = self.persisted.max(height);
        if let Some((at, block, count)) = count {
            let ours = self
                .committed
                .get(&at)
                .is_some_and(|(committed, _)| *committed == block);
            if ours {
                self.adopted += 1;
                let held = self.frontier.replace((at, count));
                self.committed = self.committed.split_off(&at.next());
                self.fold();
                if let Some(held) = held.filter(|(was, _)| *was >= at) {
                    debug_assert_eq!(
                        self.frontier.as_ref(),
                        Some(&held),
                        "the count read at {at:?} folds to another frontier than the one held",
                    );
                }
            } else if self.frontier.as_ref().is_none_or(|(held, _)| *held < at) {
                self.committed = self.committed.split_off(&at.next());
                self.frontier = None;
            }
        }
        self.committed = self.committed.split_off(&height.next());
        if self.frontier.as_ref().is_some_and(|(at, _)| *at < height) {
            self.frontier = None;
        }
    }

    /// The count at a chain's genesis `height`, read whole off a store
    /// nothing else writes yet.
    pub fn seeded(&mut self, height: BlockHeight, count: StandingAnswers) {
        self.committed = self.committed.split_off(&height.next());
        self.frontier = Some((height, count));
        self.adopted += 1;
        self.fold();
    }

    /// How many counts read off the store this voter has taken.
    pub const fn adopted(&self) -> u64 {
        self.adopted
    }

    /// The count at `tip`, this voter's committed tip, where it holds
    /// one.
    pub fn at_tip(&self, tip: BlockHeight) -> Option<&StandingAnswers> {
        self.frontier
            .as_ref()
            .filter(|(at, _)| *at == tip)
            .map(|(_, count)| count)
    }

    /// The count behind a block whose parent is reached from `tip` by
    /// `ancestors`, the pending blocks from the tip's child to the
    /// parent, where every delta on the way is held.
    pub fn at(
        &self,
        tip: BlockHeight,
        ancestors: impl IntoIterator<Item = BlockHash>,
    ) -> Option<StandingAnswers> {
        let mut count = self.at_tip(tip)?.clone();
        for block in ancestors {
            let advanced = count.advance(&self.pending.get(&block)?.0);
            debug_assert!(
                advanced.is_ok(),
                "the answer count behind {block:?} falls below zero"
            );
            if let Err(route) = advanced {
                warn!(?route, ?block, "Answer count would fall below zero");
                return None;
            }
        }
        Some(count)
    }

    /// The highest committed block this voter holds no delta for.
    #[cfg(test)]
    pub fn hole(&self) -> Option<BlockHeight> {
        self.committed
            .iter()
            .rev()
            .find(|(_, (_, delta))| delta.is_none())
            .map(|(height, _)| *height)
    }

    /// How many committed blocks are held.
    #[cfg(test)]
    pub fn committed_len(&self) -> usize {
        self.committed.len()
    }

    /// Fold the run of measured commits directly above the frontier
    /// into it, keeping them.
    fn fold(&mut self) {
        let Some((at, count)) = self.frontier.as_mut() else {
            return;
        };
        let mut below_zero = false;
        for (height, (_, delta)) in self.committed.range(at.next()..) {
            let Some(delta) = delta.as_ref().filter(|_| *height == at.next()) else {
                break;
            };
            let advanced = count.advance(delta);
            debug_assert!(
                advanced.is_ok(),
                "the answer count at {height:?} falls below zero"
            );
            if let Err(route) = advanced {
                warn!(
                    ?route,
                    height = height.inner(),
                    "Answer count would fall below zero"
                );
                below_zero = true;
                break;
            }
            *at = *height;
        }
        if below_zero {
            self.frontier = None;
        }
    }
}
