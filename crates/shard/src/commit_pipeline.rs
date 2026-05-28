//! Commit pipeline: out-of-order commit buffering.
//!
//! When the 2-chain rule fires `BlockReadyToCommit` for the committable
//! parent and the height is beyond `committed_height + 1` (e.g.
//! signature verification completed out of order), the commit is parked
//! in [`CommitPipeline::out_of_order`] keyed by target height and
//! drained in sequence once the predecessor commits.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_core::CommitSource;
use hyperscale_types::{BlockHeight, CertifiedBlock, Verified};

pub struct CommitPipeline {
    /// Out-of-order commit buffer: commits received with height greater than
    /// `committed_height + 1`, parked until the predecessor commits.
    /// Keyed by target height.
    out_of_order: BTreeMap<BlockHeight, (Arc<Verified<CertifiedBlock>>, CommitSource)>,
}

impl CommitPipeline {
    pub const fn new() -> Self {
        Self {
            out_of_order: BTreeMap::new(),
        }
    }

    /// Drop all pipeline entries at or below `committed_height`.
    pub fn cleanup_committed(&mut self, committed_height: BlockHeight) {
        self.out_of_order
            .retain(|height, _| *height > committed_height);
    }

    /// Park a commit received with height beyond the next expected height.
    pub fn buffer_out_of_order(
        &mut self,
        height: BlockHeight,
        certified: Arc<Verified<CertifiedBlock>>,
        source: CommitSource,
    ) {
        self.out_of_order.insert(height, (certified, source));
    }

    /// Take the buffered out-of-order commit at `height`, if any.
    ///
    /// Used by the commit-chain drain loop to process the next buffered
    /// commit after committing the predecessor.
    pub fn take_out_of_order(
        &mut self,
        height: BlockHeight,
    ) -> Option<(Arc<Verified<CertifiedBlock>>, CommitSource)> {
        self.out_of_order.remove(&height)
    }

    pub fn out_of_order_len(&self) -> usize {
        self.out_of_order.len()
    }

    /// True if a commit is buffered for `height` in the out-of-order pipeline.
    pub fn has_out_of_order_at(&self, height: BlockHeight) -> bool {
        self.out_of_order.contains_key(&height)
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        Block, BlockHash, QuorumCertificate, Round, ShardGroupId, SignerBitfield, StateRoot,
        ValidatorId, WeightedTimestamp, zero_bls_signature,
    };

    use super::*;

    fn make_certified(height: u64, tag: u64) -> Arc<Verified<CertifiedBlock>> {
        let block = Block::genesis(ShardGroupId::new(0), ValidatorId::new(tag), StateRoot::ZERO);
        let qc = QuorumCertificate::new(
            block.hash(),
            ShardGroupId::new(0),
            BlockHeight::new(height),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        );
        // SAFETY: synthetic test fixture, no real signature.
        let verified_qc = Verified::<QuorumCertificate>::new_unchecked(qc);
        let certified = CertifiedBlock::new_unchecked(block, verified_qc);
        // SAFETY: synthetic test fixture; pipeline buffering doesn't
        // exercise the predicate.
        Arc::new(Verified::<CertifiedBlock>::new_unchecked(certified))
    }

    #[test]
    fn take_out_of_order_removes_and_returns_entry() {
        let mut pipeline = CommitPipeline::new();
        let certified = make_certified(5, 1);
        let hash = certified.block().hash();
        pipeline
            .out_of_order
            .insert(BlockHeight::new(5), (certified, CommitSource::Aggregator));

        let taken = pipeline.take_out_of_order(BlockHeight::new(5));
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().0.block().hash(), hash);
        assert_eq!(pipeline.out_of_order_len(), 0);
    }

    #[test]
    fn cleanup_committed_drops_entries_at_and_below_height() {
        let mut pipeline = CommitPipeline::new();
        pipeline.out_of_order.insert(
            BlockHeight::new(4),
            (make_certified(4, 4), CommitSource::Aggregator),
        );
        pipeline.out_of_order.insert(
            BlockHeight::new(5),
            (make_certified(5, 5), CommitSource::Aggregator),
        );
        pipeline.out_of_order.insert(
            BlockHeight::new(6),
            (make_certified(6, 6), CommitSource::Aggregator),
        );

        pipeline.cleanup_committed(BlockHeight::new(5));

        assert_eq!(pipeline.out_of_order_len(), 1);
        assert!(pipeline.out_of_order.contains_key(&BlockHeight::new(6)));
    }
}

#[cfg(test)]
mod properties {
    use hyperscale_types::{
        Block, BlockHash, QuorumCertificate, Round, ShardGroupId, SignerBitfield, StateRoot,
        ValidatorId, WeightedTimestamp, zero_bls_signature,
    };
    use proptest::prelude::*;

    use super::*;

    fn make_certified(height: u64, tag: u64) -> Arc<Verified<CertifiedBlock>> {
        let block = Block::genesis(ShardGroupId::new(0), ValidatorId::new(tag), StateRoot::ZERO);
        let qc = QuorumCertificate::new(
            block.hash(),
            ShardGroupId::new(0),
            BlockHeight::new(height),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        );
        // SAFETY: synthetic test fixture, no real signature.
        let verified_qc = Verified::<QuorumCertificate>::new_unchecked(qc);
        let certified = CertifiedBlock::new_unchecked(block, verified_qc);
        // SAFETY: synthetic test fixture; pipeline buffering doesn't
        // exercise the predicate.
        Arc::new(Verified::<CertifiedBlock>::new_unchecked(certified))
    }

    proptest! {
        /// Invariant: `cleanup_committed(h1)` followed by `cleanup_committed(h2)`
        /// leaves the pipeline in the same state as a single
        /// `cleanup_committed(max(h1, h2))` call, regardless of argument order.
        #[test]
        fn cleanup_committed_is_order_independent_and_monotone(
            heights in prop::collection::vec(0u64..20, 1..20),
            h1 in 0u64..25,
            h2 in 0u64..25,
        ) {
            let seed = |heights: &[u64]| {
                let mut p = CommitPipeline::new();
                for &h in heights {
                    p.out_of_order.insert(
                        BlockHeight::new(h),
                        (make_certified(h, h), CommitSource::Aggregator),
                    );
                }
                p
            };

            let mut a = seed(&heights);
            a.cleanup_committed(BlockHeight::new(h1));
            a.cleanup_committed(BlockHeight::new(h2));

            let mut b = seed(&heights);
            b.cleanup_committed(BlockHeight::new(h2));
            b.cleanup_committed(BlockHeight::new(h1));

            let mut c = seed(&heights);
            c.cleanup_committed(BlockHeight::new(h1.max(h2)));

            prop_assert_eq!(a.out_of_order_len(), b.out_of_order_len());
            prop_assert_eq!(a.out_of_order_len(), c.out_of_order_len());
        }

        /// Invariant: after `cleanup_committed(h)`, every remaining entry has a
        /// height strictly greater than `h`.
        #[test]
        fn cleanup_committed_leaves_only_entries_above_height(
            heights in prop::collection::vec(0u64..30, 0..30),
            cutoff in 0u64..35,
        ) {
            let mut p = CommitPipeline::new();
            for &h in &heights {
                p.out_of_order.insert(
                    BlockHeight::new(h),
                    (make_certified(h, h), CommitSource::Aggregator),
                );
            }

            p.cleanup_committed(BlockHeight::new(cutoff));

            for height in p.out_of_order.keys() {
                prop_assert!(height.inner() > cutoff);
            }
        }

        /// Invariant: `buffer` then `take` at the same key is an identity —
        /// the value comes back and the structure is left empty at that key.
        #[test]
        fn insert_then_take_is_identity(
            height in 0u64..100,
            tag in 0u64..100,
        ) {
            let mut p = CommitPipeline::new();
            let certified = make_certified(height, tag);
            let hash = certified.block().hash();

            p.out_of_order.insert(
                BlockHeight::new(height),
                (certified, CommitSource::Aggregator),
            );
            let taken = p.take_out_of_order(BlockHeight::new(height));
            prop_assert!(taken.is_some());
            prop_assert_eq!(taken.unwrap().0.block().hash(), hash);
            prop_assert!(!p.out_of_order.contains_key(&BlockHeight::new(height)));
        }
    }
}
