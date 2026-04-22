//! Commit pipeline: certified blocks awaiting commit, out-of-order commit
//! buffering, and commit buffering for blocks still awaiting data.
//!
//! A block travels through this pipeline after its QC forms:
//!
//! 1. QC forms → block enters [`CommitPipeline::certified_blocks`]
//! 2. Two-chain rule fires `BlockReadyToCommit` for the committable parent
//! 3. If the block data (transactions/certificates) has not fully arrived,
//!    the commit is parked in [`CommitPipeline::awaiting_data`] keyed by
//!    block hash, to be retried when data arrives.
//! 4. If the commit arrives out of order (height > `committed_height + 1`),
//!    it is parked in [`CommitPipeline::out_of_order`] keyed by height, to
//!    be drained in sequence once the predecessor commits.

use hyperscale_core::CommitSource;
use hyperscale_types::{Block, BlockHash, BlockHeight, QuorumCertificate};
use std::collections::{BTreeMap, HashMap};

pub(crate) struct CommitPipeline {
    /// Blocks that have been certified (have QC) but not yet committed.
    /// Keyed by block hash.
    pub(crate) certified_blocks: HashMap<BlockHash, Block>,

    /// Out-of-order commit buffer: commits received with height greater than
    /// `committed_height + 1`, parked until the predecessor commits.
    /// Keyed by target height.
    pub(crate) out_of_order: BTreeMap<BlockHeight, (BlockHash, QuorumCertificate, CommitSource)>,

    /// Awaiting-data commit buffer: commits whose block payload
    /// (transactions/certificates) has not fully arrived yet, retried when
    /// the block completes. Keyed by block hash.
    pub(crate) awaiting_data: HashMap<BlockHash, (BlockHeight, QuorumCertificate, CommitSource)>,
}

impl CommitPipeline {
    pub fn new() -> Self {
        Self {
            certified_blocks: HashMap::new(),
            out_of_order: BTreeMap::new(),
            awaiting_data: HashMap::new(),
        }
    }

    /// Drop all pipeline entries at or below `committed_height`.
    pub fn cleanup_committed(&mut self, committed_height: BlockHeight) {
        self.certified_blocks
            .retain(|_, block| block.height() > committed_height);
        self.awaiting_data
            .retain(|_, (height, _, _)| *height > committed_height);
        self.out_of_order
            .retain(|height, _| *height > committed_height);
    }

    /// Take the buffered out-of-order commit at `height`, if any.
    ///
    /// Used by the commit-chain drain loop to process the next buffered
    /// commit after committing the predecessor.
    pub fn take_out_of_order(
        &mut self,
        height: BlockHeight,
    ) -> Option<(BlockHash, QuorumCertificate, CommitSource)> {
        self.out_of_order.remove(&height)
    }

    /// Take the awaiting-data commit for `block_hash`, if any.
    ///
    /// Used when a previously-incomplete block finishes assembling and its
    /// parked commit should be retried.
    pub fn take_awaiting_data(
        &mut self,
        block_hash: &BlockHash,
    ) -> Option<(BlockHeight, QuorumCertificate, CommitSource)> {
        self.awaiting_data.remove(block_hash)
    }

    pub fn certified_blocks_len(&self) -> usize {
        self.certified_blocks.len()
    }

    pub fn out_of_order_len(&self) -> usize {
        self.out_of_order.len()
    }

    pub fn awaiting_data_len(&self) -> usize {
        self.awaiting_data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{Hash, QuorumCertificate};

    fn make_qc(height: u64) -> QuorumCertificate {
        let mut qc = QuorumCertificate::genesis();
        qc.height = BlockHeight(height);
        qc
    }

    fn bh(tag: &[u8]) -> BlockHash {
        BlockHash::from_raw(Hash::from_bytes(tag))
    }

    #[test]
    fn take_out_of_order_removes_and_returns_entry() {
        let mut pipeline = CommitPipeline::new();
        let hash = bh(b"h5");
        pipeline
            .out_of_order
            .insert(BlockHeight(5), (hash, make_qc(5), CommitSource::Aggregator));

        let taken = pipeline.take_out_of_order(BlockHeight(5));
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().0, hash);
        assert_eq!(pipeline.out_of_order_len(), 0);
    }

    #[test]
    fn take_awaiting_data_removes_and_returns_entry() {
        let mut pipeline = CommitPipeline::new();
        let hash = bh(b"h5");
        pipeline
            .awaiting_data
            .insert(hash, (BlockHeight(5), make_qc(5), CommitSource::Aggregator));

        let taken = pipeline.take_awaiting_data(&hash);
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().0, BlockHeight(5));
        assert_eq!(pipeline.awaiting_data_len(), 0);
    }

    #[test]
    fn cleanup_committed_drops_entries_at_and_below_height() {
        let mut pipeline = CommitPipeline::new();
        let h4 = bh(b"h4");
        let h5 = bh(b"h5");
        let h6 = bh(b"h6");

        pipeline
            .out_of_order
            .insert(BlockHeight(4), (h4, make_qc(4), CommitSource::Aggregator));
        pipeline
            .out_of_order
            .insert(BlockHeight(5), (h5, make_qc(5), CommitSource::Aggregator));
        pipeline
            .out_of_order
            .insert(BlockHeight(6), (h6, make_qc(6), CommitSource::Aggregator));
        pipeline
            .awaiting_data
            .insert(h5, (BlockHeight(5), make_qc(5), CommitSource::Aggregator));
        pipeline
            .awaiting_data
            .insert(h6, (BlockHeight(6), make_qc(6), CommitSource::Aggregator));

        pipeline.cleanup_committed(BlockHeight(5));

        assert_eq!(pipeline.out_of_order_len(), 1);
        assert!(pipeline.out_of_order.contains_key(&BlockHeight(6)));
        assert_eq!(pipeline.awaiting_data_len(), 1);
        assert!(pipeline.awaiting_data.contains_key(&h6));
    }
}

#[cfg(test)]
mod properties {
    use super::*;
    use hyperscale_types::Hash;
    use proptest::prelude::*;

    fn make_qc(height: u64) -> QuorumCertificate {
        let mut qc = QuorumCertificate::genesis();
        qc.height = BlockHeight(height);
        qc
    }

    fn hash_for(tag: u64) -> BlockHash {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&tag.to_le_bytes());
        BlockHash::from_raw(Hash::from_bytes(&bytes))
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
                    let hash = hash_for(h);
                    p.out_of_order.insert(
                        BlockHeight(h),
                        (hash, make_qc(h), CommitSource::Aggregator),
                    );
                    p.awaiting_data.insert(
                        hash,
                        (BlockHeight(h), make_qc(h), CommitSource::Aggregator),
                    );
                }
                p
            };

            let mut a = seed(&heights);
            a.cleanup_committed(BlockHeight(h1));
            a.cleanup_committed(BlockHeight(h2));

            let mut b = seed(&heights);
            b.cleanup_committed(BlockHeight(h2));
            b.cleanup_committed(BlockHeight(h1));

            let mut c = seed(&heights);
            c.cleanup_committed(BlockHeight(h1.max(h2)));

            prop_assert_eq!(a.out_of_order_len(), b.out_of_order_len());
            prop_assert_eq!(a.out_of_order_len(), c.out_of_order_len());
            prop_assert_eq!(a.awaiting_data_len(), b.awaiting_data_len());
            prop_assert_eq!(a.awaiting_data_len(), c.awaiting_data_len());
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
                let hash = hash_for(h);
                p.out_of_order.insert(
                    BlockHeight(h),
                    (hash, make_qc(h), CommitSource::Aggregator),
                );
                p.awaiting_data.insert(
                    hash,
                    (BlockHeight(h), make_qc(h), CommitSource::Aggregator),
                );
            }

            p.cleanup_committed(BlockHeight(cutoff));

            for height in p.out_of_order.keys() {
                prop_assert!(height.0 > cutoff);
            }
            for (height, _, _) in p.awaiting_data.values() {
                prop_assert!(height.0 > cutoff);
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
            let hash = hash_for(tag);

            p.out_of_order.insert(
                BlockHeight(height),
                (hash, make_qc(height), CommitSource::Aggregator),
            );
            let taken = p.take_out_of_order(BlockHeight(height));
            prop_assert!(taken.is_some());
            prop_assert_eq!(taken.unwrap().0, hash);
            prop_assert!(!p.out_of_order.contains_key(&BlockHeight(height)));

            p.awaiting_data.insert(
                hash,
                (BlockHeight(height), make_qc(height), CommitSource::Aggregator),
            );
            let taken = p.take_awaiting_data(&hash);
            prop_assert!(taken.is_some());
            prop_assert_eq!(taken.unwrap().0, BlockHeight(height));
            prop_assert!(!p.awaiting_data.contains_key(&hash));
        }
    }
}
