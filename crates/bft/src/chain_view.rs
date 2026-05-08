//! Read-only view over the node's knowledge of the chain.
//!
//! `ChainView<'a>` bundles the committed-tip scalars, the latest QC, and a
//! borrowed reference to the pending block map. It unifies reads that would
//! otherwise have to thread half a dozen coordinator fields through every
//! helper — proposal building, header validation, commit decisions all
//! consult the same chain state.
//!
//! The view is **strictly a borrow**: no state is owned here, no lifecycle,
//! no mutations. It's a lens, not a sub-machine. The underlying fields live
//! on `BftCoordinator` / `PendingBlock` just as before.

use std::collections::{HashMap, HashSet};

use hyperscale_types::{
    Block, BlockHash, BlockHeader, BlockHeight, InFlightCount, ProvisionHash, QuorumCertificate,
    ShardGroupId, StateRoot, TxHash, WaveId,
};
use tracing::warn;

use crate::pending::PendingBlock;

pub struct ChainView<'a> {
    local_shard: ShardGroupId,
    committed_height: BlockHeight,
    committed_hash: BlockHash,
    committed_state_root: StateRoot,
    latest_qc: Option<&'a QuorumCertificate>,
    pending: &'a HashMap<BlockHash, PendingBlock>,
}

impl<'a> ChainView<'a> {
    pub const fn new(
        local_shard: ShardGroupId,
        committed_height: BlockHeight,
        committed_hash: BlockHash,
        committed_state_root: StateRoot,
        latest_qc: Option<&'a QuorumCertificate>,
        pending: &'a HashMap<BlockHash, PendingBlock>,
    ) -> Self {
        Self {
            local_shard,
            committed_height,
            committed_hash,
            committed_state_root,
            latest_qc,
            pending,
        }
    }

    /// Borrow a pending block by hash. Used by callers that need to inspect
    /// per-block state (received transactions, finalized waves) beyond what
    /// the dedicated header / state-root accessors expose.
    pub fn get_pending(&self, block_hash: BlockHash) -> Option<&PendingBlock> {
        self.pending.get(&block_hash)
    }

    /// Look up a block by hash in the pending block map (if assembled).
    /// Returns `None` if the block isn't pending or hasn't been constructed.
    fn get_block(&self, block_hash: BlockHash) -> Option<Block> {
        let pending = self.pending.get(&block_hash)?;
        let block = pending.block()?;
        Some((*block).clone())
    }

    /// Header-only lookup, cheaper than `get_block` when only header fields
    /// are needed. Pending blocks always carry their header even before full
    /// assembly, so this succeeds in cases where `get_block` would fail.
    pub fn get_header(&self, block_hash: BlockHash) -> Option<&BlockHeader> {
        self.pending.get(&block_hash).map(PendingBlock::header)
    }

    /// State root of the parent block. Returns the committed-tip state root
    /// when `parent_block_hash` IS the committed tip (may have been pruned
    /// from `pending` by cleanup) or when lookup otherwise fails.
    pub fn parent_state_root(&self, parent_block_hash: BlockHash) -> StateRoot {
        if parent_block_hash == self.committed_hash {
            return self.committed_state_root;
        }
        self.get_header(parent_block_hash).map_or_else(
            || {
                warn!(
                    ?parent_block_hash,
                    committed_hash = ?self.committed_hash,
                    "Parent header not found for state root lookup"
                );
                self.committed_state_root
            },
            BlockHeader::state_root,
        )
    }

    /// In-flight count on the parent header. Returns zero if the header is
    /// missing (parent pruned from `pending`).
    pub fn parent_in_flight(&self, parent_block_hash: BlockHash) -> InFlightCount {
        self.get_header(parent_block_hash)
            .map_or(InFlightCount::ZERO, BlockHeader::in_flight)
    }

    /// Parent to use when building the next proposal: the latest QC's block
    /// if any, otherwise the committed tip under a genesis QC tagged with
    /// the local shard.
    pub fn proposal_parent(&self) -> (BlockHash, QuorumCertificate) {
        self.latest_qc.map_or_else(
            || {
                (
                    self.committed_hash,
                    QuorumCertificate::genesis(self.local_shard),
                )
            },
            |qc| (qc.block_hash(), qc.clone()),
        )
    }

    /// Walk the QC chain from `parent_block_hash` back to committed height,
    /// collecting certificate, transaction, and provision hashes from
    /// ancestor blocks. Used by the proposer (to filter duplicates) and
    /// validators (to reject blocks containing already-included items).
    ///
    /// Two walks are fused: full blocks via `get_block` (assembled pending
    /// blocks), then a manifest-only fallback for ancestors not yet
    /// assembled. The just-committed block (at or below `committed_height`)
    /// is covered separately by
    /// [`CommitDedupIndex`](crate::commit_dedup::CommitDedupIndex)'s
    /// `contains_*` queries, populated synchronously inside
    /// [`crate::coordinator::BftCoordinator::record_block_committed`].
    pub fn collect_ancestor_hashes(
        &self,
        parent_block_hash: BlockHash,
    ) -> (HashSet<WaveId>, HashSet<TxHash>, HashSet<ProvisionHash>) {
        let mut cert_ids: HashSet<WaveId> = HashSet::new();
        let mut tx_hashes: HashSet<TxHash> = HashSet::new();
        let mut provision_hashes: HashSet<ProvisionHash> = HashSet::new();

        let mut current_hash = parent_block_hash;
        while let Some(block) = self.get_block(current_hash) {
            if block.height() <= self.committed_height {
                break;
            }
            for cert in block.certificates().iter() {
                cert_ids.insert(cert.wave_id().clone());
            }
            for tx in block.transactions().iter() {
                tx_hashes.insert(tx.hash());
            }
            current_hash = block.header().parent_block_hash();
        }

        let mut current_hash = parent_block_hash;
        while let Some(pending) = self.pending.get(&current_hash) {
            let h = pending.header().height();
            if h <= self.committed_height {
                break;
            }
            let manifest = pending.manifest();
            if pending.block().is_none() {
                for tx_hash in manifest.tx_hashes().iter() {
                    tx_hashes.insert(*tx_hash);
                }
            }
            for batch_hash in manifest.provision_hashes().iter() {
                provision_hashes.insert(*batch_hash);
            }
            current_hash = pending.header().parent_block_hash();
        }

        (cert_ids, tx_hashes, provision_hashes)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_types::{
        BlockManifest, BoundedVec, CertificateRoot, Hash, LocalReceiptRoot, LocalTimestamp,
        ProposerTimestamp, ProvisionsRoot, Round, ShardGroupId, SignerBitfield, TransactionRoot,
        ValidatorId, WeightedTimestamp, zero_bls_signature,
    };

    use super::*;

    fn make_header(height: u8, parent_block_hash: BlockHash) -> BlockHeader {
        BlockHeader::new(
            ShardGroupId::new(0),
            BlockHeight::new(u64::from(height)),
            parent_block_hash,
            QuorumCertificate::genesis(ShardGroupId::new(0)),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(1000),
            Round::INITIAL,
            false,
            StateRoot::from_raw(Hash::from_bytes(&[height; 32])),
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            std::collections::BTreeMap::new(),
            InFlightCount::new(u32::from(height)),
        )
    }

    fn make_block(height: u8, parent_block_hash: BlockHash) -> Block {
        Block::Live {
            header: make_header(height, parent_block_hash),
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
        }
    }

    /// Build a `ChainView` referencing scoped dummy state. Ownership stays
    /// with the closure so the view's borrows are safe.
    fn run_view<R>(
        committed_height: u64,
        committed_hash: BlockHash,
        committed_state_root: StateRoot,
        pending: &HashMap<BlockHash, PendingBlock>,
        latest_qc: Option<&QuorumCertificate>,
        f: impl FnOnce(&ChainView<'_>) -> R,
    ) -> R {
        let view = ChainView {
            local_shard: ShardGroupId::new(0),
            committed_height: BlockHeight::new(committed_height),
            committed_hash,
            committed_state_root,
            latest_qc,
            pending,
        };
        f(&view)
    }

    fn bh(tag: &[u8]) -> BlockHash {
        BlockHash::from_raw(Hash::from_bytes(tag))
    }

    fn pending_from_block(block: &Block) -> PendingBlock {
        let mut pb = PendingBlock::from_complete_block(block, vec![], vec![], LocalTimestamp::ZERO);
        pb.construct_block().expect("construct block");
        pb
    }

    #[test]
    fn get_block_finds_assembled_pending_blocks() {
        let hash_missing = bh(b"missing");

        let pending_block = {
            let mut pb = PendingBlock::from_manifest(
                make_header(6, BlockHash::ZERO),
                BlockManifest::default(),
                LocalTimestamp::ZERO,
            );
            pb.construct_block().unwrap();
            pb
        };
        let pending_hash = pending_block.header().hash();
        let mut pending = HashMap::new();
        pending.insert(pending_hash, pending_block);

        run_view(
            0,
            BlockHash::ZERO,
            StateRoot::ZERO,
            &pending,
            None,
            |view| {
                assert!(view.get_block(pending_hash).is_some());
                assert!(view.get_block(hash_missing).is_none());
            },
        );
    }

    #[test]
    fn get_header_returns_header_even_when_block_not_assembled() {
        let parent = bh(b"parent");
        let header = make_header(3, parent);
        let block_hash = header.hash();

        // Pending block without a constructed inner block — should still
        // yield a header.
        let pending_block =
            PendingBlock::from_manifest(header, BlockManifest::default(), LocalTimestamp::ZERO);
        let mut pending = HashMap::new();
        pending.insert(block_hash, pending_block);

        run_view(
            0,
            BlockHash::ZERO,
            StateRoot::ZERO,
            &pending,
            None,
            |view| {
                assert!(view.get_block(block_hash).is_none());
                let h = view.get_header(block_hash).expect("header available");
                assert_eq!(h.height(), BlockHeight::new(3));
            },
        );
    }

    #[test]
    fn parent_state_root_uses_committed_tip_on_match() {
        let tip_hash = bh(b"tip");
        let tip_root = StateRoot::from_raw(Hash::from_bytes(b"tip_root"));

        run_view(10, tip_hash, tip_root, &HashMap::new(), None, |view| {
            assert_eq!(view.parent_state_root(tip_hash), tip_root);
        });
    }

    #[test]
    fn parent_state_root_reads_header_state_root_when_present() {
        let tip_hash = bh(b"tip");
        let tip_root = StateRoot::ZERO;

        let block = make_block(5, BlockHash::ZERO);
        let hash = block.hash();
        let expected_state_root = block.header().state_root();

        let mut pending = HashMap::new();
        pending.insert(hash, pending_from_block(&block));

        run_view(4, tip_hash, tip_root, &pending, None, |view| {
            assert_eq!(view.parent_state_root(hash), expected_state_root);
        });
    }

    #[test]
    fn parent_state_root_falls_back_to_tip_when_unknown() {
        let tip_hash = bh(b"tip");
        let tip_root = StateRoot::from_raw(Hash::from_bytes(b"tip_root"));
        let unknown = bh(b"unknown");

        run_view(10, tip_hash, tip_root, &HashMap::new(), None, |view| {
            assert_eq!(view.parent_state_root(unknown), tip_root);
        });
    }

    #[test]
    fn parent_in_flight_returns_header_value_or_zero() {
        let block = make_block(7, BlockHash::ZERO);
        let hash = block.hash();
        let expected_in_flight = block.header().in_flight();
        let unknown = bh(b"unknown");

        let mut pending = HashMap::new();
        pending.insert(hash, pending_from_block(&block));

        run_view(
            0,
            BlockHash::ZERO,
            StateRoot::ZERO,
            &pending,
            None,
            |view| {
                assert_eq!(view.parent_in_flight(hash), expected_in_flight);
                assert_eq!(view.parent_in_flight(unknown), InFlightCount::ZERO);
            },
        );
    }

    #[test]
    fn proposal_parent_returns_latest_qc_when_present() {
        let qc_block = bh(b"qc_block");
        let qc = QuorumCertificate::new(
            qc_block,
            ShardGroupId::new(0),
            BlockHeight::new(5),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(1000),
        );

        run_view(
            0,
            BlockHash::ZERO,
            StateRoot::ZERO,
            &HashMap::new(),
            Some(&qc),
            |view| {
                let (hash, returned_qc) = view.proposal_parent();
                assert_eq!(hash, qc_block);
                assert_eq!(returned_qc.height(), BlockHeight::new(5));
            },
        );
    }

    #[test]
    fn proposal_parent_falls_back_to_committed_tip_without_qc() {
        let tip_hash = bh(b"tip");

        run_view(
            0,
            tip_hash,
            StateRoot::ZERO,
            &HashMap::new(),
            None,
            |view| {
                let (hash, qc) = view.proposal_parent();
                assert_eq!(hash, tip_hash);
                assert!(qc.is_genesis());
            },
        );
    }
}
