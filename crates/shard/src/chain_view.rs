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
//! on `ShardCoordinator` / `PendingBlock` just as before.

use std::collections::HashSet;

use hyperscale_types::{
    BlockHash, BlockHeader, BlockHeight, InFlightCount, ProvisionHash, QuorumCertificate,
    ShardGroupId, StateRoot, TxHash, Verified, WaveId,
};
use tracing::warn;

use crate::pending::{PendingBlock, PendingBlocks};

pub struct ChainView<'a> {
    local_shard: ShardGroupId,
    committed_height: BlockHeight,
    committed_hash: BlockHash,
    committed_state_root: StateRoot,
    latest_qc: Option<&'a Verified<QuorumCertificate>>,
    pending: &'a PendingBlocks,
}

impl<'a> ChainView<'a> {
    pub const fn new(
        local_shard: ShardGroupId,
        committed_height: BlockHeight,
        committed_hash: BlockHash,
        committed_state_root: StateRoot,
        latest_qc: Option<&'a Verified<QuorumCertificate>>,
        pending: &'a PendingBlocks,
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
        self.pending.get(block_hash)
    }

    /// Header-only lookup. Pending blocks always carry their header even
    /// before full assembly, so this succeeds even when the body hasn't been
    /// constructed yet.
    pub fn get_header(&self, block_hash: BlockHash) -> Option<&BlockHeader> {
        self.pending.get(block_hash).map(PendingBlock::header)
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
    pub fn proposal_parent(&self) -> (BlockHash, Verified<QuorumCertificate>) {
        self.latest_qc.map_or_else(
            || {
                (
                    self.committed_hash,
                    Verified::<QuorumCertificate>::genesis(self.local_shard),
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
    /// The manifest carries the full tx / cert / provision hash lists for
    /// every pending ancestor whether or not its body has assembled, so a
    /// single walk reads from it uniformly. Reading the block body instead
    /// would stop the walk at the first not-yet-assembled ancestor and drop
    /// the dedup contributions of every assembled block below it. The
    /// just-committed block (at or below `committed_height`) is covered
    /// separately by
    /// [`CommitDedupIndex`](crate::commit_dedup::CommitDedupIndex)'s
    /// `contains_*` queries, populated synchronously inside
    /// [`crate::coordinator::ShardCoordinator::record_block_committed`].
    pub fn collect_ancestor_hashes(
        &self,
        parent_block_hash: BlockHash,
    ) -> (HashSet<WaveId>, HashSet<TxHash>, HashSet<ProvisionHash>) {
        let mut cert_ids: HashSet<WaveId> = HashSet::new();
        let mut tx_hashes: HashSet<TxHash> = HashSet::new();
        let mut provision_hashes: HashSet<ProvisionHash> = HashSet::new();

        let mut current_hash = parent_block_hash;
        while let Some(pending) = self.pending.get(current_hash) {
            if pending.header().height() <= self.committed_height {
                break;
            }
            let manifest = pending.manifest();
            for tx_hash in manifest.tx_hashes().iter() {
                tx_hashes.insert(*tx_hash);
            }
            for cert_id in manifest.cert_ids().iter() {
                cert_ids.insert(cert_id.clone());
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
        BeaconWitnessLeafCount, BeaconWitnessRoot, Block, BlockManifest, BoundedVec,
        CertificateRoot, Hash, LocalReceiptRoot, LocalTimestamp, ProposerTimestamp, ProvisionsRoot,
        QuorumCertificate, Round, RoutableTransaction, ShardGroupId, SignerBitfield,
        TransactionRoot, ValidatorId, Verifiable, WeightedTimestamp, test_utils,
        zero_bls_signature,
    };

    use super::*;

    fn make_header(height: u8, parent_block_hash: BlockHash) -> BlockHeader {
        BlockHeader::new(
            ShardGroupId::ROOT,
            BlockHeight::new(u64::from(height)),
            parent_block_hash,
            QuorumCertificate::genesis(ShardGroupId::ROOT),
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
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
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
        pending: &PendingBlocks,
        latest_qc: Option<&Verified<QuorumCertificate>>,
        f: impl FnOnce(&ChainView<'_>) -> R,
    ) -> R {
        let view = ChainView {
            local_shard: ShardGroupId::ROOT,
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
        let mut pb =
            PendingBlock::from_complete_block(block, vec![], vec![], vec![], LocalTimestamp::ZERO);
        pb.construct_block().expect("construct block");
        pb
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
        let mut pending = PendingBlocks::new();
        pending.insert(pending_block);

        run_view(
            0,
            BlockHash::ZERO,
            StateRoot::ZERO,
            &pending,
            None,
            |view| {
                assert!(
                    view.get_pending(block_hash)
                        .is_some_and(|p| p.block().is_none())
                );
                let h = view.get_header(block_hash).expect("header available");
                assert_eq!(h.height(), BlockHeight::new(3));
            },
        );
    }

    #[test]
    fn collect_ancestor_hashes_includes_manifest_only_cert_ids() {
        // A manifest-only ancestor (header known, body not yet assembled) still
        // contributes its certificate wave-ids to dedup, matching the
        // assembled-block walk; otherwise a descendant could re-include a
        // finalized wave already present above the committed tip.
        let header = make_header(3, BlockHash::ZERO);
        let block_hash = header.hash();
        let wave = WaveId::new(
            ShardGroupId::ROOT,
            BlockHeight::new(2),
            std::collections::BTreeSet::new(),
        );
        let manifest = BlockManifest::new(vec![], vec![wave.clone()], vec![], vec![]);
        let pending_block = PendingBlock::from_manifest(header, manifest, LocalTimestamp::ZERO);
        let mut pending = PendingBlocks::new();
        pending.insert(pending_block);

        run_view(
            0,
            BlockHash::ZERO,
            StateRoot::ZERO,
            &pending,
            None,
            |view| {
                assert!(
                    view.get_pending(block_hash)
                        .is_some_and(|p| p.block().is_none()),
                    "ancestor must stay manifest-only for this case",
                );
                let (cert_ids, _txs, _provisions) = view.collect_ancestor_hashes(block_hash);
                assert!(
                    cert_ids.contains(&wave),
                    "manifest-only ancestor cert wave-id missing from dedup set",
                );
            },
        );
    }

    #[test]
    fn collect_ancestor_hashes_covers_assembled_block_below_unassembled() {
        // Chain above the committed tip: walk start `middle` (manifest-only) ->
        // `low` (assembled, height 1) -> committed. `low`'s transaction must
        // still land in the dedup set even though an unassembled ancestor sits
        // between it and the walk start — otherwise a descendant could
        // re-include a transaction already present above the committed tip.
        let tx: Arc<Verifiable<RoutableTransaction>> =
            Arc::new(Verifiable::from(test_utils::test_transaction(7)));
        let tx_hash = tx.hash();
        let low = Block::Live {
            header: make_header(1, BlockHash::ZERO),
            transactions: Arc::new(vec![tx].into()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
        };
        let low_pending = pending_from_block(&low);
        let low_hash = low_pending.header().hash();

        let middle = PendingBlock::from_manifest(
            make_header(2, low_hash),
            BlockManifest::default(),
            LocalTimestamp::ZERO,
        );
        let middle_hash = middle.header().hash();

        let mut pending = PendingBlocks::new();
        pending.insert(low_pending);
        pending.insert(middle);

        run_view(
            0,
            BlockHash::ZERO,
            StateRoot::ZERO,
            &pending,
            None,
            |view| {
                // Precondition: `low` is assembled, `middle` is not.
                assert!(
                    view.get_pending(low_hash)
                        .is_some_and(|p| p.block().is_some())
                );
                assert!(
                    view.get_pending(middle_hash)
                        .is_some_and(|p| p.block().is_none())
                );

                let (_certs, tx_hashes, _provisions) = view.collect_ancestor_hashes(middle_hash);
                assert!(
                    tx_hashes.contains(&tx_hash),
                    "assembled ancestor below an unassembled one dropped from dedup set",
                );
            },
        );
    }

    #[test]
    fn parent_state_root_uses_committed_tip_on_match() {
        let tip_hash = bh(b"tip");
        let tip_root = StateRoot::from_raw(Hash::from_bytes(b"tip_root"));

        run_view(
            10,
            tip_hash,
            tip_root,
            &PendingBlocks::new(),
            None,
            |view| {
                assert_eq!(view.parent_state_root(tip_hash), tip_root);
            },
        );
    }

    #[test]
    fn parent_state_root_reads_header_state_root_when_present() {
        let tip_hash = bh(b"tip");
        let tip_root = StateRoot::ZERO;

        let block = make_block(5, BlockHash::ZERO);
        let hash = block.hash();
        let expected_state_root = block.header().state_root();

        let mut pending = PendingBlocks::new();
        pending.insert(pending_from_block(&block));

        run_view(4, tip_hash, tip_root, &pending, None, |view| {
            assert_eq!(view.parent_state_root(hash), expected_state_root);
        });
    }

    #[test]
    fn parent_state_root_falls_back_to_tip_when_unknown() {
        let tip_hash = bh(b"tip");
        let tip_root = StateRoot::from_raw(Hash::from_bytes(b"tip_root"));
        let unknown = bh(b"unknown");

        run_view(
            10,
            tip_hash,
            tip_root,
            &PendingBlocks::new(),
            None,
            |view| {
                assert_eq!(view.parent_state_root(unknown), tip_root);
            },
        );
    }

    #[test]
    fn parent_in_flight_returns_header_value_or_zero() {
        let block = make_block(7, BlockHash::ZERO);
        let hash = block.hash();
        let expected_in_flight = block.header().in_flight();
        let unknown = bh(b"unknown");

        let mut pending = PendingBlocks::new();
        pending.insert(pending_from_block(&block));

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
            ShardGroupId::ROOT,
            BlockHeight::new(5),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(1000),
        );
        // SAFETY: synthetic test fixture, no real signature.
        let qc = Verified::<QuorumCertificate>::new_unchecked_for_test(qc);

        run_view(
            0,
            BlockHash::ZERO,
            StateRoot::ZERO,
            &PendingBlocks::new(),
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
            &PendingBlocks::new(),
            None,
            |view| {
                let (hash, qc) = view.proposal_parent();
                assert_eq!(hash, tip_hash);
                assert!(qc.is_genesis());
            },
        );
    }
}
