//! Read-only view over the node's knowledge of the chain.
//!
//! `ChainView<'a>` bundles the committed-tip scalars, the latest QC, the
//! genesis block, and borrowed references to the pending + certified block
//! maps. It unifies reads that would otherwise have to thread half a dozen
//! coordinator fields through every helper — proposal building, header
//! validation, commit decisions all consult the same chain state.
//!
//! The view is **strictly a borrow**: no state is owned here, no lifecycle,
//! no mutations. It's a lens, not a sub-machine. The underlying fields live
//! on `BftCoordinator` / `CommitPipeline` / `PendingBlock` just as before.

#[cfg(test)]
use hyperscale_types::Hash;
use hyperscale_types::{
    Block, BlockHash, BlockHeader, BlockHeight, ProvisionHash, QuorumCertificate, StateRoot,
    TxHash, WaveIdHash,
};
use std::collections::{HashMap, HashSet};
use tracing::warn;

use crate::pending::PendingBlock;
use crate::tx_cache::CommittedTxCache;

pub struct ChainView<'a> {
    pub committed_height: BlockHeight,
    pub committed_hash: BlockHash,
    pub committed_state_root: StateRoot,
    pub latest_qc: Option<&'a QuorumCertificate>,
    pub genesis: Option<&'a Block>,
    pub certified: &'a HashMap<BlockHash, Block>,
    pub pending: &'a HashMap<BlockHash, PendingBlock>,
}

impl ChainView<'_> {
    /// Look up a block by hash across certified, pending (if assembled), and
    /// genesis. Returns `None` if no source has the block.
    pub fn get_block(&self, block_hash: BlockHash) -> Option<Block> {
        if let Some(block) = self.certified.get(&block_hash) {
            return Some(block.clone());
        }
        if let Some(pending) = self.pending.get(&block_hash)
            && let Some(block) = pending.block()
        {
            return Some((*block).clone());
        }
        if let Some(genesis) = self.genesis
            && genesis.hash() == block_hash
        {
            return Some(genesis.clone());
        }
        None
    }

    /// Header-only lookup, cheaper than `get_block` when only header fields
    /// are needed. Pending blocks always carry their header even before full
    /// assembly, so this succeeds in cases where `get_block` would fail.
    pub fn get_header(&self, block_hash: BlockHash) -> Option<BlockHeader> {
        if let Some(block) = self.certified.get(&block_hash) {
            return Some(block.header().clone());
        }
        if let Some(pending) = self.pending.get(&block_hash) {
            return Some(pending.header().clone());
        }
        if let Some(genesis) = self.genesis
            && genesis.hash() == block_hash
        {
            return Some(genesis.header().clone());
        }
        None
    }

    /// State root of the parent block. Returns the committed-tip state root
    /// when `parent_block_hash` IS the committed tip (may have been pruned from
    /// the in-memory caches by cleanup) or when lookup otherwise fails.
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
            |h| h.state_root,
        )
    }

    /// In-flight count on the parent header. Returns `0` if the header is
    /// missing (parent pruned from in-memory caches).
    pub fn parent_in_flight(&self, parent_block_hash: BlockHash) -> u32 {
        self.get_header(parent_block_hash)
            .map_or(0, |h| h.in_flight)
    }

    /// Parent to use when building the next proposal: the latest QC's block
    /// if any, otherwise the committed tip under a genesis QC.
    pub fn proposal_parent(&self) -> (BlockHash, QuorumCertificate) {
        self.latest_qc.map_or_else(
            || (self.committed_hash, QuorumCertificate::genesis()),
            |qc| (qc.block_hash, qc.clone()),
        )
    }

    /// Walk the QC chain from `parent_block_hash` back to committed height,
    /// collecting certificate, transaction, and provision hashes from
    /// ancestor blocks. Used by the proposer (to filter duplicates) and
    /// validators (to reject blocks containing already-included items).
    ///
    /// Two walks are fused: full blocks via `get_block` (certified +
    /// assembled pending), then a manifest-only fallback for ancestors not
    /// yet assembled. Recently-committed hashes from `tx_cache` are folded
    /// in so proposal dedup sees the latest commit even before the async
    /// `BlockCommitted` event clears the mempool.
    pub fn collect_ancestor_hashes(
        &self,
        parent_block_hash: BlockHash,
        tx_cache: &CommittedTxCache,
    ) -> (HashSet<WaveIdHash>, HashSet<TxHash>, HashSet<ProvisionHash>) {
        let mut cert_hashes: HashSet<WaveIdHash> = HashSet::new();
        let mut tx_hashes: HashSet<TxHash> = HashSet::new();
        let mut provision_hashes: HashSet<ProvisionHash> = HashSet::new();

        tx_hashes.extend(tx_cache.recent_tx_hashes());
        cert_hashes.extend(tx_cache.recent_cert_hashes());

        let mut current_hash = parent_block_hash;
        while let Some(block) = self.get_block(current_hash) {
            if block.height() <= self.committed_height {
                break;
            }
            for cert in block.certificates() {
                cert_hashes.insert(cert.wave_id().hash());
            }
            for tx in block.transactions() {
                tx_hashes.insert(tx.hash());
            }
            current_hash = block.header().parent_block_hash;
        }

        let mut current_hash = parent_block_hash;
        while let Some(pending) = self.pending.get(&current_hash) {
            let h = pending.header().height;
            if h <= self.committed_height {
                break;
            }
            let manifest = pending.manifest();
            if pending.block().is_none() {
                for tx_hash in &manifest.tx_hashes {
                    tx_hashes.insert(*tx_hash);
                }
            }
            for batch_hash in &manifest.provision_hashes {
                provision_hashes.insert(*batch_hash);
            }
            current_hash = pending.header().parent_block_hash;
        }

        (cert_hashes, tx_hashes, provision_hashes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        BlockManifest, CertificateRoot, LocalReceiptRoot, LocalTimestamp, ProposerTimestamp,
        ProvisionsRoot, Round, ShardGroupId, TransactionRoot, ValidatorId, WeightedTimestamp,
    };
    use std::collections::BTreeMap;

    fn make_header(height: u8, parent_block_hash: BlockHash) -> BlockHeader {
        BlockHeader {
            shard_group_id: ShardGroupId(0),
            height: BlockHeight(u64::from(height)),
            parent_block_hash,
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: ProposerTimestamp(1000),
            round: Round::INITIAL,
            is_fallback: false,
            state_root: StateRoot::from_raw(Hash::from_bytes(&[height; 32])),
            transaction_root: TransactionRoot::ZERO,
            certificate_root: CertificateRoot::ZERO,
            local_receipt_root: LocalReceiptRoot::ZERO,
            provision_root: ProvisionsRoot::ZERO,
            waves: vec![],
            provision_tx_roots: BTreeMap::new(),
            in_flight: u32::from(height),
        }
    }

    fn make_block(height: u8, parent_block_hash: BlockHash) -> Block {
        Block::Live {
            header: make_header(height, parent_block_hash),
            transactions: vec![],
            certificates: vec![],
            provisions: vec![],
        }
    }

    /// Build a `ChainView` referencing scoped dummy state. Ownership stays
    /// with the closure so the view's borrows are safe.
    #[allow(clippy::too_many_arguments)]
    fn run_view<R>(
        committed_height: u64,
        committed_hash: BlockHash,
        committed_state_root: StateRoot,
        certified: &HashMap<BlockHash, Block>,
        pending: &HashMap<BlockHash, PendingBlock>,
        latest_qc: Option<&QuorumCertificate>,
        genesis: Option<&Block>,
        f: impl FnOnce(&ChainView<'_>) -> R,
    ) -> R {
        let view = ChainView {
            committed_height: BlockHeight(committed_height),
            committed_hash,
            committed_state_root,
            latest_qc,
            genesis,
            certified,
            pending,
        };
        f(&view)
    }

    fn bh(tag: &[u8]) -> BlockHash {
        BlockHash::from_raw(Hash::from_bytes(tag))
    }

    #[test]
    fn get_block_finds_certified_pending_and_genesis() {
        let hash_c = bh(b"certified");
        let hash_p = bh(b"pending");
        let genesis = make_block(0, BlockHash::ZERO);
        let genesis_hash = genesis.hash();

        let certified_block = make_block(5, BlockHash::ZERO);
        let certified_hash = certified_block.hash();
        let mut certified = HashMap::new();
        certified.insert(certified_hash, certified_block);

        let pending_block = {
            let mut pb = PendingBlock::from_manifest(
                make_header(6, certified_hash),
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
            &certified,
            &pending,
            None,
            Some(&genesis),
            |view| {
                assert!(view.get_block(certified_hash).is_some());
                assert!(view.get_block(pending_hash).is_some());
                assert!(view.get_block(genesis_hash).is_some());
                assert!(view.get_block(hash_c).is_none());
                assert!(view.get_block(hash_p).is_none());
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
            &HashMap::new(),
            &pending,
            None,
            None,
            |view| {
                assert!(view.get_block(block_hash).is_none());
                let h = view.get_header(block_hash).expect("header available");
                assert_eq!(h.height, BlockHeight(3));
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
            &HashMap::new(),
            &HashMap::new(),
            None,
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
        let expected_state_root = block.header().state_root;

        let mut certified = HashMap::new();
        certified.insert(hash, block);

        run_view(
            4,
            tip_hash,
            tip_root,
            &certified,
            &HashMap::new(),
            None,
            None,
            |view| {
                assert_eq!(view.parent_state_root(hash), expected_state_root);
            },
        );
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
            &HashMap::new(),
            &HashMap::new(),
            None,
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
        let expected_in_flight = block.header().in_flight;
        let unknown = bh(b"unknown");

        let mut certified = HashMap::new();
        certified.insert(hash, block);

        run_view(
            0,
            BlockHash::ZERO,
            StateRoot::ZERO,
            &certified,
            &HashMap::new(),
            None,
            None,
            |view| {
                assert_eq!(view.parent_in_flight(hash), expected_in_flight);
                assert_eq!(view.parent_in_flight(unknown), 0);
            },
        );
    }

    #[test]
    fn proposal_parent_returns_latest_qc_when_present() {
        let qc_block = bh(b"qc_block");
        let mut qc = QuorumCertificate::genesis();
        qc.block_hash = qc_block;
        qc.height = BlockHeight(5);
        qc.weighted_timestamp = WeightedTimestamp(1000);

        run_view(
            0,
            BlockHash::ZERO,
            StateRoot::ZERO,
            &HashMap::new(),
            &HashMap::new(),
            Some(&qc),
            None,
            |view| {
                let (hash, returned_qc) = view.proposal_parent();
                assert_eq!(hash, qc_block);
                assert_eq!(returned_qc.height, BlockHeight(5));
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
            &HashMap::new(),
            None,
            None,
            |view| {
                let (hash, qc) = view.proposal_parent();
                assert_eq!(hash, tip_hash);
                assert!(qc.is_genesis());
            },
        );
    }
}
