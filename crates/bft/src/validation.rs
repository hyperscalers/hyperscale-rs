//! Pure pre-vote validation helpers.
//!
//! These functions check a received block header or block contents against
//! the rules every honest validator applies before voting:
//!
//! - Header structure: proposer selection, parent-QC quorum, timestamp bounds.
//! - Block contents: transaction ordering, `waves` recomputation, and
//!   cross-ancestor transaction uniqueness.
//!
//! Everything here is stateless — callers supply `committed_height`,
//! `qc_chain_tx_hashes`, etc. explicitly. The async verification pipeline
//! lives in [`crate::verification`]; this module is just the pure rules.
//!
//! Errors are returned as human-readable strings so the caller can log a
//! single diagnostic line at the rejection site.
use crate::config::BftConfig;
use crate::tx_cache::CommittedTxCache;
use hyperscale_types::{
    Block, BlockHeader, BlockHeight, RoutableTransaction, TopologySnapshot, TxHash, VotePower,
};
#[cfg(test)]
use hyperscale_types::{
    CertificateRoot, Hash, LocalReceiptRoot, ProvisionsRoot, StateRoot, TransactionRoot,
    WeightedTimestamp,
};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

/// Validate block header structure, proposer, and parent QC quorum. Returns
/// `Err(..)` with a human-readable reason on any check failure.
pub(crate) fn validate_header(
    topology: &TopologySnapshot,
    header: &BlockHeader,
    committed_height: BlockHeight,
    config: &BftConfig,
    now: Duration,
) -> Result<(), String> {
    let height = header.height;
    let round = header.round;

    if height <= committed_height {
        return Err(format!(
            "height {} is at or below committed height {}",
            height.0, committed_height.0
        ));
    }

    let expected_proposer = topology.proposer_for(height, round);
    if header.proposer != expected_proposer {
        return Err(format!(
            "wrong proposer: expected {:?}, got {:?}",
            expected_proposer, header.proposer
        ));
    }

    if !header.parent_qc.is_genesis() {
        let committee = topology.local_committee();
        let qc_power: u64 = header
            .parent_qc
            .signers
            .set_indices()
            .filter_map(|i| committee.get(i))
            .map(|&vid| topology.voting_power(vid).unwrap_or(0))
            .sum();
        if !VotePower::has_quorum(qc_power, topology.local_voting_power()) {
            return Err("parent QC does not have quorum".to_string());
        }

        if header.parent_qc.height.0 + 1 != height.0 {
            return Err(format!(
                "parent QC height {} doesn't match block height {} - 1",
                header.parent_qc.height.0, height.0
            ));
        }

        if header.parent_hash != header.parent_qc.block_hash {
            return Err(format!(
                "parent_hash {:?} doesn't match parent_qc.block_hash {:?}",
                header.parent_hash, header.parent_qc.block_hash
            ));
        }
    } else if height.0 != committed_height.0 + 1 {
        return Err(format!(
            "genesis QC only valid for first block after committed height, got height {}",
            height.0
        ));
    }

    validate_timestamp(header, config, now)?;

    Ok(())
}

/// Validate that the proposer's timestamp is within acceptable bounds.
///
/// The timestamp must not be more than `config.max_timestamp_delay_ms`
/// behind our clock nor more than `config.max_timestamp_rush_ms` ahead.
///
/// Skipped for genesis blocks (fixed zero timestamp) and fallback blocks
/// (they inherit parent weighted-timestamp, which can be older than the
/// delay threshold during extended view changes). Fallback blocks are
/// empty and carry a QC-validated timestamp, so this carve-out is safe.
pub(crate) fn validate_timestamp(
    header: &BlockHeader,
    config: &BftConfig,
    now: Duration,
) -> Result<(), String> {
    if header.is_genesis() {
        return Ok(());
    }
    if header.is_fallback {
        return Ok(());
    }

    let now_ms = now.as_millis() as u64;
    let header_ts_ms = header.timestamp.as_millis();

    if header_ts_ms < now_ms.saturating_sub(config.max_timestamp_delay_ms) {
        return Err(format!(
            "proposer timestamp {} is too old (now: {}, max delay: {}ms)",
            header_ts_ms, now_ms, config.max_timestamp_delay_ms
        ));
    }

    if header_ts_ms > now_ms + config.max_timestamp_rush_ms {
        return Err(format!(
            "proposer timestamp {} is too far ahead (now: {}, max rush: {}ms)",
            header_ts_ms, now_ms, config.max_timestamp_rush_ms
        ));
    }

    Ok(())
}

/// Validate transaction ordering in a proposed block: transactions must be
/// sorted by hash (ascending, strict). Intra-block duplicate detection falls
/// out of the same check.
pub(crate) fn validate_transaction_ordering(block: &Block) -> Result<(), String> {
    verify_hash_sorted(block.transactions(), "transactions")
}

/// Validate that a block's `waves` field matches the value recomputed from
/// its transactions. Prevents a Byzantine proposer from lying about which
/// waves exist.
pub(crate) fn validate_waves(topology: &TopologySnapshot, block: &Block) -> Result<(), String> {
    let expected = hyperscale_types::compute_waves(topology, block.height(), block.transactions());

    if block.header().waves != expected {
        return Err(format!(
            "waves mismatch: header={:?}, computed={:?}",
            block.header().waves,
            expected
        ));
    }

    Ok(())
}

/// Validate that no transaction in the block has already been committed or
/// appears in an ancestor block above committed height (the QC chain).
/// Intra-block duplicates are excluded by the strict hash-ordering check.
///
/// Caller must precompute `qc_chain_tx_hashes` via the driver's QC-chain
/// walk; this function keeps validation pure and does not reach into pending
/// block storage itself.
pub(crate) fn validate_no_duplicate_transactions(
    block: &Block,
    qc_chain_tx_hashes: &HashSet<TxHash>,
    tx_cache: &CommittedTxCache,
) -> Result<(), String> {
    if block.transactions().is_empty() {
        return Ok(());
    }

    for tx in block.transactions() {
        let tx_hash = tx.hash();
        if qc_chain_tx_hashes.contains(&tx_hash) {
            return Err(format!(
                "transaction {} already in QC chain ancestor",
                tx_hash,
            ));
        }
        if let Some(ts) = tx_cache.tx_commit_ts(&tx_hash) {
            return Err(format!(
                "transaction {} already committed at {}",
                tx_hash, ts,
            ));
        }
    }
    Ok(())
}

/// Run all pre-vote block-contents checks: transaction ordering, `waves`
/// recomputation, and cross-ancestor transaction uniqueness. Returns a
/// single diagnostic on the first failure so the caller can log once.
pub(crate) fn validate_block_for_vote(
    topology: &TopologySnapshot,
    block: &Block,
    qc_chain_tx_hashes: &HashSet<TxHash>,
    tx_cache: &CommittedTxCache,
) -> Result<(), String> {
    validate_transaction_ordering(block)?;
    validate_waves(topology, block)?;
    validate_no_duplicate_transactions(block, qc_chain_tx_hashes, tx_cache)?;
    Ok(())
}

/// Verify that a list of transactions is sorted by hash in strict ascending
/// order. `section` is used in the error message for diagnostics.
fn verify_hash_sorted(txs: &[Arc<RoutableTransaction>], section: &str) -> Result<(), String> {
    for window in txs.windows(2) {
        if window[0].hash() >= window[1].hash() {
            return Err(format!(
                "{} section not in hash order: {} >= {}",
                section,
                window[0].hash(),
                window[1].hash()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_test_helpers::TestCommittee;
    use hyperscale_types::{
        compute_waves, test_utils, BlockHash, BlockHeader, ProposerTimestamp, QuorumCertificate,
        Round, RoutableTransaction, ShardGroupId, ValidatorId, ValidatorInfo, ValidatorSet,
    };
    use std::collections::BTreeMap;

    fn topology() -> TopologySnapshot {
        let committee = TestCommittee::new(4, 42);
        let validators: Vec<ValidatorInfo> = (0..committee.size())
            .map(|i| ValidatorInfo {
                validator_id: committee.validator_id(i),
                public_key: *committee.public_key(i),
                voting_power: 1,
            })
            .collect();
        TopologySnapshot::new(ValidatorId(0), 1, ValidatorSet::new(validators))
    }

    fn header_at_height(height: BlockHeight, timestamp_ms: u64) -> BlockHeader {
        BlockHeader {
            shard_group_id: ShardGroupId(0),
            height,
            parent_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(height.0 % 4),
            timestamp: ProposerTimestamp(timestamp_ms),
            round: Round(0),
            is_fallback: false,
            state_root: StateRoot::ZERO,
            transaction_root: TransactionRoot::ZERO,
            certificate_root: CertificateRoot::ZERO,
            local_receipt_root: LocalReceiptRoot::ZERO,
            provision_root: ProvisionsRoot::ZERO,
            waves: vec![],
            provision_tx_roots: BTreeMap::new(),
            in_flight: 0,
        }
    }

    fn block_with_waves(height: BlockHeight, waves: Vec<hyperscale_types::WaveId>) -> Block {
        let header = BlockHeader {
            shard_group_id: ShardGroupId(0),
            height,
            parent_hash: BlockHash::ZERO,
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: ProposerTimestamp(0),
            round: Round::INITIAL,
            is_fallback: false,
            state_root: StateRoot::ZERO,
            transaction_root: TransactionRoot::ZERO,
            certificate_root: CertificateRoot::ZERO,
            local_receipt_root: LocalReceiptRoot::ZERO,
            provision_root: ProvisionsRoot::ZERO,
            waves,
            provision_tx_roots: BTreeMap::new(),
            in_flight: 0,
        };
        Block::Live {
            header,
            transactions: Vec::new(),
            certificates: Vec::new(),
            provisions: Vec::new(),
        }
    }

    #[test]
    fn validate_waves_accepts_recomputed_waves() {
        let topo = topology();
        let height = BlockHeight(1);
        let expected = compute_waves(&topo, height, &[]);
        let block = block_with_waves(height, expected);
        assert!(validate_waves(&topo, &block).is_ok());
    }

    #[test]
    fn validate_waves_rejects_tampered_waves() {
        let topo = topology();
        let block = block_with_waves(
            BlockHeight(1),
            vec![hyperscale_types::WaveId::new(
                ShardGroupId(99),
                BlockHeight(1),
                Default::default(),
            )],
        );
        assert!(validate_waves(&topo, &block).is_err());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // validate_timestamp
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn validate_timestamp_skips_genesis() {
        let config = BftConfig::default();
        let now = Duration::from_secs(100);
        let mut header = header_at_height(BlockHeight(0), 0);
        header.parent_hash = BlockHash::from_raw(Hash::from_bytes(b"genesis_parent"));
        header.proposer = ValidatorId(0);
        assert!(validate_timestamp(&header, &config, now).is_ok());
    }

    #[test]
    fn validate_timestamp_accepts_within_bounds() {
        let config = BftConfig::default();
        let now = Duration::from_secs(100);
        for ts_ms in [99_000, 100_000, 101_000] {
            let header = header_at_height(BlockHeight(1), ts_ms);
            assert!(
                validate_timestamp(&header, &config, now).is_ok(),
                "ts_ms={ts_ms} should be within bounds"
            );
        }
    }

    #[test]
    fn validate_timestamp_rejects_too_old() {
        let config = BftConfig::default();
        let now = Duration::from_secs(100);
        let header = header_at_height(BlockHeight(1), 50_000);
        let err = validate_timestamp(&header, &config, now).unwrap_err();
        assert!(err.contains("too old"));
    }

    #[test]
    fn validate_timestamp_rejects_too_far_ahead() {
        let config = BftConfig::default();
        let now = Duration::from_secs(100);
        let header = header_at_height(BlockHeight(1), 110_000);
        let err = validate_timestamp(&header, &config, now).unwrap_err();
        assert!(err.contains("too far ahead"));
    }

    #[test]
    fn validate_timestamp_at_boundary() {
        let config = BftConfig::default();
        let now = Duration::from_secs(100);

        // Exactly max delay (now - 30s) — OK.
        assert!(
            validate_timestamp(&header_at_height(BlockHeight(1), 70_000), &config, now).is_ok()
        );
        // Just past max delay — fail.
        assert!(
            validate_timestamp(&header_at_height(BlockHeight(1), 69_999), &config, now).is_err()
        );
        // Exactly max rush (now + 2s) — OK.
        assert!(
            validate_timestamp(&header_at_height(BlockHeight(1), 102_000), &config, now).is_ok()
        );
        // Just past max rush — fail.
        assert!(
            validate_timestamp(&header_at_height(BlockHeight(1), 102_001), &config, now).is_err()
        );
    }

    #[test]
    fn validate_timestamp_skips_fallback_blocks() {
        let config = BftConfig::default();
        let now = Duration::from_secs(100);

        // 50s old would normally fail (max_delay = 30s), but fallback blocks
        // inherit the parent's weighted timestamp across view changes.
        let mut header = header_at_height(BlockHeight(1), 50_000);
        header.round = Round(5);
        header.is_fallback = true;
        assert!(validate_timestamp(&header, &config, now).is_ok());

        header.is_fallback = false;
        assert!(validate_timestamp(&header, &config, now).is_err());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // validate_transaction_ordering
    // ═══════════════════════════════════════════════════════════════════════

    fn block_with_transactions(
        height: BlockHeight,
        transactions: Vec<Arc<RoutableTransaction>>,
    ) -> Block {
        Block::Live {
            header: header_at_height(height, 100_000),
            transactions,
            certificates: Vec::new(),
            provisions: Vec::new(),
        }
    }

    fn tx(seed: u8) -> Arc<RoutableTransaction> {
        Arc::new(test_utils::test_transaction(seed))
    }

    fn sorted_txs(seeds: &[u8]) -> Vec<Arc<RoutableTransaction>> {
        let mut txs: Vec<_> = seeds.iter().map(|&s| tx(s)).collect();
        txs.sort_by_key(|t| t.hash());
        txs
    }

    #[test]
    fn validate_transaction_ordering_accepts_empty_block() {
        let block = block_with_transactions(BlockHeight(5), vec![]);
        assert!(validate_transaction_ordering(&block).is_ok());
    }

    #[test]
    fn validate_transaction_ordering_accepts_single_tx() {
        let block = block_with_transactions(BlockHeight(5), vec![tx(1)]);
        assert!(validate_transaction_ordering(&block).is_ok());
    }

    #[test]
    fn validate_transaction_ordering_accepts_sorted() {
        let block = block_with_transactions(BlockHeight(5), sorted_txs(&[10, 20, 30]));
        assert!(validate_transaction_ordering(&block).is_ok());
    }

    #[test]
    fn validate_transaction_ordering_rejects_reversed() {
        let mut txs = sorted_txs(&[10, 20, 30]);
        txs.reverse();
        let block = block_with_transactions(BlockHeight(5), txs);
        let err = validate_transaction_ordering(&block).unwrap_err();
        assert!(err.contains("not in hash order"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // validate_no_duplicate_transactions
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn validate_no_duplicate_transactions_accepts_empty_block() {
        let block = block_with_transactions(BlockHeight(5), vec![]);
        let qc_chain = HashSet::new();
        let tx_cache = CommittedTxCache::new();
        assert!(validate_no_duplicate_transactions(&block, &qc_chain, &tx_cache).is_ok());
    }

    #[test]
    fn validate_no_duplicate_transactions_accepts_unique() {
        let block = block_with_transactions(BlockHeight(5), sorted_txs(&[10, 20]));
        let qc_chain = HashSet::new();
        let tx_cache = CommittedTxCache::new();
        assert!(validate_no_duplicate_transactions(&block, &qc_chain, &tx_cache).is_ok());
    }

    #[test]
    fn validate_no_duplicate_transactions_rejects_qc_chain_dup() {
        let txs = sorted_txs(&[10, 20]);
        let dup_hash = txs[0].hash();
        let block = block_with_transactions(BlockHeight(6), txs);
        let qc_chain: HashSet<_> = [dup_hash].into_iter().collect();
        let tx_cache = CommittedTxCache::new();
        let err = validate_no_duplicate_transactions(&block, &qc_chain, &tx_cache).unwrap_err();
        assert!(err.contains("already in QC chain ancestor"));
    }

    #[test]
    fn validate_no_duplicate_transactions_rejects_tx_cache_dup() {
        let txs = sorted_txs(&[10, 20]);
        let dup_hash = txs[0].hash();
        let block = block_with_transactions(BlockHeight(6), txs);
        let qc_chain = HashSet::new();
        let mut tx_cache = CommittedTxCache::new();
        tx_cache.register_committed(&[dup_hash], WeightedTimestamp(100_000));
        let err = validate_no_duplicate_transactions(&block, &qc_chain, &tx_cache).unwrap_err();
        assert!(err.contains("already committed"));
    }
}
