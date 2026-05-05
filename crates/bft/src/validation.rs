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
use std::collections::HashSet;
use std::sync::Arc;

use hyperscale_types::{
    Block, BlockHeader, BlockHeight, LocalTimestamp, ProvisionHash, QuorumCertificate,
    RoutableTransaction, TopologySnapshot, TxHash, VotePower, WaveId, compute_waves,
};

use crate::commit_dedup::CommitDedupIndex;
use crate::config::BftConfig;

/// True if `qc.signers` represents at least 2f+1 of the local committee's
/// voting power. The synced-block apply path and consensus pre-vote path
/// both call this — without it, a single Byzantine signer suffices to pass
/// the BLS-only `VerifyQcSignature` check that follows.
#[must_use]
pub fn qc_has_local_quorum_power(topology: &TopologySnapshot, qc: &QuorumCertificate) -> bool {
    let committee = topology.local_committee();
    let qc_power: u64 = qc
        .signers
        .set_indices()
        .filter_map(|i| committee.get(i))
        .map(|&vid| topology.voting_power(vid).unwrap_or(0))
        .sum();
    VotePower::has_quorum(qc_power, topology.local_voting_power())
}

/// Validate block header structure, proposer, and parent QC quorum. Returns
/// `Err(..)` with a human-readable reason on any check failure.
pub fn validate_header(
    topology: &TopologySnapshot,
    header: &BlockHeader,
    committed_height: BlockHeight,
    config: &BftConfig,
    now: LocalTimestamp,
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
        if !qc_has_local_quorum_power(topology, &header.parent_qc) {
            return Err("parent QC does not have quorum".to_string());
        }

        if header.parent_qc.height.0 + 1 != height.0 {
            return Err(format!(
                "parent QC height {} doesn't match block height {} - 1",
                header.parent_qc.height.0, height.0
            ));
        }

        if header.parent_block_hash != header.parent_qc.block_hash {
            return Err(format!(
                "parent_block_hash {:?} doesn't match parent_qc.block_hash {:?}",
                header.parent_block_hash, header.parent_qc.block_hash
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
pub fn validate_timestamp(
    header: &BlockHeader,
    config: &BftConfig,
    now: LocalTimestamp,
) -> Result<(), String> {
    if header.is_genesis() {
        return Ok(());
    }
    if header.is_fallback {
        return Ok(());
    }

    let now_ms = now.as_millis();
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
pub fn validate_transaction_ordering(block: &Block) -> Result<(), String> {
    verify_hash_sorted(block.transactions(), "transactions")
}

/// Validate that a block's `waves` field matches the value recomputed from
/// its transactions. Prevents a Byzantine proposer from lying about which
/// waves exist.
pub fn validate_waves(topology: &TopologySnapshot, block: &Block) -> Result<(), String> {
    let expected = compute_waves(topology, block.height(), block.transactions());

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
pub fn validate_no_duplicate_transactions(
    block: &Block,
    qc_chain_tx_hashes: &HashSet<TxHash>,
    dedup_index: &CommitDedupIndex,
) -> Result<(), String> {
    if block.transactions().is_empty() {
        return Ok(());
    }

    for tx in block.transactions().iter() {
        let tx_hash = tx.hash();
        if qc_chain_tx_hashes.contains(&tx_hash) {
            return Err(format!(
                "transaction {tx_hash} already in QC chain ancestor"
            ));
        }
        if dedup_index.contains_tx(&tx_hash) {
            return Err(format!(
                "transaction {tx_hash} already committed within its validity window"
            ));
        }
    }
    Ok(())
}

/// Validate that no finalized wave in the block has already been committed
/// or appears in an ancestor block above committed height. Mirrors
/// [`validate_no_duplicate_transactions`] but for `wave_id`.
///
/// Both proposer and validator hit `record_block_committed` synchronously
/// during their respective commit handlers, so their `dedup_index` reflects
/// the same just-committed waves at the same logical moment. Validation
/// against this shared state is therefore safe under the on-qc-formed race.
pub fn validate_no_duplicate_certificates(
    block: &Block,
    qc_chain_cert_ids: &HashSet<WaveId>,
    dedup_index: &CommitDedupIndex,
) -> Result<(), String> {
    if block.certificates().is_empty() {
        return Ok(());
    }

    for fw in block.certificates().iter() {
        let wave_id = fw.wave_id();
        if qc_chain_cert_ids.contains(wave_id) {
            return Err(format!(
                "wave certificate {wave_id:?} already in QC chain ancestor"
            ));
        }
        if dedup_index.contains_cert(wave_id) {
            return Err(format!(
                "wave certificate {wave_id:?} already committed within its retention window"
            ));
        }
    }
    Ok(())
}

/// Validate that no provisions batch in the block has already been committed
/// or appears in an ancestor block above committed height. Mirrors
/// [`validate_no_duplicate_transactions`] but for `ProvisionHash`.
///
/// Without this check, the on-qc-formed race could cause a proposer to
/// re-include a just-committed batch — the duplicate is technically
/// idempotent (admission no-ops via `pipeline.has_verified`), but the
/// re-inclusion wastes block bytes and re-runs verification. Validators
/// reject it outright.
pub fn validate_no_duplicate_provisions(
    block: &Block,
    qc_chain_provision_hashes: &HashSet<ProvisionHash>,
    dedup_index: &CommitDedupIndex,
) -> Result<(), String> {
    if block.provisions().is_empty() {
        return Ok(());
    }

    for batch in block.provisions() {
        let provision_hash = batch.hash();
        if qc_chain_provision_hashes.contains(&provision_hash) {
            return Err(format!(
                "provisions batch {provision_hash:?} already in QC chain ancestor"
            ));
        }
        if dedup_index.contains_provision(&provision_hash) {
            return Err(format!(
                "provisions batch {provision_hash:?} already committed within its retention window"
            ));
        }
    }
    Ok(())
}

/// Run all pre-vote block-contents checks: transaction ordering, `waves`
/// recomputation, and cross-ancestor uniqueness for txs, certs, and
/// provisions. Returns a single diagnostic on the first failure so the
/// caller can log once.
pub fn validate_block_for_vote(
    topology: &TopologySnapshot,
    block: &Block,
    qc_chain_tx_hashes: &HashSet<TxHash>,
    qc_chain_cert_ids: &HashSet<WaveId>,
    qc_chain_provision_hashes: &HashSet<ProvisionHash>,
    dedup_index: &CommitDedupIndex,
) -> Result<(), String> {
    validate_transaction_ordering(block)?;
    validate_waves(topology, block)?;
    validate_no_duplicate_transactions(block, qc_chain_tx_hashes, dedup_index)?;
    validate_no_duplicate_certificates(block, qc_chain_cert_ids, dedup_index)?;
    validate_no_duplicate_provisions(block, qc_chain_provision_hashes, dedup_index)?;
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
    use std::collections::{BTreeMap, BTreeSet};

    use hyperscale_test_helpers::{TestCommittee, make_finalized_wave};
    use hyperscale_types::{
        BlockHash, BlockHeader, CertificateRoot, FinalizedWave, Hash, LocalReceiptRoot,
        MerkleInclusionProof, ProposerTimestamp, Provisions, ProvisionsRoot, QuorumCertificate,
        Round, RoutableTransaction, ShardGroupId, StateRoot, TransactionDecision, TransactionRoot,
        TxEntries, ValidatorId, ValidatorInfo, ValidatorSet, WeightedTimestamp, compute_waves,
        test_utils,
    };

    use super::*;

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
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            parent_qc: QuorumCertificate::genesis(ShardGroupId(0)),
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

    fn block_with_waves(height: BlockHeight, waves: Vec<WaveId>) -> Block {
        let header = BlockHeader {
            shard_group_id: ShardGroupId(0),
            height,
            parent_block_hash: BlockHash::ZERO,
            parent_qc: QuorumCertificate::genesis(ShardGroupId(0)),
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
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
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
            vec![WaveId::new(
                ShardGroupId(99),
                BlockHeight(1),
                BTreeSet::new(),
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
        let now = LocalTimestamp::from_millis(100_000);
        let mut header = header_at_height(BlockHeight(0), 0);
        header.parent_block_hash = BlockHash::from_raw(Hash::from_bytes(b"genesis_parent"));
        header.proposer = ValidatorId(0);
        assert!(validate_timestamp(&header, &config, now).is_ok());
    }

    #[test]
    fn validate_timestamp_accepts_within_bounds() {
        let config = BftConfig::default();
        let now = LocalTimestamp::from_millis(100_000);
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
        let now = LocalTimestamp::from_millis(100_000);
        let header = header_at_height(BlockHeight(1), 50_000);
        let err = validate_timestamp(&header, &config, now).unwrap_err();
        assert!(err.contains("too old"));
    }

    #[test]
    fn validate_timestamp_rejects_too_far_ahead() {
        let config = BftConfig::default();
        let now = LocalTimestamp::from_millis(100_000);
        let header = header_at_height(BlockHeight(1), 110_000);
        let err = validate_timestamp(&header, &config, now).unwrap_err();
        assert!(err.contains("too far ahead"));
    }

    #[test]
    fn validate_timestamp_at_boundary() {
        let config = BftConfig::default();
        let now = LocalTimestamp::from_millis(100_000);

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
        let now = LocalTimestamp::from_millis(100_000);

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
            transactions: Arc::new(transactions),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
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
        let dedup_index = CommitDedupIndex::new();
        assert!(validate_no_duplicate_transactions(&block, &qc_chain, &dedup_index).is_ok());
    }

    #[test]
    fn validate_no_duplicate_transactions_accepts_unique() {
        let block = block_with_transactions(BlockHeight(5), sorted_txs(&[10, 20]));
        let qc_chain = HashSet::new();
        let dedup_index = CommitDedupIndex::new();
        assert!(validate_no_duplicate_transactions(&block, &qc_chain, &dedup_index).is_ok());
    }

    #[test]
    fn validate_no_duplicate_transactions_rejects_qc_chain_dup() {
        let txs = sorted_txs(&[10, 20]);
        let dup_hash = txs[0].hash();
        let block = block_with_transactions(BlockHeight(6), txs);
        let qc_chain: HashSet<_> = std::iter::once(dup_hash).collect();
        let dedup_index = CommitDedupIndex::new();
        let err = validate_no_duplicate_transactions(&block, &qc_chain, &dedup_index).unwrap_err();
        assert!(err.contains("already in QC chain ancestor"));
    }

    #[test]
    fn validate_no_duplicate_transactions_rejects_retention_dup() {
        let txs = sorted_txs(&[10, 20]);
        let dup_tx = Arc::clone(&txs[0]);
        let block = block_with_transactions(BlockHeight(6), txs);
        let qc_chain = HashSet::new();
        let mut dedup_index = CommitDedupIndex::new();
        dedup_index.register_committed_txs(&[dup_tx]);
        let err = validate_no_duplicate_transactions(&block, &qc_chain, &dedup_index).unwrap_err();
        assert!(err.contains("already committed"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // validate_no_duplicate_certificates
    // ═══════════════════════════════════════════════════════════════════════

    fn block_with_certificates(
        height: BlockHeight,
        certificates: Vec<Arc<FinalizedWave>>,
    ) -> Block {
        Block::Live {
            header: header_at_height(height, 100_000),
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(certificates),
            provisions: Arc::new(Vec::new()),
        }
    }

    fn finalized_wave_at(height: u64) -> Arc<FinalizedWave> {
        Arc::new(make_finalized_wave(
            BlockHeight(height),
            TxHash::from_raw(Hash::from_bytes(
                &[u8::try_from(height).unwrap_or(u8::MAX); 32],
            )),
            TransactionDecision::Accept,
        ))
    }

    #[test]
    fn validate_no_duplicate_certificates_accepts_empty_block() {
        let block = block_with_certificates(BlockHeight(5), vec![]);
        let qc_chain = HashSet::new();
        let dedup_index = CommitDedupIndex::new();
        assert!(validate_no_duplicate_certificates(&block, &qc_chain, &dedup_index).is_ok());
    }

    #[test]
    fn validate_no_duplicate_certificates_accepts_unique() {
        let block = block_with_certificates(BlockHeight(5), vec![finalized_wave_at(1)]);
        let qc_chain = HashSet::new();
        let dedup_index = CommitDedupIndex::new();
        assert!(validate_no_duplicate_certificates(&block, &qc_chain, &dedup_index).is_ok());
    }

    #[test]
    fn validate_no_duplicate_certificates_rejects_qc_chain_dup() {
        let fw = finalized_wave_at(1);
        let dup_id = fw.wave_id().clone();
        let block = block_with_certificates(BlockHeight(6), vec![fw]);
        let qc_chain: HashSet<_> = std::iter::once(dup_id).collect();
        let dedup_index = CommitDedupIndex::new();
        let err = validate_no_duplicate_certificates(&block, &qc_chain, &dedup_index).unwrap_err();
        assert!(err.contains("already in QC chain ancestor"));
    }

    #[test]
    fn validate_no_duplicate_certificates_rejects_retention_dup() {
        let fw = finalized_wave_at(1);
        let block = block_with_certificates(BlockHeight(6), vec![Arc::clone(&fw)]);
        let qc_chain = HashSet::new();
        let mut dedup_index = CommitDedupIndex::new();
        dedup_index.register_committed_certs(&[fw]);
        let err = validate_no_duplicate_certificates(&block, &qc_chain, &dedup_index).unwrap_err();
        assert!(err.contains("already committed"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // validate_no_duplicate_provisions
    // ═══════════════════════════════════════════════════════════════════════

    fn block_with_provisions(height: BlockHeight, provisions: Vec<Arc<Provisions>>) -> Block {
        Block::Live {
            header: header_at_height(height, 100_000),
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(provisions),
        }
    }

    fn provisions_with_seed(seed: u8) -> Arc<Provisions> {
        let tx_hash = TxHash::from_raw(Hash::from_bytes(&[seed; 32]));
        Arc::new(Provisions::new(
            ShardGroupId(0),
            ShardGroupId(1),
            BlockHeight(u64::from(seed)),
            MerkleInclusionProof::dummy(),
            vec![TxEntries {
                tx_hash,
                entries: vec![],
                target_nodes: vec![],
            }],
        ))
    }

    #[test]
    fn validate_no_duplicate_provisions_accepts_empty_block() {
        let block = block_with_provisions(BlockHeight(5), vec![]);
        let qc_chain = HashSet::new();
        let dedup_index = CommitDedupIndex::new();
        assert!(validate_no_duplicate_provisions(&block, &qc_chain, &dedup_index).is_ok());
    }

    #[test]
    fn validate_no_duplicate_provisions_accepts_unique() {
        let block = block_with_provisions(BlockHeight(5), vec![provisions_with_seed(1)]);
        let qc_chain = HashSet::new();
        let dedup_index = CommitDedupIndex::new();
        assert!(validate_no_duplicate_provisions(&block, &qc_chain, &dedup_index).is_ok());
    }

    #[test]
    fn validate_no_duplicate_provisions_rejects_qc_chain_dup() {
        let p = provisions_with_seed(1);
        let dup_hash = p.hash();
        let block = block_with_provisions(BlockHeight(6), vec![p]);
        let qc_chain: HashSet<_> = std::iter::once(dup_hash).collect();
        let dedup_index = CommitDedupIndex::new();
        let err = validate_no_duplicate_provisions(&block, &qc_chain, &dedup_index).unwrap_err();
        assert!(err.contains("already in QC chain ancestor"));
    }

    #[test]
    fn validate_no_duplicate_provisions_rejects_retention_dup() {
        let p = provisions_with_seed(1);
        let block = block_with_provisions(BlockHeight(6), vec![Arc::clone(&p)]);
        let qc_chain = HashSet::new();
        let mut dedup_index = CommitDedupIndex::new();
        dedup_index.register_committed_provisions(&[p], WeightedTimestamp(1_000));
        let err = validate_no_duplicate_provisions(&block, &qc_chain, &dedup_index).unwrap_err();
        assert!(err.contains("already committed"));
    }
}
