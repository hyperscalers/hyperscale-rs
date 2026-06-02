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

#[cfg(test)]
use hyperscale_types::{BeaconWitnessLeafCount, BeaconWitnessRoot};
use hyperscale_types::{
    Block, BlockHeader, BlockHeight, LocalTimestamp, MAX_ROUND_GAP, MAX_TIMESTAMP_DELAY,
    MAX_TIMESTAMP_RUSH, ProvisionHash, QuorumCertificate, RoutableTransaction, ShardGroupId,
    TopologySnapshot, TxHash, Verifiable, VotePower, WaveId, compute_waves,
};

use crate::commit_dedup::CommitDedupIndex;

/// True if `qc.signers()` represents at least 2f+1 of the local committee's
/// voting power. The synced-block apply path and consensus pre-vote path
/// both call this — without it, a single Byzantine signer suffices to pass
/// the BLS-only `VerifyQcSignature` check that follows.
#[must_use]
pub fn qc_has_local_quorum_power(
    topology: &TopologySnapshot,
    local_shard: ShardGroupId,
    qc: &QuorumCertificate,
) -> bool {
    let committee = topology.committee_for_shard(local_shard);
    let qc_power: VotePower = qc
        .signers()
        .set_indices()
        .filter_map(|i| committee.get(i))
        .map(|&vid| {
            topology
                .voting_power(vid)
                .expect("committee member has voting power (TopologySnapshot invariant)")
        })
        .sum();
    VotePower::has_quorum(qc_power, topology.voting_power_for_shard(local_shard))
}

/// Validate block header structure, proposer, and parent QC quorum. Returns
/// `Err(..)` with a human-readable reason on any check failure.
pub fn validate_header(
    topology: &TopologySnapshot,
    local_shard: ShardGroupId,
    header: &BlockHeader,
    committed_height: BlockHeight,
    now: LocalTimestamp,
) -> Result<(), String> {
    let height = header.height();
    let round = header.round();

    if height <= committed_height {
        return Err(format!(
            "height {} is at or below committed height {}",
            height.inner(),
            committed_height.inner()
        ));
    }

    let expected_proposer = topology.proposer_for(local_shard, round);
    if header.proposer() != expected_proposer {
        return Err(format!(
            "wrong proposer: expected {:?}, got {:?}",
            expected_proposer,
            header.proposer()
        ));
    }

    // The round span between the parent QC and this block is the number of
    // skipped rounds every validator materializes as `MissedProposal`
    // beacon-witness leaves. Bound it so a Byzantine proposer (the
    // deterministic proposer for arbitrarily large rounds) can't name itself
    // at a runaway round and force an unbounded per-block allocation.
    let parent_round = header.parent_qc().round();
    if round < parent_round {
        return Err(format!(
            "round {} is below parent QC round {}",
            round.inner(),
            parent_round.inner()
        ));
    }
    if round.inner() - parent_round.inner() > MAX_ROUND_GAP {
        return Err(format!(
            "round gap {} exceeds maximum {MAX_ROUND_GAP} (round {}, parent QC round {})",
            round.inner() - parent_round.inner(),
            round.inner(),
            parent_round.inner()
        ));
    }

    if !header.parent_qc().is_genesis() {
        if !qc_has_local_quorum_power(topology, local_shard, header.parent_qc()) {
            return Err("parent QC does not have quorum".to_string());
        }

        if header.parent_qc().height().next() != height {
            return Err(format!(
                "parent QC height {} doesn't match block height {} - 1",
                header.parent_qc().height().inner(),
                height.inner()
            ));
        }

        if header.parent_block_hash() != header.parent_qc().block_hash() {
            return Err(format!(
                "parent_block_hash {:?} doesn't match parent_qc.block_hash() {:?}",
                header.parent_block_hash(),
                header.parent_qc().block_hash()
            ));
        }
    } else if height != committed_height.next() {
        return Err(format!(
            "genesis QC only valid for first block after committed height, got height {}",
            height.inner()
        ));
    }

    validate_timestamp(header, now)?;

    Ok(())
}

/// Validate that the proposer's timestamp is within acceptable bounds.
///
/// The timestamp must not be more than [`MAX_TIMESTAMP_DELAY`] behind our
/// clock nor more than [`MAX_TIMESTAMP_RUSH`] ahead.
///
/// Skipped for genesis blocks (fixed zero timestamp) and fallback blocks,
/// which inherit the parent's weighted timestamp and so can sit below the
/// delay threshold during extended view changes. The carve-out is sound
/// because `header.timestamp()` is a non-authenticated liveness hint with
/// no consensus consumer — the BFT clock is the QC's `weighted_timestamp`,
/// aggregated from voters' own clocks, not this field.
pub fn validate_timestamp(header: &BlockHeader, now: LocalTimestamp) -> Result<(), String> {
    if header.is_genesis() {
        return Ok(());
    }
    if header.is_fallback() {
        return Ok(());
    }

    let max_delay_ms = u64::try_from(MAX_TIMESTAMP_DELAY.as_millis()).unwrap_or(u64::MAX);
    let max_rush_ms = u64::try_from(MAX_TIMESTAMP_RUSH.as_millis()).unwrap_or(u64::MAX);

    let now_ms = now.as_millis();
    let header_ts_ms = header.timestamp().as_millis();

    if header_ts_ms < now_ms.saturating_sub(max_delay_ms) {
        return Err(format!(
            "proposer timestamp {header_ts_ms} is too old (now: {now_ms}, max delay: {max_delay_ms}ms)"
        ));
    }

    if header_ts_ms > now_ms.saturating_add(max_rush_ms) {
        return Err(format!(
            "proposer timestamp {header_ts_ms} is too far ahead (now: {now_ms}, max rush: {max_rush_ms}ms)"
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
pub fn validate_waves(
    topology: &TopologySnapshot,
    local_shard: ShardGroupId,
    block: &Block,
) -> Result<(), String> {
    let expected = compute_waves(local_shard, topology, block.height(), block.transactions());

    if block.header().waves().0 != expected {
        return Err(format!(
            "waves mismatch: header={:?}, computed={:?}",
            block.header().waves(),
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
    local_shard: ShardGroupId,
    block: &Block,
    qc_chain_tx_hashes: &HashSet<TxHash>,
    qc_chain_cert_ids: &HashSet<WaveId>,
    qc_chain_provision_hashes: &HashSet<ProvisionHash>,
    dedup_index: &CommitDedupIndex,
) -> Result<(), String> {
    validate_transactions_verified(block)?;
    validate_transaction_ordering(block)?;
    validate_waves(topology, local_shard, block)?;
    validate_no_duplicate_transactions(block, qc_chain_tx_hashes, dedup_index)?;
    validate_no_duplicate_certificates(block, qc_chain_cert_ids, dedup_index)?;
    validate_no_duplicate_provisions(block, qc_chain_provision_hashes, dedup_index)?;
    Ok(())
}

/// Refuse to vote on a block whose `transactions` entries are not all
/// `Verifiable::Verified`. Honest voters source every tx from local
/// admission-validated state (mempool / fetch cache); an `Unverified` entry
/// means assembly couldn't obtain or validate the body, and voting would
/// break the BFT-transitive trust chain that downstream `from_persisted`
/// gates rely on.
fn validate_transactions_verified(block: &Block) -> Result<(), String> {
    for tx in block.transactions().iter() {
        if tx.verified().is_none() {
            return Err(format!(
                "transaction {} is not admission-validated",
                tx.hash()
            ));
        }
    }
    Ok(())
}

/// Verify that a list of transactions is sorted by hash in strict ascending
/// order. `section` is used in the error message for diagnostics.
fn verify_hash_sorted(
    txs: &[Arc<Verifiable<RoutableTransaction>>],
    section: &str,
) -> Result<(), String> {
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
    use std::collections::BTreeSet;

    use hyperscale_test_helpers::{TestCommittee, make_finalized_wave};
    use hyperscale_types::{
        BlockHash, BlockHeader, BoundedVec, CertificateRoot, FinalizedWave, Hash, InFlightCount,
        LocalReceiptRoot, MerkleInclusionProof, NetworkDefinition, ProposerTimestamp,
        ProvisionEntry, Provisions, ProvisionsRoot, QuorumCertificate, Round, RoutableTransaction,
        ShardGroupId, StateRoot, TransactionDecision, TransactionRoot, ValidatorId, ValidatorInfo,
        ValidatorSet, Verifiable, WeightedTimestamp, compute_waves, test_utils,
    };

    use super::*;

    fn topology() -> TopologySnapshot {
        let committee = TestCommittee::new(4, 42);
        let validators: Vec<ValidatorInfo> = (0..committee.size())
            .map(|i| ValidatorInfo {
                validator_id: committee.validator_id(i),
                public_key: *committee.public_key(i),
                voting_power: VotePower::new(1),
            })
            .collect();
        TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(validators),
        )
    }

    fn local_shard() -> ShardGroupId {
        ShardGroupId::new(0)
    }

    fn header_at_height(height: BlockHeight, timestamp_ms: u64) -> BlockHeader {
        BlockHeader::new(
            ShardGroupId::new(0),
            height,
            BlockHash::from_raw(Hash::from_bytes(b"parent")),
            QuorumCertificate::genesis(ShardGroupId::new(0)),
            ValidatorId::new(height.inner() % 4),
            ProposerTimestamp::from_millis(timestamp_ms),
            Round::new(0),
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            std::collections::BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
        )
    }

    fn header_with_overrides(
        base: &BlockHeader,
        round: Option<Round>,
        is_fallback: Option<bool>,
        parent_block_hash: Option<BlockHash>,
        proposer: Option<ValidatorId>,
    ) -> BlockHeader {
        BlockHeader::new(
            base.shard_group_id(),
            base.height(),
            parent_block_hash.unwrap_or_else(|| base.parent_block_hash()),
            base.parent_qc().clone(),
            proposer.unwrap_or_else(|| base.proposer()),
            base.timestamp(),
            round.unwrap_or_else(|| base.round()),
            is_fallback.unwrap_or_else(|| base.is_fallback()),
            base.state_root(),
            base.transaction_root(),
            base.certificate_root(),
            base.local_receipt_root(),
            base.provision_root(),
            base.waves().clone().into_inner(),
            base.provision_tx_roots().clone().into_inner(),
            base.in_flight(),
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
        )
    }

    fn block_with_waves(height: BlockHeight, waves: Vec<WaveId>) -> Block {
        let header = BlockHeader::new(
            ShardGroupId::new(0),
            height,
            BlockHash::ZERO,
            QuorumCertificate::genesis(ShardGroupId::new(0)),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(0),
            Round::INITIAL,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            waves,
            std::collections::BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
        );
        Block::Live {
            header,
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
        }
    }

    #[test]
    fn validate_waves_accepts_recomputed_waves() {
        let topo = topology();
        let height = BlockHeight::new(1);
        let expected = compute_waves(local_shard(), &topo, height, &[]);
        let block = block_with_waves(height, expected);
        assert!(validate_waves(&topo, local_shard(), &block).is_ok());
    }

    #[test]
    fn validate_waves_rejects_tampered_waves() {
        let topo = topology();
        let block = block_with_waves(
            BlockHeight::new(1),
            vec![WaveId::new(
                ShardGroupId::new(99),
                BlockHeight::new(1),
                BTreeSet::new(),
            )],
        );
        assert!(validate_waves(&topo, local_shard(), &block).is_err());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // validate_timestamp
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn validate_timestamp_skips_genesis() {
        let now = LocalTimestamp::from_millis(100_000);
        let header = header_with_overrides(
            &header_at_height(BlockHeight::new(0), 0),
            None,
            None,
            Some(BlockHash::from_raw(Hash::from_bytes(b"genesis_parent"))),
            Some(ValidatorId::new(0)),
        );
        assert!(validate_timestamp(&header, now).is_ok());
    }

    #[test]
    fn validate_timestamp_accepts_within_bounds() {
        let now = LocalTimestamp::from_millis(100_000);
        for ts_ms in [99_000, 100_000, 101_000] {
            let header = header_at_height(BlockHeight::new(1), ts_ms);
            assert!(
                validate_timestamp(&header, now).is_ok(),
                "ts_ms={ts_ms} should be within bounds"
            );
        }
    }

    #[test]
    fn validate_timestamp_rejects_too_old() {
        let now = LocalTimestamp::from_millis(100_000);
        let header = header_at_height(BlockHeight::new(1), 50_000);
        let err = validate_timestamp(&header, now).unwrap_err();
        assert!(err.contains("too old"));
    }

    #[test]
    fn validate_timestamp_rejects_too_far_ahead() {
        let now = LocalTimestamp::from_millis(100_000);
        let header = header_at_height(BlockHeight::new(1), 110_000);
        let err = validate_timestamp(&header, now).unwrap_err();
        assert!(err.contains("too far ahead"));
    }

    #[test]
    fn validate_timestamp_at_boundary() {
        let now = LocalTimestamp::from_millis(100_000);

        // Exactly max delay (now - 30s) — OK.
        assert!(validate_timestamp(&header_at_height(BlockHeight::new(1), 70_000), now).is_ok());
        // Just past max delay — fail.
        assert!(validate_timestamp(&header_at_height(BlockHeight::new(1), 69_999), now).is_err());
        // Exactly max rush (now + 2s) — OK.
        assert!(validate_timestamp(&header_at_height(BlockHeight::new(1), 102_000), now).is_ok());
        // Just past max rush — fail.
        assert!(validate_timestamp(&header_at_height(BlockHeight::new(1), 102_001), now).is_err());
    }

    #[test]
    fn validate_timestamp_skips_fallback_blocks() {
        let now = LocalTimestamp::from_millis(100_000);

        // 50s old would normally fail (MAX_TIMESTAMP_DELAY = 30s), but fallback
        // blocks inherit the parent's weighted timestamp across view changes.
        let base = header_at_height(BlockHeight::new(1), 50_000);
        let header_fallback =
            header_with_overrides(&base, Some(Round::new(5)), Some(true), None, None);
        assert!(validate_timestamp(&header_fallback, now).is_ok());

        let header_normal =
            header_with_overrides(&base, Some(Round::new(5)), Some(false), None, None);
        assert!(validate_timestamp(&header_normal, now).is_err());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // validate_header round-gap bound
    // ═══════════════════════════════════════════════════════════════════════

    fn header_at_round(height: BlockHeight, round: Round, topo: &TopologySnapshot) -> BlockHeader {
        let base = header_at_height(height, 100_000);
        let proposer = topo.proposer_for(local_shard(), round);
        header_with_overrides(&base, Some(round), None, None, Some(proposer))
    }

    #[test]
    fn validate_header_rejects_runaway_round_gap() {
        let topo = topology();
        let now = LocalTimestamp::from_millis(100_000);
        let height = BlockHeight::new(1);
        let header = header_at_round(height, Round::new(MAX_ROUND_GAP + 1), &topo);

        let err =
            validate_header(&topo, local_shard(), &header, BlockHeight::new(0), now).unwrap_err();
        assert!(err.contains("round gap"), "got: {err}");
    }

    #[test]
    fn validate_header_accepts_round_gap_at_cap() {
        let topo = topology();
        let now = LocalTimestamp::from_millis(100_000);
        let height = BlockHeight::new(1);
        let header = header_at_round(height, Round::new(MAX_ROUND_GAP), &topo);

        assert!(validate_header(&topo, local_shard(), &header, BlockHeight::new(0), now).is_ok());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // validate_transaction_ordering
    // ═══════════════════════════════════════════════════════════════════════

    fn block_with_transactions(
        height: BlockHeight,
        transactions: Vec<Arc<Verifiable<RoutableTransaction>>>,
    ) -> Block {
        Block::Live {
            header: header_at_height(height, 100_000),
            transactions: Arc::new(transactions.into()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
        }
    }

    fn tx(seed: u8) -> Arc<Verifiable<RoutableTransaction>> {
        Arc::new(Verifiable::from(test_utils::test_transaction(seed)))
    }

    fn sorted_txs(seeds: &[u8]) -> Vec<Arc<Verifiable<RoutableTransaction>>> {
        let mut txs: Vec<_> = seeds.iter().map(|&s| tx(s)).collect();
        txs.sort_by_key(|t| t.hash());
        txs
    }

    #[test]
    fn validate_transaction_ordering_accepts_empty_block() {
        let block = block_with_transactions(BlockHeight::new(5), vec![]);
        assert!(validate_transaction_ordering(&block).is_ok());
    }

    #[test]
    fn validate_transaction_ordering_accepts_single_tx() {
        let block = block_with_transactions(BlockHeight::new(5), vec![tx(1)]);
        assert!(validate_transaction_ordering(&block).is_ok());
    }

    #[test]
    fn validate_transaction_ordering_accepts_sorted() {
        let block = block_with_transactions(BlockHeight::new(5), sorted_txs(&[10, 20, 30]));
        assert!(validate_transaction_ordering(&block).is_ok());
    }

    #[test]
    fn validate_transaction_ordering_rejects_reversed() {
        let mut txs = sorted_txs(&[10, 20, 30]);
        txs.reverse();
        let block = block_with_transactions(BlockHeight::new(5), txs);
        let err = validate_transaction_ordering(&block).unwrap_err();
        assert!(err.contains("not in hash order"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // validate_no_duplicate_transactions
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn validate_no_duplicate_transactions_accepts_empty_block() {
        let block = block_with_transactions(BlockHeight::new(5), vec![]);
        let qc_chain = HashSet::new();
        let dedup_index = CommitDedupIndex::new();
        assert!(validate_no_duplicate_transactions(&block, &qc_chain, &dedup_index).is_ok());
    }

    #[test]
    fn validate_no_duplicate_transactions_accepts_unique() {
        let block = block_with_transactions(BlockHeight::new(5), sorted_txs(&[10, 20]));
        let qc_chain = HashSet::new();
        let dedup_index = CommitDedupIndex::new();
        assert!(validate_no_duplicate_transactions(&block, &qc_chain, &dedup_index).is_ok());
    }

    #[test]
    fn validate_no_duplicate_transactions_rejects_qc_chain_dup() {
        let txs = sorted_txs(&[10, 20]);
        let dup_hash = txs[0].hash();
        let block = block_with_transactions(BlockHeight::new(6), txs);
        let qc_chain: HashSet<_> = std::iter::once(dup_hash).collect();
        let dedup_index = CommitDedupIndex::new();
        let err = validate_no_duplicate_transactions(&block, &qc_chain, &dedup_index).unwrap_err();
        assert!(err.contains("already in QC chain ancestor"));
    }

    #[test]
    fn validate_no_duplicate_transactions_rejects_retention_dup() {
        let txs = sorted_txs(&[10, 20]);
        let dup_tx = Arc::clone(&txs[0]);
        let block = block_with_transactions(BlockHeight::new(6), txs);
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
        let wrapped: Vec<Arc<Verifiable<FinalizedWave>>> = certificates
            .into_iter()
            .map(|fw| Arc::new((*fw).clone().into()))
            .collect();
        Block::Live {
            header: header_at_height(height, 100_000),
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(wrapped.into()),
            provisions: Arc::new(BoundedVec::new()),
        }
    }

    fn finalized_wave_at(height: u64) -> Arc<FinalizedWave> {
        Arc::new(make_finalized_wave(
            BlockHeight::new(height),
            TxHash::from_raw(Hash::from_bytes(
                &[u8::try_from(height).unwrap_or(u8::MAX); 32],
            )),
            TransactionDecision::Accept,
        ))
    }

    #[test]
    fn validate_no_duplicate_certificates_accepts_empty_block() {
        let block = block_with_certificates(BlockHeight::new(5), vec![]);
        let qc_chain = HashSet::new();
        let dedup_index = CommitDedupIndex::new();
        assert!(validate_no_duplicate_certificates(&block, &qc_chain, &dedup_index).is_ok());
    }

    #[test]
    fn validate_no_duplicate_certificates_accepts_unique() {
        let block = block_with_certificates(BlockHeight::new(5), vec![finalized_wave_at(1)]);
        let qc_chain = HashSet::new();
        let dedup_index = CommitDedupIndex::new();
        assert!(validate_no_duplicate_certificates(&block, &qc_chain, &dedup_index).is_ok());
    }

    #[test]
    fn validate_no_duplicate_certificates_rejects_qc_chain_dup() {
        let fw = finalized_wave_at(1);
        let dup_id = fw.wave_id().clone();
        let block = block_with_certificates(BlockHeight::new(6), vec![fw]);
        let qc_chain: HashSet<_> = std::iter::once(dup_id).collect();
        let dedup_index = CommitDedupIndex::new();
        let err = validate_no_duplicate_certificates(&block, &qc_chain, &dedup_index).unwrap_err();
        assert!(err.contains("already in QC chain ancestor"));
    }

    #[test]
    fn validate_no_duplicate_certificates_rejects_retention_dup() {
        let fw = finalized_wave_at(1);
        let block = block_with_certificates(BlockHeight::new(6), vec![Arc::clone(&fw)]);
        let qc_chain = HashSet::new();
        let mut dedup_index = CommitDedupIndex::new();
        let fw_verifiable = Arc::new((*fw).clone().into());
        dedup_index.register_committed_certs(&[fw_verifiable]);
        let err = validate_no_duplicate_certificates(&block, &qc_chain, &dedup_index).unwrap_err();
        assert!(err.contains("already committed"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // validate_no_duplicate_provisions
    // ═══════════════════════════════════════════════════════════════════════

    fn block_with_provisions(height: BlockHeight, provisions: Vec<Arc<Provisions>>) -> Block {
        let wrapped: Vec<Arc<Verifiable<Provisions>>> = provisions
            .into_iter()
            .map(|p| Arc::new((*p).clone().into()))
            .collect();
        Block::Live {
            header: header_at_height(height, 100_000),
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(wrapped.into()),
        }
    }

    fn provisions_with_seed(seed: u8) -> Arc<Provisions> {
        let tx_hash = TxHash::from_raw(Hash::from_bytes(&[seed; 32]));
        Arc::new(Provisions::new(
            ShardGroupId::new(0),
            ShardGroupId::new(1),
            BlockHeight::new(u64::from(seed)),
            MerkleInclusionProof::dummy(),
            vec![ProvisionEntry::new(tx_hash, vec![], vec![], vec![])],
        ))
    }

    #[test]
    fn validate_no_duplicate_provisions_accepts_empty_block() {
        let block = block_with_provisions(BlockHeight::new(5), vec![]);
        let qc_chain = HashSet::new();
        let dedup_index = CommitDedupIndex::new();
        assert!(validate_no_duplicate_provisions(&block, &qc_chain, &dedup_index).is_ok());
    }

    #[test]
    fn validate_no_duplicate_provisions_accepts_unique() {
        let block = block_with_provisions(BlockHeight::new(5), vec![provisions_with_seed(1)]);
        let qc_chain = HashSet::new();
        let dedup_index = CommitDedupIndex::new();
        assert!(validate_no_duplicate_provisions(&block, &qc_chain, &dedup_index).is_ok());
    }

    #[test]
    fn validate_no_duplicate_provisions_rejects_qc_chain_dup() {
        let p = provisions_with_seed(1);
        let dup_hash = p.hash();
        let block = block_with_provisions(BlockHeight::new(6), vec![p]);
        let qc_chain: HashSet<_> = std::iter::once(dup_hash).collect();
        let dedup_index = CommitDedupIndex::new();
        let err = validate_no_duplicate_provisions(&block, &qc_chain, &dedup_index).unwrap_err();
        assert!(err.contains("already in QC chain ancestor"));
    }

    #[test]
    fn validate_no_duplicate_provisions_rejects_retention_dup() {
        let p = provisions_with_seed(1);
        let block = block_with_provisions(BlockHeight::new(6), vec![Arc::clone(&p)]);
        let qc_chain = HashSet::new();
        let mut dedup_index = CommitDedupIndex::new();
        dedup_index
            .register_committed_provisions(&[p.hash()], WeightedTimestamp::from_millis(1_000));
        let err = validate_no_duplicate_provisions(&block, &qc_chain, &dedup_index).unwrap_err();
        assert!(err.contains("already committed"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // validate_transactions_verified / validate_block_for_vote verified-arm
    // ═══════════════════════════════════════════════════════════════════════

    fn verified_tx(seed: u8) -> Arc<Verifiable<RoutableTransaction>> {
        Arc::new(Verifiable::from(test_utils::verified_test_transaction(
            seed,
        )))
    }

    fn sorted_verified_txs(seeds: &[u8]) -> Vec<Arc<Verifiable<RoutableTransaction>>> {
        let mut txs: Vec<_> = seeds.iter().map(|&s| verified_tx(s)).collect();
        txs.sort_by_key(|t| t.hash());
        txs
    }

    #[test]
    fn validate_transactions_verified_accepts_empty_block() {
        let block = block_with_transactions(BlockHeight::new(1), vec![]);
        assert!(validate_transactions_verified(&block).is_ok());
    }

    #[test]
    fn validate_transactions_verified_accepts_all_verified() {
        let block =
            block_with_transactions(BlockHeight::new(1), sorted_verified_txs(&[10, 20, 30]));
        assert!(validate_transactions_verified(&block).is_ok());
    }

    #[test]
    fn validate_transactions_verified_rejects_any_unverified() {
        // Mix one Unverified entry into an otherwise-Verified block.
        let mut txs = sorted_verified_txs(&[10, 20]);
        let unverified = tx(30);
        txs.push(unverified);
        txs.sort_by_key(|t| t.hash());
        let block = block_with_transactions(BlockHeight::new(1), txs);
        let err = validate_transactions_verified(&block).unwrap_err();
        assert!(err.contains("not admission-validated"));
    }

    #[test]
    fn validate_block_for_vote_rejects_unverified_before_other_checks() {
        // Out-of-order + Unverified: the verified-check fires first and
        // short-circuits before ordering is examined.
        let topo = topology();
        let mut txs = sorted_verified_txs(&[10, 20]);
        txs.reverse(); // intentionally mis-sort to prove short-circuit
        txs.push(tx(30)); // Unverified entry
        let block = block_with_transactions(BlockHeight::new(1), txs);
        let err = validate_block_for_vote(
            &topo,
            local_shard(),
            &block,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            &CommitDedupIndex::new(),
        )
        .unwrap_err();
        assert!(err.contains("not admission-validated"));
    }
}
