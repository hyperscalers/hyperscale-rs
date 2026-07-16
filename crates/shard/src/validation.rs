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
    Block, BlockHeader, BlockHeight, LocalTimestamp, MAX_ROUND_GAP, MAX_TIMESTAMP_DELAY,
    MAX_TIMESTAMP_RUSH, ProvisionHash, QuorumCertificate, RoutableTransaction, ShardId,
    TopologySnapshot, TxHash, Verifiable, VoteCount, WaveId, compute_waves,
};

use crate::commit_dedup::CommitDedupIndex;

/// True if `qc.signers()` represents at least 2f+1 of the local committee's
/// voting power. The synced-block apply path and consensus pre-vote path
/// both call this — without it, a single Byzantine signer suffices to pass
/// the BLS-only `VerifyQcSignature` check that follows.
#[must_use]
pub fn qc_has_local_quorum_power(
    topology_snapshot: &TopologySnapshot,
    local_shard: ShardId,
    qc: &QuorumCertificate,
) -> bool {
    let committee = topology_snapshot.consensus_committee_for_shard(local_shard);
    let qc_power: VoteCount = qc
        .signers()
        .set_indices()
        .filter_map(|i| committee.get(i))
        .map(|&vid| {
            topology_snapshot
                .vote_of(vid)
                .expect("committee member has voting power (TopologySnapshot invariant)")
        })
        .sum();
    VoteCount::has_quorum(qc_power, topology_snapshot.committee_votes(local_shard))
}

/// True if `qc`'s `weighted_timestamp` is implausibly far ahead of `now`.
///
/// The weighted timestamp rides outside the QC's signed message
/// (`block_vote_message` covers only shard/height/round/hashes), so a Byzantine
/// proposer or forwarder can rewrite it on an otherwise-genuine QC and still
/// pass `VerifyQcSignature`. A far-future value poisons the BFT clock that
/// anchors transaction-validity windows — honest transactions fall outside the
/// window (blocks go empty) and the aggregation floor propagates the skew
/// irreversibly. An honestly-aggregated weighted timestamp is a mean of voters'
/// clocks from an earlier round, so it leads ours by at most the honest skew
/// envelope; anything beyond is rejected. Checked wherever an untrusted QC
/// enters chain state: header validation, synced-block admission,
/// timeout-quorum `high_qc` adoption, and local QC aggregation (per-vote
/// timestamps are equally unsigned, so the aggregated mean is no more
/// trustworthy than a received QC's field).
#[must_use]
pub fn qc_weighted_timestamp_too_far_ahead(qc: &QuorumCertificate, now: LocalTimestamp) -> bool {
    let weighted_ms = qc.weighted_timestamp().as_millis();
    let max_ahead_ms =
        u64::try_from((MAX_TIMESTAMP_DELAY + MAX_TIMESTAMP_RUSH).as_millis()).unwrap_or(u64::MAX);
    weighted_ms > now.as_millis().saturating_add(max_ahead_ms)
}

/// Validate block header structure, proposer, and parent QC quorum. Returns
/// `Err(..)` with a human-readable reason on any check failure.
///
/// The header's two committee-keyed checks resolve against different
/// committees at an epoch boundary: the proposer of block `h` belongs to
/// `committee(h)` (`proposer_committee`), while the parent QC over `h-1` was
/// signed by `committee(h-1)` (`parent_committee`). The caller resolves each
/// by weighted timestamp and passes both; `parent_committee` is `None` only
/// when the parent QC is genesis (no quorum to check).
pub fn validate_header(
    proposer_committee: &TopologySnapshot,
    parent_committee: Option<&TopologySnapshot>,
    local_shard: ShardId,
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

    let expected_proposer = proposer_committee.proposer_for(local_shard, round);
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
        // The parent QC's signing committee is `committee(h-1)`. When the
        // caller can't resolve it (we don't hold `h-1`'s header yet), skip the
        // quorum **pre-check** — it's a cheap DoS filter, and the parent QC is
        // fully BLS-verified against the exact committee before we ever vote,
        // once `h-1` arrives. The structural checks below need no committee.
        if let Some(parent_committee) = parent_committee
            && !qc_has_local_quorum_power(parent_committee, local_shard, header.parent_qc())
        {
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

    // The parent QC's `weighted_timestamp` anchors this block's
    // transaction-validity window but rides outside the QC's signed message, so
    // a Byzantine proposer or forwarder can forge it; a far-future value forces
    // empty blocks and propagates irreversibly through the aggregation floor.
    // See [`qc_weighted_timestamp_too_far_ahead`].
    if qc_weighted_timestamp_too_far_ahead(header.parent_qc(), now) {
        return Err(format!(
            "parent QC weighted timestamp {} is too far ahead (now: {})",
            header.parent_qc().weighted_timestamp().as_millis(),
            now.as_millis()
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
    topology_snapshot: &TopologySnapshot,
    local_shard: ShardId,
    block: &Block,
) -> Result<(), String> {
    let expected = compute_waves(
        local_shard,
        topology_snapshot,
        block.height(),
        block.transactions(),
    );

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
#[allow(clippy::too_many_arguments)] // single dispatch over the pre-vote content checks
pub fn validate_block_for_vote(
    topology_snapshot: &TopologySnapshot,
    local_shard: ShardId,
    block: &Block,
    qc_chain_tx_hashes: &HashSet<TxHash>,
    qc_chain_cert_ids: &HashSet<WaveId>,
    qc_chain_provision_hashes: &HashSet<ProvisionHash>,
    dedup_index: &CommitDedupIndex,
    coasting: bool,
) -> Result<(), String> {
    if coasting {
        validate_coast_block_empty(block)?;
    }
    validate_transactions_verified(block)?;
    validate_transaction_ordering(block)?;
    validate_waves(topology_snapshot, local_shard, block)?;
    validate_no_duplicate_transactions(block, qc_chain_tx_hashes, dedup_index)?;
    validate_no_duplicate_certificates(block, qc_chain_cert_ids, dedup_index)?;
    validate_no_duplicate_provisions(block, qc_chain_provision_hashes, dedup_index)?;
    Ok(())
}

/// A coast block — one whose parent QC's weighted timestamp lands past
/// the shard's terminal window — exists only to certify the crossing.
/// It must carry no transactions, no certificates, and no provisions, so
/// state stays frozen at the crossing's root.
fn validate_coast_block_empty(block: &Block) -> Result<(), String> {
    if !block.transactions().is_empty() {
        return Err(format!(
            "coast block past the terminal window carries {} transactions",
            block.transactions().len()
        ));
    }
    if !block.certificates().is_empty() {
        return Err(format!(
            "coast block past the terminal window carries {} certificates",
            block.certificates().len()
        ));
    }
    if !block.provisions().is_empty() {
        return Err(format!(
            "coast block past the terminal window carries {} provisions",
            block.provisions().len()
        ));
    }
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

    use hyperscale_types::test_utils::{TestCommittee, make_finalized_wave};
    use hyperscale_types::{
        BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeader, BoundedVec,
        CertificateRoot, ChainOrigin, FinalizedWave, Hash, InFlightCount, LocalReceiptRoot,
        MerkleInclusionProof, NetworkDefinition, ProposerTimestamp, ProvisionEntry, Provisions,
        ProvisionsRoot, QuorumCertificate, Round, RoutableTransaction, ShardId, SignerBitfield,
        StateRoot, TransactionDecision, TransactionRoot, ValidatorId, ValidatorInfo, ValidatorSet,
        Verifiable, VrfProof, WeightedTimestamp, bls_keypair_from_seed, compute_waves, test_utils,
        zero_bls_signature,
    };

    use super::*;

    fn topology_snapshot() -> TopologySnapshot {
        let committee = TestCommittee::new(4, 42);
        let validators: Vec<ValidatorInfo> = (0..committee.size())
            .map(|i| ValidatorInfo {
                validator_id: committee.validator_id(i),
                public_key: *committee.public_key(i),
            })
            .collect();
        TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(validators),
        )
    }

    fn local_shard() -> ShardId {
        ShardId::ROOT
    }

    fn header_at_height(height: BlockHeight, timestamp_ms: u64) -> BlockHeader {
        BlockHeader::new(
            ShardId::ROOT,
            height,
            BlockHash::from_raw(Hash::from_bytes(b"parent")),
            QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT),
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
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
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
            base.shard_id(),
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
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        )
    }

    fn block_with_waves(height: BlockHeight, waves: Vec<WaveId>) -> Block {
        let header = BlockHeader::new(
            ShardId::ROOT,
            height,
            BlockHash::ZERO,
            QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT),
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
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        );
        Block::Live {
            header,
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
            ready_signals: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
        }
    }

    #[test]
    fn validate_waves_accepts_recomputed_waves() {
        let topo = topology_snapshot();
        let height = BlockHeight::new(1);
        let expected = compute_waves(local_shard(), &topo, height, &[]);
        let block = block_with_waves(height, expected);
        assert!(validate_waves(&topo, local_shard(), &block).is_ok());
    }

    #[test]
    fn validate_waves_rejects_tampered_waves() {
        let topo = topology_snapshot();
        let block = block_with_waves(
            BlockHeight::new(1),
            vec![WaveId::new(
                ShardId::leaf(8, 99),
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
        let topo = topology_snapshot();
        let now = LocalTimestamp::from_millis(100_000);
        let height = BlockHeight::new(1);
        let header = header_at_round(height, Round::new(MAX_ROUND_GAP + 1), &topo);

        let err = validate_header(
            &topo,
            Some(&topo),
            local_shard(),
            &header,
            BlockHeight::new(0),
            now,
        )
        .unwrap_err();
        assert!(err.contains("round gap"), "got: {err}");
    }

    #[test]
    fn validate_header_accepts_round_gap_at_cap() {
        let topo = topology_snapshot();
        let now = LocalTimestamp::from_millis(100_000);
        let height = BlockHeight::new(1);
        let header = header_at_round(height, Round::new(MAX_ROUND_GAP), &topo);

        assert!(
            validate_header(
                &topo,
                Some(&topo),
                local_shard(),
                &header,
                BlockHeight::new(0),
                now
            )
            .is_ok()
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // validate_header parent-QC weighted-timestamp bound
    // ═══════════════════════════════════════════════════════════════════════

    /// A non-genesis parent QC for height 1 with quorum signers (3 of the
    /// 4-member committee) and a chosen `weighted_timestamp`.
    fn quorum_parent_qc(weighted_ms: u64) -> QuorumCertificate {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        QuorumCertificate::new(
            BlockHash::from_raw(Hash::from_bytes(b"parent_block")),
            ShardId::ROOT,
            BlockHeight::new(1),
            BlockHash::from_raw(Hash::from_bytes(b"grandparent")),
            Round::new(0),
            signers,
            zero_bls_signature(),
            WeightedTimestamp::from_millis(weighted_ms),
        )
    }

    /// A height-2, round-1 header that extends `parent_qc`, with the correct
    /// proposer and a valid proposer timestamp, so the parent-QC timestamp
    /// bound is the only check under test.
    fn header_extending(parent_qc: QuorumCertificate, now: LocalTimestamp) -> BlockHeader {
        let round = Round::new(1);
        let proposer = topology_snapshot().proposer_for(local_shard(), round);
        BlockHeader::new(
            ShardId::ROOT,
            BlockHeight::new(2),
            parent_qc.block_hash(),
            parent_qc,
            proposer,
            ProposerTimestamp::from_millis(now.as_millis()),
            round,
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
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        )
    }

    #[test]
    fn validate_header_rejects_far_future_parent_qc_timestamp() {
        let topo = topology_snapshot();
        let now = LocalTimestamp::from_millis(1_000_000);

        // Parent QC an hour ahead of our clock — far beyond the honest skew
        // envelope. The unsigned `weighted_timestamp` lets a Byzantine peer
        // forge this on an otherwise-genuine QC.
        let header = header_extending(quorum_parent_qc(now.as_millis() + 3_600_000), now);

        let err = validate_header(
            &topo,
            Some(&topo),
            local_shard(),
            &header,
            BlockHeight::new(0),
            now,
        )
        .unwrap_err();
        assert!(
            err.contains("parent QC weighted timestamp"),
            "expected far-future parent QC rejection, got: {err}"
        );
    }

    #[test]
    fn validate_header_accepts_recent_parent_qc_timestamp() {
        let topo = topology_snapshot();
        let now = LocalTimestamp::from_millis(1_000_000);

        // Honest case: the parent QC was aggregated a few seconds ago, so its
        // weighted timestamp sits just behind our clock.
        let header = header_extending(quorum_parent_qc(now.as_millis() - 5_000), now);

        assert!(
            validate_header(
                &topo,
                Some(&topo),
                local_shard(),
                &header,
                BlockHeight::new(0),
                now
            )
            .is_ok(),
            "honest recent parent QC timestamp must pass"
        );
    }

    #[test]
    fn qc_weighted_timestamp_bound_is_the_honest_skew_envelope() {
        let now = LocalTimestamp::from_millis(1_000_000);
        let envelope_ms =
            u64::try_from((MAX_TIMESTAMP_DELAY + MAX_TIMESTAMP_RUSH).as_millis()).unwrap();

        // Behind our clock (the honest case) and exactly at the envelope: kept.
        assert!(!qc_weighted_timestamp_too_far_ahead(
            &quorum_parent_qc(now.as_millis() - 100_000),
            now
        ));
        assert!(!qc_weighted_timestamp_too_far_ahead(
            &quorum_parent_qc(now.as_millis() + envelope_ms),
            now
        ));

        // One millisecond past the envelope: rejected.
        assert!(qc_weighted_timestamp_too_far_ahead(
            &quorum_parent_qc(now.as_millis() + envelope_ms + 1),
            now
        ));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // validate_header two-committee resolution (epoch boundary)
    // ═══════════════════════════════════════════════════════════════════════

    /// A uniform-power committee over `ids`, one shard.
    fn committee_with_ids(ids: &[u64]) -> TopologySnapshot {
        let validators: Vec<ValidatorInfo> = ids
            .iter()
            .map(|&id| {
                let mut seed = [0u8; 32];
                seed[..8].copy_from_slice(&id.to_le_bytes());
                ValidatorInfo {
                    validator_id: ValidatorId::new(id),
                    public_key: bls_keypair_from_seed(&seed).public_key(),
                }
            })
            .collect();
        TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(validators),
        )
    }

    /// A non-genesis parent QC over height 1 with a single signer — below
    /// quorum in any committee of more than one member.
    fn single_signer_parent_qc(weighted_ms: u64) -> QuorumCertificate {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        QuorumCertificate::new(
            BlockHash::from_raw(Hash::from_bytes(b"parent_block")),
            ShardId::ROOT,
            BlockHeight::new(1),
            BlockHash::from_raw(Hash::from_bytes(b"grandparent")),
            Round::new(0),
            signers,
            zero_bls_signature(),
            WeightedTimestamp::from_millis(weighted_ms),
        )
    }

    /// A height-2, round-1 header extending `parent_qc`, proposed by `proposer`,
    /// with a valid proposer timestamp — so proposer and parent-QC quorum are
    /// the only committee-keyed checks under test.
    fn header_with_proposer(
        parent_qc: QuorumCertificate,
        proposer: ValidatorId,
        now: LocalTimestamp,
    ) -> BlockHeader {
        BlockHeader::new(
            ShardId::ROOT,
            BlockHeight::new(2),
            parent_qc.block_hash(),
            parent_qc,
            proposer,
            ProposerTimestamp::from_millis(now.as_millis()),
            Round::new(1),
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
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        )
    }

    #[test]
    fn validate_header_keys_proposer_and_parent_on_distinct_committees() {
        // At an epoch boundary the proposer of block `h` belongs to
        // `committee(h)` while `h`'s parent QC was signed by `committee(h-1)`.
        // `validate_header` draws the proposer from the first committee and
        // checks the parent-QC quorum against the second; passing the committees
        // in the wrong roles rejects the header.
        let now = LocalTimestamp::from_millis(1_000_000);
        let parent_committee = committee_with_ids(&[0, 1, 2, 3]); // committee(h-1)
        let proposer_committee = committee_with_ids(&[10, 11, 12, 13]); // committee(h)

        let round = Round::new(1);
        let proposer = proposer_committee.proposer_for(local_shard(), round);
        let header = header_with_proposer(quorum_parent_qc(now.as_millis() - 5_000), proposer, now);

        assert!(
            validate_header(
                &proposer_committee,
                Some(&parent_committee),
                local_shard(),
                &header,
                BlockHeight::new(0),
                now,
            )
            .is_ok(),
            "header must validate under committee(h) proposer + committee(h-1) quorum",
        );

        let err = validate_header(
            &parent_committee,
            Some(&proposer_committee),
            local_shard(),
            &header,
            BlockHeight::new(0),
            now,
        )
        .unwrap_err();
        assert!(
            err.contains("wrong proposer"),
            "drawing the proposer from the parent committee must reject: {err}"
        );
    }

    #[test]
    fn validate_header_skips_parent_quorum_when_committee_unresolved() {
        // When `h-1`'s header hasn't arrived its committee can't be resolved, so
        // the caller passes `None` and the cheap quorum pre-check is skipped —
        // the parent QC is still fully BLS-verified against the exact committee
        // before this node votes. A resolved committee runs the pre-check and
        // rejects a sub-quorum parent QC.
        let topo = topology_snapshot();
        let now = LocalTimestamp::from_millis(1_000_000);
        let proposer = topo.proposer_for(local_shard(), Round::new(1));
        let header = header_with_proposer(
            single_signer_parent_qc(now.as_millis() - 5_000),
            proposer,
            now,
        );

        let err = validate_header(
            &topo,
            Some(&topo),
            local_shard(),
            &header,
            BlockHeight::new(0),
            now,
        )
        .unwrap_err();
        assert!(
            err.contains("parent QC does not have quorum"),
            "a resolved parent committee must enforce the quorum pre-check: {err}"
        );

        assert!(
            validate_header(
                &topo,
                None,
                local_shard(),
                &header,
                BlockHeight::new(0),
                now
            )
            .is_ok(),
            "an unresolved parent committee must skip the quorum pre-check",
        );
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
            ready_signals: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
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
            ready_signals: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
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
            ready_signals: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
        }
    }

    fn provisions_with_seed(seed: u8) -> Arc<Provisions> {
        let tx_hash = TxHash::from_raw(Hash::from_bytes(&[seed; 32]));
        Arc::new(Provisions::new(
            ShardId::leaf(1, 0),
            ShardId::leaf(1, 1),
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
        let topo = topology_snapshot();
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
            false,
        )
        .unwrap_err();
        assert!(err.contains("not admission-validated"));
    }

    #[test]
    fn coast_blocks_must_be_empty() {
        // Past the terminal window a block exists only to certify the
        // crossing: any content fails the pre-vote check.
        let topo = topology_snapshot();
        let with_tx = block_with_transactions(BlockHeight::new(1), sorted_verified_txs(&[10]));
        let err = validate_block_for_vote(
            &topo,
            local_shard(),
            &with_tx,
            &HashSet::new(),
            &HashSet::new(),
            &HashSet::new(),
            &CommitDedupIndex::new(),
            true,
        )
        .unwrap_err();
        assert!(err.contains("coast block"), "{err}");

        let empty = block_with_transactions(BlockHeight::new(1), Vec::new());
        assert!(
            validate_block_for_vote(
                &topo,
                local_shard(),
                &empty,
                &HashSet::new(),
                &HashSet::new(),
                &HashSet::new(),
                &CommitDedupIndex::new(),
                true,
            )
            .is_ok()
        );
    }
}
