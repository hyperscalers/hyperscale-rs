//! Pure pre-vote validation helpers.
//!
//! These functions check a received block header or block contents against
//! the rules every honest validator applies before voting:
//!
//! - Header structure: proposer selection, parent-QC quorum, timestamp bounds.
//! - Block contents: the section-level rules here, and each section's
//!   items through the [`crate::admission`] predicate the proposer
//!   selected them by.
//!
//! Everything here is stateless — callers supply the [`Admission`]
//! context explicitly. The async verification pipeline lives in
//! [`crate::verification`]; this module is just the pure rules.
//!
//! Errors are returned as human-readable strings so the caller can log a
//! single diagnostic line at the rejection site.
use std::sync::Arc;

use hyperscale_types::{
    AbandonmentRoot, Block, BlockHeader, BlockHeight, LeafRoot, LocalTimestamp, MAX_ROUND_GAP,
    MAX_TIMESTAMP_DELAY, MAX_TIMESTAMP_RUSH, QuorumCertificate, ShardId, ShardLoad,
    StateClaimsRoot, TopologySnapshot, Transaction, Verifiable, VoteCount,
};

use crate::admission::{
    Admission, FinalizationsFold, FinalizationsSection, ProvisionsFold, ProvisionsSection,
    RecordsFold, RecordsSection, StateClaimsFold, StateClaimsSection, TransactionsFold,
    TransactionsSection, admit_all, unwrapped,
};

/// True if `qc.signers()` represents at least 2f+1 of the local committee's
/// voting power. The synced-block apply path and consensus pre-vote path
/// both call this — without it, a single Byzantine signer suffices to pass
/// the signature-only `VerifyQcSignature` check that follows.
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
/// (`BlockVoteMessage` covers only shard/height/round/hashes), so a Byzantine
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
/// signed by `committee(h-1)` (`parent_committee`). Both are anchored on
/// `h-1`'s header, so both are `None` when it hasn't arrived and the caller
/// can't resolve them; `parent_committee` is additionally `None` when the
/// parent QC is genesis (no quorum to check). A skipped proposer check is
/// re-run against the exact committee before this node votes.
pub fn validate_header(
    proposer_committee: Option<&TopologySnapshot>,
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

    if let Some(committee) = proposer_committee {
        validate_proposer(committee, local_shard, header)?;
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
        // fully signature-verified against the exact committee before we ever vote,
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

/// Validate that `header` names the proposer its committee elects for the
/// header's round.
pub fn validate_proposer(
    proposer_committee: &TopologySnapshot,
    local_shard: ShardId,
    header: &BlockHeader,
) -> Result<(), String> {
    let expected_proposer = proposer_committee.proposer_for(local_shard, header.round());
    if header.proposer() != expected_proposer {
        return Err(format!(
            "wrong proposer: expected {:?}, got {:?}",
            expected_proposer,
            header.proposer()
        ));
    }
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

/// The header's running work total must be its parent's advanced by the
/// work the block's own certificates report.
///
/// Pure over the block plus one scalar off the parent header, which is what
/// keeps a shard's attested work honest without any storage read: a
/// proposer inflating its shard's emission weight has to inflate receipts
/// its committee already checked under `local_receipt_root`.
fn validate_block_work(block: &Block, parent_load: Option<ShardLoad>) -> Result<(), String> {
    // An unresolvable parent load is this node's own gap, not the block's,
    // so it abstains rather than rejecting: recovery reads the scalar off
    // the committed tip's stored header and a fresh start seeds `ZERO`, so
    // the only way here is a store with no block at its committed height.
    let Some(parent_load) = parent_load else {
        tracing::warn!(
            height = block.height().inner(),
            "Skipping the work-total check — parent load unresolvable"
        );
        return Ok(());
    };
    let claimed = block.header().load().cumulative_work;
    let expected = parent_load
        .advance(block.attested_work(), None)
        .cumulative_work;
    if claimed != expected {
        return Err(format!(
            "header claims cumulative work {claimed} but the parent's {} \
             plus this block's {} is {expected}",
            parent_load.cumulative_work,
            block.attested_work(),
        ));
    }
    Ok(())
}

/// Run every pre-vote block-contents check: the section-level rules —
/// a coast block empty, the work total, every transaction verified and
/// in hash order, each committing root over its section — and then each
/// section's items through the one [`Section`] predicate the proposer
/// selected them by, in the order the folds depend on: provisions, the
/// transactions they engage, finalizations, the records held to their
/// names, state claims. Returns a single diagnostic on the first failure
/// so the caller can log once.
pub fn validate_block_for_vote(
    ctx: &Admission<'_>,
    block: &Block,
    coasting: bool,
    parent_load: Option<ShardLoad>,
) -> Result<(), String> {
    if coasting {
        validate_coast_block_empty(block)?;
    }
    validate_block_work(block, parent_load)?;
    validate_transactions_verified(block)?;
    validate_transaction_ordering(block)?;
    validate_roots_commit_sections(block)?;
    admit_sections(ctx, block)
}

/// Every section's items through its [`Section`](crate::admission::Section)
/// predicate, in the order the folds depend on.
pub fn admit_sections(ctx: &Admission<'_>, block: &Block) -> Result<(), String> {
    let mut provisions = ProvisionsFold::default();
    admit_all::<ProvisionsSection>(
        ctx,
        &mut provisions,
        block.provisions().iter().map(unwrapped),
    )?;
    let mut transactions = TransactionsFold::beside(&provisions);
    admit_all::<TransactionsSection<'_>>(
        ctx,
        &mut transactions,
        block.transactions().iter().map(unwrapped),
    )?;
    let mut finalizations = FinalizationsFold::from(ctx);
    admit_all::<FinalizationsSection>(
        ctx,
        &mut finalizations,
        block.certificates().iter().map(unwrapped),
    )?;
    let mut records = RecordsFold::after(&finalizations);
    admit_all::<RecordsSection<'_>>(ctx, &mut records, block.abandonment_records())?;
    let mut state_claims = StateClaimsFold::default();
    admit_all::<StateClaimsSection>(ctx, &mut state_claims, block.state_claims())?;
    Ok(())
}

/// The header's abandonment root and state-claims root commit the
/// sections they claim.
///
/// What this establishes is that every replica reads the same section:
/// the root binds the items to the header, and the canonical order the
/// section rule holds each item to means one set of answers has one
/// encoding, so two proposers naming the same claims cannot produce
/// blocks that differ.
pub fn validate_roots_commit_sections(block: &Block) -> Result<(), String> {
    let computed = AbandonmentRoot::over(block.abandonment_records());
    let claimed = block.header().abandonment_root();
    if computed != claimed {
        return Err(format!(
            "abandonment root {claimed:?} does not commit the block's records {computed:?}"
        ));
    }
    let computed = StateClaimsRoot::over(block.state_claims());
    let claimed = block.header().state_claims_root();
    if computed != claimed {
        return Err(format!(
            "state claims root {claimed:?} does not commit the block's claims {computed:?}"
        ));
    }
    Ok(())
}

/// A coast block — one whose parent QC's weighted timestamp lands past
/// the shard's terminal window — exists only to certify the crossing. It
/// must carry no content of any kind, so state stays frozen at the
/// crossing's root: no transactions, no certificates, no provisions, and
/// no boundary records, which a chain whose own capacity to resolve
/// anything ended at its cut has nothing left to write down.
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
    if !block.abandonment_records().is_empty() {
        return Err(format!(
            "coast block past the terminal window carries {} abandonment records",
            block.abandonment_records().len()
        ));
    }
    if !block.state_claims().is_empty() {
        return Err(format!(
            "coast block past the terminal window carries {} state claims",
            block.state_claims().len()
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
fn verify_hash_sorted(txs: &[Arc<Verifiable<Transaction>>], section: &str) -> Result<(), String> {
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
    use hyperscale_crypto_bls::BlsSigner;
    use hyperscale_types::test_utils::{
        TestCommittee, make_finalization, make_undecided_finalization, stub_abort_charge,
        test_principal,
    };
    use hyperscale_types::{
        AbandonmentRecord, AbandonmentRoot, Address, AddressClass, AggregateSignature, Anchor,
        BlockHash, BlockHeader, BlockHeaderParts, ChainOrigin, Deadline, Finalization, Hash,
        Inclusion, LocalKey, MAX_PROPOSAL_EVIDENCE_BYTES, MAX_SUBINTENTS,
        MAX_SWEEPABLE_CREATED_PER_BLOCK, MAX_UNSETTLED_PER_BLOCK, MerkleInclusionProof,
        NetworkDefinition, PrincipalAddr, ProposerTimestamp, ProvisionEntry, Provisions,
        QuorumCertificate, Round, RoutePrefix, ShardId, ShardLoad, Signer, SignerBitfield,
        StateClaim, StateClaimsRoot, StateRoot, SubstateKey, TimestampRange, Transaction,
        TransactionDecision, TxHash, UnsettledTx, ValidatorId, ValidatorInfo, ValidatorSet,
        Verifiable, Verified, WeightedTimestamp, WitnessSources, test_utils,
    };

    use super::*;
    use crate::admission::fixtures::{Against, DEPARTURE_CUT_MS, departures};
    use crate::commit_dedup::CommitDedupIndex;

    /// Admit `block`'s sections against `against`.
    fn admit(against: &Against, block: &Block) -> Result<(), String> {
        admit_sections(&against.ctx(), block)
    }

    /// Admission under the test committee, with nothing behind the parent.
    fn plain() -> Against {
        Against::window(topology_snapshot())
    }

    /// Admission anchored after a cut at which both of `ROOT`'s children
    /// departed with their handoffs open, so an abandonment record naming
    /// either at that cut is one the schedule attests.
    fn after_departures() -> Against {
        let (left, right) = ShardId::ROOT.children();
        let (survivors_left, survivors_right) = (left.children(), right.children());
        let schedule = departures(
            &[left, right],
            &[
                survivors_left.0,
                survivors_left.1,
                survivors_right.0,
                survivors_right.1,
            ],
            None,
        );
        let mut against = Against::schedule(topology_snapshot(), schedule);
        against.anchor = WeightedTimestamp::from_millis(DEPARTURE_CUT_MS + 500);
        // A survivor under the right half, so the routes the fixtures
        // name under either departed half are remote to it.
        against.local_shard = survivors_right.0;
        against
    }

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
        BlockHeader::new(BlockHeaderParts {
            height,
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
            proposer: ValidatorId::new(height.inner() % 4),
            timestamp: ProposerTimestamp::from_millis(timestamp_ms),
            round: Round::new(0),
            provision_tx_roots: std::collections::BTreeMap::new(),
            ..Default::default()
        })
    }

    fn header_with_overrides(
        base: &BlockHeader,
        round: Option<Round>,
        is_fallback: Option<bool>,
        parent_block_hash: Option<BlockHash>,
        proposer: Option<ValidatorId>,
    ) -> BlockHeader {
        BlockHeader::new(BlockHeaderParts {
            shard_id: base.shard_id(),
            height: base.height(),
            parent_block_hash: parent_block_hash.unwrap_or_else(|| base.parent_block_hash()),
            parent_qc: base.parent_qc().clone().into(),
            proposer: proposer.unwrap_or_else(|| base.proposer()),
            timestamp: base.timestamp(),
            round: round.unwrap_or_else(|| base.round()),
            is_fallback: is_fallback.unwrap_or_else(|| base.is_fallback()),
            state_root: base.state_root(),
            transaction_root: base.transaction_root(),
            certificate_root: base.certificate_root(),
            local_receipt_root: base.local_receipt_root(),
            provision_root: base.provision_root(),
            provision_tx_roots: base.provision_tx_roots().clone(),
            work_in_flight: base.work_in_flight(),
            ..Default::default()
        })
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
            Some(&topo),
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
                Some(&topo),
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
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(weighted_ms),
        )
    }

    /// A height-2, round-1 header that extends `parent_qc`, with the correct
    /// proposer and a valid proposer timestamp, so the parent-QC timestamp
    /// bound is the only check under test.
    fn header_extending(parent_qc: QuorumCertificate, now: LocalTimestamp) -> BlockHeader {
        let round = Round::new(1);
        let proposer = topology_snapshot().proposer_for(local_shard(), round);
        BlockHeader::new(BlockHeaderParts {
            height: BlockHeight::new(2),
            parent_block_hash: parent_qc.block_hash(),
            parent_qc: parent_qc.into(),
            proposer,
            timestamp: ProposerTimestamp::from_millis(now.as_millis()),
            round,
            provision_tx_roots: std::collections::BTreeMap::new(),
            ..Default::default()
        })
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
            Some(&topo),
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
                Some(&topo),
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
                    public_key: BlsSigner::from_seed(&seed).public_key(),
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
            AggregateSignature::ZERO,
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
        BlockHeader::new(BlockHeaderParts {
            height: BlockHeight::new(2),
            parent_block_hash: parent_qc.block_hash(),
            parent_qc: parent_qc.into(),
            proposer,
            timestamp: ProposerTimestamp::from_millis(now.as_millis()),
            round: Round::new(1),
            provision_tx_roots: std::collections::BTreeMap::new(),
            ..Default::default()
        })
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
                Some(&proposer_committee),
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
            Some(&parent_committee),
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
        // the parent QC is still fully signature-verified against the exact committee
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
            Some(&topo),
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
                Some(&topo),
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
        transactions: Vec<Arc<Verifiable<Transaction>>>,
    ) -> Block {
        Block::Live {
            header: header_at_height(height, 100_000),
            transactions: Arc::new(transactions),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
        }
    }

    /// A block creating sweepable cells fits the cap right up to what a
    /// transaction can add, and one that would pass it is refused.
    ///
    /// The count is summed off the derivations rather than off anything
    /// the header claims, so a proposer cannot understate what its block
    /// will make the chain carry.
    ///
    /// An envelope binds at most `MAX_SUBINTENTS`, so the cap is reached
    /// by a block of fully composed transactions rather than by one
    /// transaction — which is the shape it is sized for.
    #[test]
    fn a_block_may_create_sweepable_cells_up_to_the_cap() {
        // Each fully composed transaction creates its subintents'
        // nullifiers, all on this one shard, and its committed cell
        // beside them.
        let full = MAX_SWEEPABLE_CREATED_PER_BLOCK / (MAX_SUBINTENTS + 1);
        let mut txs: Vec<Arc<Verifiable<Transaction>>> = (0..full)
            .map(|i| {
                Arc::new(Verifiable::from(test_utils::stub_transaction_binding(
                    u32::try_from(i).expect("fewer than u32 transactions"),
                    MAX_SUBINTENTS,
                    test_utils::test_validity_range(),
                )))
            })
            .collect();
        let at_cap = block_with_transactions(BlockHeight::new(3), txs.clone());
        assert!(admit(&plain(), &at_cap).is_ok());

        txs.push(Arc::new(Verifiable::from(
            test_utils::stub_transaction_binding(
                u32::MAX,
                MAX_SUBINTENTS,
                test_utils::test_validity_range(),
            ),
        )));
        let over = block_with_transactions(BlockHeight::new(3), txs);
        let err = admit(&plain(), &over).expect_err("past the cap is refused");
        assert!(err.contains("sweepable cells"), "{err}");

        // A block that binds nothing creates only its transactions'
        // committed cells — the common case must not pay for this rule.
        let binding_nothing = block_with_transactions(BlockHeight::new(3), vec![tx(1)]);
        assert!(admit(&plain(), &binding_nothing).is_ok());
    }

    /// A block carrying records, rooted the way the header claims.
    fn block_with_verdicts(verdicts: Vec<AbandonmentRecord>, root: AbandonmentRoot) -> Block {
        let base = header_at_height(BlockHeight::new(6), 100_000);
        Block::Live {
            header: BlockHeader::new(BlockHeaderParts {
                height: base.height(),
                parent_block_hash: base.parent_block_hash(),
                parent_qc: base.parent_qc().clone().into(),
                proposer: base.proposer(),
                timestamp: base.timestamp(),
                round: base.round(),
                provision_tx_roots: std::collections::BTreeMap::new(),
                abandonment_root: root,
                ..Default::default()
            }),
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(verdicts),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        }
    }

    /// A block carrying `bundles` under a header claiming `root`.
    fn block_with_state_claims(bundles: Vec<StateClaim>, root: StateClaimsRoot) -> Block {
        let base = header_at_height(BlockHeight::new(6), 100_000);
        Block::Live {
            header: BlockHeader::new(BlockHeaderParts {
                height: base.height(),
                parent_block_hash: base.parent_block_hash(),
                parent_qc: base.parent_qc().clone().into(),
                proposer: base.proposer(),
                timestamp: base.timestamp(),
                round: base.round(),
                provision_tx_roots: std::collections::BTreeMap::new(),
                state_claims_root: root,
                ..Default::default()
            }),
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(bundles),
            witness_sources: Arc::new(WitnessSources::empty()),
        }
    }

    /// A claim against `ROOT` at `height`, answering for `keys`.
    fn bundle_at(height: u64, keys: &[u8]) -> StateClaim {
        StateClaim::new(
            Anchor {
                shard: ShardId::ROOT,
                height: BlockHeight::new(height),
                state_root: StateRoot::from_raw(Hash::from_bytes(b"root")),
                ts: WeightedTimestamp::from_millis(height * 1_000),
            },
            keys.iter().map(|seed| {
                let key = SubstateKey {
                    owner: Address::new([*seed; 31], AddressClass::Component),
                    local: LocalKey([*seed; 16]),
                };
                (key, Inclusion::Absent)
            }),
        )
    }

    /// The section is bound to the header's root and held to one form:
    /// ascending without repeats, every bundle naming something. A
    /// second form of the same answers, or a root that does not commit
    /// them, is refused before any proof is walked.
    #[test]
    fn a_state_proof_section_is_held_to_its_root_and_form() {
        let held = |bundles: Vec<StateClaim>, root: StateClaimsRoot| {
            let block = block_with_state_claims(bundles, root);
            validate_roots_commit_sections(&block).and_then(|()| admit(&plain(), &block))
        };
        let bundles = vec![bundle_at(3, &[1]), bundle_at(4, &[2, 3])];
        let root = StateClaimsRoot::over(&bundles);
        assert!(held(bundles.clone(), root).is_ok());

        let err = held(bundles.clone(), StateClaimsRoot::ZERO)
            .expect_err("a root that does not commit the bundles is refused");
        assert!(err.contains("does not commit"), "{err}");

        let reversed: Vec<StateClaim> = bundles.iter().rev().cloned().collect();
        let err = held(reversed.clone(), StateClaimsRoot::over(&reversed))
            .expect_err("out of order is a second form of the same section");
        assert!(err.contains("repeats or precedes"), "{err}");

        let repeated = vec![bundle_at(3, &[1]), bundle_at(3, &[1])];
        let err = held(repeated.clone(), StateClaimsRoot::over(&repeated))
            .expect_err("a repeated bundle is refused");
        assert!(err.contains("repeats or precedes"), "{err}");

        let empty = vec![StateClaim {
            cells: Vec::new(),
            ..bundle_at(3, &[1])
        }];
        let err = held(empty.clone(), StateClaimsRoot::over(&empty))
            .expect_err("a bundle naming no key is refused");
        assert!(err.contains("empty"), "{err}");
    }

    /// The figures of a name reaching one route under each departed
    /// half, so a record against either half may name it.
    fn named(tx_hash: TxHash) -> UnsettledTx {
        let route = |tag: u8| RoutePrefix::of(Address::new([tag; 31], AddressClass::Principal));
        UnsettledTx {
            tx_hash,
            deadline: Deadline::of(WeightedTimestamp::from_millis(900)),
            declared_work: 11,
            charge: stub_abort_charge(11),
            reach: vec![route(0x00), route(0xC0)],
        }
    }

    fn verdict(shard: ShardId, seeds: &[u8]) -> AbandonmentRecord {
        AbandonmentRecord::new(
            shard,
            WeightedTimestamp::from_millis(DEPARTURE_CUT_MS),
            seeds
                .iter()
                .map(|&seed| named(TxHash::from(Hash::from_bytes(&[seed; 32])))),
        )
    }

    /// A block's records held to the header's root and to admission,
    /// under a schedule attesting every departure the fixtures name.
    fn held_records(block: &Block) -> Result<(), String> {
        validate_roots_commit_sections(block).and_then(|()| admit(&after_departures(), block))
    }

    /// The header commits the records, so a block whose root does not
    /// cover what it carries is refused before anyone asks whether the
    /// records are true.
    #[test]
    fn a_block_whose_root_does_not_commit_its_records_is_refused() {
        let records = vec![verdict(ShardId::ROOT.children().0, &[1, 2])];
        let honest = AbandonmentRoot::over(&records);
        assert!(held_records(&block_with_verdicts(records.clone(), honest)).is_ok());

        let err = held_records(&block_with_verdicts(records, AbandonmentRoot::ZERO)).unwrap_err();
        assert!(err.contains("does not commit"), "{err}");
    }

    /// One claim has one encoding. A record out of its canonical order is
    /// a second form of the same claim and is refused, so two proposers
    /// naming the same transactions cannot build differing blocks.
    #[test]
    fn a_record_out_of_its_canonical_form_is_refused() {
        let malformed =
            AbandonmentRecord::new(ShardId::ROOT, WeightedTimestamp::from_millis(1_000), []);
        let root = AbandonmentRoot::over(std::slice::from_ref(&malformed));
        let err = held_records(&block_with_verdicts(vec![malformed], root)).unwrap_err();
        assert!(
            err.contains("empty, over its cap, or out of order"),
            "{err}"
        );
    }

    /// Ascending by shard, which is what gives uniqueness and one encoding
    /// per claim set at once: two records for one shard would leave which
    /// answer counts to the reader, and a reordering would be a second
    /// form of the same block.
    #[test]
    fn records_out_of_shard_order_or_repeating_a_shard_are_refused() {
        let (left, right) = ShardId::ROOT.children();
        assert!(left < right, "the fixture relies on the child ordering");

        let ordered = vec![verdict(left, &[1]), verdict(right, &[2])];
        let root = AbandonmentRoot::over(&ordered);
        assert!(held_records(&block_with_verdicts(ordered, root)).is_ok());

        for records in [
            vec![verdict(right, &[2]), verdict(left, &[1])],
            vec![verdict(left, &[1]), verdict(left, &[2])],
        ] {
            let root = AbandonmentRoot::over(&records);
            let err = held_records(&block_with_verdicts(records, root)).unwrap_err();
            assert!(err.contains("repeats or precedes"), "{err}");
        }
    }

    /// The budget is one across every record a block carries, and it is
    /// spent in bytes: a name costs its reach as well as itself, so a
    /// section well under the drain's count can still be several frames
    /// wide.
    ///
    /// The sum is what makes it a bound. Each record here is well inside
    /// its own decode cap, so without the running total a block could
    /// spend the whole budget once per record.
    #[test]
    fn records_weighing_more_than_the_frame_affords_are_refused() {
        let (left, right) = ShardId::ROOT.children();
        // A name at an ordinary route's reach, spread under both
        // departed halves so either record may name it, and enough of
        // them between two records to clear the byte budget while
        // staying well under the drain's count.
        let wide = |seed: usize| UnsettledTx {
            reach: (0..6u8)
                .map(|at| RoutePrefix::from(Address::new([at * 0x30; 31], AddressClass::Component)))
                .collect(),
            ..named(TxHash::from(Hash::from_bytes(&seed.to_le_bytes())))
        };
        let per_record = MAX_PROPOSAL_EVIDENCE_BYTES / wide(0).wire_weight() / 2 + 1;
        let span = |shard: ShardId, from: usize| {
            AbandonmentRecord::new(
                shard,
                WeightedTimestamp::from_millis(DEPARTURE_CUT_MS),
                (from..from + per_record).map(wide),
            )
        };
        let records = vec![span(left, 0), span(right, per_record)];
        let named: usize = records.iter().map(|r| r.unsettled().len()).sum();
        assert!(
            named < MAX_UNSETTLED_PER_BLOCK,
            "the count admits this section, so only the weight can refuse it",
        );

        let root = AbandonmentRoot::over(&records);
        let err = held_records(&block_with_verdicts(records, root)).unwrap_err();
        assert!(err.contains("over the section's budget"), "{err}");
    }

    /// The running work total is a validity condition, not a hint: a header
    /// claiming more than its parent's total plus its own certificates'
    /// work is rejected, and the honest claim passes. A block with no
    /// certificates consumes nothing, so it must repeat its parent's total
    /// rather than reset.
    #[test]
    fn a_header_cannot_overstate_the_work_of_its_shard() {
        let parent = ShardLoad::ZERO.advance(500, None);
        // The fixture carries no certificates, so the honest claim is the
        // parent's total unchanged.
        let honest = block_with_transactions(BlockHeight::new(1), Vec::new());
        assert_eq!(honest.attested_work(), 0);
        assert_eq!(honest.header().load().cumulative_work, 0);

        // Claiming zero against a parent that has consumed 500 understates,
        // and is refused just as an overstatement is.
        let err = validate_block_work(&honest, Some(parent)).unwrap_err();
        assert!(err.contains("cumulative work"), "{err}");

        // The matching claim passes.
        assert!(validate_block_work(&honest, Some(ShardLoad::ZERO)).is_ok());

        // An unresolvable parent load abstains rather than rejecting.
        assert!(validate_block_work(&honest, None).is_ok());
    }

    fn tx(seed: u8) -> Arc<Verifiable<Transaction>> {
        Arc::new(Verifiable::from(test_utils::test_transaction(seed)))
    }

    fn sorted_txs(seeds: &[u8]) -> Vec<Arc<Verifiable<Transaction>>> {
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
        assert!(admit(&plain(), &block).is_ok());
    }

    #[test]
    fn validate_no_duplicate_transactions_accepts_unique() {
        let block = block_with_transactions(BlockHeight::new(5), sorted_txs(&[10, 20]));
        assert!(admit(&plain(), &block).is_ok());
    }

    #[test]
    fn validate_no_duplicate_transactions_rejects_qc_chain_dup() {
        let txs = sorted_txs(&[10, 20]);
        let dup_hash = txs[0].hash();
        let block = block_with_transactions(BlockHeight::new(6), txs);
        let mut against = plain();
        against.chain.txs.insert(dup_hash);
        let err = admit(&against, &block).unwrap_err();
        assert!(err.contains("already in QC chain ancestor"));
    }

    #[test]
    fn validate_no_duplicate_transactions_rejects_retention_dup() {
        let txs = sorted_txs(&[10, 20]);
        let dup_tx = Arc::clone(&txs[0]);
        let block = block_with_transactions(BlockHeight::new(6), txs);
        let mut against = plain();
        against.dedup.register_committed_txs(&[dup_tx]);
        let err = admit(&against, &block).unwrap_err();
        assert!(err.contains("already committed"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // validate_no_duplicate_certificates
    // ═══════════════════════════════════════════════════════════════════════

    fn block_with_certificates(height: BlockHeight, certificates: Vec<Arc<Finalization>>) -> Block {
        let wrapped: Vec<Arc<Verifiable<Finalization>>> = certificates
            .into_iter()
            .map(|fw| Arc::new((*fw).clone().into()))
            .collect();
        Block::Live {
            header: header_at_height(height, 100_000),
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(wrapped),
            provisions: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
        }
    }

    fn finalization_at(height: u64) -> Arc<Finalization> {
        Arc::new(make_finalization(
            BlockHeight::new(height),
            TxHash::from(Hash::from_bytes(
                &[u8::try_from(height).unwrap_or(u8::MAX); 32],
            )),
            TransactionDecision::Accept,
        ))
    }

    /// A finalization over `tx_hash`, on a tick distinct from any other
    /// built at the same height — the shape a second verdict takes.
    fn finalization_over(height: u64, tx_hash: TxHash) -> Arc<Finalization> {
        Arc::new(make_finalization(
            BlockHeight::new(height),
            tx_hash,
            TransactionDecision::Aborted,
        ))
    }

    fn no_resolutions(block: &Block, dedup_index: CommitDedupIndex) -> Result<(), String> {
        let mut against = after_departures();
        against.dedup = dedup_index;
        admit(&against, block)
    }

    #[test]
    fn validate_no_duplicate_resolutions_accepts_empty_block() {
        let block = block_with_certificates(BlockHeight::new(5), vec![]);
        assert!(no_resolutions(&block, CommitDedupIndex::new()).is_ok());
    }

    #[test]
    fn validate_no_duplicate_resolutions_accepts_unique() {
        let block = block_with_certificates(BlockHeight::new(5), vec![finalization_at(1)]);
        assert!(no_resolutions(&block, CommitDedupIndex::new()).is_ok());
    }

    /// The same certificate again is refused on its identity, which is
    /// the rule that answers whether or not its members reach a verdict.
    /// The transaction rule below covers the other shape — a *different*
    /// certificate reaching a second verdict for one name.
    #[test]
    fn validate_no_duplicate_resolutions_rejects_retention_dup() {
        let fw = finalization_at(1);
        let block = block_with_certificates(BlockHeight::new(6), vec![Arc::clone(&fw)]);
        let mut dedup_index = CommitDedupIndex::new();
        dedup_index.register_committed_certs(&[Arc::new((*fw).clone().into())]);
        let err = no_resolutions(&block, dedup_index).unwrap_err();
        assert!(
            err.contains("was already committed within its retention window"),
            "{err}"
        );
    }

    /// A certificate whose members reach no verdict is held to the chain
    /// exactly like one that does. Nothing about its names can refuse it
    /// — it resolves none — so identity is the only thing that can.
    #[test]
    fn a_committed_certificate_deciding_nothing_cannot_ride_a_second_block() {
        let fw = Arc::new(make_undecided_finalization(
            BlockHeight::new(1),
            TxHash::from(Hash::from_bytes(b"retired")),
            TransactionDecision::Accept,
        ));
        assert_eq!(fw.deciding_tx_hashes().count(), 0);
        let block = block_with_certificates(BlockHeight::new(6), vec![Arc::clone(&fw)]);
        let mut dedup_index = CommitDedupIndex::new();
        dedup_index.register_committed_certs(&[Arc::new((*fw).clone().into())]);
        let err = no_resolutions(&block, dedup_index).unwrap_err();
        assert!(
            err.contains("was already committed within its retention window"),
            "{err}"
        );
    }

    /// A second verdict for one transaction is refused however it is
    /// dressed. The tick differs, so nothing about the certificate's
    /// identity gives it away — settlement and abandonment are exclusive
    /// because the rule asks about the transaction.
    #[test]
    fn a_transaction_a_committed_block_resolved_cannot_be_resolved_again() {
        let settled = finalization_at(1);
        let tx_hash = settled
            .tx_hashes()
            .next()
            .expect("a tick names its members");
        let mut dedup_index = CommitDedupIndex::new();
        dedup_index.register_committed_certs(&[Arc::new((*settled).clone().into())]);

        let abandoned = finalization_over(9, tx_hash);
        assert_ne!(abandoned.tick_id(), settled.tick_id());
        let block = block_with_certificates(BlockHeight::new(6), vec![abandoned]);

        let err = no_resolutions(&block, dedup_index).unwrap_err();
        assert!(
            err.contains("already resolved within its retention window"),
            "{err}"
        );
    }

    /// A boundary record is a request for a verdict, so it is held to the
    /// same rule. It reaches replicas that hold no account of the
    /// transaction and rebuild one from it, which is exactly the replica
    /// that cannot tell the name is stale — so the block carrying it is
    /// where the staleness has to be caught.
    #[test]
    fn a_record_naming_a_resolved_transaction_is_refused() {
        let settled = finalization_at(1);
        let tx_hash = settled
            .tx_hashes()
            .next()
            .expect("a tick names its members");
        let mut dedup_index = CommitDedupIndex::new();
        dedup_index.register_committed_certs(&[Arc::new((*settled).clone().into())]);

        let block = block_with_verdicts(
            vec![AbandonmentRecord::new(
                ShardId::ROOT.children().0,
                WeightedTimestamp::from_millis(DEPARTURE_CUT_MS),
                [named(tx_hash)],
            )],
            AbandonmentRoot::ZERO,
        );
        let err = no_resolutions(&block, dedup_index).unwrap_err();
        assert!(
            err.contains("already resolved within its retention window"),
            "{err}"
        );
    }

    /// And a record naming what the same block resolves, which no window
    /// or index has seen yet.
    #[test]
    fn a_record_naming_what_its_own_block_resolves_is_refused() {
        let settled = finalization_at(1);
        let tx_hash = settled
            .tx_hashes()
            .next()
            .expect("a tick names its members");
        let block = Block::Live {
            header: header_at_height(BlockHeight::new(6), 100_000),
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(vec![Arc::new((*settled).clone().into())]),
            provisions: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(vec![AbandonmentRecord::new(
                ShardId::ROOT.children().0,
                WeightedTimestamp::from_millis(DEPARTURE_CUT_MS),
                [named(tx_hash)],
            )]),
        };
        let err = no_resolutions(&block, CommitDedupIndex::new()).unwrap_err();
        assert!(err.contains("which the same block resolves"), "{err}");
    }

    /// The same, one block earlier: an ancestor above committed height
    /// has resolved it and nothing has committed yet.
    #[test]
    fn a_transaction_an_ancestor_resolved_cannot_be_resolved_again() {
        let settled = finalization_at(1);
        let tx_hash = settled
            .tx_hashes()
            .next()
            .expect("a tick names its members");
        let block =
            block_with_certificates(BlockHeight::new(6), vec![finalization_over(9, tx_hash)]);
        let mut against = plain();
        against.chain.resolved.insert(tx_hash);
        let err = admit(&against, &block).unwrap_err();
        assert!(
            err.contains("already resolved by a QC chain ancestor"),
            "{err}"
        );
    }

    /// And within one block, where neither the ancestor walk nor the
    /// retention window can see it.
    #[test]
    fn a_transaction_cannot_be_resolved_twice_within_one_block() {
        let settled = finalization_at(1);
        let tx_hash = settled
            .tx_hashes()
            .next()
            .expect("a tick names its members");
        let block = block_with_certificates(
            BlockHeight::new(6),
            vec![settled, finalization_over(9, tx_hash)],
        );
        let err = no_resolutions(&block, CommitDedupIndex::new()).unwrap_err();
        assert!(
            err.contains("resolved twice within the same block"),
            "{err}"
        );
    }

    /// A block settling `determined` (as determined halves) and `legs`
    /// (as legs halves).
    fn block_settling(determined: &[u64], legs: &[u64]) -> Block {
        use hyperscale_types::{
            AggregateSignature, ExecutionCertificate, GlobalReceiptRoot, SignerBitfield, TickHalf,
            TickId,
        };
        let half = |height: u64, half: TickHalf| {
            let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(height));
            let ec = ExecutionCertificate::new(
                tick_id,
                WeightedTimestamp::from_millis(height),
                GlobalReceiptRoot::ZERO,
                Vec::new(),
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            );
            Arc::new(Verifiable::from(Finalization::new(
                tick_id,
                half,
                vec![Arc::new(ec)],
                Vec::new(),
            )))
        };
        let certificates: Vec<_> = determined
            .iter()
            .map(|h| half(*h, TickHalf::Determined))
            .chain(legs.iter().map(|h| half(*h, TickHalf::Legs)))
            .collect();
        Block::Live {
            header: header_at_height(BlockHeight::new(100), 100_000),
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(certificates),
            provisions: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
        }
    }

    /// Admission above a parent whose settlement frontier is `frontier`.
    fn above_frontier(frontier: u64) -> Against {
        let mut against = plain();
        against.parent_settled_frontier = Some(BlockHeight::new(frontier));
        against
    }

    /// The reproduced corruption, refused. Two ticks over one cell
    /// settled in reverse across two blocks lose the later write; the
    /// second block is the one carrying the lower tick, and its
    /// determined half sits at or below the frontier its parent already
    /// reached.
    #[test]
    fn a_determined_half_below_the_parent_frontier_is_refused() {
        // The parent settled tick 2. This block offers tick 1.
        let err = admit(&above_frontier(2), &block_settling(&[1], &[])).unwrap_err();
        assert!(err.contains("at or below the frontier"), "{err}");
    }

    /// Determined halves within one block must rise, or the receipts
    /// apply in the order the block lists them and invert inside it.
    #[test]
    fn determined_halves_must_rise_within_a_block() {
        let err = admit(&above_frontier(3), &block_settling(&[6, 4], &[])).unwrap_err();
        assert!(err.contains("at or below the frontier"), "{err}");
        assert!(admit(&above_frontier(3), &block_settling(&[4, 6], &[])).is_ok());
    }

    /// Admission above `frontier` with the chain owing determined
    /// halves for `owed`.
    fn owing(frontier: u64, owed: &[u64]) -> Against {
        let mut against = above_frontier(frontier);
        against.owed_determined = owed.iter().map(|h| BlockHeight::new(*h)).collect();
        against
    }

    /// The half that skips an owed one is the half refused, not the owed
    /// one when it finally arrives.
    ///
    /// Carrying tick 6 while tick 4 still owes its half would put the
    /// frontier past 4, and 4's certificate — late because its tick
    /// leader's aggregation rotated — is then refused for good, leaving
    /// its members committed and never finalized.
    #[test]
    fn a_determined_half_may_not_settle_past_a_tick_still_owing_one() {
        let err = admit(&owing(3, &[4]), &block_settling(&[6], &[])).unwrap_err();
        assert!(err.contains("still owes"), "{err}");
    }

    /// The block that carries both carries them in order, and the owed
    /// tick is owed no longer once its own half is admitted ahead of the
    /// later one.
    #[test]
    fn a_block_carrying_the_owed_half_first_carries_the_later_one_too() {
        assert!(admit(&owing(3, &[4]), &block_settling(&[4, 6], &[])).is_ok());
    }

    /// The rule measures the gap and nothing else: a tick owed at or
    /// below the frontier is already settled or already refused, and one
    /// above the half being admitted has not been skipped.
    #[test]
    fn only_a_tick_between_the_frontier_and_the_half_is_a_skip() {
        assert!(admit(&owing(4, &[4]), &block_settling(&[6], &[])).is_ok());
        assert!(admit(&owing(3, &[9]), &block_settling(&[6], &[])).is_ok());
    }

    /// A validator that never composed the earlier tick owes nothing for
    /// it and enforces nothing — it offers and accepts the later half in
    /// good faith, and the composing quorum is what refuses the block.
    #[test]
    fn a_validator_holding_no_owed_tick_judges_only_the_frontier() {
        assert!(admit(&owing(3, &[]), &block_settling(&[6], &[])).is_ok());
    }

    /// A legs half is unconstrained. It waits on a counterpart and may
    /// land arbitrarily late; its declared cells are claimed against
    /// every later tick from the moment it executes, so it has nothing
    /// to invert against — and holding it to the frontier would wedge a
    /// tick composed entirely of legs, which never advances one.
    #[test]
    fn a_legs_half_settles_whatever_the_frontier_says() {
        assert!(admit(&above_frontier(7), &block_settling(&[], &[1])).is_ok());
        assert!(admit(&above_frontier(7), &block_settling(&[8], &[1])).is_ok());
    }

    /// A certificate anchored before the chain's origin names a tick on
    /// a predecessor and is refused outright.
    #[test]
    fn a_certificate_anchored_before_the_origin_is_refused() {
        let mut against = above_frontier(0);
        against.chain_origin = WeightedTimestamp::from_millis(5);
        let err = admit(&against, &block_settling(&[4], &[])).unwrap_err();
        assert!(err.contains("predates this chain's origin"), "{err}");
        assert!(admit(&against, &block_settling(&[6], &[])).is_ok());
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
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(wrapped),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
        }
    }

    fn provisions_with_seed(seed: u8) -> Arc<Provisions> {
        let tx_hash = TxHash::from(Hash::from_bytes(&[seed; 32]));
        Arc::new(Provisions::new(
            ShardId::leaf(1, 0),
            ShardId::leaf(1, 1),
            BlockHeight::new(u64::from(seed)),
            WeightedTimestamp::ZERO,
            MerkleInclusionProof::dummy(),
            vec![ProvisionEntry::new(tx_hash, vec![])],
        ))
    }

    #[test]
    fn validate_no_duplicate_provisions_accepts_empty_block() {
        let block = block_with_provisions(BlockHeight::new(5), vec![]);
        assert!(admit(&plain(), &block).is_ok());
    }

    #[test]
    fn validate_no_duplicate_provisions_accepts_unique() {
        let block = block_with_provisions(BlockHeight::new(5), vec![provisions_with_seed(1)]);
        assert!(admit(&plain(), &block).is_ok());
    }

    #[test]
    fn validate_no_duplicate_provisions_rejects_qc_chain_dup() {
        let p = provisions_with_seed(1);
        let dup_hash = p.hash();
        let block = block_with_provisions(BlockHeight::new(6), vec![p]);
        let mut against = plain();
        against.chain.provisions.insert(dup_hash);
        let err = admit(&against, &block).unwrap_err();
        assert!(err.contains("already in QC chain ancestor"));
    }

    #[test]
    fn validate_no_duplicate_provisions_rejects_retention_dup() {
        let p = provisions_with_seed(1);
        let block = block_with_provisions(BlockHeight::new(6), vec![Arc::clone(&p)]);
        let mut against = plain();
        against
            .dedup
            .register_committed_provisions(&[p.hash()], WeightedTimestamp::from_millis(1_000));
        let err = admit(&against, &block).unwrap_err();
        assert!(err.contains("already committed"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // validate_provisions_not_fenced
    // ═══════════════════════════════════════════════════════════════════════

    /// A snapshot whose `shard` is under a pending recovery fenced at
    /// `frontier` — the governing snapshot of a block validated after the
    /// recovery folded.
    fn snapshot_recovering(shard: ShardId, frontier: BlockHeight) -> TopologySnapshot {
        use hyperscale_types::{Epoch, NetworkDefinition, RecoveryCause, ShardRecovery};
        TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(Vec::new()),
        )
        .with_pending_recoveries(
            std::iter::once((
                shard,
                ShardRecovery {
                    cause: RecoveryCause::Halt,
                    rotated_at: Epoch::new(2),
                    retained: Vec::new(),
                    attested_frontier: frontier,
                },
            ))
            .collect(),
        )
    }

    #[test]
    fn validate_provisions_not_fenced_rejects_above_frontier() {
        // provisions_with_seed(9) sources from ShardId::leaf(1, 0) at
        // height 9 — above a frontier of 5 the batch is fenced content.
        let block = block_with_provisions(BlockHeight::new(6), vec![provisions_with_seed(9)]);
        let snapshot = snapshot_recovering(ShardId::leaf(1, 0), BlockHeight::new(5));
        let err = admit(&Against::window(snapshot), &block).unwrap_err();
        assert!(err.contains("recovering shard"));
    }

    #[test]
    fn validate_provisions_not_fenced_accepts_frontier_and_below() {
        // At the frontier the batch is legitimate pre-failure history.
        let block = block_with_provisions(BlockHeight::new(6), vec![provisions_with_seed(5)]);
        let snapshot = snapshot_recovering(ShardId::leaf(1, 0), BlockHeight::new(5));
        assert!(admit(&Against::window(snapshot), &block).is_ok());
    }

    #[test]
    fn validate_provisions_not_fenced_ignores_other_shards_and_clean_snapshots() {
        let block = block_with_provisions(BlockHeight::new(6), vec![provisions_with_seed(9)]);
        // Recovery pending for a different shard.
        let other = snapshot_recovering(ShardId::leaf(1, 1), BlockHeight::new(5));
        assert!(admit(&Against::window(other), &block).is_ok());
        // No recovery pending at all — a pre-fold governing snapshot.
        let clean = snapshot_recovering(ShardId::leaf(1, 1), BlockHeight::new(5));
        let mut recoveries = clean.pending_recoveries().clone();
        recoveries.clear();
        let clean = clean.with_pending_recoveries(recoveries);
        assert!(admit(&Against::window(clean), &block).is_ok());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // validate_transactions_verified / validate_block_for_vote verified-arm
    // ═══════════════════════════════════════════════════════════════════════

    fn verified_tx(seed: u8) -> Arc<Verifiable<Transaction>> {
        Arc::new(Verifiable::from(test_utils::verified_test_transaction(
            seed,
        )))
    }

    fn sorted_verified_txs(seeds: &[u8]) -> Vec<Arc<Verifiable<Transaction>>> {
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
            &Against::window(topo).ctx(),
            &block,
            false,
            Some(ShardLoad::ZERO),
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
            &Against::window(topo.clone()).ctx(),
            &with_tx,
            true,
            Some(ShardLoad::ZERO),
        )
        .unwrap_err();
        assert!(err.contains("coast block"), "{err}");

        // A boundary record is content too. A chain whose capacity to
        // resolve anything ended at its cut has nothing left to write
        // down, so the rule covers every body list rather than three of
        // four.
        let records = vec![verdict(ShardId::ROOT, &[1])];
        let with_record = block_with_verdicts(records.clone(), AbandonmentRoot::over(&records));
        let err = validate_block_for_vote(
            &Against::window(topo.clone()).ctx(),
            &with_record,
            true,
            Some(ShardLoad::ZERO),
        )
        .unwrap_err();
        assert!(err.contains("abandonment records"), "{err}");

        let empty = block_with_transactions(BlockHeight::new(1), Vec::new());
        assert!(
            validate_block_for_vote(
                &Against::window(topo).ctx(),
                &empty,
                true,
                Some(ShardLoad::ZERO)
            )
            .is_ok()
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // validate_engagement
    // ═══════════════════════════════════════════════════════════════════════

    /// A signed stub transaction whose derived owners are exactly
    /// `owners`, paying from `payer`, wrapped verified for block content.
    fn stub_tx(payer: PrincipalAddr, owners: &[Address]) -> Arc<Verifiable<Transaction>> {
        test_utils::install_stub_protocol_statics();
        let validity = TimestampRange::new(
            WeightedTimestamp::ZERO,
            WeightedTimestamp::from_millis(100_000),
        );
        Arc::new(Verifiable::from(Verified::new_unchecked_for_test(
            test_utils::stub_transaction(payer, owners, 1_000, validity),
        )))
    }

    /// Admission at `local` under `topo`, with nothing committed.
    fn engaged(topo: &TopologySnapshot, local: ShardId) -> Against {
        engaged_with(topo, local, CommitDedupIndex::new())
    }

    /// Admission at `local` under `topo`, with `dedup` committed.
    fn engaged_with(topo: &TopologySnapshot, local: ShardId, dedup: CommitDedupIndex) -> Against {
        let mut against = Against::window(topo.clone());
        against.local_shard = local;
        against.dedup = dedup;
        against
    }

    fn block_with_tx(
        tx: &Arc<Verifiable<Transaction>>,
        provisions: Vec<Arc<Verifiable<Provisions>>>,
    ) -> Block {
        Block::Live {
            header: header_at_height(BlockHeight::new(1), 100_000),
            transactions: Arc::new(vec![Arc::clone(tx)]),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(provisions),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
        }
    }

    #[test]
    fn engagement_demands_the_payer_bundle() {
        // Two-shard trie: a clear top bit routes to leaf(1, 0), a set one
        // to leaf(1, 1). The payer lives on the remote shard.
        let topo = TestCommittee::new(4, 42).topology_snapshot(2);
        let local = ShardId::leaf(1, 0);
        let local_owner = test_principal(0x01);
        let payer_owner = test_principal(0x81);
        let tx = stub_tx(payer_owner, &[local_owner.address(), payer_owner.address()]);
        let tx_hash = tx.hash();

        // No bundle anywhere: the counterpart must not engage.
        let bare = block_with_tx(&tx, Vec::new());
        let err = admit(&engaged(&topo, local), &bare).unwrap_err();
        assert!(err.contains("payer bundle"), "{err}");

        // The payer's empty-entry bundle in the same block: engaged.
        let bundle: Arc<Verifiable<Provisions>> = Arc::new(
            Verified::<Provisions>::new_unchecked_for_test(Provisions::new(
                ShardId::leaf(1, 1),
                local,
                BlockHeight::new(1),
                WeightedTimestamp::ZERO,
                MerkleInclusionProof::dummy(),
                vec![ProvisionEntry::new(tx_hash, vec![])],
            ))
            .into(),
        );
        let paired = block_with_tx(&tx, vec![Arc::clone(&bundle)]);
        assert!(admit(&engaged(&topo, local), &paired).is_ok());

        // A bundle committed within the retention window: engaged.
        let mut dedup = CommitDedupIndex::new();
        dedup.register_committed_provision_txs(
            std::slice::from_ref(&bundle),
            WeightedTimestamp::from_millis(1_000),
        );
        assert!(admit(&engaged_with(&topo, local, dedup), &bare).is_ok());

        // A bundle from the wrong source shard is not engagement evidence.
        let wrong_source: Arc<Verifiable<Provisions>> = Arc::new(
            Verified::<Provisions>::new_unchecked_for_test(Provisions::new(
                local,
                ShardId::leaf(1, 1),
                BlockHeight::new(1),
                WeightedTimestamp::ZERO,
                MerkleInclusionProof::dummy(),
                vec![ProvisionEntry::new(tx_hash, vec![])],
            ))
            .into(),
        );
        let mispaired = block_with_tx(&tx, vec![wrong_source]);
        let err = admit(&engaged(&topo, local), &mispaired).unwrap_err();
        assert!(err.contains("payer bundle"), "{err}");
    }

    #[test]
    fn engagement_exempts_the_payer_shard_and_single_shard_legs() {
        let topo = TestCommittee::new(4, 42).topology_snapshot(2);
        let local_owner = test_principal(0x01);
        let payer_owner = test_principal(0x81);

        // At the payer's own shard the reservation, not the bundle, is
        // the gate — no bundle demanded.
        let cross = stub_tx(payer_owner, &[local_owner.address(), payer_owner.address()]);
        let at_payer = block_with_tx(&cross, Vec::new());
        assert!(admit(&engaged(&topo, ShardId::leaf(1, 1)), &at_payer).is_ok());

        // A single-shard leg engages nothing remotely.
        let single = stub_tx(local_owner, &[local_owner.address()]);
        let local_only = block_with_tx(&single, Vec::new());
        assert!(admit(&engaged(&topo, ShardId::leaf(1, 0)), &local_only).is_ok());
    }
}
