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
//! Everything here is stateless — callers supply the [`Committed`]
//! context explicitly. The async verification pipeline lives in
//! [`crate::verification`]; this module is just the pure rules.
//!
//! Errors are returned as human-readable strings so the caller can log a
//! single diagnostic line at the rejection site.
use std::sync::Arc;

use hyperscale_types::{
    Block, BlockHeader, BlockHeight, DeclaredWork, LocalTimestamp, MAX_ROUND_GAP,
    MAX_TICK_STAGED_BYTES, MAX_TIMESTAMP_DELAY, MAX_TIMESTAMP_RUSH, QuorumCertificate, ShardId,
    ShardLoad, TickLine, TopologySnapshot, Transaction, Verifiable, VoteCount,
    tick_manifest_admits_block, tick_manifest_admits_members, tick_terms_admit_block,
};

use crate::admission::{
    Committed, FinalizationsFold, FinalizationsSection, ProvisionsFold, ProvisionsSection,
    RecordsFold, RecordsSection, StateClaimsFold, StateClaimsSection, TransactionsFold,
    TransactionsSection, admit_all, unwrapped,
};
use crate::tick_members::{run_by, states_entry};

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
/// irreversibly. An honestly-aggregated weighted timestamp is one honest
/// voter's clock reading from an earlier round, so it leads ours by at most the
/// honest skew envelope; anything beyond is rejected. Checked wherever an
/// untrusted QC enters chain state: header validation, synced-block admission,
/// and timeout-quorum `high_qc` adoption. A QC this node aggregates itself is
/// not one of them — the median over a quorum is an honest voter's own
/// reading, so no bound on it bounds an adversary.
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

    // A certificate proves the rounds between the parent QC and this block
    // were abandoned: it is for the round before this one, and the parent
    // QC meets every round its signers reported, so the proposer extends a
    // QC at least as high as any of them held. A block in the round right
    // after its parent QC skips nothing and carries none; one that skips
    // rounds must carry one. Its signature is checked before the vote,
    // against the committee signing the block.
    if round > parent_round.next() && header.timeout_cert().is_none() {
        return Err(format!(
            "round {} skips past parent QC round {} without a timeout certificate",
            round.inner(),
            parent_round.inner()
        ));
    }
    if let Some(tc) = header.timeout_cert() {
        if round <= parent_round.next() {
            return Err(format!(
                "round {} follows its parent QC directly yet carries a timeout certificate",
                round.inner()
            ));
        }
        if tc.shard_id() != header.shard_id() || tc.round().next() != round {
            return Err(format!(
                "timeout certificate for round {} does not precede round {}",
                tc.round().inner(),
                round.inner()
            ));
        }
        if tc.max_high_qc_round() > parent_round {
            return Err(format!(
                "parent QC round {} is below the timeout certificate's reported round {}",
                parent_round.inner(),
                tc.max_high_qc_round().inner()
            ));
        }
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
    } else if header.parent_qc().height().next() != height {
        // A genesis QC sits at its chain's origin height, directly below
        // the chain's first block. Above that, a block has a real parent
        // and must carry the QC certifying it; a genesis QC there would
        // skip the quorum and linkage checks and anchor the block's
        // validity window at the origin's weighted time.
        return Err(format!(
            "genesis QC at height {} cannot parent block height {}",
            header.parent_qc().height().inner(),
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

/// The header's running totals must be their parent's advanced by what
/// this block carries: the fee total by what its certificates charged,
/// the declared one by what its transactions reserve on this shard, and
/// the block count by one.
///
/// `used` is the transactions section's own fold, handed back rather
/// than summed a second time: what a header claims its blocks reserved
/// has to be the figure the block's caps admitted it against, and two
/// spellings of the sum could differ.
///
/// Pure over the block plus one load off the parent header, which is what
/// keeps a shard's figures honest without any storage read: a
/// proposer inflating its shard's emission weight has to inflate receipts
/// its committee already checked under the body root.
fn validate_block_work(
    block: &Block,
    parent_load: Option<ShardLoad>,
    used: DeclaredWork,
) -> Result<(), String> {
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
    let expected = parent_load.advance(block.charged(), used, None);
    let claimed = block.header().load();
    if claimed.cumulative_fees != expected.cumulative_fees {
        return Err(format!(
            "header claims cumulative fees {} but the parent's {} \
             plus this block's {} is {}",
            claimed.cumulative_fees,
            parent_load.cumulative_fees,
            block.charged(),
            expected.cumulative_fees,
        ));
    }
    if claimed.used != expected.used {
        return Err(format!(
            "header claims the chain has reserved {:?} but the parent's \
             {:?} plus this block's {used:?} is {:?}",
            claimed.used, parent_load.used, expected.used,
        ));
    }
    // The count is the denominator `used` is read against: the beacon
    // differences two of these records to reach the capacity those
    // blocks had, and both the price controller and the fullness mean
    // divide by it. Left unchecked, a proposer freezing its own counter
    // reads as saturated forever and one inflating it drags the
    // network-wide ratio toward zero.
    if claimed.blocks != expected.blocks {
        return Err(format!(
            "header claims the chain has committed {} blocks but the \
             parent's {} plus this one is {}",
            claimed.blocks, parent_load.blocks, expected.blocks,
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
/// names, state claims, crossing re-offers. Returns a single diagnostic
/// on the first failure so the caller can log once.
pub fn validate_block_for_vote(
    ctx: &Committed<'_>,
    block: &Block,
    parent_load: Option<ShardLoad>,
) -> Result<(), String> {
    validate_transactions_verified(block)?;
    validate_transaction_ordering(block)?;
    validate_tick_manifest_budget(block)?;
    validate_terms_section(block)?;
    // The sections first, because the load check reads what the
    // transactions section folded rather than summing it again.
    let budget = admit_sections(ctx, block)?;
    validate_block_work(block, parent_load, budget)
}

/// A coast block's pre-vote check: empty, which leaves nothing for any
/// section to admit, and otherwise held to the checks every block is.
///
/// Needs no committed view, because an empty block reads none: a coast
/// or recovery bridge block anchored in a window this node has evicted
/// is judged all the same.
pub fn validate_coast_block_for_vote(
    block: &Block,
    parent_load: Option<ShardLoad>,
) -> Result<(), String> {
    validate_coast_block_empty(block)?;
    validate_transactions_verified(block)?;
    validate_transaction_ordering(block)?;
    validate_tick_manifest_budget(block)?;
    validate_block_work(block, parent_load, DeclaredWork::ZERO)
}

/// Every section's items through its [`Section`](crate::admission::Section)
/// predicate, in the order the folds depend on.
///
/// Returns what the block's transactions reserve on this shard, which
/// the header's own claim is checked against.
pub fn admit_sections(ctx: &Committed<'_>, block: &Block) -> Result<DeclaredWork, String> {
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
    Ok(transactions.budget)
}

/// The tick manifest fits its byte budget, names no more members than a
/// tick's manifest may, and its member lines carry no more than
/// [`MAX_TICK_STAGED_BYTES`] staged between them.
pub fn validate_tick_manifest_budget(block: &Block) -> Result<(), String> {
    let weight: usize = block
        .tick_manifest()
        .iter()
        .map(TickLine::wire_weight)
        .sum();
    if !tick_manifest_admits_block(weight) {
        return Err(format!(
            "tick manifest weighs {weight} bytes, over its budget"
        ));
    }
    let members = block
        .tick_manifest()
        .iter()
        .filter(|line| matches!(line, TickLine::Member { .. }))
        .count();
    if !tick_manifest_admits_members(members) {
        return Err(format!(
            "tick manifest names {members} members, over its cap"
        ));
    }
    let staged = block
        .tick_manifest()
        .iter()
        .filter_map(|line| match line {
            TickLine::Member { staged, .. } => Some(*staged),
            TickLine::Fate { .. } | TickLine::Discard { .. } | TickLine::End { .. } => None,
        })
        .fold(0u64, u64::saturating_add);
    if staged > MAX_TICK_STAGED_BYTES {
        return Err(format!("tick manifest stages {staged} bytes, over its cap"));
    }
    Ok(())
}

/// The terms section is one a block may carry: its entries weigh within
/// the section's byte budget between them, every transaction of the
/// block is named by an entry or a member line that runs it, and one a
/// line runs is named by an entry as well only where that entry's
/// crossings are not empty, the entries in the block's transaction
/// order.
///
/// Read against transactions already held to strictly ascending hash
/// order, so one walk of the two lists holds the entries to that order
/// too: an entry out of place, repeated, or naming no transaction of the
/// block is left unmatched.
fn validate_terms_section(block: &Block) -> Result<(), String> {
    let weight: usize = block
        .terms()
        .iter()
        .map(|entry| entry.terms.wire_weight())
        .sum();
    if !tick_terms_admit_block(weight) {
        return Err(format!(
            "terms section weighs {weight} bytes, over its budget"
        ));
    }
    let run = run_by(block.tick_manifest());
    let mut stated = block.terms().iter().peekable();
    for tx in block.transactions().iter() {
        let tx = tx.hash();
        let runs = run.contains(&tx);
        match (stated.next_if(|entry| entry.tx == tx), runs) {
            (Some(_), false) | (None, true) => {}
            (Some(entry), true) => {
                if !states_entry(true, &entry.terms) {
                    return Err(format!(
                        "terms section states {tx}, which a line of the block runs and whose terms carry no crossing"
                    ));
                }
            }
            (None, false) => {
                return Err(format!(
                    "transaction {tx} has neither its terms stated nor a line running it"
                ));
            }
        }
    }
    if let Some(stray) = stated.next() {
        return Err(format!(
            "terms section states {}, which no transaction of the block matches in order",
            stray.tx
        ));
    }
    Ok(())
}

/// A coast block — one whose parent QC's weighted timestamp lands past
/// the shard's terminal window — exists only to certify the crossing. It
/// must carry no content of any kind, so state stays frozen at the
/// crossing's root: no transactions, no certificates, no provisions, and
/// no boundary records or stated terms, which a chain whose own capacity
/// to resolve anything ended at its cut has nothing left to write down.
/// Of tick lines it carries fates and ends and no other.
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
    if !block.terms().is_empty() {
        return Err(format!(
            "coast block past the terminal window carries {} terms entries",
            block.terms().len()
        ));
    }
    // A coast block carries fates and ends and no other line. Which
    // coast block may carry any, and exactly which, is judged over the
    // chain up to its parent.
    if let Some(line) = block.tick_manifest().iter().find(|line| match line {
        TickLine::Fate { .. } | TickLine::End { .. } => false,
        TickLine::Member { .. } | TickLine::Discard { .. } => true,
    }) {
        return Err(format!(
            "coast block past the terminal window carries tick lines other than fates and ends: {line:?}"
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
pub mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
    use std::time::Duration;

    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};
    use hyperscale_engine::tick_select::{
        CommittedSets, awaited_core, member_lines, member_of, staged_past_cap,
    };
    use hyperscale_hbor::{Capped, from_slice, to_vec};
    use hyperscale_storage::test_helpers::{
        commit_settled_at, make_state_writes, state_key, yes_receipt,
    };
    use hyperscale_storage::{
        MemberIndex, MemberInputs, MemberRow, MemberSections, RowState, Substates, TickRow, Waiting,
    };
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::test_utils::{
        TestCommittee, make_finalization, make_finalization_on, make_leg_finalization_on, rebound,
        stating, stub_abort_charge, stub_stated_terms, test_principal,
    };
    use hyperscale_types::{
        AbandonmentRecord, AbandonmentRoot, Address, AddressClass, AggregateSignature,
        BeaconWitnessCommit, BeaconWitnessLeafCount, BlockHash, BlockHeader, BlockHeaderParts,
        BodyRootContext, ChainOrigin, CommittedAt, ConsensusReceipt, Deadline, Derivation,
        DerivationError, Derived, DiscardCause, Engagement, EngagementRoot, Epoch, Evidence,
        ExecutionOutcome, Finalization, GlobalReceiptHash, Hash, Inclusion, Joins, LeafRoot,
        LegRole, LocalKey, MAX_CLAIMS_BYTES, MAX_FINALIZED_TX_PER_BLOCK, MAX_INTENTS,
        MAX_NAMED_MEMBERS_PER_TICK, MAX_PROPOSAL_EVIDENCE_BYTES, MAX_STAGED_RECEIPT_BYTES,
        MAX_STANDING_TOWARD_SHARD, MAX_STATE_CLAIMS_BYTES, MAX_STATE_CLAIMS_PER_BLOCK,
        MAX_SWEEPABLE_CREATED_PER_BLOCK, MAX_TICK_LINES_PER_BLOCK, MAX_TICK_TERMS_BYTES,
        MAX_TXS_PER_BLOCK, MAX_UNSETTLED_PER_BLOCK, MAX_VERDICT_CLAIMS_BYTES, MemberTerms,
        MerkleInclusionProof, NetworkDefinition, Owes, PriceTable, PrincipalAddr,
        ProposerTimestamp, ProvisionEntry, Provisions, ProvisionsRoot, QuorumCertificate,
        RETENTION_HORIZON, Round, RoutePrefix, SectionRoots, SetRoot, Settlement, ShardId,
        ShardLoad, Signer, SignerBitfield, StateClaim, StateClaimsRoot, StateRoot, StateWrites,
        StatedTerms, StoredReceipt, SubstateKey, TickId, TickManifest, TickManifestRoot, Timeout,
        TimeoutCertificate, TimestampRange, TopologySchedule, Transaction, TransactionDecision,
        TransactionEnvelope, TxHash, TxOutcome, UnsettledTx, ValidatorId, ValidatorInfo,
        ValidatorSet, Verifiable, Verified, Verify, VoteCount, WeightedTimestamp, Window,
        WitnessSources, claims_admit_block, receipt_hash_of, state_claims_admit_block, test_utils,
        verdict_leaf,
    };
    use hyperscale_vm_effects::{CrossingId, Hash32, IntentHash, ProtocolHasher};

    use super::*;
    use crate::admission::fixtures::{Against, DEPARTURE_CUT_MS, departures};
    use crate::admission::{
        FinalizationsFold, FinalizationsSection, Section, StateClaimsFold, StateClaimsSection,
        standing_toward,
    };
    use crate::commit_dedup::CommitDedupIndex;
    use crate::precut::Precut;
    use crate::proposal::{Prefilter, select_finalizations, select_transactions};

    /// The body root check the vote path dispatches, run in place, and
    /// the tick manifest's budget beside it.
    fn sections_bound(block: &Block) -> Result<(), String> {
        block
            .header()
            .body_root()
            .verify(&BodyRootContext {
                block,
                validity_anchor: block.header().parent_qc().weighted_timestamp(),
            })
            .map_err(|err| err.to_string())?;
        validate_tick_manifest_budget(block)
    }

    /// Admit `block`'s sections against `against`.
    fn admit(against: &Against, block: &Block) -> Result<(), String> {
        admit_sections(&against.ctx(), block).map(|_| ())
    }

    /// A half settles only members its own tick holds in flight in that
    /// half: one the rows never named, one a discard let go of, and one
    /// held in the other half are refused.
    #[test]
    fn a_half_settles_only_members_its_tick_holds_in_that_half() {
        let tx = TxHash::from(Hash::from_bytes(b"held member"));
        let reserved = test_utils::finalization_of(
            BlockHeight::new(2),
            vec![
                TxOutcome::new(
                    tx,
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                )
                .charging(0),
            ],
        );
        let settles = |against: &Against, fw: &Finalization| {
            let ctx = against.ctx();
            FinalizationsSection::admit(&ctx, &mut FinalizationsFold::from(&ctx), fw)
        };
        let row = |state| member_row(tx, state);

        let mut against = plain();
        assert!(settles(&against, &reserved).is_err(), "no row names it");
        for refused in [
            in_flight(3, Settlement::Alone),
            in_flight(2, Settlement::Shared),
            RowState::Released {
                settlement: Settlement::Alone,
            },
        ] {
            against.members.members.insert(tx, row(refused));
            assert!(settles(&against, &reserved).is_err(), "{refused:?}");
        }
        against
            .members
            .members
            .insert(tx, row(in_flight(2, Settlement::Alone)));
        against.members.ticks.insert(
            BlockHeight::new(2),
            TickRow {
                members: Capped::from_array([tx]),
                determined_unsettled: true,
                awaiting: 0,
            },
        );
        assert_eq!(settles(&against, &reserved), Ok(()));
    }

    /// `tx`'s row standing in `state`, committed at height 1.
    fn member_row(tx: TxHash, state: RowState) -> MemberRow {
        MemberRow {
            tx,
            deadline: Deadline::of(WeightedTimestamp::from_millis(u64::MAX / 4)),
            committed: WeightedTimestamp::ZERO,
            height: BlockHeight::new(1),
            state,
            holds: Capped::empty(),
            reach: Capped::empty(),
            awaits: Capped::empty(),
            charge: stub_abort_charge(0),
            share: 0,
            reserves: Capped::empty(),
            crossings: Capped::empty(),
            owes: Owes::default(),
            waiting: None,
            covered: false,
            executed: !matches!(state, RowState::Pending),
            hearing: Capped::empty(),
        }
    }

    fn in_flight(tick: u64, settlement: Settlement) -> RowState {
        RowState::InFlight {
            tick: BlockHeight::new(tick),
            joins: Joins::Executes,
            settlement,
        }
    }

    /// The effects receipt of `tx`'s run: no writes and no events, under
    /// the hash that content recomputes to, which [`succeeded`] states
    /// and [`stated_in`] records.
    fn effects_of(tx: TxHash) -> StoredReceipt {
        StoredReceipt {
            tx_hash: tx,
            consensus: Arc::new(ConsensusReceipt::Succeeded {
                receipt_hash: effects_hash(),
                writes: StateWrites::default(),
                beacon_witness_events: Capped::empty(),
                events: Capped::empty(),
            }),
        }
    }

    /// The hash of every [`effects_of`] receipt.
    fn effects_hash() -> GlobalReceiptHash {
        receipt_hash_of(
            &ConsensusReceipt::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
                writes: StateWrites::default(),
                beacon_witness_events: Capped::empty(),
                events: Capped::empty(),
            },
            true,
        )
        .expect("a projected success")
    }

    /// The legs half of tick 2 accepting each of `named`.
    fn legs_naming(named: &[TxHash]) -> Finalization {
        Finalization::accepting(
            TickId::new(ShardId::ROOT, BlockHeight::new(2)),
            Capped::new(named.iter().map(|&tx| effects_of(tx)).collect())
                .expect("a list written out in a test"),
        )
    }

    /// Where a row stands once the stating half of the tick at `tick`
    /// has stated its yes.
    fn stated_in(tick: u64) -> RowState {
        RowState::Stated {
            tick: BlockHeight::new(tick),
            receipt: effects_hash(),
        }
    }

    /// Admission over rows holding each of `standing` stated in tick 2:
    /// what a legs half of it names.
    fn holding_legs(standing: &[TxHash]) -> Against {
        let mut against = plain();
        for &tx in standing {
            against
                .members
                .members
                .insert(tx, member_row(tx, stated_in(2)));
        }
        against
    }

    /// Admission over rows holding each of `standing` in flight beside a
    /// counterpart in tick 2, with the tick row that counts them.
    fn holding_in_flight(standing: &[TxHash]) -> Against {
        let mut against = plain();
        for &tx in standing {
            against
                .members
                .members
                .insert(tx, member_row(tx, in_flight(2, Settlement::Shared)));
        }
        against.members.ticks.insert(
            BlockHeight::new(2),
            TickRow {
                members: Capped::new(standing.to_vec()).expect("a list written out in a test"),
                determined_unsettled: false,
                awaiting: u32::try_from(standing.len()).expect("a few members"),
            },
        );
        against
    }

    /// A core member's outcome, charged `share`, awaiting another shard.
    fn core_outcome(tx: TxHash, outcome: ExecutionOutcome, share: u128) -> TxOutcome {
        use hyperscale_types::Role;
        TxOutcome::new(tx, outcome)
            .charging(share)
            .awaiting([ShardId::leaf(1, 1)])
            .as_role(Role::Core)
    }

    fn succeeded() -> ExecutionOutcome {
        ExecutionOutcome::Succeeded {
            receipt_hash: effects_hash(),
        }
    }

    /// The stating half of tick 2 over `outcomes`, on a certificate
    /// anchored at `anchor_ms`: two anchors give two copies of one half.
    fn stating_at(anchor_ms: u64, outcomes: Vec<TxOutcome>) -> Finalization {
        use hyperscale_types::{ExecutionCertificate, GlobalReceiptRoot, TickHalf};
        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(2));
        let certificate = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::from_millis(anchor_ms),
            GlobalReceiptRoot::ZERO,
            Capped::new(outcomes).expect("a list written out in a test"),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        );
        let receipts: Vec<StoredReceipt> = certificate
            .tx_outcomes()
            .iter()
            .filter_map(|outcome| match outcome.outcome() {
                ExecutionOutcome::Succeeded { receipt_hash } => {
                    Some(yes_receipt(outcome.tx_hash(), *receipt_hash))
                }
                ExecutionOutcome::Failed | ExecutionOutcome::Aborted => None,
            })
            .collect();
        Finalization::new(
            tick_id,
            TickHalf::Stated,
            Some(Arc::new(certificate)),
            Capped::new(receipts).expect("a list written out in a test"),
        )
    }

    /// The stating half of tick 2 stating a yes for each of `yes`.
    fn stating_yes(anchor_ms: u64, yes: &[TxHash]) -> Finalization {
        stating_at(
            anchor_ms,
            yes.iter()
                .map(|&tx| core_outcome(tx, succeeded(), 3))
                .collect(),
        )
    }

    /// `against` after a block at height 3 carrying `halves` commits.
    fn after_committing(mut against: Against, halves: &[&Finalization]) -> Against {
        let certificates: Vec<Arc<Verifiable<Finalization>>> = halves
            .iter()
            .map(|fw| Arc::new(Verifiable::from((*fw).clone())))
            .collect();
        against.members.advance(&MemberInputs::deriving(
            ShardId::ROOT,
            BlockHeight::new(3),
            WeightedTimestamp::from_millis(3),
            std::iter::empty(),
            MemberSections {
                certificates: &certificates,
                records: &[],
                claims: &[],
            },
            against.schedule.windows(),
            Vec::new(),
        ));
        against
    }

    fn settles(against: &Against, fw: &Finalization) -> Result<(), String> {
        let ctx = against.ctx();
        FinalizationsSection::admit(&ctx, &mut FinalizationsFold::from(&ctx), fw)
    }

    /// A tick takes one stating half. A second copy of it, attested at
    /// another anchor and so under another hash, is refused in the block
    /// that carries the first, and in a later block by the rows the
    /// first moved.
    #[test]
    fn a_second_stating_half_of_one_tick_is_refused() {
        let (first, second) = (
            TxHash::from(Hash::from_bytes(b"first core")),
            TxHash::from(Hash::from_bytes(b"second core")),
        );
        let (half, copy) = (
            stating_yes(2, &[first, second]),
            stating_yes(9, &[first, second]),
        );
        assert_ne!(half.receipt_hash(), copy.receipt_hash());

        let against = holding_in_flight(&[first, second]);
        let ctx = against.ctx();
        let mut fold = FinalizationsFold::from(&ctx);
        assert_eq!(FinalizationsSection::admit(&ctx, &mut fold, &half), Ok(()));
        let err = FinalizationsSection::admit(&ctx, &mut fold, &copy).unwrap_err();
        assert!(err.contains("second stating half of tick 2"), "{err}");
        assert!(
            fold.resolved_here.is_empty(),
            "a stated name joins no resolved set: {:?}",
            fold.resolved_here,
        );

        let later = after_committing(holding_in_flight(&[first, second]), &[&half]);
        assert!(
            later
                .members
                .members
                .values()
                .all(|row| matches!(row.state, RowState::Stated { .. })),
        );
        let err = settles(&later, &copy).unwrap_err();
        assert!(
            err.contains("does not hold in flight beside a counterpart"),
            "{err}"
        );
    }

    /// Each outcome of a stating half counts against the block's cap on
    /// finalized transactions, a yes that settles nothing included:
    /// each moves a row.
    #[test]
    fn a_stated_yes_counts_toward_the_finalized_cap() {
        let (first, second) = (
            TxHash::from(Hash::from_bytes(b"first core")),
            TxHash::from(Hash::from_bytes(b"second core")),
        );
        let half = stating_yes(2, &[first, second]);
        assert_eq!(half.tx_count(), 0, "it settles nothing");
        let against = holding_in_flight(&[first, second]);
        let ctx = against.ctx();

        let mut room = FinalizationsFold::from(&ctx);
        room.tx_count = MAX_FINALIZED_TX_PER_BLOCK - 2;
        assert_eq!(FinalizationsSection::admit(&ctx, &mut room, &half), Ok(()));
        assert_eq!(room.tx_count, MAX_FINALIZED_TX_PER_BLOCK);

        let mut full = FinalizationsFold::from(&ctx);
        full.tx_count = MAX_FINALIZED_TX_PER_BLOCK - 1;
        let err = FinalizationsSection::admit(&ctx, &mut full, &half).unwrap_err();
        assert!(err.contains("finalized transactions"), "{err}");
        assert!(full.stated_here.is_empty(), "a refused half is not carried");
    }

    /// A stating half is whole: one stating fewer members than its tick
    /// holds outside the determined half is refused, since no later
    /// stating half could reach the rest. A refusal it settles counts as
    /// a yes does.
    #[test]
    fn a_stating_half_omitting_a_standing_member_is_refused() {
        let (first, second) = (
            TxHash::from(Hash::from_bytes(b"first core")),
            TxHash::from(Hash::from_bytes(b"second core")),
        );
        let against = holding_in_flight(&[first, second]);
        let err = settles(&against, &stating_yes(2, &[first])).unwrap_err();
        assert!(
            err.contains("covers 1 members of tick 2, which holds 2 for its Stated half"),
            "{err}",
        );

        let whole = stating_at(
            2,
            vec![
                core_outcome(first, succeeded(), 3),
                core_outcome(second, ExecutionOutcome::Failed, 3),
            ],
        );
        assert_eq!(settles(&against, &whole), Ok(()));

        // A tick whose rows a discard thinned is stated over what stands.
        let mut thinned = holding_in_flight(&[first]);
        thinned.members.members.insert(
            second,
            member_row(
                second,
                RowState::Released {
                    settlement: Settlement::Shared,
                },
            ),
        );
        assert_eq!(settles(&thinned, &stating_yes(2, &[first])), Ok(()));
        let err = settles(&thinned, &stating_yes(2, &[first, second])).unwrap_err();
        assert!(
            err.contains("does not hold in flight beside a counterpart"),
            "{err}"
        );
    }

    /// Every outcome of a stating half stands over a row of its own: a
    /// yes over a row no counterpart shares, one its tick does not hold,
    /// and one the determined half settles are refused.
    #[test]
    fn a_stating_half_naming_an_unheld_outcome_is_refused() {
        let (held, stranger) = (
            TxHash::from(Hash::from_bytes(b"held core")),
            TxHash::from(Hash::from_bytes(b"a stranger")),
        );
        let against = holding_in_flight(&[held]);
        let err = settles(&against, &stating_yes(2, &[stranger])).unwrap_err();
        assert!(
            err.contains("does not hold in flight beside a counterpart"),
            "{err}"
        );
        let err = settles(
            &against,
            &stating_at(2, vec![core_outcome(stranger, ExecutionOutcome::Failed, 3)]),
        )
        .unwrap_err();
        assert!(err.contains("does not hold for its Stated half"), "{err}");

        for (state, why) in [
            (
                in_flight(2, Settlement::Awaited),
                "no counterpart shares it",
            ),
            (
                in_flight(2, Settlement::Alone),
                "the determined half settles it",
            ),
            (in_flight(3, Settlement::Shared), "another tick holds it"),
            (stated_in(2), "already stated"),
        ] {
            let mut other = holding_in_flight(&[held]);
            other.members.members.insert(held, member_row(held, state));
            assert!(
                settles(&other, &stating_yes(2, &[held])).is_err(),
                "a yes over a row where {why}",
            );
        }

        // An abort with a reach settles in the stating half, over the
        // row its line put in flight.
        let mut aborting = holding_in_flight(&[held]);
        aborting
            .members
            .members
            .insert(held, member_row(held, in_flight(2, Settlement::Awaited)));
        assert_eq!(
            settles(
                &aborting,
                &stating_at(2, vec![core_outcome(held, ExecutionOutcome::Aborted, 3)]),
            ),
            Ok(()),
        );
    }

    /// A legs half names rows its tick's stating half has stated, and
    /// every half is judged against the parent's rows: a legs half ahead
    /// of the stating half, or beside it in one block, is refused, and
    /// rides the block after the stating half commits. The member it
    /// accepts stands accepted, in no tick, and a second legs half
    /// naming it is refused.
    #[test]
    fn a_legs_half_before_its_stating_half_is_refused() {
        let member = TxHash::from(Hash::from_bytes(b"a core member"));
        let (stating, legs) = (stating_yes(2, &[member]), legs_naming(&[member]));

        let against = holding_in_flight(&[member]);
        let err = settles(&against, &legs).unwrap_err();
        assert!(err.contains("does not hold for its Legs half"), "{err}");

        let ctx = against.ctx();
        let mut fold = FinalizationsFold::from(&ctx);
        assert_eq!(
            FinalizationsSection::admit(&ctx, &mut fold, &stating),
            Ok(())
        );
        let err = FinalizationsSection::admit(&ctx, &mut fold, &legs).unwrap_err();
        assert!(err.contains("does not hold for its Legs half"), "{err}");

        let stated = after_committing(holding_in_flight(&[member]), &[&stating]);
        assert_eq!(settles(&stated, &legs), Ok(()));
        let settled = after_committing(stated, &[&legs]);
        assert_eq!(settled.members.members[&member].state, RowState::Accepted);
        assert!(settled.members.ticks.is_empty());
        let err = settles(&settled, &legs).unwrap_err();
        assert!(err.contains("does not hold for its Legs half"), "{err}");
    }

    /// A legs half whose receipt recomputes to the hash it names, and so
    /// decodes, is refused where that hash is not the one the member's
    /// stated row records: the receipt it carries is the row's or none.
    #[test]
    fn a_receipt_whose_content_misses_the_rows_hash_is_refused() {
        let member = TxHash::from(Hash::from_bytes(b"a core member"));
        let unhashed = ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            writes: make_state_writes(1, 1, vec![1]),
            beacon_witness_events: Capped::empty(),
            events: Capped::empty(),
        };
        let receipt_hash = receipt_hash_of(&unhashed, true).expect("a projected success");
        assert_ne!(receipt_hash, effects_hash());
        let other = Finalization::accepting(
            TickId::new(ShardId::ROOT, BlockHeight::new(2)),
            Capped::new(vec![StoredReceipt {
                tx_hash: member,
                consensus: Arc::new(ConsensusReceipt::Succeeded {
                    receipt_hash,
                    writes: make_state_writes(1, 1, vec![1]),
                    beacon_witness_events: Capped::empty(),
                    events: Capped::empty(),
                }),
            }])
            .expect("a list written out in a test"),
        );
        let stated = holding_legs(&[member]);
        let err = settles(&stated, &other).unwrap_err();
        assert!(err.contains("does not record"), "{err}");
        assert_eq!(settles(&stated, &legs_naming(&[member])), Ok(()));
    }

    /// A core member's share enters the cumulative fees once, in the
    /// block carrying its tick's stating half: the legs half that later
    /// settles it adds nothing, whichever way its counterparts decided,
    /// and neither does the abort of a stated member, whose line states
    /// the share its row carries once stated, which is nothing.
    #[test]
    fn cumulative_fees_count_a_core_member_once() {
        let (accepted, refused) = (
            TxHash::from(Hash::from_bytes(b"an accepted core")),
            TxHash::from(Hash::from_bytes(b"a refused core")),
        );
        let stating = Arc::new(stating_at(
            2,
            vec![
                core_outcome(accepted, succeeded(), 30),
                core_outcome(refused, ExecutionOutcome::Failed, 12),
            ],
        ));
        let legs = Arc::new(legs_naming(&[accepted]));
        assert_eq!(legs.tx_hashes().collect::<Vec<_>>(), [accepted]);
        let fees_after = |blocks: &[&Block]| {
            blocks
                .iter()
                .fold(
                    ShardLoad::ZERO.advance(500, DeclaredWork::ZERO, None),
                    |load, block| load.advance(block.charged(), DeclaredWork::ZERO, None),
                )
                .cumulative_fees
        };
        let stating_block =
            block_with_certificates(BlockHeight::new(3), vec![Arc::clone(&stating)]);
        let legs_block = block_with_certificates(BlockHeight::new(4), vec![legs]);
        assert_eq!(
            stating_block.charged(),
            42,
            "the stating block carries every share its certificate attests",
        );
        assert_eq!(legs_block.charged(), 0, "and the legs block none");
        assert_eq!(fees_after(&[&stating_block, &legs_block]), 542);

        // The same member aborted by a line after it stated. The fold
        // zeroes the share of the row it states, the abort line states
        // the row's share, and the tick seating the abort attests that.
        let mut running = holding_in_flight(&[accepted, refused]);
        running
            .members
            .members
            .get_mut(&accepted)
            .expect("held above")
            .share = 30;
        let stated = after_committing(running, &[&stating]);
        let row = &stated.members.members[&accepted];
        assert!(matches!(row.state, RowState::Stated { .. }));
        assert_eq!(row.share, 0, "the stating half counted it");
        let aborting = Arc::new(stating_at(
            9,
            vec![core_outcome(accepted, ExecutionOutcome::Aborted, row.share)],
        ));
        let abort_block = block_with_certificates(BlockHeight::new(5), vec![aborting]);
        assert_eq!(abort_block.charged(), 0);
        assert_eq!(
            fees_after(&[&stating_block, &abort_block]),
            542,
            "stated and then aborted, the member is counted once",
        );
    }

    /// The evidence a block's lines turn on is read for every shard a
    /// stated row reaches, as for the row in flight it was: without it a
    /// stated row beside a departed counterpart could never be judged
    /// unanswerable.
    #[test]
    fn committed_sets_read_the_evidence_a_stated_row_reaches() {
        use crate::tick_members::{Ancestry, OwnContent, committed_sets};
        let peer = ShardId::leaf(1, 1);
        let tx = TxHash::from(Hash::from_bytes(b"a held core"));
        let reads = |state: RowState| {
            let mut against = plain();
            against.members.members.insert(
                tx,
                MemberRow {
                    reach: Capped::from_array([peer]),
                    ..member_row(tx, state)
                },
            );
            committed_sets(
                &against.members,
                &Ancestry::over(
                    &against.members,
                    std::iter::empty(),
                    against.schedule.windows(),
                ),
                &OwnContent::default(),
                &against.dedup,
                against.anchor,
                &against.snapshot,
                &against.schedule,
            )
            .evidence
            .into_keys()
            .collect::<Vec<_>>()
        };
        assert_eq!(reads(stated_in(2)), vec![peer]);
        assert_eq!(reads(in_flight(2, Settlement::Shared)), vec![peer]);
        assert_eq!(
            reads(RowState::Released {
                settlement: Settlement::Alone,
            }),
            vec![],
            "a row no counterpart settles against reads none",
        );
    }

    /// Two legs halves of one tick, naming different members, ride one
    /// block: neither repeats a name of the other, and each counts its
    /// own names against the block's cap, not its tick's.
    #[test]
    fn two_legs_halves_of_one_tick_ride_one_block_and_charge_their_names() {
        let (first, second) = (
            TxHash::from(Hash::from_bytes(b"first leg")),
            TxHash::from(Hash::from_bytes(b"second leg")),
        );
        let against = holding_legs(&[first, second]);
        let ctx = against.ctx();
        let mut fold = FinalizationsFold::from(&ctx);
        for named in [first, second] {
            assert_eq!(
                FinalizationsSection::admit(&ctx, &mut fold, &legs_naming(&[named]),),
                Ok(()),
            );
        }
        assert_eq!(fold.resolved_here, HashSet::from([first, second]));
        assert_eq!(fold.tx_count, 2, "each half counts the members it names");
    }

    /// Once a legs half has settled one member of a tick, a later one
    /// naming a member that still stands there is admitted.
    #[test]
    fn a_second_legs_finalization_of_one_tick_is_admitted() {
        let standing = TxHash::from(Hash::from_bytes(b"standing leg"));
        let against = holding_legs(&[standing]);
        let ctx = against.ctx();
        assert_eq!(
            FinalizationsSection::admit(
                &ctx,
                &mut FinalizationsFold::from(&ctx),
                &legs_naming(&[standing]),
            ),
            Ok(()),
        );
    }

    /// A legs half naming a member an earlier one settled is refused: in
    /// a later block by the row the first deleted, and in the same block
    /// by the name the first carries.
    #[test]
    fn a_legs_half_naming_a_member_the_first_settled_is_refused() {
        let (settled, standing) = (
            TxHash::from(Hash::from_bytes(b"settled leg")),
            TxHash::from(Hash::from_bytes(b"standing leg")),
        );
        let both = legs_naming(&[settled, standing]);

        let against = holding_legs(&[standing]);
        let ctx = against.ctx();
        let err = FinalizationsSection::admit(&ctx, &mut FinalizationsFold::from(&ctx), &both)
            .unwrap_err();
        assert!(err.contains("does not hold for its Legs half"), "{err}");

        let against = holding_legs(&[settled, standing]);
        let ctx = against.ctx();
        let mut fold = FinalizationsFold::from(&ctx);
        assert_eq!(
            FinalizationsSection::admit(&ctx, &mut fold, &legs_naming(&[settled]),),
            Ok(()),
        );
        let err = FinalizationsSection::admit(&ctx, &mut fold, &both).unwrap_err();
        assert!(
            err.contains("resolved twice within the same block"),
            "{err}"
        );
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
        against.local_shard = survivor();
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
            provision_tx_roots: Capped::default(),
            // A chain contiguous from genesis: one committed block per
            // height, none of which carried anything.
            load: ShardLoad {
                blocks: height.inner(),
                ..ShardLoad::ZERO
            },
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
            body_root: base.body_root(),
            provision_tx_roots: base.provision_tx_roots().clone(),
            txs_in_flight: base.txs_in_flight(),
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
        let parent_round = header.parent_qc().round().inner();
        let header = with_certificate(&header, certificate_for(MAX_ROUND_GAP - 1, parent_round));

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

    /// A certificate for `round` from three shares reporting `reported`;
    /// `validate_header` checks its shape, not its signatures.
    fn certificate_for(round: u64, reported: u64) -> TimeoutCertificate {
        let net = NetworkDefinition::simulator();
        let reported_qc = QuorumCertificate::new(
            BlockHash::ZERO,
            local_shard(),
            BlockHeight::new(reported),
            BlockHash::ZERO,
            Round::new(reported),
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        );
        let shares: Vec<Verified<Timeout>> = (0..3u64)
            .map(|voter| {
                Verified::<Timeout>::sign_local(
                    &net,
                    local_shard(),
                    Round::new(round),
                    reported_qc.clone(),
                    ValidatorId::new(voter),
                    &BlsSigner::generate(),
                )
                .expect("sign")
            })
            .collect();
        let positioned: Vec<(usize, &Verified<Timeout>)> = (0..3).zip(&shares).collect();
        Verified::<TimeoutCertificate>::from_verified_timeouts(
            &BlsVerifier,
            local_shard(),
            Round::new(round),
            &positioned,
            reported_qc,
            VoteCount::of(3),
        )
        .expect("assembles")
        .into_inner()
    }

    fn with_certificate(header: &BlockHeader, tc: TimeoutCertificate) -> BlockHeader {
        BlockHeader::new(BlockHeaderParts {
            timeout_cert: Some(tc),
            ..header.clone().into_parts()
        })
    }

    fn validates(header: &BlockHeader, topo: &TopologySnapshot) -> Result<(), String> {
        validate_header(
            Some(topo),
            Some(topo),
            local_shard(),
            header,
            BlockHeight::new(0),
            LocalTimestamp::from_millis(100_000),
        )
    }

    /// A certificate for the round before, reporting no round above the
    /// parent QC's, is well-formed on a block that skips rounds.
    #[test]
    fn validate_header_accepts_a_certificate_for_the_round_before() {
        let topo = topology_snapshot();
        let header = header_at_round(BlockHeight::new(1), Round::new(5), &topo);
        let parent_round = header.parent_qc().round().inner();
        let header = with_certificate(&header, certificate_for(4, parent_round));
        assert!(validates(&header, &topo).is_ok());
    }

    /// A certificate for another round, one whose signers reported a QC
    /// above the parent's, or one on a block that skips nothing is refused.
    #[test]
    fn validate_header_refuses_a_certificate_that_does_not_justify_the_skip() {
        let topo = topology_snapshot();
        let skipping = header_at_round(BlockHeight::new(1), Round::new(5), &topo);
        let parent_round = skipping.parent_qc().round().inner();

        let wrong_round = with_certificate(&skipping, certificate_for(3, parent_round));
        let err = validates(&wrong_round, &topo).unwrap_err();
        assert!(err.contains("does not precede"), "got: {err}");

        let above_parent = with_certificate(&skipping, certificate_for(4, parent_round + 1));
        let err = validates(&above_parent, &topo).unwrap_err();
        assert!(err.contains("reported round"), "got: {err}");

        let contiguous = header_at_round(BlockHeight::new(1), Round::new(parent_round + 1), &topo);
        let contiguous = with_certificate(&contiguous, certificate_for(parent_round, parent_round));
        let err = validates(&contiguous, &topo).unwrap_err();
        assert!(err.contains("follows its parent QC directly"), "got: {err}");
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
            provision_tx_roots: Capped::default(),
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
            provision_tx_roots: Capped::default(),
            ..Default::default()
        })
    }

    /// A genesis QC parents only its chain's first block. A block further up
    /// the chain carrying one — a fresh committee proposing before it holds
    /// a real QC — is rejected even when it sits one above the committed tip.
    #[test]
    fn a_genesis_qc_cannot_parent_a_block_above_the_origin() {
        let now = LocalTimestamp::from_millis(1_000_000);
        let first = header_at_height(BlockHeight::new(1), now.as_millis());
        validate_header(None, None, local_shard(), &first, BlockHeight::GENESIS, now)
            .expect("a genesis QC parents the chain's first block");

        let above = header_at_height(BlockHeight::new(1165), now.as_millis());
        let err = validate_header(
            None,
            None,
            local_shard(),
            &above,
            BlockHeight::new(1164),
            now,
        )
        .expect_err("a genesis QC cannot parent a block above the chain's origin");
        assert!(err.contains("cannot parent"), "unexpected rejection: {err}");
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

    /// An otherwise empty block whose header claims `load`.
    fn block_claiming(height: BlockHeight, load: ShardLoad) -> Block {
        Block::Live {
            header: BlockHeader::new(BlockHeaderParts {
                height,
                parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
                parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
                proposer: ValidatorId::new(height.inner() % 4),
                timestamp: ProposerTimestamp::from_millis(100_000),
                round: Round::new(0),
                provision_tx_roots: Capped::default(),
                load,
                ..Default::default()
            }),
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
        }
    }

    fn block_with_transactions(
        height: BlockHeight,
        transactions: Vec<Arc<Verifiable<Transaction>>>,
    ) -> Block {
        Block::Live {
            header: header_at_height(height, 100_000),
            transactions: Arc::new(
                Capped::new(transactions).expect("a list written out in a test"),
            ),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
        }
    }

    /// A block creating sweepable cells fits the cap right up to what a
    /// transaction can add, and one that would pass it is refused.
    ///
    /// The count is summed off the derivations rather than off anything
    /// the header claims, so a proposer cannot understate what its block
    /// will make the chain carry.
    ///
    /// An envelope carries at most `MAX_INTENTS`, so the cap is reached
    /// by a block of fully composed transactions rather than by one
    /// transaction — which is the shape it is sized for. Every nullifier
    /// is a signature to verify, so enough of them to fill the cap would
    /// pass the compute cap first; the fold starts near the cap and a
    /// few fill it, so what is judged is the count at the one that
    /// carries it past.
    #[test]
    fn a_block_may_create_sweepable_cells_up_to_the_cap() {
        use crate::admission::ProvisionsFold;

        // Each fully composed transaction creates one nullifier per
        // intent, all on this one shard, and its committed cell beside
        // them.
        let cells = MAX_INTENTS + 1;
        let full = 3;
        let composed = |seed: u32| {
            Arc::new(Verifiable::from(test_utils::stub_transaction_binding(
                seed,
                MAX_INTENTS - 1,
                test_utils::test_validity_range(),
            )))
        };
        let mut txs: Vec<Arc<Verifiable<Transaction>>> = (0..full)
            .map(|i| composed(u32::try_from(i).expect("fewer than u32 transactions")))
            .collect();
        let against = plain();
        let provisions = ProvisionsFold::default();
        let near_cap = || {
            let mut fold = TransactionsFold::beside(&provisions);
            fold.sweepable = MAX_SWEEPABLE_CREATED_PER_BLOCK - full * cells;
            fold
        };
        let mut at_cap = near_cap();
        admit_all::<TransactionsSection<'_>>(
            &against.ctx(),
            &mut at_cap,
            txs.iter().map(unwrapped),
        )
        .expect("a block at the cap is admitted");
        assert_eq!(at_cap.sweepable, MAX_SWEEPABLE_CREATED_PER_BLOCK);

        txs.push(composed(u32::MAX));
        let err = admit_all::<TransactionsSection<'_>>(
            &against.ctx(),
            &mut near_cap(),
            txs.iter().map(unwrapped),
        )
        .expect_err("past the cap is refused");
        assert!(err.contains("sweepable cells"), "{err}");

        // A block that binds nothing creates only its transactions'
        // committed cells — the common case must not pay for this rule.
        let binding_nothing = block_with_transactions(BlockHeight::new(3), vec![tx(1)]);
        assert!(admit(&plain(), &binding_nothing).is_ok());
    }

    /// A transaction whose only leg on a shard is an outbound deposit is
    /// the recipient's fold's to credit, never a transaction that shard
    /// commits; the payer's shard admits it.
    #[test]
    fn a_transaction_this_shard_only_delivers_for_is_refused() {
        use crate::admission::ProvisionsFold;

        test_utils::install_stub_protocol_statics();
        let (payer_shard, recipient_shard) = ShardId::ROOT.children();
        let payer = PrincipalAddr::new([0x10; 31]);
        let recipient = Address::new([0x90; 31], AddressClass::Component);
        let transfer = Arc::new(Verifiable::from(
            test_utils::stub_transaction(
                payer,
                &[payer.address(), recipient],
                1_000,
                test_utils::test_validity_range(),
            )
            .with_legs(
                &test_utils::StubVmStatics,
                vec![
                    test_utils::leg_shape(payer.address(), LegRole::Core, &[]),
                    test_utils::leg_shape(recipient, LegRole::Outbound, &[(0, 0)]),
                ],
            ),
        ));
        let on = |local: ShardId| {
            let mut against = Against::window(TopologySnapshot::new(
                NetworkDefinition::simulator(),
                2,
                ValidatorSet::new(Vec::new()),
            ));
            against.local_shard = local;
            let provisions = ProvisionsFold::default();
            admit_all::<TransactionsSection<'_>>(
                &against.ctx(),
                &mut TransactionsFold::beside(&provisions),
                std::iter::once(&transfer).map(unwrapped),
            )
        };

        assert!(
            on(recipient_shard)
                .expect_err("the recipient's shard only delivers")
                .contains("only delivers here"),
        );
        assert_eq!(on(payer_shard), Ok(()), "the payer's shard commits it");
    }

    /// Admission on the shard holding `0x10`-prefixed principals of a
    /// four-shard trie, and the two siblings holding `0x50` and `0x90`.
    fn among_four_shards() -> (Against, ShardId, ShardId) {
        test_utils::install_stub_protocol_statics();
        let mut against = Against::window(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            4,
            ValidatorSet::new(Vec::new()),
        ));
        let home = |seed: u8| {
            against
                .snapshot
                .shard_trie()
                .shard_for_prefix(test_principal(seed).address())
        };
        let (local, near, far) = (home(0x10), home(0x50), home(0x90));
        against.local_shard = local;
        against.members = MemberIndex::empty(local);
        (against, near, far)
    }

    /// A whole transaction paid from the local shard of
    /// [`among_four_shards`] by the principal `payer` and writing under
    /// the principal `other` too, so its member there awaits `other`'s
    /// shard.
    fn awaiting(payer: u8, other: u8) -> Transaction {
        let payer = test_principal(payer);
        test_utils::stub_transaction(
            payer,
            &[payer.address(), test_principal(other).address()],
            1_000,
            test_utils::test_validity_range(),
        )
    }

    /// `count` rows in flight in tick 2, each awaiting `shard`.
    fn stand_toward(against: &mut Against, shard: ShardId, count: usize) -> Vec<TxHash> {
        (0..count)
            .map(|i| {
                let tx = TxHash::from(Hash::from_bytes(&i.to_le_bytes()));
                let mut row = member_row(tx, in_flight(2, Settlement::Shared));
                row.awaits = Capped::from_array([shard]);
                against.members.members.insert(tx, row);
                tx
            })
            .collect()
    }

    /// Admit `transactions` in order into one transactions fold.
    fn admit_in_order(against: &Against, transactions: &[&Transaction]) -> Vec<Result<(), String>> {
        let ctx = against.ctx();
        let provisions = ProvisionsFold::default();
        let mut fold = TransactionsFold::beside(&provisions);
        transactions
            .iter()
            .map(|tx| TransactionsSection::admit(&ctx, &mut fold, tx))
            .collect()
    }

    /// The stub derivation, retaining `self.0` bytes on every shard:
    /// what a publish of an artifact that wide declares.
    struct Retaining(u64);

    impl Derivation for Retaining {
        fn derive(&self, vm: &TransactionEnvelope) -> Result<Derived, DerivationError> {
            let mut derived = test_utils::StubVmStatics.derive(vm)?;
            derived.work.retention = self.0;
            derived.everywhere.retention = self.0;
            Ok(derived)
        }
    }

    /// [`awaiting`]'s transaction, derived as retaining `retention`.
    fn retaining(payer: u8, other: u8, retention: u64) -> Transaction {
        let tx = Transaction::new(awaiting(payer, other).body().clone());
        tx.try_derived(&Retaining(retention))
            .expect("the stub derivation routes it");
        tx
    }

    /// A transaction with a member a sibling's verdict can discard whose
    /// staged bound passes the receipt cap is refused at admission, free
    /// of charge: its row could never stage the yes it would state. The
    /// same declaration on a member no sibling's verdict can discard is
    /// admitted, since it states no yes, and so is a shared member whose
    /// bound fits.
    #[test]
    fn an_abortable_member_whose_bound_passes_the_receipt_cap_is_refused_at_admission() {
        let (against, _, _) = among_four_shards();
        let trie = against.snapshot.shard_trie();
        let near_the_cell_limit = MAX_STAGED_RECEIPT_BYTES;
        let shared = retaining(0x10, 0x50, near_the_cell_limit);
        let alone = retaining(0x13, 0x13, near_the_cell_limit);
        let fitting = retaining(0x11, 0x51, near_the_cell_limit / 2);
        assert!(member_of(&shared, trie, against.local_shard).abortable());
        assert!(!member_of(&alone, trie, against.local_shard).abortable());
        assert!(staged_past_cap(&shared, trie).is_some());
        assert_eq!(staged_past_cap(&alone, trie), None);
        assert_eq!(staged_past_cap(&fitting, trie), None);

        let verdicts = admit_in_order(&against, &[&shared, &alone, &fitting]);
        let err = verdicts[0]
            .as_ref()
            .expect_err("a yes it could never stage");
        assert!(err.contains("could never state"), "{err}");
        assert_eq!(
            verdicts[1],
            Ok(()),
            "a member no sibling shares states no yes"
        );
        assert_eq!(verdicts[2], Ok(()), "a bound within the cap");
    }

    /// A core transaction is refused where the cap's worth of rows
    /// already stand toward a shard it awaits, counting the ones its own
    /// block admitted ahead of it, while one awaiting another shard and
    /// one awaiting nobody are admitted beside it.
    #[test]
    fn the_cap_refuses_one_more_toward_a_shard_and_admits_toward_another() {
        let (mut against, near, far) = among_four_shards();
        let (first, second) = (awaiting(0x10, 0x50), awaiting(0x11, 0x51));
        let (elsewhere, alone) = (awaiting(0x12, 0x90), awaiting(0x13, 0x13));
        let trie = against.snapshot.shard_trie();
        let awaited = |tx| awaited_core(&member_of(tx, trie, against.local_shard));
        assert_eq!(awaited(&first)[..], [near]);
        assert_eq!(awaited(&second)[..], [near]);
        assert_eq!(awaited(&elsewhere)[..], [far]);
        assert!(awaited(&alone).is_empty());

        // One place left toward the near shard: the block's first
        // transaction takes it and its second is refused.
        stand_toward(&mut against, near, MAX_STANDING_TOWARD_SHARD - 1);
        let verdicts = admit_in_order(&against, &[&first, &second, &elsewhere, &alone]);
        assert_eq!(verdicts[0], Ok(()));
        let err = verdicts[1].as_ref().expect_err("the cap is reached");
        assert!(err.contains("already stand toward"), "{err}");
        assert_eq!(verdicts[2], Ok(()), "another shard has its own count");
        assert_eq!(
            verdicts[3],
            Ok(()),
            "a member awaiting nobody is not counted"
        );

        // At the cap in the parent's rows, none is admitted toward it.
        stand_toward(&mut against, near, MAX_STANDING_TOWARD_SHARD);
        let verdicts = admit_in_order(&against, &[&first, &elsewhere]);
        assert!(verdicts[0].is_err());
        assert_eq!(verdicts[1], Ok(()));
    }

    /// The count is the rows standing at the parent: once a row awaiting
    /// the capped shard ends, the next block admits one more toward it,
    /// and only one.
    #[test]
    fn the_count_falls_when_a_row_ends() {
        let (mut against, near, _) = among_four_shards();
        let (first, second) = (awaiting(0x10, 0x50), awaiting(0x11, 0x51));
        let standing = stand_toward(&mut against, near, MAX_STANDING_TOWARD_SHARD);
        assert!(admit_in_order(&against, &[&first])[0].is_err());

        let fated = MemberInputs {
            manifest: Arc::new(Capped::from_array([TickLine::Fate {
                tx: standing[0],
                charge: stub_abort_charge(0),
            }])),
            ..MemberInputs::still(against.local_shard)
        };
        against.members.advance(&fated);
        assert_eq!(
            against.members.members.len(),
            MAX_STANDING_TOWARD_SHARD - 1,
            "the fate ended one row"
        );
        let verdicts = admit_in_order(&against, &[&first, &second]);
        assert_eq!(verdicts[0], Ok(()), "the ended row's place is free");
        assert!(verdicts[1].is_err(), "and it is the only one");
    }

    /// [`among_four_shards`] anchored in its fifth window on a one-second
    /// grid, in which each of `leaving` is scheduled to leave the trie at
    /// the window's end.
    fn in_the_final_epoch_of(leaving: &[ShardId]) -> Against {
        let (plain, ..) = among_four_shards();
        let final_epoch = Epoch::new(5);
        let window = plain
            .snapshot
            .clone()
            .with_scheduled_terminals(leaving.iter().map(|&shard| (shard, final_epoch)).collect());
        let schedule = TopologySchedule::new(1_000, final_epoch, Arc::new(window));
        let mut against = Against::schedule(plain.snapshot.clone(), schedule);
        against.local_shard = plain.local_shard;
        against.members = plain.members;
        against.anchor = WeightedTimestamp::from_millis(5_500);
        against
    }

    /// A core transaction is refused where a shard its member here awaits
    /// leaves the trie at the end of the block's own window, and every
    /// one is refused where this shard does, while a member awaiting
    /// nobody is admitted beside them: the row it would write could not
    /// be read accepted by a sibling before the cut.
    #[test]
    fn a_core_transaction_toward_a_terminating_shard_is_not_admitted() {
        let (_, near, _) = among_four_shards();
        let (toward_near, toward_far) = (awaiting(0x10, 0x50), awaiting(0x12, 0x90));
        let alone = awaiting(0x13, 0x13);

        let sibling_leaves = in_the_final_epoch_of(&[near]);
        let verdicts = admit_in_order(&sibling_leaves, &[&toward_near, &toward_far, &alone]);
        let err = verdicts[0]
            .as_ref()
            .expect_err("the near shard is terminating");
        assert!(err.contains("terminating"), "{err}");
        assert_eq!(verdicts[1], Ok(()), "the far shard runs on");
        assert_eq!(verdicts[2], Ok(()), "a member awaiting nobody");

        let local = sibling_leaves.local_shard;
        let this_leaves = in_the_final_epoch_of(&[local]);
        let verdicts = admit_in_order(&this_leaves, &[&toward_near, &toward_far, &alone]);
        for refused in &verdicts[..2] {
            let err = refused.as_ref().expect_err("this shard is terminating");
            assert!(err.contains("terminating"), "{err}");
        }
        assert_eq!(verdicts[2], Ok(()), "a member awaiting nobody");

        let nobody_leaves = in_the_final_epoch_of(&[]);
        assert_eq!(
            admit_in_order(&nobody_leaves, &[&toward_near, &toward_far]),
            vec![Ok(()), Ok(())],
        );
    }

    /// Past the cut the departed shard's id is out of the trie, and a
    /// transaction classified under the window after it awaits the
    /// successor holding its owners, which is admitted.
    #[test]
    fn and_is_admitted_after_the_cut() {
        let (_, near, _) = among_four_shards();
        let toward_near = awaiting(0x10, 0x50);
        let after = lives(None, Some(near));
        let schedule = TopologySchedule::new(1_000, Epoch::new(6), Arc::new(after.clone()));
        let (plain, ..) = among_four_shards();
        let mut against = Against::schedule(after, schedule);
        against.local_shard = plain.local_shard;
        against.members = plain.members;
        against.anchor = WeightedTimestamp::from_millis(6_500);
        let member = member_of(
            &toward_near,
            against.snapshot.shard_trie(),
            against.local_shard,
        );
        let awaited = awaited_core(&member);
        assert_eq!(awaited.len(), 1);
        assert!(near.is_ancestor_of(awaited[0]), "{awaited:?}");
        assert_eq!(admit_in_order(&against, &[&toward_near]), vec![Ok(())]);
    }

    /// The committed sets a block's lines are named over hold a waiting
    /// member whose settlement it shares with a sibling as terminating
    /// where that sibling leaves the trie at the end of the block's
    /// window, and every such member where this shard does. A member
    /// awaiting nobody is never held so, and none is where nothing
    /// leaves.
    #[test]
    fn committed_sets_hold_a_shared_waiting_member_terminating_in_the_final_epoch() {
        use crate::tick_members::{Ancestry, OwnContent, committed_sets};
        let (_, near, far) = among_four_shards();
        let waiting = |seed: &[u8], settlement: Settlement, awaits: Option<ShardId>| {
            let tx = TxHash::from(Hash::from_bytes(seed));
            let row = MemberRow {
                awaits: Capped::new(awaits.into_iter().collect()).expect("one shard at most"),
                waiting: Some(Waiting {
                    staged: 0,
                    leg: false,
                    settlement,
                    declared: Capped::empty(),
                    engages: Capped::empty(),
                    waits: false,
                }),
                ..member_row(tx, RowState::Pending)
            };
            (tx, row)
        };
        let rows = [
            waiting(b"toward near", Settlement::Shared, Some(near)),
            waiting(b"toward far", Settlement::Shared, Some(far)),
            waiting(b"alone", Settlement::Alone, None),
        ];
        let [toward_near, toward_far, alone] = rows.each_ref().map(|(tx, _)| *tx);
        let terminating = |leaving: &[ShardId]| {
            let mut against = in_the_final_epoch_of(leaving);
            for (tx, row) in &rows {
                against.members.members.insert(*tx, row.clone());
            }
            committed_sets(
                &against.members,
                &Ancestry::over(
                    &against.members,
                    std::iter::empty(),
                    against.schedule.windows(),
                ),
                &OwnContent::default(),
                &against.dedup,
                against.anchor,
                &against.snapshot,
                &against.schedule,
            )
            .terminating
        };

        assert_eq!(
            terminating(&[near]),
            BTreeSet::from([toward_near]),
            "only the member awaiting the leaving sibling",
        );
        let local = in_the_final_epoch_of(&[]).local_shard;
        assert_eq!(
            terminating(&[local]),
            BTreeSet::from([toward_near, toward_far]),
            "every shared member where this shard leaves",
        );
        assert!(!terminating(&[near, local]).contains(&alone));
        assert_eq!(terminating(&[]), BTreeSet::new());
    }

    /// [`among_four_shards`] classified under a snapshot naming every
    /// shard formed at genesis, and anchored in `window`.
    fn anchored_in(window: TopologySnapshot) -> (Against, ShardId, ShardId) {
        let (against, near, far) = among_four_shards();
        let at_genesis = |snapshot: &TopologySnapshot| {
            snapshot
                .shard_trie()
                .leaves()
                .map(|shard| (shard, Epoch::GENESIS))
                .collect::<BTreeMap<_, _>>()
        };
        let classifying = against.snapshot.clone();
        let classifying = classifying.clone().with_formed(at_genesis(&classifying));
        let schedule = TopologySchedule::new(u64::MAX / 2, Epoch::GENESIS, Arc::new(window));
        let mut anchored = Against::schedule(classifying, schedule);
        anchored.local_shard = against.local_shard;
        anchored.members = against.members;
        (anchored, near, far)
    }

    /// The window [`among_four_shards`]' snapshot runs under each leaf,
    /// formed at genesis but for `later`'s chain, formed in epoch 7; and
    /// with `absent` split in two where it is named.
    fn lives(later: Option<ShardId>, absent: Option<ShardId>) -> TopologySnapshot {
        let mut leaves: Vec<ShardId> = TopologySnapshot::new(
            NetworkDefinition::simulator(),
            4,
            ValidatorSet::new(Vec::new()),
        )
        .shard_trie()
        .leaves()
        .collect();
        if let Some(absent) = absent {
            leaves.retain(|shard| *shard != absent);
            leaves.extend(<[ShardId; 2]>::from(absent.children()));
        }
        let formed = leaves
            .iter()
            .map(|&shard| {
                let epoch = if Some(shard) == later { 7 } else { 0 };
                (shard, Epoch::new(epoch))
            })
            .collect();
        TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &ValidatorSet::new(Vec::new()),
            leaves
                .into_iter()
                .map(|shard| (shard, Vec::new()))
                .collect(),
            HashMap::new(),
            BTreeMap::new(),
            HashMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
        )
        .with_formed(formed)
    }

    /// A core member is classified under its block's parent's window and
    /// judged by the chains its block's own window runs. Where the two
    /// name another life for a shard it awaits, a later chain under the
    /// same id or none at all, the transaction is refused, so the row it
    /// would write never awaits a chain other than the one running at its
    /// commit. One awaiting a shard whose life is unchanged is admitted
    /// beside it, as is every one under one life.
    #[test]
    fn a_core_member_classified_under_another_life_is_refused() {
        let (_, near, _) = among_four_shards();
        let (toward_near, toward_far) = (awaiting(0x10, 0x50), awaiting(0x12, 0x90));
        for window in [lives(Some(near), None), lives(None, Some(near))] {
            let (against, ..) = anchored_in(window);
            let verdicts = admit_in_order(&against, &[&toward_near, &toward_far]);
            let err = verdicts[0]
                .as_ref()
                .expect_err("another life of the near shard");
            assert!(err.contains("life"), "{err}");
            assert_eq!(verdicts[1], Ok(()), "the far shard's life is unchanged");
        }
        let (unchanged, ..) = anchored_in(lives(None, None));
        assert_eq!(
            admit_in_order(&unchanged, &[&toward_near, &toward_far]),
            vec![Ok(()), Ok(())],
        );
    }

    /// A member that awaits no other shard writes a row no sibling's
    /// reading judges, so another life of a shard it reaches refuses
    /// nothing.
    #[test]
    fn a_leg_is_admitted_across_a_life_change() {
        let (against, near, _) = among_four_shards();
        let payer = test_principal(0x10);
        let core = test_principal(0x50).address();
        let leg = test_utils::stub_transaction(
            payer,
            &[payer.address(), core],
            1_000,
            test_utils::test_validity_range(),
        )
        .with_legs(
            &test_utils::StubVmStatics,
            vec![
                test_utils::leg_shape(payer.address(), LegRole::Inbound, &[]),
                test_utils::leg_shape(core, LegRole::Core, &[(0, 0)]),
            ],
        );
        let member = member_of(&leg, against.snapshot.shard_trie(), against.local_shard);
        assert!(awaited_core(&member).is_empty());
        assert!(member.reach().contains(&near));
        for window in [lives(Some(near), None), lives(None, Some(near))] {
            let (anchored, ..) = anchored_in(window);
            assert_eq!(admit_in_order(&anchored, &[&leg]), vec![Ok(())]);
        }
    }

    /// An abort line names its row awaiting nobody, so the row stops
    /// counting toward the shard it awaited in the block that aborts it,
    /// ahead of the determined half that deletes it.
    #[test]
    fn the_count_falls_when_a_row_is_aborted() {
        let (mut against, near, _) = among_four_shards();
        let (first, second) = (awaiting(0x10, 0x50), awaiting(0x11, 0x51));
        let standing = stand_toward(&mut against, near, MAX_STANDING_TOWARD_SHARD);
        assert_eq!(
            standing_toward(&against.members).toward(near),
            MAX_STANDING_TOWARD_SHARD
        );

        let aborted = MemberInputs {
            height: BlockHeight::new(3),
            manifest: Arc::new(Capped::from_array([TickLine::Member {
                staged: 0,
                tx: standing[0],
                joins: Joins::Aborted,
                settlement: Settlement::Awaited,
                holds: Capped::empty(),
                reach: Capped::from_array([near]),
                awaits: Capped::empty(),
                charge: stub_abort_charge(0),
                share: 0,
                reserves: Capped::empty(),
                deadline: Deadline::of(WeightedTimestamp::from_millis(u64::MAX / 4)),
                crossings: Capped::empty(),
            }])),
            ..MemberInputs::still(against.local_shard)
        };
        against.members.advance(&aborted);
        assert_eq!(
            against.members.members.len(),
            MAX_STANDING_TOWARD_SHARD,
            "the aborted row still stands"
        );
        assert_eq!(
            standing_toward(&against.members).toward(near),
            MAX_STANDING_TOWARD_SHARD - 1
        );
        let verdicts = admit_in_order(&against, &[&first, &second]);
        assert_eq!(verdicts[0], Ok(()), "the aborted row's place is free");
        assert!(verdicts[1].is_err(), "and it is the only one");
    }

    /// Rows a recovery released, each awaiting one sibling that still
    /// answers and covered by no record, hold that sibling at its cap
    /// only to their deadline where they never ran: the block anchored
    /// there aborts every one of them, which takes each out of the count
    /// toward the sibling, and the stating half of that block's tick
    /// deletes the rows and takes them out of the drain. Rows that ran
    /// hold it to no clock: the first block names their aborts.
    #[test]
    fn released_rows_leave_the_count_and_the_drain_from_their_deadline() {
        use hyperscale_engine::tick_select::{CommittedSets, member_lines};
        use hyperscale_storage::SettledHalf;
        use hyperscale_types::{Evidence, TickHalf};

        let (mut against, near, _) = among_four_shards();
        let first = awaiting(0x10, 0x50);
        let deadline = Deadline::of(WeightedTimestamp::from_millis(10_000));
        let standing = stand_toward(&mut against, near, MAX_STANDING_TOWARD_SHARD);
        for row in against.members.members.values_mut() {
            row.state = RowState::Released {
                settlement: Settlement::Shared,
            };
            row.reach = Capped::from_array([near]);
            row.deadline = deadline;
        }
        let mut ran = against.members.clone();
        for row in against.members.members.values_mut() {
            row.executed = false;
        }
        let named = |rows: &MemberIndex, anchor: WeightedTimestamp| {
            let (lines, missing, _) = member_lines(
                rows,
                anchor,
                &CommittedSets::default(),
                &|_, _| Evidence::Live { terminating: false },
                false,
                &BTreeSet::new(),
                &BTreeMap::new(),
            );
            assert!(missing.is_empty());
            lines
        };
        let short = deadline.at().minus(Duration::from_millis(1));
        assert_eq!(named(&ran, short).len(), MAX_STANDING_TOWARD_SHARD);
        ran.members.clear();
        assert!(named(&against.members, short).is_empty());
        assert!(admit_in_order(&against, &[&first])[0].is_err());

        let aborts = named(&against.members, deadline.at());
        assert_eq!(aborts.len(), MAX_STANDING_TOWARD_SHARD);
        assert!(aborts.iter().all(|line| matches!(
            line,
            TickLine::Member {
                joins: Joins::Aborted,
                settlement: Settlement::Awaited,
                ..
            }
        )));
        against.members.advance(&MemberInputs {
            height: BlockHeight::new(3),
            manifest: Arc::new(Capped::new(aborts).expect("one block's lines")),
            ..MemberInputs::still(against.local_shard)
        });
        assert_eq!(standing_toward(&against.members).toward(near), 0);
        assert_eq!(
            against.members.members.len(),
            MAX_STANDING_TOWARD_SHARD,
            "an aborted row stands in the drain until its half settles",
        );
        assert_eq!(admit_in_order(&against, &[&first])[0], Ok(()));

        against.members.advance(&MemberInputs {
            height: BlockHeight::new(4),
            settled: vec![SettledHalf {
                tick: TickId::new(against.local_shard, BlockHeight::new(3)),
                half: TickHalf::Stated,
                deleted: standing,
                stated: Vec::new(),
                accepted: Vec::new(),
            }],
            ..MemberInputs::still(against.local_shard)
        });
        assert!(against.members.members.is_empty() && against.members.ticks.is_empty());
    }

    /// `transactions` in hash order, as a block carries them and a ready
    /// set offers them.
    fn in_hash_order(mut transactions: Vec<Transaction>) -> Vec<Arc<Verifiable<Transaction>>> {
        transactions.sort_by_key(Transaction::hash);
        transactions
            .into_iter()
            .map(|tx| Arc::new(Verifiable::from(tx)))
            .collect()
    }

    /// A voter refuses a block carrying one transaction more toward a
    /// shard than the cap leaves room for, and admits the same block
    /// without it.
    #[test]
    fn a_block_one_transaction_past_the_cap_is_refused_by_the_voter() {
        let (mut against, near, _) = among_four_shards();
        stand_toward(&mut against, near, MAX_STANDING_TOWARD_SHARD - 1);
        let within = vec![awaiting(0x10, 0x50), awaiting(0x12, 0x90)];
        let mut past = within.clone();
        past.push(awaiting(0x11, 0x51));

        let block = |transactions| block_with_transactions(BlockHeight::new(3), transactions);
        assert_eq!(admit(&against, &block(in_hash_order(within))), Ok(()));
        let err =
            admit(&against, &block(in_hash_order(past))).expect_err("one transaction past the cap");
        assert!(err.contains("already stand toward"), "{err}");
    }

    /// A proposer offered more toward a shard than the cap leaves room
    /// for drops the excess and keeps everything else, and what it keeps
    /// is a block its voters admit.
    #[test]
    fn a_proposer_drops_what_the_cap_refuses_and_keeps_the_rest() {
        let (mut against, near, _) = among_four_shards();
        stand_toward(&mut against, near, MAX_STANDING_TOWARD_SHARD - 1);
        let toward_near = [awaiting(0x10, 0x50), awaiting(0x11, 0x51)];
        let others = [awaiting(0x12, 0x90), awaiting(0x13, 0x13)];
        let ready: Vec<Arc<Verified<Transaction>>> =
            in_hash_order(toward_near.iter().chain(&others).cloned().collect())
                .into_iter()
                .map(|tx| Arc::new(Verified::new_unchecked_for_test(tx.as_unverified().clone())))
                .collect();

        let ctx = against.ctx();
        let provisions = ProvisionsFold::default();
        let selected = select_transactions(
            &ctx,
            Prefilter {
                precut: &Precut::adopted(against.local_shard, &[]),
            },
            &mut TransactionsFold::beside(&provisions),
            &ready,
        );
        let kept: Vec<TxHash> = selected.iter().map(|tx| tx.hash()).collect();
        let offered_near: Vec<TxHash> = ready
            .iter()
            .map(|tx| tx.hash())
            .filter(|hash| toward_near.iter().any(|tx| tx.hash() == *hash))
            .collect();
        assert_eq!(kept.len(), 3, "one toward {near:?} is dropped");
        assert!(
            kept.contains(&offered_near[0]) && !kept.contains(&offered_near[1]),
            "the first offered toward {near:?} takes the last place"
        );
        assert!(others.iter().all(|tx| kept.contains(&tx.hash())));

        let carried = selected
            .iter()
            .map(|tx| Arc::new(Verifiable::from(tx.as_ref().as_ref().clone())))
            .collect();
        assert_eq!(
            admit(
                &against,
                &block_with_transactions(BlockHeight::new(3), carried)
            ),
            Ok(()),
            "a voter admits what the proposer kept"
        );
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
                provision_tx_roots: Capped::default(),
                body_root: SectionRoots {
                    abandonment: root,
                    ..SectionRoots::EMPTY
                }
                .root(),
                ..Default::default()
            }),
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(
                Capped::new(verdicts).expect("a list written out in a test"),
            ),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
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
                provision_tx_roots: Capped::default(),
                body_root: SectionRoots {
                    state_claims: root,
                    ..SectionRoots::EMPTY
                }
                .root(),
                ..Default::default()
            }),
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::new(bundles).expect("a list written out in a test")),
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        }
    }

    /// Claims at one anchor of `shard` wide enough that together they
    /// outrun the section's budget: each reads two hundred cells of a
    /// tree holding two thousand, over disjoint ascending ranges, so
    /// the one that does not fit leaves room for a piece of itself.
    /// Returns the tree's leaves beside them.
    pub fn wide_claims(shard: ShardId) -> (Vec<SubstateKey>, Vec<StateClaim>) {
        wide_claims_at(shard, 3)
    }

    /// [`wide_claims`] at `shard`'s `height`.
    pub fn wide_claims_at(shard: ShardId, height: u64) -> (Vec<SubstateKey>, Vec<StateClaim>) {
        let leaves: Vec<SubstateKey> = (0u16..2_048)
            .map(|at| SubstateKey {
                owner: test_utils::test_prefix(u8::try_from(at / 256).expect("under 8")),
                local: LocalKey([u8::try_from(at % 256).expect("masked"); 16]),
            })
            .collect();
        let mut sorted = leaves.clone();
        sorted.sort_unstable();
        let claims: Vec<StateClaim> = sorted
            .chunks(200)
            .map(|asked| test_utils::proven_claim(shard, height, &leaves, asked))
            .collect();
        let total: usize = claims.iter().map(StateClaim::wire_weight).sum();
        assert!(
            !state_claims_admit_block(total),
            "the fixture's {total} bytes must outrun the budget",
        );
        (leaves, claims)
    }

    /// Verdict claims at `shard`'s `height` that together outrun the
    /// section's budget: each reads present the verdict leaves of
    /// sixteen members, over disjoint ascending ranges of one tree.
    /// Returns the members beside them, in the order the claims name
    /// them.
    pub fn verdict_claims_at(shard: ShardId, height: u64) -> (Vec<TxHash>, Vec<StateClaim>) {
        let mut keyed: Vec<(SubstateKey, TxHash)> = (0u64..1_280)
            .map(|seed| {
                let tx = TxHash::from(Hash::from_bytes(&seed.to_le_bytes()));
                (verdict_leaf(shard, tx), tx)
            })
            .collect();
        keyed.sort_unstable();
        let leaves: Vec<SubstateKey> = keyed.iter().map(|(leaf, _)| *leaf).collect();
        let claims: Vec<StateClaim> = keyed
            .chunks(16)
            .map(|named| {
                let asked: Vec<SubstateKey> = named.iter().map(|(leaf, _)| *leaf).collect();
                test_utils::proven_claim(shard, height, &leaves, &asked)
                    .hearing(named.iter().map(|(_, tx)| *tx))
            })
            .collect();
        let total: usize = claims.iter().map(StateClaim::wire_weight).sum();
        assert!(
            claims.iter().all(StateClaim::is_verdict_claim) && !claims_admit_block(total),
            "the fixture's {total} bytes of verdict claims must outrun the section's budget",
        );
        (keyed.into_iter().map(|(_, tx)| tx).collect(), claims)
    }

    /// A claim against `ROOT` at `height`, answering absent for `keys`,
    /// with a real proof of it.
    fn bundle_at(height: u64, keys: &[u8]) -> StateClaim {
        let asked: Vec<SubstateKey> = keys
            .iter()
            .map(|seed| test_utils::test_key(*seed))
            .collect();
        test_utils::proven_claim(ShardId::leaf(1, 0), height, &[], &asked)
    }

    /// The section is bound to the header's root and held to one form:
    /// ascending without repeats, every bundle naming something. A
    /// second form of the same answers, or a root that does not commit
    /// them, is refused.
    #[test]
    fn a_state_proof_section_is_held_to_its_root_and_form() {
        let held = |bundles: Vec<StateClaim>, root: StateClaimsRoot| {
            let block = block_with_state_claims(bundles, root);
            sections_bound(&block).and_then(|()| admit(&plain(), &block))
        };
        let bundles = vec![bundle_at(3, &[1]), bundle_at(4, &[2, 3])];
        let root = StateClaimsRoot::over(&bundles);
        assert!(held(bundles.clone(), root).is_ok());

        let err = held(bundles.clone(), StateClaimsRoot::ZERO)
            .expect_err("a root that does not commit the bundles is refused");
        assert!(err.contains("body root"), "{err}");

        let reversed: Vec<StateClaim> = bundles.iter().rev().cloned().collect();
        let err = held(reversed.clone(), StateClaimsRoot::over(&reversed))
            .expect_err("out of order is a second form of the same section");
        assert!(err.contains("repeats or precedes"), "{err}");

        let repeated = vec![bundle_at(3, &[1]), bundle_at(3, &[1])];
        let err = held(repeated.clone(), StateClaimsRoot::over(&repeated))
            .expect_err("a repeated bundle is refused");
        assert!(err.contains("repeats or precedes"), "{err}");

        let empty = vec![StateClaim {
            cells: Capped::empty(),
            ..bundle_at(3, &[1])
        }];
        let err = held(empty.clone(), StateClaimsRoot::over(&empty))
            .expect_err("a bundle naming no key is refused");
        assert!(err.contains("empty"), "{err}");
    }

    /// A claim is checked from the block alone: one whose proof bears
    /// out every reading under its anchor's root is admitted, and one
    /// whose proof reconstructs another root, speaks for another
    /// shard's tree, carries a key the claim does not read, or
    /// disagrees with a reading is refused. A proof bit flipped fails
    /// the header's root before the claim is walked, and the sealed
    /// form keeps the claims and their root.
    #[test]
    fn a_state_claim_is_checked_from_the_block() {
        let held = |bundles: Vec<StateClaim>| {
            let root = StateClaimsRoot::over(&bundles);
            let block = block_with_state_claims(bundles, root);
            sections_bound(&block).and_then(|()| admit(&plain(), &block))
        };
        let (present, absent) = (test_utils::test_key(1), test_utils::test_key(2));
        let claim =
            test_utils::proven_claim(ShardId::leaf(1, 0), 3, &[present], &[present, absent]);
        assert!(held(vec![claim.clone()]).is_ok());

        let mut other_root = claim.clone();
        other_root.anchor.state_root = StateRoot::from_raw(Hash::from_bytes(b"another"));
        let err = held(vec![other_root]).expect_err("a proof of another root is refused");
        assert!(err.contains("does not prove"), "{err}");

        let mut other_shard = claim.clone();
        other_shard.anchor.shard = ShardId::leaf(1, 1);
        let err = held(vec![other_shard]).expect_err("a proof of another shard's tree is refused");
        assert!(err.contains("does not prove"), "{err}");

        let extra = StateClaim::new(
            claim.anchor,
            [(present, claim.reading(present).unwrap())],
            claim.proof.clone(),
        );
        let err = held(vec![extra]).expect_err("a proof claiming a key the claim does not read");
        assert!(err.contains("does not prove"), "{err}");

        let mut disagreeing = claim.clone();
        disagreeing.cells = Capped::new(vec![
            (present, Inclusion::Absent.into()),
            (absent, Inclusion::Absent.into()),
        ])
        .expect("two cells");
        let err = held(vec![disagreeing]).expect_err("a reading the proof does not bear out");
        assert!(err.contains("does not prove"), "{err}");

        let mut flipped = claim.clone();
        let mut bytes = flipped.proof.as_bytes().to_vec();
        bytes[0] ^= 0x80;
        flipped.proof = MerkleInclusionProof::new(bytes);
        let block = block_with_state_claims(
            vec![flipped],
            StateClaimsRoot::over(std::slice::from_ref(&claim)),
        );
        let err = sections_bound(&block)
            .expect_err("a proof bit flipped under the honest root fails the root");
        assert!(err.contains("body root"), "{err}");

        let live = block_with_state_claims(vec![claim.clone()], StateClaimsRoot::over(&[claim]));
        let sealed = live.clone().into_sealed();
        assert_eq!(sealed.state_claims(), live.state_claims());
        assert!(sections_bound(&sealed).is_ok());
        assert!(admit(&plain(), &sealed).is_ok());
    }

    /// The section's order rule: claims ascend by anchor, and claims at
    /// one anchor carry disjoint keys in ascending order.
    #[test]
    fn the_claim_order_rule_has_three_cases() {
        let held = |bundles: Vec<StateClaim>| {
            let root = StateClaimsRoot::over(&bundles);
            let block = block_with_state_claims(bundles, root);
            sections_bound(&block).and_then(|()| admit(&plain(), &block))
        };
        let key = test_utils::test_key;
        let at = |height: u64, asked: &[SubstateKey]| {
            test_utils::proven_claim(ShardId::leaf(1, 0), height, &[key(1), key(3)], asked)
        };
        assert!(
            held(vec![at(3, &[key(1), key(2)]), at(3, &[key(3), key(4)])]).is_ok(),
            "disjoint ascending claims at one anchor are admitted",
        );
        let err = held(vec![at(3, &[key(1), key(2)]), at(3, &[key(2), key(3)])])
            .expect_err("two claims at one anchor reading one key are refused");
        assert!(err.contains("repeats or precedes"), "{err}");
        let err = held(vec![at(3, &[key(1), key(2)]), at(3, &[key(1)])])
            .expect_err("a claim at one anchor below the last key is refused");
        assert!(err.contains("repeats or precedes"), "{err}");
        let err = held(vec![at(4, &[key(1)]), at(3, &[key(2)])])
            .expect_err("claims at two anchors out of order are refused");
        assert!(err.contains("repeats or precedes"), "{err}");
    }

    /// The section is spent by the byte, proof included: the claim that
    /// takes the weight past the budget is refused, however few claims
    /// stand before it.
    #[test]
    fn a_claims_section_past_its_budget_is_refused() {
        let (leaves, wide) = wide_claims(ShardId::leaf(1, 0));
        let mut fold = StateClaimsFold::default();
        let mut carried = 0usize;
        let mut refused = None;
        for claim in &wide {
            match StateClaimsSection::admit(&plain().ctx(), &mut fold, claim) {
                Ok(()) => carried += 1,
                Err(err) => {
                    refused = Some(err);
                    break;
                }
            }
        }
        let err = refused.expect("the wide claims outrun the budget");
        assert!(err.contains("over the section's budget"), "{err}");
        assert!(
            carried > 0 && carried < wide.len(),
            "{carried} of {} carried",
            wide.len()
        );
        assert!(state_claims_admit_block(fold.weight));
        assert!(!state_claims_admit_block(
            fold.weight + wide[carried].wire_weight()
        ));
        drop(leaves);
    }

    /// A block's claims are held to the section's budget, and its
    /// claims that are not verdict claims to their own share of it. So
    /// a block whose other claims fill their share carries verdict
    /// claims in the rest, to within a claim of the bytes only they
    /// spend, and a block with no other claim carries verdict claims
    /// to within a claim of the whole. A claim more is refused, and the
    /// refusal names the bound it broke.
    #[test]
    fn a_block_is_held_to_the_section_and_its_other_claims_to_their_share() {
        let shard = ShardId::leaf(1, 0);
        let (_, wide) = wide_claims_at(shard, 3);
        let (_, heard) = verdict_claims_at(shard, 4);
        let weight =
            |claims: &[StateClaim]| claims.iter().map(StateClaim::wire_weight).sum::<usize>();
        let fill = |claims: &[StateClaim], room: usize| {
            (0..=claims.len())
                .rev()
                .find(|count| weight(&claims[..*count]) <= room)
                .expect("no claim fits any room")
        };
        let others = fill(&wide, MAX_STATE_CLAIMS_BYTES);
        let beside = fill(&heard, MAX_CLAIMS_BYTES - weight(&wide[..others]));
        let alone = fill(&heard, MAX_CLAIMS_BYTES);
        assert!(
            (1..wide.len()).contains(&others)
                && beside >= 1
                && (beside + 1..heard.len()).contains(&alone),
            "each fixture fills its room and outruns it",
        );
        assert!(
            weight(&heard[..=beside]) > MAX_VERDICT_CLAIMS_BYTES,
            "beside a full share of other claims the verdict claims ride to within a claim of \
             the bytes only they spend",
        );
        assert!(
            weight(&heard[..alone]) > MAX_STATE_CLAIMS_BYTES,
            "and with no other claim, well past them",
        );
        let held = |others: usize, verdicts: usize| {
            let claims: Vec<StateClaim> = wide[..others]
                .iter()
                .chain(&heard[..verdicts])
                .cloned()
                .collect();
            let root = StateClaimsRoot::over(&claims);
            let block = block_with_state_claims(claims, root);
            sections_bound(&block).and_then(|()| admit(&plain(), &block))
        };
        assert_eq!(held(others, beside), Ok(()), "the section full");
        assert_eq!(held(others, 0), Ok(()));
        assert_eq!(held(0, alone), Ok(()), "verdict claims alone fill it");

        let section = format!("over the section's budget of {MAX_CLAIMS_BYTES}");
        let inside = format!("over the section's budget of {MAX_STATE_CLAIMS_BYTES} for them");
        let err = held(others, beside + 1).expect_err("one verdict claim past the section");
        assert!(err.contains(&section), "{err}");
        let err = held(0, alone + 1).expect_err("and with no other claim beside them");
        assert!(err.contains(&section), "{err}");
        let err = held(others + 1, 0).expect_err("one other claim past their share");
        assert!(
            err.contains("not verdict claims") && err.contains(&inside),
            "{err}"
        );
        let err = held(others + 1, beside).expect_err("and with verdict claims beside it");
        assert!(err.contains(&inside), "{err}");
    }

    /// A block carries no more claims that are not verdict claims than
    /// their count, and verdict claims in the places past it.
    #[test]
    fn a_block_is_held_to_the_count_of_its_other_claims() {
        let shard = ShardId::leaf(1, 0);
        let mut keys: Vec<SubstateKey> = (0..=u8::MAX)
            .flat_map(|at| [0x30, 0x31].map(|owner| (owner, at)))
            .map(|(owner, at)| SubstateKey {
                owner: test_utils::test_prefix(owner),
                local: LocalKey([at; 16]),
            })
            .collect();
        keys.sort_unstable();
        keys.truncate(MAX_STATE_CLAIMS_PER_BLOCK + 1);
        let single: Vec<StateClaim> = keys
            .iter()
            .map(|key| test_utils::proven_claim(shard, 3, &keys, std::slice::from_ref(key)))
            .collect();
        let (_, heard) = verdict_claims_at(shard, 4);
        let held = |others: usize, verdicts: usize| {
            let claims: Vec<StateClaim> = single[..others]
                .iter()
                .chain(&heard[..verdicts])
                .cloned()
                .collect();
            let root = StateClaimsRoot::over(&claims);
            let block = block_with_state_claims(claims, root);
            sections_bound(&block).and_then(|()| admit(&plain(), &block))
        };
        assert_eq!(held(MAX_STATE_CLAIMS_PER_BLOCK, 2), Ok(()));
        for verdicts in [0, 2] {
            let err = held(MAX_STATE_CLAIMS_PER_BLOCK + 1, verdicts)
                .expect_err("one claim past the count");
            assert!(
                err.contains("that are not verdict claims a block carries"),
                "{err}"
            );
        }
    }

    /// The figures of a name reaching one route under each departed
    /// half, so a record against either half may name it.
    fn named(tx_hash: TxHash) -> UnsettledTx {
        let route = |tag: u8| RoutePrefix::of(Address::new([tag; 31], AddressClass::Principal));
        UnsettledTx {
            tx_hash,
            deadline: Deadline::of(WeightedTimestamp::from_millis(900)),
            charged: 11,
            charge: stub_abort_charge(11),
            committed: CommittedAt {
                height: BlockHeight::new(1),
                anchor: WeightedTimestamp::ZERO,
                committee_anchor: WeightedTimestamp::ZERO,
            },
            reach: Capped::from_array([route(0x00), route(0xC0)]),
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
        sections_bound(block).and_then(|()| admit(&after_departures(), block))
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
        assert!(err.contains("body root"), "{err}");
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

    /// The departures a block's anchored window attests are the ones the
    /// schedule's walk over its retained windows finds, while every
    /// terminal record stands: the same shards, the same cuts, and the
    /// same evidence verdicts, open handoff or stamped.
    #[test]
    fn departures_read_off_the_window_equal_the_schedule_walk() {
        use hyperscale_types::{Epoch, WindowLookup};

        let (left, right) = ShardId::ROOT.children();
        let (survivors_left, survivors_right) = (left.children(), right.children());
        let survivors = [
            survivors_left.0,
            survivors_left.1,
            survivors_right.0,
            survivors_right.1,
        ];
        for handoff in [None, Some(Epoch::new(1))] {
            let schedule = departures(&[left, right], &survivors, handoff);
            let windows = schedule.windows();
            for ms in [DEPARTURE_CUT_MS + 1, DEPARTURE_CUT_MS + 500, 5_500, 15_500] {
                let at = WeightedTimestamp::from_millis(ms);
                let WindowLookup::Window(window) = schedule.lookup(at) else {
                    panic!("the fixture holds every window it anchors in");
                };
                let mut read: Vec<_> = window.departures(windows).collect();
                let mut walked: Vec<_> = schedule.departures_at(at).collect();
                read.sort_unstable_by_key(|(shard, _)| shard.inner());
                walked.sort_unstable_by_key(|(shard, _)| shard.inner());
                assert_eq!(read, walked, "at {ms}");
                assert_eq!(read.len(), 2);
                for shard in [left, right, survivors[0]] {
                    assert_eq!(
                        window.terminal_cut(shard, windows),
                        schedule.terminal_cut_for_shard(shard, at),
                        "{shard:?} at {ms}"
                    );
                    assert_eq!(
                        window.evidence_readable(shard, at, windows),
                        schedule.terminal_evidence_readable(shard, at),
                        "{shard:?} at {ms}"
                    );
                }
            }
        }
    }

    /// Once a departed shard's terminal record has dropped from the
    /// window a block is anchored in, a record naming that departure is
    /// refused alike by a replica that still retains the window its chain
    /// ended in and by one that has evicted it: the anchored window is
    /// the whole answer.
    #[test]
    fn a_record_after_its_boundary_drops_is_refused_alike() {
        use std::collections::BTreeMap;

        use hyperscale_types::Epoch;

        let (left, right) = ShardId::ROOT.children();
        let (survivors_left, survivors_right) = (left.children(), right.children());
        let mut deep = departures(
            &[left, right],
            &[
                survivors_left.0,
                survivors_left.1,
                survivors_right.0,
                survivors_right.1,
            ],
            None,
        );
        let dropped = Arc::new((**deep.head()).clone().with_boundaries(BTreeMap::new()));
        for epoch in 6..=20u64 {
            deep.insert(Epoch::new(epoch), Arc::clone(&dropped));
        }
        deep.set_head(Arc::clone(&dropped));
        let mut shallow = deep.clone();
        shallow.evict_below(Epoch::new(6));

        let records = vec![verdict(left, &[1])];
        let block = block_with_verdicts(records.clone(), AbandonmentRoot::over(&records));
        let refusal = |schedule| {
            let mut against = Against::schedule(topology_snapshot(), schedule);
            against.anchor = WeightedTimestamp::from_millis(7_500);
            against.local_shard = survivors_right.0;
            admit(&against, &block).unwrap_err()
        };
        let from_deep = refusal(deep);
        assert!(from_deep.contains("does not attest"), "{from_deep}");
        assert_eq!(from_deep, refusal(shallow));
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
            reach: Capped::new(
                (0..6u8)
                    .map(|at| {
                        RoutePrefix::from(Address::new([at * 0x30; 31], AddressClass::Component))
                    })
                    .collect(),
            )
            .expect("a reach written out in a test"),
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

    /// The running totals are validity conditions, not hints: a header
    /// claiming more than its parent's plus what this block carries is
    /// rejected, and the honest claim passes. A block with no
    /// certificates consumes nothing and one with no transactions
    /// reserves nothing, so either must repeat its parent's total rather
    /// than reset.
    #[test]
    fn a_header_cannot_overstate_the_load_of_its_shard() {
        let reserved = DeclaredWork {
            compute: 64,
            ..DeclaredWork::ZERO
        };
        let parent = ShardLoad::ZERO.advance(500, reserved, None);
        // The fixture carries no certificates and no transactions, so the
        // honest claim is an empty chain's totals with the count at one.
        let honest = block_with_transactions(BlockHeight::new(1), Vec::new());
        assert_eq!(honest.charged(), 0);
        assert_eq!(
            honest.header().load(),
            ShardLoad::ZERO.advance(0, DeclaredWork::ZERO, None)
        );

        // Claiming zero against a parent that has consumed 500 understates,
        // and is refused just as an overstatement is.
        let err = validate_block_work(&honest, Some(parent), DeclaredWork::ZERO).unwrap_err();
        assert!(err.contains("cumulative fees"), "{err}");

        // The declared total is held to the same rule, and on its own:
        // a parent that reserved something and a block that reserves
        // nothing must still repeat the parent's vector.
        let carried = ShardLoad::ZERO.advance(0, reserved, None);
        let err = validate_block_work(&honest, Some(carried), DeclaredWork::ZERO).unwrap_err();
        assert!(err.contains("has reserved"), "{err}");

        // The matching claim passes.
        assert!(validate_block_work(&honest, Some(ShardLoad::ZERO), DeclaredWork::ZERO).is_ok());

        // An unresolvable parent load abstains rather than rejecting.
        assert!(validate_block_work(&honest, None, DeclaredWork::ZERO).is_ok());
    }

    /// The block count is held to the same rule as the totals it is the
    /// denominator of.
    ///
    /// The beacon differences two of these records to reach the capacity
    /// those blocks had, so a count a proposer chose freely is a
    /// utilization it chose freely: frozen, the shard reads as saturated
    /// however little it carried; inflated, it drags the network-wide
    /// ratio every price row steps on toward zero.
    #[test]
    fn a_header_cannot_choose_the_count_its_utilization_divides_by() {
        let parent = ShardLoad::ZERO.advance(0, DeclaredWork::ZERO, None);

        // Frozen at the parent's, so an epoch of blocks differences to no
        // capacity at all.
        let frozen = block_claiming(BlockHeight::new(2), parent);
        let err = validate_block_work(&frozen, Some(parent), DeclaredWork::ZERO).unwrap_err();
        assert!(err.contains("has committed"), "{err}");

        // And inflated, which is the same freedom pointed the other way.
        let inflated = block_claiming(
            BlockHeight::new(2),
            ShardLoad {
                blocks: 1_000_000,
                ..parent
            },
        );
        let err = validate_block_work(&inflated, Some(parent), DeclaredWork::ZERO).unwrap_err();
        assert!(err.contains("has committed"), "{err}");

        // One on from the parent is the only claim that passes.
        let honest = block_claiming(
            BlockHeight::new(2),
            parent.advance(0, DeclaredWork::ZERO, None),
        );
        assert!(validate_block_work(&honest, Some(parent), DeclaredWork::ZERO).is_ok());
    }

    /// An abort is charged like anything else, so a block settling
    /// nothing but aborts still advances its chain's fee total.
    ///
    /// The price is owed on every outcome — the network routed,
    /// provisioned and ran a batch for the transaction whichever verdict
    /// it reached — so an emission weight read off these totals must not
    /// go to zero for a shard whose epoch went badly.
    #[test]
    fn a_block_of_nothing_but_aborts_still_advances_the_fee_total() {
        let charged = 4_096u128;
        let aborted = test_utils::finalization_of(
            BlockHeight::new(1),
            vec![
                TxOutcome::new(
                    TxHash::from(Hash::from_bytes(b"one")),
                    ExecutionOutcome::Failed,
                )
                .charging(charged),
                TxOutcome::new(
                    TxHash::from(Hash::from_bytes(b"two")),
                    ExecutionOutcome::Failed,
                )
                .charging(charged),
            ],
        );
        let block = block_with_certificates(BlockHeight::new(1), vec![Arc::new(aborted)]);
        assert_eq!(
            block.charged(),
            charged * 2,
            "every outcome carries its charge, whatever it decided"
        );

        // The header has to claim exactly that, and nothing less.
        let parent = ShardLoad::ZERO;
        let err = validate_block_work(&block, Some(parent), DeclaredWork::ZERO)
            .expect_err("the fixture header claims its parent's total unchanged");
        assert!(err.contains("cumulative fees"), "{err}");
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
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::new(wrapped).expect("a list written out in a test")),
            provisions: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
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

    /// The shard [`after_departures`] admits as, whose ticks its blocks
    /// carry.
    fn survivor() -> ShardId {
        ShardId::ROOT.children().1.children().0
    }

    /// [`finalization_at`] for a tick of [`survivor`].
    fn survivor_finalization_at(height: u64) -> Arc<Finalization> {
        Arc::new(make_finalization_on(
            survivor(),
            BlockHeight::new(height),
            TxHash::from(Hash::from_bytes(
                &[u8::try_from(height).unwrap_or(u8::MAX); 32],
            )),
            TransactionDecision::Accept,
        ))
    }

    /// [`finalization_over`] for a tick of [`survivor`].
    fn survivor_finalization_over(height: u64, tx_hash: TxHash) -> Arc<Finalization> {
        Arc::new(make_finalization_on(
            survivor(),
            BlockHeight::new(height),
            tx_hash,
            TransactionDecision::Aborted,
        ))
    }

    fn no_resolutions(block: &Block, dedup_index: CommitDedupIndex) -> Result<(), String> {
        let mut against = after_departures();
        against.dedup = dedup_index;
        admit_settling(&mut against, block)
    }

    #[test]
    fn validate_no_duplicate_resolutions_accepts_empty_block() {
        let block = block_with_certificates(BlockHeight::new(5), vec![]);
        assert!(no_resolutions(&block, CommitDedupIndex::new()).is_ok());
    }

    #[test]
    fn validate_no_duplicate_resolutions_accepts_unique() {
        let block = block_with_certificates(BlockHeight::new(5), vec![survivor_finalization_at(1)]);
        assert!(no_resolutions(&block, CommitDedupIndex::new()).is_ok());
    }

    /// The same certificate again is refused on its identity, which is
    /// the rule that answers whether or not its members reach a verdict.
    /// The transaction rule below covers the other shape — a *different*
    /// certificate reaching a second verdict for one name.
    #[test]
    fn validate_no_duplicate_resolutions_rejects_retention_dup() {
        let fw = survivor_finalization_at(1);
        let block = block_with_certificates(BlockHeight::new(6), vec![Arc::clone(&fw)]);
        let mut dedup_index = CommitDedupIndex::new();
        dedup_index
            .register_committed_certs(&[Arc::new((*fw).clone().into())], WeightedTimestamp::ZERO);
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
        let fw = Arc::new(make_leg_finalization_on(
            survivor(),
            BlockHeight::new(1),
            TxHash::from(Hash::from_bytes(b"retired")),
        ));
        assert_eq!(fw.deciding_tx_hashes().count(), 0);
        let block = block_with_certificates(BlockHeight::new(6), vec![Arc::clone(&fw)]);
        let mut dedup_index = CommitDedupIndex::new();
        dedup_index
            .register_committed_certs(&[Arc::new((*fw).clone().into())], WeightedTimestamp::ZERO);
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
        let settled = survivor_finalization_at(1);
        let tx_hash = settled
            .tx_hashes()
            .next()
            .expect("a tick names its members");
        let mut dedup_index = CommitDedupIndex::new();
        dedup_index.register_committed_certs(
            &[Arc::new((*settled).clone().into())],
            WeightedTimestamp::ZERO,
        );

        let abandoned = survivor_finalization_over(9, tx_hash);
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
        let settled = survivor_finalization_at(1);
        let tx_hash = settled
            .tx_hashes()
            .next()
            .expect("a tick names its members");
        let mut dedup_index = CommitDedupIndex::new();
        dedup_index.register_committed_certs(
            &[Arc::new((*settled).clone().into())],
            WeightedTimestamp::ZERO,
        );

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
        let settled = survivor_finalization_at(1);
        let tx_hash = settled
            .tx_hashes()
            .next()
            .expect("a tick names its members");
        let block = Block::Live {
            header: header_at_height(BlockHeight::new(6), 100_000),
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::from_array([Arc::new((*settled).clone().into())])),
            provisions: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Capped::from_array([AbandonmentRecord::new(
                ShardId::ROOT.children().0,
                WeightedTimestamp::from_millis(DEPARTURE_CUT_MS),
                [named(tx_hash)],
            )])),
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
        let settled = survivor_finalization_at(1);
        let tx_hash = settled
            .tx_hashes()
            .next()
            .expect("a tick names its members");
        let block = block_with_certificates(
            BlockHeight::new(6),
            vec![settled, survivor_finalization_over(9, tx_hash)],
        );
        let err = no_resolutions(&block, CommitDedupIndex::new()).unwrap_err();
        assert!(
            err.contains("resolved twice within the same block"),
            "{err}"
        );
    }

    /// The one member a determined half of [`block_settling`] at
    /// `height` settles.
    fn settled_at(height: u64) -> TxHash {
        TxHash::from(Hash::from_bytes(&height.to_be_bytes()))
    }

    /// Admit `block`, a block of [`block_settling`], against `against`
    /// holding the rows its determined halves settle.
    fn admit_settling(against: &mut Against, block: &Block) -> Result<(), String> {
        against.holding_settled(block.certificates());
        admit(against, block)
    }

    /// A block settling `determined` (as determined halves), each over
    /// its one member [`settled_at`] its height, and `legs` (as legs
    /// halves).
    fn block_settling(determined: &[u64], legs: &[u64]) -> Block {
        block_settling_ticks_of(ShardId::ROOT, determined, legs)
    }

    /// [`block_settling`] over ticks of `shard`.
    fn block_settling_ticks_of(shard: ShardId, determined: &[u64], legs: &[u64]) -> Block {
        use hyperscale_types::{
            AggregateSignature, ConsensusReceipt, ExecutionCertificate, GlobalReceiptRoot,
            SignerBitfield, StoredReceipt, TickHalf, TickId, compute_global_receipt_root,
        };
        let half = |height: u64, half: TickHalf| {
            let tick_id = TickId::new(shard, BlockHeight::new(height));
            let outcomes: Vec<TxOutcome> = if half == TickHalf::Determined {
                vec![alone(settled_at(height))]
            } else {
                Vec::new()
            };
            let receipts: Vec<StoredReceipt> = outcomes
                .iter()
                .map(|outcome| {
                    StoredReceipt::new(
                        outcome.tx_hash(),
                        Arc::new(ConsensusReceipt::Succeeded {
                            receipt_hash: GlobalReceiptHash::ZERO,
                            writes: StateWrites::default(),
                            beacon_witness_events: Capped::empty(),
                            events: Capped::empty(),
                        }),
                    )
                })
                .collect();
            let root = if outcomes.is_empty() {
                GlobalReceiptRoot::ZERO
            } else {
                compute_global_receipt_root(&outcomes)
            };
            let ec = ExecutionCertificate::new(
                tick_id,
                WeightedTimestamp::from_millis(height),
                root,
                Capped::new(outcomes).expect("a list written out in a test"),
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            );
            Arc::new(Verifiable::from(Finalization::new(
                tick_id,
                half,
                Some(Arc::new(ec)),
                Capped::new(receipts).expect("a list written out in a test"),
            )))
        };
        let certificates: Vec<_> = determined
            .iter()
            .map(|h| half(*h, TickHalf::Determined))
            .chain(legs.iter().map(|h| half(*h, TickHalf::Legs)))
            .collect();
        Block::Live {
            header: header_at_height(BlockHeight::new(100), 100_000),
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(
                Capped::new(certificates).expect("a list written out in a test"),
            ),
            provisions: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
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
        let err = admit_settling(&mut above_frontier(2), &block_settling(&[1], &[])).unwrap_err();
        assert!(err.contains("at or below the frontier"), "{err}");
    }

    /// Determined halves within one block must rise, or the receipts
    /// apply in the order the block lists them and invert inside it. The
    /// later tick listed first settles past the earlier one, which still
    /// owes its half.
    #[test]
    fn determined_halves_must_rise_within_a_block() {
        let err =
            admit_settling(&mut above_frontier(3), &block_settling(&[6, 4], &[])).unwrap_err();
        assert!(err.contains("still owes"), "{err}");
        assert!(admit_settling(&mut above_frontier(3), &block_settling(&[4, 6], &[])).is_ok());
    }

    /// Admission above `frontier` with the chain owing determined
    /// halves for `owed`: a tick row at each, flagged as owing its half.
    fn owing(frontier: u64, owed: &[u64]) -> Against {
        use hyperscale_storage::TickRow;
        let mut against = above_frontier(frontier);
        for &height in owed {
            against.members.ticks.insert(
                BlockHeight::new(height),
                TickRow {
                    determined_unsettled: true,
                    ..TickRow::default()
                },
            );
        }
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
        let err = admit_settling(&mut owing(3, &[4]), &block_settling(&[6], &[])).unwrap_err();
        assert!(err.contains("still owes"), "{err}");
    }

    /// The block that carries both carries them in order, and the owed
    /// tick is owed no longer once its own half is admitted ahead of the
    /// later one.
    #[test]
    fn a_block_carrying_the_owed_half_first_carries_the_later_one_too() {
        assert!(admit_settling(&mut owing(3, &[4]), &block_settling(&[4, 6], &[])).is_ok());
    }

    /// The rule measures the gap and nothing else: a tick owed at or
    /// below the frontier is already settled or already refused, and one
    /// above the half being admitted has not been skipped.
    #[test]
    fn only_a_tick_between_the_frontier_and_the_half_is_a_skip() {
        assert!(admit_settling(&mut owing(4, &[4]), &block_settling(&[6], &[])).is_ok());
        assert!(admit_settling(&mut owing(3, &[9]), &block_settling(&[6], &[])).is_ok());
    }

    /// A legs half waits for every determined half the chain owes at or
    /// below its tick. Its members were judged over a baseline folding
    /// those halves' unsettled output, so settling ahead of one lands a
    /// debit on a credit state does not yet hold.
    #[test]
    fn a_legs_half_does_not_settle_ahead_of_a_determined_credit() {
        // An earlier tick still owes its determined half.
        let earlier = admit_settling(&mut owing(3, &[4]), &block_settling(&[], &[5]));
        assert!(
            earlier.is_err(),
            "the legs half of tick 5 is admitted while tick 4 owes its determined half"
        );
        // The half's own tick owes one.
        let same = admit_settling(&mut owing(3, &[5]), &block_settling(&[], &[5]));
        assert!(
            same.is_err(),
            "the legs half of tick 5 is admitted while tick 5 owes its determined half"
        );
        // The block that settles the owed half first carries the legs
        // half behind it.
        assert!(admit_settling(&mut owing(3, &[4]), &block_settling(&[4], &[5])).is_ok());
        assert!(admit_settling(&mut owing(3, &[5]), &block_settling(&[5], &[5])).is_ok());
        // Settling one owed half does not release a legs half past
        // another.
        let err = admit_settling(&mut owing(3, &[4, 5]), &block_settling(&[4], &[5])).unwrap_err();
        assert!(err.contains("still owes"), "{err}");
    }

    /// The legs half of the tick at `height` accepting `tx`, its effects
    /// receipt leaving `writes`.
    fn legs_leaving(height: u64, tx: TxHash, writes: StateWrites) -> Finalization {
        let unhashed = ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            writes,
            beacon_witness_events: Capped::empty(),
            events: Capped::empty(),
        };
        let receipt_hash = receipt_hash_of(&unhashed, true).expect("a projected success");
        let ConsensusReceipt::Succeeded { writes, .. } = unhashed else {
            unreachable!("built a success")
        };
        Finalization::accepting(
            TickId::new(ShardId::ROOT, BlockHeight::new(height)),
            Capped::from_array([StoredReceipt::new(
                tx,
                Arc::new(ConsensusReceipt::Succeeded {
                    receipt_hash,
                    writes,
                    beacon_witness_events: Capped::empty(),
                    events: Capped::empty(),
                }),
            )]),
        )
    }

    /// What `cell` holds once a store holding nothing commits `block`,
    /// its finalizations settled in the order it lists them.
    fn cell_after_committing(block: &Block, cell: SubstateKey) -> Option<Vec<u8>> {
        let storage = SimShardStorage::default();
        commit_settled_at(
            &storage,
            &Arc::new(Verified::new_unchecked_for_test(test_utils::certify(
                block.clone(),
                0,
            ))),
            &[],
            &[],
            &BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
        );
        storage.cell(cell)
    }

    /// The same wait keeps an exclusive write. A receipt states a cell's
    /// value outright and settlement keeps the last one stated, so a legs
    /// half settled ahead of an earlier tick's determined half writing
    /// the same cell has its value replaced by the earlier tick's: no
    /// debit overruns and nothing halts, the later write is just gone.
    #[test]
    fn a_later_write_is_not_erased_by_an_earlier_determined_half() {
        let cell = state_key(7, 1);
        let stating = |value: u8| make_state_writes(7, 1, vec![value]);
        let earlier = Arc::new(test_utils::make_finalization_leaving(
            BlockHeight::new(4),
            TxHash::from(Hash::from_bytes(b"earlier writer")),
            stating(4),
        ));
        let member = TxHash::from(Hash::from_bytes(b"later writer"));
        let later = Arc::new(legs_leaving(5, member, stating(5)));
        let carrying = |halves: &[&Arc<Finalization>]| {
            block_with_certificates(
                BlockHeight::new(1),
                halves.iter().copied().map(Arc::clone).collect(),
            )
        };

        // Tick 4 owes its determined half, and tick 5 holds the later
        // writer stated, for a legs half to settle.
        let mut against = owing(3, &[4]);
        let receipt = later.settled_receipts().expect("a legs half names")[0].1;
        against.members.members.insert(
            member,
            member_row(
                member,
                RowState::Stated {
                    tick: BlockHeight::new(5),
                    receipt,
                },
            ),
        );

        // The legs half is refused alone, which would leave tick 4's
        // half to land on it in a later block.
        let err = admit(&against, &carrying(&[&later])).unwrap_err();
        assert!(err.contains("still owes"), "{err}");

        // And ahead of that half within one block, the order that
        // commits tick 4's value over tick 5's.
        let inverted = carrying(&[&later, &earlier]);
        let err = admit(&against, &inverted).unwrap_err();
        assert!(err.contains("still owes"), "{err}");
        assert_eq!(cell_after_committing(&inverted, cell), Some(vec![4]));

        // Behind it the block is admitted, and the cell commits at what
        // the later tick wrote.
        let ordered = carrying(&[&earlier, &later]);
        assert_eq!(admit_settling(&mut against, &ordered), Ok(()));
        assert_eq!(cell_after_committing(&ordered, cell), Some(vec![5]));
    }

    /// A legs half at or below the frontier waits on nothing, whatever
    /// the chain owes above it or is still listed as owing below: every
    /// determined half up to its tick has settled.
    #[test]
    fn a_legs_half_at_or_below_the_frontier_is_admitted() {
        assert!(admit_settling(&mut owing(7, &[9]), &block_settling(&[], &[5])).is_ok());
        assert!(admit_settling(&mut owing(7, &[5]), &block_settling(&[], &[5])).is_ok());
        assert!(admit_settling(&mut owing(7, &[5, 9]), &block_settling(&[], &[7])).is_ok());
        // A tick owed above the half holds a later half and not this one.
        assert!(admit_settling(&mut owing(3, &[9]), &block_settling(&[], &[5])).is_ok());
    }

    /// A parent whose frontier cannot be read leaves the order unjudged
    /// for either half; the vote on such a block is skipped where its
    /// header's frontier is checked.
    #[test]
    fn an_unreadable_frontier_judges_no_half() {
        let mut against = owing(3, &[4]);
        against.parent_settled_frontier = None;
        assert!(admit_settling(&mut against, &block_settling(&[], &[5])).is_ok());
        assert!(admit_settling(&mut against, &block_settling(&[6], &[])).is_ok());
    }

    /// What a proposer selects, a voter reading the same rows admits in
    /// the order selected: a legs half offered ahead of the determined
    /// half it waits on is left for a later block, and one offered behind
    /// it rides.
    #[test]
    fn a_voter_admits_the_halves_a_proposer_selects() {
        let mut against = owing(3, &[4, 6]);
        against.holding_settled(block_settling(&[4, 6], &[]).certificates());
        let ctx = against.ctx();
        let offered = |determined: &[u64], legs: &[u64]| {
            block_settling(determined, legs).certificates().to_vec()
        };
        let halves = |selected: &[Arc<Verifiable<Finalization>>]| -> Vec<(u64, bool)> {
            selected
                .iter()
                .map(|fw| (fw.tick_id().block_height().inner(), fw.is_determined()))
                .collect()
        };

        // Tick 4's two halves, then tick 6's with its legs half first.
        let mut candidates = offered(&[4], &[4]);
        let mut later = offered(&[6], &[6]);
        later.reverse();
        candidates.extend(later);
        let selected = select_finalizations(&ctx, &mut FinalizationsFold::from(&ctx), candidates);
        assert_eq!(halves(&selected), [(4, true), (4, false), (6, true)]);
        let mut voter = FinalizationsFold::from(&ctx);
        assert!(
            admit_all::<FinalizationsSection>(&ctx, &mut voter, selected.iter().map(unwrapped))
                .is_ok()
        );

        // A voter owing a tick the proposer's rows did not name refuses
        // the legs half the proposer selected in good faith.
        let unaware = owing(3, &[]);
        let unaware_ctx = unaware.ctx();
        let selected = select_finalizations(
            &unaware_ctx,
            &mut FinalizationsFold::from(&unaware_ctx),
            offered(&[], &[5]),
        );
        assert_eq!(halves(&selected), [(5, false)]);
        let mut voter = FinalizationsFold::from(&ctx);
        assert!(
            admit_all::<FinalizationsSection>(&ctx, &mut voter, selected.iter().map(unwrapped))
                .is_err()
        );
    }

    /// A member's success awaiting no other shard: what a determined half
    /// settles of a row.
    fn alone(tx: TxHash) -> TxOutcome {
        TxOutcome::new(tx, succeeded()).charging(0)
    }

    /// The determined half of tick 2 on a certificate attesting
    /// `outcomes` under their own root, projected to those of `kept` and
    /// carrying the receipt each of them settles.
    fn determined_projected(outcomes: Vec<TxOutcome>, kept: &[TxHash]) -> Finalization {
        determined_projected_at(2, outcomes, kept)
    }

    /// [`determined_projected`] on a certificate anchored at `anchor_ms`.
    fn determined_projected_at(
        anchor_ms: u64,
        outcomes: Vec<TxOutcome>,
        kept: &[TxHash],
    ) -> Finalization {
        use hyperscale_types::{
            ConsensusReceipt, ExecutionCertificate, StoredReceipt, TickHalf,
            compute_global_receipt_root,
        };
        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(2));
        let whole = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::from_millis(anchor_ms),
            compute_global_receipt_root(&outcomes),
            Capped::new(outcomes).expect("a list written out in a test"),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        );
        let projected = whole
            .project_to(&kept.iter().copied().collect())
            .expect("the certificate attests a kept member");
        let receipts: Vec<StoredReceipt> = projected
            .tx_outcomes()
            .iter()
            .map(|outcome| {
                StoredReceipt::new(
                    outcome.tx_hash(),
                    Arc::new(ConsensusReceipt::Succeeded {
                        receipt_hash: effects_hash(),
                        writes: StateWrites::default(),
                        beacon_witness_events: Capped::empty(),
                        events: Capped::empty(),
                    }),
                )
            })
            .collect();
        Finalization::new(
            tick_id,
            TickHalf::Determined,
            Some(Arc::new(projected)),
            Capped::new(receipts).expect("a list written out in a test"),
        )
    }

    /// Admission above a frontier of 1 over the rows tick 2 holds for
    /// its determined half: each of `standing` in flight and settled by
    /// that half alone, under the tick row owing it. A tick holding no
    /// such row has no tick row.
    fn holding_alone(standing: &[TxHash]) -> Against {
        let mut against = owing(1, &[2]);
        for &tx in standing {
            against
                .members
                .members
                .insert(tx, member_row(tx, in_flight(2, Settlement::Alone)));
        }
        if !standing.is_empty() {
            against.members.ticks.insert(
                BlockHeight::new(2),
                TickRow {
                    members: Capped::new(standing.to_vec()).expect("a list written out in a test"),
                    determined_unsettled: true,
                    awaiting: 0,
                },
            );
        }
        against
    }

    /// A determined half covers every member its tick holds for it. A
    /// tick's certificate projects to any subset of its outcomes under
    /// the same root and signature, so a half over one of the two rows a
    /// tick holds is well formed in itself: its certificate proves
    /// against the signed root, and its receipts follow from its
    /// outcomes. Admitting it carries the frontier to the tick with the
    /// other row standing, where no determined half reaches it again.
    #[test]
    fn a_determined_half_projected_to_a_subset_is_refused() {
        let (first, second) = (
            TxHash::from(Hash::from_bytes(b"first alone")),
            TxHash::from(Hash::from_bytes(b"second alone")),
        );
        let outcomes = || vec![alone(first), alone(second)];
        let whole = determined_projected(outcomes(), &[first, second]);
        let subset = determined_projected(outcomes(), &[first]);

        assert_eq!(subset.tx_hashes().collect::<Vec<_>>(), vec![first]);
        assert!(
            !subset
                .local_ec()
                .expect("its own certificate")
                .is_complete()
        );
        assert_eq!(subset.validate_against_certificates(), Ok(()));
        let wire = to_vec(&subset).expect("a half encodes");
        assert!(
            from_slice::<Finalization>(&wire).is_ok(),
            "the projection proves against the root its tick signed",
        );
        assert_ne!(subset.receipt_hash(), whole.receipt_hash());

        let against = holding_alone(&[first, second]);
        assert_eq!(settles(&against, &whole), Ok(()));
        let err = settles(&against, &subset).unwrap_err();
        assert!(
            err.contains("covers 1 members of tick 2, which holds 2 for its Determined half"),
            "{err}",
        );
    }

    /// A proposer holding a tick's complete certificate projects it to
    /// part of the tick's determined members and carries the half in a
    /// block. Every voter refuses the block, by the pre-vote check that
    /// admits the block carrying the whole half.
    #[test]
    fn a_voter_refuses_a_block_carrying_part_of_a_determined_half() {
        let (first, second) = (
            TxHash::from(Hash::from_bytes(b"first alone")),
            TxHash::from(Hash::from_bytes(b"second alone")),
        );
        let outcomes = || vec![alone(first), alone(second)];
        let carrying = |kept: &[TxHash]| {
            block_with_certificates(
                BlockHeight::new(3),
                vec![Arc::new(determined_projected(outcomes(), kept))],
            )
        };
        let against = holding_alone(&[first, second]);
        let voted = |block: &Block| validate_block_for_vote(&against.ctx(), block, None);

        assert_eq!(voted(&carrying(&[first, second])), Ok(()));
        for part in [[first], [second]] {
            let err = voted(&carrying(&part)).unwrap_err();
            assert!(
                err.contains("covers 1 members of tick 2, which holds 2 for its Determined half"),
                "{err}",
            );
            assert!(admit(&against, &carrying(&part)).is_err());
        }
    }

    /// A determined half is whole over its outcomes: every one stands
    /// over a row its tick holds for the half, and together they number
    /// those rows. A half over its rows is admitted, and so is the copy a
    /// later committee re-attested; one carrying an outcome beside them
    /// that no row holds is refused.
    #[test]
    fn a_determined_half_is_whole_over_every_outcome_it_carries() {
        let (first, second, stranger) = (
            TxHash::from(Hash::from_bytes(b"first alone")),
            TxHash::from(Hash::from_bytes(b"second alone")),
            TxHash::from(Hash::from_bytes(b"no row")),
        );
        let whole = |outcomes: Vec<TxOutcome>| {
            let names: Vec<TxHash> = outcomes.iter().map(TxOutcome::tx_hash).collect();
            determined_projected(outcomes, &names)
        };

        let rows = holding_alone(&[first, second]);
        let held = whole(vec![alone(first), alone(second)]);
        assert_eq!(settles(&rows, &held), Ok(()));
        let err = settles(
            &rows,
            &whole(vec![alone(first), alone(stranger), alone(second)]),
        )
        .unwrap_err();
        assert!(
            err.contains("does not hold for its Determined half"),
            "{err}"
        );

        let later = determined_projected_at(9, vec![alone(first), alone(second)], &[first, second]);
        let reanchored = held
            .reanchored(&Verified::new_unchecked_for_test(
                later.local_ec().expect("its own certificate").clone(),
            ))
            .expect("the same outcomes under the same root at a later anchor");
        assert_ne!(reanchored.receipt_hash(), held.receipt_hash());
        assert_eq!(settles(&rows, &reanchored), Ok(()));
    }

    /// A determined half settling no row is refused: over an outcome no
    /// row holds, and over no outcome at all.
    #[test]
    fn a_determined_half_over_no_row_is_refused() {
        use hyperscale_types::{ExecutionCertificate, GlobalReceiptRoot, TickHalf};
        let stranger = TxHash::from(Hash::from_bytes(b"no row"));
        let err = settles(
            &holding_alone(&[]),
            &determined_projected(vec![alone(stranger)], &[stranger]),
        )
        .unwrap_err();
        assert!(
            err.contains("does not hold for its Determined half"),
            "{err}"
        );

        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(2));
        let empty = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::from_millis(2),
            GlobalReceiptRoot::ZERO,
            Capped::empty(),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        );
        let none = Finalization::new(
            tick_id,
            TickHalf::Determined,
            Some(Arc::new(empty)),
            Capped::empty(),
        );
        let err = settles(&holding_alone(&[]), &none).unwrap_err();
        assert!(err.contains("settles no member of tick 2"), "{err}");
    }

    /// What stands once a block at height 3 offered `half` commits over
    /// `against`: the rows after the half folds where admission lets it
    /// ride and the rows as they were where it does not, under the
    /// frontier the block's determined halves end at, owing what the
    /// rows owe.
    fn after_offering(against: Against, half: &Finalization) -> Against {
        let (carried, frontier) = {
            let ctx = against.ctx();
            let mut fold = FinalizationsFold::from(&ctx);
            let carried = FinalizationsSection::admit(&ctx, &mut fold, half).is_ok();
            (carried, fold.frontier)
        };
        let one = [half];
        let halves: &[&Finalization] = if carried { &one } else { &[] };
        let mut later = after_committing(against, halves);
        later.parent_settled_frontier = frontier;
        later
    }

    /// How a block offered the determined half of tick 2 over `outcomes`
    /// projected to `kept` leaves a member of `rows` stranded, where it
    /// does: standing in flight for a determined half its tick no longer
    /// owes, or one the chain refuses.
    fn stranded_by(
        outcomes: &dyn Fn() -> Vec<TxOutcome>,
        rows: &[TxHash],
        kept: &[TxHash],
    ) -> Option<String> {
        let later = after_offering(holding_alone(rows), &determined_projected(outcomes(), kept));
        let standing: Vec<TxHash> = rows
            .iter()
            .copied()
            .filter(|tx| {
                later
                    .members
                    .members
                    .get(tx)
                    .is_some_and(|row| row.state == in_flight(2, Settlement::Alone))
            })
            .collect();
        if standing.is_empty() {
            return None;
        }
        let owed = later
            .members
            .ticks
            .get(&BlockHeight::new(2))
            .is_some_and(|tick| tick.determined_unsettled);
        // The half an honest replica holds, which is over every member
        // of the tick.
        let whole_names: Vec<TxHash> = outcomes().iter().map(TxOutcome::tx_hash).collect();
        let whole = settles(&later, &determined_projected(outcomes(), &whole_names));
        (!owed || whole.is_err()).then(|| {
            format!(
                "{} of {} rows stand in flight in tick 2; tick row owes its determined half: \
                 {owed}; frontier: {:?}; the whole half: {whole:?}",
                standing.len(),
                rows.len(),
                later.parent_settled_frontier.map(BlockHeight::inner),
            )
        })
    }

    /// A row a tick holds for its determined half is settled by one:
    /// while it stands in flight its tick owes the half, and the whole
    /// half is admitted. So no block leaves a member standing behind a
    /// determined half that named a tick-mate.
    #[test]
    fn a_member_left_out_of_a_determined_half_is_still_settled_by_one() {
        let (first, second) = (
            TxHash::from(Hash::from_bytes(b"first alone")),
            TxHash::from(Hash::from_bytes(b"second alone")),
        );
        let two_rows = || vec![alone(first), alone(second)];
        assert_eq!(
            [
                stranded_by(&two_rows, &[first, second], &[first, second]),
                stranded_by(&two_rows, &[first, second], &[first]),
            ],
            [None, None],
        );
    }

    /// The shard whose escrowed records the members below consume.
    const PRODUCER: ShardId = ShardId::leaf(2, 1);
    /// A second core shard, which one of them shares its verdict with.
    const SIBLING: ShardId = ShardId::leaf(2, 2);

    /// The crossing `seed`'s member consumes out of `PRODUCER`.
    fn consumed(seed: u8) -> CrossingId {
        CrossingId {
            producer: Address::new([seed; 31], AddressClass::Component),
            consumer: Address::new([seed | 0x80; 31], AddressClass::Component),
            intent: IntentHash(Hash32([seed; 32])),
            local: 0,
            output: 0,
        }
    }

    /// What a block at `height` anchored at `anchor` and naming `lines`
    /// writes to the rows.
    fn block_naming(height: u64, anchor: WeightedTimestamp, lines: Vec<TickLine>) -> MemberInputs {
        MemberInputs {
            height: BlockHeight::new(height),
            committed: anchor,
            manifest: Arc::new(Capped::new(lines).expect("a manifest's lines")),
            ..MemberInputs::still(ShardId::ROOT)
        }
    }

    /// The rows a chain holds once its tick at height 2 has run `tx`, a
    /// core member consuming `crossing` on `settlement`, beside the
    /// committed inputs holding the arrival it ran off: the member
    /// committed at height 1 on its terms, and named at height 2 by the
    /// one line the chain names over that arrival.
    fn run_in_tick_2(
        tx: TxHash,
        settlement: Settlement,
        crossing: CrossingId,
        deadline: Deadline,
    ) -> (MemberIndex, CommittedSets) {
        let (reach, awaits) = if settlement == Settlement::Shared {
            (vec![PRODUCER, SIBLING], vec![SIBLING])
        } else {
            (vec![PRODUCER], vec![])
        };
        let mut rows = MemberIndex::empty(ShardId::ROOT);
        rows.advance(&MemberInputs {
            height: BlockHeight::new(1),
            committed: WeightedTimestamp::from_millis(1_000),
            transactions: vec![(tx, deadline)],
            terms: vec![StatedTerms {
                tx,
                terms: MemberTerms {
                    staged: 0,
                    leg: false,
                    settlement,
                    declared: Capped::empty(),
                    reach: Capped::new(reach).expect("two shards"),
                    awaits: Capped::new(awaits).expect("one shard"),
                    engages: Capped::empty(),
                    crossings: Capped::from_array([crossing]),
                    waits: false,
                    charge: stub_abort_charge(1),
                    share: 0,
                    reserves: Capped::empty(),
                },
            }],
            ..MemberInputs::still(ShardId::ROOT)
        });
        let arrived = CommittedSets {
            arrived: BTreeSet::from([(crossing.record_key(&ProtocolHasher), tx)]),
            ..CommittedSets::default()
        };
        let anchor = WeightedTimestamp::from_millis(2_000);
        let (lines, missing, _) = member_lines(
            &rows,
            anchor,
            &arrived,
            &|_, _| Evidence::Live { terminating: false },
            false,
            &BTreeSet::new(),
            &BTreeMap::new(),
        );
        assert!(missing.is_empty());
        assert!(
            matches!(
                lines.as_slice(),
                [TickLine::Member { tx: named, joins: Joins::Executes, settlement: on, .. }]
                    if *named == tx && *on == settlement
            ),
            "the arrival in hand, the chain names the member to run: {lines:?}",
        );
        rows.advance(&block_naming(2, anchor, lines));
        (rows, arrived)
    }

    /// Admission above a settlement frontier of 1 over `rows`, owing the
    /// determined halves they owe.
    fn over(rows: &MemberIndex) -> Against {
        let mut against = above_frontier(1);
        against.members = rows.clone();
        against
    }

    /// `rows` after a halt recovery's crossing block, anchored at
    /// `anchor` with `arrived` still in hand: the lines the chain names
    /// there, which are the discard of the tick at height 2 and nothing
    /// else, folded.
    fn recovered_at(
        mut rows: MemberIndex,
        arrived: &CommittedSets,
        anchor: WeightedTimestamp,
    ) -> MemberIndex {
        let (lines, missing, _) = member_lines(
            &rows,
            anchor,
            arrived,
            &|_, _| Evidence::Live { terminating: false },
            true,
            &BTreeSet::new(),
            &BTreeMap::new(),
        );
        assert!(missing.is_empty());
        assert_eq!(
            lines,
            vec![TickLine::Discard {
                tick: TickId::new(ShardId::ROOT, BlockHeight::new(2)),
                cause: DiscardCause::Recovery,
            }],
        );
        rows.advance(&block_naming(9, anchor, lines));
        assert!(
            rows.ticks.is_empty(),
            "the recovery discards the tick whole"
        );
        rows
    }

    /// No line answers `Never` for a member a tick ran that no recovery
    /// released, no sibling's state refuses and that did not reach its
    /// stating window's end unstated, at any clock, under any evidence,
    /// covered by a record or not. A member its own tick decides is named
    /// by no line while that tick owes its determined half. One a sibling
    /// shares the verdict on is named by an abort a record covers, which
    /// answers nothing, by a fate, or, once its stating window closes
    /// with no record covering it, by an abort answering `Never` for what
    /// it consumed: it never stated, so its effects apply nowhere. A
    /// stated one is named by none of these.
    #[test]
    fn a_ran_member_answers_never_only_once_its_stating_window_closes_unstated() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(10_000));
        let lapse = Window::LegEntry.of(deadline).end;
        let unstated_from = Window::Stating.of(deadline).end;
        let (taker, sharer) = (
            TxHash::from(Hash::from_bytes(b"alone core")),
            TxHash::from(Hash::from_bytes(b"shared core")),
        );
        let (alone_in_flight, taker_arrived) =
            run_in_tick_2(taker, Settlement::Alone, consumed(1), deadline);
        let (shared_in_flight, sharer_arrived) =
            run_in_tick_2(sharer, Settlement::Shared, consumed(2), deadline);
        let stated =
            after_committing(over(&shared_in_flight), &[&stating_yes(2, &[sharer])]).members;

        for (rows, arrived, tx) in [
            (&alone_in_flight, &taker_arrived, taker),
            (&shared_in_flight, &sharer_arrived, sharer),
            (&stated, &sharer_arrived, sharer),
        ] {
            let mut covered = rows.clone();
            covered.advance(&MemberInputs {
                height: BlockHeight::new(4),
                covered: vec![tx],
                ..MemberInputs::still(ShardId::ROOT)
            });
            assert!(covered.members[&tx].covered);
            for rows in [rows, &covered] {
                for anchor in [
                    WeightedTimestamp::from_millis(3_000),
                    deadline.at(),
                    unstated_from.minus(Duration::from_millis(1)),
                    unstated_from,
                    lapse,
                    lapse.plus(RETENTION_HORIZON),
                ] {
                    for said in [
                        Evidence::Live { terminating: false },
                        Evidence::Live { terminating: true },
                        Evidence::Readable,
                        Evidence::Unreadable,
                        Evidence::Unknown,
                    ] {
                        let (lines, _, _) = member_lines(
                            rows,
                            anchor,
                            arrived,
                            &|_, _| said,
                            false,
                            &BTreeSet::new(),
                            &BTreeMap::new(),
                        );
                        let unstated = rows.members[&tx].state == in_flight(2, Settlement::Shared)
                            && !rows.members[&tx].covered
                            && anchor >= unstated_from;
                        let mut answered = false;
                        for line in &lines {
                            let TickLine::Member {
                                joins, crossings, ..
                            } = line
                            else {
                                continue;
                            };
                            assert!(
                                *joins == Joins::Aborted && crossings.is_empty() != unstated,
                                "under {said:?} at {anchor:?}: {line:?}",
                            );
                            answered |= !crossings.is_empty();
                        }
                        if unstated && matches!(said, Evidence::Live { .. } | Evidence::Readable) {
                            assert!(answered, "under {said:?} at {anchor:?}: {lines:?}");
                        }
                        if rows.members[&tx].state == in_flight(2, Settlement::Alone) {
                            assert_eq!(lines, vec![], "under {said:?} at {anchor:?}");
                        }
                    }
                }
            }
        }
    }

    /// A core member a halt recovery released lands no take of the
    /// crossing it consumed before the frontier, whether its own tick
    /// decided it or a sibling shares its verdict, and whether it stood
    /// in flight or stated when the chain halted.
    ///
    /// Short of the recovery, the half its replaced committee certified
    /// is admitted over its row and settles its effects. Past the
    /// recovery's discard the row stands released: admission refuses
    /// that half and every other of its tick, at any later block, and no
    /// line names the member to run again though its arrival still
    /// stands in the committed inputs. Where its own tick decided it, a
    /// fate ends the row from the close of its leg entry window. Where a
    /// sibling shares its verdict, an abort at once ends it while a
    /// shard it reaches can answer, answering its crossing `Never` unless
    /// a record covers it, and a fate once none can.
    #[test]
    fn a_member_a_recovery_released_takes_nothing_off_a_reading_below_the_bridge() {
        let deadline = Deadline::of(WeightedTimestamp::from_millis(10_000));
        let lapse = Window::LegEntry.of(deadline).end;
        let (taker, sharer) = (
            TxHash::from(Hash::from_bytes(b"alone core")),
            TxHash::from(Hash::from_bytes(b"shared core")),
        );
        let anchors = [
            WeightedTimestamp::from_millis(3_000),
            deadline.at(),
            lapse.minus(Duration::from_millis(1)),
            lapse,
            lapse.plus(RETENTION_HORIZON),
        ];

        // The member its own tick decides, in flight when the chain
        // halts, and the determined half its replaced committee
        // certified for it.
        let (halted, taker_arrived) =
            run_in_tick_2(taker, Settlement::Alone, consumed(1), deadline);
        let take = determined_projected(vec![alone(taker)], &[taker]);
        assert_eq!(
            settles(&over(&halted), &take),
            Ok(()),
            "short of the recovery the half settles the take",
        );

        // The member a sibling shares the verdict on, stated when the
        // chain halts, and the legs half that accepts it.
        let (shared_in_flight, sharer_arrived) =
            run_in_tick_2(sharer, Settlement::Shared, consumed(2), deadline);
        let yes = stating_yes(2, &[sharer]);
        assert_eq!(settles(&over(&shared_in_flight), &yes), Ok(()));
        let stated = after_committing(over(&shared_in_flight), &[&yes]).members;
        assert_eq!(stated.members[&sharer].state, stated_in(2));
        let accept = legs_naming(&[sharer]);
        assert_eq!(
            settles(&over(&stated), &accept),
            Ok(()),
            "short of the recovery the half settles the take",
        );

        let cases: [(
            &MemberIndex,
            &CommittedSets,
            TxHash,
            Settlement,
            Vec<&Finalization>,
        ); 3] = [
            (
                &halted,
                &taker_arrived,
                taker,
                Settlement::Alone,
                vec![&take],
            ),
            (
                &shared_in_flight,
                &sharer_arrived,
                sharer,
                Settlement::Shared,
                vec![&yes, &accept],
            ),
            (
                &stated,
                &sharer_arrived,
                sharer,
                Settlement::Shared,
                vec![&yes, &accept],
            ),
        ];
        for (before, arrived, tx, settlement, halves) in cases {
            for at in 0..anchors.len() {
                let rows = recovered_at(before.clone(), arrived, anchors[at]);
                assert_eq!(rows.members[&tx].state, RowState::Released { settlement });
                released_lands_nothing(&rows, arrived, tx, &anchors[at..], &halves);
            }
        }
    }

    /// Hold `rows`, in which a recovery's crossing block released `tx`, to
    /// landing nothing for it: admission refuses each of `halves`, and
    /// at each of `anchors`, under every reading of its counterparts'
    /// evidence and with `arrived` in hand, the chain names the fate
    /// that ends its row, an abort at once where a sibling shares its
    /// verdict and can answer, which answers the crossings its row still
    /// lists unless a record covers it, or no line at all. Folding the
    /// fate leaves no row, and each half is refused still.
    fn released_lands_nothing(
        rows: &MemberIndex,
        arrived: &CommittedSets,
        tx: TxHash,
        anchors: &[WeightedTimestamp],
        halves: &[&Finalization],
    ) {
        let row = &rows.members[&tx];
        let RowState::Released { settlement } = row.state else {
            panic!("the recovery released the member: {:?}", row.state);
        };
        assert!(row.executed, "the member ran");
        assert_eq!(
            row.crossings.is_empty(),
            settlement != Settlement::Shared,
            "a member that ran keeps the crossings an abort answers only where its \
             settlement is shared",
        );
        assert!(
            !row.owes.is_empty(),
            "a member that ran owes its crossings until its row goes",
        );
        let answered = if row.covered {
            Capped::empty()
        } else {
            row.crossings.clone()
        };
        for half in halves {
            let err = settles(&over(rows), half).unwrap_err();
            assert!(
                err.contains("does not hold"),
                "{:?} half over a released row: {err}",
                half.half(),
            );
        }

        let lapse = Window::LegEntry.of(row.deadline).end;
        let fate = TickLine::Fate {
            tx,
            charge: row.charge,
        };
        for &anchor in anchors {
            for said in [
                Evidence::Live { terminating: false },
                Evidence::Live { terminating: true },
                Evidence::Readable,
                Evidence::Unreadable,
                Evidence::Unknown,
            ] {
                for recovery in [false, true] {
                    let (lines, missing, _) = member_lines(
                        rows,
                        anchor,
                        arrived,
                        &|_, _| said,
                        recovery,
                        &BTreeSet::new(),
                        &BTreeMap::new(),
                    );
                    let fated = match settlement {
                        Settlement::Alone => anchor >= lapse,
                        Settlement::Shared | Settlement::Awaited => said == Evidence::Unreadable,
                    };
                    // A shared member that ran is aborted at once, any
                    // other from its deadline.
                    let aborted = settlement != Settlement::Alone
                        && (row.deadline.passed(anchor) || settlement == Settlement::Shared)
                        && matches!(said, Evidence::Live { .. } | Evidence::Readable);
                    if aborted {
                        assert!(
                            matches!(
                                lines.as_slice(),
                                [TickLine::Member { tx: named, joins: Joins::Aborted, crossings, .. }]
                                    if *named == tx && *crossings == answered
                            ),
                            "{settlement:?} under {said:?} at {anchor:?}: {lines:?}",
                        );
                    } else {
                        assert_eq!(
                            lines,
                            if fated { vec![fate.clone()] } else { vec![] },
                            "{settlement:?} under {said:?} at {anchor:?}",
                        );
                    }
                    assert_eq!(
                        missing.contains(&tx),
                        settlement == Settlement::Shared && said == Evidence::Unknown,
                    );
                }
            }
        }

        let mut ended = rows.clone();
        ended.advance(&block_naming(10, lapse, vec![fate]));
        assert!(ended.members.is_empty() && ended.ticks.is_empty());
        for half in halves {
            assert!(settles(&over(&ended), half).is_err());
        }
    }

    /// A half certified below a bridge of this shard's recovery is
    /// refused in every block anchored at or past the bridge, while the
    /// recovery is pending and once its record has cleared: a determined
    /// half over the rows its tick still holds. Below the bridge, and on
    /// a shard no recovery is recorded for, it is admitted.
    #[test]
    fn a_half_certified_below_the_bridge_is_refused_in_every_block_past_it() {
        use hyperscale_types::{
            Epoch, RecoveryBinding, RecoveryCause, ShardRecovery, TopologySchedule,
            TopologySnapshot,
        };

        let member = TxHash::from(Hash::from_bytes(b"first alone"));
        let whole = determined_projected_at(20_500, vec![alone(member)], &[member]);
        let recovered = |recovery: Option<bool>| {
            let mut snapshot = TopologySnapshot::new(
                NetworkDefinition::simulator(),
                1,
                ValidatorSet::new(Vec::new()),
            );
            if let Some(pending) = recovery {
                snapshot = snapshot.with_recoveries(BTreeMap::from([(
                    ShardId::ROOT,
                    vec![RecoveryBinding {
                        rotated_at: Epoch::new(20),
                        attested_frontier: BlockHeight::new(1),
                        completed: !pending,
                    }],
                )]));
                if pending {
                    snapshot = snapshot.with_pending_recoveries(BTreeMap::from([(
                        ShardId::ROOT,
                        ShardRecovery {
                            cause: RecoveryCause::Halt,
                            rotated_at: Epoch::new(20),
                            retained: Vec::new(),
                            attested_frontier: BlockHeight::new(1),
                        },
                    )]));
                }
            }
            let mut schedule =
                TopologySchedule::new(1_000, Epoch::GENESIS, Arc::new(snapshot.clone()));
            for epoch in 1..=60 {
                schedule.insert(Epoch::new(epoch), Arc::new(snapshot.clone()));
            }
            (snapshot, schedule)
        };
        let against = |recovery: Option<bool>, rows: &[TxHash], anchor_ms: u64| {
            let mut against = holding_alone(rows);
            (against.snapshot, against.schedule) = recovered(recovery);
            against.anchor = WeightedTimestamp::from_millis(anchor_ms);
            against
        };

        for recovery in [Some(true), Some(false), None] {
            assert_eq!(
                settles(&against(recovery, &[member], 20_900), &whole),
                Ok(()),
                "below the bridge, recovery {recovery:?}",
            );
            for anchor_ms in [21_000, 21_100, 59_000] {
                let admitted = settles(&against(recovery, &[member], anchor_ms), &whole);
                if recovery.is_some() {
                    assert!(
                        admitted
                            .as_ref()
                            .is_err_and(|err| err.contains("below a recovery bridge")),
                        "at {anchor_ms}, recovery {recovery:?}: {admitted:?}",
                    );
                } else {
                    assert_eq!(admitted, Ok(()), "at {anchor_ms} with no recovery");
                }
            }
        }
    }

    /// A voter whose dedup index is fresh — after a halt recovery past f,
    /// a whole committee can be — admits a batch the chain carried before
    /// it began folding: no completeness gate holds the vote back, and
    /// the shallow tier over-admits per item rather than stalling.
    #[test]
    fn a_shallow_committee_still_commits() {
        let bundle = Provisions::new(
            ShardId::leaf(1, 1),
            ShardId::ROOT,
            BlockHeight::new(3),
            WeightedTimestamp::ZERO,
            MerkleInclusionProof::dummy(),
            Capped::from_array([ProvisionEntry::new(
                TxHash::from(Hash::from_bytes(b"carried before")),
                Capped::empty(),
            )]),
        );
        let fresh = plain();
        assert!(!fresh.dedup.is_complete(fresh.anchor));
        let mut fold = ProvisionsFold::default();
        assert!(ProvisionsSection::admit(&fresh.ctx(), &mut fold, &bundle).is_ok());
    }

    /// A legs half is not held to the frontier. It waits on a
    /// counterpart and may land arbitrarily late, and where the chain
    /// owes no determined half up to its tick nothing orders it: holding
    /// it to the frontier would wedge a tick composed entirely of legs,
    /// which never advances one.
    #[test]
    fn a_legs_half_settles_whatever_the_frontier_says() {
        assert!(admit_settling(&mut above_frontier(7), &block_settling(&[], &[1])).is_ok());
        assert!(admit_settling(&mut above_frontier(7), &block_settling(&[8], &[1])).is_ok());
    }

    /// A certificate anchored before the chain's origin names a tick on
    /// a predecessor and is refused outright.
    #[test]
    fn a_certificate_anchored_before_the_origin_is_refused() {
        let since_origin = || {
            let mut against = above_frontier(0);
            against.chain_origin = WeightedTimestamp::from_millis(5);
            against
        };
        let err = admit_settling(&mut since_origin(), &block_settling(&[4], &[])).unwrap_err();
        assert!(err.contains("predates this chain's origin"), "{err}");
        assert!(admit_settling(&mut since_origin(), &block_settling(&[6], &[])).is_ok());
    }

    /// A block settles ticks of its own chain and no other's. A sibling's
    /// finalization is certified by the sibling's committee over receipts
    /// this chain never executed, and anchoring it past this chain's
    /// origin does not make it this chain's: either half is refused.
    #[test]
    fn a_finalization_of_another_shards_tick_is_refused() {
        let (local, sibling) = ShardId::ROOT.children();
        for (determined, legs) in [(&[6][..], &[][..]), (&[][..], &[6][..])] {
            let mut against = above_frontier(0);
            against.local_shard = local;
            against.chain_origin = WeightedTimestamp::from_millis(5);
            let err = admit(
                &against,
                &block_settling_ticks_of(sibling, determined, legs),
            )
            .unwrap_err();
            assert!(err.contains("names a tick of another shard"), "{err}");
            assert!(
                admit_settling(
                    &mut against,
                    &block_settling_ticks_of(local, determined, legs)
                )
                .is_ok(),
                "the same half of this chain's own tick is carried",
            );
        }
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
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::new(wrapped).expect("a list written out in a test")),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
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
            Capped::from_array([ProvisionEntry::new(tx_hash, Capped::empty())]),
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
        let against = plain();
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
        let err =
            validate_block_for_vote(&Against::window(topo).ctx(), &block, Some(ShardLoad::ZERO))
                .unwrap_err();
        assert!(err.contains("not admission-validated"));
    }

    #[test]
    fn coast_blocks_must_be_empty() {
        // Past the terminal window a block exists only to certify the
        // crossing: any content fails the pre-vote check.
        let with_tx = block_with_transactions(BlockHeight::new(1), sorted_verified_txs(&[10]));
        let err = validate_coast_block_for_vote(&with_tx, Some(ShardLoad::ZERO)).unwrap_err();
        assert!(err.contains("coast block"), "{err}");

        // A boundary record is content too. A chain whose capacity to
        // resolve anything ended at its cut has nothing left to write
        // down, so the rule covers every body list rather than three of
        // four.
        let records = vec![verdict(ShardId::ROOT, &[1])];
        let with_record = block_with_verdicts(records.clone(), AbandonmentRoot::over(&records));
        let err = validate_coast_block_for_vote(&with_record, Some(ShardLoad::ZERO)).unwrap_err();
        assert!(err.contains("abandonment records"), "{err}");

        let empty = block_with_transactions(BlockHeight::new(1), Vec::new());
        assert!(validate_coast_block_for_vote(&empty, Some(ShardLoad::ZERO)).is_ok());
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
            transactions: Arc::new(Capped::from_array([Arc::clone(tx)])),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::new(provisions).expect("a list written out in a test")),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
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
                Capped::from_array([ProvisionEntry::new(tx_hash, Capped::empty())]),
            ))
            .into(),
        );
        let paired = block_with_tx(&tx, vec![Arc::clone(&bundle)]);
        assert!(admit(&engaged(&topo, local), &paired).is_ok());

        // A bundle an earlier block committed, registered through that
        // block's own list: engaged.
        let mut dedup = CommitDedupIndex::new();
        dedup.register_committed_engagements(
            &paired.engagements(),
            WeightedTimestamp::from_millis(1_000),
        );
        assert!(admit(&engaged_with(&topo, local, dedup), &bare).is_ok());

        // The same block committed and sealed feeds the same entry.
        let mut dedup = CommitDedupIndex::new();
        dedup.register_committed_engagements(
            &paired.clone().into_sealed().engagements(),
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
                Capped::from_array([ProvisionEntry::new(tx_hash, Capped::empty())]),
            ))
            .into(),
        );
        let mispaired = block_with_tx(&tx, vec![wrong_source]);
        let err = admit(&engaged(&topo, local), &mispaired).unwrap_err();
        assert!(err.contains("payer bundle"), "{err}");
    }

    /// The payer's bundle for `tx`, from `payer` at `height`, with the
    /// empty entry a payer holding none of its reads sends.
    fn payer_bundle(
        payer: ShardId,
        local: ShardId,
        height: u64,
        tx_hash: TxHash,
    ) -> Arc<Verifiable<Provisions>> {
        Arc::new(
            Verified::<Provisions>::new_unchecked_for_test(Provisions::new(
                payer,
                local,
                BlockHeight::new(height),
                WeightedTimestamp::ZERO,
                MerkleInclusionProof::dummy(),
                Capped::from_array([ProvisionEntry::new(tx_hash, Capped::empty())]),
            ))
            .into(),
        )
    }

    /// A committed payer entry engages only while its committing anchor
    /// plus the horizon is ahead of the admitting anchor, and only at a
    /// source height no recovery fences.
    #[test]
    fn a_committed_engagement_lapses_and_is_fenced_at_admission() {
        use hyperscale_types::{Epoch, RecoveryCause, ShardRecovery};

        let topo = TestCommittee::new(4, 42).topology_snapshot(2);
        let local = ShardId::leaf(1, 0);
        let payer = ShardId::leaf(1, 1);
        let local_owner = test_principal(0x01);
        let payer_owner = test_principal(0x81);
        let tx = stub_tx(payer_owner, &[local_owner.address(), payer_owner.address()]);
        let committed = block_with_tx(&tx, vec![payer_bundle(payer, local, 7, tx.hash())]);
        let bare = block_with_tx(&tx, Vec::new());
        let anchor = WeightedTimestamp::from_millis(1_000);
        let with_entry = |topo: &TopologySnapshot, at: WeightedTimestamp| {
            let mut dedup = CommitDedupIndex::new();
            dedup.register_committed_engagements(&committed.engagements(), anchor);
            let mut against = engaged_with(topo, local, dedup);
            against.anchor = at;
            against
        };

        let deadline = anchor.plus(RETENTION_HORIZON);
        let inside = deadline.minus(Duration::from_millis(1));
        assert!(admit(&with_entry(&topo, inside), &bare).is_ok());
        let err = admit(&with_entry(&topo, deadline), &bare).unwrap_err();
        assert!(err.contains("payer bundle"), "{err}");

        let recovering = topo.with_pending_recoveries(
            std::iter::once((
                payer,
                ShardRecovery {
                    cause: RecoveryCause::Halt,
                    rotated_at: Epoch::new(2),
                    retained: Vec::new(),
                    attested_frontier: BlockHeight::new(6),
                },
            ))
            .collect(),
        );
        let err = admit(&with_entry(&recovering, inside), &bare).unwrap_err();
        assert!(err.contains("payer bundle"), "{err}");
    }

    /// The committed arm is keyed by the payer's shard under the
    /// admitting anchor's trie. A payer bundle committed under the
    /// parent before the payer split engages nothing once admission
    /// resolves the payer to a child, so the transaction is refused and
    /// no value moves.
    #[test]
    fn a_payer_cut_between_commit_and_admission_refuses() {
        let before = TestCommittee::new(4, 42).topology_snapshot(2);
        let after = TestCommittee::new(4, 42).topology_snapshot(4);
        let payer_owner = test_principal(0x81);
        let local_owner = test_principal(0x01);
        let tx = stub_tx(payer_owner, &[local_owner.address(), payer_owner.address()]);
        let parent_payer = before.shard_trie().shard_for_prefix(tx.fee_payer());
        let child_payer = after.shard_trie().shard_for_prefix(tx.fee_payer());
        let local = after.shard_trie().shard_for_prefix(local_owner.address());
        assert_eq!(parent_payer, ShardId::leaf(1, 1));
        assert!(parent_payer.is_ancestor_of(child_payer), "the payer split");
        assert_ne!(local, child_payer);

        let committed = block_with_tx(&tx, vec![payer_bundle(parent_payer, local, 7, tx.hash())]);
        let mut dedup = CommitDedupIndex::new();
        dedup.register_committed_engagements(
            &committed.engagements(),
            WeightedTimestamp::from_millis(1_000),
        );
        let err = admit(
            &engaged_with(&after, local, dedup),
            &block_with_tx(&tx, Vec::new()),
        )
        .unwrap_err();
        assert!(err.contains("payer bundle"), "{err}");
    }

    /// The header's body root commits what the block's provisions name:
    /// an engagements section over anything else is refused, and the sealed form of
    /// an honest block, which keeps the list, passes as the live one does.
    #[test]
    fn the_body_root_commits_what_the_provisions_engage() {
        let local = ShardId::leaf(1, 0);
        let payer = ShardId::leaf(1, 1);
        let tx_hash = TxHash::from(Hash::from_bytes(b"engaged"));
        let provisions = vec![
            payer_bundle(payer, local, 3, tx_hash),
            payer_bundle(payer, local, 4, tx_hash),
        ];
        let provision_hashes: Vec<Hash> = provisions.iter().map(|p| p.hash().into_raw()).collect();
        let with_root = |root: EngagementRoot| {
            let base = header_at_height(BlockHeight::new(6), 100_000);
            Block::Live {
                header: BlockHeader::new(BlockHeaderParts {
                    height: base.height(),
                    parent_block_hash: base.parent_block_hash(),
                    parent_qc: base.parent_qc().clone().into(),
                    proposer: base.proposer(),
                    timestamp: base.timestamp(),
                    round: base.round(),
                    provision_tx_roots: Capped::default(),
                    body_root: SectionRoots {
                        provisions: ProvisionsRoot::over(&provision_hashes),
                        engagements: root,
                        ..SectionRoots::EMPTY
                    }
                    .root(),
                    ..Default::default()
                }),
                transactions: Arc::new(Capped::empty()),
                certificates: Arc::new(Capped::empty()),
                provisions: Arc::new(
                    Capped::new(provisions.clone()).expect("a list written out in a test"),
                ),
                abandonment_records: Arc::new(Capped::empty()),
                state_claims: Arc::new(Capped::empty()),
                tick_manifest: Arc::new(Capped::empty()),
                terms: Arc::new(Capped::empty()),
                witness_sources: Arc::new(WitnessSources::empty()),
            }
        };
        let honest = EngagementRoot::over(&Engagement::of_provisions(&provisions));

        let err = sections_bound(&with_root(EngagementRoot::ZERO))
            .expect_err("a root claiming nothing does not commit two entries");
        assert!(err.contains("body root"), "{err}");
        let short = EngagementRoot::over(&Engagement::of_provisions(&provisions[..1]));
        let err = sections_bound(&with_root(short)).expect_err("a root omitting one entry fails");
        assert!(err.contains("body root"), "{err}");

        let live = with_root(honest);
        assert!(sections_bound(&live).is_ok());
        let sealed = live.into_sealed();
        assert_eq!(sealed.engagements().len(), 2);
        assert!(sections_bound(&sealed).is_ok());
    }

    /// The header's body root commits the block's tick lines, in both
    /// forms, and a coast block names nothing but fates.
    #[test]
    fn the_body_root_commits_the_tick_lines_and_a_coast_block_names_nothing_but_fates() {
        let lines: TickManifest = Capped::from_array([TickLine::Discard {
            tick: TickId::new(ShardId::ROOT, BlockHeight::new(3)),
            cause: DiscardCause::Recovery,
        }]);
        let with_root = |root: TickManifestRoot| {
            let base = header_at_height(BlockHeight::new(6), 100_000);
            Block::Live {
                header: BlockHeader::new(BlockHeaderParts {
                    height: base.height(),
                    parent_block_hash: base.parent_block_hash(),
                    parent_qc: base.parent_qc().clone().into(),
                    proposer: base.proposer(),
                    timestamp: base.timestamp(),
                    round: base.round(),
                    provision_tx_roots: Capped::default(),
                    body_root: SectionRoots {
                        tick_manifest: root,
                        ..SectionRoots::EMPTY
                    }
                    .root(),
                    ..Default::default()
                }),
                transactions: Arc::new(Capped::empty()),
                certificates: Arc::new(Capped::empty()),
                provisions: Arc::new(Capped::empty()),
                abandonment_records: Arc::new(Capped::empty()),
                state_claims: Arc::new(Capped::empty()),
                tick_manifest: Arc::new(lines.clone()),
                terms: Arc::new(Capped::empty()),
                witness_sources: Arc::new(WitnessSources::empty()),
            }
        };

        let err = sections_bound(&with_root(TickManifestRoot::ZERO))
            .expect_err("a root claiming nothing does not commit a line");
        assert!(err.contains("body root"), "{err}");

        let honest = with_root(TickManifestRoot::over(&lines));
        assert!(sections_bound(&honest).is_ok());
        let sealed = honest.clone().into_sealed();
        assert_eq!(
            sealed.tick_manifest().len(),
            1,
            "sealing keeps the manifest"
        );
        assert!(sections_bound(&sealed).is_ok());

        let err = validate_coast_block_for_vote(&honest, Some(ShardLoad::ZERO)).unwrap_err();
        assert!(err.contains("tick lines"), "{err}");
    }

    /// The header's body root commits the block's terms section on the
    /// vote path, in both forms: a block stating an entry its header
    /// does not bind, stating none of the entry it binds, or stating
    /// another than the one bound is refused.
    #[test]
    fn a_block_stating_terms_its_header_does_not_bind_is_refused() {
        let entry = stub_stated_terms(TxHash::from(Hash::from_bytes(b"stated")), 3);
        let mut other = entry.clone();
        other.terms.share += 1;
        let empty = block_with_transactions(BlockHeight::new(6), Vec::new());

        let honest = rebound(stating(empty.clone(), vec![entry.clone()]));
        assert_eq!(honest.terms().len(), 1);
        assert!(sections_bound(&honest).is_ok());
        assert!(sections_bound(&honest.clone().into_sealed()).is_ok());

        for (forged, why) in [
            (stating(empty, vec![entry]), "an entry no root commits"),
            (
                stating(honest.clone(), Vec::new()),
                "a bound entry left out",
            ),
            (stating(honest, vec![other]), "another entry than the bound"),
        ] {
            for block in [forged.clone(), forged.into_sealed()] {
                let err = sections_bound(&block).expect_err(why);
                assert!(err.contains("body root"), "{why}: {err}");
            }
        }
    }

    /// `count` verified transactions in hash order, each its own payer's.
    fn transactions_in_order(count: usize) -> Vec<Arc<Verifiable<Transaction>>> {
        let mut txs: Vec<Arc<Verifiable<Transaction>>> = (0..count)
            .map(|seed| {
                Arc::new(Verifiable::from(Verified::new_unchecked_for_test(
                    test_utils::stub_transaction_binding(
                        u32::try_from(seed).expect("fewer than u32 transactions"),
                        0,
                        test_utils::test_validity_range(),
                    ),
                )))
            })
            .collect();
        txs.sort_by_key(|tx| tx.hash());
        txs
    }

    /// A block whose terms entries weigh within the section's budget
    /// between them passes the budget, and one entry more is refused
    /// before a vote.
    #[test]
    fn a_block_whose_terms_pass_their_budget_is_refused() {
        let wide = |tx: TxHash| {
            let mut entry = stub_stated_terms(tx, 3);
            entry.terms.declared =
                Capped::new(vec![entry.terms.declared[0]; 64]).expect("a list under the cap");
            entry
        };
        let fitting = MAX_TICK_TERMS_BYTES
            / wide(TxHash::from(Hash::from_bytes(b"stated")))
                .terms
                .wire_weight();
        assert!(
            fitting < MAX_TXS_PER_BLOCK,
            "the budget binds before the cap"
        );
        let txs = transactions_in_order(fitting + 1);
        let stating_entries = |count: usize| {
            let carried = txs[..count].to_vec();
            let entries = carried.iter().map(|tx| wide(tx.hash())).collect();
            rebound(stating(
                block_with_transactions(BlockHeight::new(1), carried),
                entries,
            ))
        };

        assert!(validate_terms_section(&stating_entries(fitting)).is_ok());
        let over = stating_entries(fitting + 1);
        assert!(
            sections_bound(&over).is_ok(),
            "the header binds the section"
        );
        let err = validate_block_for_vote(
            &Against::window(topology_snapshot()).ctx(),
            &over,
            Some(ShardLoad::ZERO),
        )
        .unwrap_err();
        assert!(err.contains("terms section weighs"), "{err}");
    }

    /// `block` naming `lines`, under a header binding them.
    fn naming_lines(mut block: Block, lines: Vec<TickLine>) -> Block {
        let (Block::Live { tick_manifest, .. } | Block::Sealed { tick_manifest, .. }) = &mut block;
        *tick_manifest = Arc::new(Capped::new(lines).expect("a list written out in a test"));
        rebound(block)
    }

    /// A line naming `tx` on `joins`.
    fn joining(tx: TxHash, joins: Joins) -> TickLine {
        TickLine::Member {
            staged: 0,
            tx,
            joins,
            settlement: Settlement::Alone,
            holds: Capped::empty(),
            reach: Capped::empty(),
            awaits: Capped::empty(),
            charge: stub_abort_charge(0),
            share: 0,
            reserves: Capped::empty(),
            deadline: Deadline::of(WeightedTimestamp::from_millis(u64::MAX / 4)),
            crossings: Capped::empty(),
        }
    }

    /// Every transaction a block commits stands on terms the block
    /// states or on a line of the block that runs it: one with neither
    /// would get no row, so the block is refused before a vote. An abort
    /// runs nothing, and does not stand in for the entry.
    #[test]
    fn a_block_committing_a_transaction_without_its_terms_is_refused() {
        let txs = transactions_in_order(2);
        let [first, second] = [txs[0].hash(), txs[1].hash()];
        let carrying = |entries: Vec<TxHash>, lines: Vec<TickLine>| {
            naming_lines(
                stating(
                    block_with_transactions(BlockHeight::new(1), txs.clone()),
                    entries
                        .into_iter()
                        .map(|tx| stub_stated_terms(tx, 3))
                        .collect(),
                ),
                lines,
            )
        };
        for (entries, lines, why) in [
            (vec![first, second], vec![], "both stated"),
            (
                vec![second],
                vec![joining(first, Joins::Executes)],
                "one run, one stated",
            ),
            (
                vec![first, second],
                vec![joining(second, Joins::Aborted)],
                "an abort beside its entry",
            ),
        ] {
            assert!(
                validate_terms_section(&carrying(entries, lines)).is_ok(),
                "{why}"
            );
        }
        for (entries, lines, why) in [
            (vec![first], vec![], "one left unstated"),
            (vec![], vec![], "none stated"),
            (
                vec![first],
                vec![joining(second, Joins::Aborted)],
                "an abort in place of the entry",
            ),
        ] {
            let block = carrying(entries, lines);
            let err = validate_terms_section(&block).expect_err(why);
            assert!(err.contains("neither its terms stated"), "{why}: {err}");
            assert!(sections_bound(&block).is_ok(), "the header binds it");
            assert!(
                validate_block_for_vote(
                    &Against::window(topology_snapshot()).ctx(),
                    &block,
                    Some(ShardLoad::ZERO),
                )
                .is_err(),
                "{why}",
            );
        }
    }

    /// A block of `txs` stating stub terms for each of `entries`, every
    /// entry's crossings cleared unless `crossings`, beside `lines`.
    fn carrying_terms(
        txs: &[Arc<Verifiable<Transaction>>],
        entries: Vec<TxHash>,
        crossings: bool,
        lines: Vec<TickLine>,
    ) -> Block {
        naming_lines(
            stating(
                block_with_transactions(BlockHeight::new(1), txs.to_vec()),
                entries
                    .into_iter()
                    .map(|tx| {
                        let mut entry = stub_stated_terms(tx, 3);
                        if !crossings {
                            entry.terms.crossings = Capped::empty();
                        }
                        entry
                    })
                    .collect(),
            ),
            lines,
        )
    }

    /// A transaction a line of the block runs has no entry where its
    /// terms carry no crossing: its row is the line's to write. And the
    /// entries stand in the block's transaction order, each naming a
    /// transaction the block commits, once.
    #[test]
    fn a_block_stating_terms_for_a_member_it_runs_is_refused() {
        let txs = transactions_in_order(3);
        let [first, second, third] = [txs[0].hash(), txs[1].hash(), txs[2].hash()];
        let stray = TxHash::from(Hash::from_bytes(b"committed by no block"));
        let carrying = |entries: Vec<TxHash>, lines: Vec<TickLine>| {
            carrying_terms(&txs, entries, false, lines)
        };
        let err = validate_terms_section(&carrying(
            vec![first, second, third],
            vec![joining(second, Joins::Executes)],
        ))
        .expect_err("stated without crossings and run");
        assert!(err.contains("which a line of the block runs"), "{err}");
        assert!(
            validate_terms_section(&carrying(
                vec![first, third],
                vec![joining(second, Joins::ExecutesAborted)],
            ))
            .is_ok()
        );

        for (entries, why) in [
            (vec![second, first, third], "out of order"),
            (
                vec![first, second, third, stray],
                "a hash it does not commit",
            ),
            (vec![first, first, second, third], "one hash twice"),
        ] {
            assert!(
                validate_terms_section(&carrying(entries, vec![])).is_err(),
                "{why}",
            );
        }
    }

    /// A transaction a line of the block runs whose terms carry
    /// crossings may have its entry stated beside the line, which its
    /// row owes from, and may go without one: the block's equality with
    /// the section its proposer derives is what holds the entry there.
    #[test]
    fn a_block_stating_crossing_terms_for_a_member_it_runs_is_admitted() {
        let txs = transactions_in_order(3);
        let [first, second, third] = [txs[0].hash(), txs[1].hash(), txs[2].hash()];
        for runs in [Joins::Executes, Joins::ExecutesAborted] {
            assert_eq!(
                validate_terms_section(&carrying_terms(
                    &txs,
                    vec![first, second, third],
                    true,
                    vec![joining(second, runs)],
                )),
                Ok(())
            );
            assert_eq!(
                validate_terms_section(&carrying_terms(
                    &txs,
                    vec![first, third],
                    true,
                    vec![joining(second, runs)],
                )),
                Ok(())
            );
        }
    }

    /// The coast check admits a fate and an end, the lines a terminal
    /// lets its rows go by, and refuses a member line or a discard
    /// beside them: which coast block may carry either is the chain's to
    /// judge, not this check's.
    #[test]
    fn a_coast_block_may_carry_fates_and_ends_and_no_other_line() {
        let ended = TxHash::from(Hash::from_bytes(b"ended"));
        let fate = TickLine::Fate {
            tx: TxHash::from(Hash::from_bytes(b"fated")),
            charge: stub_abort_charge(0),
        };
        let end = TickLine::End { tx: ended };
        let coast = |lines: Vec<TickLine>| {
            naming_lines(
                block_with_transactions(BlockHeight::new(1), Vec::new()),
                lines,
            )
        };
        for lines in [
            vec![end.clone()],
            vec![fate.clone(), end.clone()],
            vec![end.clone(), fate],
        ] {
            let block = coast(lines);
            assert!(sections_bound(&block).is_ok(), "the header binds them");
            assert_eq!(validate_coast_block_empty(&block), Ok(()));
            assert_eq!(
                validate_coast_block_for_vote(&block, Some(ShardLoad::ZERO)),
                Ok(())
            );
        }
        for other in [
            joining(ended, Joins::Aborted),
            TickLine::Discard {
                tick: TickId::new(ShardId::ROOT, BlockHeight::new(3)),
                cause: DiscardCause::Abandoned(ended),
            },
        ] {
            let err = validate_coast_block_empty(&coast(vec![end.clone(), other]))
                .expect_err("a line a coast block does not carry");
            assert!(err.contains("tick lines"), "{err}");
        }
    }

    /// A block's member lines stage no more than
    /// [`MAX_TICK_STAGED_BYTES`] between them: lines summing to the cap
    /// are within the budget, and one byte past it is refused, off the
    /// lines alone.
    #[test]
    fn a_block_whose_lines_pass_the_staged_bound_is_refused() {
        let staging = |staged: &[u64]| {
            naming_lines(
                block_with_transactions(BlockHeight::new(1), Vec::new()),
                staged
                    .iter()
                    .enumerate()
                    .map(|(at, &bytes)| {
                        let mut line = joining(
                            TxHash::from(Hash::from_bytes(&at.to_be_bytes())),
                            Joins::Executes,
                        );
                        if let TickLine::Member { staged, .. } = &mut line {
                            *staged = bytes;
                        }
                        line
                    })
                    .collect(),
            )
        };
        let half = MAX_TICK_STAGED_BYTES / 2;
        assert_eq!(
            validate_tick_manifest_budget(&staging(&[half, MAX_TICK_STAGED_BYTES - half])),
            Ok(())
        );
        let err =
            validate_tick_manifest_budget(&staging(&[half, MAX_TICK_STAGED_BYTES - half + 1]))
                .expect_err("a byte past the cap");
        assert!(err.contains("stages"), "{err}");
    }

    /// An end line names no member and runs nothing: a manifest of them
    /// at the line cap is within the member cap and the byte budget, and
    /// a transaction the block commits that an end names still needs its
    /// terms stated.
    #[test]
    fn an_end_line_counts_as_no_member_and_runs_nothing() {
        let txs = transactions_in_order(1);
        let committed = txs[0].hash();
        const { assert!(MAX_TICK_LINES_PER_BLOCK > MAX_NAMED_MEMBERS_PER_TICK) };
        let full = naming_lines(
            block_with_transactions(BlockHeight::new(1), Vec::new()),
            vec![TickLine::End { tx: committed }; MAX_TICK_LINES_PER_BLOCK],
        );
        assert_eq!(validate_tick_manifest_budget(&full), Ok(()));

        let carrying = |entries: Vec<TxHash>| {
            naming_lines(
                stating(
                    block_with_transactions(BlockHeight::new(1), txs.clone()),
                    entries
                        .into_iter()
                        .map(|tx| stub_stated_terms(tx, 3))
                        .collect(),
                ),
                vec![TickLine::End { tx: committed }],
            )
        };
        assert_eq!(validate_terms_section(&carrying(vec![committed])), Ok(()));
        let err = validate_terms_section(&carrying(Vec::new()))
            .expect_err("an end in place of the entry");
        assert!(err.contains("neither its terms stated"), "{err}");
    }

    /// A coast block states no terms: it commits no transaction, so an
    /// entry is content a chain past its cut has nothing to write down
    /// for, whatever the header binds.
    #[test]
    fn a_coast_block_carrying_terms_is_refused() {
        let entry = stub_stated_terms(TxHash::from(Hash::from_bytes(b"stated")), 3);
        let coast = rebound(stating(
            block_with_transactions(BlockHeight::new(1), Vec::new()),
            vec![entry],
        ));
        assert!(
            sections_bound(&coast).is_ok(),
            "the header binds the section"
        );
        let err = validate_coast_block_for_vote(&coast, Some(ShardLoad::ZERO)).unwrap_err();
        assert!(err.contains("terms entries"), "{err}");
    }

    /// The signed ceiling is the payer shard's verdict and no other
    /// shard's.
    ///
    /// Two shards whose blocks sit either side of a fold name two
    /// tables, so a guard every participant applied would admit a
    /// straddling transaction on one and refuse it on the other — one
    /// shard committing what its counterpart will never carry. The shard
    /// that burns against the ceiling is the one that judges it.
    #[test]
    fn the_ceiling_is_judged_where_the_fee_is_burned() {
        // A level no fixture ceiling covers.
        let topo = TestCommittee::new(4, 42)
            .topology_snapshot(2)
            .with_prices(PriceTable {
                compute: PriceTable::GENESIS.compute * 1_000_000,
                ..PriceTable::GENESIS
            });
        let local = ShardId::leaf(1, 0);
        let payer_shard = ShardId::leaf(1, 1);
        let local_owner = test_principal(0x01);
        let payer_owner = test_principal(0x81);
        let tx = stub_tx(payer_owner, &[local_owner.address(), payer_owner.address()]);
        let tx_hash = tx.hash();

        // On the payer's own shard, which needs no bundle to engage:
        // refused, since this is the chain that would burn against the
        // ceiling.
        let err = admit(
            &engaged(&topo, payer_shard),
            &block_with_tx(&tx, Vec::new()),
        )
        .expect_err("the payer's shard prices it past the signed ceiling");
        assert!(err.contains("signs a ceiling"), "{err}");

        // On the counterpart, at the same table and with the payer
        // bundle in hand: carried. What the ceiling covers is not this
        // chain's question, and asking it here is what would fork the
        // two verdicts across a fold.
        let bundle: Arc<Verifiable<Provisions>> = Arc::new(
            Verified::<Provisions>::new_unchecked_for_test(Provisions::new(
                payer_shard,
                local,
                BlockHeight::new(1),
                WeightedTimestamp::ZERO,
                MerkleInclusionProof::dummy(),
                Capped::from_array([ProvisionEntry::new(tx_hash, Capped::empty())]),
            ))
            .into(),
        );
        assert!(admit(&engaged(&topo, local), &block_with_tx(&tx, vec![bundle])).is_ok());
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
