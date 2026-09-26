//! Pure shard consensus algorithm functions shared between production and simulation runners.
//!
//! These functions contain the core cryptographic verification and consensus
//! algorithms, separated from dispatch (thread pool vs inline) and result
//! delivery (channel vs event queue) concerns.

use std::collections::{HashMap, hash_map};
use std::sync::Arc;

use hyperscale_core::{Action, ActionContext, PreparedBlock, ProtocolEvent};
use hyperscale_engine::legs::{Classified, local_work_over};
use hyperscale_hbor::Capped;
use hyperscale_metrics::record_signature_verification_latency;
use hyperscale_network::Network;
use hyperscale_storage::{
    BeaconChainReader, ChainWrites, JmtSnapshot, MemberInputs, ParentAnchor, ShardChainWriter,
    ShardStorage, SubstateStore, SubstateView, SweepIndex, TerminalWindow, VersionedStore,
    colliding_committed_cell, colliding_member_row, committed_tx_cells, creations_of,
    load_read_frontier, sweep_for_block, without_colliding_committed_cells,
    without_colliding_member_rows,
};
use hyperscale_types::network::gossip::{
    CertifiedBlockHeaderGossip, ShardForkProofGossip, ShardVoteEquivocationGossip,
};
use hyperscale_types::network::notification::{
    BlockHeaderNotification, BlockVoteNotification, ReadySignalNotification, TimeoutNotification,
};
use hyperscale_types::{
    AbandonmentRecord, AbandonmentRoot, BeaconWitnessLeafCount, BeaconWitnessRootContext, Block,
    BlockHash, BlockHeader, BlockHeaderParts, BlockHeight, BlockProposalMessage, BlockVote,
    BlockVoteMessage, CertificateRoot, CertifiedBlockHeader, CertifiedBlockHeaderSenderMessage,
    CertifiedHeaderVerifyError, CheckOutcome, CommitWindow, ConsensusPublicKey, ConsensusReceipt,
    Deadline, DeferOn, Derivation, Engagement, EngagementRoot, Epoch, EpochWindows, Finalization,
    FrontierInputs, Hash, LocalReceiptRoot, MAX_FINALIZED_TX_PER_BLOCK,
    MAX_PROVISION_TARGET_SHARDS, MAX_PROVISIONS_PER_BLOCK, MAX_READY_SIGNALS_PER_BLOCK,
    MAX_STATE_CLAIMS_PER_BLOCK, MAX_TXS_PER_BLOCK, NetworkDefinition, PreparedCommit,
    PrincipalAddr as AccountAddr, ProposerTimestamp, ProvisionHash, ProvisionTxRootsContext,
    ProvisionTxRootsMap, Provisions, ProvisionsRoot, QcContext, QuorumCertificate, ReadySignal,
    ReshapeTrigger, Resolutions, RevealChain, Round, SetRoot, SettledTxsRoot, ShardId, ShardLoad,
    SplitChildRoots, StateClaim, StateClaimsRoot, StateRoot, StateRootContext, Stopwatch,
    StoredReceipt, SubstateKey, SweepFrontier, TickManifest, TickManifestRoot, Timeout,
    TimeoutContext, TopologySnapshot, Transaction, TransactionRoot, TransactionRootContext, TxHash,
    TxsInFlight, UnsettledTx, ValidatorId, Verifiable, VerificationKind, Verified, Verifier,
    Verify, VoteCount, VrfProof, WeightedTimestamp, WitnessSources, absorb_committed_cells,
    commit_witness_window, derive_leaves, fees_over_certificates, local_settled_tx_hashes,
    missed_proposals_since_prev_commit, next_reveal_chain, protocol_statics, shard_reveal_sign,
    signed_bytes, verify_shard_vote_equivocation, vrf_output_from_proof,
};

use crate::local_crossings::{
    disagreeing_parent_reading, keep_standing_unclaimed, misstated_unclaimed, parent_claims,
};
use crate::read_fence::{Dropped, drop_refused};

/// Result of QC verification and assembly.
pub struct QcVerificationResult {
    /// Block being voted on.
    pub block_hash: BlockHash,
    /// Assembled QC, or `None` if quorum wasn't reached or aggregation failed.
    ///
    /// Carried as a [`Verified<QuorumCertificate>`] because the QC is verified
    /// by construction: every vote that fed into the aggregation was
    /// individually signature-checked, the signer set cleared the quorum
    /// threshold, and [`Verified::<QuorumCertificate>::from_verified_votes`]
    /// produced the typed witness from those preconditions.
    pub qc: Option<Verified<QuorumCertificate>>,
    /// Verified votes returned when no QC was formed (for accumulation across rounds).
    /// Empty when a QC is successfully built.
    pub verified_votes: Vec<(usize, Verified<BlockVote>)>,
}

/// Verify block votes and build a quorum certificate if quorum is reached.
///
/// Thin composition of [`verify_vote_batch`] (signature verification) and
/// [`Verified::<QuorumCertificate>::from_verified_votes`] (aggregation +
/// bitfield + timestamp) with the quorum-threshold check between them.
/// Returns an empty `verified_votes` vec on success and the full verified
/// set on failure so the caller can accumulate across rounds.
///
/// Called from the dispatch layer via `Action::VerifyAndBuildQuorumCertificate`;
/// the split helpers exist for focused unit testing of each phase.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn verify_and_build_qc(
    verifier: &dyn Verifier,
    network: &NetworkDefinition,
    block_hash: BlockHash,
    shard_id: ShardId,
    height: BlockHeight,
    round: Round,
    parent_block_hash: BlockHash,
    parent_weighted_timestamp: WeightedTimestamp,
    votes_to_verify: Vec<(usize, BlockVote, ConsensusPublicKey)>,
    already_verified: Vec<(usize, Verified<BlockVote>)>,
    total_votes: VoteCount,
) -> QcVerificationResult {
    let signing_message = signed_bytes(
        &BlockVoteMessage {
            shard_group: shard_id,
            height,
            round,
            block_hash,
            parent_block_hash,
        },
        network,
    );

    let all_verified = verify_vote_batch(
        verifier,
        block_hash,
        &signing_message,
        votes_to_verify,
        already_verified,
    );

    let verified_votes_count = VoteCount::of(all_verified.len());
    if all_verified.is_empty() || !VoteCount::has_quorum(verified_votes_count, total_votes) {
        return QcVerificationResult {
            block_hash,
            qc: None,
            verified_votes: all_verified,
        };
    }

    let qc = Verified::<QuorumCertificate>::from_verified_votes(
        verifier,
        block_hash,
        shard_id,
        height,
        round,
        parent_block_hash,
        parent_weighted_timestamp,
        &all_verified,
    );

    let return_votes = if qc.is_none() { all_verified } else { vec![] };
    QcVerificationResult {
        block_hash,
        qc,
        verified_votes: return_votes,
    }
}

/// Verify a batch of vote signatures, appending the valid ones to
/// `already_verified` and returning the combined verified set.
///
/// Wraps [`Verified::<BlockVote>::verify_batch`] with the committee
/// bookkeeping (`(idx, vote, pubkey)` tuples → `(idx, verified)`); the typed
/// batch verifier owns the verification work and the individual-verify fallback.
pub(crate) fn verify_vote_batch(
    verifier: &dyn Verifier,
    block_hash: BlockHash,
    signing_message: &[u8],
    votes_to_verify: Vec<(usize, BlockVote, ConsensusPublicKey)>,
    already_verified: Vec<(usize, Verified<BlockVote>)>,
) -> Vec<(usize, Verified<BlockVote>)> {
    let mut all_verified = already_verified;

    if votes_to_verify.is_empty() {
        return all_verified;
    }

    // Capture per-vote bookkeeping (`idx` and the raw vote's voter for
    // failure logging) alongside the `(vote, pubkey)` pairs the typed
    // verifier consumes.
    let mut bookkeeping: Vec<(usize, ValidatorId)> = Vec::with_capacity(votes_to_verify.len());
    let mut to_verify: Vec<(BlockVote, ConsensusPublicKey)> =
        Vec::with_capacity(votes_to_verify.len());
    for (idx, vote, pk) in votes_to_verify {
        bookkeeping.push((idx, vote.voter()));
        to_verify.push((vote, pk));
    }

    let results = Verified::<BlockVote>::verify_batch(verifier, signing_message, to_verify);

    for ((idx, voter), result) in bookkeeping.into_iter().zip(results) {
        if let Some(verified) = result {
            all_verified.push((idx, verified));
        } else {
            tracing::warn!(?voter, ?block_hash, "Invalid vote signature detected");
        }
    }

    all_verified
}

/// Result of building a proposal block.
pub struct ProposalResult {
    /// The constructed proposal block (header + payload).
    pub block: Block,
    /// Hash of the constructed block, cached so callers don't recompute.
    pub block_hash: BlockHash,
    /// JMT prepared-commit closure from the proposer's pre-commit,
    /// threaded to the commit pipeline so the proposer doesn't recompute
    /// on commit.
    pub(crate) prepared_commit: PreparedCommit,
    /// JMT snapshot from the speculative state-root computation.
    /// Inserted into `PendingChain` so child verifications can chain on
    /// top.
    pub jmt_snapshot: Arc<JmtSnapshot>,
}

/// Build a proposal block, always computing the state root via `prepare_block_commit`.
///
/// Uses the overlay (the view's pending snapshots) when the JMT hasn't committed the
/// parent yet, so certificates are always included when available.
///
/// Algorithm:
/// 1. `prepare_block_commit()` with overlay snapshots → `state_root` + handle
/// 2. Compute tx/cert/receipt/provision roots
/// 3. Build `BlockHeader` + `Block`, hash it
/// 4. Return block, hash, prepared commit handle
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)] // one linear block-assembly pipeline
pub fn build_proposal<S: ShardChainWriter + SubstateStore + VersionedStore + SweepIndex>(
    view: &Arc<SubstateView<S>>,
    proposer: ValidatorId,
    height: BlockHeight,
    round: Round,
    parent_block_hash: BlockHash,
    parent_qc: QuorumCertificate,
    timestamp: ProposerTimestamp,
    is_fallback: bool,
    parent_state_root: StateRoot,
    parent_block_height: BlockHeight,
    transactions: &Capped<Vec<Arc<Verified<Transaction>>>, MAX_TXS_PER_BLOCK>,
    certificates: Capped<Vec<Arc<Verifiable<Finalization>>>, MAX_FINALIZED_TX_PER_BLOCK>,
    local_shard: ShardId,
    chain_origin: WeightedTimestamp,
    topology_snapshot: &TopologySnapshot,
    provisions: Capped<Vec<Arc<Verifiable<Provisions>>>, MAX_PROVISIONS_PER_BLOCK>,
    abandonment_records: Capped<Vec<AbandonmentRecord>, MAX_PROVISION_TARGET_SHARDS>,
    state_claims: Capped<Vec<StateClaim>, MAX_STATE_CLAIMS_PER_BLOCK>,
    parent_in_flight: TxsInFlight,
    parent_settled_frontier: BlockHeight,
    parent_sweep_frontier: SweepFrontier,
    parent_load: Option<ShardLoad>,
    substate_bytes: Option<u64>,
    ready_signals: Capped<Vec<ReadySignal>, MAX_READY_SIGNALS_PER_BLOCK>,
    reshape_trigger: Option<ReshapeTrigger>,
    randomness_reveal: VrfProof,
    parent_witness_leaves: &[Hash],
    beacon_witness_base: BeaconWitnessLeafCount,
    parent_reveal_chain: RevealChain,
    parent_committee_anchor_epoch: Epoch,
    committee_anchor_epoch: Epoch,
    carry_split_child_roots: bool,
    terminal_settled_txs: Option<SettledTxsRoot>,
    frontier: &FrontierInputs,
) -> ProposalResult {
    // The proposer builds on an anchored view of its parent — the state
    // this block's settling movements land on, the pending chain its
    // priors are judged against, and the reads execution accumulated.
    let base_reads = view.take_base_reads();
    // Read through the view's snapshot, which resolves the base at the
    // anchor height. Reading the view directly resolves at whatever this
    // validator has persisted, and a movement baseline that moves with
    // persistence progress forks the root against replicas that lag.
    let anchored = view.snapshot();
    // A transaction this chain already committed — its own or an
    // inherited marker is present in the parent state — is dropped, and
    // one whose marker another transaction here names is deferred: the
    // first of each set is kept, and everything below reads the kept
    // list, so the block a verifier refuses is never built. The dropped
    // ones stay pooled.
    let mut transactions = transactions.clone();
    without_colliding_committed_cells(local_shard, chain_origin, &mut transactions, &anchored);
    // The same for a transaction whose member row key another's takes.
    without_colliding_member_rows(local_shard, &mut transactions, &anchored);
    let transactions = &transactions;
    // The sweep, before the root it moves. Removals are ordinary writes,
    // so they fold in with the block's settling receipts and land under
    // `state_root` like anything else — and the frontier the walk stops
    // at is what the header claims, since that is what a verifier
    // recomputes.
    //
    // Walked through the view rather than the store: a cell a certified
    // but unpersisted ancestor created or retired is one this block's
    // removals must account for, and the store alone does not know it.
    let (removals, sweep_frontier) = sweep_for_block(
        view.as_ref(),
        parent_sweep_frontier,
        parent_qc.weighted_timestamp(),
    );
    // What the chain writes of its own accord: a committed-transaction
    // cell for every transaction the block carries. Derived from the
    // block's own transactions, so every reader of the root — the
    // proposer's voters, a replica committing on the certificate alone,
    // a split child following the block — derives the same set.
    let creations = committed_tx_cells(local_shard, transactions.iter().map(|tx| &***tx));
    // The lines naming what this block's tick holds and lets go, and
    // what the block does to tick membership.
    let tick_manifest: Arc<TickManifest> = Arc::new(Capped::empty());
    let members = MemberInputs::from_parts(
        local_shard,
        height,
        parent_qc.weighted_timestamp(),
        transactions.iter().map(|tx| &***tx),
        &certificates,
        &abandonment_records,
        Arc::clone(&tick_manifest),
    );
    let (state_root, jmt_snapshot, prepared) = view.base().prepare_block_commit(
        ParentAnchor {
            state_root: parent_state_root,
            height: parent_block_height,
            state: &anchored,
            pending: view.pending_snapshots(),
            base_reads: Some(&base_reads),
        },
        &certificates,
        ChainWrites {
            creations: &creations,
            removals: &removals,
            frontier,
            state_claims: &state_claims,
            members: &members,
        },
        height,
    );

    let split_child_roots = carry_split_child_roots
        .then(|| split_child_roots_for_header(&jmt_snapshot, local_shard, height))
        .flatten();

    // Lift each `Verified<Transaction>` into `Verifiable` so block
    // construction and per-root compute calls see the form that
    // `Block.transactions` carries.
    let transactions = transactions.map(|tx| Arc::new(Verifiable::from((**tx).clone())));

    let receipts: Vec<StoredReceipt> = certificates
        .iter()
        .flat_map(|fw| fw.receipts().iter().cloned())
        .collect();

    // Finalize the beacon-witness commitment: the content leaves append
    // onto the coordinator-resolved parent window. The
    // missed-round walk derives here from the same `(parent_round, round,
    // topology)` the verifier reads, so proposer and verifier share the one
    // helper and their leaf order can't drift.
    let witness_sources = Arc::new(WitnessSources::new(
        ready_signals,
        reshape_trigger,
        randomness_reveal,
    ));
    let missed = missed_proposals_since_prev_commit(
        local_shard,
        height,
        parent_qc.round(),
        round,
        topology_snapshot,
    );
    let new_witness_leaves = derive_leaves(
        local_shard,
        topology_snapshot,
        &receipts,
        &missed,
        &witness_sources,
    );
    let (beacon_witness_root, beacon_witness_leaf_count) = commit_witness_window(
        parent_witness_leaves,
        &new_witness_leaves,
        beacon_witness_base,
    );

    // The reveal chain closes the block's anchor epoch: it extends the
    // parent's when both anchor in the same epoch and reseeds otherwise, so
    // a boundary block — the last anchored in the epoch it ends — carries
    // that epoch's whole run.
    let reveal_chain = next_reveal_chain(
        parent_reveal_chain,
        parent_committee_anchor_epoch,
        committee_anchor_epoch,
        vrf_output_from_proof(witness_sources.randomness_reveal()),
    );

    let mut provision_hashes: Vec<ProvisionHash> = provisions.iter().map(|p| p.hash()).collect();
    provision_hashes.sort();

    let transaction_root = Verified::<TransactionRoot>::compute(&transactions).into_inner();
    let certificate_root = Verified::<CertificateRoot>::compute(&certificates).into_inner();
    let local_receipt_root = Verified::<LocalReceiptRoot>::compute(&receipts).into_inner();
    let raw_provision_hashes: Vec<Hash> = provision_hashes.iter().map(|h| h.into_raw()).collect();
    let provision_root = Verified::<ProvisionsRoot>::compute(&raw_provision_hashes).into_inner();
    let provision_tx_roots = Verified::<ProvisionTxRootsMap>::compute(
        local_shard,
        topology_snapshot,
        &transactions,
        &committing_shards(topology_snapshot),
    )
    .into_inner();

    // The drain is deterministic from the block's own content: the
    // places its transactions take, less those its certificates give
    // back. Both terms read off this block, so a validator reaches the
    // same total without any history behind it.
    let txs_in_flight = parent_in_flight
        .saturating_add(transactions.len() as u64)
        .saturating_sub(certificates.iter().fold(0u64, |total, fw| {
            total.saturating_add(fw.as_unverified().released())
        }));

    // Settlement order, folded the same way and read off the same list.
    // The certificates arrive in the order the ticks executed and the
    // selection keeps it, so the frontier lands on the last determined
    // half the block carries; a proposal that ordered them otherwise, or
    // reached below the parent's frontier, is what verification refuses.
    let settled_tick_frontier = certificates
        .iter()
        .filter(|fw| fw.as_unverified().is_determined())
        .map(|fw| fw.as_unverified().tick_id().block_height())
        .fold(parent_settled_frontier, BlockHeight::max);

    // The running totals: the attested one advanced by what this block's
    // certificates report, and the declared one by what its transactions
    // reserve on this shard — the same figure the block's own caps
    // admitted it against. An unresolvable parent load falls back to a
    // zero baseline; a voter that cannot resolve the parent abstains
    // from the load check on its side.
    let load = parent_load.unwrap_or(ShardLoad::ZERO).advance(
        fees_over_certificates(&certificates),
        local_work_over(
            transactions.iter().map(|tx| &***tx),
            topology_snapshot.shard_trie(),
            local_shard,
        ),
        substate_bytes,
    );

    // What departed shards left unresolved, committed so a verdict on it
    // outlives the settled set the records were read from.
    let abandonment_root = Verified::<AbandonmentRoot>::compute(&abandonment_records).into_inner();
    // Proofs of counterparts' cells, committed so every replica folds
    // the same answers at this height.
    let state_claims_root = Verified::<StateClaimsRoot>::compute(&state_claims).into_inner();
    // What the provisions engage, committed so a sealed form keeps the
    // entries the engagement tier folds after the bodies are gone.
    let engagement_root = EngagementRoot::over(&Engagement::of_provisions(&provisions));
    let tick_manifest_root = Verified::<TickManifestRoot>::compute(&tick_manifest).into_inner();

    let header = BlockHeader::new(BlockHeaderParts {
        shard_id: local_shard,
        height,
        parent_block_hash,
        parent_qc: parent_qc.into(),
        proposer,
        timestamp,
        round,
        is_fallback,
        state_root,
        transaction_root,
        certificate_root,
        local_receipt_root,
        provision_root,
        provision_tx_roots,
        abandonment_root,
        state_claims_root,
        engagement_root,
        tick_manifest_root,
        txs_in_flight,
        settled_tick_frontier,
        sweep_frontier,
        beacon_witness_root,
        beacon_witness_leaf_count,
        beacon_witness_base,
        reveal_chain,
        split_child_roots,
        terminal_settled_txs,
        load,
    });

    let block = Block::Live {
        header,
        transactions: Arc::new(transactions),
        certificates: Arc::new(certificates),
        provisions: Arc::new(provisions),
        abandonment_records: Arc::new(abandonment_records),
        state_claims: Arc::new(state_claims),
        tick_manifest,
        witness_sources,
    };

    let block_hash = block.hash();

    ProposalResult {
        block,
        block_hash,
        prepared_commit: prepared,
        jmt_snapshot,
    }
}

/// Final-epoch headers of a splitting shard carry the root node's two
/// child hashes, read from the same JMT computation that produced the
/// header's state root. A leaf root (≤1-key tree) yields no pair;
/// replicas then reject the header, which can only arise if a shard
/// drained to nearly nothing while its split stayed pending.
fn split_child_roots_for_header(
    jmt_snapshot: &JmtSnapshot,
    local_shard: ShardId,
    height: BlockHeight,
) -> Option<SplitChildRoots> {
    let pair = jmt_snapshot
        .root_child_hashes()
        .map(|(left, right)| SplitChildRoots { left, right });
    if pair.is_none() {
        tracing::error!(
            shard = ?local_shard,
            height = height.inner(),
            "split-pending final epoch but the state root has no internal root node"
        );
    }
    pair
}

/// A package published in this block is usable by transactions admitted
/// after it commits, and this is where that becomes true.
/// The completion event for one check on `block_hash`: a pass, or a
/// refusal logged with the verifier's reason.
fn check_completed<T, E: std::fmt::Display>(
    block_hash: BlockHash,
    kind: VerificationKind,
    result: Result<T, E>,
) -> ProtocolEvent {
    let outcome = match result {
        Ok(_) => CheckOutcome::Checked { bytes_delta: 0 },
        Err(reason) => {
            tracing::warn!(?block_hash, ?kind, %reason, "Block check FAILED");
            CheckOutcome::Refused
        }
    };
    ProtocolEvent::BlockCheckCompleted {
        block_hash,
        kind,
        outcome,
    }
}

/// The placement and the table each name's own commit ran under, by the
/// epoch that froze them.
///
/// Keyed on the committee anchor and not on the block's own, because
/// that is the one admission judged the ceiling at and the one the
/// ledger priced under — a block's two anchors straddle an epoch cut
/// once per window, and a record is written a deadline after the commit
/// it names, so neither is reliably the window carrying the record.
///
/// Read off the committed beacon chain rather than the live schedule. A
/// name outlives the window that froze it for as long as its counterpart
/// stays silent, which no retention bound reaches; the chain holds one
/// state per epoch contiguously from genesis, so every validator
/// resolves the same pair for the same anchor however far back it sits.
///
/// An epoch the chain does not hold is one above this node's fold. Its
/// names are left out, and the check that misses one waits on the terms
/// an unheld body already sets.
fn commit_windows_for(
    chain: &dyn BeaconChainReader,
    windows: EpochWindows,
    entries: &[UnsettledTx],
) -> HashMap<Epoch, CommitWindow> {
    let mut resolved: HashMap<Epoch, CommitWindow> = HashMap::new();
    for stated in entries.iter().map(|entry| entry.committed.committee_anchor) {
        let epoch = windows.epoch_for(stated);
        if let hash_map::Entry::Vacant(slot) = resolved.entry(epoch)
            && let Some(state) = chain.get_state_by_epoch(epoch)
        {
            slot.insert(state.commit_window());
        }
    }
    resolved
}

fn absorb_finalized_cells(ticks: &[Arc<Verifiable<Finalization>>], derivation: &dyn Derivation) {
    let receipts: Vec<Arc<ConsensusReceipt>> = ticks
        .iter()
        .flat_map(|fw| fw.consensus_receipts())
        .collect();
    absorb_committed_cells(receipts.iter().map(AsRef::as_ref), derivation);
}

/// Handle the shard-owned delegated [`Action`] variants.
///
/// Outcomes flow through `ctx.notify` (state-machine inputs) and
/// `ctx.commit_prepared` (prepared blocks for the `io_loop`'s chain). Variants
/// owned by other coordinator crates hit `unreachable!()` — the caller
/// (node's dispatcher) routes by variant prefix.
#[allow(clippy::too_many_lines)] // single dispatch over shard-owned Action variants
pub fn handle_action<S, N>(action: Action, ctx: &ActionContext<'_, S, N>)
where
    S: ShardStorage,
    N: Network,
{
    match action {
        Action::VerifyAndBuildQuorumCertificate {
            block_hash,
            shard_id,
            height,
            round,
            parent_block_hash,
            parent_weighted_timestamp,
            votes_to_verify,
            verified_votes,
            total_votes,
        } => {
            let start = Stopwatch::start();
            let result = verify_and_build_qc(
                ctx.verifier,
                ctx.topology_snapshot.network(),
                block_hash,
                shard_id,
                height,
                round,
                parent_block_hash,
                parent_weighted_timestamp,
                votes_to_verify,
                verified_votes,
                total_votes,
            );
            record_signature_verification_latency("vote", start.elapsed().as_secs_f64());
            ctx.notify_protocol(ProtocolEvent::QuorumCertificateResult {
                block_hash: result.block_hash,
                qc: result.qc,
                verified_votes: result.verified_votes,
            });
        }

        Action::VerifyQcSignature {
            qc,
            public_keys,
            quorum_threshold,
            block_hash,
        } => {
            let qc_ctx = QcContext {
                verifier: ctx.verifier,
                network: ctx.topology_snapshot.network(),
                public_keys: &public_keys,
                quorum_threshold,
            };
            // The verified arm short-circuits inside `upgrade`; only the
            // unverified arm performs signature work, so we gate the latency
            // metric on `is_verified` to keep the histogram aligned with
            // actual aggregation calls.
            let measured = !qc.is_verified();
            let start = Stopwatch::start();
            let result = qc.upgrade(&qc_ctx).map_err(|(_, err)| err);
            if measured {
                record_signature_verification_latency("qc", start.elapsed().as_secs_f64());
            }
            ctx.notify_protocol(ProtocolEvent::QcSignatureVerified { block_hash, result });
        }

        Action::VerifyRemoteHeaderQc {
            certified_header,
            sender,
            committee_public_keys,
            quorum_threshold,
            shard,
            height,
        } => {
            let start = Stopwatch::start();
            let qc_ctx = QcContext {
                verifier: ctx.verifier,
                network: ctx.topology_snapshot.network(),
                public_keys: &committee_public_keys,
                quorum_threshold,
            };
            // SAFETY for `from_qc_attestation`: the verified QC's source
            // committee accepted the header (and its `parent_qc`) before
            // voting; this node skips local per-root verification because
            // the QC's BFT majority attests on its behalf.
            let result = Box::new(
                certified_header
                    .qc()
                    .verify(&qc_ctx)
                    .map_err(CertifiedHeaderVerifyError::from)
                    .and_then(|verified_qc| {
                        Verified::<CertifiedBlockHeader>::from_qc_attestation(
                            certified_header.header().clone(),
                            verified_qc,
                        )
                    }),
            );
            record_signature_verification_latency(
                "remote_header_qc",
                start.elapsed().as_secs_f64(),
            );
            ctx.notify_protocol(ProtocolEvent::RemoteHeaderQcVerified {
                shard,
                height,
                sender,
                result,
            });
        }

        Action::VerifyShardForkProof { proof, committees } => {
            let start = Stopwatch::start();
            let verified = proof
                .verify_resolved(ctx.verifier, ctx.topology_snapshot.network(), &committees)
                .is_ok();
            record_signature_verification_latency(
                "shard_fork_proof",
                start.elapsed().as_secs_f64(),
            );
            ctx.notify_protocol(ProtocolEvent::ShardForkProofVerified { proof, verified });
        }

        Action::VerifyShardVoteEquivocation { evidence, pubkey } => {
            let start = Stopwatch::start();
            let verified = verify_shard_vote_equivocation(
                ctx.verifier,
                &evidence,
                ctx.topology_snapshot.network(),
                &pubkey,
            )
            .is_ok();
            record_signature_verification_latency(
                "shard_vote_equivocation",
                start.elapsed().as_secs_f64(),
            );
            ctx.notify_protocol(ProtocolEvent::ShardVoteEquivocationVerified {
                evidence,
                verified,
            });
        }

        Action::VerifyTransactionRoot {
            block_hash,
            expected_root,
            transactions,
            validity_anchor,
        } => {
            let start = Stopwatch::start();
            let tx_ctx = TransactionRootContext {
                transactions: &transactions,
                validity_anchor,
            };
            let result = expected_root.verify(&tx_ctx);
            record_signature_verification_latency(
                "transaction_root",
                start.elapsed().as_secs_f64(),
            );
            ctx.notify_protocol(check_completed(
                block_hash,
                VerificationKind::TransactionRoot,
                result,
            ));
        }

        Action::VerifyProvisionTxRoots {
            block_hash,
            expected,
            transactions,
            topology_snapshot,
        } => {
            let start = Stopwatch::start();
            let committing = committing_shards(&topology_snapshot);
            let ptx_ctx = ProvisionTxRootsContext {
                local_shard: ctx.shard,
                topology_snapshot: &topology_snapshot,
                transactions: &transactions,
                committing: &committing,
            };
            let result = expected.verify(&ptx_ctx);
            record_signature_verification_latency(
                "provision_tx_roots",
                start.elapsed().as_secs_f64(),
            );
            ctx.notify_protocol(check_completed(
                block_hash,
                VerificationKind::ProvisionTxRoots,
                result,
            ));
        }

        Action::VerifyReservations {
            block_hash,
            demands,
            read_height,
        } => {
            // Balance reads anchor at the height the block's ancestry
            // proves committed — the coordinator dispatches only once
            // its own commit pipeline has materialized it — so every
            // replica reads identical state regardless of local commit
            // or persistence progress.
            let view = ctx.pending_chain.view_at_committed_tip();
            let mut result: Result<(), String> = Ok(());
            'demands: for demand in &demands {
                // The reservation engages only for signers the payer's
                // rule admits — the stored rule, read beside the balance
                // at the same anchored height, through the statics seam
                // so its encoding stays the VM's fact.
                let Ok(payer) = AccountAddr::try_from(demand.vault.owner) else {
                    result = Err(format!(
                        "payer {:?}: the vault owner is not a principal",
                        demand.vault.owner
                    ));
                    break;
                };
                let Some(auth_cell) = view.get_substate_at_height(demand.auth_cell, read_height)
                else {
                    result = Err(format!(
                        "payer {:?}: authority history unavailable at height {}",
                        demand.vault.owner,
                        read_height.inner()
                    ));
                    break;
                };
                for attested_by in &demand.attesting_sets {
                    if !protocol_statics().rule_admits(auth_cell.as_deref(), payer, attested_by) {
                        result = Err(format!(
                            "payer {:?}: rule does not admit the attesting set {attested_by:?}",
                            demand.vault.owner
                        ));
                        break 'demands;
                    }
                }
                let Some(cell) = view.get_substate_at_height(demand.vault, read_height) else {
                    result = Err(format!(
                        "payer {:?}: balance history unavailable at height {}",
                        demand.vault.owner,
                        read_height.inner()
                    ));
                    break;
                };
                let balance = cell
                    .and_then(|bytes| <[u8; 16]>::try_from(bytes.as_slice()).ok())
                    .map_or(0u128, u128::from_le_bytes);
                if balance < demand.demand {
                    result = Err(format!(
                        "payer {:?}: balance {balance} under reservation demand {}",
                        demand.vault.owner, demand.demand
                    ));
                    break;
                }
            }
            ctx.notify_protocol(check_completed(
                block_hash,
                VerificationKind::Reservations,
                result,
            ));
        }

        Action::VerifyResolutions {
            block_hash,
            entries,
            successes,
            anchor,
            windows,
        } => {
            // A resolution names a transaction committed before it — a
            // record epochs after the commit, a finalization a tick or
            // more after — so the store's persist lag never reaches a
            // name, and a body lifted out of it carries no derivation of
            // its own: this node derives it, and one it cannot derive it
            // does not hold.
            let hashes: Vec<TxHash> = entries
                .iter()
                .map(|entry| entry.tx_hash)
                .chain(successes.iter().copied())
                .collect();
            let derivation = ctx.executor.derivation();
            let held: HashMap<TxHash, Verified<Transaction>> = ctx
                .pending_chain
                .transactions_batch(&hashes)
                .into_iter()
                .filter(|tx| tx.try_derived(derivation.as_ref()).is_ok())
                .map(|tx| (tx.hash(), tx))
                .collect();
            // A name says where this chain committed its transaction,
            // and the block at that height is what checks it: one this
            // store holds either carries the transaction under the
            // anchor the name states or refutes the name, and one it
            // does not hold leaves the name unanswered, as a body it
            // does not hold does.
            let committed_at = |entry: &UnsettledTx| -> Option<bool> {
                let height = entry.committed.height;
                let carried = ctx.pending_chain.transactions_for_block(height)?;
                let header = ctx.pending_chain.certified_header(height)?;
                Some(
                    carried.iter().any(|tx| tx.hash() == entry.tx_hash)
                        && header.header().parent_qc().weighted_timestamp()
                            == entry.committed.anchor,
                )
            };
            let committed_windows = commit_windows_for(ctx.beacon_chain, windows, &entries);
            let verdict = Resolutions::of(entries, |entry| {
                let tx = held.get(&entry.tx_hash)?;
                // A window above this node's fold is one to wait for, on
                // the terms an unheld body already sets.
                let at =
                    committed_windows.get(&windows.epoch_for(entry.committed.committee_anchor))?;
                let classified =
                    Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), &at.trie);
                let restated = committed_at(entry)?
                    && UnsettledTx::for_transaction(
                        tx,
                        entry.committed,
                        classified.local_price(tx, ctx.shard, &at.prices),
                        classified.escrowed_records(ctx.shard),
                        &at.prices,
                    ) == *entry;
                Some(restated)
            })
            .and_successes(successes, |tx_hash| {
                // A success at or past the deadline is one a leg may
                // already have reclaimed against. That the members held
                // to it awaited nobody is the outcome's own attestation,
                // read where the names were gathered.
                held.get(&tx_hash)
                    .map(|tx| Deadline::of_transaction(tx).passed(anchor))
            });
            // An exact answer passes; a wrong figure or an overdue
            // success refuses the block; a name this validator's store
            // never held is neither — the check waits for the body.
            let outcome = match verdict {
                Resolutions::Exact => CheckOutcome::Checked { bytes_delta: 0 },
                Resolutions::Wrong(tx_hash) => {
                    tracing::warn!(
                        ?block_hash,
                        ?tx_hash,
                        "Resolutions verification FAILED: a record misstates a figure"
                    );
                    CheckOutcome::Refused
                }
                Resolutions::Overdue(tx_hash) => {
                    tracing::warn!(
                        ?block_hash,
                        ?tx_hash,
                        "Resolutions verification FAILED: a finalization succeeds past the deadline"
                    );
                    CheckOutcome::Refused
                }
                Resolutions::Unknown(tx_hash) => {
                    CheckOutcome::Deferred(DeferOn::Bodies(vec![tx_hash]))
                }
            };
            ctx.notify_protocol(ProtocolEvent::BlockCheckCompleted {
                block_hash,
                kind: VerificationKind::Resolutions,
                outcome,
            });
        }

        Action::VerifyProvisionRoot {
            block_hash,
            expected_root,
            batch_hashes,
        } => {
            let start = Stopwatch::start();
            let raw_batch_hashes: Vec<Hash> = batch_hashes.iter().map(|h| h.into_raw()).collect();
            let result = expected_root.verify(raw_batch_hashes.as_slice());
            record_signature_verification_latency("provision_root", start.elapsed().as_secs_f64());
            ctx.notify_protocol(check_completed(
                block_hash,
                VerificationKind::ProvisionRoot,
                result,
            ));
        }

        Action::VerifyCertificateRoot {
            block_hash,
            expected_root,
            certificates,
        } => {
            let start = Stopwatch::start();
            let result = expected_root.verify(certificates.as_slice());
            record_signature_verification_latency(
                "certificate_root",
                start.elapsed().as_secs_f64(),
            );
            ctx.notify_protocol(check_completed(
                block_hash,
                VerificationKind::CertificateRoot,
                result,
            ));
        }

        Action::VerifyBeaconWitnessRoot {
            block_hash,
            expected_root,
            expected_leaf_count,
            claimed_base,
            claimed_reveal_chain,
            parent_reveal_chain,
            parent_committee_anchor_epoch,
            committee_anchor_epoch,
            parent_leaves_start,
            parent_witness_leaves,
            parent_round,
            height,
            round,
            witness_sources,
            substate_bytes,
            claimed_substate_bytes,
            thresholds,
            finalizations,
            topology_snapshot,
        } => {
            let start = Stopwatch::start();
            let receipts: Vec<StoredReceipt> = finalizations
                .iter()
                .flat_map(|fw| fw.receipts().iter().cloned())
                .collect();
            let bw_ctx = BeaconWitnessRootContext {
                verifier: ctx.verifier,
                expected_leaf_count,
                claimed_base,
                claimed_reveal_chain,
                parent_reveal_chain,
                parent_committee_anchor_epoch,
                committee_anchor_epoch,
                parent_leaves_start,
                parent_witness_leaves,
                parent_round,
                shard: ctx.shard,
                height,
                round,
                receipts: &receipts,
                witness_sources: &witness_sources,
                substate_bytes,
                claimed_substate_bytes,
                thresholds,
                topology_snapshot: &topology_snapshot,
            };
            // `verify` gates the reveal's signature validity (its proof by
            // the block's proposer) before folding its digest, so an
            // unverified reveal can never reach the root — the grind check
            // lives inside the shared verifier, off the main loop on the
            // dispatch pool.
            let result = expected_root.verify(&bw_ctx);
            record_signature_verification_latency(
                "beacon_witness_root",
                start.elapsed().as_secs_f64(),
            );
            ctx.notify_protocol(check_completed(
                block_hash,
                VerificationKind::BeaconWitnessRoot,
                result,
            ));
        }

        Action::VerifyStateRoot {
            block_hash,
            parent_block_hash,
            parent_state_root,
            parent_block_height,
            expected_root,
            expected_local_receipt_root,
            finalizations,
            creations,
            block_height,
            claimed_split_child_roots,
            split_child_roots_required,
            terminal_settled_txs_required,
            claimed_terminal_settled_txs,
            parent_weighted_timestamp,
            settled_txs_window_floor,
            parent_sweep_frontier,
            claimed_sweep_frontier,
            frontier,
            members,
            fence,
            state_claims,
            abandonment_records,
        } => {
            // Pre-flight: hash the receipts and compare to the QC'd
            // `local_receipt_root`. If they diverge, JMT recomputation
            // can't match `state_root` either (receipts ARE the JMT input),
            // so short-circuit on the receipt-root failure alone — the
            // pipeline rejects the block on the receipt-root refusal
            // error without needing a synthetic state-root failure event.
            let stored_receipts: Vec<StoredReceipt> = finalizations
                .iter()
                .flat_map(|fw| fw.receipts().iter().cloned())
                .collect();

            let receipt_start = Stopwatch::start();
            let receipt_result = expected_local_receipt_root.verify(stored_receipts.as_slice());
            record_signature_verification_latency(
                "local_receipt_root",
                receipt_start.elapsed().as_secs_f64(),
            );
            let receipt_root_valid = receipt_result.is_ok();
            ctx.notify_protocol(check_completed(
                block_hash,
                VerificationKind::LocalReceiptRoot,
                receipt_result,
            ));

            if !receipt_root_valid {
                return;
            }

            let start = Stopwatch::start();
            let view = ctx
                .pending_chain
                .view_at(parent_block_hash, parent_block_height);
            // The view is freshly anchored — nothing has read through
            // it, so there is no execution cache to carry.
            let anchored = view.snapshot();
            // The block's sweep, recomputed. A walk from the parent's
            // frontier under the cap lands on exactly one position, so
            // the frontier the header claims either is the one this
            // produces or the block is refused: a claim short of it is a
            // sweep the proposer declined to finish, and one past it
            // reaches cells the clock does not yet allow. The removal
            // set needs no separate check — it is what this same walk
            // returned.
            let (removals, computed_sweep_frontier) = sweep_for_block(
                view.as_ref(),
                parent_sweep_frontier,
                parent_weighted_timestamp,
            );
            if computed_sweep_frontier != claimed_sweep_frontier {
                tracing::warn!(
                    ?block_hash,
                    height = block_height.inner(),
                    ?claimed_sweep_frontier,
                    ?computed_sweep_frontier,
                    "Rejecting block whose sweep frontier is not the one its interval produces"
                );
                ctx.notify_protocol(ProtocolEvent::BlockCheckCompleted {
                    block_hash,
                    kind: VerificationKind::StateRoot,
                    outcome: CheckOutcome::Refused,
                });
                return;
            }
            // A block carries no transaction this chain already
            // committed — its own or inherited marker present in the
            // parent state — and none whose marker another of its
            // transactions names. The first is the re-inclusion rule,
            // read off state so a restarted or snap-synced voter answers
            // as a live one does; two creations at one key would halt
            // every replica in the fold's assert. A validity rule at vote
            // time, judged against the anchored view: a replica following
            // a certified block never evaluates it.
            if let Some(key) = colliding_committed_cell(&creations, &anchored) {
                tracing::warn!(
                    ?block_hash,
                    height = block_height.inner(),
                    ?key,
                    "Rejecting block whose committed cell is already present or named twice"
                );
                ctx.notify_protocol(ProtocolEvent::BlockCheckCompleted {
                    block_hash,
                    kind: VerificationKind::StateRoot,
                    outcome: CheckOutcome::Refused,
                });
                return;
            }
            // Nor one whose member row key a standing row or another
            // of its transactions takes: one row would stand for two.
            if let Some(tx) = colliding_member_row(
                members.shard,
                members.transactions.iter().map(|(tx, _)| *tx),
                &anchored,
            ) {
                tracing::warn!(
                    ?block_hash,
                    height = block_height.inner(),
                    ?tx,
                    "Rejecting block whose member row key is already taken"
                );
                ctx.notify_protocol(ProtocolEvent::BlockCheckCompleted {
                    block_hash,
                    kind: VerificationKind::StateRoot,
                    outcome: CheckOutcome::Refused,
                });
                return;
            }
            // The read frontier's fence, judged against the parent
            // state: a record presence below the floor its producer's
            // lineage has been read to, one below a same-block absence
            // of its key, or a deleting absence below the floor or off
            // the record's owner. A validity rule at vote time, like the
            // collision above: a replica following a certified block
            // never evaluates it.
            let parent_frontier = load_read_frontier(&anchored, ctx.shard);
            if let Err(refusal) = fence.check(&parent_frontier) {
                tracing::warn!(
                    ?block_hash,
                    height = block_height.inner(),
                    %refusal,
                    "Rejecting block the read frontier refuses"
                );
                ctx.notify_protocol(ProtocolEvent::BlockCheckCompleted {
                    block_hash,
                    kind: VerificationKind::StateRoot,
                    outcome: CheckOutcome::Refused,
                });
                return;
            }
            // A reading the block takes at its own parent is held to
            // this replica's own parent view, since it carries no proof.
            // Which crossings the proposer read there is its choice;
            // what each reading says is not.
            if let Some(key) = disagreeing_parent_reading(&state_claims, ctx.shard, &anchored) {
                tracing::warn!(
                    ?block_hash,
                    height = block_height.inner(),
                    ?key,
                    "Rejecting block whose parent-anchored reading disagrees with the parent state"
                );
                ctx.notify_protocol(ProtocolEvent::BlockCheckCompleted {
                    block_hash,
                    kind: VerificationKind::StateRoot,
                    outcome: CheckOutcome::Refused,
                });
                return;
            }
            // A crossing a departure names off this shard's leaf carries
            // no proof: its record is held to this replica's own parent
            // view, present and as the name restates it.
            if let Some(key) = misstated_unclaimed(&abandonment_records, &anchored) {
                tracing::warn!(
                    ?block_hash,
                    height = block_height.inner(),
                    ?key,
                    "Rejecting block naming a crossing whose record the parent state does not hold"
                );
                ctx.notify_protocol(ProtocolEvent::BlockCheckCompleted {
                    block_hash,
                    kind: VerificationKind::StateRoot,
                    outcome: CheckOutcome::Refused,
                });
                return;
            }
            let (computed_root, jmt_snapshot, prepared) = view.base().prepare_block_commit(
                ParentAnchor {
                    state_root: parent_state_root,
                    height: parent_block_height,
                    state: &anchored,
                    pending: view.pending_snapshots(),
                    base_reads: None,
                },
                &finalizations,
                ChainWrites {
                    creations: &creations_of(&creations),
                    removals: &removals,
                    frontier: &frontier,
                    state_claims: &state_claims,
                    members: &members,
                },
                block_height,
            );
            // A terminating shard's boundary header carries the settled
            // root its surviving counterparts read; recompute it from the
            // committed chain whenever the shard terminates at the next
            // boundary, split or merge.
            let computed_terminal_settled_txs = match terminal_settled_txs_required.then(|| {
                ctx.pending_chain.terminal_settled_txs_root(
                    &TerminalWindow {
                        local_shard: ctx.shard,
                        parent_block_hash,
                        parent_block_height,
                        anchor_wt: parent_weighted_timestamp,
                        settled_window_floor: settled_txs_window_floor,
                    },
                    &finalizations,
                )
            }) {
                None => None,
                Some(Ok(root)) => Some(root),
                // The window reaches below what this store answers for, so
                // the root is not computable here. Refusing says that;
                // carrying a root taken over the prefix would claim a
                // smaller set than every full-history replica attests, and
                // read back as a mismatch rather than as a gap.
                Some(Err(coverage)) => {
                    tracing::warn!(
                        ?block_hash,
                        height = block_height.inner(),
                        missing_at = ?coverage.short_at(),
                        "Declining a terminal block whose window runs below the blocks held here"
                    );
                    ctx.notify_protocol(ProtocolEvent::BlockCheckCompleted {
                        block_hash,
                        kind: VerificationKind::StateRoot,
                        outcome: CheckOutcome::Refused,
                    });
                    return;
                }
            };
            let verify_result = expected_root.verify(&StateRootContext {
                computed_root: &computed_root,
                claimed_split_child_roots,
                split_child_roots_required,
                claimed_terminal_settled_txs,
                computed_terminal_settled_txs,
                terminal_settled_txs_required,
            });
            record_signature_verification_latency("state_root", start.elapsed().as_secs_f64());
            let bytes_delta = jmt_snapshot.bytes_delta;
            if verify_result.is_ok() {
                absorb_finalized_cells(&finalizations, ctx.executor.derivation().as_ref());
                // SAFETY: `prepared` belongs to the same JMT replay that just
                // produced the matching `computed_root` — only routed when
                // verification succeeds.
                (ctx.commit_prepared)(PreparedBlock {
                    block_hash,
                    parent_block_hash,
                    block_height,
                    prepared,
                    jmt_snapshot,
                    settled_txs: local_settled_tx_hashes(&finalizations, ctx.shard),
                });
            }
            let outcome = match verify_result {
                Ok(_) => CheckOutcome::Checked { bytes_delta },
                Err(e) => {
                    tracing::warn!(
                        block_hash = ?block_hash,
                        block_height = block_height.inner(),
                        parent_block_height = parent_block_height.inner(),
                        reason = %e,
                        "State root verification FAILED"
                    );
                    CheckOutcome::Refused
                }
            };
            ctx.notify_protocol(ProtocolEvent::BlockCheckCompleted {
                block_hash,
                kind: VerificationKind::StateRoot,
                outcome,
            });
        }

        Action::BuildProposal {
            shard_id,
            chain_origin,
            proposer,
            height,
            round,
            parent_block_hash,
            parent_qc,
            timestamp,
            is_fallback,
            parent_state_root,
            parent_block_height,
            transactions,
            finalizations,
            provisions,
            abandonment_records,
            state_claims,
            fee_checks,
            fee_read_height,
            parent_in_flight,
            parent_settled_frontier,
            parent_sweep_frontier,
            parent_load,
            substate_bytes,
            ready_signals,
            reshape_trigger,
            parent_witness_leaves,
            beacon_witness_base,
            parent_reveal_chain,
            parent_committee_anchor_epoch,
            committee_anchor_epoch,
            carry_split_child_roots,
            carry_terminal_settled_txs,
            settled_txs_window_floor,
            classification_topology_snapshot: classification_topology,
            frontier,
            fence,
            parent_anchor,
            local_crossings,
        } => {
            // Sign the block's randomness reveal here — off the main loop, on
            // the dispatch pool — so the sans-io coordinator holds no key. Its
            // digest is the link the block adds to its reveal chain; the proof
            // rides the block body and manifest for the verifier's re-check.
            let Ok(randomness_reveal) = shard_reveal_sign(
                ctx.signer.as_ref(),
                ctx.topology_snapshot.network(),
                shard_id,
                height,
            ) else {
                tracing::error!(
                    ?shard_id,
                    height = height.inner(),
                    "cannot sign randomness reveal; skipping proposal"
                );
                return;
            };
            let view = ctx
                .pending_chain
                .view_at(parent_block_hash, parent_block_height);
            // What the read frontier would refuse, dropped before the
            // block is built so a proposal never refuses itself: every
            // refused presence or deleting absence is cut from its claim.
            // The frontier's inputs are then recomputed over the claims
            // kept.
            let (state_claims, frontier) = {
                let anchored = view.snapshot();
                let parent_frontier = load_read_frontier(&anchored, shard_id);
                let Dropped { claims, refused } =
                    drop_refused(state_claims, &fence, frontier.windows, &parent_frontier);
                if refused > 0 {
                    tracing::debug!(
                        ?shard_id,
                        height = height.inner(),
                        refused,
                        "Dropped what the read frontier refuses from the proposal"
                    );
                }
                // The crossings whose ends share this shard, read at the
                // parent through the same anchored view, beside the
                // claims in the section's order.
                let mut claims = claims;
                claims.extend(parent_claims(&local_crossings, parent_anchor, &anchored));
                claims.sort_unstable();
                let frontier = FrontierInputs::for_block(
                    &claims,
                    frontier.windows,
                    frontier.anchor,
                    frontier.local,
                );
                (claims, frontier)
            };
            // A crossing named off a leaf the parent no longer holds as
            // named would refuse the block at every voter.
            let abandonment_records =
                keep_standing_unclaimed(abandonment_records, &view.snapshot());
            // Drop transactions whose payer cannot cover its cumulative
            // reservation demand — the builder-side form of the voters'
            // reservation verification, reading the same
            // committed-height balances, so a proposal never
            // self-rejects.
            let transactions = if fee_checks.is_empty() {
                transactions
            } else {
                let mut running: HashMap<SubstateKey, u128> = fee_checks
                    .iter()
                    .map(|check| (check.vault, check.demand))
                    .collect();
                let auth_cells: HashMap<SubstateKey, Option<Vec<u8>>> = fee_checks
                    .iter()
                    .map(|check| {
                        let cell = view
                            .get_substate_at_height(check.auth_cell, fee_read_height)
                            .flatten();
                        (check.vault, cell)
                    })
                    .collect();
                let balances: HashMap<SubstateKey, u128> = fee_checks
                    .iter()
                    .map(|check| {
                        let balance = view
                            .get_substate_at_height(check.vault, fee_read_height)
                            .flatten()
                            .and_then(|bytes| <[u8; 16]>::try_from(bytes.as_slice()).ok())
                            .map_or(0u128, u128::from_le_bytes);
                        (check.vault, balance)
                    })
                    .collect();
                let mut dropped = 0usize;
                let mut unbound = 0usize;
                let kept: Vec<_> = transactions
                    .into_iter()
                    .filter(|tx| {
                        let vault = tx.fee_vault();
                        let Some(used) = running.get_mut(&vault) else {
                            return true;
                        };
                        // The builder-side form of the voters' payer
                        // binding verdict, over the same cell they will
                        // read, so a proposal never self-rejects on a
                        // signer the payer's rule refuses.
                        let auth_cell = auth_cells.get(&vault).and_then(Option::as_deref);
                        if !tx.payer_admits_attesters(auth_cell) {
                            unbound += 1;
                            return false;
                        }
                        let max_fee = tx.terms().max_fee;
                        let wanted = used.saturating_add(max_fee);
                        if wanted > balances.get(&vault).copied().unwrap_or(0) {
                            dropped += 1;
                            return false;
                        }
                        *used = wanted;
                        true
                    })
                    .collect();
                if dropped > 0 {
                    tracing::debug!(
                        dropped,
                        height = height.inner(),
                        "Dropped transactions whose payer cannot cover its fee reservation"
                    );
                }
                if unbound > 0 {
                    tracing::debug!(
                        unbound,
                        height = height.inner(),
                        "Dropped transactions whose payer's rule does not admit their signer"
                    );
                }
                kept
            };
            // A terminating shard's boundary header carries the settled
            // root its surviving counterparts read — whenever the shard
            // terminates at the next boundary, split or merge.
            let terminal_settled_txs = match carry_terminal_settled_txs.then(|| {
                ctx.pending_chain.terminal_settled_txs_root(
                    &TerminalWindow {
                        local_shard: shard_id,
                        parent_block_hash,
                        parent_block_height,
                        anchor_wt: parent_qc.weighted_timestamp(),
                        settled_window_floor: settled_txs_window_floor,
                    },
                    &finalizations,
                )
            }) {
                None => None,
                Some(Ok(root)) => Some(root),
                // Nothing to propose: a boundary header carries this root
                // or it is not a boundary header, and the root computed
                // here would be short. Leaving the slot empty rotates it
                // to a proposer whose store reaches, which is the same
                // response the round already has for one that cannot
                // answer in time.
                Some(Err(coverage)) => {
                    tracing::warn!(
                        shard = ?shard_id,
                        height = height.inner(),
                        round = round.inner(),
                        missing_at = ?coverage.short_at(),
                        "Skipping a terminal proposal whose window runs below the blocks held here"
                    );
                    return;
                }
            };
            // A block carries no more than its fields state, so a
            // selection past one of them is a block no peer could decode.
            // Leaving the slot empty rotates it to another proposer,
            // which is the response the round already has for one that
            // cannot answer.
            let (
                Ok(transactions),
                Ok(finalizations),
                Ok(provisions),
                Ok(abandonment_records),
                Ok(state_claims),
                Ok(ready_signals),
            ) = (
                Capped::new(transactions),
                Capped::new(finalizations),
                Capped::new(provisions),
                Capped::new(abandonment_records),
                Capped::new(state_claims),
                Capped::new(ready_signals),
            )
            else {
                tracing::warn!(
                    shard = ?shard_id,
                    height = height.inner(),
                    round = round.inner(),
                    "Skipping a proposal whose selection outgrew what a block carries"
                );
                return;
            };
            let result = build_proposal(
                &view,
                proposer,
                height,
                round,
                parent_block_hash,
                parent_qc,
                timestamp,
                is_fallback,
                parent_state_root,
                parent_block_height,
                &transactions,
                finalizations.clone(),
                shard_id,
                chain_origin,
                &classification_topology,
                provisions.clone(),
                abandonment_records,
                state_claims,
                parent_in_flight,
                parent_settled_frontier,
                parent_sweep_frontier,
                parent_load,
                substate_bytes,
                ready_signals,
                reshape_trigger,
                randomness_reveal,
                &parent_witness_leaves,
                beacon_witness_base,
                parent_reveal_chain,
                parent_committee_anchor_epoch,
                committee_anchor_epoch,
                carry_split_child_roots,
                terminal_settled_txs,
                &frontier,
            );
            let block_hash = result.block_hash;
            let bytes_delta = result.jmt_snapshot.bytes_delta;
            absorb_finalized_cells(&finalizations, ctx.executor.derivation().as_ref());
            (ctx.commit_prepared)(PreparedBlock {
                block_hash,
                parent_block_hash,
                block_height: height,
                prepared: result.prepared_commit,
                jmt_snapshot: result.jmt_snapshot,
                settled_txs: local_settled_tx_hashes(&finalizations, shard_id),
            });
            ctx.notify_protocol(ProtocolEvent::ProposalBuilt {
                height,
                round,
                block: Arc::new(result.block),
                block_hash,
                finalizations: finalizations.into_inner(),
                provisions: provisions.into_inner(),
                bytes_delta,
            });
        }

        // ── Sign + broadcast actions ──────────────────────────────────────
        Action::BroadcastBlockHeader { header, manifest } => {
            let block_hash = header.hash();
            let msg = signed_bytes(
                &BlockProposalMessage {
                    shard_group: header.shard_id(),
                    height: header.height(),
                    round: header.round(),
                    block_hash,
                },
                ctx.topology_snapshot.network(),
            );
            let Ok(sig) = ctx.signer.sign(&msg) else {
                tracing::error!(?block_hash, "cannot sign block header; skipping broadcast");
                return;
            };
            let gossip = BlockHeaderNotification::new(*header, *manifest, sig);
            let local_peers: Vec<ValidatorId> = ctx
                .topology_snapshot
                .committee_for_shard(ctx.shard)
                .iter()
                .filter(|&&v| v != ctx.me)
                .copied()
                .collect();
            ctx.network.notify(&local_peers, &gossip);
        }

        Action::SignAndBroadcastBlockVote {
            block_hash,
            parent_block_hash,
            height,
            round,
            timestamp,
            next_proposers,
            position,
        } => {
            // The position this vote ratcheted must be durable before
            // the signature exists — a crash between them costs at most
            // an abstention, never a second vote in a consumed round.
            ctx.vote_registers.persist_vote_position(ctx.me, &position);
            let Ok(verified) = Verified::<BlockVote>::sign_local(
                ctx.topology_snapshot.network(),
                block_hash,
                parent_block_hash,
                ctx.shard,
                height,
                round,
                ctx.me,
                ctx.signer.as_ref(),
                timestamp,
            ) else {
                tracing::error!(?block_hash, "cannot sign block vote; abstaining");
                return;
            };
            let gossip = BlockVoteNotification::new(verified.clone());
            ctx.network.notify(&next_proposers, &gossip);
            // Feed our own signed vote back for local VoteSet tracking.
            ctx.notify_protocol(ProtocolEvent::VerifiedBlockVoteReceived { vote: verified });
        }

        Action::SignAndBroadcastTimeout {
            round,
            high_qc,
            recipients,
            position,
        } => {
            // Same persistence rule as the vote arm: the abandoned round
            // is durable before the timeout signature exists.
            ctx.vote_registers.persist_vote_position(ctx.me, &position);
            let Ok(verified) = Verified::<Timeout>::sign_local(
                ctx.topology_snapshot.network(),
                ctx.shard,
                round,
                high_qc,
                ctx.me,
                ctx.signer.as_ref(),
            ) else {
                tracing::error!(?round, "cannot sign timeout; abstaining");
                return;
            };
            let gossip = TimeoutNotification::new(verified.clone());
            ctx.network.notify(&recipients, &gossip);
            // Feed our own signed timeout back for local TimeoutKeeper tracking.
            ctx.notify_protocol(ProtocolEvent::VerifiedTimeoutReceived { timeout: verified });
        }

        Action::SignAndBroadcastReadySignal {
            shard,
            wt_window_start,
            wt_window_end,
            recipients,
        } => {
            let Ok(signal) = ReadySignal::sign(
                ctx.topology_snapshot.network(),
                ctx.me,
                shard,
                wt_window_start,
                wt_window_end,
                ctx.signer.as_ref(),
            ) else {
                tracing::error!(?shard, "cannot sign ready signal; skipping");
                return;
            };
            // No local feedback: the sender is outside the consensus
            // subset, so it never proposes and its own pool entry would
            // never drain — only the recipients' pools matter.
            ctx.network
                .notify(&recipients, &ReadySignalNotification::new(signal));
        }

        Action::VerifyTimeout {
            timeout,
            voter_public_key,
        } => {
            let start = Stopwatch::start();
            let result = timeout.verify(&TimeoutContext {
                verifier: ctx.verifier,
                network: ctx.topology_snapshot.network(),
                voter_public_key: &voter_public_key,
            });
            record_signature_verification_latency("timeout", start.elapsed().as_secs_f64());
            match result {
                Ok(verified) => {
                    ctx.notify_protocol(ProtocolEvent::VerifiedTimeoutReceived {
                        timeout: verified,
                    });
                }
                Err(_) => {
                    tracing::warn!(voter = ?timeout.voter(), "Dropping timeout with an invalid signature share");
                }
            }
        }

        Action::BroadcastCertifiedBlockHeader { certified_header } => {
            let msg = signed_bytes(
                &CertifiedBlockHeaderSenderMessage {
                    shard_id: certified_header.header().shard_id(),
                    height: certified_header.header().height(),
                    block_hash: certified_header.header().hash(),
                },
                ctx.topology_snapshot.network(),
            );
            let Ok(sig) = ctx.signer.sign(&msg) else {
                tracing::error!("cannot sign certified header gossip; skipping");
                return;
            };
            let gossip = CertifiedBlockHeaderGossip {
                certified_header: Arc::new(Verifiable::<CertifiedBlockHeader>::from(
                    certified_header,
                )),
                sender: ctx.me,
                sender_signature: sig,
            };
            ctx.network.broadcast_global(&gossip);
        }

        Action::BroadcastShardForkProof { proof } => {
            // Self-authenticating: gossip the proof unsigned; every recipient
            // re-verifies it against its own topology.
            let gossip = ShardForkProofGossip {
                proof: Arc::from(proof),
            };
            ctx.network.broadcast_global(&gossip);
        }

        Action::BroadcastShardVoteEquivocation { evidence } => {
            // Self-authenticating: gossip the pair unsigned; every recipient
            // re-verifies both signatures under the accused key.
            let gossip = ShardVoteEquivocationGossip {
                evidence: Arc::from(evidence),
            };
            ctx.network.broadcast_global(&gossip);
        }

        _ => unreachable!("hyperscale_shard::handle_action called with non-shard action"),
    }
}

/// The shards that commit each transaction under `topology`.
///
/// Its participants, less any that only take delivery of its owed
/// crossings: what a block's provision fan-out reaches, on the proposer
/// and the verifier alike.
pub fn committing_shards(
    topology: &TopologySnapshot,
) -> impl Fn(&Transaction) -> Vec<ShardId> + '_ {
    move |tx| {
        Classified::freeze(
            tx.legs(),
            tx.fee_payer(),
            tx.accounts(),
            topology.shard_trie(),
        )
        .committing(topology.all_shards_for_transaction(tx))
        .into_iter()
        .collect()
    }
}

#[cfg(test)]
mod tests {

    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};
    use hyperscale_hbor::Capped;
    use hyperscale_types::test_utils::{
        install_stub_protocol_statics, stub_abort_charge, stub_transaction, test_prefix,
        test_principal,
    };
    use hyperscale_types::{
        BeaconBlockHash, BeaconChainConfig, BeaconState, CertificateRoot, CertifiedBeaconBlock,
        CommittedAt, LocalReceiptRoot, PriceTable, ProposerTimestamp, ProvisionsRoot,
        ShardCommittee, Signer, StoredReceipt, TimestampRange, TransactionRoot, TxRootVerifyError,
    };

    use super::*;

    /// A beacon chain that answers for the epochs it was given and for
    /// nothing else — the reads `commit_windows_for` takes, without the
    /// blocks a real commit would pair them with.
    struct Folded(HashMap<Epoch, Arc<BeaconState>>);

    impl Folded {
        fn to(epochs: &[(u64, u64)]) -> Self {
            Self(
                epochs
                    .iter()
                    .map(|(epoch, compute)| {
                        let mut state = BeaconState::empty(BeaconChainConfig::default());
                        state.prices = PriceTable {
                            compute: *compute,
                            ..PriceTable::GENESIS
                        };
                        state.shard_committees.insert(
                            ShardId::ROOT,
                            ShardCommittee {
                                members: vec![ValidatorId::new(1)],
                            },
                        );
                        (Epoch::new(*epoch), Arc::new(state))
                    })
                    .collect(),
            )
        }
    }

    impl BeaconChainReader for Folded {
        fn get_state_by_epoch(&self, epoch: Epoch) -> Option<Arc<BeaconState>> {
            self.0.get(&epoch).map(Arc::clone)
        }

        fn get_beacon_block_by_epoch(
            &self,
            _epoch: Epoch,
        ) -> Option<Arc<Verified<CertifiedBeaconBlock>>> {
            None
        }

        fn get_beacon_block_by_hash(
            &self,
            _hash: BeaconBlockHash,
        ) -> Option<Arc<Verified<CertifiedBeaconBlock>>> {
            None
        }

        fn latest_committed_epoch(&self) -> Option<Epoch> {
            self.0.keys().copied().max()
        }

        fn latest_committed(
            &self,
        ) -> Option<(Arc<Verified<CertifiedBeaconBlock>>, Arc<BeaconState>)> {
            None
        }
    }

    /// One name, committed at `committee_anchor` with its block's own
    /// anchor at `anchor`.
    fn named_at(committee_anchor: u64, anchor: u64) -> UnsettledTx {
        UnsettledTx {
            tx_hash: TxHash::from(Hash::from_bytes(b"tx")),
            deadline: Deadline::of(WeightedTimestamp::from_millis(60_000)),
            charged: 5,
            charge: stub_abort_charge(5),
            committed: CommittedAt {
                height: BlockHeight::new(1),
                anchor: WeightedTimestamp::from_millis(anchor),
                committee_anchor: WeightedTimestamp::from_millis(committee_anchor),
            },
            reach: Capped::empty(),
            escrowed: Capped::empty(),
        }
    }

    /// A name is weighed at the window its own commit ran under, never
    /// at the one carrying the record.
    ///
    /// A record is written when a deadline lapses, epochs after the
    /// commit it names, and the table moves in between. Weighed at the
    /// carrying window, every name whose commit predates a fold that
    /// stepped a row restates wrongly — and a wrong figure refuses the
    /// block, so the abandonment never commits and the drain place is
    /// never released.
    #[test]
    fn a_name_is_weighed_at_the_window_that_committed_it() {
        let windows = EpochWindows::new(1_000);
        let chain = Folded::to(&[(0, 1), (1, 2)]);

        let resolved = commit_windows_for(&chain, windows, &[named_at(500, 500)]);

        assert_eq!(
            resolved[&Epoch::new(0)].prices.compute,
            1,
            "the table its commit was charged at"
        );
        assert!(
            !resolved.contains_key(&Epoch::new(1)),
            "and never the one the record is carried in"
        );
    }

    /// A name whose commit straddles an epoch cut is weighed at the
    /// anchor that froze its figures, not at the one that dated it.
    ///
    /// Every block carries two anchors, and for the first block of a
    /// window they fall either side of the cut. Admission judged the
    /// ceiling at the committee's and the ledger priced the entry there,
    /// so only that one names the table the figures were frozen against.
    #[test]
    fn a_name_committed_across_a_cut_is_weighed_where_it_was_frozen() {
        let windows = EpochWindows::new(1_000);
        let chain = Folded::to(&[(0, 1), (1, 2)]);

        // The first block of the later window: its own anchor sits in
        // that window, the anchor its parent carried in the earlier one.
        let resolved = commit_windows_for(&chain, windows, &[named_at(900, 1_100)]);

        assert_eq!(
            resolved[&Epoch::new(0)].prices.compute,
            1,
            "the committee anchor's window is the one that froze the figures"
        );
        assert!(
            !resolved.contains_key(&Epoch::new(1)),
            "and never the window its own anchor opens"
        );
    }

    /// A window above this node's fold leaves its name out rather than
    /// standing something else in for it. The check that misses one
    /// answers `Unknown`, which defers the block; a stand-in would weigh
    /// the share at a placement the transaction never ran under.
    #[test]
    fn an_unfolded_epoch_resolves_no_window() {
        let windows = EpochWindows::new(1_000);
        let chain = Folded::to(&[(0, 1)]);

        let resolved = commit_windows_for(&chain, windows, &[named_at(5_000, 5_000)]);

        assert!(resolved.is_empty());
    }

    fn shard() -> ShardId {
        ShardId::ROOT
    }

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn make_vote(
        keys: &[BlsSigner],
        voter_index: usize,
        block_hash: BlockHash,
        height: BlockHeight,
        round: Round,
        timestamp_ms: u64,
    ) -> BlockVote {
        BlockVote::new(
            &net(),
            block_hash,
            BlockHash::ZERO,
            shard(),
            height,
            round,
            ValidatorId::new(voter_index as u64),
            &keys[voter_index],
            ProposerTimestamp::from_millis(timestamp_ms),
        )
        .expect("sign")
    }

    fn keypairs(n: usize) -> Vec<BlsSigner> {
        (0..n).map(|_| BlsSigner::generate()).collect()
    }

    // ─── verify_vote_batch ──────────────────────────────────────────────

    #[test]
    fn verify_vote_batch_empty_input_returns_already_verified_unchanged() {
        let keys = keypairs(2);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"block"));
        let v = make_vote(
            &keys,
            0,
            block_hash,
            BlockHeight::new(1),
            Round::INITIAL,
            1000,
        );
        let already = vec![(0usize, Verified::<BlockVote>::new_unchecked_for_test(v))];
        let out = verify_vote_batch(
            &BlsVerifier,
            block_hash,
            b"msg",
            Vec::new(),
            already.clone(),
        );
        assert_eq!(out.len(), already.len());
    }

    #[test]
    fn verify_vote_batch_accepts_all_valid_signatures() {
        let keys = keypairs(3);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b1"));
        let height = BlockHeight::new(1);
        let round = Round::INITIAL;
        let msg = signed_bytes(
            &BlockVoteMessage {
                shard_group: shard(),
                height,
                round,
                block_hash,
                parent_block_hash: BlockHash::ZERO,
            },
            &net(),
        );

        let to_verify: Vec<_> = (0..3)
            .map(|i| {
                let vote = make_vote(&keys, i, block_hash, height, round, 1000);
                (i, vote, keys[i].public_key())
            })
            .collect();

        let out = verify_vote_batch(&BlsVerifier, block_hash, &msg, to_verify, Vec::new());
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn verify_vote_batch_falls_back_when_one_signature_bad() {
        let keys = keypairs(3);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b1"));
        let height = BlockHeight::new(1);
        let round = Round::INITIAL;
        let msg = signed_bytes(
            &BlockVoteMessage {
                shard_group: shard(),
                height,
                round,
                block_hash,
                parent_block_hash: BlockHash::ZERO,
            },
            &net(),
        );

        // Vote 1's signature is replaced by a signature over a different block.
        let other_hash = BlockHash::from_raw(Hash::from_bytes(b"other"));
        let bad_vote = make_vote(&keys, 1, block_hash, height, round, 1000);
        let bad_signing_vote = make_vote(&keys, 1, other_hash, height, round, 1000);
        let (block_hash_v, sg, h, r, voter, _, ts) = bad_vote.into_parts();
        let bad_vote = BlockVote::from_parts(
            block_hash_v,
            sg,
            h,
            r,
            voter,
            bad_signing_vote.signature(),
            ts,
        );

        let to_verify = vec![
            (
                0usize,
                make_vote(&keys, 0, block_hash, height, round, 1000),
                keys[0].public_key(),
            ),
            (1usize, bad_vote, keys[1].public_key()),
            (
                2usize,
                make_vote(&keys, 2, block_hash, height, round, 1000),
                keys[2].public_key(),
            ),
        ];

        let out = verify_vote_batch(&BlsVerifier, block_hash, &msg, to_verify, Vec::new());
        let indices: Vec<_> = out.iter().map(|(i, _)| *i).collect();
        assert_eq!(indices, vec![0, 2]);
    }

    #[test]
    fn verify_vote_batch_rejects_all_when_wrong_message() {
        let keys = keypairs(2);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b1"));
        let wrong_msg = b"unrelated";
        let to_verify: Vec<_> = (0..2)
            .map(|i| {
                let vote = make_vote(
                    &keys,
                    i,
                    block_hash,
                    BlockHeight::new(1),
                    Round::INITIAL,
                    1000,
                );
                (i, vote, keys[i].public_key())
            })
            .collect();
        let out = verify_vote_batch(&BlsVerifier, block_hash, wrong_msg, to_verify, Vec::new());
        assert!(out.is_empty());
    }

    // ─── build_qc_from_verified ─────────────────────────────────────────

    #[test]
    fn build_qc_from_verified_produces_round_trippable_qc() {
        let keys = keypairs(3);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"block"));
        let height = BlockHeight::new(5);
        let round = Round::INITIAL;
        // `make_vote` signs over a ZERO parent, so the QC must carry the same
        // parent to re-verify — the binding this fix adds.
        let parent = BlockHash::ZERO;

        let verified: Vec<_> = (0..3)
            .map(|i| {
                let vote = make_vote(&keys, i, block_hash, height, round, 1000);
                (i, Verified::<BlockVote>::new_unchecked_for_test(vote))
            })
            .collect();

        let qc = Verified::<QuorumCertificate>::from_verified_votes(
            &BlsVerifier,
            block_hash,
            shard(),
            height,
            round,
            parent,
            WeightedTimestamp::ZERO,
            &verified,
        )
        .expect("build_qc should succeed");

        // build_qc_from_verified wraps with `new_unchecked` under the
        // "votes pre-verified + quorum confirmed" trust source, so the
        // returned QC must round-trip through the Verify impl when fed
        // back its committee context.
        let pubs: Vec<_> = keys.iter().map(BlsSigner::public_key).collect();
        let net = net();
        let qc_ctx = QcContext {
            verifier: &BlsVerifier,
            network: &net,
            public_keys: &pubs,
            quorum_threshold: VoteCount::new(3),
        };
        qc.as_ref()
            .verify(&qc_ctx)
            .expect("freshly built QC must re-verify");
        assert_eq!(qc.block_hash(), block_hash);
        assert_eq!(qc.height(), height);
        assert_eq!(qc.parent_block_hash(), parent);
        assert_eq!(qc.signer_count(), 3);
    }

    #[test]
    fn build_qc_from_verified_sorts_signers_bitfield_deterministically() {
        let keys = keypairs(4);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b"));
        let verified: Vec<_> = [2, 0, 3]
            .into_iter()
            .map(|i: usize| {
                let vote = make_vote(
                    &keys,
                    i,
                    block_hash,
                    BlockHeight::new(1),
                    Round::INITIAL,
                    1000,
                );
                (i, Verified::<BlockVote>::new_unchecked_for_test(vote))
            })
            .collect();

        let qc = Verified::<QuorumCertificate>::from_verified_votes(
            &BlsVerifier,
            block_hash,
            shard(),
            BlockHeight::new(1),
            Round::INITIAL,
            BlockHash::ZERO,
            WeightedTimestamp::ZERO,
            &verified,
        )
        .unwrap();

        let set: Vec<_> = qc.signers().set_indices().collect();
        assert_eq!(set, vec![0, 2, 3]);
    }

    #[test]
    fn build_qc_from_verified_takes_the_median_timestamp() {
        let keys = keypairs(3);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b"));
        // Each vote weighs one and the aggregate is their lower median, so
        // three votes at 1000 / 2000 / 3000 yield 2000.
        let verified = vec![
            (
                0usize,
                Verified::<BlockVote>::new_unchecked_for_test(make_vote(
                    &keys,
                    0,
                    block_hash,
                    BlockHeight::new(1),
                    Round::INITIAL,
                    1000,
                )),
            ),
            (
                1,
                Verified::<BlockVote>::new_unchecked_for_test(make_vote(
                    &keys,
                    1,
                    block_hash,
                    BlockHeight::new(1),
                    Round::INITIAL,
                    2000,
                )),
            ),
            (
                2,
                Verified::<BlockVote>::new_unchecked_for_test(make_vote(
                    &keys,
                    2,
                    block_hash,
                    BlockHeight::new(1),
                    Round::INITIAL,
                    3000,
                )),
            ),
        ];

        let qc = Verified::<QuorumCertificate>::from_verified_votes(
            &BlsVerifier,
            block_hash,
            shard(),
            BlockHeight::new(1),
            Round::INITIAL,
            BlockHash::ZERO,
            WeightedTimestamp::ZERO,
            &verified,
        )
        .unwrap();

        assert_eq!(qc.weighted_timestamp().as_millis(), 2000);
    }

    #[test]
    fn build_qc_from_verified_clamps_vote_timestamps_to_parent_floor() {
        let keys = keypairs(3);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b"));
        // Two voters under the floor (500, 800) and one above (3000); floor=2000.
        // Without the clamp the median would be 800 — below parent. With it
        // each below-floor vote rises to 2000, so the median of
        // (2000, 2000, 3000) is 2000, monotonically >= parent.
        let verified = vec![
            (
                0usize,
                Verified::<BlockVote>::new_unchecked_for_test(make_vote(
                    &keys,
                    0,
                    block_hash,
                    BlockHeight::new(1),
                    Round::INITIAL,
                    500,
                )),
            ),
            (
                1,
                Verified::<BlockVote>::new_unchecked_for_test(make_vote(
                    &keys,
                    1,
                    block_hash,
                    BlockHeight::new(1),
                    Round::INITIAL,
                    800,
                )),
            ),
            (
                2,
                Verified::<BlockVote>::new_unchecked_for_test(make_vote(
                    &keys,
                    2,
                    block_hash,
                    BlockHeight::new(1),
                    Round::INITIAL,
                    3000,
                )),
            ),
        ];

        let parent_floor = WeightedTimestamp::from_millis(2000);
        let qc = Verified::<QuorumCertificate>::from_verified_votes(
            &BlsVerifier,
            block_hash,
            shard(),
            BlockHeight::new(1),
            Round::INITIAL,
            BlockHash::ZERO,
            parent_floor,
            &verified,
        )
        .unwrap();

        assert_eq!(qc.weighted_timestamp().as_millis(), 2000);
        assert!(qc.weighted_timestamp().as_millis() >= parent_floor.as_millis());
    }

    /// A rushed vote timestamp cannot move the aggregate off an honest
    /// voter's own reading.
    ///
    /// The timestamp rides outside `BlockVoteMessage`, so a committee member
    /// picks it freely and the vote still verifies. The lower median of a
    /// quorum's clamped readings is indexed at `(k - 1) / 2`, which for every
    /// `k >= 2f + 1` sits inside the honest band whatever the forged values
    /// are — here, one voter three minutes ahead leaves the aggregate on the
    /// two honest middle readings rather than dragging it 44 seconds forward.
    #[test]
    fn build_qc_from_verified_ignores_a_rushed_vote_timestamp() {
        let keys = keypairs(4);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b"));
        let verified: Vec<_> = [1000u64, 2000, 3000, 180_000]
            .into_iter()
            .enumerate()
            .map(|(idx, ms)| {
                (
                    idx,
                    Verified::<BlockVote>::new_unchecked_for_test(make_vote(
                        &keys,
                        idx,
                        block_hash,
                        BlockHeight::new(1),
                        Round::INITIAL,
                        ms,
                    )),
                )
            })
            .collect();

        let qc = Verified::<QuorumCertificate>::from_verified_votes(
            &BlsVerifier,
            block_hash,
            shard(),
            BlockHeight::new(1),
            Round::INITIAL,
            BlockHash::ZERO,
            WeightedTimestamp::ZERO,
            &verified,
        )
        .unwrap();

        assert_eq!(qc.weighted_timestamp().as_millis(), 2500);
    }

    // ─── verify_and_build_qc (composition) ──────────────────────────────

    #[test]
    fn verify_and_build_qc_returns_none_without_quorum() {
        // 3 votes of power 1 each, total 4 → 3/4 = quorum only if 2f+1 where f=1 (3/4 OK).
        // Use total_votes=10 to force failure (3 < 2/3*10 = 6.67).
        let keys = keypairs(3);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b"));
        let height = BlockHeight::new(1);
        let round = Round::INITIAL;
        let to_verify: Vec<_> = (0..3)
            .map(|i| {
                let vote = make_vote(&keys, i, block_hash, height, round, 1000);
                (i, vote, keys[i].public_key())
            })
            .collect();

        let result = verify_and_build_qc(
            &BlsVerifier,
            &net(),
            block_hash,
            shard(),
            height,
            round,
            BlockHash::ZERO,
            WeightedTimestamp::ZERO,
            to_verify,
            Vec::new(),
            VoteCount::new(10),
        );

        assert!(result.qc.is_none());
        assert_eq!(result.verified_votes.len(), 3);
    }

    #[test]
    fn verify_and_build_qc_builds_qc_when_quorum_reached() {
        let keys = keypairs(4);
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"b"));
        let height = BlockHeight::new(1);
        let round = Round::INITIAL;
        let to_verify: Vec<_> = (0..3)
            .map(|i| {
                let vote = make_vote(&keys, i, block_hash, height, round, 1000);
                (i, vote, keys[i].public_key())
            })
            .collect();

        let result = verify_and_build_qc(
            &BlsVerifier,
            &net(),
            block_hash,
            shard(),
            height,
            round,
            BlockHash::ZERO,
            WeightedTimestamp::ZERO,
            to_verify,
            Vec::new(),
            VoteCount::new(4),
        );

        let qc = result.qc.expect("quorum reached, QC expected");
        assert_eq!(qc.signer_count(), 3);
        assert!(result.verified_votes.is_empty());
    }

    // Signature-verification predicate tests live next to the type, in
    // `crates/types/src/shard/quorum_certificate.rs::tests`.

    // ─── root verifiers ─────────────────────────────────────────────────

    #[test]
    fn verify_transaction_root_accepts_matching_root_and_rejects_otherwise() {
        let txs: Vec<Arc<Verifiable<Transaction>>> = Vec::new();
        let root = Verified::<TransactionRoot>::compute(&txs).into_inner();
        let anchor = WeightedTimestamp::ZERO;
        let ctx = TransactionRootContext {
            transactions: &txs,
            validity_anchor: anchor,
        };
        assert!(root.verify(&ctx).is_ok());
        assert!(
            TransactionRoot::from_raw(Hash::from_bytes(b"wrong"))
                .verify(&ctx)
                .is_err()
        );
    }

    #[test]
    fn verify_transaction_root_rejects_expired_tx() {
        use std::time::Duration;

        let anchor = WeightedTimestamp::from_millis(100_000);
        // Range ends at 1_000ms — anchor at 100_000ms is well past
        // end_timestamp_exclusive, so the tx is expired.
        let expired_range = TimestampRange::new(
            WeightedTimestamp::ZERO,
            WeightedTimestamp::from_millis(1_000),
        );
        install_stub_protocol_statics();
        let tx = Arc::new(Verifiable::from(stub_transaction(
            test_principal(1),
            &[test_prefix(1)],
            1_000,
            expired_range,
        )));
        let txs = vec![tx];
        let root = Verified::<TransactionRoot>::compute(&txs).into_inner();

        let ctx = TransactionRootContext {
            transactions: &txs,
            validity_anchor: anchor,
        };
        assert!(matches!(
            root.verify(&ctx),
            Err(TxRootVerifyError::ValidityWindowExpired { .. })
        ));

        // Same root, anchor inside the range — verification passes.
        let valid_range = TimestampRange::new(anchor, anchor.plus(Duration::from_mins(1)));

        let tx2 = Arc::new(Verifiable::from(stub_transaction(
            test_principal(2),
            &[test_prefix(2)],
            1_000,
            valid_range,
        )));
        let txs2 = vec![tx2];
        let root2 = Verified::<TransactionRoot>::compute(&txs2).into_inner();
        let ctx2 = TransactionRootContext {
            transactions: &txs2,
            validity_anchor: anchor,
        };
        assert!(root2.verify(&ctx2).is_ok());
    }

    #[test]
    fn verify_transaction_root_rejects_malformed_range() {
        use std::time::Duration;

        let anchor = WeightedTimestamp::from_millis(1_000);
        // Length over MAX_VALIDITY_RANGE.
        let too_wide = TimestampRange::new(
            WeightedTimestamp::ZERO,
            anchor.plus(Duration::from_mins(10)),
        );
        install_stub_protocol_statics();
        let tx = Arc::new(Verifiable::from(stub_transaction(
            test_principal(3),
            &[test_prefix(3)],
            1_000,
            too_wide,
        )));
        let txs = vec![tx];
        let root = Verified::<TransactionRoot>::compute(&txs).into_inner();

        let ctx = TransactionRootContext {
            transactions: &txs,
            validity_anchor: anchor,
        };
        assert!(
            root.verify(&ctx).is_err(),
            "malformed range must reject even when merkle root matches"
        );
    }

    #[test]
    fn verify_provision_root_matches_compute_provision_root() {
        let hashes = vec![Hash::from_bytes(b"a"), Hash::from_bytes(b"b")];
        let root = Verified::<ProvisionsRoot>::compute(&hashes).into_inner();
        assert!(root.verify(hashes.as_slice()).is_ok());
        assert!(
            ProvisionsRoot::from_raw(Hash::from_bytes(b"nope"))
                .verify(hashes.as_slice())
                .is_err()
        );
    }

    #[test]
    fn verify_certificate_root_matches_compute_certificate_root() {
        let certs: Vec<Arc<Verifiable<Finalization>>> = Vec::new();
        let root = Verified::<CertificateRoot>::compute(&certs).into_inner();
        assert!(root.verify(certs.as_slice()).is_ok());
        assert!(
            CertificateRoot::from_raw(Hash::from_bytes(b"wrong"))
                .verify(certs.as_slice())
                .is_err()
        );
    }

    #[test]
    fn verify_local_receipt_root_matches_compute_local_receipt_root() {
        let receipts: Vec<StoredReceipt> = Vec::new();
        let root = Verified::<LocalReceiptRoot>::compute(&receipts).into_inner();
        assert!(root.verify(receipts.as_slice()).is_ok());
        assert!(
            LocalReceiptRoot::from_raw(Hash::from_bytes(b"wrong"))
                .verify(receipts.as_slice())
                .is_err()
        );
    }
}
