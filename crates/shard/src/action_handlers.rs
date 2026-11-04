//! Pure shard consensus algorithm functions shared between production and simulation runners.
//!
//! These functions contain the core cryptographic verification and consensus
//! algorithms, separated from dispatch (thread pool vs inline) and result
//! delivery (channel vs event queue) concerns.

use std::collections::{BTreeMap, BTreeSet, HashMap, hash_map};
use std::sync::Arc;

use hyperscale_core::{
    ActionContext, ConsensusAction, PreparedBlock, ProtocolEvent, StateRootCheck,
};
use hyperscale_engine::legs::{Classified, local_work_over};
use hyperscale_engine::tick_select::{
    CommittedSets, ManifestInputs, ManifestKind, contentions, end_lines, licensed_lines,
    terminal_fates, wounded,
};
use hyperscale_hbor::Capped;
use hyperscale_metrics::{
    record_hold_contentions, record_hold_inversions_proven, record_intake_capped,
    record_signature_verification_failure, record_signature_verification_latency,
};
use hyperscale_network::{Network, Verdict, VerdictKey};
use hyperscale_provisions::provision_tx_roots;
use hyperscale_storage::{
    BeaconChainReader, BlockSweep, ChainWrites, JmtSnapshot, MemberIndex, MemberInputs,
    MemberSections, ParentAnchor, PersistedPastAnchor, PreparedBlockView, ShardChainWriter,
    ShardStorage, SubstateStore, SubstateView, SweepIndex, TerminalWindow, VersionedStore,
    answer_additions, committed_tx_cells, creations_of, record_arrivals, settling_writes,
    without_colliding_committed_cells, without_colliding_member_rows,
};
use hyperscale_types::network::Signed;
use hyperscale_types::network::gossip::{CertifiedBlockHeaderGossip, ShardForkProofGossip};
use hyperscale_types::network::notification::{
    BlockHeaderNotification, BlockVoteNotification, QcAnnouncementNotification,
    ReadySignalNotification, TimeoutNotification,
};
use hyperscale_types::{
    AbandonmentRecord, AbandonmentRoot, AnswerAdditions, BeaconWitnessLeafCount,
    BeaconWitnessRootContext, Block, BlockHash, BlockHeader, BlockHeaderParts, BlockHeight,
    BlockProposalMessage, BlockVote, BlockVoteMessage, BodyRootContext, CertificateRoot,
    CertifiedBlockHeader, CertifiedBlockHeaderSenderMessage, CertifiedHeaderVerifyError,
    CheckOutcome, CommitWindow, ConsensusPublicKey, ConsensusReceipt, ConsensusSignature, DeferOn,
    Derivation, Engagement, EngagementRoot, Epoch, EpochWindows, Finalization, FrontierInputs,
    Hash, LeafRoot, LocalReceiptRoot, MAX_CLAIMS_PER_BLOCK, MAX_FINALIZED_TX_PER_BLOCK,
    MAX_PROVISION_TARGET_SHARDS, MAX_PROVISIONS_PER_BLOCK, MAX_READY_SIGNALS_PER_BLOCK,
    MAX_TXS_PER_BLOCK, NetworkDefinition, PreparedCommit, ProposerTimestamp, Provision,
    ProvisionHash, ProvisionTxRootsJudged, ProvisionTxRootsMap, ProvisionsRoot, QcContext,
    QuorumCertificate, ReadySignal, ReshapeTrigger, Resolutions, RevealChain, Round, SectionRoots,
    SetRoot, SettledTxsRoot, ShardId, ShardLoad, SplitChildRoots, StandingAnswers, StateClaim,
    StateClaimsRoot, StateRoot, StateRootContext, StateRootVerifyError, Stopwatch, StoredReceipt,
    SubstateClaim, SubstateKey, SweepFrontier, TermsRoot, TermsSection, TickLine, TickManifest,
    TickManifestRoot, Timeout, TimeoutCertificate, TimeoutContext, TopologySnapshot, Transaction,
    TransactionRoot, TxHash, TxsInFlight, UnsettledTx, ValidatorId, Verifiable, VerificationKind,
    Verified, Verifier, Verify, VoteCount, VrfProof, WeightedTimestamp, WitnessSources,
    absorb_committed_cells, commit_witness_window, derive_leaves, fees_over_certificates,
    local_settled_tx_hashes, missed_proposals_since_prev_commit, next_reveal_chain,
    shard_prefix_path, shard_reveal_sign, signed_bytes, tick_terms_admit_block,
    vrf_output_from_proof,
};

use crate::parent_checks::{
    AtParent, ParentRefusal, PayerCharges, ProposalClaims, proposal_claims, refused_at_parent,
    within_the_cap, without_refused_reclaims,
};
use crate::tick_members::{derived_terms, stated_terms, states_entry};

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
/// Called from the dispatch layer via `ConsensusAction::VerifyAndBuildQuorumCertificate`;
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
    committee_epoch: Epoch,
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
            committee_epoch,
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
        committee_epoch,
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
            record_signature_verification_failure("vote");
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
    /// What the block adds to its chain's answers and owed crossings,
    /// measured as a voter's state-root check measures it.
    pub additions: AnswerAdditions,
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
///
/// # Errors
///
/// [`PersistedPastAnchor`] when the store has persisted past the parent
/// before the block's sweep could be walked: a block at this height is
/// already committed here, so there is nothing to propose.
///
/// # Panics
///
/// Never: the member lines stop at the manifest's line cap.
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
    transactions: &Capped<Vec<Verified<Transaction>>, MAX_TXS_PER_BLOCK>,
    certificates: Capped<Vec<Verifiable<Finalization>>, MAX_FINALIZED_TX_PER_BLOCK>,
    local_shard: ShardId,
    chain_origin: WeightedTimestamp,
    topology_snapshot: &TopologySnapshot,
    provisions: Capped<Vec<Verifiable<Provision>>, MAX_PROVISIONS_PER_BLOCK>,
    abandonment_records: Capped<Vec<AbandonmentRecord>, MAX_PROVISION_TARGET_SHARDS>,
    state_claims: Capped<Vec<StateClaim>, MAX_CLAIMS_PER_BLOCK>,
    parent_settled_frontier: BlockHeight,
    sweep: BlockSweep,
    parent_load: Option<ShardLoad>,
    substate: SubstateClaim,
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
    manifest: &ManifestInputs,
    timeout_cert: Option<TimeoutCertificate>,
    standing: Option<&StandingAnswers>,
) -> Result<ProposalResult, PersistedPastAnchor> {
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
    // What would carry the chain's standing answers past the cap goes
    // before anything is named over it: a record its credit or decline
    // would answer is cut from its claim, and a transaction owing
    // crossings goes back to the pool. Without a count every addition
    // goes.
    let (state_claims, records_capped, transactions_capped) = within_the_cap(
        standing,
        topology_snapshot.shard_trie(),
        local_shard,
        parent_qc.weighted_timestamp(),
        &anchored,
        state_claims.into_inner(),
        &mut transactions,
    );
    let state_claims: Capped<Vec<StateClaim>, MAX_CLAIMS_PER_BLOCK> =
        Capped::new(state_claims).expect("cutting a reading adds no claim");
    record_intake_capped("arrival", records_capped as u64);
    record_intake_capped("transaction", transactions_capped as u64);
    // The sweep, before the root it moves. Removals are ordinary writes,
    // so they fold in with the block's settling receipts and land under
    // `state_root` like anything else — and the frontier the walk stops
    // at is what the header claims, since that is what a verifier
    // recomputes.
    //
    // Walked through the view rather than the store: a cell a certified
    // but unpersisted ancestor created or retired is one this block's
    // removals must account for, and the store alone does not know it.
    let (removals, sweep_frontier) = view.sweep_for_block(sweep, parent_qc.weighted_timestamp())?;
    // The member lines, named over the block as it will be carried: the
    // parent's rows with this block's own content folded in, what the
    // chain up to the parent says of each member, and the bundles and
    // claims the block keeps. Named before anything below reads the
    // transactions, since naming is what settles the list: where the
    // terms the lines leave unstated pass the section's budget, the
    // tail goes back to the pool.
    let anchor = parent_qc.weighted_timestamp();
    let parent_rows = MemberIndex::load(&anchored, local_shard);
    let mut committed = manifest.committed.clone();
    committed.engaged.extend(
        Engagement::of_provisions(&provisions)
            .into_iter()
            .map(|engagement| (engagement.source, engagement.tx_hash)),
    );
    committed.arrived.extend(record_arrivals(&state_claims));
    let Named {
        mut rows,
        mut pending,
        lines,
        contended,
        proven,
    } = (Naming {
        parent: &parent_rows,
        shard: local_shard,
        height,
        anchor,
        committee: topology_snapshot,
        certificates: &certificates,
        records: &abandonment_records,
        claims: &state_claims,
        windows: frontier.windows,
        manifest,
        committed: &committed,
    })
    .within_terms_budget(&mut transactions);
    record_hold_contentions(contended);
    record_hold_inversions_proven(proven);
    let transactions = &transactions;
    let tick_manifest: Arc<TickManifest> =
        Arc::new(Capped::new(lines).expect("the budget stops at the line cap"));
    // What the block states: the terms of every transaction it commits
    // that no line of it runs, or whose terms carry crossings. The fold
    // below reads this section and not the derived set, as every replica
    // committing the block does.
    let stated = stated_terms(std::mem::take(&mut pending.terms), &tick_manifest);
    let terms: Arc<TermsSection> = Arc::new(
        Capped::new(stated.clone()).expect("one entry at most for each transaction of the block"),
    );
    let members = MemberInputs {
        manifest: Arc::clone(&tick_manifest),
        terms: stated,
        ..pending
    };
    // A record the fold could not return beside everything else the
    // block writes is left to a later block, its consumer's `Never` cut
    // from the claims before the root reads them, and its own reading
    // with it where nothing else reads the record.
    let settling: Vec<StoredReceipt> = certificates
        .iter()
        .flat_map(|fw| fw.settling_receipts())
        .collect();
    let merged = settling_writes(
        &settling,
        &state_claims,
        &members,
        &anchored,
        &shard_prefix_path(local_shard),
    );
    let state_claims: Capped<Vec<StateClaim>, MAX_CLAIMS_PER_BLOCK> = Capped::new(
        without_refused_reclaims(state_claims.into_inner(), &members, &merged, &anchored),
    )
    .expect("cutting a reading adds no claim");
    let additions = answer_additions(
        &members,
        &state_claims,
        &anchored,
        &shard_prefix_path(local_shard),
    );
    debug_assert!(
        standing.map_or(additions.is_empty(), |standing| standing
            .admits(&additions, topology_snapshot.shard_trie())
            .is_ok()),
        "a proposal adds what its own cap left out"
    );
    // The read marks of the claims carried: a parent claim the cut left
    // reading nothing raises none.
    let frontier = &FrontierInputs::for_block(
        &state_claims,
        frontier.windows,
        frontier.anchor,
        frontier.local,
    );
    // What the chain writes of its own accord: a committed-transaction
    // cell for every transaction the block carries. Derived from the
    // block's own transactions, so every reader of the root — the
    // proposer's voters, a replica committing on the certificate alone,
    // a split child following the block — derives the same set.
    let creations = committed_tx_cells(local_shard, transactions.iter().map(|tx| &**tx));
    // The drain is the member rows standing after the block: the rows
    // the lines were named over, folded once more with the block as
    // carried, which leaves what the commit's own fold leaves. Read
    // off committed state and the block alone, so a voter folding the
    // same block over the same rows reaches the same count.
    rows.advance(&members);
    let txs_in_flight = TxsInFlight::new(rows.members.len() as u64);
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
            sweep_frontier,
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
    let transactions = transactions.map(|tx| Verifiable::from(tx.clone()));

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
        &settling,
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

    let raw_provision_hashes: Vec<Hash> = provision_hashes.iter().map(|h| h.into_raw()).collect();
    // Each leaf binds the keys its part serves out of the state this
    // block leaves, which the header's state root commits, and the
    // block's clock, which commits its transactions.
    let provision_tx_roots = provision_tx_roots(
        &PreparedBlockView {
            parent: &anchored,
            block: &jmt_snapshot,
        },
        topology_snapshot.shard_trie(),
        local_shard,
        anchor,
        &transactions,
    )
    .expect("a proposal's transactions are verified, which derives them");

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
            transactions.iter().map(|tx| &**tx),
            topology_snapshot.shard_trie(),
            local_shard,
        ),
        substate.bytes,
    );

    let body_root = SectionRoots {
        transactions: Verified::<TransactionRoot>::compute(&transactions).into_inner(),
        certificates: CertificateRoot::over(&certificates),
        local_receipts: LocalReceiptRoot::over(&receipts),
        provisions: ProvisionsRoot::over(&raw_provision_hashes),
        // What departed shards left unresolved, committed so a verdict on
        // it outlives the settled set the records were read from.
        abandonment: AbandonmentRoot::over(&abandonment_records),
        // Proofs of counterparts' cells, committed so every replica folds
        // the same answers at this height.
        state_claims: StateClaimsRoot::over(&state_claims),
        // What the provisions engage, committed so a sealed form keeps the
        // entries the engagement tier folds after the bodies are gone.
        engagements: EngagementRoot::over(&Engagement::of_provisions(&provisions)),
        tick_manifest: TickManifestRoot::over(&tick_manifest),
        terms: TermsRoot::over(&terms),
    }
    .root();

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
        body_root,
        provision_tx_roots,
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
        substate_base: substate.base,
        timeout_cert,
    });

    let block = Block::Live {
        header,
        transactions: Arc::new(transactions),
        certificates: Arc::new(certificates),
        provisions: Arc::new(provisions),
        abandonment_records: Arc::new(abandonment_records),
        state_claims: Arc::new(state_claims),
        tick_manifest,
        terms,
        witness_sources,
    };

    let block_hash = block.hash();

    Ok(ProposalResult {
        block,
        block_hash,
        prepared_commit: prepared,
        jmt_snapshot,
        additions,
    })
}

/// What a block's lines are named over, beside its transactions.
pub(crate) struct Naming<'a> {
    /// Tick membership at the parent.
    pub(crate) parent: &'a MemberIndex,
    /// The proposing chain.
    pub(crate) shard: ShardId,
    /// The block's height.
    pub(crate) height: BlockHeight,
    /// The block's parent-QC clock.
    pub(crate) anchor: WeightedTimestamp,
    /// The committee the block is classified under.
    pub(crate) committee: &'a TopologySnapshot,
    /// The finalizations the block carries.
    pub(crate) certificates: &'a [Verifiable<Finalization>],
    /// The boundary records the block carries.
    pub(crate) records: &'a [AbandonmentRecord],
    /// The state claims the block carries.
    pub(crate) claims: &'a [StateClaim],
    /// The epoch grid the claims' anchors are marked on.
    pub(crate) windows: EpochWindows,
    /// What the coordinator gathered of the members the block may name.
    pub(crate) manifest: &'a ManifestInputs,
    /// What committed content says of them, the block's own bundles and
    /// claims included.
    pub(crate) committed: &'a CommittedSets,
}

/// A block's lines as named over one list of transactions.
pub(crate) struct Named {
    /// The rows the lines were named over: the parent's, advanced by the
    /// block's content with every transaction on its derived terms.
    pub(crate) rows: MemberIndex,
    /// That content: what the block writes before its lines are named.
    pub(crate) pending: MemberInputs,
    /// The lines.
    pub(crate) lines: Vec<TickLine>,
    /// The hold contentions the lines leave standing.
    pub(crate) contended: usize,
    /// The lines that abort the victim of a proven hold cycle.
    pub(crate) proven: usize,
}

impl Naming<'_> {
    /// The lines a block of `transactions` names.
    ///
    /// # Panics
    ///
    /// If a transaction is not routed, or declares more accesses than a
    /// member holds: selection offers neither.
    pub(crate) fn over(&self, transactions: &[Verified<Transaction>]) -> Named {
        let pending = MemberInputs::deriving(
            self.shard,
            self.height,
            self.anchor,
            transactions.iter().map(|tx| &**tx),
            MemberSections {
                certificates: self.certificates,
                records: self.records,
                claims: self.claims,
            },
            self.windows,
            derived_terms(
                self.committee,
                self.shard,
                transactions.iter().map(|tx| &**tx),
            ),
        );
        let mut rows = self.parent.clone();
        rows.advance_content(&pending);
        let (lines, contended, proven) = match self.manifest.kind {
            ManifestKind::Members => {
                let victims = wounded(&rows, self.anchor, self.claims);
                let (mut lines, _, budget) = licensed_lines(
                    &rows,
                    self.anchor,
                    self.committed,
                    &|shard, committed| self.committed.evidence(shard, committed),
                    self.manifest.recovery,
                    &victims,
                    &self.committed.siblings,
                );
                // Every accepted row no sibling can still ask about is
                // ended, after the other lines and out of what they left.
                lines.extend(end_lines(
                    &rows,
                    self.parent,
                    &self.committed.siblings,
                    budget,
                ));
                let contended = contentions(&rows, &lines, self.anchor, self.committed).len();
                let proven = lines
                    .iter()
                    .filter(
                        |line| matches!(line, TickLine::Member { tx, .. } if victims.contains(tx)),
                    )
                    .count();
                (lines, contended, proven)
            }
            ManifestKind::Fates => (terminal_fates(&rows), 0, 0),
            ManifestKind::Empty => (Vec::new(), 0, 0),
        };
        Named {
            rows,
            pending,
            lines,
            contended,
            proven,
        }
    }

    /// The lines a block of `transactions` names, with the section they
    /// leave held to its budget.
    ///
    /// Selection charged the entry of every transaction reaching beyond
    /// this shard and nothing for the rest, which are ready in their own
    /// block unless a standing hold or the manifest's budget keeps them
    /// out of its tick. A transaction the block runs keeps its entry only
    /// where its terms carry crossings, which only one reaching beyond
    /// the shard does, so selection charged every entry so kept. Where
    /// the entries of those kept out carry the section past its budget,
    /// the transactions no line names and selection did not charge are
    /// dropped from the tail of the block's order until what is left
    /// fits, and the lines are named once more over the kept list. A
    /// dropped transaction claimed no hold and spent no budget, so the
    /// second naming names every line of the first and leaves a section
    /// no heavier than the drop left. A dropped transaction stays pooled.
    pub(crate) fn within_terms_budget(
        &self,
        transactions: &mut Capped<Vec<Verified<Transaction>>, MAX_TXS_PER_BLOCK>,
    ) -> Named {
        let named = self.over(transactions);
        let dropped = named.past_terms_budget(transactions, self.committee);
        if dropped.is_empty() {
            return named;
        }
        transactions.retain(|tx| !dropped.contains(&tx.hash()));
        self.over(transactions)
    }
}

impl Named {
    /// The transactions to drop so the section these lines leave fits
    /// its budget, weighing every entry [`stated_terms`] keeps: from the
    /// tail of `transactions`, the block's order, those no line names
    /// that reach no further than this shard.
    fn past_terms_budget(
        &self,
        transactions: &[Verified<Transaction>],
        committee: &TopologySnapshot,
    ) -> BTreeSet<TxHash> {
        let named: BTreeMap<TxHash, bool> = self
            .lines
            .iter()
            .filter_map(|line| match line {
                TickLine::Member { tx, joins, .. } => Some((*tx, joins.dispatched())),
                TickLine::Fate { .. } | TickLine::Discard { .. } | TickLine::End { .. } => None,
            })
            .collect();
        let mut weight: usize = self
            .pending
            .terms
            .iter()
            .filter(|entry| states_entry(named.get(&entry.tx) == Some(&true), &entry.terms))
            .map(|entry| entry.terms.wire_weight())
            .sum();
        let mut dropped = BTreeSet::new();
        for (tx, entry) in transactions.iter().zip(&self.pending.terms).rev() {
            if tick_terms_admit_block(weight) {
                break;
            }
            if !named.contains_key(&entry.tx) && committee.is_single_shard_transaction(tx) {
                weight -= entry.terms.wire_weight();
                dropped.insert(entry.tx);
            }
        }
        dropped
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

/// The completion event for one check on `block_hash`: a pass, or a
/// refusal logged with the verifier's reason.
fn check_completed<T, E: std::fmt::Display>(
    block_hash: BlockHash,
    kind: VerificationKind,
    result: Result<T, E>,
) -> ProtocolEvent {
    let outcome = match result {
        Ok(_) => CheckOutcome::checked(),
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
/// Keyed on the epoch the committing block's QC signed, because that
/// window is the one admission judged the ceiling at and the one the
/// ledger priced under — neither of the block's anchors names it across
/// a halt recovery's bridge, and a record is written a deadline after
/// the commit it names, so the window carrying the record is not it
/// either.
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
    entries: &[UnsettledTx],
) -> HashMap<Epoch, CommitWindow> {
    let mut resolved: HashMap<Epoch, CommitWindow> = HashMap::new();
    for epoch in entries.iter().map(|entry| entry.committed.committee_epoch) {
        if let hash_map::Entry::Vacant(slot) = resolved.entry(epoch)
            && let Some(state) = chain.get_state_by_epoch(epoch)
        {
            slot.insert(state.commit_window());
        }
    }
    resolved
}

/// Whether this chain's blocks bear out where `entry` says its
/// transaction committed; `None` when a block it reads is not held,
/// which leaves the name unanswered as an unheld body does.
///
/// The block at the stated height carries the transaction under the
/// anchor the name states. The block above it fixes the committee
/// window: the QC certifying the carrying block, which the child's hash
/// pins, states the epoch its quorum signed, and that is the window the
/// commit froze its classification and price at. A name stating any
/// other epoch states figures under a table the commit never ran under,
/// however exactly they restate there.
///
/// Both headers and the carrying manifest stay in the store for as long
/// as the transaction's member row stands, however far beneath its
/// chain floor: the store's `ChainHold` keeps the metadata rows at the
/// committing height and the one above it.
fn bears_out_commit<H: AsRef<CertifiedBlockHeader>>(
    entry: &UnsettledTx,
    carries: impl Fn(BlockHeight, TxHash) -> Option<bool>,
    certified_header: impl Fn(BlockHeight) -> Option<H>,
) -> Option<bool> {
    let committed = entry.committed;
    if !carries(committed.height, entry.tx_hash)? {
        return Some(false);
    }
    let carrying = certified_header(committed.height)?;
    let carrying = carrying.as_ref().header();
    let child = certified_header(committed.height.next())?;
    let certifying = child.as_ref().header().parent_qc();
    Some(
        carrying.parent_qc().weighted_timestamp() == committed.anchor
            && certifying.block_hash() == carrying.hash()
            && certifying.committee_epoch() == committed.committee_epoch,
    )
}

/// How the names `entries` stand against this chain and the windows
/// their commits ran under, `held` the transactions this node holds and
/// can derive: each name must be borne out by the chain
/// ([`bears_out_commit`]) and restate its figures exactly under its
/// stated window. A window above this node's fold is one to wait for, on
/// the terms an unheld body already sets.
fn resolutions_of<H: AsRef<CertifiedBlockHeader>>(
    entries: Vec<UnsettledTx>,
    held: &HashMap<TxHash, Verified<Transaction>>,
    chain: &dyn BeaconChainReader,
    shard: ShardId,
    carries: impl Fn(BlockHeight, TxHash) -> Option<bool>,
    certified_header: impl Fn(BlockHeight) -> Option<H>,
) -> Resolutions {
    let committed_windows = commit_windows_for(chain, &entries);
    Resolutions::of(entries, |entry| {
        let tx = held.get(&entry.tx_hash)?;
        let at = committed_windows.get(&entry.committed.committee_epoch)?;
        let classified = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), &at.trie);
        let restated = bears_out_commit(entry, &carries, &certified_header)?
            && UnsettledTx::for_transaction(
                tx,
                entry.committed,
                classified.local_price(tx, shard, &at.prices),
                &at.prices,
            ) == *entry;
        Some(restated)
    })
}

fn absorb_finalized_cells(ticks: &[Verifiable<Finalization>], derivation: &dyn Derivation) {
    let receipts: Vec<Arc<ConsensusReceipt>> = ticks
        .iter()
        .flat_map(|fw| fw.settling_receipts())
        .map(|receipt| receipt.consensus)
        .collect();
    absorb_committed_cells(receipts.iter().map(AsRef::as_ref), derivation);
}

/// Name every target whose provision root a judged block's header claims
/// otherwise than this voter computes, with both roots: an absent side is
/// a target one of them owes nothing.
fn warn_provision_root_differences(
    block_hash: BlockHash,
    block_height: BlockHeight,
    claimed: &ProvisionTxRootsMap,
    computed: &ProvisionTxRootsMap,
) {
    let targets: BTreeSet<ShardId> = claimed.keys().chain(computed.keys()).copied().collect();
    for target in targets {
        let (claimed, computed) = (claimed.get(&target), computed.get(&target));
        if claimed != computed {
            tracing::warn!(
                ?block_hash,
                height = block_height.inner(),
                target = target.inner(),
                ?claimed,
                ?computed,
                "Provision root claimed for a target differs from the one computed"
            );
        }
    }
}

/// The cells the block built on `view`'s anchor removed, for the state
/// root check of that block.
///
/// `coasting` is a voter's own reading of whether the schedule lets a
/// block at the anchor only coast. A voter recomputes the sweep: a walk
/// from the parent's frontier under the cap lands on exactly one
/// position, so the frontier the header claims either is the one the
/// walk produces or the block is refused, with the position the walk
/// landed on as the inner error. A claim short of it is a sweep the
/// proposer declined to finish, and one past it reaches cells the clock
/// does not yet allow. The removal set needs no separate check, being
/// what the same walk returned.
///
/// `None` is a block a quorum has certified, which is not held to the
/// walk: it removed the interval its header names above its parent's
/// frontier, whatever this replica's schedule says of its anchor, and
/// the root the check lands on answers for that. It is held to the
/// bounds every walk keeps, which read nothing of a schedule (see
/// [`SweepFrontier::reached_from`]), with the bound it breaks as the
/// inner error: a claim past the clock's ceiling would remove cells
/// that have not expired, under a root that agrees with it.
///
/// # Errors
///
/// [`PersistedPastAnchor`] when the store was written past the view's
/// anchor, under which neither reading has an answer.
pub fn swept_by<S>(
    view: &SubstateView<S>,
    parent_sweep_frontier: SweepFrontier,
    claimed_sweep_frontier: SweepFrontier,
    parent_weighted_timestamp: WeightedTimestamp,
    coasting: Option<bool>,
) -> Result<Result<Vec<SubstateKey>, SweepFrontier>, PersistedPastAnchor>
where
    S: SubstateStore + VersionedStore + SweepIndex,
{
    let Some(coasting) = coasting else {
        if let Err(bound) =
            claimed_sweep_frontier.reached_from(parent_sweep_frontier, parent_weighted_timestamp)
        {
            return Ok(Err(bound));
        }
        return view
            .sweep_through(parent_sweep_frontier, claimed_sweep_frontier)
            .map(Ok);
    };
    view.sweep_for_block(
        BlockSweep::of_child(parent_sweep_frontier, coasting),
        parent_weighted_timestamp,
    )
    .map(|(removals, landed)| {
        if landed == claimed_sweep_frontier {
            Ok(removals)
        } else {
            Err(landed)
        }
    })
}

/// Run shard consensus work.
///
/// Outcomes flow through `ctx.notify` (state-machine inputs) and
/// `ctx.commit_prepared` (prepared blocks for the `io_loop`'s chain).
#[allow(clippy::too_many_lines)] // single dispatch over ConsensusAction variants
pub fn handle_action<S, N>(action: ConsensusAction, ctx: &ActionContext<'_, S, N>)
where
    S: ShardStorage,
    N: Network,
{
    match action {
        ConsensusAction::VerifyAndBuildQuorumCertificate {
            block_hash,
            shard_id,
            height,
            round,
            committee_epoch,
            parent_block_hash,
            parent_weighted_timestamp,
            votes_to_verify,
            verified_votes,
            total_votes,
            binding,
        } => {
            let start = Stopwatch::start();
            let result = verify_and_build_qc(
                ctx.verifier,
                ctx.topology_snapshot.network(),
                block_hash,
                shard_id,
                height,
                round,
                committee_epoch,
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
                binding,
            });
        }

        ConsensusAction::VerifyQcSignature {
            qc,
            public_keys,
            quorum_threshold,
            subject,
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
            if result.is_err() {
                record_signature_verification_failure("qc");
            }
            ctx.notify_protocol(ProtocolEvent::QcSignatureVerified { subject, result });
        }

        ConsensusAction::VerifyRemoteHeaderQc {
            certified_header,
            source,
            committee_public_keys,
            quorum_threshold,
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
            if matches!(*result, Err(CertifiedHeaderVerifyError::Qc(_))) {
                record_signature_verification_failure("remote_header_qc");
            }
            ctx.network.settle(
                VerdictKey::from_digest(certified_header.copy_digest()),
                remote_header_verdict(&result),
            );
            ctx.notify_protocol(ProtocolEvent::RemoteHeaderQcVerified {
                certified_header,
                source,
                result,
            });
        }

        ConsensusAction::VerifyShardForkProof { proof, committees } => {
            let start = Stopwatch::start();
            let verified = proof
                .verify_resolved(ctx.verifier, ctx.topology_snapshot.network(), &committees)
                .is_ok();
            record_signature_verification_latency(
                "shard_fork_proof",
                start.elapsed().as_secs_f64(),
            );
            if !verified {
                record_signature_verification_failure("shard_fork_proof");
            }
            ctx.notify_protocol(ProtocolEvent::ShardForkProofVerified { proof, verified });
        }

        ConsensusAction::VerifyBodyRoot {
            block,
            validity_anchor,
        } => {
            let start = Stopwatch::start();
            let result = block.header().body_root().verify(&BodyRootContext {
                block: &block,
                validity_anchor,
            });
            record_signature_verification_latency("body_root", start.elapsed().as_secs_f64());
            ctx.notify_protocol(check_completed(
                block.hash(),
                VerificationKind::BodyRoot,
                result,
            ));
        }

        ConsensusAction::VerifyResolutions {
            block_hash,
            entries,
        } => {
            // A resolution names a transaction committed before it — a
            // record epochs after the commit, a finalization a tick or
            // more after — so the store's persist lag never reaches a
            // name, and a body lifted out of it carries no derivation of
            // its own: this node derives it, and one it cannot derive it
            // does not hold.
            let hashes: Vec<TxHash> = entries.iter().map(|entry| entry.tx_hash).collect();
            let derivation = ctx.executor.derivation();
            let held: HashMap<TxHash, Verified<Transaction>> = ctx
                .pending_chain
                .transactions_batch(&hashes)
                .into_iter()
                .filter(|tx| tx.try_derived(derivation.as_ref()).is_ok())
                .map(|tx| (tx.hash(), tx))
                .collect();
            let verdict = resolutions_of(
                entries,
                &held,
                ctx.beacon_chain,
                ctx.shard,
                |height, tx| ctx.pending_chain.carries(height, tx),
                |height| ctx.pending_chain.certified_header(height),
            );
            // An exact answer passes; a wrong figure refuses the block; a
            // name this validator's store never held is neither — the
            // check waits for the body.
            let outcome = match verdict {
                Resolutions::Exact => CheckOutcome::checked(),
                Resolutions::Wrong(tx_hash) => {
                    tracing::warn!(
                        ?block_hash,
                        ?tx_hash,
                        "Resolutions verification FAILED: a record misstates a figure"
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

        ConsensusAction::VerifyBeaconWitnessRoot {
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
            settling,
            thresholds,
            finalizations,
            topology_snapshot,
        } => {
            let start = Stopwatch::start();
            let receipts: Vec<StoredReceipt> = finalizations
                .iter()
                .flat_map(|fw| fw.settling_receipts())
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
                settling,
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

        ConsensusAction::VerifyStateRoot(check) => {
            let StateRootCheck {
                block_hash,
                transactions,
                parent_block_hash,
                parent_state_root,
                parent_block_height,
                expected_root,
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
                parent_judgement,
                state_claims,
            } = *check;
            let start = Stopwatch::start();
            let view = ctx
                .pending_chain
                .view_at(parent_block_hash, parent_block_height);
            // The view is freshly anchored — nothing has read through
            // it, so there is no execution cache to carry.
            let anchored = view.snapshot();
            // A store persisted past the parent holds a committed block
            // at this height, so this block is either that one or one
            // that can no longer commit, and the coordinator dropped it
            // from its pending set at the commit. Neither verdict would
            // be read.
            let swept = swept_by(
                &view,
                parent_sweep_frontier,
                claimed_sweep_frontier,
                parent_weighted_timestamp,
                parent_judgement
                    .as_ref()
                    .map(|judgement| judgement.coasting),
            );
            let removals = match swept {
                Ok(Ok(removals)) => removals,
                Ok(Err(refuting)) => {
                    if parent_judgement.is_some() {
                        tracing::warn!(
                            ?block_hash,
                            height = block_height.inner(),
                            ?claimed_sweep_frontier,
                            walked_to = ?refuting,
                            "Rejecting block whose sweep frontier is not the one its walk lands on"
                        );
                    } else {
                        tracing::warn!(
                            ?block_hash,
                            height = block_height.inner(),
                            ?parent_sweep_frontier,
                            ?claimed_sweep_frontier,
                            bound = ?refuting,
                            "Rejecting certified block whose sweep frontier no walk lands on"
                        );
                    }
                    ctx.notify_protocol(ProtocolEvent::BlockCheckCompleted {
                        block_hash,
                        kind: VerificationKind::StateRoot,
                        outcome: CheckOutcome::Refused,
                    });
                    return;
                }
                Err(past) => {
                    tracing::debug!(
                        ?block_hash,
                        height = block_height.inner(),
                        persisted = past.persisted.inner(),
                        "Dropping a state root check whose parent the store has persisted past"
                    );
                    return;
                }
            };
            if let Some(judgement) = &parent_judgement
                && let Err(refusal) = refused_at_parent(
                    &AtParent {
                        local: ctx.shard,
                        creations: &creations,
                        members: &members,
                        fence: &judgement.fence,
                        state_claims: &state_claims,
                        transactions: &transactions,
                        finalizations: &finalizations,
                    },
                    &anchored,
                )
            {
                tracing::warn!(
                    ?block_hash,
                    height = block_height.inner(),
                    %refusal,
                    "Rejecting block its parent state refuses"
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
                    sweep_frontier: claimed_sweep_frontier,
                    frontier: &frontier,
                    state_claims: &state_claims,
                    members: &members,
                },
                block_height,
            );
            // A judged block's provision roots are recomputed over the
            // state it leaves, which its state root commits, and held to
            // its claim whether the claim is empty or not. A certified
            // block's are not judged. Timed on its own and kept out of the
            // state root's figure.
            let provision_timer = Stopwatch::start();
            let computed = parent_judgement.as_ref().map(|judgement| {
                provision_tx_roots(
                    &PreparedBlockView {
                        parent: &anchored,
                        block: &jmt_snapshot,
                    },
                    &judgement.provisions.trie,
                    ctx.shard,
                    parent_weighted_timestamp,
                    &transactions,
                )
            });
            let provision_elapsed = provision_timer.elapsed();
            if computed.is_some() {
                record_signature_verification_latency(
                    "provision_tx_roots",
                    provision_elapsed.as_secs_f64(),
                );
            }
            let computed_provision_tx_roots = match computed {
                None => None,
                Some(Ok(computed)) => Some(computed),
                Some(Err(unrouted)) => {
                    tracing::warn!(
                        ?block_hash,
                        height = block_height.inner(),
                        %unrouted,
                        "Rejecting block whose provision roots this node cannot route"
                    );
                    ctx.notify_protocol(ProtocolEvent::BlockCheckCompleted {
                        block_hash,
                        kind: VerificationKind::StateRoot,
                        outcome: CheckOutcome::Refused,
                    });
                    return;
                }
            };
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
                provision_tx_roots: parent_judgement
                    .as_ref()
                    .zip(computed_provision_tx_roots.as_ref())
                    .map(|(judgement, computed)| ProvisionTxRootsJudged {
                        claimed: &judgement.provisions.claimed,
                        computed,
                    }),
            });
            record_signature_verification_latency(
                "state_root",
                start
                    .elapsed()
                    .saturating_sub(provision_elapsed)
                    .as_secs_f64(),
            );
            let bytes_delta = jmt_snapshot.bytes_delta;
            let answers = jmt_snapshot.answer_delta(&anchored, &shard_prefix_path(ctx.shard));
            let additions = answer_additions(
                &members,
                &state_claims,
                &anchored,
                &shard_prefix_path(ctx.shard),
            );
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
                Ok(_) => CheckOutcome::Checked {
                    bytes_delta,
                    answers,
                    additions,
                },
                Err(e) => {
                    tracing::warn!(
                        block_hash = ?block_hash,
                        block_height = block_height.inner(),
                        parent_block_height = parent_block_height.inner(),
                        reason = %e,
                        "State root verification FAILED"
                    );
                    if let (
                        StateRootVerifyError::ProvisionTxRootsMismatch,
                        Some(judgement),
                        Some(computed),
                    ) = (&e, &parent_judgement, &computed_provision_tx_roots)
                    {
                        warn_provision_root_differences(
                            block_hash,
                            block_height,
                            &judgement.provisions.claimed,
                            computed,
                        );
                    }
                    CheckOutcome::Refused
                }
            };
            ctx.notify_protocol(ProtocolEvent::BlockCheckCompleted {
                block_hash,
                kind: VerificationKind::StateRoot,
                outcome,
            });
        }

        ConsensusAction::BuildProposal {
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
            parent_settled_frontier,
            sweep,
            parent_load,
            substate,
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
            rowless,
            manifest,
            timeout_cert,
            standing_answers,
        } => {
            let Some(signing) = &ctx.signing else {
                tracing::error!(?shard_id, "proposal dispatched without a signer; skipping");
                return;
            };
            // Sign the block's randomness reveal here — off the main loop, on
            // the dispatch pool — so the sans-io coordinator holds no key. Its
            // digest is the link the block adds to its reveal chain; the proof
            // rides the block body and manifest for the verifier's re-check.
            let Some(entry) = signing.enter("BuildProposal") else {
                return;
            };
            let revealed = shard_reveal_sign(
                signing.key.as_ref(),
                ctx.topology_snapshot.network(),
                shard_id,
                height,
            );
            drop(entry);
            let Ok(randomness_reveal) = revealed else {
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
            // What the read frontier would refuse is dropped before the
            // block is built, so a proposal never refuses itself.
            let ProposalClaims {
                claims: state_claims,
                frontier,
                refused,
            } = proposal_claims(
                state_claims,
                &fence,
                &frontier,
                &local_crossings,
                &rowless,
                parent_anchor,
                &view.snapshot(),
            );
            if refused > 0 {
                tracing::debug!(
                    ?shard_id,
                    height = height.inner(),
                    refused,
                    "Dropped what the read frontier refuses from the proposal"
                );
            }
            // Drop what a payer would refuse, charged against the parent
            // view every voter judges the block by, so a proposal never
            // refuses itself.
            let parent_state = view.snapshot();
            let mut charges = PayerCharges::new(shard_id, &parent_state);
            let mut unadmitted = 0usize;
            let mut uncovered = 0usize;
            let transactions: Vec<_> = transactions
                .into_iter()
                .filter(|tx| match charges.charge(tx) {
                    Ok(()) => true,
                    Err(ParentRefusal::UnadmittedPayer(_)) => {
                        unadmitted += 1;
                        false
                    }
                    Err(_) => {
                        uncovered += 1;
                        false
                    }
                })
                .collect();
            if uncovered > 0 {
                tracing::debug!(
                    uncovered,
                    height = height.inner(),
                    "Dropped transactions whose payer cannot cover its fee reservation"
                );
            }
            if unadmitted > 0 {
                tracing::debug!(
                    unadmitted,
                    height = height.inner(),
                    "Dropped transactions whose payer's rule does not admit their signer"
                );
            }
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
            let built = build_proposal(
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
                parent_settled_frontier,
                sweep,
                parent_load,
                substate,
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
                &manifest,
                timeout_cert,
                standing_answers.as_ref(),
            );
            // A store persisted past the parent holds a committed block at
            // this height; the slot has nothing left to fill.
            let result = match built {
                Ok(result) => result,
                Err(past) => {
                    tracing::debug!(
                        shard = ?shard_id,
                        height = height.inner(),
                        round = round.inner(),
                        persisted = past.persisted.inner(),
                        "Skipping a proposal whose parent the store has persisted past"
                    );
                    return;
                }
            };
            let block_hash = result.block_hash;
            let bytes_delta = result.jmt_snapshot.bytes_delta;
            let answers = result
                .jmt_snapshot
                .answer_delta(&view.snapshot(), &shard_prefix_path(shard_id));
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
                answers,
                additions: result.additions,
            });
        }

        // ── Sign + broadcast actions ──────────────────────────────────────
        ConsensusAction::BroadcastBlockHeader {
            header,
            manifest,
            recipients,
            position,
        } => {
            let Some(signing) = &ctx.signing else {
                tracing::error!("block header dispatched without a signer; skipping");
                return;
            };
            let Some(_entry) = signing.enter("BroadcastBlockHeader") else {
                return;
            };
            // The proposer's spent round is durable before the header
            // signature exists, as the vote arm's position is.
            ctx.vote_registers
                .persist_vote_position(signing.me, &position);
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
            let Ok(sig) = signing.key.sign(&msg) else {
                tracing::error!(?block_hash, "cannot sign block header; skipping broadcast");
                return;
            };
            let gossip = BlockHeaderNotification::new(*header, *manifest, sig);
            ctx.network.notify(&recipients, &gossip);
        }

        ConsensusAction::SignAndBroadcastBlockVote {
            block_hash,
            parent_block_hash,
            height,
            round,
            committee_epoch,
            timestamp,
            next_proposers,
            position,
            signer: _,
        } => {
            let Some(signing) = &ctx.signing else {
                tracing::error!(
                    ?block_hash,
                    "block vote dispatched without a signer; abstaining"
                );
                return;
            };
            let Some(_entry) = signing.enter("SignAndBroadcastBlockVote") else {
                return;
            };
            // The position this vote ratcheted must be durable before
            // the signature exists — a crash between them costs at most
            // an abstention, never a second vote in a consumed round.
            ctx.vote_registers
                .persist_vote_position(signing.me, &position);
            let Ok(verified) = Verified::<BlockVote>::sign_local(
                ctx.topology_snapshot.network(),
                block_hash,
                parent_block_hash,
                ctx.shard,
                height,
                round,
                committee_epoch,
                signing.me,
                signing.key.as_ref(),
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

        ConsensusAction::SignAndBroadcastTimeout {
            round,
            high_qc,
            high_tc,
            recipients,
            position,
            signer: _,
        } => {
            let Some(signing) = &ctx.signing else {
                tracing::error!(?round, "timeout dispatched without a signer; abstaining");
                return;
            };
            let Some(_entry) = signing.enter("SignAndBroadcastTimeout") else {
                return;
            };
            // Same persistence rule as the vote arm: the abandoned round
            // is durable before the timeout signature exists.
            ctx.vote_registers
                .persist_vote_position(signing.me, &position);
            let Ok(verified) = Verified::<Timeout>::sign_local(
                ctx.topology_snapshot.network(),
                ctx.shard,
                round,
                high_qc,
                signing.me,
                signing.key.as_ref(),
            ) else {
                tracing::error!(?round, "cannot sign timeout; abstaining");
                return;
            };
            let verified = verified.with_high_tc(high_tc);
            let gossip = TimeoutNotification::new(verified.clone());
            ctx.network.notify(&recipients, &gossip);
            // Feed our own signed timeout back for local TimeoutKeeper tracking.
            ctx.notify_protocol(ProtocolEvent::VerifiedTimeoutReceived { timeout: verified });
        }

        ConsensusAction::SignAndBroadcastQcAnnouncement {
            qc,
            recipients,
            signer: _,
        } => {
            let Some(signing) = &ctx.signing else {
                tracing::error!("QC announcement dispatched without a signer; skipping");
                return;
            };
            let Some(_entry) = signing.enter("SignAndBroadcastQcAnnouncement") else {
                return;
            };
            let mut announcement = QcAnnouncementNotification {
                qc,
                sender: signing.me,
                sender_signature: ConsensusSignature::ZERO,
            };
            let message = announcement.signing_message(ctx.topology_snapshot.network());
            let Ok(signature) = signing.key.sign(&message) else {
                tracing::error!("cannot sign QC announcement; skipping");
                return;
            };
            announcement.sender_signature = signature;
            ctx.network.notify(&recipients, &announcement);
        }

        ConsensusAction::SignAndBroadcastReadySignal {
            shard,
            wt_window_start,
            wt_window_end,
            recipients,
            local_recipient,
            signer: _,
        } => {
            let Some(signing) = &ctx.signing else {
                tracing::error!(?shard, "ready signal dispatched without a signer; skipping");
                return;
            };
            let Some(_entry) = signing.enter("SignAndBroadcastReadySignal") else {
                return;
            };
            let Ok(signal) = ReadySignal::sign(
                ctx.topology_snapshot.network(),
                signing.me,
                shard,
                wt_window_start,
                wt_window_end,
                signing.key.as_ref(),
            ) else {
                tracing::error!(?shard, "cannot sign ready signal; skipping");
                return;
            };
            if local_recipient {
                ctx.notify_protocol(ProtocolEvent::ReadySignalReceived {
                    signal: signal.clone(),
                });
            }
            if !recipients.is_empty() {
                ctx.network
                    .notify(&recipients, &ReadySignalNotification::new(signal));
            }
        }

        ConsensusAction::VerifyTimeout {
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
            if let Ok(verified) = result {
                ctx.notify_protocol(ProtocolEvent::VerifiedTimeoutReceived { timeout: verified });
            } else {
                record_signature_verification_failure("timeout");
                tracing::warn!(voter = ?timeout.voter(), "Dropping timeout with an invalid signature share");
            }
        }

        ConsensusAction::BroadcastCertifiedBlockHeader { certified_header } => {
            let Some(signing) = &ctx.signing else {
                tracing::error!("certified header gossip dispatched without a signer; skipping");
                return;
            };
            let Some(_entry) = signing.enter("BroadcastCertifiedBlockHeader") else {
                return;
            };
            let msg = signed_bytes(
                &CertifiedBlockHeaderSenderMessage {
                    shard_id: certified_header.header().shard_id(),
                    height: certified_header.header().height(),
                    block_hash: certified_header.header().hash(),
                },
                ctx.topology_snapshot.network(),
            );
            let Ok(sig) = signing.key.sign(&msg) else {
                tracing::error!("cannot sign certified header gossip; skipping");
                return;
            };
            let gossip = CertifiedBlockHeaderGossip {
                certified_header: Verifiable::<CertifiedBlockHeader>::from(certified_header),
                sender: signing.me,
                sender_signature: sig,
            };
            ctx.network.broadcast_global(&gossip);
        }

        ConsensusAction::BroadcastShardForkProof { proof } => {
            // Self-authenticating: gossip the proof unsigned; every recipient
            // re-verifies it against its own topology.
            let gossip = ShardForkProofGossip {
                proof: Arc::from(proof),
            };
            ctx.network.broadcast_global(&gossip);
        }
    }
}

/// The verdict a remote header's check settles for every gossiped copy of
/// it. A copy travels on only once its certificate holds, and a false one
/// is its sender's to answer for. The check ran under the committee of the
/// window the certificate's signers name, which every anchor that admits
/// that window resolves alike, so a failure is final whether or not the
/// header's parent named the anchor.
const fn remote_header_verdict(
    result: &Result<Verified<CertifiedBlockHeader>, CertifiedHeaderVerifyError>,
) -> Verdict {
    match result {
        Ok(_) => Verdict::Accept,
        Err(_) => Verdict::Reject,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use hyperscale_core::{Parallelism, ParentJudgement, ProvisionJudgement};
    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};
    use hyperscale_engine::{ExecutionMode, Executor};
    use hyperscale_hbor::Capped;
    use hyperscale_network::{
        Answerers, GossipHandler, NotificationHandler, RequestError, RequestHandler,
        ResponseVerdict,
    };
    use hyperscale_provisions::Unrouted;
    use hyperscale_storage::test_helpers::{commit_writes, placeholder_local_ec};
    use hyperscale_storage::{
        ChainEntry, ChainHold, MemberIndex, MemberInputs, PendingChain, ShardChainReader,
        TickChain, committed_here,
    };
    use hyperscale_storage_memory::{SimBeaconStorage, SimShardStorage};
    use hyperscale_types::test_utils::{
        StubVmStatics, TestCommittee, install_stub_protocol_statics, stating_half_on,
        stub_abort_charge, stub_stated_terms, stub_transaction, stub_transaction_with_reads,
        test_pool, test_prefix, test_principal,
    };
    use hyperscale_types::{
        Address, AddressClass, AggregateSignature, BeaconBlockHash, BeaconChainConfig, BeaconState,
        BeaconWitnessEvent, BodyRoot, BodyRootVerifyError, CertifiedBeaconBlock, CollectionId,
        CommittedAt, Deadline, DeclaredKey, DeclaredRange, DerivationError, Derived, EntryKey,
        ExecutionOutcome, GlobalReceiptHash, GossipMessage, LocalKey, MessageClass, NetworkMessage,
        PriceTable, PrincipalAddr, ProposerTimestamp, ProtocolHasher, ProvisionTxRoot,
        ProvisionTxRootsMap, ReadFence, Request, Role, RoutingCommittees, SettledWrites,
        ShardCommittee, ShardTrie, Signer, SignerBitfield, Stake, StateWrites, TickHalf, TickId,
        TimestampRange, TransactionEnvelope, TxOutcome, entry_leaf_key, provision_leaf,
        receipt_hash_of, served_digest,
    };

    use super::*;

    /// A derivation recording every committed cell it is offered, and
    /// deriving nothing.
    #[derive(Default)]
    struct Offered(Mutex<Vec<[u8; 16]>>);

    impl Derivation for Offered {
        fn derive(&self, _: &TransactionEnvelope) -> Result<Derived, DerivationError> {
            Err(DerivationError::Refused("records offers only".into()))
        }

        fn absorb_committed_cell(&self, _: [u8; 32], local: [u8; 16], _: &[u8]) {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(local);
        }
    }

    /// A yes a stating half carries settles nothing where the half
    /// commits: no witness leaf lifts its beacon facts, no committed cell
    /// it writes is offered to the package cache, and none of its writes
    /// is settled. The same receipt settled by a determined half does all
    /// three.
    #[test]
    fn a_yes_receipt_emits_no_witness_absorbs_no_cell_and_writes_nothing_at_stating() {
        install_stub_protocol_statics();
        let mut writes = StateWrites::default();
        writes.cells.insert(
            SubstateKey {
                owner: Address::new([0x42; 31], AddressClass::Component),
                local: LocalKey([0x42; 16]),
            },
            Some(b"a package".to_vec()),
        );
        let witness = BeaconWitnessEvent::StakeDeposit {
            pool_id: test_pool(1),
            amount: Stake::from_quanta(5),
        };
        let unhashed = ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            writes: writes.clone(),
            beacon_witness_events: Capped::from_array([witness.clone()]),
            events: Capped::empty(),
        };
        let receipt_hash = receipt_hash_of(&unhashed, true).expect("a projected success");
        let tx = TxHash::from(Hash::from_bytes(b"a stated yes"));
        let receipt = StoredReceipt::new(
            tx,
            Arc::new(ConsensusReceipt::Succeeded {
                receipt_hash,
                writes,
                beacon_witness_events: Capped::from_array([witness]),
                events: Capped::empty(),
            }),
        );
        let yes = TxOutcome::new(tx, ExecutionOutcome::Succeeded { receipt_hash })
            .charging(1)
            .awaiting([ShardId::leaf(1, 1)])
            .as_role(Role::Core);
        let stating = stating_half_on(
            ShardId::ROOT,
            BlockHeight::new(1),
            vec![yes],
            vec![receipt.clone()],
        );
        assert_eq!(stating.validate_against_certificates(), Ok(()));
        let determined = Finalization::new(
            *stating.tick_id(),
            TickHalf::Determined,
            stating.local_ec().cloned(),
            Capped::from_array([receipt]),
        );

        let snapshot = TestCommittee::new(4, 7).topology_snapshot(1);
        let sources = WitnessSources::new(Capped::empty(), None, VrfProof::ZERO);
        let effects = |fw: &Finalization| {
            let receipts = fw.settling_receipts();
            let leaves = derive_leaves(ShardId::ROOT, &snapshot, &receipts, &[], &sources);
            let offered = Offered::default();
            absorb_finalized_cells(&[Verifiable::from(fw.clone())], &offered);
            let offered = offered
                .0
                .into_inner()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (leaves.len(), offered.len(), receipts.len())
        };
        assert_eq!(effects(&stating), (0, 0, 0), "the yes settles nothing");
        assert_eq!(
            effects(&determined),
            (1, 1, 1),
            "where its effects settle, they do"
        );
    }

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
        ) -> Option<Verified<CertifiedBeaconBlock>> {
            None
        }

        fn get_beacon_block_by_hash(
            &self,
            _hash: BeaconBlockHash,
        ) -> Option<Verified<CertifiedBeaconBlock>> {
            None
        }

        fn latest_committed_epoch(&self) -> Option<Epoch> {
            self.0.keys().copied().max()
        }

        fn latest_committed(&self) -> Option<(Verified<CertifiedBeaconBlock>, Arc<BeaconState>)> {
            None
        }
    }

    /// One name, committed at height 1 under the window `committee_epoch`
    /// keys, with its block's own anchor at `anchor`.
    fn named_at(committee_epoch: u64, anchor: u64) -> UnsettledTx {
        UnsettledTx {
            tx_hash: TxHash::from(Hash::from_bytes(b"tx")),
            deadline: Deadline::of(WeightedTimestamp::from_millis(60_000)),
            charged: 5,
            charge: stub_abort_charge(5),
            committed: CommittedAt {
                height: BlockHeight::new(1),
                anchor: WeightedTimestamp::from_millis(anchor),
                committee_epoch: Epoch::new(committee_epoch),
            },
            reach: Capped::empty(),
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
        let chain = Folded::to(&[(0, 1), (1, 2)]);

        let resolved = commit_windows_for(&chain, &[named_at(0, 500)]);

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

    /// A name is weighed at the window its commit's quorum signed, which
    /// neither of the block's anchors names across a halt recovery's
    /// bridge: the fresh committee signs the window it was seated in.
    #[test]
    fn a_name_is_weighed_at_its_signed_window_whatever_its_anchor_dates() {
        let chain = Folded::to(&[(2, 1), (21, 2)]);

        // Anchored in epoch 2, certified by a committee seated for 21.
        let resolved = commit_windows_for(&chain, &[named_at(21, 2_500)]);

        assert_eq!(
            resolved[&Epoch::new(21)].prices.compute,
            2,
            "the signed window is the one that froze the figures"
        );
        assert!(
            !resolved.contains_key(&Epoch::new(2)),
            "and never the window its anchor dates"
        );
    }

    /// A window above this node's fold leaves its name out rather than
    /// standing something else in for it. The check that misses one
    /// answers `Unknown`, which defers the block; a stand-in would weigh
    /// the share at a placement the transaction never ran under.
    #[test]
    fn an_unfolded_epoch_resolves_no_window() {
        let chain = Folded::to(&[(0, 1)]);

        let resolved = commit_windows_for(&chain, &[named_at(5, 5_000)]);

        assert!(resolved.is_empty());
    }

    /// The headers at heights 0 to 2 of a chain whose block 1 dates at
    /// `anchor` and whose block 2, extending it, pins a QC over block 1
    /// that its quorum signed under `signed`.
    fn committed_chain(anchor: u64, signed: u64) -> [Verified<CertifiedBlockHeader>; 3] {
        let certify = |height: u64, parent: BlockHash, dated: u64, epoch: u64| {
            let height = BlockHeight::new(height);
            let header = BlockHeader::new(BlockHeaderParts {
                height,
                parent_block_hash: parent,
                parent_qc: Verifiable::from(QuorumCertificate::new(
                    parent,
                    ShardId::ROOT,
                    height.prev().unwrap_or(height),
                    BlockHash::ZERO,
                    Round::INITIAL,
                    Epoch::new(epoch),
                    SignerBitfield::empty(),
                    AggregateSignature::ZERO,
                    WeightedTimestamp::from_millis(dated),
                )),
                ..Default::default()
            });
            let qc = QuorumCertificate::new(
                header.hash(),
                ShardId::ROOT,
                height,
                parent,
                Round::INITIAL,
                Epoch::GENESIS,
                SignerBitfield::empty(),
                AggregateSignature::ZERO,
                WeightedTimestamp::ZERO,
            );
            Verified::<CertifiedBlockHeader>::from_persisted(CertifiedBlockHeader::new(header, qc))
        };
        let below = certify(0, BlockHash::ZERO, 0, 0);
        let carrying = certify(1, below.header().hash(), anchor, 0);
        let child = certify(2, carrying.header().hash(), anchor, signed);
        [below, carrying, child]
    }

    /// Whether the chain `held` bears out `entry`, block 1 carrying it.
    fn borne_out(entry: &UnsettledTx, held: &[Verified<CertifiedBlockHeader>]) -> Option<bool> {
        bears_out_commit(
            entry,
            |height, _| (height == BlockHeight::new(1)).then_some(true),
            |height| held.get(usize::try_from(height.inner()).ok()?).cloned(),
        )
    }

    /// A name pricing its commit in a window the chain does not fix for
    /// it is refused, however exactly its figures restate there: the
    /// window is the proposer's to choose otherwise, and the burn with it.
    #[test]
    fn a_name_stating_another_window_than_its_commit_ran_under_is_refused() {
        let chain = committed_chain(600, 0);

        assert_eq!(borne_out(&named_at(0, 600), &chain), Some(true));
        assert_eq!(
            borne_out(&named_at(1, 600), &chain),
            Some(false),
            "a dearer window"
        );
        let later = committed_chain(1_600, 1);
        assert_eq!(
            borne_out(&named_at(0, 1_600), &later),
            Some(false),
            "a cheaper window"
        );
        assert_eq!(
            borne_out(&named_at(0, 1_600), &chain),
            Some(false),
            "another anchor"
        );
    }

    /// A child that does not pin a QC over the carrying block fixes
    /// nothing, and a missing one leaves the name unanswered.
    #[test]
    fn a_committee_epoch_is_read_only_off_the_carrying_blocks_child() {
        let [below, carrying, _] = committed_chain(600, 0);
        let [_, _, unlinked] = committed_chain(700, 0);

        assert_eq!(
            borne_out(&named_at(0, 600), &[below, carrying.clone(), unlinked]),
            Some(false)
        );
        assert_eq!(
            bears_out_commit(
                &named_at(0, 600),
                |_, _| Some(true),
                |height| (height == BlockHeight::new(1)).then(|| carrying.clone()),
            ),
            None
        );
    }

    /// A record naming a transaction a halt recovery's crossing block
    /// committed restates exactly at the window the block's QC signed,
    /// the one the fresh committee was seated in, and is refused stating
    /// the window its committee anchor dates, figures and all.
    ///
    /// The carrying block is anchored in epoch 2, below the bridge at 21,
    /// and its child pins a QC its quorum signed under 21.
    #[test]
    fn a_record_named_from_a_bridged_commit_restates_exactly() {
        install_stub_protocol_statics();
        let tx = Verified::<Transaction>::from_persisted(stub_transaction(
            test_principal(1),
            &[test_prefix(1)],
            1_000_000,
            TimestampRange::new(
                WeightedTimestamp::ZERO,
                WeightedTimestamp::from_millis(60_000),
            ),
        ));
        let mut beacon = Folded::to(&[(2, 1), (21, 1)]);
        let dear = Arc::make_mut(
            beacon
                .0
                .get_mut(&Epoch::new(21))
                .expect("the fixture folds 21"),
        );
        dear.prices = PriceTable {
            compute: 1_000 * PriceTable::GENESIS.compute,
            read_bytes: 1_000 * PriceTable::GENESIS.read_bytes,
            write_bytes: 1_000 * PriceTable::GENESIS.write_bytes,
            footprint: 1_000 * PriceTable::GENESIS.footprint,
            retention: 1_000 * PriceTable::GENESIS.retention,
        };
        let chain = committed_chain(2_500, 21);
        let named = |epoch: u64| {
            let at = beacon
                .get_state_by_epoch(Epoch::new(epoch))
                .expect("the fixture folds the epoch")
                .commit_window();
            let classified = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), &at.trie);
            UnsettledTx::for_transaction(
                &tx,
                CommittedAt {
                    height: BlockHeight::new(1),
                    anchor: WeightedTimestamp::from_millis(2_500),
                    committee_epoch: Epoch::new(epoch),
                },
                classified.local_price(&tx, ShardId::ROOT, &at.prices),
                &at.prices,
            )
        };
        let (bridged, raw) = (named(21), named(2));
        assert_ne!(
            (bridged.charged, bridged.charge),
            (raw.charged, raw.charge),
            "the two windows price the transaction differently"
        );
        let held = HashMap::from([(tx.hash(), tx.clone())]);
        let verdict = |entry: &UnsettledTx| {
            resolutions_of(
                vec![entry.clone()],
                &held,
                &beacon,
                ShardId::ROOT,
                |height, _| (height == BlockHeight::new(1)).then_some(true),
                |height| chain.get(usize::try_from(height.inner()).ok()?).cloned(),
            )
        };

        assert_eq!(verdict(&bridged), Resolutions::Exact);
        assert_eq!(verdict(&raw), Resolutions::Wrong(tx.hash()));
    }

    /// A record naming a member committed beneath the chain floor is
    /// judged from the rows the store's hold keeps there, and nothing
    /// else: the signed window restates exactly, and another is refused.
    #[test]
    fn a_record_naming_a_member_beneath_the_floor_restates_from_the_held_rows() {
        install_stub_protocol_statics();
        let tx = Verified::<Transaction>::from_persisted(stub_transaction(
            test_principal(1),
            &[test_prefix(1)],
            1_000_000,
            TimestampRange::new(
                WeightedTimestamp::ZERO,
                WeightedTimestamp::from_millis(60_000),
            ),
        ));
        let mut members = MemberIndex::empty(ShardId::ROOT);
        members.advance(&MemberInputs {
            height: BlockHeight::new(1),
            transactions: vec![(tx.hash(), Deadline::of_transaction(&tx))],
            terms: vec![stub_stated_terms(tx.hash(), 1)],
            ..MemberInputs::still(ShardId::ROOT)
        });
        let kept = ChainHold::of(&members);
        let collected: Vec<Option<Verified<CertifiedBlockHeader>>> = committed_chain(2_500, 21)
            .into_iter()
            .zip(0u64..)
            .map(|(header, height)| kept.keeps_row(BlockHeight::new(height)).then_some(header))
            .collect();
        assert!(
            collected[0].is_none(),
            "the fixture collects a row the hold does not keep"
        );

        let beacon = Folded::to(&[(2, 1), (21, 1)]);
        let named = |epoch: u64| {
            let at = beacon
                .get_state_by_epoch(Epoch::new(epoch))
                .expect("the fixture folds the epoch")
                .commit_window();
            let classified = Classified::freeze(tx.legs(), tx.fee_payer(), tx.accounts(), &at.trie);
            UnsettledTx::for_transaction(
                &tx,
                CommittedAt {
                    height: BlockHeight::new(1),
                    anchor: WeightedTimestamp::from_millis(2_500),
                    committee_epoch: Epoch::new(epoch),
                },
                classified.local_price(&tx, ShardId::ROOT, &at.prices),
                &at.prices,
            )
        };
        let held = HashMap::from([(tx.hash(), tx.clone())]);
        let verdict = |entry: &UnsettledTx| {
            resolutions_of(
                vec![entry.clone()],
                &held,
                &beacon,
                ShardId::ROOT,
                |height, _| (height == BlockHeight::new(1)).then_some(true),
                |height| {
                    collected
                        .get(usize::try_from(height.inner()).ok()?)
                        .cloned()
                        .flatten()
                },
            )
        };

        assert_eq!(verdict(&named(21)), Resolutions::Exact);
        assert_eq!(verdict(&named(2)), Resolutions::Wrong(tx.hash()));
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
            Epoch::GENESIS,
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
                committee_epoch: Epoch::GENESIS,
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
                committee_epoch: Epoch::GENESIS,
            },
            &net(),
        );

        // Vote 1's signature is replaced by a signature over a different block.
        let other_hash = BlockHash::from_raw(Hash::from_bytes(b"other"));
        let bad_vote = make_vote(&keys, 1, block_hash, height, round, 1000);
        let bad_signing_vote = make_vote(&keys, 1, other_hash, height, round, 1000);
        let (block_hash_v, sg, h, r, epoch, voter, _, ts) = bad_vote.into_parts();
        let bad_vote = BlockVote::from_parts(
            block_hash_v,
            sg,
            h,
            r,
            epoch,
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
            Epoch::GENESIS,
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
            Epoch::GENESIS,
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
            Epoch::GENESIS,
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
            Epoch::GENESIS,
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
            Epoch::GENESIS,
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
            Epoch::GENESIS,
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
            Epoch::GENESIS,
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

    /// A block carrying `txs` whose header commits them.
    fn block_carrying(txs: &[Verifiable<Transaction>]) -> Block {
        let draft = |header| Block::Live {
            header,
            transactions: Arc::new(
                Capped::new(txs.to_vec()).expect("a list written out in a test"),
            ),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            terms: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        let unrooted = draft(BlockHeader::new(BlockHeaderParts::default()));
        draft(BlockHeader::new(BlockHeaderParts {
            body_root: SectionRoots::of(&unrooted).root(),
            ..Default::default()
        }))
    }

    #[test]
    fn verify_body_root_accepts_matching_root_and_rejects_otherwise() {
        let block = block_carrying(&[]);
        let ctx = BodyRootContext {
            block: &block,
            validity_anchor: WeightedTimestamp::ZERO,
        };
        assert!(block.header().body_root().verify(&ctx).is_ok());
        assert!(matches!(
            BodyRoot::from_raw(Hash::from_bytes(b"wrong")).verify(&ctx),
            Err(BodyRootVerifyError::Mismatch { .. })
        ));
    }

    #[test]
    fn verify_body_root_rejects_expired_tx() {
        use std::time::Duration;

        let anchor = WeightedTimestamp::from_millis(100_000);
        // Range ends at 1_000ms — anchor at 100_000ms is well past
        // end_timestamp_exclusive, so the tx is expired.
        let expired_range = TimestampRange::new(
            WeightedTimestamp::ZERO,
            WeightedTimestamp::from_millis(1_000),
        );
        install_stub_protocol_statics();
        let expired = block_carrying(&[(Verifiable::from(stub_transaction(
            test_principal(1),
            &[test_prefix(1)],
            1_000,
            expired_range,
        )))]);
        let ctx = BodyRootContext {
            block: &expired,
            validity_anchor: anchor,
        };
        assert!(matches!(
            expired.header().body_root().verify(&ctx),
            Err(BodyRootVerifyError::ValidityWindowExpired { .. })
        ));

        // The anchor inside the range — verification passes.
        let valid_range = TimestampRange::new(anchor, anchor.plus(Duration::from_mins(1)));
        let valid = block_carrying(&[(Verifiable::from(stub_transaction(
            test_principal(2),
            &[test_prefix(2)],
            1_000,
            valid_range,
        )))]);
        let ctx = BodyRootContext {
            block: &valid,
            validity_anchor: anchor,
        };
        assert!(valid.header().body_root().verify(&ctx).is_ok());
    }

    #[test]
    fn verify_body_root_rejects_malformed_range() {
        use std::time::Duration;

        let anchor = WeightedTimestamp::from_millis(1_000);
        // Length over MAX_VALIDITY_RANGE.
        let too_wide = TimestampRange::new(
            WeightedTimestamp::ZERO,
            anchor.plus(Duration::from_mins(10)),
        );
        install_stub_protocol_statics();
        let block = block_carrying(&[(Verifiable::from(stub_transaction(
            test_principal(3),
            &[test_prefix(3)],
            1_000,
            too_wide,
        )))]);
        let ctx = BodyRootContext {
            block: &block,
            validity_anchor: anchor,
        };
        assert!(
            block.header().body_root().verify(&ctx).is_err(),
            "malformed range must reject even when the body root matches"
        );
    }

    fn remote_header(height: u64) -> CertifiedBlockHeader {
        use hyperscale_types::{AggregateSignature, SignerBitfield};

        let shard = ShardId::leaf(1, 1);
        let height = BlockHeight::new(height);
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: shard,
            height,
            ..Default::default()
        });
        let qc = QuorumCertificate::new(
            header.hash(),
            shard,
            height,
            BlockHash::ZERO,
            Round::INITIAL,
            Epoch::GENESIS,
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        );
        CertifiedBlockHeader::new(header, qc)
    }

    /// A forged certificate is the forwarder's to answer for, and a copy
    /// of it arriving later is refused on arrival.
    #[test]
    fn a_forged_header_rejects() {
        use hyperscale_network::deferred::{Deferred, Waiting};
        use hyperscale_types::QcVerifyError;

        let header = remote_header(7);
        let key = VerdictKey::from_digest(header.copy_digest());
        let mut waiting = Waiting::default();

        assert!(matches!(
            waiting.defer(&[key], "forged"),
            Deferred::Waits(_)
        ));
        let verdict = remote_header_verdict(&Err(CertifiedHeaderVerifyError::Qc(
            QcVerifyError::InvalidSignature,
        )));
        assert_eq!(
            waiting.settle(key, verdict),
            vec![("forged", Verdict::Reject)]
        );
        assert_eq!(
            waiting.defer(&[key], "copy"),
            Deferred::Settled("copy", Verdict::Reject)
        );
    }

    /// A network that drops everything it is handed.
    struct Silent;

    impl Network for Silent {
        fn broadcast_to_shard<M: GossipMessage + 'static>(&self, _: ShardId, _: &M) {}
        fn broadcast_global<M: GossipMessage + 'static>(&self, _: &M) {}
        fn register_gossip_handler<M: GossipMessage + 'static>(&self, _: impl GossipHandler<M>) {}
        fn register_host_gossip_handler<M: GossipMessage + 'static>(
            &self,
            _: impl Fn(M) + Send + Sync + 'static,
        ) {
        }
        fn register_request_handler<R: Request + Send + 'static>(
            &self,
            _: ShardId,
            _: impl RequestHandler<R>,
        ) where
            R::Response: Send + 'static,
        {
        }
        fn notify<M: NetworkMessage + 'static>(&self, _: &[ValidatorId], _: &M) {}
        fn register_notification_handler<M: NetworkMessage + Clone + 'static>(
            &self,
            _: impl NotificationHandler<M>,
        ) {
        }
        fn subscribe_shard(&self, _: ShardId) {}
        fn unsubscribe_shard(&self, _: ShardId) {}
        fn update_topology(&self, _: Arc<TopologySnapshot>) {}
        fn update_routing_committees(&self, _: Arc<RoutingCommittees>) {}
        fn request_from<R: Request + Clone + 'static>(
            &self,
            _: ShardId,
            _: Answerers,
            _: Option<ValidatorId>,
            _: R,
            _: Option<MessageClass>,
            _: Box<dyn FnOnce(Result<R::Response, RequestError>) -> ResponseVerdict + Send>,
        ) {
        }
    }

    /// The shard the judged blocks below are this replica's.
    const LOCAL: ShardId = ShardId::leaf(1, 0);
    /// The shard their transaction's payer is on.
    const PAYER_SHARD: ShardId = ShardId::leaf(1, 1);

    /// A block at height 1 over an empty store, carrying one transaction
    /// that reads a cell here for a payer on the other shard: what this
    /// shard owes the payer is the one part serving that cell.
    struct Judged {
        storage: Arc<SimShardStorage>,
        pending_chain: Arc<PendingChain<SimShardStorage>>,
        trie: ShardTrie,
        tx: Verifiable<Transaction>,
        /// The state root the block leaves, and the map that state gives.
        root: StateRoot,
        honest: ProvisionTxRootsMap,
        sweep_frontier: SweepFrontier,
    }

    impl Judged {
        fn new() -> Self {
            install_stub_protocol_statics();
            let trie = ShardTrie::uniform(1);
            let payer = PrincipalAddr::new([0x80; 31]);
            let held = PrincipalAddr::new([0x10; 31]);
            assert_eq!(trie.shard_for_prefix(held.address()), LOCAL);
            assert_eq!(trie.shard_for_prefix(payer.address()), PAYER_SHARD);
            let tx = Verifiable::from(stub_transaction_with_reads(
                payer,
                &[held.address()],
                &[payer.address()],
                1_000,
                TimestampRange::new(
                    WeightedTimestamp::ZERO,
                    WeightedTimestamp::from_millis(60_000),
                ),
            ));
            let storage = Arc::new(SimShardStorage::default());
            let pending_chain = Arc::new(PendingChain::new(
                Arc::clone(&storage),
                BlockHeight::GENESIS,
            ));
            let view = pending_chain.view_at(BlockHash::ZERO, BlockHeight::GENESIS);
            let (removals, sweep_frontier) = view
                .sweep_for_block(
                    BlockSweep::of_child(SweepFrontier::ZERO, false),
                    WeightedTimestamp::ZERO,
                )
                .expect("nothing is persisted");
            let anchored = view.snapshot();
            let (root, jmt_snapshot, _) = view.base().prepare_block_commit(
                ParentAnchor {
                    state_root: view.base().state_root(),
                    height: BlockHeight::GENESIS,
                    state: &anchored,
                    pending: view.pending_snapshots(),
                    base_reads: None,
                },
                &[],
                ChainWrites {
                    creations: &[],
                    removals: &removals,
                    sweep_frontier,
                    frontier: &FrontierInputs::still(LOCAL),
                    state_claims: &[],
                    members: &MemberInputs::still(LOCAL),
                },
                BlockHeight::new(1),
            );
            let honest = provision_tx_roots(
                &PreparedBlockView {
                    parent: &anchored,
                    block: &jmt_snapshot,
                },
                &trie,
                LOCAL,
                WeightedTimestamp::ZERO,
                std::slice::from_ref(&tx),
            )
            .expect("the transaction is derived");
            assert!(honest.contains_key(&PAYER_SHARD));
            Self {
                storage,
                pending_chain,
                trie,
                tx,
                root,
                honest,
                sweep_frontier,
            }
        }

        /// The judgement a voter holds the block to, its header claiming
        /// `claimed`.
        fn judgement(&self, claimed: ProvisionTxRootsMap) -> ParentJudgement {
            ParentJudgement {
                fence: ReadFence::default(),
                coasting: false,
                provisions: ProvisionJudgement {
                    claimed,
                    trie: self.trie.clone(),
                },
            }
        }

        /// Run the state-root check of the block carrying `tx`, judged by
        /// `judgement`: its outcome, and whether its tree was seated.
        fn check(
            &self,
            tx: Verifiable<Transaction>,
            judgement: Option<ParentJudgement>,
        ) -> (CheckOutcome, bool) {
            let check = StateRootCheck {
                block_hash: BlockHash::from_raw(Hash::from_bytes(b"judged")),
                transactions: Arc::new(Capped::from_array([tx])),
                parent_block_hash: BlockHash::ZERO,
                parent_state_root: self.storage.state_root(),
                parent_block_height: BlockHeight::GENESIS,
                expected_root: self.root,
                finalizations: Vec::new(),
                creations: Vec::new(),
                block_height: BlockHeight::new(1),
                claimed_split_child_roots: None,
                split_child_roots_required: false,
                terminal_settled_txs_required: false,
                claimed_terminal_settled_txs: None,
                parent_weighted_timestamp: WeightedTimestamp::ZERO,
                settled_txs_window_floor: None,
                parent_sweep_frontier: SweepFrontier::ZERO,
                claimed_sweep_frontier: self.sweep_frontier,
                frontier: FrontierInputs::still(LOCAL),
                members: MemberInputs::still(LOCAL),
                parent_judgement: judgement,
                state_claims: Vec::new(),
            };
            state_root_verdict(&self.storage, &self.pending_chain, check)
        }
    }

    /// Run `check` through the state-root handler of a `LOCAL` replica
    /// over `storage` and `pending_chain`: its outcome, and whether its
    /// tree was seated.
    fn state_root_verdict(
        storage: &Arc<SimShardStorage>,
        pending_chain: &Arc<PendingChain<SimShardStorage>>,
        check: StateRootCheck,
    ) -> (CheckOutcome, bool) {
        let reported: Arc<Mutex<Vec<ProtocolEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&reported);
        let seated = Mutex::new(0usize);
        let commit_prepared = |_: PreparedBlock| {
            *seated.lock().expect("seated lock") += 1;
        };
        let executor = Executor::new(ExecutionMode::Serial);
        let snapshot = TestCommittee::new(4, 7).topology_snapshot(2);
        let tick_chain = Arc::new(TickChain::new(Arc::clone(storage)));
        let ctx = ActionContext {
            executor: &executor,
            topology_snapshot: &snapshot,
            signing: None,
            shard: LOCAL,
            pending_chain,
            tick_chain: &tick_chain,
            vote_registers: storage.as_ref(),
            beacon_chain: &SimBeaconStorage::new(),
            network: &Arc::new(Silent),
            verifier: &BlsVerifier,
            notify: Arc::new(move |event| sink.lock().expect("reported lock").push(event)),
            commit_prepared: &commit_prepared,
            par: Parallelism::Sequential,
        };
        handle_action(ConsensusAction::VerifyStateRoot(Box::new(check)), &ctx);
        let reported = std::mem::take(&mut *reported.lock().expect("reported lock"));
        let [
            ProtocolEvent::BlockCheckCompleted {
                kind: VerificationKind::StateRoot,
                outcome,
                ..
            },
        ] = &reported[..]
        else {
            panic!("one state-root verdict: {reported:?}")
        };
        let seated = *seated.lock().expect("seated lock") > 0;
        (outcome.clone(), seated)
    }

    /// The map a voter computes over the state an honest block leaves is
    /// the proposer's, and the block's state root checks out and seats.
    #[test]
    fn an_honest_provision_map_is_the_voters_own() {
        let block = Judged::new();
        let (outcome, seated) = block.check(
            block.tx.clone(),
            Some(block.judgement(block.honest.clone())),
        );
        assert!(matches!(outcome, CheckOutcome::Checked { .. }));
        assert!(seated);
    }

    /// A header whose root for the payer shard commits the transaction's
    /// part stripped of its cell, or any root but the one the served
    /// keys give, refuses the state root and seats no tree.
    #[test]
    fn a_map_over_a_stripped_part_refuses_the_state_root() {
        let block = Judged::new();
        let stripped = ProvisionTxRootsMap::new(BTreeMap::from([(
            PAYER_SHARD,
            ProvisionTxRoot::over(&[provision_leaf(
                block.tx.hash(),
                WeightedTimestamp::ZERO,
                served_digest(std::iter::empty()),
            )]),
        )]))
        .expect("one target");
        assert_ne!(stripped, block.honest);
        let (outcome, seated) = block.check(block.tx.clone(), Some(block.judgement(stripped)));
        assert_eq!(outcome, CheckOutcome::Refused);
        assert!(!seated);
    }

    /// A header claiming no provision roots for a block that owes the
    /// payer shard a part is refused: an empty claim is compared like any
    /// other.
    #[test]
    fn an_empty_claim_over_an_owed_part_refuses_the_state_root() {
        let block = Judged::new();
        let (outcome, seated) = block.check(
            block.tx.clone(),
            Some(block.judgement(ProvisionTxRootsMap::default())),
        );
        assert_eq!(outcome, CheckOutcome::Refused);
        assert!(!seated);
    }

    /// The block's transaction as a node whose derivation refused it
    /// holds it: its declaration read, its routing not.
    fn underived(block: &Judged) -> Verifiable<Transaction> {
        let tx = Transaction::new(block.tx.as_unverified().body().clone());
        assert!(tx.try_declared(&StubVmStatics).is_ok());
        assert!(!tx.is_routed());
        Verifiable::from(tx)
    }

    /// A judged block carrying a transaction this node has not derived
    /// has no map to compare, and is refused rather than passed or left
    /// unanswered: even under an empty claim, which a map that skipped
    /// the transaction would match.
    #[test]
    fn an_unrouted_transaction_under_a_judgement_is_refused() {
        let block = Judged::new();
        let tx = underived(&block);
        let state = block
            .pending_chain
            .view_at(BlockHash::ZERO, BlockHeight::GENESIS);
        assert_eq!(
            provision_tx_roots(
                &state.snapshot(),
                &block.trie,
                LOCAL,
                WeightedTimestamp::ZERO,
                std::slice::from_ref(&tx)
            ),
            Err(Unrouted { tx_hash: tx.hash() }),
        );
        let (outcome, seated) =
            block.check(tx, Some(block.judgement(ProvisionTxRootsMap::default())));
        assert_eq!(outcome, CheckOutcome::Refused);
        assert!(!seated);
    }

    /// A certified block's state root is checked with no judgement: one
    /// carrying a cross-shard transaction this node has not derived
    /// seats its tree, its map never read.
    #[test]
    fn a_synced_block_with_an_underived_transaction_seats_its_tree() {
        let block = Judged::new();
        let (outcome, seated) = block.check(underived(&block), None);
        assert!(matches!(outcome, CheckOutcome::Checked { .. }));
        assert!(seated);
    }

    /// The collection the ranged reader's interval sits in.
    const COLLECTION: CollectionId = CollectionId([0xEE; 16]);

    /// Entry changes in [`COLLECTION`] under `owner`: `(order, value)`, a
    /// `None` value deleting.
    fn entry_changes(owner: Address, changes: &[(u128, Option<u8>)]) -> SettledWrites {
        SettledWrites::from_parts(
            BTreeMap::new(),
            changes
                .iter()
                .map(|(order, value)| {
                    (
                        EntryKey {
                            owner,
                            collection: COLLECTION,
                            order: *order,
                        },
                        value.map(|byte| vec![byte]),
                    )
                })
                .collect(),
        )
    }

    /// A `LOCAL` tick at `height` settling `writes`.
    fn settling(height: BlockHeight, writes: SettledWrites) -> Verifiable<Finalization> {
        let receipt = StoredReceipt::new(
            TxHash::from(Hash::from_bytes(&height.inner().to_le_bytes())),
            Arc::new(ConsensusReceipt::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
                writes: writes.into(),
                beacon_witness_events: Capped::empty(),
                events: Capped::empty(),
            }),
        );
        Verifiable::from(Finalization::new(
            TickId::new(LOCAL, height),
            TickHalf::Determined,
            Some(placeholder_local_ec(LOCAL, height)),
            Capped::from_array([receipt]),
        ))
    }

    /// The parent a proposal below builds on.
    struct Parent {
        hash: BlockHash,
        height: BlockHeight,
        state_root: StateRoot,
        sweep_frontier: SweepFrontier,
    }

    /// The block `LOCAL`'s proposer builds on `parent` over `chain`,
    /// carrying `transactions` and `finalization`.
    fn proposed(
        chain: &Arc<PendingChain<SimShardStorage>>,
        committee: &TopologySnapshot,
        parent: &Parent,
        transactions: &[Verified<Transaction>],
        finalization: Verifiable<Finalization>,
    ) -> ProposalResult {
        let height = parent.height.next();
        let parent_qc = QuorumCertificate::new(
            parent.hash,
            LOCAL,
            parent.height,
            BlockHash::ZERO,
            Round::new(parent.height.inner()),
            Epoch::GENESIS,
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        );
        build_proposal(
            &chain.view_at(parent.hash, parent.height),
            ValidatorId::new(0),
            height,
            Round::new(height.inner()),
            parent.hash,
            parent_qc,
            ProposerTimestamp::from_millis(0),
            false,
            parent.state_root,
            parent.height,
            &Capped::new(transactions.to_vec()).expect("a list written out in a test"),
            Capped::from_array([finalization]),
            LOCAL,
            WeightedTimestamp::ZERO,
            committee,
            Capped::empty(),
            Capped::empty(),
            Capped::empty(),
            BlockHeight::GENESIS,
            BlockSweep::of_child(parent.sweep_frontier, false),
            None,
            SubstateClaim::default(),
            Capped::empty(),
            None,
            VrfProof::ZERO,
            &[],
            BeaconWitnessLeafCount::ZERO,
            RevealChain::ZERO,
            Epoch::GENESIS,
            Epoch::GENESIS,
            false,
            None,
            &FrontierInputs::still(LOCAL),
            &ManifestInputs::default(),
            None,
            Some(&StandingAnswers::default()),
        )
        .expect("nothing is persisted past the parent")
    }

    /// A proposal whose cross-shard transaction reads a declared interval
    /// both it and its pipelined, unpersisted parent write into commits
    /// the entries the interval holds after the block, read through the
    /// persisted store, the parent's overlay and the block's own writes;
    /// and a voter judging the header recomputes the same map and seats
    /// the block.
    #[test]
    fn a_range_read_over_a_pipelined_parent_is_the_voters_own() {
        install_stub_protocol_statics();
        let committee = TestCommittee::new(4, 7).topology_snapshot(2);
        let trie = committee.shard_trie().clone();
        assert_eq!(trie, ShardTrie::uniform(1));
        let payer = PrincipalAddr::new([0x80; 31]);
        let held = PrincipalAddr::new([0x10; 31]).address();
        assert_eq!(trie.shard_for_prefix(held), LOCAL);
        assert_eq!(trie.shard_for_prefix(payer.address()), PAYER_SHARD);
        let interval = DeclaredRange {
            owner: held,
            collection: COLLECTION,
            lo: 0,
            hi: 20,
            cap: 8,
        };
        let stub = stub_transaction_with_reads(
            payer,
            &[held],
            &[payer.address()],
            1_000,
            TimestampRange::new(
                WeightedTimestamp::ZERO,
                WeightedTimestamp::from_millis(60_000),
            ),
        );
        let mut routing = stub.routing().clone();
        routing.provision_keys.push(DeclaredKey::Range(interval));
        let tx = stub.with_routing(&StubVmStatics, routing);

        // The persisted store holds orders 0, 5 and 30; the parent adds
        // 1 and 3 and deletes 5; the block adds 2 and 25 and deletes 3.
        // The interval holds 0, 1 and 2 after the block.
        let storage = Arc::new(SimShardStorage::default());
        commit_writes(
            &*storage,
            &entry_changes(held, &[(0, Some(1)), (5, Some(1)), (30, Some(1))]),
        );
        let (base_height, Some(base_hash)) = storage.committed_head() else {
            panic!("the store holds a committed block")
        };
        let chain = Arc::new(PendingChain::new(
            Arc::clone(&storage),
            BlockHeight::GENESIS,
        ));
        let base = Parent {
            hash: base_hash,
            height: base_height,
            state_root: storage.state_root(),
            sweep_frontier: SweepFrontier::ZERO,
        };
        let parent_built = proposed(
            &chain,
            &committee,
            &base,
            &[],
            settling(
                base_height.next(),
                entry_changes(held, &[(1, Some(2)), (3, Some(2)), (5, None)]),
            ),
        );
        let parent_header = parent_built.block.header();
        chain.insert(
            parent_built.block_hash,
            ChainEntry {
                parent_block_hash: base_hash,
                height: parent_header.height(),
                settled_txs: Vec::new(),
                jmt_snapshot: Arc::clone(&parent_built.jmt_snapshot),
                certified_block: None,
            },
        );
        assert_eq!(storage.jmt_height(), base_height, "the parent is pending");
        let parent = Parent {
            hash: parent_built.block_hash,
            height: parent_header.height(),
            state_root: parent_header.state_root(),
            sweep_frontier: parent_header.sweep_frontier(),
        };
        let built = proposed(
            &chain,
            &committee,
            &parent,
            &[Verified::new_unchecked_for_test(tx.clone())],
            settling(
                parent.height.next(),
                entry_changes(held, &[(2, Some(3)), (3, None), (25, Some(3))]),
            ),
        );
        assert_eq!(built.block.transactions().len(), 1, "the reader is carried");
        assert_eq!(
            built.block.header().provision_tx_roots(),
            &owed_over(tx.hash(), held, &[0, 1, 2]),
            "the proposer commits what the interval holds after the block",
        );

        let (outcome, seated) =
            state_root_verdict(&storage, &chain, judged_check(&built, &parent, trie));
        assert!(
            matches!(outcome, CheckOutcome::Checked { .. }),
            "the voter's map is the proposer's: {outcome:?}",
        );
        assert!(seated);
    }

    /// The map a block owes [`PAYER_SHARD`] for one transaction `tx_hash`
    /// serving `held`'s stub cell and the [`COLLECTION`] entries at
    /// `orders`.
    fn owed_over(tx_hash: TxHash, held: Address, orders: &[u128]) -> ProvisionTxRootsMap {
        let mut served: Vec<SubstateKey> = orders
            .iter()
            .map(|&order| {
                entry_leaf_key(
                    &ProtocolHasher,
                    EntryKey {
                        owner: held,
                        collection: COLLECTION,
                        order,
                    },
                )
            })
            .collect();
        served.push(SubstateKey {
            owner: held,
            local: LocalKey([0; 16]),
        });
        served.sort_unstable();
        ProvisionTxRootsMap::new(BTreeMap::from([(
            PAYER_SHARD,
            ProvisionTxRoot::over(&[provision_leaf(
                tx_hash,
                WeightedTimestamp::ZERO,
                served_digest(served.into_iter()),
            )]),
        )]))
        .expect("one target")
    }

    /// The state-root check a voter runs on `built` over `parent`, judged
    /// under `trie` against the map its header claims: every input read
    /// off the block as the coordinator reads it.
    fn judged_check(built: &ProposalResult, parent: &Parent, trie: ShardTrie) -> StateRootCheck {
        let block = &built.block;
        let frontier = FrontierInputs::still(LOCAL);
        StateRootCheck {
            block_hash: built.block_hash,
            transactions: Arc::clone(block.transactions()),
            parent_block_hash: parent.hash,
            parent_state_root: parent.state_root,
            parent_block_height: parent.height,
            expected_root: block.header().state_root(),
            finalizations: block.certificates().iter().cloned().collect(),
            creations: committed_here(
                LOCAL,
                WeightedTimestamp::ZERO,
                block.transactions().iter().map(Verifiable::as_unverified),
            ),
            block_height: block.height(),
            claimed_split_child_roots: None,
            split_child_roots_required: false,
            terminal_settled_txs_required: false,
            claimed_terminal_settled_txs: None,
            parent_weighted_timestamp: WeightedTimestamp::ZERO,
            settled_txs_window_floor: None,
            parent_sweep_frontier: parent.sweep_frontier,
            claimed_sweep_frontier: block.header().sweep_frontier(),
            members: MemberInputs::of(block, frontier.windows),
            frontier,
            parent_judgement: Some(ParentJudgement {
                fence: ReadFence::default(),
                coasting: false,
                provisions: ProvisionJudgement {
                    claimed: block.header().provision_tx_roots().clone(),
                    trie,
                },
            }),
            state_claims: block.state_claims().to_vec(),
        }
    }
}
