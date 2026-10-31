//! Shard consensus work a shard loop delegates: QC build and verify,
//! block checks, proposal building, and header, vote and timeout
//! sign-and-broadcast. Run by `hyperscale_shard::action_handlers`.

use std::sync::Arc;

use hyperscale_dispatch::DispatchPool;
use hyperscale_engine::tick_select::ManifestInputs;
use hyperscale_storage::BlockSweep;
use hyperscale_types::{
    AbandonmentRecord, Anchor, BeaconWitnessLeafCount, BeaconWitnessRoot, Block, BlockHash,
    BlockHeader, BlockHeight, BlockManifest, BlockVote, CertifiedBlockHeader, ConsensusPublicKey,
    Epoch, EpochWindows, Finalization, FrontierInputs, Hash, HeaderSource, ProposerTimestamp,
    ProvisionTxRootsMap, Provisions, QuorumCertificate, ReadFence, ReadySignal, ReshapeKind,
    ReshapeThresholds, ReshapeTrigger, ResolvedCommittee, RevealChain, Round, Settling,
    ShardForkProof, ShardId, ShardLoad, SharedTransactions, SharedWitnessSources, StandingAnswers,
    StateClaim, StateRoot, SubstateClaim, Timeout, TimeoutCertificate, TopologySnapshot,
    Transaction, TxHash, UnsettledTx, ValidatorId, Verifiable, Verified, VoteCount, VotePosition,
    WeightedTimestamp,
};
use hyperscale_vm_effects::CrossingId;

use super::{Delegated, HeaderCommittee, QcSubject, StateRootCheck};

/// Shard consensus work, run on the consensus dispatch pool.
#[derive(Debug, Clone, strum::IntoStaticStr)]
#[allow(clippy::large_enum_variant)] // boxing every large variant adds allocations on the hot dispatch path
pub enum ConsensusAction {
    /// Sign and broadcast a block header (proposal) to the local shard.
    ///
    /// The `io_loop` signs the header on the consensus crypto pool before sending.
    BroadcastBlockHeader {
        /// Block header to sign and broadcast.
        header: Box<BlockHeader>,
        /// Manifest listing the block's tx / cert / provision hashes.
        manifest: Box<BlockManifest>,
        /// The shard's committee to send the header to, less the proposer:
        /// the head's, or the terminal-clamped committee that certifies the
        /// block while a splitting parent the head no longer carries has yet
        /// to commit its terminal.
        recipients: Vec<ValidatorId>,
        /// The signing position the proposer's self-vote reaches: its round
        /// spent and its lock at the block's parent QC. The runner persists
        /// it durably before the header signature exists, so a restarted
        /// proposer never signs a second header at the round whether or not
        /// its self-vote was ever signed.
        position: VotePosition,
    },

    /// Sign and broadcast a block vote to the next proposer(s).
    ///
    /// The `io_loop` signs the vote on the consensus crypto pool, then
    /// broadcasts to the next proposer and feeds the signed vote back
    /// to the state machine for local `VoteSet` tracking.
    SignAndBroadcastBlockVote {
        /// Block being voted on.
        block_hash: BlockHash,
        /// Parent of the voted block (from its header), bound into the vote signature.
        parent_block_hash: BlockHash,
        /// Block height.
        height: BlockHeight,
        /// Round at which the vote is being cast.
        round: Round,
        /// Voter's local timestamp at vote time. Aggregated stake-weighted
        /// across votes into the QC's `weighted_timestamp` — the BFT clock.
        timestamp: ProposerTimestamp,
        /// Local-shard validators eligible to propose the next block; they
        /// need this vote to assemble the QC.
        next_proposers: Vec<ValidatorId>,
        /// The signing position this vote ratchets — the registers and
        /// the uncommitted chain justifying them. The runner persists it
        /// durably before the signature leaves the process, so a
        /// crash-restarted validator can never re-vote this round, and
        /// comes back able to extend the certificate it locked on.
        position: VotePosition,
        /// The attached signer casting the vote.
        signer: ValidatorId,
    },

    /// Sign and broadcast a timeout to the local-shard committee.
    ///
    /// Emitted when the round timer fires instead of advancing locally. The
    /// `io_loop` signs the timeout on the consensus crypto pool, broadcasts it
    /// to `recipients`, and feeds the signed timeout back to the state machine
    /// for the local `TimeoutKeeper`. On `2f+1` timeouts the committee adopts
    /// the maximum `high_qc` and advances the round together.
    SignAndBroadcastTimeout {
        /// Round being abandoned.
        round: Round,
        /// The signer's highest certified block — carried so the next leader
        /// can adopt and extend the quorum-max QC. Self-authenticating.
        high_qc: QuorumCertificate,
        /// The signer's highest timeout certificate, carried so a replica
        /// behind it syncs its view. Self-authenticating.
        high_tc: Option<TimeoutCertificate>,
        /// Local-shard committee members who tally timeouts for this round.
        recipients: Vec<ValidatorId>,
        /// The signing position this timeout ratchets. The runner
        /// persists it durably before the signature leaves the process,
        /// so a crash-restarted validator can never vote a round it
        /// already abandoned.
        position: VotePosition,
        /// The attached signer timing the round out.
        signer: ValidatorId,
    },

    /// Sign and send a just-formed QC for a block this validator proposed
    /// to the local-shard committee, so members that received no votes
    /// learn it before their round timers fire.
    SignAndBroadcastQcAnnouncement {
        /// The QC formed for our block.
        qc: QuorumCertificate,
        /// Local-shard committee members.
        recipients: Vec<ValidatorId>,
        /// The attached signer announcing: the block's proposer, or the
        /// replica's designated sender.
        signer: ValidatorId,
    },

    /// Sign and broadcast a "ready on shard" signal to the local committee.
    ///
    /// Emitted when block sync reaches the tip while the local validator is
    /// a committee member still outside the consensus subset. The `io_loop`
    /// signs the canonical ready-signal message and notifies `recipients`;
    /// their pools hold the signal until a proposer drains it into a block
    /// manifest and the beacon's `Ready` witness flips `ready: true`.
    SignAndBroadcastReadySignal {
        /// Shard whose synced state the signal attests readiness for — the
        /// emitting member's own shard. Bound into the signed message.
        shard: ShardId,
        /// First weighted timestamp at which the signal is eligible for
        /// inclusion.
        wt_window_start: WeightedTimestamp,
        /// Last eligible inclusion weighted timestamp; the signer re-emits
        /// if the window passes uncollected.
        wt_window_end: WeightedTimestamp,
        /// Local-shard committee members (full membership view) beyond
        /// the signers of the emitting replica: the signal goes to them
        /// over the network.
        recipients: Vec<ValidatorId>,
        /// Whether another signer of the emitting replica is a committee
        /// member: the signal is fed back to the replica's pool rather
        /// than sent.
        local_recipient: bool,
        /// The attached signer signalling its readiness.
        signer: ValidatorId,
    },

    /// Sign and broadcast a committed block header globally to all shards.
    ///
    /// Used for the light-client provisions pattern. When a block commits,
    /// this broadcasts the header + QC so remote shards can verify state roots.
    /// The `io_loop` signs on the consensus crypto pool before sending.
    BroadcastCertifiedBlockHeader {
        /// Header + QC bundle to broadcast globally. The proposer builds it
        /// from its locally-verified [`Verified<CertifiedBlock>`], so the
        /// predicate holds at the emit site; the gossip wrapper preserves
        /// the marker across in-process local dispatch.
        certified_header: Verified<CertifiedBlockHeader>,
    },

    /// Broadcast a shard fork proof globally on first local verification.
    ///
    /// The proof self-authenticates (it carries the accused committee's own
    /// QCs), so no signing is needed — the handler wraps it in a
    /// `ShardForkProofGossip` and gossips it; every recipient re-verifies
    /// locally. Broadcast once per forked shard so the network converges on
    /// the fence.
    BroadcastShardForkProof {
        /// The self-proving fork evidence to gossip.
        proof: Box<ShardForkProof>,
    },

    /// Verify block votes and build a Quorum Certificate if quorum is reached.
    ///
    /// This combines vote verification and QC building into a single operation:
    /// 1. Batch-verifies all vote signatures through the scheme verifier
    /// 2. If enough valid votes for quorum: aggregates signatures into a QC
    /// 3. If not enough valid votes: returns the verified votes so state machine
    ///    can wait for more votes
    ///
    /// This avoids wasting CPU on votes that will never be used (e.g., when a
    /// block never reaches quorum due to view change or leader failure).
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::QuorumCertificateResult` when complete.
    VerifyAndBuildQuorumCertificate {
        /// Block hash the QC would be for.
        block_hash: BlockHash,
        /// Shard group this QC belongs to.
        shard_id: ShardId,
        /// Block height.
        height: BlockHeight,
        /// Round number.
        round: Round,
        /// Parent block hash (from the block's header).
        parent_block_hash: BlockHash,
        /// Parent QC's `weighted_timestamp` — monotonicity floor applied to
        /// every vote timestamp during the (uniform) weighted-time aggregation.
        /// Without this, slow-clocked or Byzantine voters can drag the
        /// aggregated `weighted_timestamp` back below the parent's, breaking
        /// deadline pruning and validity-window monotonicity.
        parent_weighted_timestamp: WeightedTimestamp,
        /// Votes to verify and potentially aggregate.
        /// Each tuple is (`committee_index`, vote, `public_key`).
        votes_to_verify: Vec<(usize, BlockVote, ConsensusPublicKey)>,
        /// Already-verified votes (e.g., our own vote).
        /// Each tuple is (`committee_index`, vote).
        verified_votes: Vec<(usize, Verified<BlockVote>)>,
        /// Total votes in the committee (the quorum denominator).
        total_votes: VoteCount,
        /// The binding of the block's vote set the batch was taken under,
        /// echoed by the result so a batch that outlives its binding forms
        /// no QC.
        binding: u64,
    },

    /// Verify a Quorum Certificate's aggregated signature **and**
    /// confirm the signers carry quorum-meeting voting power. Both checks
    /// together constitute the [`Verified<QuorumCertificate>`] predicate.
    ///
    /// CRITICAL for shard consensus safety: a Byzantine proposer could otherwise
    /// include a fake QC with invalid signatures or under-quorum signers.
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `ProtocolEvent::QcSignatureVerified` when complete.
    VerifyQcSignature {
        /// The QC to verify (carries `shard_id` for self-contained
        /// verification). When the wrapper is already
        /// `Verifiable::Verified` — e.g. the caller hit a cached
        /// verified value — the handler short-circuits and emits the
        /// verified result without rerunning signature aggregation.
        qc: Verifiable<QuorumCertificate>,
        /// Public keys of the signers (pre-resolved by state machine from QC's signer bitfield).
        public_keys: Vec<ConsensusPublicKey>,
        /// Quorum threshold for the QC's shard.
        quorum_threshold: VoteCount,
        /// What the verification answers, echoed back on the result.
        subject: QcSubject,
    },

    /// Verify a wire timeout's signature share off-thread, then tally it.
    ///
    /// Emitted by the state machine after the cheap committee/shard screen
    /// passes. The consensus crypto pool checks the share against
    /// `voter_public_key` and feeds the result back as
    /// `ProtocolEvent::VerifiedTimeoutReceived`, which the `TimeoutKeeper`
    /// tallies — keeping per-timeout pairing checks off the shard loop thread
    /// during a view change, as the vote path's aggregate verification does.
    VerifyTimeout {
        /// The unverified timeout share to check.
        timeout: Timeout,
        /// The voter's public key, pre-resolved by the state machine from
        /// the topology (where the committee-membership gate also runs).
        voter_public_key: ConsensusPublicKey,
    },

    /// Verify a remote block header's QC for cross-shard deferral validation.
    ///
    /// Verifies the aggregated signature on the QC, checks voting power meets
    /// quorum, and confirms `block_hash` matches `hash(header)`.
    ///
    /// Delegated to `ConsensusCrypto` thread pool.
    /// Returns `ProtocolEvent::RemoteHeaderQcVerified` when complete.
    VerifyRemoteHeaderQc {
        /// The remote header to verify.
        certified_header: CertifiedBlockHeader,
        /// Source of the candidate header; threaded back through the
        /// callback so the coordinator can remove the failed candidate
        /// from its pending map on error.
        source: HeaderSource,
        /// Public keys for the remote shard's committee (from topology).
        committee_public_keys: Vec<ConsensusPublicKey>,
        /// Quorum threshold for the remote shard.
        quorum_threshold: VoteCount,
        /// Whether a held parent named the committee. A QC that fails
        /// under a guessed one is not held against the copy's sender.
        committee: HeaderCommittee,
    },

    /// Verify an assembled shard fork proof off the state-machine thread.
    ///
    /// A fork proof costs up to four QC verifications; a flood of garbage
    /// proofs would stall the state machine if run inline. The dispatcher
    /// (which holds the topology schedule) resolves each QC's committee via
    /// [`ShardForkProof::resolve_committees`] and passes them here so the
    /// handler runs pure signature verification — the same emitter-resolves shape as
    /// [`crate::BeaconAction::VerifyBeaconBlock`].
    ///
    /// Delegated to the consensus crypto pool. Returns
    /// `ProtocolEvent::ShardForkProofVerified`.
    VerifyShardForkProof {
        /// The proof to verify.
        proof: Box<ShardForkProof>,
        /// Committees resolved for the proof's QCs, positionally aligned to
        /// its canonical QC order.
        committees: Vec<ResolvedCommittee>,
    },

    /// Verify a block's state root against the JMT: apply the block's
    /// shard-local state changes and compare the resulting root against
    /// the header's `state_root`.
    ///
    /// The action handler walks the snapshot chain from `parent_block_hash`
    /// to build an overlay of uncommitted tree nodes, then calls
    /// `prepare_block_commit` which computes the JMT root and caches a
    /// `PreparedCommit` for efficient commit later.
    VerifyStateRoot(Box<StateRootCheck>),

    /// Verify a block's beacon-witness root + leaf count.
    ///
    /// Re-derives the new witness leaves from the same deterministic
    /// sources the proposer used — receipts (via `finalizations`), the
    /// missed-round walk over `(parent_round, round)` against
    /// `topology_snapshot`, and the block's carried `witness_sources` —
    /// then applies them against `parent_witness_leaves` (the accumulator
    /// state the parent block left behind) and compares the resulting
    /// `(root, leaf_count)` to the header's claim. A mismatch fails the
    /// check; honest validators reject the block.
    ///
    /// Pure CPU; no JMT dependency. Runs in parallel with the other
    /// per-root verifiers.
    VerifyBeaconWitnessRoot {
        /// Block whose beacon-witness root is being verified.
        block_hash: BlockHash,
        /// Expected accumulator root from the block header.
        expected_root: BeaconWitnessRoot,
        /// Expected accumulator leaf count from the block header.
        expected_leaf_count: BeaconWitnessLeafCount,
        /// The block header's claimed witness window base, checked
        /// against the schedule-resolved value for the block's window.
        claimed_base: BeaconWitnessLeafCount,
        /// Header's claimed reveal chain, recomputed from the parent's and
        /// this block's reveal output.
        claimed_reveal_chain: RevealChain,
        /// Reveal chain on the parent header.
        parent_reveal_chain: RevealChain,
        /// Anchor epoch of the parent header.
        parent_committee_anchor_epoch: Epoch,
        /// Anchor epoch of the block being verified.
        committee_anchor_epoch: Epoch,
        /// Absolute leaf index of `parent_witness_leaves[0]` — the
        /// committed accumulator's retained-window start.
        parent_leaves_start: BeaconWitnessLeafCount,
        /// Accumulator leaves at the parent block — the window the
        /// proposer appended onto. Captured by the coordinator from its
        /// committed accumulator plus any in-chain pending-block deltas.
        parent_witness_leaves: Vec<Hash>,
        /// Parent round; used with `round` to walk
        /// `(parent_round + 1 .. round)` for the `MissedProposal` channel.
        parent_round: Round,
        /// Block height (anchors `MissedProposal`'s `proposer_for` lookup).
        height: BlockHeight,
        /// Block round; the upper bound of the missed-round walk.
        round: Round,
        /// The block's carried witness sources. Every claim is
        /// re-verified inside the shared verifier before its leaf folds
        /// — equivocation evidence against each equivocator's registered
        /// key, the reshape assertion against the locally recomputed
        /// load predicate, the randomness reveal against the
        /// proposer's key — so an invalid entry fails the block.
        witness_sources: SharedWitnessSources,
        /// Committed substate byte total behind the parent block's
        /// post-state — the load the reshape predicate evaluates. `None`
        /// takes the predicate out of play (reshaping disabled, or the
        /// ancestry crosses a halt recovery's sync-admitted suffix); the
        /// recomputed assertion must then be absent.
        substate_bytes: Option<u64>,
        /// The header's own claim about that total, checked against it.
        claimed_substate_bytes: Option<u64>,
        /// What the block must assert of its shard's latched reshape: the
        /// kind and admission its committee window names the shard
        /// draining under, and whether the rows at its parent are quiet.
        /// `None` where no draining is named, or the parent lies in a
        /// recovery's suffix band.
        settling: Option<(ReshapeKind, Settling)>,
        /// Reshape thresholds in force for this network.
        thresholds: ReshapeThresholds,
        /// Finalizations whose receipts contribute receipt-sourced
        /// witness events.
        finalizations: Vec<Verifiable<Finalization>>,
        /// Topology snapshot for `proposer_for` lookups in the
        /// missed-round walk.
        topology_snapshot: TopologySnapshot,
    },

    /// Verify a block's body root and per-tx validity windows.
    ///
    /// Recomputes every section's root from `block`, combines them, and
    /// compares against the header's `body_root`; also checks that every
    /// tx's `validity_range` is well-formed and contains `validity_anchor`.
    /// Returns `ProtocolEvent::BlockCheckCompleted` for the body root; the
    /// verifier's error distinguishes a root mismatch from an out-of-window
    /// transaction.
    ///
    /// Pure CPU; no JMT dependency.
    VerifyBodyRoot {
        /// The block whose body root is being verified.
        block: Block,
        /// Parent QC's `weighted_timestamp` — the shard consensus-authenticated clock
        /// every honest validator agrees on for this block. The validity
        /// check is `start_inclusive <= anchor < end_exclusive`. The
        /// one-block lag (this block's own QC may carry a slightly later
        /// timestamp) is bounded by `MAX_VALIDITY_RANGE`.
        validity_anchor: WeightedTimestamp,
    },

    /// Verify a block's per-target-shard provisions commitments.
    ///
    /// Recomputes the per-target map from the block's transactions, its
    /// certificates and its crossing re-offers, and compares against the
    /// block header's `provision_tx_roots` by full-map equality. Catches
    /// tampering with which txs are claimed to target which shard.
    ///
    /// Pure CPU operation — verified in parallel with other root verifications.
    VerifyProvisionTxRoots {
        /// Block whose provision-tx roots are being verified.
        block_hash: BlockHash,
        /// Expected per-target roots from the block header.
        expected: ProvisionTxRootsMap,
        /// Transactions in the block.
        transactions: SharedTransactions,
        /// Topology snapshot used to route txs to target shards.
        topology_snapshot: TopologySnapshot,
    },

    /// Check the figures a block's abandonment records restate against
    /// the committed transactions they name.
    ///
    /// A record restates each name's deadline, reservation and charge so
    /// a replica whose replay never reached the transaction composes the
    /// same abort as one that held it; unchecked, that would let a
    /// proposer choose the vault and the amount an abort burns. Every
    /// figure is a function of the body, and the body is read off the
    /// store — where a validator that committed the transaction holds it
    /// at any distance — so the check needs no window of its own. A body
    /// the store never held answers `Unknown`, and the vote defers on it
    /// rather than accepting.
    /// Returns `ProtocolEvent::BlockCheckCompleted`.
    VerifyResolutions {
        /// Block whose resolutions are being checked.
        block_hash: BlockHash,
        /// Every name the block's records carry.
        entries: Vec<UnsettledTx>,
        /// The epoch grid, which places each name's stated commit anchor
        /// in the window that froze its figures. Carried rather than
        /// read off the store because it is a property of the chain
        /// config and not of any one window.
        windows: EpochWindows,
    },

    /// Build a complete block proposal.
    ///
    /// Computes the new state root from certificates, builds the complete block,
    /// and caches the `WriteBatch` for efficient commit later.
    ///
    /// Returns `ProtocolEvent::ProposalBuilt` with the complete block.
    ///
    /// This combines state root computation and block building into a single
    /// round-trip, enabling the proposer to use the fast commit path (1 fsync).
    BuildProposal {
        /// Local shard producing this proposal.
        shard_id: ShardId,
        /// The shard chain's [`cut`](hyperscale_types::ChainOrigin::cut):
        /// a transaction whose range opened before it is also judged by
        /// an inherited marker.
        chain_origin: WeightedTimestamp,
        /// Validator id of the proposer (this node).
        proposer: ValidatorId,
        /// Height of the new block.
        height: BlockHeight,
        /// Round at which the proposal is being made.
        round: Round,
        /// Parent block hash; the new block extends this.
        parent_block_hash: BlockHash,
        /// QC over the parent block (genesis QC for the first block).
        parent_qc: QuorumCertificate,
        /// Proposer-supplied timestamp on the new block header.
        timestamp: ProposerTimestamp,
        /// `true` if this is a fallback (empty) proposal during view changes.
        is_fallback: bool,
        /// Parent's state root (base for state root computation via overlay).
        parent_state_root: StateRoot,
        /// Height of the parent block (stable anchor for JMT computation).
        parent_block_height: BlockHeight,
        /// Transactions to include in the proposal.
        transactions: Vec<Verified<Transaction>>,
        /// Finalizations to include in the block (carries certs + receipts + ECs).
        finalizations: Vec<Verifiable<Finalization>>,
        /// Provisions from remote shards, included in this block.
        provisions: Vec<Verifiable<Provisions>>,
        /// What departed shards left unresolved of this chain's business
        /// — written down here while the settled sets they were read
        /// from can still be checked against.
        abandonment_records: Vec<AbandonmentRecord>,
        /// Proofs of counterparts' cells this proposer's fetches
        /// answered, for every replica to fold at commit.
        state_claims: Vec<StateClaim>,
        /// The block's parent as an anchor: the one anchor a crossing
        /// whose ends share this shard is read at.
        parent_anchor: Anchor,
        /// The crossings whose ends share this shard and whose
        /// settlement the mirrors say is due, for the handler to read
        /// at the parent and carry beside the claims.
        local_crossings: Vec<CrossingId>,
        /// The transactions whose member rows the handler may read
        /// absent at the parent and carry beside the claims: each
        /// issued an escrowed record the claims hold for a consumer
        /// here. It reads those a decline of the block it builds reads,
        /// the reading a decline is written on.
        rowless: Vec<TxHash>,
        /// Parent block's settlement frontier — the highest tick whose
        /// determined half has settled at or below it. The block advances
        /// it by the determined halves it carries, and may carry none
        /// below it.
        parent_settled_frontier: BlockHeight,
        /// The block's sweep: from where the parent's stopped, or held
        /// there for a coasting block.
        sweep: BlockSweep,
        /// Attested load on the parent's header — the running gas total
        /// this block advances by the gas its own certificates report.
        parent_load: Option<ShardLoad>,
        /// Committed substate byte total behind the parent's post-state —
        /// the level this block attests, resolved by the coordinator ahead
        /// of the build so the header and the reshape assertion it carries
        /// agree on one value — and the committed height it is counted
        /// from, if any. A `None` total takes the reshape predicate out of
        /// play, and the header states that absence rather than guessing.
        substate: SubstateClaim,
        /// Number of transactions finalized by finalizations in this block.
        /// Dwell-eligible [`ReadySignal`]s drained from the proposer's pool
        /// for inclusion in the block's manifest. Beacon's `Ready` witness
        /// derives one entry per included signal at block-assembly time.
        ready_signals: Vec<ReadySignal>,
        /// The proposer's reshape assertion for the manifest, derived
        /// from the load predicate over the parent state's substate
        /// count.
        reshape_trigger: Option<ReshapeTrigger>,
        /// The trimmed parent-window accumulator leaves this block's new
        /// witnesses append onto, resolved by the coordinator (which owns the
        /// accumulator and does the ancestor walk). The handler signs the
        /// block's randomness reveal on the dispatch pool, derives the
        /// block's new leaves over these, and finalizes `beacon_witness_root`
        /// and the leaf count.
        parent_witness_leaves: Vec<Hash>,
        /// The witness window base of the block's window, resolved by the
        /// coordinator from the same schedule entry as the block's
        /// committee. Stamped verbatim into the header.
        beacon_witness_base: BeaconWitnessLeafCount,
        /// Reveal chain on the parent header — what this block's chain
        /// extends when both anchor in the same epoch.
        parent_reveal_chain: RevealChain,
        /// Anchor epoch of the parent header. Differing from `committee_anchor_epoch`
        /// is what reseeds the chain.
        parent_committee_anchor_epoch: Epoch,
        /// Anchor epoch of the block being built —
        /// `epoch_for(parent_qc.weighted_timestamp)`.
        committee_anchor_epoch: Epoch,
        /// Whether the block's window is the shard's final epoch before
        /// a split, resolved by the coordinator from the schedule. When
        /// set, the handler extracts the root node's two child hashes
        /// from the JMT computation and stamps them into the header as
        /// `split_child_roots`.
        carry_split_child_roots: bool,
        /// Whether the block's window is the shard's final epoch before it
        /// terminates at a reshape boundary — a split parent *or* a merge
        /// child, broader than `carry_split_child_roots`. When set, the
        /// handler computes the `settled_txs_root` over the committed
        /// retention window and stamps it into the header.
        carry_terminal_settled_txs: bool,
        /// The schedule's settled-window floor for the shard at the block's
        /// anchor, paired with `carry_terminal_settled_txs` — extends the
        /// committed window walk back to the reshape's admission.
        settled_txs_window_floor: Option<WeightedTimestamp>,
        /// The block's **anchored** committee snapshot, resolved by the
        /// coordinator as `at_for_shard(local_shard, parent_qc.wt)` — the
        /// same one the verifier recomputes against. Classification
        /// (`ticks`, `provision_tx_roots`) keys on this, not the `ArcSwap`
        /// head, so a head-flipped proposer at a reshape boundary produces
        /// a header that resolves identically on every replica.
        classification_topology_snapshot: Arc<TopologySnapshot>,
        /// What the offered claims do to the read frontier; the handler
        /// recomputes it over the claims it keeps.
        frontier: FrontierInputs,
        /// What the read frontier judges of the offered content. The
        /// handler drops whatever it refuses against the parent state.
        fence: ReadFence,
        /// What the block's member lines are named over: what committed
        /// content up to the parent says of each member. The handler
        /// adds the block's own bundles and claims once it has dropped
        /// what the block will not carry.
        manifest: ManifestInputs,
        /// The certificate for the round before `round`, when the block
        /// skips rounds past `parent_qc`.
        timeout_cert: Option<TimeoutCertificate>,
        /// The answers and owed crossings the chain stands holding at the
        /// parent, `None` where the proposer cannot rebuild them; the
        /// handler leaves out what would carry them past the cap, and
        /// without a count every addition.
        standing_answers: Option<StandingAnswers>,
    },
}

impl Delegated for ConsensusAction {
    const POOL: DispatchPool = DispatchPool::Consensus;

    fn type_name(&self) -> &'static str {
        self.into()
    }

    fn signer(&self) -> Option<ValidatorId> {
        match self {
            Self::SignAndBroadcastBlockVote { signer, .. }
            | Self::SignAndBroadcastTimeout { signer, .. }
            | Self::SignAndBroadcastQcAnnouncement { signer, .. }
            | Self::SignAndBroadcastReadySignal { signer, .. } => Some(*signer),
            Self::BuildProposal { proposer, .. } => Some(*proposer),
            Self::BroadcastBlockHeader { header, .. } => Some(header.proposer()),
            Self::BroadcastCertifiedBlockHeader { certified_header } => {
                Some(certified_header.header().proposer())
            }
            Self::BroadcastShardForkProof { .. }
            | Self::VerifyAndBuildQuorumCertificate { .. }
            | Self::VerifyQcSignature { .. }
            | Self::VerifyTimeout { .. }
            | Self::VerifyRemoteHeaderQc { .. }
            | Self::VerifyShardForkProof { .. }
            | Self::VerifyStateRoot(_)
            | Self::VerifyBeaconWitnessRoot { .. }
            | Self::VerifyBodyRoot { .. }
            | Self::VerifyProvisionTxRoots { .. }
            | Self::VerifyResolutions { .. } => None,
        }
    }

    fn envelope_only(&self) -> bool {
        false
    }
}
