//! Node state machine.

mod execution;
mod proposal;
mod provisions;
mod sync;
mod timers;
mod transactions;

use hyperscale_bft::{BftConfig, BftCoordinator, RecoveredState};
use hyperscale_core::{Action, ProtocolEvent, StateMachine, TimerId};
use hyperscale_execution::ExecutionCoordinator;
use hyperscale_mempool::{MempoolConfig, MempoolCoordinator};
use hyperscale_provisions::{OutboundProvisionTracker, ProvisionConfig, ProvisionCoordinator};
use hyperscale_remote_headers::RemoteHeaderCoordinator;
use hyperscale_topology::TopologyCoordinator;
use hyperscale_types::{
    Block, BlockHash, BlockHeader, BlockManifest, CertifiedBlock, LocalTimestamp,
    QuorumCertificate, ShardGroupId, StateRoot, TopologySnapshot,
};
use std::sync::Arc;
use tracing::instrument;

/// Index type for simulation-only node routing.
/// Production uses `ValidatorId` (from message signatures) and `PeerId` (libp2p).
pub type NodeIndex = u32;

// ─── Constants ──────────────────────────────────────────────────────────

/// Combined node state machine.
///
/// Composes BFT, execution, mempool, and provisions into a single state machine.
/// View changes are handled implicitly via local round advancement in `BftCoordinator` (HotStuff-2 style).
///
/// Note: Sync is handled entirely by the runner (production: `SyncManager`, simulation: runner logic).
/// The runner sends `SyncBlockReadyToApply` events directly to BFT when synced blocks are ready.
pub struct NodeStateMachine {
    /// This node's index (simulation-only, for routing).
    node_index: NodeIndex,

    /// Network topology — passed by reference to subsystem methods.
    topology: TopologyCoordinator,

    /// BFT consensus state (includes implicit round advancement).
    bft: BftCoordinator,

    /// Execution state.
    execution: ExecutionCoordinator,

    /// Mempool state.
    mempool: MempoolCoordinator,

    /// Provision coordination for cross-shard transactions.
    provisions: ProvisionCoordinator,

    /// Retains outbound provisions until the target shard's
    /// execution certificates ACK every transaction they contain.
    outbound_provisions: OutboundProvisionTracker,

    /// Remote block header coordination (single source of truth).
    remote_headers: RemoteHeaderCoordinator,

    /// Current time.
    now: LocalTimestamp,
}

impl std::fmt::Debug for NodeStateMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeStateMachine")
            .field("node_index", &self.node_index)
            .field("shard", &self.topology.snapshot().local_shard())
            .field("bft", &self.bft)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

impl NodeStateMachine {
    /// Create a new node state machine.
    ///
    /// # Arguments
    ///
    /// * `node_index` - Deterministic node index for ordering
    /// * `topology` - Network topology
    /// * `signing_key` - Key for signing votes and proposals
    /// * `bft_config` - BFT configuration
    /// * `recovered` - State recovered from storage. Use `RecoveredState::default()` for fresh start.
    /// * `mempool_config` - Mempool configuration
    /// * `provision_config` - Provision coordinator configuration
    #[must_use]
    pub fn new(
        node_index: NodeIndex,
        topology: TopologyCoordinator,
        bft_config: &BftConfig,
        recovered: RecoveredState,
        mempool_config: MempoolConfig,
        provision_config: ProvisionConfig,
        provision_store: Arc<hyperscale_provisions::ProvisionStore>,
    ) -> Self {
        Self {
            node_index,
            bft: BftCoordinator::new(node_index, bft_config.clone(), recovered),
            execution: ExecutionCoordinator::new(),
            mempool: MempoolCoordinator::with_config(mempool_config),
            provisions: ProvisionCoordinator::with_config_and_store(
                provision_config,
                Arc::clone(&provision_store),
            ),
            outbound_provisions: OutboundProvisionTracker::new(provision_store),
            remote_headers: RemoteHeaderCoordinator::new(),
            topology,
            now: LocalTimestamp::ZERO,
        }
    }

    // ─── Accessors ──────────────────────────────────────────────────────

    /// Get this node's index.
    #[must_use]
    pub const fn node_index(&self) -> NodeIndex {
        self.node_index
    }

    /// Get this node's shard.
    #[must_use]
    pub fn shard(&self) -> ShardGroupId {
        self.topology.snapshot().local_shard()
    }

    /// Get the current topology snapshot.
    #[must_use]
    pub fn topology(&self) -> &TopologySnapshot {
        self.topology.snapshot()
    }

    /// Get a reference to the mempool state.
    #[must_use]
    pub const fn mempool(&self) -> &MempoolCoordinator {
        &self.mempool
    }

    /// Get a reference to the BFT state.
    #[must_use]
    pub const fn bft(&self) -> &BftCoordinator {
        &self.bft
    }

    /// Get a reference to the execution state.
    #[must_use]
    pub const fn execution(&self) -> &ExecutionCoordinator {
        &self.execution
    }

    /// Get a reference to the provision coordinator.
    #[must_use]
    pub const fn provisions(&self) -> &ProvisionCoordinator {
        &self.provisions
    }

    /// Get a reference to the remote header coordinator.
    #[must_use]
    pub const fn remote_headers(&self) -> &RemoteHeaderCoordinator {
        &self.remote_headers
    }

    /// Get the last committed JMT root hash (delegated to BFT's verification pipeline).
    #[must_use]
    pub const fn last_committed_jmt_root(&self) -> StateRoot {
        self.bft.jmt_root()
    }

    /// Initialize the node with a genesis block.
    ///
    /// Returns actions to be processed (e.g., initial timers).
    pub fn initialize_genesis(&mut self, genesis: &Block) -> Vec<Action> {
        self.bft
            .initialize_genesis(self.topology.snapshot(), genesis)
        // Note: No separate view change timer - round advancement is handled
        // implicitly via the proposal timer (HotStuff-2 style)
    }

    // ─── Event Handlers ─────────────────────────────────────────────────

    /// Handle a received block header — validate in-flight limits.
    fn on_block_header_received(
        &mut self,
        header: &BlockHeader,
        manifest: BlockManifest,
    ) -> Vec<Action> {
        // Total transaction count across all sections
        let total_tx_count = manifest.transaction_count();

        // Validate in-flight limits only for the next block after committed height.
        // For blocks further ahead, skip validation - validators at different heights
        // have different in_flight() counts, causing split votes and view changes.
        let committed_height = self.bft.committed_height();
        let is_next_block = header.height == committed_height + 1;

        if is_next_block
            && self
                .mempool
                .would_exceed_in_flight(total_tx_count, manifest.cert_hashes.len())
        {
            tracing::warn!(
                block_hash = ?header.hash(),
                height = header.height.0,
                "Rejecting block that would exceed in-flight limit"
            );
            return vec![];
        }

        self.bft.on_block_header(
            self.topology.snapshot(),
            header,
            manifest,
            |h| self.mempool.get_transaction(h),
            |h| self.execution.get_finalized_wave_by_hash(h),
            |h| self.provisions.get_provisions_by_hash(h),
        )
    }

    /// Handle QC formed — may trigger immediate next proposal.
    fn on_qc_formed(&mut self, block_hash: BlockHash, qc: &QuorumCertificate) -> Vec<Action> {
        // Count transactions and certificates in the block that will be committed.
        // This is critical for respecting in-flight limits: the BlockCommitted
        // event won't be processed until after we select transactions, so we
        // need to preemptively account for:
        // - Transactions that will INCREASE in-flight (new commits)
        // - Certificates that will DECREASE in-flight (completed transactions)
        let (pending_tx_count, pending_cert_count) = self.bft.pending_commit_counts(qc);

        let inputs = self.gather_proposal_inputs(pending_tx_count, pending_cert_count);

        self.bft.on_qc_formed(
            self.topology.snapshot(),
            block_hash,
            qc,
            &inputs.ready_txs,
            inputs.finalized_waves,
            inputs.provisions,
        )
    }

    /// Handle block committed — notify all subsystems in the correct order.
    fn on_block_committed(&mut self, certified: &CertifiedBlock) -> Vec<Action> {
        let mut actions = Vec::new();
        let block_hash = certified.block.hash();

        // Register committed transactions with BFT for proposal dedup.
        // The tx_cache reads each tx's `validity_range.end_timestamp_exclusive`
        // to bound its own retention.
        self.bft
            .register_committed_transactions(certified.block.transactions());

        // Mark this block as a usable parent for child state-root verifications.
        // By the time BlockCommitted fires, the block's JMT snapshot is in
        // PendingChain (populated either by a prior VerifyStateRoot or by the
        // inline CommitBlockByQcOnly computation), so children can verify
        // against it without waiting on RocksDB persistence.
        self.bft.on_block_committed_verification(block_hash);

        // Mempool: marks Pending → Committed for block.transactions, then drives
        // each tx in `block.certificates` to its terminal state (Completed +
        // tombstone). Same behavior for consensus and sync commit paths.
        actions.extend(
            self.mempool
                .on_block_committed(self.topology.snapshot(), certified),
        );

        // Remote header coordinator: update liveness and check for timeouts.
        actions.extend(
            self.remote_headers
                .on_block_committed(self.topology.snapshot(), certified),
        );

        // Provisions coordinator: prune + schedule fallback timeouts. Reads
        // provision hashes directly off the block — Live carries them
        // inline, Sealed has none (empty slice).
        actions.extend(
            self.provisions
                .on_block_committed(self.topology.snapshot(), certified),
        );

        // Outbound provision safety sweep — runs on the BFT-authenticated
        // weighted timestamp so every validator evicts deterministically.
        self.outbound_provisions
            .on_block_committed(certified.qc.weighted_timestamp);

        actions.extend(self.apply_block_to_execution(certified));

        // Block committed changes in-flight counts — trigger proposal attempt
        // so the next proposer can include newly ready transactions.
        actions.push(Action::Continuation(ProtocolEvent::ContentAvailable));

        actions
    }

    /// Apply a committed block to execution: cert cleanup, wave setup +
    /// dispatch (Live) or wave-assignment recording only (Sealed), and
    /// vote emission. Provisions live inline on `Block::Live` — no
    /// separate argument needed.
    fn apply_block_to_execution(&mut self, certified: &CertifiedBlock) -> Vec<Action> {
        let mut actions = Vec::new();

        // Release execution's per-wave bookkeeping for wave certs included in
        // this block. Per-tx terminal state for the mempool is already handled
        // separately by `on_block_committed` reading `block.certificates`.
        self.execution
            .cleanup_committed_waves(certified.block.certificates());

        actions.extend(
            self.execution
                .on_block_committed(self.topology.snapshot(), certified),
        );

        // Round voting: scan all incomplete waves and emit votes for complete ones.
        // This is the SINGLE path to execution voting. Abort intents have already
        // been processed above (with override semantics), so the accumulator state
        // is deterministic at this height. All validators at this height produce
        // the same votes.
        actions.extend(self.execution.emit_vote_actions(self.topology.snapshot()));

        actions
    }
}

impl StateMachine for NodeStateMachine {
    #[instrument(skip(self), fields(
        node = self.node_index,
        shard = self.topology.snapshot().local_shard().0,
        event = %event.type_name(),
        height = self.bft.committed_height().0,
    ))]
    #[allow(clippy::too_many_lines)] // single dispatch over the ProtocolEvent enum; one arm per variant
    fn handle(&mut self, event: ProtocolEvent) -> Vec<Action> {
        let mut actions = match event {
            // ── Timers ───────────────────────────────────────────────────
            ProtocolEvent::CleanupTimer => self.on_cleanup_timer(),
            ProtocolEvent::ViewChangeTimer => self.on_view_change_timer(),
            ProtocolEvent::ContentAvailable => self.try_event_driven_proposal(),

            // ── BFT Consensus ────────────────────────────────────────────
            ProtocolEvent::BlockHeaderReceived { header, manifest } => {
                self.on_block_header_received(&header, manifest)
            }
            ProtocolEvent::QuorumCertificateFormed { block_hash, qc } => {
                self.on_qc_formed(block_hash, &qc)
            }
            ProtocolEvent::RemoteBlockCommitted {
                committed_header,
                sender,
            } => {
                // Route through the centralized remote header coordinator.
                // It performs structural pre-checks and dispatches QC verification.
                // Downstream consumers receive headers via RemoteHeaderAdmitted.
                let header = Arc::new(committed_header);
                let topology = self.topology.snapshot();
                self.remote_headers
                    .on_remote_block_committed(topology, header, sender)
            }
            ProtocolEvent::BlockVoteReceived { vote } => {
                self.bft.on_block_vote(self.topology.snapshot(), vote)
            }
            ProtocolEvent::BlockReadyToCommit {
                block_hash,
                qc,
                source,
            } => {
                self.bft
                    .on_block_ready_to_commit(self.topology.snapshot(), block_hash, qc, source)
            }
            ProtocolEvent::QuorumCertificateResult {
                block_hash,
                qc,
                verified_votes,
            } => self
                .bft
                .on_qc_result(self.topology.snapshot(), block_hash, qc, verified_votes),
            ProtocolEvent::QcSignatureVerified { block_hash, valid } => self
                .bft
                .on_qc_signature_verified(self.topology.snapshot(), block_hash, valid),
            ProtocolEvent::RemoteHeaderQcVerified {
                shard,
                height,
                header,
                valid,
            } => self.remote_headers.on_remote_header_qc_verified(
                self.topology.snapshot(),
                shard,
                height,
                header,
                valid,
            ),
            ProtocolEvent::RemoteHeaderAdmitted { committed_header } => {
                // Fan out verified header to downstream consumers.
                // BFT already received the header in RemoteHeaderQcVerified
                // (early insertion for deferral proof validation).
                let topology = self.topology.snapshot();
                let shard = committed_header.shard_group_id();

                // Execution: register expected execution certs from waves.
                self.execution.on_verified_remote_header(
                    topology,
                    shard,
                    committed_header.header.height,
                    &committed_header.header.waves,
                );

                // Provision: register expected provisions and join with buffered batches.
                self.provisions
                    .on_verified_remote_header(topology, &committed_header)
            }
            ProtocolEvent::BlockRootVerified {
                kind,
                block_hash,
                valid,
            } => self
                .bft
                .on_block_root_verified(self.topology.snapshot(), kind, block_hash, valid),
            ProtocolEvent::ProposalBuilt {
                height,
                round,
                block,
                block_hash,
                finalized_waves,
                provisions,
            } => self.bft.on_proposal_built(
                self.topology.snapshot(),
                height,
                round,
                &block,
                block_hash,
                finalized_waves,
                provisions,
            ),

            // ── Block Committed ──────────────────────────────────────────
            ProtocolEvent::BlockCommitted { certified } => self.on_block_committed(&certified),

            // ── Block Persisted (RocksDB write complete) ───────────────
            // Advances `last_persisted_height`, a fallback gate for deferred
            // state root verifications (steady-state unblocking happens on
            // `BlockCommitted`). Still needed for boot-time catch-up: a
            // freshly-booted node has persisted state but an empty
            // in-memory set, so child verifications of just-persisted
            // parents unblock here. Also drives auto-resume-from-sync.
            ProtocolEvent::BlockPersisted { height } => {
                let mut actions = self
                    .bft
                    .on_block_persisted(self.topology.snapshot(), height);
                // If BFT just resumed from sync, reschedule the cleanup timer.
                if !actions.is_empty() {
                    actions.push(Action::SetTimer {
                        id: TimerId::Cleanup,
                        duration: self.bft.config().cleanup_interval,
                    });
                }
                actions
            }

            // ── Provisions ───────────────────────────────────────────────
            evt @ (ProtocolEvent::ProvisionsReceived { .. }
            | ProtocolEvent::StateProvisionsVerified { .. }
            | ProtocolEvent::ProvisionsAdmitted { .. }
            | ProtocolEvent::OutboundProvisionBroadcast { .. }
            | ProtocolEvent::OutboundEcObserved { .. }) => self.handle_provisions(evt),

            // ── Execution ────────────────────────────────────────────────
            evt @ (ProtocolEvent::ExecutionBatchCompleted { .. }
            | ProtocolEvent::ExecutionVoteReceived { .. }
            | ProtocolEvent::ExecutionVotesVerifiedAndAggregated { .. }
            | ProtocolEvent::ExecutionCertificateAggregated { .. }
            | ProtocolEvent::ExecutionCertificateSignatureVerified { .. }
            | ProtocolEvent::WaveCompleted { .. }
            | ProtocolEvent::ExecutionCertificateAdmitted { .. }) => self.handle_execution(evt),

            // ── Transactions ─────────────────────────────────────────────
            evt @ (ProtocolEvent::ExecutionCertificateCreated { .. }
            | ProtocolEvent::TransactionGossipReceived { .. }
            | ProtocolEvent::TransactionsAdmitted { .. }) => self.handle_transaction(evt),

            // ── Sync ─────────────────────────────────────────────────────
            evt @ (ProtocolEvent::SyncBlockReadyToApply { .. }
            | ProtocolEvent::SyncEcVerificationComplete { .. }
            | ProtocolEvent::SyncProtocolComplete { .. }
            | ProtocolEvent::SyncResumed
            | ProtocolEvent::ChainMetadataFetched { .. }) => self.handle_sync(evt),

            // ── Global Consensus / Epoch (not yet implemented) ───────────
            // When implemented, route to GlobalConsensusState.
            // The #[instrument] span already logs the specific event name.
            //
            // TODO(epoch): After transition_to_next_epoch() / mark_shard_splitting() /
            // clear_shard_splitting() mutates self.topology, emit
            // Action::TopologyChanged { topology: Arc::clone(self.topology.snapshot()) }
            // so the io_loop updates its shared topology snapshot.
            ProtocolEvent::GlobalConsensusTimer
            | ProtocolEvent::GlobalBlockReceived { .. }
            | ProtocolEvent::GlobalBlockVoteReceived { .. }
            | ProtocolEvent::GlobalQcFormed { .. }
            | ProtocolEvent::EpochEndApproaching { .. }
            | ProtocolEvent::EpochTransitionReady { .. }
            | ProtocolEvent::EpochTransitionComplete { .. }
            | ProtocolEvent::ValidatorSyncComplete { .. }
            | ProtocolEvent::ShardSplitInitiated { .. }
            | ProtocolEvent::ShardSplitComplete { .. }
            | ProtocolEvent::ShardMergeInitiated { .. }
            | ProtocolEvent::ShardMergeComplete { .. } => vec![],

            ProtocolEvent::FinalizedWavesAdmitted { waves } => self
                .bft
                .on_finalized_waves_admitted(self.topology.snapshot(), &waves),
        };

        // Drain any state root verifications that became ready during this event.
        for ready in self.bft.drain_ready_state_root_verifications() {
            actions.push(Action::VerifyStateRoot {
                block_hash: ready.block_hash,
                parent_block_hash: ready.parent_block_hash,
                parent_state_root: ready.parent_state_root,
                parent_block_height: ready.parent_block_height,
                expected_root: ready.expected_root,
                finalized_waves: ready.finalized_waves,
                block_height: ready.block_height,
            });
        }

        // Re-enter try_propose if a deferred proposal was unblocked.
        // ContentAvailable triggers fresh tx selection against current state,
        // avoiding stale transactions from the original deferral.
        if self.bft.take_ready_proposal() {
            actions.push(Action::Continuation(ProtocolEvent::ContentAvailable));
        }

        actions
    }

    fn set_time(&mut self, now: LocalTimestamp) {
        self.now = now;
        self.bft.set_time(now);
    }

    fn now(&self) -> LocalTimestamp {
        self.now
    }
}
