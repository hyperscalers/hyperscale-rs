//! Node state machine.

use hyperscale_bft::{BftConfig, BftCoordinator, RecoveredState};
use hyperscale_core::{Action, ProtocolEvent, StateMachine, TimerId};
use hyperscale_execution::ExecutionCoordinator;
use hyperscale_mempool::{MempoolConfig, MempoolState};
use hyperscale_provisions::{ProvisionConfig, ProvisionCoordinator};
use hyperscale_remote_headers::RemoteHeaderCoordinator;
use hyperscale_topology::TopologyState;
use hyperscale_types::{
    Block, BlockHeader, BlockManifest, CertifiedBlock, FinalizedWave, Hash, Provision,
    QuorumCertificate, ReadyTransactions, RoutableTransaction, ShardGroupId, TopologySnapshot,
};
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;

/// Index type for simulation-only node routing.
/// Production uses ValidatorId (from message signatures) and PeerId (libp2p).
pub type NodeIndex = u32;

// ─── Constants ──────────────────────────────────────────────────────────

/// Combined node state machine.
///
/// Composes BFT, execution, mempool, and provisions into a single state machine.
/// View changes are handled implicitly via local round advancement in BftCoordinator (HotStuff-2 style).
///
/// Note: Sync is handled entirely by the runner (production: SyncManager, simulation: runner logic).
/// The runner sends SyncBlockReadyToApply events directly to BFT when synced blocks are ready.
pub struct NodeStateMachine {
    /// This node's index (simulation-only, for routing).
    node_index: NodeIndex,

    /// Network topology — passed by reference to subsystem methods.
    topology: TopologyState,

    /// BFT consensus state (includes implicit round advancement).
    bft: BftCoordinator,

    /// Execution state.
    execution: ExecutionCoordinator,

    /// Mempool state.
    mempool: MempoolState,

    /// Provision coordination for cross-shard transactions.
    provisions: ProvisionCoordinator,

    /// Remote block header coordination (single source of truth).
    remote_headers: RemoteHeaderCoordinator,

    /// Current time.
    now: Duration,
}

impl std::fmt::Debug for NodeStateMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeStateMachine")
            .field("node_index", &self.node_index)
            .field("shard", &self.topology.snapshot().local_shard())
            .field("bft", &self.bft)
            .field("now", &self.now)
            .finish()
    }
}

/// Inputs gathered for building a block proposal.
///
/// Used by both `ContentAvailable` and `QuorumCertificateFormed` handlers
/// to avoid duplicating the ready-transaction gathering logic.
struct ProposalInputs {
    ready_txs: ReadyTransactions,
    finalized_waves: Vec<Arc<FinalizedWave>>,
    provision_batches: Vec<Arc<Provision>>,
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
    pub fn new(
        node_index: NodeIndex,
        topology: TopologyState,
        bft_config: BftConfig,
        recovered: RecoveredState,
        mempool_config: MempoolConfig,
        provision_config: ProvisionConfig,
    ) -> Self {
        Self {
            node_index,
            bft: BftCoordinator::new(node_index, bft_config.clone(), recovered),
            execution: ExecutionCoordinator::new(),
            mempool: MempoolState::with_config(mempool_config),
            provisions: ProvisionCoordinator::with_config(provision_config),
            remote_headers: RemoteHeaderCoordinator::new(),
            topology,
            now: Duration::ZERO,
        }
    }

    // ─── Accessors ──────────────────────────────────────────────────────

    /// Get this node's index.
    pub fn node_index(&self) -> NodeIndex {
        self.node_index
    }

    /// Get this node's shard.
    pub fn shard(&self) -> ShardGroupId {
        self.topology.snapshot().local_shard()
    }

    /// Get the current topology snapshot.
    pub fn topology(&self) -> &TopologySnapshot {
        self.topology.snapshot()
    }

    /// Get a reference to the mempool state.
    pub fn mempool(&self) -> &MempoolState {
        &self.mempool
    }

    /// Get a reference to the BFT state.
    pub fn bft(&self) -> &BftCoordinator {
        &self.bft
    }

    /// Get a reference to the execution state.
    pub fn execution(&self) -> &ExecutionCoordinator {
        &self.execution
    }

    /// Get a reference to the provision coordinator.
    pub fn provisions(&self) -> &ProvisionCoordinator {
        &self.provisions
    }

    /// Get a reference to the remote header coordinator.
    pub fn remote_headers(&self) -> &RemoteHeaderCoordinator {
        &self.remote_headers
    }

    /// Get the last committed JMT root hash (delegated to BFT's verification pipeline).
    pub fn last_committed_jmt_root(&self) -> Hash {
        self.bft.jmt_root()
    }

    /// Initialize the node with a genesis block.
    ///
    /// Returns actions to be processed (e.g., initial timers).
    pub fn initialize_genesis(&mut self, genesis: Block) -> Vec<Action> {
        self.bft
            .initialize_genesis(self.topology.snapshot(), genesis)
        // Note: No separate view change timer - round advancement is handled
        // implicitly via the proposal timer (HotStuff-2 style)
    }

    // ─── Shared Helpers ─────────────────────────────────────────────────

    /// Gather all inputs needed for a block proposal.
    ///
    /// Used by both `on_proposal_timer` and `on_qc_formed` to avoid duplicating
    /// the ready-transaction + abort intents + certificates gathering logic.
    fn gather_proposal_inputs(
        &mut self,
        pending_txs: usize,
        pending_certs: usize,
    ) -> ProposalInputs {
        // Request extra transactions from the mempool to compensate for QC-chain
        // duplicates that will be filtered by BFT during proposal building.
        let max_txs = self.bft.config().max_transactions_per_block + self.bft.dedup_overhead();
        let ready_txs = self
            .mempool
            .ready_transactions(max_txs, pending_txs, pending_certs);
        let finalized_waves = self.execution.get_finalized_waves();
        let provision_batches = self.provisions.queued_provisions();

        ProposalInputs {
            ready_txs,
            finalized_waves,
            provision_batches,
        }
    }

    // ─── Event Handlers ─────────────────────────────────────────────────

    /// Handle cleanup timer.
    #[instrument(skip(self))]
    fn on_cleanup_timer(&mut self) -> Vec<Action> {
        // Reschedule the cleanup timer
        let mut actions = vec![Action::SetTimer {
            id: TimerId::Cleanup,
            duration: self.bft.config().cleanup_interval,
        }];

        // Check pending blocks that need fetch requests.
        // We delay fetching to give gossip and local certificate creation
        // time to fill in missing data first.
        actions.extend(
            self.bft
                .check_pending_block_fetches(self.topology.snapshot(), false),
        );

        // Check if we're behind and need to catch up via sync.
        // This handles the case where we have a higher latest_qc than committed_height,
        // meaning the network has progressed but we're stuck.
        actions.extend(self.bft.check_sync_health(self.topology.snapshot()));

        // Clean up old tombstones in mempool to prevent unbounded memory growth.
        self.mempool.cleanup_default_tombstones();

        actions
    }

    /// Handle view change timer — check if the leader has timed out.
    fn on_view_change_timer(&mut self) -> Vec<Action> {
        match self.bft.check_round_timeout(self.topology.snapshot()) {
            Some(actions) => actions,
            None => {
                // Conditions not met yet. Reschedule for the remaining time
                // until the actual timeout fires (relative to last_leader_activity).
                let remaining = self.bft.remaining_view_change_timeout();
                vec![Action::SetTimer {
                    id: TimerId::ViewChange,
                    duration: remaining,
                }]
            }
        }
    }

    /// Handle content available — try to propose if we're the proposer.
    fn on_content_available(&mut self) -> Vec<Action> {
        self.try_event_driven_proposal()
    }

    /// Shared proposal logic for ContentAvailable and QC-formed paths.
    fn try_event_driven_proposal(&mut self) -> Vec<Action> {
        let (pending_txs, pending_certs) = self.bft.pending_block_counts();
        let inputs = self.gather_proposal_inputs(pending_txs, pending_certs);

        self.bft.try_propose(
            self.topology.snapshot(),
            &inputs.ready_txs,
            inputs.finalized_waves,
            inputs.provision_batches,
        )
    }

    /// Handle a received block header — validate in-flight limits.
    fn on_block_header_received(
        &mut self,
        header: BlockHeader,
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
            |h| self.provisions.get_batch_by_hash(h),
        )
    }

    /// Handle QC formed — may trigger immediate next proposal.
    fn on_qc_formed(&mut self, block_hash: Hash, qc: QuorumCertificate) -> Vec<Action> {
        // Count transactions and certificates in the block that will be committed.
        // This is critical for respecting in-flight limits: the BlockCommitted
        // event won't be processed until after we select transactions, so we
        // need to preemptively account for:
        // - Transactions that will INCREASE in-flight (new commits)
        // - Certificates that will DECREASE in-flight (completed transactions)
        let (pending_tx_count, pending_cert_count) = self.bft.pending_commit_counts(&qc);

        let inputs = self.gather_proposal_inputs(pending_tx_count, pending_cert_count);

        self.bft.on_qc_formed(
            self.topology.snapshot(),
            block_hash,
            qc,
            &inputs.ready_txs,
            inputs.finalized_waves,
            inputs.provision_batches,
        )
    }

    /// Handle block committed — notify all subsystems in the correct order.
    fn on_block_committed(&mut self, certified: CertifiedBlock) -> Vec<Action> {
        let mut actions = Vec::new();
        let block_hash = certified.block.hash();

        // Register committed tx hashes with BFT for timeout abort validation.
        let tx_hashes: Vec<Hash> = certified
            .block
            .transactions()
            .iter()
            .map(|tx| tx.hash())
            .collect();
        self.bft.register_committed_transactions(
            &tx_hashes,
            certified.qc.weighted_timestamp.as_millis(),
        );

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
                .on_block_committed(self.topology.snapshot(), &certified),
        );

        // Remote header coordinator: update liveness and check for timeouts.
        actions.extend(
            self.remote_headers
                .on_block_committed(self.topology.snapshot(), &certified),
        );

        // Provisions coordinator: prune + schedule fallback timeouts. Reads
        // provision hashes directly off the block — Live carries them
        // inline, Sealed has none (empty slice).
        actions.extend(
            self.provisions
                .on_block_committed(self.topology.snapshot(), &certified),
        );

        actions.extend(self.apply_block_to_execution(&certified));

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
        for cert in certified.block.certificates() {
            let cert_hash = cert.wave_id().hash();
            self.bft.remove_committed_transaction(&cert_hash);
        }

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

    /// Handle transaction executed — notify mempool and check pending blocks.
    fn on_transaction_executed(&mut self, tx_hash: Hash, accepted: bool) -> Vec<Action> {
        // Notify mempool
        let mut actions =
            self.mempool
                .on_transaction_executed(self.topology.snapshot(), tx_hash, accepted);

        // Check if any pending blocks are waiting for the finalized wave
        // that contains this tx.
        if let Some(wave_id) = self.execution.get_wave_assignment(&tx_hash) {
            let wave_id_hash = wave_id.hash();
            if let Some(fw) = self.execution.get_finalized_wave_by_hash(&wave_id_hash) {
                actions.extend(self.bft.check_pending_blocks_for_finalized_wave(
                    self.topology.snapshot(),
                    wave_id_hash,
                    &fw,
                ));
            }
        }

        actions
    }

    fn on_ec_created(&mut self, tx_hashes: Vec<Hash>) -> Vec<Action> {
        self.mempool.on_ec_created(&tx_hashes);
        vec![]
    }

    /// Handle transaction gossip received — add to mempool and check pending blocks.
    fn on_transaction_gossip_received(
        &mut self,
        tx: Arc<RoutableTransaction>,
        submitted_locally: bool,
    ) -> Vec<Action> {
        // Only add to our mempool if this transaction involves our shard.
        // Cross-shard transactions that don't touch our shard should be ignored.
        if !self.topology.snapshot().involves_local_shard(&tx) {
            return vec![];
        }

        let tx_hash = tx.hash();
        let tx_for_pending = Arc::clone(&tx);
        let mut actions =
            self.mempool
                .on_transaction_gossip(self.topology.snapshot(), tx, submitted_locally);

        // Check if any pending blocks are now complete
        actions.extend(self.bft.check_pending_blocks_for_transaction(
            self.topology.snapshot(),
            tx_hash,
            &tx_for_pending,
        ));

        // New transaction available — signal for event-driven proposal.
        actions.push(Action::Continuation(ProtocolEvent::ContentAvailable));

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
    fn handle(&mut self, event: ProtocolEvent) -> Vec<Action> {
        let mut actions = match event {
            // ── Timers ───────────────────────────────────────────────────
            ProtocolEvent::CleanupTimer => self.on_cleanup_timer(),
            ProtocolEvent::ViewChangeTimer => self.on_view_change_timer(),
            ProtocolEvent::ContentAvailable => self.on_content_available(),

            // ── BFT Consensus ────────────────────────────────────────────
            ProtocolEvent::BlockHeaderReceived { header, manifest } => {
                self.on_block_header_received(header, manifest)
            }
            ProtocolEvent::QuorumCertificateFormed { block_hash, qc } => {
                self.on_qc_formed(block_hash, qc)
            }
            ProtocolEvent::RemoteBlockCommitted {
                committed_header,
                sender,
            } => {
                // Route through the centralized remote header coordinator.
                // It performs structural pre-checks and dispatches QC verification.
                // Downstream consumers receive headers via RemoteHeaderVerified.
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
            ProtocolEvent::RemoteHeaderVerified { committed_header } => {
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
                    .on_verified_remote_header(topology, committed_header)
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
                block.clone(),
                block_hash,
                finalized_waves,
                provisions,
            ),

            // ── Block Committed ──────────────────────────────────────────
            ProtocolEvent::BlockCommitted { certified } => self.on_block_committed(certified),

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

            // ── Provision ───────────────────────────────────────────────
            ProtocolEvent::StateProvisionReceived { batch } => self
                .provisions
                .on_state_provisions_received(self.topology.snapshot(), batch),
            ProtocolEvent::StateProvisionVerified {
                batch,
                committed_header,
                valid,
            } => self.provisions.on_state_provisions_verified(
                self.topology.snapshot(),
                batch,
                committed_header,
                valid,
            ),
            ProtocolEvent::ProvisionVerified { batch } => {
                let mut actions = self
                    .bft
                    .check_pending_blocks_for_provision(self.topology.snapshot(), &batch);
                // New provision batch queued — signal for event-driven proposal.
                actions.push(Action::Continuation(ProtocolEvent::ContentAvailable));
                actions
            }

            // ── Execution ────────────────────────────────────────────────
            ProtocolEvent::ExecutionBatchCompleted {
                wave_id,
                results,
                tx_outcomes,
            } => {
                // Results arriving can (a) finalize a wave whose local EC
                // landed ahead of the engine, (b) unblock new vote
                // emission. Thread both through.
                let mut actions =
                    self.execution
                        .on_execution_batch_completed(wave_id, results, tx_outcomes);
                actions.extend(self.execution.emit_vote_actions(self.topology.snapshot()));
                actions
            }

            // ── Wave Execution (wave-based voting) ────────────────────────
            ProtocolEvent::ExecutionVoteReceived { vote } => self
                .execution
                .on_execution_vote(self.topology.snapshot(), vote),
            ProtocolEvent::ExecutionVotesVerifiedAndAggregated {
                wave_id,
                block_hash,
                verified_votes,
            } => self.execution.on_votes_verified(
                self.topology.snapshot(),
                wave_id,
                block_hash,
                verified_votes,
            ),
            ProtocolEvent::ExecutionCertificateAggregated {
                wave_id,
                certificate,
            } => self.execution.on_certificate_aggregated(
                self.topology.snapshot(),
                wave_id,
                certificate,
            ),
            ProtocolEvent::ExecutionCertificateReceived { cert } => self
                .execution
                .on_wave_certificate(self.topology.snapshot(), cert),
            ProtocolEvent::ExecutionCertificateSignatureVerified { certificate, valid } => {
                let mut actions = self.execution.on_certificate_verified(
                    self.topology.snapshot(),
                    certificate,
                    valid,
                );
                // Remote EC abort propagation may unlock local accumulators — re-scan.
                actions.extend(self.execution.emit_vote_actions(self.topology.snapshot()));
                actions
            }

            // ── Transactions ─────────────────────────────────────────────
            ProtocolEvent::TransactionExecuted { tx_hash, accepted } => {
                self.on_transaction_executed(tx_hash, accepted)
            }
            ProtocolEvent::ExecutionCertificateCreated { tx_hashes } => {
                self.on_ec_created(tx_hashes)
            }
            ProtocolEvent::WaveCompleted {
                wave_cert: _,
                tx_hashes: _,
            } => {
                // New finalized wave available — signal for event-driven proposal.
                vec![Action::Continuation(ProtocolEvent::ContentAvailable)]
            }
            ProtocolEvent::TransactionGossipReceived {
                tx,
                submitted_locally,
            } => self.on_transaction_gossip_received(tx, submitted_locally),
            // ── Fetch Protocol ───────────────────────────────────────────
            ProtocolEvent::TransactionFetchDelivered {
                block_hash,
                transactions,
            } => self.bft.on_transaction_fetch_received(
                self.topology.snapshot(),
                block_hash,
                transactions,
            ),
            // ── Storage / Sync ───────────────────────────────────────────
            ProtocolEvent::SyncBlockReadyToApply { certified } => self
                .bft
                .on_sync_block_ready_to_apply(self.topology.snapshot(), certified),
            // Handled by IoLoop directly (sync verification pipeline).
            ProtocolEvent::SyncEcVerificationComplete { .. } => vec![],
            // SyncProtocol finished fetching — tell BftCoordinator to exit sync
            // mode so it can re-enter sync if still behind, or resume
            // normal consensus.
            ProtocolEvent::SyncProtocolComplete { .. } => {
                self.bft.on_sync_complete(self.topology.snapshot())
            }
            // Sync recovery complete — flush expected provisions and remote
            // headers immediately so we can participate in execution for
            // recent blocks within the WAVE_TIMEOUT window.
            ProtocolEvent::SyncResumed => {
                let topo = self.topology.snapshot();
                let mut actions = self.remote_headers.flush_expected_headers(topo);
                actions.extend(self.provisions.flush_expected_provisions(topo));
                actions
            }
            ProtocolEvent::ChainMetadataFetched { height, hash, qc } => self
                .bft
                .on_chain_metadata_fetched(self.topology.snapshot(), height, hash, qc),

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

            // ── Finalized Wave Fetch Delivery ────────────────────────────
            ProtocolEvent::FinalizedWaveFetchDelivered { wave } => {
                let wave_id_hash = wave.wave_id_hash();
                self.bft.check_pending_blocks_for_finalized_wave(
                    self.topology.snapshot(),
                    wave_id_hash,
                    &wave,
                )
            }
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

    fn set_time(&mut self, now: Duration) {
        self.now = now;
        self.bft.set_time(now);
        self.execution.set_time(now);
        self.mempool.set_time(now);
        self.provisions.set_time(now);
    }

    fn now(&self) -> Duration {
        self.now
    }
}
