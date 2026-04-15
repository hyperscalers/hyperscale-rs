//! Node state machine.

use hyperscale_bft::{BftConfig, BftState, RecoveredState};
use hyperscale_core::{Action, ProtocolEvent, StateMachine, TimerId};
use hyperscale_execution::ExecutionState;
use hyperscale_mempool::{MempoolConfig, MempoolState};
use hyperscale_provisions::ProvisionCoordinator;
use hyperscale_remote_headers::RemoteHeaderCoordinator;
use hyperscale_topology::TopologyState;
use hyperscale_types::{
    Block, BlockHeader, BlockHeight, BlockManifest, FinalizedWave, Hash, Provision,
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
/// View changes are handled implicitly via local round advancement in BftState (HotStuff-2 style).
///
/// Note: Sync is handled entirely by the runner (production: SyncManager, simulation: runner logic).
/// The runner sends SyncBlockReadyToApply events directly to BFT when synced blocks are ready.
pub struct NodeStateMachine {
    /// This node's index (simulation-only, for routing).
    node_index: NodeIndex,

    /// Network topology — passed by reference to subsystem methods.
    topology: TopologyState,

    /// BFT consensus state (includes implicit round advancement).
    bft: BftState,

    /// Execution state.
    execution: ExecutionState,

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
/// Used by both `ProposalTimer` and `QuorumCertificateFormed` handlers
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
    pub fn new(
        node_index: NodeIndex,
        topology: TopologyState,
        bft_config: BftConfig,
        recovered: RecoveredState,
        mempool_config: MempoolConfig,
    ) -> Self {
        Self {
            node_index,
            bft: BftState::new(
                node_index,
                topology.snapshot(),
                bft_config.clone(),
                recovered,
            ),
            execution: ExecutionState::new(),
            mempool: MempoolState::with_config(mempool_config),
            provisions: ProvisionCoordinator::new(),
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
    pub fn bft(&self) -> &BftState {
        &self.bft
    }

    /// Get a reference to the execution state.
    pub fn execution(&self) -> &ExecutionState {
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

    /// Get the last committed JVT root hash (delegated to BFT's verification pipeline).
    pub fn last_committed_jvt_root(&self) -> Hash {
        self.bft.jvt_root()
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
        let current_height = BlockHeight(self.bft.committed_height());
        self.mempool.cleanup_default_tombstones(current_height);

        actions
    }

    /// Handle proposal timer — propose a block or advance the round on timeout.
    fn on_proposal_timer(&mut self) -> Vec<Action> {
        // Check if we should advance the round due to timeout.
        // Delegated to BftState which owns timeout tracking.
        if let Some(actions) = self.bft.check_round_timeout(self.topology.snapshot()) {
            return actions;
        }

        // Normal proposal timer - try to propose if we're the proposer
        //
        // Account for pipelining: multiple blocks can be proposed before any commit.
        // We must count txs/certs in ALL pending blocks to avoid exceeding in-flight limits.
        let (pending_txs, pending_certs) = self.bft.pending_block_counts();

        let inputs = self.gather_proposal_inputs(pending_txs, pending_certs);

        self.bft.on_proposal_timer(
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
        let is_next_block = header.height.0 == committed_height + 1;

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
    fn on_block_committed(
        &mut self,
        block_hash: Hash,
        height: u64,
        block: Block,
        provision_hashes: Vec<Hash>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let block_height = BlockHeight(height);

        // Register committed tx hashes with BFT for timeout abort validation.
        let tx_hashes: Vec<Hash> = block.transactions.iter().map(|tx| tx.hash()).collect();
        self.bft
            .register_committed_transactions(&tx_hashes, block_height);

        // Remove committed wave certificates from execution state.
        // They've been included in this block, so don't need to be proposed again.
        // Returns per-tx (tx_hash, decision) pairs for mempool terminal state updates.
        let committed_txs = self
            .execution
            .on_certificates_committed(&block.certificates);
        for cert in &block.certificates {
            let cert_hash = cert.wave_id.hash();
            self.bft.remove_committed_transaction(&cert_hash);
        }

        // Notify mempool and provisions of per-tx terminal states
        // from committed wave certificates. Wave certs are lean (no per-tx data),
        // so we use the decisions extracted from FinalizedWave above.
        for (tx_hash, decision) in &committed_txs {
            if *decision == hyperscale_types::TransactionDecision::Aborted {
                hyperscale_metrics::record_transaction_aborted();
            }
            actions.extend(self.mempool.on_certificate_committed(
                self.topology.snapshot(),
                *tx_hash,
                *decision,
                block_height,
            ));
        }

        // Pass all transactions from block to execution (no need for mempool lookup).
        let all_txs = block.transactions.clone();
        actions.extend(self.execution.on_block_committed(
            self.topology.snapshot(),
            block_hash,
            height,
            block.header.timestamp,
            block.header.proposer,
            all_txs,
        ));

        // Also let mempool handle it (marks transactions as committed, processes deferrals/aborts)
        actions.extend(
            self.mempool
                .on_block_committed_full(self.topology.snapshot(), &block),
        );

        // Remote header coordinator: update liveness and check for timeouts.
        actions.extend(
            self.remote_headers
                .on_block_committed(self.topology.snapshot()),
        );

        // Apply committed provisions deterministically. Resolve provision hashes
        // to batch data via the ProvisionCoordinator — this works identically for
        // both consensus and sync commit paths since hashes come from the manifest.
        let provision_batches: Vec<Arc<Provision>> = provision_hashes
            .iter()
            .filter_map(|h| self.provisions.get_batch_by_hash(h))
            .collect();
        if !provision_batches.is_empty() {
            actions.extend(self.execution.apply_committed_provisions(
                self.topology.snapshot(),
                &provision_batches,
                height,
            ));
        }

        // Let provisions coordinator handle cleanup + fallback timeouts.
        actions.extend(self.provisions.on_block_committed(
            self.topology.snapshot(),
            &block,
            &provision_hashes,
        ));

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

    fn on_transaction_provisioned(&mut self, tx_hash: Hash) -> Vec<Action> {
        self.mempool.on_transaction_provisioned(tx_hash);
        vec![]
    }

    fn on_wave_ready(&mut self, tx_hashes: Vec<Hash>) -> Vec<Action> {
        self.mempool.on_wave_ready(&tx_hashes);
        vec![]
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

        actions
    }
}

impl StateMachine for NodeStateMachine {
    #[instrument(skip(self), fields(
        node = self.node_index,
        shard = self.topology.snapshot().local_shard().0,
        event = %event.type_name(),
        height = self.bft.committed_height(),
    ))]
    fn handle(&mut self, event: ProtocolEvent) -> Vec<Action> {
        let mut actions = match event {
            // ── Timers ───────────────────────────────────────────────────
            ProtocolEvent::CleanupTimer => self.on_cleanup_timer(),
            ProtocolEvent::ProposalTimer => self.on_proposal_timer(),

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
            ProtocolEvent::BlockReadyToCommit { block_hash, qc } => self
                .bft
                .on_block_ready_to_commit(self.topology.snapshot(), block_hash, qc),
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
            } => {
                // Store valid headers into BFT immediately so they're available
                // for deferral merkle proof validation without a 1-step delay.
                // Must capture returned actions — unblocked abort intent
                // verifications are emitted here.
                let mut actions = if valid {
                    self.bft.on_verified_remote_header(Arc::clone(&header))
                } else {
                    vec![]
                };
                actions.extend(self.remote_headers.on_remote_header_qc_verified(
                    self.topology.snapshot(),
                    shard,
                    height,
                    header,
                    valid,
                ));
                actions
            }
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
                    committed_header.header.height.0,
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
                provision_hashes,
            } => self.bft.on_proposal_built(
                self.topology.snapshot(),
                height,
                round,
                block.clone(),
                block_hash,
                finalized_waves,
                provision_hashes,
            ),

            // ── Block Committed ──────────────────────────────────────────
            ProtocolEvent::BlockCommitted {
                block_hash,
                height,
                block,
                provision_hashes,
            } => self.on_block_committed(block_hash, height, block, provision_hashes),

            // ── Block Persisted (RocksDB write complete) ───────────────
            // Unblock deferred state root verifications whose parent's
            // tree nodes are now in the tree store. This MUST happen on
            // BlockPersisted (not BlockCommitted) because sync blocks
            // skip VerifyStateRoot — their JVT snapshots are never cached
            // in jvt_snapshot_cache, so the tree nodes only become
            // available once commit_block writes them to storage.
            // Consensus blocks are unaffected: their parents' tree nodes
            // are available via verified_state_roots (from prior
            // VerifyStateRoot), so the deferral gate already passes.
            ProtocolEvent::BlockPersisted { height } => {
                let mut actions = self.bft.on_jvt_committed(self.topology.snapshot(), height);
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
            ProtocolEvent::ProvisionVerified { batch } => self
                .bft
                .check_pending_blocks_for_provision(self.topology.snapshot(), &batch),

            // ── Execution ────────────────────────────────────────────────
            ProtocolEvent::ExecutionBatchCompleted {
                results,
                tx_outcomes,
            } => {
                let mut actions = self
                    .execution
                    .on_execution_batch_completed(results, tx_outcomes);
                // Execution results gate vote emission — re-scan.
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
            ProtocolEvent::TransactionProvisioned { tx_hash } => {
                self.on_transaction_provisioned(tx_hash)
            }
            ProtocolEvent::WaveReady { tx_hashes } => self.on_wave_ready(tx_hashes),
            ProtocolEvent::ExecutionCertificateCreated { tx_hashes } => {
                self.on_ec_created(tx_hashes)
            }
            ProtocolEvent::WaveCompleted {
                wave_cert: _,
                tx_hashes: _,
            } => {
                // Wave-level finalization event. Per-tx handling is done via
                // TransactionExecuted events emitted alongside WaveCompleted.
                // Future: use this for wave-level mempool notifications.
                vec![]
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
            ProtocolEvent::SyncBlockReadyToApply {
                block,
                qc,
                local_receipts,
            } => self.bft.on_sync_block_ready_to_apply(
                self.topology.snapshot(),
                block,
                qc,
                local_receipts,
            ),
            // Handled by IoLoop directly (sync verification pipeline).
            ProtocolEvent::SyncEcVerificationComplete { .. } => vec![],
            // SyncProtocol finished fetching — tell BftState to exit sync
            // mode so it can re-enter sync if still behind, or resume
            // normal consensus.
            ProtocolEvent::SyncProtocolComplete { .. } => {
                self.bft.on_sync_complete(self.topology.snapshot())
            }
            // Sync recovery complete — flush expected provisions and remote
            // headers immediately so we can participate in execution for
            // recent blocks within the WAVE_TIMEOUT_BLOCKS window.
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

        // Emit deferred BuildProposal if its parent tree became available.
        actions.extend(self.bft.take_ready_proposal());

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
