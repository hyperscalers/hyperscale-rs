//! Node state machine.

use hyperscale_bft::{BftConfig, BftState, RecoveredState};
use hyperscale_core::{Action, Event, OutboundMessage, StateMachine, SubStateMachine};
use hyperscale_execution::ExecutionState;
use hyperscale_livelock::LivelockState;
use hyperscale_mempool::MempoolState;
use hyperscale_types::{Block, KeyPair, ShardGroupId, Topology};
use std::sync::Arc;
use std::time::Duration;

/// Index type for simulation-only node routing.
/// Production uses ValidatorId (from message signatures) and PeerId (libp2p).
pub type NodeIndex = u32;

/// Combined node state machine.
///
/// Composes BFT, execution, mempool, and livelock into a single state machine.
/// View changes are handled implicitly via local round advancement in BftState (HotStuff-2 style).
///
/// Note: Sync is handled entirely by the runner (production: SyncManager, simulation: runner logic).
/// The runner sends SyncBlockReadyToApply events directly to BFT when synced blocks are ready.
pub struct NodeStateMachine {
    /// This node's index (simulation-only, for routing).
    node_index: NodeIndex,

    /// Network topology (single source of truth).
    topology: Arc<dyn Topology>,

    /// BFT consensus state (includes implicit round advancement).
    bft: BftState,

    /// Execution state.
    execution: ExecutionState,

    /// Mempool state.
    mempool: MempoolState,

    /// Livelock prevention state (cycle detection for cross-shard TXs).
    livelock: LivelockState,

    /// Current time.
    now: Duration,

    /// Time of last QC formation (for round timeout detection).
    last_qc_time: Duration,
}

impl std::fmt::Debug for NodeStateMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeStateMachine")
            .field("node_index", &self.node_index)
            .field("shard", &self.topology.local_shard())
            .field("bft", &self.bft)
            .field("now", &self.now)
            .finish()
    }
}

impl NodeStateMachine {
    /// Create a new node state machine.
    ///
    /// # Arguments
    ///
    /// * `node_index` - Deterministic node index for ordering
    /// * `topology` - Network topology (single source of truth)
    /// * `signing_key` - Key for signing votes and proposals
    /// * `bft_config` - BFT configuration
    /// * `recovered` - State recovered from storage. Use `RecoveredState::default()` for fresh start.
    pub fn new(
        node_index: NodeIndex,
        topology: Arc<dyn Topology>,
        signing_key: KeyPair,
        bft_config: BftConfig,
        recovered: RecoveredState,
    ) -> Self {
        let local_shard = topology.local_shard();

        Self {
            node_index,
            topology: topology.clone(),
            bft: BftState::new(
                node_index,
                signing_key.clone(),
                topology.clone(),
                bft_config.clone(),
                recovered,
            ),
            execution: ExecutionState::new(topology.clone(), signing_key),
            mempool: MempoolState::new(topology.clone()),
            livelock: LivelockState::new(local_shard, topology),
            now: Duration::ZERO,
            last_qc_time: Duration::ZERO,
        }
    }

    /// Get this node's index.
    pub fn node_index(&self) -> NodeIndex {
        self.node_index
    }

    /// Get this node's shard.
    pub fn shard(&self) -> ShardGroupId {
        self.topology.local_shard()
    }

    /// Get a reference to the topology.
    pub fn topology(&self) -> &Arc<dyn Topology> {
        &self.topology
    }

    /// Get a reference to the mempool state.
    pub fn mempool(&self) -> &MempoolState {
        &self.mempool
    }

    /// Get a reference to the BFT state.
    pub fn bft(&self) -> &BftState {
        &self.bft
    }

    /// Get a mutable reference to the BFT state.
    pub fn bft_mut(&mut self) -> &mut BftState {
        &mut self.bft
    }

    /// Get a reference to the execution state.
    pub fn execution(&self) -> &ExecutionState {
        &self.execution
    }

    /// Get a reference to the livelock state.
    pub fn livelock(&self) -> &LivelockState {
        &self.livelock
    }

    /// Initialize the node with a genesis block.
    ///
    /// Returns actions to be processed (e.g., initial timers).
    pub fn initialize_genesis(&mut self, genesis: Block) -> Vec<Action> {
        self.bft.initialize_genesis(genesis)
        // Note: No separate view change timer - round advancement is handled
        // implicitly via the proposal timer (HotStuff-2 style)
    }

    /// Handle cleanup timer.
    fn on_cleanup_timer(&mut self) -> Vec<Action> {
        // Clean up expired tombstones in livelock state
        self.livelock.cleanup();

        // TODO: Clean up other stale state (mempool, execution, etc.)
        vec![]
    }

    /// Handle block committed event.
    ///
    /// Resets round timeout tracking.
    fn on_block_committed(&mut self, _height: u64) -> Vec<Action> {
        // Reset round advancement timeout - progress was made
        self.last_qc_time = self.now;

        // Note: Sync progress tracking is now handled by the runner
        // (production: SyncManager, simulation: runner.sync_targets)
        vec![]
    }

    /// Check if we should advance the round due to timeout.
    ///
    /// Called from proposal timer to detect if no QC has formed.
    fn should_advance_round(&self) -> bool {
        let timeout = self.bft.config().view_change_timeout;
        self.now.saturating_sub(self.last_qc_time) >= timeout
    }
}

impl StateMachine for NodeStateMachine {
    fn handle(&mut self, event: Event) -> Vec<Action> {
        // Route event to appropriate sub-state machine
        match &event {
            // Timer events
            Event::CleanupTimer => return self.on_cleanup_timer(),

            // ProposalTimer handles both proposal AND implicit round advancement
            Event::ProposalTimer => {
                // Check if we should advance the round due to timeout
                if self.should_advance_round() {
                    // Reset the timeout so we don't immediately trigger another view change.
                    // Without this, every subsequent timer tick (every 300ms) would trigger
                    // another view change since last_qc_time would still be stale.
                    self.last_qc_time = self.now;

                    let max_txs = self.bft.config().max_transactions_per_block;
                    let txs = self.mempool.ready_transactions(max_txs);
                    let deferred = self.livelock.get_pending_deferrals();
                    let current_height =
                        hyperscale_types::BlockHeight(self.bft.committed_height() + 1);
                    let aborted = self.mempool.get_timed_out_transactions(
                        current_height,
                        30, // execution_timeout_blocks
                        3,  // max_retries
                    );
                    let certificates = self.execution.get_finalized_certificates();

                    tracing::info!("Round timeout - advancing round (implicit view change)");
                    return self
                        .bft
                        .advance_round(&txs, deferred, aborted, certificates);
                }

                // Normal proposal timer - try to propose if we're the proposer
                let max_txs = self.bft.config().max_transactions_per_block;
                let txs = self.mempool.ready_transactions(max_txs);
                // Get pending deferrals from livelock state
                let deferred = self.livelock.get_pending_deferrals();
                // Get timed-out transactions from mempool
                // Config: 30 blocks timeout, max 3 retries (per design Decision #27)
                let current_height = hyperscale_types::BlockHeight(self.bft.committed_height() + 1);
                let aborted = self.mempool.get_timed_out_transactions(
                    current_height,
                    30, // execution_timeout_blocks
                    3,  // max_retries
                );
                // Get finalized certificates (removed when committed in a block)
                let certificates = self.execution.get_finalized_certificates();
                return self
                    .bft
                    .on_proposal_timer(&txs, deferred, aborted, certificates);
            }

            // BlockHeaderReceived needs mempool for transaction lookup and certificates
            Event::BlockHeaderReceived {
                header,
                tx_hashes,
                cert_hashes,
                deferred,
                aborted,
            } => {
                let mempool_txs = self.mempool.transactions_by_hash();
                let local_certs = self.execution.finalized_certificates_by_hash();
                return self.bft.on_block_header(
                    header.clone(),
                    tx_hashes.clone(),
                    cert_hashes.clone(),
                    deferred.clone(),
                    aborted.clone(),
                    &mempool_txs,
                    &local_certs,
                );
            }

            // QuorumCertificateFormed may trigger immediate proposal, so pass mempool
            // Also reset the QC timeout since progress was made
            Event::QuorumCertificateFormed { block_hash, qc } => {
                // Reset timeout - QC formed means progress
                self.last_qc_time = self.now;

                let max_txs = self.bft.config().max_transactions_per_block;
                let txs = self.mempool.ready_transactions(max_txs);
                let deferred = self.livelock.get_pending_deferrals();
                let current_height = hyperscale_types::BlockHeight(self.bft.committed_height() + 1);
                let aborted = self.mempool.get_timed_out_transactions(
                    current_height,
                    30, // execution_timeout_blocks
                    3,  // max_retries
                );
                let certificates = self.execution.get_finalized_certificates();
                return self.bft.on_qc_formed(
                    *block_hash,
                    qc.clone(),
                    &txs,
                    deferred,
                    aborted,
                    certificates,
                );
            }

            // Other BFT events don't need mempool context
            Event::BlockVoteReceived { .. }
            | Event::BlockReadyToCommit { .. }
            | Event::VoteSignatureVerified { .. }
            | Event::QcSignatureVerified { .. } => {
                if let Some(actions) = self.bft.try_handle(&event) {
                    return actions;
                }
            }

            // Block committed needs special handling - notify multiple subsystems
            Event::BlockCommitted {
                block_hash,
                height,
                block,
            } => {
                let mut actions = self.on_block_committed(*height);
                let block_height = hyperscale_types::BlockHeight(*height);

                // Register newly committed cross-shard TXs with livelock for cycle detection.
                // Must happen BEFORE livelock.on_block_committed() processes deferrals.
                for tx in &block.transactions {
                    if self.livelock.is_cross_shard(tx) {
                        self.livelock.on_cross_shard_committed(tx, block_height);
                    }
                }

                // Livelock: process deferrals/aborts/certs, add tombstones, cleanup tracking
                self.livelock.on_block_committed(block);

                // Cleanup execution state for deferred transactions
                // This must happen BEFORE passing new transactions to execution,
                // so that retries can be processed fresh
                for deferral in &block.deferred {
                    self.execution.cleanup_transaction(&deferral.tx_hash);
                }

                // Cleanup execution state for aborted transactions
                for abort in &block.aborted {
                    self.execution.cleanup_transaction(&abort.tx_hash);
                }

                // Remove committed certificates from execution state
                // They've been included in this block, so don't need to be proposed again
                for cert in &block.committed_certificates {
                    self.execution
                        .remove_finalized_certificate(&cert.transaction_hash);
                }

                // Pass transactions directly from block to execution (no need for mempool lookup)
                let exec_actions = self.execution.on_block_committed(
                    *block_hash,
                    *height,
                    block.transactions.clone(),
                );
                actions.extend(exec_actions);

                // Also let mempool handle it (marks transactions as committed, processes deferrals/aborts)
                if let Some(mempool_actions) = self.mempool.try_handle(&event) {
                    actions.extend(mempool_actions);
                }

                return actions;
            }

            // StateProvisionReceived: route to livelock for cycle detection, then execution
            Event::StateProvisionReceived { provision } => {
                // First: cycle detection in livelock (may queue a deferral)
                self.livelock.on_provision_received(provision);

                // Then: pass to execution for quorum tracking
                if let Some(actions) = self.execution.try_handle(&event) {
                    return actions;
                }
            }

            // Other execution events
            Event::TransactionsExecuted { .. }
            | Event::CrossShardTransactionExecuted { .. }
            | Event::StateVoteReceived { .. }
            | Event::StateCertificateReceived { .. }
            | Event::MerkleRootComputed { .. }
            | Event::ProvisionSignatureVerified { .. }
            | Event::StateVoteSignatureVerified { .. }
            | Event::StateCertificateSignatureVerified { .. } => {
                if let Some(actions) = self.execution.try_handle(&event) {
                    return actions;
                }
            }

            // SubmitTransaction needs special handling to add gossip broadcast
            Event::SubmitTransaction { tx } => {
                let mut actions = self.mempool.on_submit_transaction_arc(Arc::clone(tx));

                // Broadcast transaction to all shards involved in this transaction
                let gossip = hyperscale_messages::TransactionGossip::from_arc(Arc::clone(tx));
                for shard in self.topology.all_shards_for_transaction(tx) {
                    actions.push(Action::BroadcastToShard {
                        message: OutboundMessage::TransactionGossip(Box::new(gossip.clone())),
                        shard,
                    });
                }

                return actions;
            }

            // TransactionExecuted is emitted by execution, handled by mempool AND BFT
            // BFT might have pending blocks waiting for this certificate
            Event::TransactionExecuted { tx_hash, .. } => {
                let mut actions = vec![];

                // Notify mempool
                if let Some(mempool_actions) = self.mempool.try_handle(&event) {
                    actions.extend(mempool_actions);
                }

                // Check if any pending blocks are now complete with this certificate
                let local_certs = self.execution.finalized_certificates_by_hash();
                actions.extend(
                    self.bft
                        .check_pending_blocks_for_certificate(*tx_hash, &local_certs),
                );

                return actions;
            }

            // TransactionGossipReceived: add to mempool AND notify BFT
            // The BFT might have pending blocks waiting for this transaction
            Event::TransactionGossipReceived { tx } => {
                let tx_hash = tx.hash();
                let mut actions = self.mempool.on_transaction_gossip_arc(Arc::clone(tx));

                // Check if any pending blocks are now complete
                let mempool_map = self.mempool.as_hash_map();
                actions.extend(
                    self.bft
                        .check_pending_blocks_for_transaction(tx_hash, &mempool_map),
                );

                return actions;
            }

            // Storage callback events - route to appropriate handler
            Event::StateEntriesFetched { .. } => {
                // TODO: Route to execution for provisioning completion
                if let Some(actions) = self.execution.try_handle(&event) {
                    return actions;
                }
            }

            Event::BlockFetched { .. } => {
                // This is for local storage fetch, not sync
                // For now, this is a no-op
            }

            // Sync protocol events
            // Note: SyncNeeded is now Action::StartSync (emitted by BFT, handled by runner).
            // SyncBlockReceived is handled by the runner's SyncManager.
            // The runner sends SyncBlockReadyToApply directly when blocks are ready.
            Event::SyncBlockReceived { .. } => {
                // Runner handles this - should not reach state machine
                tracing::warn!("SyncBlockReceived event reached NodeStateMachine - should be handled by runner");
            }

            Event::SyncBlockReadyToApply { block, qc } => {
                // Apply the synced block to BFT state
                return self.bft.on_synced_block_ready(block.clone(), qc.clone());
            }

            Event::SyncComplete { height } => {
                tracing::info!(height, "Sync complete, resuming normal consensus");
                // Reset round timeout since we've caught up
                self.last_qc_time = self.now;
            }

            Event::ChainMetadataFetched { .. } => {
                // Route to BFT for recovery
                if let Some(actions) = self.bft.try_handle(&event) {
                    return actions;
                }
            }

            // Transaction status changes from execution state machine
            Event::TransactionStatusChanged { .. } => {
                // Route to mempool to update status
                if let Some(actions) = self.mempool.try_handle(&event) {
                    return actions;
                }
            }

            // ═══════════════════════════════════════════════════════════════════════
            // Global Consensus / Epoch Events
            // TODO: Route to GlobalConsensusState when implemented
            // ═══════════════════════════════════════════════════════════════════════
            Event::GlobalConsensusTimer => {
                // Will be handled by GlobalConsensusState
                tracing::trace!("GlobalConsensusTimer - not yet implemented");
            }

            Event::GlobalBlockReceived { epoch, height, .. } => {
                tracing::debug!(?epoch, ?height, "GlobalBlockReceived - not yet implemented");
            }

            Event::GlobalBlockVoteReceived {
                block_hash, shard, ..
            } => {
                tracing::debug!(
                    ?block_hash,
                    ?shard,
                    "GlobalBlockVoteReceived - not yet implemented"
                );
            }

            Event::GlobalQcFormed { block_hash, epoch } => {
                tracing::info!(?block_hash, ?epoch, "GlobalQcFormed - not yet implemented");
            }

            Event::EpochEndApproaching {
                current_epoch,
                end_height,
            } => {
                tracing::info!(
                    ?current_epoch,
                    ?end_height,
                    "EpochEndApproaching - not yet implemented"
                );
                // TODO: Stop accepting new transactions, drain in-flight
            }

            Event::EpochTransitionReady {
                from_epoch,
                to_epoch,
                ..
            } => {
                tracing::info!(
                    ?from_epoch,
                    ?to_epoch,
                    "EpochTransitionReady - not yet implemented"
                );
                // TODO: Update DynamicTopology, notify subsystems
            }

            Event::EpochTransitionComplete {
                new_epoch,
                new_shard,
                is_waiting,
            } => {
                tracing::info!(
                    ?new_epoch,
                    ?new_shard,
                    is_waiting,
                    "EpochTransitionComplete - not yet implemented"
                );
            }

            Event::ValidatorSyncComplete { epoch, shard } => {
                tracing::info!(
                    ?epoch,
                    ?shard,
                    "ValidatorSyncComplete - not yet implemented"
                );
                // TODO: Transition from Waiting to Active state
            }

            Event::ShardSplitInitiated {
                source_shard,
                new_shard,
                split_point,
            } => {
                tracing::info!(
                    ?source_shard,
                    ?new_shard,
                    split_point,
                    "ShardSplitInitiated - not yet implemented"
                );
                // TODO: Mark shard as splitting in topology
            }

            Event::ShardSplitComplete {
                source_shard,
                new_shard,
            } => {
                tracing::info!(
                    ?source_shard,
                    ?new_shard,
                    "ShardSplitComplete - not yet implemented"
                );
            }

            Event::ShardMergeInitiated {
                shard_a,
                shard_b,
                merged_shard,
            } => {
                tracing::info!(
                    ?shard_a,
                    ?shard_b,
                    ?merged_shard,
                    "ShardMergeInitiated - not yet implemented"
                );
            }

            Event::ShardMergeComplete { merged_shard } => {
                tracing::info!(?merged_shard, "ShardMergeComplete - not yet implemented");
            }

            // ═══════════════════════════════════════════════════════════════════════
            // Transaction Fetch Protocol
            // BFT emits Action::FetchTransactions; runner handles retries and delivers results.
            // ═══════════════════════════════════════════════════════════════════════
            Event::TransactionReceived {
                block_hash,
                transactions,
            } => {
                return self
                    .bft
                    .on_transaction_fetch_received(*block_hash, transactions.clone());
            }

            // ═══════════════════════════════════════════════════════════════════════
            // Certificate Fetch Protocol
            // BFT emits Action::FetchCertificates; runner handles retries and delivers results.
            // ═══════════════════════════════════════════════════════════════════════
            Event::CertificateReceived {
                block_hash,
                certificates,
            } => {
                // Verify each fetched certificate's embedded StateCertificates against
                // our current topology. This ensures we don't accept forged certificates
                // from Byzantine peers.
                let mut actions = Vec::new();
                for cert in certificates {
                    actions.extend(
                        self.execution
                            .verify_fetched_certificate(*block_hash, cert.clone()),
                    );
                }
                return actions;
            }

            Event::FetchedCertificateVerified {
                block_hash,
                certificate,
            } => {
                // Cancel local certificate building - we're using the fetched one
                self.execution
                    .cancel_certificate_building(&certificate.transaction_hash);

                // Certificate has been verified - add to pending block
                return self.bft.on_certificate_fetch_received(
                    *block_hash,
                    vec![std::sync::Arc::new(certificate.clone())],
                );
            }
        }

        // Event not handled by any sub-machine
        tracing::warn!(?event, "Unhandled event");
        vec![]
    }

    fn set_time(&mut self, now: Duration) {
        self.now = now;
        self.bft.set_time(now);
        self.execution.set_time(now);
        self.mempool.set_time(now);
        self.livelock.set_time(now);
    }

    fn now(&self) -> Duration {
        self.now
    }
}
