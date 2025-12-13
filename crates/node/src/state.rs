//! Node state machine.

use hyperscale_bft::{BftConfig, BftState, RecoveredState, ViewChangeState};
use hyperscale_core::{Action, Event, OutboundMessage, StateMachine, SubStateMachine};
use hyperscale_execution::ExecutionState;
use hyperscale_livelock::LivelockState;
use hyperscale_mempool::MempoolState;
use hyperscale_sync::{SyncConfig, SyncState};
use hyperscale_types::{Block, KeyPair, ShardGroupId, Topology};
use std::sync::Arc;
use std::time::Duration;

/// Index type for simulation-only node routing.
/// Production uses ValidatorId (from message signatures) and PeerId (libp2p).
pub type NodeIndex = u32;

/// Combined node state machine.
///
/// Composes BFT, view change, execution, mempool, livelock, and sync into a single state machine.
pub struct NodeStateMachine {
    /// This node's index (simulation-only, for routing).
    node_index: NodeIndex,

    /// Network topology (single source of truth).
    topology: Arc<dyn Topology>,

    /// BFT consensus state.
    bft: BftState,

    /// View change state for liveness.
    view_change: ViewChangeState,

    /// Execution state.
    execution: ExecutionState,

    /// Mempool state.
    mempool: MempoolState,

    /// Livelock prevention state (cycle detection for cross-shard TXs).
    livelock: LivelockState,

    /// Sync state for catching up when behind.
    sync: SyncState,

    /// Current time.
    now: Duration,
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
        // Total validators for sync peer selection
        let total_validators = topology.local_committee().len() as u32;

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
            view_change: ViewChangeState::new(
                local_shard,
                signing_key.clone(),
                topology.clone(),
                bft_config.view_change_timeout,
            ),
            execution: ExecutionState::new(topology.clone(), signing_key),
            mempool: MempoolState::new(topology.clone()),
            livelock: LivelockState::new(local_shard, topology),
            sync: SyncState::new(SyncConfig::default(), total_validators),
            now: Duration::ZERO,
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

    /// Get a reference to the view change state.
    pub fn view_change(&self) -> &ViewChangeState {
        &self.view_change
    }

    /// Get a mutable reference to the view change state.
    pub fn view_change_mut(&mut self) -> &mut ViewChangeState {
        &mut self.view_change
    }

    /// Get a reference to the execution state.
    pub fn execution(&self) -> &ExecutionState {
        &self.execution
    }

    /// Get a reference to the sync state.
    pub fn sync(&self) -> &SyncState {
        &self.sync
    }

    /// Get a reference to the livelock state.
    pub fn livelock(&self) -> &LivelockState {
        &self.livelock
    }

    /// Check if we're currently syncing.
    pub fn is_syncing(&self) -> bool {
        self.sync.is_syncing()
    }

    /// Initialize the node with a genesis block.
    ///
    /// Returns actions to be processed (e.g., initial timers).
    pub fn initialize_genesis(&mut self, genesis: Block) -> Vec<Action> {
        let mut actions = self.bft.initialize_genesis(genesis);

        // Also set up the view change timer
        actions.push(Action::SetTimer {
            id: hyperscale_core::TimerId::ViewChange,
            duration: Duration::from_secs(5), // Default view change timeout
        });

        actions
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
    /// This updates view change state to reset timeout on progress,
    /// and notifies sync state of progress.
    fn on_block_committed(&mut self, height: u64) -> Vec<Action> {
        // Reset view change timeout on progress
        self.view_change.reset_timeout(height + 1); // Next height to work on

        // Update highest QC in view change state
        if let Some(qc) = self.bft.latest_qc() {
            self.view_change.update_highest_qc(qc.clone());
        }

        // Notify sync state of committed height and get any follow-up actions
        // (e.g., sending the next synced block for verification)
        self.sync.set_committed_height(height)
    }
}

impl StateMachine for NodeStateMachine {
    fn handle(&mut self, event: Event) -> Vec<Action> {
        // Route event to appropriate sub-state machine
        match &event {
            // Timer events
            Event::CleanupTimer => return self.on_cleanup_timer(),

            // View change timer goes to ViewChangeState
            Event::ViewChangeTimer => {
                return self.view_change.on_view_change_timer();
            }

            // View change votes and certificates go to ViewChangeState
            Event::ViewChangeVoteReceived { vote } => {
                // Check if the vote is for a higher height - this means we're behind
                // and need to sync before we can participate in view change.
                let vote_height = vote.height.0;
                let our_height = self.bft.committed_height();

                if vote_height > our_height + 1 {
                    // We're significantly behind - trigger sync using the highest_qc from the vote
                    // The vote's highest_qc tells us what blocks the sender has committed
                    let highest_qc = &vote.highest_qc;
                    if !highest_qc.is_genesis() && highest_qc.height.0 > our_height {
                        tracing::info!(
                            our_height,
                            vote_height,
                            qc_height = highest_qc.height.0,
                            "Detected we're behind from view change vote, triggering sync"
                        );
                        return vec![Action::EnqueueInternal {
                            event: Event::SyncNeeded {
                                target_height: highest_qc.height.0,
                                target_hash: highest_qc.block_hash,
                            },
                        }];
                    }
                }

                // Delegate verification to runner (async)
                return self.view_change.on_view_change_vote(vote.clone());
            }

            // View change vote signature verification completed
            Event::ViewChangeVoteSignatureVerified { vote, valid } => {
                let mut actions = self
                    .view_change
                    .on_vote_signature_verified(vote.clone(), *valid);

                // Check if quorum was reached (ViewChangeQuorumReached will be in actions)
                for action in &actions {
                    if let Action::EnqueueInternal {
                        event: Event::ViewChangeQuorumReached { height, new_round },
                    } = action
                    {
                        // Apply view change when quorum is reached
                        tracing::info!(height, new_round, "View change quorum reached");
                        actions.extend(self.view_change.apply_view_change(*height, *new_round));
                        break;
                    }
                }
                return actions;
            }

            // View change highest QC verification completed
            Event::ViewChangeHighestQcVerified { vote, valid } => {
                let mut actions = self
                    .view_change
                    .on_highest_qc_verified(vote.clone(), *valid);

                // Check if quorum was reached (ViewChangeQuorumReached will be in actions)
                for action in &actions {
                    if let Action::EnqueueInternal {
                        event: Event::ViewChangeQuorumReached { height, new_round },
                    } = action
                    {
                        // Apply view change when quorum is reached
                        tracing::info!(height, new_round, "View change quorum reached");
                        actions.extend(self.view_change.apply_view_change(*height, *new_round));
                        break;
                    }
                }
                return actions;
            }

            // View change certificate signature verification completed
            Event::ViewChangeCertificateSignatureVerified { certificate, valid } => {
                return self
                    .view_change
                    .on_certificate_signature_verified(certificate.clone(), *valid);
            }

            Event::ViewChangeCertificateReceived { cert } => {
                // Check if the certificate is for a higher height - this means we're behind
                let cert_height = cert.height.0;
                let our_height = self.bft.committed_height();

                if cert_height > our_height + 1 {
                    // We're significantly behind - trigger sync using the highest_qc from the cert
                    let highest_qc = &cert.highest_qc;
                    if !highest_qc.is_genesis() && highest_qc.height.0 > our_height {
                        tracing::info!(
                            our_height,
                            cert_height,
                            qc_height = highest_qc.height.0,
                            "Detected we're behind from view change certificate, triggering sync"
                        );
                        return vec![Action::EnqueueInternal {
                            event: Event::SyncNeeded {
                                target_height: highest_qc.height.0,
                                target_hash: highest_qc.block_hash,
                            },
                        }];
                    }
                }

                return self.view_change.on_view_change_certificate(cert.clone());
            }

            // ProposalTimer needs mempool transactions, pending deferrals, aborts, and certificates
            Event::ProposalTimer => {
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
            Event::QuorumCertificateFormed { block_hash, qc } => {
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

            // ViewChangeQuorumReached is an internal signal that's already handled
            // in the verification callback handlers above. If it somehow gets enqueued
            // separately, we can safely ignore it (quorum was already applied).
            Event::ViewChangeQuorumReached { .. } => {
                return vec![];
            }

            // Other BFT events don't need mempool context
            Event::BlockVoteReceived { .. }
            | Event::BlockReadyToCommit { .. }
            | Event::VoteSignatureVerified { .. }
            | Event::QcSignatureVerified { .. }
            | Event::ViewChangeCompleted { .. } => {
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

                // Broadcast transaction to all validators in our shard
                let gossip = hyperscale_messages::TransactionGossip::from_arc(Arc::clone(tx));
                actions.push(Action::BroadcastToShard {
                    message: OutboundMessage::TransactionGossip(Box::new(gossip)),
                    shard: self.shard(),
                });

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
            Event::SyncNeeded {
                target_height,
                target_hash,
            } => {
                return self.sync.on_sync_needed(*target_height, *target_hash);
            }

            Event::SyncBlockReceived { block, qc } => {
                return self.sync.on_block_received(block.clone(), qc.clone());
            }

            Event::SyncBlockReadyToApply { block, qc } => {
                // Apply the synced block to BFT state
                return self.bft.on_synced_block_ready(block.clone(), qc.clone());
            }

            Event::SyncComplete { height } => {
                tracing::info!(height, "Sync complete, resuming normal consensus");
                // Cancel sync state (if not already done)
                let actions = self.sync.cancel_sync();
                // Reset view change timeout since we've caught up
                self.view_change.reset_timeout(*height + 1);
                return actions;
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
            // ═══════════════════════════════════════════════════════════════════════
            Event::TransactionFetchTimer { block_hash } => {
                return self.bft.on_transaction_fetch_timer(*block_hash);
            }

            Event::TransactionFetchNeeded {
                block_hash,
                proposer,
                missing_tx_hashes,
            } => {
                // The runner will handle this by making a request to the proposer or peers.
                // Return an action that signals the runner to fetch transactions.
                tracing::info!(
                    block_hash = ?block_hash,
                    proposer = ?proposer,
                    missing_count = missing_tx_hashes.len(),
                    "Transaction fetch needed - runner should request from peer"
                );
                // Return the event as-is in an action for the runner to handle.
                // The runner will make the network request and deliver TransactionFetchReceived.
                return vec![Action::EnqueueInternal {
                    event: Event::TransactionFetchNeeded {
                        block_hash: *block_hash,
                        proposer: *proposer,
                        missing_tx_hashes: missing_tx_hashes.clone(),
                    },
                }];
            }

            Event::TransactionFetchReceived {
                block_hash,
                transactions,
            } => {
                return self
                    .bft
                    .on_transaction_fetch_received(*block_hash, transactions.clone());
            }
        }

        // Event not handled by any sub-machine
        tracing::warn!(?event, "Unhandled event");
        vec![]
    }

    fn set_time(&mut self, now: Duration) {
        self.now = now;
        self.bft.set_time(now);
        self.view_change.set_time(now);
        self.execution.set_time(now);
        self.mempool.set_time(now);
        self.livelock.set_time(now);
        self.sync.set_time(now);
    }

    fn now(&self) -> Duration {
        self.now
    }
}
