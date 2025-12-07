//! Production runner implementation.

use crate::network::{InboundSyncRequest, Libp2pAdapter, Libp2pConfig, NetworkError};
use crate::storage::RocksDbStorage;
use crate::sync::{SyncConfig, SyncManager};
use crate::thread_pools::ThreadPoolManager;
use crate::timers::TimerManager;
use hyperscale_bft::BftConfig;
use hyperscale_core::TransactionStatus;
use hyperscale_engine::{NetworkDefinition, RadixExecutor};
use hyperscale_types::BlockHeight;

// Re-export NodeIndex from node crate (simulation-only concept).
// Production code will use ValidatorId from topology instead.
use hyperscale_core::{Action, Event, RequestId, StateMachine};
pub use hyperscale_node::NodeIndex;
use hyperscale_node::NodeStateMachine;
use hyperscale_types::{KeyPair, RoutableTransaction, ShardGroupId, Topology};
use libp2p::identity;
use parking_lot::RwLock;
use sbor::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

/// Errors from the production runner.
#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("Event channel closed")]
    ChannelClosed,
    #[error("Request dropped")]
    RequestDropped,
    #[error("Send error: {0}")]
    SendError(String),
    #[error("Network error: {0}")]
    NetworkError(#[from] NetworkError),
}

/// Handle for shutting down a running ProductionRunner.
///
/// When dropped, signals the runner to exit gracefully.
#[derive(Debug)]
pub struct ShutdownHandle {
    tx: Option<oneshot::Sender<()>>,
}

impl ShutdownHandle {
    /// Trigger shutdown (consumes the handle).
    pub fn shutdown(mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for ShutdownHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Production runner with async I/O.
///
/// Uses the event aggregator pattern: a single task owns the state machine
/// and receives events via an mpsc channel.
///
/// # Thread Pool Configuration
///
/// The runner uses configurable thread pools for different workloads:
/// - **Crypto Pool**: BLS signature verification (CPU-bound)
/// - **Execution Pool**: Transaction execution via Radix Engine (CPU/memory)
/// - **I/O Pool**: Network, storage, timers (tokio runtime)
///
/// Use `ThreadPoolConfig` to customize core allocation, or use defaults
/// based on available CPU cores.
pub struct ProductionRunner {
    /// Receives events from all sources.
    event_rx: mpsc::Receiver<Event>,
    /// Clone this to send events from network, timers, callbacks.
    event_tx: mpsc::Sender<Event>,
    /// The state machine (owned, not shared).
    state: NodeStateMachine,
    /// Start time for calculating elapsed duration.
    start_time: Instant,
    /// Pending client requests awaiting response.
    pending_requests: HashMap<RequestId, oneshot::Sender<TransactionStatus>>,
    /// Next request ID.
    next_request_id: u64,
    /// Thread pool manager for crypto and execution workloads.
    thread_pools: Arc<ThreadPoolManager>,
    /// Timer manager for setting/cancelling timers.
    timer_manager: TimerManager,
    /// Network adapter (optional - None for testing without network).
    network: Option<Arc<Libp2pAdapter>>,
    /// Sync manager for fetching blocks from peers (optional - requires network).
    sync_manager: Option<SyncManager>,
    /// Local shard for network broadcasts.
    local_shard: ShardGroupId,
    /// Network topology (needed for cross-shard execution).
    topology: Arc<dyn Topology>,
    /// Block storage (optional - None for testing without persistence).
    /// Wrapped in RwLock for thread-safe mutable access from execution thread pool.
    storage: Option<Arc<RwLock<RocksDbStorage>>>,
    /// Transaction executor (optional - requires storage).
    executor: Option<Arc<RadixExecutor>>,
    /// Inbound sync request channel (from network adapter).
    sync_request_rx: Option<mpsc::Receiver<InboundSyncRequest>>,
    /// Shutdown signal receiver.
    shutdown_rx: oneshot::Receiver<()>,
    /// Shutdown handle sender (stored to return to caller).
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl ProductionRunner {
    /// Create a new production runner with default thread pool configuration.
    ///
    /// Uses `ThreadPoolConfig::auto()` to detect available cores and allocate
    /// threads using recommended ratios.
    pub fn new(
        node_index: NodeIndex,
        topology: Arc<dyn Topology>,
        signing_key: KeyPair,
        bft_config: BftConfig,
        channel_capacity: usize,
    ) -> Result<Self, RunnerError> {
        let thread_pools =
            ThreadPoolManager::auto().map_err(|e| RunnerError::SendError(e.to_string()))?;
        Self::with_thread_pools(
            node_index,
            topology,
            signing_key,
            bft_config,
            channel_capacity,
            Arc::new(thread_pools),
        )
    }

    /// Create a new production runner with custom thread pool configuration.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use hyperscale_production::{ProductionRunner, ThreadPoolConfig, ThreadPoolManager};
    /// use std::sync::Arc;
    ///
    /// let config = ThreadPoolConfig::builder()
    ///     .crypto_threads(4)
    ///     .execution_threads(8)
    ///     .io_threads(2)
    ///     .build()
    ///     .unwrap();
    ///
    /// let thread_pools = Arc::new(ThreadPoolManager::new(config).unwrap());
    ///
    /// // let runner = ProductionRunner::with_thread_pools(..., thread_pools);
    /// ```
    pub fn with_thread_pools(
        node_index: NodeIndex,
        topology: Arc<dyn Topology>,
        signing_key: KeyPair,
        bft_config: BftConfig,
        channel_capacity: usize,
        thread_pools: Arc<ThreadPoolManager>,
    ) -> Result<Self, RunnerError> {
        let (event_tx, event_rx) = mpsc::channel(channel_capacity);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let local_shard = topology.local_shard();
        let state = NodeStateMachine::new(node_index, topology.clone(), signing_key, bft_config);
        let timer_manager = TimerManager::new(event_tx.clone());

        Ok(Self {
            event_rx,
            event_tx,
            state,
            start_time: Instant::now(),
            pending_requests: HashMap::new(),
            next_request_id: 0,
            thread_pools,
            timer_manager,
            network: None,
            sync_manager: None,
            local_shard,
            topology,
            storage: None,
            executor: None,
            sync_request_rx: None,
            shutdown_rx,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    /// Create a new production runner with network support.
    ///
    /// This is the full-featured constructor that includes libp2p networking.
    /// Use this for production deployments.
    ///
    /// # Arguments
    ///
    /// * `storage` - Optional RocksDB storage for block persistence and serving sync requests
    #[allow(clippy::too_many_arguments)]
    pub async fn with_network(
        node_index: NodeIndex,
        topology: Arc<dyn Topology>,
        signing_key: KeyPair,
        bft_config: BftConfig,
        channel_capacity: usize,
        thread_pools: Arc<ThreadPoolManager>,
        network_config: Libp2pConfig,
        ed25519_keypair: identity::Keypair,
        storage: Option<Arc<RwLock<RocksDbStorage>>>,
    ) -> Result<Self, RunnerError> {
        let (event_tx, event_rx) = mpsc::channel(channel_capacity);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let validator_id = topology.local_validator_id();
        let local_shard = topology.local_shard();
        let state = NodeStateMachine::new(node_index, topology.clone(), signing_key, bft_config);
        let timer_manager = TimerManager::new(event_tx.clone());

        // Create network adapter (returns both adapter and sync request receiver)
        let (network, sync_request_rx) = Libp2pAdapter::new(
            network_config,
            ed25519_keypair,
            validator_id,
            local_shard,
            event_tx.clone(),
        )
        .await?;

        // Subscribe to local shard topics
        network.subscribe_shard(local_shard).await?;

        // Create sync manager
        let sync_manager =
            SyncManager::new(SyncConfig::default(), network.clone(), event_tx.clone());

        // Create executor if storage is provided
        // Note: Using simulator network for now - production should use mainnet
        let executor = storage
            .as_ref()
            .map(|_| Arc::new(RadixExecutor::new(NetworkDefinition::simulator())));

        // Register all validators for peer validation
        // Note: In production, we'd derive PeerId from ed25519 public keys in topology
        // For now, this is a placeholder - validators need to be registered separately

        Ok(Self {
            event_rx,
            event_tx,
            state,
            start_time: Instant::now(),
            pending_requests: HashMap::new(),
            next_request_id: 0,
            thread_pools,
            timer_manager,
            network: Some(network),
            sync_manager: Some(sync_manager),
            local_shard,
            topology,
            storage,
            executor,
            sync_request_rx: Some(sync_request_rx),
            shutdown_rx,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    /// Get a reference to the thread pool manager.
    pub fn thread_pools(&self) -> &Arc<ThreadPoolManager> {
        &self.thread_pools
    }

    /// Get a reference to the network adapter (if configured).
    pub fn network(&self) -> Option<&Arc<Libp2pAdapter>> {
        self.network.as_ref()
    }

    /// Get the local shard ID.
    pub fn local_shard(&self) -> ShardGroupId {
        self.local_shard
    }

    /// Get a sender for submitting events.
    pub fn event_sender(&self) -> mpsc::Sender<Event> {
        self.event_tx.clone()
    }

    /// Take the shutdown handle.
    ///
    /// Returns a handle that when dropped triggers graceful shutdown.
    /// Can only be called once; subsequent calls return None.
    pub fn shutdown_handle(&mut self) -> Option<ShutdownHandle> {
        self.shutdown_tx
            .take()
            .map(|tx| ShutdownHandle { tx: Some(tx) })
    }

    /// Get a mutable reference to the sync manager (if configured).
    pub fn sync_manager_mut(&mut self) -> Option<&mut SyncManager> {
        self.sync_manager.as_mut()
    }

    /// Check if sync is in progress.
    pub fn is_syncing(&self) -> bool {
        self.sync_manager.as_ref().is_some_and(|s| s.is_syncing())
    }

    /// Run the main event loop.
    ///
    /// This should be spawned as a task. It runs until the event channel closes.
    ///
    /// The state machine runs on the current thread (the caller should ensure
    /// this is pinned to a dedicated core if desired). Crypto and execution
    /// work is dispatched to the configured thread pools.
    ///
    /// # Priority Handling
    ///
    /// Consensus events (from gossipsub) are prioritized over sync requests:
    /// - Uses `biased` select to always check consensus channel first
    /// - Drains up to `CONSENSUS_BATCH_SIZE` events before checking sync
    /// - Ensures consensus stays responsive under sync load
    pub async fn run(mut self) -> Result<(), RunnerError> {
        // Maximum consensus events to process before checking sync (10:1 ratio)
        const CONSENSUS_BATCH_SIZE: usize = 10;

        let config = self.thread_pools.config();
        tracing::info!(
            node_index = self.state.node_index(),
            shard = ?self.state.shard(),
            crypto_threads = config.crypto_threads,
            execution_threads = config.execution_threads,
            io_threads = config.io_threads,
            pin_cores = config.pin_cores,
            "Starting production runner"
        );

        // Sync tick interval (100ms)
        let mut sync_tick = tokio::time::interval(Duration::from_millis(100));
        sync_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Track consecutive consensus events for batch limiting
        let mut consensus_batch_count: usize = 0;

        loop {
            // We need to handle the sync_request_rx conditionally since it's Option
            // Use a helper async block that returns None if the receiver is None
            let sync_request_future = async {
                if let Some(rx) = &mut self.sync_request_rx {
                    rx.recv().await
                } else {
                    // Never resolve if there's no receiver
                    std::future::pending::<Option<InboundSyncRequest>>().await
                }
            };

            // Use biased select for priority: consensus events are always checked first.
            // After CONSENSUS_BATCH_SIZE events, we yield to sync to prevent starvation.
            tokio::select! {
                biased;

                // SHUTDOWN: Always check shutdown first (highest priority)
                _ = &mut self.shutdown_rx => {
                    tracing::info!("Shutdown signal received");
                    break;
                }

                // HIGH PRIORITY: Handle incoming consensus events
                // Only check this branch if we haven't hit the batch limit
                event = self.event_rx.recv(), if consensus_batch_count < CONSENSUS_BATCH_SIZE => {
                    match event {
                        Some(event) => {
                            consensus_batch_count += 1;

                            // Update time
                            let now = self.start_time.elapsed();
                            self.state.set_time(now);

                            // Check for SyncNeeded - handle specially
                            let sync_target = if let Event::SyncNeeded { target_height, target_hash } = &event {
                                Some((*target_height, *target_hash))
                            } else {
                                None
                            };

                            // Process event synchronously (fast)
                            let actions = self.state.handle(event);

                            // Execute actions
                            for action in actions {
                                if let Err(e) = self.process_action(action).await {
                                    tracing::error!(error = ?e, "Error processing action");
                                }
                            }

                            // If this was a sync request, start the sync manager
                            if let Some((target_height, target_hash)) = sync_target {
                                if let Some(sync_mgr) = &mut self.sync_manager {
                                    sync_mgr.start_sync(target_height, target_hash);
                                }
                            }
                        }
                        None => {
                            // Channel closed, exit loop
                            break;
                        }
                    }
                }

                // LOW PRIORITY: Handle inbound sync requests from peers
                // This branch is checked when consensus is idle OR after batch limit hit
                Some(request) = sync_request_future => {
                    self.handle_inbound_sync_request(request);
                    // Reset batch counter - we yielded to sync, now back to prioritizing consensus
                    consensus_batch_count = 0;
                }

                // MEDIUM PRIORITY: Periodic sync manager tick
                // This drives outbound sync fetches, so give it some priority
                _ = sync_tick.tick() => {
                    if let Some(sync_mgr) = &mut self.sync_manager {
                        sync_mgr.tick().await;
                    }
                    // Reset batch counter - we yielded, now back to prioritizing consensus
                    consensus_batch_count = 0;
                }
            }
        }

        tracing::info!("Production runner stopped");
        Ok(())
    }

    /// Process an action.
    async fn process_action(&mut self, action: Action) -> Result<(), RunnerError> {
        match action {
            // Network I/O - broadcast via gossipsub topics
            Action::BroadcastToShard { shard, message } => {
                if let Some(network) = &self.network {
                    network.broadcast_shard(shard, &message).await?;
                    tracing::debug!(?shard, msg_type = message.type_name(), "Broadcast to shard");
                } else {
                    tracing::debug!(
                        ?shard,
                        msg_type = message.type_name(),
                        "Would broadcast to shard (network not configured)"
                    );
                }
            }

            Action::BroadcastGlobal { message } => {
                if let Some(network) = &self.network {
                    network.broadcast_global(&message).await?;
                    tracing::debug!(msg_type = message.type_name(), "Broadcast globally");
                } else {
                    tracing::debug!(
                        msg_type = message.type_name(),
                        "Would broadcast globally (network not configured)"
                    );
                }
            }

            // Timers via timer manager
            Action::SetTimer { id, duration } => {
                self.timer_manager.set_timer(id, duration);
            }

            Action::CancelTimer { id } => {
                self.timer_manager.cancel_timer(id);
            }

            // Crypto verification on dedicated crypto thread pool
            Action::VerifyVoteSignature {
                vote,
                public_key,
                signing_message,
            } => {
                let event_tx = self.event_tx.clone();
                self.thread_pools.spawn_crypto(move || {
                    // Verify vote signature against domain-separated message
                    let valid = public_key.verify(&signing_message, &vote.signature);
                    let _ = event_tx.blocking_send(Event::VoteSignatureVerified { vote, valid });
                });
            }

            Action::VerifyProvisionSignature {
                provision,
                public_key,
            } => {
                let event_tx = self.event_tx.clone();
                self.thread_pools.spawn_crypto(move || {
                    // Build signing message (must match ExecutionState::sign_provision)
                    let mut msg = Vec::new();
                    msg.extend_from_slice(b"STATE_PROVISION");
                    msg.extend_from_slice(provision.transaction_hash.as_bytes());
                    msg.extend_from_slice(&provision.target_shard.0.to_le_bytes());
                    msg.extend_from_slice(&provision.source_shard.0.to_le_bytes());
                    msg.extend_from_slice(&provision.block_height.0.to_le_bytes());
                    for entry in &provision.entries {
                        msg.extend_from_slice(entry.hash().as_bytes());
                    }

                    let valid = public_key.verify(&msg, &provision.signature);
                    let _ = event_tx
                        .blocking_send(Event::ProvisionSignatureVerified { provision, valid });
                });
            }

            Action::VerifyStateVoteSignature { vote, public_key } => {
                let event_tx = self.event_tx.clone();
                self.thread_pools.spawn_crypto(move || {
                    // Build signing message (must match ExecutionState::create_vote)
                    let mut msg = Vec::new();
                    msg.extend_from_slice(b"EXEC_VOTE");
                    msg.extend_from_slice(vote.transaction_hash.as_bytes());
                    msg.extend_from_slice(vote.state_root.as_bytes());
                    msg.extend_from_slice(&vote.shard_group_id.0.to_le_bytes());
                    msg.push(if vote.success { 1 } else { 0 });

                    let valid = public_key.verify(&msg, &vote.signature);
                    let _ =
                        event_tx.blocking_send(Event::StateVoteSignatureVerified { vote, valid });
                });
            }

            Action::VerifyStateCertificateSignature {
                certificate,
                public_keys,
            } => {
                let event_tx = self.event_tx.clone();
                self.thread_pools.spawn_crypto(move || {
                    // Build signing message
                    let mut msg = Vec::new();
                    msg.extend_from_slice(b"STATE_CERT");
                    msg.extend_from_slice(certificate.transaction_hash.as_bytes());
                    msg.extend_from_slice(certificate.outputs_merkle_root.as_bytes());
                    msg.extend_from_slice(&certificate.shard_group_id.0.to_le_bytes());
                    msg.push(if certificate.success { 1 } else { 0 });

                    // Get signer keys based on bitfield
                    let signer_keys: Vec<_> = public_keys
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| certificate.signers.is_set(*i))
                        .map(|(_, pk)| pk.clone())
                        .collect();

                    let valid = if signer_keys.is_empty() {
                        // No signers - valid only if zero signature (single-shard case)
                        certificate.aggregated_signature == hyperscale_types::Signature::zero()
                    } else {
                        // Verify aggregated BLS signature
                        match hyperscale_types::PublicKey::aggregate_bls(&signer_keys) {
                            Ok(aggregated_pk) => {
                                aggregated_pk.verify(&msg, &certificate.aggregated_signature)
                            }
                            Err(_) => false,
                        }
                    };

                    let _ = event_tx.blocking_send(Event::StateCertificateSignatureVerified {
                        certificate,
                        valid,
                    });
                });
            }

            Action::VerifyQcSignature {
                qc,
                public_keys,
                block_hash,
                signing_message,
            } => {
                let event_tx = self.event_tx.clone();
                self.thread_pools.spawn_crypto(move || {
                    // Get signer keys based on QC's signer bitfield
                    let signer_keys: Vec<_> = public_keys
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| qc.signers.is_set(*i))
                        .map(|(_, pk)| pk.clone())
                        .collect();

                    let valid = if signer_keys.is_empty() {
                        // No signers - invalid QC (genesis is handled before action is emitted)
                        false
                    } else {
                        // Verify aggregated BLS signature against domain-separated message
                        match hyperscale_types::PublicKey::aggregate_bls(&signer_keys) {
                            Ok(aggregated_pk) => {
                                aggregated_pk.verify(&signing_message, &qc.aggregated_signature)
                            }
                            Err(_) => false,
                        }
                    };

                    let _ =
                        event_tx.blocking_send(Event::QcSignatureVerified { block_hash, valid });
                });
            }

            Action::VerifyViewChangeVoteSignature {
                vote,
                public_key,
                signing_message,
            } => {
                let event_tx = self.event_tx.clone();
                self.thread_pools.spawn_crypto(move || {
                    let valid = public_key.verify(&signing_message, &vote.signature);
                    let _ = event_tx
                        .blocking_send(Event::ViewChangeVoteSignatureVerified { vote, valid });
                });
            }

            Action::VerifyViewChangeHighestQc {
                vote,
                public_keys,
                signing_message,
            } => {
                let event_tx = self.event_tx.clone();
                self.thread_pools.spawn_crypto(move || {
                    // Get signer keys based on the highest_qc's signer bitfield
                    let signer_keys: Vec<_> = public_keys
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| vote.highest_qc.signers.is_set(*i))
                        .map(|(_, pk)| pk.clone())
                        .collect();

                    let valid = if signer_keys.is_empty() {
                        false
                    } else {
                        // Verify against domain-separated signing message
                        match hyperscale_types::PublicKey::aggregate_bls(&signer_keys) {
                            Ok(aggregated_pk) => aggregated_pk
                                .verify(&signing_message, &vote.highest_qc.aggregated_signature),
                            Err(_) => false,
                        }
                    };

                    let _ =
                        event_tx.blocking_send(Event::ViewChangeHighestQcVerified { vote, valid });
                });
            }

            // Transaction execution on dedicated execution thread pool
            Action::ExecuteTransactions {
                block_hash,
                transactions,
                state_root: _,
            } => {
                let event_tx = self.event_tx.clone();
                let storage = self.storage.clone();
                let executor = self.executor.clone();

                self.thread_pools.spawn_execution(move || {
                    let results = match (storage, executor) {
                        (Some(storage), Some(executor)) => {
                            // Execute transactions with write lock on storage
                            let mut storage_guard = storage.write();
                            match executor.execute_single_shard(&mut *storage_guard, &transactions) {
                                Ok(output) => output
                                    .results()
                                    .iter()
                                    .map(|r| hyperscale_types::ExecutionResult {
                                        transaction_hash: r.tx_hash,
                                        success: r.success,
                                        state_root: r.outputs_merkle_root,
                                        writes: r.state_writes.clone(),
                                        error: r.error.clone(),
                                    })
                                    .collect(),
                                Err(e) => {
                                    tracing::warn!(?block_hash, error = %e, "Transaction execution failed");
                                    transactions
                                        .iter()
                                        .map(|tx| hyperscale_types::ExecutionResult {
                                            transaction_hash: tx.hash(),
                                            success: false,
                                            state_root: hyperscale_types::Hash::ZERO,
                                            writes: vec![],
                                            error: Some(format!("{}", e)),
                                        })
                                        .collect()
                                }
                            }
                        }
                        _ => {
                            tracing::warn!("No storage/executor configured, returning failed results");
                            transactions
                                .iter()
                                .map(|tx| hyperscale_types::ExecutionResult {
                                    transaction_hash: tx.hash(),
                                    success: false,
                                    state_root: hyperscale_types::Hash::ZERO,
                                    writes: vec![],
                                    error: Some("No executor configured".to_string()),
                                })
                                .collect()
                        }
                    };

                    let _ = event_tx.blocking_send(Event::TransactionsExecuted {
                        block_hash,
                        results,
                    });
                });
            }

            // Cross-shard transaction execution with provisions
            Action::ExecuteCrossShardTransaction {
                tx_hash,
                transaction,
                provisions,
            } => {
                let event_tx = self.event_tx.clone();
                let storage = self.storage.clone();
                let executor = self.executor.clone();
                let topology = self.topology.clone();
                let local_shard = self.local_shard;

                self.thread_pools.spawn_execution(move || {
                    let result = match (storage, executor) {
                        (Some(storage), Some(executor)) => {
                            // Determine which nodes are local to this shard
                            let is_local_node = |node_id: &hyperscale_types::NodeId| -> bool {
                                topology.shard_for_node_id(node_id) == local_shard
                            };

                            // Execute with provisions
                            let mut storage_guard = storage.write();
                            match executor.execute_cross_shard(
                                &mut *storage_guard,
                                &[transaction],
                                &provisions,
                                is_local_node,
                            ) {
                                Ok(output) => {
                                    if let Some(r) = output.results().first() {
                                        hyperscale_types::ExecutionResult {
                                            transaction_hash: r.tx_hash,
                                            success: r.success,
                                            state_root: r.outputs_merkle_root,
                                            writes: r.state_writes.clone(),
                                            error: r.error.clone(),
                                        }
                                    } else {
                                        hyperscale_types::ExecutionResult {
                                            transaction_hash: tx_hash,
                                            success: false,
                                            state_root: hyperscale_types::Hash::ZERO,
                                            writes: vec![],
                                            error: Some("No execution result".to_string()),
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(?tx_hash, error = %e, "Cross-shard execution failed");
                                    hyperscale_types::ExecutionResult {
                                        transaction_hash: tx_hash,
                                        success: false,
                                        state_root: hyperscale_types::Hash::ZERO,
                                        writes: vec![],
                                        error: Some(format!("{}", e)),
                                    }
                                }
                            }
                        }
                        _ => {
                            tracing::warn!("No storage/executor configured for cross-shard execution");
                            hyperscale_types::ExecutionResult {
                                transaction_hash: tx_hash,
                                success: false,
                                state_root: hyperscale_types::Hash::ZERO,
                                writes: vec![],
                                error: Some("No executor configured".to_string()),
                            }
                        }
                    };

                    let _ = event_tx.blocking_send(Event::CrossShardTransactionExecuted {
                        tx_hash,
                        result,
                    });
                });
            }

            // Merkle computation on execution pool (can be parallelized internally)
            // Note: This action is currently not emitted by any state machine.
            Action::ComputeMerkleRoot { tx_hash, writes } => {
                let event_tx = self.event_tx.clone();

                self.thread_pools.spawn_execution(move || {
                    // Simple merkle root computation using hash chain
                    // A proper implementation would use a sparse Merkle tree
                    let root = if writes.is_empty() {
                        hyperscale_types::Hash::ZERO
                    } else {
                        // Sort writes for determinism
                        let mut sorted = writes;
                        sorted.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));

                        // Hash chain
                        let mut data = Vec::new();
                        for (node_id, value) in &sorted {
                            data.extend_from_slice(&node_id.0);
                            data.extend_from_slice(value);
                        }
                        hyperscale_types::Hash::from_bytes(&data)
                    };
                    let _ = event_tx.blocking_send(Event::MerkleRootComputed { tx_hash, root });
                });
            }

            // Internal events go back through the channel
            Action::EnqueueInternal { event } => {
                self.event_tx
                    .send(event)
                    .await
                    .map_err(|e| RunnerError::SendError(e.to_string()))?;
            }

            // Client responses
            Action::EmitTransactionResult { request_id, result } => {
                if let Some(tx) = self.pending_requests.remove(&request_id) {
                    // Map TransactionDecision to TransactionStatus::Finalized
                    // Finalized means the decision (Accept/Reject) has been made
                    let _ = tx.send(TransactionStatus::Finalized(result));
                }
                tracing::debug!(?request_id, ?result, "Transaction result");
            }

            Action::EmitTransactionStatus {
                request_id,
                tx_hash,
                status,
            } => {
                tracing::debug!(?request_id, ?tx_hash, ?status, "Transaction status");
                // TODO: Route to status subscribers
            }

            Action::EmitCommittedBlock { block } => {
                tracing::info!(block_hash = ?block.hash(), "Block committed");
                // TODO: Notify subscribers
            }

            // Storage writes
            Action::PersistBlock { block: _, qc: _ } => {
                // TODO: self.storage.persist_block(&block, &qc).await;
            }

            Action::PersistTransactionCertificate { certificate: _ } => {
                // TODO: self.storage.persist_certificate(&certificate).await;
            }

            Action::PersistSubstateWrites {
                tx_hash: _,
                writes: _,
            } => {
                // TODO: self.storage.persist_substate_writes(&tx_hash, &writes).await;
            }

            // Storage reads - delegate to async storage, send callback event
            Action::FetchStateEntries { tx_hash, nodes: _ } => {
                // TODO: Implement async storage fetch
                // let entries = self.storage.fetch_state_entries(&nodes).await;
                let entries = vec![];
                let _ = self
                    .event_tx
                    .send(Event::StateEntriesFetched { tx_hash, entries })
                    .await;
            }

            Action::FetchBlock { height } => {
                // TODO: Implement async storage fetch
                // let block = self.storage.fetch_block(height).await;
                let block = None;
                let _ = self
                    .event_tx
                    .send(Event::BlockFetched { height, block })
                    .await;
            }

            Action::FetchChainMetadata => {
                // TODO: Implement async storage fetch
                // let (height, hash, qc) = self.storage.fetch_chain_metadata().await;
                let _ = self
                    .event_tx
                    .send(Event::ChainMetadataFetched {
                        height: hyperscale_types::BlockHeight(0),
                        hash: None,
                        qc: None,
                    })
                    .await;
            }
        }

        Ok(())
    }

    /// Submit a transaction and wait for result.
    pub async fn submit_transaction(
        &mut self,
        tx: RoutableTransaction,
    ) -> Result<TransactionStatus, RunnerError> {
        let request_id = RequestId(self.next_request_id);
        self.next_request_id += 1;

        let (response_tx, response_rx) = oneshot::channel();
        self.pending_requests.insert(request_id, response_tx);

        // Send event to the state machine
        self.event_tx
            .send(Event::SubmitTransaction { tx, request_id })
            .await
            .map_err(|e| RunnerError::SendError(e.to_string()))?;

        // Wait for response
        response_rx.await.map_err(|_| RunnerError::RequestDropped)
    }

    /// Handle an inbound sync request from a peer.
    ///
    /// Looks up the requested block from storage and sends the response
    /// back via the network adapter.
    fn handle_inbound_sync_request(&self, request: InboundSyncRequest) {
        let height = BlockHeight(request.height);
        let channel_id = request.channel_id;

        tracing::debug!(
            peer = %request.peer,
            height = request.height,
            channel_id = channel_id,
            "Handling inbound sync request"
        );

        // Look up block from storage
        let response = if let Some(storage) = &self.storage {
            if let Some((block, qc)) = storage.read().get_block(height) {
                // Encode the response as SBOR: (Some(block), Some(qc))
                match sbor::basic_encode(&(Some(&block), Some(&qc))) {
                    Ok(data) => data,
                    Err(e) => {
                        tracing::warn!(height = request.height, error = ?e, "Failed to encode block response");
                        // Send empty response on encoding failure
                        sbor::basic_encode(&(None::<()>, None::<()>)).unwrap_or_default()
                    }
                }
            } else {
                tracing::trace!(height = request.height, "Block not found for sync request");
                // Send "not found" response
                sbor::basic_encode(&(None::<()>, None::<()>)).unwrap_or_default()
            }
        } else {
            tracing::warn!("Received sync request but no storage configured");
            // Send empty response
            sbor::basic_encode(&(None::<()>, None::<()>)).unwrap_or_default()
        };

        // Send response via network adapter
        if let Some(network) = &self.network {
            if let Err(e) = network.send_block_response(channel_id, response) {
                tracing::warn!(
                    height = request.height,
                    channel_id = channel_id,
                    error = ?e,
                    "Failed to send block response"
                );
            }
        }
    }
}
