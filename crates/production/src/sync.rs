//! Sync manager for fetching blocks from peers.
//!
//! Thin async adapter around the shared [`SyncProtocol`] state machine.
//! This module handles production-specific concerns:
//! - Spawning tokio tasks for network fetches via `RequestManager`
//! - Peer selection from topology
//! - Metrics recording
//! - Delivering validated blocks to BFT via event channel
//!
//! The core protocol logic (height queues, sliding windows, block validation)
//! lives in `hyperscale_node::SyncProtocol`, shared with the simulation runner.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
//! │  BFT Actions    │────▶│  SyncManager     │────▶│ RequestManager  │
//! │ (StartSync)     │     │ (async adapter)  │     │ (retry/peers)   │
//! └─────────────────┘     └──────┬───────────┘     └─────────────────┘
//!                                │
//!                         ┌──────▼───────────┐
//!                         │  SyncProtocol    │
//!                         │ (shared state    │
//!                         │  machine)        │
//!                         └──────────────────┘
//! ```

use hyperscale_core::Event;
use hyperscale_metrics as metrics;
use hyperscale_network_libp2p::{
    compute_peer_id_for_validator, PeerId, RequestManager, RequestPriority,
};
use hyperscale_node::{SyncInput, SyncOutput, SyncProtocol};
use hyperscale_types::{BlockHeight, Hash, Topology};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

// Re-export shared types used by the rest of the production crate.
pub use hyperscale_node::SyncStateKind;

// ═══════════════════════════════════════════════════════════════════════════
// Production-Specific Status Type
// ═══════════════════════════════════════════════════════════════════════════

/// Sync status for external APIs.
///
/// Extends the shared protocol status with production-specific fields
/// like `sync_peers` (derived from topology).
#[derive(Debug, Clone, Serialize)]
pub struct SyncStatus {
    /// Current sync state ("idle" or "syncing").
    pub state: SyncStateKind,
    /// Current committed height.
    pub current_height: u64,
    /// Target height (if syncing).
    pub target_height: Option<u64>,
    /// Number of blocks behind target.
    pub blocks_behind: u64,
    /// Number of connected peers capable of sync.
    pub sync_peers: usize,
    /// Number of pending fetch requests.
    pub pending_fetches: usize,
    /// Number of heights queued for fetch.
    pub queued_heights: usize,
}

impl Default for SyncStatus {
    fn default() -> Self {
        Self {
            state: SyncStateKind::Idle,
            current_height: 0,
            target_height: None,
            blocks_behind: 0,
            sync_peers: 0,
            pending_fetches: 0,
            queued_heights: 0,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration for the production sync manager.
///
/// Wraps the shared protocol config with production-specific settings.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Shared protocol configuration (window size, max concurrent fetches).
    pub protocol: hyperscale_node::SyncConfig,

    /// Maximum number of spawned tokio fetch tasks.
    /// This limits how many tasks wait in RequestManager's acquire_slot() queue.
    /// Should be <= RequestManager's max_concurrent to avoid slot acquisition timeouts.
    pub max_spawned_fetches: usize,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            protocol: hyperscale_node::SyncConfig::default(),
            // Leave headroom for FetchManager (tx/cert fetches) which shares RequestManager.
            // RequestManager has 64 slots; use ~half for sync, leaving room for fetch.
            max_spawned_fetches: 32,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Fetch Result (from spawned tokio tasks)
// ═══════════════════════════════════════════════════════════════════════════

/// Result of an async block fetch operation from a spawned task.
#[derive(Debug)]
enum FetchTaskResult {
    /// Successfully received response bytes from a peer.
    Success {
        height: u64,
        response_bytes: Vec<u8>,
    },
    /// Failed to fetch after all retries.
    Failed { height: u64, error: String },
}

// ═══════════════════════════════════════════════════════════════════════════
// SyncManager Implementation
// ═══════════════════════════════════════════════════════════════════════════

/// Production sync manager — async adapter around [`SyncProtocol`].
///
/// Delegates retry logic and peer selection to `RequestManager`.
/// Core protocol logic (height queues, validation, windowing) is in `SyncProtocol`.
pub struct SyncManager {
    /// Production-specific config.
    config: SyncConfig,
    /// Shared protocol state machine.
    protocol: SyncProtocol,
    /// Request manager for network requests with retry.
    request_manager: Arc<RequestManager>,
    /// Event sender for delivering fetched blocks to BFT.
    event_tx: mpsc::Sender<Event>,
    /// Network topology — source of truth for committee membership.
    topology: Arc<dyn Topology>,
    /// Number of spawned fetch tasks currently running.
    spawned_tasks: usize,
    /// Channel for receiving results from spawned fetch tasks.
    fetch_result_rx: mpsc::Receiver<FetchTaskResult>,
    /// Sender cloned into each spawned fetch task.
    fetch_result_tx: mpsc::Sender<FetchTaskResult>,
}

impl SyncManager {
    /// Create a new sync manager.
    pub fn new(
        config: SyncConfig,
        request_manager: Arc<RequestManager>,
        event_tx: mpsc::Sender<Event>,
        topology: Arc<dyn Topology>,
    ) -> Self {
        let buffer = config.protocol.sync_window_size.max(32) as usize;
        let (fetch_result_tx, fetch_result_rx) = mpsc::channel(buffer);

        let protocol = SyncProtocol::new(config.protocol.clone());

        Self {
            config,
            protocol,
            request_manager,
            event_tx,
            topology,
            spawned_tasks: 0,
            fetch_result_rx,
            fetch_result_tx,
        }
    }

    /// Check if we're currently syncing.
    pub fn is_syncing(&self) -> bool {
        self.protocol.is_syncing()
    }

    /// Get the number of blocks behind target (for metrics).
    pub fn blocks_behind(&self) -> u64 {
        self.protocol.blocks_behind()
    }

    /// Get a snapshot of the current sync status for external APIs.
    pub fn status(&self) -> SyncStatus {
        let proto_status = self.protocol.status();
        SyncStatus {
            state: proto_status.state,
            current_height: proto_status.current_height,
            target_height: proto_status.target_height,
            blocks_behind: proto_status.blocks_behind,
            sync_peers: self.sync_peer_count(),
            pending_fetches: proto_status.pending_fetches,
            queued_heights: proto_status.queued_heights,
        }
    }

    /// Start syncing to a target height.
    pub fn start_sync(&mut self, target_height: u64, target_hash: Hash) {
        let outputs = self.protocol.handle(SyncInput::StartSync {
            target_height,
            target_hash,
        });
        self.process_outputs(outputs);
    }

    /// Update the committed height (called when state machine commits a block).
    ///
    /// Returns `Some(target_height)` if sync completed, so the runner can
    /// send `Event::SyncComplete` to the state machine.
    pub fn set_committed_height(&mut self, height: u64) -> Option<u64> {
        let outputs = self.protocol.handle(SyncInput::BlockCommitted { height });
        self.process_outputs_returning_sync_complete(outputs)
    }

    /// Tick the sync manager — called periodically to drive fetch progress.
    ///
    /// Drains completed fetch results and feeds them into the protocol,
    /// then processes any new outputs (which may spawn more fetch tasks).
    pub async fn tick(&mut self) {
        // Drain completed fetch results from spawned tasks.
        while let Ok(result) = self.fetch_result_rx.try_recv() {
            self.spawned_tasks = self.spawned_tasks.saturating_sub(1);

            let input = match result {
                FetchTaskResult::Success {
                    height,
                    response_bytes,
                } => {
                    // Decode wire format: Option<(Block, QuorumCertificate)>
                    let decoded = sbor::basic_decode(&response_bytes);
                    match decoded {
                        Ok(block) => SyncInput::BlockResponseReceived {
                            height,
                            block: Box::new(block),
                        },
                        Err(e) => {
                            warn!(height, error = ?e, "Failed to decode sync response");
                            metrics::record_sync_response_error("decode_error");
                            SyncInput::BlockFetchFailed { height }
                        }
                    }
                }
                FetchTaskResult::Failed { height, error } => {
                    warn!(height, error, "Sync fetch exhausted all retries");
                    metrics::record_sync_response_error("exhausted");
                    SyncInput::BlockFetchFailed { height }
                }
            };

            let outputs = self.protocol.handle(input);
            self.process_outputs(outputs);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Output Processing
    // ═══════════════════════════════════════════════════════════════════════

    /// Process protocol outputs — spawn fetches and deliver blocks.
    fn process_outputs(&mut self, outputs: Vec<SyncOutput>) {
        let peers = self.get_sync_peers();

        for output in outputs {
            match output {
                SyncOutput::FetchBlock { height } => {
                    if peers.is_empty() {
                        // No peers available — tell protocol the fetch failed so it re-queues.
                        let retry_outputs =
                            self.protocol.handle(SyncInput::BlockFetchFailed { height });
                        // Don't recurse — just drop. Will retry on next tick.
                        drop(retry_outputs);
                        continue;
                    }
                    if self.spawned_tasks < self.config.max_spawned_fetches {
                        self.spawn_fetch(height, peers.clone());
                    } else {
                        // Too many tasks — tell protocol to re-queue.
                        let retry_outputs =
                            self.protocol.handle(SyncInput::BlockFetchFailed { height });
                        drop(retry_outputs);
                    }
                }
                SyncOutput::DeliverBlock { block, qc } => {
                    let height = block.header.height.0;
                    debug!(height, "Delivering synced block to BFT");
                    metrics::record_sync_block_downloaded();
                    let event = Event::SyncBlockReadyToApply {
                        block: *block,
                        qc: *qc,
                    };
                    // Use try_send to avoid blocking the event loop.
                    if let Err(e) = self.event_tx.try_send(event) {
                        warn!(height, error = ?e, "Failed to deliver synced block");
                    }
                }
                SyncOutput::SyncComplete { height } => {
                    info!(height, "Sync complete");
                    // Handled by the caller (set_committed_height returns Some).
                }
            }
        }
    }

    /// Like `process_outputs` but returns the SyncComplete height if present.
    fn process_outputs_returning_sync_complete(&mut self, outputs: Vec<SyncOutput>) -> Option<u64> {
        let mut sync_complete_height = None;
        let peers = self.get_sync_peers();

        for output in outputs {
            match output {
                SyncOutput::FetchBlock { height } => {
                    if peers.is_empty() {
                        let retry_outputs =
                            self.protocol.handle(SyncInput::BlockFetchFailed { height });
                        drop(retry_outputs);
                        continue;
                    }
                    if self.spawned_tasks < self.config.max_spawned_fetches {
                        self.spawn_fetch(height, peers.clone());
                    } else {
                        let retry_outputs =
                            self.protocol.handle(SyncInput::BlockFetchFailed { height });
                        drop(retry_outputs);
                    }
                }
                SyncOutput::DeliverBlock { block, qc } => {
                    let height = block.header.height.0;
                    debug!(height, "Delivering synced block to BFT");
                    metrics::record_sync_block_downloaded();
                    let event = Event::SyncBlockReadyToApply {
                        block: *block,
                        qc: *qc,
                    };
                    if let Err(e) = self.event_tx.try_send(event) {
                        warn!(height, error = ?e, "Failed to deliver synced block");
                    }
                }
                SyncOutput::SyncComplete { height } => {
                    info!(height, "Sync complete - returning to normal consensus");
                    sync_complete_height = Some(height);
                }
            }
        }

        sync_complete_height
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Async Task Spawning
    // ═══════════════════════════════════════════════════════════════════════

    /// Spawn a fetch request as a background tokio task.
    fn spawn_fetch(&mut self, height: u64, peers: Vec<PeerId>) {
        info!(height, peer_count = peers.len(), "Spawning sync fetch");

        self.spawned_tasks += 1;
        let request_manager = self.request_manager.clone();
        let result_tx = self.fetch_result_tx.clone();

        tokio::spawn(async move {
            debug!(height, "Sync fetch task starting");

            let result = request_manager
                .request_block(&peers, BlockHeight(height), RequestPriority::Background)
                .await;

            let fetch_result = match result {
                Ok((_peer, response_bytes)) => FetchTaskResult::Success {
                    height,
                    response_bytes: response_bytes.to_vec(),
                },
                Err(e) => {
                    info!(height, error = %e, "Sync fetch failed");
                    FetchTaskResult::Failed {
                        height,
                        error: format!("{}", e),
                    }
                }
            };

            let _ = result_tx.send(fetch_result).await;
        });
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Peer Helpers
    // ═══════════════════════════════════════════════════════════════════════

    /// Get the count of same-shard peers available for sync (excluding self).
    fn sync_peer_count(&self) -> usize {
        let local_shard = self.topology.local_shard();
        let local_validator = self.topology.local_validator_id();

        self.topology
            .committee_for_shard(local_shard)
            .iter()
            .filter(|&&v| v != local_validator)
            .count()
    }

    /// Get peer IDs for sync (excluding self).
    fn get_sync_peers(&self) -> Vec<PeerId> {
        let local_shard = self.topology.local_shard();
        let local_validator = self.topology.local_validator_id();

        self.topology
            .committee_for_shard(local_shard)
            .iter()
            .filter(|&&v| v != local_validator)
            .filter_map(|&v| {
                let pk = self.topology.public_key(v)?;
                Some(compute_peer_id_for_validator(&pk))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_config_defaults() {
        let config = SyncConfig::default();
        assert_eq!(config.max_spawned_fetches, 32);
        assert_eq!(config.protocol.sync_window_size, 64);
    }

    #[test]
    fn test_sync_status_default() {
        let status = SyncStatus::default();
        assert_eq!(status.state, SyncStateKind::Idle);
        assert_eq!(status.current_height, 0);
        assert!(status.target_height.is_none());
    }
}
