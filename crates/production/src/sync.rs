//! Sync manager for fetching blocks from peers.
//!
//! The sync manager handles block synchronization by delegating request retry
//! and peer selection to the `RequestManager`. This module focuses on:
//! - Tracking what heights need to be fetched
//! - Ordering and delivering complete blocks to BFT
//! - Malicious peer banning (distinct from transient failures)
//!
//! # Design: Complete Blocks Only
//!
//! Sync only accepts **complete blocks** with all transactions, certificates,
//! and a QC. If a peer can't provide a complete block (e.g., returns metadata
//! only or an empty response), we treat it as "peer doesn't have the block"
//! and retry with another peer.
//!
//! This simplifies the sync protocol significantly:
//! - No need to track partial state or "backfill" missing data
//! - No coordination with FetchManager during sync
//! - Clear success/failure semantics
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
//! │  SyncNeeded     │────▶│  SyncManager     │────▶│ RequestManager  │
//! │  (from BFT)     │     │ (orchestration)  │     │ (retry/peers)   │
//! └─────────────────┘     └──────────────────┘     └─────────────────┘
//!                                                          │
//!                                                          ▼
//!                                                   ┌─────────────┐
//!                                                   │  Network    │
//!                                                   │  Adapter    │
//!                                                   └─────────────┘
//! ```
//!
//! The `RequestManager` handles:
//! - Intelligent retry (same peer first, then rotate)
//! - Peer health tracking and weighted selection
//! - Adaptive concurrency control
//! - Exponential backoff
//!
//! While `SyncManager` handles:
//! - What heights need syncing
//! - Block validation and ordering
//! - Malicious peer banning

use crate::metrics;
use crate::network::{compute_peer_id_for_validator, RequestManager, RequestPriority};
use crate::sync_error::SyncResponseError;
use hyperscale_core::Event;
use hyperscale_types::{Block, BlockHeight, Hash, QuorumCertificate, Topology};
use libp2p::PeerId;
use serde::Serialize;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

/// Result of an async block fetch operation.
#[derive(Debug)]
pub enum SyncFetchResult {
    /// Successfully fetched a block.
    Success {
        height: u64,
        response_bytes: Vec<u8>,
    },
    /// Failed to fetch a block after all retries.
    Failed { height: u64, error: String },
}

// ═══════════════════════════════════════════════════════════════════════════
// Sync State Types (for Status API)
// ═══════════════════════════════════════════════════════════════════════════

/// The current state of the sync protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncStateKind {
    /// Not syncing, node is up to date.
    Idle,
    /// Actively fetching and applying blocks.
    Syncing,
}

impl SyncStateKind {
    /// Returns a string representation for metrics/logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            SyncStateKind::Idle => "idle",
            SyncStateKind::Syncing => "syncing",
        }
    }
}

/// Sync status for external APIs.
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
// Sync Configuration
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration for the sync manager.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Maximum number of spawned fetch tasks.
    /// This limits how many tasks wait in RequestManager's acquire_slot() queue.
    /// Should be <= RequestManager's max_concurrent to avoid slot acquisition timeouts.
    /// RequestManager handles actual network concurrency; this prevents task explosion.
    pub max_spawned_fetches: usize,

    /// Base ban duration for malicious peers.
    /// Actual ban duration uses exponential backoff: base * 2^(ban_count - 1)
    pub base_ban_duration: Duration,

    /// Maximum ban duration (caps the exponential backoff).
    pub max_ban_duration: Duration,

    /// Maximum number of heights to queue ahead of committed height.
    /// This creates a sliding window that limits memory usage in BFT's buffered_synced_blocks.
    pub sync_window_size: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            // Leave headroom for FetchManager (tx/cert fetches) which shares RequestManager.
            // RequestManager has 64 slots; use ~half for sync, leaving room for fetch.
            max_spawned_fetches: 32,
            base_ban_duration: Duration::from_secs(600), // 10 minutes
            max_ban_duration: Duration::from_secs(86400), // 24 hours
            sync_window_size: 64,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Peer Ban Tracking
// ═══════════════════════════════════════════════════════════════════════════

/// Peer ban state for malicious behavior.
///
/// This is separate from the health-based selection in RequestManager.
/// Bans are for Byzantine/malicious peers, not transient network failures.
#[derive(Debug, Clone, Default)]
struct PeerBanState {
    /// When the ban expires (None = not banned).
    banned_until: Option<Instant>,
    /// Number of times this peer has been banned (for exponential backoff).
    ban_count: u32,
}

// ═══════════════════════════════════════════════════════════════════════════
// Validation Functions
// ═══════════════════════════════════════════════════════════════════════════

/// Validate a sync response (block + QC) before accepting it.
pub fn validate_sync_response(
    requested_height: u64,
    block: &Block,
    qc: &QuorumCertificate,
) -> Result<(), SyncResponseError> {
    if block.header.height.0 != requested_height {
        return Err(SyncResponseError::StateMismatch {
            height: block.header.height.0,
            current: requested_height,
        });
    }

    let block_hash = block.hash();
    if qc.block_hash != block_hash {
        return Err(SyncResponseError::QcBlockHashMismatch {
            height: requested_height,
        });
    }

    if qc.height.0 != requested_height {
        return Err(SyncResponseError::QcHeightMismatch {
            block_height: requested_height,
            qc_height: qc.height.0,
        });
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// SyncManager Implementation
// ═══════════════════════════════════════════════════════════════════════════

/// Manages sync block fetching for the production runner.
///
/// Delegates retry logic and peer selection to `RequestManager`.
/// Focuses on height tracking and block validation.
pub struct SyncManager {
    /// Configuration.
    config: SyncConfig,
    /// Request manager for network requests with retry.
    request_manager: Arc<RequestManager>,
    /// Event sender for delivering fetched blocks.
    event_tx: mpsc::Sender<Event>,
    /// Network topology - source of truth for committee membership.
    topology: Arc<dyn Topology>,
    /// Current sync target (if syncing).
    sync_target: Option<(u64, Hash)>,
    /// Heights we need to fetch (min-heap ensures lowest height is fetched first).
    heights_to_fetch: BinaryHeap<Reverse<u64>>,
    /// Set of heights currently in the queue (for O(1) duplicate checking).
    heights_queued: HashSet<u64>,
    /// Heights currently being fetched.
    heights_in_flight: HashSet<u64>,
    /// Our current committed height (updated by state machine).
    committed_height: u64,
    /// Channel for receiving results from spawned fetch tasks.
    fetch_result_rx: mpsc::Receiver<SyncFetchResult>,
    /// Sender for spawned fetch tasks to report results.
    fetch_result_tx: mpsc::Sender<SyncFetchResult>,
    /// Peer ban states for malicious behavior.
    peer_bans: HashMap<PeerId, PeerBanState>,
}

impl SyncManager {
    /// Create a new sync manager.
    pub fn new(
        config: SyncConfig,
        request_manager: Arc<RequestManager>,
        event_tx: mpsc::Sender<Event>,
        topology: Arc<dyn Topology>,
    ) -> Self {
        // Buffer size for result channel - sync_window_size is a reasonable upper bound
        // since we won't have more in-flight fetches than the window allows
        let (fetch_result_tx, fetch_result_rx) = mpsc::channel(config.sync_window_size as usize);

        Self {
            config,
            request_manager,
            event_tx,
            topology,
            sync_target: None,
            heights_to_fetch: BinaryHeap::new(),
            heights_queued: HashSet::new(),
            heights_in_flight: HashSet::new(),
            committed_height: 0,
            fetch_result_rx,
            fetch_result_tx,
            peer_bans: HashMap::new(),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Height Queue Helpers
    // ═══════════════════════════════════════════════════════════════════════════

    /// Queue a height for fetching (no-op if already queued or in-flight).
    fn queue_height(&mut self, height: u64) {
        if !self.heights_in_flight.contains(&height) && self.heights_queued.insert(height) {
            self.heights_to_fetch.push(Reverse(height));
        }
    }

    /// Pop the next height to fetch (lowest height first).
    fn pop_next_height(&mut self) -> Option<u64> {
        while let Some(Reverse(height)) = self.heights_to_fetch.pop() {
            if self.heights_queued.remove(&height) && !self.heights_in_flight.contains(&height) {
                return Some(height);
            }
        }
        None
    }

    /// Clear all queued heights.
    fn clear_height_queue(&mut self) {
        self.heights_to_fetch.clear();
        self.heights_queued.clear();
    }

    /// Remove heights at or below a threshold.
    fn remove_heights_at_or_below(&mut self, threshold: u64) {
        self.heights_queued.retain(|&h| h > threshold);
        self.heights_in_flight.retain(|&h| h > threshold);
    }

    /// Get the count of same-shard peers available for sync (excluding self and banned).
    fn sync_peer_count(&self) -> usize {
        let local_shard = self.topology.local_shard();
        let local_validator = self.topology.local_validator_id();
        let now = Instant::now();

        self.topology
            .committee_for_shard(local_shard)
            .iter()
            .filter(|&&v| v != local_validator)
            .filter_map(|&v| {
                let pk = self.topology.public_key(v)?;
                let peer_id = compute_peer_id_for_validator(&pk);
                // Exclude banned peers
                if self.is_peer_banned(&peer_id, now) {
                    None
                } else {
                    Some(())
                }
            })
            .count()
    }

    /// Get peer IDs for sync (excluding self and banned).
    fn get_sync_peers(&self) -> Vec<PeerId> {
        let local_shard = self.topology.local_shard();
        let local_validator = self.topology.local_validator_id();
        let now = Instant::now();

        self.topology
            .committee_for_shard(local_shard)
            .iter()
            .filter(|&&v| v != local_validator)
            .filter_map(|&v| {
                let pk = self.topology.public_key(v)?;
                let peer_id = compute_peer_id_for_validator(&pk);
                if self.is_peer_banned(&peer_id, now) {
                    None
                } else {
                    Some(peer_id)
                }
            })
            .collect()
    }

    /// Check if a peer is banned.
    fn is_peer_banned(&self, peer: &PeerId, now: Instant) -> bool {
        self.peer_bans
            .get(peer)
            .and_then(|s| s.banned_until)
            .is_some_and(|until| now < until)
    }

    /// Check if we're currently syncing.
    pub fn is_syncing(&self) -> bool {
        self.sync_target.is_some()
    }

    /// Get the sync target height.
    pub fn sync_target_height(&self) -> Option<u64> {
        self.sync_target.map(|(h, _)| h)
    }

    /// Get the number of blocks we're behind (for metrics).
    pub fn blocks_behind(&self) -> u64 {
        self.sync_target
            .map(|(target, _)| target.saturating_sub(self.committed_height))
            .unwrap_or(0)
    }

    /// Get the current sync state kind.
    pub fn state_kind(&self) -> SyncStateKind {
        if self.sync_target.is_some() {
            SyncStateKind::Syncing
        } else {
            SyncStateKind::Idle
        }
    }

    /// Get a snapshot of the current sync status for external APIs.
    pub fn status(&self) -> SyncStatus {
        SyncStatus {
            state: self.state_kind(),
            current_height: self.committed_height,
            target_height: self.sync_target.map(|(h, _)| h),
            blocks_behind: self.blocks_behind(),
            sync_peers: self.sync_peer_count(),
            pending_fetches: self.heights_in_flight.len(),
            queued_heights: self.heights_to_fetch.len(),
        }
    }

    /// Update the committed height (called when state machine commits a block).
    pub fn set_committed_height(&mut self, height: u64) -> Option<u64> {
        self.committed_height = height;
        self.remove_heights_at_or_below(height);

        if let Some((target, _)) = self.sync_target {
            if height >= target {
                info!(
                    height,
                    target, "Sync complete - returning to normal consensus"
                );
                self.sync_target = None;
                self.clear_height_queue();
                return Some(target);
            }

            // Sync still in progress - extend the sliding window
            self.queue_heights_in_window();
        }

        None
    }

    /// Start syncing to a target height.
    pub fn start_sync(&mut self, target_height: u64, target_hash: Hash) {
        if self.sync_target.is_some_and(|(t, _)| t >= target_height) {
            return;
        }

        let old_target = self.sync_target.map(|(h, _)| h);

        info!(
            target_height,
            ?target_hash,
            ?old_target,
            committed = self.committed_height,
            "Starting sync"
        );

        self.sync_target = Some((target_height, target_hash));
        self.queue_heights_in_window();
        self.spawn_pending_fetches();
    }

    /// Queue heights within the sync window for fetching.
    fn queue_heights_in_window(&mut self) {
        let Some((target_height, _)) = self.sync_target else {
            return;
        };

        let first_height = self.committed_height + 1;
        let window_end = if self.config.sync_window_size == 0 {
            target_height
        } else {
            (self.committed_height + self.config.sync_window_size).min(target_height)
        };

        // Log what's currently in flight to help debug stuck fetches
        if !self.heights_in_flight.is_empty() {
            let in_flight: Vec<_> = self.heights_in_flight.iter().copied().collect();
            debug!(
                ?in_flight,
                first_height, window_end, "Heights currently in flight"
            );
        }

        for height in first_height..=window_end {
            if !self.heights_in_flight.contains(&height) {
                self.queue_height(height);
            }
        }
    }

    /// Cancel the current sync operation.
    pub fn cancel_sync(&mut self) {
        debug!("Cancelling sync");
        self.sync_target = None;
        self.clear_height_queue();
        self.heights_in_flight.clear();
    }

    /// Tick the sync manager - called periodically to drive fetch progress.
    pub async fn tick(&mut self) {
        self.process_fetch_results().await;

        if self.sync_target.is_none() {
            return;
        }

        self.spawn_pending_fetches();
    }

    /// Spawn pending fetches up to the configured limit.
    ///
    /// Limits spawned tasks to avoid overwhelming RequestManager's acquire_slot() queue.
    /// RequestManager handles actual network concurrency; this prevents task explosion
    /// that would cause slot acquisition timeouts under high load.
    fn spawn_pending_fetches(&mut self) {
        let peers = self.get_sync_peers();
        if peers.is_empty() {
            return;
        }

        while self.heights_in_flight.len() < self.config.max_spawned_fetches {
            if let Some(height) = self.pop_next_height() {
                self.heights_in_flight.insert(height);
                self.spawn_fetch(height, peers.clone());
            } else {
                break;
            }
        }
    }

    /// Process any completed fetch results from spawned tasks.
    async fn process_fetch_results(&mut self) {
        while let Ok(result) = self.fetch_result_rx.try_recv() {
            match result {
                SyncFetchResult::Success {
                    height,
                    response_bytes,
                } => {
                    self.heights_in_flight.remove(&height);
                    self.handle_block_response(height, response_bytes).await;
                }
                SyncFetchResult::Failed { height, error } => {
                    self.heights_in_flight.remove(&height);
                    warn!(height, error, "Sync fetch exhausted all retries");
                    metrics::record_sync_response_error("exhausted");
                    // Re-queue for another attempt
                    self.queue_height(height);
                }
            }
        }
    }

    /// Spawn a fetch request as a background task.
    fn spawn_fetch(&self, height: u64, peers: Vec<PeerId>) {
        info!(height, peer_count = peers.len(), "Spawning sync fetch");

        let request_manager = self.request_manager.clone();
        let result_tx = self.fetch_result_tx.clone();

        tokio::spawn(async move {
            debug!(height, "Sync fetch task starting request_block");

            // RequestManager handles retry, peer selection, and backoff
            let result = request_manager
                .request_block(&peers, BlockHeight(height), RequestPriority::Background)
                .await;

            let (fetch_result, success) = match result {
                Ok((_peer, response_bytes)) => (
                    SyncFetchResult::Success {
                        height,
                        response_bytes: response_bytes.to_vec(),
                    },
                    true,
                ),
                Err(ref e) => {
                    info!(height, error = %e, "Sync fetch request_block failed");
                    (
                        SyncFetchResult::Failed {
                            height,
                            error: format!("{}", e),
                        },
                        false,
                    )
                }
            };

            debug!(height, success, "Sync fetch task sending result");
            let _ = result_tx.send(fetch_result).await;
            debug!(height, "Sync fetch task completed");
        });
    }

    /// Handle a block response.
    ///
    /// We only accept complete blocks (block + QC). Empty responses or decode
    /// errors are treated as "peer doesn't have the block" and we re-queue
    /// the height for retry with another peer.
    async fn handle_block_response(&mut self, height: u64, response_bytes: Vec<u8>) {
        // Wire format: Option<(Block, QuorumCertificate)>
        // Some = complete block, None = not available
        let decoded: Result<Option<(Block, QuorumCertificate)>, _> =
            sbor::basic_decode(&response_bytes);

        match decoded {
            Ok(Some((block, qc))) => {
                // Complete block received - validate and deliver
                match validate_sync_response(height, &block, &qc) {
                    Ok(()) => {
                        self.on_block_received(height, block, qc).await;
                    }
                    Err(error) => {
                        warn!(height, ?error, "Invalid sync response");
                        metrics::record_sync_response_error(error.metric_label());
                        self.queue_height(height);
                    }
                }
            }
            Ok(None) => {
                // Peer doesn't have the block - try another peer
                warn!(
                    height,
                    "Empty sync response - peer doesn't have block, re-queuing"
                );
                metrics::record_sync_response_error("empty");
                self.queue_height(height);
            }
            Err(e) => {
                warn!(height, error = ?e, "Failed to decode sync response");
                metrics::record_sync_response_error("decode_error");
                self.queue_height(height);
            }
        }
    }

    /// Handle a received block.
    async fn on_block_received(&mut self, height: u64, block: Block, qc: QuorumCertificate) {
        trace!(height, "Block received for sync");
        metrics::record_sync_block_downloaded();

        if !self.validate_block(&block, &qc) {
            warn!(height, "Invalid block received during sync");
            self.queue_height(height);
            return;
        }

        debug!(height, "Delivering synced block to BFT for verification");
        let event = Event::SyncBlockReadyToApply { block, qc };
        if let Err(e) = self.event_tx.send(event).await {
            warn!(height, error = ?e, "Failed to deliver synced block");
        }
    }

    /// Validate a block against its QC.
    fn validate_block(&self, block: &Block, qc: &QuorumCertificate) -> bool {
        if qc.block_hash != block.hash() {
            warn!(
                block_hash = ?block.hash(),
                qc_hash = ?qc.block_hash,
                height = block.header.height.0,
                "QC block hash mismatch"
            );
            return false;
        }

        if qc.height != block.header.height {
            warn!(
                block_height = block.header.height.0,
                qc_height = qc.height.0,
                "QC height mismatch"
            );
            return false;
        }

        true
    }

    /// Ban a peer for malicious behavior.
    pub fn ban_peer(&mut self, peer: PeerId, error: &SyncResponseError) {
        let state = self.peer_bans.entry(peer).or_default();

        let multiplier = 2u32.saturating_pow(state.ban_count.min(10));
        let ban_duration = self
            .config
            .base_ban_duration
            .saturating_mul(multiplier)
            .min(self.config.max_ban_duration);

        state.banned_until = Some(Instant::now() + ban_duration);
        state.ban_count += 1;

        warn!(
            ?peer,
            error = %error,
            ban_duration_secs = ban_duration.as_secs(),
            ban_count = state.ban_count,
            "Banning peer for malicious sync response"
        );

        metrics::record_sync_peer_banned();
    }

    /// Check if a peer is currently banned (public API).
    pub fn is_peer_banned_public(&self, peer: &PeerId) -> bool {
        self.is_peer_banned(peer, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_config_defaults() {
        let config = SyncConfig::default();
        assert_eq!(config.max_spawned_fetches, 32);
        assert_eq!(config.sync_window_size, 64);
        assert_eq!(config.base_ban_duration, Duration::from_secs(600));
    }

    #[test]
    fn test_sync_status_default() {
        let status = SyncStatus::default();
        assert_eq!(status.state, SyncStateKind::Idle);
        assert_eq!(status.current_height, 0);
        assert!(status.target_height.is_none());
    }
}
