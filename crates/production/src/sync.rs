//! Sync manager for fetching blocks from peers.
//!
//! The sync manager handles block synchronization by delegating request retry
//! and peer selection to the `RequestManager`. This module focuses on:
//! - Tracking what heights need to be fetched
//! - Ordering and delivering blocks to BFT
//! - Handling metadata-only responses via backfill
//! - Malicious peer banning (distinct from transient failures)
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
//! │  SyncNeeded     │────▶│  SyncManager     │────▶│ RequestManager  │
//! │  (from BFT)     │     │ (orchestration)  │     │ (retry/peers)   │
//! └─────────────────┘     └──────────────────┘     └─────────────────┘
//!                                │                         │
//!                                ▼                         ▼
//!                         ┌──────────────┐          ┌─────────────┐
//!                         │   Storage    │          │  Network    │
//!                         │  (backfill)  │          │  Adapter    │
//!                         └──────────────┘          └─────────────┘
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
//! - Backfill for metadata-only responses

use crate::metrics;
use crate::network::{compute_peer_id_for_validator, RequestManager, RequestPriority};
use crate::storage::RocksDbStorage;
use crate::sync_error::SyncResponseError;
use hyperscale_core::Event;
use hyperscale_types::{Block, BlockHeight, BlockMetadata, Hash, QuorumCertificate, Topology};
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

    /// Timeout for backfill operations (fetching missing txs/certs after metadata-only response).
    pub backfill_timeout: Duration,

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
            backfill_timeout: Duration::from_secs(30),
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

/// A pending sync backfill - block where we have metadata but are fetching txs/certs.
#[derive(Debug)]
struct PendingBackfill {
    /// Block metadata (header + tx/cert hashes + QC).
    metadata: BlockMetadata,
    /// When backfill started.
    started: Instant,
    /// Transaction hashes we've received.
    received_txs: HashSet<Hash>,
    /// Certificate hashes we've received.
    received_certs: HashSet<Hash>,
    /// Whether we've triggered fetch requests.
    fetch_triggered: bool,
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
/// Focuses on height tracking, block validation, and backfill.
pub struct SyncManager {
    /// Configuration.
    config: SyncConfig,
    /// Request manager for network requests with retry.
    request_manager: Arc<RequestManager>,
    /// Storage for reconstructing blocks from metadata.
    storage: Arc<RocksDbStorage>,
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
    /// Pending backfills - blocks where we have metadata but are fetching txs/certs.
    pending_backfills: HashMap<u64, PendingBackfill>,
    /// Reverse lookup: block hash -> height for O(1) backfill lookup.
    backfill_hash_to_height: HashMap<Hash, u64>,
    /// Peer ban states for malicious behavior.
    peer_bans: HashMap<PeerId, PeerBanState>,
}

impl SyncManager {
    /// Create a new sync manager.
    pub fn new(
        config: SyncConfig,
        request_manager: Arc<RequestManager>,
        storage: Arc<RocksDbStorage>,
        event_tx: mpsc::Sender<Event>,
        topology: Arc<dyn Topology>,
    ) -> Self {
        // Buffer size for result channel - sync_window_size is a reasonable upper bound
        // since we won't have more in-flight fetches than the window allows
        let (fetch_result_tx, fetch_result_rx) = mpsc::channel(config.sync_window_size as usize);

        Self {
            config,
            request_manager,
            storage,
            event_tx,
            topology,
            sync_target: None,
            heights_to_fetch: BinaryHeap::new(),
            heights_queued: HashSet::new(),
            heights_in_flight: HashSet::new(),
            committed_height: 0,
            fetch_result_rx,
            fetch_result_tx,
            pending_backfills: HashMap::new(),
            backfill_hash_to_height: HashMap::new(),
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
        trace!(height, "Spawning sync fetch");

        let request_manager = self.request_manager.clone();
        let result_tx = self.fetch_result_tx.clone();

        tokio::spawn(async move {
            // RequestManager handles retry, peer selection, and backoff
            let result = request_manager
                .request_block(&peers, BlockHeight(height), RequestPriority::Background)
                .await;

            let fetch_result = match result {
                Ok((_peer, response_bytes)) => SyncFetchResult::Success {
                    height,
                    response_bytes: response_bytes.to_vec(),
                },
                Err(e) => SyncFetchResult::Failed {
                    height,
                    error: format!("{}", e),
                },
            };

            let _ = result_tx.send(fetch_result).await;
        });
    }

    /// Handle a block response.
    async fn handle_block_response(&mut self, height: u64, response_bytes: Vec<u8>) {
        let decoded: Result<
            (
                Option<Block>,
                Option<QuorumCertificate>,
                Option<BlockMetadata>,
            ),
            _,
        > = sbor::basic_decode(&response_bytes);

        match decoded {
            Ok((Some(block), Some(qc), _)) => {
                match validate_sync_response(height, &block, &qc) {
                    Ok(()) => {
                        self.on_block_received(height, block, qc).await;
                    }
                    Err(error) => {
                        // Note: We can't ban here since RequestManager handles peer selection
                        // In a full implementation, we'd want to communicate malicious responses back
                        warn!(height, ?error, "Invalid sync response");
                        metrics::record_sync_response_error(error.metric_label());
                        self.queue_height(height);
                    }
                }
            }
            Ok((None, None, Some(metadata))) => {
                info!(
                    height,
                    tx_count = metadata.tx_hashes.len(),
                    cert_count = metadata.cert_hashes.len(),
                    "Received metadata-only sync response, starting backfill"
                );
                self.start_backfill(height, metadata);
                metrics::record_sync_metadata_only();
            }
            Ok((None, None, None)) | Ok((None, _, _)) | Ok((_, None, _)) => {
                debug!(height, "Empty sync response - re-queuing");
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

    // ═══════════════════════════════════════════════════════════════════════════
    // Backfill Methods
    // ═══════════════════════════════════════════════════════════════════════════

    /// Start a backfill for a block where we have metadata but missing txs/certs.
    fn start_backfill(&mut self, height: u64, metadata: BlockMetadata) {
        if self.pending_backfills.contains_key(&height) {
            debug!(height, "Backfill already pending for height");
            return;
        }

        if height <= self.committed_height {
            debug!(height, "Not starting backfill - already committed");
            return;
        }

        info!(
            height,
            tx_count = metadata.tx_hashes.len(),
            cert_count = metadata.cert_hashes.len(),
            "Starting sync backfill"
        );

        // Add reverse lookup for O(1) block hash -> height mapping
        let block_hash = metadata.header.hash();
        self.backfill_hash_to_height.insert(block_hash, height);

        self.pending_backfills.insert(
            height,
            PendingBackfill {
                metadata,
                started: Instant::now(),
                received_txs: HashSet::new(),
                received_certs: HashSet::new(),
                fetch_triggered: false,
            },
        );

        self.try_complete_backfill(height);
    }

    /// Notify that transactions have been received (from FetchManager).
    pub fn on_transactions_received(&mut self, block_hash: Hash, tx_hashes: &[Hash]) {
        // O(1) lookup using reverse map instead of O(n) scan
        let Some(&height) = self.backfill_hash_to_height.get(&block_hash) else {
            return;
        };

        if let Some(backfill) = self.pending_backfills.get_mut(&height) {
            for hash in tx_hashes {
                backfill.received_txs.insert(*hash);
            }
            debug!(
                height,
                received = backfill.received_txs.len(),
                needed = backfill.metadata.tx_hashes.len(),
                "Backfill received transactions"
            );
        }
        self.try_complete_backfill(height);
    }

    /// Notify that certificates have been received (from FetchManager).
    pub fn on_certificates_received(&mut self, block_hash: Hash, cert_hashes: &[Hash]) {
        // O(1) lookup using reverse map instead of O(n) scan
        let Some(&height) = self.backfill_hash_to_height.get(&block_hash) else {
            return;
        };

        if let Some(backfill) = self.pending_backfills.get_mut(&height) {
            for hash in cert_hashes {
                backfill.received_certs.insert(*hash);
            }
            debug!(
                height,
                received = backfill.received_certs.len(),
                needed = backfill.metadata.cert_hashes.len(),
                "Backfill received certificates"
            );
        }
        self.try_complete_backfill(height);
    }

    /// Try to complete a backfill by reconstructing the block from storage.
    fn try_complete_backfill(&mut self, height: u64) {
        if !self.pending_backfills.contains_key(&height) {
            return;
        }

        let block_height = BlockHeight(height);

        if let Some((block, qc)) = self.storage.get_block_denormalized(block_height) {
            info!(
                height,
                txs = block.transactions.len(),
                certs = block.committed_certificates.len(),
                "Backfill complete - block reconstructed from storage"
            );

            // Remove from both maps
            if let Some(backfill) = self.pending_backfills.remove(&height) {
                let block_hash = backfill.metadata.header.hash();
                self.backfill_hash_to_height.remove(&block_hash);
            }

            let event = Event::SyncBlockReadyToApply { block, qc };
            let event_tx = self.event_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = event_tx.send(event).await {
                    warn!(height, error = ?e, "Failed to deliver backfilled block to BFT");
                }
            });

            return;
        }

        let backfill = self.pending_backfills.get_mut(&height).unwrap();

        if !backfill.fetch_triggered {
            backfill.fetch_triggered = true;

            let missing_txs: Vec<Hash> = backfill
                .metadata
                .tx_hashes
                .iter()
                .filter(|h| self.storage.get_transaction(h).is_none())
                .cloned()
                .collect();

            let missing_certs: Vec<Hash> = backfill
                .metadata
                .cert_hashes
                .iter()
                .filter(|h| self.storage.get_certificate(h).is_none())
                .cloned()
                .collect();

            if !missing_txs.is_empty() || !missing_certs.is_empty() {
                info!(
                    height,
                    missing_txs = missing_txs.len(),
                    missing_certs = missing_certs.len(),
                    "Backfill needs fetch for missing data"
                );
            }
        }
    }

    /// Get pending backfill fetch requests.
    pub fn get_pending_backfill_fetches(
        &self,
    ) -> Vec<(Hash, hyperscale_types::ValidatorId, Vec<Hash>, Vec<Hash>)> {
        let mut result = Vec::new();

        for backfill in self.pending_backfills.values() {
            if !backfill.fetch_triggered {
                continue;
            }

            let block_hash = backfill.metadata.header.hash();
            let proposer = backfill.metadata.header.proposer;

            // Collect missing txs and certs in a single pass
            let mut missing_txs = Vec::new();
            let mut missing_certs = Vec::new();

            for h in &backfill.metadata.tx_hashes {
                if self.storage.get_transaction(h).is_none() {
                    missing_txs.push(*h);
                }
            }

            for h in &backfill.metadata.cert_hashes {
                if self.storage.get_certificate(h).is_none() {
                    missing_certs.push(*h);
                }
            }

            if !missing_txs.is_empty() || !missing_certs.is_empty() {
                result.push((block_hash, proposer, missing_txs, missing_certs));
            }
        }

        result
    }

    /// Tick backfills - check for completions and timeouts.
    pub fn tick_backfills(&mut self) {
        let timeout = self.config.backfill_timeout;
        let now = Instant::now();

        // First, remove timed-out backfills and collect heights that need completion check
        let mut heights_to_check = Vec::new();
        let mut hashes_to_remove = Vec::new();

        self.pending_backfills.retain(|&height, backfill| {
            if now.duration_since(backfill.started) > timeout {
                warn!(
                    height,
                    timeout_secs = timeout.as_secs(),
                    "Backfill timed out"
                );
                metrics::record_sync_response_error("backfill_timeout");
                // Track hash for reverse lookup cleanup
                hashes_to_remove.push(backfill.metadata.header.hash());
                false
            } else {
                heights_to_check.push(height);
                true
            }
        });

        // Clean up reverse lookup for timed-out backfills
        for hash in hashes_to_remove {
            self.backfill_hash_to_height.remove(&hash);
        }

        // Then try to complete remaining backfills
        for height in heights_to_check {
            self.try_complete_backfill(height);
        }
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
