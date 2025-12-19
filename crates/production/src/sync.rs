//! Sync manager for fetching blocks from peers.
//!
//! The sync manager handles all aspects of block synchronization:
//! - Peer selection (round-robin with failure tracking)
//! - Parallel block fetches
//! - Retries with exponential backoff
//! - Timeout handling
//! - Block validation and ordering
//! - Delivery to BFT via SyncBlockReadyToApply events
//!
//! This is a complete sync solution - no separate SyncState SubStateMachine needed.

use crate::metrics;
use crate::network::{compute_peer_id_for_validator, Libp2pAdapter};
use crate::sync_error::SyncResponseError;
use hyperscale_core::Event;
use hyperscale_types::{Block, BlockHeight, Hash, QuorumCertificate, Topology};
use libp2p::PeerId;
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
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
        peer: PeerId,
        response_bytes: Vec<u8>,
    },
    /// Failed to fetch a block.
    Failed {
        height: u64,
        peer: PeerId,
        error: String,
    },
}

// ═══════════════════════════════════════════════════════════════════════════
// Sync State Types (for Status API)
// ═══════════════════════════════════════════════════════════════════════════

/// The current state of the sync protocol.
///
/// This enum represents the high-level sync state for external observability.
/// Note: This lives in `SyncManager` (production-only), not in `SyncState`
/// (deterministic state machine), as it involves I/O concerns like peer queries.
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
///
/// This struct provides a snapshot of the sync manager's current state,
/// suitable for JSON serialization and exposure via HTTP endpoints.
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
    /// Maximum number of concurrent fetch requests.
    pub max_concurrent_fetches: usize,
    /// Initial timeout for sync requests.
    pub initial_timeout: Duration,
    /// Maximum timeout for sync requests (after exponential backoff).
    pub max_timeout: Duration,
    /// Maximum retries per block before giving up on a peer.
    pub max_retries_per_peer: u32,
    /// Cooldown period before retrying a failed peer.
    pub peer_cooldown: Duration,
    /// Base ban duration for malicious peers.
    /// Actual ban duration uses exponential backoff: base * 2^(ban_count - 1)
    pub base_ban_duration: Duration,
    /// Maximum ban duration (caps the exponential backoff).
    pub max_ban_duration: Duration,
    /// Desperation mode: if we're this many blocks behind and all peers are in cooldown,
    /// reset cooldowns to allow retrying. This prevents getting stuck when all peers
    /// temporarily fail but we urgently need to catch up.
    pub desperation_threshold_blocks: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            // Allow up to 16 concurrent fetches for faster catch-up.
            // With 3 peers (4-validator shard minus self) at 2 requests each,
            // we could do 6 concurrent, but we allow more headroom for larger shards.
            max_concurrent_fetches: 16,
            initial_timeout: Duration::from_millis(500),
            max_timeout: Duration::from_secs(5),
            max_retries_per_peer: 3,
            // Short cooldown to allow quick recovery from transient failures.
            // The desperation mode will reset cooldowns if we fall too far behind.
            peer_cooldown: Duration::from_secs(5),
            base_ban_duration: Duration::from_secs(600), // 10 minutes
            max_ban_duration: Duration::from_secs(86400), // 24 hours
            // If 3+ blocks behind and all peers in cooldown, enter desperation mode.
            // Low threshold ensures we don't get stuck due to transient network issues.
            desperation_threshold_blocks: 3,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Peer Reputation
// ═══════════════════════════════════════════════════════════════════════════

/// Peer reputation for sync protocol.
///
/// Tracks peer behavior to identify reliable peers and ban malicious ones.
/// Reputation is used for peer selection and malicious peer detection.
#[derive(Debug, Clone, Default)]
pub struct PeerReputation {
    /// Number of successful sync responses.
    pub successes: u32,
    /// Number of non-malicious failures (timeouts, network errors).
    pub failures: u32,
    /// Number of in-flight requests to this peer.
    pub in_flight: u32,
    /// Whether this peer is currently banned.
    pub banned_until: Option<Instant>,
    /// Number of times this peer has been banned (for exponential backoff).
    pub ban_count: u32,
    /// Time of last successful response.
    pub last_success: Option<Instant>,
    /// Time of last failure (for cooldown calculation).
    pub last_failure: Option<Instant>,
    /// Count of consecutive empty responses (peer doesn't have blocks we need).
    /// Reset on success. Used to deprioritize peers that are also behind.
    pub empty_responses: u32,
    /// Time of last empty response.
    pub last_empty_response: Option<Instant>,
}

/// A pending sync fetch request.
#[derive(Debug)]
#[allow(dead_code)]
struct PendingFetch {
    /// The height being fetched.
    height: u64,
    /// The peer we're fetching from.
    peer: PeerId,
    /// When the request was sent.
    started: Instant,
    /// Current retry count.
    retries: u32,
    /// Peers that have been tried for this height (and returned empty or failed).
    /// Used to avoid retrying the same peer.
    tried_peers: HashSet<PeerId>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Validation Functions
// ═══════════════════════════════════════════════════════════════════════════

/// Validate a sync response (block + QC) before accepting it.
///
/// This performs basic structural validation:
/// - Block height matches the requested height
/// - QC hash matches the block's hash
/// - QC height matches the block's height
///
/// Note: Full QC signature verification is done later by BftState.
///
/// Returns `Ok(())` if valid, or a `SyncResponseError` describing the issue.
pub fn validate_sync_response(
    requested_height: u64,
    block: &Block,
    qc: &QuorumCertificate,
) -> Result<(), SyncResponseError> {
    // Validate block height matches request
    if block.header.height.0 != requested_height {
        return Err(SyncResponseError::StateMismatch {
            height: block.header.height.0,
            current: requested_height,
        });
    }

    // Validate QC certifies this block (hash match)
    let block_hash = block.hash();
    if qc.block_hash != block_hash {
        return Err(SyncResponseError::QcBlockHashMismatch {
            height: requested_height,
        });
    }

    // Validate QC height matches block height
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
/// The sync manager is responsible for:
/// 1. Receiving sync requests from BFT (via `SyncNeeded` event)
/// 2. Fetching blocks from peers using request-response protocol (concurrently)
/// 3. Validating and ordering received blocks
/// 4. Delivering verified blocks directly to BFT for commitment
///
/// This is a complete sync solution - no separate SyncState SubStateMachine needed.
pub struct SyncManager {
    /// Configuration.
    config: SyncConfig,
    /// Network adapter for sending requests.
    network: Arc<Libp2pAdapter>,
    /// Event sender for delivering fetched blocks.
    event_tx: mpsc::Sender<Event>,
    /// Network topology - source of truth for committee membership.
    /// We query this directly for peer selection instead of maintaining a separate map.
    topology: Arc<dyn Topology>,
    /// Current sync target (if syncing).
    sync_target: Option<(u64, Hash)>,
    /// Heights we need to fetch.
    heights_to_fetch: VecDeque<u64>,
    /// Currently pending fetch requests.
    pending_fetches: HashMap<u64, PendingFetch>,
    /// Peers that have been tried for each height (for retry rotation).
    /// Cleared when sync completes or height is successfully fetched.
    tried_peers_for_height: HashMap<u64, HashSet<PeerId>>,
    /// Peer reputations for selection and failure tracking.
    /// Keyed by PeerId, computed from topology on demand.
    peer_reputations: HashMap<PeerId, PeerReputation>,
    /// Our current committed height (updated by state machine).
    committed_height: u64,
    /// Channel for receiving results from spawned fetch tasks.
    fetch_result_rx: mpsc::Receiver<SyncFetchResult>,
    /// Sender for spawned fetch tasks to report results.
    fetch_result_tx: mpsc::Sender<SyncFetchResult>,
}

impl SyncManager {
    /// Create a new sync manager.
    ///
    /// The topology is used as the source of truth for peer discovery.
    /// We query it directly for committee members instead of maintaining
    /// a separate peer map.
    pub fn new(
        config: SyncConfig,
        network: Arc<Libp2pAdapter>,
        event_tx: mpsc::Sender<Event>,
        topology: Arc<dyn Topology>,
    ) -> Self {
        // Channel for fetch results - buffer size matches max concurrent fetches
        let (fetch_result_tx, fetch_result_rx) =
            mpsc::channel(config.max_concurrent_fetches.max(16));

        Self {
            config,
            network,
            event_tx,
            topology,
            sync_target: None,
            heights_to_fetch: VecDeque::new(),
            pending_fetches: HashMap::new(),
            tried_peers_for_height: HashMap::new(),
            peer_reputations: HashMap::new(),
            committed_height: 0,
            fetch_result_rx,
            fetch_result_tx,
        }
    }

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
    ///
    /// This provides a complete view of the sync manager's state,
    /// suitable for JSON serialization and exposure via HTTP endpoints.
    pub fn status(&self) -> SyncStatus {
        SyncStatus {
            state: self.state_kind(),
            current_height: self.committed_height,
            target_height: self.sync_target.map(|(h, _)| h),
            blocks_behind: self.blocks_behind(),
            sync_peers: self.sync_peer_count(),
            pending_fetches: self.pending_fetches.len(),
            queued_heights: self.heights_to_fetch.len(),
        }
    }

    /// Update the committed height (called when state machine commits a block).
    pub fn set_committed_height(&mut self, height: u64) {
        self.committed_height = height;

        // Remove heights at or below committed from pending lists
        self.heights_to_fetch.retain(|h| *h > height);

        // When removing pending fetches, decrement in_flight for the associated peers
        // to prevent the counter from getting stuck
        let peers_to_decrement: Vec<_> = self
            .pending_fetches
            .iter()
            .filter(|(h, _)| **h <= height)
            .map(|(_, fetch)| fetch.peer)
            .collect();
        for peer in peers_to_decrement {
            if let Some(rep) = self.peer_reputations.get_mut(&peer) {
                rep.in_flight = rep.in_flight.saturating_sub(1);
            }
        }
        self.pending_fetches.retain(|h, _| *h > height);

        // Check if sync is complete
        if let Some((target, _)) = self.sync_target {
            if height >= target {
                debug!(height, target, "Sync complete");
                self.sync_target = None;
                self.heights_to_fetch.clear();
            }
        }
    }

    /// Start syncing to a target height.
    ///
    /// Called when state machine emits `SyncNeeded`.
    /// Spawns initial batch of fetches immediately rather than deferring to tick().
    pub fn start_sync(&mut self, target_height: u64, target_hash: Hash) {
        // Already syncing to this or higher target?
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

        // Queue heights to fetch. We don't track "already fetched" heights because
        // BFT is the source of truth - it will ignore duplicates. This avoids bugs
        // where SyncManager thinks a block was fetched but BFT lost it (e.g., due to
        // QC verification failure clearing pending_synced_block_verifications).
        let first_height = self.committed_height + 1;
        for height in first_height..=target_height {
            if !self.pending_fetches.contains_key(&height)
                && !self.heights_to_fetch.contains(&height)
            {
                self.heights_to_fetch.push_back(height);
            }
        }

        // Spawn initial batch of fetches immediately (don't wait for tick)
        self.spawn_pending_fetches();
    }

    /// Cancel the current sync operation.
    pub fn cancel_sync(&mut self) {
        debug!("Cancelling sync");
        self.sync_target = None;
        self.heights_to_fetch.clear();
        self.pending_fetches.clear();
    }

    /// Tick the sync manager - called periodically to drive fetch progress.
    ///
    /// This should be called regularly (e.g., every 100ms) to:
    /// - Process completed fetch results
    /// - Check for timed out requests
    /// - Spawn more fetches if under the concurrent limit
    ///
    /// Note: Initial fetches are spawned immediately in start_sync().
    /// This tick only handles ongoing progress and retries.
    pub async fn tick(&mut self) {
        // Always process any pending fetch results, even if not syncing
        // (we may have outstanding fetches from before sync was cancelled)
        self.process_fetch_results().await;

        if self.sync_target.is_none() {
            return;
        }

        // Check for timed out requests
        self.check_timeouts();

        // Spawn more fetches if we're under the limit
        self.spawn_pending_fetches();
    }

    /// Spawn pending fetches up to the concurrent limit.
    ///
    /// Called both from start_sync() for immediate spawning and from tick()
    /// for ongoing progress after retries or when slots free up.
    fn spawn_pending_fetches(&mut self) {
        while self.pending_fetches.len() < self.config.max_concurrent_fetches {
            if let Some(height) = self.heights_to_fetch.pop_front() {
                if let Some(peer) = self.select_peer() {
                    self.spawn_fetch(height, peer);
                } else {
                    // No available peers, put height back and stop
                    self.heights_to_fetch.push_front(height);
                    break;
                }
            } else {
                break;
            }
        }
    }

    /// Process any completed fetch results from spawned tasks.
    ///
    /// This drains the fetch result channel and processes each result,
    /// delivering blocks to BFT as they become ready.
    async fn process_fetch_results(&mut self) {
        // Process all available results without blocking
        while let Ok(result) = self.fetch_result_rx.try_recv() {
            match result {
                SyncFetchResult::Success {
                    height,
                    peer,
                    response_bytes,
                } => {
                    self.handle_block_response(height, peer, response_bytes)
                        .await;
                }
                SyncFetchResult::Failed {
                    height,
                    peer,
                    error,
                } => {
                    self.on_fetch_failed(height, peer, &error);
                }
            }
        }
    }

    /// Spawn a fetch request as a background task (non-blocking).
    ///
    /// The fetch result will be sent to the fetch_result channel and
    /// processed in the next tick.
    fn spawn_fetch(&mut self, height: u64, peer: PeerId) {
        trace!(height, ?peer, "Spawning concurrent sync fetch");

        // Update peer reputation (create entry if needed)
        let rep = self.peer_reputations.entry(peer).or_default();
        rep.in_flight += 1;

        // Record pending fetch
        self.pending_fetches.insert(
            height,
            PendingFetch {
                height,
                peer,
                started: Instant::now(),
                retries: 0,
                tried_peers: HashSet::new(),
            },
        );

        // Clone what we need for the spawned task
        let network = self.network.clone();
        let result_tx = self.fetch_result_tx.clone();

        // Spawn the fetch as a background task
        tokio::spawn(async move {
            let result = match network.request_block(peer, BlockHeight(height)).await {
                Ok(response_bytes) => SyncFetchResult::Success {
                    height,
                    peer,
                    response_bytes,
                },
                Err(e) => SyncFetchResult::Failed {
                    height,
                    peer,
                    error: format!("network error: {e}"),
                },
            };

            // Send result back - ignore error if receiver dropped
            let _ = result_tx.send(result).await;
        });
    }

    /// Handle a received block response.
    ///
    /// Validates the block and delivers it immediately to BFT.
    /// BFT handles ordering and decides when to apply each block.
    pub async fn on_block_received(
        &mut self,
        height: u64,
        block: Block,
        qc: QuorumCertificate,
        from_peer: PeerId,
    ) {
        // Always decrement in_flight when we receive a response, even if the height
        // was already handled (e.g., by a timeout). This prevents in_flight from getting
        // stuck if a timed-out request eventually completes.
        let rep = self.peer_reputations.entry(from_peer).or_default();
        rep.in_flight = rep.in_flight.saturating_sub(1);

        // Remove from pending
        if let Some(_pending) = self.pending_fetches.remove(&height) {
            // Clean up tried peers tracking for this height
            self.tried_peers_for_height.remove(&height);

            // Mark peer as successful - reset failure count and empty_responses
            rep.successes += 1;
            rep.failures = 0; // Reset on success
            rep.empty_responses = 0; // Reset empty response count
            rep.last_success = Some(Instant::now());

            trace!(height, ?from_peer, "Block received for sync");

            // Record metrics
            metrics::record_sync_block_downloaded();

            // Validate block matches QC
            if !self.validate_block(&block, &qc) {
                warn!(height, ?from_peer, "Invalid block received during sync");
                // Re-queue for retry from another peer
                if !self.heights_to_fetch.contains(&height) {
                    self.heights_to_fetch.push_back(height);
                }
                return;
            }

            // Deliver immediately to BFT - it handles ordering and deduplication
            debug!(height, "Delivering synced block to BFT for verification");
            let event = Event::SyncBlockReadyToApply { block, qc };
            if let Err(e) = self.event_tx.send(event).await {
                warn!(height, error = ?e, "Failed to deliver synced block");
            }
        } else {
            // Request was already handled (likely by timeout) - just log it
            trace!(
                height,
                ?from_peer,
                "Late block response (already handled by timeout)"
            );
        }
    }

    /// Validate a block against its QC.
    fn validate_block(&self, block: &Block, qc: &QuorumCertificate) -> bool {
        // Verify the QC certifies this block
        if qc.block_hash != block.hash() {
            warn!(
                block_hash = ?block.hash(),
                qc_hash = ?qc.block_hash,
                height = block.header.height.0,
                "QC block hash mismatch"
            );
            return false;
        }

        // Verify height matches
        if qc.height != block.header.height {
            warn!(
                block_height = block.header.height.0,
                qc_height = qc.height.0,
                "QC height mismatch"
            );
            return false;
        }

        // Note: QC signature verification is done by BftState when processing
        // SyncBlockReadyToApply. We just validate basic properties here.
        true
    }

    /// Handle a failed fetch (timeout or error).
    ///
    /// This is for non-malicious failures like timeouts and network errors.
    /// For malicious responses, use `on_sync_response_error()` instead.
    pub fn on_fetch_failed(&mut self, height: u64, peer: PeerId, reason: &str) {
        // Always decrement in_flight when we receive a failure, even if the height
        // was already handled. This prevents in_flight from getting stuck.
        let rep = self.peer_reputations.entry(peer).or_default();
        rep.in_flight = rep.in_flight.saturating_sub(1);

        if let Some(_pending) = self.pending_fetches.remove(&height) {
            warn!(height, ?peer, reason, "Sync fetch failed");

            // Record metric for the failure type
            let error_type = if reason.contains("timeout") {
                "timeout"
            } else {
                "network_error"
            };
            metrics::record_sync_response_error(error_type);

            // Update peer reputation (non-malicious failure)
            rep.failures += 1;
            rep.last_failure = Some(Instant::now());

            // Re-queue the height for retry (with a different peer if possible)
            self.heights_to_fetch.push_back(height);
        } else {
            // Request was already handled (likely by timeout) - just log it
            trace!(
                height,
                ?peer,
                reason,
                "Late failure for already-handled request"
            );
        }
    }

    /// Select the best peer for a sync request.
    ///
    /// Selection criteria:
    /// 1. Only consider peers in our shard (from topology)
    /// 2. Exclude ourselves
    /// 3. Skip banned peers
    /// 4. Skip peers in cooldown (too many failures)
    /// 5. Skip peers with too many in-flight requests
    /// 6. Prefer peers with fewer in-flight requests
    /// 7. Prefer peers with fewer failures
    ///
    /// If all peers are in cooldown and we're significantly behind (desperation mode),
    /// cooldowns are reset to allow immediate retries.
    fn select_peer(&mut self) -> Option<PeerId> {
        let now = Instant::now();

        // Try normal peer selection first
        if let Some(peer) = self.select_peer_inner(now) {
            return Some(peer);
        }

        // No peers available - check if we should enter desperation mode
        let local_shard = self.topology.local_shard();
        let local_validator = self.topology.local_validator_id();
        let committee = self.topology.committee_for_shard(local_shard);
        let same_shard_count = committee.iter().filter(|&&v| v != local_validator).count();

        if same_shard_count == 0 {
            return None;
        }

        let in_cooldown_count = self
            .peer_reputations
            .values()
            .filter(|rep| {
                rep.failures >= self.config.max_retries_per_peer
                    && rep
                        .last_failure
                        .is_some_and(|lf| now.duration_since(lf) < self.config.peer_cooldown)
            })
            .count();
        let banned = self
            .peer_reputations
            .values()
            .filter(|rep| self.is_peer_banned_inner(rep, now))
            .count();
        let at_max_inflight = self
            .peer_reputations
            .values()
            .filter(|rep| rep.in_flight >= 2)
            .count();

        // Check for desperation mode: all peers blocked (cooldown or max in-flight) and we're far behind
        let blocks_behind = self.blocks_behind();
        let all_in_cooldown =
            in_cooldown_count == same_shard_count && banned == 0 && at_max_inflight == 0;
        let all_at_max_inflight =
            at_max_inflight == same_shard_count && banned == 0 && in_cooldown_count == 0;

        if all_in_cooldown && blocks_behind >= self.config.desperation_threshold_blocks {
            warn!(
                same_shard_peers = same_shard_count,
                blocks_behind,
                "DESPERATION MODE: All peers in cooldown but {} blocks behind - resetting cooldowns",
                blocks_behind
            );

            // Reset failure counts and cooldowns for all peers (but not bans)
            for rep in self.peer_reputations.values_mut() {
                if rep.banned_until.is_none() {
                    rep.failures = 0;
                    rep.last_failure = None;
                }
            }

            // Now retry peer selection with reset cooldowns
            return self.select_peer_inner(now);
        }

        // Desperation mode for stuck in-flight counters: if all peers are at max in-flight
        // and we're far behind, reset in-flight counters. This handles cases where spawned
        // fetch tasks hung or never reported results, leaving in_flight stuck.
        if all_at_max_inflight && blocks_behind >= self.config.desperation_threshold_blocks {
            warn!(
                same_shard_peers = same_shard_count,
                blocks_behind,
                at_max_inflight,
                "DESPERATION MODE: All peers at max in-flight but {} blocks behind - resetting in-flight counters",
                blocks_behind
            );

            // Reset in-flight counters for all peers (they're clearly stuck)
            for rep in self.peer_reputations.values_mut() {
                if rep.banned_until.is_none() {
                    rep.in_flight = 0;
                }
            }

            // Also clear pending fetches since they're clearly orphaned
            self.pending_fetches.clear();

            // Now retry peer selection with reset in-flight
            return self.select_peer_inner(now);
        }

        // Desperation mode for banned peers: if we have banned peers and we're far behind,
        // lift the bans. Bans are meant to protect against Byzantine peers, but if we're
        // stuck and can't make progress, we need to try again.
        if banned > 0 && blocks_behind >= self.config.desperation_threshold_blocks {
            warn!(
                same_shard_peers = same_shard_count,
                blocks_behind,
                banned,
                "DESPERATION MODE: {} peers banned but {} blocks behind - lifting bans",
                banned,
                blocks_behind
            );

            // Lift all bans
            for rep in self.peer_reputations.values_mut() {
                rep.banned_until = None;
                rep.failures = 0;
                rep.last_failure = None;
            }

            // Now retry peer selection with lifted bans
            return self.select_peer_inner(now);
        }

        warn!(
            same_shard_peers = same_shard_count,
            in_cooldown = in_cooldown_count,
            banned,
            at_max_inflight,
            "No sync peers available - all peers filtered out"
        );

        None
    }

    /// Inner peer selection logic (without desperation mode handling).
    fn select_peer_inner(&self, now: Instant) -> Option<PeerId> {
        let local_shard = self.topology.local_shard();
        let local_validator = self.topology.local_validator_id();
        let committee = self.topology.committee_for_shard(local_shard);

        // Build list of available peers from committee (excluding self)
        let available: Vec<_> = committee
            .iter()
            .filter(|&&v| v != local_validator)
            .filter_map(|&validator_id| {
                // Get peer ID from topology
                let pk = self.topology.public_key(validator_id)?;
                let peer_id = compute_peer_id_for_validator(&pk);

                // Check reputation filters
                if let Some(rep) = self.peer_reputations.get(&peer_id) {
                    // Skip banned peers
                    if self.is_peer_banned_inner(rep, now) {
                        return None;
                    }

                    // Check failure cooldown (for non-banned peers with many failures)
                    if rep.failures >= self.config.max_retries_per_peer {
                        if let Some(last_failure) = rep.last_failure {
                            if now.duration_since(last_failure) < self.config.peer_cooldown {
                                return None;
                            }
                        }
                    }

                    // Allow up to 2 concurrent requests per peer
                    if rep.in_flight >= 2 {
                        return None;
                    }
                }

                Some(peer_id)
            })
            .collect();

        if available.is_empty() {
            return None;
        }

        // Select peer with fewest in-flight requests and lowest failure count
        available.into_iter().min_by_key(|peer| {
            let rep = self
                .peer_reputations
                .get(peer)
                .map(|r| (r.in_flight, r.failures));
            rep.unwrap_or((0, 0))
        })
    }

    /// Check if a peer is banned (internal helper using pre-fetched Instant).
    fn is_peer_banned_inner(&self, rep: &PeerReputation, now: Instant) -> bool {
        rep.banned_until.is_some_and(|until| now < until)
    }

    /// Check if a peer is currently banned.
    pub fn is_peer_banned(&self, peer: &PeerId) -> bool {
        self.peer_reputations
            .get(peer)
            .map(|rep| self.is_peer_banned_inner(rep, Instant::now()))
            .unwrap_or(false)
    }

    /// Ban a peer for malicious behavior.
    ///
    /// Uses exponential backoff for repeat offenders:
    /// - 1st ban: base_ban_duration (default 10 min)
    /// - 2nd ban: base * 2 (20 min)
    /// - 3rd ban: base * 4 (40 min)
    /// - ... capped at max_ban_duration (default 24 hours)
    fn ban_peer(&mut self, peer: PeerId, error: &SyncResponseError) {
        let rep = self.peer_reputations.entry(peer).or_default();

        // Calculate ban duration with exponential backoff
        let multiplier = 2u32.saturating_pow(rep.ban_count.min(10));
        let ban_duration = self
            .config
            .base_ban_duration
            .saturating_mul(multiplier)
            .min(self.config.max_ban_duration);

        rep.banned_until = Some(Instant::now() + ban_duration);
        rep.ban_count += 1;

        warn!(
            ?peer,
            error = %error,
            ban_duration_secs = ban_duration.as_secs(),
            ban_count = rep.ban_count,
            "Banning peer for malicious sync response"
        );

        // Record metric
        metrics::record_sync_peer_banned();
    }

    /// Handle a sync response error.
    ///
    /// This method categorizes errors as malicious or non-malicious:
    /// - Malicious errors (invalid blocks, bad QCs) result in peer bans
    /// - Non-malicious errors (timeouts, network issues) just increment failure count
    /// - Empty responses (peer doesn't have the block) are tracked separately
    ///
    /// The height is re-queued for retry with a different peer.
    pub fn on_sync_response_error(&mut self, peer: PeerId, height: u64, error: SyncResponseError) {
        // Record the error metric
        metrics::record_sync_response_error(error.metric_label());

        // Get the tried_peers from the pending fetch before removing it
        let tried_peers = self
            .pending_fetches
            .remove(&height)
            .map(|f| {
                let mut tried = f.tried_peers;
                tried.insert(peer); // Add current peer to tried set
                tried
            })
            .unwrap_or_else(|| {
                let mut tried = HashSet::new();
                tried.insert(peer);
                tried
            });

        // Update in-flight count
        if let Some(rep) = self.peer_reputations.get_mut(&peer) {
            rep.in_flight = rep.in_flight.saturating_sub(1);
        }

        if error.is_malicious() {
            // Ban the peer for malicious behavior
            self.ban_peer(peer, &error);
        } else if error.is_empty_response() {
            // Empty response: peer doesn't have the block (probably also behind)
            // Track this separately from other failures
            let rep = self.peer_reputations.entry(peer).or_default();
            rep.empty_responses += 1;
            rep.last_empty_response = Some(Instant::now());
            debug!(
                ?peer,
                height,
                empty_responses = rep.empty_responses,
                "Peer returned empty sync response (doesn't have block)"
            );
        } else {
            // Non-malicious network error: increment failure count
            if let Some(rep) = self.peer_reputations.get_mut(&peer) {
                rep.failures += 1;
                rep.last_failure = Some(Instant::now());
            }
            debug!(
                ?peer,
                height,
                error = %error,
                "Non-malicious sync error"
            );
        }

        // Re-queue the height for retry with a different peer
        // Store the tried_peers so we can avoid them on retry
        self.queue_height_with_tried_peers(height, tried_peers);
    }

    /// Queue a height for fetching, tracking which peers have already been tried.
    fn queue_height_with_tried_peers(&mut self, height: u64, tried_peers: HashSet<PeerId>) {
        // Store tried peers for this height so spawn_fetch can use them
        // We use a simple approach: store in a separate map
        self.tried_peers_for_height.insert(height, tried_peers);
        self.heights_to_fetch.push_back(height);
    }

    /// Handle a block response from a peer.
    ///
    /// Decodes the response, validates the block and QC, and either:
    /// - Calls `on_block_received` for valid blocks
    /// - Calls `on_sync_response_error` for invalid/empty responses
    async fn handle_block_response(&mut self, height: u64, peer: PeerId, response_bytes: Vec<u8>) {
        // Decode the response: (Option<Block>, Option<QC>)
        let decoded: Result<(Option<Block>, Option<QuorumCertificate>), _> =
            sbor::basic_decode(&response_bytes);

        match decoded {
            Ok((Some(block), Some(qc))) => {
                // Validate block and QC
                match validate_sync_response(height, &block, &qc) {
                    Ok(()) => {
                        // Block and QC are valid - deliver to state machine
                        // Note: Full QC signature verification happens in BftState
                        self.on_block_received(height, block, qc, peer).await;
                    }
                    Err(error) => {
                        self.on_sync_response_error(peer, height, error);
                    }
                }
            }
            Ok((None, _)) | Ok((_, None)) => {
                // Peer doesn't have this block (empty response)
                let error = SyncResponseError::EmptyResponse { height };
                self.on_sync_response_error(peer, height, error);
            }
            Err(e) => {
                // Decode error - treat as network error (non-malicious)
                warn!(height, ?peer, error = ?e, "Failed to decode sync response");
                let error = SyncResponseError::NetworkError {
                    reason: format!("decode error: {e:?}"),
                };
                self.on_sync_response_error(peer, height, error);
            }
        }
    }

    /// Check for timed out requests.
    fn check_timeouts(&mut self) {
        let now = Instant::now();
        let timeout = self.config.initial_timeout;

        let timed_out: Vec<_> = self
            .pending_fetches
            .iter()
            .filter(|(_, fetch)| now.duration_since(fetch.started) > timeout)
            .map(|(h, f)| (*h, f.peer))
            .collect();

        for (height, peer) in timed_out {
            self.on_fetch_failed(height, peer, "timeout");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::ShardGroupId;
    use libp2p::PeerId;
    use std::time::Duration;

    /// Test-only helper to create a SyncManager without network dependencies.
    /// This creates a manager with mock/stub internals suitable for unit testing
    /// the peer reputation, banning, and status logic.
    fn create_test_sync_manager() -> TestSyncManager {
        TestSyncManager {
            config: SyncConfig::default(),
            sync_target: None,
            heights_to_fetch: VecDeque::new(),
            pending_fetches: HashMap::new(),
            peer_reputations: HashMap::new(),
            peer_shards: HashMap::new(),
            local_shard: ShardGroupId(0),
            committed_height: 0,
        }
    }

    /// A test-only version of SyncManager that doesn't require network.
    /// Contains the same fields as SyncManager that are relevant for testing
    /// peer reputation and sync status logic.
    struct TestSyncManager {
        config: SyncConfig,
        sync_target: Option<(u64, Hash)>,
        heights_to_fetch: VecDeque<u64>,
        pending_fetches: HashMap<u64, PendingFetch>,
        peer_reputations: HashMap<PeerId, PeerReputation>,
        peer_shards: HashMap<PeerId, ShardGroupId>,
        local_shard: ShardGroupId,
        committed_height: u64,
    }

    impl TestSyncManager {
        fn register_peer(&mut self, peer_id: PeerId) {
            self.peer_shards.insert(peer_id, self.local_shard);
            self.peer_reputations.entry(peer_id).or_default();
        }

        fn sync_peer_count(&self) -> usize {
            self.peer_shards
                .iter()
                .filter(|(_, &shard)| shard == self.local_shard)
                .count()
        }

        fn is_peer_banned(&self, peer: &PeerId) -> bool {
            self.peer_reputations
                .get(peer)
                .map(|rep| rep.banned_until.is_some_and(|until| Instant::now() < until))
                .unwrap_or(false)
        }

        fn ban_peer(&mut self, peer: PeerId, _error: &SyncResponseError) {
            let rep = self.peer_reputations.entry(peer).or_default();

            let multiplier = 2u32.saturating_pow(rep.ban_count.min(10));
            let ban_duration = self
                .config
                .base_ban_duration
                .saturating_mul(multiplier)
                .min(self.config.max_ban_duration);

            rep.banned_until = Some(Instant::now() + ban_duration);
            rep.ban_count += 1;
        }

        fn on_sync_response_error(&mut self, peer: PeerId, height: u64, error: SyncResponseError) {
            self.pending_fetches.remove(&height);

            if let Some(rep) = self.peer_reputations.get_mut(&peer) {
                rep.in_flight = rep.in_flight.saturating_sub(1);
            }

            if error.is_malicious() {
                self.ban_peer(peer, &error);
            } else if let Some(rep) = self.peer_reputations.get_mut(&peer) {
                rep.failures += 1;
                rep.last_failure = Some(Instant::now());
            }

            self.heights_to_fetch.push_back(height);
        }

        fn blocks_behind(&self) -> u64 {
            self.sync_target
                .map(|(target, _)| target.saturating_sub(self.committed_height))
                .unwrap_or(0)
        }

        fn select_peer(&mut self) -> Option<PeerId> {
            let now = Instant::now();

            // Try normal selection first
            if let Some(peer) = self.select_peer_inner(now) {
                return Some(peer);
            }

            // Check for desperation mode
            let same_shard_count = self
                .peer_shards
                .iter()
                .filter(|(_, &shard)| shard == self.local_shard)
                .count();

            if same_shard_count == 0 {
                return None;
            }

            let in_cooldown_count = self
                .peer_reputations
                .values()
                .filter(|rep| {
                    rep.failures >= self.config.max_retries_per_peer
                        && rep
                            .last_failure
                            .is_some_and(|lf| now.duration_since(lf) < self.config.peer_cooldown)
                })
                .count();
            let banned = self
                .peer_reputations
                .values()
                .filter(|rep| rep.banned_until.is_some_and(|until| now < until))
                .count();
            let at_max_inflight = self
                .peer_reputations
                .values()
                .filter(|rep| rep.in_flight >= 2)
                .count();

            let blocks_behind = self.blocks_behind();
            let all_in_cooldown =
                in_cooldown_count == same_shard_count && banned == 0 && at_max_inflight == 0;
            let all_at_max_inflight =
                at_max_inflight == same_shard_count && banned == 0 && in_cooldown_count == 0;

            if all_in_cooldown && blocks_behind >= self.config.desperation_threshold_blocks {
                // Reset cooldowns
                for rep in self.peer_reputations.values_mut() {
                    if rep.banned_until.is_none() {
                        rep.failures = 0;
                        rep.last_failure = None;
                    }
                }
                return self.select_peer_inner(now);
            }

            // Desperation mode for stuck in-flight counters
            if all_at_max_inflight && blocks_behind >= self.config.desperation_threshold_blocks {
                for rep in self.peer_reputations.values_mut() {
                    if rep.banned_until.is_none() {
                        rep.in_flight = 0;
                    }
                }
                self.pending_fetches.clear();
                return self.select_peer_inner(now);
            }

            None
        }

        fn select_peer_inner(&self, now: Instant) -> Option<PeerId> {
            let available: Vec<_> = self
                .peer_shards
                .iter()
                .filter(|(_, &shard)| shard == self.local_shard)
                .map(|(peer, _)| peer)
                .filter(|peer| {
                    if let Some(rep) = self.peer_reputations.get(peer) {
                        // Skip banned peers
                        if rep.banned_until.is_some_and(|until| now < until) {
                            return false;
                        }

                        // Check failure cooldown
                        if rep.failures >= self.config.max_retries_per_peer {
                            if let Some(last_failure) = rep.last_failure {
                                if now.duration_since(last_failure) < self.config.peer_cooldown {
                                    return false;
                                }
                            }
                        }

                        rep.in_flight < 2
                    } else {
                        true
                    }
                })
                .copied()
                .collect();

            if available.is_empty() {
                return None;
            }

            available.into_iter().min_by_key(|peer| {
                let rep = self
                    .peer_reputations
                    .get(peer)
                    .map(|r| (r.in_flight, r.failures));
                rep.unwrap_or((0, 0))
            })
        }

        fn state_kind(&self) -> SyncStateKind {
            if self.sync_target.is_some() {
                SyncStateKind::Syncing
            } else {
                SyncStateKind::Idle
            }
        }

        fn status(&self) -> SyncStatus {
            SyncStatus {
                state: self.state_kind(),
                current_height: self.committed_height,
                target_height: self.sync_target.map(|(h, _)| h),
                blocks_behind: self
                    .sync_target
                    .map(|(target, _)| target.saturating_sub(self.committed_height))
                    .unwrap_or(0),
                sync_peers: self.sync_peer_count(),
                pending_fetches: self.pending_fetches.len(),
                queued_heights: self.heights_to_fetch.len(),
            }
        }

        fn start_sync(&mut self, target_height: u64, target_hash: Hash) {
            self.sync_target = Some((target_height, target_hash));
            for h in (self.committed_height + 1)..=target_height {
                self.heights_to_fetch.push_back(h);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Existing tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_sync_config_defaults() {
        let config = SyncConfig::default();
        assert_eq!(config.max_concurrent_fetches, 16);
        assert_eq!(config.initial_timeout, Duration::from_millis(500));
        assert_eq!(config.max_retries_per_peer, 3);
    }

    #[test]
    fn test_peer_registration() {
        // Can't easily test without a network, but we can test the config
        let config = SyncConfig::default();
        assert!(config.max_concurrent_fetches > 0);
    }

    #[test]
    fn test_sync_state_kind_serialization() {
        // Test that SyncStateKind serializes correctly
        let idle = SyncStateKind::Idle;
        let syncing = SyncStateKind::Syncing;

        assert_eq!(idle.as_str(), "idle");
        assert_eq!(syncing.as_str(), "syncing");

        // Test JSON serialization
        let idle_json = serde_json::to_string(&idle).unwrap();
        let syncing_json = serde_json::to_string(&syncing).unwrap();

        assert_eq!(idle_json, "\"idle\"");
        assert_eq!(syncing_json, "\"syncing\"");
    }

    #[test]
    fn test_sync_status_serialization() {
        let status = SyncStatus {
            state: SyncStateKind::Syncing,
            current_height: 100,
            target_height: Some(200),
            blocks_behind: 100,
            sync_peers: 3,
            pending_fetches: 2,
            queued_heights: 98,
        };

        let json = serde_json::to_value(&status).unwrap();

        assert_eq!(json["state"], "syncing");
        assert_eq!(json["current_height"], 100);
        assert_eq!(json["target_height"], 200);
        assert_eq!(json["blocks_behind"], 100);
        assert_eq!(json["sync_peers"], 3);
        assert_eq!(json["pending_fetches"], 2);
        assert_eq!(json["queued_heights"], 98);
    }

    #[test]
    fn test_sync_status_idle() {
        let status = SyncStatus {
            state: SyncStateKind::Idle,
            current_height: 500,
            target_height: None,
            blocks_behind: 0,
            sync_peers: 5,
            pending_fetches: 0,
            queued_heights: 0,
        };

        let json = serde_json::to_value(&status).unwrap();

        assert_eq!(json["state"], "idle");
        assert_eq!(json["current_height"], 500);
        assert!(json["target_height"].is_null());
        assert_eq!(json["blocks_behind"], 0);
    }

    #[test]
    fn test_sync_config_ban_defaults() {
        let config = SyncConfig::default();
        assert_eq!(config.base_ban_duration, Duration::from_secs(600));
        assert_eq!(config.max_ban_duration, Duration::from_secs(86400));
    }

    #[test]
    fn test_peer_reputation_default() {
        let rep = PeerReputation::default();
        assert_eq!(rep.successes, 0);
        assert_eq!(rep.failures, 0);
        assert_eq!(rep.in_flight, 0);
        assert!(rep.banned_until.is_none());
        assert_eq!(rep.ban_count, 0);
        assert!(rep.last_success.is_none());
        assert!(rep.last_failure.is_none());
    }

    #[test]
    fn test_sync_response_error_malicious_detection() {
        // Test that malicious errors are correctly identified
        // These are errors where the peer sent provably invalid data
        let malicious_errors = [
            SyncResponseError::QcBlockHashMismatch { height: 1 },
            SyncResponseError::QcHeightMismatch {
                block_height: 1,
                qc_height: 2,
            },
            SyncResponseError::QcSignatureInvalid { height: 1 },
            SyncResponseError::QcInsufficientQuorum {
                height: 1,
                voting_power: 50,
                required: 67,
            },
            SyncResponseError::BlockHashMismatch { height: 1 },
            SyncResponseError::BlockParentMismatch { height: 1 },
        ];

        for err in malicious_errors {
            assert!(err.is_malicious(), "{} should be malicious", err);
        }

        // Test that non-malicious errors are correctly identified
        // These are transient issues that don't warrant banning
        let non_malicious_errors = [
            SyncResponseError::NoRequestPending,
            SyncResponseError::PeerMismatch,
            SyncResponseError::RequestIdMismatch {
                expected: 1,
                actual: 2,
            },
            SyncResponseError::StateMismatch {
                height: 10,
                current: 20,
            },
            SyncResponseError::Timeout { height: 1 },
            SyncResponseError::NetworkError {
                reason: "test".to_string(),
            },
            // EmptyResponse is non-malicious - peer may have pruned the block
            SyncResponseError::EmptyResponse { height: 1 },
        ];

        for err in non_malicious_errors {
            assert!(!err.is_malicious(), "{} should not be malicious", err);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Peer banning tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_ban_peer_sets_banned_until() {
        let mut mgr = create_test_sync_manager();
        let peer = PeerId::random();
        mgr.register_peer(peer);

        let error = SyncResponseError::QcBlockHashMismatch { height: 1 };
        mgr.ban_peer(peer, &error);

        // Peer should be banned
        assert!(mgr.is_peer_banned(&peer));

        // Ban count should be 1
        let rep = mgr.peer_reputations.get(&peer).unwrap();
        assert_eq!(rep.ban_count, 1);
        assert!(rep.banned_until.is_some());
    }

    #[test]
    fn test_ban_peer_exponential_backoff() {
        let mut mgr = create_test_sync_manager();
        // Use short durations for testing
        mgr.config.base_ban_duration = Duration::from_millis(100);
        mgr.config.max_ban_duration = Duration::from_secs(10);

        let peer = PeerId::random();
        mgr.register_peer(peer);

        let error = SyncResponseError::QcSignatureInvalid { height: 1 };

        // First ban: base duration (100ms)
        mgr.ban_peer(peer, &error);
        let rep = mgr.peer_reputations.get(&peer).unwrap();
        assert_eq!(rep.ban_count, 1);

        // Second ban: 2x base (200ms)
        mgr.ban_peer(peer, &error);
        let rep = mgr.peer_reputations.get(&peer).unwrap();
        assert_eq!(rep.ban_count, 2);

        // Third ban: 4x base (400ms)
        mgr.ban_peer(peer, &error);
        let rep = mgr.peer_reputations.get(&peer).unwrap();
        assert_eq!(rep.ban_count, 3);

        // Fourth ban: 8x base (800ms)
        mgr.ban_peer(peer, &error);
        let rep = mgr.peer_reputations.get(&peer).unwrap();
        assert_eq!(rep.ban_count, 4);
    }

    #[test]
    fn test_ban_duration_capped_at_max() {
        let mut mgr = create_test_sync_manager();
        mgr.config.base_ban_duration = Duration::from_secs(100);
        mgr.config.max_ban_duration = Duration::from_secs(500);

        let peer = PeerId::random();
        mgr.register_peer(peer);

        let error = SyncResponseError::BlockHashMismatch { height: 1 };

        // Ban multiple times to exceed max
        for _ in 0..10 {
            mgr.ban_peer(peer, &error);
        }

        // The ban duration should be capped, but we can verify ban_count increases
        let rep = mgr.peer_reputations.get(&peer).unwrap();
        assert_eq!(rep.ban_count, 10);
        // banned_until should be set (we can't easily check the exact duration without mocking time)
        assert!(rep.banned_until.is_some());
    }

    #[test]
    fn test_is_peer_banned_returns_false_for_unknown_peer() {
        let mgr = create_test_sync_manager();
        let unknown_peer = PeerId::random();

        // Unknown peer should not be considered banned
        assert!(!mgr.is_peer_banned(&unknown_peer));
    }

    #[test]
    fn test_is_peer_banned_returns_false_for_unbanned_peer() {
        let mut mgr = create_test_sync_manager();
        let peer = PeerId::random();
        mgr.register_peer(peer);

        // Registered but not banned peer should not be banned
        assert!(!mgr.is_peer_banned(&peer));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Peer selection tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_select_peer_returns_none_when_no_peers() {
        let mut mgr = create_test_sync_manager();
        assert!(mgr.select_peer().is_none());
    }

    #[test]
    fn test_select_peer_returns_available_peer() {
        let mut mgr = create_test_sync_manager();
        let peer = PeerId::random();
        mgr.register_peer(peer);

        let selected = mgr.select_peer();
        assert_eq!(selected, Some(peer));
    }

    #[test]
    fn test_select_peer_skips_banned_peers() {
        let mut mgr = create_test_sync_manager();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        mgr.register_peer(peer1);
        mgr.register_peer(peer2);

        // Ban peer1
        let error = SyncResponseError::QcBlockHashMismatch { height: 1 };
        mgr.ban_peer(peer1, &error);

        // Should select peer2 (the non-banned one)
        let selected = mgr.select_peer();
        assert_eq!(selected, Some(peer2));
    }

    #[test]
    fn test_select_peer_returns_none_when_all_banned() {
        let mut mgr = create_test_sync_manager();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        mgr.register_peer(peer1);
        mgr.register_peer(peer2);

        // Ban both peers
        let error = SyncResponseError::QcBlockHashMismatch { height: 1 };
        mgr.ban_peer(peer1, &error);
        mgr.ban_peer(peer2, &error);

        // No peers available
        assert!(mgr.select_peer().is_none());
    }

    #[test]
    fn test_select_peer_prefers_fewer_in_flight() {
        let mut mgr = create_test_sync_manager();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        mgr.register_peer(peer1);
        mgr.register_peer(peer2);

        // Give peer1 an in-flight request
        mgr.peer_reputations.get_mut(&peer1).unwrap().in_flight = 1;

        // Should prefer peer2 (fewer in-flight)
        let selected = mgr.select_peer();
        assert_eq!(selected, Some(peer2));
    }

    #[test]
    fn test_select_peer_skips_peers_at_max_in_flight() {
        let mut mgr = create_test_sync_manager();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        mgr.register_peer(peer1);
        mgr.register_peer(peer2);

        // Give peer1 max in-flight requests (2)
        mgr.peer_reputations.get_mut(&peer1).unwrap().in_flight = 2;

        // Should only return peer2
        let selected = mgr.select_peer();
        assert_eq!(selected, Some(peer2));
    }

    #[test]
    fn test_select_peer_skips_peers_in_cooldown() {
        let mut mgr = create_test_sync_manager();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        mgr.register_peer(peer1);
        mgr.register_peer(peer2);

        // Put peer1 in cooldown (max failures + recent failure)
        let rep1 = mgr.peer_reputations.get_mut(&peer1).unwrap();
        rep1.failures = mgr.config.max_retries_per_peer;
        rep1.last_failure = Some(Instant::now());

        // Should select peer2 (peer1 is in cooldown)
        let selected = mgr.select_peer();
        assert_eq!(selected, Some(peer2));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Desperation mode tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_desperation_mode_resets_cooldowns_when_far_behind() {
        let mut mgr = create_test_sync_manager();
        mgr.config.desperation_threshold_blocks = 10;

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        mgr.register_peer(peer1);
        mgr.register_peer(peer2);

        // Put both peers in cooldown
        for peer in [peer1, peer2] {
            let rep = mgr.peer_reputations.get_mut(&peer).unwrap();
            rep.failures = mgr.config.max_retries_per_peer;
            rep.last_failure = Some(Instant::now());
        }

        // Without sync target (not behind), should return None
        assert!(mgr.select_peer().is_none());

        // Start syncing - now we're 20 blocks behind (above threshold)
        mgr.committed_height = 80;
        mgr.start_sync(100, Hash::from_bytes(&[1u8; 32]));

        // With desperation mode, should reset cooldowns and return a peer
        let selected = mgr.select_peer();
        assert!(selected.is_some());

        // Verify cooldowns were reset
        for peer in [peer1, peer2] {
            let rep = mgr.peer_reputations.get(&peer).unwrap();
            assert_eq!(rep.failures, 0);
            assert!(rep.last_failure.is_none());
        }
    }

    #[test]
    fn test_desperation_mode_does_not_trigger_when_not_far_behind() {
        let mut mgr = create_test_sync_manager();
        mgr.config.desperation_threshold_blocks = 10;

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        mgr.register_peer(peer1);
        mgr.register_peer(peer2);

        // Put both peers in cooldown
        for peer in [peer1, peer2] {
            let rep = mgr.peer_reputations.get_mut(&peer).unwrap();
            rep.failures = mgr.config.max_retries_per_peer;
            rep.last_failure = Some(Instant::now());
        }

        // Only 5 blocks behind (below threshold of 10)
        mgr.committed_height = 95;
        mgr.start_sync(100, Hash::from_bytes(&[1u8; 32]));

        // Should still return None (not desperate enough)
        assert!(mgr.select_peer().is_none());

        // Verify cooldowns were NOT reset
        for peer in [peer1, peer2] {
            let rep = mgr.peer_reputations.get(&peer).unwrap();
            assert_eq!(rep.failures, mgr.config.max_retries_per_peer);
            assert!(rep.last_failure.is_some());
        }
    }

    #[test]
    fn test_desperation_mode_does_not_reset_bans() {
        let mut mgr = create_test_sync_manager();
        mgr.config.desperation_threshold_blocks = 10;

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        mgr.register_peer(peer1);
        mgr.register_peer(peer2);

        // Ban peer1 (malicious)
        let error = SyncResponseError::QcBlockHashMismatch { height: 1 };
        mgr.ban_peer(peer1, &error);

        // Put peer2 in cooldown
        let rep2 = mgr.peer_reputations.get_mut(&peer2).unwrap();
        rep2.failures = mgr.config.max_retries_per_peer;
        rep2.last_failure = Some(Instant::now());

        // 20 blocks behind
        mgr.committed_height = 80;
        mgr.start_sync(100, Hash::from_bytes(&[1u8; 32]));

        // Desperation mode should NOT reset the ban, only the cooldown
        // Since peer1 is banned and peer2 is in cooldown, but it's not "all in cooldown"
        // (one is banned), desperation mode shouldn't trigger
        // Actually, desperation mode only triggers when ALL peers are in cooldown (not banned)
        // In this case, only peer2 is in cooldown, peer1 is banned, so it won't trigger
        assert!(mgr.select_peer().is_none());

        // peer1 should still be banned
        assert!(mgr.is_peer_banned(&peer1));
    }

    #[test]
    fn test_desperation_mode_only_resets_cooldowns_not_bans() {
        let mut mgr = create_test_sync_manager();
        mgr.config.desperation_threshold_blocks = 10;

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();
        mgr.register_peer(peer1);
        mgr.register_peer(peer2);
        mgr.register_peer(peer3);

        // Put all peers in cooldown
        for peer in [peer1, peer2, peer3] {
            let rep = mgr.peer_reputations.get_mut(&peer).unwrap();
            rep.failures = mgr.config.max_retries_per_peer;
            rep.last_failure = Some(Instant::now());
        }

        // 20 blocks behind
        mgr.committed_height = 80;
        mgr.start_sync(100, Hash::from_bytes(&[1u8; 32]));

        // Should trigger desperation mode and return a peer
        let selected = mgr.select_peer();
        assert!(selected.is_some());

        // All cooldowns should be reset
        for peer in [peer1, peer2, peer3] {
            let rep = mgr.peer_reputations.get(&peer).unwrap();
            assert_eq!(rep.failures, 0, "Cooldown should be reset for {:?}", peer);
        }
    }

    #[test]
    fn test_desperation_mode_for_stuck_in_flight() {
        let mut mgr = create_test_sync_manager();
        mgr.config.desperation_threshold_blocks = 10;

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();
        mgr.register_peer(peer1);
        mgr.register_peer(peer2);
        mgr.register_peer(peer3);

        // Put all peers at max in-flight (simulating stuck counters)
        for peer in [peer1, peer2, peer3] {
            let rep = mgr.peer_reputations.get_mut(&peer).unwrap();
            rep.in_flight = 2; // At max in-flight threshold
        }

        // 20 blocks behind
        mgr.committed_height = 80;
        mgr.start_sync(100, Hash::from_bytes(&[1u8; 32]));

        // Should trigger desperation mode for in-flight and return a peer
        let selected = mgr.select_peer();
        assert!(selected.is_some());

        // All in-flight counters should be reset
        for peer in [peer1, peer2, peer3] {
            let rep = mgr.peer_reputations.get(&peer).unwrap();
            assert_eq!(rep.in_flight, 0, "In-flight should be reset for {:?}", peer);
        }
    }

    #[test]
    fn test_desperation_mode_for_in_flight_does_not_trigger_when_not_far_behind() {
        let mut mgr = create_test_sync_manager();
        mgr.config.desperation_threshold_blocks = 10;

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        mgr.register_peer(peer1);
        mgr.register_peer(peer2);

        // Put all peers at max in-flight
        for peer in [peer1, peer2] {
            let rep = mgr.peer_reputations.get_mut(&peer).unwrap();
            rep.in_flight = 2;
        }

        // Only 5 blocks behind (below threshold of 10)
        mgr.committed_height = 95;
        mgr.start_sync(100, Hash::from_bytes(&[1u8; 32]));

        // Should still return None (not desperate enough)
        assert!(mgr.select_peer().is_none());

        // In-flight counters should NOT be reset
        for peer in [peer1, peer2] {
            let rep = mgr.peer_reputations.get(&peer).unwrap();
            assert_eq!(rep.in_flight, 2);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // on_sync_response_error tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_on_sync_response_error_bans_for_malicious() {
        let mut mgr = create_test_sync_manager();
        let peer = PeerId::random();
        mgr.register_peer(peer);

        // Add a pending fetch to be removed
        mgr.pending_fetches.insert(
            100,
            PendingFetch {
                height: 100,
                peer,
                started: Instant::now(),
                retries: 0,
                tried_peers: HashSet::new(),
            },
        );

        // Send a malicious error
        let error = SyncResponseError::QcSignatureInvalid { height: 100 };
        mgr.on_sync_response_error(peer, 100, error);

        // Peer should be banned
        assert!(mgr.is_peer_banned(&peer));

        // Height should be re-queued
        assert!(mgr.heights_to_fetch.contains(&100));

        // Pending fetch should be removed
        assert!(!mgr.pending_fetches.contains_key(&100));
    }

    #[test]
    fn test_on_sync_response_error_no_ban_for_non_malicious() {
        let mut mgr = create_test_sync_manager();
        let peer = PeerId::random();
        mgr.register_peer(peer);

        // Send a non-malicious error
        let error = SyncResponseError::Timeout { height: 100 };
        mgr.on_sync_response_error(peer, 100, error);

        // Peer should NOT be banned
        assert!(!mgr.is_peer_banned(&peer));

        // But failure count should increase
        let rep = mgr.peer_reputations.get(&peer).unwrap();
        assert_eq!(rep.failures, 1);
        assert!(rep.last_failure.is_some());

        // Height should be re-queued
        assert!(mgr.heights_to_fetch.contains(&100));
    }

    #[test]
    fn test_on_sync_response_error_empty_response_not_malicious() {
        let mut mgr = create_test_sync_manager();
        let peer = PeerId::random();
        mgr.register_peer(peer);

        // EmptyResponse is non-malicious (peer may have pruned the block)
        let error = SyncResponseError::EmptyResponse { height: 100 };
        mgr.on_sync_response_error(peer, 100, error);

        // Peer should NOT be banned
        assert!(!mgr.is_peer_banned(&peer));

        // Failure count should increase
        let rep = mgr.peer_reputations.get(&peer).unwrap();
        assert_eq!(rep.failures, 1);
    }

    #[test]
    fn test_on_sync_response_error_decrements_in_flight() {
        let mut mgr = create_test_sync_manager();
        let peer = PeerId::random();
        mgr.register_peer(peer);

        // Set in_flight to 2
        mgr.peer_reputations.get_mut(&peer).unwrap().in_flight = 2;

        let error = SyncResponseError::NetworkError {
            reason: "test".to_string(),
        };
        mgr.on_sync_response_error(peer, 100, error);

        // in_flight should be decremented
        let rep = mgr.peer_reputations.get(&peer).unwrap();
        assert_eq!(rep.in_flight, 1);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Status API tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_status_when_idle() {
        let mut mgr = create_test_sync_manager();
        mgr.committed_height = 100;

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        mgr.register_peer(peer1);
        mgr.register_peer(peer2);

        let status = mgr.status();

        assert_eq!(status.state, SyncStateKind::Idle);
        assert_eq!(status.current_height, 100);
        assert_eq!(status.target_height, None);
        assert_eq!(status.blocks_behind, 0);
        assert_eq!(status.sync_peers, 2);
        assert_eq!(status.pending_fetches, 0);
        assert_eq!(status.queued_heights, 0);
    }

    #[test]
    fn test_status_when_syncing() {
        let mut mgr = create_test_sync_manager();
        mgr.committed_height = 50;

        let peer = PeerId::random();
        mgr.register_peer(peer);

        // Start syncing to height 100
        mgr.start_sync(100, Hash::from_bytes(&[1u8; 32]));

        let status = mgr.status();

        assert_eq!(status.state, SyncStateKind::Syncing);
        assert_eq!(status.current_height, 50);
        assert_eq!(status.target_height, Some(100));
        assert_eq!(status.blocks_behind, 50);
        assert_eq!(status.sync_peers, 1);
        assert_eq!(status.pending_fetches, 0);
        assert_eq!(status.queued_heights, 50); // heights 51-100
    }

    #[test]
    fn test_status_with_pending_fetches() {
        let mut mgr = create_test_sync_manager();
        mgr.committed_height = 50;

        let peer = PeerId::random();
        mgr.register_peer(peer);

        mgr.start_sync(100, Hash::from_bytes(&[1u8; 32]));

        // Add some pending fetches
        mgr.pending_fetches.insert(
            51,
            PendingFetch {
                height: 51,
                peer,
                started: Instant::now(),
                retries: 0,
                tried_peers: HashSet::new(),
            },
        );
        mgr.pending_fetches.insert(
            52,
            PendingFetch {
                height: 52,
                peer,
                started: Instant::now(),
                retries: 0,
                tried_peers: HashSet::new(),
            },
        );

        let status = mgr.status();

        assert_eq!(status.pending_fetches, 2);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Sync response validation tests
    // ═══════════════════════════════════════════════════════════════════════════

    use hyperscale_types::{BlockHeader, Signature, SignerBitfield, ValidatorId, VotePower};

    fn make_test_block(height: u64) -> Block {
        Block {
            header: BlockHeader {
                height: BlockHeight(height),
                parent_hash: Hash::from_bytes(&[0u8; 32]),
                parent_qc: QuorumCertificate::genesis(),
                proposer: ValidatorId(0),
                timestamp: 0,
                round: 0,
                is_fallback: false,
            },
            transactions: vec![],
            committed_certificates: vec![],
            deferred: vec![],
            aborted: vec![],
            commitment_proofs: std::collections::HashMap::new(),
        }
    }

    fn make_valid_qc_for_block(block: &Block) -> QuorumCertificate {
        QuorumCertificate {
            block_hash: block.hash(),
            height: block.header.height,
            parent_block_hash: block.header.parent_hash,
            round: block.header.round,
            aggregated_signature: Signature::zero(),
            signers: SignerBitfield::new(0),
            voting_power: VotePower(u64::MAX),
            weighted_timestamp_ms: 0,
        }
    }

    #[test]
    fn test_validate_sync_response_valid() {
        let block = make_test_block(100);
        let qc = make_valid_qc_for_block(&block);

        let result = validate_sync_response(100, &block, &qc);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_sync_response_wrong_height() {
        let block = make_test_block(100);
        let qc = make_valid_qc_for_block(&block);

        // Request height 99, but block is at height 100
        let result = validate_sync_response(99, &block, &qc);
        assert!(matches!(
            result,
            Err(SyncResponseError::StateMismatch {
                height: 100,
                current: 99
            })
        ));
    }

    #[test]
    fn test_validate_sync_response_qc_hash_mismatch() {
        let block = make_test_block(100);
        let mut qc = make_valid_qc_for_block(&block);
        // Corrupt the QC's block hash
        qc.block_hash = Hash::from_bytes(&[0xFFu8; 32]);

        let result = validate_sync_response(100, &block, &qc);
        assert!(matches!(
            result,
            Err(SyncResponseError::QcBlockHashMismatch { height: 100 })
        ));

        // This should be malicious
        assert!(result.unwrap_err().is_malicious());
    }

    #[test]
    fn test_validate_sync_response_qc_height_mismatch() {
        let block = make_test_block(100);
        let mut qc = make_valid_qc_for_block(&block);
        // Corrupt the QC's height
        qc.height = BlockHeight(99);

        let result = validate_sync_response(100, &block, &qc);
        assert!(matches!(
            result,
            Err(SyncResponseError::QcHeightMismatch {
                block_height: 100,
                qc_height: 99
            })
        ));

        // This should be malicious
        assert!(result.unwrap_err().is_malicious());
    }

    #[test]
    fn test_validate_sync_response_all_checks_pass_in_order() {
        // Height mismatch should be caught first (before QC validation)
        let block = make_test_block(100);
        let mut qc = make_valid_qc_for_block(&block);
        qc.block_hash = Hash::from_bytes(&[0xFFu8; 32]); // Bad hash
        qc.height = BlockHeight(99); // Bad height

        // Request wrong height - should report StateMismatch, not QC errors
        let result = validate_sync_response(50, &block, &qc);
        assert!(matches!(
            result,
            Err(SyncResponseError::StateMismatch { .. })
        ));
    }
}
