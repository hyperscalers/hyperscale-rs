//! Fetch manager for retrieving missing transactions and certificates from peers.
//!
//! The fetch manager handles all aspects of transaction and certificate fetching:
//! - Peer selection with fallback (proposer first, then other committee members)
//! - Parallel fetch requests for improved throughput
//! - Automatic retries with exponential backoff
//! - Request deduplication to avoid redundant network traffic
//! - Peer reputation tracking for reliability
//!
//! # Architecture
//!
//! When a block header arrives but transactions/certificates are missing, the BFT
//! layer emits `Action::FetchTransactions` or `Action::FetchCertificates`. The
//! `FetchManager` handles these by:
//!
//! 1. Checking if we already have an in-flight request for this block
//! 2. Selecting peers to request from (proposer + fallback peers)
//! 3. Spawning concurrent fetch tasks
//! 4. Processing responses and delivering data via events
//! 5. Retrying failed requests with different peers
//!
//! This mirrors the `SyncManager` pattern but optimized for smaller, more frequent
//! requests that need low latency.

use crate::metrics;
use crate::network::Libp2pAdapter;
use crate::storage::RocksDbStorage;
use hyperscale_core::Event;
use hyperscale_messages::response::{GetCertificatesResponse, GetTransactionsResponse};
use hyperscale_types::{Hash, RoutableTransaction, TransactionCertificate, ValidatorId};
use libp2p::PeerId;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

// ═══════════════════════════════════════════════════════════════════════════
// Fetch Configuration
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration for the fetch manager.
#[derive(Debug, Clone)]
pub struct FetchConfig {
    /// Maximum number of concurrent fetch requests per block.
    /// Higher values increase parallelism but also network load.
    pub max_concurrent_per_block: usize,

    /// Maximum total concurrent fetch requests across all blocks.
    /// Prevents overwhelming the network during many pending blocks.
    pub max_total_concurrent: usize,

    /// Initial timeout for fetch requests.
    pub initial_timeout: Duration,

    /// Maximum timeout for fetch requests (after exponential backoff).
    pub max_timeout: Duration,

    /// Maximum retries before giving up on a fetch request.
    pub max_retries: u32,

    /// Cooldown period before retrying a failed peer.
    pub peer_cooldown: Duration,

    /// How long to wait before considering a fetch stale (for cleanup).
    pub stale_fetch_timeout: Duration,

    /// Maximum number of hashes to request in a single fetch.
    /// Larger batches are chunked into multiple requests.
    pub max_hashes_per_request: usize,

    /// Number of peers to fetch from immediately in parallel.
    /// When a fetch request arrives, we spawn requests to this many peers
    /// simultaneously instead of waiting for the first peer to time out.
    /// This reduces latency under CPU pressure at the cost of redundant requests.
    /// Set to 1 to disable proactive parallel fetching.
    pub proactive_parallel_peers: usize,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            // Increased to allow parallel chunked fetching across more peers
            max_concurrent_per_block: 8,
            max_total_concurrent: 32,
            initial_timeout: Duration::from_millis(500),
            max_timeout: Duration::from_secs(5),
            max_retries: 3,
            // Short cooldown allows quick recovery from transient failures.
            // Failed peers can be retried quickly while still avoiding
            // hammering a truly unavailable peer.
            peer_cooldown: Duration::from_secs(3),
            stale_fetch_timeout: Duration::from_secs(30),
            // Smaller chunks for better parallelization across peers
            max_hashes_per_request: 50,
            // Fetch from 4 peers in parallel by default to enable chunked
            // parallel fetching for large requests (e.g., 335 certs across 4 peers)
            proactive_parallel_peers: 4,
        }
    }
}

impl FetchConfig {
    /// Create config optimized for low-latency local networks.
    #[cfg(test)]
    pub fn for_local() -> Self {
        Self {
            initial_timeout: Duration::from_millis(100),
            max_timeout: Duration::from_secs(1),
            peer_cooldown: Duration::from_secs(2),
            ..Default::default()
        }
    }

    /// Create config for high-latency WANs.
    #[cfg(test)]
    pub fn for_wan() -> Self {
        Self {
            initial_timeout: Duration::from_secs(2),
            max_timeout: Duration::from_secs(15),
            peer_cooldown: Duration::from_secs(30),
            ..Default::default()
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Fetch Types
// ═══════════════════════════════════════════════════════════════════════════

/// Type of fetch request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FetchKind {
    /// Fetching transactions for a pending block.
    Transaction,
    /// Fetching certificates for a pending block.
    Certificate,
}

impl FetchKind {
    /// Returns a string representation for metrics/logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            FetchKind::Transaction => "transaction",
            FetchKind::Certificate => "certificate",
        }
    }
}

/// Unique identifier for a fetch request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FetchId {
    /// The block hash this fetch is for.
    pub block_hash: Hash,
    /// The type of fetch.
    pub kind: FetchKind,
}

/// Result of an async fetch operation.
#[derive(Debug)]
pub enum FetchResult {
    /// Successfully fetched transactions.
    TransactionsReceived {
        block_hash: Hash,
        peer: PeerId,
        transactions: Vec<Arc<RoutableTransaction>>,
    },
    /// Successfully fetched certificates.
    CertificatesReceived {
        block_hash: Hash,
        peer: PeerId,
        certificates: Vec<TransactionCertificate>,
    },
    /// Failed to fetch.
    Failed {
        block_hash: Hash,
        kind: FetchKind,
        peer: PeerId,
        error: String,
    },
}

/// A pending fetch request (tracking in-flight requests).
#[derive(Debug)]
struct PendingFetchRequest {
    /// The peer we're fetching from.
    #[allow(dead_code)]
    peer: PeerId,
    /// When the request was sent.
    started: Instant,
    /// Current retry count for this peer.
    #[allow(dead_code)]
    retries: u32,
}

/// State for a block's fetch operation (may have multiple in-flight requests).
#[derive(Debug)]
struct BlockFetchState {
    /// The block hash.
    #[allow(dead_code)]
    block_hash: Hash,
    /// The type of fetch (transaction or certificate).
    #[allow(dead_code)]
    kind: FetchKind,
    /// The original proposer (preferred peer).
    proposer: ValidatorId,
    /// Hashes we still need to fetch.
    missing_hashes: HashSet<Hash>,
    /// Hashes we've received.
    received_hashes: HashSet<Hash>,
    /// Currently in-flight requests (peer -> request state).
    in_flight: HashMap<PeerId, PendingFetchRequest>,
    /// Peers we've already tried (for rotation).
    tried_peers: HashSet<PeerId>,
    /// When this fetch was started.
    created: Instant,
    /// Total retry count across all peers.
    total_retries: u32,
}

impl BlockFetchState {
    fn new(block_hash: Hash, kind: FetchKind, proposer: ValidatorId, hashes: Vec<Hash>) -> Self {
        Self {
            block_hash,
            kind,
            proposer,
            missing_hashes: hashes.into_iter().collect(),
            received_hashes: HashSet::new(),
            in_flight: HashMap::new(),
            tried_peers: HashSet::new(),
            created: Instant::now(),
            total_retries: 0,
        }
    }

    /// Check if this fetch is complete (all hashes received).
    fn is_complete(&self) -> bool {
        self.missing_hashes.is_empty()
    }

    /// Check if this fetch is stale (too old).
    fn is_stale(&self, timeout: Duration) -> bool {
        self.created.elapsed() > timeout
    }

    /// Mark hashes as received.
    fn mark_received(&mut self, hashes: impl IntoIterator<Item = Hash>) {
        for hash in hashes {
            if self.missing_hashes.remove(&hash) {
                self.received_hashes.insert(hash);
            }
        }
    }

    /// Get hashes that are still missing and not currently being fetched.
    fn unfetched_hashes(&self) -> Vec<Hash> {
        self.missing_hashes.iter().copied().collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Peer Reputation
// ═══════════════════════════════════════════════════════════════════════════

/// Peer reputation for fetch operations.
#[derive(Debug, Clone, Default)]
pub struct FetchPeerReputation {
    /// Number of successful fetch responses.
    pub successes: u32,
    /// Number of failed fetch attempts.
    pub failures: u32,
    /// Number of currently in-flight requests to this peer.
    pub in_flight: u32,
    /// Time of last failure (for cooldown calculation).
    pub last_failure: Option<Instant>,
}

impl FetchPeerReputation {
    /// Check if this peer is in cooldown.
    fn is_in_cooldown(&self, cooldown: Duration) -> bool {
        self.last_failure
            .map(|t| t.elapsed() < cooldown)
            .unwrap_or(false)
    }

    /// Calculate a score for peer selection (higher is better).
    fn score(&self) -> i32 {
        let success_score = self.successes as i32 * 10;
        let failure_penalty = self.failures as i32 * 5;
        let in_flight_penalty = self.in_flight as i32 * 2;
        success_score - failure_penalty - in_flight_penalty
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Fetch Status (for external APIs)
// ═══════════════════════════════════════════════════════════════════════════

/// Fetch status for external APIs.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FetchStatus {
    /// Number of blocks with pending transaction fetches.
    pub pending_tx_blocks: usize,
    /// Number of blocks with pending certificate fetches.
    pub pending_cert_blocks: usize,
    /// Total in-flight requests.
    pub in_flight_requests: usize,
    /// Number of tracked peers.
    pub tracked_peers: usize,
}

// ═══════════════════════════════════════════════════════════════════════════
// FetchManager Implementation
// ═══════════════════════════════════════════════════════════════════════════

/// Manages fetching of transactions and certificates from peers.
///
/// The FetchManager coordinates all aspects of data fetching:
/// - Receives fetch requests from BFT actions
/// - Selects appropriate peers (proposer first, then fallbacks)
/// - Spawns concurrent fetch tasks
/// - Processes responses and delivers data
/// - Handles retries and failures
pub struct FetchManager {
    /// Configuration.
    config: FetchConfig,
    /// Network adapter for sending requests.
    network: Arc<Libp2pAdapter>,
    /// Storage for persisting fetched data.
    /// Fetched transactions and certificates are eagerly persisted to ensure
    /// they're available for sync requests from peers.
    storage: Arc<RocksDbStorage>,
    /// Event sender for delivering fetched data.
    event_tx: mpsc::Sender<Event>,
    /// Pending transaction fetches by block hash.
    tx_fetches: HashMap<Hash, BlockFetchState>,
    /// Pending certificate fetches by block hash.
    cert_fetches: HashMap<Hash, BlockFetchState>,
    /// Peer reputations for fetch operations.
    peer_reputations: HashMap<PeerId, FetchPeerReputation>,
    /// Known committee members (ValidatorId -> PeerId).
    /// Used for fallback peer selection.
    committee_peers: HashMap<ValidatorId, PeerId>,
    /// Queue of pending fetch tasks (block_hash, kind).
    /// Used when we're at max concurrent and need to wait.
    pending_queue: VecDeque<FetchId>,
    /// Channel for receiving results from spawned fetch tasks.
    result_rx: mpsc::Receiver<FetchResult>,
    /// Sender for spawned fetch tasks to report results.
    result_tx: mpsc::Sender<FetchResult>,
    /// Total in-flight requests (for limiting).
    total_in_flight: usize,
}

impl FetchManager {
    /// Create a new fetch manager.
    pub fn new(
        config: FetchConfig,
        network: Arc<Libp2pAdapter>,
        storage: Arc<RocksDbStorage>,
        event_tx: mpsc::Sender<Event>,
    ) -> Self {
        // Channel for fetch results - buffer size matches max concurrent
        let (result_tx, result_rx) = mpsc::channel(config.max_total_concurrent.max(32));

        Self {
            config,
            network,
            storage,
            event_tx,
            tx_fetches: HashMap::new(),
            cert_fetches: HashMap::new(),
            peer_reputations: HashMap::new(),
            committee_peers: HashMap::new(),
            pending_queue: VecDeque::new(),
            result_rx,
            result_tx,
            total_in_flight: 0,
        }
    }

    /// Register a committee member's peer ID.
    ///
    /// Called during initialization to build the peer map for fallback selection.
    pub fn register_committee_member(&mut self, validator_id: ValidatorId, peer_id: PeerId) {
        self.committee_peers.insert(validator_id, peer_id);
        self.peer_reputations.entry(peer_id).or_default();
        debug!(
            validator_id = validator_id.0,
            ?peer_id,
            "Registered committee member for fetch"
        );
    }

    /// Get the current fetch status for external APIs.
    pub fn status(&self) -> FetchStatus {
        FetchStatus {
            pending_tx_blocks: self.tx_fetches.len(),
            pending_cert_blocks: self.cert_fetches.len(),
            in_flight_requests: self.total_in_flight,
            tracked_peers: self.peer_reputations.len(),
        }
    }

    /// Request transactions for a pending block.
    ///
    /// Called when BFT emits `Action::FetchTransactions`.
    pub fn request_transactions(
        &mut self,
        block_hash: Hash,
        proposer: ValidatorId,
        tx_hashes: Vec<Hash>,
    ) {
        if tx_hashes.is_empty() {
            return;
        }

        // Check if we already have a fetch for this block
        if let Some(state) = self.tx_fetches.get_mut(&block_hash) {
            // Update missing hashes (BFT may have received some via gossip)
            let new_missing: HashSet<Hash> = tx_hashes.into_iter().collect();
            state.missing_hashes = state
                .missing_hashes
                .intersection(&new_missing)
                .copied()
                .collect();
            debug!(
                ?block_hash,
                remaining = state.missing_hashes.len(),
                "Updated existing transaction fetch"
            );
            return;
        }

        info!(
            ?block_hash,
            proposer = proposer.0,
            count = tx_hashes.len(),
            "Starting transaction fetch"
        );

        // Create new fetch state
        let state = BlockFetchState::new(block_hash, FetchKind::Transaction, proposer, tx_hashes);
        self.tx_fetches.insert(block_hash, state);

        // Queue for processing
        self.pending_queue.push_back(FetchId {
            block_hash,
            kind: FetchKind::Transaction,
        });

        metrics::record_fetch_started(FetchKind::Transaction);
    }

    /// Request certificates for a pending block.
    ///
    /// Called when BFT emits `Action::FetchCertificates`.
    pub fn request_certificates(
        &mut self,
        block_hash: Hash,
        proposer: ValidatorId,
        cert_hashes: Vec<Hash>,
    ) {
        if cert_hashes.is_empty() {
            return;
        }

        // Check if we already have a fetch for this block
        if let Some(state) = self.cert_fetches.get_mut(&block_hash) {
            // Update missing hashes
            let new_missing: HashSet<Hash> = cert_hashes.into_iter().collect();
            state.missing_hashes = state
                .missing_hashes
                .intersection(&new_missing)
                .copied()
                .collect();
            debug!(
                ?block_hash,
                remaining = state.missing_hashes.len(),
                "Updated existing certificate fetch"
            );
            return;
        }

        info!(
            ?block_hash,
            proposer = proposer.0,
            count = cert_hashes.len(),
            "Starting certificate fetch"
        );

        // Create new fetch state
        let state = BlockFetchState::new(block_hash, FetchKind::Certificate, proposer, cert_hashes);
        self.cert_fetches.insert(block_hash, state);

        // Queue for processing
        self.pending_queue.push_back(FetchId {
            block_hash,
            kind: FetchKind::Certificate,
        });

        metrics::record_fetch_started(FetchKind::Certificate);
    }

    /// Cancel a fetch for a block (e.g., block completed via gossip).
    #[allow(dead_code)]
    pub fn cancel_fetch(&mut self, block_hash: Hash, kind: FetchKind) {
        let removed = match kind {
            FetchKind::Transaction => self.tx_fetches.remove(&block_hash).is_some(),
            FetchKind::Certificate => self.cert_fetches.remove(&block_hash).is_some(),
        };

        if removed {
            debug!(?block_hash, ?kind, "Cancelled fetch");
            // Remove from pending queue
            self.pending_queue
                .retain(|id| !(id.block_hash == block_hash && id.kind == kind));
        }
    }

    /// Tick the fetch manager - called periodically to drive fetch progress.
    ///
    /// This should be called regularly (e.g., every 50-100ms) to:
    /// - Process completed fetch results
    /// - Start new fetch requests
    /// - Check for timed out requests
    /// - Clean up stale fetches
    pub async fn tick(&mut self) {
        // Process any completed fetch results
        self.process_results().await;

        // Clean up stale fetches (and notify BFT of failures)
        self.cleanup_stale().await;

        // Process pending queue - spawn new fetches
        self.process_pending_queue().await;

        // Check for timed out requests
        self.check_timeouts().await;
    }

    /// Process completed fetch results from spawned tasks.
    async fn process_results(&mut self) {
        while let Ok(result) = self.result_rx.try_recv() {
            match result {
                FetchResult::TransactionsReceived {
                    block_hash,
                    peer,
                    transactions,
                } => {
                    self.handle_transactions_received(block_hash, peer, transactions)
                        .await;
                }
                FetchResult::CertificatesReceived {
                    block_hash,
                    peer,
                    certificates,
                } => {
                    self.handle_certificates_received(block_hash, peer, certificates)
                        .await;
                }
                FetchResult::Failed {
                    block_hash,
                    kind,
                    peer,
                    error,
                } => {
                    self.handle_fetch_failed(block_hash, kind, peer, &error)
                        .await;
                }
            }
        }
    }

    /// Handle received transactions.
    async fn handle_transactions_received(
        &mut self,
        block_hash: Hash,
        peer: PeerId,
        transactions: Vec<Arc<RoutableTransaction>>,
    ) {
        self.total_in_flight = self.total_in_flight.saturating_sub(1);

        // Update peer reputation
        if let Some(rep) = self.peer_reputations.get_mut(&peer) {
            rep.successes += 1;
            rep.in_flight = rep.in_flight.saturating_sub(1);
        }

        let Some(state) = self.tx_fetches.get_mut(&block_hash) else {
            trace!(
                ?block_hash,
                "Received transactions for unknown/completed fetch"
            );
            return;
        };

        // Mark in-flight request as complete
        state.in_flight.remove(&peer);

        // Mark received hashes
        let received_hashes: Vec<Hash> = transactions.iter().map(|tx| tx.hash()).collect();
        let received_count = received_hashes.len();
        state.mark_received(received_hashes);

        info!(
            ?block_hash,
            received = received_count,
            remaining = state.missing_hashes.len(),
            "Received transactions from peer"
        );

        metrics::record_fetch_items_received(FetchKind::Transaction, received_count);

        // Eagerly persist fetched transactions to storage.
        // This ensures they're available for sync requests from peers, preventing
        // the scenario where all validators have data in memory but can't serve
        // sync requests because storage is empty.
        //
        // Note: We persist before BFT validation. This is safe because:
        // 1. Transactions are stored by hash (content-addressable)
        // 2. Blocks reference specific hashes - invalid data won't be used
        // 3. Worst case is wasted disk space from Byzantine peers
        if !transactions.is_empty() {
            let storage = self.storage.clone();
            let txs_to_persist = transactions.clone();
            tokio::spawn(async move {
                for tx in &txs_to_persist {
                    storage.put_transaction(tx);
                }
            });
        }

        // Deliver to BFT
        if !transactions.is_empty() {
            let event = Event::TransactionReceived {
                block_hash,
                transactions,
            };
            if let Err(e) = self.event_tx.send(event).await {
                warn!(?block_hash, error = ?e, "Failed to deliver transactions to BFT");
            }
        }

        // Check if complete
        if state.is_complete() {
            info!(?block_hash, "Transaction fetch complete");
            self.tx_fetches.remove(&block_hash);
            metrics::record_fetch_completed(FetchKind::Transaction);
        } else if state.in_flight.is_empty() && !state.missing_hashes.is_empty() {
            // Partial response - some txs were not returned by the peer.
            // Re-queue to fetch remaining from other peers.
            info!(
                ?block_hash,
                remaining = state.missing_hashes.len(),
                "Partial transaction response, re-queuing for remaining"
            );
            // Clear tried_peers to allow retrying with all peers for the remaining hashes.
            // Don't reset total_retries - we track retries per fetch attempt, not per hash.
            // But we do reset it partially since we made progress (received some data).
            state.tried_peers.clear();
            state.total_retries = state.total_retries.saturating_sub(1);
            self.pending_queue.push_back(FetchId {
                block_hash,
                kind: FetchKind::Transaction,
            });
        }
    }

    /// Handle received certificates.
    async fn handle_certificates_received(
        &mut self,
        block_hash: Hash,
        peer: PeerId,
        certificates: Vec<TransactionCertificate>,
    ) {
        self.total_in_flight = self.total_in_flight.saturating_sub(1);

        // Update peer reputation
        if let Some(rep) = self.peer_reputations.get_mut(&peer) {
            rep.successes += 1;
            rep.in_flight = rep.in_flight.saturating_sub(1);
        }

        let Some(state) = self.cert_fetches.get_mut(&block_hash) else {
            trace!(
                ?block_hash,
                "Received certificates for unknown/completed fetch"
            );
            return;
        };

        // Mark in-flight request as complete
        state.in_flight.remove(&peer);

        // Mark received hashes
        let received_hashes: Vec<Hash> = certificates
            .iter()
            .map(|cert| cert.transaction_hash)
            .collect();
        let received_count = received_hashes.len();
        state.mark_received(received_hashes);

        info!(
            ?block_hash,
            received = received_count,
            remaining = state.missing_hashes.len(),
            "Received certificates from peer"
        );

        metrics::record_fetch_items_received(FetchKind::Certificate, received_count);

        // Eagerly persist fetched certificates to storage.
        // This ensures they're available for sync requests from peers, preventing
        // the scenario where all validators have data in memory but can't serve
        // sync requests because storage is empty.
        //
        // Note: We persist before BFT signature verification. This is safe because:
        // 1. Certificates are stored by transaction hash (content-addressable)
        // 2. Blocks reference specific hashes - invalid data won't be used
        // 3. Worst case is wasted disk space from Byzantine peers
        if !certificates.is_empty() {
            let storage = self.storage.clone();
            let certs_to_persist = certificates.clone();
            tokio::spawn(async move {
                for cert in &certs_to_persist {
                    storage.put_certificate(&cert.transaction_hash, cert);
                }
            });
        }

        // Deliver to BFT
        if !certificates.is_empty() {
            let event = Event::CertificateReceived {
                block_hash,
                certificates,
            };
            if let Err(e) = self.event_tx.send(event).await {
                warn!(?block_hash, error = ?e, "Failed to deliver certificates to BFT");
            }
        }

        // Check if complete
        if state.is_complete() {
            info!(?block_hash, "Certificate fetch complete");
            self.cert_fetches.remove(&block_hash);
            metrics::record_fetch_completed(FetchKind::Certificate);
        } else if state.in_flight.is_empty() && !state.missing_hashes.is_empty() {
            // Partial response - some certs were not returned by the peer.
            // Re-queue to fetch remaining from other peers.
            info!(
                ?block_hash,
                remaining = state.missing_hashes.len(),
                "Partial certificate response, re-queuing for remaining"
            );
            // Clear tried_peers to allow retrying with all peers for the remaining hashes.
            // Don't reset total_retries - we track retries per fetch attempt, not per hash.
            // But we do reset it partially since we made progress (received some data).
            state.tried_peers.clear();
            state.total_retries = state.total_retries.saturating_sub(1);
            self.pending_queue.push_back(FetchId {
                block_hash,
                kind: FetchKind::Certificate,
            });
        }
    }

    /// Handle a failed fetch request.
    async fn handle_fetch_failed(
        &mut self,
        block_hash: Hash,
        kind: FetchKind,
        peer: PeerId,
        error: &str,
    ) {
        self.total_in_flight = self.total_in_flight.saturating_sub(1);

        // Update peer reputation
        if let Some(rep) = self.peer_reputations.get_mut(&peer) {
            rep.failures += 1;
            rep.in_flight = rep.in_flight.saturating_sub(1);
            rep.last_failure = Some(Instant::now());
        }

        let state = match kind {
            FetchKind::Transaction => self.tx_fetches.get_mut(&block_hash),
            FetchKind::Certificate => self.cert_fetches.get_mut(&block_hash),
        };

        let Some(state) = state else {
            return;
        };

        // Mark in-flight request as complete
        state.in_flight.remove(&peer);

        warn!(
            ?block_hash,
            ?kind,
            ?peer,
            error,
            in_flight_remaining = state.in_flight.len(),
            "Fetch request failed"
        );

        metrics::record_fetch_failed(kind);

        // Only increment retry counter when ALL in-flight requests have completed.
        // This prevents parallel requests from exhausting retries prematurely.
        // We count a "retry round" as one full attempt across all peers.
        if !state.in_flight.is_empty() {
            // Other requests still in flight - wait for them
            return;
        }

        // All in-flight requests have completed (either succeeded or failed).
        // If we still have missing hashes, increment retry counter and re-queue.
        if !state.missing_hashes.is_empty() {
            state.total_retries += 1;

            // Check if we should give up
            if state.total_retries >= self.config.max_retries {
                warn!(
                    ?block_hash,
                    ?kind,
                    retries = state.total_retries,
                    "Giving up on fetch after max retries"
                );
                match kind {
                    FetchKind::Transaction => {
                        self.tx_fetches.remove(&block_hash);
                        let event = Event::TransactionFetchFailed { block_hash };
                        if let Err(e) = self.event_tx.send(event).await {
                            warn!(?block_hash, error = ?e, "Failed to send TransactionFetchFailed event");
                        }
                    }
                    FetchKind::Certificate => {
                        self.cert_fetches.remove(&block_hash);
                        let event = Event::CertificateFetchFailed { block_hash };
                        if let Err(e) = self.event_tx.send(event).await {
                            warn!(?block_hash, error = ?e, "Failed to send CertificateFetchFailed event");
                        }
                    }
                }
                return;
            }

            // Re-queue for retry with fresh peers
            info!(
                ?block_hash,
                ?kind,
                retries = state.total_retries,
                remaining = state.missing_hashes.len(),
                "Re-queuing fetch after round failure"
            );
            state.tried_peers.clear();
            self.pending_queue.push_back(FetchId { block_hash, kind });
        }
    }

    /// Process the pending queue and spawn new fetch tasks.
    async fn process_pending_queue(&mut self) {
        // Collect fetch tasks to spawn (to avoid borrow issues)
        let mut to_spawn: Vec<(Hash, FetchKind, PeerId, Vec<Hash>)> = Vec::new();
        let max_hashes = self.config.max_hashes_per_request;
        let max_per_block = self.config.max_concurrent_per_block;
        let peer_cooldown = self.config.peer_cooldown;
        let proactive_peers = self.config.proactive_parallel_peers;

        while self.total_in_flight + to_spawn.len() < self.config.max_total_concurrent {
            let Some(fetch_id) = self.pending_queue.pop_front() else {
                break;
            };

            // First, get immutable info we need for peer selection
            let peer_selection_info = {
                let state = match fetch_id.kind {
                    FetchKind::Transaction => self.tx_fetches.get(&fetch_id.block_hash),
                    FetchKind::Certificate => self.cert_fetches.get(&fetch_id.block_hash),
                };

                let Some(state) = state else {
                    // Fetch was cancelled or completed
                    continue;
                };

                // Check if we're already at max concurrent for this block
                if state.in_flight.len() >= max_per_block {
                    // Put back in queue for later
                    self.pending_queue.push_back(fetch_id);
                    continue;
                }

                // Extract info for peer selection
                Some((
                    state.proposer,
                    state.tried_peers.clone(),
                    state.in_flight.keys().copied().collect::<HashSet<PeerId>>(),
                    state.unfetched_hashes(),
                    state.in_flight.len(),
                ))
            };

            let Some((proposer, tried_peers, in_flight_peers, hashes, current_in_flight)) =
                peer_selection_info
            else {
                continue;
            };

            if hashes.is_empty() {
                continue;
            }

            // Determine how many peers to fetch from in parallel.
            // For new fetches (no in-flight), use proactive_parallel_peers.
            // For retries (already have in-flight), just add one more peer.
            let peers_to_add = if current_in_flight == 0 {
                // New fetch: proactively request from multiple peers
                proactive_peers.min(max_per_block)
            } else {
                // Retry/continuation: add one peer at a time
                1
            };

            // Select multiple peers for parallel fetching
            let selected_peers = self.select_multiple_peers(
                proposer,
                &tried_peers,
                &in_flight_peers,
                peer_cooldown,
                peers_to_add,
            );

            if selected_peers.is_empty() {
                // No available peers, put back in queue
                self.pending_queue.push_back(fetch_id);
                break;
            }

            // Now get mutable access to update state
            let state = match fetch_id.kind {
                FetchKind::Transaction => self.tx_fetches.get_mut(&fetch_id.block_hash),
                FetchKind::Certificate => self.cert_fetches.get_mut(&fetch_id.block_hash),
            };

            let Some(state) = state else {
                continue;
            };

            // Chunk the hashes and distribute across peers for parallel fetching.
            // Each peer gets a different chunk to maximize throughput.
            let chunks: Vec<Vec<Hash>> = hashes.chunks(max_hashes).map(|c| c.to_vec()).collect();

            // Distribute chunks across selected peers (round-robin if more chunks than peers)
            for (i, peer) in selected_peers.iter().enumerate() {
                // Each peer gets chunks at positions: i, i+num_peers, i+2*num_peers, ...
                let peer_chunks: Vec<Hash> = chunks
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| j % selected_peers.len() == i)
                    .flat_map(|(_, chunk)| chunk.iter().copied())
                    .collect();

                if peer_chunks.is_empty() {
                    continue;
                }

                // Mark peer as tried
                state.tried_peers.insert(*peer);

                // Record in-flight request
                state.in_flight.insert(
                    *peer,
                    PendingFetchRequest {
                        peer: *peer,
                        started: Instant::now(),
                        retries: 0,
                    },
                );

                // Queue for spawning
                to_spawn.push((fetch_id.block_hash, fetch_id.kind, *peer, peer_chunks));
            }
        }

        // Now spawn all the fetch tasks
        for (block_hash, kind, peer, hashes) in to_spawn {
            // Update reputation
            if let Some(rep) = self.peer_reputations.get_mut(&peer) {
                rep.in_flight += 1;
            }

            self.total_in_flight += 1;

            // Spawn the fetch task
            self.spawn_fetch(block_hash, kind, peer, hashes);
        }
    }

    /// Select multiple peers for parallel fetching.
    ///
    /// Returns up to `count` peers, always including the proposer first if available.
    /// This enables proactive parallel fetching to reduce latency under CPU pressure.
    fn select_multiple_peers(
        &self,
        proposer: ValidatorId,
        tried_peers: &HashSet<PeerId>,
        in_flight_peers: &HashSet<PeerId>,
        peer_cooldown: Duration,
        count: usize,
    ) -> Vec<PeerId> {
        let mut selected = Vec::with_capacity(count);

        // First, try the proposer if we haven't already
        if let Some(&proposer_peer) = self.committee_peers.get(&proposer) {
            if !tried_peers.contains(&proposer_peer) && !in_flight_peers.contains(&proposer_peer) {
                let is_available = self
                    .peer_reputations
                    .get(&proposer_peer)
                    .map(|rep| !rep.is_in_cooldown(peer_cooldown) && rep.in_flight < 3)
                    .unwrap_or(true);

                if is_available {
                    selected.push(proposer_peer);
                }
            }
        }

        if selected.len() >= count {
            return selected;
        }

        // Build a set of already-selected peers to avoid duplicates
        let mut already_selected: HashSet<PeerId> = selected.iter().copied().collect();

        // Collect other committee members, sorted by reputation
        let mut candidates: Vec<_> = self
            .committee_peers
            .iter()
            .filter(|(_, &peer)| {
                !tried_peers.contains(&peer)
                    && !in_flight_peers.contains(&peer)
                    && !already_selected.contains(&peer)
            })
            .filter_map(|(_, &peer)| {
                let rep = self.peer_reputations.get(&peer)?;
                if rep.is_in_cooldown(peer_cooldown) || rep.in_flight >= 3 {
                    return None;
                }
                Some((peer, rep.score()))
            })
            .collect();

        // Sort by score (highest first)
        candidates.sort_by(|a, b| b.1.cmp(&a.1));

        // Take up to (count - already selected) more peers
        for (peer, _score) in candidates {
            if selected.len() >= count {
                break;
            }
            if already_selected.insert(peer) {
                selected.push(peer);
            }
        }

        selected
    }

    /// Spawn a fetch task.
    fn spawn_fetch(&self, block_hash: Hash, kind: FetchKind, peer: PeerId, hashes: Vec<Hash>) {
        trace!(
            ?block_hash,
            ?kind,
            ?peer,
            count = hashes.len(),
            "Spawning fetch task"
        );

        let network = self.network.clone();
        let result_tx = self.result_tx.clone();
        let timeout = self.config.initial_timeout;

        tokio::spawn(async move {
            let result = match kind {
                FetchKind::Transaction => {
                    Self::fetch_transactions(network, peer, block_hash, hashes, timeout).await
                }
                FetchKind::Certificate => {
                    Self::fetch_certificates(network, peer, block_hash, hashes, timeout).await
                }
            };

            // Send result back to manager (ignore send errors - manager may have shut down)
            let _ = result_tx.send(result).await;
        });
    }

    /// Fetch transactions from a peer.
    async fn fetch_transactions(
        network: Arc<Libp2pAdapter>,
        peer: PeerId,
        block_hash: Hash,
        tx_hashes: Vec<Hash>,
        timeout: Duration,
    ) -> FetchResult {
        let start = Instant::now();

        let result = tokio::time::timeout(
            timeout,
            network.request_transactions(peer, block_hash, tx_hashes),
        )
        .await;

        let elapsed = start.elapsed();
        metrics::record_fetch_latency(FetchKind::Transaction, elapsed);

        match result {
            Ok(Ok(response_bytes)) => {
                match sbor::basic_decode::<GetTransactionsResponse>(&response_bytes) {
                    Ok(response) => FetchResult::TransactionsReceived {
                        block_hash,
                        peer,
                        transactions: response.into_transactions(),
                    },
                    Err(e) => FetchResult::Failed {
                        block_hash,
                        kind: FetchKind::Transaction,
                        peer,
                        error: format!("decode error: {:?}", e),
                    },
                }
            }
            Ok(Err(e)) => FetchResult::Failed {
                block_hash,
                kind: FetchKind::Transaction,
                peer,
                error: format!("network error: {}", e),
            },
            Err(_) => FetchResult::Failed {
                block_hash,
                kind: FetchKind::Transaction,
                peer,
                error: "timeout".to_string(),
            },
        }
    }

    /// Fetch certificates from a peer.
    async fn fetch_certificates(
        network: Arc<Libp2pAdapter>,
        peer: PeerId,
        block_hash: Hash,
        cert_hashes: Vec<Hash>,
        timeout: Duration,
    ) -> FetchResult {
        let start = Instant::now();

        let result = tokio::time::timeout(
            timeout,
            network.request_certificates(peer, block_hash, cert_hashes),
        )
        .await;

        let elapsed = start.elapsed();
        metrics::record_fetch_latency(FetchKind::Certificate, elapsed);

        match result {
            Ok(Ok(response_bytes)) => {
                match sbor::basic_decode::<GetCertificatesResponse>(&response_bytes) {
                    Ok(response) => FetchResult::CertificatesReceived {
                        block_hash,
                        peer,
                        certificates: response.into_certificates(),
                    },
                    Err(e) => FetchResult::Failed {
                        block_hash,
                        kind: FetchKind::Certificate,
                        peer,
                        error: format!("decode error: {:?}", e),
                    },
                }
            }
            Ok(Err(e)) => FetchResult::Failed {
                block_hash,
                kind: FetchKind::Certificate,
                peer,
                error: format!("network error: {}", e),
            },
            Err(_) => FetchResult::Failed {
                block_hash,
                kind: FetchKind::Certificate,
                peer,
                error: "timeout".to_string(),
            },
        }
    }

    /// Check for timed out requests and retry them.
    async fn check_timeouts(&mut self) {
        let timeout = self.config.max_timeout;

        // Check transaction fetches
        let mut timed_out: Vec<(Hash, PeerId)> = Vec::new();
        for (block_hash, state) in &self.tx_fetches {
            for (peer, req) in &state.in_flight {
                if req.started.elapsed() > timeout {
                    timed_out.push((*block_hash, *peer));
                }
            }
        }

        for (block_hash, peer) in timed_out {
            self.handle_fetch_failed(block_hash, FetchKind::Transaction, peer, "timeout")
                .await;
        }

        // Check certificate fetches
        let mut timed_out: Vec<(Hash, PeerId)> = Vec::new();
        for (block_hash, state) in &self.cert_fetches {
            for (peer, req) in &state.in_flight {
                if req.started.elapsed() > timeout {
                    timed_out.push((*block_hash, *peer));
                }
            }
        }

        for (block_hash, peer) in timed_out {
            self.handle_fetch_failed(block_hash, FetchKind::Certificate, peer, "timeout")
                .await;
        }
    }

    /// Clean up stale fetches (that have been pending too long).
    ///
    /// Sends failure events to BFT for any stale fetches so blocks don't get
    /// stuck in pending state indefinitely.
    async fn cleanup_stale(&mut self) {
        let stale_timeout = self.config.stale_fetch_timeout;

        // Collect stale transaction fetches
        let stale_tx_hashes: Vec<Hash> = self
            .tx_fetches
            .iter()
            .filter(|(_, state)| state.is_stale(stale_timeout))
            .map(|(hash, _)| *hash)
            .collect();

        // Remove and notify for each stale transaction fetch
        for hash in stale_tx_hashes {
            if let Some(state) = self.tx_fetches.remove(&hash) {
                warn!(
                    ?hash,
                    missing = state.missing_hashes.len(),
                    age_secs = state.created.elapsed().as_secs(),
                    "Cleaning up stale transaction fetch - notifying BFT"
                );
                // Notify BFT so it can handle the failure (e.g., remove pending block)
                let event = Event::TransactionFetchFailed { block_hash: hash };
                if let Err(e) = self.event_tx.send(event).await {
                    warn!(?hash, error = ?e, "Failed to send TransactionFetchFailed for stale fetch");
                }
            }
        }

        // Collect stale certificate fetches
        let stale_cert_hashes: Vec<Hash> = self
            .cert_fetches
            .iter()
            .filter(|(_, state)| state.is_stale(stale_timeout))
            .map(|(hash, _)| *hash)
            .collect();

        // Remove and notify for each stale certificate fetch
        for hash in stale_cert_hashes {
            if let Some(state) = self.cert_fetches.remove(&hash) {
                warn!(
                    ?hash,
                    missing = state.missing_hashes.len(),
                    age_secs = state.created.elapsed().as_secs(),
                    "Cleaning up stale certificate fetch - notifying BFT"
                );
                // Notify BFT so it can handle the failure
                let event = Event::CertificateFetchFailed { block_hash: hash };
                if let Err(e) = self.event_tx.send(event).await {
                    warn!(?hash, error = ?e, "Failed to send CertificateFetchFailed for stale fetch");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_config_defaults() {
        let config = FetchConfig::default();
        assert_eq!(config.max_concurrent_per_block, 8);
        assert_eq!(config.max_total_concurrent, 32);
        assert_eq!(config.max_retries, 3);
        // Proactive parallel fetching with 4 peers for chunked distribution
        assert_eq!(config.proactive_parallel_peers, 4);
        assert_eq!(config.max_hashes_per_request, 50);
    }

    #[test]
    fn test_fetch_config_proactive_parallel() {
        // Default enables proactive parallel fetching with 4 peers
        let default_config = FetchConfig::default();
        assert_eq!(default_config.proactive_parallel_peers, 4);

        // for_local and for_wan inherit the default
        let local_config = FetchConfig::for_local();
        assert_eq!(local_config.proactive_parallel_peers, 4);

        let wan_config = FetchConfig::for_wan();
        assert_eq!(wan_config.proactive_parallel_peers, 4);
    }

    #[test]
    fn test_peer_reputation_cooldown() {
        let mut rep = FetchPeerReputation::default();
        assert!(!rep.is_in_cooldown(Duration::from_secs(10)));

        rep.last_failure = Some(Instant::now());
        assert!(rep.is_in_cooldown(Duration::from_secs(10)));
    }

    #[test]
    fn test_peer_reputation_score() {
        let mut rep = FetchPeerReputation::default();
        assert_eq!(rep.score(), 0);

        rep.successes = 5;
        assert_eq!(rep.score(), 50);

        rep.failures = 2;
        assert_eq!(rep.score(), 40);

        rep.in_flight = 3;
        assert_eq!(rep.score(), 34);
    }

    #[test]
    fn test_block_fetch_state() {
        let block_hash = Hash::from_bytes(b"test_block");
        let hashes = vec![
            Hash::from_bytes(b"tx1"),
            Hash::from_bytes(b"tx2"),
            Hash::from_bytes(b"tx3"),
        ];

        let mut state = BlockFetchState::new(
            block_hash,
            FetchKind::Transaction,
            ValidatorId(0),
            hashes.clone(),
        );

        assert!(!state.is_complete());
        assert_eq!(state.unfetched_hashes().len(), 3);

        state.mark_received(vec![hashes[0], hashes[1]]);
        assert!(!state.is_complete());
        assert_eq!(state.unfetched_hashes().len(), 1);

        state.mark_received(vec![hashes[2]]);
        assert!(state.is_complete());
    }
}
