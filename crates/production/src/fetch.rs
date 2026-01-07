//! Fetch manager for retrieving missing transactions and certificates from peers.
//!
//! The fetch manager handles transaction and certificate fetching by delegating
//! retry logic and peer selection to the `RequestManager`. This module focuses on:
//! - Tracking what data is missing for each pending block
//! - Chunking large requests for parallel fetching
//! - Delivering fetched data to BFT via events
//! - Persisting fetched data to storage
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
//! │  BFT Actions    │────▶│  FetchManager    │────▶│ RequestManager  │
//! │ FetchTx/Certs   │     │ (orchestration)  │     │ (retry/peers)   │
//! └─────────────────┘     └──────────────────┘     └─────────────────┘
//!                                │                         │
//!                                ▼                         ▼
//!                         ┌──────────────┐          ┌─────────────┐
//!                         │   Storage    │          │  Network    │
//!                         │  (persist)   │          │  Adapter    │
//!                         └──────────────┘          └─────────────┘
//! ```
//!
//! The key insight is that `RequestManager` handles:
//! - Intelligent retry (same peer first, then rotate)
//! - Peer health tracking and weighted selection
//! - Adaptive concurrency control
//! - Exponential backoff
//!
//! While `FetchManager` handles:
//! - What hashes are missing for each block
//! - Chunking requests across multiple parallel fetches
//! - Delivering results to BFT
//! - Persisting to storage

use crate::metrics;
use crate::network::{RequestManager, RequestPriority};
use crate::storage::RocksDbStorage;
use hyperscale_core::Event;
use hyperscale_messages::response::{GetCertificatesResponse, GetTransactionsResponse};
use hyperscale_types::{Hash, RoutableTransaction, TransactionCertificate, ValidatorId};
use libp2p::PeerId;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

// ═══════════════════════════════════════════════════════════════════════════
// Fetch Configuration
// ═══════════════════════════════════════════════════════════════════════════

/// Configuration for the fetch manager.
#[derive(Debug, Clone)]
pub struct FetchConfig {
    /// Maximum number of concurrent fetch operations per block.
    /// Each operation fetches a chunk of hashes.
    /// This provides fairness across blocks, not global limiting.
    pub max_concurrent_per_block: usize,

    /// Maximum number of hashes to request in a single fetch.
    /// Larger batches are chunked into multiple requests.
    pub max_hashes_per_request: usize,

    /// Number of parallel fetch operations to spawn for new requests.
    /// Chunks are distributed across this many parallel fetches.
    pub parallel_fetches: usize,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            max_concurrent_per_block: 8,
            max_hashes_per_request: 50,
            parallel_fetches: 4,
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

/// Result of an async fetch operation.
#[derive(Debug)]
pub enum FetchResult {
    /// Successfully fetched transactions.
    TransactionsReceived {
        block_hash: Hash,
        transactions: Vec<Arc<RoutableTransaction>>,
    },
    /// Successfully fetched certificates.
    CertificatesReceived {
        block_hash: Hash,
        certificates: Vec<TransactionCertificate>,
    },
    /// Failed to fetch after all retries.
    Failed {
        block_hash: Hash,
        kind: FetchKind,
        hashes: Vec<Hash>,
        error: String,
    },
}

/// State for a block's fetch operation.
#[derive(Debug)]
struct BlockFetchState {
    /// The block hash (for debugging).
    #[allow(dead_code)]
    block_hash: Hash,
    /// The type of fetch (for debugging).
    #[allow(dead_code)]
    kind: FetchKind,
    /// The proposer of the block (preferred fetch target).
    proposer: ValidatorId,
    /// Hashes we still need to fetch.
    missing_hashes: HashSet<Hash>,
    /// Hashes currently being fetched (in-flight).
    in_flight_hashes: HashSet<Hash>,
    /// Hashes that have been successfully received.
    /// Prevents re-adding hashes when BFT re-requests.
    received_hashes: HashSet<Hash>,
    /// Number of in-flight fetch operations for this block.
    in_flight_count: usize,
}

impl BlockFetchState {
    fn new(block_hash: Hash, kind: FetchKind, proposer: ValidatorId, hashes: Vec<Hash>) -> Self {
        Self {
            block_hash,
            kind,
            proposer,
            missing_hashes: hashes.into_iter().collect(),
            in_flight_hashes: HashSet::new(),
            received_hashes: HashSet::new(),
            in_flight_count: 0,
        }
    }

    /// Check if this fetch is complete (all hashes received).
    fn is_complete(&self) -> bool {
        self.missing_hashes.is_empty() && self.in_flight_hashes.is_empty()
    }

    /// Get hashes that need fetching (not in-flight).
    fn hashes_to_fetch(&self) -> Vec<Hash> {
        self.missing_hashes
            .difference(&self.in_flight_hashes)
            .copied()
            .collect()
    }

    /// Mark hashes as in-flight.
    fn mark_in_flight(&mut self, hashes: &[Hash]) {
        for hash in hashes {
            self.in_flight_hashes.insert(*hash);
        }
        self.in_flight_count += 1;
    }

    /// Mark hashes as received (removes from both missing and in-flight, adds to received).
    fn mark_received(&mut self, hashes: impl IntoIterator<Item = Hash>) {
        for hash in hashes {
            self.missing_hashes.remove(&hash);
            self.in_flight_hashes.remove(&hash);
            self.received_hashes.insert(hash);
        }
    }

    /// Check if a hash has already been received.
    fn was_received(&self, hash: &Hash) -> bool {
        self.received_hashes.contains(hash)
    }

    /// Mark a fetch operation as failed (return hashes to missing pool).
    fn mark_fetch_failed(&mut self, hashes: &[Hash]) {
        for hash in hashes {
            self.in_flight_hashes.remove(hash);
            // Hash stays in missing_hashes for retry
        }
        self.in_flight_count = self.in_flight_count.saturating_sub(1);
    }

    /// Mark a fetch operation as complete (decrement in-flight count).
    fn mark_fetch_complete(&mut self) {
        self.in_flight_count = self.in_flight_count.saturating_sub(1);
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
    /// Total in-flight fetch operations.
    pub in_flight_operations: usize,
}

// ═══════════════════════════════════════════════════════════════════════════
// FetchManager Implementation
// ═══════════════════════════════════════════════════════════════════════════

/// Manages fetching of transactions and certificates from peers.
///
/// Delegates retry logic and peer selection to `RequestManager`.
/// Focuses on tracking missing data and orchestrating parallel fetches.
/// Global concurrency is managed by RequestManager; this only tracks per-block fairness.
pub struct FetchManager {
    /// Configuration.
    config: FetchConfig,
    /// Request manager for network requests with retry.
    request_manager: Arc<RequestManager>,
    /// Storage for persisting fetched data.
    storage: Arc<RocksDbStorage>,
    /// Event sender for delivering fetched data.
    event_tx: mpsc::Sender<Event>,
    /// Pending transaction fetches by block hash.
    tx_fetches: HashMap<Hash, BlockFetchState>,
    /// Pending certificate fetches by block hash.
    cert_fetches: HashMap<Hash, BlockFetchState>,
    /// Known committee members (ValidatorId -> PeerId).
    committee_peers: HashMap<ValidatorId, PeerId>,
    /// Channel for receiving results from spawned fetch tasks.
    result_rx: mpsc::Receiver<FetchResult>,
    /// Sender for spawned fetch tasks to report results.
    result_tx: mpsc::Sender<FetchResult>,
}

impl FetchManager {
    /// Create a new fetch manager.
    pub fn new(
        config: FetchConfig,
        request_manager: Arc<RequestManager>,
        storage: Arc<RocksDbStorage>,
        event_tx: mpsc::Sender<Event>,
    ) -> Self {
        // Buffer size for result channel - enough for reasonable parallelism
        let (result_tx, result_rx) = mpsc::channel(64);

        Self {
            config,
            request_manager,
            storage,
            event_tx,
            tx_fetches: HashMap::new(),
            cert_fetches: HashMap::new(),
            committee_peers: HashMap::new(),
            result_rx,
            result_tx,
        }
    }

    /// Register a committee member's peer ID.
    pub fn register_committee_member(&mut self, validator_id: ValidatorId, peer_id: PeerId) {
        self.committee_peers.insert(validator_id, peer_id);
        debug!(
            validator_id = validator_id.0,
            ?peer_id,
            "Registered committee member for fetch"
        );
    }

    /// Get the current fetch status for external APIs.
    pub fn status(&self) -> FetchStatus {
        // Count in-flight operations across all blocks
        let in_flight: usize = self
            .tx_fetches
            .values()
            .chain(self.cert_fetches.values())
            .map(|s| s.in_flight_count)
            .sum();

        FetchStatus {
            pending_tx_blocks: self.tx_fetches.len(),
            pending_cert_blocks: self.cert_fetches.len(),
            in_flight_operations: in_flight,
        }
    }

    /// Get all registered peer IDs.
    fn get_peers(&self) -> Vec<PeerId> {
        self.committee_peers.values().copied().collect()
    }

    /// Request transactions for a pending block.
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
            // Add any new hashes (but skip already-received or in-flight)
            let count_before = state.missing_hashes.len();
            for hash in tx_hashes {
                // Don't re-add hashes that are already received or in-flight
                if !state.was_received(&hash) && !state.in_flight_hashes.contains(&hash) {
                    state.missing_hashes.insert(hash);
                }
            }
            debug!(
                ?block_hash,
                before = count_before,
                after = state.missing_hashes.len(),
                "Updated existing transaction fetch"
            );
            return;
        }

        info!(
            ?block_hash,
            count = tx_hashes.len(),
            proposer = proposer.0,
            "Starting transaction fetch"
        );

        let state = BlockFetchState::new(block_hash, FetchKind::Transaction, proposer, tx_hashes);
        self.tx_fetches.insert(block_hash, state);
        metrics::record_fetch_started(FetchKind::Transaction);
    }

    /// Request certificates for a pending block.
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
            // Add any new hashes (but skip already-received or in-flight)
            let count_before = state.missing_hashes.len();
            for hash in cert_hashes {
                // Don't re-add hashes that are already received or in-flight
                if !state.was_received(&hash) && !state.in_flight_hashes.contains(&hash) {
                    state.missing_hashes.insert(hash);
                }
            }
            debug!(
                ?block_hash,
                before = count_before,
                after = state.missing_hashes.len(),
                "Updated existing certificate fetch"
            );
            return;
        }

        info!(
            ?block_hash,
            count = cert_hashes.len(),
            proposer = proposer.0,
            "Starting certificate fetch"
        );

        let state = BlockFetchState::new(block_hash, FetchKind::Certificate, proposer, cert_hashes);
        self.cert_fetches.insert(block_hash, state);
        metrics::record_fetch_started(FetchKind::Certificate);
    }

    /// Cancel a fetch for a block.
    #[allow(dead_code)]
    pub fn cancel_fetch(&mut self, block_hash: Hash, kind: FetchKind) {
        let removed = match kind {
            FetchKind::Transaction => self.tx_fetches.remove(&block_hash).is_some(),
            FetchKind::Certificate => self.cert_fetches.remove(&block_hash).is_some(),
        };

        if removed {
            debug!(?block_hash, ?kind, "Cancelled fetch");
        }
    }

    /// Cancel all pending fetches.
    ///
    /// Called when sync starts to free up request slots. Sync delivers complete
    /// blocks that will supersede the pending gossip blocks we were fetching for.
    pub fn cancel_all(&mut self) {
        let tx_count = self.tx_fetches.len();
        let cert_count = self.cert_fetches.len();

        if tx_count > 0 || cert_count > 0 {
            info!(
                tx_fetches = tx_count,
                cert_fetches = cert_count,
                "Cancelling all fetches for sync"
            );
            self.tx_fetches.clear();
            self.cert_fetches.clear();
        }
    }

    /// Tick the fetch manager - called periodically to drive progress.
    pub async fn tick(&mut self) {
        // Process completed fetch results
        self.process_results().await;

        // Spawn new fetch operations for pending blocks
        self.spawn_pending_fetches().await;
    }

    /// Process completed fetch results.
    async fn process_results(&mut self) {
        while let Ok(result) = self.result_rx.try_recv() {
            match result {
                FetchResult::TransactionsReceived {
                    block_hash,
                    transactions,
                } => {
                    self.handle_transactions_received(block_hash, transactions)
                        .await;
                }
                FetchResult::CertificatesReceived {
                    block_hash,
                    certificates,
                } => {
                    self.handle_certificates_received(block_hash, certificates)
                        .await;
                }
                FetchResult::Failed {
                    block_hash,
                    kind,
                    hashes,
                    error,
                } => {
                    self.handle_fetch_failed(block_hash, kind, &hashes, &error)
                        .await;
                }
            }
        }
    }

    /// Handle received transactions.
    async fn handle_transactions_received(
        &mut self,
        block_hash: Hash,
        transactions: Vec<Arc<RoutableTransaction>>,
    ) {
        let Some(state) = self.tx_fetches.get_mut(&block_hash) else {
            trace!(
                ?block_hash,
                "Received transactions for unknown/completed fetch"
            );
            return;
        };

        state.mark_fetch_complete();

        // Mark received hashes
        let received_hashes: Vec<Hash> = transactions.iter().map(|tx| tx.hash()).collect();
        let received_count = received_hashes.len();
        state.mark_received(received_hashes);

        info!(
            ?block_hash,
            received = received_count,
            remaining = state.missing_hashes.len(),
            "Received transactions"
        );

        metrics::record_fetch_items_received(FetchKind::Transaction, received_count);

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
        }
    }

    /// Handle received certificates.
    async fn handle_certificates_received(
        &mut self,
        block_hash: Hash,
        certificates: Vec<TransactionCertificate>,
    ) {
        let Some(state) = self.cert_fetches.get_mut(&block_hash) else {
            trace!(
                ?block_hash,
                "Received certificates for unknown/completed fetch"
            );
            return;
        };

        state.mark_fetch_complete();

        // Mark received hashes
        let received_hashes: Vec<Hash> = certificates.iter().map(|c| c.transaction_hash).collect();
        let received_count = received_hashes.len();
        state.mark_received(received_hashes);

        info!(
            ?block_hash,
            received = received_count,
            remaining = state.missing_hashes.len(),
            "Received certificates"
        );

        metrics::record_fetch_items_received(FetchKind::Certificate, received_count);

        // Persist to storage
        if !certificates.is_empty() {
            let storage = self.storage.clone();
            let certs = certificates.clone();
            tokio::spawn(async move {
                for cert in &certs {
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
        }
    }

    /// Handle a failed fetch.
    async fn handle_fetch_failed(
        &mut self,
        block_hash: Hash,
        kind: FetchKind,
        hashes: &[Hash],
        error: &str,
    ) {
        warn!(
            ?block_hash,
            ?kind,
            hash_count = hashes.len(),
            error,
            "Fetch operation failed"
        );
        metrics::record_fetch_failed(kind);

        // Mark the hashes as no longer in-flight so they can be retried
        let state = match kind {
            FetchKind::Transaction => self.tx_fetches.get_mut(&block_hash),
            FetchKind::Certificate => self.cert_fetches.get_mut(&block_hash),
        };

        if let Some(state) = state {
            state.mark_fetch_failed(hashes);
        }
    }

    /// Spawn fetch operations for pending blocks.
    ///
    /// Global concurrency is managed by RequestManager. This method only enforces
    /// per-block fairness limits to prevent one block from starving others.
    async fn spawn_pending_fetches(&mut self) {
        let peers = self.get_peers();
        if peers.is_empty() {
            return;
        }

        // Collect fetches to spawn (block_hash, kind, hashes, proposer)
        let mut to_spawn: Vec<(Hash, FetchKind, Vec<Hash>, ValidatorId)> = Vec::new();

        // Check transaction fetches
        for (block_hash, state) in &mut self.tx_fetches {
            if state.in_flight_count >= self.config.max_concurrent_per_block {
                continue;
            }

            let hashes = state.hashes_to_fetch();
            if hashes.is_empty() {
                continue;
            }

            // Calculate how many chunks we can spawn (limited by per-block fairness)
            let available_slots = (self.config.max_concurrent_per_block - state.in_flight_count)
                .min(self.config.parallel_fetches);

            for chunk in hashes
                .chunks(self.config.max_hashes_per_request)
                .take(available_slots)
            {
                let chunk_vec = chunk.to_vec();
                state.mark_in_flight(&chunk_vec);
                to_spawn.push((
                    *block_hash,
                    FetchKind::Transaction,
                    chunk_vec,
                    state.proposer,
                ));
            }
        }

        // Check certificate fetches
        for (block_hash, state) in &mut self.cert_fetches {
            if state.in_flight_count >= self.config.max_concurrent_per_block {
                continue;
            }

            let hashes = state.hashes_to_fetch();
            if hashes.is_empty() {
                continue;
            }

            // Calculate how many chunks we can spawn (limited by per-block fairness)
            let available_slots = (self.config.max_concurrent_per_block - state.in_flight_count)
                .min(self.config.parallel_fetches);

            for chunk in hashes
                .chunks(self.config.max_hashes_per_request)
                .take(available_slots)
            {
                let chunk_vec = chunk.to_vec();
                state.mark_in_flight(&chunk_vec);
                to_spawn.push((
                    *block_hash,
                    FetchKind::Certificate,
                    chunk_vec,
                    state.proposer,
                ));
            }
        }

        // Spawn the fetch tasks
        for (block_hash, kind, hashes, proposer) in to_spawn {
            self.spawn_fetch(block_hash, kind, hashes, proposer, peers.clone());
        }
    }

    /// Spawn a single fetch operation.
    ///
    /// The proposer is used to prioritize fetching from the block's proposer,
    /// who is guaranteed to have all transactions and certificates for their block.
    fn spawn_fetch(
        &self,
        block_hash: Hash,
        kind: FetchKind,
        hashes: Vec<Hash>,
        proposer: ValidatorId,
        peers: Vec<PeerId>,
    ) {
        // Look up the proposer's PeerId to pass as preferred peer.
        // The proposer is guaranteed to have the data we need.
        let preferred_peer = self.committee_peers.get(&proposer).copied();
        if preferred_peer.is_some() {
            trace!(
                ?block_hash,
                ?kind,
                proposer = proposer.0,
                "Will prioritize proposer peer for fetch"
            );
        }

        trace!(
            ?block_hash,
            ?kind,
            count = hashes.len(),
            "Spawning fetch task"
        );

        let request_manager = self.request_manager.clone();
        let result_tx = self.result_tx.clone();

        tokio::spawn(async move {
            let fetch_result = match kind {
                FetchKind::Transaction => {
                    Self::fetch_transactions(
                        request_manager,
                        &peers,
                        preferred_peer,
                        block_hash,
                        hashes,
                    )
                    .await
                }
                FetchKind::Certificate => {
                    Self::fetch_certificates(
                        request_manager,
                        &peers,
                        preferred_peer,
                        block_hash,
                        hashes,
                    )
                    .await
                }
            };

            let _ = result_tx.send(fetch_result).await;
        });
    }

    /// Fetch transactions using RequestManager.
    async fn fetch_transactions(
        request_manager: Arc<RequestManager>,
        peers: &[PeerId],
        preferred_peer: Option<PeerId>,
        block_hash: Hash,
        tx_hashes: Vec<Hash>,
    ) -> FetchResult {
        let start = Instant::now();

        // RequestManager handles retry, peer selection, and backoff
        let response = request_manager
            .request_transactions(
                peers,
                preferred_peer,
                block_hash,
                tx_hashes.clone(),
                RequestPriority::Critical,
            )
            .await;

        let (_peer, response_bytes) = match response {
            Ok(r) => r,
            Err(e) => {
                return FetchResult::Failed {
                    block_hash,
                    kind: FetchKind::Transaction,
                    hashes: tx_hashes,
                    error: format!("{}", e),
                };
            }
        };

        let elapsed = start.elapsed();
        metrics::record_fetch_latency(FetchKind::Transaction, elapsed);

        // Decode response
        match sbor::basic_decode::<GetTransactionsResponse>(&response_bytes) {
            Ok(response) => FetchResult::TransactionsReceived {
                block_hash,
                transactions: response.into_transactions(),
            },
            Err(e) => FetchResult::Failed {
                block_hash,
                kind: FetchKind::Transaction,
                hashes: tx_hashes,
                error: format!("decode error: {:?}", e),
            },
        }
    }

    /// Fetch certificates using RequestManager.
    async fn fetch_certificates(
        request_manager: Arc<RequestManager>,
        peers: &[PeerId],
        preferred_peer: Option<PeerId>,
        block_hash: Hash,
        cert_hashes: Vec<Hash>,
    ) -> FetchResult {
        let start = Instant::now();

        // RequestManager handles retry, peer selection, and backoff
        let response = request_manager
            .request_certificates(
                peers,
                preferred_peer,
                block_hash,
                cert_hashes.clone(),
                RequestPriority::Critical,
            )
            .await;

        let (_peer, response_bytes) = match response {
            Ok(r) => r,
            Err(e) => {
                return FetchResult::Failed {
                    block_hash,
                    kind: FetchKind::Certificate,
                    hashes: cert_hashes,
                    error: format!("{}", e),
                };
            }
        };

        let elapsed = start.elapsed();
        metrics::record_fetch_latency(FetchKind::Certificate, elapsed);

        // Decode response
        match sbor::basic_decode::<GetCertificatesResponse>(&response_bytes) {
            Ok(response) => FetchResult::CertificatesReceived {
                block_hash,
                certificates: response.into_certificates(),
            },
            Err(e) => FetchResult::Failed {
                block_hash,
                kind: FetchKind::Certificate,
                hashes: cert_hashes,
                error: format!("decode error: {:?}", e),
            },
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
        assert_eq!(config.parallel_fetches, 4);
        assert_eq!(config.max_hashes_per_request, 50);
    }

    #[test]
    fn test_block_fetch_state() {
        let block_hash = Hash::from_bytes(b"test_block");
        let proposer = ValidatorId(1);
        let hashes = vec![
            Hash::from_bytes(b"tx1_hash_data_here"),
            Hash::from_bytes(b"tx2_hash_data_here"),
            Hash::from_bytes(b"tx3_hash_data_here"),
        ];

        let mut state =
            BlockFetchState::new(block_hash, FetchKind::Transaction, proposer, hashes.clone());

        assert!(!state.is_complete());
        assert_eq!(state.hashes_to_fetch().len(), 3);

        // Mark some as in-flight
        state.mark_in_flight(&[hashes[0], hashes[1]]);
        assert_eq!(state.hashes_to_fetch().len(), 1); // Only tx3 available

        // Receive one
        state.mark_received(vec![hashes[0]]);
        assert!(!state.is_complete());
        assert_eq!(state.missing_hashes.len(), 2); // tx2, tx3 still missing
        assert_eq!(state.in_flight_hashes.len(), 1); // tx2 still in-flight

        // Complete the fetch operation and receive remaining
        state.mark_fetch_complete();
        state.mark_received(vec![hashes[1], hashes[2]]);
        assert!(state.is_complete());
    }

    #[test]
    fn test_fetch_kind_str() {
        assert_eq!(FetchKind::Transaction.as_str(), "transaction");
        assert_eq!(FetchKind::Certificate.as_str(), "certificate");
    }

    #[test]
    fn test_received_hashes_prevents_readd() {
        let block_hash = Hash::from_bytes(b"test_block");
        let proposer = ValidatorId(1);
        let hashes = vec![
            Hash::from_bytes(b"tx1_hash_data_here"),
            Hash::from_bytes(b"tx2_hash_data_here"),
        ];

        let mut state =
            BlockFetchState::new(block_hash, FetchKind::Transaction, proposer, hashes.clone());

        // Receive first hash
        state.mark_received(vec![hashes[0]]);
        assert!(state.was_received(&hashes[0]));
        assert!(!state.was_received(&hashes[1]));

        // Verify the received hash is no longer in missing_hashes
        assert!(!state.missing_hashes.contains(&hashes[0]));
        assert!(state.missing_hashes.contains(&hashes[1]));

        // Try to "re-add" via the check used in request_transactions/request_certificates
        // This simulates BFT re-requesting hashes after they were already received
        let should_add =
            !state.was_received(&hashes[0]) && !state.in_flight_hashes.contains(&hashes[0]);
        assert!(!should_add, "Should not re-add already received hash");

        // But a new hash should be addable
        let new_hash = Hash::from_bytes(b"tx3_hash_data_here");
        let should_add_new =
            !state.was_received(&new_hash) && !state.in_flight_hashes.contains(&new_hash);
        assert!(should_add_new, "Should allow adding new hash");
    }
}
