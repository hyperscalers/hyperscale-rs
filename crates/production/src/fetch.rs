//! Fetch manager for retrieving missing transactions and certificates from peers.
//!
//! Thin async adapter around the shared [`FetchProtocol`] state machine.
//! This module handles production-specific concerns:
//! - Spawning tokio tasks for network fetches via `RequestManager`
//! - Peer selection and proposer preference
//! - Persisting fetched certificates to RocksDB
//! - Delivering fetched data to BFT via event channel
//!
//! The core protocol logic (per-block hash tracking, chunking, completion detection)
//! lives in `hyperscale_network::FetchProtocol`, shared with the simulation runner.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
//! │  BFT Actions    │────▶│  FetchManager    │────▶│ RequestManager  │
//! │ FetchTx/Certs   │     │ (async adapter)  │     │ (retry/peers)   │
//! └─────────────────┘     └──────┬───────────┘     └─────────────────┘
//!                                │
//!                         ┌──────▼───────────┐
//!                         │  FetchProtocol   │
//!                         │ (shared state    │
//!                         │  machine)        │
//!                         └──────────────────┘
//! ```

use hyperscale_core::Event;
use hyperscale_messages::response::{GetCertificatesResponse, GetTransactionsResponse};
use hyperscale_metrics as metrics;
use hyperscale_network::{FetchInput, FetchOutput, FetchProtocol};
use hyperscale_network_libp2p::{PeerId, RequestManager, RequestPriority};
use hyperscale_storage::ConsensusStore;
use hyperscale_storage_rocksdb::RocksDbStorage;
use hyperscale_types::{Hash, RoutableTransaction, TransactionCertificate, ValidatorId};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

// Re-export shared types used by the rest of the production crate.
pub use hyperscale_network::{FetchConfig, FetchKind, FetchStatus};

// ═══════════════════════════════════════════════════════════════════════════
// Callback Result from Spawned Tasks
// ═══════════════════════════════════════════════════════════════════════════

/// Result of an async fetch operation from a spawned task.
#[derive(Debug)]
enum FetchTaskResult {
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

// ═══════════════════════════════════════════════════════════════════════════
// FetchManager Implementation
// ═══════════════════════════════════════════════════════════════════════════

/// Production fetch manager — async adapter around [`FetchProtocol`].
///
/// Delegates retry logic and peer selection to `RequestManager`.
/// Core protocol logic (hash tracking, chunking, completion) is in `FetchProtocol`.
pub struct FetchManager {
    /// Shared protocol state machine.
    protocol: FetchProtocol,
    /// Request manager for network requests with retry.
    request_manager: Arc<RequestManager>,
    /// Storage for persisting fetched certificates.
    storage: Arc<RocksDbStorage>,
    /// Event sender for delivering fetched data to BFT.
    event_tx: mpsc::Sender<Event>,
    /// Known committee members (ValidatorId -> PeerId).
    committee_peers: HashMap<ValidatorId, PeerId>,
    /// Channel for receiving results from spawned fetch tasks.
    result_rx: mpsc::Receiver<FetchTaskResult>,
    /// Sender cloned into each spawned fetch task.
    result_tx: mpsc::Sender<FetchTaskResult>,
}

impl FetchManager {
    /// Create a new fetch manager.
    pub fn new(
        config: FetchConfig,
        request_manager: Arc<RequestManager>,
        storage: Arc<RocksDbStorage>,
        event_tx: mpsc::Sender<Event>,
    ) -> Self {
        let (result_tx, result_rx) = mpsc::channel(64);

        Self {
            protocol: FetchProtocol::new(config),
            request_manager,
            storage,
            event_tx,
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
        self.protocol.status()
    }

    /// Request transactions for a pending block.
    pub fn request_transactions(
        &mut self,
        block_hash: Hash,
        proposer: ValidatorId,
        tx_hashes: Vec<Hash>,
    ) {
        let outputs = self.protocol.handle(FetchInput::RequestTransactions {
            block_hash,
            proposer,
            tx_hashes,
        });
        if !outputs.is_empty() {
            self.process_outputs(outputs);
        }
        metrics::record_fetch_started(FetchKind::Transaction.as_str());
    }

    /// Request certificates for a pending block.
    pub fn request_certificates(
        &mut self,
        block_hash: Hash,
        proposer: ValidatorId,
        cert_hashes: Vec<Hash>,
    ) {
        let outputs = self.protocol.handle(FetchInput::RequestCertificates {
            block_hash,
            proposer,
            cert_hashes,
        });
        if !outputs.is_empty() {
            self.process_outputs(outputs);
        }
        metrics::record_fetch_started(FetchKind::Certificate.as_str());
    }

    /// Cancel a fetch for a specific block.
    pub fn cancel_fetch(&mut self, block_hash: Hash, _kind: FetchKind) {
        self.protocol.handle(FetchInput::CancelFetch { block_hash });
    }

    /// Cancel all pending fetches (e.g., when sync starts).
    pub fn cancel_all(&mut self) {
        self.protocol.handle(FetchInput::CancelAll);
    }

    /// Tick the fetch manager — called periodically to drive progress.
    ///
    /// Drains completed fetch results, feeds them into the protocol,
    /// then ticks the protocol to spawn pending operations.
    pub async fn tick(&mut self) {
        // Drain completed fetch results from spawned tasks.
        while let Ok(result) = self.result_rx.try_recv() {
            let (input, metric_kind, metric_count) = match result {
                FetchTaskResult::TransactionsReceived {
                    block_hash,
                    transactions,
                } => {
                    let count = transactions.len();
                    (
                        FetchInput::TransactionsReceived {
                            block_hash,
                            transactions,
                        },
                        Some(FetchKind::Transaction),
                        count,
                    )
                }
                FetchTaskResult::CertificatesReceived {
                    block_hash,
                    certificates,
                } => {
                    let count = certificates.len();
                    // Persist certificates to storage in the background.
                    if !certificates.is_empty() {
                        let storage = self.storage.clone();
                        let certs = certificates.clone();
                        tokio::spawn(async move {
                            for cert in &certs {
                                storage.store_certificate(cert);
                            }
                        });
                    }
                    (
                        FetchInput::CertificatesReceived {
                            block_hash,
                            certificates,
                        },
                        Some(FetchKind::Certificate),
                        count,
                    )
                }
                FetchTaskResult::Failed {
                    block_hash,
                    kind,
                    hashes,
                    error,
                } => {
                    warn!(
                        ?block_hash,
                        ?kind,
                        hash_count = hashes.len(),
                        error,
                        "Fetch operation failed"
                    );
                    metrics::record_fetch_failed(kind.as_str());
                    (
                        FetchInput::FetchFailed {
                            block_hash,
                            kind,
                            hashes,
                        },
                        None,
                        0,
                    )
                }
            };

            if let Some(kind) = metric_kind {
                metrics::record_fetch_items_received(kind.as_str(), metric_count);
            }

            let outputs = self.protocol.handle(input);
            self.process_outputs(outputs);
        }

        // Tick the protocol to spawn pending fetch operations.
        let outputs = self.protocol.handle(FetchInput::Tick);
        self.process_outputs(outputs);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Output Processing
    // ═══════════════════════════════════════════════════════════════════════

    /// Process protocol outputs — spawn fetches and deliver data.
    fn process_outputs(&mut self, outputs: Vec<FetchOutput>) {
        for output in outputs {
            match output {
                FetchOutput::FetchTransactions {
                    block_hash,
                    proposer,
                    tx_hashes,
                } => {
                    self.spawn_transaction_fetch(block_hash, proposer, tx_hashes);
                }
                FetchOutput::FetchCertificates {
                    block_hash,
                    proposer,
                    cert_hashes,
                } => {
                    self.spawn_certificate_fetch(block_hash, proposer, cert_hashes);
                }
                FetchOutput::DeliverTransactions {
                    block_hash,
                    transactions,
                } => {
                    if !transactions.is_empty() {
                        let event = Event::TransactionReceived {
                            block_hash,
                            transactions,
                        };
                        if let Err(e) = self.event_tx.try_send(event) {
                            warn!(?block_hash, error = ?e, "Failed to deliver transactions to BFT");
                        }
                    }
                    metrics::record_fetch_completed(FetchKind::Transaction.as_str());
                }
                FetchOutput::DeliverCertificates {
                    block_hash,
                    certificates,
                } => {
                    if !certificates.is_empty() {
                        let event = Event::CertificateReceived {
                            block_hash,
                            certificates,
                        };
                        if let Err(e) = self.event_tx.try_send(event) {
                            warn!(?block_hash, error = ?e, "Failed to deliver certificates to BFT");
                        }
                    }
                    metrics::record_fetch_completed(FetchKind::Certificate.as_str());
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Async Task Spawning
    // ═══════════════════════════════════════════════════════════════════════

    /// Get all registered peer IDs.
    fn get_peers(&self) -> Vec<PeerId> {
        self.committee_peers.values().copied().collect()
    }

    /// Spawn a transaction fetch as a background tokio task.
    fn spawn_transaction_fetch(
        &self,
        block_hash: Hash,
        proposer: ValidatorId,
        tx_hashes: Vec<Hash>,
    ) {
        let peers = self.get_peers();
        if peers.is_empty() {
            return;
        }

        let preferred_peer = self.committee_peers.get(&proposer).copied();
        if preferred_peer.is_some() {
            trace!(
                ?block_hash,
                proposer = proposer.0,
                "Will prioritize proposer peer for tx fetch"
            );
        }

        trace!(
            ?block_hash,
            count = tx_hashes.len(),
            "Spawning transaction fetch task"
        );

        let request_manager = self.request_manager.clone();
        let result_tx = self.result_tx.clone();

        tokio::spawn(async move {
            let start = Instant::now();

            let response = request_manager
                .request_transactions(
                    &peers,
                    preferred_peer,
                    block_hash,
                    tx_hashes.clone(),
                    RequestPriority::Critical,
                )
                .await;

            let (_peer, response_bytes) = match response {
                Ok(r) => r,
                Err(e) => {
                    let _ = result_tx
                        .send(FetchTaskResult::Failed {
                            block_hash,
                            kind: FetchKind::Transaction,
                            hashes: tx_hashes,
                            error: format!("{}", e),
                        })
                        .await;
                    return;
                }
            };

            let elapsed = start.elapsed();
            metrics::record_fetch_latency(FetchKind::Transaction.as_str(), elapsed.as_secs_f64());

            let fetch_result = match sbor::basic_decode::<GetTransactionsResponse>(&response_bytes)
            {
                Ok(response) => FetchTaskResult::TransactionsReceived {
                    block_hash,
                    transactions: response.into_transactions(),
                },
                Err(e) => FetchTaskResult::Failed {
                    block_hash,
                    kind: FetchKind::Transaction,
                    hashes: tx_hashes,
                    error: format!("decode error: {:?}", e),
                },
            };

            let _ = result_tx.send(fetch_result).await;
        });
    }

    /// Spawn a certificate fetch as a background tokio task.
    fn spawn_certificate_fetch(
        &self,
        block_hash: Hash,
        proposer: ValidatorId,
        cert_hashes: Vec<Hash>,
    ) {
        let peers = self.get_peers();
        if peers.is_empty() {
            return;
        }

        let preferred_peer = self.committee_peers.get(&proposer).copied();
        if preferred_peer.is_some() {
            trace!(
                ?block_hash,
                proposer = proposer.0,
                "Will prioritize proposer peer for cert fetch"
            );
        }

        trace!(
            ?block_hash,
            count = cert_hashes.len(),
            "Spawning certificate fetch task"
        );

        let request_manager = self.request_manager.clone();
        let result_tx = self.result_tx.clone();

        tokio::spawn(async move {
            let start = Instant::now();

            let response = request_manager
                .request_certificates(
                    &peers,
                    preferred_peer,
                    block_hash,
                    cert_hashes.clone(),
                    RequestPriority::Critical,
                )
                .await;

            let (_peer, response_bytes) = match response {
                Ok(r) => r,
                Err(e) => {
                    let _ = result_tx
                        .send(FetchTaskResult::Failed {
                            block_hash,
                            kind: FetchKind::Certificate,
                            hashes: cert_hashes,
                            error: format!("{}", e),
                        })
                        .await;
                    return;
                }
            };

            let elapsed = start.elapsed();
            metrics::record_fetch_latency(FetchKind::Certificate.as_str(), elapsed.as_secs_f64());

            let fetch_result = match sbor::basic_decode::<GetCertificatesResponse>(&response_bytes)
            {
                Ok(response) => FetchTaskResult::CertificatesReceived {
                    block_hash,
                    certificates: response.into_certificates(),
                },
                Err(e) => FetchTaskResult::Failed {
                    block_hash,
                    kind: FetchKind::Certificate,
                    hashes: cert_hashes,
                    error: format!("decode error: {:?}", e),
                },
            };

            let _ = result_tx.send(fetch_result).await;
        });
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
    fn test_fetch_kind_str() {
        assert_eq!(FetchKind::Transaction.as_str(), "transaction");
        assert_eq!(FetchKind::Certificate.as_str(), "certificate");
    }
}
