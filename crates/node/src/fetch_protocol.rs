//! Fetch protocol state machine.
//!
//! Pure synchronous state machine for transaction/certificate fetching.
//! Tracks missing hashes per block and handles chunking. Does NOT handle
//! peer selection, async dispatch, or storage persistence — those stay
//! in the runner-specific wrapper.
//!
//! # Usage
//!
//! ```text
//! Runner ──► FetchProtocol::handle(FetchInput) ──► Vec<FetchOutput>
//! ```

use hyperscale_metrics as metrics;
use hyperscale_types::{Hash, RoutableTransaction, TransactionCertificate, ValidatorId};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info, trace};

/// Configuration for the fetch protocol.
#[derive(Debug, Clone)]
pub struct FetchConfig {
    /// Maximum number of concurrent fetch operations per block.
    pub max_concurrent_per_block: usize,

    /// Maximum number of hashes to request in a single fetch.
    pub max_hashes_per_request: usize,

    /// Number of parallel fetch operations to spawn for new requests.
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

/// Type of fetch request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FetchKind {
    /// Fetching transactions.
    Transaction,
    /// Fetching certificates.
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

/// Fetch status for external APIs.
#[derive(Debug, Clone, Serialize)]
pub struct FetchStatus {
    /// Number of blocks with pending transaction fetches.
    pub pending_tx_blocks: usize,
    /// Number of blocks with pending certificate fetches.
    pub pending_cert_blocks: usize,
    /// Total in-flight fetch operations.
    pub in_flight_operations: usize,
}

/// Inputs to the fetch protocol state machine.
#[derive(Debug)]
pub enum FetchInput {
    /// Request transactions for a pending block.
    RequestTransactions {
        block_hash: Hash,
        proposer: ValidatorId,
        tx_hashes: Vec<Hash>,
    },
    /// Request certificates for a pending block.
    RequestCertificates {
        block_hash: Hash,
        proposer: ValidatorId,
        cert_hashes: Vec<Hash>,
    },
    /// Transactions were received for a block.
    TransactionsReceived {
        block_hash: Hash,
        transactions: Vec<Arc<RoutableTransaction>>,
    },
    /// Certificates were received for a block.
    CertificatesReceived {
        block_hash: Hash,
        certificates: Vec<TransactionCertificate>,
    },
    /// A fetch operation failed.
    FetchFailed {
        block_hash: Hash,
        kind: FetchKind,
        hashes: Vec<Hash>,
    },
    /// Cancel fetch for a specific block.
    CancelFetch { block_hash: Hash },
    /// Cancel all pending fetches (e.g., when sync starts).
    CancelAll,
    /// Tick: spawn pending fetch operations.
    Tick,
}

/// Outputs from the fetch protocol state machine.
#[derive(Debug)]
pub enum FetchOutput {
    /// Request the runner to fetch transactions.
    FetchTransactions {
        block_hash: Hash,
        proposer: ValidatorId,
        tx_hashes: Vec<Hash>,
    },
    /// Request the runner to fetch certificates.
    FetchCertificates {
        block_hash: Hash,
        proposer: ValidatorId,
        cert_hashes: Vec<Hash>,
    },
    /// Deliver fetched transactions to BFT.
    DeliverTransactions {
        block_hash: Hash,
        transactions: Vec<Arc<RoutableTransaction>>,
    },
    /// Deliver fetched certificates to BFT.
    DeliverCertificates {
        block_hash: Hash,
        certificates: Vec<TransactionCertificate>,
    },
}

/// Per-block fetch state.
#[derive(Debug)]
struct BlockFetchState {
    proposer: ValidatorId,
    missing_hashes: HashSet<Hash>,
    in_flight_hashes: HashSet<Hash>,
    received_hashes: HashSet<Hash>,
    in_flight_count: usize,
}

impl BlockFetchState {
    fn new(proposer: ValidatorId, hashes: Vec<Hash>) -> Self {
        Self {
            proposer,
            missing_hashes: hashes.into_iter().collect(),
            in_flight_hashes: HashSet::new(),
            received_hashes: HashSet::new(),
            in_flight_count: 0,
        }
    }

    fn is_complete(&self) -> bool {
        self.missing_hashes.is_empty() && self.in_flight_hashes.is_empty()
    }

    fn hashes_to_fetch(&self) -> Vec<Hash> {
        self.missing_hashes
            .difference(&self.in_flight_hashes)
            .copied()
            .collect()
    }

    fn mark_in_flight(&mut self, hashes: &[Hash]) {
        for hash in hashes {
            self.in_flight_hashes.insert(*hash);
        }
        self.in_flight_count += 1;
    }

    fn mark_received(&mut self, hashes: impl IntoIterator<Item = Hash>) {
        for hash in hashes {
            self.missing_hashes.remove(&hash);
            self.in_flight_hashes.remove(&hash);
            self.received_hashes.insert(hash);
        }
    }

    fn was_received(&self, hash: &Hash) -> bool {
        self.received_hashes.contains(hash)
    }

    fn mark_fetch_failed(&mut self, hashes: &[Hash]) {
        for hash in hashes {
            self.in_flight_hashes.remove(hash);
        }
        self.in_flight_count = self.in_flight_count.saturating_sub(1);
    }

    fn mark_fetch_complete(&mut self) {
        self.in_flight_count = self.in_flight_count.saturating_sub(1);
    }
}

/// Fetch protocol state machine.
pub struct FetchProtocol {
    config: FetchConfig,
    tx_fetches: HashMap<Hash, BlockFetchState>,
    cert_fetches: HashMap<Hash, BlockFetchState>,
}

impl FetchProtocol {
    /// Create a new fetch protocol state machine.
    pub fn new(config: FetchConfig) -> Self {
        Self {
            config,
            tx_fetches: HashMap::new(),
            cert_fetches: HashMap::new(),
        }
    }

    /// Process an input and return outputs.
    pub fn handle(&mut self, input: FetchInput) -> Vec<FetchOutput> {
        match input {
            FetchInput::RequestTransactions {
                block_hash,
                proposer,
                tx_hashes,
            } => self.handle_request_transactions(block_hash, proposer, tx_hashes),
            FetchInput::RequestCertificates {
                block_hash,
                proposer,
                cert_hashes,
            } => self.handle_request_certificates(block_hash, proposer, cert_hashes),
            FetchInput::TransactionsReceived {
                block_hash,
                transactions,
            } => self.handle_transactions_received(block_hash, transactions),
            FetchInput::CertificatesReceived {
                block_hash,
                certificates,
            } => self.handle_certificates_received(block_hash, certificates),
            FetchInput::FetchFailed {
                block_hash,
                kind,
                hashes,
            } => self.handle_fetch_failed(block_hash, kind, hashes),
            FetchInput::CancelFetch { block_hash } => {
                self.tx_fetches.remove(&block_hash);
                self.cert_fetches.remove(&block_hash);
                debug!(?block_hash, "Cancelled fetch");
                vec![]
            }
            FetchInput::CancelAll => {
                let tx_count = self.tx_fetches.len();
                let cert_count = self.cert_fetches.len();
                if tx_count > 0 || cert_count > 0 {
                    info!(tx_count, cert_count, "Cancelling all fetches");
                }
                self.tx_fetches.clear();
                self.cert_fetches.clear();
                vec![]
            }
            FetchInput::Tick => self.spawn_pending_fetches(),
        }
    }

    /// Get current fetch status.
    pub fn status(&self) -> FetchStatus {
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

    // ═══════════════════════════════════════════════════════════════════════
    // Input Handlers
    // ═══════════════════════════════════════════════════════════════════════

    fn handle_request_transactions(
        &mut self,
        block_hash: Hash,
        proposer: ValidatorId,
        tx_hashes: Vec<Hash>,
    ) -> Vec<FetchOutput> {
        if tx_hashes.is_empty() {
            return vec![];
        }

        if let Some(state) = self.tx_fetches.get_mut(&block_hash) {
            for hash in tx_hashes {
                if !state.was_received(&hash) && !state.in_flight_hashes.contains(&hash) {
                    state.missing_hashes.insert(hash);
                }
            }
            return vec![];
        }

        info!(
            ?block_hash,
            count = tx_hashes.len(),
            proposer = proposer.0,
            "Starting transaction fetch"
        );
        metrics::record_fetch_started("transaction");

        let state = BlockFetchState::new(proposer, tx_hashes);
        self.tx_fetches.insert(block_hash, state);
        vec![]
    }

    fn handle_request_certificates(
        &mut self,
        block_hash: Hash,
        proposer: ValidatorId,
        cert_hashes: Vec<Hash>,
    ) -> Vec<FetchOutput> {
        if cert_hashes.is_empty() {
            return vec![];
        }

        if let Some(state) = self.cert_fetches.get_mut(&block_hash) {
            for hash in cert_hashes {
                if !state.was_received(&hash) && !state.in_flight_hashes.contains(&hash) {
                    state.missing_hashes.insert(hash);
                }
            }
            return vec![];
        }

        info!(
            ?block_hash,
            count = cert_hashes.len(),
            proposer = proposer.0,
            "Starting certificate fetch"
        );
        metrics::record_fetch_started("certificate");

        let state = BlockFetchState::new(proposer, cert_hashes);
        self.cert_fetches.insert(block_hash, state);
        vec![]
    }

    fn handle_transactions_received(
        &mut self,
        block_hash: Hash,
        transactions: Vec<Arc<RoutableTransaction>>,
    ) -> Vec<FetchOutput> {
        let Some(state) = self.tx_fetches.get_mut(&block_hash) else {
            trace!(?block_hash, "Transactions received for unknown fetch");
            return vec![];
        };

        state.mark_fetch_complete();

        let received_hashes: Vec<Hash> = transactions.iter().map(|tx| tx.hash()).collect();
        let received_count = received_hashes.len();
        state.mark_received(received_hashes);
        metrics::record_fetch_items_received("transaction", received_count);

        info!(
            ?block_hash,
            received = received_count,
            remaining = state.missing_hashes.len(),
            "Received transactions"
        );

        let mut outputs = Vec::new();

        if !transactions.is_empty() {
            outputs.push(FetchOutput::DeliverTransactions {
                block_hash,
                transactions,
            });
        }

        if state.is_complete() {
            info!(?block_hash, "Transaction fetch complete");
            metrics::record_fetch_completed("transaction");
            self.tx_fetches.remove(&block_hash);
        }

        outputs
    }

    fn handle_certificates_received(
        &mut self,
        block_hash: Hash,
        certificates: Vec<TransactionCertificate>,
    ) -> Vec<FetchOutput> {
        let Some(state) = self.cert_fetches.get_mut(&block_hash) else {
            trace!(?block_hash, "Certificates received for unknown fetch");
            return vec![];
        };

        state.mark_fetch_complete();

        let received_hashes: Vec<Hash> = certificates.iter().map(|c| c.transaction_hash).collect();
        let received_count = received_hashes.len();
        state.mark_received(received_hashes);
        metrics::record_fetch_items_received("certificate", received_count);

        info!(
            ?block_hash,
            received = received_count,
            remaining = state.missing_hashes.len(),
            "Received certificates"
        );

        let mut outputs = Vec::new();

        if !certificates.is_empty() {
            outputs.push(FetchOutput::DeliverCertificates {
                block_hash,
                certificates,
            });
        }

        if state.is_complete() {
            info!(?block_hash, "Certificate fetch complete");
            metrics::record_fetch_completed("certificate");
            self.cert_fetches.remove(&block_hash);
        }

        outputs
    }

    fn handle_fetch_failed(
        &mut self,
        block_hash: Hash,
        kind: FetchKind,
        hashes: Vec<Hash>,
    ) -> Vec<FetchOutput> {
        let state = match kind {
            FetchKind::Transaction => self.tx_fetches.get_mut(&block_hash),
            FetchKind::Certificate => self.cert_fetches.get_mut(&block_hash),
        };

        if let Some(state) = state {
            state.mark_fetch_failed(&hashes);
            metrics::record_fetch_failed(kind.as_str());
        }

        vec![]
    }

    /// Spawn pending fetch operations across all blocks.
    fn spawn_pending_fetches(&mut self) -> Vec<FetchOutput> {
        let mut outputs = Vec::new();

        // Transaction fetches
        for (block_hash, state) in &mut self.tx_fetches {
            if state.in_flight_count >= self.config.max_concurrent_per_block {
                continue;
            }

            let hashes = state.hashes_to_fetch();
            if hashes.is_empty() {
                continue;
            }

            let available_slots = (self.config.max_concurrent_per_block - state.in_flight_count)
                .min(self.config.parallel_fetches);

            for chunk in hashes
                .chunks(self.config.max_hashes_per_request)
                .take(available_slots)
            {
                let chunk_vec = chunk.to_vec();
                state.mark_in_flight(&chunk_vec);
                outputs.push(FetchOutput::FetchTransactions {
                    block_hash: *block_hash,
                    proposer: state.proposer,
                    tx_hashes: chunk_vec,
                });
            }
        }

        // Certificate fetches
        for (block_hash, state) in &mut self.cert_fetches {
            if state.in_flight_count >= self.config.max_concurrent_per_block {
                continue;
            }

            let hashes = state.hashes_to_fetch();
            if hashes.is_empty() {
                continue;
            }

            let available_slots = (self.config.max_concurrent_per_block - state.in_flight_count)
                .min(self.config.parallel_fetches);

            for chunk in hashes
                .chunks(self.config.max_hashes_per_request)
                .take(available_slots)
            {
                let chunk_vec = chunk.to_vec();
                state.mark_in_flight(&chunk_vec);
                outputs.push(FetchOutput::FetchCertificates {
                    block_hash: *block_hash,
                    proposer: state.proposer,
                    cert_hashes: chunk_vec,
                });
            }
        }

        outputs
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
    fn test_request_and_tick() {
        let mut protocol = FetchProtocol::new(FetchConfig::default());
        let block_hash = Hash::from_bytes(b"test_block");
        let hashes = vec![
            Hash::from_bytes(b"tx1_hash_data_here"),
            Hash::from_bytes(b"tx2_hash_data_here"),
        ];

        protocol.handle(FetchInput::RequestTransactions {
            block_hash,
            proposer: ValidatorId(1),
            tx_hashes: hashes.clone(),
        });

        // Tick should emit FetchTransactions
        let outputs = protocol.handle(FetchInput::Tick);
        assert!(!outputs.is_empty());
        assert!(outputs
            .iter()
            .any(|o| matches!(o, FetchOutput::FetchTransactions { .. })));
    }

    #[test]
    fn test_cancel_all() {
        let mut protocol = FetchProtocol::new(FetchConfig::default());
        let block_hash = Hash::from_bytes(b"test_block");

        protocol.handle(FetchInput::RequestTransactions {
            block_hash,
            proposer: ValidatorId(1),
            tx_hashes: vec![Hash::from_bytes(b"tx1_hash_data_here")],
        });

        protocol.handle(FetchInput::CancelAll);

        let status = protocol.status();
        assert_eq!(status.pending_tx_blocks, 0);
        assert_eq!(status.pending_cert_blocks, 0);
    }

    #[test]
    fn test_fetch_kind_str() {
        assert_eq!(FetchKind::Transaction.as_str(), "transaction");
        assert_eq!(FetchKind::Certificate.as_str(), "certificate");
    }
}
