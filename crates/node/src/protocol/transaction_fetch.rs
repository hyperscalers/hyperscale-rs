//! Transaction fetch protocol state machine.
//!
//! Pure synchronous state machine for transaction fetching.
//! Tracks missing hashes per block and handles chunking. Does NOT handle
//! peer selection, async dispatch, or storage persistence — those stay
//! in the runner-specific wrapper.
//!
//! # Usage
//!
//! ```text
//! Runner ──► TransactionFetchProtocol::handle(TransactionFetchInput) ──► Vec<TransactionFetchOutput>
//! ```

use hyperscale_messages::request::GetTransactionsRequest;
use hyperscale_messages::response::GetTransactionsResponse;
use hyperscale_metrics as metrics;
use hyperscale_storage::ConsensusStore;
use hyperscale_types::{Hash, RoutableTransaction, ValidatorId};
use quick_cache::sync::Cache as QuickCache;
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info, trace};

/// Configuration for the fetch protocol.
#[derive(Debug, Clone)]
pub struct TransactionFetchConfig {
    /// Maximum number of concurrent fetch operations per block.
    pub max_concurrent_per_block: usize,

    /// Maximum number of hashes to request in a single fetch.
    pub max_hashes_per_request: usize,

    /// Number of parallel fetch operations to spawn for new requests.
    pub parallel_fetches: usize,
}

impl Default for TransactionFetchConfig {
    fn default() -> Self {
        Self {
            max_concurrent_per_block: 8,
            max_hashes_per_request: 50,
            parallel_fetches: 4,
        }
    }
}

/// Fetch status for external APIs.
#[derive(Debug, Clone, Serialize)]
pub struct TransactionFetchStatus {
    /// Number of blocks with pending transaction fetches.
    pub pending_tx_blocks: usize,
    /// Total in-flight fetch operations.
    pub in_flight_operations: usize,
}

/// Inputs to the fetch protocol state machine.
#[derive(Debug)]
pub enum TransactionFetchInput {
    /// Request transactions for a pending block.
    RequestTransactions {
        block_hash: Hash,
        proposer: ValidatorId,
        tx_hashes: Vec<Hash>,
    },
    /// Transactions were received for a block.
    TransactionsReceived {
        block_hash: Hash,
        transactions: Vec<Arc<RoutableTransaction>>,
    },
    /// A fetch operation failed.
    FetchFailed { block_hash: Hash, hashes: Vec<Hash> },
    /// Cancel fetch for a specific block.
    CancelFetch { block_hash: Hash },
    /// Tick: spawn pending fetch operations.
    Tick,
}

/// Outputs from the fetch protocol state machine.
#[derive(Debug)]
pub enum TransactionFetchOutput {
    /// Request the runner to fetch transactions.
    FetchTransactions {
        block_hash: Hash,
        proposer: ValidatorId,
        tx_hashes: Vec<Hash>,
    },
    /// Deliver fetched transactions to BFT.
    DeliverTransactions {
        block_hash: Hash,
        transactions: Vec<Arc<RoutableTransaction>>,
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
pub struct TransactionFetchProtocol {
    config: TransactionFetchConfig,
    tx_fetches: BTreeMap<Hash, BlockFetchState>,
}

impl TransactionFetchProtocol {
    /// Create a new fetch protocol state machine.
    pub fn new(config: TransactionFetchConfig) -> Self {
        Self {
            config,
            tx_fetches: BTreeMap::new(),
        }
    }

    /// Process an input and return outputs.
    pub fn handle(&mut self, input: TransactionFetchInput) -> Vec<TransactionFetchOutput> {
        match input {
            TransactionFetchInput::RequestTransactions {
                block_hash,
                proposer,
                tx_hashes,
            } => self.handle_request_transactions(block_hash, proposer, tx_hashes),
            TransactionFetchInput::TransactionsReceived {
                block_hash,
                transactions,
            } => self.handle_transactions_received(block_hash, transactions),
            TransactionFetchInput::FetchFailed { block_hash, hashes } => {
                self.handle_fetch_failed(block_hash, hashes)
            }
            TransactionFetchInput::CancelFetch { block_hash } => {
                self.tx_fetches.remove(&block_hash);
                debug!(?block_hash, "Cancelled fetch");
                vec![]
            }
            TransactionFetchInput::Tick => self.spawn_pending_fetches(),
        }
    }

    /// Get current fetch status.
    pub fn status(&self) -> TransactionFetchStatus {
        let in_flight: usize = self.tx_fetches.values().map(|s| s.in_flight_count).sum();

        TransactionFetchStatus {
            pending_tx_blocks: self.tx_fetches.len(),
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
    ) -> Vec<TransactionFetchOutput> {
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

    fn handle_transactions_received(
        &mut self,
        block_hash: Hash,
        transactions: Vec<Arc<RoutableTransaction>>,
    ) -> Vec<TransactionFetchOutput> {
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
            outputs.push(TransactionFetchOutput::DeliverTransactions {
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

    fn handle_fetch_failed(
        &mut self,
        block_hash: Hash,
        hashes: Vec<Hash>,
    ) -> Vec<TransactionFetchOutput> {
        if let Some(state) = self.tx_fetches.get_mut(&block_hash) {
            state.mark_fetch_failed(&hashes);
            metrics::record_fetch_failed("transaction");
        }

        vec![]
    }

    /// Spawn pending fetch operations across all blocks.
    fn spawn_pending_fetches(&mut self) -> Vec<TransactionFetchOutput> {
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
                outputs.push(TransactionFetchOutput::FetchTransactions {
                    block_hash: *block_hash,
                    proposer: state.proposer,
                    tx_hashes: chunk_vec,
                });
            }
        }

        outputs
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Inbound request serving
// ═══════════════════════════════════════════════════════════════════════

/// Maximum items returned in a single transaction fetch response.
const MAX_ITEMS_PER_RESPONSE: usize = 500;

/// Serve an inbound transaction fetch request.
///
/// Checks the in-memory cache first (for recently received but not yet
/// committed transactions), then falls back to storage.
pub fn serve_transaction_request(
    storage: &impl ConsensusStore,
    tx_cache: &QuickCache<Hash, Arc<RoutableTransaction>>,
    req: GetTransactionsRequest,
) -> GetTransactionsResponse {
    let requested_count = req.tx_hashes.len();
    trace!(
        block_hash = ?req.block_hash,
        tx_count = requested_count,
        "Handling transaction fetch request"
    );

    let hashes = if requested_count > MAX_ITEMS_PER_RESPONSE {
        &req.tx_hashes[..MAX_ITEMS_PER_RESPONSE]
    } else {
        &req.tx_hashes
    };

    let mut found = Vec::with_capacity(hashes.len());
    let mut missing = Vec::new();
    for hash in hashes {
        if let Some(tx) = tx_cache.get(hash) {
            found.push(tx);
        } else {
            missing.push(*hash);
        }
    }
    if !missing.is_empty() {
        found.extend(
            storage
                .get_transactions_batch(&missing)
                .into_iter()
                .map(Arc::new),
        );
    }

    let found_count = found.len();
    debug!(
        block_hash = ?req.block_hash,
        requested = requested_count,
        found = found_count,
        "Responding to transaction fetch request"
    );
    metrics::record_fetch_response_sent("transaction", found_count);
    GetTransactionsResponse::new(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_config_defaults() {
        let config = TransactionFetchConfig::default();
        assert_eq!(config.max_concurrent_per_block, 8);
        assert_eq!(config.parallel_fetches, 4);
        assert_eq!(config.max_hashes_per_request, 50);
    }

    #[test]
    fn test_request_and_tick() {
        let mut protocol = TransactionFetchProtocol::new(TransactionFetchConfig::default());
        let block_hash = Hash::from_bytes(b"test_block");
        let hashes = vec![
            Hash::from_bytes(b"tx1_hash_data_here"),
            Hash::from_bytes(b"tx2_hash_data_here"),
        ];

        protocol.handle(TransactionFetchInput::RequestTransactions {
            block_hash,
            proposer: ValidatorId(1),
            tx_hashes: hashes.clone(),
        });

        // Tick should emit FetchTransactions
        let outputs = protocol.handle(TransactionFetchInput::Tick);
        assert!(!outputs.is_empty());
        assert!(outputs
            .iter()
            .any(|o| matches!(o, TransactionFetchOutput::FetchTransactions { .. })));
    }
}
