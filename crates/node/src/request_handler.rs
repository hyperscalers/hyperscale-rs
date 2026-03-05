//! Request handler for block sync, data fetch, and provision serving.
//!
//! Processes incoming requests using `ConsensusStore` and `SubstateStore`
//! trait methods. SBOR decode/encode is handled by the network layer via
//! `Network::register_typed_request_handler` — these methods receive typed
//! requests and return typed responses.
//!
//! Request types:
//! - `GetBlockRequest` / `GetBlockResponse` — block sync
//! - `GetTransactionsRequest` / `GetTransactionsResponse` — transaction fetch
//! - `GetCertificatesRequest` / `GetCertificatesResponse` — certificate fetch
//! - `GetProvisionsRequest` / `GetProvisionsResponse` — provision fetch for fallback recovery

use hyperscale_messages::request::{
    GetBlockRequest, GetCertificatesRequest, GetProvisionsRequest, GetTransactionsRequest,
};
use hyperscale_messages::response::{
    GetBlockResponse, GetCertificatesResponse, GetProvisionsResponse, GetTransactionsResponse,
};
use hyperscale_metrics as metrics;
use hyperscale_storage::{ConsensusStore, SubstateStore};
use hyperscale_types::{
    Hash, RoutableTransaction, StateProvision, Topology, TransactionCertificate,
};
use quick_cache::sync::Cache as QuickCache;
use std::sync::Arc;
use tracing::{debug, trace};

/// Configuration for the request handler.
#[derive(Debug, Clone)]
pub struct RequestHandlerConfig {
    /// Maximum number of items to return in a single fetch response.
    pub max_items_per_response: usize,
}

impl Default for RequestHandlerConfig {
    fn default() -> Self {
        Self {
            max_items_per_response: 500,
        }
    }
}

/// Request handler, parameterized over storage.
///
/// Handles block sync, transaction fetch, certificate fetch, and provision
/// serving requests. Transport-specific I/O (stream framing, compression,
/// metrics) is handled by the transport layer's inbound router.
pub struct RequestHandler<S: ConsensusStore + SubstateStore> {
    config: RequestHandlerConfig,
    storage: Arc<S>,
    topology: Arc<dyn Topology>,
    /// Cache for recently received transactions (not yet committed to storage).
    recently_received_txs: Arc<QuickCache<Hash, Arc<RoutableTransaction>>>,
    /// Cache for recently built certificates (not yet persisted to storage).
    recently_built_certs: Arc<QuickCache<Hash, Arc<TransactionCertificate>>>,
}

impl<S: ConsensusStore + SubstateStore> RequestHandler<S> {
    /// Create a new request handler.
    pub fn new(
        config: RequestHandlerConfig,
        storage: Arc<S>,
        topology: Arc<dyn Topology>,
        recently_received_txs: Arc<QuickCache<Hash, Arc<RoutableTransaction>>>,
        recently_built_certs: Arc<QuickCache<Hash, Arc<TransactionCertificate>>>,
    ) -> Self {
        Self {
            config,
            storage,
            topology,
            recently_received_txs,
            recently_built_certs,
        }
    }

    /// Handle a block sync request.
    pub fn handle_block_request(&self, req: GetBlockRequest) -> GetBlockResponse {
        trace!(height = req.height.0, "Handling block sync request");

        match self.storage.get_block_for_sync(req.height) {
            Some((block, qc)) => GetBlockResponse::found(block, qc),
            None => GetBlockResponse::not_found(),
        }
    }

    /// Handle a transaction fetch request.
    pub fn handle_transaction_request(
        &self,
        tx_request: GetTransactionsRequest,
    ) -> GetTransactionsResponse {
        let requested_count = tx_request.tx_hashes.len();
        trace!(
            block_hash = ?tx_request.block_hash,
            tx_count = requested_count,
            "Handling transaction fetch request"
        );

        let hashes_to_fetch = if requested_count > self.config.max_items_per_response {
            &tx_request.tx_hashes[..self.config.max_items_per_response]
        } else {
            &tx_request.tx_hashes
        };

        // Check in-memory cache first, then fall back to storage
        let mut found_transactions = Vec::with_capacity(hashes_to_fetch.len());
        let mut missing_hashes = Vec::new();

        for hash in hashes_to_fetch {
            if let Some(tx) = self.recently_received_txs.get(hash) {
                found_transactions.push(tx);
            } else {
                missing_hashes.push(*hash);
            }
        }

        if !missing_hashes.is_empty() {
            let from_storage: Vec<Arc<_>> = self
                .storage
                .get_transactions_batch(&missing_hashes)
                .into_iter()
                .map(Arc::new)
                .collect();
            found_transactions.extend(from_storage);
        }

        let found_count = found_transactions.len();
        debug!(
            block_hash = ?tx_request.block_hash,
            requested = requested_count,
            found = found_count,
            "Responding to transaction fetch request"
        );
        metrics::record_fetch_response_sent("transaction", found_count);

        GetTransactionsResponse::new(found_transactions)
    }

    /// Handle a certificate fetch request.
    pub fn handle_certificate_request(
        &self,
        cert_request: GetCertificatesRequest,
    ) -> GetCertificatesResponse {
        let requested_count = cert_request.cert_hashes.len();
        trace!(
            block_hash = ?cert_request.block_hash,
            cert_count = requested_count,
            "Handling certificate fetch request"
        );

        let hashes_to_fetch = if requested_count > self.config.max_items_per_response {
            &cert_request.cert_hashes[..self.config.max_items_per_response]
        } else {
            &cert_request.cert_hashes
        };

        // Check in-memory cache first, then fall back to storage
        let mut found_certificates = Vec::with_capacity(hashes_to_fetch.len());
        let mut missing_hashes = Vec::new();

        for hash in hashes_to_fetch {
            if let Some(cert) = self.recently_built_certs.get(hash) {
                found_certificates.push((*cert).clone());
            } else {
                missing_hashes.push(*hash);
            }
        }

        if !missing_hashes.is_empty() {
            let from_storage = self.storage.get_certificates_batch(&missing_hashes);
            found_certificates.extend(from_storage);
        }

        let found_count = found_certificates.len();
        debug!(
            block_hash = ?cert_request.block_hash,
            requested = requested_count,
            found = found_count,
            "Responding to certificate fetch request"
        );
        metrics::record_fetch_response_sent("certificate", found_count);

        GetCertificatesResponse::new(found_certificates)
    }

    /// Handle a provision request from a target shard needing our state.
    ///
    /// Looks up the block at the requested height, identifies transactions
    /// that involve the requesting shard, collects the local state entries
    /// and merkle proofs, and returns them as `StateProvision`s.
    pub fn handle_provision_request(&self, req: GetProvisionsRequest) -> GetProvisionsResponse {
        trace!(
            block_height = req.block_height.0,
            target_shard = req.target_shard.0,
            "Handling provision request"
        );

        let local_shard = self.topology.local_shard();

        // Look up the block at the requested height
        let (block, _qc) = match self.storage.get_block(req.block_height) {
            Some(pair) => pair,
            None => {
                debug!(
                    block_height = req.block_height.0,
                    "Provision request: block not found"
                );
                return GetProvisionsResponse { provisions: None };
            }
        };

        let mut provisions = Vec::new();

        // Use the block header's state_version (QC-attested, matches state_root).
        // Both data and proofs must come from this version so the target shard
        // can verify against header.state_root.
        let block_state_version = block.header.state_version;

        // Iterate all transactions in the block
        let all_txs = block
            .retry_transactions
            .iter()
            .chain(block.priority_transactions.iter())
            .chain(block.transactions.iter());

        for tx in all_txs {
            // Check if this transaction involves the requesting target shard
            let shards = self.topology.all_shards_for_transaction(tx);
            if !shards.contains(&req.target_shard) {
                continue;
            }

            // Collect nodes owned by our local shard
            let mut owned_nodes: Vec<_> = tx
                .declared_reads
                .iter()
                .chain(tx.declared_writes.iter())
                .filter(|&node_id| self.topology.shard_for_node_id(node_id) == local_shard)
                .copied()
                .collect();
            owned_nodes.sort();
            owned_nodes.dedup();

            if owned_nodes.is_empty() {
                continue;
            }

            // Fetch state entries and generate merkle proofs at the block's version.
            // If the version is no longer available (GC'd), respond with None so
            // the requester can try a different peer.
            let entries = match hyperscale_engine::fetch_state_entries(
                &*self.storage,
                &owned_nodes,
                block_state_version,
            ) {
                Some(entries) => entries,
                None => {
                    debug!(
                        block_height = req.block_height.0,
                        state_version = block_state_version,
                        "Provision request: historical state version unavailable"
                    );
                    return GetProvisionsResponse { provisions: None };
                }
            };
            let storage_keys: Vec<Vec<u8>> =
                entries.iter().map(|e| e.storage_key.clone()).collect();
            let merkle_proofs = self
                .storage
                .generate_merkle_proofs(&storage_keys, block_state_version);

            let entries = Arc::new(entries);
            let merkle_proofs = Arc::new(merkle_proofs);

            provisions.push(StateProvision {
                transaction_hash: tx.hash(),
                target_shard: req.target_shard,
                source_shard: local_shard,
                block_height: req.block_height,
                block_timestamp: block.header.timestamp,
                state_version: block_state_version,
                entries,
                merkle_proofs,
            });
        }

        debug!(
            block_height = req.block_height.0,
            target_shard = req.target_shard.0,
            provision_count = provisions.len(),
            "Responding to provision request"
        );

        GetProvisionsResponse {
            provisions: Some(provisions),
        }
    }
}
