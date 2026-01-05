//! Routes inbound network requests to appropriate handlers.
//!
//! This component receives raw request bytes from the transport layer and routes them
//! to the appropriate handler based on request type. It unifies the handling of:
//! - Block sync requests
//! - Transaction fetch requests
//! - Certificate fetch requests
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────────┐
//! │                         Libp2pAdapter                                      │
//! │  ┌─────────────────────────────────────────────────────────────────────┐   │
//! │  │  Inbound Request                                                    │   │
//! │  │  (raw bytes + channel_id)                                           │   │
//! │  └───────────────────────────────┬─────────────────────────────────────┘   │
//! └──────────────────────────────────┼─────────────────────────────────────────┘
//!                                    │
//!                                    ▼
//! ┌────────────────────────────────────────────────────────────────────────────┐
//! │                         InboundRouter                                      │
//! │                                                                            │
//! │  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────────────────┐    │
//! │  │  Block Request  │  │ Transaction Req  │  │ Certificate Request     │    │
//! │  │  (8 bytes)      │  │ (SBOR encoded)   │  │ (SBOR encoded)          │    │
//! │  └────────┬────────┘  └────────┬─────────┘  └───────────┬─────────────┘    │
//! │           │                    │                        │                  │
//! │           ▼                    ▼                        ▼                  │
//! │  ┌─────────────────────────────────────────────────────────────────────┐   │
//! │  │                    Storage / Handler                                │   │
//! │  │                    (reads data, encodes response)                   │   │
//! │  └─────────────────────────────────────────────────────────────────────┘   │
//! │                                    │                                       │
//! │                                    ▼                                       │
//! │  ┌─────────────────────────────────────────────────────────────────────┐   │
//! │  │                adapter.respond(channel_id, bytes)                   │   │
//! │  └─────────────────────────────────────────────────────────────────────┘   │
//! └────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Design Goals
//!
//! 1. **Separation of Concerns**: The Libp2pAdapter knows nothing about blocks/transactions/certificates
//! 2. **Unified Response Path**: All responses go through adapter's `respond()` method
//! 3. **Request Type Discrimination**: Moved out of the adapter into this router

use super::adapter::Libp2pAdapter;
use crate::storage::RocksDbStorage;
use bytes::Bytes;
use hyperscale_messages::request::{
    GetCertificatesRequest, GetTransactionsRequest, FETCH_TYPE_CERTIFICATE, FETCH_TYPE_TRANSACTION,
};
use hyperscale_messages::response::{GetCertificatesResponse, GetTransactionsResponse};
use hyperscale_types::{
    Block, BlockHeight, BlockMetadata, Hash, QuorumCertificate, TransactionCertificate,
};
use libp2p::PeerId;
use quick_cache::sync::Cache as QuickCache;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

/// A generic inbound request from a peer.
///
/// This unified type replaces the separate `InboundSyncRequest`, `InboundTransactionRequest`,
/// and `InboundCertificateRequest` types. The router discriminates request types internally.
#[derive(Debug)]
pub struct InboundRequest {
    /// The requesting peer.
    pub peer: PeerId,
    /// Raw request payload.
    pub payload: Bytes,
    /// Opaque response channel ID (used to send the response).
    pub channel_id: u64,
}

/// Configuration for the inbound router.
#[derive(Debug, Clone)]
pub struct InboundRouterConfig {
    /// Maximum number of items to return in a single fetch response.
    /// Prevents memory exhaustion from large requests.
    pub max_items_per_response: usize,
}

impl Default for InboundRouterConfig {
    fn default() -> Self {
        Self {
            max_items_per_response: 500,
        }
    }
}

/// Handle for the inbound router task.
pub struct InboundRouterHandle {
    join_handle: tokio::task::JoinHandle<()>,
}

impl InboundRouterHandle {
    /// Check if the router task is still running.
    pub fn is_running(&self) -> bool {
        !self.join_handle.is_finished()
    }

    /// Wait for the router task to complete.
    pub async fn wait(self) {
        let _ = self.join_handle.await;
    }
}

/// Routes inbound requests to appropriate handlers.
///
/// The router receives raw request bytes and:
/// 1. Discriminates request type based on payload structure
/// 2. Decodes the request
/// 3. Looks up data from storage
/// 4. Encodes and sends the response via adapter.respond()
pub struct InboundRouter {
    config: InboundRouterConfig,
    /// Network adapter for sending responses.
    adapter: Arc<Libp2pAdapter>,
    /// Storage for reading blocks, transactions, and certificates.
    storage: Arc<RocksDbStorage>,
    /// Cache for recently built certificates (not yet persisted to storage).
    recently_built_certs: Arc<QuickCache<Hash, Arc<TransactionCertificate>>>,
}

impl InboundRouter {
    /// Create a new inbound router.
    pub fn new(
        config: InboundRouterConfig,
        adapter: Arc<Libp2pAdapter>,
        storage: Arc<RocksDbStorage>,
        recently_built_certs: Arc<QuickCache<Hash, Arc<TransactionCertificate>>>,
    ) -> Self {
        Self {
            config,
            adapter,
            storage,
            recently_built_certs,
        }
    }

    /// Spawn the inbound router as a background task.
    ///
    /// The router will process requests from the given channel until it closes.
    pub fn spawn(
        config: InboundRouterConfig,
        adapter: Arc<Libp2pAdapter>,
        storage: Arc<RocksDbStorage>,
        recently_built_certs: Arc<QuickCache<Hash, Arc<TransactionCertificate>>>,
        mut request_rx: mpsc::UnboundedReceiver<InboundRequest>,
    ) -> InboundRouterHandle {
        let join_handle = tokio::spawn(async move {
            let router = Self::new(config, adapter, storage, recently_built_certs);

            tracing::info!("InboundRouter started");

            while let Some(request) = request_rx.recv().await {
                router.handle_request(request);

                // Drain any additional pending requests for batch efficiency
                while let Ok(request) = request_rx.try_recv() {
                    router.handle_request(request);
                }
            }

            tracing::info!("InboundRouter shutting down (channel closed)");
        });

        InboundRouterHandle { join_handle }
    }

    /// Handle an inbound request by routing to the appropriate handler.
    fn handle_request(&self, request: InboundRequest) {
        let payload = &request.payload;

        // Discriminate request type based on payload structure:
        // 1. Block sync request: exactly 8 bytes (u64 height in little-endian)
        // 2. Transaction/Certificate fetch: SBOR-encoded with fetch_type tag at byte 4
        // 3. Direct consensus message: handled elsewhere (decoded as direct message)

        if payload.len() == 8 {
            // Block sync request (8-byte height)
            self.handle_block_request(request);
        } else if payload.len() > 8 {
            // SBOR-encoded fetch request - check fetch_type at byte 4
            // Basic SBOR encoding: [0x5b (prefix), 0x21 (Tuple), 0x03 (field count), 0x07 (u8 type), value, ...]
            let fetch_type = payload.get(4).copied();

            match fetch_type {
                Some(FETCH_TYPE_TRANSACTION) => {
                    self.handle_transaction_request(request);
                }
                Some(FETCH_TYPE_CERTIFICATE) => {
                    self.handle_certificate_request(request);
                }
                _ => {
                    warn!(
                        peer = %request.peer,
                        len = payload.len(),
                        fetch_type = ?fetch_type,
                        "Unknown fetch request type"
                    );
                }
            }
        } else {
            warn!(
                peer = %request.peer,
                len = payload.len(),
                "Invalid request (too short)"
            );
        }
    }

    /// Handle a block sync request.
    fn handle_block_request(&self, request: InboundRequest) {
        use crate::storage::SyncBlockData;

        // Decode height from 8 bytes (little-endian u64)
        let height_bytes: [u8; 8] = match request.payload.as_ref().try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                warn!(peer = %request.peer, "Invalid block request (not 8 bytes)");
                return;
            }
        };
        let height = u64::from_le_bytes(height_bytes);
        let block_height = BlockHeight(height);
        let channel_id = request.channel_id;

        trace!(
            peer = %request.peer,
            height = height,
            channel_id = channel_id,
            "Handling block sync request"
        );

        // Clone for the blocking task
        let storage = self.storage.clone();
        let adapter = self.adapter.clone();

        // Spawn on blocking thread pool to avoid blocking the router.
        // RocksDB reads are synchronous I/O that can take ms for large blocks.
        tokio::task::spawn_blocking(move || {
            let response = match storage.get_block_for_sync(block_height) {
                Some(SyncBlockData::Complete(block, qc)) => {
                    // Full block available - encode as (Some(block), Some(qc), None)
                    match sbor::basic_encode(&(Some(&block), Some(&qc), None::<BlockMetadata>)) {
                        Ok(data) => data,
                        Err(e) => {
                            warn!(height, error = ?e, "Failed to encode block response");
                            Self::encode_empty_block_response()
                        }
                    }
                }
                Some(SyncBlockData::MetadataOnly(metadata)) => {
                    // Metadata only - encode as (None, None, Some(metadata))
                    debug!(
                        height,
                        tx_count = metadata.tx_hashes.len(),
                        cert_count = metadata.cert_hashes.len(),
                        "Returning metadata-only sync response"
                    );
                    match sbor::basic_encode(&(
                        None::<Block>,
                        None::<QuorumCertificate>,
                        Some(&metadata),
                    )) {
                        Ok(data) => data,
                        Err(e) => {
                            warn!(height, error = ?e, "Failed to encode metadata response");
                            Self::encode_empty_block_response()
                        }
                    }
                }
                None => {
                    trace!(height, "Block not found for sync request");
                    Self::encode_empty_block_response()
                }
            };

            // Send response via adapter
            if let Err(e) = adapter.respond(channel_id, response) {
                warn!(height, channel_id, error = ?e, "Failed to send block response");
            }
        });
    }

    /// Handle a transaction fetch request.
    fn handle_transaction_request(&self, request: InboundRequest) {
        let channel_id = request.channel_id;

        // Decode the request
        let tx_request = match sbor::basic_decode::<GetTransactionsRequest>(&request.payload) {
            Ok(req) => req,
            Err(e) => {
                warn!(peer = %request.peer, error = ?e, "Failed to decode transaction request");
                return;
            }
        };

        let requested_count = tx_request.tx_hashes.len();
        trace!(
            peer = %request.peer,
            block_hash = ?tx_request.block_hash,
            tx_count = requested_count,
            channel_id = channel_id,
            "Handling transaction fetch request"
        );

        // Limit the number of hashes to prevent DoS
        let hashes_to_fetch = if requested_count > self.config.max_items_per_response {
            &tx_request.tx_hashes[..self.config.max_items_per_response]
        } else {
            &tx_request.tx_hashes
        };

        // Read directly from RocksDB storage (block cache handles hot data)
        let found_transactions: Vec<Arc<_>> = self
            .storage
            .get_transactions_batch(hashes_to_fetch)
            .into_iter()
            .map(Arc::new)
            .collect();
        let found_count = found_transactions.len();

        debug!(
            block_hash = ?tx_request.block_hash,
            requested = requested_count,
            found = found_count,
            "Responding to transaction fetch request"
        );

        // Encode the response
        let response = GetTransactionsResponse::new(found_transactions);
        let response_bytes = match sbor::basic_encode(&response) {
            Ok(data) => data,
            Err(e) => {
                warn!(error = ?e, "Failed to encode transaction response");
                sbor::basic_encode(&GetTransactionsResponse::empty()).unwrap_or_default()
            }
        };

        // Send response via adapter
        if let Err(e) = self.adapter.respond(channel_id, response_bytes) {
            warn!(channel_id, error = ?e, "Failed to send transaction response");
        }

        // Update metrics
        crate::metrics::record_fetch_response_sent("transaction", found_count);
    }

    /// Handle a certificate fetch request.
    fn handle_certificate_request(&self, request: InboundRequest) {
        let channel_id = request.channel_id;

        // Decode the request
        let cert_request = match sbor::basic_decode::<GetCertificatesRequest>(&request.payload) {
            Ok(req) => req,
            Err(e) => {
                warn!(peer = %request.peer, error = ?e, "Failed to decode certificate request");
                return;
            }
        };

        let requested_count = cert_request.cert_hashes.len();
        trace!(
            peer = %request.peer,
            block_hash = ?cert_request.block_hash,
            cert_count = requested_count,
            channel_id = channel_id,
            "Handling certificate fetch request"
        );

        // Limit the number of hashes to prevent DoS
        let hashes_to_fetch = if requested_count > self.config.max_items_per_response {
            &cert_request.cert_hashes[..self.config.max_items_per_response]
        } else {
            &cert_request.cert_hashes
        };

        // First check the in-memory cache for recently built certificates.
        // This handles the race where we built a cert and included it in a block,
        // but the async storage write hasn't completed yet.
        let mut found_certificates = Vec::with_capacity(hashes_to_fetch.len());
        let mut missing_hashes = Vec::new();

        for hash in hashes_to_fetch {
            if let Some(cert) = self.recently_built_certs.get(hash) {
                found_certificates.push((*cert).clone());
            } else {
                missing_hashes.push(*hash);
            }
        }

        // Fall back to RocksDB for any not found in cache
        if !missing_hashes.is_empty() {
            let from_storage = self.storage.get_certificates_batch(&missing_hashes);
            found_certificates.extend(from_storage);
        }

        let found_count = found_certificates.len();
        let from_cache = hashes_to_fetch.len() - missing_hashes.len();

        debug!(
            block_hash = ?cert_request.block_hash,
            requested = requested_count,
            found = found_count,
            from_cache = from_cache,
            "Responding to certificate fetch request"
        );

        // Encode the response
        let response = GetCertificatesResponse::new(found_certificates);
        let response_bytes = match sbor::basic_encode(&response) {
            Ok(data) => data,
            Err(e) => {
                warn!(error = ?e, "Failed to encode certificate response");
                sbor::basic_encode(&GetCertificatesResponse::empty()).unwrap_or_default()
            }
        };

        // Send response via adapter
        if let Err(e) = self.adapter.respond(channel_id, response_bytes) {
            warn!(channel_id, error = ?e, "Failed to send certificate response");
        }

        // Update metrics
        crate::metrics::record_fetch_response_sent("certificate", found_count);
    }

    /// Encode an empty block response.
    fn encode_empty_block_response() -> Vec<u8> {
        sbor::basic_encode(&(
            None::<Block>,
            None::<QuorumCertificate>,
            None::<BlockMetadata>,
        ))
        .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = InboundRouterConfig::default();
        assert_eq!(config.max_items_per_response, 500);
    }
}
