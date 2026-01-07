//! Routes inbound network requests to appropriate handlers.
//!
//! This component accepts incoming streams from peers and routes them to the
//! appropriate handler based on request type. It unifies the handling of:
//! - Block sync requests
//! - Transaction fetch requests
//! - Certificate fetch requests
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────────┐
//! │                         libp2p_stream                                      │
//! │  ┌─────────────────────────────────────────────────────────────────────┐   │
//! │  │  Incoming Stream                                                    │   │
//! │  │  (bidirectional raw stream)                                         │   │
//! │  └───────────────────────────────┬─────────────────────────────────────┘   │
//! └──────────────────────────────────┼─────────────────────────────────────────┘
//!                                    │
//!                                    ▼
//! ┌────────────────────────────────────────────────────────────────────────────┐
//! │                         InboundRouter                                      │
//! │                                                                            │
//! │  1. Read length-prefixed request from stream                              │
//! │  2. Discriminate request type based on payload                            │
//! │  3. Look up data from storage                                             │
//! │  4. Write length-prefixed response to stream                              │
//! │  5. Close stream                                                          │
//! │                                                                            │
//! └────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Design Goals
//!
//! 1. **Separation of Concerns**: Transport layer knows nothing about blocks/transactions/certificates
//! 2. **Request-Response via Streams**: Uses raw libp2p streams with length-prefixed framing
//! 3. **Request Type Discrimination**: Determines type from payload structure

use super::adapter::{Libp2pAdapter, STREAM_PROTOCOL};
use super::wire;
use crate::storage::RocksDbStorage;
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use hyperscale_messages::request::{
    GetCertificatesRequest, GetTransactionsRequest, FETCH_TYPE_CERTIFICATE, FETCH_TYPE_TRANSACTION,
};
use hyperscale_messages::response::{GetCertificatesResponse, GetTransactionsResponse};
use hyperscale_types::{
    Block, BlockHeight, Hash, QuorumCertificate, RoutableTransaction, TransactionCertificate,
};
use libp2p::{PeerId, Stream};
use quick_cache::sync::Cache as QuickCache;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, trace, warn};

/// Timeout for reading requests and writing responses on streams.
const STREAM_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum request size (10MB).
const MAX_REQUEST_SIZE: usize = 10 * 1024 * 1024;

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
/// The router accepts incoming streams and for each:
/// 1. Reads the length-prefixed request
/// 2. Discriminates request type based on payload structure
/// 3. Looks up data from storage
/// 4. Writes the length-prefixed response
/// 5. Closes the stream
pub struct InboundRouter {
    config: InboundRouterConfig,
    /// Storage for reading blocks, transactions, and certificates.
    storage: Arc<RocksDbStorage>,
    /// Cache for recently received transactions (not yet committed to storage).
    /// Checked before RocksDB to serve fetch requests for transactions received via gossip.
    recently_received_txs: Arc<QuickCache<Hash, Arc<RoutableTransaction>>>,
    /// Cache for recently built certificates (not yet persisted to storage).
    recently_built_certs: Arc<QuickCache<Hash, Arc<TransactionCertificate>>>,
}

impl InboundRouter {
    /// Create a new inbound router.
    pub fn new(
        config: InboundRouterConfig,
        storage: Arc<RocksDbStorage>,
        recently_received_txs: Arc<QuickCache<Hash, Arc<RoutableTransaction>>>,
        recently_built_certs: Arc<QuickCache<Hash, Arc<TransactionCertificate>>>,
    ) -> Self {
        Self {
            config,
            storage,
            recently_received_txs,
            recently_built_certs,
        }
    }

    /// Spawn the inbound router as a background task.
    ///
    /// The router will accept incoming streams until the stream control is dropped.
    pub fn spawn(
        config: InboundRouterConfig,
        adapter: Arc<Libp2pAdapter>,
        storage: Arc<RocksDbStorage>,
        recently_received_txs: Arc<QuickCache<Hash, Arc<RoutableTransaction>>>,
        recently_built_certs: Arc<QuickCache<Hash, Arc<TransactionCertificate>>>,
    ) -> InboundRouterHandle {
        let join_handle = tokio::spawn(async move {
            let router = Arc::new(Self::new(
                config,
                storage,
                recently_received_txs,
                recently_built_certs,
            ));
            let mut control = adapter.stream_control();

            // Register to accept incoming streams for our protocol
            let mut incoming = match control.accept(STREAM_PROTOCOL) {
                Ok(incoming) => incoming,
                Err(e) => {
                    tracing::error!(error = ?e, "Failed to register stream protocol");
                    return;
                }
            };

            tracing::info!("InboundRouter started, accepting incoming streams");

            // Accept incoming streams
            while let Some((peer_id, stream)) = incoming.next().await {
                let router_clone = router.clone();

                // Spawn a task to handle each stream concurrently
                tokio::spawn(async move {
                    if let Err(e) = router_clone.handle_stream(peer_id, stream).await {
                        debug!(peer = %peer_id, error = ?e, "Stream handling failed");
                    }
                });
            }

            tracing::info!("InboundRouter shutting down (incoming streams closed)");
        });

        InboundRouterHandle { join_handle }
    }

    /// Handle a single incoming stream.
    async fn handle_stream(&self, peer: PeerId, mut stream: Stream) -> Result<(), StreamError> {
        // Read length-prefixed compressed request with timeout
        let compressed_request = tokio::time::timeout(STREAM_IO_TIMEOUT, async {
            let mut len_bytes = [0u8; 4];
            stream.read_exact(&mut len_bytes).await?;
            let len = u32::from_be_bytes(len_bytes) as usize;

            if len > MAX_REQUEST_SIZE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "request too large",
                ));
            }

            let mut data = vec![0u8; len];
            stream.read_exact(&mut data).await?;
            Ok::<Vec<u8>, std::io::Error>(data)
        })
        .await
        .map_err(|_| StreamError::Timeout)?
        .map_err(StreamError::Io)?;

        // Decompress request
        let request_data = wire::decompress(&compressed_request).map_err(|e| {
            StreamError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("decompression failed: {}", e),
            ))
        })?;

        // Process the request and get response (returns SBOR-encoded bytes)
        let response_sbor = self.process_request(peer, &request_data);

        // Compress response
        let response_data = wire::compress(&response_sbor);

        // Write length-prefixed compressed response with timeout
        tokio::time::timeout(STREAM_IO_TIMEOUT, async {
            let len = response_data.len() as u32;
            stream.write_all(&len.to_be_bytes()).await?;
            stream.write_all(&response_data).await?;
            stream.flush().await?;
            stream.close().await?;
            Ok::<(), std::io::Error>(())
        })
        .await
        .map_err(|_| StreamError::Timeout)?
        .map_err(StreamError::Io)?;

        Ok(())
    }

    /// Process a request and return the response bytes.
    fn process_request(&self, peer: PeerId, payload: &[u8]) -> Vec<u8> {
        // Discriminate request type based on payload structure:
        // 1. Block sync request: exactly 8 bytes (u64 height in little-endian)
        // 2. Transaction/Certificate fetch: SBOR-encoded with fetch_type tag at byte 4

        if payload.len() == 8 {
            // Block sync request (8-byte height)
            self.handle_block_request(peer, payload)
        } else if payload.len() > 8 {
            // SBOR-encoded fetch request - check fetch_type at byte 4
            let fetch_type = payload.get(4).copied();

            match fetch_type {
                Some(FETCH_TYPE_TRANSACTION) => self.handle_transaction_request(peer, payload),
                Some(FETCH_TYPE_CERTIFICATE) => self.handle_certificate_request(peer, payload),
                _ => {
                    warn!(
                        peer = %peer,
                        len = payload.len(),
                        fetch_type = ?fetch_type,
                        "Unknown fetch request type"
                    );
                    vec![]
                }
            }
        } else {
            warn!(
                peer = %peer,
                len = payload.len(),
                "Invalid request (too short)"
            );
            vec![]
        }
    }

    /// Handle a block sync request.
    fn handle_block_request(&self, peer: PeerId, payload: &[u8]) -> Vec<u8> {
        // Decode height from 8 bytes (little-endian u64)
        let height_bytes: [u8; 8] = match payload.try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                warn!(peer = %peer, "Invalid block request (not 8 bytes)");
                return sbor::basic_encode(&None::<(Block, QuorumCertificate)>).unwrap_or_default();
            }
        };
        let height = u64::from_le_bytes(height_bytes);
        let block_height = BlockHeight(height);

        trace!(
            peer = %peer,
            height = height,
            "Handling block sync request"
        );

        // Wire format: Option<(Block, QuorumCertificate)>
        let sync_response: Option<(Block, QuorumCertificate)> =
            self.storage.get_block_for_sync(block_height);

        match sbor::basic_encode(&sync_response) {
            Ok(data) => data,
            Err(e) => {
                warn!(height, error = ?e, "Failed to encode block response");
                sbor::basic_encode(&None::<(Block, QuorumCertificate)>).unwrap_or_default()
            }
        }
    }

    /// Handle a transaction fetch request.
    fn handle_transaction_request(&self, peer: PeerId, payload: &[u8]) -> Vec<u8> {
        // Decode the request
        let tx_request = match sbor::basic_decode::<GetTransactionsRequest>(payload) {
            Ok(req) => req,
            Err(e) => {
                warn!(peer = %peer, error = ?e, "Failed to decode transaction request");
                return sbor::basic_encode(&GetTransactionsResponse::empty()).unwrap_or_default();
            }
        };

        let requested_count = tx_request.tx_hashes.len();
        trace!(
            peer = %peer,
            block_hash = ?tx_request.block_hash,
            tx_count = requested_count,
            "Handling transaction fetch request"
        );

        // Limit the number of hashes to prevent DoS
        let hashes_to_fetch = if requested_count > self.config.max_items_per_response {
            &tx_request.tx_hashes[..self.config.max_items_per_response]
        } else {
            &tx_request.tx_hashes
        };

        // First check the in-memory cache for recently received transactions.
        // This serves transactions that were received via gossip but not yet
        // committed to storage (avoiding redundant RocksDB writes).
        let mut found_transactions = Vec::with_capacity(hashes_to_fetch.len());
        let mut missing_hashes = Vec::new();

        for hash in hashes_to_fetch {
            if let Some(tx) = self.recently_received_txs.get(hash) {
                found_transactions.push(tx);
            } else {
                missing_hashes.push(*hash);
            }
        }

        // Fall back to RocksDB for any not found in cache
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
        let from_cache = hashes_to_fetch.len() - missing_hashes.len();

        debug!(
            block_hash = ?tx_request.block_hash,
            requested = requested_count,
            found = found_count,
            from_cache = from_cache,
            "Responding to transaction fetch request"
        );

        // Encode the response
        let response = GetTransactionsResponse::new(found_transactions);
        match sbor::basic_encode(&response) {
            Ok(data) => {
                crate::metrics::record_fetch_response_sent("transaction", found_count);
                data
            }
            Err(e) => {
                warn!(error = ?e, "Failed to encode transaction response");
                sbor::basic_encode(&GetTransactionsResponse::empty()).unwrap_or_default()
            }
        }
    }

    /// Handle a certificate fetch request.
    fn handle_certificate_request(&self, peer: PeerId, payload: &[u8]) -> Vec<u8> {
        // Decode the request
        let cert_request = match sbor::basic_decode::<GetCertificatesRequest>(payload) {
            Ok(req) => req,
            Err(e) => {
                warn!(peer = %peer, error = ?e, "Failed to decode certificate request");
                return sbor::basic_encode(&GetCertificatesResponse::empty()).unwrap_or_default();
            }
        };

        let requested_count = cert_request.cert_hashes.len();
        trace!(
            peer = %peer,
            block_hash = ?cert_request.block_hash,
            cert_count = requested_count,
            "Handling certificate fetch request"
        );

        // Limit the number of hashes to prevent DoS
        let hashes_to_fetch = if requested_count > self.config.max_items_per_response {
            &cert_request.cert_hashes[..self.config.max_items_per_response]
        } else {
            &cert_request.cert_hashes
        };

        // First check the in-memory cache for recently built certificates
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
        match sbor::basic_encode(&response) {
            Ok(data) => {
                crate::metrics::record_fetch_response_sent("certificate", found_count);
                data
            }
            Err(e) => {
                warn!(error = ?e, "Failed to encode certificate response");
                sbor::basic_encode(&GetCertificatesResponse::empty()).unwrap_or_default()
            }
        }
    }
}

/// Errors that can occur during stream handling.
#[derive(Debug)]
enum StreamError {
    Timeout,
    Io(std::io::Error),
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::Timeout => write!(f, "stream timeout"),
            StreamError::Io(e) => write!(f, "stream I/O error: {}", e),
        }
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
