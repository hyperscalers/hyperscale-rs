//! Generic inbound request handler.
//!
//! Processes sync/fetch requests using `ConsensusStore` trait methods.
//! Transport-specific I/O (libp2p streams, metrics) stays in the transport crate.

use hyperscale_messages::request::{
    GetCertificatesRequest, GetTransactionsRequest, FETCH_TYPE_CERTIFICATE, FETCH_TYPE_TRANSACTION,
};
use hyperscale_messages::response::{GetCertificatesResponse, GetTransactionsResponse};
use hyperscale_metrics as metrics;
use hyperscale_storage::ConsensusStore;
use hyperscale_types::{
    Block, BlockHeight, Hash, QuorumCertificate, RoutableTransaction, TransactionCertificate,
};
use quick_cache::sync::Cache as QuickCache;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, trace, warn};

/// Errors from inbound request processing.
#[derive(Debug, Error)]
pub enum InboundError {
    #[error("Request too short ({len} bytes)")]
    TooShort { len: usize },

    #[error("Unknown fetch type: {0}")]
    UnknownFetchType(u8),

    #[error("SBOR decode error: {0}")]
    DecodeError(String),

    #[error("SBOR encode error: {0}")]
    EncodeError(String),
}

/// Configuration for the inbound handler.
#[derive(Debug, Clone)]
pub struct InboundHandlerConfig {
    /// Maximum number of items to return in a single fetch response.
    pub max_items_per_response: usize,
}

impl Default for InboundHandlerConfig {
    fn default() -> Self {
        Self {
            max_items_per_response: 500,
        }
    }
}

/// Generic inbound request handler, parameterized over storage.
///
/// Handles block sync, transaction fetch, and certificate fetch requests.
/// Transport-specific I/O (stream framing, compression, metrics) is handled
/// by the caller in the transport crate.
pub struct InboundHandler<S: ConsensusStore> {
    config: InboundHandlerConfig,
    storage: Arc<S>,
    /// Cache for recently received transactions (not yet committed to storage).
    recently_received_txs: Arc<QuickCache<Hash, Arc<RoutableTransaction>>>,
    /// Cache for recently built certificates (not yet persisted to storage).
    recently_built_certs: Arc<QuickCache<Hash, Arc<TransactionCertificate>>>,
}

impl<S: ConsensusStore> InboundHandler<S> {
    /// Create a new inbound handler.
    pub fn new(
        config: InboundHandlerConfig,
        storage: Arc<S>,
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

    /// Process a request payload and return SBOR-encoded response bytes.
    ///
    /// Request discrimination:
    /// - 8 bytes: block sync request (little-endian u64 height)
    /// - >8 bytes with fetch_type at byte 4: transaction or certificate fetch
    pub fn process_request(&self, payload: &[u8]) -> Result<Vec<u8>, InboundError> {
        if payload.len() == 8 {
            Ok(self.handle_block_request(payload))
        } else if payload.len() > 8 {
            let fetch_type = payload[4];
            match fetch_type {
                FETCH_TYPE_TRANSACTION => Ok(self.handle_transaction_request(payload)),
                FETCH_TYPE_CERTIFICATE => Ok(self.handle_certificate_request(payload)),
                other => Err(InboundError::UnknownFetchType(other)),
            }
        } else {
            Err(InboundError::TooShort { len: payload.len() })
        }
    }

    /// Handle a block sync request.
    fn handle_block_request(&self, payload: &[u8]) -> Vec<u8> {
        let height_bytes: [u8; 8] = match payload.try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                return sbor::basic_encode(&None::<(Block, QuorumCertificate)>).unwrap_or_default();
            }
        };
        let height = u64::from_le_bytes(height_bytes);
        let block_height = BlockHeight(height);

        trace!(height, "Handling block sync request");

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
    fn handle_transaction_request(&self, payload: &[u8]) -> Vec<u8> {
        let tx_request = match sbor::basic_decode::<GetTransactionsRequest>(payload) {
            Ok(req) => req,
            Err(e) => {
                warn!(error = ?e, "Failed to decode transaction request");
                return sbor::basic_encode(&GetTransactionsResponse::empty()).unwrap_or_default();
            }
        };

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

        let response = GetTransactionsResponse::new(found_transactions);
        sbor::basic_encode(&response).unwrap_or_default()
    }

    /// Handle a certificate fetch request.
    fn handle_certificate_request(&self, payload: &[u8]) -> Vec<u8> {
        let cert_request = match sbor::basic_decode::<GetCertificatesRequest>(payload) {
            Ok(req) => req,
            Err(e) => {
                warn!(error = ?e, "Failed to decode certificate request");
                return sbor::basic_encode(&GetCertificatesResponse::empty()).unwrap_or_default();
            }
        };

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

        let response = GetCertificatesResponse::new(found_certificates);
        sbor::basic_encode(&response).unwrap_or_default()
    }
}
