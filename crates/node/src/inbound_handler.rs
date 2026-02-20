//! Inbound request handler for block sync and data fetch.
//!
//! Processes incoming request-response payloads using `ConsensusStore` trait methods.
//! Transport-specific I/O (libp2p streams, framing, compression) stays in the
//! transport crate (`network-libp2p`). This module implements
//! [`InboundRequestHandler`] so it can be plugged into any transport's inbound router.
//!
//! # Wire Format
//!
//! Requests arrive as: `[type_id_len: u16 LE][type_id: UTF-8][SBOR payload]`
//!
//! The `type_id` string dispatches to the appropriate handler:
//! - `"block.request"` — block sync (SBOR-encoded `GetBlockRequest`)
//! - `"transaction.request"` — transaction fetch (SBOR-encoded `GetTransactionsRequest`)
//! - `"certificate.request"` — certificate fetch (SBOR-encoded `GetCertificatesRequest`)

use hyperscale_messages::request::{
    GetBlockRequest, GetCertificatesRequest, GetTransactionsRequest,
};
use hyperscale_messages::response::{GetCertificatesResponse, GetTransactionsResponse};
use hyperscale_metrics as metrics;
use hyperscale_network::{parse_request_frame, InboundRequestHandler};
use hyperscale_storage::ConsensusStore;
use hyperscale_types::{
    Block, Hash, QuorumCertificate, RoutableTransaction, TransactionCertificate,
};
use quick_cache::sync::Cache as QuickCache;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, trace};

/// Errors from inbound request processing.
#[derive(Debug, Error)]
pub enum InboundError {
    #[error("Request frame error: {0}")]
    FrameError(String),

    #[error("Unknown request type: {0}")]
    UnknownRequestType(String),

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

/// Inbound request handler, parameterized over storage.
///
/// Handles block sync, transaction fetch, and certificate fetch requests.
/// Transport-specific I/O (stream framing, compression, metrics) is handled
/// by the transport layer's inbound router.
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

    /// Process a framed request payload and return SBOR-encoded response bytes.
    ///
    /// Parses the type_id framing, dispatches to the appropriate handler based
    /// on the type_id string.
    pub fn process_request(&self, payload: &[u8]) -> Result<Vec<u8>, InboundError> {
        let (type_id, sbor_payload) =
            parse_request_frame(payload).map_err(|e| InboundError::FrameError(e.to_string()))?;

        match type_id {
            "block.request" => self.handle_block_request(sbor_payload),
            "transaction.request" => self.handle_transaction_request(sbor_payload),
            "certificate.request" => self.handle_certificate_request(sbor_payload),
            _ => Err(InboundError::UnknownRequestType(type_id.to_string())),
        }
    }

    /// Handle a block sync request.
    fn handle_block_request(&self, sbor_payload: &[u8]) -> Result<Vec<u8>, InboundError> {
        let req: GetBlockRequest = sbor::basic_decode(sbor_payload)
            .map_err(|e| InboundError::DecodeError(format!("{e:?}")))?;

        trace!(height = req.height.0, "Handling block sync request");

        let sync_response: Option<(Block, QuorumCertificate)> =
            self.storage.get_block_for_sync(req.height);

        sbor::basic_encode(&sync_response).map_err(|e| InboundError::EncodeError(format!("{e:?}")))
    }

    /// Handle a transaction fetch request.
    fn handle_transaction_request(&self, sbor_payload: &[u8]) -> Result<Vec<u8>, InboundError> {
        let tx_request: GetTransactionsRequest = sbor::basic_decode(sbor_payload)
            .map_err(|e| InboundError::DecodeError(format!("{e:?}")))?;

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
        sbor::basic_encode(&response).map_err(|e| InboundError::EncodeError(format!("{e:?}")))
    }

    /// Handle a certificate fetch request.
    fn handle_certificate_request(&self, sbor_payload: &[u8]) -> Result<Vec<u8>, InboundError> {
        let cert_request: GetCertificatesRequest = sbor::basic_decode(sbor_payload)
            .map_err(|e| InboundError::DecodeError(format!("{e:?}")))?;

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
        sbor::basic_encode(&response).map_err(|e| InboundError::EncodeError(format!("{e:?}")))
    }
}

impl<S: ConsensusStore + 'static> InboundRequestHandler for InboundHandler<S> {
    fn handle_request(&self, payload: &[u8]) -> Vec<u8> {
        match self.process_request(payload) {
            Ok(data) => data,
            Err(e) => {
                debug!(error = %e, "Inbound request processing failed");
                vec![]
            }
        }
    }
}
