//! RPC client for submitting transactions to Hyperscale nodes.

mod types;

use std::time::Duration;

use hex::encode as hex_encode;
use hyperscale_hbor::to_vec as hbor_to_vec;
use hyperscale_types::Transaction;
use reqwest::{Client, Error as ReqwestError};
pub use types::*;

/// Client for submitting transactions via RPC.
pub struct RpcClient {
    base_url: String,
    client: Client,
}

impl RpcClient {
    /// Create a new RPC client.
    ///
    /// # Panics
    ///
    /// Panics if the underlying `reqwest::Client` fails to build (unreachable
    /// for a default-feature build).
    pub fn new(base_url: impl Into<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            base_url: base_url.into(),
            client,
        }
    }

    /// Submit a transaction to the node.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::EncodingFailed`] if HBOR encoding fails, or
    /// [`RpcError::Http`] for any HTTP-level failure.
    pub async fn submit_transaction(&self, tx: &Transaction) -> Result<SubmissionResult, RpcError> {
        let tx_bytes = hbor_to_vec(tx).map_err(|e| RpcError::EncodingFailed(format!("{e:?}")))?;
        let tx_hex = hex_encode(tx_bytes);

        let request = SubmitTransactionRequest {
            transaction_hex: tx_hex,
        };

        let response = self
            .client
            .post(format!("{}/api/v1/transactions", self.base_url))
            .json(&request)
            .send()
            .await
            .map_err(RpcError::Http)?;

        let status = response.status();
        let body: SubmitTransactionResponse = response.json().await.map_err(RpcError::Http)?;

        Ok(SubmissionResult {
            accepted: body.accepted,
            hash: body.hash,
            error: body.error,
            status_code: status.as_u16(),
        })
    }

    /// Get node status.
    ///
    /// Collapses the per-vnode entries into a process-level summary. Reports
    /// the minimum committed height across hosted vnodes so a multi-vnode
    /// host that's only producing for one of its shards still looks "behind"
    /// to consumers polling for readiness.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Http`] for any HTTP-level failure.
    pub async fn get_status(&self) -> Result<NodeStatus, RpcError> {
        let response = self
            .client
            .get(format!("{}/api/v1/status", self.base_url))
            .send()
            .await
            .map_err(RpcError::Http)?;

        let status: NodeStatusResponse = response.json().await.map_err(RpcError::Http)?;

        let min_block_height = status
            .vnodes
            .iter()
            .map(|v| v.block_height)
            .min()
            .unwrap_or(0);

        Ok(NodeStatus {
            connected_peers: status.connected_peers,
            vnode_count: status.vnodes.len(),
            min_block_height,
        })
    }

    /// Check if node is ready to accept transactions.
    pub async fn is_ready(&self) -> bool {
        let response = self
            .client
            .get(format!("{}/ready", self.base_url))
            .send()
            .await;

        matches!(response, Ok(r) if r.status().is_success())
    }

    /// Get transaction status by hash.
    ///
    /// Returns the current status of a transaction, or an error if the
    /// transaction is not found or the request fails.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::TransactionNotFound`] if the node responds with
    /// HTTP 404, or [`RpcError::Http`] for any other HTTP-level failure.
    pub async fn get_transaction_status(
        &self,
        tx_hash: &str,
    ) -> Result<TransactionStatusResponse, RpcError> {
        let response = self
            .client
            .get(format!("{}/api/v1/transactions/{}", self.base_url, tx_hash))
            .send()
            .await
            .map_err(RpcError::Http)?;

        let status = response.status();
        let body: TransactionStatusResponse = response.json().await.map_err(RpcError::Http)?;

        // If the response indicates an error at the HTTP level, convert to RpcError
        if status.as_u16() == 404 {
            return Err(RpcError::TransactionNotFound(tx_hash.to_string()));
        }

        Ok(body)
    }

    /// Get the base URL of this client.
    #[must_use]
    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }
}

/// RPC errors.
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    /// Underlying `reqwest` HTTP failure.
    #[error("HTTP error: {0}")]
    Http(#[from] ReqwestError),

    /// HBOR encoding of the outgoing transaction failed.
    #[error("Failed to encode transaction: {0}")]
    EncodingFailed(String),

    /// The node refused the transaction (e.g. invalid format, backpressure).
    #[error("Transaction rejected: {0}")]
    Rejected(String),

    /// The node could not be reached (e.g. timeout, refused connection).
    #[error("Node unavailable")]
    Unavailable,

    /// The node returned HTTP 404 for the requested transaction hash.
    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),
}
