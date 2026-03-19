//! RPC client for submitting transactions to Hyperscale nodes.

use hyperscale_codec as sbor;

mod types;

pub use types::*;

use hyperscale_types::RoutableTransaction;
use reqwest::Client;
use std::time::Duration;

/// Client for submitting transactions via RPC.
pub struct RpcClient {
    base_url: String,
    client: Client,
}

impl RpcClient {
    /// Create a new RPC client.
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
    pub async fn submit_transaction(
        &self,
        tx: &RoutableTransaction,
    ) -> Result<SubmissionResult, RpcError> {
        // Encode transaction as SBOR
        let tx_bytes = sbor::prelude::basic_encode(tx)
            .map_err(|e| RpcError::EncodingFailed(format!("{:?}", e)))?;

        // Convert to hex
        let tx_hex = hex::encode(tx_bytes);

        // Build request
        let request = SubmitTransactionRequest {
            transaction_hex: tx_hex,
        };

        // Send request
        let response = self
            .client
            .post(format!("{}/api/v1/transactions", self.base_url))
            .json(&request)
            .send()
            .await
            .map_err(RpcError::Http)?;

        let status = response.status();

        // Parse response
        let body: SubmitTransactionResponse = response.json().await.map_err(RpcError::Http)?;

        Ok(SubmissionResult {
            accepted: body.accepted,
            hash: body.hash,
            error: body.error,
            status_code: status.as_u16(),
        })
    }

    /// Get node status.
    pub async fn get_status(&self) -> Result<NodeStatus, RpcError> {
        let response = self
            .client
            .get(format!("{}/api/v1/status", self.base_url))
            .send()
            .await
            .map_err(RpcError::Http)?;

        let status: NodeStatusResponse = response.json().await.map_err(RpcError::Http)?;

        Ok(NodeStatus {
            validator_id: status.validator_id,
            shard: status.shard,
            block_height: status.block_height,
            connected_peers: status.connected_peers,
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
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

/// RPC errors.
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Failed to encode transaction: {0}")]
    EncodingFailed(String),

    #[error("Transaction rejected: {0}")]
    Rejected(String),

    #[error("Node unavailable")]
    Unavailable,

    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),
}
