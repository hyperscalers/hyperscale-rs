//! HTTP RPC server for validator nodes.
//!
//! This module provides the HTTP API for interacting with a validator node.
//! The API is organized into several endpoint groups:
//!
//! # Health & Readiness
//!
//! - `GET /health` - Liveness probe (always returns 200 if server running)
//! - `GET /ready` - Readiness probe (200 if ready for consensus, 503 otherwise)
//!
//! # Metrics & Observability
//!
//! - `GET /metrics` - Prometheus metrics in text format
//! - `GET /api/v1/status` - Node status (validator ID, shard, height, peers)
//! - `GET /api/v1/sync` - Sync status details
//!
//! # Transactions
//!
//! - `POST /api/v1/transactions` - Submit a transaction (returns 202 Accepted)
//! - `GET /api/v1/transactions/:hash` - Get transaction status
//!
//! # Async Transaction Validation
//!
//! Transaction submission uses async validation similar to Ethereum's `eth_sendRawTransaction`:
//! 1. Structural validation (hex decode, SBOR decode) - errors return 400 immediately
//! 2. Submit to shared `ValidationBatcherHandle` for async crypto validation
//! 3. Return 202 Accepted with transaction hash
//! 4. Client polls `GET /api/v1/transactions/{hash}` to check result
//!
//! This provides deduplication and batched parallel validation shared with network gossip.
//!
//! # Example
//!
//! The RPC server is typically created after the `ProductionRunner` to get the shared
//! validation batcher handle:
//!
//! ```ignore
//! // Build runner first to get validation handle
//! let runner = ProductionRunner::builder()
//!     // ... configuration ...
//!     .build()
//!     .await?;
//!
//! // Get validation handle from runner
//! let validation_handle = runner.tx_validation_handle();
//!
//! // Create RPC server with shared validation handle
//! let config = RpcServerConfig {
//!     listen_addr: "0.0.0.0:8080".parse()?,
//!     metrics_enabled: true,
//! };
//! let server = RpcServer::new(config, validation_handle);
//! server.serve().await?;
//! ```

mod handlers;
mod routes;
mod server;
pub(crate) mod state;
mod types;

pub use server::{RpcServer, RpcServerConfig, RpcServerHandle};
pub use state::{MempoolSnapshot, NodeStatusState, RpcState, TransactionStatusCache};
pub use types::*;
