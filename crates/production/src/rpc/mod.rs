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
//! - `POST /api/v1/transactions` - Submit a transaction
//! - `GET /api/v1/transactions/:hash` - Get transaction status
//!
//! # Example
//!
//! ```no_run
//! use hyperscale_production::rpc::{RpcServer, RpcServerConfig};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let config = RpcServerConfig {
//!     listen_addr: "0.0.0.0:8080".parse()?,
//!     metrics_enabled: true,
//! };
//!
//! // Create server with transaction submission channel
//! let (tx_sender, tx_receiver) = tokio::sync::mpsc::channel(1000);
//! let server = RpcServer::new(config, tx_sender);
//!
//! // Start serving
//! server.serve().await?;
//! # Ok(())
//! # }
//! ```

mod handlers;
mod routes;
mod server;
mod types;

pub use handlers::NodeStatusState;
pub use server::{RpcServer, RpcServerConfig, RpcServerHandle};
pub use types::*;
