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
//! Transaction submission performs structural validation (hex + SBOR decode)
//! synchronously and returns 400 on failure. Valid submissions are forwarded
//! into the consensus thread via the same dispatch pool that handles network
//! gossip, so signature verification and admission run on the configurable
//! `tx_validation_threads` worker pool. Clients receive 202 Accepted plus
//! the transaction hash and poll `GET /api/v1/transactions/{hash}` for the
//! verification outcome.

mod handlers;
mod routes;
mod server;
pub(crate) mod state;
mod types;

pub use server::{RpcServer, RpcServerConfig, RpcServerHandle};
pub use state::{
    MempoolSnapshot, NodeStatusState, RpcState, TxSubmissionSender, VnodeMempoolStats,
    VnodeStatusEntry,
};
pub use types::*;
