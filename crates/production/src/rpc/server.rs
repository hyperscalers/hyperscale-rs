//! RPC server implementation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use axum::serve;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::task::{JoinError, JoinHandle, spawn};
use tracing::{error, info};

use super::routes::create_router;
use super::state::RpcState;
use crate::handle::NodeHandle;

/// Errors from the RPC server.
#[derive(Debug, Error)]
pub enum RpcServerError {
    /// The server could not bind to the configured listen address.
    #[error("Failed to bind to address: {0}")]
    BindError(#[from] std::io::Error),
}

/// Configuration for the RPC server.
#[derive(Debug, Clone)]
pub struct RpcServerConfig {
    /// Address to listen on.
    pub listen_addr: SocketAddr,
    /// Enable metrics endpoint.
    pub metrics_enabled: bool,
    /// Number of blocks behind before rejecting transaction submissions.
    ///
    /// When the node is syncing and falls this many blocks behind, new transaction
    /// submissions are rejected with 503. This prevents a syncing node from getting
    /// further behind by processing new transactions instead of catching up.
    ///
    /// Set to `None` to disable sync-based backpressure.
    /// Default: 10 blocks
    pub sync_backpressure_threshold: Option<u64>,
}

impl Default for RpcServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 8080)),
            metrics_enabled: true,
            sync_backpressure_threshold: Some(10),
        }
    }
}

/// Handle for controlling a running RPC server.
pub struct RpcServerHandle {
    /// Task handle for the server.
    task: JoinHandle<()>,
    /// Ready flag to set when node is ready.
    ready_flag: Arc<AtomicBool>,
}

impl RpcServerHandle {
    /// Mark the node as ready (for readiness probe).
    pub fn set_ready(&self, ready: bool) {
        self.ready_flag.store(ready, Ordering::SeqCst);
    }

    /// Abort the server.
    pub fn abort(&self) {
        self.task.abort();
    }

    /// Wait for the server to finish.
    ///
    /// # Errors
    ///
    /// Returns the underlying `JoinError` if the server task panicked or was cancelled.
    pub async fn join(self) -> Result<(), JoinError> {
        self.task.await
    }
}

/// RPC server for validator nodes.
pub struct RpcServer {
    config: RpcServerConfig,
    state: RpcState,
}

impl RpcServer {
    /// A server answering for the host behind `node`, readiness read from
    /// `ready`. Once the host stops, its reads answer empty and its
    /// submissions and previews are refused.
    #[must_use]
    pub fn for_node(config: RpcServerConfig, node: &NodeHandle, ready: Arc<AtomicBool>) -> Self {
        let state = RpcState {
            ready,
            node: node.clone(),
            start_time: Instant::now(),
            sync_backpressure_threshold: config.sync_backpressure_threshold,
        };
        Self { config, state }
    }

    /// Start the server and return a handle for control.
    ///
    /// # Errors
    ///
    /// Returns [`RpcServerError::BindError`] if the listener cannot bind to
    /// the configured address.
    pub async fn start(self) -> Result<RpcServerHandle, RpcServerError> {
        let addr = self.config.listen_addr;
        let ready_flag = self.state.ready.clone();

        let router = create_router(self.state);

        let listener = TcpListener::bind(addr).await?;
        info!(addr = %addr, "RPC server listening");

        let task = spawn(async move {
            if let Err(e) = serve(listener, router).await {
                error!(error = ?e, "RPC server error");
            }
        });

        Ok(RpcServerHandle { task, ready_flag })
    }

    /// Start and serve until shutdown (convenience method).
    ///
    /// # Errors
    ///
    /// Returns [`RpcServerError::BindError`] if the listener cannot bind. Errors
    /// from the spawned server task itself are logged and discarded.
    pub async fn serve(self) -> Result<(), RpcServerError> {
        let handle = self.start().await?;
        let _ = handle.join().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RpcServerConfig::default();
        assert_eq!(config.listen_addr.port(), 8080);
        assert!(config.metrics_enabled);
    }
}
