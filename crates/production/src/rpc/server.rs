//! RPC server implementation.

use super::routes::create_router;
use super::state::{MempoolSnapshot, NodeStatusState, RpcState, TransactionStatusCache};
use crate::sync::SyncStatus;
use hyperscale_types::RoutableTransaction;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tracing::{error, info};

/// Errors from the RPC server.
#[derive(Debug, Error)]
pub enum RpcServerError {
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
}

impl Default for RpcServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 8080)),
            metrics_enabled: true,
        }
    }
}

/// Handle for controlling a running RPC server.
pub struct RpcServerHandle {
    /// Task handle for the server.
    task: JoinHandle<()>,
    /// Ready flag to set when node is ready.
    ready_flag: Arc<AtomicBool>,
    /// Sync status provider for updates.
    sync_status: Arc<RwLock<SyncStatus>>,
    /// Node status provider for updates.
    node_status: Arc<RwLock<NodeStatusState>>,
    /// Transaction status cache for updates.
    tx_status_cache: Arc<RwLock<TransactionStatusCache>>,
    /// Mempool snapshot for updates.
    mempool_snapshot: Arc<RwLock<MempoolSnapshot>>,
}

impl RpcServerHandle {
    /// Mark the node as ready (for readiness probe).
    pub fn set_ready(&self, ready: bool) {
        self.ready_flag.store(ready, Ordering::SeqCst);
    }

    /// Get a reference to the sync status for updates.
    pub fn sync_status(&self) -> &Arc<RwLock<SyncStatus>> {
        &self.sync_status
    }

    /// Get a reference to the node status for updates.
    pub fn node_status(&self) -> &Arc<RwLock<NodeStatusState>> {
        &self.node_status
    }

    /// Get a reference to the transaction status cache for updates.
    pub fn tx_status_cache(&self) -> &Arc<RwLock<TransactionStatusCache>> {
        &self.tx_status_cache
    }

    /// Get a reference to the mempool snapshot for updates.
    pub fn mempool_snapshot(&self) -> &Arc<RwLock<MempoolSnapshot>> {
        &self.mempool_snapshot
    }

    /// Abort the server.
    pub fn abort(&self) {
        self.task.abort();
    }

    /// Wait for the server to finish.
    pub async fn join(self) -> Result<(), tokio::task::JoinError> {
        self.task.await
    }
}

/// RPC server for validator nodes.
pub struct RpcServer {
    config: RpcServerConfig,
    state: RpcState,
}

impl RpcServer {
    /// Create a new RPC server.
    ///
    /// # Arguments
    ///
    /// * `config` - Server configuration
    /// * `tx_submission_tx` - Channel to submit transactions to the runner for validation and gossip
    pub fn new(
        config: RpcServerConfig,
        tx_submission_tx: mpsc::UnboundedSender<Arc<RoutableTransaction>>,
    ) -> Self {
        let state = RpcState {
            ready: Arc::new(AtomicBool::new(false)),
            sync_status: Arc::new(RwLock::new(SyncStatus::default())),
            node_status: Arc::new(RwLock::new(NodeStatusState::default())),
            tx_submission_tx,
            start_time: Instant::now(),
            tx_status_cache: Arc::new(RwLock::new(TransactionStatusCache::new())),
            mempool_snapshot: Arc::new(RwLock::new(MempoolSnapshot::default())),
            tx_ingress: None,
        };

        Self { config, state }
    }

    /// Create a new RPC server with pre-configured state.
    ///
    /// This allows sharing state between the server and other components.
    #[allow(clippy::too_many_arguments)]
    pub fn with_state(
        config: RpcServerConfig,
        ready: Arc<AtomicBool>,
        sync_status: Arc<RwLock<SyncStatus>>,
        node_status: Arc<RwLock<NodeStatusState>>,
        tx_submission_tx: mpsc::UnboundedSender<Arc<RoutableTransaction>>,
        tx_status_cache: Arc<RwLock<TransactionStatusCache>>,
        mempool_snapshot: Arc<RwLock<MempoolSnapshot>>,
    ) -> Self {
        let state = RpcState {
            ready,
            sync_status,
            node_status,
            tx_submission_tx,
            start_time: Instant::now(),
            tx_status_cache,
            mempool_snapshot,
            tx_ingress: None,
        };

        Self { config, state }
    }

    /// Start the server and return a handle for control.
    pub async fn start(self) -> Result<RpcServerHandle, RpcServerError> {
        let addr = self.config.listen_addr;
        let ready_flag = self.state.ready.clone();
        let sync_status = self.state.sync_status.clone();
        let node_status = self.state.node_status.clone();
        let tx_status_cache = self.state.tx_status_cache.clone();
        let mempool_snapshot = self.state.mempool_snapshot.clone();

        let router = create_router(self.state);

        let listener = tokio::net::TcpListener::bind(addr).await?;
        info!(addr = %addr, "RPC server listening");

        let task = tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router).await {
                error!(error = ?e, "RPC server error");
            }
        });

        Ok(RpcServerHandle {
            task,
            ready_flag,
            sync_status,
            node_status,
            tx_status_cache,
            mempool_snapshot,
        })
    }

    /// Start and serve until shutdown (convenience method).
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

    #[tokio::test]
    async fn test_server_creation() {
        let config = RpcServerConfig::default();
        let (tx_submission_tx, _rx) = mpsc::unbounded_channel();
        let server = RpcServer::new(config, tx_submission_tx);

        // Server should be created successfully
        assert!(!server.state.ready.load(Ordering::SeqCst));
    }
}
