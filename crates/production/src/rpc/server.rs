//! RPC server implementation.

use super::routes::create_router;
use super::state::{MempoolSnapshot, NodeStatusState, RpcState, TxSubmissionSender};
use crate::status::SyncStatus;
use arc_swap::ArcSwap;
use hyperscale_core::TransactionStatus;
use hyperscale_types::Hash;
use quick_cache::sync::Cache as QuickCache;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use tokio::sync::RwLock;
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
    /// Sync status provider for updates.
    sync_status: Arc<ArcSwap<SyncStatus>>,
    /// Node status provider for updates.
    node_status: Arc<RwLock<NodeStatusState>>,
    /// Transaction status cache (shared from NodeLoop's QuickCache).
    tx_status_cache: Arc<QuickCache<Hash, TransactionStatus>>,
    /// Mempool snapshot for updates.
    mempool_snapshot: Arc<RwLock<MempoolSnapshot>>,
}

impl RpcServerHandle {
    /// Mark the node as ready (for readiness probe).
    pub fn set_ready(&self, ready: bool) {
        self.ready_flag.store(ready, Ordering::SeqCst);
    }

    /// Get a reference to the sync status for updates.
    pub fn sync_status(&self) -> &Arc<ArcSwap<SyncStatus>> {
        &self.sync_status
    }

    /// Get a reference to the node status for updates.
    pub fn node_status(&self) -> &Arc<RwLock<NodeStatusState>> {
        &self.node_status
    }

    /// Get a reference to the transaction status cache.
    pub fn tx_status_cache(&self) -> &Arc<QuickCache<Hash, TransactionStatus>> {
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
    /// * `tx_submission_tx` - Crossbeam channel to submit transactions directly to NodeLoop
    /// * `tx_status_cache` - Transaction status cache shared from NodeLoop
    pub fn new(
        config: RpcServerConfig,
        tx_submission_tx: TxSubmissionSender,
        tx_status_cache: Arc<QuickCache<Hash, TransactionStatus>>,
    ) -> Self {
        let sync_backpressure_threshold = config.sync_backpressure_threshold;
        let state = RpcState {
            ready: Arc::new(AtomicBool::new(false)),
            sync_status: Arc::new(ArcSwap::new(Arc::new(SyncStatus::default()))),
            node_status: Arc::new(RwLock::new(NodeStatusState::default())),
            tx_submission_tx,
            start_time: Instant::now(),
            tx_status_cache,
            mempool_snapshot: Arc::new(RwLock::new(MempoolSnapshot::default())),
            sync_backpressure_threshold,
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
        sync_status: Arc<ArcSwap<SyncStatus>>,
        node_status: Arc<RwLock<NodeStatusState>>,
        tx_submission_tx: TxSubmissionSender,
        tx_status_cache: Arc<QuickCache<Hash, TransactionStatus>>,
        mempool_snapshot: Arc<RwLock<MempoolSnapshot>>,
    ) -> Self {
        let sync_backpressure_threshold = config.sync_backpressure_threshold;
        let state = RpcState {
            ready,
            sync_status,
            node_status,
            tx_submission_tx,
            start_time: Instant::now(),
            tx_status_cache,
            mempool_snapshot,
            sync_backpressure_threshold,
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
        let (tx_submission_tx, _rx) = crossbeam::channel::unbounded();
        let tx_status_cache = Arc::new(QuickCache::new(1000));
        let server = RpcServer::new(config, tx_submission_tx, tx_status_cache);

        // Server should be created successfully
        assert!(!server.state.ready.load(Ordering::SeqCst));
    }
}
