//! Inbound request-serving caches.
//!
//! [`SharedCaches`] groups the in-memory caches that back peer-facing
//! request handlers (transaction, finalized-wave, execution-cert,
//! provision) plus the cross-thread transaction-status view used by
//! external RPC consumers. Each field is `Arc`-shared, so the same
//! handles flow into the network handler closures (registered once at
//! genesis) and into RPC state.
//!
//! The caches are independent of the consensus state machine; the `io_loop`
//! mutates them in response to outbound events (`TrackExecutionCertificate`,
//! `Continuation(FinalizedWavesAdmitted)`, validated transactions, terminal
//! status), and handlers read them on remote-peer requests.

use hyperscale_provisions::ProvisionStore;
use hyperscale_types::{
    ExecutionCertificate, FinalizedWave, RoutableTransaction, TransactionStatus, TxHash, WaveId,
    WaveIdHash,
};
use quick_cache::sync::Cache as QuickCache;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Default certificate cache capacity.
pub(super) const DEFAULT_CERT_CACHE_SIZE: usize = 10_000;
/// Default transaction cache capacity.
pub(super) const DEFAULT_TX_CACHE_SIZE: usize = 50_000;
/// Default transaction status cache capacity.
pub(super) const DEFAULT_TX_STATUS_CACHE_SIZE: usize = 100_000;

/// Execution certificate cache shared between the `io_loop` (which inserts
/// on `TrackExecutionCertificate`) and the inbound EC fetch handler.
pub type ExecCertCache = Arc<Mutex<HashMap<(WaveIdHash, WaveId), Arc<ExecutionCertificate>>>>;

/// Inbound request-serving caches plus the cross-thread transaction-status
/// view exposed to external RPC consumers.
pub struct SharedCaches {
    /// Validated transactions, keyed by hash. Populated when the validation
    /// pipeline accepts a tx; queried by the inbound transaction request
    /// handler before falling through to `RocksDB`.
    pub tx: Arc<QuickCache<TxHash, Arc<RoutableTransaction>>>,
    /// Latest emitted status per transaction. Survives mempool eviction so
    /// RPC `tx_status` lookups can answer for finalized/expired txs.
    pub tx_status: Arc<QuickCache<TxHash, TransactionStatus>>,
    /// Finalized waves, keyed by wave-id hash. Populated by `io_loop`'s
    /// `Continuation(FinalizedWavesAdmitted)` interception; queried by the
    /// inbound finalized-wave handler.
    pub finalized_wave: Arc<QuickCache<WaveIdHash, Arc<FinalizedWave>>>,
    /// Outbound + local provision store, owned by the
    /// [`ProvisionCoordinator`]. Cloned here so handlers (block, block-topup,
    /// local-provision, cross-shard provision) can read it without going
    /// through the state machine.
    ///
    /// [`ProvisionCoordinator`]: hyperscale_provisions::ProvisionCoordinator
    pub provision_store: Arc<ProvisionStore>,
    /// Execution certificates seen recently, for fallback serving when a
    /// remote shard fetches an EC we already aggregated. Pruned tier-wise
    /// in the `TrackExecutionCertificate` action handler.
    pub exec_cert: ExecCertCache,
}

impl SharedCaches {
    /// Construct caches at `io_loop` startup. The `ProvisionStore` is
    /// produced by the provision coordinator and cloned in.
    pub fn new(provision_store: Arc<ProvisionStore>) -> Self {
        Self {
            tx: Arc::new(QuickCache::new(DEFAULT_TX_CACHE_SIZE)),
            tx_status: Arc::new(QuickCache::new(DEFAULT_TX_STATUS_CACHE_SIZE)),
            finalized_wave: Arc::new(QuickCache::new(DEFAULT_CERT_CACHE_SIZE)),
            provision_store,
            exec_cert: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
