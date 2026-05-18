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
//! mutates them in response to outbound events
//! (`Continuation(FinalizedWavesAdmitted)`, validated transactions, terminal
//! status), and handlers read them on remote-peer requests.

use std::sync::Arc;

use hyperscale_execution::{ExecCertStore, FinalizedWaveStore};
use hyperscale_mempool::TxStore;
use hyperscale_provisions::ProvisionStore;
use hyperscale_types::{FinalizedWave, TransactionStatus, TxHash, WaveId};
use quick_cache::sync::Cache as QuickCache;

/// Default certificate cache capacity.
pub(super) const DEFAULT_CERT_CACHE_SIZE: usize = 10_000;
/// Default transaction status cache capacity.
pub(super) const DEFAULT_TX_STATUS_CACHE_SIZE: usize = 100_000;

/// Inbound request-serving caches plus the cross-thread transaction-status
/// view exposed to external RPC consumers.
pub struct SharedCaches {
    /// Shared transaction body store. Populated by mempool admission;
    /// pruned alongside tombstones when validity windows expire. Queried
    /// by the inbound transaction request handler before falling through
    /// to storage. Owned jointly with [`hyperscale_mempool::MempoolCoordinator`]
    /// — both hold `Arc<TxStore>` pointing at the same map, so the network
    /// worker can read bodies without contending on a mempool lock.
    pub tx_store: Arc<TxStore>,
    /// Latest emitted status per transaction. Survives mempool eviction so
    /// RPC `tx_status` lookups can answer for finalized/expired txs.
    pub tx_status: Arc<QuickCache<TxHash, TransactionStatus>>,
    /// Finalized waves, keyed by `WaveId`. Populated by `io_loop`'s
    /// `Continuation(FinalizedWavesAdmitted)` interception; queried by the
    /// inbound finalized-wave handler.
    pub finalized_wave: Arc<QuickCache<WaveId, Arc<FinalizedWave>>>,
    /// Outbound + local provision store, owned by the
    /// [`ProvisionCoordinator`]. Cloned here so handlers (block, block-topup,
    /// local-provision, cross-shard provision) can read it without going
    /// through the state machine.
    ///
    /// [`ProvisionCoordinator`]: hyperscale_provisions::ProvisionCoordinator
    pub provision_store: Arc<ProvisionStore>,
    /// Aggregated local-shard execution certificates awaiting block commit,
    /// owned by the [`ExecutionCoordinator`]. Cloned here so the inbound EC
    /// fetch handler can serve cross-shard fallback requests without taking
    /// a coordinator lock; on cache miss the handler falls through to
    /// storage.
    ///
    /// [`ExecutionCoordinator`]: hyperscale_execution::ExecutionCoordinator
    pub exec_cert_store: Arc<ExecCertStore>,
    /// Per-shard finalized-wave store, shared with every same-shard
    /// `ExecutionCoordinator`. Read by sync-inventory bloom and
    /// elided-block rehydration so neither has to reach through
    /// `vnodes[0].state` for shard-scoped data.
    pub finalized_wave_store: Arc<FinalizedWaveStore>,
}

impl SharedCaches {
    /// Construct caches at `io_loop` startup. The `ProvisionStore`,
    /// `TxStore`, `ExecCertStore`, and `FinalizedWaveStore` are owned
    /// by their respective state machines; clones are passed in so the
    /// same `Arc`s flow into network handler closures and sync helpers.
    pub fn new(
        provision_store: Arc<ProvisionStore>,
        tx_store: Arc<TxStore>,
        exec_cert_store: Arc<ExecCertStore>,
        finalized_wave_store: Arc<FinalizedWaveStore>,
    ) -> Self {
        Self {
            tx_store,
            tx_status: Arc::new(QuickCache::new(DEFAULT_TX_STATUS_CACHE_SIZE)),
            finalized_wave: Arc::new(QuickCache::new(DEFAULT_CERT_CACHE_SIZE)),
            provision_store,
            exec_cert_store,
            finalized_wave_store,
        }
    }
}
