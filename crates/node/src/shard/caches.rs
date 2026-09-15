//! Inbound request-serving caches.
//!
//! [`SharedCaches`] groups the in-memory caches that back peer-facing
//! request handlers (transaction, finalization, execution-cert,
//! provision) plus the cross-thread transaction-status view used by
//! external RPC consumers. Each field is `Arc`-shared, so the same
//! handles flow into the network handler closures (registered once at
//! genesis) and into RPC state.
//!
//! The caches are independent of the consensus state machine; the `io_loop`
//! mutates them in response to outbound events
//! (`Continuation(FinalizationsAdmitted)`, validated transactions, terminal
//! status), and handlers read them on remote-peer requests.

use std::sync::Arc;

use hyperscale_execution::{ExecCertStore, FinalizationStore};
use hyperscale_mempool::TxStore;
use hyperscale_provisions::{ProvisionStore, VerifiedHeaderBuffer};
use hyperscale_types::{Finalization, FinalizationHash, ProvenCells, Verifiable};
use quick_cache::sync::Cache as QuickCache;

/// Default certificate cache capacity.
pub(super) const DEFAULT_CERT_CACHE_SIZE: usize = 10_000;

/// Inbound request-serving caches.
pub struct SharedCaches {
    /// Shared transaction body store. Populated by mempool admission;
    /// pruned alongside tombstones when validity windows expire. Queried
    /// by the inbound transaction request handler before falling through
    /// to storage. Owned jointly with [`hyperscale_mempool::MempoolCoordinator`]
    /// — both hold `Arc<TxStore>` pointing at the same map, so the network
    /// worker can read bodies without contending on a mempool lock.
    pub(crate) tx_store: Arc<TxStore>,
    /// Finalizations, keyed by `TickId`. Populated by `io_loop`'s
    /// `Continuation(FinalizationsAdmitted)` interception; queried by the
    /// inbound finalization handler.
    pub(crate) finalization: Arc<QuickCache<FinalizationHash, Arc<Verifiable<Finalization>>>>,
    /// Outbound + local provision store, owned by the
    /// [`ProvisionCoordinator`]. Cloned here so handlers (block, block-topup,
    /// local-provision, cross-shard provision) can read it without going
    /// through the state machine.
    ///
    /// [`ProvisionCoordinator`]: hyperscale_provisions::ProvisionCoordinator
    pub(crate) provision_store: Arc<ProvisionStore>,
    /// Verified source-shard headers, owned by the
    /// [`ProvisionCoordinator`]. The `local_provision.request` handler
    /// reads this to bundle each returned provision with its matching
    /// source header — the receiver can then admit both without buffering
    /// for a header that's still in flight.
    ///
    /// [`ProvisionCoordinator`]: hyperscale_provisions::ProvisionCoordinator
    pub(crate) verified_headers: Arc<VerifiedHeaderBuffer>,
    /// Aggregated local-shard execution certificates awaiting block commit,
    /// owned by the [`ExecutionCoordinator`]. Cloned here so the inbound EC
    /// fetch handler can serve cross-shard fallback requests without taking
    /// a coordinator lock; on cache miss the handler falls through to
    /// storage.
    ///
    /// [`ExecutionCoordinator`]: hyperscale_execution::ExecutionCoordinator
    pub(crate) exec_cert_store: Arc<ExecCertStore>,
    /// Per-shard finalization store, shared with every same-shard
    /// `ExecutionCoordinator`.
    pub(crate) finalization_store: Arc<FinalizationStore>,
    /// The counterpart cells this node has proven, owned by the
    /// `ShardCoordinator` and filled by the `ExecutionCoordinator`'s
    /// fetches. Cloned here so the relayed-state-proof handler can pass
    /// a peer the bytes without going through the state machine.
    pub(crate) proven_cells: Arc<ProvenCells>,
}

impl SharedCaches {
    /// Construct caches at `io_loop` startup. The `ProvisionStore`,
    /// `TxStore`, `ExecCertStore`, `FinalizationStore` and `ProvenCells`
    /// are owned by their respective state machines; clones are passed
    /// in so the same `Arc`s flow into network handler closures and sync
    /// helpers.
    #[allow(clippy::too_many_arguments)] // one per store the handlers read
    pub(crate) fn new(
        provision_store: Arc<ProvisionStore>,
        verified_headers: Arc<VerifiedHeaderBuffer>,
        tx_store: Arc<TxStore>,
        exec_cert_store: Arc<ExecCertStore>,
        finalization_store: Arc<FinalizationStore>,
        proven_cells: Arc<ProvenCells>,
    ) -> Self {
        Self {
            tx_store,
            finalization: Arc::new(QuickCache::new(DEFAULT_CERT_CACHE_SIZE)),
            provision_store,
            verified_headers,
            exec_cert_store,
            finalization_store,
            proven_cells,
        }
    }
}
