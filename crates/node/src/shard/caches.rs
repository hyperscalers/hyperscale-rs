//! Inbound request-serving caches.
//!
//! [`SharedCaches`] groups the in-memory caches that back peer-facing
//! request handlers (transaction, finalization, execution-cert,
//! provision) and the replica stores they read. Each field is
//! `Arc`-shared, so the same handles flow into the network handler
//! closures registered for the shard.
//!
//! The caches are independent of the consensus state machine; the shard's
//! loop mutates them in response to outbound events
//! (`Continuation(FinalizationsAdmitted)`, validated transactions, terminal
//! status), and handlers read them on remote-peer requests.

use std::sync::Arc;

use hyperscale_execution::{CrossingIndexSlot, ExecCertStore, FinalizationStore};
use hyperscale_mempool::TxStore;
use hyperscale_provisions::{ProvisionStore, VerifiedHeaderBuffer};
use hyperscale_types::cache::{BoundedCache, bounded_cache};
use hyperscale_types::{Finalization, FinalizationHash, Verifiable};

use crate::replica::NodeStateMachine;

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
    /// Finalizations, keyed by `FinalizationHash`. Populated by the loop's
    /// `Continuation(FinalizationsAdmitted)` interception; queried by the
    /// inbound finalization handler.
    pub(crate) finalization: Arc<BoundedCache<FinalizationHash, Arc<Verifiable<Finalization>>>>,
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
    /// owned by the [`ExecutionCoordinator`]. Cloned here for its size
    /// gauge.
    ///
    /// [`ExecutionCoordinator`]: hyperscale_execution::ExecutionCoordinator
    pub(crate) exec_cert_store: Arc<ExecCertStore>,
    /// Per-shard finalization store, owned by the replica's
    /// `ExecutionCoordinator`.
    pub(crate) finalization_store: Arc<FinalizationStore>,
    /// The replica's crossing index slot, bound to the shard's chain once
    /// the chain is open.
    pub(crate) crossing_index: Arc<CrossingIndexSlot>,
}

impl SharedCaches {
    /// Construct caches at loop startup over the stores `replica`'s
    /// coordinators own; the same `Arc`s flow into network handler
    /// closures and sync helpers.
    pub(crate) fn new(replica: &NodeStateMachine) -> Self {
        let execution = replica.execution_coordinator();
        let provisions = replica.provisions_coordinator();
        Self {
            tx_store: Arc::clone(replica.mempool_coordinator().tx_store()),
            finalization: Arc::new(bounded_cache(DEFAULT_CERT_CACHE_SIZE)),
            provision_store: Arc::clone(provisions.store()),
            verified_headers: Arc::clone(provisions.verified_headers()),
            exec_cert_store: Arc::clone(execution.exec_cert_store()),
            finalization_store: Arc::clone(execution.finalization_store()),
            crossing_index: Arc::clone(execution.crossing_index()),
        }
    }
}
