//! Bundle of per-payload fetch state machines owned by the I/O loop.
//!
//! [`FetchHost`] holds one [`Fetch<Id>`] per payload binding, plus the
//! cross-binding fanout (`apply_admission`) and metric readouts. Lifting
//! these out of `IoLoop` makes "what fetches the I/O loop is orchestrating"
//! explicit and isolates per-payload state from sync state.

use hyperscale_core::ProtocolEvent;

use super::FetchConfig;
use super::binding::{
    ExecCertBinding, ExecCertFetch, FetchBinding, FinalizedWaveBinding, FinalizedWaveFetch,
    LocalProvisionBinding, LocalProvisionFetch, ProvisionBinding, ProvisionFetch,
    TransactionBinding, TransactionFetch,
};
use crate::config::NodeConfig;

/// Per-payload fetch state machines owned by the I/O loop.
pub struct FetchHost {
    /// Per-block transaction fetch (intra-shard, pinned to proposer).
    pub transaction: TransactionFetch,

    /// Per-block local-provision fetch (intra-shard, pinned to proposer).
    pub local_provision: LocalProvisionFetch,

    /// Per-block finalized-wave fetch (intra-shard, rotates through committee).
    pub finalized_wave: FinalizedWaveFetch,

    /// Cross-shard provision fetch (rotates through source committee).
    pub provision: ProvisionFetch,

    /// Cross-shard execution-cert fetch (rotates through source committee).
    pub exec_cert: ExecCertFetch,
}

impl FetchHost {
    /// Build the fetch host from a node config.
    #[must_use]
    pub fn new(config: &NodeConfig) -> Self {
        Self {
            transaction: TransactionFetch::new("transaction", config.transaction_fetch.clone()),
            local_provision: LocalProvisionFetch::new(
                "local_provision",
                FetchConfig {
                    max_in_flight: 64,
                    max_ids_per_request: 16,
                    parallel_chunks_per_tick: 2,
                },
            ),
            finalized_wave: FinalizedWaveFetch::new(
                "finalized_wave",
                FetchConfig {
                    max_in_flight: 8,
                    max_ids_per_request: 4,
                    parallel_chunks_per_tick: 1,
                },
            ),
            provision: ProvisionFetch::new("provision", config.provision_fetch.clone()),
            exec_cert: ExecCertFetch::new("exec_cert", config.exec_cert_fetch.clone()),
        }
    }

    /// True if any per-payload fetch has work outstanding (in-flight or
    /// queued). Keeps the `FetchTick` timer alive so deferred ids
    /// eventually retry.
    #[must_use]
    pub fn has_any_pending(&self) -> bool {
        self.transaction.has_pending()
            || self.local_provision.has_pending()
            || self.finalized_wave.has_pending()
            || self.provision.has_pending()
            || self.exec_cert.has_pending()
    }

    /// Fan an admission `ProtocolEvent` across every binding. Each
    /// binding's `apply_admission` is a no-op for events it doesn't
    /// subscribe to.
    pub fn apply_admission(&mut self, event: &ProtocolEvent) {
        TransactionBinding::apply_admission(&mut self.transaction, event);
        LocalProvisionBinding::apply_admission(&mut self.local_provision, event);
        FinalizedWaveBinding::apply_admission(&mut self.finalized_wave, event);
        ProvisionBinding::apply_admission(&mut self.provision, event);
        ExecCertBinding::apply_admission(&mut self.exec_cert, event);
    }

    /// Snapshot per-binding fetch counts. The I/O loop flattens this into
    /// the larger `MetricsSnapshot`.
    #[must_use]
    pub fn metrics(&self) -> FetchMetrics {
        FetchMetrics {
            transaction_in_flight: self.transaction.in_flight_count(),
            transaction_pending: self.transaction.pending_count(),
            local_provision_in_flight: self.local_provision.in_flight_count(),
            local_provision_pending: self.local_provision.pending_count(),
            finalized_wave_in_flight: self.finalized_wave.in_flight_count(),
            finalized_wave_pending: self.finalized_wave.pending_count(),
            provision_in_flight: self.provision.in_flight_count(),
            provision_pending: self.provision.pending_count(),
            exec_cert_in_flight: self.exec_cert.in_flight_count(),
            exec_cert_pending: self.exec_cert.pending_count(),
        }
    }
}

/// Cheap aggregate of per-binding fetch counts.
///
/// Returned by [`FetchHost::metrics`]; flattened into the broader
/// `MetricsSnapshot` by the I/O loop.
#[allow(missing_docs)] // flat readouts; field names are the documentation
pub struct FetchMetrics {
    pub transaction_in_flight: usize,
    pub transaction_pending: usize,
    pub local_provision_in_flight: usize,
    pub local_provision_pending: usize,
    pub finalized_wave_in_flight: usize,
    pub finalized_wave_pending: usize,
    pub provision_in_flight: usize,
    pub provision_pending: usize,
    pub exec_cert_in_flight: usize,
    pub exec_cert_pending: usize,
}
