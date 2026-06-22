//! Per-shard per-payload fetch state machines.
//!
//! [`FetchHost`] holds one [`Fetch`](super::Fetch) per payload binding plus
//! metric readouts for one shard. Keeping these here, rather than on
//! [`ShardLoop`], names "what fetches this shard is orchestrating" as
//! one bundle and isolates per-payload state from sync state.
//!
//! [`ShardLoop`]: crate::shard_loop::ShardLoop

use super::FetchConfig;
use super::binding::{
    BeaconProposalFetch, ExecCertFetch, FinalizedWaveFetch, LocalProvisionFetch, ProvisionFetch,
    ShardWitnessFetch, TransactionFetch,
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

    /// Cross-shard beacon-witness fetch (rotates through source committee).
    pub shard_witness: ShardWitnessFetch,

    /// Missing-proposal fetch (rotates through beacon committee).
    pub beacon_proposal: BeaconProposalFetch,
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
            shard_witness: ShardWitnessFetch::new(
                "shard_witness",
                config.shard_witness_fetch.clone(),
            ),
            beacon_proposal: BeaconProposalFetch::new(
                "beacon_proposal",
                config.beacon_proposal_fetch.clone(),
            ),
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
            || self.shard_witness.has_pending()
            || self.beacon_proposal.has_pending()
    }

    /// Snapshot per-binding fetch counts. The I/O loop flattens this into
    /// the larger `MetricsSnapshot`.
    #[must_use]
    pub fn metrics(&self) -> FetchMetrics {
        FetchMetrics {
            transaction_in_flight: self.transaction.in_flight_count(),
            transaction_pending: self.transaction.pending_count(),
            transaction_oldest_in_flight_age_ms: self.transaction.oldest_in_flight_age_ms(),
            local_provision_in_flight: self.local_provision.in_flight_count(),
            local_provision_pending: self.local_provision.pending_count(),
            local_provision_oldest_in_flight_age_ms: self.local_provision.oldest_in_flight_age_ms(),
            finalized_wave_in_flight: self.finalized_wave.in_flight_count(),
            finalized_wave_pending: self.finalized_wave.pending_count(),
            finalized_wave_oldest_in_flight_age_ms: self.finalized_wave.oldest_in_flight_age_ms(),
            provision_in_flight: self.provision.in_flight_count(),
            provision_pending: self.provision.pending_count(),
            provision_oldest_in_flight_age_ms: self.provision.oldest_in_flight_age_ms(),
            exec_cert_in_flight: self.exec_cert.in_flight_count(),
            exec_cert_pending: self.exec_cert.pending_count(),
            exec_cert_oldest_in_flight_age_ms: self.exec_cert.oldest_in_flight_age_ms(),
            shard_witness_in_flight: self.shard_witness.in_flight_count(),
            shard_witness_pending: self.shard_witness.pending_count(),
            shard_witness_oldest_in_flight_age_ms: self.shard_witness.oldest_in_flight_age_ms(),
            beacon_proposal_in_flight: self.beacon_proposal.in_flight_count(),
            beacon_proposal_pending: self.beacon_proposal.pending_count(),
            beacon_proposal_oldest_in_flight_age_ms: self.beacon_proposal.oldest_in_flight_age_ms(),
        }
    }
}

/// Cheap aggregate of per-binding fetch counts.
///
/// Returned by [`FetchHost::metrics`]; flattened into the broader
/// `MetricsSnapshot` by the I/O loop.
///
/// `_oldest_in_flight_age_ms` is `0` when nothing is in flight; otherwise
/// the age (in milliseconds) of the longest-running in-flight entry.
/// Alerting on this rising past tens of seconds catches admission paths
/// that silently dropped a response without notifying the FSM — the
/// pin scenario the rest of this work fixed for specific known sites.
#[allow(missing_docs)] // flat readouts; field names are the documentation
pub struct FetchMetrics {
    pub transaction_in_flight: usize,
    pub transaction_pending: usize,
    pub transaction_oldest_in_flight_age_ms: u64,
    pub local_provision_in_flight: usize,
    pub local_provision_pending: usize,
    pub local_provision_oldest_in_flight_age_ms: u64,
    pub finalized_wave_in_flight: usize,
    pub finalized_wave_pending: usize,
    pub finalized_wave_oldest_in_flight_age_ms: u64,
    pub provision_in_flight: usize,
    pub provision_pending: usize,
    pub provision_oldest_in_flight_age_ms: u64,
    pub exec_cert_in_flight: usize,
    pub exec_cert_pending: usize,
    pub exec_cert_oldest_in_flight_age_ms: u64,
    pub shard_witness_in_flight: usize,
    pub shard_witness_pending: usize,
    pub shard_witness_oldest_in_flight_age_ms: u64,
    pub beacon_proposal_in_flight: usize,
    pub beacon_proposal_pending: usize,
    pub beacon_proposal_oldest_in_flight_age_ms: u64,
}
