//! Per-shard per-payload fetch state machines.
//!
//! [`FetchHost`] holds one [`Fetch`](super::Fetch) per payload binding plus
//! metric readouts for one shard. Keeping these here, rather than on
//! [`ShardLoop`], names "what fetches this shard is orchestrating" as
//! one bundle and isolates per-payload state from sync state.
//!
//! [`ShardLoop`]: crate::shard_loop::ShardLoop

use super::binding::{BeaconProposalFetch, ShardWitnessFetch, TransactionFetch};
use crate::config::NodeConfig;

/// Per-payload fetch state machines owned by the I/O loop.
pub struct FetchHost {
    /// Per-block transaction fetch (intra-shard, pinned to proposer).
    pub transaction: TransactionFetch,

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
            || self.shard_witness.has_pending()
            || self.beacon_proposal.has_pending()
    }
}

/// Cheap aggregate of per-binding fetch counts (all payloads). Built by
/// [`ShardIo::fetch_metrics`](crate::shard::ShardIo::fetch_metrics) from the
/// `FetchHost` payloads plus the cross-shard fetch instances on
/// [`CrossShardState`](crate::shard::cross_shard::CrossShardState); flattened
/// into the broader `MetricsSnapshot` by the I/O loop.
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
