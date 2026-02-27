//! Consolidated configuration for NodeLoop.

use crate::fetch_protocol::FetchConfig;
use crate::inbound_handler::InboundHandlerConfig;
use crate::sync_protocol::SyncConfig;
use std::time::Duration;

/// Configuration for [`NodeLoop`](crate::node_loop::NodeLoop).
///
/// Bundles all sub-component configs so runners can pass a single value.
#[derive(Debug, Default, Clone)]
pub struct NodeConfig {
    pub sync: SyncConfig,
    pub fetch: FetchConfig,
    pub inbound: InboundHandlerConfig,
    pub batch: BatchConfig,
}

/// Batching thresholds for the node loop.
///
/// Each batch has a maximum item count and a time window. The batch flushes
/// when either limit is reached. Defaults match the previous hard-coded
/// constants.
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Cross-shard execution batch.
    pub cross_shard_max: usize,
    pub cross_shard_window: Duration,

    /// State vote verification batch.
    pub state_vote_max: usize,
    pub state_vote_window: Duration,

    /// State certificate verification batch.
    pub state_cert_max: usize,
    pub state_cert_window: Duration,

    /// Broadcast state vote batch.
    pub broadcast_vote_max: usize,
    pub broadcast_vote_window: Duration,

    /// Broadcast state certificate batch.
    pub broadcast_cert_max: usize,
    pub broadcast_cert_window: Duration,

    /// Broadcast state provision batch.
    pub broadcast_provision_max: usize,
    pub broadcast_provision_window: Duration,

    /// Transaction validation batch.
    pub tx_validation_max: usize,
    pub tx_validation_window: Duration,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            cross_shard_max: 256,
            cross_shard_window: Duration::from_millis(5),

            state_vote_max: 64,
            state_vote_window: Duration::from_millis(20),

            state_cert_max: 64,
            state_cert_window: Duration::from_millis(15),

            broadcast_vote_max: 64,
            broadcast_vote_window: Duration::from_millis(15),

            broadcast_cert_max: 64,
            broadcast_cert_window: Duration::from_millis(15),

            broadcast_provision_max: 64,
            broadcast_provision_window: Duration::from_millis(15),

            tx_validation_max: 128,
            tx_validation_window: Duration::from_millis(20),
        }
    }
}
