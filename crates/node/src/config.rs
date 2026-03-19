//! Consolidated configuration for IoLoop.

use crate::protocol::fetch::FetchConfig;
use crate::protocol::provision_fetch::ProvisionFetchConfig;
use crate::protocol::sync::SyncConfig;
use std::time::Duration;

/// Configuration for [`IoLoop`](crate::io_loop::IoLoop).
///
/// Bundles all sub-component configs so runners can pass a single value.
#[derive(Debug, Default, Clone)]
pub struct IoLoopConfig {
    pub sync: SyncConfig,
    pub fetch: FetchConfig,
    pub provision_fetch: ProvisionFetchConfig,
    pub batch: BatchConfig,
}

/// Batching thresholds for the I/O loop.
///
/// Each batch has a maximum item count and a time window. The batch flushes
/// when either limit is reached. Defaults match the previous hard-coded
/// constants.
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Cross-shard execution batch.
    pub cross_shard_max: usize,
    pub cross_shard_window: Duration,

    /// Execution vote verification batch.
    pub execution_vote_max: usize,
    pub execution_vote_window: Duration,

    /// Execution certificate verification batch.
    pub execution_certificate_max: usize,
    pub execution_certificate_window: Duration,

    /// Broadcast execution vote batch.
    pub broadcast_vote_max: usize,
    pub broadcast_vote_window: Duration,

    /// Broadcast execution certificate batch.
    pub broadcast_cert_max: usize,
    pub broadcast_cert_window: Duration,

    /// Transaction validation batch.
    pub tx_validation_max: usize,
    pub tx_validation_window: Duration,

    /// Committed block header sender signature verification batch.
    pub committed_header_max: usize,
    pub committed_header_window: Duration,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            cross_shard_max: 256,
            cross_shard_window: Duration::from_millis(5),

            execution_vote_max: 64,
            execution_vote_window: Duration::from_millis(20),

            execution_certificate_max: 64,
            execution_certificate_window: Duration::from_millis(15),

            broadcast_vote_max: 64,
            broadcast_vote_window: Duration::from_millis(15),

            broadcast_cert_max: 64,
            broadcast_cert_window: Duration::from_millis(15),

            tx_validation_max: 128,
            tx_validation_window: Duration::from_millis(20),

            committed_header_max: 32,
            committed_header_window: Duration::from_millis(15),
        }
    }
}
