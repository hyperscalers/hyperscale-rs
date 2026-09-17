//! shard consensus configuration.
//!
//! Operator-tunable knobs only. Protocol-invariant timing constants (view-change
//! cadence, proposer-timestamp admission bounds, stall-attack ceiling) live in
//! [`hyperscale_types::time`] and must match across every validator.

use std::time::Duration;

/// Local-only operational tuning for the shard consensus runtime.
#[derive(Debug, Clone)]
pub struct ShardConsensusConfig {
    /// Interval between cleanup timer fires.
    /// The cleanup timer performs periodic housekeeping tasks:
    /// - Checks sync health and triggers catch-up sync if needed
    /// - Re-offers the halted tip while a halt recovery names this
    ///   member retained, so it must stay well under
    ///   `hyperscale_types::HALT_HARVEST_WAIT` for the fresh committee
    ///   to see the offer inside its wait
    pub cleanup_interval: Duration,

    /// Maximum number of synced blocks to submit for parallel QC verification
    /// at once. Bounds memory usage from buffered blocks and prevents
    /// overwhelming the crypto pool during sync catch-up.
    pub(crate) max_parallel_sync_verifications: usize,
}

impl Default for ShardConsensusConfig {
    fn default() -> Self {
        Self {
            cleanup_interval: Duration::from_secs(1),
            max_parallel_sync_verifications: 16,
        }
    }
}

impl ShardConsensusConfig {
    /// Create a new shard consensus configuration with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}
