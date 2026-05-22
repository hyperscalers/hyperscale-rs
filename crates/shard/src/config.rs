//! BFT configuration.
//!
//! Operator-tunable knobs only. Protocol-invariant timing constants (view-change
//! cadence, proposer-timestamp admission bounds, stall-attack ceiling) live in
//! [`hyperscale_types::time`] and must match across every validator.

use std::time::Duration;

/// Local-only operational tuning for the BFT runtime.
#[derive(Debug, Clone)]
pub struct ShardConsensusConfig {
    /// Timeout before fetching missing transactions from peers.
    /// If a pending block is still incomplete after this duration, request
    /// the missing transactions directly from the proposer or a peer.
    pub transaction_fetch_timeout: Duration,

    /// Timeout before fetching missing certificates from peers.
    /// If a pending block is still missing certificates after this duration,
    /// request them directly from the proposer or a peer.
    pub certificate_fetch_timeout: Duration,

    /// Interval between cleanup timer fires.
    /// The cleanup timer performs periodic housekeeping tasks:
    /// - Checks sync health and triggers catch-up sync if needed
    pub cleanup_interval: Duration,

    /// Maximum number of synced blocks to submit for parallel QC verification
    /// at once. Bounds memory usage from buffered blocks and prevents
    /// overwhelming the crypto pool during sync catch-up.
    pub max_parallel_sync_verifications: usize,
}

impl Default for ShardConsensusConfig {
    fn default() -> Self {
        Self {
            transaction_fetch_timeout: Duration::from_millis(150),
            certificate_fetch_timeout: Duration::from_millis(500),
            cleanup_interval: Duration::from_secs(1),
            max_parallel_sync_verifications: 16,
        }
    }
}

impl ShardConsensusConfig {
    /// Create a new BFT configuration with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}
