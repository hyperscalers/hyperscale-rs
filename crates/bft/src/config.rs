//! BFT configuration.

use std::time::Duration;

/// BFT consensus configuration.
#[derive(Debug, Clone)]
pub struct BftConfig {
    /// Base timeout for view change (before backoff).
    pub view_change_timeout: Duration,

    /// Linear backoff increment per round at the same height.
    ///
    /// When view changes occur, the timeout increases linearly:
    /// `effective_timeout = view_change_timeout + view_change_timeout_increment * rounds_at_height`
    ///
    /// This prevents "thundering herd" problems where all validators timeout
    /// simultaneously under network stress, causing cascading view changes.
    ///
    /// Set to `Duration::ZERO` to disable backoff (constant timeout).
    pub view_change_timeout_increment: Duration,

    /// Maximum view change timeout (caps the linear backoff).
    ///
    /// If set, the effective timeout is capped at this value regardless of
    /// how many rounds have elapsed. This provides operational predictability
    /// at the cost of potentially slower convergence in extreme network conditions.
    ///
    /// Set to `None` to disable the cap.
    /// Default: 30 seconds (reasonable upper bound for most networks).
    pub view_change_timeout_max: Option<Duration>,

    /// Maximum transactions per block.
    pub max_transactions_per_block: usize,

    /// Maximum finalized transactions per block (across all wave certificates).
    /// Older waves (by kickoff `block_height`) are prioritized over newer ones.
    pub max_finalized_transactions_per_block: usize,

    /// Maximum remote-shard provision transactions per block, summed across
    /// all provisions. Oldest batches (FIFO queue order) are included
    /// first; once the running total would exceed this cap, the rest stay
    /// queued for the next proposal. Bounds build/verify work and the
    /// per-block `local_provision.request` fetch fan-out on voters who
    /// missed the original cross-shard gossip.
    pub max_provision_transactions_per_block: usize,

    /// Maximum acceptable delay for proposer timestamp behind our clock (ms).
    pub max_timestamp_delay_ms: u64,

    /// Maximum acceptable rush for proposer timestamp ahead of our clock (ms).
    pub max_timestamp_rush_ms: u64,

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

impl Default for BftConfig {
    fn default() -> Self {
        Self {
            view_change_timeout: Duration::from_secs(3),
            view_change_timeout_increment: Duration::from_secs(1),
            view_change_timeout_max: Some(Duration::from_secs(30)),
            max_transactions_per_block: 4096,
            max_finalized_transactions_per_block: 8192,
            max_provision_transactions_per_block: 4096,
            max_timestamp_delay_ms: 30_000,
            max_timestamp_rush_ms: 2_000,
            transaction_fetch_timeout: Duration::from_millis(150),
            certificate_fetch_timeout: Duration::from_millis(500),
            cleanup_interval: Duration::from_secs(1),
            max_parallel_sync_verifications: 16,
        }
    }
}

impl BftConfig {
    /// Create a new BFT configuration with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the view change timeout.
    #[must_use]
    pub const fn with_view_change_timeout(mut self, timeout: Duration) -> Self {
        self.view_change_timeout = timeout;
        self
    }

    /// Set the view change timeout increment (linear backoff per round).
    #[must_use]
    pub const fn with_view_change_timeout_increment(mut self, increment: Duration) -> Self {
        self.view_change_timeout_increment = increment;
        self
    }

    /// Set the maximum view change timeout (caps the linear backoff).
    ///
    /// Pass `None` to disable the cap.
    #[must_use]
    pub const fn with_view_change_timeout_max(mut self, max: Option<Duration>) -> Self {
        self.view_change_timeout_max = max;
        self
    }

    /// Set the maximum transactions per block.
    #[must_use]
    pub const fn with_max_transactions(mut self, max: usize) -> Self {
        self.max_transactions_per_block = max;
        self
    }

    /// Set the maximum finalized transactions per block.
    #[must_use]
    pub const fn with_max_finalized_transactions(mut self, max: usize) -> Self {
        self.max_finalized_transactions_per_block = max;
        self
    }

    /// Set the maximum provision transactions per block (summed across all
    /// included provisions).
    #[must_use]
    pub const fn with_max_provision_transactions(mut self, max: usize) -> Self {
        self.max_provision_transactions_per_block = max;
        self
    }
}
