//! BFT configuration.

use std::time::Duration;

/// BFT consensus configuration.
#[derive(Debug, Clone)]
pub struct BftConfig {
    /// Interval between proposal attempts.
    pub proposal_interval: Duration,

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

    /// Maximum certificates per block.
    pub max_certificates_per_block: usize,

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

    /// Timeout for removing stale incomplete pending blocks.
    /// If a pending block remains incomplete (missing transactions/certificates)
    /// after this duration, it is removed from pending_blocks. This allows sync
    /// to be triggered when a later block header arrives, since has_block_at_height()
    /// will no longer return true for the stale block's height.
    ///
    /// This prevents a node from getting permanently stuck when transaction/certificate
    /// fetches fail repeatedly (e.g., proposer offline, network issues).
    pub stale_pending_block_timeout: Duration,

    /// Interval between cleanup timer fires.
    /// The cleanup timer performs periodic housekeeping tasks:
    /// - Removes stale pending blocks that have been incomplete too long
    /// - Checks sync health and triggers catch-up sync if needed
    pub cleanup_interval: Duration,

    /// Minimum time between block proposals (rate limiting).
    ///
    /// Even when a QC forms immediately, we wait at least this long since the last
    /// proposal before proposing the next block. This prevents burst behavior under
    /// high load where blocks could otherwise be produced at wire speed, causing:
    /// - Fast validators to race ahead of slower ones
    /// - Vote accumulation storms from rapid block production
    /// - Excessive pressure on the execution layer
    ///
    /// Set to Duration::ZERO to disable rate limiting (not recommended for production).
    pub min_block_interval: Duration,
}

impl Default for BftConfig {
    fn default() -> Self {
        Self {
            proposal_interval: Duration::from_millis(300),
            view_change_timeout: Duration::from_secs(3),
            view_change_timeout_increment: Duration::from_millis(500),
            view_change_timeout_max: Some(Duration::from_secs(30)),
            max_transactions_per_block: 1024,
            max_certificates_per_block: 4096,
            max_timestamp_delay_ms: 30_000,
            max_timestamp_rush_ms: 2_000,
            transaction_fetch_timeout: Duration::from_millis(50),
            certificate_fetch_timeout: Duration::from_millis(500),
            stale_pending_block_timeout: Duration::from_secs(30),
            cleanup_interval: Duration::from_secs(1),
            min_block_interval: Duration::from_millis(150),
        }
    }
}

impl BftConfig {
    /// Create a new BFT configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the proposal interval.
    pub fn with_proposal_interval(mut self, interval: Duration) -> Self {
        self.proposal_interval = interval;
        self
    }

    /// Set the view change timeout.
    pub fn with_view_change_timeout(mut self, timeout: Duration) -> Self {
        self.view_change_timeout = timeout;
        self
    }

    /// Set the view change timeout increment (linear backoff per round).
    pub fn with_view_change_timeout_increment(mut self, increment: Duration) -> Self {
        self.view_change_timeout_increment = increment;
        self
    }

    /// Set the maximum view change timeout (caps the linear backoff).
    ///
    /// Pass `None` to disable the cap.
    pub fn with_view_change_timeout_max(mut self, max: Option<Duration>) -> Self {
        self.view_change_timeout_max = max;
        self
    }

    /// Set the maximum transactions per block.
    pub fn with_max_transactions(mut self, max: usize) -> Self {
        self.max_transactions_per_block = max;
        self
    }

    /// Set the minimum block interval.
    pub fn with_min_block_interval(mut self, interval: Duration) -> Self {
        self.min_block_interval = interval;
        self
    }
}
