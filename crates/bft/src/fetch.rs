//! Fetch timeout tracking for pending blocks.
//!
//! Tracks when each pending block was created so that `check_pending_block_fetches`
//! can decide when to request missing transactions/certificates.

use hyperscale_types::Hash;
use std::collections::HashMap;
use std::time::Duration;

/// Tracks fetch timing for pending blocks.
///
/// When a block header arrives, we record the time. After a configurable
/// timeout, we emit fetch requests for any missing data. This gives
/// gossip and local certificate creation time to fill in missing data
/// before resorting to explicit fetching.
pub(crate) struct FetchCoordinator {
    /// Tracks when each pending block was created (hash -> creation time).
    pending_block_created_at: HashMap<Hash, Duration>,
}

impl FetchCoordinator {
    /// Create a new FetchCoordinator.
    pub fn new() -> Self {
        Self {
            pending_block_created_at: HashMap::new(),
        }
    }

    /// Record when a pending block was created (for fetch timeout).
    pub fn track(&mut self, block_hash: Hash, now: Duration) {
        self.pending_block_created_at.insert(block_hash, now);
    }

    /// Get the creation time for a pending block.
    pub fn created_at(&self, block_hash: &Hash) -> Option<Duration> {
        self.pending_block_created_at.get(block_hash).copied()
    }

    /// Remove entries for blocks no longer in pending_blocks.
    pub fn cleanup(&mut self, pending_blocks: &HashMap<Hash, crate::pending::PendingBlock>) {
        self.pending_block_created_at
            .retain(|hash, _| pending_blocks.contains_key(hash));
    }
}
