//! Production-specific sync status types.

pub use hyperscale_node::SyncStateKind;
use serde::Serialize;

/// Sync status for external APIs.
///
/// Extends the shared protocol status with production-specific fields
/// like `sync_peers` (derived from topology).
#[derive(Debug, Clone, Serialize)]
pub struct SyncStatus {
    /// Current sync state ("idle" or "syncing").
    pub state: SyncStateKind,
    /// Current committed height.
    pub current_height: u64,
    /// Target height (if syncing).
    pub target_height: Option<u64>,
    /// Number of blocks behind target.
    pub blocks_behind: u64,
    /// Number of connected peers capable of sync.
    pub sync_peers: usize,
    /// Number of pending fetch requests.
    pub pending_fetches: usize,
    /// Number of heights queued for fetch.
    pub queued_heights: usize,
}

impl Default for SyncStatus {
    fn default() -> Self {
        Self {
            state: SyncStateKind::Idle,
            current_height: 0,
            target_height: None,
            blocks_behind: 0,
            sync_peers: 0,
            pending_fetches: 0,
            queued_heights: 0,
        }
    }
}
