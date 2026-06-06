//! Production-specific sync status types.

use std::collections::HashMap;

use hyperscale_node::BlockSyncStateKind;
use serde::Serialize;

/// Cross-shard sync status for external APIs.
///
/// Each hosted shard maintains its own block-sync FSM; this type
/// exposes every shard's view side by side. `sync_peers` is the only
/// process-level field — derived from the libp2p adapter's connected
/// peer set, not per-shard.
///
/// The map is keyed by [`hyperscale_types::ShardId::inner`] (a
/// `u64`) so the type derives `Serialize` directly — JSON object keys
/// must be string-stringifiable, and `u64` satisfies that.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SyncStatus {
    /// Per-hosted-shard sync state, keyed by shard id.
    pub shards: HashMap<u64, ShardSyncState>,
    /// Number of connected peers capable of sync. Process-level — the
    /// libp2p adapter is shared across hosted shards.
    pub sync_peers: usize,
}

/// One hosted shard's view of its block-sync FSM.
#[derive(Debug, Clone, Serialize)]
pub struct ShardSyncState {
    /// Current sync state ("idle" or "syncing").
    pub state: BlockSyncStateKind,
    /// Current committed height.
    pub current_height: u64,
    /// Target height (if syncing).
    pub target_height: Option<u64>,
    /// Number of blocks behind target.
    pub blocks_behind: u64,
    /// Number of pending fetch requests.
    pub pending_fetches: usize,
    /// Number of heights queued for fetch.
    pub queued_heights: usize,
}

impl Default for ShardSyncState {
    fn default() -> Self {
        Self {
            state: BlockSyncStateKind::Idle,
            current_height: 0,
            target_height: None,
            blocks_behind: 0,
            pending_fetches: 0,
            queued_heights: 0,
        }
    }
}
