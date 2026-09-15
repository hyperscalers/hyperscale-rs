//! Production-specific sync status types.

use std::collections::HashMap;

use hyperscale_node::BlockSyncStatus;
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
    pub(crate) shards: HashMap<u64, BlockSyncStatus>,
    /// Number of connected peers capable of sync. Process-level — the
    /// libp2p adapter is shared across hosted shards.
    pub(crate) sync_peers: usize,
}
