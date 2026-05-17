//! Block-sync binding for the generic [`Sync`] state machine.
//!
//! [`BlockSyncBinding`] declares block-sync's per-binding type info:
//! single-instance scope (`Scope = ()`) and a small piece of
//! payload-private state — [`BlockSyncState`] — tracking heights whose
//! last response failed rehydration and need a full refetch.
//!
//! The `IoLoop` block-sync handlers own request dispatch, response decoding,
//! rehydration, and feed scheduling events back into [`Sync`]. The FSM itself
//! doesn't know what a `CertifiedBlock` looks like.
//!
//! Public API:
//! - [`BlockSyncBinding`] — marker type implementing [`SyncBinding`]
//! - [`BlockSyncState`] — binding-private state owned by `Sync<BlockSyncBinding>`
//! - [`BlockSync`] — type alias for `Sync<BlockSyncBinding>`
//! - [`BlockSyncInput`] / [`BlockSyncOutput`] — type aliases for
//!   `SyncInput<BlockSyncBinding>` / `SyncOutput<BlockSyncBinding>`
//! - [`BlockSyncStateKind`] — high-level Idle/Syncing tag for status APIs
//! - [`BlockSyncStatus`] — combined status snapshot (state + scope counters)

use std::collections::HashSet;

use hyperscale_types::BlockHeight;
use serde::Serialize;

use super::{ScopeStatus, Sync, SyncBinding, SyncConfig, SyncInput, SyncOutput};

/// Configuration alias for block-sync.
pub type BlockSyncConfig = SyncConfig;

/// Type alias: block-sync is `Sync<BlockSyncBinding>`.
pub type BlockSync = Sync<BlockSyncBinding>;

/// Type alias for block-sync inputs.
pub type BlockSyncInput = SyncInput<BlockSyncBinding>;

/// Type alias for block-sync outputs.
pub type BlockSyncOutput = SyncOutput<BlockSyncBinding>;

/// Marker type implementing [`SyncBinding`] for block-sync.
pub struct BlockSyncBinding;

/// Block-sync's per-id auxiliary state.
#[derive(Debug, Default)]
pub struct BlockSyncState {
    /// Heights whose previous response failed rehydration. The next fetch
    /// for these heights must omit the inventory bloom so the responder
    /// cannot elide bodies the requester couldn't resolve last time.
    /// Drained when the height is admitted or the protocol completes.
    pub force_full_refetch: HashSet<BlockHeight>,
}

impl SyncBinding for BlockSyncBinding {
    type Scope = ();
    type State = BlockSyncState;
    const NAME: &'static str = "block_sync";

    /// Drop force-full markers at or below the new committed height.
    fn on_admitted(state: &mut Self::State, _scope: &Self::Scope, committed: BlockHeight) {
        state.force_full_refetch.retain(|&h| h > committed);
    }

    /// Clear all force-full markers when sync catches up.
    fn on_complete(state: &mut Self::State, _scope: &Self::Scope, _height: BlockHeight) {
        state.force_full_refetch.clear();
    }
}

/// High-level sync state for external APIs (RPC / status).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockSyncStateKind {
    /// Not syncing, node is up to date.
    #[default]
    Idle,
    /// Actively fetching and applying blocks.
    Syncing,
}

impl BlockSyncStateKind {
    /// Stable string tag for metrics / logging.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Syncing => "syncing",
        }
    }
}

/// Combined block-sync status snapshot.
#[derive(Debug, Clone, Serialize, Default)]
pub struct BlockSyncStatus {
    /// Idle / Syncing tag.
    pub state: BlockSyncStateKind,
    /// Highest admitted height.
    pub current_height: u64,
    /// Highest known target.
    pub target_height: Option<u64>,
    /// Heights behind target.
    pub blocks_behind: u64,
    /// In-flight fetch ranges.
    pub pending_fetches: usize,
    /// Heights queued or deferred awaiting fetch.
    pub queued_heights: usize,
}

/// Convenience accessors on `Sync<BlockSyncBinding>` that map the
/// generic's per-scope status into block-sync's external shape.
impl Sync<BlockSyncBinding> {
    /// Mark `height` so its next fetch omits the inventory bloom.
    pub fn mark_force_full_refetch(&mut self, height: BlockHeight) {
        self.binding_state_mut().force_full_refetch.insert(height);
    }

    /// Whether `height` is flagged for a full refetch.
    #[must_use]
    pub fn force_full(&self, height: BlockHeight) -> bool {
        self.binding_state().force_full_refetch.contains(&height)
    }

    /// Block-sync status for the (only) scope.
    #[must_use]
    pub fn block_sync_status(&self) -> BlockSyncStatus {
        let scope: ScopeStatus = self.status(&());
        let is_syncing = self.is_syncing();
        BlockSyncStatus {
            state: if is_syncing {
                BlockSyncStateKind::Syncing
            } else {
                BlockSyncStateKind::Idle
            },
            current_height: scope.current_height,
            target_height: if is_syncing {
                Some(scope.target_height)
            } else {
                None
            },
            blocks_behind: scope.blocks_behind,
            pending_fetches: scope.pending_fetches,
            queued_heights: scope.queued_heights,
        }
    }

    /// Number of blocks behind the current target.
    #[must_use]
    pub fn blocks_behind(&self) -> u64 {
        self.status(&()).blocks_behind
    }
}
