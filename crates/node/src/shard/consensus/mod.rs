//! Per-shard consensus subsystem.
//!
//! Colocates everything block-consensus the shard driver touches: the
//! block-sync FSM [`binding`](block), its inbound [`serve`](block_serve)
//! responder, the `impl ShardLoop` [`glue`](block_sync) that drives fetches
//! and delivers synced blocks to consensus, and the certified-header
//! [`gossip`] handler that feeds cross-shard provisioning.

mod block;
mod block_serve;
mod block_sync;
mod gossip;

pub use block::{
    BlockSync, BlockSyncConfig, BlockSyncInput, BlockSyncOutput, BlockSyncStateKind,
    BlockSyncStatus,
};
pub use block_serve::serve_block_request;
