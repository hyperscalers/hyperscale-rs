//! Mempool state machine.
//!
//! A pure, synchronous state machine driving the transaction mempool.
//! The [`MempoolCoordinator`] composes three sub-machines:
//!
//! - Tombstones + evicted-body cache for terminal-state deduplication.
//! - Lock tracker for node-level state locks and in-flight counters.
//! - Ready set for incrementally-maintained pending-tx selection.
//!
//! Callers drive the coordinator via `on_submit_transaction`,
//! `on_transaction_gossip`, `on_block_committed`, and related lifecycle
//! methods; all I/O is deferred to the caller via returned `Action`s.

mod coordinator;
mod lock_tracker;
mod ready_set;
mod tombstones;

pub use coordinator::{
    DEFAULT_MIN_DWELL_TIME, LockContentionStats, MempoolConfig, MempoolCoordinator,
    MempoolMemoryStats,
};
