//! Mempool state machine.
//!
//! A pure, synchronous state machine driving the transaction mempool.
//! The [`MempoolCoordinator`] composes:
//!
//! - [`TxStore`] of pending transactions keyed by hash.
//! - Tombstone store + evicted-body cache for terminal-state dedup.
//! - `ExpectedTxs` sub-machine that backfills cross-shard transactions
//!   referenced by remote provisions before source-shard gossip arrives.
//!
//! Callers drive the coordinator via `on_submit_transaction`,
//! `on_transaction_gossip`, `on_block_committed`, and related lifecycle
//! methods; all I/O is deferred to the caller via returned `Action`s.

mod coordinator;
mod expected_txs;
mod tombstones;
mod tx_store;

pub use coordinator::{
    DEFAULT_MAX_PENDING, DEFAULT_MIN_DWELL_TIME, MempoolConfig, MempoolCoordinator,
    MempoolMemoryStats,
};
pub use tx_store::TxStore;
