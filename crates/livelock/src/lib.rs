//! Livelock prevention for cross-shard transactions.
//!
//! This crate implements provision-based cycle detection to prevent bidirectional
//! livelock in cross-shard transactions.
//!
//! # Problem
//!
//! Cross-shard transactions can deadlock when two shards each have committed
//! transactions that need state from the other:
//!
//! ```text
//! Shard A commits TX_O (needs state from C)
//! Shard C commits TX_P (needs state from A)
//!
//! Result: A waits for C, C waits for A → Deadlock
//! ```
//!
//! # Solution
//!
//! When a shard commits a cross-shard transaction, it broadcasts provisions to
//! other shards. The provision itself is proof of commitment. When receiving a
//! provision, we check for bidirectional cycles:
//!
//! 1. Do we have a committed TX that needs the sender's state?
//! 2. Does the sender have a committed TX that needs our state?
//!
//! If both are true, we have a cycle. The transaction with the higher hash
//! is deferred (loses), releasing its locks. Both shards independently reach
//! the same conclusion with no extra communication.
//!
//! # Components
//!
//! - [`LivelockState`] - Sub-state machine for cycle detection and deferral management

mod state;
mod tracker;

pub use state::LivelockState;
