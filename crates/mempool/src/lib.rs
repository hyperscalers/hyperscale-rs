//! Mempool state machine.
//!
//! This crate implements the transaction mempool as a pure, synchronous
//! state machine. It handles:
//!
//! - Transaction submission and validation
//! - Transaction gossip
//! - Transaction status tracking
//! - Conflict detection
//!
//! # Key Difference from Async Version
//!
//! Uses `HashMap` instead of `DashMap` since there's no concurrent access.
//! All access is serialized through the event loop.

mod state;

pub use state::{LockContentionStats, MempoolConfig, MempoolState};
