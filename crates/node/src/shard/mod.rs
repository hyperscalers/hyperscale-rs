//! Per-shard scope: the I/O state and core infrastructure each hosted
//! shard owns.
//!
//! [`ShardIo`] holds one shard's storage, sync/fetch hosts, commit
//! pipeline, caches, and batch accumulators ([`io`]). [`commit`] is the
//! dual-input block-commit coordinator that merges the consensus
//! `CommitBlock` path and the sync `CommitBlockByQcOnly` path. The
//! remaining children are the per-shard caches, request-serving verify
//! helpers, phase-time stamps, and settled-waves acquisition.

pub mod caches;
pub mod commit;
pub mod consensus;
pub mod cross_shard;
pub mod io;
pub mod mempool;
pub mod phase_times;
pub mod verify;

pub use io::{CertifiedHeaderVerificationItem, ShardIo};
