//! Per-shard scope: the I/O state and core infrastructure each hosted
//! shard owns.
//!
//! [`ShardIo`] ([`io`]) composes one shard's per-subsystem state —
//! [`consensus`], [`cross_shard`], [`mempool`] — over shared infra:
//! storage, the commit pipeline, request-serving caches. [`commit`] is the
//! dual-input block-commit coordinator that merges the consensus
//! `CommitBlock` path and the sync `CommitBlockByQcOnly` path. The
//! remaining children are the per-shard caches, request-serving verify
//! helpers, and phase-time stamps.

pub mod caches;
pub mod commit;
pub mod consensus;
pub mod cross_shard;
pub mod io;
pub mod mempool;
pub mod phase_times;
pub mod verify;

pub use io::ShardIo;
