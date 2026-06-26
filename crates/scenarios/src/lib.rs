//! Portable node-behavioral scenarios.
//!
//! A *scenario* is a plain synchronous function over an abstract [`Cluster`]:
//! it drives the cluster from a precondition to a postcondition and asserts the
//! postcondition. The same function body runs on both harnesses — the
//! simulation's logical clock and production's wall-clock QUIC + `RocksDB`
//! cluster — via two thin adaptors that each implement [`Cluster`]. A scenario
//! that passes on one harness and fails on the other is then a real divergence,
//! not a test-authoring artefact.
//!
//! This crate owns the harness-agnostic surface: the [`Cluster`] trait, the
//! portable [`ScenarioConfig`], the [`Budget`] unit, the read combinators in
//! [`query`], the await combinators in [`wait`], the transaction builders in
//! [`tx`], and the [`grow_to`] step that reaches a multi-shard starting
//! topology. The two adaptors (`SimCluster`, `ProdCluster`) and the scenario
//! functions are supplied by the test crates that depend on this one.

mod budget;
mod cluster;
mod config;
mod grow;
mod liveness;
mod multi_vnode;
pub mod query;
mod reshape;
mod straddler;
mod transactions;
pub mod tx;
pub mod wait;

pub use budget::{Budget, epochs};
pub use cluster::Cluster;
pub use config::ScenarioConfig;
pub use grow::{grow_to, vote_reshape_threshold};
pub use liveness::liveness_baseline;
pub use multi_vnode::multi_vnode_progress;
pub use reshape::{merge_lifecycle, split_lifecycle};
pub use straddler::{merge_straddler_atomic, split_straddler_atomic};
pub use transactions::{cross_shard_tx, livelock_resolves_promptly, single_shard_tx};
