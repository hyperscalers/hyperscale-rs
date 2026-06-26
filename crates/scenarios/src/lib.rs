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
//! Each module at the crate root is one such scenario (or a small family of
//! them). The harness-agnostic vocabulary they are written against — the
//! [`Cluster`] trait, [`ScenarioConfig`], [`Budget`], and the [`query`],
//! [`wait`], [`tx`], and [`grow_to`] helpers — lives in [`support`]. The two
//! adaptors (`SimCluster`, `ProdCluster`) are supplied by the test crates that
//! depend on this one.

mod support;

mod liveness;
mod multi_vnode;
mod reshape;
mod straddler;
mod transactions;

pub use liveness::liveness_baseline;
pub use multi_vnode::multi_vnode_progress;
pub use reshape::{merge_lifecycle, split_lifecycle};
pub use straddler::{merge_straddler_atomic, split_straddler_atomic};
pub use support::{
    Budget, Cluster, ScenarioConfig, epochs, grow_to, query, tx, vote_reshape_threshold, wait,
};
pub use transactions::{cross_shard_tx, livelock_resolves_promptly, single_shard_tx};
