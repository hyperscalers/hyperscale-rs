//! Harness-agnostic vocabulary shared by every scenario.
//!
//! This is the stable surface a scenario is written against: the [`Cluster`]
//! trait both harnesses implement, the portable [`ScenarioConfig`], the
//! [`Budget`] unit, the read combinators in [`query`], the await combinators in
//! [`wait`], the transaction builders in [`tx`], and the [`grow_to`] step that
//! reaches a multi-shard starting topology.

mod budget;
mod cluster;
mod config;
mod grow;
pub mod query;
pub mod tx;
pub mod wait;

pub use budget::{Budget, epochs};
pub use cluster::Cluster;
pub use config::ScenarioConfig;
pub use grow::{grow_to, vote_reshape_threshold};
