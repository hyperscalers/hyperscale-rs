//! Composite consensus node — state machine plus per-shard drivers.
//!
//! This crate is the integration point. It owns two concerns:
//!
//! - [`NodeStateMachine`] composes the per-domain coordinators (shard consensus,
//!   execution, mempool, provisions, remote-headers, topology) into a
//!   single deterministic state machine over `ProtocolEvent` inputs
//!   and `Action` outputs.
//! - [`host::NodeHost`] composes process-scoped resources ([`ProcessIo`])
//!   plus one [`shard_loop::ShardLoop`] per hosted shard, wrapping the
//!   state machine with transport-dependent plumbing: network I/O,
//!   thread-pool dispatch, timer scheduling, block-sync and per-payload
//!   fetch sub-machines.
//!
//! # Topology sharing
//!
//! The state machine owns the topology coordinator; per-shard drivers
//! receive a [`SharedTopologySnapshot`] (an `ArcSwap<TopologyState>`)
//! for inbound verification only. Cross-shard broadcasts and fetches
//! encode their recipients in the emitted `Action` itself, so delegated
//! handlers never need to read topology from the state machine.
//!
//! # Provision DA fallback
//!
//! Cross-shard provisions are gossiped optimistically; if a target shard
//! misses the broadcast, [`shard_io::fetch::provision_serve`] answers
//! `provision.request` from `RocksDB` and the historical JMT. Reads are
//! bounded by `jmt_history_length` (256 blocks by default).
//!
//! [`ProcessIo`]: crate::process_io::ProcessIo

mod batch_accumulator;
mod config;
pub mod event;
pub mod host;
pub mod process_io;
mod shard_io;
pub mod shard_loop;
pub mod snap_sync;
mod state;
mod vnode;
pub mod witness_history;

pub use config::NodeConfig;
pub use host::NodeHost;
pub use shard_io::ShardIo;
pub use shard_io::sync::block::BlockSyncStateKind;
pub use shard_loop::{NodeStatusSnapshot, SharedTopologySnapshot, TimerOp, timer_event};
pub use state::NodeStateMachine;
pub use vnode::{Vnode, VnodeInit};
