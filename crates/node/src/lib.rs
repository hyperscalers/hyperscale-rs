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
//! misses the broadcast, [`fetch::provision_serve`] answers
//! `provision.request` from `RocksDB` and the historical JMT. Reads are
//! bounded by `jmt_history_length` (256 blocks by default).
//!
//! [`ProcessIo`]: crate::process::ProcessIo

mod batch_accumulator;
mod beacon;
pub mod bootstrap;
mod config;
pub mod event;
mod fetch;
pub mod host;
pub mod pool_loop;
pub mod process;
mod shard;
pub mod shard_loop;
mod state;
mod sync;
mod vnode;

pub use config::NodeConfig;
pub use fetch::state_range_serve::serve_state_range_request;
pub use fetch::witness_history_serve::serve_witness_history_request;
pub use host::NodeHost;
pub use process::TxStatusCache;
pub use shard::ShardIo;
pub use shard_loop::{NodeStatusSnapshot, SharedTopologySnapshot, TimerOp, timer_event};
pub use state::NodeStateMachine;
pub use sync::block::BlockSyncStateKind;
pub use sync::block_serve::serve_block_request;
pub use sync::settled_waves_serve::serve_settled_waves_request;
pub use vnode::{SeatFollower, SeatVnodeGroup, Vnode, VnodeInit, seat_follower, seat_vnode_group};
