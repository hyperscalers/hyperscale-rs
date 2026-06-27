//! Composite consensus node — state machine plus per-shard drivers.
//!
//! This crate is the integration point. It owns two concerns:
//!
//! - [`NodeStateMachine`] composes the per-domain coordinators (shard consensus,
//!   execution, mempool, provisions, remote-headers, topology) into a
//!   single deterministic state machine over `ProtocolEvent` inputs
//!   and `Action` outputs.
//! - [`host::NodeHost`] composes process-scoped resources ([`ProcessIo`])
//!   plus one [`shard::ShardLoop`] per hosted shard, wrapping the
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
//! misses the broadcast, the cross-shard `provision_serve` path answers
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
pub mod reshape;
pub mod shard;
mod state;
mod sync;
mod vnode;

pub use bootstrap::state_range_serve::serve_state_range_request;
pub use bootstrap::witness_history_serve::serve_witness_history_request;
pub use config::NodeConfig;
pub use host::{NodeHost, ShardGenesis};
pub use process::TxStatusCache;
pub use shard::consensus::{BlockSyncStateKind, serve_block_request};
pub use shard::cross_shard::serve_settled_waves_request;
pub use shard::{SharedTopologySnapshot, TimerOp, timer_event};
pub use state::NodeStateMachine;
pub use vnode::{SeatFollower, SeatVnodeGroup, Vnode, VnodeInit, seat_follower, seat_vnode_group};
