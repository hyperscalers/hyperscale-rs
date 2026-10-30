//! Composite consensus node — the replica state machine plus the drivers
//! that run it.
//!
//! This crate is the integration point. It owns two concerns:
//!
//! - [`NodeStateMachine`] is one shard's replica: the shard consensus,
//!   execution, mempool, provisions and remote-header coordinators, and
//!   the beacon schedule they read, composed into a single deterministic
//!   state machine over `ProtocolEvent` inputs and `Action` outputs.
//! - [`NodeHost`] composes process-scoped resources ([`ProcessIo`]), the
//!   host's one [`BeaconLoop`], and one [`ShardLoop`] per hosted shard,
//!   wrapping each replica with transport-dependent plumbing: network I/O,
//!   thread-pool dispatch, timer scheduling, block sync and per-payload
//!   fetches.
//!
//! The loops take [`event`] inputs; [`bootstrap`], [`reshape`] and
//! [`seating`] hold the sans-io sequencers and placement rules a runner
//! drives around them.
//!
//! # Topology sharing
//!
//! The beacon loop is the one writer of the topology the process
//! publishes; shard loops and network handlers read it through a
//! [`SharedTopologySnapshot`] (an `ArcSwap<TopologySnapshot>`) for inbound
//! verification only. Cross-shard broadcasts and fetches encode their
//! recipients in the emitted `Action` itself, so delegated handlers never
//! need to read topology from the state machine.
//!
//! # Provision DA fallback
//!
//! Cross-shard provisions are gossiped optimistically; if a target shard
//! misses the broadcast, the cross-shard provision serve answers
//! `provision.request` from the shard's store and the historical JMT.
//! Reads are bounded by the retention floor — `RETENTION_HORIZON` of
//! weighted time behind the tip.

mod batch_accumulator;
mod beacon;
pub mod bootstrap;
mod config;
pub mod event;
mod fetch;
mod host;
mod network_lane;
mod process;
mod replica;
pub mod reshape;
pub mod seating;
mod serve;
mod shard;
mod sync;

pub use beacon::BeaconLoop;
pub use bootstrap::state_range_serve::serve_state_range_request;
pub use bootstrap::witness_history_serve::serve_witness_history_request;
pub use config::{BatchConfig, NodeConfig};
pub use fetch::FetchConfig;
pub use host::{
    HostResources, HostedChain, NodeHost, ShardGenesis, attach_shard, chain_anchors, detach_shard,
};
pub use process::{ProcessIo, TxStatusCache};
pub use replica::{NodeStateMachine, ReplicaConfig};
pub use shard::consensus::{BlockSyncStateKind, BlockSyncStatus, serve_block_request};
pub use shard::cross_shard::serve_local_certified_headers;
pub use shard::{
    ShardLoop, SharedTopologySnapshot, ThreadShardLoop, installed_network_genesis_block,
    network_genesis_block,
};
