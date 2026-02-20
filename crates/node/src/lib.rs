//! Combined node state machine.
//!
//! This crate composes the BFT, execution, and mempool state machines
//! into a complete consensus node. It also contains the transport-independent
//! sync and fetch protocol state machines.

pub mod action_handler;
pub mod fetch_protocol;
pub mod gossip_dispatch;
pub mod inbound_handler;
pub mod node_loop;
pub mod sync_protocol;

mod state;

pub use fetch_protocol::{
    FetchConfig, FetchInput, FetchKind, FetchOutput, FetchProtocol, FetchStatus,
};
pub use inbound_handler::{InboundHandler, InboundHandlerConfig};
pub use node_loop::TimerOp;
pub use state::NodeStateMachine;
pub use sync_protocol::{
    SyncConfig, SyncInput, SyncOutput, SyncProtocol, SyncStateKind, SyncStatus,
};
