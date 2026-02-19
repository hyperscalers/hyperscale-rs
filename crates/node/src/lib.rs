//! Combined node state machine.
//!
//! This crate composes the BFT, execution, and mempool state machines
//! into a complete consensus node. It also contains the transport-independent
//! sync and fetch protocol state machines.

pub mod action_handler;
pub mod fetch_protocol;
pub mod sync_protocol;

mod state;

pub use fetch_protocol::{
    FetchConfig, FetchInput, FetchKind, FetchOutput, FetchProtocol, FetchStatus,
};
pub use state::NodeStateMachine;
pub use sync_protocol::{
    SyncConfig, SyncInput, SyncOutput, SyncProtocol, SyncStateKind, SyncStatus,
};
