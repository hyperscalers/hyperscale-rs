//! Core types for Hyperscale consensus.
//!
//! This crate provides the foundational types for the consensus architecture:
//!
//! - [`ProtocolEvent`]: Events processed by the state machine
//! - [`Action`]: All possible outputs from the state machine
//! - [`StateMachine`]: The trait that all state machines implement
//!
//! The driver-specific input types (`HostEvent`, `ShardScopedInput`,
//! `FetchFailureKind`, `EventPriority`) live in
//! `hyperscale_node::event`, since they're not part of the
//! deterministic state-machine contract.
//!
//! # Architecture
//!
//! The core is built on a two-level event model:
//!
//! ```text
//! HostEvent → ShardLoop (intercepts I/O events) → ProtocolEvent → StateMachine::handle() → Actions
//! ```
//!
//! The state machine is:
//! - **Synchronous**: No async, no .await
//! - **Deterministic**: Same state + event = same actions
//! - **Pure-ish**: Mutates self, but performs no I/O
//!
//! All I/O is handled by the runner (simulation or production) which:
//! 1. Delivers shard inputs to the shard's loop
//! 2. `ShardLoop` intercepts I/O events (sync, fetch, validation) and forwards
//!    `ProtocolEvent`s to the state machine
//! 3. Executes the returned actions
//! 4. Converts action results back into shard / process inputs

mod action;
mod action_context;
mod beacon_action;
mod fetch_ids;
mod fetch_request;
mod gate;
mod protocol_event;
mod timer;
mod traits;

pub use action::{
    Action, ConsensusAction, CrossShardExecutionRequest, Delegated, ExecutionAction,
    HeaderCommittee, KeepDelta, ObserveDelta, ParentJudgement, ParticipationChange,
    ProvisionAction, ProvisionsRequest, QcSubject, StateRootCheck, SyncClaimId,
};
pub use action_context::{ActionContext, BeaconActionContext, PreparedBlock, Signing};
pub use beacon_action::{BeaconAction, BeaconBlockCheck, ParticipantAction};
pub use fetch_ids::{BeaconFetchIds, FetchIds};
pub use fetch_request::FetchRequest;
pub use gate::{Gate, GateEntry};
pub use hyperscale_dispatch::Parallelism;
pub use protocol_event::{CommitSource, ProtocolEvent, TickBatchOutcome};
pub use timer::TimerId;
pub use traits::StateMachine;
