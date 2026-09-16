//! Engine integration: tick-batch transaction execution.
//!
//! Synchronous execution shared by the production runner and the
//! deterministic simulator. The [`Executor`] does NOT own storage: the
//! runner owns it and passes a snapshot per call.
//!
//! State machines emit `Action::ExecuteTransactions`; the runner drives
//! the executor over the tick's batch, which projects the shard-invariant
//! [`CachedOutput`] into the local shard's [`ExecutedTx`] via
//! [`project_to_shard`].
//!
//! Execution itself is derivation through the effects bridge, an owned
//! committed base pre-read from the tick's JMT-backed snapshot, the
//! kernel's deterministic-parallel batch executor, and the movement fold
//! that turns schedule-invariant receipts into per-transaction absolute
//! `database_updates`. Guests run on the blessed wasmtime engine natively
//! and on the reference interpreter on wasm32; the vm repo's differential
//! suite pins byte-identical receipts and fuel across both.
//!
//! [`genesis`] seeds the stdlib world: the account package published
//! under its artifact hash, funded accounts registered as its instances,
//! and their balances as identity-keyed vault cells.

#![warn(missing_docs)]

mod backend;
mod batch;
mod executor;
mod output;
mod preview;
mod receipt;
mod records;

/// Genesis seeding: the stdlib world and funded-account cells.
pub mod genesis;
pub mod legs;
/// Shard assignment and write filtering for `StateWrites`.
pub mod sharding;

pub use backend::Availability;
pub use batch::{TickBatchContext, TickEnvironment, TickTxInput};
#[cfg(feature = "test-utils")]
pub use executor::AllCodeRuns;
pub use executor::{
    CodeAvailability, CodeUnavailable, Executor, artifact_package, build_fee_receipt,
    instance_of_record, protocol_hash,
};
pub use genesis::{GenesisConfig, PROTOCOL_RESOURCE, World, genesis_world, genesis_writes};
pub use hyperscale_effects_bridge::{LocalCells, account_address, terms_of};
pub use hyperscale_vm_kernel::{DOMAIN_SEALED_DRAW, ExecutionMode};
pub use output::ExecutedTx;
pub use preview::{
    DeclaredReads, FetchedCells, FetchedEntries, Holds, PreviewGrants, PreviewInputs,
    PreviewOutcome, PreviewReport, ResourceChange,
};
pub use receipt::{CachedOutput, project_to_shard};
