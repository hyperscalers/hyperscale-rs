//! Shared building blocks for fetch protocols.

pub mod instances;
mod peer_rotator;
mod retry_clock;
pub mod scope_fetch;
pub mod slot_tracker;

pub use scope_fetch::{ScopeFetch, ScopeFetchInput, ScopeFetchOutput};
pub use slot_tracker::SlotTracker;
