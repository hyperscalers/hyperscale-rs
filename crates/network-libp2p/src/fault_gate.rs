//! Per-node libp2p fault gate.
//!
//! Consulted at the transport's delivery seams. The `test-utils` feature selects
//! one of two implementations of `FaultState`, so no consumer carries a `cfg`:
//!
//! - enabled: wraps the shared fault engine — drop rules keyed on message
//!   type/host/tier plus a partition block-set, with a `PeerId → HostId` map the
//!   harness populates.
//! - disabled: a zero-sized no-op — every consult returns "deliver", so the
//!   delivery seams call the gate at no cost and no fault machinery reaches the
//!   validator binary.

#[cfg_attr(feature = "test-utils", path = "fault_gate/enabled.rs")]
#[cfg_attr(not(feature = "test-utils"), path = "fault_gate/disabled.rs")]
mod imp;

pub use imp::FaultState;
