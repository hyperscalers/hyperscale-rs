//! Centralized provision coordination for cross-shard transactions.
//!
//! This crate provides the `ProvisionCoordinator`, which centralizes all provision
//! tracking and verification for cross-shard transactions.
//!
//! # Problem
//!
//! The previous architecture had several issues:
//!
//! 1. **Byzantine vulnerability in livelock**: Cycle detection processed unverified provisions,
//!    allowing malicious validators to forge provisions and trigger false deferrals.
//!
//! 2. **Fragmented provision state**: Provisions were tracked in multiple places
//!    (ExecutionState, LivelockState) with different views (verified vs unverified).
//!
//! # Solution
//!
//! The `ProvisionCoordinator` provides:
//!
//! - **Single source of truth**: All provision lifecycle management in one place
//! - **Quorum-based triggers**: Events emitted only after verified quorum is reached
//! - **Byzantine safety**: Only verified provisions affect state machine decisions
//!
//! Note: Backpressure is handled by the mempool module, which tracks in-flight
//! transactions and enforces limits. The provisions module provides query methods
//! (like `has_any_verified_provisions`) that mempool uses for its decisions.
//!
//! # Architecture
//!
//! ```text
//! Network
//!     │
//!     ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │ ProvisionCoordinator.try_handle(StateProvisionReceived)     │
//! │                                                             │
//! │   1. Auto-register if tx not registered (remote TX)         │
//! │   2. Queue for signature verification                       │
//! │   3. Action::VerifyProvisionSignature                       │
//! └─────────────────────────────────────────────────────────────┘
//!                     │
//!                     ▼
//!             Runner verifies signature
//!                     │
//!                     ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │ ProvisionCoordinator.try_handle(ProvisionSignatureVerified) │
//! │                                                             │
//! │   1. Store in verified_provisions                           │
//! │   2. Update reverse indexes                                 │
//! │   3. Check shard quorum                                     │
//! │   4. If quorum: emit ProvisionQuorumReached                 │
//! │      → LivelockState uses for cycle detection               │
//! │      → ExecutionState uses for execution                    │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Components
//!
//! - [`ProvisionCoordinator`] - Main sub-state machine
//! - [`TxRegistration`] - Registration info for cross-shard transactions

pub mod handlers;

mod state;

pub use state::{ProvisionCoordinator, TxRegistration};
