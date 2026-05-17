//! Per-validator bundle hosted by the `IoLoop`.
//!
//! One [`Vnode`] per validator identity. The `IoLoop` owns `Vec<Vnode>`
//! and drives each vnode's state machine in turn. Same-shard vnodes
//! share their `ShardIo` (see `crates/node/src/shard/`); cross-shard
//! vnodes live independently.
//!
//! Per-step scratch (emitted statuses, action counter, timer ops)
//! lives on the `Vnode` so each step's outputs are bound to a specific
//! validator.

use std::sync::Arc;

use hyperscale_types::{
    Bls12381G1PrivateKey, ShardGroupId, TransactionStatus, TxHash, ValidatorId,
};

use crate::NodeStateMachine;
use crate::io_loop::TimerOp;

/// Per-validator bundle hosted by the `IoLoop`.
pub struct Vnode {
    /// This validator's network identity.
    pub validator_id: ValidatorId,

    /// The shard this validator is currently a member of.
    pub shard: ShardGroupId,

    /// Per-validator state machine.
    pub state: NodeStateMachine,

    /// BLS signing key for votes and proposals. Shared with
    /// `DispatchHandles` via `Arc` so delegated handlers running on
    /// thread pools can sign without re-entering the pinned thread.
    pub signing_key: Arc<Bls12381G1PrivateKey>,

    /// Per-step buffer of `(tx_hash, status)` pairs emitted via
    /// `Action::EmitTransactionStatus`. Drained into `StepOutput` at
    /// the end of each `step()` for the runner to forward to RPC
    /// subscribers.
    pub emitted_statuses: Vec<(TxHash, TransactionStatus)>,

    /// Per-step counter of actions produced by the state machine.
    /// Drained into `StepOutput` for the runner's metrics; reset by
    /// `step()` (and cleared mid-step by handlers that synthesize
    /// follow-up events).
    pub actions_generated: usize,

    /// Per-step buffer of timer set/cancel operations. The runner is
    /// responsible for translating these into actual timer-driver
    /// calls since timer firing is inherently runner-specific
    /// (wall-clock in production, logical-clock in simulation).
    pub pending_timer_ops: Vec<TimerOp>,
}
