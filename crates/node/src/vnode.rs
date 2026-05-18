//! Per-validator bundle hosted by the `IoLoop`.
//!
//! One [`Vnode`] per validator identity, owned by a [`ShardGroup`] in
//! the `IoLoop`'s `shards` map. Same-shard vnodes share the enclosing
//! `ShardGroup`'s `ShardIo`; cross-shard vnodes live in different
//! groups. The vnode's shard is implied by which group it lives in —
//! no denormalized field.
//!
//! Per-step scratch (emitted statuses, action counter, timer ops)
//! lives on the `Vnode` so each step's outputs are bound to a specific
//! validator.
//!
//! [`ShardGroup`]: crate::io_loop::ShardGroup

use std::sync::Arc;

use hyperscale_types::{Bls12381G1PrivateKey, TransactionStatus, TxHash, ValidatorId};

use crate::NodeStateMachine;
use crate::io_loop::TimerOp;

/// Caller-supplied bundle for constructing one [`Vnode`]. The
/// `IoLoop` constructor wraps each entry into a full [`Vnode`] and
/// shares one `ShardIo` across same-shard entries.
pub struct VnodeInit {
    /// Per-validator state machine, already populated with its
    /// `TopologyCoordinator` (the constructor reads `validator_id`
    /// and `local_shard` from there).
    pub state: NodeStateMachine,
    /// BLS signing key for this validator's votes and proposals.
    /// Shared with the validator-bind service (production) by `Arc`
    /// so the key has exactly one allocation regardless of how many
    /// off-thread consumers hold it.
    pub signing_key: Arc<Bls12381G1PrivateKey>,
}

/// Per-validator bundle hosted by the `IoLoop`.
pub struct Vnode {
    /// This validator's network identity.
    pub validator_id: ValidatorId,

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
