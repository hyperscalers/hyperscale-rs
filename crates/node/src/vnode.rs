//! Per-validator bundle hosted by the `IoLoop`.
//!
//! One [`Vnode`] per validator identity, owned by a [`ShardGroup`] in
//! the `IoLoop`'s `shards` map. Same-shard vnodes share the enclosing
//! `ShardGroup`'s `ShardIo`; cross-shard vnodes live in different
//! groups. The vnode's shard is implied by which group it lives in —
//! no denormalized field.
//!
//! Per-step scratch (emitted statuses, action counter, timer ops)
//! lives on the `IoLoop`, not here — those buffers are step-local
//! and carry the emitting vnode's `(shard, idx)` via the existing
//! action-dispatch threading.
//!
//! [`ShardGroup`]: crate::io_loop::ShardGroup

use std::sync::Arc;

use hyperscale_types::{Bls12381G1PrivateKey, ValidatorId};

use crate::NodeStateMachine;

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
}
