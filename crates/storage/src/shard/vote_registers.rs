//! Durable safe-vote registers.

use hyperscale_types::{SafeVoteRegisters, ValidatorId};

/// Durable per-validator safe-vote registers.
///
/// A vote or timeout signature may leave the process only after the
/// registers it advanced are durable, so a validator that crashes and
/// restarts can never sign again at a position it already consumed.
/// Implementations must uphold:
///
/// - **Durable on return.** `persist_safe_vote_registers` returns only
///   once the record survives a process crash (production fsyncs; the
///   in-memory backend's records live exactly as long as the store
///   handle, which is what a simulated restart preserves).
/// - **Monotone.** Writes merge field-wise-max into the stored record,
///   so out-of-order calls from concurrent signers cannot regress it,
///   and a write that raises nothing is a no-op.
/// - **Bound to the chain incarnation.** Records are tagged with the
///   store's chain origin at write time and ignored by reads when the
///   tag no longer matches — a store seeded from a parent shard's
///   checkpoint carries the parent's records, and rounds on the child
///   chain are unrelated to the parent's.
///
/// All methods take `&self`; implementations use interior mutability.
pub trait SafeVoteRegisterStore: Send + Sync {
    /// Merge `registers` into `validator`'s durable record (field-wise
    /// max) and return once the result is durable.
    fn persist_safe_vote_registers(&self, validator: ValidatorId, registers: SafeVoteRegisters);

    /// The durable record for `validator`, or `None` when none exists
    /// or the stored record belongs to a different chain incarnation.
    fn safe_vote_registers(&self, validator: ValidatorId) -> Option<SafeVoteRegisters>;
}
