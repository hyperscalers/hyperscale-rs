//! Durable ratification registers.

use hyperscale_types::{
    BeaconBlockHash, Epoch, RatifyPhase, RatifyRound, RatifyVoteRecord, ValidatorId,
};

/// Durable per-validator ratification registers.
///
/// A ratify-vote signature may leave the process only after the
/// `(round, phase)` slot it consumes is durable, so a crashed and
/// restarted pool member can never double-vote a round — and its lock
/// (the highest precommit) survives, so it keeps re-prevoting the
/// locked value instead of freeing itself for a competing one.
/// Implementations must uphold:
///
/// - **Durable on return.** `record_ratify_vote` returns only once the
///   record survives a process crash (production fsyncs; the in-memory
///   backend's records live exactly as long as the store handle, which
///   is what a simulated restart preserves).
/// - **Epoch supersede.** A vote for a newer epoch replaces the whole
///   record — ratification is per-epoch state. A vote for an epoch
///   older than the stored record leaves it unchanged: the record
///   never regresses to a superseded epoch.
/// - **First-wins per slot.** A second write to an occupied
///   `(round, phase)` slot changes nothing and is a no-op (no fsync).
///
/// All methods take `&self`; implementations use interior mutability.
pub trait RatifyRegisterStore: Send + Sync {
    /// Record that `validator` signs `block_hash` at
    /// `(epoch, round, phase)` and return once the record is durable.
    fn record_ratify_vote(
        &self,
        validator: ValidatorId,
        epoch: Epoch,
        round: RatifyRound,
        phase: RatifyPhase,
        block_hash: BeaconBlockHash,
    );

    /// The durable record for `validator`, or `None` when it has never
    /// signed a ratify vote on this store.
    fn ratify_record(&self, validator: ValidatorId) -> Option<RatifyVoteRecord>;
}
