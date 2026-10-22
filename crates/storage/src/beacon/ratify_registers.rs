//! Durable ratification registers.

use hyperscale_types::{
    BeaconBlockHash, Epoch, RatifyPhase, RatifyPolka, RatifyRound, RatifyVoteRecord, ValidatorId,
};

/// Durable per-validator ratification registers.
///
/// A ratify-vote signature may leave the process only after the
/// `(round, phase)` slot it consumes is durable, so a crashed and
/// restarted pool member can never double-vote a round — and its lock
/// (the highest precommit) survives, so it keeps re-prevoting the
/// locked value instead of freeing itself for a competing one, with
/// the polka it locked on to prove it.
/// Implementations must uphold:
///
/// - **Durable on return.** `admit_ratify_vote` returns only once the
///   record survives a process crash (production fsyncs; the in-memory
///   backend's records live exactly as long as the store handle, which
///   is what a simulated restart preserves).
/// - **Epoch supersede.** A vote for a newer epoch replaces the whole
///   record — ratification is per-epoch state. A vote for an epoch
///   older than the stored record is refused and leaves it unchanged:
///   the record never regresses to a superseded epoch.
/// - **One value per slot.** A vote at an occupied `(round, phase)`
///   slot is admitted only for the value the slot holds, and changes
///   nothing (no fsync); any other value is refused.
/// - **One guard.** The check and the write happen under one guard, so
///   two concurrent signers for one validator cannot both admit
///   different values at one slot.
/// - **The lock's polka.** A precommit that becomes the record's
///   highest replaces the stored polka with its own, in the same
///   durable write as its slot.
///
/// All methods take `&self`; implementations use interior mutability.
pub trait RatifyRegisterStore: Send + Sync {
    /// Admit `validator` signing `block_hash` at `(epoch, round, phase)`
    /// — a precommit with `polka`, the prevote quorum it locks on — and
    /// return `true` once the record is durable, or `false` when the
    /// signature would contradict it ([`RatifyVoteRecord::admit`]).
    #[must_use]
    fn admit_ratify_vote(
        &self,
        validator: ValidatorId,
        epoch: Epoch,
        round: RatifyRound,
        phase: RatifyPhase,
        block_hash: BeaconBlockHash,
        polka: RatifyPolka,
    ) -> bool;

    /// The durable record for `validator`, or `None` when it has never
    /// signed a ratify vote on this store.
    fn ratify_record(&self, validator: ValidatorId) -> Option<RatifyVoteRecord>;
}
