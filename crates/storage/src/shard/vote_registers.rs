//! Durable safe-vote registers.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_types::{Block, BlockHeight, SafeVoteRegisters, ValidatorId, VotePosition};

/// Durable per-validator safe-vote registers.
///
/// A vote or timeout signature may leave the process only after the
/// registers it advanced are durable, so a validator that crashes and
/// restarts can never sign again at a position it already consumed.
/// Implementations must uphold:
///
/// - **Durable on return.** `persist_vote_position` returns only once
///   the record survives a process crash (production fsyncs; the
///   in-memory backend's records live exactly as long as the store
///   handle, which is what a simulated restart preserves).
/// - **One write.** The registers and the blocks justifying them land
///   together or not at all. A record that outlives its justification
///   describes a lock its holder can never satisfy again.
/// - **Monotone.** Writes merge field-wise-max into the stored record,
///   so out-of-order calls from concurrent signers cannot regress it.
///   A write that raises nothing and stores no new block writes nothing,
///   so a proposer's self-vote after its header costs no second write.
/// - **Bound to the chain incarnation.** Records are tagged with the
///   store's chain origin at write time and ignored by reads when the
///   tag no longer matches — a store seeded from a parent shard's
///   checkpoint carries the parent's records, and rounds on the child
///   chain are unrelated to the parent's.
///
/// All methods take `&self`; implementations use interior mutability.
pub trait SafeVoteRegisterStore: Send + Sync {
    /// Merge `position.registers` into `validator`'s durable record
    /// (field-wise max), store `position.justification` beside it, and
    /// return once both are durable.
    fn persist_vote_position(&self, validator: ValidatorId, position: &VotePosition);

    /// The uncommitted blocks stored beside the registers, above
    /// `committed_height` and in height order. What a restarted
    /// validator needs to extend the certificate its record carries;
    /// everything at or below the committed tip is the chain's own.
    fn voted_blocks_above(&self, committed_height: BlockHeight) -> Vec<Arc<Block>>;

    /// The durable record for `validator`, or `None` when none exists
    /// or the stored record belongs to a different chain incarnation.
    fn safe_vote_registers(&self, validator: ValidatorId) -> Option<SafeVoteRegisters>;

    /// The durable record of every validator that has signed on this
    /// store's chain incarnation.
    fn all_safe_vote_registers(&self) -> BTreeMap<ValidatorId, SafeVoteRegisters>;
}

/// Carry the rounds every validator signed in on `replaced` onto `store`,
/// rebuilt beneath the same chain to take its place.
///
/// A rebuilt store holds the chain as its attested anchor left it and
/// none of what its host signed, while the rounds its validators consumed
/// on the replaced store are still theirs to refuse. Without them a
/// signer attached here signs a second time in a round the chain may not
/// have left, and votes beneath a lock it took.
///
/// Only the two rounds travel. The certificate and the blocks beside a
/// record describe the replaced store's view of the chain, which the
/// anchor supersedes: the lock is satisfied by the certificates the
/// chain's live peers hold, as a snap-synced joiner's is.
///
/// Durable on return, so call it before any signer attached over `store`
/// can sign, and only once nothing signs against `replaced`.
pub fn carry_signed_rounds<R, S>(replaced: &R, store: &S)
where
    R: SafeVoteRegisterStore + ?Sized,
    S: SafeVoteRegisterStore + ?Sized,
{
    for (validator, signed) in replaced.all_safe_vote_registers() {
        let position = VotePosition {
            registers: SafeVoteRegisters {
                locked_round: signed.locked_round,
                last_voted_round: signed.last_voted_round,
                high_qc: None,
                high_tc: None,
            },
            justification: Vec::new(),
        };
        store.persist_vote_position(validator, &position);
    }
}
