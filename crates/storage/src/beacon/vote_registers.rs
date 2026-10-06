//! Durable beacon consensus registers.

use hyperscale_types::{BeaconVote, ValidatorId};

/// Durable per-validator registers of the SPC consensus messages a
/// beacon committee member signed.
///
/// They cover the inner-PC votes and empty-view attestations, the
/// messages whose content a restart recomputes from lost memory. A
/// signature for one of them may be created only once
/// [`admit_beacon_vote`](Self::admit_beacon_vote) allows it, so a
/// crashed and restarted member signs nothing that contradicts what it
/// signed before the crash. Implementations must uphold:
///
/// - **The record decides.** The verdict is
///   [`BeaconVoteRecord::admit`](hyperscale_types::BeaconVoteRecord::admit)
///   over the stored record, checked and written under one guard so
///   concurrent signers of one validator never both take a slot.
/// - **Durable before it allows.** A vote that records a fresh slot
///   returns `true` only once the record survives a machine crash
///   (production fsyncs). A repeat of a held slot writes nothing.
///
/// All methods take `&self`; implementations use interior mutability.
pub trait BeaconVoteRegisterStore: Send + Sync {
    /// Whether `validator` may sign `vote`: `true` when its slot is
    /// fresh (now durably recorded) or already holds the same content,
    /// `false` when signing would contradict the record.
    fn admit_beacon_vote(&self, validator: ValidatorId, vote: &BeaconVote) -> bool;
}
