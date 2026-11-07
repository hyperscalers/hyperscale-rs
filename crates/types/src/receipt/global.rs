//! The executing shard's signed receipt (Tier 1).

use hyperscale_hbor::Hbor;

use crate::{BeaconWitnessRoot, EffectsDigest, EventRoot, GlobalReceiptHash, Hash, WritesRoot};

/// The receipt an executing shard signs over: one shard's attestation of
/// what it ran of a transaction.
///
/// Every term but one is this shard's. `writes_root` commits to the
/// writes this shard attests — for a batch with cross-shard members the
/// delta is projected to the executing shard before the root is taken,
/// and the fee burn lands only on the payer's side — `event_root` to the
/// events its own emitters produced, `beacon_witness_root` to the beacon
/// facts lifted from them, and `success` to whether what it ran
/// committed. So the participants in one transaction produce per-shard
/// hashes, and a shard running only its own legs of a transaction could
/// attest nothing wider.
///
/// `effects` is the term every participant of a shared member derives
/// alike: the digest of the whole run, which a counterpart can hold this
/// shard to. [`EffectsDigest::ZERO`] for a member nobody shares.
///
/// This hash is what validators sign over in execution votes.
/// Ephemeral — never written to storage, only lives for EC aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Hbor)]
pub struct GlobalReceipt {
    success: bool,
    event_root: EventRoot,
    beacon_witness_root: BeaconWitnessRoot,
    writes_root: WritesRoot,
    effects: EffectsDigest,
}

impl GlobalReceipt {
    /// Build a `GlobalReceipt` from its parts.
    #[must_use]
    pub const fn new(
        success: bool,
        event_root: EventRoot,
        beacon_witness_root: BeaconWitnessRoot,
        writes_root: WritesRoot,
        effects: EffectsDigest,
    ) -> Self {
        Self {
            success,
            event_root,
            beacon_witness_root,
            writes_root,
            effects,
        }
    }

    /// Whether the legs this shard ran committed (`true`) or were
    /// rejected (`false`).
    ///
    /// One shard's fact, never the transaction's verdict: a shard
    /// reporting `true` for a transaction its core refused is stating
    /// what it ran, not disagreeing. The transaction-level answer is the
    /// tick's verdict over every participant's outcome.
    #[must_use]
    pub const fn success(&self) -> bool {
        self.success
    }

    /// Merkle root of the events this shard's own emitters produced.
    #[must_use]
    pub const fn event_root(&self) -> EventRoot {
        self.event_root
    }

    /// Merkle root over the beacon-witness events this shard's receipt
    /// carries: the facts lifted from its own emitters' events.
    ///
    /// Folded into [`Self::receipt_hash`] so a receipt cannot gain or
    /// lose a fact under one signed hash. `BeaconWitnessRoot::ZERO` for
    /// a receipt carrying none.
    #[must_use]
    pub const fn beacon_witness_root(&self) -> BeaconWitnessRoot {
        self.beacon_witness_root
    }

    /// Commitment over the writes this shard attests: the hash of the
    /// canonical `StateWrites` encoding. Projected to the executing
    /// shard for any batch with cross-shard members; a whole-locality
    /// batch commits the full fold.
    #[must_use]
    pub const fn writes_root(&self) -> WritesRoot {
        self.writes_root
    }

    /// The whole run's digest where a counterpart shares the member's
    /// verdict, and [`EffectsDigest::ZERO`] otherwise.
    #[must_use]
    pub const fn effects(&self) -> EffectsDigest {
        self.effects
    }

    /// Compute the global receipt hash.
    ///
    /// This is the value signed over in execution votes and stored on certificates.
    #[must_use]
    pub fn receipt_hash(&self) -> GlobalReceiptHash {
        let outcome_byte = if self.success { [1u8] } else { [0u8] };
        GlobalReceiptHash::from_raw(Hash::from_parts(&[
            &outcome_byte,
            self.event_root.as_raw().as_bytes(),
            self.beacon_witness_root.as_raw().as_bytes(),
            self.writes_root.as_raw().as_bytes(),
            self.effects.as_raw().as_bytes(),
        ]))
    }
}
