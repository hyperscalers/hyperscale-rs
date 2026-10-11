//! The executing shard's signed receipt (Tier 1).

use hyperscale_hbor::Hbor;

use crate::{BeaconWitnessRoot, EventRoot, GlobalReceiptHash, Hash, WritesRoot};

/// The receipt an executing shard signs over: one shard's attestation of
/// what it ran of a transaction.
///
/// Every term is this shard's. `writes_root` commits to the writes this
/// shard attests — for a batch with cross-shard members the delta is
/// projected to the executing shard before the root is taken, and the
/// fee burn lands only on the payer's side — `event_root` to the events
/// its own emitters produced, `beacon_witness_root` to the beacon facts
/// lifted from them, and `success` to whether what it ran committed. So
/// the participants in one transaction produce per-shard hashes;
/// agreement across shards is outcome-level in the certificates, never
/// hash equality. A shard running only its own legs
/// of a transaction could attest nothing wider.
///
/// This hash is what validators sign over in execution votes.
/// Ephemeral — never written to storage, only lives for EC aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Hbor)]
pub struct GlobalReceipt {
    success: bool,
    event_root: EventRoot,
    beacon_witness_root: BeaconWitnessRoot,
    writes_root: WritesRoot,
}

impl GlobalReceipt {
    /// Build a `GlobalReceipt` from its parts.
    #[must_use]
    pub const fn new(
        success: bool,
        event_root: EventRoot,
        beacon_witness_root: BeaconWitnessRoot,
        writes_root: WritesRoot,
    ) -> Self {
        Self {
            success,
            event_root,
            beacon_witness_root,
            writes_root,
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
        ]))
    }
}
