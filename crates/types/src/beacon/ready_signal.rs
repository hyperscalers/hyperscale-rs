//! Validator-emitted "ready on shard" signal.
//!
//! A newly-placed validator broadcasts a [`ReadySignal`] when they've
//! finished syncing their shard's state. Other committee members hold
//! valid signals in a local pool; the next proposer drains
//! dwell-eligible signals into the block they produce, and beacon's
//! `Ready` witness flips the validator's status from
//! `OnShard { ready: false }` to `OnShard { ready: true }` once the
//! shard's beacon-witness accumulator surfaces it.
//!
//! The signal is BLS-signed over canonical bytes whose layout lives in
//! [`crate::signing::ready_signal_message`].

use std::time::Duration;

use sbor::prelude::BasicSbor;

use crate::{Bls12381G2Signature, ShardId, ValidatorId, WeightedTimestamp};

/// The weighted-time span a [`ReadySignal`]'s `[start, end]` validity
/// window covers, scaled to the running network's `epoch_duration_ms`.
///
/// Sized at two epochs. A signal folds into the beacon at an epoch
/// boundary, and the anchor it opens its window from can itself be up to
/// a full epoch old (boundary records refresh once per epoch), so two
/// epochs leaves roughly one epoch of effective budget for the signal to
/// commit on its shard and fold — enough with margin, yet tight enough to
/// bound how long a proposer can hoard a departed validator's signal.
/// Scaling with the configured epoch keeps that bound at two epochs
/// whatever the epoch is set to, so it stays invariant to block rate and
/// latency — the property a fixed block-count window lacked. A signal
/// that expires uncollected is re-emitted against a fresher anchor.
#[must_use]
pub const fn ready_signal_window(epoch_duration_ms: u64) -> Duration {
    Duration::from_millis(epoch_duration_ms.saturating_mul(2))
}

/// Validator-emitted attestation that they're synced and ready to sign
/// on a specific shard.
///
/// The signed message binds `(network.id, validator_id, shard, wt_window)`
/// so the signal can't be replayed across networks and can't be hoarded
/// past its `[start, end]` weighted-time window. The `shard` binding names
/// the shard whose state the emitter attests it has synced — its own shard
/// for an ordinary member, the pending child for a split observer, the
/// child it runs for a merge keeper. The beacon fold credits the readiness
/// only to a seat whose target matches `shard`, so a signal retained across
/// a reshape lapse cannot mark a seat the emitter never synced. Window
/// enforcement is the proposer/voter's job; the type itself just carries
/// the parameters.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ReadySignal {
    /// Validator emitting the signal.
    validator_id: ValidatorId,
    /// Shard whose synced state the signal attests readiness for.
    shard: ShardId,
    /// First weighted timestamp at which the signal is eligible for
    /// inclusion — a block whose parent-QC `weighted_timestamp` falls in
    /// `[start, end]` may carry it.
    wt_window_start: WeightedTimestamp,
    /// Last weighted timestamp at which the signal is eligible for
    /// inclusion. The emitter sizes `end - start` via
    /// [`ready_signal_window`]; validators re-emit if the window passes
    /// uncollected.
    wt_window_end: WeightedTimestamp,
    /// BLS sig over [`crate::signing::ready_signal_message`].
    sig: Bls12381G2Signature,
}

impl ReadySignal {
    /// Build a `ReadySignal` from its parts.
    #[must_use]
    pub const fn new(
        validator_id: ValidatorId,
        shard: ShardId,
        wt_window_start: WeightedTimestamp,
        wt_window_end: WeightedTimestamp,
        sig: Bls12381G2Signature,
    ) -> Self {
        Self {
            validator_id,
            shard,
            wt_window_start,
            wt_window_end,
            sig,
        }
    }

    /// Validator emitting the signal.
    #[must_use]
    pub const fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    /// Shard whose synced state the signal attests readiness for.
    #[must_use]
    pub const fn shard(&self) -> ShardId {
        self.shard
    }

    /// First eligible inclusion weighted timestamp.
    #[must_use]
    pub const fn wt_window_start(&self) -> WeightedTimestamp {
        self.wt_window_start
    }

    /// Last eligible inclusion weighted timestamp.
    #[must_use]
    pub const fn wt_window_end(&self) -> WeightedTimestamp {
        self.wt_window_end
    }

    /// BLS signature over the canonical signing bytes.
    #[must_use]
    pub const fn sig(&self) -> Bls12381G2Signature {
        self.sig
    }
}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;

    #[test]
    fn sbor_round_trip() {
        let signal = ReadySignal::new(
            ValidatorId::new(7),
            ShardId::ROOT,
            WeightedTimestamp::from_millis(100),
            WeightedTimestamp::from_millis(228),
            Bls12381G2Signature([0xAB; 96]),
        );
        let bytes = basic_encode(&signal).unwrap();
        let decoded: ReadySignal = basic_decode(&bytes).unwrap();
        assert_eq!(signal, decoded);
    }

    #[test]
    fn accessors_return_constructor_values() {
        let shard = ShardId::ROOT.children().0;
        let signal = ReadySignal::new(
            ValidatorId::new(3),
            shard,
            WeightedTimestamp::from_millis(50),
            WeightedTimestamp::from_millis(99),
            Bls12381G2Signature([0xCD; 96]),
        );
        assert_eq!(signal.validator_id(), ValidatorId::new(3));
        assert_eq!(signal.shard(), shard);
        assert_eq!(signal.wt_window_start(), WeightedTimestamp::from_millis(50));
        assert_eq!(signal.wt_window_end(), WeightedTimestamp::from_millis(99));
        assert_eq!(signal.sig(), Bls12381G2Signature([0xCD; 96]));
    }
}
