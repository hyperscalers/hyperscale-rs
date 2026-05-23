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

use sbor::prelude::BasicSbor;

use crate::{BlockHeight, Bls12381G2Signature, ValidatorId};

/// Validator-emitted attestation that they're synced and ready to sign
/// on their shard.
///
/// The signed message binds `(chain_id, validator_id, height_window)`
/// so the signal can't be replayed across chains and can't be hoarded
/// past its `[start, end]` window. Window enforcement is the
/// proposer/voter's job; the type itself just carries the parameters.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ReadySignal {
    /// Validator emitting the signal.
    validator_id: ValidatorId,
    /// First block height at which the signal is eligible for
    /// inclusion.
    height_window_start: BlockHeight,
    /// Last block height at which the signal is eligible for
    /// inclusion. `end - start` must not exceed
    /// [`MAX_READY_WINDOW_BLOCKS`](crate::MAX_READY_WINDOW_BLOCKS);
    /// validators re-emit if the window passes uncollected.
    height_window_end: BlockHeight,
    /// BLS sig over [`crate::signing::ready_signal_message`].
    sig: Bls12381G2Signature,
}

impl ReadySignal {
    /// Build a `ReadySignal` from its parts.
    #[must_use]
    pub const fn new(
        validator_id: ValidatorId,
        height_window_start: BlockHeight,
        height_window_end: BlockHeight,
        sig: Bls12381G2Signature,
    ) -> Self {
        Self {
            validator_id,
            height_window_start,
            height_window_end,
            sig,
        }
    }

    /// Validator emitting the signal.
    #[must_use]
    pub const fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    /// First eligible inclusion height.
    #[must_use]
    pub const fn height_window_start(&self) -> BlockHeight {
        self.height_window_start
    }

    /// Last eligible inclusion height.
    #[must_use]
    pub const fn height_window_end(&self) -> BlockHeight {
        self.height_window_end
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
            BlockHeight::new(100),
            BlockHeight::new(228),
            Bls12381G2Signature([0xAB; 96]),
        );
        let bytes = basic_encode(&signal).unwrap();
        let decoded: ReadySignal = basic_decode(&bytes).unwrap();
        assert_eq!(signal, decoded);
    }

    #[test]
    fn accessors_return_constructor_values() {
        let signal = ReadySignal::new(
            ValidatorId::new(3),
            BlockHeight::new(50),
            BlockHeight::new(99),
            Bls12381G2Signature([0xCD; 96]),
        );
        assert_eq!(signal.validator_id(), ValidatorId::new(3));
        assert_eq!(signal.height_window_start(), BlockHeight::new(50));
        assert_eq!(signal.height_window_end(), BlockHeight::new(99));
        assert_eq!(signal.sig(), Bls12381G2Signature([0xCD; 96]));
    }
}
