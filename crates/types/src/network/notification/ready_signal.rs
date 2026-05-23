//! Validator-emitted "ready on shard" signal notification.

use sbor::prelude::BasicSbor;

use crate::{MessageClass, NetworkMessage, ReadySignal};

/// Fire-and-forget broadcast of a [`ReadySignal`] from the emitting
/// validator to every member of their shard committee.
///
/// Recipients validate the signal (BLS sig + window) and pool it
/// locally; the next proposer drains dwell-eligible signals into the
/// block's
/// [`BlockManifest::ready_signals`](crate::BlockManifest::ready_signals).
/// Beacon's `Ready` witness derives one entry per included signal.
///
/// Fan-out is shard-committee-wide rather than proposer-only so a
/// single Byzantine proposer can't suppress a validator's readiness
/// indefinitely — the next honest proposer already holds the signal.
/// Senders re-emit if their window passes uncollected.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ReadySignalNotification {
    /// The signal being submitted. Carries its own validator id +
    /// height window + BLS sig.
    pub signal: ReadySignal,
}

impl ReadySignalNotification {
    /// Build a notification wrapping `signal`.
    #[must_use]
    pub const fn new(signal: ReadySignal) -> Self {
        Self { signal }
    }
}

impl NetworkMessage for ReadySignalNotification {
    fn message_type_id() -> &'static str {
        "beacon.ready_signal"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

#[cfg(test)]
mod tests {
    use sbor::{basic_decode, basic_encode};

    use super::*;
    use crate::{BlockHeight, Bls12381G2Signature, ValidatorId};

    fn sample_signal() -> ReadySignal {
        ReadySignal::new(
            ValidatorId::new(11),
            BlockHeight::new(100),
            BlockHeight::new(228),
            Bls12381G2Signature([0x42; 96]),
        )
    }

    #[test]
    fn sbor_round_trip() {
        let n = ReadySignalNotification::new(sample_signal());
        let bytes = basic_encode(&n).unwrap();
        let decoded: ReadySignalNotification = basic_decode(&bytes).unwrap();
        assert_eq!(n, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(ReadySignalNotification::class(), MessageClass::Consensus);
    }
}
