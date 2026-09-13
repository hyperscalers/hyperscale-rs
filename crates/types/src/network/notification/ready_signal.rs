//! Validator-emitted "ready on shard" signal notification.

use hyperscale_hbor::Hbor;

use crate::{MessageClass, NetworkMessage, ReadySignal};

/// Fire-and-forget broadcast of a [`ReadySignal`] from the emitting
/// validator to every member of their shard committee.
///
/// Recipients validate the signal (signature + window) and pool it
/// locally; the next proposer drains dwell-eligible signals into the
/// block's
/// [`WitnessSources::ready_signals`](crate::WitnessSources::ready_signals).
/// Beacon's `Ready` witness derives one entry per included signal.
///
/// Fan-out is shard-committee-wide rather than proposer-only so a
/// single Byzantine proposer can't suppress a validator's readiness
/// indefinitely — the next honest proposer already holds the signal.
/// Senders re-emit if their window passes uncollected.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct ReadySignalNotification {
    /// The signal being submitted. Carries its own validator id +
    /// height window + signature.
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
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::{ConsensusSignature, ShardId, ValidatorId, WeightedTimestamp};

    fn sample_signal() -> ReadySignal {
        ReadySignal::new(
            ValidatorId::new(11),
            ShardId::ROOT,
            WeightedTimestamp::from_millis(100),
            WeightedTimestamp::from_millis(228),
            ConsensusSignature::new([0x42; 96]),
        )
    }

    #[test]
    fn hbor_round_trip() {
        let n = ReadySignalNotification::new(sample_signal());
        let bytes = hbor_to_vec(&n).unwrap();
        let decoded: ReadySignalNotification = hbor_from_slice(&bytes).unwrap();
        assert_eq!(n, decoded);
    }

    #[test]
    fn class_is_consensus() {
        assert_eq!(ReadySignalNotification::class(), MessageClass::Consensus);
    }
}
