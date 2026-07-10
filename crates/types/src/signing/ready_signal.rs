//! Domain-separated signing for validator "ready on shard" signals.

use crate::{NetworkDefinition, ShardId, ValidatorId, WeightedTimestamp};

/// Domain tag for validator "ready on shard" signals.
///
/// Format: `HYPERSCALE_READY_SIGNAL_v1` || `network.id` || `validator_id` ||
/// `shard` || `wt_window_start` || `wt_window_end`
///
/// Signed by the validator and broadcast to their shard committee. The
/// `shard` binding names the shard whose synced state the signal attests,
/// so a signal from a validator's prior reshape seat cannot be re-credited
/// to a seat on a different shard. The proposer includes valid dwell-eligible
/// signals in the next block's manifest; verifiers re-derive these bytes to
/// check the BLS sig before admitting the signal to their local pool. The
/// weighted-time window bounds replay surface — a signal hoarded past `end`
/// no longer validates.
pub const DOMAIN_READY_SIGNAL: &[u8] = b"HYPERSCALE_READY_SIGNAL_v1";

/// Build the canonical signing bytes for a
/// [`ReadySignal`](crate::ReadySignal).
#[must_use]
pub fn ready_signal_message(
    network: &NetworkDefinition,
    validator_id: ValidatorId,
    shard: ShardId,
    wt_window_start: WeightedTimestamp,
    wt_window_end: WeightedTimestamp,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(DOMAIN_READY_SIGNAL.len() + 1 + 8 + 8 + 8 + 8);
    message.extend_from_slice(DOMAIN_READY_SIGNAL);
    message.push(network.id);
    message.extend_from_slice(&validator_id.to_le_bytes());
    message.extend_from_slice(&shard.to_le_bytes());
    message.extend_from_slice(&wt_window_start.as_millis().to_le_bytes());
    message.extend_from_slice(&wt_window_end.as_millis().to_le_bytes());
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    #[test]
    fn ready_signal_message_byte_layout_is_pinned() {
        let network = net();
        let validator = ValidatorId::new(0x0123_4567_89AB_CDEF);
        let shard = ShardId::ROOT.children().1;
        let start = WeightedTimestamp::from_millis(100);
        let end = WeightedTimestamp::from_millis(228);

        let msg = ready_signal_message(&network, validator, shard, start, end);
        let mut expected = Vec::with_capacity(DOMAIN_READY_SIGNAL.len() + 1 + 8 + 8 + 8 + 8);
        expected.extend_from_slice(DOMAIN_READY_SIGNAL);
        expected.push(network.id);
        expected.extend_from_slice(&validator.to_le_bytes());
        expected.extend_from_slice(&shard.to_le_bytes());
        expected.extend_from_slice(&start.as_millis().to_le_bytes());
        expected.extend_from_slice(&end.as_millis().to_le_bytes());

        assert_eq!(msg, expected);
        assert_eq!(msg.len(), DOMAIN_READY_SIGNAL.len() + 1 + 8 + 8 + 8 + 8);
    }

    #[test]
    fn ready_signal_message_differs_by_window() {
        let validator = ValidatorId::new(7);
        let shard = ShardId::ROOT;
        let a = ready_signal_message(
            &net(),
            validator,
            shard,
            WeightedTimestamp::from_millis(0),
            WeightedTimestamp::from_millis(1),
        );
        let b = ready_signal_message(
            &net(),
            validator,
            shard,
            WeightedTimestamp::from_millis(0),
            WeightedTimestamp::from_millis(2),
        );
        assert_ne!(a, b);
    }

    #[test]
    fn ready_signal_message_differs_by_shard() {
        let validator = ValidatorId::new(7);
        let (left, right) = ShardId::ROOT.children();
        let start = WeightedTimestamp::from_millis(0);
        let end = WeightedTimestamp::from_millis(1);
        let a = ready_signal_message(&net(), validator, left, start, end);
        let b = ready_signal_message(&net(), validator, right, start, end);
        assert_ne!(a, b);
    }
}
