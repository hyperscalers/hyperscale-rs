//! Event queue with deterministic ordering.

use std::cmp::Ordering;
use std::time::Duration;

use hyperscale_dispatch_sync::Job;
use hyperscale_network_memory::NodeIndex;
use hyperscale_node::shard::{EventPriority, HostEvent};

/// What the runner does for a host when its key comes up.
pub enum SimEvent {
    /// Feed the host one of its own events.
    Host(HostEvent),
    /// Flush the host's batches whose deadlines have passed: a production
    /// shard loop sleeps until its nearest batch deadline and flushes what
    /// expired when it wakes.
    BatchDeadline,
    /// Run work the host's deferred dispatcher queued, now that its
    /// processing time has passed.
    Deferred(Job),
    /// Start the host's crashed process again.
    Restart,
}

impl SimEvent {
    pub(crate) fn priority(&self) -> EventPriority {
        match self {
            Self::Host(event) => event.priority(),
            Self::BatchDeadline => EventPriority::Timer,
            Self::Deferred(_) | Self::Restart => EventPriority::Internal,
        }
    }
}

/// Key for ordering events in the queue.
///
/// Events are ordered by:
/// 1. Time (earlier first)
/// 2. Priority (internal before network before client)
/// 3. Tie-break: a seed-drawn order among the hosts due at one instant
/// 4. Node index (a host's events at one instant share a tie-break)
/// 5. Sequence number (FIFO for same time/priority/node)
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct EventKey {
    /// When this event should be processed.
    pub(crate) time: Duration,
    /// Priority for ordering at same time.
    pub(crate) priority: EventPriority,
    /// Where this host falls among the hosts due at `time`: a pure
    /// function of the run's seed, the time and the host, so one host's
    /// events at one instant share it and keep their sequence order.
    tiebreak: u64,
    /// Which node receives this event.
    pub(crate) node_index: NodeIndex,
    /// Sequence number for deterministic FIFO ordering.
    pub(crate) sequence: u64,
}

impl EventKey {
    /// Create a new event key for `event`.
    pub(crate) fn new(
        time: Duration,
        event: &SimEvent,
        node_index: NodeIndex,
        sequence: u64,
        tiebreak_seed: u64,
    ) -> Self {
        Self {
            time,
            priority: event.priority(),
            tiebreak: tiebreak(tiebreak_seed, time, node_index),
            node_index,
            sequence,
        }
    }
}

impl Ord for EventKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Order by time first
        match self.time.cmp(&other.time) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // Then by priority (Internal < Timer < Network < Client)
        match self.priority.cmp(&other.priority) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // Then by the seed-drawn order among hosts due at this instant
        match self.tiebreak.cmp(&other.tiebreak) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // Then by node index (deterministic ordering)
        match self.node_index.cmp(&other.node_index) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // Finally by sequence (FIFO)
        self.sequence.cmp(&other.sequence)
    }
}

/// A host's place among the hosts due at `time`, mixed from the seed.
fn tiebreak(seed: u64, time: Duration, node_index: NodeIndex) -> u64 {
    let nanos = u64::try_from(time.as_nanos()).unwrap_or(u64::MAX);
    splitmix64(seed ^ splitmix64(nanos ^ (u64::from(node_index) << 48)))
}

/// One step of the `SplitMix64` generator: a bijective mix of a `u64`.
const fn splitmix64(value: u64) -> u64 {
    let mut z = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

impl PartialOrd for EventKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_hosts_events_at_an_instant_keep_their_order() {
        let at = Duration::from_millis(1500);
        let key = |host, sequence| EventKey {
            time: at,
            priority: EventPriority::Network,
            tiebreak: tiebreak(7, at, host),
            node_index: host,
            sequence,
        };
        assert!(key(3, 1) < key(3, 2));
    }

    #[test]
    fn the_seed_decides_which_host_runs_first_at_an_instant() {
        let at = Duration::from_millis(1500);
        let first = |seed| tiebreak(seed, at, 0) < tiebreak(seed, at, 1);
        assert!(
            (0..64).any(first) && !(0..64).all(first),
            "some seeds must run host 0 first and some host 1",
        );
    }

    #[test]
    fn test_event_key_ordering() {
        let earlier = EventKey {
            time: Duration::from_secs(1),
            priority: EventPriority::Network,
            tiebreak: 0,
            node_index: 0,
            sequence: 1,
        };
        let later = EventKey {
            time: Duration::from_secs(2),
            priority: EventPriority::Network,
            tiebreak: 0,
            node_index: 0,
            sequence: 2,
        };
        assert!(earlier < later);
    }

    #[test]
    fn test_priority_ordering_at_same_time() {
        let internal = EventKey {
            time: Duration::from_secs(1),
            priority: EventPriority::Internal,
            tiebreak: 0,
            node_index: 0,
            sequence: 2, // Higher sequence, but should still be first
        };
        let network = EventKey {
            time: Duration::from_secs(1),
            priority: EventPriority::Network,
            tiebreak: 0,
            node_index: 0,
            sequence: 1,
        };
        assert!(
            internal < network,
            "Internal events should process before network"
        );
    }

    #[test]
    fn test_node_ordering_at_same_time_and_priority() {
        let node0 = EventKey {
            time: Duration::from_secs(1),
            priority: EventPriority::Network,
            tiebreak: 0,
            node_index: 0,
            sequence: 2,
        };
        let node1 = EventKey {
            time: Duration::from_secs(1),
            priority: EventPriority::Network,
            tiebreak: 0,
            node_index: 1,
            sequence: 1,
        };
        assert!(node0 < node1, "Lower node index should process first");
    }
}
