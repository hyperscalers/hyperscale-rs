//! Event queue with deterministic ordering.

use crate::NodeIndex;
use hyperscale_core::{EventPriority, NodeInput};
use std::cmp::Ordering;
use std::time::Duration;

/// Key for ordering events in the queue.
///
/// Events are ordered by:
/// 1. Time (earlier first)
/// 2. Priority (internal before network before client)
/// 3. Node index (deterministic ordering)
/// 4. Sequence number (FIFO for same time/priority/node)
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct EventKey {
    /// When this event should be processed.
    pub time: Duration,
    /// Priority for ordering at same time.
    pub priority: EventPriority,
    /// Which node receives this event.
    pub node_index: NodeIndex,
    /// Sequence number for deterministic FIFO ordering.
    pub sequence: u64,
}

impl EventKey {
    /// Create a new event key from a [`NodeInput`].
    pub fn new(time: Duration, event: &NodeInput, node_index: NodeIndex, sequence: u64) -> Self {
        Self {
            time,
            priority: event.priority(),
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

        // Then by node index (deterministic ordering)
        match self.node_index.cmp(&other.node_index) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // Finally by sequence (FIFO)
        self.sequence.cmp(&other.sequence)
    }
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
    fn test_event_key_ordering() {
        let earlier = EventKey {
            time: Duration::from_secs(1),
            priority: EventPriority::Network,
            node_index: 0,
            sequence: 1,
        };
        let later = EventKey {
            time: Duration::from_secs(2),
            priority: EventPriority::Network,
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
            node_index: 0,
            sequence: 2, // Higher sequence, but should still be first
        };
        let network = EventKey {
            time: Duration::from_secs(1),
            priority: EventPriority::Network,
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
            node_index: 0,
            sequence: 2,
        };
        let node1 = EventKey {
            time: Duration::from_secs(1),
            priority: EventPriority::Network,
            node_index: 1,
            sequence: 1,
        };
        assert!(node0 < node1, "Lower node index should process first");
    }
}
