//! Independent random streams for the simulated transport.
//!
//! Every draw the transport makes — loss, jitter, which peer a request
//! asks — comes from a stream owned by the link or requester it concerns,
//! each derived from the run's seed. A message on one link never moves the
//! draws of another, so a change that adds or removes traffic perturbs only
//! the links it touches, and a failure bisected across such a change keeps
//! its schedule everywhere else.

use std::collections::BTreeMap;

use blake3::Hasher as Blake3Hasher;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use crate::NodeIndex;

/// The transport's random streams, one per directed link and one per
/// requester's peer selection, created on first use.
pub struct LinkStreams {
    seed: u64,
    links: BTreeMap<(NodeIndex, NodeIndex), ChaCha8Rng>,
    pickers: BTreeMap<NodeIndex, ChaCha8Rng>,
}

impl LinkStreams {
    /// Streams derived from `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            seed,
            links: BTreeMap::new(),
            pickers: BTreeMap::new(),
        }
    }

    /// The stream for messages sent from `from` to `to`.
    pub(crate) fn link(&mut self, from: NodeIndex, to: NodeIndex) -> &mut ChaCha8Rng {
        let seed = self.seed;
        self.links
            .entry((from, to))
            .or_insert_with(|| derive(seed, b"link", &[from, to]))
    }

    /// The stream `requester` picks request peers from.
    pub(crate) fn picker(&mut self, requester: NodeIndex) -> &mut ChaCha8Rng {
        let seed = self.seed;
        self.pickers
            .entry(requester)
            .or_insert_with(|| derive(seed, b"picker", &[requester]))
    }
}

fn derive(seed: u64, label: &[u8], nodes: &[NodeIndex]) -> ChaCha8Rng {
    let mut hasher = Blake3Hasher::new();
    hasher.update(&seed.to_le_bytes());
    hasher.update(label);
    for node in nodes {
        hasher.update(&node.to_le_bytes());
    }
    ChaCha8Rng::from_seed(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use rand::RngExt;

    use super::*;

    #[test]
    fn a_link_draws_the_same_whatever_other_links_drew() {
        let mut quiet = LinkStreams::new(7);
        let mut busy = LinkStreams::new(7);
        for _ in 0..100 {
            let _: u64 = busy.link(1, 2).random();
        }
        let quiet_draw: u64 = quiet.link(0, 1).random();
        let busy_draw: u64 = busy.link(0, 1).random();
        assert_eq!(quiet_draw, busy_draw);
    }

    #[test]
    fn the_two_directions_of_a_link_are_distinct_streams() {
        let mut streams = LinkStreams::new(7);
        let out: u64 = streams.link(0, 1).random();
        let back: u64 = streams.link(1, 0).random();
        assert_ne!(out, back);
    }
}
