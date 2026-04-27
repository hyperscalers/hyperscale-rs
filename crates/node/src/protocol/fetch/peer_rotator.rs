//! Per-peer rotation with exponential backoff.
//!
//! Walks a peer list, marking each as tried after dispatch. When every peer
//! has been tried, advances a [`RetryClock`] round to delay the next sweep.

use super::retry_clock::RetryClock;
use hyperscale_types::ValidatorId;
use std::collections::HashSet;
use std::time::Instant;

/// Rotation state for a single fetch entry.
#[derive(Debug)]
pub struct PeerRotator {
    peers: Vec<ValidatorId>,
    tried: HashSet<ValidatorId>,
    retry: RetryClock,
}

impl PeerRotator {
    /// Build a rotator over `peers`. The first untried peer is always
    /// returned first.
    #[must_use]
    pub fn new(peers: Vec<ValidatorId>) -> Self {
        Self {
            peers,
            tried: HashSet::new(),
            retry: RetryClock::new(),
        }
    }

    /// Replace the peer list and reset rotation state. Used when a duplicate
    /// request brings in a fresh peer pool.
    pub fn refresh(&mut self, peers: Vec<ValidatorId>) {
        self.peers = peers;
        self.tried.clear();
        self.retry.reset();
    }

    /// Pick the next peer to try at `now`. Returns `None` if a backoff is
    /// active or every peer in the current round has been tried (in the
    /// latter case the round is advanced and the caller retries on the next
    /// tick).
    pub fn next(&mut self, now: Instant) -> Option<ValidatorId> {
        if !self.retry.is_ready(now) {
            return None;
        }

        let peer = self.peers.iter().find(|p| !self.tried.contains(p)).copied();

        if let Some(p) = peer {
            self.tried.insert(p);
            Some(p)
        } else {
            self.retry.advance_round(now);
            self.tried.clear();
            None
        }
    }

    #[cfg(test)]
    const fn peer_count(&self) -> usize {
        self.peers.len()
    }

    #[cfg(test)]
    const fn rounds(&self) -> u32 {
        self.retry.rounds()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn vid(n: u64) -> ValidatorId {
        ValidatorId(n)
    }

    #[test]
    fn next_walks_peer_list_in_order() {
        let mut rot = PeerRotator::new(vec![vid(1), vid(2), vid(3)]);
        let t = Instant::now();
        assert_eq!(rot.next(t), Some(vid(1)));
        assert_eq!(rot.next(t), Some(vid(2)));
        assert_eq!(rot.next(t), Some(vid(3)));
    }

    #[test]
    fn next_advances_round_when_all_tried() {
        let mut rot = PeerRotator::new(vec![vid(1)]);
        let t0 = Instant::now();

        assert_eq!(rot.next(t0), Some(vid(1)));
        assert!(rot.next(t0).is_none());
        assert_eq!(rot.rounds(), 1);

        assert!(rot.next(t0 + Duration::from_millis(500)).is_none());
        assert_eq!(rot.next(t0 + Duration::from_secs(1)), Some(vid(1)));
    }

    #[test]
    fn refresh_resets_rotation_and_backoff() {
        let mut rot = PeerRotator::new(vec![vid(1)]);
        let t0 = Instant::now();
        rot.next(t0);
        rot.next(t0);
        assert_eq!(rot.rounds(), 1);

        rot.refresh(vec![vid(2), vid(3)]);
        assert_eq!(rot.rounds(), 0);
        assert_eq!(rot.peer_count(), 2);
        assert_eq!(rot.next(t0), Some(vid(2)));
    }

    #[test]
    fn empty_peer_list_only_advances_rounds() {
        let mut rot = PeerRotator::new(vec![]);
        let t0 = Instant::now();
        assert!(rot.next(t0).is_none());
        assert_eq!(rot.rounds(), 1);
    }
}
