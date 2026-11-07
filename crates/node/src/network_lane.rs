//! A hosted shard's network lane: the bounded queue that what peers send
//! unbidden waits on for the shard's driver, and the share of it each peer
//! may hold.
//!
//! A lane full for want of a drain says only that this host is behind, so
//! a refusal then costs the sender nothing. That alone would let one peer
//! fill the lane and keep it full, crowding out every other peer's traffic
//! at no cost to itself. So each peer has a fair share of the lane: its
//! capacity split evenly among the peers using it. A peer refused room
//! while it holds less than its share is crowded out, and while another
//! peer is, no peer at or past its share is given room, so the room a
//! drain frees goes to the crowded. A peer past its share that finds the
//! lane full while another is crowded out is refused as an item this host
//! would not take, which its transport charges it for. Every other refusal
//! of a full lane is for nothing: a lane that fills while no one is
//! crowded out, however its peers split it, is this host's own stall.
//!
//! The peers using a lane are those holding items on it and those that
//! offered one within the last two generations, a generation being the
//! time the driver takes to drain a lane's worth of items. A peer refused
//! for a full lane counts as one of them, so its arrival shrinks the share
//! of a peer already holding the lane. A crowded peer stays crowded until
//! the lane takes an input of its, or it ages out of the record. The
//! record is bounded by the lane's capacity, past which every share would
//! be under one item.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use crossbeam::channel::{Receiver, Sender, TrySendError, bounded, never};
use hyperscale_network::{PeerId, Verdict};

use crate::event::HostEvent;

/// What became of an input offered to a network lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    /// The lane took it.
    Taken,
    /// The lane has no room for the peer: it is full, or what room it has
    /// is kept for a peer crowded out. No one's fault.
    Full,
    /// The lane is full, the peer holds more than its share of it, and
    /// another peer is crowded out.
    OverShare,
}

impl Offer {
    /// The verdict on a message whose input met this offer.
    #[must_use]
    pub const fn verdict(self) -> Verdict {
        match self {
            Self::Taken => Verdict::Accept,
            Self::Full => Verdict::Busy,
            Self::OverShare => Verdict::Ignore,
        }
    }

    /// The verdict on a message whose input met this offer, if it was
    /// refused.
    #[must_use]
    pub const fn refusal(self) -> Option<Verdict> {
        match self {
            Self::Taken => None,
            refused => Some(refused.verdict()),
        }
    }

    /// The offer of one message to two lanes: taken if either took it, and
    /// past the peer's share if either refused it so.
    #[must_use]
    pub const fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Taken, _) | (_, Self::Taken) => Self::Taken,
            (Self::OverShare, _) | (_, Self::OverShare) => Self::OverShare,
            (Self::Full, Self::Full) => Self::Full,
        }
    }
}

/// An input on a network lane, with the peer whose share it counts
/// against.
#[derive(Debug)]
pub struct NetworkInput {
    peer: PeerId,
    event: HostEvent,
}

/// The sending end of a shard's network lane.
#[derive(Debug, Clone)]
pub struct NetworkLane {
    sender: Sender<NetworkInput>,
    occupancy: Arc<Mutex<Occupancy>>,
}

/// The receiving end of a shard's network lane. Each input taken off it
/// leaves its peer's share.
#[derive(Debug)]
pub struct NetworkLaneReceiver {
    receiver: Receiver<NetworkInput>,
    occupancy: Arc<Mutex<Occupancy>>,
}

/// A network lane holding at most `capacity` inputs.
///
/// # Panics
///
/// Panics if `capacity` is zero.
#[must_use]
pub fn network_lane(capacity: usize) -> (NetworkLane, NetworkLaneReceiver) {
    assert!(capacity > 0, "a network lane holds some input");
    let (sender, receiver) = bounded(capacity);
    let occupancy = Arc::new(Mutex::new(Occupancy::new(capacity)));
    (
        NetworkLane {
            sender,
            occupancy: Arc::clone(&occupancy),
        },
        NetworkLaneReceiver {
            receiver,
            occupancy,
        },
    )
}

impl NetworkLane {
    /// Offer `event`, sent by `peer`. A closed lane takes it, dropped.
    #[must_use]
    pub fn offer(&self, event: HostEvent, peer: PeerId) -> Offer {
        let mut occupancy = lock(&self.occupancy);
        let offer = occupancy.admit(peer);
        if offer != Offer::Taken {
            return offer;
        }
        match self.sender.try_send(NetworkInput { peer, event }) {
            Ok(()) => {
                occupancy.hold(peer);
                Offer::Taken
            }
            Err(TrySendError::Disconnected(_)) => Offer::Taken,
            Err(TrySendError::Full(_)) => Offer::Full,
        }
    }

    /// Inputs on the lane `peer` holds.
    #[must_use]
    pub fn held_by(&self, peer: PeerId) -> usize {
        lock(&self.occupancy).peers.get(&peer).map_or(0, |p| p.held)
    }

    /// Inputs on the lane.
    #[must_use]
    pub fn held(&self) -> usize {
        lock(&self.occupancy).held
    }

    /// Peers the lane keeps a share for.
    #[must_use]
    pub fn peers(&self) -> usize {
        lock(&self.occupancy).peers.len()
    }
}

impl NetworkLaneReceiver {
    /// The channel to wait on; what it yields goes through [`Self::take`].
    #[must_use]
    pub const fn receiver(&self) -> &Receiver<NetworkInput> {
        &self.receiver
    }

    /// The event `input` carries, released from its peer's share.
    #[must_use]
    pub fn take(&self, input: NetworkInput) -> HostEvent {
        lock(&self.occupancy).release(input.peer);
        input.event
    }

    /// The next input on the lane, if it holds one.
    #[must_use]
    pub fn try_recv(&self) -> Option<HostEvent> {
        let input = self.receiver.try_recv().ok()?;
        Some(self.take(input))
    }

    /// Every input on the lane now, taken in order.
    pub fn try_iter(&self) -> impl Iterator<Item = HostEvent> + '_ {
        std::iter::from_fn(|| self.try_recv())
    }

    /// Inputs waiting on the lane.
    #[must_use]
    pub fn len(&self) -> usize {
        self.receiver.len()
    }

    /// Whether the lane holds no input.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.receiver.is_empty()
    }

    /// Stop waiting on a lane whose senders are all gone.
    pub fn close(&mut self) {
        self.receiver = never();
    }
}

fn lock(occupancy: &Mutex<Occupancy>) -> MutexGuard<'_, Occupancy> {
    occupancy.lock().expect("network lane occupancy lock")
}

/// What each peer holds of a lane, and which peers are using it.
#[derive(Debug)]
struct Occupancy {
    capacity: usize,
    /// Inputs on the lane, or taken off and not yet released.
    held: usize,
    /// The peers using the lane: at most `capacity` of them.
    peers: HashMap<PeerId, Holding>,
    /// The peers in `peers` that are crowded out.
    crowded: usize,
    /// Inputs released in the current generation.
    released: usize,
    generation: u64,
}

#[derive(Debug)]
struct Holding {
    held: usize,
    /// The generation of the peer's latest offer.
    offered_in: u64,
    /// Refused room while it held less than its share, and given none
    /// since.
    crowded: bool,
}

impl Occupancy {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            held: 0,
            peers: HashMap::new(),
            crowded: 0,
            released: 0,
            generation: 0,
        }
    }

    /// Whether the lane has room for one more input from `peer`, noting
    /// that `peer` is using it.
    fn admit(&mut self, peer: PeerId) -> Offer {
        let known = self.peers.contains_key(&peer);
        if !known && self.peers.len() >= self.capacity {
            // Every share is under one input already; a peer the lane has
            // no record for waits for one as for room.
            return Offer::Full;
        }
        let users = self.peers.len() + usize::from(!known);
        let share = (self.capacity / users).max(1);
        let full = self.held >= self.capacity;
        let generation = self.generation;
        let holding = self.peers.entry(peer).or_insert(Holding {
            held: 0,
            offered_in: generation,
            crowded: false,
        });
        holding.offered_in = generation;
        let others_crowded = self.crowded > usize::from(holding.crowded);
        if others_crowded && holding.held >= share {
            if full && holding.held > share {
                return Offer::OverShare;
            }
            return Offer::Full;
        }
        if full {
            if holding.held < share && !holding.crowded {
                holding.crowded = true;
                self.crowded += 1;
            }
            return Offer::Full;
        }
        Offer::Taken
    }

    fn hold(&mut self, peer: PeerId) {
        self.held += 1;
        if let Some(holding) = self.peers.get_mut(&peer) {
            holding.held += 1;
            if holding.crowded {
                holding.crowded = false;
                self.crowded -= 1;
            }
        }
    }

    /// Release an input of `peer`'s, and once a lane's worth have been
    /// released, begin a generation, forgetting the peers that neither
    /// hold an input nor offered one in the generation that ended.
    fn release(&mut self, peer: PeerId) {
        self.held = self.held.saturating_sub(1);
        if let Some(holding) = self.peers.get_mut(&peer) {
            holding.held = holding.held.saturating_sub(1);
        }
        self.released += 1;
        if self.released < self.capacity {
            return;
        }
        self.released = 0;
        self.generation += 1;
        let previous = self.generation - 1;
        self.peers
            .retain(|_, holding| holding.held > 0 || holding.offered_in >= previous);
        self.crowded = self
            .peers
            .values()
            .filter(|holding| holding.crowded)
            .count();
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::ShardId;

    use super::*;
    use crate::event::ShardScopedInput;

    fn input() -> HostEvent {
        HostEvent::shard(ShardId::ROOT, ShardScopedInput::FetchTick)
    }

    fn peer(key: u64) -> PeerId {
        PeerId::new(key)
    }

    /// A lone peer may fill the lane, and a stall that keeps it full
    /// refuses the peer for nothing, however long it lasts.
    #[test]
    fn a_lone_peer_filling_a_stalled_lane_is_never_charged() {
        let (lane, _stalled) = network_lane(4);
        for _ in 0..4 {
            assert_eq!(lane.offer(input(), peer(1)), Offer::Taken);
        }
        for _ in 0..100 {
            assert_eq!(lane.offer(input(), peer(1)), Offer::Full);
        }
    }

    /// Peers that fill a stalled lane between them crowd no one out, so
    /// none is charged, however unevenly they split it.
    #[test]
    fn peers_filling_a_stalled_lane_between_them_are_never_charged() {
        let (lane, _stalled) = network_lane(4);
        for key in [1, 2, 1, 1] {
            assert_eq!(lane.offer(input(), peer(key)), Offer::Taken);
        }
        for _ in 0..10 {
            assert_eq!(lane.offer(input(), peer(1)), Offer::Full);
        }
        // The second peer holds one of its two places: crowded out.
        assert_eq!(lane.offer(input(), peer(2)), Offer::Full);
        assert_eq!(lane.offer(input(), peer(1)), Offer::OverShare);
    }

    /// A peer holding a full lane past its share is charged only once
    /// another peer has been refused room; the room a drain frees then
    /// goes to the crowded peer, and once it has room the first is
    /// refused for nothing again.
    #[test]
    fn a_peer_past_its_share_is_charged_only_once_another_is_crowded_out() {
        let (lane, receiver) = network_lane(4);
        for _ in 0..4 {
            assert_eq!(lane.offer(input(), peer(1)), Offer::Taken);
        }
        assert_eq!(lane.offer(input(), peer(1)), Offer::Full, "no one crowded");
        assert_eq!(lane.offer(input(), peer(2)), Offer::Full);
        assert_eq!(lane.offer(input(), peer(1)), Offer::OverShare);

        assert!(receiver.try_recv().is_some());
        assert_eq!(
            lane.offer(input(), peer(1)),
            Offer::Full,
            "the room a drain frees is kept for the crowded peer",
        );
        assert_eq!(lane.offer(input(), peer(2)), Offer::Taken);
        assert_eq!(lane.offer(input(), peer(1)), Offer::Full, "no one crowded");
        assert_eq!(lane.held_by(peer(1)), 3);
        assert_eq!(lane.held_by(peer(2)), 1);
    }

    /// Every input the driver takes leaves its peer's share, so a drained
    /// lane holds nothing of anyone's.
    #[test]
    fn a_drained_lane_holds_nothing() {
        let (lane, receiver) = network_lane(8);
        for key in [1, 2, 3, 1, 2, 3] {
            assert_eq!(lane.offer(input(), peer(key)), Offer::Taken);
        }
        assert_eq!(lane.held(), 6);
        assert_eq!(receiver.try_iter().count(), 6);
        assert_eq!(lane.held(), 0);
        for key in 1..=3 {
            assert_eq!(lane.held_by(peer(key)), 0);
        }
    }

    /// The lane keeps a share for at most as many peers as it has places,
    /// and forgets a peer that neither holds an input nor offered one for
    /// a generation.
    #[test]
    fn the_peers_a_lane_keeps_are_bounded_and_age_out() {
        let (lane, receiver) = network_lane(4);
        assert_eq!(lane.offer(input(), peer(0)), Offer::Taken);
        for key in 1..100 {
            let _ = lane.offer(input(), peer(key));
        }
        assert_eq!(lane.peers(), 4, "one peer per place at most");
        assert_eq!(
            lane.offer(input(), peer(100)),
            Offer::Full,
            "a peer past the record waits as for room",
        );

        // Two generations of one peer's traffic forget every other.
        let _ = receiver.try_iter().count();
        for _ in 0..8 {
            assert_eq!(lane.offer(input(), peer(0)), Offer::Taken);
            assert!(receiver.try_recv().is_some());
        }
        assert_eq!(lane.peers(), 1);
        assert_eq!(lane.held(), 0);
    }
}
