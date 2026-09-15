//! The window of past epoch seeds a draw can still reach.

use std::collections::BTreeMap;

use hyperscale_hbor::Hbor;

use crate::{Epoch, Randomness};

/// Which of the beacon's two rolls produced an epoch's seed.
///
/// The two are not interchangeable to a consumer that draws on one. The
/// reveal fold has no include-or-omit lever — a shard's chain is
/// consensus-derived, so a proposer forfeits its slot rather than
/// quietly dropping a link — while the ceremony mixes the beacon
/// committee's own outputs, each of which its holder may withhold. An
/// epoch with no crossing at all falls back to the second, which is rare
/// and self-announcing but is still a seed somebody could have steered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub enum SeedSource {
    /// The fold over every crossing shard's closed reveal chain.
    #[hbor(discriminant = 0)]
    Reveals,
    /// The beacon committee's own reveal mix.
    #[hbor(discriminant = 1)]
    Ceremony,
}

/// One epoch's seed, beside how it was rolled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub struct EpochSeed {
    /// The seed itself.
    pub randomness: Randomness,
    /// Which roll produced it.
    pub source: SeedSource,
}

/// The retained window of epoch seeds, newest-bounded by what the fold
/// has applied and oldest-bounded by [`SEED_WINDOW_EPOCHS`].
///
/// Thirty-two bytes an epoch, so the whole window is kilobytes and rides
/// the topology snapshot rather than pinning old snapshots to a
/// retention floor sized for other consumers entirely.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hbor)]
#[hbor(transparent)]
pub struct SeedRing(BTreeMap<Epoch, EpochSeed>);

/// How many epochs of seed the ring keeps.
///
/// A draw that names an epoch outside it has no answer, so this is the
/// span between an epoch's seed being rolled and the last moment
/// anything can still resolve against it — five hours at five-minute
/// epochs.
pub const SEED_WINDOW_EPOCHS: u64 = 64;

impl SeedRing {
    /// Record `epoch`'s seed and drop whatever fell out of the window.
    pub fn record(&mut self, epoch: Epoch, seed: EpochSeed) {
        self.0.insert(epoch, seed);
        let floor = Epoch::new(epoch.inner().saturating_sub(SEED_WINDOW_EPOCHS));
        self.0.retain(|held, _| *held >= floor);
    }

    /// The seed `epoch` was rolled with, if the ring still holds it.
    ///
    /// Which side of the window a miss fell outside is deliberately not
    /// answered. The distinction would be a wait-or-refuse for a caller
    /// that branched on it, and none does: what a draw settles against
    /// is the window [`Self::folded`] and [`Self::newest`] build, which
    /// carries the same fact where the kernel reads it.
    #[must_use]
    pub fn get(&self, epoch: Epoch) -> Option<EpochSeed> {
        self.0.get(&epoch).copied()
    }

    /// The epochs whose seeds came from the reveal fold, which are the
    /// ones a draw may settle on — the ceremony's are left out, since
    /// they are seeds a beacon member could have withheld from.
    pub fn folded(&self) -> impl Iterator<Item = (Epoch, Randomness)> + '_ {
        self.0
            .iter()
            .filter(|(_, seed)| matches!(seed.source, SeedSource::Reveals))
            .map(|(epoch, seed)| (*epoch, seed.randomness))
    }

    /// The newest epoch the ring holds, if it holds any.
    #[must_use]
    pub fn newest(&self) -> Option<Epoch> {
        self.0.keys().next_back().copied()
    }

    /// How many epochs the ring holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the ring holds nothing — every network before its first
    /// fold.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;

    fn seed(byte: u8) -> EpochSeed {
        EpochSeed {
            randomness: Randomness::new([byte; 32]),
            source: SeedSource::Reveals,
        }
    }

    #[test]
    fn a_recorded_seed_reads_back_at_its_own_epoch() {
        let mut ring = SeedRing::default();
        ring.record(Epoch::new(7), seed(0x11));
        assert_eq!(ring.get(Epoch::new(7)), Some(seed(0x11)));
    }

    /// The window's extent: the floor is inside it, a step below is
    /// gone, and anything past the newest fold was never in it.
    #[test]
    fn the_window_keeps_its_floor_and_drops_what_fell_below() {
        let mut ring = SeedRing::default();
        for epoch in 1..=(SEED_WINDOW_EPOCHS + 10) {
            ring.record(Epoch::new(epoch), seed(0x22));
        }
        let newest = SEED_WINDOW_EPOCHS + 10;

        assert_eq!(ring.get(Epoch::new(newest)), Some(seed(0x22)));
        assert_eq!(ring.get(Epoch::new(newest + 1)), None);
        assert_eq!(ring.get(Epoch::new(1)), None);
        assert_eq!(
            ring.get(Epoch::new(newest - SEED_WINDOW_EPOCHS)),
            Some(seed(0x22)),
            "the floor itself is inside the window"
        );
        assert_eq!(ring.get(Epoch::new(newest - SEED_WINDOW_EPOCHS - 1)), None);
    }

    /// Before the first fold the ring holds nothing, genesis included: a
    /// network with no seed has nothing to be past.
    #[test]
    fn an_empty_ring_holds_nothing() {
        let ring = SeedRing::default();
        assert_eq!(ring.get(Epoch::GENESIS), None);
        assert!(ring.is_empty());
        assert_eq!(ring.newest(), None);
    }

    #[test]
    fn the_window_bounds_what_the_ring_holds() {
        let mut ring = SeedRing::default();
        for epoch in 0..(SEED_WINDOW_EPOCHS * 3) {
            ring.record(Epoch::new(epoch), seed(0x33));
        }
        assert_eq!(ring.len(), usize::try_from(SEED_WINDOW_EPOCHS).unwrap() + 1);
    }

    #[test]
    fn a_ring_round_trips_through_its_encoding() {
        let mut ring = SeedRing::default();
        ring.record(Epoch::new(3), seed(0x44));
        ring.record(
            Epoch::new(4),
            EpochSeed {
                randomness: Randomness::new([0x55; 32]),
                source: SeedSource::Ceremony,
            },
        );
        let bytes = hbor_to_vec(&ring).expect("encodes");
        let decoded: SeedRing = hbor_from_slice(&bytes).expect("decodes");
        assert_eq!(ring, decoded);
    }
}
