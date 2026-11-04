//! The window of past epoch seeds a draw can still reach.

use std::collections::BTreeMap;

use hyperscale_hbor::Hbor;
use hyperscale_vm_types::SeedWindow;

use crate::{Epoch, EpochWindows, RETENTION_HORIZON, Randomness};

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

/// The retained epoch seeds, newest-bounded by what the fold has applied
/// and oldest-bounded by [`SeedRing::retained_epochs`].
///
/// Thirty-two bytes an epoch, so the whole ring is kilobytes and rides
/// the topology snapshot rather than pinning old snapshots to a
/// retention floor sized for other consumers entirely.
///
/// Every epoch past genesis is recorded once, in order, and a seed is the
/// beacon's: two rings holding an epoch hold the same seed for it. So a
/// draw's window is the same off any ring that holds the whole of it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hbor)]
#[hbor(transparent)]
pub struct SeedRing(BTreeMap<Epoch, EpochSeed>);

/// How many epochs a draw reaches back over: a transaction clocked in
/// epoch `E` draws on the seeds of `[E - SEED_WINDOW_EPOCHS, E - 1]`,
/// a little over five hours at five-minute epochs.
///
/// A seal maturing into an epoch below that window has no answer and
/// never will.
pub const SEED_WINDOW_EPOCHS: u64 = 64;

impl SeedRing {
    /// How many epochs below its newest the ring keeps on `windows`.
    ///
    /// A tick reads the ring its block's window carried, which can be
    /// that window's own fold. A member named to execute is named short
    /// of its deadline, which lies at most [`RETENTION_HORIZON`] past its
    /// clock, so its tick's window sits at most that many epochs, rounded
    /// up, past the member's own. Keeping that many beyond the draw window
    /// keeps the whole of it, and one more covers a payer's leg attested
    /// aborted, which is named at its deadline rather than short of it.
    #[must_use]
    pub const fn retained_epochs(windows: EpochWindows) -> u64 {
        let epoch_ms = windows.epoch_duration_ms();
        if epoch_ms == 0 {
            return SEED_WINDOW_EPOCHS;
        }
        let horizon_ms = RETENTION_HORIZON.as_secs() * 1_000;
        SEED_WINDOW_EPOCHS + horizon_ms.div_ceil(epoch_ms) + 1
    }

    /// Record `epoch`'s seed and drop whatever fell below the ring's
    /// depth on `windows`.
    pub fn record(&mut self, epoch: Epoch, seed: EpochSeed, windows: EpochWindows) {
        self.0.insert(epoch, seed);
        let floor = epoch.saturating_sub(Self::retained_epochs(windows));
        self.0.retain(|held, _| *held >= floor);
    }

    /// The seed `epoch` was rolled with, if the ring still holds it.
    ///
    /// Which side of the ring a miss fell outside is deliberately not
    /// answered: what a draw settles against is the window
    /// [`Self::window_for`] builds, which carries the same fact where the
    /// kernel reads it.
    #[must_use]
    pub fn get(&self, epoch: Epoch) -> Option<EpochSeed> {
        self.0.get(&epoch).copied()
    }

    /// The window a transaction clocked in `epoch` draws on: the seeds of
    /// the [`SEED_WINDOW_EPOCHS`] epochs before its own, with the epoch
    /// before its own as the frontier. `None` where this ring is missing
    /// any of them, which a caller waits out rather than answers.
    ///
    /// Nothing reads its own epoch's seed: two replicas of one window can
    /// hold it or not, as far as each has folded the beacon, and a draw on
    /// it would be one tick with two answers. Below the frontier the
    /// answer is a function of `epoch` alone, whichever ring it is read
    /// off.
    ///
    /// Only the reveal-folded epochs cross into the window. A ceremony
    /// roll is a seed a beacon member could have withheld from, and a
    /// draw settled on one is settled on a value somebody had a lever
    /// over — so a seal maturing into such an epoch answers `Expired` and
    /// the round closes again.
    #[must_use]
    pub fn window_for(&self, epoch: Epoch) -> Option<SeedWindow> {
        let Some(frontier) = epoch.inner().checked_sub(1) else {
            return Some(SeedWindow::unfolded());
        };
        // The genesis epoch rolls no seed, so epoch 1's is the first.
        let oldest = epoch.inner().saturating_sub(SEED_WINDOW_EPOCHS).max(1);
        let mut usable = BTreeMap::new();
        for at in oldest..=frontier {
            let seed = self.get(Epoch::new(at))?;
            if matches!(seed.source, SeedSource::Reveals) {
                usable.insert(at, *seed.randomness.as_bytes());
            }
        }
        Some(SeedWindow::new(usable, Some(frontier)))
    }

    /// Take in every seed `other` holds that this ring does not.
    pub fn absorb(&mut self, other: &Self) {
        for (epoch, seed) in &other.0 {
            self.0.entry(*epoch).or_insert(*seed);
        }
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
    use hyperscale_vm_types::Drawn;

    use super::*;
    use crate::WeightedTimestamp;

    fn seed(byte: u8) -> EpochSeed {
        EpochSeed {
            randomness: Randomness::new([byte; 32]),
            source: SeedSource::Reveals,
        }
    }

    const PRODUCTION: EpochWindows = EpochWindows::new(0, 300_000);
    const THIRTY_SECONDS: EpochWindows = EpochWindows::new(0, 30_000);

    /// Each epoch's seed is a byte of its own number, so a window read
    /// off the wrong epoch reads a different seed.
    fn seed_of(epoch: u64) -> EpochSeed {
        seed(u8::try_from(epoch % 251).unwrap())
    }

    /// A ring folded from epoch 1 through `newest`, as the beacon folds.
    fn folded_through(newest: u64, windows: EpochWindows) -> SeedRing {
        let mut ring = SeedRing::default();
        for epoch in 1..=newest {
            ring.record(Epoch::new(epoch), seed_of(epoch), windows);
        }
        ring
    }

    #[test]
    fn a_recorded_seed_reads_back_at_its_own_epoch() {
        let mut ring = SeedRing::default();
        ring.record(Epoch::new(7), seed(0x11), PRODUCTION);
        assert_eq!(ring.get(Epoch::new(7)), Some(seed(0x11)));
    }

    /// The depth is the draw window plus the epochs a tick can run past
    /// its member's clock, plus one for a leg named at its deadline.
    #[test]
    fn the_depth_covers_the_draw_window_and_the_tick_horizon() {
        assert_eq!(
            SeedRing::retained_epochs(PRODUCTION),
            SEED_WINDOW_EPOCHS + 2
        );
        assert_eq!(
            SeedRing::retained_epochs(THIRTY_SECONDS),
            SEED_WINDOW_EPOCHS + 6
        );
        assert_eq!(
            SeedRing::retained_epochs(EpochWindows::new(0, 0)),
            SEED_WINDOW_EPOCHS,
            "a grid that never advances has no tick to run late"
        );
    }

    /// The ring's extent: the floor is inside it, a step below is gone,
    /// and anything past the newest fold was never in it.
    #[test]
    fn the_ring_keeps_its_floor_and_drops_what_fell_below() {
        let depth = SeedRing::retained_epochs(THIRTY_SECONDS);
        let newest = depth + 10;
        let ring = folded_through(newest, THIRTY_SECONDS);

        assert_eq!(ring.get(Epoch::new(newest)), Some(seed_of(newest)));
        assert_eq!(ring.get(Epoch::new(newest + 1)), None);
        assert_eq!(
            ring.get(Epoch::new(newest - depth)),
            Some(seed_of(newest - depth)),
            "the floor itself is inside the ring"
        );
        assert_eq!(ring.get(Epoch::new(newest - depth - 1)), None);
        assert_eq!(ring.len(), usize::try_from(depth).unwrap() + 1);
    }

    /// Before the first fold the ring holds nothing, genesis included: a
    /// network with no seed has nothing to be past.
    #[test]
    fn an_empty_ring_holds_nothing() {
        let ring = SeedRing::default();
        assert_eq!(ring.get(Epoch::GENESIS), None);
        assert!(ring.is_empty());
    }

    /// A replica that has folded beacon `E - 1` holds a window `E` whose
    /// ring ends at `E - 1`; one that has folded `E` too holds the copy
    /// that replaced it, ending at `E`. A draw clocked in `E` reads the
    /// same window off both, at either edge.
    #[test]
    fn either_copy_of_a_window_draws_alike() {
        const E: u64 = 100;
        let behind = folded_through(E - 1, PRODUCTION);
        let ahead = folded_through(E, PRODUCTION);
        let window = behind.window_for(Epoch::new(E)).expect("held");
        assert_eq!(Some(&window), ahead.window_for(Epoch::new(E)).as_ref());

        assert_eq!(window.at(E), Drawn::Pending, "its own epoch is ahead");
        assert_eq!(
            window.at(E - 1),
            Drawn::Ready(*seed_of(E - 1).randomness.as_bytes())
        );
        assert_eq!(
            window.at(E - SEED_WINDOW_EPOCHS),
            Drawn::Ready(*seed_of(E - SEED_WINDOW_EPOCHS).randomness.as_bytes())
        );
        assert_eq!(window.at(E - SEED_WINDOW_EPOCHS - 1), Drawn::Expired);
    }

    /// A ring that has not folded the epoch before the clock's cannot
    /// say whether that seed is ready, so it gives no window at all.
    #[test]
    fn a_ring_short_of_the_frontier_gives_no_window() {
        let ring = folded_through(98, PRODUCTION);
        assert_eq!(ring.window_for(Epoch::new(100)), None);
        assert!(ring.window_for(Epoch::new(99)).is_some());
    }

    /// A tick on thirty-second epochs runs at most the retention horizon
    /// past its member's clock: five epochs past it at the latest, a
    /// sixth for a leg named at its deadline. Its window's ring then still
    /// holds the oldest seed the member draws on, and one epoch later it
    /// would not.
    #[test]
    fn a_tick_at_its_horizon_still_holds_the_oldest_seed() {
        const E: u64 = 200;
        let clock = THIRTY_SECONDS.window_of(Epoch::new(E)).end.as_millis() - 1;
        let latest = THIRTY_SECONDS.epoch_for(WeightedTimestamp::from_millis(
            clock + RETENTION_HORIZON.as_secs() * 1_000 - 1,
        ));
        assert_eq!(latest, Epoch::new(E + 5));

        let named_at_deadline = folded_through(E + 6, THIRTY_SECONDS);
        let window = named_at_deadline
            .window_for(Epoch::new(E))
            .expect("the ring of a tick six epochs on holds the whole window");
        assert_eq!(
            window,
            folded_through(E - 1, THIRTY_SECONDS)
                .window_for(Epoch::new(E))
                .unwrap()
        );
        assert_eq!(
            window.at(E - SEED_WINDOW_EPOCHS),
            Drawn::Ready(*seed_of(E - SEED_WINDOW_EPOCHS).randomness.as_bytes())
        );
        assert_eq!(
            folded_through(E + 7, THIRTY_SECONDS).window_for(Epoch::new(E)),
            None
        );
    }

    /// The window keeps out a ceremony roll, below a frontier that says
    /// it happened: a seal maturing into one never opens.
    #[test]
    fn a_ceremony_epoch_reads_expired() {
        let mut ring = folded_through(9, PRODUCTION);
        ring.record(
            Epoch::new(10),
            EpochSeed {
                randomness: Randomness::new([0x55; 32]),
                source: SeedSource::Ceremony,
            },
            PRODUCTION,
        );
        let window = ring.window_for(Epoch::new(11)).expect("held");
        assert_eq!(window.at(10), Drawn::Expired);
        assert_eq!(
            window.at(9),
            Drawn::Ready(*seed_of(9).randomness.as_bytes())
        );
    }

    /// Genesis rolls no seed: the genesis window is ahead of everything,
    /// and epoch 1's window holds nothing below a frontier at genesis.
    #[test]
    fn the_first_windows_need_no_seed() {
        let empty = SeedRing::default();
        assert_eq!(
            empty.window_for(Epoch::GENESIS),
            Some(SeedWindow::unfolded())
        );
        let first = empty.window_for(Epoch::new(1)).expect("nothing to hold");
        assert_eq!(first.at(0), Drawn::Expired);
        assert_eq!(first.at(1), Drawn::Pending);
        assert_eq!(empty.window_for(Epoch::new(2)), None);
    }

    /// Absorbing a fresher ring fills in what a stale one lacks.
    #[test]
    fn an_absorbed_ring_fills_the_frontier() {
        let mut stale = folded_through(98, PRODUCTION);
        stale.absorb(&folded_through(100, PRODUCTION));
        assert_eq!(
            stale.window_for(Epoch::new(100)),
            folded_through(99, PRODUCTION).window_for(Epoch::new(100))
        );
    }

    #[test]
    fn a_ring_round_trips_through_its_encoding() {
        let mut ring = SeedRing::default();
        ring.record(Epoch::new(3), seed(0x44), PRODUCTION);
        ring.record(
            Epoch::new(4),
            EpochSeed {
                randomness: Randomness::new([0x55; 32]),
                source: SeedSource::Ceremony,
            },
            PRODUCTION,
        );
        let bytes = hbor_to_vec(&ring).expect("encodes");
        let decoded: SeedRing = hbor_from_slice(&bytes).expect("decodes");
        assert_eq!(ring, decoded);
    }
}
