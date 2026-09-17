//! Network delay estimated from the committed chain.
//!
//! Every committed block carries one delay measurement: the time from the
//! proposer stamping its header to the median voter stamping its vote, which
//! is one dissemination hop plus verification as the quorum saw it. The
//! vote-side reading is the parent QC's `weighted_timestamp` in the *child*
//! header, where it is hash-pinned; the QC object's own timestamp rides
//! outside the signed message and a relay can rewrite it. Both inputs are
//! committed chain data, so two replicas at the same committed height hold
//! the same estimate.
//!
//! A fallback block opens no sample: it is stamped with the parent QC's
//! timestamp rather than the proposer's clock, so its sample would measure
//! the abandoned rounds before it, not the network. It still closes its
//! parent's sample, since the QC it pins was voted before those rounds.
//!
//! The window is one committee rotation. Round robin gives each leader one
//! sample per rotation, so fewer than a third of the samples come from
//! Byzantine proposers, and a Byzantine proposer moves only its own sample.
//! The upper median therefore sits inside the honest band. A window shorter
//! than a rotation reports nothing: its honest-boundedness would depend on
//! where Byzantine members sit in committee order.

use std::collections::VecDeque;
use std::time::Duration;

use hyperscale_types::{ProposerTimestamp, Round, WeightedTimestamp};

/// The chain-derived delay estimate.
pub struct DelayEstimator {
    /// Oldest first, at most one rotation.
    samples: VecDeque<Duration>,
    /// Round and proposer stamp of the newest committed non-fallback block
    /// whose sample the next commit closes.
    open: Option<(Round, ProposerTimestamp)>,
    /// Committee size at the last observation; sizes the window.
    rotation: usize,
}

/// The fields of a committed header the estimator reads.
#[derive(Clone, Copy, Debug)]
pub struct CommittedSample {
    pub round: Round,
    pub timestamp: ProposerTimestamp,
    pub is_fallback: bool,
    pub parent_qc_round: Round,
    pub parent_qc_weighted_timestamp: WeightedTimestamp,
}

impl DelayEstimator {
    pub const fn new() -> Self {
        Self {
            samples: VecDeque::new(),
            open: None,
            rotation: 0,
        }
    }

    /// Feed a committed header in chain order. Closes the open sample when
    /// this header's parent QC certifies it, then opens one for this header
    /// unless it is a fallback block. `committee_len` is the size of the
    /// committee that certified the block and sizes the window.
    pub fn observe(&mut self, committed: CommittedSample, committee_len: usize) {
        self.rotation = committee_len;
        self.close(&committed);
        while self.samples.len() > self.rotation {
            self.samples.pop_front();
        }
        self.open(committed);
    }

    /// Feed a header committed before this replica started, in chain
    /// order, ahead of any live commit. The rotation is unknown until a
    /// live commit names its committee, so nothing is trimmed or reported
    /// yet; the first live commit sizes the window and the newest rotation
    /// of what was replayed is trusted at once. The caller bounds how much
    /// it replays.
    pub fn replay(&mut self, committed: CommittedSample) {
        self.close(&committed);
        self.open(committed);
    }

    fn close(&mut self, committed: &CommittedSample) {
        if let Some((round, stamped)) = self.open.take()
            && committed.parent_qc_round == round
        {
            let voted = committed.parent_qc_weighted_timestamp.as_millis();
            let sample = Duration::from_millis(voted.saturating_sub(stamped.as_millis()));
            self.samples.push_back(sample);
        }
    }

    const fn open(&mut self, committed: CommittedSample) {
        if !committed.is_fallback {
            self.open = Some((committed.round, committed.timestamp));
        }
    }

    /// Upper median once the window holds a full rotation.
    pub fn delay(&self) -> Option<Duration> {
        if self.rotation == 0 || self.samples.len() < self.rotation {
            return None;
        }
        let mut sorted: Vec<Duration> = self.samples.iter().copied().collect();
        sorted.sort_unstable();
        Some(sorted[sorted.len() / 2])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A committed header at `round` stamped at `stamped_ms`, certified by a
    /// parent QC at `parent_round` whose quorum voted at `voted_ms`.
    fn committed(
        round: u64,
        stamped_ms: u64,
        parent_round: u64,
        voted_ms: u64,
        is_fallback: bool,
    ) -> CommittedSample {
        CommittedSample {
            round: Round::new(round),
            timestamp: ProposerTimestamp::from_millis(stamped_ms),
            is_fallback,
            parent_qc_round: Round::new(parent_round),
            parent_qc_weighted_timestamp: WeightedTimestamp::from_millis(voted_ms),
        }
    }

    /// A healthy chain: block `i` at round `i`, stamped at `i * period`,
    /// voted `delay_ms` later, so every sample is `delay_ms`.
    fn healthy(i: u64, period: u64, delay_ms: u64) -> CommittedSample {
        let stamped = i * period;
        let parent_voted = (i - 1) * period + delay_ms;
        committed(i, stamped, i - 1, parent_voted, false)
    }

    #[test]
    fn nothing_before_the_second_commit() {
        let mut est = DelayEstimator::new();
        assert_eq!(est.delay(), None);
        est.observe(healthy(1, 1_000, 200), 1);
        assert_eq!(est.delay(), None);
        est.observe(healthy(2, 1_000, 200), 1);
        assert_eq!(est.delay(), Some(Duration::from_millis(200)));
    }

    #[test]
    fn untrusted_below_a_full_rotation_and_trusted_at_it() {
        let n = 4usize;
        let mut est = DelayEstimator::new();
        for i in 1..=4u64 {
            est.observe(healthy(i, 1_000, 150), n);
            assert_eq!(est.delay(), None, "after commit {i}");
        }
        est.observe(healthy(5, 1_000, 150), n);
        assert_eq!(est.delay(), Some(Duration::from_millis(150)));
    }

    #[test]
    fn a_fallback_block_closes_its_parent_but_opens_nothing() {
        let mut est = DelayEstimator::new();
        est.observe(healthy(1, 1_000, 100), 1);
        // The fallback at round 3 pins the QC for round 1's block, voted
        // before round 2 was abandoned: a valid sample for round 1.
        est.observe(committed(3, 1_100, 1, 1_100, true), 1);
        assert_eq!(est.delay(), Some(Duration::from_millis(100)));
        // Its own stamp is the parent QC's time, so the next block closes
        // nothing for it: the window still holds only round 1's sample.
        est.observe(committed(4, 4_000, 3, 3_900, false), 1);
        assert_eq!(est.delay(), Some(Duration::from_millis(100)));
        est.observe(healthy(5, 1_000, 100), 1);
        assert_eq!(est.delay(), Some(Duration::from_millis(100)));
    }

    #[test]
    fn the_open_sample_closes_on_its_own_qc_and_on_nothing_else() {
        let mut est = DelayEstimator::new();
        est.observe(healthy(1, 1_000, 100), 1);
        // Round 2 was abandoned, but the block at round 3 carries the QC
        // that certifies round 1's block, and that QC's quorum reading is
        // when round 1 was voted: a valid sample for round 1.
        est.observe(committed(3, 3_000, 1, 1_100, false), 1);
        assert_eq!(est.delay(), Some(Duration::from_millis(100)));
        // A parent QC for some other round than the open block's (a replay
        // that skipped a header) closes nothing.
        est.observe(committed(5, 5_000, 4, 4_100, false), 1);
        assert_eq!(est.delay(), Some(Duration::from_millis(100)));
    }

    #[test]
    fn a_rushed_stamp_saturates_at_zero() {
        let mut est = DelayEstimator::new();
        est.observe(committed(1, 5_000, 0, 0, false), 1);
        est.observe(committed(2, 6_000, 1, 4_000, false), 1);
        assert_eq!(est.delay(), Some(Duration::ZERO));
    }

    #[test]
    fn growing_the_committee_untrusts_until_refilled_and_shrinking_drops_the_oldest() {
        let mut est = DelayEstimator::new();
        for i in 1..=5 {
            est.observe(healthy(i, 1_000, 100), 4);
        }
        assert_eq!(est.delay(), Some(Duration::from_millis(100)));

        est.observe(healthy(6, 1_000, 100), 6);
        assert_eq!(est.delay(), None, "five samples do not fill six");
        est.observe(healthy(7, 1_000, 100), 6);
        assert_eq!(est.delay(), Some(Duration::from_millis(100)));

        // Shrink to 2: only the newest two remain, and one slow sample is
        // then the upper median.
        est.observe(committed(8, 8_000, 7, 7_900, false), 2);
        est.observe(healthy(9, 1_000, 100), 2);
        assert_eq!(est.delay(), Some(Duration::from_millis(900)));
    }

    #[test]
    fn a_byzantine_third_cannot_leave_the_honest_band() {
        // n = 7, f = 2. Honest samples are 100ms; two proposers stamp their
        // headers far in the past (inflating their samples) and, in a second
        // run, far ahead (zeroing them).
        let n = 7usize;
        for byzantine_stamp_offset in [-30_000i64, 2_000] {
            let mut est = DelayEstimator::new();
            let mut i = 1u64;
            // Prime one open sample.
            est.observe(healthy(i, 1_000, 100), n);
            i += 1;
            for _ in 0..=n {
                let byzantine = i % 7 == 2 || i % 7 == 3;
                let stamped = if byzantine {
                    let honest = i64::try_from(i * 1_000).unwrap();
                    u64::try_from((honest + byzantine_stamp_offset).max(0)).unwrap()
                } else {
                    i * 1_000
                };
                let parent_voted = (i - 1) * 1_000 + 100;
                est.observe(committed(i, stamped, i - 1, parent_voted, false), n);
                i += 1;
            }
            assert_eq!(
                est.delay(),
                Some(Duration::from_millis(100)),
                "offset {byzantine_stamp_offset}",
            );
        }
    }

    #[test]
    fn a_replayed_rotation_is_trusted_at_the_first_live_commit() {
        let mut est = DelayEstimator::new();
        for i in 1..=9 {
            est.replay(healthy(i, 1_000, 100));
        }
        assert_eq!(
            est.delay(),
            None,
            "no rotation is known before a live commit"
        );
        est.observe(healthy(10, 1_000, 100), 4);
        assert_eq!(est.delay(), Some(Duration::from_millis(100)));
    }

    #[test]
    fn a_replay_keeps_only_the_newest_rotation() {
        let mut est = DelayEstimator::new();
        for i in 1..=9 {
            // Old samples are slow; the newest rotation is fast.
            let delay = if i <= 5 { 900 } else { 100 };
            est.replay(healthy(i, 1_000, delay));
        }
        est.observe(healthy(10, 1_000, 100), 4);
        assert_eq!(est.delay(), Some(Duration::from_millis(100)));
    }

    #[test]
    fn two_estimators_fed_the_same_chain_agree() {
        let mut a = DelayEstimator::new();
        let mut b = DelayEstimator::new();
        for i in 1..=12 {
            let sample = healthy(i, 700, 50 * (i % 3) + 100);
            a.observe(sample, 4);
            b.observe(sample, 4);
        }
        assert_eq!(a.delay(), b.delay());
        assert!(a.delay().is_some());
    }
}
