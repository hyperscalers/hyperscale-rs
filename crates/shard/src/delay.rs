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
//! The window belongs to one committee and holds one rotation of it. Round
//! robin gives each leader one sample per rotation, so fewer than a third of
//! the samples come from Byzantine proposers, and a Byzantine proposer moves
//! only its own sample. The upper median therefore sits inside the honest
//! band. A window shorter than a rotation reports nothing: its
//! honest-boundedness would depend on where Byzantine members sit in
//! committee order. A membership change empties the window: a member seated
//! by the change holds no block the previous committee certified, so only
//! blocks the current committee certified are data every member shares, and
//! sharing the data is what makes every member's timer the same.

use std::collections::VecDeque;
use std::time::Duration;

use hyperscale_types::{ProposerTimestamp, Round, ValidatorId, WeightedTimestamp};

/// How long a pending block waits for its transactions to arrive by gossip
/// before they are fetched from the proposer, while the chain has yet to
/// measure a full rotation.
pub const FETCH_TIMEOUT_DEFAULT: Duration = Duration::from_millis(150);

/// Floor on the fetch wait once the delay is measured.
pub const FETCH_TIMEOUT_MIN: Duration = Duration::from_millis(100);

/// Cap on the fetch wait once the delay is measured.
pub const FETCH_TIMEOUT_MAX: Duration = Duration::from_secs(2);

/// Network delays per fetch wait: the gossip that carries a block's
/// transactions is one hop behind the header, and the fetch that replaces
/// it is a round trip, so waiting two delays before fetching costs at most
/// one wasted request against a slow hop.
pub const FETCH_DELAY_MULTIPLIER: u32 = 2;

/// The chain-derived delay estimate.
pub struct DelayEstimator {
    /// Oldest first, at most one rotation of `committee`.
    samples: VecDeque<Duration>,
    /// Round and proposer stamp of the newest committed non-fallback block
    /// whose sample the next commit closes.
    open: Option<(Round, ProposerTimestamp)>,
    /// The committee whose blocks the window measures; its size is the
    /// window's. Empty until the first observation.
    committee: Vec<ValidatorId>,
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
            committee: Vec::new(),
        }
    }

    /// Feed a committed header in chain order. `committee` is the one that
    /// certified the block; a membership change empties the window first.
    /// Closes the open sample when this header's parent QC certifies it,
    /// then opens one for this header unless it is a fallback block.
    pub fn observe(&mut self, sample: CommittedSample, committee: &[ValidatorId]) {
        if self.committee != committee {
            self.committee = committee.to_vec();
            self.samples.clear();
            self.open = None;
        }
        if let Some((round, stamped)) = self.open.take()
            && sample.parent_qc_round == round
        {
            let voted = sample.parent_qc_weighted_timestamp.as_millis();
            let sample = Duration::from_millis(voted.saturating_sub(stamped.as_millis()));
            self.samples.push_back(sample);
        }
        while self.samples.len() > self.committee.len() {
            self.samples.pop_front();
        }
        if !sample.is_fallback {
            self.open = Some((sample.round, sample.timestamp));
        }
    }

    /// Upper median once the window holds a full rotation.
    pub fn delay(&self) -> Option<Duration> {
        if self.committee.is_empty() || self.samples.len() < self.committee.len() {
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

    /// A committee of `n` members.
    fn committee(n: u64) -> Vec<ValidatorId> {
        (0..n).map(ValidatorId::new).collect()
    }

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
        let one = committee(1);
        assert_eq!(est.delay(), None);
        est.observe(healthy(1, 1_000, 200), &one);
        assert_eq!(est.delay(), None);
        est.observe(healthy(2, 1_000, 200), &one);
        assert_eq!(est.delay(), Some(Duration::from_millis(200)));
    }

    #[test]
    fn untrusted_below_a_full_rotation_and_trusted_at_it() {
        let four = committee(4);
        let mut est = DelayEstimator::new();
        for i in 1..=4 {
            est.observe(healthy(i, 1_000, 150), &four);
            assert_eq!(est.delay(), None, "after commit {i}");
        }
        est.observe(healthy(5, 1_000, 150), &four);
        assert_eq!(est.delay(), Some(Duration::from_millis(150)));
    }

    #[test]
    fn a_fallback_block_closes_its_parent_but_opens_nothing() {
        let one = committee(1);
        let mut est = DelayEstimator::new();
        est.observe(healthy(1, 1_000, 100), &one);
        // The fallback at round 3 pins the QC for round 1's block, voted
        // before round 2 was abandoned: a valid sample for round 1.
        est.observe(committed(3, 1_100, 1, 1_100, true), &one);
        assert_eq!(est.delay(), Some(Duration::from_millis(100)));
        // Its own stamp is the parent QC's time, so the next block closes
        // nothing for it: the window still holds only round 1's sample.
        est.observe(committed(4, 4_000, 3, 3_900, false), &one);
        assert_eq!(est.delay(), Some(Duration::from_millis(100)));
        est.observe(healthy(5, 1_000, 100), &one);
        assert_eq!(est.delay(), Some(Duration::from_millis(100)));
    }

    #[test]
    fn the_open_sample_closes_on_its_own_qc_and_on_nothing_else() {
        let one = committee(1);
        let mut est = DelayEstimator::new();
        est.observe(healthy(1, 1_000, 100), &one);
        // Round 2 was abandoned, but the block at round 3 carries the QC
        // that certifies round 1's block, and that QC's quorum reading is
        // when round 1 was voted: a valid sample for round 1.
        est.observe(committed(3, 3_000, 1, 1_100, false), &one);
        assert_eq!(est.delay(), Some(Duration::from_millis(100)));
        // A parent QC for some other round than the open block's (a replay
        // that skipped a header) closes nothing.
        est.observe(committed(5, 5_000, 4, 4_100, false), &one);
        assert_eq!(est.delay(), Some(Duration::from_millis(100)));
    }

    #[test]
    fn a_rushed_stamp_saturates_at_zero() {
        let one = committee(1);
        let mut est = DelayEstimator::new();
        est.observe(committed(1, 5_000, 0, 0, false), &one);
        est.observe(committed(2, 6_000, 1, 4_000, false), &one);
        assert_eq!(est.delay(), Some(Duration::ZERO));
    }

    #[test]
    fn a_membership_change_empties_the_window() {
        let four = committee(4);
        let mut est = DelayEstimator::new();
        for i in 1..=5 {
            est.observe(healthy(i, 1_000, 100), &four);
        }
        assert_eq!(est.delay(), Some(Duration::from_millis(100)));

        // One member swapped: the previous committee's samples say nothing
        // a member seated by the swap can also see.
        let mut swapped = committee(4);
        swapped[3] = ValidatorId::new(9);
        est.observe(healthy(6, 1_000, 100), &swapped);
        assert_eq!(est.delay(), None, "the swap must empty the window");
        // The window needs a full rotation of the new committee's own
        // blocks: the block that crossed the change opens the first sample.
        for i in 7..=9 {
            est.observe(healthy(i, 1_000, 100), &swapped);
            assert_eq!(est.delay(), None, "after commit {i}");
        }
        est.observe(healthy(10, 1_000, 100), &swapped);
        assert_eq!(est.delay(), Some(Duration::from_millis(100)));
    }

    #[test]
    fn the_same_membership_keeps_the_window_and_a_grown_one_refills() {
        let four = committee(4);
        let mut est = DelayEstimator::new();
        for i in 1..=5 {
            est.observe(healthy(i, 1_000, 100), &four);
        }
        assert_eq!(est.delay(), Some(Duration::from_millis(100)));
        // The same members again: an epoch cut without a swap keeps the
        // window.
        est.observe(healthy(6, 1_000, 100), &committee(4));
        assert_eq!(est.delay(), Some(Duration::from_millis(100)));

        let six = committee(6);
        est.observe(healthy(7, 1_000, 100), &six);
        assert_eq!(est.delay(), None, "a grown committee starts over");
        for i in 8..=13 {
            est.observe(healthy(i, 1_000, 100), &six);
        }
        assert_eq!(est.delay(), Some(Duration::from_millis(100)));
    }

    #[test]
    fn a_byzantine_third_cannot_leave_the_honest_band() {
        // n = 7, f = 2. Honest samples are 100ms; two proposers stamp their
        // headers far in the past (inflating their samples) and, in a second
        // run, far ahead (zeroing them).
        let seven = committee(7);
        for byzantine_stamp_offset in [-30_000i64, 2_000] {
            let mut est = DelayEstimator::new();
            let mut i = 1u64;
            // Prime one open sample.
            est.observe(healthy(i, 1_000, 100), &seven);
            i += 1;
            for _ in 0..=7 {
                let byzantine = i % 7 == 2 || i % 7 == 3;
                let stamped = if byzantine {
                    let honest = i64::try_from(i * 1_000).unwrap();
                    u64::try_from((honest + byzantine_stamp_offset).max(0)).unwrap()
                } else {
                    i * 1_000
                };
                let parent_voted = (i - 1) * 1_000 + 100;
                est.observe(committed(i, stamped, i - 1, parent_voted, false), &seven);
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
    fn two_estimators_fed_the_same_chain_agree() {
        let four = committee(4);
        let mut a = DelayEstimator::new();
        let mut b = DelayEstimator::new();
        for i in 1..=12 {
            let sample = healthy(i, 700, 50 * (i % 3) + 100);
            a.observe(sample, &four);
            b.observe(sample, &four);
        }
        assert_eq!(a.delay(), b.delay());
        assert!(a.delay().is_some());
    }
}
