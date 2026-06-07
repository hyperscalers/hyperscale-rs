//! Buffers verified timeout shares per round for the HotStuff-2 pacemaker.
//!
//! A replica broadcasts a [`Timeout`] when its round timer fires instead of
//! advancing locally. The keeper tallies the verified shares per round and
//! reports the two thresholds the pacemaker acts on:
//!
//! - **f+1** (`> 1/3` power): at least one honest replica has abandoned the
//!   round, so we broadcast our own timeout too (Bracha amplification).
//! - **2f+1** (`> 2/3` power, a quorum): the round is provably abandoned, so we
//!   adopt the quorum-max `high_qc` and advance together.
//!
//! Timeouts are deduplicated by voter. Shares are verified before they reach
//! the keeper; the carried `high_qc` is a self-authenticating QC, verified
//! separately at adoption.

use std::collections::{BTreeMap, HashMap};

use hyperscale_types::{QuorumCertificate, Round, Timeout, ValidatorId, Verified, VoteCount};

/// Per-round tally of verified timeout shares, deduplicated by voter.
struct RoundTimeouts {
    by_voter: HashMap<ValidatorId, (Verified<Timeout>, VoteCount)>,
    total_power: VoteCount,
}

impl Default for RoundTimeouts {
    fn default() -> Self {
        Self {
            by_voter: HashMap::new(),
            total_power: VoteCount::ZERO,
        }
    }
}

/// Buffers verified timeouts per round and exposes the pacemaker thresholds.
#[derive(Default)]
pub struct TimeoutKeeper {
    rounds: BTreeMap<Round, RoundTimeouts>,
}

impl TimeoutKeeper {
    /// Empty keeper.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a verified timeout, deduplicated by voter. Returns `true` if it
    /// was newly recorded (a fresh voter for its round).
    pub fn record(&mut self, timeout: Verified<Timeout>, power: VoteCount) -> bool {
        let round = timeout.round();
        let voter = timeout.voter();
        let entry = self.rounds.entry(round).or_default();
        if entry.by_voter.contains_key(&voter) {
            return false;
        }
        entry.total_power = entry.total_power.saturating_add(power);
        entry.by_voter.insert(voter, (timeout, power));
        true
    }

    /// Combined voting power of the timeouts seen for `round`.
    #[must_use]
    pub fn power(&self, round: Round) -> VoteCount {
        self.rounds
            .get(&round)
            .map_or(VoteCount::ZERO, |r| r.total_power)
    }

    /// Whether `voter`'s timeout for `round` is already tallied. Lets callers
    /// skip re-verifying a retransmitted share the keeper would dedup anyway.
    #[must_use]
    pub fn contains(&self, round: Round, voter: ValidatorId) -> bool {
        self.rounds
            .get(&round)
            .is_some_and(|r| r.by_voter.contains_key(&voter))
    }

    /// Every `high_qc` carried by a timeout for `round`, sorted by QC round
    /// descending. The pacemaker walks these and adopts the highest that
    /// *verifies*: a Byzantine timeout's `high_qc` is unverified here (only its
    /// BLS share was checked at intake), so a forged high-round QC would sort
    /// first — returning the whole list, rather than just the max, lets the
    /// caller skip it and still reach the genuine quorum-max an honest timeout
    /// carries. Empty if no timeouts seen.
    #[must_use]
    pub fn high_qcs_by_round_desc(&self, round: Round) -> Vec<QuorumCertificate> {
        let Some(entry) = self.rounds.get(&round) else {
            return Vec::new();
        };
        let mut qcs: Vec<QuorumCertificate> = entry
            .by_voter
            .values()
            .map(|(timeout, _)| timeout.high_qc().clone())
            .collect();
        qcs.sort_by_key(|qc| std::cmp::Reverse(qc.round()));
        qcs
    }

    /// Drop every round strictly below `round` (GC once the chain advances).
    pub fn prune_below(&mut self, round: Round) {
        self.rounds.retain(|r, _| *r >= round);
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        BlockHash, BlockHeight, NetworkDefinition, ShardId, SignerBitfield, Timeout,
        WeightedTimestamp, generate_bls_keypair, zero_bls_signature,
    };

    use super::*;

    const SHARD: ShardId = ShardId::ROOT;

    fn high_qc_at(round: u64) -> QuorumCertificate {
        QuorumCertificate::new(
            BlockHash::ZERO,
            SHARD,
            BlockHeight::new(round),
            BlockHash::ZERO,
            Round::new(round),
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        )
    }

    fn timeout(round: u64, high_qc_round: u64, voter: u64) -> Verified<Timeout> {
        let net = NetworkDefinition::simulator();
        let key = generate_bls_keypair();
        Verified::<Timeout>::sign_local(
            &net,
            SHARD,
            Round::new(round),
            high_qc_at(high_qc_round),
            ValidatorId::new(voter),
            &key,
        )
    }

    #[test]
    fn record_dedups_by_voter() {
        let mut keeper = TimeoutKeeper::new();
        let r = Round::new(5);

        assert!(keeper.record(timeout(5, 1, 7), VoteCount::new(1)));
        // Same voter, same round: rejected, power counted once.
        assert!(!keeper.record(timeout(5, 2, 7), VoteCount::new(1)));
        assert_eq!(keeper.power(r), VoteCount::new(1));

        // Distinct voter: accepted, power accumulates.
        assert!(keeper.record(timeout(5, 1, 9), VoteCount::new(1)));
        assert_eq!(keeper.power(r), VoteCount::new(2));
    }

    #[test]
    fn contains_reports_tallied_voters() {
        let mut keeper = TimeoutKeeper::new();
        let r = Round::new(5);

        assert!(!keeper.contains(r, ValidatorId::new(7)));
        keeper.record(timeout(5, 1, 7), VoteCount::new(1));
        assert!(keeper.contains(r, ValidatorId::new(7)));

        // A different voter or round is not present.
        assert!(!keeper.contains(r, ValidatorId::new(8)));
        assert!(!keeper.contains(Round::new(6), ValidatorId::new(7)));
    }

    #[test]
    fn power_is_per_round() {
        let mut keeper = TimeoutKeeper::new();
        keeper.record(timeout(5, 1, 7), VoteCount::new(1));
        keeper.record(timeout(6, 1, 7), VoteCount::new(1));

        assert_eq!(keeper.power(Round::new(5)), VoteCount::new(1));
        assert_eq!(keeper.power(Round::new(6)), VoteCount::new(1));
        assert_eq!(keeper.power(Round::new(7)), VoteCount::ZERO);
    }

    #[test]
    fn high_qcs_sorted_by_round_desc() {
        let mut keeper = TimeoutKeeper::new();
        keeper.record(timeout(9, 3, 0), VoteCount::new(1));
        keeper.record(timeout(9, 7, 1), VoteCount::new(1));
        keeper.record(timeout(9, 4, 2), VoteCount::new(1));

        // Highest first, so the pacemaker tries the quorum-max before falling
        // back to lower candidates when one fails verification.
        let rounds: Vec<u64> = keeper
            .high_qcs_by_round_desc(Round::new(9))
            .iter()
            .map(|qc| qc.round().inner())
            .collect();
        assert_eq!(rounds, vec![7, 4, 3]);
        assert!(keeper.high_qcs_by_round_desc(Round::new(10)).is_empty());
    }

    #[test]
    fn prune_below_drops_old_rounds() {
        let mut keeper = TimeoutKeeper::new();
        keeper.record(timeout(5, 1, 0), VoteCount::new(1));
        keeper.record(timeout(6, 1, 0), VoteCount::new(1));
        keeper.record(timeout(7, 1, 0), VoteCount::new(1));

        keeper.prune_below(Round::new(6));

        assert_eq!(keeper.power(Round::new(5)), VoteCount::ZERO);
        assert_eq!(keeper.power(Round::new(6)), VoteCount::new(1));
        assert_eq!(keeper.power(Round::new(7)), VoteCount::new(1));
    }
}
