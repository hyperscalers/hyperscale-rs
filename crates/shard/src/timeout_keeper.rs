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

use std::collections::BTreeMap;

use hyperscale_types::{
    QuorumCertificate, Round, ShardId, Timeout, TimeoutCertificate, ValidatorId, Verified,
    Verifier, VoteCount,
};

/// Per-round tally of verified timeout shares, deduplicated by voter.
struct RoundTimeouts {
    by_voter: BTreeMap<ValidatorId, (Verified<Timeout>, VoteCount)>,
    total_power: VoteCount,
}

impl Default for RoundTimeouts {
    fn default() -> Self {
        Self {
            by_voter: BTreeMap::new(),
            total_power: VoteCount::ZERO,
        }
    }
}

/// Buffers verified timeouts per round and exposes the pacemaker thresholds.
#[derive(Default)]
pub struct TimeoutKeeper {
    rounds: BTreeMap<Round, RoundTimeouts>,
    /// The committee the recorded power was counted under. Power from one
    /// committee never counts toward another's thresholds.
    members: Vec<ValidatorId>,
}

impl TimeoutKeeper {
    /// Empty keeper.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record a verified timeout, deduplicated by voter. Returns `true` if it
    /// was newly recorded (a fresh voter for its round).
    pub(crate) fn record(&mut self, timeout: Verified<Timeout>, power: VoteCount) -> bool {
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
    pub(crate) fn power(&self, round: Round) -> VoteCount {
        self.rounds
            .get(&round)
            .map_or(VoteCount::ZERO, |r| r.total_power)
    }

    /// Whether `voter`'s timeout for `round` is already tallied. Lets callers
    /// skip re-verifying a retransmitted share the keeper would dedup anyway.
    #[must_use]
    pub(crate) fn contains(&self, round: Round, voter: ValidatorId) -> bool {
        self.rounds
            .get(&round)
            .is_some_and(|r| r.by_voter.contains_key(&voter))
    }

    /// Every `high_qc` carried by a timeout for `round`, sorted by QC round
    /// descending. The pacemaker walks these and adopts the highest that
    /// *verifies*: a Byzantine timeout's `high_qc` is unverified here (only its
    /// signature share was checked at intake), so a forged high-round QC would sort
    /// first — returning the whole list, rather than just the max, lets the
    /// caller skip it and still reach the genuine quorum-max an honest timeout
    /// carries. Empty if no timeouts seen.
    #[must_use]
    pub(crate) fn high_qcs_by_round_desc(&self, round: Round) -> Vec<QuorumCertificate> {
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

    /// A timeout certificate for `round` from the recorded shares of
    /// `members` — the committee's consensus members, in committee order —
    /// whose reported QC round is at most `hint`'s.
    ///
    /// A share reporting above `hint` is left out rather than failing the
    /// certificate: its carried QC is unverified at intake, so a Byzantine
    /// share can report any round, and every honest share qualifies once
    /// the caller has adopted the QCs they carry. `None` when the
    /// qualifying shares fall short of `quorum_threshold`.
    pub(crate) fn certificate(
        &self,
        verifier: &dyn Verifier,
        shard: ShardId,
        round: Round,
        members: &[ValidatorId],
        hint: &QuorumCertificate,
        quorum_threshold: VoteCount,
    ) -> Option<Verified<TimeoutCertificate>> {
        let entry = self.rounds.get(&round)?;
        let shares: Vec<(usize, &Verified<Timeout>)> = members
            .iter()
            .enumerate()
            .filter_map(|(position, member)| {
                let (timeout, _) = entry.by_voter.get(member)?;
                (timeout.high_qc_round() <= hint.round()).then_some((position, timeout))
            })
            .collect();
        Verified::<TimeoutCertificate>::from_verified_timeouts(
            verifier,
            shard,
            round,
            &shares,
            hint.clone(),
            quorum_threshold,
        )
    }

    /// Count from here on under the committee of `members`, dropping every
    /// share recorded under another.
    pub(crate) fn count_under(&mut self, members: &[ValidatorId]) {
        if self.members != members {
            self.rounds.clear();
            self.members = members.to_vec();
        }
    }

    /// Drop every round strictly below `round` (GC once the chain advances).
    pub(crate) fn prune_below(&mut self, round: Round) {
        self.rounds.retain(|r, _| *r >= round);
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto_bls::BlsSigner;
    use hyperscale_types::{
        AggregateSignature, BlockHash, BlockHeight, NetworkDefinition, ShardId, SignerBitfield,
        Timeout, WeightedTimestamp,
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
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        )
    }

    fn timeout(round: u64, high_qc_round: u64, voter: u64) -> Verified<Timeout> {
        let net = NetworkDefinition::simulator();
        let key = BlsSigner::generate();
        Verified::<Timeout>::sign_local(
            &net,
            SHARD,
            Round::new(round),
            high_qc_at(high_qc_round),
            ValidatorId::new(voter),
            &key,
        )
        .expect("sign")
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

    /// The certificate takes shares at or below its hint and leaves out one
    /// reporting above it, still reaching a quorum on the rest.
    #[test]
    fn certificate_leaves_out_a_share_above_its_hint() {
        use hyperscale_crypto_bls::BlsVerifier;
        use hyperscale_types::{ConsensusPublicKey, Signer, TimeoutCertificateContext, Verify};

        let net = NetworkDefinition::simulator();
        let keys: Vec<BlsSigner> = (0..4).map(|_| BlsSigner::generate()).collect();
        let members: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let share = |voter: usize, reported: u64| {
            Verified::<Timeout>::sign_local(
                &net,
                SHARD,
                Round::new(9),
                high_qc_at(reported),
                members[voter],
                &keys[voter],
            )
            .expect("sign")
        };
        let mut keeper = TimeoutKeeper::new();
        keeper.record(share(0, 5), VoteCount::new(1));
        keeper.record(share(1, 7), VoteCount::new(1));
        keeper.record(share(2, 99), VoteCount::new(1));
        keeper.record(share(3, 6), VoteCount::new(1));

        let tc = keeper
            .certificate(
                &BlsVerifier,
                SHARD,
                Round::new(9),
                &members,
                &high_qc_at(7),
                VoteCount::of(3),
            )
            .expect("three shares qualify");
        assert_eq!(tc.max_high_qc_round(), Round::new(7));
        assert!(!tc.signers().is_set(2));
        let public_keys: Vec<ConsensusPublicKey> = keys.iter().map(Signer::public_key).collect();
        assert!(
            tc.verify(&TimeoutCertificateContext {
                network: &net,
                public_keys: &public_keys,
                quorum_threshold: VoteCount::of(3),
                verifier: &BlsVerifier,
            })
            .is_ok()
        );

        assert!(
            keeper
                .certificate(
                    &BlsVerifier,
                    SHARD,
                    Round::new(9),
                    &members,
                    &high_qc_at(5),
                    VoteCount::of(3),
                )
                .is_none(),
            "only one share reports at or below 5",
        );
    }

    /// Shares counted under one committee do not carry over to another.
    #[test]
    fn a_new_committee_starts_from_an_empty_tally() {
        let mut keeper = TimeoutKeeper::new();
        let first = [ValidatorId::new(0), ValidatorId::new(1)];
        keeper.count_under(&first);
        keeper.record(timeout(5, 1, 0), VoteCount::new(1));
        keeper.count_under(&first);
        assert_eq!(keeper.power(Round::new(5)), VoteCount::new(1));

        keeper.count_under(&[ValidatorId::new(0), ValidatorId::new(2)]);
        assert_eq!(keeper.power(Round::new(5)), VoteCount::ZERO);
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
