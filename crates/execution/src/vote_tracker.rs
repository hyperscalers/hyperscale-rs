//! Execution vote tracker.
//!
//! Tracks the collection of execution votes during the cross-shard
//! atomic execution protocol.
//!
//! ## Round Voting
//!
//! Validators vote at each block commit where their wave is complete.
//! Votes include `vote_anchor_ts` in the BLS-signed message, so votes at
//! different heights have different signatures and cannot be aggregated.
//! The tracker groups by `(global_receipt_root, vote_anchor_ts)` and checks quorum
//! per group.
//!
//! ## Deferred Verification Optimization
//!
//! Votes are NOT verified when received. Instead, they are buffered until
//! we have enough voting power for quorum. This avoids wasting CPU on votes
//! we'll never use.

use std::collections::{BTreeMap, HashSet};

use hyperscale_types::{
    BlockHash, Bls12381G1PublicKey, ExecutionVote, GlobalReceiptRoot, ValidatorId, Verified,
    VotePower, WaveId, WeightedTimestamp,
};

/// Key for grouping votes: `(global_receipt_root, vote_anchor_ts)`.
///
/// Votes at different heights have different BLS signatures and cannot be
/// aggregated together. This prevents stale votes from combining with new
/// ones if an abort intent changes the `global_receipt_root` between heights.
type VoteKey = (GlobalReceiptRoot, WeightedTimestamp);

/// Tracks execution votes for a specific wave within a block.
///
/// After executing all transactions in a wave, validators create an execution
/// vote on the receipt root. This tracker collects votes and determines when
/// quorum is reached for BLS signature aggregation into an execution certificate.
#[derive(Debug)]
pub struct VoteTracker {
    /// Wave identifier.
    wave_id: WaveId,
    /// Block hash this wave belongs to.
    block_hash: BlockHash,
    /// Quorum threshold (2f+1 voting power).
    quorum: VotePower,

    // ═══════════════════════════════════════════════════════════════════════
    // Verified votes (passed signature verification)
    // ═══════════════════════════════════════════════════════════════════════
    /// Verified votes grouped by (`global_receipt_root`, `vote_anchor_ts`).
    votes_by_key: BTreeMap<VoteKey, Vec<Verified<ExecutionVote>>>,
    /// Voting power per (`global_receipt_root`, `vote_anchor_ts`) (verified votes only).
    power_by_key: BTreeMap<VoteKey, VotePower>,

    // ═══════════════════════════════════════════════════════════════════════
    // Unverified votes (buffered until quorum possible)
    // ═══════════════════════════════════════════════════════════════════════
    /// Unverified votes buffered for batch verification.
    /// Each entry is (vote, `public_key`, `voting_power`).
    unverified_votes: Vec<(ExecutionVote, Bls12381G1PublicKey, VotePower)>,
    /// Total voting power of unverified votes.
    unverified_power: VotePower,
    /// Validators we've already seen votes from at each `vote_anchor_ts` (dedup).
    /// Key is (`validator_id`, `vote_anchor_ts`).
    seen: HashSet<(ValidatorId, WeightedTimestamp)>,
    /// Whether a verification batch is currently in flight.
    pending_verification: bool,
}

impl VoteTracker {
    /// Create a new execution vote tracker.
    #[must_use]
    pub fn new(wave_id: WaveId, block_hash: BlockHash, quorum: VotePower) -> Self {
        Self {
            wave_id,
            block_hash,
            quorum,
            votes_by_key: BTreeMap::new(),
            power_by_key: BTreeMap::new(),
            unverified_votes: Vec::new(),
            unverified_power: VotePower::ZERO,
            seen: HashSet::new(),
            pending_verification: false,
        }
    }

    /// Get the wave ID.
    #[must_use]
    pub const fn wave_id(&self) -> &WaveId {
        &self.wave_id
    }

    /// Get the block hash.
    #[must_use]
    pub const fn block_hash(&self) -> BlockHash {
        self.block_hash
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Deferred Verification Methods
    // ═══════════════════════════════════════════════════════════════════════

    /// Buffer an unverified vote for later batch verification.
    ///
    /// Returns `true` if the vote was buffered, `false` if it was a duplicate.
    /// Dedup is per (validator, `vote_anchor_ts`) — the same validator can vote at
    /// multiple heights (round voting), but only once per height.
    pub fn buffer_unverified_vote(
        &mut self,
        vote: ExecutionVote,
        public_key: Bls12381G1PublicKey,
        voting_power: VotePower,
    ) -> bool {
        let dedup_key = (vote.validator(), vote.vote_anchor_ts());

        if self.seen.contains(&dedup_key) {
            return false;
        }

        self.seen.insert(dedup_key);
        self.unverified_votes.push((vote, public_key, voting_power));
        self.unverified_power += voting_power;
        true
    }

    /// Check if we should trigger batch verification.
    ///
    /// Verification is triggered when:
    /// 1. We have unverified votes
    /// 2. No verification is already in flight
    /// 3. Total power (verified + unverified) could reach quorum
    #[must_use]
    pub fn should_trigger_verification(&self) -> bool {
        if self.unverified_votes.is_empty() || self.pending_verification {
            return false;
        }

        let best_verified_power = self
            .power_by_key
            .values()
            .max()
            .copied()
            .unwrap_or(VotePower::ZERO);

        let total_potential = best_verified_power + self.unverified_power;
        total_potential >= self.quorum
    }

    /// Take unverified votes for batch verification.
    ///
    /// Marks verification as pending. Call `on_verification_complete` when done.
    pub fn take_unverified_votes(
        &mut self,
    ) -> Vec<(ExecutionVote, Bls12381G1PublicKey, VotePower)> {
        self.pending_verification = true;
        self.unverified_power = VotePower::ZERO;
        std::mem::take(&mut self.unverified_votes)
    }

    /// Handle verification completion.
    pub const fn on_verification_complete(&mut self) {
        self.pending_verification = false;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Verified Vote Methods
    // ═══════════════════════════════════════════════════════════════════════

    /// Add a verified vote and its voting power.
    ///
    /// Idempotent per `(validator, vote_anchor_ts)`: redundant calls (e.g.
    /// own-vote re-feeds from leader-rotation retries that land on `self`)
    /// are dropped so [`Self::power_by_key`] only counts unique signers.
    /// Dedup scans [`Self::votes_by_key`] — a validator may have voted on
    /// any `global_receipt_root` at this anchor, so the check spans every
    /// bucket sharing the incoming `vote_anchor_ts`.
    pub fn add_verified_vote(&mut self, vote: Verified<ExecutionVote>, power: VotePower) {
        let validator = vote.validator();
        let anchor_ts = vote.vote_anchor_ts();
        let already_counted = self
            .votes_by_key
            .iter()
            .filter(|((_, ts), _)| *ts == anchor_ts)
            .any(|(_, votes)| votes.iter().any(|v| v.validator() == validator));
        if already_counted {
            return;
        }
        let key = (vote.global_receipt_root(), anchor_ts);
        self.votes_by_key.entry(key).or_default().push(vote);
        *self.power_by_key.entry(key).or_insert(VotePower::ZERO) += power;
    }

    /// Check if quorum is reached for any (`global_receipt_root`, `vote_anchor_ts`) pair.
    ///
    /// Returns `Some((global_receipt_root, vote_anchor_ts, total_power))` if quorum reached.
    /// If multiple pairs have quorum, returns the one with the lowest `vote_anchor_ts`.
    #[must_use]
    pub fn check_quorum(&self) -> Option<(GlobalReceiptRoot, WeightedTimestamp, VotePower)> {
        let mut best: Option<(GlobalReceiptRoot, WeightedTimestamp, VotePower)> = None;
        for (&(global_receipt_root, vote_anchor_ts), &power) in &self.power_by_key {
            if power >= self.quorum {
                match &best {
                    Some((_, best_anchor, _)) if vote_anchor_ts >= *best_anchor => {}
                    _ => best = Some((global_receipt_root, vote_anchor_ts, power)),
                }
            }
        }
        best
    }

    /// Take votes for a specific (`global_receipt_root`, `vote_anchor_ts`) pair.
    pub fn take_votes(
        &mut self,
        global_receipt_root: GlobalReceiptRoot,
        vote_anchor_ts: WeightedTimestamp,
    ) -> Vec<Verified<ExecutionVote>> {
        let key = (global_receipt_root, vote_anchor_ts);
        self.votes_by_key.remove(&key).unwrap_or_default()
    }

    /// Return the total verified voting power across all (`global_receipt_root`, `vote_anchor_ts`) groups.
    ///
    /// Saturates at `u64::MAX` if the sum would overflow — quorum gates
    /// already cap at the topology's voting-power total, so a saturated
    /// reading still gives a correct "well above quorum" answer.
    #[must_use]
    pub fn total_verified_power(&self) -> VotePower {
        self.power_by_key
            .values()
            .fold(VotePower::ZERO, |acc, &p| acc.saturating_add(p))
    }

    /// Return the number of distinct receipt roots across all verified vote groups.
    #[must_use]
    pub fn distinct_global_receipt_root_count(&self) -> usize {
        self.power_by_key
            .keys()
            .map(|(root, _)| root)
            .collect::<HashSet<_>>()
            .len()
    }

    /// Return a summary of verified voting power per global receipt root (summed across vote heights).
    /// Used for diagnostics when quorum cannot be reached.
    #[must_use]
    pub fn global_receipt_root_power_summary(&self) -> Vec<(GlobalReceiptRoot, VotePower)> {
        let mut by_root: BTreeMap<GlobalReceiptRoot, VotePower> = BTreeMap::new();
        for (&(root, _), &power) in &self.power_by_key {
            *by_root.entry(root).or_insert(VotePower::ZERO) += power;
        }
        by_root.into_iter().collect()
    }
}

#[cfg(test)]
impl VoteTracker {
    /// Check if verification is pending.
    #[must_use]
    pub const fn is_verification_pending(&self) -> bool {
        self.pending_verification
    }

    /// Get votes for a specific global receipt root at any height (for tests).
    #[must_use]
    pub fn votes_for_global_receipt_root(
        &self,
        global_receipt_root: GlobalReceiptRoot,
    ) -> Vec<&Verified<ExecutionVote>> {
        self.votes_by_key
            .iter()
            .filter(|((root, _), _)| *root == global_receipt_root)
            .flat_map(|(_, votes)| votes.iter())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_types::{
        BlockHeight, Hash, ShardGroupId, generate_bls_keypair, zero_bls_signature,
    };

    use super::*;

    fn make_test_public_key() -> Bls12381G1PublicKey {
        generate_bls_keypair().public_key()
    }

    fn make_vote(validator: u64, global_receipt_root: GlobalReceiptRoot) -> ExecutionVote {
        ExecutionVote::new(
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            BlockHeight::new(10),
            WeightedTimestamp::from_millis(11),
            WaveId::new(ShardGroupId::new(0), BlockHeight::new(0), BTreeSet::new()),
            ShardGroupId::new(0),
            global_receipt_root,
            5,
            vec![],
            ValidatorId::new(validator),
            zero_bls_signature(),
        )
    }

    fn make_verified_vote(
        validator: u64,
        global_receipt_root: GlobalReceiptRoot,
    ) -> Verified<ExecutionVote> {
        Verified::new_unchecked_for_test(make_vote(validator, global_receipt_root))
    }

    #[test]
    fn test_vote_tracker_quorum() {
        let mut tracker = VoteTracker::new(
            WaveId::new(ShardGroupId::new(0), BlockHeight::new(0), BTreeSet::new()),
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            VotePower::new(3),
        );

        let root = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"receipt_root"));

        tracker.add_verified_vote(make_verified_vote(0, root), VotePower::new(1));
        assert!(tracker.check_quorum().is_none());

        tracker.add_verified_vote(make_verified_vote(1, root), VotePower::new(1));
        assert!(tracker.check_quorum().is_none());

        tracker.add_verified_vote(make_verified_vote(2, root), VotePower::new(1));
        let result = tracker.check_quorum();
        assert!(result.is_some());
        let (r, vh, power) = result.unwrap();
        assert_eq!(r, root);
        assert_eq!(vh, WeightedTimestamp::from_millis(11)); // vote_anchor_ts from make_vote
        assert_eq!(power, VotePower::new(3));
        assert_eq!(tracker.votes_for_global_receipt_root(root).len(), 3);
    }

    #[test]
    fn test_vote_tracker_conflicting_roots() {
        let mut tracker = VoteTracker::new(
            WaveId::new(ShardGroupId::new(0), BlockHeight::new(0), BTreeSet::new()),
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            VotePower::new(3),
        );

        let root_a = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root_a"));
        let root_b = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root_b"));

        tracker.add_verified_vote(make_verified_vote(0, root_a), VotePower::new(1));
        tracker.add_verified_vote(make_verified_vote(1, root_b), VotePower::new(1));
        tracker.add_verified_vote(make_verified_vote(2, root_a), VotePower::new(1));
        // 2 for root_a, 1 for root_b — no quorum
        assert!(tracker.check_quorum().is_none());

        tracker.add_verified_vote(make_verified_vote(3, root_a), VotePower::new(1));
        let result = tracker.check_quorum().unwrap();
        assert_eq!(result.0, root_a);
    }

    #[test]
    fn test_deferred_verification_flow() {
        let pk = make_test_public_key();
        let root = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root"));
        let mut tracker = VoteTracker::new(
            WaveId::new(ShardGroupId::new(0), BlockHeight::new(0), BTreeSet::new()),
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            VotePower::new(3),
        );

        // Buffer 2 votes — not enough for quorum
        assert!(tracker.buffer_unverified_vote(make_vote(0, root), pk, VotePower::new(1)));
        assert!(tracker.buffer_unverified_vote(make_vote(1, root), pk, VotePower::new(1)));
        assert!(!tracker.should_trigger_verification());

        // Buffer 3rd — now enough
        assert!(tracker.buffer_unverified_vote(make_vote(2, root), pk, VotePower::new(1)));
        assert!(tracker.should_trigger_verification());

        // Take votes
        let votes = tracker.take_unverified_votes();
        assert_eq!(votes.len(), 3);
        assert!(tracker.is_verification_pending());
        assert!(!tracker.should_trigger_verification());

        // Complete verification
        tracker.on_verification_complete();
        assert!(!tracker.is_verification_pending());
    }

    #[test]
    fn test_duplicate_validator_rejected() {
        let pk = make_test_public_key();
        let root = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root"));
        let mut tracker = VoteTracker::new(
            WaveId::new(ShardGroupId::new(0), BlockHeight::new(0), BTreeSet::new()),
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            VotePower::new(3),
        );

        assert!(tracker.buffer_unverified_vote(make_vote(0, root), pk, VotePower::new(1)));
        assert!(!tracker.buffer_unverified_vote(make_vote(0, root), pk, VotePower::new(1)));
    }

    #[test]
    fn duplicate_verified_vote_does_not_inflate_power() {
        // Own votes bypass `buffer_unverified_vote` and arrive directly at
        // `add_verified_vote`. Leader-rotation retries that land on `self`
        // re-feed the same own vote; the tally must count it once.
        let root = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root"));
        let mut tracker = VoteTracker::new(
            WaveId::new(ShardGroupId::new(0), BlockHeight::new(0), BTreeSet::new()),
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            VotePower::new(3),
        );

        tracker.add_verified_vote(make_verified_vote(0, root), VotePower::new(1));
        tracker.add_verified_vote(make_verified_vote(0, root), VotePower::new(1));
        tracker.add_verified_vote(make_verified_vote(0, root), VotePower::new(1));

        assert_eq!(tracker.total_verified_power(), VotePower::new(1));
        assert!(tracker.check_quorum().is_none());
    }

    #[test]
    fn test_combined_verified_and_unverified_power() {
        let pk = make_test_public_key();
        let root = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root"));
        let mut tracker = VoteTracker::new(
            WaveId::new(ShardGroupId::new(0), BlockHeight::new(0), BTreeSet::new()),
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            VotePower::new(3),
        );

        // 1 verified + 2 unverified = 3 → should trigger
        tracker.add_verified_vote(make_verified_vote(0, root), VotePower::new(1));
        assert!(tracker.buffer_unverified_vote(make_vote(1, root), pk, VotePower::new(1)));
        assert!(!tracker.should_trigger_verification());

        assert!(tracker.buffer_unverified_vote(make_vote(2, root), pk, VotePower::new(1)));
        assert!(tracker.should_trigger_verification());
    }
}
