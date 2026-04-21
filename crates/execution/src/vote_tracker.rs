//! Execution vote tracker.
//!
//! Tracks the collection of execution votes during the cross-shard
//! atomic execution protocol.
//!
//! ## Round Voting
//!
//! Validators vote at each block commit where their wave is complete.
//! Votes include `vote_anchor_ts_ms` in the BLS-signed message, so votes at
//! different heights have different signatures and cannot be aggregated.
//! The tracker groups by `(global_receipt_root, vote_anchor_ts_ms)` and checks quorum
//! per group.
//!
//! ## Deferred Verification Optimization
//!
//! Votes are NOT verified when received. Instead, they are buffered until
//! we have enough voting power for quorum. This avoids wasting CPU on votes
//! we'll never use.

use hyperscale_types::{Bls12381G1PublicKey, ExecutionVote, Hash, ValidatorId, WaveId};
use std::collections::{BTreeMap, HashSet};

/// Key for grouping votes: `(global_receipt_root, vote_anchor_ts_ms)`.
///
/// Votes at different heights have different BLS signatures and cannot be
/// aggregated together. This prevents stale votes from combining with new
/// ones if an abort intent changes the global_receipt_root between heights.
type VoteKey = (Hash, u64);

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
    block_hash: Hash,
    /// Quorum threshold (2f+1 voting power).
    quorum: u64,

    // ═══════════════════════════════════════════════════════════════════════
    // Verified votes (passed signature verification)
    // ═══════════════════════════════════════════════════════════════════════
    /// Verified votes grouped by (global_receipt_root, vote_anchor_ts_ms).
    votes_by_key: BTreeMap<VoteKey, Vec<ExecutionVote>>,
    /// Voting power per (global_receipt_root, vote_anchor_ts_ms) (verified votes only).
    power_by_key: BTreeMap<VoteKey, u64>,

    // ═══════════════════════════════════════════════════════════════════════
    // Unverified votes (buffered until quorum possible)
    // ═══════════════════════════════════════════════════════════════════════
    /// Unverified votes buffered for batch verification.
    /// Each entry is (vote, public_key, voting_power).
    unverified_votes: Vec<(ExecutionVote, Bls12381G1PublicKey, u64)>,
    /// Total voting power of unverified votes.
    unverified_power: u64,
    /// Validators we've already seen votes from at each vote_anchor_ts_ms (dedup).
    /// Key is (validator_id, vote_anchor_ts_ms).
    seen: HashSet<(ValidatorId, u64)>,
    /// Whether a verification batch is currently in flight.
    pending_verification: bool,
}

impl VoteTracker {
    /// Create a new execution vote tracker.
    pub fn new(wave_id: WaveId, block_hash: Hash, quorum: u64) -> Self {
        Self {
            wave_id,
            block_hash,
            quorum,
            votes_by_key: BTreeMap::new(),
            power_by_key: BTreeMap::new(),
            unverified_votes: Vec::new(),
            unverified_power: 0,
            seen: HashSet::new(),
            pending_verification: false,
        }
    }

    /// Get the wave ID.
    pub fn wave_id(&self) -> &WaveId {
        &self.wave_id
    }

    /// Get the block hash.
    pub fn block_hash(&self) -> Hash {
        self.block_hash
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Deferred Verification Methods
    // ═══════════════════════════════════════════════════════════════════════

    /// Buffer an unverified vote for later batch verification.
    ///
    /// Returns `true` if the vote was buffered, `false` if it was a duplicate.
    /// Dedup is per (validator, vote_anchor_ts_ms) — the same validator can vote at
    /// multiple heights (round voting), but only once per height.
    pub fn buffer_unverified_vote(
        &mut self,
        vote: ExecutionVote,
        public_key: Bls12381G1PublicKey,
        voting_power: u64,
    ) -> bool {
        let dedup_key = (vote.validator, vote.vote_anchor_ts_ms);

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
    pub fn should_trigger_verification(&self) -> bool {
        if self.unverified_votes.is_empty() || self.pending_verification {
            return false;
        }

        let best_verified_power = self.power_by_key.values().max().copied().unwrap_or(0);

        let total_potential = best_verified_power + self.unverified_power;
        total_potential >= self.quorum
    }

    /// Take unverified votes for batch verification.
    ///
    /// Marks verification as pending. Call `on_verification_complete` when done.
    pub fn take_unverified_votes(&mut self) -> Vec<(ExecutionVote, Bls12381G1PublicKey, u64)> {
        self.pending_verification = true;
        self.unverified_power = 0;
        std::mem::take(&mut self.unverified_votes)
    }

    /// Handle verification completion.
    pub fn on_verification_complete(&mut self) {
        self.pending_verification = false;
    }

    /// Check if verification is pending.
    #[cfg(test)]
    pub fn is_verification_pending(&self) -> bool {
        self.pending_verification
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Verified Vote Methods
    // ═══════════════════════════════════════════════════════════════════════

    /// Add a verified vote and its voting power.
    pub fn add_verified_vote(&mut self, vote: ExecutionVote, power: u64) {
        let key = (vote.global_receipt_root, vote.vote_anchor_ts_ms);
        self.votes_by_key.entry(key).or_default().push(vote);
        *self.power_by_key.entry(key).or_insert(0) += power;
    }

    /// Check if quorum is reached for any (global_receipt_root, vote_anchor_ts_ms) pair.
    ///
    /// Returns `Some((global_receipt_root, vote_anchor_ts_ms, total_power))` if quorum reached.
    /// If multiple pairs have quorum, returns the one with the lowest vote_anchor_ts_ms.
    pub fn check_quorum(&self) -> Option<(Hash, u64, u64)> {
        let mut best: Option<(Hash, u64, u64)> = None;
        for (&(global_receipt_root, vote_anchor_ts_ms), &power) in &self.power_by_key {
            if power >= self.quorum {
                match &best {
                    Some((_, best_height, _)) if vote_anchor_ts_ms >= *best_height => {}
                    _ => best = Some((global_receipt_root, vote_anchor_ts_ms, power)),
                }
            }
        }
        best
    }

    /// Take votes for a specific (global_receipt_root, vote_anchor_ts_ms) pair.
    pub fn take_votes(
        &mut self,
        global_receipt_root: &Hash,
        vote_anchor_ts_ms: u64,
    ) -> Vec<ExecutionVote> {
        let key = (*global_receipt_root, vote_anchor_ts_ms);
        self.votes_by_key.remove(&key).unwrap_or_default()
    }

    /// Return the total verified voting power across all (global_receipt_root, vote_anchor_ts_ms) groups.
    pub fn total_verified_power(&self) -> u64 {
        self.power_by_key.values().sum()
    }

    /// Return the number of distinct receipt roots across all verified vote groups.
    pub fn distinct_global_receipt_root_count(&self) -> usize {
        self.power_by_key
            .keys()
            .map(|(root, _)| root)
            .collect::<HashSet<_>>()
            .len()
    }

    /// Return a summary of verified voting power per global receipt root (summed across vote heights).
    /// Used for diagnostics when quorum cannot be reached.
    pub fn global_receipt_root_power_summary(&self) -> Vec<(Hash, u64)> {
        let mut by_root: BTreeMap<Hash, u64> = BTreeMap::new();
        for (&(root, _), &power) in &self.power_by_key {
            *by_root.entry(root).or_insert(0) += power;
        }
        by_root.into_iter().collect()
    }

    /// Get votes for a specific global receipt root at any height (for tests).
    #[cfg(test)]
    pub fn votes_for_global_receipt_root(&self, global_receipt_root: &Hash) -> Vec<&ExecutionVote> {
        self.votes_by_key
            .iter()
            .filter(|((root, _), _)| root == global_receipt_root)
            .flat_map(|(_, votes)| votes.iter())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{generate_bls_keypair, zero_bls_signature, ShardGroupId};
    use std::collections::BTreeSet;

    fn make_test_public_key() -> Bls12381G1PublicKey {
        generate_bls_keypair().public_key()
    }

    fn make_vote(validator: u64, global_receipt_root: Hash) -> ExecutionVote {
        ExecutionVote {
            block_hash: Hash::from_bytes(b"block"),
            block_height: 10,
            vote_anchor_ts_ms: 11,
            wave_id: WaveId::new(ShardGroupId(0), 0, BTreeSet::new()),
            shard_group_id: ShardGroupId(0),
            global_receipt_root,
            tx_count: 5,
            tx_outcomes: vec![],
            validator: ValidatorId(validator),
            signature: zero_bls_signature(),
        }
    }

    #[test]
    fn test_vote_tracker_quorum() {
        let mut tracker = VoteTracker::new(
            WaveId::new(ShardGroupId(0), 0, BTreeSet::new()),
            Hash::from_bytes(b"block"),
            3,
        );

        let root = Hash::from_bytes(b"receipt_root");

        tracker.add_verified_vote(make_vote(0, root), 1);
        assert!(tracker.check_quorum().is_none());

        tracker.add_verified_vote(make_vote(1, root), 1);
        assert!(tracker.check_quorum().is_none());

        tracker.add_verified_vote(make_vote(2, root), 1);
        let result = tracker.check_quorum();
        assert!(result.is_some());
        let (r, vh, power) = result.unwrap();
        assert_eq!(r, root);
        assert_eq!(vh, 11); // vote_anchor_ts_ms from make_vote
        assert_eq!(power, 3);
        assert_eq!(tracker.votes_for_global_receipt_root(&root).len(), 3);
    }

    #[test]
    fn test_vote_tracker_conflicting_roots() {
        let mut tracker = VoteTracker::new(
            WaveId::new(ShardGroupId(0), 0, BTreeSet::new()),
            Hash::from_bytes(b"block"),
            3,
        );

        let root_a = Hash::from_bytes(b"root_a");
        let root_b = Hash::from_bytes(b"root_b");

        tracker.add_verified_vote(make_vote(0, root_a), 1);
        tracker.add_verified_vote(make_vote(1, root_b), 1);
        tracker.add_verified_vote(make_vote(2, root_a), 1);
        // 2 for root_a, 1 for root_b — no quorum
        assert!(tracker.check_quorum().is_none());

        tracker.add_verified_vote(make_vote(3, root_a), 1);
        let result = tracker.check_quorum().unwrap();
        assert_eq!(result.0, root_a);
    }

    #[test]
    fn test_deferred_verification_flow() {
        let pk = make_test_public_key();
        let root = Hash::from_bytes(b"root");
        let mut tracker = VoteTracker::new(
            WaveId::new(ShardGroupId(0), 0, BTreeSet::new()),
            Hash::from_bytes(b"block"),
            3,
        );

        // Buffer 2 votes — not enough for quorum
        assert!(tracker.buffer_unverified_vote(make_vote(0, root), pk, 1));
        assert!(tracker.buffer_unverified_vote(make_vote(1, root), pk, 1));
        assert!(!tracker.should_trigger_verification());

        // Buffer 3rd — now enough
        assert!(tracker.buffer_unverified_vote(make_vote(2, root), pk, 1));
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
        let root = Hash::from_bytes(b"root");
        let mut tracker = VoteTracker::new(
            WaveId::new(ShardGroupId(0), 0, BTreeSet::new()),
            Hash::from_bytes(b"block"),
            3,
        );

        assert!(tracker.buffer_unverified_vote(make_vote(0, root), pk, 1));
        assert!(!tracker.buffer_unverified_vote(make_vote(0, root), pk, 1));
    }

    #[test]
    fn test_combined_verified_and_unverified_power() {
        let pk = make_test_public_key();
        let root = Hash::from_bytes(b"root");
        let mut tracker = VoteTracker::new(
            WaveId::new(ShardGroupId(0), 0, BTreeSet::new()),
            Hash::from_bytes(b"block"),
            3,
        );

        // 1 verified + 2 unverified = 3 → should trigger
        tracker.add_verified_vote(make_vote(0, root), 1);
        assert!(tracker.buffer_unverified_vote(make_vote(1, root), pk, 1));
        assert!(!tracker.should_trigger_verification());

        assert!(tracker.buffer_unverified_vote(make_vote(2, root), pk, 1));
        assert!(tracker.should_trigger_verification());
    }
}
