//! Wave vote tracker for execution wave voting.
//!
//! Tracks the collection of execution wave votes during the cross-shard
//! atomic execution protocol. Replaces per-tx `VoteTracker` with per-wave
//! granularity for dramatically reduced message counts.
//!
//! ## Deferred Verification Optimization
//!
//! Same approach as the per-tx VoteTracker: votes are NOT verified when
//! received. Instead, they are buffered until we have enough voting power
//! for quorum. This avoids wasting CPU on votes we'll never use.

use hyperscale_types::{Bls12381G1PublicKey, ExecutionWaveVote, Hash, ValidatorId, WaveId};
use std::collections::{BTreeMap, HashSet};

/// Tracks wave votes for a specific wave within a block.
///
/// After executing all transactions in a wave, validators create a wave vote
/// on the wave receipt root. This tracker collects votes and determines when
/// quorum is reached for BLS signature aggregation into a wave certificate.
#[derive(Debug)]
pub struct WaveVoteTracker {
    /// Wave identifier.
    wave_id: WaveId,
    /// Block hash this wave belongs to.
    block_hash: Hash,
    /// Quorum threshold (2f+1 voting power).
    quorum: u64,

    // ═══════════════════════════════════════════════════════════════════════
    // Verified votes (passed signature verification)
    // ═══════════════════════════════════════════════════════════════════════
    /// Verified votes grouped by wave_receipt_root.
    votes_by_receipt_root: BTreeMap<Hash, Vec<ExecutionWaveVote>>,
    /// Voting power per receipt root (verified votes only).
    power_by_receipt_root: BTreeMap<Hash, u64>,

    // ═══════════════════════════════════════════════════════════════════════
    // Unverified votes (buffered until quorum possible)
    // ═══════════════════════════════════════════════════════════════════════
    /// Unverified votes buffered for batch verification.
    /// Each entry is (vote, public_key, voting_power).
    unverified_votes: Vec<(ExecutionWaveVote, Bls12381G1PublicKey, u64)>,
    /// Total voting power of unverified votes.
    unverified_power: u64,
    /// Validators we've already seen votes from (for deduplication).
    seen_validators: HashSet<ValidatorId>,
    /// Whether a verification batch is currently in flight.
    pending_verification: bool,
}

impl WaveVoteTracker {
    /// Create a new wave vote tracker.
    pub fn new(wave_id: WaveId, block_hash: Hash, quorum: u64) -> Self {
        Self {
            wave_id,
            block_hash,
            quorum,
            votes_by_receipt_root: BTreeMap::new(),
            power_by_receipt_root: BTreeMap::new(),
            unverified_votes: Vec::new(),
            unverified_power: 0,
            seen_validators: HashSet::new(),
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

    /// Check if we've already seen a vote from this validator.
    pub fn has_seen_validator(&self, validator_id: ValidatorId) -> bool {
        self.seen_validators.contains(&validator_id)
    }

    /// Buffer an unverified vote for later batch verification.
    ///
    /// Returns `true` if the vote was buffered, `false` if it was a duplicate.
    pub fn buffer_unverified_vote(
        &mut self,
        vote: ExecutionWaveVote,
        public_key: Bls12381G1PublicKey,
        voting_power: u64,
    ) -> bool {
        let validator_id = vote.validator;

        if self.seen_validators.contains(&validator_id) {
            return false;
        }

        self.seen_validators.insert(validator_id);
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

        let best_verified_power = self
            .power_by_receipt_root
            .values()
            .max()
            .copied()
            .unwrap_or(0);

        let total_potential = best_verified_power + self.unverified_power;
        total_potential >= self.quorum
    }

    /// Take unverified votes for batch verification.
    ///
    /// Marks verification as pending. Call `on_verification_complete` when done.
    pub fn take_unverified_votes(&mut self) -> Vec<(ExecutionWaveVote, Bls12381G1PublicKey, u64)> {
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
    pub fn add_verified_vote(&mut self, vote: ExecutionWaveVote, power: u64) {
        let receipt_root = vote.wave_receipt_root;
        self.votes_by_receipt_root
            .entry(receipt_root)
            .or_default()
            .push(vote);
        *self.power_by_receipt_root.entry(receipt_root).or_insert(0) += power;
    }

    /// Check if quorum is reached for any receipt root (verified votes only).
    ///
    /// Returns `Some((receipt_root, total_power))` if quorum is reached.
    pub fn check_quorum(&self) -> Option<(Hash, u64)> {
        for (receipt_root, power) in &self.power_by_receipt_root {
            if *power >= self.quorum {
                return Some((*receipt_root, *power));
            }
        }
        None
    }

    /// Take votes for a specific receipt root (ownership transfer).
    pub fn take_votes_for_receipt_root(&mut self, receipt_root: &Hash) -> Vec<ExecutionWaveVote> {
        self.votes_by_receipt_root
            .remove(receipt_root)
            .unwrap_or_default()
    }

    /// Get votes for a specific receipt root (reference, for tests).
    #[cfg(test)]
    pub fn votes_for_receipt_root(&self, receipt_root: &Hash) -> &[ExecutionWaveVote] {
        self.votes_by_receipt_root
            .get(receipt_root)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{generate_bls_keypair, zero_bls_signature, ShardGroupId};

    fn make_test_public_key() -> Bls12381G1PublicKey {
        generate_bls_keypair().public_key()
    }

    fn make_wave_vote(validator: u64, receipt_root: Hash) -> ExecutionWaveVote {
        ExecutionWaveVote {
            block_hash: Hash::from_bytes(b"block"),
            block_height: 10,
            wave_id: WaveId::zero(),
            shard_group_id: ShardGroupId(0),
            wave_receipt_root: receipt_root,
            tx_count: 5,
            validator: ValidatorId(validator),
            signature: zero_bls_signature(),
        }
    }

    #[test]
    fn test_wave_vote_tracker_quorum() {
        let mut tracker = WaveVoteTracker::new(WaveId::zero(), Hash::from_bytes(b"block"), 3);

        let root = Hash::from_bytes(b"receipt_root");

        tracker.add_verified_vote(make_wave_vote(0, root), 1);
        assert!(tracker.check_quorum().is_none());

        tracker.add_verified_vote(make_wave_vote(1, root), 1);
        assert!(tracker.check_quorum().is_none());

        tracker.add_verified_vote(make_wave_vote(2, root), 1);
        let result = tracker.check_quorum();
        assert!(result.is_some());
        let (r, power) = result.unwrap();
        assert_eq!(r, root);
        assert_eq!(power, 3);
        assert_eq!(tracker.votes_for_receipt_root(&root).len(), 3);
    }

    #[test]
    fn test_wave_vote_tracker_conflicting_roots() {
        let mut tracker = WaveVoteTracker::new(WaveId::zero(), Hash::from_bytes(b"block"), 3);

        let root_a = Hash::from_bytes(b"root_a");
        let root_b = Hash::from_bytes(b"root_b");

        tracker.add_verified_vote(make_wave_vote(0, root_a), 1);
        tracker.add_verified_vote(make_wave_vote(1, root_b), 1);
        tracker.add_verified_vote(make_wave_vote(2, root_a), 1);
        // 2 for root_a, 1 for root_b — no quorum
        assert!(tracker.check_quorum().is_none());

        tracker.add_verified_vote(make_wave_vote(3, root_a), 1);
        let result = tracker.check_quorum().unwrap();
        assert_eq!(result.0, root_a);
    }

    #[test]
    fn test_deferred_verification_flow() {
        let pk = make_test_public_key();
        let root = Hash::from_bytes(b"root");
        let mut tracker = WaveVoteTracker::new(WaveId::zero(), Hash::from_bytes(b"block"), 3);

        // Buffer 2 votes — not enough for quorum
        assert!(tracker.buffer_unverified_vote(make_wave_vote(0, root), pk, 1));
        assert!(tracker.buffer_unverified_vote(make_wave_vote(1, root), pk, 1));
        assert!(!tracker.should_trigger_verification());

        // Buffer 3rd — now enough
        assert!(tracker.buffer_unverified_vote(make_wave_vote(2, root), pk, 1));
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
        let mut tracker = WaveVoteTracker::new(WaveId::zero(), Hash::from_bytes(b"block"), 3);

        assert!(tracker.buffer_unverified_vote(make_wave_vote(0, root), pk, 1));
        assert!(!tracker.buffer_unverified_vote(make_wave_vote(0, root), pk, 1));
    }

    #[test]
    fn test_combined_verified_and_unverified_power() {
        let pk = make_test_public_key();
        let root = Hash::from_bytes(b"root");
        let mut tracker = WaveVoteTracker::new(WaveId::zero(), Hash::from_bytes(b"block"), 3);

        // 1 verified + 2 unverified = 3 → should trigger
        tracker.add_verified_vote(make_wave_vote(0, root), 1);
        assert!(tracker.buffer_unverified_vote(make_wave_vote(1, root), pk, 1));
        assert!(!tracker.should_trigger_verification());

        assert!(tracker.buffer_unverified_vote(make_wave_vote(2, root), pk, 1));
        assert!(tracker.should_trigger_verification());
    }
}
