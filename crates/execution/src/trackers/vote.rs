//! Vote tracker for cross-shard execution voting.
//!
//! Tracks the collection of execution votes during Phase 4 of the
//! cross-shard 2PC protocol.
//!
//! ## Deferred Verification Optimization
//!
//! Votes are NOT verified when received. Instead, they are buffered until
//! we have enough for quorum (threshold count). At that point, we send a single
//! `VerifyAndAggregateStateVotes` action that batch-verifies all signatures.
//!
//! This avoids wasting CPU on votes we'll never use (e.g., if we only
//! receive 2 of 3 needed votes, we don't verify any).

use hyperscale_types::{
    Bls12381G1PublicKey, Hash, NodeId, ShardGroupId, StateVoteBlock, ValidatorId,
};
use std::collections::{BTreeMap, HashSet};
use tracing::instrument;

/// Tracks votes for a cross-shard transaction.
///
/// After executing a transaction with provisioned state, validators create
/// votes on the execution result (merkle root). This tracker collects votes
/// and determines when quorum is reached.
///
/// The tracker now supports deferred verification: unverified votes are buffered
/// until we have enough voting power to possibly reach quorum, then batch-verified.
#[derive(Debug)]
pub struct VoteTracker {
    /// Transaction hash.
    tx_hash: Hash,
    /// Participating shards (for broadcasting certificate).
    participating_shards: Vec<ShardGroupId>,
    /// Read nodes from transaction.
    read_nodes: Vec<NodeId>,
    /// Quorum threshold (2f+1).
    quorum: u64,

    // ═══════════════════════════════════════════════════════════════════════
    // Verified votes (passed signature verification)
    // ═══════════════════════════════════════════════════════════════════════
    /// Verified votes grouped by merkle root.
    votes_by_root: BTreeMap<Hash, Vec<StateVoteBlock>>,
    /// Voting power per merkle root (verified votes only).
    power_by_root: BTreeMap<Hash, u64>,

    // ═══════════════════════════════════════════════════════════════════════
    // Unverified votes (buffered until quorum possible)
    // ═══════════════════════════════════════════════════════════════════════
    /// Unverified votes buffered for batch verification.
    /// Each entry is (vote, public_key, voting_power).
    unverified_votes: Vec<(StateVoteBlock, Bls12381G1PublicKey, u64)>,
    /// Total voting power of unverified votes.
    unverified_power: u64,
    /// Validators we've already seen votes from (for deduplication).
    seen_validators: HashSet<ValidatorId>,
    /// Whether a verification batch is currently in flight.
    pending_verification: bool,
}

impl VoteTracker {
    /// Create a new vote tracker.
    ///
    /// # Arguments
    ///
    /// * `tx_hash` - The transaction being tracked
    /// * `participating_shards` - All shards involved in this transaction
    /// * `read_nodes` - Nodes read by this transaction
    /// * `quorum` - Voting power required for quorum
    pub fn new(
        tx_hash: Hash,
        participating_shards: Vec<ShardGroupId>,
        read_nodes: Vec<NodeId>,
        quorum: u64,
    ) -> Self {
        Self {
            tx_hash,
            participating_shards,
            read_nodes,
            quorum,
            votes_by_root: BTreeMap::new(),
            power_by_root: BTreeMap::new(),
            unverified_votes: Vec::new(),
            unverified_power: 0,
            seen_validators: HashSet::new(),
            pending_verification: false,
        }
    }

    /// Get the participating shards.
    pub fn participating_shards(&self) -> &[ShardGroupId] {
        &self.participating_shards
    }

    /// Get the read nodes.
    pub fn read_nodes(&self) -> &[NodeId] {
        &self.read_nodes
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Deferred Verification Methods
    // ═══════════════════════════════════════════════════════════════════════════

    /// Check if we've already seen a vote from this validator.
    pub fn has_seen_validator(&self, validator_id: ValidatorId) -> bool {
        self.seen_validators.contains(&validator_id)
    }

    /// Buffer an unverified vote for later batch verification.
    ///
    /// Returns `true` if the vote was buffered, `false` if it was a duplicate.
    pub fn buffer_unverified_vote(
        &mut self,
        vote: StateVoteBlock,
        public_key: Bls12381G1PublicKey,
        voting_power: u64,
    ) -> bool {
        let validator_id = vote.validator;

        // Deduplication check
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

        // Get the best verified power (highest power for any merkle root)
        let best_verified_power = self.power_by_root.values().max().copied().unwrap_or(0);

        // Total potential power if all unverified votes are valid and agree
        let total_potential = best_verified_power + self.unverified_power;

        total_potential >= self.quorum
    }

    /// Take unverified votes for batch verification.
    ///
    /// Marks verification as pending. Call `on_verification_complete` when done.
    pub fn take_unverified_votes(&mut self) -> Vec<(StateVoteBlock, Bls12381G1PublicKey, u64)> {
        self.pending_verification = true;
        self.unverified_power = 0;
        std::mem::take(&mut self.unverified_votes)
    }

    /// Handle verification completion.
    ///
    /// Clears the pending flag so new votes can trigger another verification batch.
    pub fn on_verification_complete(&mut self) {
        self.pending_verification = false;
    }

    /// Check if verification is pending (test helper).
    #[cfg(test)]
    pub fn is_verification_pending(&self) -> bool {
        self.pending_verification
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Verified Vote Methods
    // ═══════════════════════════════════════════════════════════════════════════

    /// Add a verified vote and its voting power.
    #[instrument(level = "debug", skip(self, vote), fields(
        tx_hash = %self.tx_hash,
        validator = vote.validator.0,
        power = power,
        quorum = self.quorum,
    ))]
    pub fn add_verified_vote(&mut self, vote: StateVoteBlock, power: u64) {
        let state_root = vote.state_root;
        self.votes_by_root.entry(state_root).or_default().push(vote);
        *self.power_by_root.entry(state_root).or_insert(0) += power;
    }

    /// Check if quorum is reached for any merkle root (verified votes only).
    ///
    /// Returns `Some((merkle_root, total_power))` if quorum is reached, `None` otherwise.
    /// Use `votes_for_root()` to get the actual votes after checking quorum.
    pub fn check_quorum(&self) -> Option<(Hash, u64)> {
        for (merkle_root, power) in &self.power_by_root {
            if *power >= self.quorum {
                return Some((*merkle_root, *power));
            }
        }
        None
    }

    /// Get votes for a specific merkle root (reference).
    #[cfg(test)]
    pub fn votes_for_root(&self, merkle_root: &Hash) -> &[StateVoteBlock] {
        self.votes_by_root
            .get(merkle_root)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Take votes for a specific merkle root (ownership transfer, avoids clone).
    pub fn take_votes_for_root(&mut self, merkle_root: &Hash) -> Vec<StateVoteBlock> {
        self.votes_by_root.remove(merkle_root).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{generate_bls_keypair, zero_bls_signature, ValidatorId};

    fn make_test_public_key() -> Bls12381G1PublicKey {
        generate_bls_keypair().public_key()
    }

    #[test]
    fn test_vote_tracker_quorum() {
        let tx_hash = Hash::from_bytes(b"test_tx");
        let merkle_root = Hash::from_bytes(b"merkle_root");

        let mut tracker = VoteTracker::new(
            tx_hash,
            vec![ShardGroupId(0)],
            vec![],
            3, // quorum = 3
        );

        let vote = StateVoteBlock {
            transaction_hash: tx_hash,
            shard_group_id: ShardGroupId(0),
            state_root: merkle_root,
            success: true,
            state_writes: vec![],
            validator: ValidatorId(0),
            signature: zero_bls_signature(),
        };

        // Not quorum yet
        tracker.add_verified_vote(vote.clone(), 1);
        assert!(tracker.check_quorum().is_none());

        tracker.add_verified_vote(vote.clone(), 1);
        assert!(tracker.check_quorum().is_none());

        tracker.add_verified_vote(vote.clone(), 1);

        // Now quorum
        let result = tracker.check_quorum();
        assert!(result.is_some());
        let (root, power) = result.unwrap();
        assert_eq!(root, merkle_root);
        assert_eq!(tracker.votes_for_root(&root).len(), 3);
        assert_eq!(power, 3);
    }

    #[test]
    fn test_vote_tracker_multiple_roots() {
        let tx_hash = Hash::from_bytes(b"test_tx");
        let root_a = Hash::from_bytes(b"root_a");
        let root_b = Hash::from_bytes(b"root_b");

        let mut tracker = VoteTracker::new(tx_hash, vec![ShardGroupId(0)], vec![], 3);

        let vote_a = StateVoteBlock {
            transaction_hash: tx_hash,
            shard_group_id: ShardGroupId(0),
            state_root: root_a,
            success: true,
            state_writes: vec![],
            validator: ValidatorId(0),
            signature: zero_bls_signature(),
        };

        let vote_b = StateVoteBlock {
            transaction_hash: tx_hash,
            shard_group_id: ShardGroupId(0),
            state_root: root_b,
            success: true,
            state_writes: vec![],
            validator: ValidatorId(1),
            signature: zero_bls_signature(),
        };

        // Split votes - no quorum
        tracker.add_verified_vote(vote_a.clone(), 1);
        tracker.add_verified_vote(vote_b.clone(), 1);
        tracker.add_verified_vote(vote_a.clone(), 1);
        assert!(tracker.check_quorum().is_none());

        // Third vote for root_a reaches quorum
        tracker.add_verified_vote(vote_a.clone(), 1);
        let result = tracker.check_quorum();
        assert!(result.is_some());
        let (root, _power) = result.unwrap();
        assert_eq!(root, root_a);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Deferred Verification Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_buffer_unverified_vote() {
        let tx_hash = Hash::from_bytes(b"test_tx");
        let merkle_root = Hash::from_bytes(b"merkle_root");
        let pk = make_test_public_key();

        let mut tracker = VoteTracker::new(tx_hash, vec![ShardGroupId(0)], vec![], 3);

        let vote = StateVoteBlock {
            transaction_hash: tx_hash,
            shard_group_id: ShardGroupId(0),
            state_root: merkle_root,
            success: true,
            state_writes: vec![],
            validator: ValidatorId(0),
            signature: zero_bls_signature(),
        };

        // First buffer should succeed
        assert!(tracker.buffer_unverified_vote(vote.clone(), pk, 1));

        // Duplicate should fail
        assert!(!tracker.buffer_unverified_vote(vote.clone(), pk, 1));

        // Different validator should succeed
        let vote2 = StateVoteBlock {
            validator: ValidatorId(1),
            ..vote
        };
        assert!(tracker.buffer_unverified_vote(vote2, pk, 1));
    }

    #[test]
    fn test_should_trigger_verification_not_enough_power() {
        let tx_hash = Hash::from_bytes(b"test_tx");
        let merkle_root = Hash::from_bytes(b"merkle_root");
        let pk = make_test_public_key();

        let mut tracker = VoteTracker::new(tx_hash, vec![ShardGroupId(0)], vec![], 3);

        let vote = StateVoteBlock {
            transaction_hash: tx_hash,
            shard_group_id: ShardGroupId(0),
            state_root: merkle_root,
            success: true,
            state_writes: vec![],
            validator: ValidatorId(0),
            signature: zero_bls_signature(),
        };

        // Only 1 vote with power 1, quorum is 3 - should not trigger
        tracker.buffer_unverified_vote(vote, pk, 1);
        assert!(!tracker.should_trigger_verification());
    }

    #[test]
    fn test_should_trigger_verification_enough_power() {
        let tx_hash = Hash::from_bytes(b"test_tx");
        let merkle_root = Hash::from_bytes(b"merkle_root");
        let pk = make_test_public_key();

        let mut tracker = VoteTracker::new(tx_hash, vec![ShardGroupId(0)], vec![], 3);

        // Buffer 3 votes with power 1 each - should trigger
        for i in 0..3 {
            let vote = StateVoteBlock {
                transaction_hash: tx_hash,
                shard_group_id: ShardGroupId(0),
                state_root: merkle_root,
                success: true,
                state_writes: vec![],
                validator: ValidatorId(i),
                signature: zero_bls_signature(),
            };
            tracker.buffer_unverified_vote(vote, pk, 1);
        }

        assert!(tracker.should_trigger_verification());
    }

    #[test]
    fn test_take_unverified_votes() {
        let tx_hash = Hash::from_bytes(b"test_tx");
        let merkle_root = Hash::from_bytes(b"merkle_root");
        let pk = make_test_public_key();

        let mut tracker = VoteTracker::new(tx_hash, vec![ShardGroupId(0)], vec![], 3);

        // Buffer votes
        for i in 0..3 {
            let vote = StateVoteBlock {
                transaction_hash: tx_hash,
                shard_group_id: ShardGroupId(0),
                state_root: merkle_root,
                success: true,
                state_writes: vec![],
                validator: ValidatorId(i),
                signature: zero_bls_signature(),
            };
            tracker.buffer_unverified_vote(vote, pk, 1);
        }

        // Take votes
        let votes = tracker.take_unverified_votes();
        assert_eq!(votes.len(), 3);
        assert!(tracker.is_verification_pending());

        // Should not trigger again while pending
        assert!(!tracker.should_trigger_verification());

        // Complete verification
        tracker.on_verification_complete();
        assert!(!tracker.is_verification_pending());
    }

    #[test]
    fn test_deferred_verification_with_verified_votes() {
        let tx_hash = Hash::from_bytes(b"test_tx");
        let merkle_root = Hash::from_bytes(b"merkle_root");
        let pk = make_test_public_key();

        let mut tracker = VoteTracker::new(tx_hash, vec![ShardGroupId(0)], vec![], 3);

        // Add 1 verified vote
        let vote1 = StateVoteBlock {
            transaction_hash: tx_hash,
            shard_group_id: ShardGroupId(0),
            state_root: merkle_root,
            success: true,
            state_writes: vec![],
            validator: ValidatorId(0),
            signature: zero_bls_signature(),
        };
        tracker.add_verified_vote(vote1, 1);

        // 1 verified + 1 unverified = 2, not enough for quorum 3
        let vote2 = StateVoteBlock {
            validator: ValidatorId(1),
            ..tracker.votes_by_root.values().next().unwrap()[0].clone()
        };
        tracker.buffer_unverified_vote(vote2, pk, 1);
        assert!(!tracker.should_trigger_verification());

        // Add another unverified - now 1 verified + 2 unverified = 3, should trigger
        let vote3 = StateVoteBlock {
            transaction_hash: tx_hash,
            shard_group_id: ShardGroupId(0),
            state_root: merkle_root,
            success: true,
            state_writes: vec![],
            validator: ValidatorId(2),
            signature: zero_bls_signature(),
        };
        tracker.buffer_unverified_vote(vote3, pk, 1);
        assert!(tracker.should_trigger_verification());
    }
}
