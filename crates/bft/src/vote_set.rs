//! Vote set for collecting block votes.
//!
//! ## Deferred Verification Optimization
//!
//! Votes are NOT verified when received. Instead, they are buffered until
//! we have enough for quorum. At that point, we send a single
//! `VerifyAndBuildQuorumCertificate` action that batch-verifies all signatures
//! and builds the QC in one operation.
//!
//! This avoids wasting CPU on votes we'll never use (e.g., if a block
//! never reaches quorum due to view change or leader failure).

#[cfg(test)]
use hyperscale_types::QuorumCertificate;
use hyperscale_types::{BlockHeader, BlockHeight, BlockVote, Hash, PublicKey, VotePower};

/// Votes for a specific block.
///
/// The vote set supports deferred verification: unverified votes are buffered
/// until we have enough voting power to possibly reach quorum, then batch-verified.
#[derive(Debug, Clone)]
pub struct VoteSet {
    /// Block hash being voted on.
    block_hash: Option<Hash>,

    /// Block height.
    height: Option<BlockHeight>,

    /// Round number when votes are collected.
    round: Option<u64>,

    /// Parent block hash (from the block's header).
    parent_block_hash: Option<Hash>,

    // ═══════════════════════════════════════════════════════════════════════
    // Verified votes (passed signature verification)
    // ═══════════════════════════════════════════════════════════════════════
    /// Verified votes with their committee indices.
    /// Each tuple is (committee_index, vote, voting_power).
    verified_votes: Vec<(usize, BlockVote, u64)>,

    /// Total voting power from verified votes.
    verified_power: u64,

    /// Sum of (timestamp * stake_weight) for verified votes.
    verified_timestamp_weight_sum: u128,

    // ═══════════════════════════════════════════════════════════════════════
    // Unverified votes (buffered until quorum possible)
    // ═══════════════════════════════════════════════════════════════════════
    /// Unverified votes buffered for batch verification.
    /// Each tuple is (committee_index, vote, public_key, voting_power).
    unverified_votes: Vec<(usize, BlockVote, PublicKey, u64)>,

    /// Total voting power of unverified votes.
    unverified_power: u64,

    /// Bitfield tracking which validators we've seen votes from (verified or unverified).
    /// Used for deduplication.
    seen_validators: Vec<bool>,

    /// Whether a verification batch is currently in flight.
    pending_verification: bool,

    /// Whether QC has already been built from this vote set.
    qc_built: bool,
}

impl VoteSet {
    /// Create a new vote set.
    pub fn new(header: Option<BlockHeader>, num_validators: usize) -> Self {
        let (block_hash, height, round, parent_block_hash) = if let Some(h) = &header {
            (
                Some(h.hash()),
                Some(h.height),
                Some(h.round),
                Some(h.parent_hash),
            )
        } else {
            (None, None, None, None)
        };

        Self {
            block_hash,
            height,
            round,
            parent_block_hash,
            verified_votes: Vec::new(),
            verified_power: 0,
            verified_timestamp_weight_sum: 0,
            unverified_votes: Vec::new(),
            unverified_power: 0,
            seen_validators: vec![false; num_validators],
            pending_verification: false,
            qc_built: false,
        }
    }

    /// Get the block height.
    pub fn height(&self) -> Option<u64> {
        self.height.map(|h| h.0)
    }

    /// Get the round number.
    pub fn round(&self) -> Option<u64> {
        self.round
    }

    /// Get the current verified voting power.
    pub fn verified_power(&self) -> u64 {
        self.verified_power
    }

    /// Get the current unverified voting power.
    pub fn unverified_power(&self) -> u64 {
        self.unverified_power
    }

    /// Check if we've already seen a vote from this validator.
    pub fn has_seen_validator(&self, committee_index: usize) -> bool {
        committee_index < self.seen_validators.len() && self.seen_validators[committee_index]
    }

    /// Update the vote set with header information.
    ///
    /// This is needed when votes arrive before the header. The vote set
    /// can accumulate votes, but it needs the header info (particularly
    /// parent_block_hash) to trigger verification.
    pub fn set_header(&mut self, header: &BlockHeader) {
        if self.height.is_none() {
            self.height = Some(header.height);
        }
        if self.round.is_none() {
            self.round = Some(header.round);
        }
        if self.parent_block_hash.is_none() {
            self.parent_block_hash = Some(header.parent_hash);
        }
        if self.block_hash.is_none() {
            self.block_hash = Some(header.hash());
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Unverified Vote Buffering
    // ═══════════════════════════════════════════════════════════════════════════

    /// Buffer an unverified vote for later batch verification.
    ///
    /// Returns `true` if the vote was buffered, `false` if it was a duplicate.
    pub fn buffer_unverified_vote(
        &mut self,
        committee_index: usize,
        vote: BlockVote,
        public_key: PublicKey,
        voting_power: u64,
    ) -> bool {
        // Check for duplicate
        if self.has_seen_validator(committee_index) {
            return false;
        }

        // Update block hash, height, and round from first vote if not set
        if self.block_hash.is_none() {
            self.block_hash = Some(vote.block_hash);
            self.height = Some(vote.height);
            self.round = Some(vote.round);
        }

        // Mark as seen
        if committee_index < self.seen_validators.len() {
            self.seen_validators[committee_index] = true;
        }

        self.unverified_power += voting_power;
        self.unverified_votes
            .push((committee_index, vote, public_key, voting_power));

        true
    }

    /// Check if we should trigger batch verification.
    ///
    /// Returns true if:
    /// - We have enough total power (verified + unverified) to possibly reach quorum
    /// - We have unverified votes to verify
    /// - We're not already waiting for a verification result
    /// - We have the header info needed to build a QC
    pub fn should_trigger_verification(&self, total_committee_power: u64) -> bool {
        !self.pending_verification
            && !self.qc_built
            && !self.unverified_votes.is_empty()
            && self.parent_block_hash.is_some()
            && VotePower::has_quorum(
                self.verified_power + self.unverified_power,
                total_committee_power,
            )
    }

    /// Take the unverified votes for batch verification.
    ///
    /// Returns the votes and marks the vote set as pending verification.
    /// Each tuple is (committee_index, vote, public_key, voting_power).
    pub fn take_unverified_votes(&mut self) -> Vec<(usize, BlockVote, PublicKey, u64)> {
        self.pending_verification = true;
        self.unverified_power = 0;
        std::mem::take(&mut self.unverified_votes)
    }

    /// Get copies of the already-verified votes.
    ///
    /// These are votes that were added via `add_verified_vote` (e.g., our own vote)
    /// and need to be included in the QC along with newly verified votes.
    pub fn get_verified_votes(&self) -> Vec<(usize, BlockVote, u64)> {
        self.verified_votes.clone()
    }

    /// Get data needed for verification action.
    ///
    /// Returns (block_hash, height, round, parent_block_hash) or None if not ready.
    pub fn verification_data(&self) -> Option<(Hash, BlockHeight, u64, Hash)> {
        Some((
            self.block_hash?,
            self.height?,
            self.round.unwrap_or(0),
            self.parent_block_hash?,
        ))
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Verification Result Handling
    // ═══════════════════════════════════════════════════════════════════════════

    /// Called when verification completes successfully with a QC.
    ///
    /// Marks the vote set as built.
    pub fn on_qc_built(&mut self) {
        self.qc_built = true;
        self.pending_verification = false;
    }

    /// Called when verification completes but quorum wasn't reached.
    ///
    /// Adds the verified votes to the verified set and clears pending flag.
    pub fn on_votes_verified(&mut self, verified_votes: Vec<(usize, BlockVote, u64)>) {
        self.pending_verification = false;

        for (committee_index, vote, voting_power) in verified_votes {
            // Accumulate weighted timestamp
            self.verified_timestamp_weight_sum += vote.timestamp as u128 * voting_power as u128;
            self.verified_power += voting_power;
            self.verified_votes
                .push((committee_index, vote, voting_power));
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Legacy / Test Support
    // ═══════════════════════════════════════════════════════════════════════════

    /// Add a verified vote directly (for own votes that skip verification).
    ///
    /// Returns true if vote was added, false if validator already voted.
    pub fn add_verified_vote(
        &mut self,
        committee_index: usize,
        vote: BlockVote,
        voting_power: u64,
    ) -> bool {
        // Check for duplicate
        if self.has_seen_validator(committee_index) {
            return false;
        }

        // Update block hash, height, and round from first vote if not set
        if self.block_hash.is_none() {
            self.block_hash = Some(vote.block_hash);
            self.height = Some(vote.height);
            self.round = Some(vote.round);
        }

        // Mark as seen
        if committee_index < self.seen_validators.len() {
            self.seen_validators[committee_index] = true;
        }

        // Accumulate weighted timestamp
        self.verified_timestamp_weight_sum += vote.timestamp as u128 * voting_power as u128;
        self.verified_power += voting_power;
        self.verified_votes
            .push((committee_index, vote, voting_power));

        true
    }

    /// Build a Quorum Certificate from collected votes (test only).
    ///
    /// Two-chain rule (HotStuff-2): when creating a QC for block N,
    /// the committable block is at height N-1 (the parent). The committable
    /// information is derived from the QC's height and parent_block_hash
    /// via the `committable_height()` and `committable_hash()` methods.
    ///
    /// # Errors
    ///
    /// Returns error if called before reaching quorum or with no votes.
    #[cfg(test)]
    pub fn build_qc(&mut self, block_hash: Hash) -> Result<QuorumCertificate, String> {
        use hyperscale_types::{Signature, SignerBitfield};

        if self.verified_votes.is_empty() {
            return Err("cannot build QC with no votes".to_string());
        }

        if self.qc_built {
            return Err("QC already built from this vote set".to_string());
        }

        // Sort votes by committee index to ensure deterministic signature aggregation.
        // This is critical: the aggregated signature must be built in the same order
        // as the public keys will be aggregated during verification.
        self.verified_votes.sort_by_key(|(idx, _, _)| *idx);

        // Build signers bitfield - size based on max committee index
        let max_idx = self
            .verified_votes
            .iter()
            .map(|(idx, _, _)| *idx)
            .max()
            .unwrap_or(0);
        let mut signers = SignerBitfield::new(max_idx + 1);
        for (idx, _, _) in &self.verified_votes {
            signers.set(*idx);
        }

        // Extract signatures in sorted order
        let signatures: Vec<Signature> = self
            .verified_votes
            .iter()
            .map(|(_, v, _)| v.signature.clone())
            .collect();

        // Aggregate BLS signatures
        let aggregated_signature = Signature::aggregate_bls(&signatures)
            .map_err(|e| format!("failed to aggregate signatures: {}", e))?;

        // Compute stake-weighted timestamp: sum(timestamp * stake) / sum(stake)
        let weighted_timestamp_ms = if self.verified_power == 0 {
            0
        } else {
            (self.verified_timestamp_weight_sum / self.verified_power as u128) as u64
        };

        let height = self.height.ok_or("no height in vote set")?;
        let round = self.round.unwrap_or(0);
        let parent_block_hash = self
            .parent_block_hash
            .ok_or("no parent block hash in vote set")?;

        self.qc_built = true;

        Ok(QuorumCertificate {
            block_hash,
            height,
            parent_block_hash,
            round,
            aggregated_signature,
            signers,
            voting_power: VotePower(self.verified_power),
            weighted_timestamp_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{KeyPair, QuorumCertificate, ShardGroupId, ValidatorId};

    /// Test shard group.
    fn test_shard_group() -> ShardGroupId {
        ShardGroupId(0)
    }

    fn make_header(height: u64) -> BlockHeader {
        BlockHeader {
            height: BlockHeight(height),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: 1234567890,
            round: 0,
            is_fallback: false,
        }
    }

    fn make_vote(keys: &[KeyPair], voter_index: usize, block_hash: Hash, height: u64) -> BlockVote {
        // Use centralized domain-separated signing message
        let shard_group = test_shard_group();
        let round = 0u64;
        let signing_message =
            hyperscale_types::block_vote_message(shard_group, height, round, &block_hash);
        let signature = keys[voter_index].sign(&signing_message);
        BlockVote {
            block_hash,
            height: BlockHeight(height),
            round,
            voter: ValidatorId(voter_index as u64),
            signature,
            timestamp: 1000000000000,
        }
    }

    #[test]
    fn test_vote_set_creation() {
        let header = make_header(1);
        let vote_set = VoteSet::new(Some(header.clone()), 4);

        assert_eq!(vote_set.verified_power(), 0);
        assert_eq!(vote_set.height(), Some(1));
    }

    #[test]
    fn test_buffer_unverified_votes() {
        let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate_bls()).collect();
        let header = make_header(1);
        let block_hash = header.hash();
        let mut vote_set = VoteSet::new(Some(header), 4);

        // Buffer first vote
        let vote0 = make_vote(&keys, 0, block_hash, 1);
        let pk0 = keys[0].public_key();
        assert!(vote_set.buffer_unverified_vote(0, vote0, pk0, 1));
        assert_eq!(vote_set.unverified_power(), 1);
        assert_eq!(vote_set.verified_power(), 0);

        // Buffer duplicate (should fail)
        let vote0_dup = make_vote(&keys, 0, block_hash, 1);
        let pk0_dup = keys[0].public_key();
        assert!(!vote_set.buffer_unverified_vote(0, vote0_dup, pk0_dup, 1));
        assert_eq!(vote_set.unverified_power(), 1);

        // Buffer more votes
        let vote1 = make_vote(&keys, 1, block_hash, 1);
        let vote2 = make_vote(&keys, 2, block_hash, 1);
        assert!(vote_set.buffer_unverified_vote(1, vote1, keys[1].public_key(), 1));
        assert!(vote_set.buffer_unverified_vote(2, vote2, keys[2].public_key(), 1));
        assert_eq!(vote_set.unverified_power(), 3);
    }

    #[test]
    fn test_should_trigger_verification() {
        let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate_bls()).collect();
        let header = make_header(1);
        let block_hash = header.hash();
        let mut vote_set = VoteSet::new(Some(header), 4);

        let total_power = 4u64;

        // Not enough votes yet
        let vote0 = make_vote(&keys, 0, block_hash, 1);
        vote_set.buffer_unverified_vote(0, vote0, keys[0].public_key(), 1);
        assert!(!vote_set.should_trigger_verification(total_power));

        // Still not enough
        let vote1 = make_vote(&keys, 1, block_hash, 1);
        vote_set.buffer_unverified_vote(1, vote1, keys[1].public_key(), 1);
        assert!(!vote_set.should_trigger_verification(total_power));

        // Now we have quorum potential (3/4 > 2/3)
        let vote2 = make_vote(&keys, 2, block_hash, 1);
        vote_set.buffer_unverified_vote(2, vote2, keys[2].public_key(), 1);
        assert!(vote_set.should_trigger_verification(total_power));
    }

    #[test]
    fn test_add_verified_votes() {
        let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate_bls()).collect();
        let header = make_header(1);
        let block_hash = header.hash();
        let mut vote_set = VoteSet::new(Some(header), 4);

        // Add verified votes directly (e.g., own votes)
        for i in 0..3 {
            let vote = make_vote(&keys, i, block_hash, 1);
            assert!(vote_set.add_verified_vote(i, vote, 1));
        }

        assert_eq!(vote_set.verified_power(), 3);

        // Build QC
        let qc = vote_set.build_qc(block_hash).unwrap();
        assert_eq!(qc.block_hash, block_hash);
        assert_eq!(qc.height.0, 1);
        assert_eq!(qc.voting_power.0, 3);
        assert_eq!(qc.signers.count(), 3);

        // Can't build again
        assert!(vote_set.build_qc(block_hash).is_err());
    }
}
