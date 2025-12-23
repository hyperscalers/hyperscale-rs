//! Vote set for collecting block votes.

use hyperscale_types::{
    BlockHeader, BlockHeight, BlockVote, Hash, QuorumCertificate, Signature, SignerBitfield,
    VotePower,
};
use tracing::instrument;

/// Votes for a specific block.
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

    /// Collected votes with their committee indices.
    /// The committee index is needed to ensure signatures are aggregated in the
    /// same order as public keys during verification.
    votes: Vec<(usize, BlockVote)>,

    /// Bitfield tracking which validators have voted.
    signers: SignerBitfield,

    /// Total voting power accumulated from votes (stake-weighted).
    voting_power: u64,

    /// Sum of (timestamp * stake_weight) for weighted timestamp calculation.
    timestamp_weight_sum: u128,

    /// Total number of validators (for bitfield sizing).
    #[allow(dead_code)]
    num_validators: usize,

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
            votes: Vec::new(),
            signers: SignerBitfield::new(num_validators),
            voting_power: 0,
            timestamp_weight_sum: 0,
            num_validators,
            qc_built: false,
        }
    }

    /// Add a vote to this set using the committee index and stake weight.
    ///
    /// The `committee_index` is the position of the validator in the shard's committee,
    /// NOT the raw validator ID. This allows non-contiguous validator IDs to work correctly.
    ///
    /// The `stake_weight` is the validator's voting power from their stake.
    ///
    /// Returns true if vote was added, false if validator already voted.
    #[instrument(level = "debug", skip(self, vote), fields(
        block_hash = ?self.block_hash,
        height = ?self.height.map(|h| h.0),
        voter = vote.voter.0,
        power_before = self.voting_power,
        stake_weight = stake_weight,
    ))]
    pub fn add_vote(&mut self, vote: BlockVote, committee_index: usize, stake_weight: u64) -> bool {
        // Check if validator already voted (using committee index)
        if self.signers.is_set(committee_index) {
            return false;
        }

        // Update block hash, height, and round from first vote if not set
        if self.block_hash.is_none() {
            self.block_hash = Some(vote.block_hash);
            self.height = Some(vote.height);
            self.round = Some(vote.round);
        }

        self.signers.set(committee_index);
        self.voting_power += stake_weight;
        // Accumulate weighted timestamp: timestamp * stake_weight
        self.timestamp_weight_sum += vote.timestamp as u128 * stake_weight as u128;
        self.votes.push((committee_index, vote));

        true
    }

    /// Check if this set has quorum and can build a QC.
    ///
    /// Quorum formula: voted_power * 3 > total_power * 2 (i.e., > 2/3)
    ///
    /// Note: This also requires the header to be set (via constructor or `set_header`),
    /// since building a QC requires the parent_block_hash from the header.
    pub fn has_quorum(&self, total_power: u64) -> bool {
        !self.qc_built
            && self.parent_block_hash.is_some()
            && VotePower::has_quorum(self.voting_power, total_power)
    }

    /// Get the current voting power.
    pub fn voting_power(&self) -> u64 {
        self.voting_power
    }

    /// Get the block height.
    pub fn height(&self) -> Option<u64> {
        self.height.map(|h| h.0)
    }

    /// Get the round number.
    pub fn round(&self) -> Option<u64> {
        self.round
    }

    /// Update the vote set with header information.
    ///
    /// This is needed when votes arrive before the header. The vote set
    /// can accumulate votes, but it needs the header info (particularly
    /// parent_block_hash) to build a valid QC.
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

    /// Check if the vote set has header information.
    pub fn has_header(&self) -> bool {
        self.parent_block_hash.is_some()
    }

    /// Extract data needed to build a QC asynchronously.
    ///
    /// This marks the vote set as "QC building in progress" and returns all data
    /// needed by the runner to perform BLS signature aggregation off the main thread.
    ///
    /// Returns None if:
    /// - No votes collected
    /// - QC already built or being built
    /// - Missing height or parent_block_hash
    pub fn prepare_qc_build(
        &mut self,
    ) -> Option<(
        BlockHeight,
        u64,
        Hash,
        Vec<(usize, BlockVote)>,
        SignerBitfield,
        u64,
        u128,
    )> {
        if self.votes.is_empty() || self.qc_built {
            return None;
        }

        let height = self.height?;
        let round = self.round.unwrap_or(0);
        let parent_block_hash = self.parent_block_hash?;

        // Sort votes by committee index for deterministic aggregation
        self.votes.sort_by_key(|(idx, _)| *idx);

        // Mark as built to prevent duplicate building
        self.qc_built = true;

        Some((
            height,
            round,
            parent_block_hash,
            self.votes.clone(),
            self.signers.clone(),
            self.voting_power,
            self.timestamp_weight_sum,
        ))
    }

    /// Build a Quorum Certificate from collected votes.
    ///
    /// Two-chain rule (HotStuff-2): when creating a QC for block N,
    /// the committable block is at height N-1 (the parent). The committable
    /// information is derived from the QC's height and parent_block_hash
    /// via the `committable_height()` and `committable_hash()` methods.
    ///
    /// # Errors
    ///
    /// Returns error if called before reaching quorum or with no votes.
    pub fn build_qc(&mut self, block_hash: Hash) -> Result<QuorumCertificate, String> {
        if self.votes.is_empty() {
            return Err("cannot build QC with no votes".to_string());
        }

        if self.qc_built {
            return Err("QC already built from this vote set".to_string());
        }

        // Sort votes by committee index to ensure deterministic signature aggregation.
        // This is critical: the aggregated signature must be built in the same order
        // as the public keys will be aggregated during verification.
        self.votes.sort_by_key(|(idx, _)| *idx);

        // Extract signatures in sorted order
        let signatures: Vec<Signature> = self
            .votes
            .iter()
            .map(|(_, v)| v.signature.clone())
            .collect();

        // Aggregate BLS signatures
        let aggregated_signature = Signature::aggregate_bls(&signatures)
            .map_err(|e| format!("failed to aggregate signatures: {}", e))?;

        // Compute stake-weighted timestamp: sum(timestamp * stake) / sum(stake)
        let weighted_timestamp_ms = if self.voting_power == 0 {
            0
        } else {
            (self.timestamp_weight_sum / self.voting_power as u128) as u64
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
            signers: self.signers.clone(),
            voting_power: VotePower(self.voting_power),
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

        assert_eq!(vote_set.voting_power(), 0);
        assert_eq!(vote_set.height(), Some(1));
        assert!(!vote_set.has_quorum(4));
    }

    #[test]
    fn test_add_votes() {
        let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate_bls()).collect();
        let header = make_header(1);
        let block_hash = header.hash();
        let mut vote_set = VoteSet::new(Some(header), 4);

        // Add first vote
        let vote0 = make_vote(&keys, 0, block_hash, 1);
        assert!(vote_set.add_vote(vote0, 0, 1));
        assert_eq!(vote_set.voting_power(), 1);
        assert!(!vote_set.has_quorum(4));

        // Add duplicate (should fail)
        let vote0_dup = make_vote(&keys, 0, block_hash, 1);
        assert!(!vote_set.add_vote(vote0_dup, 0, 1));
        assert_eq!(vote_set.voting_power(), 1);

        // Add second and third votes
        let vote1 = make_vote(&keys, 1, block_hash, 1);
        let vote2 = make_vote(&keys, 2, block_hash, 1);
        assert!(vote_set.add_vote(vote1, 1, 1));
        assert!(vote_set.add_vote(vote2, 2, 1));
        assert_eq!(vote_set.voting_power(), 3);
        assert!(vote_set.has_quorum(4)); // 3/4 > 2/3
    }

    #[test]
    fn test_build_qc() {
        let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate_bls()).collect();
        let header = make_header(1);
        let block_hash = header.hash();
        let mut vote_set = VoteSet::new(Some(header), 4);

        // Add quorum of votes
        for i in 0..3 {
            let vote = make_vote(&keys, i, block_hash, 1);
            vote_set.add_vote(vote, i, 1);
        }

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
