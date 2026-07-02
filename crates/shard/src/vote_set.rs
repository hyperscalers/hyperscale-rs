//! Per-block vote accounting with deferred batch verification.
//!
//! A [`VoteSet`] accumulates votes for a single block. Received signatures
//! are buffered unverified until the combined (verified + unverified) power
//! could possibly reach quorum; at that point the [`crate::vote_keeper`]
//! triggers a single batch verification that either builds the QC or feeds
//! the verified votes back in via [`VoteSet::on_votes_verified`].
//!
//! Own votes are recorded as already-verified via
//! [`VoteSet::add_verified_vote`] since we just signed them.

use hyperscale_types::{
    BlockHash, BlockHeader, BlockHeight, BlockVote, Bls12381G1PublicKey, Round, Verified,
    VoteCount, WeightedTimestamp,
};

/// Votes for a specific block.
///
/// The vote set supports deferred verification: unverified votes are buffered
/// until we have enough voting power to possibly reach quorum, then batch-verified.
#[derive(Debug, Clone)]
pub struct VoteSet {
    /// Block hash being voted on.
    block_hash: Option<BlockHash>,

    /// Block height.
    height: Option<BlockHeight>,

    /// Round number when votes are collected.
    round: Option<Round>,

    /// Parent block hash (from the block's header).
    parent_block_hash: Option<BlockHash>,

    /// Parent QC's `weighted_timestamp` (from the block's header). Used as
    /// the per-vote monotonicity floor during timestamp aggregation:
    /// any vote timestamp below this is raised to the floor before being
    /// summed, so the resulting QC's `weighted_timestamp` is guaranteed
    /// >= parent's.
    parent_weighted_timestamp: Option<WeightedTimestamp>,

    // ═══════════════════════════════════════════════════════════════════════
    // Verified votes (passed signature verification)
    // ═══════════════════════════════════════════════════════════════════════
    /// Verified votes with their committee indices.
    /// Each tuple is (`committee_index`, vote).
    verified_votes: Vec<(usize, Verified<BlockVote>)>,

    /// Number of verified votes counted.
    verified_power: VoteCount,

    /// Sum of verified votes' (clamped) timestamps; divided by the vote count
    /// to yield the mean weighted timestamp.
    verified_timestamp_weight_sum: u128,

    // ═══════════════════════════════════════════════════════════════════════
    // Unverified votes (buffered until quorum possible)
    // ═══════════════════════════════════════════════════════════════════════
    /// Unverified votes buffered for batch verification.
    /// Each tuple is (`committee_index`, vote, `public_key`).
    unverified_votes: Vec<(usize, BlockVote, Bls12381G1PublicKey)>,

    /// Number of unverified votes buffered.
    unverified_power: VoteCount,

    /// Voters counted into the verified set. Permanent for the life of the
    /// vote set: a verified voter is never tallied twice, across its own vote
    /// and any number of batch results.
    verified_voters: Vec<bool>,

    /// Voters with an unverified vote currently buffered for the next batch.
    /// Transient — cleared when `take_unverified_votes` drains the buffer — so
    /// a forged vote occupies a voter's slot only until verification runs and
    /// can't censor the genuine vote that follows. Only a verified signature
    /// sets `verified_voters`.
    buffered_voters: Vec<bool>,

    /// Whether a verification batch is currently in flight.
    pending_verification: bool,

    /// Whether QC has already been built from this vote set.
    qc_built: bool,
}

impl VoteSet {
    /// Create a new vote set.
    pub fn new(header: Option<&BlockHeader>, num_validators: usize) -> Self {
        let (block_hash, height, round, parent_block_hash, parent_weighted_timestamp) = header
            .map_or((None, None, None, None, None), |h| {
                (
                    Some(h.hash()),
                    Some(h.height()),
                    Some(h.round()),
                    Some(h.parent_block_hash()),
                    Some(h.parent_qc().weighted_timestamp()),
                )
            });

        Self {
            block_hash,
            height,
            round,
            parent_block_hash,
            parent_weighted_timestamp,
            verified_votes: Vec::new(),
            verified_power: VoteCount::ZERO,
            verified_timestamp_weight_sum: 0,
            unverified_votes: Vec::new(),
            unverified_power: VoteCount::ZERO,
            verified_voters: vec![false; num_validators],
            buffered_voters: vec![false; num_validators],
            pending_verification: false,
            qc_built: false,
        }
    }

    /// Get the block height.
    pub const fn height(&self) -> Option<BlockHeight> {
        self.height
    }

    /// Get the current verified voting power.
    pub const fn verified_power(&self) -> VoteCount {
        self.verified_power
    }

    /// Get the current unverified voting power.
    pub const fn unverified_power(&self) -> VoteCount {
        self.unverified_power
    }

    /// Whether this validator's vote has already been verified and counted.
    /// Buffered-but-unverified votes are deliberately excluded, so a forged
    /// vote cannot suppress the genuine one behind it.
    pub fn has_seen_validator(&self, committee_index: usize) -> bool {
        committee_index < self.verified_voters.len() && self.verified_voters[committee_index]
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Unverified Vote Buffering
    // ═══════════════════════════════════════════════════════════════════════════

    /// Buffer an unverified vote for later batch verification.
    ///
    /// Returns `true` if the vote was buffered, `false` if it was rejected
    /// (out-of-range committee index or duplicate).
    pub fn buffer_unverified_vote(
        &mut self,
        committee_index: usize,
        vote: BlockVote,
        public_key: Bls12381G1PublicKey,
    ) -> bool {
        // Reject malformed index: with no dedup slot we couldn't track the
        // vote, so a Byzantine sender could buffer arbitrarily many copies.
        if committee_index >= self.buffered_voters.len() {
            return false;
        }

        // Dedup against verified voters (permanent) and voters already buffered
        // for the in-flight batch (transient). An unverified vote only marks
        // `buffered_voters`, so a forged vote holds the slot just until the
        // buffer drains, never permanently.
        if self.verified_voters[committee_index] || self.buffered_voters[committee_index] {
            return false;
        }

        // Latch block hash, height, and round from the first vote.
        if self.block_hash.is_none() {
            self.block_hash = Some(vote.block_hash());
            self.height = Some(vote.height());
            self.round = Some(vote.round());
        }

        self.buffered_voters[committee_index] = true;
        self.unverified_power += VoteCount::MIN;
        self.unverified_votes
            .push((committee_index, vote, public_key));

        true
    }

    /// Check if we should trigger batch verification.
    ///
    /// Returns true if:
    /// - We have enough total power (verified + unverified) to possibly reach quorum
    /// - We have unverified votes to verify
    /// - We're not already waiting for a verification result
    /// - We have the header info needed to build a QC
    pub fn should_trigger_verification(&self, total_committee_power: VoteCount) -> bool {
        !self.pending_verification
            && !self.qc_built
            && !self.unverified_votes.is_empty()
            && self.parent_block_hash.is_some()
            && VoteCount::has_quorum(
                self.verified_power + self.unverified_power,
                total_committee_power,
            )
    }

    /// Take the unverified votes for batch verification.
    ///
    /// Returns the votes and marks the vote set as pending verification.
    /// Each tuple is (`committee_index`, vote, `public_key`).
    pub fn take_unverified_votes(&mut self) -> Vec<(usize, BlockVote, Bls12381G1PublicKey)> {
        self.pending_verification = true;
        self.unverified_power = VoteCount::ZERO;
        // Reopen the buffered slots: these votes are now in the batch, and only
        // the ones whose signatures verify will mark `verified_voters`. A voter
        // whose buffered vote fails can then be re-buffered rather than censored.
        self.buffered_voters.iter_mut().for_each(|v| *v = false);
        std::mem::take(&mut self.unverified_votes)
    }

    /// Get copies of the already-verified votes.
    ///
    /// These are votes that were added via `add_verified_vote` (e.g., our own vote)
    /// and need to be included in the QC along with newly verified votes.
    pub fn get_verified_votes(&self) -> Vec<(usize, Verified<BlockVote>)> {
        self.verified_votes.clone()
    }

    /// Get data needed for verification action.
    ///
    /// Returns (`block_hash`, height, round, `parent_block_hash`,
    /// `parent_weighted_timestamp`) or `None` if not ready. The parent's
    /// weighted timestamp is the per-vote monotonicity floor used by the
    /// QC builder.
    pub fn verification_data(
        &self,
    ) -> Option<(BlockHash, BlockHeight, Round, BlockHash, WeightedTimestamp)> {
        Some((
            self.block_hash?,
            self.height?,
            self.round.unwrap_or(Round::INITIAL),
            self.parent_block_hash?,
            self.parent_weighted_timestamp?,
        ))
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Verification Result Handling
    // ═══════════════════════════════════════════════════════════════════════════

    /// Called when verification completes successfully with a QC.
    ///
    /// Marks the vote set as built.
    pub const fn on_qc_built(&mut self) {
        self.qc_built = true;
        self.pending_verification = false;
    }

    /// Called when verification completes but quorum wasn't reached.
    ///
    /// Adds the verified votes to the verified set and clears pending flag.
    pub fn on_votes_verified(&mut self, verified_votes: Vec<(usize, Verified<BlockVote>)>) {
        self.pending_verification = false;

        let floor_ms = self
            .parent_weighted_timestamp
            .map_or(0, WeightedTimestamp::as_millis);
        for (committee_index, vote) in verified_votes {
            // Mark the voter counted only now that its signature verified, and
            // skip any already tallied (its own vote, or an overlapping batch)
            // so votes are never double-counted.
            if committee_index >= self.verified_voters.len()
                || self.verified_voters[committee_index]
            {
                continue;
            }
            self.verified_voters[committee_index] = true;

            // Per-vote monotonicity clamp against parent's weighted timestamp
            // — keeps the aggregated `weighted_timestamp` monotonic regardless
            // of slow-clocked or Byzantine voters. Every vote weighs one, so
            // the aggregate is the mean of the clamped timestamps.
            let clamped_ms = vote.timestamp().as_millis().max(floor_ms);
            self.verified_timestamp_weight_sum += u128::from(clamped_ms);
            self.verified_power += VoteCount::MIN;
            self.verified_votes.push((committee_index, vote));
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Direct verified-vote insertion
    // ═══════════════════════════════════════════════════════════════════════════

    /// Add an already-verified vote to the set — used for own votes, which
    /// we just signed and so can treat as verified without a BLS check.
    /// Also used by tests that want to seed verified state directly.
    /// Returns true on insertion, false if rejected (out-of-range committee
    /// index or duplicate).
    pub fn add_verified_vote(&mut self, committee_index: usize, vote: Verified<BlockVote>) -> bool {
        // Reject malformed index: see `buffer_unverified_vote` for rationale.
        if committee_index >= self.verified_voters.len() {
            return false;
        }

        // A verified vote is authoritative; admit it even when a forged
        // unverified vote sits buffered under the same index. The buffered copy
        // is skipped at `on_votes_verified` once `verified_voters` is set here.
        if self.verified_voters[committee_index] {
            return false;
        }

        // Latch block hash, height, and round from the first vote.
        if self.block_hash.is_none() {
            self.block_hash = Some(vote.block_hash());
            self.height = Some(vote.height());
            self.round = Some(vote.round());
        }

        self.verified_voters[committee_index] = true;

        // Per-vote monotonicity clamp; see `on_votes_verified` for rationale.
        let floor_ms = self
            .parent_weighted_timestamp
            .map_or(0, WeightedTimestamp::as_millis);
        let clamped_ms = vote.timestamp().as_millis().max(floor_ms);
        self.verified_timestamp_weight_sum += u128::from(clamped_ms);
        self.verified_power += VoteCount::MIN;
        self.verified_votes.push((committee_index, vote));

        true
    }
}

#[cfg(test)]
mod test_helpers {
    use hyperscale_types::{Bls12381G2Signature, QuorumCertificate, ShardId, SignerBitfield};

    use super::*;

    impl VoteSet {
        /// Build a Quorum Certificate from collected votes (test only).
        ///
        /// Two-chain rule (HotStuff-2): when creating a QC for block N,
        /// the committable block is at height N-1 (the parent). The committable
        /// information is derived from the QC's height and `parent_block_hash`
        /// via the `committable_height()` and `committable_hash()` methods.
        ///
        /// # Errors
        ///
        /// Returns error if called before reaching quorum or with no votes.
        pub fn build_qc(
            &mut self,
            block_hash: BlockHash,
            shard_id: ShardId,
        ) -> Result<QuorumCertificate, String> {
            if self.verified_votes.is_empty() {
                return Err("cannot build QC with no votes".to_string());
            }

            if self.qc_built {
                return Err("QC already built from this vote set".to_string());
            }

            // Sort votes by committee index to ensure deterministic signature aggregation.
            // This is critical: the aggregated signature must be built in the same order
            // as the public keys will be aggregated during verification.
            self.verified_votes.sort_by_key(|(idx, _)| *idx);

            // Bitfield is sized to fit the largest committee index seen, not the full committee.
            let max_idx = self
                .verified_votes
                .iter()
                .map(|(idx, _)| *idx)
                .max()
                .unwrap_or(0);
            let mut signers = SignerBitfield::new(max_idx + 1);
            for (idx, _) in &self.verified_votes {
                signers.set(*idx);
            }

            let signatures: Vec<Bls12381G2Signature> = self
                .verified_votes
                .iter()
                .map(|(_, v)| v.signature())
                .collect();

            let aggregated_signature = Bls12381G2Signature::aggregate(&signatures, true)
                .map_err(|e| format!("failed to aggregate signatures: {e:?}"))?;

            // Mean of the clamped vote timestamps — every vote weighs one.
            let weighted_timestamp_ms = if self.verified_power == VoteCount::ZERO {
                0
            } else {
                // A mean of u64 timestamps always fits in u64.
                u64::try_from(
                    self.verified_timestamp_weight_sum / u128::from(self.verified_power.inner()),
                )
                .unwrap_or(u64::MAX)
            };

            let height = self.height.ok_or("no height in vote set")?;
            let round = self.round.unwrap_or(Round::INITIAL);
            let parent_block_hash = self
                .parent_block_hash
                .ok_or("no parent block hash in vote set")?;

            self.qc_built = true;

            Ok(QuorumCertificate::new(
                block_hash,
                shard_id,
                height,
                parent_block_hash,
                round,
                signers,
                aggregated_signature,
                WeightedTimestamp::from_millis(weighted_timestamp_ms),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_types::{
        BeaconWitnessLeafCount, BeaconWitnessRoot, Bls12381G1PrivateKey, CertificateRoot,
        ChainOrigin, Hash, InFlightCount, LocalReceiptRoot, NetworkDefinition, ProposerTimestamp,
        ProvisionsRoot, QuorumCertificate, ShardId, StateRoot, TransactionRoot, ValidatorId,
        generate_bls_keypair,
    };

    use super::*;

    fn test_shard_group() -> ShardId {
        ShardId::ROOT
    }

    fn make_header(height: BlockHeight) -> BlockHeader {
        BlockHeader::new(
            ShardId::ROOT,
            height,
            BlockHash::from_raw(Hash::from_bytes(b"parent")),
            QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(1_234_567_890),
            Round::INITIAL,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        )
    }

    fn make_vote(
        keys: &[Bls12381G1PrivateKey],
        voter_index: usize,
        block_hash: BlockHash,
        height: BlockHeight,
    ) -> BlockVote {
        BlockVote::new(
            &NetworkDefinition::simulator(),
            block_hash,
            BlockHash::ZERO,
            test_shard_group(),
            height,
            Round::INITIAL,
            ValidatorId::new(voter_index as u64),
            &keys[voter_index],
            ProposerTimestamp::from_millis(1_000_000_000_000),
        )
    }

    #[test]
    fn test_buffer_unverified_votes() {
        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let header = make_header(BlockHeight::new(1));
        let block_hash = header.hash();
        let mut vote_set = VoteSet::new(Some(&header), 4);

        // Buffer first vote
        let vote0 = make_vote(&keys, 0, block_hash, BlockHeight::new(1));
        let pk0 = keys[0].public_key();
        assert!(vote_set.buffer_unverified_vote(0, vote0, pk0));
        assert_eq!(vote_set.unverified_power(), VoteCount::new(1));
        assert_eq!(vote_set.verified_power(), VoteCount::ZERO);

        // Buffer duplicate (should fail)
        let vote0_dup = make_vote(&keys, 0, block_hash, BlockHeight::new(1));
        let pk0_dup = keys[0].public_key();
        assert!(!vote_set.buffer_unverified_vote(0, vote0_dup, pk0_dup));
        assert_eq!(vote_set.unverified_power(), VoteCount::new(1));

        // Buffer more votes
        let vote1 = make_vote(&keys, 1, block_hash, BlockHeight::new(1));
        let vote2 = make_vote(&keys, 2, block_hash, BlockHeight::new(1));
        assert!(vote_set.buffer_unverified_vote(1, vote1, keys[1].public_key()));
        assert!(vote_set.buffer_unverified_vote(2, vote2, keys[2].public_key()));
        assert_eq!(vote_set.unverified_power(), VoteCount::new(3));
    }

    #[test]
    fn test_should_trigger_verification() {
        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let header = make_header(BlockHeight::new(1));
        let block_hash = header.hash();
        let mut vote_set = VoteSet::new(Some(&header), 4);

        let total_power = VoteCount::new(4);

        // Not enough votes yet
        let vote0 = make_vote(&keys, 0, block_hash, BlockHeight::new(1));
        vote_set.buffer_unverified_vote(0, vote0, keys[0].public_key());
        assert!(!vote_set.should_trigger_verification(total_power));

        // Still not enough
        let vote1 = make_vote(&keys, 1, block_hash, BlockHeight::new(1));
        vote_set.buffer_unverified_vote(1, vote1, keys[1].public_key());
        assert!(!vote_set.should_trigger_verification(total_power));

        // Now we have quorum potential (3/4 > 2/3)
        let vote2 = make_vote(&keys, 2, block_hash, BlockHeight::new(1));
        vote_set.buffer_unverified_vote(2, vote2, keys[2].public_key());
        assert!(vote_set.should_trigger_verification(total_power));
    }

    #[test]
    fn test_add_verified_votes() {
        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let header = make_header(BlockHeight::new(1));
        let block_hash = header.hash();
        let mut vote_set = VoteSet::new(Some(&header), 4);

        // Add verified votes directly (e.g., own votes)
        for i in 0..3 {
            let vote = make_vote(&keys, i, block_hash, BlockHeight::new(1));
            assert!(
                vote_set.add_verified_vote(i, Verified::<BlockVote>::new_unchecked_for_test(vote),)
            );
        }

        assert_eq!(vote_set.verified_power(), VoteCount::new(3));

        // Build QC
        let qc = vote_set.build_qc(block_hash, test_shard_group()).unwrap();
        assert_eq!(qc.block_hash(), block_hash);
        assert_eq!(qc.height().inner(), 1);
        assert_eq!(qc.signers().count(), 3);

        // Can't build again
        assert!(vote_set.build_qc(block_hash, test_shard_group()).is_err());
    }

    #[test]
    fn forged_unverified_vote_does_not_censor_genuine_vote() {
        // A vote buffered with a bad signature must not permanently occupy its
        // voter's slot: once the batch drains and the signature fails, the
        // genuine vote from the same validator is still admissible.
        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let header = make_header(BlockHeight::new(1));
        let block_hash = header.hash();
        let mut vote_set = VoteSet::new(Some(&header), 4);

        // Attacker buffers a (would-be-forged) vote attributed to validator 0.
        let forged = make_vote(&keys, 0, block_hash, BlockHeight::new(1));
        assert!(vote_set.buffer_unverified_vote(0, forged, keys[0].public_key(),));
        // Buffering alone does not count the voter as verified.
        assert!(!vote_set.has_seen_validator(0));

        // The batch drains and every signature fails verification.
        let _ = vote_set.take_unverified_votes();
        vote_set.on_votes_verified(vec![]);

        // Validator 0's genuine vote is not blocked by the failed forgery.
        let genuine = make_vote(&keys, 0, block_hash, BlockHeight::new(1));
        assert!(vote_set.buffer_unverified_vote(0, genuine, keys[0].public_key(),));
    }

    #[test]
    fn on_votes_verified_skips_already_counted_voter() {
        // A voter counted via its own verified vote must not be tallied a
        // second time when an overlapping batch result reports it again.
        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let header = make_header(BlockHeight::new(1));
        let block_hash = header.hash();
        let mut vote_set = VoteSet::new(Some(&header), 4);

        let own = make_vote(&keys, 0, block_hash, BlockHeight::new(1));
        assert!(vote_set.add_verified_vote(0, Verified::<BlockVote>::new_unchecked_for_test(own),));
        assert_eq!(vote_set.verified_power(), VoteCount::new(1));

        let echo = make_vote(&keys, 0, block_hash, BlockHeight::new(1));
        vote_set.on_votes_verified(vec![(
            0,
            Verified::<BlockVote>::new_unchecked_for_test(echo),
        )]);
        assert_eq!(vote_set.verified_power(), VoteCount::new(1));
    }
}
