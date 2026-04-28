//! Vote accounting: own-vote locks, vote sets per block, and received-vote
//! equivocation tracking.
//!
//! ## Deferred Verification
//!
//! Votes are NOT verified when received. Instead, they are buffered in a
//! [`VoteSet`] until the combined verified + unverified power could possibly
//! reach quorum. At that point a single `VerifyAndBuildQuorumCertificate`
//! action batch-verifies all signatures and builds the QC in one operation.
//!
//! This avoids wasting CPU on votes we'll never use (e.g., if a block
//! never reaches quorum due to view change or leader failure).
//!
//! ## Equivocation Detection
//!
//! [`VoteKeeper::received_votes_by_height`] records `(height, validator) →
//! (block_hash, round)` for every verified vote we receive. A second vote
//! from the same validator at the same `(height, round)` for a different
//! block is equivocation; a vote at a later round is a legitimate revote.

use hyperscale_core::Action;
use hyperscale_types::{
    BlockHash, BlockHeader, BlockHeight, BlockVote, Round, TopologySnapshot, ValidatorId,
};
use std::collections::HashMap;
use tracing::{info, trace, warn};

pub use crate::vote_set::VoteSet;

/// Top-level vote accounting state.
///
/// Owns the per-block [`VoteSet`]s, the validator's own-vote locks (preventing
/// same-height re-voting across rounds when locked), and the received-vote
/// record used for equivocation detection.
pub struct VoteKeeper {
    /// Vote sets for blocks being voted on (`block_hash` -> vote set).
    pub(crate) vote_sets: HashMap<BlockHash, VoteSet>,

    /// Own-vote locking: tracks which block hash we voted for at each height.
    /// Critical for BFT safety — prevents voting for conflicting blocks at the
    /// same height and round. The lock may be released across rounds on
    /// timeout or when a QC proves the lock is irrelevant.
    ///
    /// Key: height, Value: (`block_hash`, round)
    pub(crate) voted_heights: HashMap<BlockHeight, (BlockHash, Round)>,

    /// Per-validator record of received verified votes for equivocation
    /// detection. Key: (height, validator), Value: (`block_hash`, round).
    /// A different-block vote at the same (height, round) is equivocation;
    /// at a later round it's a legitimate revote after unlock.
    pub(crate) received_votes_by_height: HashMap<(BlockHeight, ValidatorId), (BlockHash, Round)>,
}

impl VoteKeeper {
    pub fn new() -> Self {
        Self {
            vote_sets: HashMap::new(),
            voted_heights: HashMap::new(),
            received_votes_by_height: HashMap::new(),
        }
    }

    /// Drop all vote tracking at or below `committed_height`.
    pub fn cleanup_committed(&mut self, committed_height: BlockHeight) {
        self.vote_sets
            .retain(|_hash, vote_set| vote_set.height().is_none_or(|h| h > committed_height));
        self.voted_heights
            .retain(|height, _| *height > committed_height);
        self.received_votes_by_height
            .retain(|(height, _), _| *height > committed_height);
    }

    /// Clear vote tracking at `height` for rounds older than `new_round`, used
    /// when advancing to a new round.
    ///
    /// Drops all received-vote records for the height (a validator who voted
    /// for an older round may now legitimately vote again). Keeps vote sets
    /// at `height` only if their round is `>= new_round` — earlier-round
    /// vote sets can no longer form a QC.
    ///
    /// Returns the number of received-vote entries cleared.
    pub fn clear_for_height(&mut self, height: BlockHeight, new_round: Round) -> usize {
        let mut cleared = 0;
        self.received_votes_by_height.retain(|(h, _), _| {
            if *h == height {
                cleared += 1;
                false
            } else {
                true
            }
        });
        self.vote_sets.retain(|_hash, vote_set| {
            vote_set.height().is_none_or(|h| h != height)
                || vote_set.round().is_none_or(|r| r >= new_round)
        });
        cleared
    }

    pub fn vote_sets_len(&self) -> usize {
        self.vote_sets.len()
    }

    pub fn voted_heights_len(&self) -> usize {
        self.voted_heights.len()
    }

    pub fn received_votes_len(&self) -> usize {
        self.received_votes_by_height.len()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Own-vote lock (safety)
    // ═══════════════════════════════════════════════════════════════════════

    /// Check whether we may vote for `block_hash` at `height`.
    pub fn lock_decision(&self, height: BlockHeight, block_hash: BlockHash) -> LockDecision {
        match self.voted_heights.get(&height).copied() {
            None => LockDecision::Unlocked,
            Some((existing_hash, existing_round)) if existing_hash == block_hash => {
                LockDecision::AlreadyVotedSameBlock { existing_round }
            }
            Some((existing_block, existing_round)) => LockDecision::LockedToOther {
                existing_block,
                existing_round,
            },
        }
    }

    /// Record our own vote for `block_hash` at `(height, round)`.
    pub fn record_own_vote(&mut self, height: BlockHeight, block_hash: BlockHash, round: Round) {
        self.voted_heights.insert(height, (block_hash, round));
    }

    /// Remove the own-vote lock at `height`. Returns `true` if a lock was
    /// released. Called by timeout-based and QC-based unlock paths.
    pub fn unlock_at(&mut self, height: BlockHeight) -> bool {
        self.voted_heights.remove(&height).is_some()
    }

    /// Read-only view of own-vote locks, for callers that need to iterate
    /// (e.g., QC-based unlock iterates all heights ≤ qc.height).
    pub const fn voted_heights(&self) -> &HashMap<BlockHeight, (BlockHash, Round)> {
        &self.voted_heights
    }

    /// Block hash locked at `height`, if any.
    pub fn locked_block(&self, height: BlockHeight) -> Option<BlockHash> {
        self.voted_heights.get(&height).map(|(hash, _)| *hash)
    }

    /// True if any own vote has been recorded at `height`.
    pub fn is_locked_at(&self, height: BlockHeight) -> bool {
        self.voted_heights.contains_key(&height)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Vote ingestion
    // ═══════════════════════════════════════════════════════════════════════

    /// Accept a received block vote: committee/power checks, buffering the
    /// signature (or marking own votes as verified) into the block's
    /// [`VoteSet`], and firing batch verification once combined power can
    /// reach quorum. `header_for_vote` is the header from the caller's
    /// pending-block map; `None` is acceptable when the header hasn't been
    /// received yet — a later [`VoteSet::set_header`] fills it in.
    pub fn accept_vote(
        &mut self,
        topology: &TopologySnapshot,
        vote: BlockVote,
        committed_height: BlockHeight,
        header_for_vote: Option<&BlockHeader>,
    ) -> Vec<Action> {
        let block_hash = vote.block_hash;
        let height = vote.height;
        let is_own_vote = vote.voter == topology.local_validator_id();

        if height <= committed_height {
            trace!(
                vote_anchor_ts = height.0,
                committed_height = committed_height.0,
                voter = ?vote.voter,
                "Skipping vote for already-committed height"
            );
            return vec![];
        }

        let Some(voter_index) = topology.local_committee_index(vote.voter) else {
            warn!("Vote from validator {:?} not in committee", vote.voter);
            return vec![];
        };

        let voting_power = topology.voting_power(vote.voter).unwrap_or(0);
        if voting_power == 0 {
            warn!(
                "Vote from validator {:?} with zero voting power",
                vote.voter
            );
            return vec![];
        }

        let committee_size = topology.local_committee().len();
        let total_power = topology.local_voting_power();
        let validator_id = topology.local_validator_id();

        let public_key = if is_own_vote {
            None
        } else if let Some(pk) = topology.public_key(vote.voter) {
            Some(pk)
        } else {
            warn!("No public key for validator {:?}", vote.voter);
            return vec![];
        };

        let vote_set = self
            .vote_sets
            .entry(block_hash)
            .or_insert_with(|| VoteSet::new(header_for_vote, committee_size));

        if vote_set.has_seen_validator(voter_index) {
            trace!("Already seen vote from validator {:?}", vote.voter);
            return vec![];
        }

        if is_own_vote {
            trace!(
                block_hash = ?block_hash,
                "Adding own vote as verified"
            );
            vote_set.add_verified_vote(voter_index, vote, voting_power);
        } else {
            let public_key = public_key.expect("non-own vote implies public key resolved");
            vote_set.buffer_unverified_vote(voter_index, vote, public_key, voting_power);
            trace!(
                validator = ?validator_id,
                block_hash = ?block_hash,
                verified_power = vote_set.verified_power(),
                unverified_power = vote_set.unverified_power(),
                total_power,
                "Vote buffered"
            );
        }

        self.maybe_trigger_verification(topology, block_hash)
    }

    /// Trigger batch vote verification for `block_hash` once the combined
    /// verified + buffered voting power could reach quorum. Returns a
    /// `VerifyAndBuildQuorumCertificate` action, or empty if the quorum
    /// threshold can't be met yet or no buffered signatures are waiting.
    pub fn maybe_trigger_verification(
        &mut self,
        topology: &TopologySnapshot,
        block_hash: BlockHash,
    ) -> Vec<Action> {
        let total_power = topology.local_voting_power();

        let Some(vote_set) = self.vote_sets.get_mut(&block_hash) else {
            return vec![];
        };

        if !vote_set.should_trigger_verification(total_power) {
            return vec![];
        }

        let Some((_, height, round, parent_block_hash)) = vote_set.verification_data() else {
            return vec![];
        };

        let verified_votes = vote_set.get_verified_votes();
        let votes_to_verify = vote_set.take_unverified_votes();

        if votes_to_verify.is_empty() {
            return vec![];
        }

        info!(
            block_hash = ?block_hash,
            height = height.0,
            votes_to_verify = votes_to_verify.len(),
            already_verified = verified_votes.len(),
            "Triggering batch vote verification (quorum possible)"
        );

        vec![Action::VerifyAndBuildQuorumCertificate {
            block_hash,
            shard_group_id: topology.local_shard(),
            height,
            round,
            parent_block_hash,
            votes_to_verify,
            verified_votes,
            total_voting_power: total_power,
        }]
    }

    /// Mark the vote set for `block_hash` as having produced a QC, so
    /// subsequent duplicates are ignored. No-op if the set is absent.
    pub fn mark_qc_built(&mut self, block_hash: BlockHash) {
        if let Some(vote_set) = self.vote_sets.get_mut(&block_hash) {
            vote_set.on_qc_built();
        }
    }

    /// Record a verified vote into the per-height equivocation log, warning
    /// on a different-block vote at the same round. Called after signature
    /// verification so a forged vote can't pre-empt a legitimate one.
    pub fn track_verified_received_vote(&mut self, block_hash: BlockHash, vote: &BlockVote) {
        match self.record_received_vote(vote.height, vote.voter, block_hash, vote.round) {
            RecordResult::Accepted | RecordResult::Duplicate => {}
            RecordResult::Equivocation {
                existing_block,
                existing_round: _,
            } => {
                warn!(
                    voter = ?vote.voter,
                    height = vote.height.0,
                    round = vote.round.0,
                    existing_block = ?existing_block,
                    new_block = ?block_hash,
                    "EQUIVOCATION DETECTED: validator voted for different blocks at same height/round"
                );
            }
        }
    }

    /// Commit a verified-vote batch back to the block's [`VoteSet`] after
    /// signature verification returned without forming a QC. Logs either the
    /// pending-power state (some signatures verified) or an all-failed
    /// warning (none verified). No-op with a warning when the vote set has
    /// been cleaned up in the meantime.
    pub fn finalize_pending_batch(
        &mut self,
        block_hash: BlockHash,
        verified_votes: Vec<(usize, BlockVote, u64)>,
    ) {
        let Some(vote_set) = self.vote_sets.get_mut(&block_hash) else {
            warn!(
                block_hash = ?block_hash,
                "QC result received but no vote set found"
            );
            return;
        };

        if verified_votes.is_empty() {
            warn!(
                block_hash = ?block_hash,
                "All votes failed verification"
            );
            vote_set.on_votes_verified(vec![]);
        } else {
            vote_set.on_votes_verified(verified_votes);
            info!(
                block_hash = ?block_hash,
                verified_power = vote_set.verified_power(),
                unverified_power = vote_set.unverified_power(),
                "Votes verified but quorum not reached, waiting for more"
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Received-vote tracking (equivocation detection)
    // ═══════════════════════════════════════════════════════════════════════

    /// Record a verified received vote. Enforces the equivocation invariant:
    /// at most one `(block_hash, round)` per `(height, validator)` at any
    /// single round. Later-round votes for different blocks are allowed
    /// (legitimate revote after lock release).
    pub fn record_received_vote(
        &mut self,
        height: BlockHeight,
        voter: ValidatorId,
        block_hash: BlockHash,
        round: Round,
    ) -> RecordResult {
        let key = (height, voter);
        match self.received_votes_by_height.get(&key).copied() {
            None => {
                self.received_votes_by_height
                    .insert(key, (block_hash, round));
                RecordResult::Accepted
            }
            Some((existing_block, existing_round)) => {
                if existing_block == block_hash {
                    RecordResult::Duplicate
                } else if existing_round == round {
                    RecordResult::Equivocation {
                        existing_block,
                        existing_round,
                    }
                } else if existing_round < round {
                    self.received_votes_by_height
                        .insert(key, (block_hash, round));
                    RecordResult::Accepted
                } else {
                    RecordResult::Duplicate
                }
            }
        }
    }
}

/// Result of `VoteKeeper::lock_decision`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockDecision {
    /// No vote recorded at this height — caller may vote.
    Unlocked,
    /// Already voted for the same block at this height; caller should not
    /// re-broadcast but may proceed with verification machinery.
    AlreadyVotedSameBlock { existing_round: Round },
    /// Locked to a different block at this height; caller must not vote.
    LockedToOther {
        existing_block: BlockHash,
        existing_round: Round,
    },
}

/// Result of `VoteKeeper::record_received_vote`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordResult {
    /// Vote was accepted and recorded (first vote or legitimate later-round
    /// revote).
    Accepted,
    /// Voter already voted for the same block at an earlier or same round.
    /// No state change.
    Duplicate,
    /// Byzantine: voter previously voted for a different block at the same
    /// `(height, round)`. The original is preserved.
    Equivocation {
        existing_block: BlockHash,
        existing_round: Round,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        CertificateRoot, Hash, LocalReceiptRoot, ProvisionsRoot, QuorumCertificate, ShardGroupId,
        StateRoot, TransactionRoot, ValidatorId,
    };

    fn make_header(height: BlockHeight) -> BlockHeader {
        BlockHeader {
            shard_group_id: ShardGroupId(0),
            height,
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: hyperscale_types::ProposerTimestamp(1_234_567_890),
            round: Round::INITIAL,
            is_fallback: false,
            state_root: StateRoot::ZERO,
            transaction_root: TransactionRoot::ZERO,
            certificate_root: CertificateRoot::ZERO,
            local_receipt_root: LocalReceiptRoot::ZERO,
            provision_root: ProvisionsRoot::ZERO,
            waves: vec![],
            provision_tx_roots: std::collections::BTreeMap::new(),
            in_flight: 0,
        }
    }

    #[test]
    fn keeper_cleanup_committed_drops_entries_at_and_below_height() {
        let mut vk = VoteKeeper::new();
        vk.voted_heights.insert(
            BlockHeight(1),
            (BlockHash::from_raw(Hash::from_bytes(b"b1")), Round(0)),
        );
        vk.voted_heights.insert(
            BlockHeight(2),
            (BlockHash::from_raw(Hash::from_bytes(b"b2")), Round(0)),
        );
        vk.voted_heights.insert(
            BlockHeight(3),
            (BlockHash::from_raw(Hash::from_bytes(b"b3")), Round(0)),
        );
        vk.received_votes_by_height.insert(
            (BlockHeight(2), ValidatorId(7)),
            (BlockHash::from_raw(Hash::from_bytes(b"b2")), Round(0)),
        );

        vk.cleanup_committed(BlockHeight(2));

        assert_eq!(vk.voted_heights_len(), 1);
        assert!(vk.voted_heights.contains_key(&BlockHeight(3)));
        assert_eq!(vk.received_votes_len(), 0);
    }

    #[test]
    fn keeper_clear_for_height_keeps_current_or_later_round_vote_sets() {
        let header_at = |round: Round| {
            let mut h = make_header(BlockHeight(5));
            h.round = round;
            h
        };

        let mut vk = VoteKeeper::new();
        let hdr_r0 = header_at(Round(0));
        let hdr_r1 = header_at(Round(1));
        let hdr_r2 = header_at(Round(2));
        vk.vote_sets
            .insert(hdr_r0.hash(), VoteSet::new(Some(&hdr_r0), 4));
        vk.vote_sets
            .insert(hdr_r1.hash(), VoteSet::new(Some(&hdr_r1), 4));
        vk.vote_sets
            .insert(hdr_r2.hash(), VoteSet::new(Some(&hdr_r2), 4));
        vk.received_votes_by_height
            .insert((BlockHeight(5), ValidatorId(1)), (hdr_r0.hash(), Round(0)));

        let cleared = vk.clear_for_height(BlockHeight(5), Round(1));

        // Received-vote records for the height are always cleared.
        assert_eq!(cleared, 1);
        assert_eq!(vk.received_votes_len(), 0);

        // Vote set at round 0 is dropped; rounds 1 and 2 remain.
        assert!(!vk.vote_sets.contains_key(&hdr_r0.hash()));
        assert!(vk.vote_sets.contains_key(&hdr_r1.hash()));
        assert!(vk.vote_sets.contains_key(&hdr_r2.hash()));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Equivocation detection (record_received_vote)
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn record_received_vote_accepts_first_vote() {
        let mut vk = VoteKeeper::new();
        let h = BlockHeight(5);
        let v = ValidatorId(2);
        let block = BlockHash::from_raw(Hash::from_bytes(b"block_a"));

        assert_eq!(
            vk.record_received_vote(h, v, block, Round(0)),
            RecordResult::Accepted
        );
        assert_eq!(vk.received_votes_len(), 1);
    }

    #[test]
    fn record_received_vote_flags_equivocation_at_same_height_round() {
        let mut vk = VoteKeeper::new();
        let h = BlockHeight(5);
        let v = ValidatorId(2);
        let block_a = BlockHash::from_raw(Hash::from_bytes(b"block_a"));
        let block_b = BlockHash::from_raw(Hash::from_bytes(b"block_b"));

        vk.record_received_vote(h, v, block_a, Round(0));
        let result = vk.record_received_vote(h, v, block_b, Round(0));

        match result {
            RecordResult::Equivocation {
                existing_block,
                existing_round,
            } => {
                assert_eq!(existing_block, block_a);
                assert_eq!(existing_round, Round(0));
            }
            other => panic!("expected Equivocation, got {other:?}"),
        }
        // Original vote preserved.
        let (stored_block, _) = vk.received_votes_by_height.get(&(h, v)).copied().unwrap();
        assert_eq!(stored_block, block_a);
    }

    #[test]
    fn record_received_vote_allows_revote_at_later_round() {
        let mut vk = VoteKeeper::new();
        let h = BlockHeight(5);
        let v = ValidatorId(2);
        let block_a = BlockHash::from_raw(Hash::from_bytes(b"block_a"));
        let block_b = BlockHash::from_raw(Hash::from_bytes(b"block_b"));

        vk.record_received_vote(h, v, block_a, Round(0));
        assert_eq!(
            vk.record_received_vote(h, v, block_b, Round(1)),
            RecordResult::Accepted
        );

        let (stored_block, stored_round) =
            vk.received_votes_by_height.get(&(h, v)).copied().unwrap();
        assert_eq!(stored_block, block_b);
        assert_eq!(stored_round, Round(1));
    }

    #[test]
    fn record_received_vote_independent_per_height() {
        let mut vk = VoteKeeper::new();
        let v = ValidatorId(2);
        let round = Round(0);
        let block_a = BlockHash::from_raw(Hash::from_bytes(b"block_a"));
        let block_b = BlockHash::from_raw(Hash::from_bytes(b"block_b"));

        assert_eq!(
            vk.record_received_vote(BlockHeight(5), v, block_a, round),
            RecordResult::Accepted
        );
        // Different block at DIFFERENT height: independent, accepted.
        assert_eq!(
            vk.record_received_vote(BlockHeight(6), v, block_b, round),
            RecordResult::Accepted
        );
        assert_eq!(vk.received_votes_len(), 2);
    }

    #[test]
    fn record_received_vote_is_idempotent_on_duplicate() {
        let mut vk = VoteKeeper::new();
        let h = BlockHeight(5);
        let v = ValidatorId(2);
        let block = BlockHash::from_raw(Hash::from_bytes(b"block_a"));

        vk.record_received_vote(h, v, block, Round(0));
        assert_eq!(
            vk.record_received_vote(h, v, block, Round(0)),
            RecordResult::Duplicate
        );
    }

    #[test]
    fn record_received_vote_drops_stale_lower_round() {
        let mut vk = VoteKeeper::new();
        let h = BlockHeight(5);
        let v = ValidatorId(2);
        let block_a = BlockHash::from_raw(Hash::from_bytes(b"block_a"));
        let block_b = BlockHash::from_raw(Hash::from_bytes(b"block_b"));

        vk.record_received_vote(h, v, block_a, Round(3));
        // Later arrival at LOWER round: stale, dropped without overwriting.
        assert_eq!(
            vk.record_received_vote(h, v, block_b, Round(1)),
            RecordResult::Duplicate
        );
        let (stored_block, stored_round) =
            vk.received_votes_by_height.get(&(h, v)).copied().unwrap();
        assert_eq!(stored_block, block_a);
        assert_eq!(stored_round, Round(3));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Own-vote lock (lock_decision, record_own_vote, unlock_at)
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn lock_decision_is_unlocked_without_prior_vote() {
        let vk = VoteKeeper::new();
        assert_eq!(
            vk.lock_decision(BlockHeight(1), BlockHash::from_raw(Hash::from_bytes(b"b"))),
            LockDecision::Unlocked
        );
    }

    #[test]
    fn lock_decision_reports_same_block_after_own_vote() {
        let mut vk = VoteKeeper::new();
        let h = BlockHeight(1);
        let block = BlockHash::from_raw(Hash::from_bytes(b"b"));
        vk.record_own_vote(h, block, Round(0));

        assert_eq!(
            vk.lock_decision(h, block),
            LockDecision::AlreadyVotedSameBlock {
                existing_round: Round(0)
            }
        );
    }

    #[test]
    fn lock_decision_reports_locked_to_other_for_conflicting_block() {
        let mut vk = VoteKeeper::new();
        let h = BlockHeight(1);
        let block_a = BlockHash::from_raw(Hash::from_bytes(b"block_a"));
        let block_b = BlockHash::from_raw(Hash::from_bytes(b"block_b"));
        vk.record_own_vote(h, block_a, Round(0));

        match vk.lock_decision(h, block_b) {
            LockDecision::LockedToOther {
                existing_block,
                existing_round,
            } => {
                assert_eq!(existing_block, block_a);
                assert_eq!(existing_round, Round(0));
            }
            other => panic!("expected LockedToOther, got {other:?}"),
        }
    }

    #[test]
    fn unlock_at_releases_lock_and_reports_prior_presence() {
        let mut vk = VoteKeeper::new();
        let h = BlockHeight(1);
        vk.record_own_vote(h, BlockHash::from_raw(Hash::from_bytes(b"b")), Round(0));

        assert!(vk.unlock_at(h));
        assert!(!vk.is_locked_at(h));
        // Second unlock: no prior lock.
        assert!(!vk.unlock_at(h));
    }
}

#[cfg(test)]
mod properties {
    use super::*;
    use hyperscale_types::Hash;
    use proptest::prelude::*;
    use std::collections::HashMap;

    /// Arbitrary received-vote event, drawn from a small key space so multiple
    /// events are likely to collide on `(height, voter)` and stress the
    /// equivocation path.
    fn vote_event() -> impl Strategy<Value = (BlockHeight, ValidatorId, BlockHash, Round)> {
        (
            1u64..=4, // height
            0u64..=3, // voter
            0u8..4,   // block variant (4 distinct blocks)
            0u64..=3, // round
        )
            .prop_map(|(h, v, block_variant, r)| {
                let block = BlockHash::from_raw(Hash::from_bytes(&[block_variant; 32]));
                (BlockHeight(h), ValidatorId(v), block, Round(r))
            })
    }

    proptest! {
        /// Invariant: a stored `(block, round)` for `(height, voter)` matches
        /// what a reference-model map would hold under the same "replace only
        /// on strictly greater round; reject on equal round + different block"
        /// rules.
        #[test]
        fn record_received_vote_matches_reference_model(
            events in prop::collection::vec(vote_event(), 0..80),
        ) {
            let mut vk = VoteKeeper::new();
            let mut model: HashMap<(BlockHeight, ValidatorId), (BlockHash, Round)> = HashMap::new();

            for (h, v, block, round) in events {
                let result = vk.record_received_vote(h, v, block, round);
                let key = (h, v);
                match model.get(&key).copied() {
                    None => {
                        prop_assert_eq!(result, RecordResult::Accepted);
                        model.insert(key, (block, round));
                    }
                    Some((existing_block, existing_round)) => {
                        if existing_block == block {
                            prop_assert_eq!(result, RecordResult::Duplicate);
                        } else if existing_round == round {
                            prop_assert_eq!(
                                result,
                                RecordResult::Equivocation {
                                    existing_block,
                                    existing_round,
                                }
                            );
                        } else if existing_round < round {
                            prop_assert_eq!(result, RecordResult::Accepted);
                            model.insert(key, (block, round));
                        } else {
                            prop_assert_eq!(result, RecordResult::Duplicate);
                        }
                    }
                }
                // Invariant: the keeper's stored value always matches the model.
                let stored = vk.received_votes_by_height.get(&key).copied();
                prop_assert_eq!(stored, model.get(&key).copied());
            }
        }

        /// Invariant: for any `(height, voter)`, the stored round is
        /// monotonically non-decreasing over time.
        #[test]
        fn record_received_vote_round_is_monotone(
            events in prop::collection::vec(vote_event(), 0..80),
        ) {
            let mut vk = VoteKeeper::new();
            let mut last_round: HashMap<(BlockHeight, ValidatorId), Round> = HashMap::new();

            for (h, v, block, round) in events {
                vk.record_received_vote(h, v, block, round);
                let key = (h, v);
                if let Some((_, stored_round)) = vk.received_votes_by_height.get(&key).copied() {
                    if let Some(prev) = last_round.get(&key).copied() {
                        prop_assert!(stored_round >= prev);
                    }
                    last_round.insert(key, stored_round);
                }
            }
        }

        /// Invariant: `record_own_vote` followed by `unlock_at` returns the
        /// keeper to an "unlocked" state for that height, regardless of
        /// prior content.
        #[test]
        fn unlock_at_is_complete_inverse_of_record_own_vote(
            height in 1u64..=100,
            block_variant in 0u8..8,
            round in 0u64..=10,
        ) {
            let mut vk = VoteKeeper::new();
            let h = BlockHeight(height);
            let block = BlockHash::from_raw(Hash::from_bytes(&[block_variant; 32]));

            vk.record_own_vote(h, block, Round(round));
            prop_assert!(vk.is_locked_at(h));

            prop_assert!(vk.unlock_at(h));
            prop_assert!(!vk.is_locked_at(h));
            prop_assert_eq!(vk.lock_decision(h, block), LockDecision::Unlocked);
        }
    }
}
