//! Vote accounting: vote sets per block and received-vote equivocation
//! tracking. The safe-vote lock itself lives on the coordinator
//! (`locked_round` / `last_voted_round`), not here.
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

use std::collections::HashMap;

use hyperscale_core::Action;
#[cfg(test)]
use hyperscale_types::{BeaconWitnessLeafCount, BeaconWitnessRoot};
use hyperscale_types::{
    BlockHash, BlockHeader, BlockHeight, BlockVote, Bls12381G1PublicKey, Round, ShardGroupId,
    TopologySnapshot, ValidatorId, Verified, VotePower,
};
use tracing::{info, trace, warn};

pub use crate::vote_set::VoteSet;

/// Shared per-vote lookup result from [`VoteKeeper::preflight`].
struct VotePreflight {
    voter_index: usize,
    voting_power: VotePower,
    public_key: Bls12381G1PublicKey,
}

/// Top-level vote accounting state.
///
/// Owns the per-block [`VoteSet`]s and the received-vote record used for
/// equivocation detection. The safe-vote lock lives on the coordinator.
pub struct VoteKeeper {
    /// Vote sets for blocks being voted on (`block_hash` -> vote set).
    vote_sets: HashMap<BlockHash, VoteSet>,

    /// Per-validator record of received verified votes for equivocation
    /// detection. Key: (height, validator), Value: (`block_hash`, round).
    /// A different-block vote at the same (height, round) is equivocation;
    /// at a later round it's a legitimate revote.
    received_votes_by_height: HashMap<(BlockHeight, ValidatorId), (BlockHash, Round)>,
}

impl VoteKeeper {
    pub fn new() -> Self {
        Self {
            vote_sets: HashMap::new(),
            received_votes_by_height: HashMap::new(),
        }
    }

    /// Drop all vote tracking at or below `committed_height`.
    pub fn cleanup_committed(&mut self, committed_height: BlockHeight) {
        self.vote_sets
            .retain(|_hash, vote_set| vote_set.height().is_none_or(|h| h > committed_height));
        self.received_votes_by_height
            .retain(|(height, _), _| *height > committed_height);
    }

    pub fn vote_sets_len(&self) -> usize {
        self.vote_sets.len()
    }

    pub fn received_votes_len(&self) -> usize {
        self.received_votes_by_height.len()
    }

    /// Verified received vote for `(height, voter)`, if any.
    #[cfg(test)]
    #[must_use]
    pub fn received_vote(
        &self,
        height: BlockHeight,
        voter: ValidatorId,
    ) -> Option<(BlockHash, Round)> {
        self.received_votes_by_height.get(&(height, voter)).copied()
    }

    /// Stamp a late-arriving header into a buffered vote set so QC aggregation
    /// has the `parent_block_hash` it needs. Returns `true` if a matching
    /// vote set was present and updated.
    pub fn link_header(&mut self, block_hash: BlockHash, header: &BlockHeader) -> bool {
        let Some(vote_set) = self.vote_sets.get_mut(&block_hash) else {
            return false;
        };
        vote_set.set_header(header);
        true
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Vote ingestion
    // ═══════════════════════════════════════════════════════════════════════

    /// Admit a locally-produced, already-verified block vote into the
    /// block's [`VoteSet`] without re-checking the BLS signature, then
    /// fire batch verification if the combined power can now reach
    /// quorum. `header_for_vote` is the header from the caller's
    /// pending-block map; `None` is acceptable when the header hasn't
    /// been received yet — a later [`VoteSet::set_header`] fills it in.
    pub fn accept_verified_vote(
        &mut self,
        topology: &TopologySnapshot,
        me: ValidatorId,
        local_shard: ShardGroupId,
        vote: Verified<BlockVote>,
        committed_height: BlockHeight,
        header_for_vote: Option<&BlockHeader>,
    ) -> Vec<Action> {
        let block_hash = vote.block_hash();
        let Some(prep) = Self::preflight(topology, local_shard, &vote, committed_height) else {
            return vec![];
        };

        let committee_size = topology.committee_for_shard(local_shard).len();
        let vote_set = self
            .vote_sets
            .entry(block_hash)
            .or_insert_with(|| VoteSet::new(header_for_vote, committee_size));

        if vote_set.has_seen_validator(prep.voter_index) {
            trace!("Already seen vote from validator {:?}", vote.voter());
            return vec![];
        }

        let is_own_vote = vote.voter() == me;
        trace!(
            block_hash = ?block_hash,
            is_own_vote,
            "Admitting pre-verified vote"
        );
        vote_set.add_verified_vote(prep.voter_index, vote, prep.voting_power);

        self.maybe_trigger_verification(topology, local_shard, block_hash)
    }

    /// Accept a wire-arrived block vote: buffer its signature into the
    /// block's [`VoteSet`] and fire batch verification once combined
    /// power can reach quorum. Wire-arrived votes that claim our own
    /// validator id take the same BLS batch route as any other voter —
    /// the in-process verified path is only reachable through
    /// [`Self::accept_verified_vote`].
    pub fn accept_unverified_vote(
        &mut self,
        topology: &TopologySnapshot,
        me: ValidatorId,
        local_shard: ShardGroupId,
        vote: BlockVote,
        committed_height: BlockHeight,
        header_for_vote: Option<&BlockHeader>,
    ) -> Vec<Action> {
        let block_hash = vote.block_hash();
        let Some(prep) = Self::preflight(topology, local_shard, &vote, committed_height) else {
            return vec![];
        };

        let committee_size = topology.committee_for_shard(local_shard).len();
        let vote_set = self
            .vote_sets
            .entry(block_hash)
            .or_insert_with(|| VoteSet::new(header_for_vote, committee_size));

        if vote_set.has_seen_validator(prep.voter_index) {
            trace!("Already seen vote from validator {:?}", vote.voter());
            return vec![];
        }

        let total_power = topology.voting_power_for_shard(local_shard);
        vote_set.buffer_unverified_vote(prep.voter_index, vote, prep.public_key, prep.voting_power);
        trace!(
            validator = ?me,
            block_hash = ?block_hash,
            verified_power = vote_set.verified_power().inner(),
            unverified_power = vote_set.unverified_power().inner(),
            total_power = total_power.inner(),
            "Vote buffered"
        );

        self.maybe_trigger_verification(topology, local_shard, block_hash)
    }

    /// Shared committee/power lookup for both vote-ingestion paths.
    /// Returns `None` when the vote should be dropped (committed height,
    /// non-committee voter, missing public key).
    fn preflight(
        topology: &TopologySnapshot,
        local_shard: ShardGroupId,
        vote: &BlockVote,
        committed_height: BlockHeight,
    ) -> Option<VotePreflight> {
        let height = vote.height();
        let voter = vote.voter();

        if height <= committed_height {
            trace!(
                vote_anchor_ts = height.inner(),
                committed_height = committed_height.inner(),
                voter = ?voter,
                "Skipping vote for already-committed height"
            );
            return None;
        }

        let Some(voter_index) = topology.committee_index_for_shard(local_shard, voter) else {
            warn!("Vote from validator {:?} not in committee", voter);
            return None;
        };

        // `committee_index_for_shard` returning `Some` means the voter is in
        // the committee, and the topology snapshot invariant guarantees every
        // committee member has a positive voting power entry.
        let voting_power = topology
            .voting_power(voter)
            .expect("committee member has voting power (TopologySnapshot invariant)");

        let Some(public_key) = topology.public_key(voter) else {
            warn!("No public key for validator {:?}", voter);
            return None;
        };

        Some(VotePreflight {
            voter_index,
            voting_power,
            public_key,
        })
    }

    /// Trigger batch vote verification for `block_hash` once the combined
    /// verified + buffered voting power could reach quorum. Returns a
    /// `VerifyAndBuildQuorumCertificate` action, or empty if the quorum
    /// threshold can't be met yet or no buffered signatures are waiting.
    pub fn maybe_trigger_verification(
        &mut self,
        topology: &TopologySnapshot,
        local_shard: ShardGroupId,
        block_hash: BlockHash,
    ) -> Vec<Action> {
        let total_power = topology.voting_power_for_shard(local_shard);

        let Some(vote_set) = self.vote_sets.get_mut(&block_hash) else {
            return vec![];
        };

        if !vote_set.should_trigger_verification(total_power) {
            return vec![];
        }

        let Some((_, height, round, parent_block_hash, parent_weighted_timestamp)) =
            vote_set.verification_data()
        else {
            return vec![];
        };

        let verified_votes = vote_set.get_verified_votes();
        let votes_to_verify = vote_set.take_unverified_votes();

        if votes_to_verify.is_empty() {
            return vec![];
        }

        info!(
            block_hash = ?block_hash,
            height = height.inner(),
            votes_to_verify = votes_to_verify.len(),
            already_verified = verified_votes.len(),
            "Triggering batch vote verification (quorum possible)"
        );

        vec![Action::VerifyAndBuildQuorumCertificate {
            block_hash,
            shard_group_id: local_shard,
            height,
            round,
            parent_block_hash,
            parent_weighted_timestamp,
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
        match self.record_received_vote(vote.height(), vote.voter(), block_hash, vote.round()) {
            RecordResult::Accepted | RecordResult::Duplicate => {}
            RecordResult::Equivocation {
                existing_block,
                existing_round: _,
            } => {
                warn!(
                    voter = ?vote.voter(),
                    height = vote.height().inner(),
                    round = vote.round().inner(),
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
        verified_votes: Vec<(usize, Verified<BlockVote>, VotePower)>,
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
                verified_power = vote_set.verified_power().inner(),
                unverified_power = vote_set.unverified_power().inner(),
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
    use hyperscale_types::{
        CertificateRoot, Hash, InFlightCount, LocalReceiptRoot, ProposerTimestamp, ProvisionsRoot,
        QuorumCertificate, ShardGroupId, StateRoot, TransactionRoot, ValidatorId,
    };

    use super::*;

    fn make_header_at_round(height: BlockHeight, round: Round) -> BlockHeader {
        BlockHeader::new(
            ShardGroupId::new(0),
            height,
            BlockHash::from_raw(Hash::from_bytes(b"parent")),
            QuorumCertificate::genesis(ShardGroupId::new(0)),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(1_234_567_890),
            round,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            std::collections::BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
        )
    }

    #[test]
    fn keeper_cleanup_committed_drops_entries_at_and_below_height() {
        let mut vk = VoteKeeper::new();
        let hdr_h1 = make_header_at_round(BlockHeight::new(1), Round::new(1));
        let hdr_h3 = make_header_at_round(BlockHeight::new(3), Round::new(3));
        vk.vote_sets
            .insert(hdr_h1.hash(), VoteSet::new(Some(&hdr_h1), 4));
        vk.vote_sets
            .insert(hdr_h3.hash(), VoteSet::new(Some(&hdr_h3), 4));
        vk.received_votes_by_height.insert(
            (BlockHeight::new(2), ValidatorId::new(7)),
            (BlockHash::from_raw(Hash::from_bytes(b"b2")), Round::new(0)),
        );

        vk.cleanup_committed(BlockHeight::new(2));

        // Vote sets and received-vote records at or below the committed height
        // are dropped; the height-3 vote set survives.
        assert!(!vk.vote_sets.contains_key(&hdr_h1.hash()));
        assert!(vk.vote_sets.contains_key(&hdr_h3.hash()));
        assert_eq!(vk.received_votes_len(), 0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Equivocation detection (record_received_vote)
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn record_received_vote_accepts_first_vote() {
        let mut vk = VoteKeeper::new();
        let h = BlockHeight::new(5);
        let v = ValidatorId::new(2);
        let block = BlockHash::from_raw(Hash::from_bytes(b"block_a"));

        assert_eq!(
            vk.record_received_vote(h, v, block, Round::new(0)),
            RecordResult::Accepted
        );
        assert_eq!(vk.received_votes_len(), 1);
    }

    #[test]
    fn record_received_vote_flags_equivocation_at_same_height_round() {
        let mut vk = VoteKeeper::new();
        let h = BlockHeight::new(5);
        let v = ValidatorId::new(2);
        let block_a = BlockHash::from_raw(Hash::from_bytes(b"block_a"));
        let block_b = BlockHash::from_raw(Hash::from_bytes(b"block_b"));

        vk.record_received_vote(h, v, block_a, Round::new(0));
        let result = vk.record_received_vote(h, v, block_b, Round::new(0));

        match result {
            RecordResult::Equivocation {
                existing_block,
                existing_round,
            } => {
                assert_eq!(existing_block, block_a);
                assert_eq!(existing_round, Round::new(0));
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
        let h = BlockHeight::new(5);
        let v = ValidatorId::new(2);
        let block_a = BlockHash::from_raw(Hash::from_bytes(b"block_a"));
        let block_b = BlockHash::from_raw(Hash::from_bytes(b"block_b"));

        vk.record_received_vote(h, v, block_a, Round::new(0));
        assert_eq!(
            vk.record_received_vote(h, v, block_b, Round::new(1)),
            RecordResult::Accepted
        );

        let (stored_block, stored_round) =
            vk.received_votes_by_height.get(&(h, v)).copied().unwrap();
        assert_eq!(stored_block, block_b);
        assert_eq!(stored_round, Round::new(1));
    }

    #[test]
    fn record_received_vote_independent_per_height() {
        let mut vk = VoteKeeper::new();
        let v = ValidatorId::new(2);
        let round = Round::new(0);
        let block_a = BlockHash::from_raw(Hash::from_bytes(b"block_a"));
        let block_b = BlockHash::from_raw(Hash::from_bytes(b"block_b"));

        assert_eq!(
            vk.record_received_vote(BlockHeight::new(5), v, block_a, round),
            RecordResult::Accepted
        );
        // Different block at DIFFERENT height: independent, accepted.
        assert_eq!(
            vk.record_received_vote(BlockHeight::new(6), v, block_b, round),
            RecordResult::Accepted
        );
        assert_eq!(vk.received_votes_len(), 2);
    }

    #[test]
    fn record_received_vote_is_idempotent_on_duplicate() {
        let mut vk = VoteKeeper::new();
        let h = BlockHeight::new(5);
        let v = ValidatorId::new(2);
        let block = BlockHash::from_raw(Hash::from_bytes(b"block_a"));

        vk.record_received_vote(h, v, block, Round::new(0));
        assert_eq!(
            vk.record_received_vote(h, v, block, Round::new(0)),
            RecordResult::Duplicate
        );
    }

    #[test]
    fn record_received_vote_drops_stale_lower_round() {
        let mut vk = VoteKeeper::new();
        let h = BlockHeight::new(5);
        let v = ValidatorId::new(2);
        let block_a = BlockHash::from_raw(Hash::from_bytes(b"block_a"));
        let block_b = BlockHash::from_raw(Hash::from_bytes(b"block_b"));

        vk.record_received_vote(h, v, block_a, Round::new(3));
        // Later arrival at LOWER round: stale, dropped without overwriting.
        assert_eq!(
            vk.record_received_vote(h, v, block_b, Round::new(1)),
            RecordResult::Duplicate
        );
        let (stored_block, stored_round) =
            vk.received_votes_by_height.get(&(h, v)).copied().unwrap();
        assert_eq!(stored_block, block_a);
        assert_eq!(stored_round, Round::new(3));
    }
}

#[cfg(test)]
mod properties {
    use std::collections::HashMap;

    use hyperscale_types::Hash;
    use proptest::prelude::*;

    use super::*;

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
                (
                    BlockHeight::new(h),
                    ValidatorId::new(v),
                    block,
                    Round::new(r),
                )
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
    }
}
