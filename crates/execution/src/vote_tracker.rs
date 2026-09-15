//! Execution vote tracker.
//!
//! Tracks the collection of execution votes during the cross-shard
//! atomic execution protocol.
//!
//! ## What the anchor is in the key
//!
//! One honest validator emits one vote per tick: the builder is one-shot
//! behind a `voted` flag, the anchor is the tick's own constant
//! timestamp, and a retry re-sends the stored anchor to a rotated
//! leader. So the anchor in the tally key is not there to separate one
//! validator's votes at different heights — it is there because the
//! certificate's signer bitfield is positional against the committee
//! seated at the anchor, and a fork can produce two anchors at one tick
//! height. Grouping by `(global_receipt_root, vote_anchor_ts)` is what
//! lets a node aggregate a certificate for a tick whose block it does
//! not hold.
//!
//! ## Deferred Verification Optimization
//!
//! Votes are NOT verified when received. Instead, they are buffered until
//! we have enough voting power for quorum. This avoids wasting CPU on votes
//! we'll never use.

use std::collections::{BTreeMap, HashSet};

use hyperscale_types::{
    BlockHash, ConsensusPublicKey, ExecutionVote, GlobalReceiptRoot, TickId, ValidatorId, Verified,
    VoteCount, WeightedTimestamp,
};

/// Key for grouping votes: `(global_receipt_root, vote_anchor_ts)`.
///
/// Votes at different heights have different signatures and cannot be
/// aggregated together. This prevents stale votes from combining with new
/// ones if an abort intent changes the `global_receipt_root` between heights.
type VoteKey = (GlobalReceiptRoot, WeightedTimestamp);

/// Tracks execution votes for a specific tick within a block.
///
/// After executing all transactions in a tick, validators create an execution
/// vote on the receipt root. This tracker collects votes and determines when
/// quorum is reached for signature aggregation into an execution certificate.
#[derive(Debug)]
pub struct VoteTracker {
    /// Tick identifier.
    tick_id: TickId,
    /// Block hash this tick belongs to.
    block_hash: BlockHash,
    /// Quorum threshold (2f+1 voting power).
    quorum: VoteCount,

    // ═══════════════════════════════════════════════════════════════════════
    // Verified votes (passed signature verification)
    // ═══════════════════════════════════════════════════════════════════════
    /// Verified votes grouped by (`global_receipt_root`, `vote_anchor_ts`).
    votes_by_key: BTreeMap<VoteKey, Vec<Verified<ExecutionVote>>>,
    /// Voting power per (`global_receipt_root`, `vote_anchor_ts`) (verified votes only).
    power_by_key: BTreeMap<VoteKey, VoteCount>,

    // ═══════════════════════════════════════════════════════════════════════
    // Unverified votes (buffered until quorum possible)
    // ═══════════════════════════════════════════════════════════════════════
    /// Unverified votes buffered for batch verification.
    /// Each entry is (vote, `public_key`).
    unverified_votes: Vec<(ExecutionVote, ConsensusPublicKey)>,
    /// Number of unverified votes buffered.
    unverified_power: VoteCount,
    /// Validators with a vote buffered but not yet batch verified, keyed by
    /// (`validator_id`, `vote_anchor_ts`). Transient: a slot reopens when the
    /// batch drains, so a claimed identity cannot hold it. Permanent dedup is
    /// [`Self::add_verified_vote`]'s scan over [`Self::votes_by_key`].
    buffered: HashSet<(ValidatorId, WeightedTimestamp)>,
    /// Whether a verification batch is currently in flight.
    pending_verification: bool,
}

impl VoteTracker {
    /// Create a new execution vote tracker.
    #[must_use]
    pub(crate) fn new(tick_id: TickId, block_hash: BlockHash, quorum: VoteCount) -> Self {
        Self {
            tick_id,
            block_hash,
            quorum,
            votes_by_key: BTreeMap::new(),
            power_by_key: BTreeMap::new(),
            unverified_votes: Vec::new(),
            unverified_power: VoteCount::ZERO,
            buffered: HashSet::new(),
            pending_verification: false,
        }
    }

    /// Get the tick ID.
    #[must_use]
    pub const fn tick_id(&self) -> &TickId {
        &self.tick_id
    }

    /// Get the block hash.
    #[must_use]
    pub(crate) const fn block_hash(&self) -> BlockHash {
        self.block_hash
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Deferred Verification Methods
    // ═══════════════════════════════════════════════════════════════════════

    /// Buffer an unverified vote for later batch verification.
    ///
    /// Returns `true` if the vote was buffered, `false` if one is already
    /// buffered for this (validator, `vote_anchor_ts`). The claimed validator is
    /// unauthenticated here, so the slot it takes is released again by
    /// [`Self::take_unverified_votes`].
    pub(crate) fn buffer_unverified_vote(
        &mut self,
        vote: ExecutionVote,
        public_key: ConsensusPublicKey,
    ) -> bool {
        let dedup_key = (vote.validator(), vote.vote_anchor_ts());

        if self.buffered.contains(&dedup_key) {
            return false;
        }

        self.buffered.insert(dedup_key);
        self.unverified_votes.push((vote, public_key));
        self.unverified_power += VoteCount::MIN;
        true
    }

    /// Check if we should trigger batch verification.
    ///
    /// Verification is triggered when:
    /// 1. We have unverified votes
    /// 2. No verification is already in flight
    /// 3. Total power (verified + unverified) could reach quorum
    #[must_use]
    pub(crate) fn should_trigger_verification(&self) -> bool {
        if self.unverified_votes.is_empty() || self.pending_verification {
            return false;
        }

        let best_verified_power = self
            .power_by_key
            .values()
            .max()
            .copied()
            .unwrap_or(VoteCount::ZERO);

        let total_potential = best_verified_power + self.unverified_power;
        total_potential >= self.quorum
    }

    /// Take unverified votes for batch verification.
    ///
    /// Marks verification as pending. Call `on_verification_complete` when done.
    pub(crate) fn take_unverified_votes(&mut self) -> Vec<(ExecutionVote, ConsensusPublicKey)> {
        self.pending_verification = true;
        self.unverified_power = VoteCount::ZERO;
        // Reopen the buffered slots: these votes are now in the batch, and only
        // the ones whose signatures verify reach `add_verified_vote`. A voter
        // whose buffered vote fails can then re-buffer rather than be censored.
        self.buffered.clear();
        std::mem::take(&mut self.unverified_votes)
    }

    /// Handle verification completion.
    pub(crate) const fn on_verification_complete(&mut self) {
        self.pending_verification = false;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Verified Vote Methods
    // ═══════════════════════════════════════════════════════════════════════

    /// Add a verified vote, counting it toward its quorum bucket.
    ///
    /// Idempotent per `(validator, vote_anchor_ts)`: redundant calls (e.g.
    /// own-vote re-feeds from leader-rotation retries that land on `self`)
    /// are dropped so [`Self::power_by_key`] only counts unique signers.
    /// Dedup scans [`Self::votes_by_key`] — a validator may have voted on
    /// any `global_receipt_root` at this anchor, so the check spans every
    /// bucket sharing the incoming `vote_anchor_ts`.
    pub(crate) fn add_verified_vote(&mut self, vote: Verified<ExecutionVote>) {
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
        *self.power_by_key.entry(key).or_insert(VoteCount::ZERO) += VoteCount::MIN;
    }

    /// Check if quorum is reached for any (`global_receipt_root`, `vote_anchor_ts`) pair.
    ///
    /// Returns `Some((global_receipt_root, vote_anchor_ts, total_power))` if quorum reached.
    /// If multiple pairs have quorum, returns the one with the lowest `vote_anchor_ts`.
    #[must_use]
    pub(crate) fn check_quorum(&self) -> Option<(GlobalReceiptRoot, WeightedTimestamp, VoteCount)> {
        let mut best: Option<(GlobalReceiptRoot, WeightedTimestamp, VoteCount)> = None;
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
    pub(crate) fn take_votes(
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
    pub(crate) fn total_verified_power(&self) -> VoteCount {
        self.power_by_key
            .values()
            .fold(VoteCount::ZERO, |acc, &p| acc.saturating_add(p))
    }

    /// Return the number of distinct receipt roots across all verified vote groups.
    #[must_use]
    pub(crate) fn distinct_global_receipt_root_count(&self) -> usize {
        self.power_by_key
            .keys()
            .map(|(root, _)| root)
            .collect::<HashSet<_>>()
            .len()
    }

    /// Return a summary of verified voting power per global receipt root (summed across vote heights).
    /// Used for diagnostics when quorum cannot be reached.
    #[must_use]
    pub(crate) fn global_receipt_root_power_summary(&self) -> Vec<(GlobalReceiptRoot, VoteCount)> {
        let mut by_root: BTreeMap<GlobalReceiptRoot, VoteCount> = BTreeMap::new();
        for (&(root, _), &power) in &self.power_by_key {
            *by_root.entry(root).or_insert(VoteCount::ZERO) += power;
        }
        by_root.into_iter().collect()
    }
}

#[cfg(test)]
impl VoteTracker {
    /// Check if verification is pending.
    #[must_use]
    pub(crate) const fn is_verification_pending(&self) -> bool {
        self.pending_verification
    }

    /// Get votes for a specific global receipt root at any height (for tests).
    #[must_use]
    pub(crate) fn votes_for_global_receipt_root(
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

    use hyperscale_crypto_bls::BlsSigner;
    use hyperscale_types::{BlockHeight, ConsensusSignature, Hash, ShardId, Signer};

    use super::*;

    fn make_test_public_key() -> ConsensusPublicKey {
        BlsSigner::generate().public_key()
    }

    fn make_vote(validator: u64, global_receipt_root: GlobalReceiptRoot) -> ExecutionVote {
        ExecutionVote::new(
            WeightedTimestamp::from_millis(11),
            TickId::new(ShardId::ROOT, BlockHeight::new(0)),
            ShardId::ROOT,
            global_receipt_root,
            5,
            vec![],
            ValidatorId::new(validator),
            ConsensusSignature::ZERO,
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
            TickId::new(ShardId::ROOT, BlockHeight::new(0)),
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            VoteCount::new(3),
        );

        let root = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"receipt_root"));

        tracker.add_verified_vote(make_verified_vote(0, root));
        assert!(tracker.check_quorum().is_none());

        tracker.add_verified_vote(make_verified_vote(1, root));
        assert!(tracker.check_quorum().is_none());

        tracker.add_verified_vote(make_verified_vote(2, root));
        let result = tracker.check_quorum();
        assert!(result.is_some());
        let (r, vh, power) = result.unwrap();
        assert_eq!(r, root);
        assert_eq!(vh, WeightedTimestamp::from_millis(11)); // vote_anchor_ts from make_vote
        assert_eq!(power, VoteCount::new(3));
        assert_eq!(tracker.votes_for_global_receipt_root(root).len(), 3);
    }

    #[test]
    fn test_vote_tracker_conflicting_roots() {
        let mut tracker = VoteTracker::new(
            TickId::new(ShardId::ROOT, BlockHeight::new(0)),
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            VoteCount::new(3),
        );

        let root_a = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root_a"));
        let root_b = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root_b"));

        tracker.add_verified_vote(make_verified_vote(0, root_a));
        tracker.add_verified_vote(make_verified_vote(1, root_b));
        tracker.add_verified_vote(make_verified_vote(2, root_a));
        // 2 for root_a, 1 for root_b — no quorum
        assert!(tracker.check_quorum().is_none());

        tracker.add_verified_vote(make_verified_vote(3, root_a));
        let result = tracker.check_quorum().unwrap();
        assert_eq!(result.0, root_a);
    }

    #[test]
    fn test_deferred_verification_flow() {
        let pk = make_test_public_key();
        let root = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root"));
        let mut tracker = VoteTracker::new(
            TickId::new(ShardId::ROOT, BlockHeight::new(0)),
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            VoteCount::new(3),
        );

        // Buffer 2 votes — not enough for quorum
        assert!(tracker.buffer_unverified_vote(make_vote(0, root), pk));
        assert!(tracker.buffer_unverified_vote(make_vote(1, root), pk));
        assert!(!tracker.should_trigger_verification());

        // Buffer 3rd — now enough
        assert!(tracker.buffer_unverified_vote(make_vote(2, root), pk));
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
            TickId::new(ShardId::ROOT, BlockHeight::new(0)),
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            VoteCount::new(3),
        );

        assert!(tracker.buffer_unverified_vote(make_vote(0, root), pk));
        assert!(!tracker.buffer_unverified_vote(make_vote(0, root), pk));
    }

    #[test]
    fn duplicate_verified_vote_does_not_inflate_power() {
        // Own votes bypass `buffer_unverified_vote` and arrive directly at
        // `add_verified_vote`. Leader-rotation retries that land on `self`
        // re-feed the same own vote; the tally must count it once.
        let root = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root"));
        let mut tracker = VoteTracker::new(
            TickId::new(ShardId::ROOT, BlockHeight::new(0)),
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            VoteCount::new(3),
        );

        tracker.add_verified_vote(make_verified_vote(0, root));
        tracker.add_verified_vote(make_verified_vote(0, root));
        tracker.add_verified_vote(make_verified_vote(0, root));

        assert_eq!(tracker.total_verified_power(), VoteCount::MIN);
        assert!(tracker.check_quorum().is_none());
    }

    #[test]
    fn test_combined_verified_and_unverified_power() {
        let pk = make_test_public_key();
        let root = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root"));
        let mut tracker = VoteTracker::new(
            TickId::new(ShardId::ROOT, BlockHeight::new(0)),
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            VoteCount::new(3),
        );

        // 1 verified + 2 unverified = 3 → should trigger
        tracker.add_verified_vote(make_verified_vote(0, root));
        assert!(tracker.buffer_unverified_vote(make_vote(1, root), pk));
        assert!(!tracker.should_trigger_verification());

        assert!(tracker.buffer_unverified_vote(make_vote(2, root), pk));
        assert!(tracker.should_trigger_verification());
    }

    #[test]
    fn forged_unverified_vote_does_not_censor_genuine_vote() {
        // A vote buffered with a bad signature must not permanently occupy its
        // voter's slot: once the batch drains and the signature fails, the
        // genuine vote from the same validator is still admissible.
        let pk = make_test_public_key();
        let root = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root"));
        let mut tracker = VoteTracker::new(
            TickId::new(ShardId::ROOT, BlockHeight::new(0)),
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            VoteCount::new(3),
        );

        // An attacker buffers a (would-be-forged) vote attributed to validator 0.
        assert!(tracker.buffer_unverified_vote(make_vote(0, root), pk));

        // The batch drains and every signature fails verification, so nothing
        // is fed back through `add_verified_vote`.
        let _ = tracker.take_unverified_votes();
        tracker.on_verification_complete();

        // Validator 0's genuine vote is not blocked by the failed forgery.
        assert!(tracker.buffer_unverified_vote(make_vote(0, root), pk));
    }
}
