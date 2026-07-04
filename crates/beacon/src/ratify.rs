//! Epoch ratification tracker: rounds, polka detection, locks, and
//! commit-certificate assembly for one `(anchor, epoch)`.
//!
//! One [`RatifyTracker`] drives the local validator's votes for the
//! epoch pending at its anchor and pools every peer's verified votes.
//! The safety register is one prevote and one precommit per round;
//! everything else follows from three rules:
//!
//! - **Prevote** the verified candidate's hash when it arrives, the
//!   skip hash once the deadline passes without it. A precommit locks
//!   its value: later rounds re-prevote the lock, leaving it only for
//!   a value whose prevote quorum (polka) formed at a round strictly
//!   newer than the lock — following the pool, never leading it.
//! - **Precommit** a value exactly when its polka is observed, at
//!   rounds no older than the current one. A polka carries honest
//!   voters that verified the value, so the precommit needs no local
//!   copy of the block.
//! - **Commit** when a quorum of precommits for one hash land in one
//!   round — at any round, however stale: a certificate's validity
//!   doesn't age.
//!
//! Rounds only move forward: a round timeout advances by one, a polka
//! at a newer round fast-forwards to it. Voting into rounds already
//! left would let one validator's signatures straddle two quorums.
//!
//! No topology, no BLS, no clocks — pure data structure; the
//! coordinator feeds verified votes and timer edges in, and lifts the
//! typed [`RatifyEffect`]s into actions. Tests need validator keypairs
//! and an anchor, nothing more.

use std::collections::BTreeMap;

use hyperscale_types::{
    BeaconBlock, BeaconBlockHash, Bls12381G1PublicKey, Epoch, RatifyCert, RatifyPhase, RatifyRound,
    RatifyVote, ValidatorId, Verified, ratify_quorum,
};

/// Rounds ahead of the current one a vote may reference and still be
/// pooled. Peers legitimately run ahead by however far their timers
/// have fired; anything further is either garbage or will be re-sent
/// once this replica catches up.
const MAX_ROUND_AHEAD: u32 = 4;

/// What the tracker wants done after absorbing an event.
///
/// The coordinator lifts sign intents into signing actions (the signed
/// vote loops back through verification into
/// [`RatifyTracker::observe`], where it counts like any peer's) and
/// routes an assembled cert into block commitment.
#[derive(Debug, Clone)]
pub enum RatifyEffect {
    /// Sign and broadcast a prevote for `block_hash` at `round`.
    SignPrevote {
        /// Round the prevote is cast in.
        round: RatifyRound,
        /// Hash the prevote names.
        block_hash: BeaconBlockHash,
    },
    /// Sign and broadcast a precommit for `block_hash` at `round`.
    SignPrecommit {
        /// Round the precommit is cast in.
        round: RatifyRound,
        /// Hash the precommit names.
        block_hash: BeaconBlockHash,
    },
    /// A precommit quorum assembled into a commit certificate — the
    /// epoch's block is decided.
    CertAssembled {
        /// The self-verifying pool certificate.
        cert: Box<Verified<RatifyCert>>,
    },
}

/// Ratification state for the epoch pending at one anchor.
#[derive(Debug)]
pub struct RatifyTracker {
    anchor: BeaconBlockHash,
    epoch: Epoch,
    /// Active pool for the epoch, in the positional order every cert
    /// bitfield indexes. Fixed at construction — the pool derives from
    /// the anchor's state, common to every candidate outcome.
    pool: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    /// Canonical skip-block hash — computed once; prevoting "skip" is
    /// prevoting this.
    skip_hash: BeaconBlockHash,
    /// Hash of the verified SPC candidate, once one arrived.
    /// First-wins: a second distinct candidate (an equivocating
    /// committee double-certifying) is ignored — the pool cert is what
    /// commits, so the equivocation merely splits prevotes.
    candidate: Option<BeaconBlockHash>,
    /// Whether the epoch's skip deadline (or any round timeout, which
    /// implies it) has passed — the precondition for prevoting skip.
    deadline_passed: bool,
    round: RatifyRound,
    /// Own prevote per round — the safety register. Never two hashes
    /// in one round, never rolled back.
    prevoted: BTreeMap<RatifyRound, BeaconBlockHash>,
    /// Own precommit per round. The highest entry is the lock.
    precommitted: BTreeMap<RatifyRound, BeaconBlockHash>,
    /// Verified votes, one slot per signer per `(round, phase)`,
    /// first-wins. The slot mirrors the honest one-vote register and
    /// bounds state by pool size: an equivocating signer's second vote
    /// is dropped, so equivocation spends the only slot it has.
    votes: BTreeMap<(RatifyRound, RatifyPhase), BTreeMap<ValidatorId, Verified<RatifyVote>>>,
    /// Set once a cert assembles; the tracker is inert afterwards.
    completed: bool,
}

impl RatifyTracker {
    /// Tracker for the epoch following `anchor`, over the active pool
    /// derived from the anchor's state.
    #[must_use]
    pub fn new(
        anchor: BeaconBlockHash,
        epoch: Epoch,
        pool: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    ) -> Self {
        Self {
            anchor,
            epoch,
            pool,
            skip_hash: BeaconBlock::skip(epoch, anchor).block_hash(),
            candidate: None,
            deadline_passed: false,
            round: RatifyRound::INITIAL,
            prevoted: BTreeMap::new(),
            precommitted: BTreeMap::new(),
            votes: BTreeMap::new(),
            completed: false,
        }
    }

    /// The canonical skip-block hash for this `(anchor, epoch)`.
    #[must_use]
    pub const fn skip_block_hash(&self) -> BeaconBlockHash {
        self.skip_hash
    }

    /// Current round.
    #[must_use]
    pub const fn round(&self) -> RatifyRound {
        self.round
    }

    /// Hash of the verified candidate, if one arrived.
    #[must_use]
    pub const fn candidate(&self) -> Option<BeaconBlockHash> {
        self.candidate
    }

    /// Whether a commit certificate has assembled.
    #[must_use]
    pub const fn is_completed(&self) -> bool {
        self.completed
    }

    /// Whether the epoch's skip deadline (or a round timeout) has
    /// passed — the coordinator's timer distinguishes its first fire
    /// (the deadline) from re-fires (round timeouts) by this.
    #[must_use]
    pub const fn deadline_passed(&self) -> bool {
        self.deadline_passed
    }

    /// Whether `validator` sits in the epoch's active pool.
    #[must_use]
    pub fn pool_contains(&self, validator: ValidatorId) -> bool {
        self.pool.iter().any(|(id, _)| *id == validator)
    }

    /// A verified SPC candidate for the epoch arrived; its hash
    /// becomes prevotable.
    pub fn on_candidate(&mut self, block_hash: BeaconBlockHash) -> Vec<RatifyEffect> {
        if self.completed {
            return vec![];
        }
        if self.candidate.is_none() {
            self.candidate = Some(block_hash);
        }
        self.try_own_prevote().into_iter().collect()
    }

    /// The epoch's skip deadline passed without a commit; the skip
    /// hash becomes prevotable.
    pub fn on_deadline(&mut self) -> Vec<RatifyEffect> {
        if self.completed {
            return vec![];
        }
        self.deadline_passed = true;
        self.try_own_prevote().into_iter().collect()
    }

    /// The current round timed out without a commit: enter the next
    /// round and re-prevote per the lock rule.
    pub fn on_round_timeout(&mut self) -> Vec<RatifyEffect> {
        if self.completed {
            return vec![];
        }
        // A round timeout only fires past the epoch's deadline.
        self.deadline_passed = true;
        self.round = self.round.next();
        self.try_own_prevote().into_iter().collect()
    }

    /// Pool a verified vote and fire whatever it completes: a polka →
    /// own precommit (fast-forwarding the round if the polka is
    /// newer), a precommit quorum → the commit certificate.
    ///
    /// Votes for a different anchor or epoch, or from rounds further
    /// than [`MAX_ROUND_AHEAD`] past the current one, are dropped.
    /// Rounds behind the current one are still pooled: a stale polka
    /// feeds the lock rule, and a stale precommit quorum is still a
    /// commit.
    pub fn observe(&mut self, vote: Verified<RatifyVote>) -> Vec<RatifyEffect> {
        if self.completed
            || vote.anchor_hash() != self.anchor
            || vote.epoch() != self.epoch
            || vote.round().inner() > self.round.inner() + MAX_ROUND_AHEAD
        {
            return vec![];
        }
        let round = vote.round();
        let phase = vote.phase();
        let block_hash = vote.block_hash();
        let slot = self
            .votes
            .entry((round, phase))
            .or_default()
            .entry(vote.signer());
        let std::collections::btree_map::Entry::Vacant(slot) = slot else {
            return vec![];
        };
        slot.insert(vote);

        match phase {
            RatifyPhase::Prevote => self.on_possible_polka(round, block_hash),
            RatifyPhase::Precommit => self.try_assemble(round, block_hash).into_iter().collect(),
        }
    }

    /// React to a prevote landing: if it completed a polka at a round
    /// no older than the current one, precommit (locking the value)
    /// and fast-forward to that round.
    fn on_possible_polka(
        &mut self,
        round: RatifyRound,
        block_hash: BeaconBlockHash,
    ) -> Vec<RatifyEffect> {
        if !self.has_polka(round, block_hash)
            || round < self.round
            || self.precommitted.contains_key(&round)
        {
            return vec![];
        }
        let advanced = round > self.round;
        self.round = round;
        self.precommitted.insert(round, block_hash);
        let mut out = vec![RatifyEffect::SignPrecommit { round, block_hash }];
        if advanced {
            out.extend(self.try_own_prevote());
        }
        out
    }

    /// Cast the round's own prevote if the register is free and a
    /// value is available: the lock if one is held (leaving it only
    /// for the other value's strictly newer polka), else the candidate
    /// when held, else the skip hash once the deadline passed.
    fn try_own_prevote(&mut self) -> Option<RatifyEffect> {
        if self.prevoted.contains_key(&self.round) {
            return None;
        }
        let choice = match self.precommitted.iter().next_back() {
            Some((&lock_round, &locked)) => {
                let other = if locked == self.skip_hash {
                    self.candidate
                } else {
                    Some(self.skip_hash)
                };
                match other {
                    Some(w) if self.newer_polka_exists(w, lock_round) => Some(w),
                    _ => Some(locked),
                }
            }
            None => self
                .candidate
                .or_else(|| self.deadline_passed.then_some(self.skip_hash)),
        };
        let block_hash = choice?;
        self.prevoted.insert(self.round, block_hash);
        Some(RatifyEffect::SignPrevote {
            round: self.round,
            block_hash,
        })
    }

    /// Whether `block_hash` has a polka at some round strictly between
    /// `lock_round` and the current round — the only evidence that
    /// justifies prevoting away from a lock.
    fn newer_polka_exists(&self, block_hash: BeaconBlockHash, lock_round: RatifyRound) -> bool {
        self.votes
            .keys()
            .filter(|&&(r, phase)| {
                phase == RatifyPhase::Prevote && r > lock_round && r < self.round
            })
            .any(|&(r, _)| self.has_polka(r, block_hash))
    }

    fn has_polka(&self, round: RatifyRound, block_hash: BeaconBlockHash) -> bool {
        self.vote_count_for(round, RatifyPhase::Prevote, block_hash)
            >= ratify_quorum(self.pool.len())
    }

    /// Assemble the commit certificate if `block_hash` reached a
    /// precommit quorum at `round`.
    fn try_assemble(
        &mut self,
        round: RatifyRound,
        block_hash: BeaconBlockHash,
    ) -> Option<RatifyEffect> {
        if self.vote_count_for(round, RatifyPhase::Precommit, block_hash)
            < ratify_quorum(self.pool.len())
        {
            return None;
        }
        let bucket = self.votes.get(&(round, RatifyPhase::Precommit))?;
        let refs: Vec<&Verified<RatifyVote>> = bucket
            .values()
            .filter(|v| v.block_hash() == block_hash)
            .collect();
        let cert = Verified::<RatifyCert>::from_verified_votes(&refs, &self.pool)?;
        self.completed = true;
        Some(RatifyEffect::CertAssembled {
            cert: Box::new(cert),
        })
    }

    fn vote_count_for(
        &self,
        round: RatifyRound,
        phase: RatifyPhase,
        block_hash: BeaconBlockHash,
    ) -> usize {
        self.votes.get(&(round, phase)).map_or(0, |bucket| {
            bucket
                .values()
                .filter(|v| v.block_hash() == block_hash)
                .count()
        })
    }
}

// Flat accessors; names are the documentation.
#[allow(missing_docs)]
impl RatifyTracker {
    #[must_use]
    pub fn vote_count(&self, round: RatifyRound, phase: RatifyPhase) -> usize {
        self.votes.get(&(round, phase)).map_or(0, BTreeMap::len)
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        Bls12381G1PrivateKey, Hash, NetworkDefinition, bls_keypair_from_seed, verify_ratify_cert,
    };

    use super::*;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn signing_key(seed: u64) -> Bls12381G1PrivateKey {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s)
    }

    fn pool(
        n: u64,
    ) -> (
        Vec<(ValidatorId, Bls12381G1PublicKey)>,
        Vec<Bls12381G1PrivateKey>,
    ) {
        let mut active = Vec::new();
        let mut keys = Vec::new();
        for i in 0..n {
            let sk = signing_key(i);
            active.push((ValidatorId::new(i), sk.public_key()));
            keys.push(sk);
        }
        (active, keys)
    }

    fn anchor() -> BeaconBlockHash {
        BeaconBlockHash::from_raw(Hash::from_bytes(b"ratify-anchor"))
    }

    fn epoch() -> Epoch {
        Epoch::new(7)
    }

    fn candidate_hash() -> BeaconBlockHash {
        BeaconBlockHash::from_raw(Hash::from_bytes(b"candidate"))
    }

    fn tracker(n: u64) -> (RatifyTracker, Vec<Bls12381G1PrivateKey>) {
        let (active, keys) = pool(n);
        (RatifyTracker::new(anchor(), epoch(), active), keys)
    }

    fn vote(
        keys: &[Bls12381G1PrivateKey],
        signer: u64,
        round: u32,
        phase: RatifyPhase,
        block_hash: BeaconBlockHash,
    ) -> Verified<RatifyVote> {
        Verified::<RatifyVote>::sign_local(
            &keys[usize::try_from(signer).unwrap()],
            ValidatorId::new(signer),
            &net(),
            anchor(),
            epoch(),
            RatifyRound::new(round),
            phase,
            block_hash,
        )
    }

    fn sign_prevote_round(effects: &[RatifyEffect]) -> Option<(u32, BeaconBlockHash)> {
        effects.iter().find_map(|e| match e {
            RatifyEffect::SignPrevote { round, block_hash } => Some((round.inner(), *block_hash)),
            _ => None,
        })
    }

    fn sign_precommit_round(effects: &[RatifyEffect]) -> Option<(u32, BeaconBlockHash)> {
        effects.iter().find_map(|e| match e {
            RatifyEffect::SignPrecommit { round, block_hash } => Some((round.inner(), *block_hash)),
            _ => None,
        })
    }

    #[test]
    fn skip_hash_is_the_canonical_skip_block() {
        let (t, _) = tracker(4);
        assert_eq!(
            t.skip_block_hash(),
            BeaconBlock::skip(epoch(), anchor()).block_hash(),
        );
    }

    /// The deadline without a candidate prevotes skip; the candidate
    /// arriving afterwards cannot re-vote the round — but the next
    /// round, unlocked, converges to it.
    #[test]
    fn deadline_prevotes_skip_then_register_holds_until_next_round() {
        let (mut t, _) = tracker(7);
        let effects = t.on_deadline();
        assert_eq!(sign_prevote_round(&effects), Some((1, t.skip_block_hash())),);

        let effects = t.on_candidate(candidate_hash());
        assert!(effects.is_empty(), "round 1 prevote register is spent");

        let effects = t.on_round_timeout();
        assert_eq!(sign_prevote_round(&effects), Some((2, candidate_hash())));
    }

    /// The candidate before the deadline prevotes the candidate; the
    /// deadline afterwards cannot flip the round's vote to skip.
    #[test]
    fn candidate_prevotes_candidate_then_deadline_is_inert() {
        let (mut t, _) = tracker(7);
        let effects = t.on_candidate(candidate_hash());
        assert_eq!(sign_prevote_round(&effects), Some((1, candidate_hash())));

        let effects = t.on_deadline();
        assert!(effects.is_empty(), "round 1 prevote register is spent");
    }

    /// A second distinct candidate is ignored — first-wins.
    #[test]
    fn second_candidate_is_ignored() {
        let (mut t, _) = tracker(7);
        let _ = t.on_candidate(candidate_hash());
        let other = BeaconBlockHash::from_raw(Hash::from_bytes(b"equivocation"));
        let _ = t.on_candidate(other);
        assert_eq!(t.candidate(), Some(candidate_hash()));
    }

    /// A polka triggers exactly one precommit: the round's precommit
    /// register blocks a repeat when further prevotes extend the
    /// quorum.
    #[test]
    fn polka_triggers_a_single_precommit() {
        // Pool 7, quorum 5.
        let (mut t, keys) = tracker(7);
        for i in 0..4 {
            let effects = t.observe(vote(&keys, i, 1, RatifyPhase::Prevote, candidate_hash()));
            assert!(effects.is_empty(), "sub-quorum prevotes precommit nothing");
        }
        let effects = t.observe(vote(&keys, 4, 1, RatifyPhase::Prevote, candidate_hash()));
        assert_eq!(sign_precommit_round(&effects), Some((1, candidate_hash())),);

        let effects = t.observe(vote(&keys, 5, 1, RatifyPhase::Prevote, candidate_hash()));
        assert!(effects.is_empty(), "precommit register blocks a repeat");
    }

    /// One slot per signer per `(round, phase)`: an equivocating
    /// second vote is dropped and cannot complete a polka.
    #[test]
    fn equivocating_signer_spends_its_slot() {
        let (mut t, keys) = tracker(7);
        for i in 0..4 {
            let _ = t.observe(vote(&keys, i, 1, RatifyPhase::Prevote, candidate_hash()));
        }
        // Signer 0 votes again — for skip this time. Dropped: the slot
        // is spent, and neither hash reaches a polka.
        let effects = t.observe(vote(&keys, 0, 1, RatifyPhase::Prevote, t.skip_block_hash()));
        assert!(effects.is_empty());
        assert_eq!(t.vote_count(RatifyRound::new(1), RatifyPhase::Prevote), 4);
    }

    /// Votes for a foreign anchor, foreign epoch, or a round past the
    /// admission horizon never enter the pool.
    #[test]
    fn foreign_and_far_future_votes_are_dropped() {
        let (mut t, keys) = tracker(7);
        let foreign_anchor = Verified::<RatifyVote>::sign_local(
            &keys[0],
            ValidatorId::new(0),
            &net(),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"other-anchor")),
            epoch(),
            RatifyRound::INITIAL,
            RatifyPhase::Prevote,
            candidate_hash(),
        );
        let foreign_epoch = Verified::<RatifyVote>::sign_local(
            &keys[0],
            ValidatorId::new(0),
            &net(),
            anchor(),
            epoch().next(),
            RatifyRound::INITIAL,
            RatifyPhase::Prevote,
            candidate_hash(),
        );
        let far_future = vote(
            &keys,
            0,
            1 + MAX_ROUND_AHEAD + 1,
            RatifyPhase::Prevote,
            candidate_hash(),
        );
        assert!(t.observe(foreign_anchor).is_empty());
        assert!(t.observe(foreign_epoch).is_empty());
        assert!(t.observe(far_future).is_empty());
        assert_eq!(t.vote_count(RatifyRound::new(1), RatifyPhase::Prevote), 0);
    }

    /// A precommit quorum assembles the commit certificate, and the
    /// cert passes the pure verifier against the pool.
    #[test]
    fn precommit_quorum_assembles_verifying_cert() {
        let (mut t, keys) = tracker(7);
        let (active, _) = pool(7);
        let mut cert = None;
        for i in 0..5 {
            let effects = t.observe(vote(&keys, i, 1, RatifyPhase::Precommit, candidate_hash()));
            for e in effects {
                if let RatifyEffect::CertAssembled { cert: c } = e {
                    cert = Some(c);
                }
            }
        }
        let cert = cert.expect("quorum of precommits assembles");
        assert_eq!(cert.block_hash(), candidate_hash());
        assert_eq!(cert.signer_count(), 5);
        assert!(verify_ratify_cert(&cert, &net(), &active).is_ok());
        assert!(t.is_completed());
    }

    /// A completed tracker is inert: further votes and timer edges
    /// produce nothing.
    #[test]
    fn completed_tracker_is_inert() {
        let (mut t, keys) = tracker(7);
        for i in 0..6 {
            let _ = t.observe(vote(&keys, i, 1, RatifyPhase::Precommit, candidate_hash()));
        }
        assert!(t.is_completed());
        assert!(
            t.observe(vote(&keys, 6, 1, RatifyPhase::Precommit, candidate_hash()))
                .is_empty()
        );
        assert!(t.on_round_timeout().is_empty());
        assert!(t.on_deadline().is_empty());
        assert!(t.on_candidate(candidate_hash()).is_empty());
    }

    /// A precommit quorum completing at a round the tracker has moved
    /// past still commits — certificate validity doesn't age.
    #[test]
    fn stale_round_precommit_quorum_still_commits() {
        let (mut t, keys) = tracker(7);
        let _ = t.on_round_timeout();
        let _ = t.on_round_timeout();
        assert_eq!(t.round(), RatifyRound::new(3));

        let mut committed = false;
        for i in 0..6 {
            let effects = t.observe(vote(
                &keys,
                i,
                1,
                RatifyPhase::Precommit,
                t.skip_block_hash(),
            ));
            committed |= effects
                .iter()
                .any(|e| matches!(e, RatifyEffect::CertAssembled { .. }));
        }
        assert!(committed);
    }

    /// A polka at a newer round fast-forwards: precommit there, then
    /// prevote the (now locked) value in the new round.
    #[test]
    fn future_polka_fast_forwards_the_round() {
        let (mut t, keys) = tracker(7);
        let mut effects = vec![];
        for i in 0..5 {
            effects.extend(t.observe(vote(&keys, i, 3, RatifyPhase::Prevote, candidate_hash())));
        }
        assert_eq!(t.round(), RatifyRound::new(3));
        assert_eq!(sign_precommit_round(&effects), Some((3, candidate_hash())),);
        assert_eq!(sign_prevote_round(&effects), Some((3, candidate_hash())));
    }

    /// A lock re-prevotes across rounds: once precommitted, the
    /// deadline having passed does not flip the vote to skip.
    #[test]
    fn lock_holds_across_rounds() {
        let (mut t, keys) = tracker(7);
        let _ = t.on_candidate(candidate_hash());
        for i in 1..=4 {
            // Four peers + the own round-1 prevote below reach the
            // quorum of 5; the own prevote is not pooled until its
            // loopback arrives, so pool it explicitly as signer 0's.
            let _ = t.observe(vote(&keys, i, 1, RatifyPhase::Prevote, candidate_hash()));
        }
        let effects = t.observe(vote(&keys, 0, 1, RatifyPhase::Prevote, candidate_hash()));
        assert_eq!(
            sign_precommit_round(&effects),
            Some((1, candidate_hash())),
            "polka completes with the loopback vote",
        );

        let effects = t.on_round_timeout();
        assert_eq!(
            sign_prevote_round(&effects),
            Some((2, candidate_hash())),
            "locked value re-prevotes despite the deadline having passed",
        );
    }

    /// Leaving a lock requires a strictly newer polka: prevotes for
    /// the other value at a round between the lock and the current
    /// round justify following the pool; the same polka arriving at a
    /// round the tracker already left triggers no precommit.
    #[test]
    fn lock_leaves_only_for_a_strictly_newer_polka() {
        let (mut t, keys) = tracker(7);
        // Round 1: candidate polka → precommit → locked (candidate, 1).
        let _ = t.on_candidate(candidate_hash());
        let _ = t.observe(vote(&keys, 0, 1, RatifyPhase::Prevote, candidate_hash()));
        for i in 1..=5 {
            let _ = t.observe(vote(&keys, i, 1, RatifyPhase::Prevote, candidate_hash()));
        }
        assert_eq!(t.round(), RatifyRound::new(1));

        // Rounds 2 and 3: the lock re-prevotes the candidate.
        let effects = t.on_round_timeout();
        assert_eq!(sign_prevote_round(&effects), Some((2, candidate_hash())));
        let effects = t.on_round_timeout();
        assert_eq!(sign_prevote_round(&effects), Some((3, candidate_hash())));

        // A skip polka at round 2 lands late — the tracker is at
        // round 3, so no precommit fires for it (rounds only move
        // forward)...
        let skip = t.skip_block_hash();
        for i in 1..=6 {
            let effects = t.observe(vote(&keys, i, 2, RatifyPhase::Prevote, skip));
            assert!(
                effects.is_empty(),
                "no precommit at a round the tracker already left",
            );
        }

        // ...but it is a strictly newer polka than the round-1 lock,
        // so round 4's prevote follows the pool to skip.
        let effects = t.on_round_timeout();
        assert_eq!(sign_prevote_round(&effects), Some((4, skip)));
    }

    /// A polka re-locks: a precommit at a newer round supersedes the
    /// old lock, and later rounds re-prevote the new value.
    #[test]
    fn newer_polka_relocks_via_precommit() {
        let (mut t, keys) = tracker(7);
        // Locked (candidate, 1).
        let _ = t.on_candidate(candidate_hash());
        let _ = t.observe(vote(&keys, 0, 1, RatifyPhase::Prevote, candidate_hash()));
        for i in 1..=5 {
            let _ = t.observe(vote(&keys, i, 1, RatifyPhase::Prevote, candidate_hash()));
        }

        // Round 2: the rest of the pool prevotes skip; the polka
        // (6 of 7 without us) precommits and re-locks (skip, 2).
        let _ = t.on_round_timeout();
        let skip = t.skip_block_hash();
        let mut effects = vec![];
        for i in 1..=6 {
            effects.extend(t.observe(vote(&keys, i, 2, RatifyPhase::Prevote, skip)));
        }
        assert_eq!(sign_precommit_round(&effects), Some((2, skip)));

        // Round 3: the new lock re-prevotes skip.
        let effects = t.on_round_timeout();
        assert_eq!(sign_prevote_round(&effects), Some((3, skip)));
    }
}
