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
//! No topology, no crypto, no clocks — pure data structure; the
//! coordinator feeds verified votes and timer edges in, and lifts the
//! typed [`RatifyEffect`]s into actions. Tests need validator keypairs
//! and an anchor, nothing more.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_types::{
    BeaconBlock, BeaconBlockHash, ConsensusPublicKey, Epoch, RatifyCert, RatifyPhase, RatifyRound,
    RatifyVote, RatifyVoteRecord, ValidatorId, Verified, Verifier, ratify_quorum,
};
use tracing::warn;

/// Rounds ahead of the current one a vote may reference and still be
/// pooled. Peers legitimately run ahead by however far their timers
/// have fired; anything further is either garbage or will be re-sent
/// once this replica catches up.
const MAX_ROUND_AHEAD: u32 = 4;

/// Round from which an unlocked member stops preferring its candidate
/// and follows the pool's prevote tally. Two full rounds of a held
/// candidate failing to polka past the deadline means the pool isn't
/// converging on it — joining the leading value breaks the value split.
const CANDIDATE_PATIENCE_ROUNDS: u32 = 3;

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
    verifier: Arc<dyn Verifier>,
    anchor: BeaconBlockHash,
    epoch: Epoch,
    /// Active pool for the epoch, in the positional order every cert
    /// bitfield indexes. Fixed at construction — the pool derives from
    /// the anchor's state, common to every candidate outcome.
    pool: Vec<(ValidatorId, ConsensusPublicKey)>,
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
    /// Votes dropped for anchor/epoch/round mismatch while the epoch is
    /// still undecided — the observe-drop `warn!`'s log2 rate bound (the
    /// tracker carries no clock to bound by time).
    mismatched_drops: u64,
}

impl RatifyTracker {
    /// Tracker for the epoch following `anchor`, over the active pool
    /// derived from the anchor's state.
    #[must_use]
    pub fn new(
        verifier: Arc<dyn Verifier>,
        anchor: BeaconBlockHash,
        epoch: Epoch,
        pool: Vec<(ValidatorId, ConsensusPublicKey)>,
    ) -> Self {
        Self {
            verifier,
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
            mismatched_drops: 0,
        }
    }

    /// Install the validator's own-vote registers from the durable
    /// record a restart recovered. No-op unless the record covers this
    /// tracker's epoch.
    ///
    /// Recorded slots become spent (never re-signed), the highest
    /// recovered precommit resumes as the lock, and the current round
    /// fast-forwards to the highest recorded one so no already-left
    /// round is re-entered. `deadline_passed` stays false — the local
    /// timer re-derives it, so skip prevoting waits for a fresh fire
    /// rather than trusting pre-crash timer state.
    pub fn install_recovered_record(&mut self, record: &RatifyVoteRecord) {
        if record.epoch != self.epoch || self.completed {
            return;
        }
        if let Some(&max_round) = record
            .prevoted
            .keys()
            .chain(record.precommitted.keys())
            .max()
        {
            self.round = self.round.max(max_round);
        }
        for (&round, &block_hash) in &record.prevoted {
            self.prevoted.entry(round).or_insert(block_hash);
        }
        for (&round, &block_hash) in &record.precommitted {
            self.precommitted.entry(round).or_insert(block_hash);
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

    /// Values other than the held candidate and the skip hash that more
    /// than the pool's fault bound prevoted in one round, each with the
    /// members that prevoted it there. More than `f` prevotes include an
    /// honest member's, and an honest member prevotes only a candidate
    /// it verified: the value is a real certified candidate this member
    /// lacks, and every honest one of those members holds it. The
    /// threshold also keeps up to `f` Byzantine prevoters from naming
    /// hashes for this member to chase.
    #[must_use]
    pub fn unheld_prevoted_candidates(&self) -> BTreeMap<BeaconBlockHash, BTreeSet<ValidatorId>> {
        let faults = self.pool.len() - ratify_quorum(self.pool.len());
        let mut unheld: BTreeMap<BeaconBlockHash, BTreeSet<ValidatorId>> = BTreeMap::new();
        for ((_, phase), bucket) in &self.votes {
            if *phase != RatifyPhase::Prevote {
                continue;
            }
            let mut by_value: BTreeMap<BeaconBlockHash, BTreeSet<ValidatorId>> = BTreeMap::new();
            for (signer, vote) in bucket {
                by_value
                    .entry(vote.block_hash())
                    .or_default()
                    .insert(*signer);
            }
            for (value, voters) in by_value {
                if value == self.skip_hash
                    || Some(value) == self.candidate
                    || voters.len() <= faults
                {
                    continue;
                }
                unheld.entry(value).or_default().extend(voters);
            }
        }
        unheld
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

    /// A round timer fired without a commit: enter `target_round` if
    /// this member is not already there or past it, and re-prevote per
    /// the lock rule.
    ///
    /// `target_round` is the caller's wall-clock round: elapsed time
    /// past the epoch's skip deadline divided by the round timeout.
    /// Progression is that round alone, never a count of local fires,
    /// which keeps every pool member in the same round despite per-host
    /// timer jitter — a polka needs a 2f+1 quorum at one round, and
    /// members whose counters drift apart starve it: a polka completing
    /// behind a member's current round is not precommittable (the vote
    /// register is position-monotone), so skew that outruns the round
    /// window loses the quorum entirely. A fire that lands before its
    /// round boundary on the local clock therefore enters no round; the
    /// re-armed fire at the boundary does.
    pub fn on_round_timeout(&mut self, target_round: RatifyRound) -> Vec<RatifyEffect> {
        if self.completed {
            return vec![];
        }
        // A round timeout only fires past the epoch's deadline.
        self.deadline_passed = true;
        self.round = self.round.max(target_round);
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
        if self.completed {
            // Votes landing after the cert assembled are healthy stragglers.
            return vec![];
        }
        if vote.anchor_hash() != self.anchor
            || vote.epoch() != self.epoch
            || vote.round().inner() > self.round.inner() + MAX_ROUND_AHEAD
        {
            // A pool member's weight silently not counting is
            // liveness-critical while the epoch is undecided — a tip split
            // or a runaway round leaves the quorum short with no symptom.
            // Log2-bounded: the tracker has no clock, so the bound is a
            // power-of-two drop count.
            self.mismatched_drops += 1;
            if self.mismatched_drops.is_power_of_two() {
                warn!(
                    signer = vote.signer().inner(),
                    vote_anchor = ?vote.anchor_hash(),
                    tracker_anchor = ?self.anchor,
                    vote_epoch = vote.epoch().inner(),
                    tracker_epoch = self.epoch.inner(),
                    vote_round = vote.round().inner(),
                    tracker_round = self.round.inner(),
                    drops = self.mismatched_drops,
                    "dropping a ratify vote the tracker cannot pool — anchor, \
                     epoch, or round out of range while the epoch is undecided"
                );
            }
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
    /// for the other value's strictly newer polka), else the value of
    /// the newest polka it has evidence of, else the candidate when
    /// held, else the skip hash once the deadline passed.
    ///
    /// An unlocked member's candidate preference is bounded: from
    /// [`CANDIDATE_PATIENCE_ROUNDS`] on, it follows the pool instead,
    /// prevoting whichever of its prevotable values drew more prevotes
    /// in the newest earlier round it observed, the skip hash on a tie.
    /// Without that a pool can split on values forever: members locked
    /// on one value prevote it every round and leave it only for a
    /// newer polka of the other, so unlocked members that hold out for
    /// the other value — a candidate the locked members refuse, or a
    /// skip the candidate lockers refuse — starve both quorums. Locked
    /// members prevote their lock round after round, so following the
    /// tally joins them. On the healthy path the candidate polkas
    /// rounds before the patience runs out, so the rule only ever
    /// decides an already-stalled epoch.
    ///
    /// Polka evidence outranks both preferences: an unlocked member
    /// that has it prevotes the polka's value, the value the members
    /// that precommitted it are locked on. Evidence is a prevote quorum
    /// or more than `f` precommits; a lock held by `f` or fewer members
    /// leaves none, and there the tally is what carries the pool to it.
    /// Locked members prevote their lock every round, so a tally read
    /// by a member that missed their precommits still leans their way.
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
            None => self.newest_polka_value().or_else(|| {
                if self.deadline_passed && self.round.inner() >= CANDIDATE_PATIENCE_ROUNDS {
                    Some(self.leading_value())
                } else {
                    self.candidate
                        .or_else(|| self.deadline_passed.then_some(self.skip_hash))
                }
            }),
        };
        let block_hash = choice?;
        self.prevoted.insert(self.round, block_hash);
        Some(RatifyEffect::SignPrevote {
            round: self.round,
            block_hash,
        })
    }

    /// Whether `block_hash` has evidence of a polka at some round
    /// strictly between `lock_round` and the current round — the only
    /// thing that justifies prevoting away from a lock.
    fn newer_polka_exists(&self, block_hash: BeaconBlockHash, lock_round: RatifyRound) -> bool {
        self.votes
            .keys()
            .filter(|&&(r, _)| r > lock_round && r < self.round)
            .any(|&(r, _)| self.polka_evidenced(r, block_hash))
    }

    /// The prevotable value — the held candidate or the skip hash —
    /// with evidence of a polka at the newest round that has any.
    fn newest_polka_value(&self) -> Option<BeaconBlockHash> {
        let values: Vec<BeaconBlockHash> = self
            .candidate
            .into_iter()
            .chain(std::iter::once(self.skip_hash))
            .collect();
        self.votes.keys().rev().find_map(|&(round, _)| {
            values
                .iter()
                .copied()
                .find(|&value| self.polka_evidenced(round, value))
        })
    }

    /// Whether `block_hash` had a polka at `round`: a prevote quorum
    /// observed directly, or more precommits than the pool's fault
    /// bound. An honest member precommits only on a polka it saw, and
    /// more than `f` precommits include an honest one, so the polka
    /// existed even when this member missed the prevotes that formed
    /// it — and the members that precommitted it are locked on it.
    fn polka_evidenced(&self, round: RatifyRound, block_hash: BeaconBlockHash) -> bool {
        let faults = self.pool.len() - ratify_quorum(self.pool.len());
        self.has_polka(round, block_hash)
            || self.vote_count_for(round, RatifyPhase::Precommit, block_hash) > faults
    }

    /// The prevotable value that drew more prevotes in the newest round
    /// before the current one with any: the held candidate when it
    /// strictly leads the skip hash, the skip hash otherwise.
    fn leading_value(&self) -> BeaconBlockHash {
        let led_by_candidate = self.candidate.is_some_and(|candidate| {
            self.votes
                .keys()
                .rev()
                .find(|&&(round, phase)| phase == RatifyPhase::Prevote && round < self.round)
                .is_some_and(|&(round, _)| {
                    self.vote_count_for(round, RatifyPhase::Prevote, candidate)
                        > self.vote_count_for(round, RatifyPhase::Prevote, self.skip_hash)
                })
        });
        match self.candidate {
            Some(candidate) if led_by_candidate => candidate,
            _ => self.skip_hash,
        }
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
        let cert =
            Verified::<RatifyCert>::from_verified_votes(self.verifier.as_ref(), &refs, &self.pool)?;
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

    /// Per-value vote tallies at `(round, phase)` — the park watchdog's
    /// view of how far the pool is from a polka or a commit certificate.
    #[must_use]
    pub fn tallies(
        &self,
        round: RatifyRound,
        phase: RatifyPhase,
    ) -> BTreeMap<BeaconBlockHash, usize> {
        let mut tallies = BTreeMap::new();
        if let Some(votes) = self.votes.get(&(round, phase)) {
            for vote in votes.values() {
                *tallies.entry(vote.block_hash()).or_insert(0) += 1;
            }
        }
        tallies
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier, signer_from_u64_seed};
    use hyperscale_types::{Hash, NetworkDefinition, Signer, verify_ratify_cert};

    use super::*;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn pool(n: u64) -> (Vec<(ValidatorId, ConsensusPublicKey)>, Vec<BlsSigner>) {
        let mut active = Vec::new();
        let mut keys = Vec::new();
        for i in 0..n {
            let sk = signer_from_u64_seed(i);
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

    fn tracker(n: u64) -> (RatifyTracker, Vec<BlsSigner>) {
        let (active, keys) = pool(n);
        (
            RatifyTracker::new(Arc::new(BlsVerifier), anchor(), epoch(), active),
            keys,
        )
    }

    fn vote(
        keys: &[BlsSigner],
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
        .expect("sign")
    }

    /// A round fire one wall-clock round after the tracker's current one.
    fn next_round(t: &mut RatifyTracker) -> Vec<RatifyEffect> {
        let target = t.round().next();
        t.on_round_timeout(target)
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

        let effects = next_round(&mut t);
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
        )
        .expect("sign");
        let foreign_epoch = Verified::<RatifyVote>::sign_local(
            &keys[0],
            ValidatorId::new(0),
            &net(),
            anchor(),
            epoch().next(),
            RatifyRound::INITIAL,
            RatifyPhase::Prevote,
            candidate_hash(),
        )
        .expect("sign");
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
        assert!(verify_ratify_cert(&BlsVerifier, &cert, &net(), &active).is_ok());
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
        assert!(t.on_round_timeout(RatifyRound::INITIAL).is_empty());
        assert!(t.on_deadline().is_empty());
        assert!(t.on_candidate(candidate_hash()).is_empty());
    }

    /// A precommit quorum completing at a round the tracker has moved
    /// past still commits — certificate validity doesn't age.
    #[test]
    fn stale_round_precommit_quorum_still_commits() {
        let (mut t, keys) = tracker(7);
        let _ = next_round(&mut t);
        let _ = next_round(&mut t);
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

    /// An unlocked member that saw a candidate polka it could not
    /// precommit (the polka completed behind its round) keeps
    /// prevoting the candidate past the patience horizon: the members
    /// that precommitted it are locked there, and conceding to skip
    /// would split the pool with neither side at quorum.
    #[test]
    fn a_polka_outlasts_the_candidate_patience() {
        // Pool 7, quorum 5.
        let (mut t, keys) = tracker(7);
        let effects = t.on_candidate(candidate_hash());
        assert_eq!(sign_prevote_round(&effects), Some((1, candidate_hash())));
        let effects = next_round(&mut t);
        assert_eq!(sign_prevote_round(&effects), Some((2, candidate_hash())));

        for i in 1..=5 {
            let effects = t.observe(vote(&keys, i, 1, RatifyPhase::Prevote, candidate_hash()));
            assert!(
                sign_precommit_round(&effects).is_none(),
                "a polka behind the current round is not precommittable",
            );
        }

        for round in 3..=CANDIDATE_PATIENCE_ROUNDS + 2 {
            let effects = next_round(&mut t);
            assert_eq!(
                sign_prevote_round(&effects),
                Some((round, candidate_hash())),
                "round {round} concedes to skip past a candidate polka",
            );
        }
    }

    /// Past the patience horizon an unlocked member that never saw a
    /// polka follows the previous round's prevote tally: members locked
    /// on the candidate keep prevoting it, and joining them completes
    /// the polka that conceding to skip would starve.
    #[test]
    fn past_patience_an_unlocked_member_follows_the_leading_value() {
        // Pool 8, quorum 6: four locked on the candidate, two holding it
        // unlocked (this tracker is signer 0), two prevoting skip.
        let (mut t, keys) = tracker(8);
        let _ = t.on_candidate(candidate_hash());
        while t.round().inner() < CANDIDATE_PATIENCE_ROUNDS - 1 {
            let _ = next_round(&mut t);
        }
        let previous = t.round().inner();
        for i in 0..5 {
            let _ = t.observe(vote(
                &keys,
                i,
                previous,
                RatifyPhase::Prevote,
                candidate_hash(),
            ));
        }
        for i in 5..8 {
            let _ = t.observe(vote(
                &keys,
                i,
                previous,
                RatifyPhase::Prevote,
                t.skip_block_hash(),
            ));
        }
        let effects = next_round(&mut t);
        assert_eq!(
            sign_prevote_round(&effects),
            Some((previous + 1, candidate_hash())),
        );
    }

    /// The tally is read against skip: when skip drew as many prevotes
    /// as the candidate, the unlocked member joins skip.
    #[test]
    fn past_patience_a_tied_tally_prevotes_skip() {
        let (mut t, keys) = tracker(8);
        let _ = t.on_candidate(candidate_hash());
        while t.round().inner() < CANDIDATE_PATIENCE_ROUNDS - 1 {
            let _ = next_round(&mut t);
        }
        let previous = t.round().inner();
        for i in 0..4 {
            let _ = t.observe(vote(
                &keys,
                i,
                previous,
                RatifyPhase::Prevote,
                candidate_hash(),
            ));
        }
        for i in 4..8 {
            let _ = t.observe(vote(
                &keys,
                i,
                previous,
                RatifyPhase::Prevote,
                t.skip_block_hash(),
            ));
        }
        let effects = next_round(&mut t);
        assert_eq!(
            sign_prevote_round(&effects),
            Some((previous + 1, t.skip_block_hash())),
        );
    }

    /// The round is the wall clock's, not a count of fires: a fire
    /// whose target is the round already held — one landing before its
    /// boundary on a slow clock, then the re-armed fire at the boundary
    /// — enters the target once, so members whose timers fire early
    /// stay in the round their peers are in.
    #[test]
    fn round_timeout_enters_the_wall_clock_round_once() {
        let (mut t, _) = tracker(7);
        let _ = t.on_deadline();
        let effects = t.on_round_timeout(RatifyRound::INITIAL);
        assert_eq!(
            t.round(),
            RatifyRound::INITIAL,
            "an early fire enters no round"
        );
        assert!(effects.is_empty(), "the round-1 prevote register is spent");

        let effects = t.on_round_timeout(RatifyRound::new(2));
        assert_eq!(t.round(), RatifyRound::new(2));
        assert_eq!(sign_prevote_round(&effects), Some((2, t.skip_block_hash())));
        let effects = t.on_round_timeout(RatifyRound::new(2));
        assert_eq!(
            t.round(),
            RatifyRound::new(2),
            "a repeat fire does not ratchet"
        );
        assert!(effects.is_empty());
    }

    /// A member whose clock lags its peers' sees their polka for the
    /// round they entered first and fast-forwards into it; its own fire
    /// for that round, landing after, must not carry it a round past
    /// the pool.
    #[test]
    fn a_fast_forwarded_member_stays_in_the_pool_round() {
        // Pool 7, quorum 5.
        let (mut t, keys) = tracker(7);
        let _ = t.on_deadline();
        let skip = t.skip_block_hash();
        for i in 1..=5 {
            let _ = t.observe(vote(&keys, i, 2, RatifyPhase::Prevote, skip));
        }
        assert_eq!(t.round(), RatifyRound::new(2), "the polka fast-forwards");
        let _ = t.on_round_timeout(RatifyRound::new(2));
        assert_eq!(t.round(), RatifyRound::new(2));
    }

    /// Pool 8 (quorum 6, fault bound 2), this member holding the
    /// candidate unlocked, one round short of the patience horizon.
    /// The previous round's prevotes it saw lean to skip, but more
    /// members than that precommitted the candidate on a polka whose
    /// prevotes this member mostly missed.
    fn missed_polka_with_candidate_precommits(precommits: u64) -> RatifyTracker {
        let (mut t, keys) = tracker(8);
        let _ = t.on_candidate(candidate_hash());
        while t.round().inner() < CANDIDATE_PATIENCE_ROUNDS - 1 {
            let _ = next_round(&mut t);
        }
        let previous = t.round().inner();
        for i in 1..3 {
            let _ = t.observe(vote(
                &keys,
                i,
                previous,
                RatifyPhase::Prevote,
                candidate_hash(),
            ));
        }
        for i in 5..8 {
            let _ = t.observe(vote(
                &keys,
                i,
                previous,
                RatifyPhase::Prevote,
                t.skip_block_hash(),
            ));
        }
        for i in 1..=precommits {
            let _ = t.observe(vote(
                &keys,
                i,
                previous,
                RatifyPhase::Precommit,
                candidate_hash(),
            ));
        }
        t
    }

    /// More precommits than the fault bound prove a polka the member
    /// missed: it prevotes the value the precommitters are locked on,
    /// over both its patience and the prevote tally it saw.
    #[test]
    fn precommit_evidence_outranks_the_tally() {
        let mut t = missed_polka_with_candidate_precommits(3);
        let effects = next_round(&mut t);
        assert_eq!(
            sign_prevote_round(&effects),
            Some((CANDIDATE_PATIENCE_ROUNDS, candidate_hash())),
        );
    }

    /// Precommits within the fault bound prove nothing: the member
    /// follows the tally it saw.
    #[test]
    fn precommits_within_the_fault_bound_are_not_evidence() {
        let mut t = missed_polka_with_candidate_precommits(2);
        let effects = next_round(&mut t);
        assert_eq!(
            sign_prevote_round(&effects),
            Some((CANDIDATE_PATIENCE_ROUNDS, t.skip_block_hash())),
        );
    }

    /// Precommit evidence of a newer polka releases a lock the way the
    /// polka itself would.
    #[test]
    fn precommit_evidence_of_a_newer_polka_leaves_the_lock() {
        // Pool 7, quorum 5, fault bound 2. Locked (skip, 1).
        let (mut t, keys) = tracker(7);
        let _ = t.on_deadline();
        let skip = t.skip_block_hash();
        for i in 0..5 {
            let _ = t.observe(vote(&keys, i, 1, RatifyPhase::Prevote, skip));
        }
        let _ = t.on_candidate(candidate_hash());
        let _ = t.on_round_timeout(RatifyRound::new(3));
        for i in 1..4 {
            let _ = t.observe(vote(&keys, i, 2, RatifyPhase::Precommit, candidate_hash()));
        }
        let effects = t.on_round_timeout(RatifyRound::new(4));
        assert_eq!(sign_prevote_round(&effects), Some((4, candidate_hash())));
    }

    /// The tally covers what evidence cannot: pool 4 (quorum 3, fault
    /// bound 1) with one member isolated. Members 0, 1 and 2 prevoted
    /// the candidate; only member 1 saw all three and locked. Its one
    /// precommit is within the fault bound, so it proves nothing, and
    /// an unlocked member conceding to skip would leave skip at two
    /// and the candidate at one for as long as the isolation holds.
    /// Following the tally it saw — the candidate led — completes the
    /// candidate's polka instead.
    #[test]
    fn past_patience_the_tally_carries_a_lock_below_the_evidence_bound() {
        let (mut t, keys) = tracker(4);
        let _ = t.on_candidate(candidate_hash());
        while t.round().inner() < CANDIDATE_PATIENCE_ROUNDS - 1 {
            let _ = next_round(&mut t);
        }
        let previous = t.round().inner();
        for i in 0..2 {
            let _ = t.observe(vote(
                &keys,
                i,
                previous,
                RatifyPhase::Prevote,
                candidate_hash(),
            ));
        }
        let _ = t.observe(vote(
            &keys,
            1,
            previous,
            RatifyPhase::Precommit,
            candidate_hash(),
        ));
        let effects = next_round(&mut t);
        assert_eq!(
            sign_prevote_round(&effects),
            Some((CANDIDATE_PATIENCE_ROUNDS, candidate_hash())),
        );
    }

    /// Without any polka, an unlocked member concedes to skip once its
    /// candidate has had the patience horizon to converge.
    #[test]
    fn an_unconverged_candidate_concedes_to_skip() {
        let (mut t, _) = tracker(7);
        let _ = t.on_candidate(candidate_hash());
        let mut last = None;
        while t.round().inner() < CANDIDATE_PATIENCE_ROUNDS {
            last = sign_prevote_round(&next_round(&mut t));
        }
        assert_eq!(last, Some((CANDIDATE_PATIENCE_ROUNDS, t.skip_block_hash())));
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

        let effects = next_round(&mut t);
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
        let effects = next_round(&mut t);
        assert_eq!(sign_prevote_round(&effects), Some((2, candidate_hash())));
        let effects = next_round(&mut t);
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
        let effects = next_round(&mut t);
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
        let _ = next_round(&mut t);
        let skip = t.skip_block_hash();
        let mut effects = vec![];
        for i in 1..=6 {
            effects.extend(t.observe(vote(&keys, i, 2, RatifyPhase::Prevote, skip)));
        }
        assert_eq!(sign_precommit_round(&effects), Some((2, skip)));

        // Round 3: the new lock re-prevotes skip.
        let effects = next_round(&mut t);
        assert_eq!(sign_prevote_round(&effects), Some((3, skip)));
    }

    /// A recovered record spends its rounds: the tracker resumes at
    /// the highest recorded round with the register occupied, so
    /// neither the deadline nor the candidate can re-vote it — and the
    /// recovered lock re-prevotes at the next round.
    #[test]
    fn recovered_record_spends_rounds_and_resumes_the_lock() {
        let (mut t, _) = tracker(7);
        let skip = t.skip_block_hash();
        let mut record = RatifyVoteRecord::new(epoch());
        record.record(RatifyRound::new(1), RatifyPhase::Prevote, skip);
        record.record(RatifyRound::new(1), RatifyPhase::Precommit, skip);
        record.record(RatifyRound::new(2), RatifyPhase::Prevote, skip);
        t.install_recovered_record(&record);

        assert_eq!(
            t.round(),
            RatifyRound::new(2),
            "resumes at the highest recorded round"
        );
        let effects = t.on_deadline();
        assert!(
            effects.is_empty(),
            "recovered round-2 prevote register is spent"
        );
        let effects = t.on_candidate(candidate_hash());
        assert!(
            effects.is_empty(),
            "the candidate cannot re-vote a spent round either"
        );

        // The next round re-prevotes the recovered lock, not the
        // candidate: no newer polka justifies leaving it.
        let effects = next_round(&mut t);
        assert_eq!(sign_prevote_round(&effects), Some((3, skip)));
    }

    /// A record from another epoch's ratification is ignored outright:
    /// the registers are per-epoch state.
    #[test]
    fn recovered_record_for_another_epoch_is_ignored() {
        let (mut t, _) = tracker(7);
        let mut record = RatifyVoteRecord::new(epoch().next());
        record.record(RatifyRound::new(1), RatifyPhase::Prevote, candidate_hash());
        t.install_recovered_record(&record);

        let effects = t.on_candidate(candidate_hash());
        assert_eq!(
            sign_prevote_round(&effects),
            Some((RatifyRound::INITIAL.inner(), candidate_hash())),
            "fresh registers vote normally",
        );
    }
}
