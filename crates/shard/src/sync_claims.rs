//! Certificates peers cite for blocks this replica does not hold, held
//! while their signatures are checked.
//!
//! A header's `parent_qc`, an announced QC and a timeout's carried high QC
//! each name a certified height. Until the certificate verifies that height
//! is only a claim, and a block sync toward it parks the replica in sync
//! mode — empty proposals, no pending-block fetches — for as long as the
//! target stays above the frontier. Block sync has no exit for a target
//! the network cannot serve, so the claim must verify before the sync
//! starts.
//!
//! Each claim is keyed by its [`Carrier`], one in flight per carrier: the
//! map is bounded by twice the validator set, and one member's flood of
//! forged claims occupies only its own slots, so it cannot crowd out the
//! claims honest members carry. A carrier whose claim is refuted makes no
//! other until the view moves, [`CLAIM_RETRY_AFTER`] passes or the
//! schedule gains an epoch, whichever comes first, so a forger pays at
//! most one refuted claim per carrier per view or interval. An honest
//! certificate is refuted too while this replica's beacon lacks its
//! signer's window, and this replica's view does not move while it cannot
//! verify the network's certificates, so the latch has to lapse on the
//! clock and on the schedule as well as on the view. A slot whose results
//! never return is reclaimed after [`CLAIM_STALE_AFTER`].
//!
//! A refuted claim costs at most two pairings and one per window its walk
//! tries, which the coordinator bounds by `SYNC_CLAIM_WALK_DEPTH`; every
//! pairing is dispatched one at a time per carrier. So each carrier costs
//! this replica at most `2 + SYNC_CLAIM_WALK_DEPTH` pairings per interval,
//! and the carriers are bounded by twice the validator set.
//!
//! A timeout's or an announcement's signature does not cover the whole
//! certificate it carries, so a relay can swap a forgery into a
//! validator's message. That spends the validator's relayed slot for one
//! interval and no more: its own headers keep their slot.
//!
//! The local clock read here gates only this replica's own verification
//! work and its own sync start; nothing replicas must agree on reads it.

use std::collections::BTreeMap;
use std::time::Duration;

use hyperscale_core::SyncClaimId;
use hyperscale_types::{
    Epoch, Hash, LocalTimestamp, QuorumCertificate, Round, VIEW_CHANGE_TIMEOUT_DEFAULT,
    VIEW_CHANGE_TIMEOUT_MAX, ValidatorId, Verified,
};

/// How long a claim holds its carrier's slot without an answer. A claim
/// waits one crypto pool round trip per committee tried; one the longest
/// round timer has not seen answered lost its results.
const CLAIM_STALE_AFTER: Duration = VIEW_CHANGE_TIMEOUT_MAX;

/// How long a carrier whose claim was refuted waits before its next one is
/// checked in the same view: the base round timer, so a forger is held to
/// about one refuted claim per round.
const CLAIM_RETRY_AFTER: Duration = VIEW_CHANGE_TIMEOUT_DEFAULT;

/// Who carried a claim, and whether the certificate rode under their
/// signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Carrier {
    /// A header's proposer. The header hash covers its `parent_qc`, so the
    /// proposer signed the claim itself.
    Proposer(ValidatorId),
    /// The authenticated sender of an announcement or a timeout. Neither
    /// signature covers the whole certificate, so whoever relays the
    /// message can swap in another; held apart from the sender's own
    /// headers, so a relayed forgery spends only this slot.
    Relayer(ValidatorId),
}

/// The windows still to try for a claim, from `next` down to `floor`, once
/// every committee tried so far refutes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochWalk {
    pub next: Epoch,
    pub floor: Epoch,
}

impl EpochWalk {
    /// The walk from `top` down to `floor`, or `None` when that is empty.
    pub fn down(top: Epoch, floor: Epoch) -> Option<Self> {
        (top >= floor).then_some(Self { next: top, floor })
    }

    /// The window to try next, and the walk that remains after it.
    pub fn step(self) -> (Epoch, Option<Self>) {
        let rest = (self.next > self.floor).then(|| Self {
            next: self.next.saturating_sub(1),
            floor: self.floor,
        });
        (self.next, rest)
    }
}

/// A claim whose verifications are in flight.
struct InFlightClaim {
    id: SyncClaimId,
    qc: QuorumCertificate,
    /// Verifications still to answer.
    outstanding: usize,
    /// Whether one of them has already verified.
    verified: bool,
    /// The committees tried, as digests of what a verification reads, so a
    /// window that seats one of them again is not tried twice.
    tried: Vec<Hash>,
    walk: Option<EpochWalk>,
    /// When the last verification was dispatched, on the local clock.
    since: LocalTimestamp,
}

/// A carrier's last refuted claim.
#[derive(Clone, Copy)]
struct Refutation {
    view: Round,
    at: LocalTimestamp,
}

/// What a verification result means for its claim.
#[derive(Debug)]
pub enum ClaimOutcome {
    /// The first committee to verify the claim: sync toward it.
    Verified(Verified<QuorumCertificate>),
    /// Every committee tried refuted it and the walk has windows left: try
    /// the next through [`SyncClaims::walk_of`].
    Retry(SyncClaimId),
    /// Every committee refuted it.
    Refuted {
        carrier: Carrier,
        qc: QuorumCertificate,
    },
    /// Nothing to act on: other committees are still out, the claim was
    /// verified already, or it is no longer held.
    Pending,
}

#[derive(Default)]
pub struct SyncClaims {
    in_flight: BTreeMap<Carrier, InFlightClaim>,
    refuted: BTreeMap<Carrier, Refutation>,
    /// The newest epoch the schedule held when last observed.
    newest_epoch: Option<Epoch>,
    /// The last claim that verified. Peers keep citing one certificate for
    /// as long as it is the highest they hold — every timeout of a view
    /// change carries it — and a sync toward it starts without checking it
    /// again.
    last_verified: Option<Verified<QuorumCertificate>>,
    next_id: u64,
}

impl InFlightClaim {
    fn live(&self, now: LocalTimestamp) -> bool {
        now.saturating_sub(self.since) < CLAIM_STALE_AFTER
    }
}

impl Refutation {
    fn holds(self, view: Round, now: LocalTimestamp) -> bool {
        self.view == view && now.saturating_sub(self.at) < CLAIM_RETRY_AFTER
    }
}

impl SyncClaims {
    /// Note the newest epoch the schedule holds. A new one can seat the
    /// committee an honest refuted claim needed, so every refutation lapses.
    pub fn observe_schedule(&mut self, newest: Option<Epoch>) {
        if newest > self.newest_epoch {
            self.refuted.clear();
            self.newest_epoch = newest;
        }
    }

    /// Whether `qc` is the last claim that verified.
    pub fn is_verified(&self, qc: &QuorumCertificate) -> bool {
        self.last_verified
            .as_ref()
            .is_some_and(|verified| verified.as_ref() == qc)
    }

    /// Whether a claim of `qc` from `carrier` should be checked in `view`:
    /// no refutation of the carrier's holds, the carrier has no claim live
    /// in flight, and no live claim in flight holds this certificate.
    pub fn admits(
        &self,
        carrier: Carrier,
        qc: &QuorumCertificate,
        view: Round,
        now: LocalTimestamp,
    ) -> bool {
        !self
            .refuted
            .get(&carrier)
            .is_some_and(|refutation| refutation.holds(view, now))
            && !self
                .in_flight
                .get(&carrier)
                .is_some_and(|claim| claim.live(now))
            && !self
                .in_flight
                .values()
                .any(|claim| claim.live(now) && &claim.qc == qc)
    }

    /// Hold `qc` from `carrier` while one verification per committee in
    /// `tried` runs, with `walk` to try once they all refute. Replaces a
    /// stale claim from the same carrier, and drops every other stale one.
    pub fn track(
        &mut self,
        carrier: Carrier,
        qc: QuorumCertificate,
        tried: Vec<Hash>,
        walk: Option<EpochWalk>,
        now: LocalTimestamp,
    ) -> SyncClaimId {
        self.in_flight.retain(|_, claim| claim.live(now));
        let id = SyncClaimId(self.next_id);
        self.next_id += 1;
        self.in_flight.insert(
            carrier,
            InFlightClaim {
                id,
                qc,
                outstanding: tried.len(),
                verified: false,
                tried,
                walk,
                since: now,
            },
        );
        id
    }

    /// Claim `id`'s certificate, the walk left to it and the committees it
    /// has tried, for the caller to find the next window to try.
    pub fn walk_of(
        &self,
        id: SyncClaimId,
    ) -> Option<(QuorumCertificate, Option<EpochWalk>, Vec<Hash>)> {
        let claim = self.in_flight.values().find(|claim| claim.id == id)?;
        Some((claim.qc.clone(), claim.walk, claim.tried.clone()))
    }

    /// Record how far claim `id`'s walk got: `walk` is what remains, and
    /// `dispatched` the digest of the committee now being tried, if any.
    pub fn resume_walk(
        &mut self,
        id: SyncClaimId,
        walk: Option<EpochWalk>,
        dispatched: Option<Hash>,
        now: LocalTimestamp,
    ) {
        let Some(claim) = self.in_flight.values_mut().find(|claim| claim.id == id) else {
            return;
        };
        claim.walk = walk;
        if let Some(digest) = dispatched {
            claim.tried.push(digest);
            claim.outstanding = 1;
            claim.since = now;
        }
    }

    /// One committee answered claim `id`, in `view`.
    pub fn on_result(
        &mut self,
        id: SyncClaimId,
        result: Option<Verified<QuorumCertificate>>,
        view: Round,
        now: LocalTimestamp,
    ) -> ClaimOutcome {
        let Some((&carrier, claim)) = self.in_flight.iter_mut().find(|(_, c)| c.id == id) else {
            return ClaimOutcome::Pending;
        };
        claim.outstanding = claim.outstanding.saturating_sub(1);
        let first = match result {
            Some(verified) if !claim.verified => {
                claim.verified = true;
                self.last_verified = Some(verified.clone());
                Some(verified)
            }
            _ => None,
        };
        if claim.outstanding > 0 {
            return first.map_or(ClaimOutcome::Pending, ClaimOutcome::Verified);
        }
        if !claim.verified && claim.walk.is_some() {
            return ClaimOutcome::Retry(id);
        }
        let claim = self
            .in_flight
            .remove(&carrier)
            .expect("the claim was just read");
        if claim.verified {
            return first.map_or(ClaimOutcome::Pending, ClaimOutcome::Verified);
        }
        self.refuted
            .retain(|_, refutation| refutation.holds(view, now));
        self.refuted.insert(carrier, Refutation { view, at: now });
        ClaimOutcome::Refuted {
            carrier,
            qc: claim.qc,
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        AggregateSignature, BlockHash, BlockHeight, ShardId, SignerBitfield, WeightedTimestamp,
    };

    use super::*;

    fn qc(tag: &[u8]) -> QuorumCertificate {
        QuorumCertificate::new(
            BlockHash::from_raw(Hash::from_bytes(tag)),
            ShardId::ROOT,
            BlockHeight::new(7),
            BlockHash::ZERO,
            Round::new(7),
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        )
    }

    /// `n` distinct committee digests.
    fn tried(n: u8) -> Vec<Hash> {
        (0..n).map(|i| Hash::from_bytes(&[i])).collect()
    }

    const NOW: LocalTimestamp = LocalTimestamp::ZERO;
    const VIEW: Round = Round::new(3);
    const A: Carrier = Carrier::Proposer(ValidatorId::new(1));
    const B: Carrier = Carrier::Relayer(ValidatorId::new(2));

    /// A claim verified by one committee stays in flight until the other
    /// answers, and its certificate is not dispatched again meanwhile; the
    /// late refutation then changes nothing.
    #[test]
    fn a_verified_claim_holds_its_slot_until_every_committee_answers() {
        let mut claims = SyncClaims::default();
        let cited = qc(b"cited");
        let id = claims.track(A, cited.clone(), tried(2), None, NOW);

        let verified = Verified::new_unchecked_for_test(cited.clone());
        assert!(matches!(
            claims.on_result(id, Some(verified), VIEW, NOW),
            ClaimOutcome::Verified(_)
        ));
        assert!(claims.is_verified(&cited));
        assert!(!claims.admits(A, &qc(b"other"), VIEW, NOW));
        assert!(!claims.admits(B, &cited, VIEW, NOW));

        assert!(matches!(
            claims.on_result(id, None, VIEW, NOW),
            ClaimOutcome::Pending
        ));
        assert!(claims.admits(A, &qc(b"other"), VIEW, NOW));
    }

    /// A refutation frees the slot but holds the carrier off for the rest
    /// of the view, for at most the retry interval, and only until the
    /// schedule gains an epoch.
    #[test]
    fn a_refuted_carrier_waits_for_the_view_the_interval_or_the_schedule() {
        let mut claims = SyncClaims::default();
        claims.observe_schedule(Some(Epoch::new(1)));
        let id = claims.track(A, qc(b"forged"), tried(1), None, NOW);
        assert!(matches!(
            claims.on_result(id, None, VIEW, NOW),
            ClaimOutcome::Refuted { carrier: A, .. }
        ));
        let next = qc(b"next");
        assert!(!claims.admits(A, &next, VIEW, NOW));
        assert!(claims.admits(B, &next, VIEW, NOW));
        assert!(claims.admits(A, &next, VIEW.next(), NOW));
        assert!(claims.admits(A, &next, VIEW, NOW.plus(CLAIM_RETRY_AFTER)));

        claims.observe_schedule(Some(Epoch::new(1)));
        assert!(!claims.admits(A, &next, VIEW, NOW));
        claims.observe_schedule(Some(Epoch::new(2)));
        assert!(claims.admits(A, &next, VIEW, NOW));
    }

    /// A relayed forgery under a validator's name refutes only its relayed
    /// slot: the same validator's headers are still checked.
    #[test]
    fn a_relayed_refutation_leaves_the_proposer_path_open() {
        let mut claims = SyncClaims::default();
        let relayer = Carrier::Relayer(ValidatorId::new(5));
        let proposer = Carrier::Proposer(ValidatorId::new(5));
        let id = claims.track(relayer, qc(b"swapped"), tried(1), None, NOW);
        assert!(matches!(
            claims.on_result(id, None, VIEW, NOW),
            ClaimOutcome::Refuted { .. }
        ));
        assert!(!claims.admits(relayer, &qc(b"next"), VIEW, NOW));
        assert!(claims.admits(proposer, &qc(b"next"), VIEW, NOW));
    }

    /// One certificate cited by two carriers is checked once.
    #[test]
    fn a_certificate_in_flight_is_not_claimed_twice() {
        let mut claims = SyncClaims::default();
        let cited = qc(b"cited");
        let _ = claims.track(A, cited.clone(), tried(1), None, NOW);
        assert!(!claims.admits(B, &cited, VIEW, NOW));
        assert!(claims.admits(B, &qc(b"other"), VIEW, NOW));
    }

    /// Once every committee refutes, the walk is offered before the claim
    /// is refuted, and each window tried resets the claim's clock.
    #[test]
    fn the_walk_is_tried_after_every_other_committee_refutes() {
        let mut claims = SyncClaims::default();
        let walk = EpochWalk::down(Epoch::new(3), Epoch::new(2));
        let id = claims.track(A, qc(b"cited"), tried(2), walk, NOW);
        assert!(matches!(
            claims.on_result(id, None, VIEW, NOW),
            ClaimOutcome::Pending
        ));
        assert!(matches!(
            claims.on_result(id, None, VIEW, NOW),
            ClaimOutcome::Retry(retry) if retry == id
        ));
        let (_, remaining, held) = claims.walk_of(id).expect("held");
        assert_eq!(remaining, walk);
        assert_eq!(held.len(), 2);

        let (epoch, rest) = remaining.expect("a window left").step();
        assert_eq!(epoch, Epoch::new(3));
        let later = NOW.plus(CLAIM_STALE_AFTER);
        claims.resume_walk(id, rest, Some(tried(3).remove(2)), later);
        assert!(!claims.admits(A, &qc(b"next"), VIEW, later));

        claims.resume_walk(id, None, None, later);
        assert!(matches!(
            claims.on_result(id, None, VIEW, later),
            ClaimOutcome::Refuted { .. }
        ));
    }

    /// A claim whose results never return gives its slot back, and a
    /// result for it that arrives after the slot was retaken reaches
    /// nothing.
    #[test]
    fn a_claim_never_answered_ages_out() {
        let mut claims = SyncClaims::default();
        let stale = claims.track(A, qc(b"lost"), tried(1), None, NOW);
        assert!(!claims.admits(A, &qc(b"next"), VIEW, NOW));

        let later = NOW.plus(CLAIM_STALE_AFTER);
        assert!(claims.admits(A, &qc(b"next"), VIEW, later));
        assert!(claims.admits(B, &qc(b"lost"), VIEW, later));
        let fresh = claims.track(A, qc(b"next"), tried(1), None, later);
        assert!(matches!(
            claims.on_result(stale, None, VIEW, later),
            ClaimOutcome::Pending
        ));
        assert!(matches!(
            claims.on_result(fresh, None, VIEW, later),
            ClaimOutcome::Refuted { .. }
        ));
    }
}
