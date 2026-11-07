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
//! clock and on the schedule as well as on the view. A slot whose result
//! never returns is reclaimed after [`CLAIM_STALE_AFTER`].
//!
//! A claim is checked under the one committee its certificate names, so
//! each carrier costs this replica one pairing per interval, and the
//! carriers are bounded by twice the validator set.
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
    Epoch, LocalTimestamp, QuorumCertificate, Round, VIEW_CHANGE_TIMEOUT_DEFAULT,
    VIEW_CHANGE_TIMEOUT_MAX, ValidatorId, Verified,
};

/// How long a claim holds its carrier's slot without an answer. A claim
/// waits one crypto pool round trip; one the longest round timer has not
/// seen answered lost its result.
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

/// A claim whose verification is in flight.
struct InFlightClaim {
    id: SyncClaimId,
    qc: QuorumCertificate,
    /// When the verification was dispatched, on the local clock.
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
    /// The claim verified: sync toward it.
    Verified(Verified<QuorumCertificate>),
    /// The claim did not verify.
    Refuted {
        carrier: Carrier,
        qc: QuorumCertificate,
    },
    /// Nothing to act on: the claim is no longer held.
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

    /// Hold `qc` from `carrier` while its verification runs. Replaces a
    /// stale claim from the same carrier, and drops every other stale one.
    pub fn track(
        &mut self,
        carrier: Carrier,
        qc: QuorumCertificate,
        now: LocalTimestamp,
    ) -> SyncClaimId {
        self.in_flight.retain(|_, claim| claim.live(now));
        let id = SyncClaimId(self.next_id);
        self.next_id += 1;
        self.in_flight
            .insert(carrier, InFlightClaim { id, qc, since: now });
        id
    }

    /// Claim `id`'s verification answered, in `view`.
    pub fn on_result(
        &mut self,
        id: SyncClaimId,
        result: Option<Verified<QuorumCertificate>>,
        view: Round,
        now: LocalTimestamp,
    ) -> ClaimOutcome {
        let Some(carrier) = self
            .in_flight
            .iter()
            .find_map(|(carrier, claim)| (claim.id == id).then_some(*carrier))
        else {
            return ClaimOutcome::Pending;
        };
        let claim = self
            .in_flight
            .remove(&carrier)
            .expect("the claim was just found");
        if let Some(verified) = result {
            self.last_verified = Some(verified.clone());
            return ClaimOutcome::Verified(verified);
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
        AggregateSignature, BlockHash, BlockHeight, Hash, ShardId, SignerBitfield,
        WeightedTimestamp,
    };

    use super::*;

    fn qc(tag: &[u8]) -> QuorumCertificate {
        QuorumCertificate::new(
            BlockHash::from_raw(Hash::from_bytes(tag)),
            ShardId::ROOT,
            BlockHeight::new(7),
            BlockHash::ZERO,
            Round::new(7),
            Epoch::GENESIS,
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        )
    }

    const NOW: LocalTimestamp = LocalTimestamp::ZERO;
    const VIEW: Round = Round::new(3);
    const A: Carrier = Carrier::Proposer(ValidatorId::new(1));
    const B: Carrier = Carrier::Relayer(ValidatorId::new(2));

    /// A verified claim frees its slot and is remembered, so a sync toward
    /// it starts at once when it is cited again.
    #[test]
    fn a_verified_claim_frees_its_slot_and_is_remembered() {
        let mut claims = SyncClaims::default();
        let cited = qc(b"cited");
        let id = claims.track(A, cited.clone(), NOW);
        assert!(!claims.admits(A, &qc(b"other"), VIEW, NOW));
        assert!(!claims.admits(B, &cited, VIEW, NOW));

        let verified = Verified::new_unchecked_for_test(cited.clone());
        assert!(matches!(
            claims.on_result(id, Some(verified), VIEW, NOW),
            ClaimOutcome::Verified(_)
        ));
        assert!(claims.is_verified(&cited));
        assert!(claims.admits(A, &qc(b"other"), VIEW, NOW));
        assert!(matches!(
            claims.on_result(id, None, VIEW, NOW),
            ClaimOutcome::Pending
        ));
    }

    /// A refutation frees the slot but holds the carrier off for the rest
    /// of the view, for at most the retry interval, and only until the
    /// schedule gains an epoch.
    #[test]
    fn a_refuted_carrier_waits_for_the_view_the_interval_or_the_schedule() {
        let mut claims = SyncClaims::default();
        claims.observe_schedule(Some(Epoch::new(1)));
        let id = claims.track(A, qc(b"forged"), NOW);
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
        let id = claims.track(relayer, qc(b"swapped"), NOW);
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
        let _ = claims.track(A, cited.clone(), NOW);
        assert!(!claims.admits(B, &cited, VIEW, NOW));
        assert!(claims.admits(B, &qc(b"other"), VIEW, NOW));
    }

    /// A claim whose result never returns gives its slot back, and a
    /// result for it that arrives after the slot was retaken reaches
    /// nothing.
    #[test]
    fn a_claim_never_answered_ages_out() {
        let mut claims = SyncClaims::default();
        let stale = claims.track(A, qc(b"lost"), NOW);
        assert!(!claims.admits(A, &qc(b"next"), VIEW, NOW));

        let later = NOW.plus(CLAIM_STALE_AFTER);
        assert!(claims.admits(A, &qc(b"next"), VIEW, later));
        assert!(claims.admits(B, &qc(b"lost"), VIEW, later));
        let fresh = claims.track(A, qc(b"next"), later);
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
