//! Equivocation evidence the local coordinator has observed but not
//! yet broadcast as a proposal witness.
//!
//! PC double-signs land here, caught at vote-handler time when
//! conflicting votes arrive at the same `(validator, epoch, view,
//! round)`. `apply_epoch` re-runs verification on inclusion and jails
//! the equivocator permanently.
//!
//! Keyed by `ValidatorId` with first-wins semantics — one piece of
//! evidence per validator is enough to jail them, so subsequent
//! observations are dropped to keep the proposal-witness drain
//! bounded.
//!
//! Two-staged like the fork-proof observer beside it
//! ([`ForkProofObservations`](crate::fork_observations::ForkProofObservations)),
//! and for the same reason: a drain is not a delivery. A proposal lost
//! to a skip epoch or to admission never folds, and evidence taken for
//! it and not restored is gone from this node for good — a double-sign
//! nobody can be jailed for.

use std::collections::BTreeMap;

use hyperscale_types::{PcVoteEquivocation, ValidatorId};

/// Buffered equivocation evidence awaiting inclusion in a beacon
/// proposal.
#[derive(Debug, Default)]
pub struct EquivocationObservations {
    /// Evidence awaiting the next proposal build.
    by_validator: BTreeMap<ValidatorId, Box<PcVoteEquivocation>>,
    /// Evidence drained into a proposal whose fold has not yet revoked
    /// the accused. Restored by
    /// [`restore_undelivered`](Self::restore_undelivered) after each
    /// fold's prune.
    in_flight: BTreeMap<ValidatorId, Box<PcVoteEquivocation>>,
}

impl EquivocationObservations {
    /// Empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a PC double-sign. Returns `true` if newly recorded;
    /// `false` if evidence for this validator is already buffered or
    /// riding an unconfirmed proposal.
    pub fn record_pc_equivocation(&mut self, evidence: PcVoteEquivocation) -> bool {
        let v = evidence.validator;
        if self.by_validator.contains_key(&v) || self.in_flight.contains_key(&v) {
            return false;
        }
        self.by_validator.insert(v, Box::new(evidence));
        true
    }

    /// Drain all observed evidence for a proposal build, moving each
    /// entry into the in-flight buffer until a fold confirms it.
    ///
    /// The proposer caps the returned slice against
    /// `MAX_EQUIVOCATIONS_PER_PROPOSER` and hands the overflow back
    /// through [`retain_overflow`](Self::retain_overflow), which puts it
    /// where the next build will find it — `record_pc_equivocation`
    /// would refuse it, since a drained entry is in flight.
    pub fn drain_for_proposal(&mut self) -> Vec<PcVoteEquivocation> {
        let drained = std::mem::take(&mut self.by_validator);
        let out = drained.values().map(|boxed| (**boxed).clone()).collect();
        self.in_flight.extend(drained);
        out
    }

    /// Put evidence the proposer's cap left out of this build back where
    /// the next one will find it.
    pub fn retain_overflow(&mut self, evidence: PcVoteEquivocation) {
        let v = evidence.validator;
        self.in_flight.remove(&v);
        self.by_validator.insert(v, Box::new(evidence));
    }

    /// Drop every buffered or in-flight entry whose validator `obsolete`
    /// matches. The coordinator calls this after each `apply_epoch` with
    /// "key already revoked" — once the fold holds that status,
    /// re-proposing the evidence can't change anything, so it only
    /// wastes proposal space.
    pub fn prune(&mut self, mut obsolete: impl FnMut(ValidatorId) -> bool) {
        self.by_validator.retain(|v, _| !obsolete(*v));
        self.in_flight.retain(|v, _| !obsolete(*v));
    }

    /// Restore every in-flight entry that survived the fold's prune: its
    /// proposal was discarded (a skip epoch, or lost to admission), so
    /// the accused was never revoked and the evidence re-enters the next
    /// proposal build.
    pub fn restore_undelivered(&mut self) {
        let undelivered = std::mem::take(&mut self.in_flight);
        self.by_validator.extend(undelivered);
    }
}

// Flat accessors; names are the documentation.
#[allow(missing_docs)]
impl EquivocationObservations {
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_validator.len() + self.in_flight.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_validator.is_empty()
    }

    #[must_use]
    pub fn contains(&self, validator: ValidatorId) -> bool {
        self.by_validator.contains_key(&validator)
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        ConsensusSignature, Epoch, PcValueElement, PcVector, PcVoteRound, SpcView, ValidatorId,
    };

    use super::*;

    fn pc_evidence(v: u64) -> PcVoteEquivocation {
        let element_a = PcValueElement::new([0x11; 32]);
        let element_b = PcValueElement::new([0x22; 32]);
        PcVoteEquivocation {
            validator: ValidatorId::new(v),
            epoch: Epoch::new(7),
            view: SpcView::new(1),
            round: PcVoteRound::Vote1,
            value_a: PcVector::new(std::iter::once(element_a)),
            sig_a: ConsensusSignature::new([0x11; 96]),
            value_b: PcVector::new(std::iter::once(element_b)),
            sig_b: ConsensusSignature::new([0x22; 96]),
        }
    }

    #[test]
    fn empty_after_new() {
        let e = EquivocationObservations::new();
        assert_eq!(e.len(), 0);
        assert!(e.is_empty());
        assert!(!e.contains(ValidatorId::new(0)));
    }

    #[test]
    fn record_pc_then_query_round_trips() {
        let mut e = EquivocationObservations::new();
        assert!(e.record_pc_equivocation(pc_evidence(1)));
        assert!(e.contains(ValidatorId::new(1)));
        assert_eq!(e.len(), 1);
    }

    #[test]
    fn first_wins_when_same_validator_observed_twice() {
        let mut e = EquivocationObservations::new();
        assert!(e.record_pc_equivocation(pc_evidence(3)));
        assert!(!e.record_pc_equivocation(pc_evidence(3)));
        assert_eq!(e.len(), 1);
    }

    /// A drain is not a delivery. What it takes rides the proposal and
    /// stays held until a fold either revokes the accused or the prune
    /// hands it back — a proposal lost to a skip epoch would otherwise
    /// take the evidence with it, and nobody could be jailed.
    #[test]
    fn a_drain_holds_its_evidence_until_the_fold_answers() {
        let mut e = EquivocationObservations::new();
        e.record_pc_equivocation(pc_evidence(1));
        e.record_pc_equivocation(pc_evidence(2));

        let drained = e.drain_for_proposal();
        assert_eq!(drained.len(), 2);
        assert_eq!(e.len(), 2, "still held, in flight");
        assert!(
            !e.record_pc_equivocation(pc_evidence(1)),
            "a re-observation adds nothing to evidence already riding a proposal"
        );

        // The proposal never folded, so the evidence comes back.
        e.restore_undelivered();
        assert_eq!(e.drain_for_proposal().len(), 2);

        // And a fold that revoked the accused takes it for good.
        e.prune(|_| true);
        e.restore_undelivered();
        assert!(e.is_empty());
    }

    /// Evidence the proposer's cap left out of a build goes back where
    /// the next build looks, which `record_pc_equivocation` would
    /// refuse: the entry is in flight from the drain that produced it.
    #[test]
    fn overflow_returns_to_the_next_build() {
        let mut e = EquivocationObservations::new();
        e.record_pc_equivocation(pc_evidence(1));
        let mut drained = e.drain_for_proposal();

        e.retain_overflow(drained.pop().expect("one piece was drained"));
        assert_eq!(e.drain_for_proposal().len(), 1);
    }

    #[test]
    fn prune_drops_matching_validators_only() {
        let mut e = EquivocationObservations::new();
        e.record_pc_equivocation(pc_evidence(1));
        e.record_pc_equivocation(pc_evidence(2));
        e.prune(|v| v == ValidatorId::new(1));
        assert!(!e.contains(ValidatorId::new(1)));
        assert!(e.contains(ValidatorId::new(2)));
        assert_eq!(e.len(), 1);
    }

    #[test]
    fn drained_evidence_preserves_validator_id() {
        let mut e = EquivocationObservations::new();
        e.record_pc_equivocation(pc_evidence(7));
        e.record_pc_equivocation(pc_evidence(9));
        let drained = e.drain_for_proposal();
        let validators: Vec<ValidatorId> = drained.iter().map(|ev| ev.validator).collect();
        assert!(validators.contains(&ValidatorId::new(7)));
        assert!(validators.contains(&ValidatorId::new(9)));
    }
}
