//! Equivocation evidence the local coordinator has observed but not
//! yet broadcast as a proposal witness.
//!
//! Two flavours of evidence land here: PC double-signs (caught at
//! vote-handler time when conflicting votes arrive at the same
//! `(validator, epoch, view, round)`) and recovery contradictions
//! (caught when a validator that signed a recovery request also signs
//! a finalized block past the request's anchor). Either jails the
//! equivocator permanently when `apply_epoch` re-runs verification.
//!
//! Keyed by `ValidatorId` with first-wins semantics — one piece of
//! evidence per validator is enough to jail them, so subsequent
//! observations are dropped to keep the proposal-witness drain
//! bounded.

use std::collections::BTreeMap;

use hyperscale_types::{
    BeaconWitness, EquivocationEvidence, PcVoteEquivocation, RecoveryEquivocation, ValidatorId,
};

/// Buffered equivocation evidence awaiting inclusion in a beacon
/// proposal.
#[derive(Debug, Default)]
pub struct EquivocationObservations {
    by_validator: BTreeMap<ValidatorId, EquivocationEvidence>,
}

impl EquivocationObservations {
    /// Empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a PC double-sign. Returns `true` if newly recorded;
    /// `false` if evidence for this validator was already buffered.
    pub fn record_pc_equivocation(&mut self, evidence: PcVoteEquivocation) -> bool {
        let v = evidence.validator;
        if self.by_validator.contains_key(&v) {
            return false;
        }
        self.by_validator
            .insert(v, EquivocationEvidence::Vote(Box::new(evidence)));
        true
    }

    /// Record a recovery contradiction. Returns `true` if newly
    /// recorded; `false` if evidence for this validator was already
    /// buffered.
    pub fn record_recovery_equivocation(&mut self, evidence: RecoveryEquivocation) -> bool {
        let v = evidence.validator;
        if self.by_validator.contains_key(&v) {
            return false;
        }
        self.by_validator
            .insert(v, EquivocationEvidence::Recovery(Box::new(evidence)));
        true
    }

    /// Drain all observed evidence into `BeaconWitness::Equivocation`
    /// entries and empty the buffer. The proposer caps the returned
    /// slice against `MAX_WITNESSES_PER_PROPOSER` and re-records
    /// anything it dropped if it wants to retry next epoch.
    pub fn drain_for_proposal(&mut self) -> Vec<BeaconWitness> {
        std::mem::take(&mut self.by_validator)
            .into_values()
            .map(|evidence| BeaconWitness::Equivocation {
                evidence: Box::new(evidence),
            })
            .collect()
    }

    /// Drop evidence for `validator` — the coordinator calls this
    /// after `apply_epoch` confirms the validator is now
    /// `Jailed { Equivocation }` and further evidence is wasted.
    pub fn forget(&mut self, validator: ValidatorId) {
        self.by_validator.remove(&validator);
    }
}

// Flat accessors; names are the documentation.
#[allow(missing_docs)]
impl EquivocationObservations {
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_validator.len()
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

// Tests temporarily removed during cert-as-authenticator refactor; restore in follow-up.

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        BeaconBlockHash, Bls12381G2Signature, Epoch, GenesisConfigHash, Hash, PcValueElement,
        PcVector, PcVoteRound, RecoveryEquivocation, RecoveryRequest, RecoveryRound, SpcCert,
        SpcView, ValidatorId,
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
            sig_a: Bls12381G2Signature([0x11; 96]),
            value_b: PcVector::new(std::iter::once(element_b)),
            sig_b: Bls12381G2Signature([0x22; 96]),
        }
    }

    fn recovery_evidence(v: u64) -> RecoveryEquivocation {
        RecoveryEquivocation {
            validator: ValidatorId::new(v),
            request: RecoveryRequest::new(
                BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
                Epoch::new(7),
                RecoveryRound::new(0),
                ValidatorId::new(v),
                Bls12381G2Signature([0x33; 96]),
            ),
            block_epoch: Epoch::new(8),
            block_cert: SpcCert::Genesis {
                config_hash: GenesisConfigHash::ZERO,
            },
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
    fn record_recovery_then_query_round_trips() {
        let mut e = EquivocationObservations::new();
        assert!(e.record_recovery_equivocation(recovery_evidence(2)));
        assert!(e.contains(ValidatorId::new(2)));
        assert_eq!(e.len(), 1);
    }

    #[test]
    fn first_wins_when_same_validator_observed_twice() {
        let mut e = EquivocationObservations::new();
        assert!(e.record_pc_equivocation(pc_evidence(3)));
        assert!(!e.record_recovery_equivocation(recovery_evidence(3)));
        assert_eq!(e.len(), 1);
    }

    #[test]
    fn drain_returns_all_evidence_as_witnesses_and_empties_buffer() {
        let mut e = EquivocationObservations::new();
        e.record_pc_equivocation(pc_evidence(1));
        e.record_recovery_equivocation(recovery_evidence(2));
        let drained = e.drain_for_proposal();
        assert_eq!(drained.len(), 2);
        for witness in &drained {
            let BeaconWitness::Equivocation { .. } = witness;
        }
        assert!(e.is_empty());
    }

    #[test]
    fn forget_drops_evidence_for_that_validator_only() {
        let mut e = EquivocationObservations::new();
        e.record_pc_equivocation(pc_evidence(1));
        e.record_pc_equivocation(pc_evidence(2));
        e.forget(ValidatorId::new(1));
        assert!(!e.contains(ValidatorId::new(1)));
        assert!(e.contains(ValidatorId::new(2)));
        assert_eq!(e.len(), 1);
    }

    #[test]
    fn drained_evidence_preserves_validator_id() {
        let mut e = EquivocationObservations::new();
        e.record_pc_equivocation(pc_evidence(7));
        e.record_recovery_equivocation(recovery_evidence(9));
        let drained = e.drain_for_proposal();
        let validators: Vec<ValidatorId> = drained
            .iter()
            .map(|w| {
                let BeaconWitness::Equivocation { evidence } = w;
                evidence.validator()
            })
            .collect();
        assert!(validators.contains(&ValidatorId::new(7)));
        assert!(validators.contains(&ValidatorId::new(9)));
    }
}
