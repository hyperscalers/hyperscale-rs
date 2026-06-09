//! Commit-assembly sub-machine.
//!
//! After SPC decides an epoch, the coordinator must reproduce the
//! committed [`BeaconProposal`] set from its local pool before it can
//! assemble and adopt the block. When every committed `PcVector` element
//! resolves to a pooled proposal, assembly proceeds immediately;
//! otherwise the decided cert + output are stashed here keyed by epoch
//! while the missing proposals are fetched, and assembly resumes once
//! every awaited fetch resolves.
//!
//! Pure — no VRF, no network, no topology, no adoption. The coordinator
//! owns the impure tail: it verifies + admits fetched proposals, projects
//! the boundary contributions, and adopts. This machine only decides
//! *when* assembly is ready, against the proposal pool + committee it is
//! handed each call.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_types::{
    BeaconProposal, Epoch, PcValueElement, PcVector, SpcCert, ValidatorId, Verified,
};
use tracing::warn;

use crate::proposal_pool::BeaconProposalPool;

/// Stashed SPC-decided epoch awaiting fetches for at least one missing
/// committed proposal.
struct PendingCommitAssembly {
    epoch: Epoch,
    output: PcVector,
    cert: Verified<SpcCert>,
    awaiting: BTreeSet<ValidatorId>,
}

/// What the coordinator should do after a decode.
pub enum AssemblyDecision {
    /// Every committed element resolved — assemble and adopt the block
    /// from these verified proposals + cert.
    Assemble {
        /// Decided epoch the block commits.
        epoch: Epoch,
        /// Committee-ordered committed proposals, each pooled and verified.
        committed: Vec<(ValidatorId, Verified<BeaconProposal>)>,
        /// The SPC cert authenticating the committed set. Boxed — it
        /// dwarfs the other variants (a full `PcQc3` + vectors).
        cert: Box<Verified<SpcCert>>,
    },
    /// At least one committed proposal is missing from the pool — fetch
    /// these validators' proposals; assembly resumes when they resolve.
    AwaitFetch {
        /// Decided epoch the fetches are scoped to.
        epoch: Epoch,
        /// Validators whose committed proposals must be fetched.
        missing: Vec<ValidatorId>,
    },
    /// Nothing to do — an out-of-band resolve, a still-incomplete stash,
    /// or a stash dropped because assembly can't complete locally (the
    /// node will catch up via peer beacon-block gossip).
    Idle,
}

/// Result of decoding a committed `PcVector` against the local pool.
enum DecodeOutcome {
    Complete(Vec<(ValidatorId, Verified<BeaconProposal>)>),
    Pending { missing: Vec<ValidatorId> },
}

/// Per-epoch stash of SPC-decided outputs awaiting their missing
/// committed proposals.
#[derive(Default)]
pub struct CommitAssembler {
    pending: BTreeMap<Epoch, PendingCommitAssembly>,
}

impl CommitAssembler {
    /// Empty assembler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// SPC has decided `epoch`. Decode the committed `PcVector` against
    /// the local pool: when every non-`ZERO` element resolves to a
    /// matching pooled proposal, yield [`AssemblyDecision::Assemble`];
    /// otherwise stash the cert + output keyed by `epoch` and yield
    /// [`AssemblyDecision::AwaitFetch`] naming the validators to fetch.
    ///
    /// Concurrent stashes for different epochs are allowed; a re-fire for
    /// an epoch that already has a stash overwrites it (and is logged).
    pub fn on_decided(
        &mut self,
        epoch: Epoch,
        output: &PcVector,
        cert: Verified<SpcCert>,
        pool: &BeaconProposalPool,
        members: &[ValidatorId],
    ) -> AssemblyDecision {
        match Self::decode(pool, members, epoch, output) {
            DecodeOutcome::Complete(committed) => AssemblyDecision::Assemble {
                epoch,
                committed,
                cert: Box::new(cert),
            },
            DecodeOutcome::Pending { missing } => {
                if let Some(prior) = self.pending.insert(
                    epoch,
                    PendingCommitAssembly {
                        epoch,
                        output: output.clone(),
                        cert,
                        awaiting: missing.iter().copied().collect(),
                    },
                ) {
                    warn!(
                        epoch = epoch.inner(),
                        prior_awaiting = prior.awaiting.len(),
                        "OutputHigh re-fired for an epoch with an existing stash — overwriting",
                    );
                }
                AssemblyDecision::AwaitFetch { epoch, missing }
            }
        }
    }

    /// Whether `epoch`'s stash is still awaiting `validator`'s proposal.
    /// The coordinator gates the verify + admit of a fetched proposal on
    /// this so an out-of-band response does no work.
    #[must_use]
    pub fn is_awaiting(&self, epoch: Epoch, validator: ValidatorId) -> bool {
        self.pending
            .get(&epoch)
            .is_some_and(|p| p.awaiting.contains(&validator))
    }

    /// A fetched proposal for `validator` has been resolved into the pool
    /// (verified + admitted, or dropped on verify failure). Clears the
    /// await; once `epoch`'s stash has no outstanding fetches, re-decodes
    /// against the now-extended pool and either yields
    /// [`AssemblyDecision::Assemble`] or drops the stash
    /// ([`AssemblyDecision::Idle`] — the node catches up via peer
    /// beacon-block gossip).
    pub fn on_proposal_resolved(
        &mut self,
        epoch: Epoch,
        validator: ValidatorId,
        pool: &BeaconProposalPool,
        members: &[ValidatorId],
    ) -> AssemblyDecision {
        let still_awaiting = match self.pending.get_mut(&epoch) {
            Some(pending) => {
                if !pending.awaiting.remove(&validator) {
                    return AssemblyDecision::Idle;
                }
                !pending.awaiting.is_empty()
            }
            None => return AssemblyDecision::Idle,
        };
        if still_awaiting {
            return AssemblyDecision::Idle;
        }
        let Some(pending) = self.pending.remove(&epoch) else {
            return AssemblyDecision::Idle;
        };
        match Self::decode(pool, members, pending.epoch, &pending.output) {
            DecodeOutcome::Complete(committed) => AssemblyDecision::Assemble {
                epoch: pending.epoch,
                committed,
                cert: Box::new(pending.cert),
            },
            DecodeOutcome::Pending { missing } => {
                warn!(
                    epoch = pending.epoch.inner(),
                    still_missing = missing.len(),
                    "Assembly still incomplete after all fetches resolved — relying on peer beacon-block gossip",
                );
                AssemblyDecision::Idle
            }
        }
    }

    /// Evict stashes at or before `current_epoch` — their block already
    /// sits in the chain, so they can no longer adopt. Returns the
    /// outstanding `(epoch, validator)` fetch ids the coordinator should
    /// abandon so the binding releases its in-flight slots.
    pub fn prune_stale(&mut self, current_epoch: Epoch) -> Vec<(Epoch, ValidatorId)> {
        let stale_epochs: Vec<Epoch> = self
            .pending
            .range(..=current_epoch)
            .map(|(e, _)| *e)
            .collect();
        let mut ids: Vec<(Epoch, ValidatorId)> = Vec::new();
        for epoch in stale_epochs {
            if let Some(pending) = self.pending.remove(&epoch) {
                ids.extend(pending.awaiting.into_iter().map(|v| (epoch, v)));
            }
        }
        ids
    }

    /// Read the committed `BeaconProposal` list from the pool, in committee
    /// order, matching each non-`ZERO` `PcVector` element against the
    /// corresponding validator's [`BeaconProposal::pc_element_hash`].
    ///
    /// A non-`ZERO` element the pool can't reproduce surfaces as
    /// [`DecodeOutcome::Pending`] — the pool holds no proposal for that
    /// validator, or holds one whose digest diverges from the committed
    /// element (the fingerprint of a proposer that equivocated its
    /// proposal across the committee). Either way the position must resolve
    /// via fetch or peer block before assembly proceeds: a block omitting a
    /// committed position fails the committed-proposal binding every
    /// verifier runs, so adopting one built locally would fork this node
    /// off the canonical chain.
    fn decode(
        pool: &BeaconProposalPool,
        members: &[ValidatorId],
        epoch: Epoch,
        output: &PcVector,
    ) -> DecodeOutcome {
        let mut committed = Vec::new();
        let mut missing = Vec::new();
        for (i, element) in output.iter().enumerate() {
            if *element == PcValueElement::ZERO {
                continue;
            }
            let Some(validator) = members.get(i).copied() else {
                warn!(
                    pos = i,
                    "OutputHigh element past committee bounds — skipping",
                );
                continue;
            };
            match pool.get(validator) {
                Some(pooled) if pooled.pc_element_hash(epoch) == *element => {
                    committed.push((validator, pooled.as_ref().clone()));
                }
                Some(_) => {
                    warn!(
                        ?validator,
                        epoch = epoch.inner(),
                        "OutputHigh diverges from pooled proposal — proposer equivocated; \
                         deferring assembly to fetch or peer block",
                    );
                    missing.push(validator);
                }
                None => missing.push(validator),
            }
        }
        if missing.is_empty() {
            DecodeOutcome::Complete(committed)
        } else {
            DecodeOutcome::Pending { missing }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_types::{
        PcQc2, PcQc3, PcSignerLengths, PcXpProof, SignerBitfield, SpcView, VrfProof,
        zero_bls_signature,
    };

    use super::*;

    fn make_committee(n: u64) -> Vec<ValidatorId> {
        (0..n).map(ValidatorId::new).collect()
    }

    fn proposal(seed: u8) -> Arc<Verified<BeaconProposal>> {
        Arc::new(Verified::new_unchecked_for_test(BeaconProposal::vrf_only(
            VrfProof::new([seed; 96]),
        )))
    }

    fn element(seed: u8, epoch: Epoch) -> PcValueElement {
        proposal(seed).pc_element_hash(epoch)
    }

    fn pool_with(epoch: Epoch, entries: &[(ValidatorId, u8)]) -> BeaconProposalPool {
        let pool = BeaconProposalPool::new(epoch);
        for &(validator, seed) in entries {
            pool.admit(validator, epoch, proposal(seed));
        }
        pool
    }

    /// An opaque `Verified<SpcCert>` for the stash/lifecycle tests. The
    /// assembler only carries the cert through to the driver — it never
    /// inspects it — so a degenerate value is sufficient.
    fn dummy_cert() -> Verified<SpcCert> {
        let qc2 = PcQc2::new(
            PcVector::empty(),
            SignerBitfield::empty(),
            zero_bls_signature(),
            PcXpProof::Full,
        );
        let qc3 = PcQc3::new(
            PcVector::empty(),
            qc2,
            None,
            None,
            SignerBitfield::empty(),
            PcSignerLengths::Uniform(0),
            zero_bls_signature(),
        );
        Verified::new_unchecked_for_test(SpcCert::Direct {
            prev_view: SpcView::new(0),
            value: PcVector::empty(),
            proof: qc3.into(),
        })
    }

    // ── decode (cert-free; the pure committee-order matching) ──

    #[test]
    fn decode_all_zero_is_complete_empty() {
        let epoch = Epoch::new(7);
        let pool = BeaconProposalPool::new(epoch);
        let committee = make_committee(3);
        let output = PcVector::new(vec![PcValueElement::ZERO; 3]);
        match CommitAssembler::decode(&pool, &committee, epoch, &output) {
            DecodeOutcome::Complete(proposals) => assert!(proposals.is_empty()),
            DecodeOutcome::Pending { .. } => panic!("all-zero output is complete"),
        }
    }

    #[test]
    fn decode_matches_pooled_proposal() {
        let epoch = Epoch::new(7);
        let committee = make_committee(2);
        let pool = pool_with(epoch, &[(committee[1], 9)]);
        let output = PcVector::new(vec![PcValueElement::ZERO, element(9, epoch)]);
        match CommitAssembler::decode(&pool, &committee, epoch, &output) {
            DecodeOutcome::Complete(proposals) => {
                assert_eq!(proposals.len(), 1);
                assert_eq!(proposals[0].0, committee[1]);
            }
            DecodeOutcome::Pending { .. } => panic!("matching pooled element is complete"),
        }
    }

    #[test]
    fn decode_missing_when_unpooled() {
        let epoch = Epoch::new(7);
        let committee = make_committee(2);
        let pool = BeaconProposalPool::new(epoch);
        let output = PcVector::new(vec![element(1, epoch), PcValueElement::ZERO]);
        match CommitAssembler::decode(&pool, &committee, epoch, &output) {
            DecodeOutcome::Pending { missing } => assert_eq!(missing, vec![committee[0]]),
            DecodeOutcome::Complete(_) => panic!("unpooled element must be missing"),
        }
    }

    #[test]
    fn decode_missing_when_pooled_diverges() {
        // Validator 0's proposal is pooled (seed 1), but the committed
        // element is a different variant's digest (seed 0xFF) — the
        // equivocation fingerprint. The position can't be reproduced.
        let epoch = Epoch::new(7);
        let committee = make_committee(1);
        let pool = pool_with(epoch, &[(committee[0], 1)]);
        let output = PcVector::new(vec![element(0xFF, epoch)]);
        match CommitAssembler::decode(&pool, &committee, epoch, &output) {
            DecodeOutcome::Pending { missing } => assert_eq!(missing, vec![committee[0]]),
            DecodeOutcome::Complete(_) => panic!("divergent pooled element must be missing"),
        }
    }

    #[test]
    fn decode_skips_elements_past_committee_bounds() {
        // A non-`ZERO` element beyond the committee length is skipped, not
        // counted as missing.
        let epoch = Epoch::new(7);
        let committee = make_committee(1);
        let pool = BeaconProposalPool::new(epoch);
        let output = PcVector::new(vec![PcValueElement::ZERO, element(2, epoch)]);
        match CommitAssembler::decode(&pool, &committee, epoch, &output) {
            DecodeOutcome::Complete(proposals) => assert!(proposals.is_empty()),
            DecodeOutcome::Pending { .. } => panic!("out-of-bounds element must be skipped"),
        }
    }

    // ── stash / await / resume / prune lifecycle ──

    #[test]
    fn on_decided_complete_yields_assemble_and_no_stash() {
        let epoch = Epoch::new(7);
        let committee = make_committee(1);
        let pool = pool_with(epoch, &[(committee[0], 5)]);
        let output = PcVector::new(vec![element(5, epoch)]);
        let mut asm = CommitAssembler::new();
        match asm.on_decided(epoch, &output, dummy_cert(), &pool, &committee) {
            AssemblyDecision::Assemble {
                epoch: decided,
                committed,
                ..
            } => {
                assert_eq!(decided, epoch);
                assert_eq!(committed.len(), 1);
            }
            _ => panic!("expected Assemble"),
        }
        assert!(
            !asm.is_awaiting(epoch, committee[0]),
            "no stash on a complete decode"
        );
    }

    #[test]
    fn on_decided_pending_stashes_and_awaits() {
        let epoch = Epoch::new(7);
        let committee = make_committee(2);
        let pool = BeaconProposalPool::new(epoch);
        let output = PcVector::new(vec![element(1, epoch), element(2, epoch)]);
        let mut asm = CommitAssembler::new();
        match asm.on_decided(epoch, &output, dummy_cert(), &pool, &committee) {
            AssemblyDecision::AwaitFetch {
                epoch: awaited,
                missing,
            } => {
                assert_eq!(awaited, epoch);
                assert_eq!(missing, committee.clone());
            }
            _ => panic!("expected AwaitFetch"),
        }
        assert!(asm.is_awaiting(epoch, committee[0]));
        assert!(asm.is_awaiting(epoch, committee[1]));
    }

    #[test]
    fn resume_only_after_every_await_resolves() {
        let epoch = Epoch::new(7);
        let committee = make_committee(2);
        let pool = BeaconProposalPool::new(epoch);
        let output = PcVector::new(vec![element(1, epoch), element(2, epoch)]);
        let mut asm = CommitAssembler::new();
        let _ = asm.on_decided(epoch, &output, dummy_cert(), &pool, &committee);

        // First fetch resolves — still awaiting the second.
        pool.admit(committee[0], epoch, proposal(1));
        assert!(
            matches!(
                asm.on_proposal_resolved(epoch, committee[0], &pool, &committee),
                AssemblyDecision::Idle
            ),
            "one await outstanding",
        );
        assert!(asm.is_awaiting(epoch, committee[1]));

        // Last fetch resolves — assembly is ready.
        pool.admit(committee[1], epoch, proposal(2));
        match asm.on_proposal_resolved(epoch, committee[1], &pool, &committee) {
            AssemblyDecision::Assemble { committed, .. } => assert_eq!(committed.len(), 2),
            _ => panic!("expected Assemble once every await resolved"),
        }
        assert!(!asm.is_awaiting(epoch, committee[0]), "stash cleared");
    }

    #[test]
    fn resume_drops_stash_when_still_missing() {
        // Every await resolves but the pool still can't reproduce the
        // committed element (e.g. a failed fetch) — drop the stash and
        // wait for peer gossip.
        let epoch = Epoch::new(7);
        let committee = make_committee(1);
        let pool = BeaconProposalPool::new(epoch);
        let output = PcVector::new(vec![element(1, epoch)]);
        let mut asm = CommitAssembler::new();
        let _ = asm.on_decided(epoch, &output, dummy_cert(), &pool, &committee);
        assert!(matches!(
            asm.on_proposal_resolved(epoch, committee[0], &pool, &committee),
            AssemblyDecision::Idle
        ));
        assert!(
            !asm.is_awaiting(epoch, committee[0]),
            "stash dropped after giving up"
        );
    }

    #[test]
    fn resolve_without_a_stash_is_idle() {
        let epoch = Epoch::new(7);
        let committee = make_committee(1);
        let pool = BeaconProposalPool::new(epoch);
        let mut asm = CommitAssembler::new();
        assert!(matches!(
            asm.on_proposal_resolved(epoch, committee[0], &pool, &committee),
            AssemblyDecision::Idle
        ));
    }

    #[test]
    fn prune_stale_evicts_at_or_below_current_and_retains_later() {
        let epoch = Epoch::new(7);
        let later = Epoch::new(8);
        let committee = make_committee(1);
        let pool = BeaconProposalPool::new(epoch);
        let output = PcVector::new(vec![element(1, epoch)]);
        let mut asm = CommitAssembler::new();
        let _ = asm.on_decided(epoch, &output, dummy_cert(), &pool, &committee);
        let _ = asm.on_decided(later, &output, dummy_cert(), &pool, &committee);

        let abandoned = asm.prune_stale(epoch);
        assert_eq!(abandoned, vec![(epoch, committee[0])]);
        assert!(!asm.is_awaiting(epoch, committee[0]), "stale stash pruned");
        assert!(
            asm.is_awaiting(later, committee[0]),
            "future stash retained"
        );
    }
}
