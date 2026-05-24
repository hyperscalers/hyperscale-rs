//! Strong Prefix Consensus — pure verifiers + signing helpers.
//!
//! SPC drives one slot through a sequence of views. Each view runs an
//! inner PC instance under `pc_context(spc_context(slot), view)`; the
//! inner PC is leaderless (every committee member broadcasts their
//! `v_in`), but view *entry* is leader-driven — the cyclic-shifted
//! first party in the view's ranking proposes an [`SpcProposalObject`]
//! authorising entry.
//!
//! When a view fails (its proposer is silent or Byzantine), `f+1`
//! committee members exchange [`SpcEmptyViewMsg`]s reporting their
//! latest verifiable high triple, and `f+1` such messages aggregate
//! into an indirect [`SpcCert`] that skips ahead to the next view
//! while pinning that view's *parent triple* to a specific
//! [`SpcHighTriple`] — the one the max-reported skip signer attested
//! to. The next leader's identity falls out of the ranking; what the
//! cert constrains is what they're allowed to extend from.
//!
//! This module hosts the **verify** side of SPC — pure functions over
//! wire types from `hyperscale_types::beacon::spc`. The FSM itself, its
//! sub-machine PC instances, and the stateful parent-existence check
//! ([`SpcCert`] verification's `has_parent` gate) live alongside the
//! coordinator in the FSM module.
//!
//! # Soundness gates encoded in the verifiers
//!
//! - **Skip-sig binding to a specific reported value**: every
//!   [`SpcSkipSig`] signs `(empty_view, reported_view,
//!   reported_value_hash)`. The indirect cert's `target_value` must
//!   hash to the `reported_value_hash` of the signer whose
//!   `reported_view` equals the max — closing the path where a
//!   Byzantine prover swaps in a different valid high triple at
//!   `target_view`.
//! - **Quorum threshold**: indirect certs require ≥ `f + 1` distinct
//!   skip signers; verifiers reject ties (per-signer dedup) and short
//!   sets.
//! - **Embedded PC proof binding to the view's context**: every
//!   embedded [`PcQc3`] verifies under `pc_context(spc_ctx, view)`. A
//!   QC3 produced under a different view (or a different SPC instance)
//!   won't verify.

use std::collections::BTreeSet;

use blake3::Hasher;
use hyperscale_types::{
    Bls12381G1PrivateKey, Bls12381G1PublicKey, DOMAIN_PC_EMPTY_VIEW, Hash, NetworkDefinition,
    PC_VALUE_ELEMENT_BYTES, PcQc3, PcValueElement, PcVector, SpcCert, SpcEmptyLowEvidence,
    SpcEmptyViewMsg, SpcHighTriple, SpcProposalObject, SpcSkipSig, SpcView, ValidatorId,
    aggregate_verify_bls_different_messages, pc_context, pc_vote_signing_message,
};

use crate::pc::verify_qc3;

/// Domain tag for hashing a reported high triple's value into a 32-byte
/// digest. Keeps the digest distinct from any other Blake3 use of the
/// same `PcVector` bytes.
const HIGH_VALUE_DOMAIN: &[u8] = b"hyperscale-spc-high-value-v1";

// ─── Pure helpers ──────────────────────────────────────────────────────────

/// Resolve a committee signer's public key, or return `None` if they
/// aren't in the committee. Linear scan — committee sizes are small.
fn pubkey_in_committee(
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
    validator: ValidatorId,
) -> Option<Bls12381G1PublicKey> {
    committee
        .iter()
        .find(|(id, _)| *id == validator)
        .map(|(_, pk)| *pk)
}

/// Byzantine fault threshold for a committee of size `n` — classic
/// BFT `f = (n - 1) / 3`. Threshold for indirect certs is `f + 1`.
const fn byzantine_threshold(n: usize) -> usize {
    n.saturating_sub(1) / 3
}

/// Encode a `u64` as a 32-byte [`PcValueElement`] — little-endian in
/// the low 8 bytes, zero-padded. The exact byte layout has to match
/// what signers produced, so don't change it.
const fn pc_element_from_u64(n: u64) -> PcValueElement {
    let mut bytes = [0u8; PC_VALUE_ELEMENT_BYTES];
    let le = n.to_le_bytes();
    bytes[0] = le[0];
    bytes[1] = le[1];
    bytes[2] = le[2];
    bytes[3] = le[3];
    bytes[4] = le[4];
    bytes[5] = le[5];
    bytes[6] = le[6];
    bytes[7] = le[7];
    PcValueElement::new(bytes)
}

/// Build the canonical "skip target" vector each [`SpcSkipSig`] signs.
///
/// Layout: `[empty_view as u64, reported_view as u64,
/// reported_value_hash]`. Binding the value hash into the signed
/// vector — not just the view number — is what lets the indirect-cert
/// verifier pin `target_value` to the specific triple the max-reported
/// signer attested to, not any other valid high triple at the same
/// view.
#[must_use]
pub fn skip_target(
    empty_view: SpcView,
    reported_view: SpcView,
    reported_value_hash: Hash,
) -> PcVector {
    let hash_element = PcValueElement::new(*reported_value_hash.as_bytes());
    PcVector::new([
        pc_element_from_u64(u64::from(empty_view.inner())),
        pc_element_from_u64(u64::from(reported_view.inner())),
        hash_element,
    ])
}

/// Blake3 digest of a high triple's value under [`HIGH_VALUE_DOMAIN`].
/// The binding payload in [`skip_target`].
#[must_use]
pub fn hash_high_value(v: &PcVector) -> Hash {
    let mut h = Hasher::new();
    h.update(HIGH_VALUE_DOMAIN);
    for el in v.iter() {
        h.update(el.as_bytes());
    }
    Hash::from_bytes(h.finalize().as_bytes())
}

/// Cyclic-shift offset for view `view` in an SPC instance with `n`
/// parties. Views 1 and 2 use the input ranking (offset 0); from view
/// 3 the ranking left-shifts by `view - 2 mod n` each step.
///
/// Shared between the FSM's view-leader lookup and
/// `SpcEmptyLowEvidence::accused`-style demotion logic so the two
/// can't silently drift apart.
#[must_use]
pub const fn rank_shift_for_view(view: SpcView, n: usize) -> usize {
    let v = view.inner();
    if v <= 2 { 0 } else { (v as usize - 2) % n }
}

// ─── Verifiers ─────────────────────────────────────────────────────────────

/// Verify one [`SpcSkipSig`] against the canonical
/// `skip_target(empty_view, sig.reported_view, sig.reported_value_hash)`
/// under the SPC instance context and [`DOMAIN_PC_EMPTY_VIEW`].
///
/// Internal to [`verify_indirect_cert`]; `pub` so the FSM can also
/// gate ingestion of arriving skip statements without re-implementing
/// the message construction.
#[must_use]
pub fn verify_skip_sig(
    sig: &SpcSkipSig,
    empty_view: SpcView,
    network: &NetworkDefinition,
    spc_ctx: &[u8],
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    let Some(pk) = pubkey_in_committee(committee, sig.signer) else {
        return false;
    };
    let target = skip_target(empty_view, sig.reported_view, sig.reported_value_hash);
    let msg = pc_vote_signing_message(network, DOMAIN_PC_EMPTY_VIEW, spc_ctx, &target);
    aggregate_verify_bls_different_messages(&[msg.as_slice()], &sig.sig, &[pk])
}

/// Verify an [`SpcEmptyViewMsg`] — the signer attested to their
/// `max_high` at the time of timing out on `msg.view`.
///
/// Returns `true` iff (1) the signer is in the committee, (2) the
/// embedded `reported.proof` verifies as a real PC QC3 under
/// `pc_context(spc_ctx, reported.view)`, (3) `reported.proof.x_pe ==
/// reported.value` (the embedded QC3's high actually certifies the
/// claimed value), and (4) the BLS sig over `skip_target(msg.view,
/// reported.view, hash(reported.value))` verifies under the signer's
/// key.
#[must_use]
pub fn verify_empty_view_msg(
    msg: &SpcEmptyViewMsg,
    network: &NetworkDefinition,
    spc_ctx: &[u8],
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    let Some(pk) = pubkey_in_committee(committee, msg.signer) else {
        return false;
    };
    // Reported triple's PcQc3 must verify under the right view's PC ctx.
    let reported_pc_ctx = pc_context(spc_ctx, msg.reported.view);
    if !verify_qc3(&msg.reported.proof, network, &reported_pc_ctx, committee) {
        return false;
    }
    // VpcVerifyHigh: the embedded PcQc3's x_pe must equal the reported value.
    if msg.reported.proof.x_pe() != &msg.reported.value {
        return false;
    }
    // Sig over the canonical skip target.
    let value_hash = hash_high_value(&msg.reported.value);
    let target = skip_target(msg.view, msg.reported.view, value_hash);
    let signed = pc_vote_signing_message(network, DOMAIN_PC_EMPTY_VIEW, spc_ctx, &target);
    aggregate_verify_bls_different_messages(&[signed.as_slice()], &msg.sig, &[pk])
}

/// Verify [`SpcEmptyLowEvidence`]: the embedded round-3 cert's `x_pp`
/// is empty (an empty-low witness) and the cert itself verifies under
/// the view's PC context.
///
/// View 1 is excused from accusations, so evidence for `view <= 1` is
/// rejected even when otherwise well-formed.
#[must_use]
pub fn verify_empty_low_evidence(
    evidence: &SpcEmptyLowEvidence,
    network: &NetworkDefinition,
    spc_ctx: &[u8],
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    if evidence.view.inner() <= 1 {
        return false;
    }
    let pc_ctx = pc_context(spc_ctx, evidence.view);
    if !verify_qc3(&evidence.proof, network, &pc_ctx, committee) {
        return false;
    }
    evidence.proof.x_pp().is_empty()
}

/// Verify an [`SpcCert`] against its claimed `entering_view` — the
/// view this cert authorises a leader to enter.
///
/// Pure: validates the cryptographic gates only. The FSM also runs a
/// `has_parent` check at admission time, which depends on the local
/// observed-proposal map and isn't checkable here.
#[must_use]
pub fn verify_cert(
    cert: &SpcCert,
    entering_view: SpcView,
    network: &NetworkDefinition,
    spc_ctx: &[u8],
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    match cert {
        SpcCert::Direct {
            prev_view,
            value,
            proof,
        } => verify_direct_cert(
            *prev_view,
            value,
            proof,
            entering_view,
            network,
            spc_ctx,
            committee,
        ),
        SpcCert::Indirect {
            for_view,
            target_view,
            target_value,
            target_proof,
            skip_sigs,
        } => verify_indirect_cert(
            *for_view,
            *target_view,
            target_value,
            target_proof,
            skip_sigs.as_slice(),
            entering_view,
            network,
            spc_ctx,
            committee,
        ),
    }
}

#[allow(clippy::too_many_arguments)] // splitting via a context struct adds more noise than it removes
fn verify_direct_cert(
    prev_view: SpcView,
    value: &PcVector,
    proof: &PcQc3,
    entering_view: SpcView,
    network: &NetworkDefinition,
    spc_ctx: &[u8],
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    // `prev_view + 1 == entering_view`, guarded against u32 overflow.
    let Some(expected) = prev_view.inner().checked_add(1) else {
        return false;
    };
    if expected != entering_view.inner() {
        return false;
    }
    let pc_ctx = pc_context(spc_ctx, prev_view);
    if !verify_qc3(proof, network, &pc_ctx, committee) {
        return false;
    }
    // VpcVerifyHigh: claimed high value must equal proof.x_pe.
    proof.x_pe() == value
}

#[allow(clippy::too_many_arguments)] // splitting via a context struct adds more noise than it removes
fn verify_indirect_cert(
    for_view: SpcView,
    target_view: SpcView,
    target_value: &PcVector,
    target_proof: &PcQc3,
    skip_sigs: &[SpcSkipSig],
    entering_view: SpcView,
    network: &NetworkDefinition,
    spc_ctx: &[u8],
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    // Indirect certs only make sense at entering_view >= 2 (view 1
    // has no prior empty view to skip).
    if entering_view.inner() < 2 {
        return false;
    }
    if for_view != entering_view {
        return false;
    }
    let n = committee.len();
    let f = byzantine_threshold(n);
    if skip_sigs.len() < f + 1 {
        return false;
    }
    // Distinct signers.
    let mut seen: BTreeSet<ValidatorId> = BTreeSet::new();
    for sig in skip_sigs {
        if !seen.insert(sig.signer) {
            return false;
        }
    }
    let empty_view = SpcView::new(entering_view.inner() - 1);
    for sig in skip_sigs {
        if !verify_skip_sig(sig, empty_view, network, spc_ctx, committee) {
            return false;
        }
    }
    // Cert's target_view must equal max(reported_view) across Σ.
    let max_reported = skip_sigs
        .iter()
        .map(|s| s.reported_view)
        .max()
        .expect("skip_sigs non-empty by f+1 threshold");
    if target_view != max_reported {
        return false;
    }
    // Cert's target_value must hash to the value the max-reported
    // signer actually attested to.
    let target_value_hash = hash_high_value(target_value);
    let max_signer_attests = skip_sigs
        .iter()
        .any(|s| s.reported_view == max_reported && s.reported_value_hash == target_value_hash);
    if !max_signer_attests {
        return false;
    }
    // Target proof verifies under target_view's PC ctx, and its x_pe
    // matches the claimed target_value.
    let target_pc_ctx = pc_context(spc_ctx, target_view);
    if !verify_qc3(target_proof, network, &target_pc_ctx, committee) {
        return false;
    }
    target_proof.x_pe() == target_value
}

/// Verify the cryptographic gates of an [`SpcProposalObject`]: the
/// embedded cert verifies for the proposal's claimed `view`. Doesn't
/// check FSM-stateful invariants (proposer-rank match, `has_parent`).
#[must_use]
pub fn verify_proposal_object(
    po: &SpcProposalObject,
    network: &NetworkDefinition,
    spc_ctx: &[u8],
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    verify_cert(&po.cert, po.view, network, spc_ctx, committee)
}

// ─── Signing ───────────────────────────────────────────────────────────────

/// Sign an empty-view attestation.
///
/// `reported` is the signer's current `max_high` triple — the latest
/// PC output they consider verifiable. The sig covers
/// `skip_target(empty_view, reported.view, hash_high_value(&reported.value))`
/// under [`DOMAIN_PC_EMPTY_VIEW`], so the indirect-cert verifier can
/// extract it into an [`SpcSkipSig`] later.
#[must_use]
pub fn sign_empty_view_msg(
    sk: &Bls12381G1PrivateKey,
    signer: ValidatorId,
    network: &NetworkDefinition,
    spc_ctx: &[u8],
    empty_view: SpcView,
    reported: SpcHighTriple,
) -> SpcEmptyViewMsg {
    let value_hash = hash_high_value(&reported.value);
    let target = skip_target(empty_view, reported.view, value_hash);
    let msg = pc_vote_signing_message(network, DOMAIN_PC_EMPTY_VIEW, spc_ctx, &target);
    let sig = sk.sign_v1(&msg);
    SpcEmptyViewMsg {
        view: empty_view,
        reported,
        signer,
        sig,
    }
}

// ─── Build ─────────────────────────────────────────────────────────────────

/// Assemble an [`SpcCert::Indirect`] from a collection of empty-view
/// messages.
///
/// All inputs are assumed to verify against `empty_view` (callers run
/// [`verify_empty_view_msg`] before pooling). The cert targets the
/// triple whose `reported_view` is the maximum across the inputs —
/// per the protocol invariant — and carries every signer's
/// `(signer, reported_view, value_hash, sig)` quadruple for the
/// indirect-cert verifier.
///
/// Returns `None` when:
/// - `empty_view_msgs` is empty (no skip statements to aggregate)
/// - `empty_view + 1` overflows the `SpcView` u32
/// - any input message's `view` differs from `empty_view` (caller
///   passed mismatched skip statements)
///
/// Doesn't enforce `f + 1` threshold here — the verifier rejects
/// short sets, but callers typically pool until they have `f + 1`
/// before invoking this.
#[must_use]
pub fn build_indirect_cert(
    empty_view: SpcView,
    empty_view_msgs: &[SpcEmptyViewMsg],
) -> Option<SpcCert> {
    if empty_view_msgs.is_empty() {
        return None;
    }
    if empty_view_msgs.iter().any(|m| m.view != empty_view) {
        return None;
    }
    let for_view_raw = empty_view.inner().checked_add(1)?;
    let for_view = SpcView::new(for_view_raw);

    // Non-empty by the early-return above, so `max_by_key` returns Some.
    let target_msg = empty_view_msgs.iter().max_by_key(|m| m.reported.view)?;
    let target_value = target_msg.reported.value.clone();
    let target_view = target_msg.reported.view;
    let target_proof = target_msg.reported.proof.clone();

    let skip_sigs: Vec<SpcSkipSig> = empty_view_msgs
        .iter()
        .map(|m| SpcSkipSig {
            signer: m.signer,
            reported_view: m.reported.view,
            reported_value_hash: hash_high_value(&m.reported.value),
            sig: m.sig,
        })
        .collect();

    Some(SpcCert::Indirect {
        for_view,
        target_view,
        target_value,
        target_proof,
        skip_sigs: skip_sigs.into(),
    })
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        Bls12381G2Signature, PcQc2, PcXpProof, SignerBitfield, Slot, generate_bls_keypair,
        spc_context,
    };

    use super::*;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn committee(n: usize) -> Vec<(ValidatorId, Bls12381G1PublicKey)> {
        (0..n as u64)
            .map(|i| (ValidatorId::new(i), generate_bls_keypair().public_key()))
            .collect()
    }

    fn ctx() -> Vec<u8> {
        spc_context(Slot::new(1))
    }

    fn dummy_pc_qc3() -> PcQc3 {
        let qc2 = PcQc2::new(
            PcVector::empty(),
            SignerBitfield::new(4),
            generate_bls_keypair().sign_v1(b"unused"),
            PcXpProof::Full {
                length_multi_sig: generate_bls_keypair().sign_v1(b"unused"),
            },
        );
        PcQc3::new(
            PcVector::empty(),
            qc2,
            None,
            None,
            Vec::new(),
            generate_bls_keypair().sign_v1(b"unused"),
        )
    }

    /// `rank_shift_for_view` pins views 1 and 2 to offset 0 and
    /// shifts by `view - 2 mod n` from view 3 onward.
    #[test]
    fn rank_shift_layout_is_pinned() {
        let n = 4;
        assert_eq!(rank_shift_for_view(SpcView::new(1), n), 0);
        assert_eq!(rank_shift_for_view(SpcView::new(2), n), 0);
        assert_eq!(rank_shift_for_view(SpcView::new(3), n), 1);
        assert_eq!(rank_shift_for_view(SpcView::new(4), n), 2);
        assert_eq!(rank_shift_for_view(SpcView::new(5), n), 3);
        assert_eq!(rank_shift_for_view(SpcView::new(6), n), 0); // wraps
    }

    /// Distinct `(empty_view, reported_view, value_hash)` triples
    /// produce distinct `skip_target`s — the signed bytes diverge
    /// the way the indirect-cert binding requires.
    #[test]
    fn skip_target_differs_across_inputs() {
        let h_a = Hash::from_bytes(b"value-a");
        let h_b = Hash::from_bytes(b"value-b");
        let t1 = skip_target(SpcView::new(1), SpcView::new(0), h_a);
        let t2 = skip_target(SpcView::new(2), SpcView::new(0), h_a);
        let t3 = skip_target(SpcView::new(1), SpcView::new(1), h_a);
        let t4 = skip_target(SpcView::new(1), SpcView::new(0), h_b);
        assert_ne!(t1, t2);
        assert_ne!(t1, t3);
        assert_ne!(t1, t4);
    }

    /// `verify_empty_low_evidence` rejects evidence for view 1 even
    /// when otherwise well-formed — view 1 is excused from accusations.
    #[test]
    fn verify_empty_low_evidence_rejects_view_one() {
        let c = committee(4);
        let evidence = SpcEmptyLowEvidence {
            view: SpcView::new(1),
            proof: dummy_pc_qc3(),
        };
        assert!(!verify_empty_low_evidence(&evidence, &net(), &ctx(), &c));
    }

    /// Direct cert with `prev_view + 1 != entering_view` is rejected
    /// before any pairing — the view-arithmetic gate.
    #[test]
    fn verify_direct_cert_rejects_view_mismatch() {
        let c = committee(4);
        let cert = SpcCert::Direct {
            prev_view: SpcView::new(3),
            value: PcVector::empty(),
            proof: dummy_pc_qc3(),
        };
        // Entering view = 7 but prev_view + 1 = 4. Mismatch.
        assert!(!verify_cert(&cert, SpcView::new(7), &net(), &ctx(), &c));
    }

    /// Indirect cert at `entering_view = 1` is rejected (no prior
    /// empty view to skip).
    #[test]
    fn verify_indirect_cert_rejects_entering_view_one() {
        let c = committee(4);
        let cert = SpcCert::Indirect {
            for_view: SpcView::new(1),
            target_view: SpcView::new(0),
            target_value: PcVector::empty(),
            target_proof: dummy_pc_qc3(),
            skip_sigs: vec![].into(),
        };
        assert!(!verify_cert(&cert, SpcView::new(1), &net(), &ctx(), &c));
    }

    /// Indirect cert with fewer than `f + 1` skip sigs is rejected.
    #[test]
    fn verify_indirect_cert_rejects_under_quorum() {
        let c = committee(4); // n=4, f=1, threshold f+1=2.
        let one_sig = SpcSkipSig {
            signer: ValidatorId::new(0),
            reported_view: SpcView::new(1),
            reported_value_hash: Hash::ZERO,
            sig: generate_bls_keypair().sign_v1(b"unused"),
        };
        let cert = SpcCert::Indirect {
            for_view: SpcView::new(2),
            target_view: SpcView::new(1),
            target_value: PcVector::empty(),
            target_proof: dummy_pc_qc3(),
            skip_sigs: vec![one_sig].into(),
        };
        assert!(!verify_cert(&cert, SpcView::new(2), &net(), &ctx(), &c));
    }

    /// Indirect cert with duplicate signers in `skip_sigs` is
    /// rejected — closes a sub-quorum-inflation path.
    #[test]
    fn verify_indirect_cert_rejects_duplicate_signers() {
        let c = committee(4);
        let sig = SpcSkipSig {
            signer: ValidatorId::new(0),
            reported_view: SpcView::new(1),
            reported_value_hash: Hash::ZERO,
            sig: generate_bls_keypair().sign_v1(b"unused"),
        };
        let cert = SpcCert::Indirect {
            for_view: SpcView::new(2),
            target_view: SpcView::new(1),
            target_value: PcVector::empty(),
            target_proof: dummy_pc_qc3(),
            skip_sigs: vec![sig.clone(), sig].into(),
        };
        assert!(!verify_cert(&cert, SpcView::new(2), &net(), &ctx(), &c));
    }

    /// `build_indirect_cert` returns `None` on empty input.
    #[test]
    fn build_indirect_cert_returns_none_on_empty_input() {
        assert!(build_indirect_cert(SpcView::new(1), &[]).is_none());
    }

    /// `build_indirect_cert` returns `None` when an input message's
    /// `view` doesn't match `empty_view` — guards against the caller
    /// pooling skip statements from a different empty view.
    #[test]
    fn build_indirect_cert_rejects_mismatched_view() {
        let kp = generate_bls_keypair();
        let msg = SpcEmptyViewMsg {
            view: SpcView::new(2),
            reported: SpcHighTriple {
                view: SpcView::new(0),
                value: PcVector::empty(),
                proof: dummy_pc_qc3(),
            },
            signer: ValidatorId::new(0),
            sig: kp.sign_v1(b"unused"),
        };
        // Caller asks for empty_view = 3 but supplies a msg for view 2.
        assert!(build_indirect_cert(SpcView::new(3), std::slice::from_ref(&msg)).is_none());
    }

    /// `build_indirect_cert` picks the max-reported triple as target
    /// and assembles `skip_sigs` from every input.
    #[test]
    fn build_indirect_cert_targets_max_reported() {
        let kp_a = generate_bls_keypair();
        let kp_b = generate_bls_keypair();
        let kp_c = generate_bls_keypair();
        let mk = |signer: u64, reported_view: u32, sk: &_| SpcEmptyViewMsg {
            view: SpcView::new(5),
            reported: SpcHighTriple {
                view: SpcView::new(reported_view),
                value: PcVector::empty(),
                proof: dummy_pc_qc3(),
            },
            signer: ValidatorId::new(signer),
            sig: bls_sign_unused(sk),
        };
        let msgs = vec![mk(0, 2, &kp_a), mk(1, 4, &kp_b), mk(2, 3, &kp_c)];
        let cert = build_indirect_cert(SpcView::new(5), &msgs).expect("build succeeds");
        let SpcCert::Indirect {
            for_view,
            target_view,
            skip_sigs,
            ..
        } = cert
        else {
            panic!("expected Indirect");
        };
        assert_eq!(for_view, SpcView::new(6));
        assert_eq!(target_view, SpcView::new(4)); // max of {2,4,3}
        assert_eq!(skip_sigs.len(), 3);
    }

    fn bls_sign_unused(sk: &Bls12381G1PrivateKey) -> Bls12381G2Signature {
        sk.sign_v1(b"unused")
    }
}
