//! Strong Prefix Consensus (SPC) wire types and verifiers.
//!
//! SPC drives one slot through a sequence of views. Each view runs an
//! inner [`PcQc3`]-producing PC instance under a distinct domain
//! context; when a view fails (timeout, leader misbehaviour), `f+1`
//! committee members exchange [`SpcEmptyViewMsg`]s reporting their
//! latest verifiable high triple, and `f+1` such messages aggregate
//! into an indirect [`SpcCert`] that skips to a later view while
//! pinning the next leader to a specific [`SpcHighTriple`].
//!
//! Wire types live up top; the verify / sign / build helpers
//! ([`verify_cert`], [`verify_empty_view_msg`], [`sign_empty_view_msg`],
//! [`build_indirect_cert`], …) follow. The stateful FSM (parent
//! existence, proposal-object hashing, view scheduling) lives in the
//! beacon crate — it depends on local observed-proposal state these
//! pure verifiers can't see.
//!
//! # Soundness gates encoded in the verifiers
//!
//! - **Skip-sig binding to a specific reported value**: every skip
//!   statement signs `(empty_view, reported_view,
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

use blake3::Hasher;
use sbor::prelude::*;
use thiserror::Error;

use crate::{
    Bls12381G1PrivateKey, Bls12381G1PublicKey, Bls12381G2Signature, DOMAIN_PC_EMPTY_VIEW, Hash,
    NetworkDefinition, PcQc3, PcValueElement, PcVector, PositionalBundle, SignerBitfield,
    SpcContext, SpcView, ValidatorId, Verifiable, Verified, Verify,
    aggregate_verify_bls_different_messages, pc_context, pc_vote_signing_message, verify_qc3,
};

/// `(view, value, proof)` — a verifiable high triple.
///
/// Tracked locally as `max_high` by every SPC participant and reported
/// in [`SpcEmptyViewMsg`]s. The `proof` is the round-3 cert from the
/// PC instance that ran in `view` (`view`'s `pc_context` is derived
/// from the slot's SPC context and `view.to_le_bytes()`). Wire decode
/// lands `proof` as `Verifiable::Unverified`; locally-built triples
/// from [`Verified::<SpcHighTriple>::from_verified_proof`] preserve
/// the marker so the triple's verifier short-circuits the embedded
/// QC3 check.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SpcHighTriple {
    /// View this triple was produced in.
    pub view: SpcView,
    /// High value certified at `view`.
    pub value: PcVector,
    /// Round-3 cert from `view`'s inner PC instance, anchoring `value`.
    pub proof: Verifiable<PcQc3>,
}

/// Empty-view message — sent when a participant times out on `view`
/// without observing a leader proposal, reporting their current
/// `max_high` triple so the next leader can build an indirect cert.
///
/// `sig` is the sender's BLS signature over the canonical
/// `(skip_target, EmptyView_tag)` bytes for `view` and
/// `reported.view`. Aggregating `f+1` of these into an
/// [`SpcCert::Indirect`] authorises entry to view `view + 1`.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SpcEmptyViewMsg {
    /// The empty view.
    pub view: SpcView,
    /// Sender's current `max_high` triple.
    pub reported: SpcHighTriple,
    /// Sender's validator id.
    pub signer: ValidatorId,
    /// Sender's BLS signature over the empty-view signing bytes.
    pub sig: Bls12381G2Signature,
}

/// One signer's contribution to an [`SpcCert::Indirect`].
///
/// The signer attested that they observed `view = for_view - 1` as
/// empty and that their `max_high` at the time was `(reported_view,
/// reported_value)` — committed as a hash so the indirect cert points
/// to a *specific* high triple from a *specific* attestor, not any
/// arbitrary valid `PcQc3` at `reported_view`.
///
/// Validator identity is carried positionally by the enclosing
/// [`PositionalBundle`] in [`SpcCert::Indirect::skip_reports`]; the BLS
/// signature is folded into the cert-level
/// [`SpcCert::Indirect::skip_aggregate_sig`].
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SkipReport {
    /// View of the signer's `max_high` at the time of the skip.
    pub reported_view: SpcView,
    /// Content hash of the signer's reported high value.
    pub reported_value_hash: Hash,
}

/// Certificate authorising entry into an SPC view.
///
/// The two variants:
/// - [`Self::Direct`] is the previous view's verifiable high output —
///   the simple case where the previous view succeeded.
/// - [`Self::Indirect`] is `f+1` empty-view attestations bundled into
///   an indirect cert — when the previous view failed, the next
///   leader skips ahead by pointing at the maximum-view triple any of
///   the skip signers reported.
///
/// Genesis-block authentication is handled separately by
/// [`BeaconCert::Genesis`](crate::BeaconCert::Genesis), which carries
/// the operator-config hash directly; the SPC FSM never sees a
/// genesis-shaped cert.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub enum SpcCert {
    /// `cert^dir(prev_view, value, proof)` — the verifiable high
    /// output of `prev_view`, authorising entry to `prev_view + 1`.
    Direct {
        /// View whose output authorises the next view.
        prev_view: SpcView,
        /// Certified high value at `prev_view`.
        value: PcVector,
        /// Round-3 cert anchoring `value` in `prev_view`'s inner PC.
        /// Wire decode lands `Verifiable::Unverified`; locally-built
        /// certs from [`Verified::<SpcCert>::from_qc3_attestation`]
        /// preserve the marker.
        proof: Verifiable<PcQc3>,
    },
    /// `cert^ind(for_view - 1, (target_view, target_value,
    /// target_proof), Σ)` — `f+1` skip statements certify that view
    /// `for_view - 1` was empty; the cert points to a verifiable high
    /// triple at `target_view`, which is the maximum view index
    /// reported in `Σ`.
    Indirect {
        /// View this cert authorises entry to.
        for_view: SpcView,
        /// View of the parent triple — the maximum view in `skip_reports`.
        target_view: SpcView,
        /// Parent triple's high value at `target_view`.
        target_value: PcVector,
        /// Round-3 cert anchoring `target_value` in `target_view`'s
        /// inner PC. Wire decode lands `Verifiable::Unverified`;
        /// locally-built certs preserve the embedded marker.
        target_proof: Verifiable<PcQc3>,
        /// `Σ` — `f+1` skip statements, paired positionally with the
        /// signers' committee positions via the bundle's bitfield.
        skip_reports: PositionalBundle<SkipReport>,
        /// Different-messages BLS aggregate over each signer's BLS
        /// signature on their canonical skip-target bytes.
        skip_aggregate_sig: Bls12381G2Signature,
    },
}

/// `P_p,w` — the proposal object a leader sends to authorise entry to
/// view `view`. Pairs the cert with the view it authorises.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SpcProposalObject {
    /// View this proposal authorises entry to.
    pub view: SpcView,
    /// Cert backing the authorization.
    pub cert: SpcCert,
}

impl SpcCert {
    /// SBOR-encoded canonical bytes of this cert. Used by SPC
    /// proposal-object hashing to bind the cert into the input vector.
    ///
    /// # Panics
    ///
    /// Never in practice: every field is `BasicSbor` and the enum is
    /// closed, so encoding is total.
    #[must_use]
    pub fn encode_bytes(&self) -> Vec<u8> {
        basic_encode(self).expect("SpcCert SBOR encoding is infallible")
    }
}

// ─── Pure helpers ──────────────────────────────────────────────────────────

/// Domain tag for hashing a reported high triple's value into a 32-byte
/// digest. Keeps the digest distinct from any other Blake3 use of the
/// same `PcVector` bytes.
const HIGH_VALUE_DOMAIN: &[u8] = b"hyperscale-spc-high-value-v1";

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

/// Build the canonical "skip target" vector each empty-view skip
/// statement signs.
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
        PcValueElement::from_view_number(u64::from(empty_view.inner())),
        PcValueElement::from_view_number(u64::from(reported_view.inner())),
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

// ─── Verifiers ─────────────────────────────────────────────────────────────

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
    spc_ctx: &SpcContext,
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    let Some(pk) = pubkey_in_committee(committee, msg.signer) else {
        return false;
    };
    // Reported triple's PcQc3 must verify under the right view's PC ctx.
    // Short-circuit if the embedded marker is already live.
    let reported_pc_ctx = pc_context(spc_ctx, msg.reported.view);
    if msg.reported.proof.verified().is_none()
        && !verify_qc3(
            msg.reported.proof.as_unverified(),
            network,
            &reported_pc_ctx,
            committee,
        )
    {
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

/// Verify an [`SpcCert`] as a beacon-block authenticator, deriving
/// the cert's claimed view-entry from its own contents.
///
/// Direct certs authorise entry to `prev_view + 1`; indirect certs to
/// their `for_view`.
///
/// Use this when verifying an arbitrary cert as a standalone proof,
/// not when verifying a cert in the context of a known target view
/// (use [`verify_cert`] for that).
#[must_use]
pub fn verify_block_cert(
    cert: &SpcCert,
    network: &NetworkDefinition,
    spc_ctx: &SpcContext,
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    match cert {
        SpcCert::Direct { prev_view, .. } => {
            let Some(entering) = prev_view.inner().checked_add(1) else {
                return false;
            };
            verify_cert(cert, SpcView::new(entering), network, spc_ctx, committee)
        }
        SpcCert::Indirect { for_view, .. } => {
            verify_cert(cert, *for_view, network, spc_ctx, committee)
        }
    }
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
    spc_ctx: &SpcContext,
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
            skip_reports,
            skip_aggregate_sig,
        } => verify_indirect_cert(
            *for_view,
            *target_view,
            target_value,
            target_proof,
            skip_reports,
            *skip_aggregate_sig,
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
    proof: &Verifiable<PcQc3>,
    entering_view: SpcView,
    network: &NetworkDefinition,
    spc_ctx: &SpcContext,
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    // `prev_view + 1 == entering_view`, guarded against u32 overflow.
    let Some(expected) = prev_view.inner().checked_add(1) else {
        return false;
    };
    if expected != entering_view.inner() {
        return false;
    }
    // Short-circuit on the embedded QC3 marker.
    let pc_ctx = pc_context(spc_ctx, prev_view);
    if proof.verified().is_none() && !verify_qc3(proof.as_unverified(), network, &pc_ctx, committee)
    {
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
    target_proof: &Verifiable<PcQc3>,
    skip_reports: &PositionalBundle<SkipReport>,
    skip_aggregate_sig: Bls12381G2Signature,
    entering_view: SpcView,
    network: &NetworkDefinition,
    spc_ctx: &SpcContext,
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
    if skip_reports.len() < f + 1 {
        return false;
    }
    // Cert's target_view must equal max(reported_view) across Σ.
    let max_reported = skip_reports
        .iter()
        .map(|(_, r)| r.reported_view)
        .max()
        .expect("skip_reports non-empty by f+1 threshold");
    if target_view != max_reported {
        return false;
    }
    // Cert's target_value must hash to the value the max-reported
    // signer actually attested to.
    let target_value_hash = hash_high_value(target_value);
    let max_signer_attests = skip_reports.iter().any(|(_, r)| {
        r.reported_view == max_reported && r.reported_value_hash == target_value_hash
    });
    if !max_signer_attests {
        return false;
    }
    // Aggregate-verify every skip statement under each signer's pubkey
    // against the canonical skip-target bytes.
    let empty_view = SpcView::new(entering_view.inner() - 1);
    let mut pks: Vec<Bls12381G1PublicKey> = Vec::with_capacity(skip_reports.len());
    let mut messages_owned: Vec<Vec<u8>> = Vec::with_capacity(skip_reports.len());
    for (idx, report) in skip_reports.iter() {
        let Some((_, pk)) = committee.get(idx) else {
            return false;
        };
        let target = skip_target(empty_view, report.reported_view, report.reported_value_hash);
        messages_owned.push(pc_vote_signing_message(
            network,
            DOMAIN_PC_EMPTY_VIEW,
            spc_ctx,
            &target,
        ));
        pks.push(*pk);
    }
    let messages: Vec<&[u8]> = messages_owned.iter().map(Vec::as_slice).collect();
    if !aggregate_verify_bls_different_messages(&messages, &skip_aggregate_sig, &pks) {
        return false;
    }
    // Target proof verifies under target_view's PC ctx, and its x_pe
    // matches the claimed target_value. Short-circuit on the embedded
    // QC3 marker.
    let target_pc_ctx = pc_context(spc_ctx, target_view);
    if target_proof.verified().is_none()
        && !verify_qc3(
            target_proof.as_unverified(),
            network,
            &target_pc_ctx,
            committee,
        )
    {
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
    spc_ctx: &SpcContext,
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
/// reconstruct the canonical preimage on aggregation.
#[must_use]
pub fn sign_empty_view_msg(
    sk: &Bls12381G1PrivateKey,
    signer: ValidatorId,
    network: &NetworkDefinition,
    spc_ctx: &SpcContext,
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
/// [`verify_empty_view_msg`] before pooling). `committee` is required
/// to resolve `ValidatorId`s to positional bits in the cert's signer
/// bitfield. The cert targets the triple whose `reported_view` is the
/// maximum across the inputs — per the protocol invariant — and folds
/// every signer's individual BLS sig into a single different-messages
/// aggregate.
///
/// Returns `None` when:
/// - `empty_view_msgs` is empty (no skip statements to aggregate)
/// - `empty_view + 1` overflows the `SpcView` u32
/// - any input message's `view` differs from `empty_view` (caller
///   passed mismatched skip statements)
/// - any input message's signer is not present in `committee`
///
/// Doesn't enforce `f + 1` threshold here — the verifier rejects
/// short sets, but callers typically pool until they have `f + 1`
/// before invoking this.
#[must_use]
pub fn build_indirect_cert(
    empty_view: SpcView,
    empty_view_msgs: &[SpcEmptyViewMsg],
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
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

    let n = committee.len();
    let mut signers_bf = SignerBitfield::new(n);
    let mut indexed: Vec<(usize, SkipReport, Bls12381G2Signature)> =
        Vec::with_capacity(empty_view_msgs.len());
    for m in empty_view_msgs {
        let pos = committee.iter().position(|(id, _)| *id == m.signer)?;
        if signers_bf.is_set(pos) {
            continue;
        }
        signers_bf.set(pos);
        let report = SkipReport {
            reported_view: m.reported.view,
            reported_value_hash: hash_high_value(&m.reported.value),
        };
        indexed.push((pos, report, m.sig));
    }
    indexed.sort_by_key(|(pos, _, _)| *pos);
    let reports: Vec<SkipReport> = indexed.iter().map(|(_, r, _)| r.clone()).collect();
    let sigs: Vec<Bls12381G2Signature> = indexed.iter().map(|(_, _, s)| *s).collect();
    let skip_aggregate_sig = Bls12381G2Signature::aggregate(&sigs, true).ok()?;

    Some(SpcCert::Indirect {
        for_view,
        target_view,
        target_value,
        target_proof,
        skip_reports: PositionalBundle::new(signers_bf, reports),
        skip_aggregate_sig,
    })
}

// ─── Typestate ─────────────────────────────────────────────────────────────

/// Shared verification context for SPC wire types.
///
/// Bundles the per-instance binding context (`network`, `spc_ctx`) with
/// the committee that every signer must be drawn from. The Verify impls
/// for [`SpcEmptyViewMsg`] / [`SpcCert`] / [`SpcProposalObject`] /
/// [`SpcHighTriple`] all take this context.
#[derive(Debug, Clone, Copy)]
pub struct SpcVerifyContext<'a> {
    /// Network the signer was bound to.
    pub network: &'a NetworkDefinition,
    /// Canonical signing context for this `epoch`.
    pub spc_ctx: &'a SpcContext,
    /// Committee membership and pubkeys.
    pub committee: &'a [(ValidatorId, Bls12381G1PublicKey)],
}

/// Coarse-grained verification failure for an empty-view attestation.
///
/// Failure modes (signer membership, embedded QC3 mismatch, value-hash
/// mismatch, BLS sig check) are summarized into one variant; the
/// rejection log line records the specific reason.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("SpcEmptyViewMsg verification failed")]
pub struct SpcEmptyViewMsgVerifyError;

/// Coarse-grained verification failure for an SPC cert (Direct or
/// Indirect).
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("SpcCert verification failed")]
pub struct SpcCertVerifyError;

/// Coarse-grained verification failure for an SPC proposal object.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("SpcProposalObject verification failed")]
pub struct SpcProposalObjectVerifyError;

/// Coarse-grained verification failure for a high triple.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("SpcHighTriple verification failed")]
pub struct SpcHighTripleVerifyError;

impl Verify<&SpcVerifyContext<'_>> for SpcEmptyViewMsg {
    type Error = SpcEmptyViewMsgVerifyError;

    fn verify(&self, ctx: &SpcVerifyContext<'_>) -> Result<Verified<Self>, Self::Error> {
        if verify_empty_view_msg(self, ctx.network, ctx.spc_ctx, ctx.committee) {
            Ok(Verified::new_unchecked(self.clone()))
        } else {
            Err(SpcEmptyViewMsgVerifyError)
        }
    }
}

impl Verify<&SpcVerifyContext<'_>> for SpcCert {
    type Error = SpcCertVerifyError;

    /// Verifies as a beacon-block authenticator: derives the cert's
    /// claimed view-entry from the cert's own contents (Direct →
    /// `prev_view + 1`; Indirect → `for_view`).
    fn verify(&self, ctx: &SpcVerifyContext<'_>) -> Result<Verified<Self>, Self::Error> {
        if verify_block_cert(self, ctx.network, ctx.spc_ctx, ctx.committee) {
            Ok(Verified::new_unchecked(self.clone()))
        } else {
            Err(SpcCertVerifyError)
        }
    }
}

impl Verify<&SpcVerifyContext<'_>> for SpcProposalObject {
    type Error = SpcProposalObjectVerifyError;

    fn verify(&self, ctx: &SpcVerifyContext<'_>) -> Result<Verified<Self>, Self::Error> {
        if verify_proposal_object(self, ctx.network, ctx.spc_ctx, ctx.committee) {
            Ok(Verified::new_unchecked(self.clone()))
        } else {
            Err(SpcProposalObjectVerifyError)
        }
    }
}

impl Verify<&SpcVerifyContext<'_>> for SpcHighTriple {
    type Error = SpcHighTripleVerifyError;

    /// High-triple predicate: embedded `proof` verifies under
    /// `pc_context(spc_ctx, view)` and `proof.x_pe() == value`.
    /// Short-circuits the embedded QC3 check when its marker is live.
    fn verify(&self, ctx: &SpcVerifyContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let pc_ctx = pc_context(ctx.spc_ctx, self.view);
        if self.proof.verified().is_none()
            && !verify_qc3(
                self.proof.as_unverified(),
                ctx.network,
                &pc_ctx,
                ctx.committee,
            )
        {
            return Err(SpcHighTripleVerifyError);
        }
        if self.proof.x_pe() != &self.value {
            return Err(SpcHighTripleVerifyError);
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

// ─── Named gates ────────────────────────────────────────────────────────────

impl Verified<SpcEmptyViewMsg> {
    /// Sign an empty-view attestation locally over a verified high
    /// triple. The signer's own sig holds by definition under the
    /// private key; the embedded reported triple was already verified
    /// upstream, so the produced message is verified by construction.
    #[must_use]
    pub fn sign_local(
        sk: &Bls12381G1PrivateKey,
        signer: ValidatorId,
        network: &NetworkDefinition,
        spc_ctx: &SpcContext,
        empty_view: SpcView,
        reported: Verified<SpcHighTriple>,
    ) -> Self {
        Self::new_unchecked(sign_empty_view_msg(
            sk,
            signer,
            network,
            spc_ctx,
            empty_view,
            reported.into_inner(),
        ))
    }
}

impl Verified<SpcCert> {
    /// Build a verified [`SpcCert::Direct`] from a verified round-3
    /// attestation. The high value is extracted from `proof.x_pe()`;
    /// the embedded marker rides through to the cert's `proof` field.
    #[must_use]
    pub fn from_qc3_attestation(prev_view: SpcView, proof: Verified<PcQc3>) -> Self {
        let value = proof.x_pe().clone();
        Self::new_unchecked(SpcCert::Direct {
            prev_view,
            value,
            proof: Verifiable::from(proof),
        })
    }

    /// Aggregate verified empty-view attestations into a verified
    /// [`SpcCert::Indirect`]. Mirror of
    /// [`Verified::<PcQc1>::from_verified_votes`]. Returns `None` on the
    /// same conditions as [`build_indirect_cert`].
    #[must_use]
    pub fn from_skip_reports(
        empty_view: SpcView,
        empty_view_msgs: &[&Verified<SpcEmptyViewMsg>],
        committee: &[(ValidatorId, Bls12381G1PublicKey)],
    ) -> Option<Self> {
        let raw: Vec<SpcEmptyViewMsg> = empty_view_msgs
            .iter()
            .map(|m| (*m).as_ref().clone())
            .collect();
        build_indirect_cert(empty_view, &raw, committee).map(Self::new_unchecked)
    }

    /// Wrap a locally-assembled cert whose backing inputs were verified
    /// upstream. Trust source: the FSM produced the cert from already-
    /// verified PC votes / empty-view msgs and the assembly path is
    /// deterministic. Used at the bridge from the SPC FSM (which holds
    /// raw `SpcCert`) to coordinator-side admission.
    #[must_use]
    pub const fn from_local_build(cert: SpcCert) -> Self {
        Self::new_unchecked(cert)
    }
}

impl Verified<SpcProposalObject> {
    /// Pair a verified cert with the view it authorises. The verifier
    /// predicate is `verify_cert(po.cert, po.view, ...)`; passing in a
    /// `Verified<SpcCert>` plus the matching `view` directly satisfies
    /// it.
    #[must_use]
    pub fn from_verified_cert(view: SpcView, cert: Verified<SpcCert>) -> Self {
        Self::new_unchecked(SpcProposalObject {
            view,
            cert: cert.into_inner(),
        })
    }
}

impl Verified<SpcHighTriple> {
    /// Build a verified high triple from a verified round-3 attestation.
    /// The high value is extracted from `proof.x_pe()`; the embedded
    /// marker rides through to the triple's `proof` field.
    #[must_use]
    pub fn from_verified_proof(view: SpcView, proof: Verified<PcQc3>) -> Self {
        let value = proof.x_pe().clone();
        Self::new_unchecked(SpcHighTriple {
            view,
            value,
            proof: Verifiable::from(proof),
        })
    }

    /// Wrap a locally-built high triple whose backing inputs were
    /// already verified upstream. Mirror of
    /// [`Verified::<PcQc1>::from_local_build`].
    #[must_use]
    pub const fn from_local_build(triple: SpcHighTriple) -> Self {
        Self::new_unchecked(triple)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PcQc2, PcSignerLengths, PcValueElement, PcXpProof, SignerBitfield};

    fn sample_pc_qc3() -> PcQc3 {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        let qc2 = PcQc2::new(
            PcVector::empty(),
            signers.clone(),
            Bls12381G2Signature([0x11; 96]),
            PcXpProof::Full,
        );
        PcQc3::new(
            PcVector::empty(),
            qc2,
            None,
            None,
            signers,
            PcSignerLengths::Uniform(0),
            Bls12381G2Signature([0x33; 96]),
        )
    }

    fn sample_pc_vector(len: u8) -> PcVector {
        PcVector::new((0..len).map(|n| PcValueElement::new([n; 32])))
    }

    fn sample_high_triple() -> SpcHighTriple {
        SpcHighTriple {
            view: SpcView::new(3),
            value: sample_pc_vector(2),
            proof: sample_pc_qc3().into(),
        }
    }

    #[test]
    fn high_triple_sbor_round_trip() {
        let t = sample_high_triple();
        let bytes = basic_encode(&t).unwrap();
        let decoded: SpcHighTriple = basic_decode(&bytes).unwrap();
        assert_eq!(t, decoded);
    }

    #[test]
    fn empty_view_msg_sbor_round_trip() {
        let m = SpcEmptyViewMsg {
            view: SpcView::new(5),
            reported: sample_high_triple(),
            signer: ValidatorId::new(2),
            sig: Bls12381G2Signature([0x44; 96]),
        };
        let bytes = basic_encode(&m).unwrap();
        let decoded: SpcEmptyViewMsg = basic_decode(&bytes).unwrap();
        assert_eq!(m, decoded);
    }

    #[test]
    fn cert_direct_sbor_round_trip() {
        let c = SpcCert::Direct {
            prev_view: SpcView::new(2),
            value: sample_pc_vector(3),
            proof: sample_pc_qc3().into(),
        };
        let bytes = basic_encode(&c).unwrap();
        let decoded: SpcCert = basic_decode(&bytes).unwrap();
        assert_eq!(c, decoded);
    }

    #[test]
    fn cert_indirect_sbor_round_trip() {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        let reports = vec![
            SkipReport {
                reported_view: SpcView::new(3),
                reported_value_hash: Hash::from_bytes(b"value-a"),
            },
            SkipReport {
                reported_view: SpcView::new(4),
                reported_value_hash: Hash::from_bytes(b"value-b"),
            },
        ];
        let c = SpcCert::Indirect {
            for_view: SpcView::new(5),
            target_view: SpcView::new(4),
            target_value: sample_pc_vector(2),
            target_proof: sample_pc_qc3().into(),
            skip_reports: PositionalBundle::new(signers, reports),
            skip_aggregate_sig: Bls12381G2Signature([0xCC; 96]),
        };
        let bytes = basic_encode(&c).unwrap();
        let decoded: SpcCert = basic_decode(&bytes).unwrap();
        assert_eq!(c, decoded);
    }

    #[test]
    fn proposal_object_sbor_round_trip() {
        let p = SpcProposalObject {
            view: SpcView::new(2),
            cert: SpcCert::Direct {
                prev_view: SpcView::new(1),
                value: sample_pc_vector(1),
                proof: sample_pc_qc3().into(),
            },
        };
        let bytes = basic_encode(&p).unwrap();
        let decoded: SpcProposalObject = basic_decode(&bytes).unwrap();
        assert_eq!(p, decoded);
    }

    // ─── Verifier / builder tests ──────────────────────────────────────

    use crate::{Epoch, generate_bls_keypair, spc_context};

    fn committee(n: usize) -> Vec<(ValidatorId, Bls12381G1PublicKey)> {
        (0..n as u64)
            .map(|i| (ValidatorId::new(i), generate_bls_keypair().public_key()))
            .collect()
    }

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn ctx() -> SpcContext {
        spc_context(Epoch::new(1))
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

    /// Direct cert with `prev_view + 1 != entering_view` is rejected
    /// before any pairing — the view-arithmetic gate.
    #[test]
    fn verify_direct_cert_rejects_view_mismatch() {
        let c = committee(4);
        let cert = SpcCert::Direct {
            prev_view: SpcView::new(3),
            value: PcVector::empty(),
            proof: sample_pc_qc3().into(),
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
            target_proof: sample_pc_qc3().into(),
            skip_reports: PositionalBundle::empty(),
            skip_aggregate_sig: generate_bls_keypair().sign_v1(b"unused"),
        };
        assert!(!verify_cert(&cert, SpcView::new(1), &net(), &ctx(), &c));
    }

    /// Indirect cert with fewer than `f + 1` skip reports is rejected.
    #[test]
    fn verify_indirect_cert_rejects_under_quorum() {
        let c = committee(4); // n=4, f=1, threshold f+1=2.
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        let reports = vec![SkipReport {
            reported_view: SpcView::new(1),
            reported_value_hash: Hash::ZERO,
        }];
        let cert = SpcCert::Indirect {
            for_view: SpcView::new(2),
            target_view: SpcView::new(1),
            target_value: PcVector::empty(),
            target_proof: sample_pc_qc3().into(),
            skip_reports: PositionalBundle::new(signers, reports),
            skip_aggregate_sig: generate_bls_keypair().sign_v1(b"unused"),
        };
        assert!(!verify_cert(&cert, SpcView::new(2), &net(), &ctx(), &c));
    }

    /// `build_indirect_cert` returns `None` on empty input.
    #[test]
    fn build_indirect_cert_returns_none_on_empty_input() {
        let c = committee(4);
        assert!(build_indirect_cert(SpcView::new(1), &[], &c).is_none());
    }

    /// `build_indirect_cert` returns `None` when an input message's
    /// `view` doesn't match `empty_view` — guards against the caller
    /// pooling skip statements from a different empty view.
    #[test]
    fn build_indirect_cert_rejects_mismatched_view() {
        let c = committee(4);
        let kp = generate_bls_keypair();
        let msg = SpcEmptyViewMsg {
            view: SpcView::new(2),
            reported: SpcHighTriple {
                view: SpcView::new(0),
                value: PcVector::empty(),
                proof: sample_pc_qc3().into(),
            },
            signer: ValidatorId::new(0),
            sig: kp.sign_v1(b"unused"),
        };
        // Caller asks for empty_view = 3 but supplies a msg for view 2.
        assert!(build_indirect_cert(SpcView::new(3), std::slice::from_ref(&msg), &c).is_none());
    }

    /// `build_indirect_cert` picks the max-reported triple as target
    /// and assembles a populated `skip_reports` bundle from every input.
    #[test]
    fn build_indirect_cert_targets_max_reported() {
        let c = committee(4);
        let kp_a = generate_bls_keypair();
        let kp_b = generate_bls_keypair();
        let kp_c = generate_bls_keypair();
        let mk = |signer: u64, reported_view: u32, sk: &Bls12381G1PrivateKey| SpcEmptyViewMsg {
            view: SpcView::new(5),
            reported: SpcHighTriple {
                view: SpcView::new(reported_view),
                value: PcVector::empty(),
                proof: sample_pc_qc3().into(),
            },
            signer: ValidatorId::new(signer),
            sig: sk.sign_v1(b"unused"),
        };
        let msgs = vec![mk(0, 2, &kp_a), mk(1, 4, &kp_b), mk(2, 3, &kp_c)];
        let cert = build_indirect_cert(SpcView::new(5), &msgs, &c).expect("build succeeds");
        let SpcCert::Indirect {
            for_view,
            target_view,
            skip_reports,
            ..
        } = cert
        else {
            panic!("expected Indirect");
        };
        assert_eq!(for_view, SpcView::new(6));
        assert_eq!(target_view, SpcView::new(4)); // max of {2,4,3}
        assert_eq!(skip_reports.len(), 3);
    }
}
