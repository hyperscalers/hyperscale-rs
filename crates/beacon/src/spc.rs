//! Strong Prefix Consensus — pure verifiers + signing helpers.
//!
//! SPC drives one epoch through a sequence of views. Each view runs an
//! inner PC instance under `pc_context(spc_context(epoch), view)`; the
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

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use blake3::Hasher;
use hyperscale_types::{
    Bls12381G1PrivateKey, Bls12381G1PublicKey, Bls12381G2Signature, DOMAIN_PC_EMPTY_VIEW, Epoch,
    Hash, NetworkDefinition, PC_VALUE_ELEMENT_BYTES, PcQc1, PcQc2, PcQc3, PcValueElement, PcVector,
    PcVoteEquivocation, PositionalBundle, SignerBitfield, SkipReport, SpcCert, SpcEmptyLowEvidence,
    SpcEmptyViewMsg, SpcHighTriple, SpcMessage, SpcProposalObject, SpcView, ValidatorId,
    VpcMsgPayload, aggregate_verify_bls_different_messages, pc_context, pc_vote_signing_message,
    spc_context,
};

use crate::pc::{PcEffect, PcEvent, PcInstance, verify_qc3};

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

/// Verify an [`SpcCert`] as a beacon-block authenticator, deriving
/// the cert's claimed view-entry from its own contents.
///
/// Direct certs authorise entry to `prev_view + 1`; indirect certs to
/// their `for_view`. Genesis certs aren't SPC view-entries and are
/// rejected here — beacon-block genesis verification has its own path.
///
/// Use this when verifying an arbitrary cert as a standalone proof,
/// not when verifying a cert in the context of a known target view
/// (use [`verify_cert`] for that).
#[must_use]
pub fn verify_block_cert(
    cert: &SpcCert,
    network: &NetworkDefinition,
    spc_ctx: &[u8],
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    match cert {
        SpcCert::Genesis { .. } => false,
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
    spc_ctx: &[u8],
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    match cert {
        // Genesis isn't a real SPC view-entry cert — it's a chain
        // bootstrap. Rejecting here means the SPC FSM can't be tricked
        // into accepting a Genesis cert as a view-entry authorisation;
        // genesis-block verification has its own path.
        SpcCert::Genesis { .. } => false,
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
    skip_reports: &PositionalBundle<SkipReport>,
    skip_aggregate_sig: Bls12381G2Signature,
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

// ─── Proposal-object hashing ───────────────────────────────────────────────

/// Canonical bytes for an [`SpcProposalObject`] — the preimage of
/// [`hash_proposal_object`]. Layout: `domain || view (4 LE) || cert
/// (SBOR)`. Not signed; consumed only by the proposal-hash → input-
/// vector pipeline.
fn proposal_object_message(po: &SpcProposalObject) -> Vec<u8> {
    const DOMAIN: &[u8] = b"hyperscale-spc-proposal-object-v1";
    let mut buf = Vec::with_capacity(DOMAIN.len() + 4 + 256);
    buf.extend_from_slice(DOMAIN);
    buf.extend_from_slice(&po.view.to_le_bytes());
    buf.extend_from_slice(&po.cert.encode_bytes());
    buf
}

/// All-zero sentinel element used in compute-view-input vectors to mark
/// "no proposal object from this party yet". Cleared from the hashed
/// digest space by [`hash_proposal_object`]'s collision-avoidance
/// rehash so a real proposal object can never hash to it.
const HASH_BOTTOM: PcValueElement = PcValueElement::new([0u8; PC_VALUE_ELEMENT_BYTES]);

/// Blake3-hash a proposal object into a `PcValueElement` suitable for
/// the inner-PC input vector at the next view. The fallback rehash
/// avoids accidental collision with [`HASH_BOTTOM`]: if the natural
/// digest happens to land on all-zeros, a tag-prefixed rehash moves
/// it elsewhere while preserving full collision resistance against
/// other inputs.
fn hash_proposal_object(po: &SpcProposalObject) -> PcValueElement {
    let bytes = proposal_object_message(po);
    let mut raw = [0u8; PC_VALUE_ELEMENT_BYTES];
    raw.copy_from_slice(Hasher::new().update(&bytes).finalize().as_bytes());
    if PcValueElement::new(raw) == HASH_BOTTOM {
        let mut h2 = Hasher::new();
        h2.update(b"hyperscale-spc-proposal-bottom-collision-v1");
        h2.update(&raw);
        raw.copy_from_slice(h2.finalize().as_bytes());
    }
    PcValueElement::new(raw)
}

/// `Parent(view, value)` — walk a value vector's first non-bottom
/// element to its proposal-object preimage, returning the cert's
/// parent `(view, value)`. Used by [`commit`] to chain back to view
/// 1.
///
/// `view = 1` has no parent (returns `None`).
fn parent_of(
    view: SpcView,
    value: &PcVector,
    proposals: &BTreeMap<PcValueElement, SpcProposalObject>,
) -> Option<(SpcView, PcVector)> {
    if view.inner() == 1 {
        return None;
    }
    for el in value.iter() {
        if *el != HASH_BOTTOM
            && let Some(po) = proposals.get(el)
        {
            return Some(match &po.cert {
                SpcCert::Direct {
                    prev_view, value, ..
                } => (*prev_view, value.clone()),
                SpcCert::Indirect {
                    target_view,
                    target_value,
                    ..
                } => (*target_view, target_value.clone()),
                // Genesis certs never ride in SPC proposal objects;
                // the FSM rejects them at ingestion. Unreachable here.
                SpcCert::Genesis { .. } => return None,
            });
        }
    }
    None
}

/// `HasParent(view, value)`: view 1 always has a parent (the genesis
/// boundary); view ≥ 2 needs the first non-bottom hash in `value` to
/// reference a known proposal object.
fn has_parent(
    view: SpcView,
    value: &PcVector,
    proposals: &BTreeMap<PcValueElement, SpcProposalObject>,
) -> bool {
    view.inner() == 1 || parent_of(view, value, proposals).is_some()
}

/// Extract a cert's referenced high triple — the triple `max_high`
/// should update to on cert acceptance. Direct certs reference their
/// own `(prev_view, value, proof)`; indirect certs reference the
/// `(target_view, target_value, target_proof)` triple.
///
/// # Panics
///
/// Panics on [`SpcCert::Genesis`] — the SPC FSM rejects Genesis certs
/// at ingestion, so callers must never reach this function with one.
fn referenced_triple(cert: &SpcCert) -> SpcHighTriple {
    match cert {
        SpcCert::Genesis { .. } => {
            panic!("referenced_triple: SpcCert::Genesis not valid inside SPC FSM")
        }
        SpcCert::Direct {
            prev_view,
            value,
            proof,
        } => SpcHighTriple {
            view: *prev_view,
            value: value.clone(),
            proof: proof.clone(),
        },
        SpcCert::Indirect {
            target_view,
            target_value,
            target_proof,
            ..
        } => SpcHighTriple {
            view: *target_view,
            value: target_value.clone(),
            proof: target_proof.clone(),
        },
    }
}

// ─── FSM ───────────────────────────────────────────────────────────────────

/// What [`SpcInstance::handle`] tells its parent.
///
/// Sub-machine-local — the parent (the `BeaconCoordinator`) drains
/// these and lifts them into either internal state mutations or
/// further effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpcEffect {
    /// Sign a round-1 inner-PC vote over `v_in` (under `view`'s PC
    /// context) and broadcast it to the SPC committee.
    SignAndBroadcastPcVote1 {
        /// SPC view the vote belongs to.
        view: SpcView,
        /// Input vector to be signed as `v_in`.
        v_in: PcVector,
    },
    /// Sign a round-2 inner-PC vote derived from `qc1` and broadcast.
    SignAndBroadcastPcVote2 {
        /// SPC view the vote belongs to.
        view: SpcView,
        /// Source round-1 QC the round-2 vote is built from.
        qc1: Box<PcQc1>,
    },
    /// Sign a round-3 inner-PC vote derived from `qc2` and broadcast.
    SignAndBroadcastPcVote3 {
        /// SPC view the vote belongs to.
        view: SpcView,
        /// Source round-2 QC the round-3 vote is built from.
        qc2: Box<PcQc2>,
    },
    /// Broadcast a `new-view` to peers — we just entered `view` under
    /// `cert`.
    BroadcastNewView {
        /// View this notification authorises entry to.
        view: SpcView,
        /// Cert backing the authorisation.
        cert: Box<SpcCert>,
    },
    /// Broadcast a `new-commit` to peers — `view`'s inner PC produced
    /// the (low, proof) pair, anchoring the commit walk.
    BroadcastNewCommit {
        /// View whose inner PC produced this commit.
        view: SpcView,
        /// Committed low value.
        value: PcVector,
        /// PC round-3 cert anchoring `value` as `proof.x_pp`.
        proof: Box<PcQc3>,
    },
    /// Pass-through of an inner-PC equivocation, tagged with the SPC
    /// view so the parent can reconstruct the inner PC context.
    Equivocation {
        /// SPC view the inner PC instance belonged to.
        view: SpcView,
        /// Slim wire-form evidence of the double-sign.
        evidence: Box<PcVoteEquivocation>,
    },
    /// View `> 1` produced an empty low — surface evidence to the
    /// parent for downstream handling.
    EmptyLowEvidence(Box<SpcEmptyLowEvidence>),
    /// Sign an empty-view attestation reporting `reported` as our
    /// max high triple and broadcast it — we produced a high output
    /// at `view` but our local table can't resolve its parent, so
    /// we fall back to the view-change path. The signed message
    /// lands back on the FSM via the same `SpcEvent::EmptyView` path
    /// peer messages use.
    SignAndBroadcastEmptyView {
        /// View this empty-view attestation skips.
        view: SpcView,
        /// Our locally-known max high triple at the time of emission.
        /// Boxed to keep [`SpcEffect`] compact — `SpcHighTriple`
        /// embeds a full `PcQc3`.
        reported: Box<SpcHighTriple>,
    },
    /// Schedule a view-timeout timer. The parent fires
    /// [`SpcEvent::TimerExpired`] when it elapses.
    SetTimer {
        /// View this timer is scoped to.
        view: SpcView,
        /// How long to wait before firing.
        duration: Duration,
    },
    /// Agreed high output — terminal effect for this SPC instance.
    /// `cert` is the [`SpcCert::Direct`] that proves view 1's PC
    /// produced this high; it authenticates the resulting beacon block.
    OutputHigh {
        /// Committed high vector.
        value: PcVector,
        /// Authenticating cert.
        cert: Box<SpcCert>,
    },
}

/// Events [`SpcInstance::handle`] consumes.
#[derive(Debug, Clone)]
pub enum SpcEvent {
    /// The local validator's input vector for view 1.
    Input(PcVector),
    /// An inner-PC vote arrived, tagged with the SPC view.
    VpcMsg(Box<VpcMsgPayload>),
    /// `new-view` from a peer entering `view` under `cert`.
    ///
    /// `from` is the transport-level sender id. `NewView` isn't
    /// sender-signed (the cert authenticates the parent claim
    /// cryptographically), so `from` only determines which validator's
    /// proposal-object epoch this `NewView` fills. Two distinct valid
    /// certs from the same `from` are valid relays, not equivocation —
    /// last-write-wins.
    NewView {
        /// Validator that relayed this notification.
        from: ValidatorId,
        /// View the peer entered.
        view: SpcView,
        /// Cert backing the entry.
        cert: Box<SpcCert>,
    },
    /// `new-commit` from a peer. Self-authenticating via the embedded
    /// `proof`; sender label isn't load-bearing.
    NewCommit {
        /// View whose inner PC produced this commit.
        view: SpcView,
        /// Committed low value.
        value: PcVector,
        /// PC round-3 cert anchoring `value` as `proof.x_pp`.
        proof: Box<PcQc3>,
    },
    /// `empty-view` attestation from a peer.
    EmptyView(Box<SpcEmptyViewMsg>),
    /// Timer for `view` fired — its leader's grace period elapsed.
    /// Drives `RunVPC(view)` even on a partial proposal-object
    /// buffer so a silent leader can't stall the view indefinitely.
    TimerExpired {
        /// View whose timer fired.
        view: SpcView,
    },
}

impl SpcEvent {
    /// Reconstruct a [`SpcEvent`] from a wire [`SpcMessage`] and the
    /// transport-level sender id. `from` only affects routing of
    /// `NewView` (it determines which validator's proposal-object
    /// epoch to fill); the other variants are sender-independent.
    #[must_use]
    pub fn from_message(msg: SpcMessage, from: ValidatorId) -> Self {
        match msg {
            SpcMessage::VpcMsg(payload) => Self::VpcMsg(payload),
            SpcMessage::NewView { view, cert } => Self::NewView { from, view, cert },
            SpcMessage::NewCommit { view, value, proof } => Self::NewCommit { view, value, proof },
            SpcMessage::EmptyView(msg) => Self::EmptyView(msg),
        }
    }
}

/// Per-view local state owned by [`SpcInstance`].
struct ViewState {
    vpc: PcInstance,
    proposal_objects: BTreeMap<ValidatorId, SpcProposalObject>,
    vpc_input_fed: bool,
    /// `Q_i,w` — empty-view messages collected for this view,
    /// indexed by signer. At `f + 1` we form the indirect cert.
    empty_views: BTreeMap<ValidatorId, SpcEmptyViewMsg>,
    /// Latched once we've assembled and broadcast an indirect cert
    /// from this view's empty-views.
    indirect_cert_built: bool,
    /// Whether we've broadcast our own empty-view for this view.
    empty_view_broadcast: bool,
}

impl ViewState {
    fn new(
        network: NetworkDefinition,
        epoch: Epoch,
        view: SpcView,
        committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    ) -> Self {
        Self {
            vpc: PcInstance::new(network, epoch, view, committee),
            proposal_objects: BTreeMap::new(),
            vpc_input_fed: false,
            empty_views: BTreeMap::new(),
            indirect_cert_built: false,
            empty_view_broadcast: false,
        }
    }
}

/// Bound on `pending_empty_views` memory: at most
/// `MAX_PENDING_EMPTY_VIEW_AHEAD × n` entries. Beyond this we drop —
/// the message is far enough ahead of `current_view` that catching
/// up via state-sync is the right move.
const MAX_PENDING_EMPTY_VIEW_AHEAD: u32 = 4;

/// One SPC FSM instance, scoped to a single epoch.
///
/// Owns one inner PC instance per view it enters. The
/// `BeaconCoordinator` drives one `SpcInstance` per epoch. Handles
/// both the happy path (view 1 input → view 2 cert → commit) and
/// view-change (empty-view attestations → indirect cert → skip
/// ahead).
pub struct SpcInstance {
    network: NetworkDefinition,
    epoch: Epoch,
    spc_ctx: Vec<u8>,
    committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    me: ValidatorId,
    view_timeout: Duration,

    current_view: SpcView,
    views: BTreeMap<SpcView, ViewState>,
    proposals_by_hash: BTreeMap<PcValueElement, SpcProposalObject>,
    new_commit_broadcast: BTreeSet<SpcView>,
    max_high: Option<SpcHighTriple>,

    /// Empty-view messages we've sig-/Qc3-validated but couldn't admit
    /// yet because `has_parent` failed at receipt. Keyed by `msg.view`
    /// then sender. Re-scanned after every `enter_view` so a missing-
    /// parent message that arrives ahead of its parent proposal-object
    /// still counts toward the `f + 1` indirect-cert threshold once
    /// the gap closes.
    pending_empty_views: BTreeMap<SpcView, BTreeMap<ValidatorId, SpcEmptyViewMsg>>,

    low_output: Option<PcVector>,
    high_output: Option<PcVector>,
    /// Cert authenticating the eventual high output — stashed in
    /// `on_vpc_output_high` for view 1's PC output, retrieved by
    /// `commit()` when the walk reaches view-1's parent and emits
    /// [`SpcEffect::OutputHigh`].
    high_decisive_cert: Option<SpcCert>,
}

impl SpcInstance {
    /// Construct a fresh SPC instance for `epoch`. Creates the view-1
    /// `PcInstance` eagerly.
    ///
    /// `view_timeout` is the duration the parent (the
    /// `BeaconCoordinator`) is asked to wait between `SetTimer { view }`
    /// and `TimerExpired { view }` firing — the `2Δ` cap on a view's
    /// leader-proposal grace period before participants exchange
    /// empty-views and skip ahead.
    ///
    /// # Panics
    ///
    /// Panics if `committee.len() < 4` (inherited from `PcInstance`).
    #[must_use]
    pub fn new(
        network: NetworkDefinition,
        epoch: Epoch,
        committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
        me: ValidatorId,
        view_timeout: Duration,
    ) -> Self {
        let spc_ctx = spc_context(epoch);
        let mut views = BTreeMap::new();
        views.insert(
            SpcView::new(1),
            ViewState::new(network.clone(), epoch, SpcView::new(1), committee.clone()),
        );
        Self {
            network,
            epoch,
            spc_ctx,
            committee,
            me,
            view_timeout,
            current_view: SpcView::new(1),
            views,
            proposals_by_hash: BTreeMap::new(),
            new_commit_broadcast: BTreeSet::new(),
            max_high: None,
            pending_empty_views: BTreeMap::new(),
            low_output: None,
            high_output: None,
            high_decisive_cert: None,
        }
    }

    /// Epoch this SPC instance drives consensus for.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Highest view this instance has entered.
    #[must_use]
    pub const fn current_view(&self) -> SpcView {
        self.current_view
    }

    /// Whether view 1's inner PC has been fed its `Input`. Coordinator
    /// reads this to gate the local-proposal arrival path: once the
    /// input is fed the PC FSM has started its round-trips and a
    /// second feed would be a no-op anyway.
    #[must_use]
    pub fn view_one_input_fed(&self) -> bool {
        self.views
            .get(&SpcView::new(1))
            .is_some_and(|v| v.vpc_input_fed)
    }

    /// Latched low output, if any. View-1's inner PC produces this.
    #[must_use]
    pub const fn low_output(&self) -> Option<&PcVector> {
        self.low_output.as_ref()
    }

    /// Latched high output, if any. The commit walk surfaces this on
    /// reaching the view-1 ancestor.
    #[must_use]
    pub const fn high_output(&self) -> Option<&PcVector> {
        self.high_output.as_ref()
    }

    /// Process one event; returns the resulting effects, possibly
    /// empty.
    pub fn handle(&mut self, event: SpcEvent) -> Vec<SpcEffect> {
        match event {
            SpcEvent::Input(v) => self.on_input(v),
            SpcEvent::VpcMsg(payload) => self.on_vpc_msg(*payload),
            SpcEvent::NewView { from, view, cert } => self.on_new_view(from, view, *cert),
            SpcEvent::NewCommit { view, value, proof } => self.on_new_commit(view, &value, *proof),
            SpcEvent::EmptyView(msg) => self.on_empty_view(*msg),
            SpcEvent::TimerExpired { view } => self.on_timer_expired(view),
        }
    }

    fn on_input(&mut self, v: PcVector) -> Vec<SpcEffect> {
        let view_state = self.views.get_mut(&SpcView::new(1)).expect("view 1 exists");
        if view_state.vpc_input_fed {
            return vec![];
        }
        view_state.vpc_input_fed = true;
        let pc_effects = view_state.vpc.handle(PcEvent::Input(v));
        self.translate_pc_effects(SpcView::new(1), pc_effects)
    }

    fn on_vpc_msg(&mut self, payload: VpcMsgPayload) -> Vec<SpcEffect> {
        let view = match &payload {
            VpcMsgPayload::Vote1 { view, .. }
            | VpcMsgPayload::Vote2 { view, .. }
            | VpcMsgPayload::Vote3 { view, .. } => *view,
        };
        let Some(view_state) = self.views.get_mut(&view) else {
            // No buffering — drop messages for views we haven't entered.
            return vec![];
        };
        let pc_event = match payload {
            VpcMsgPayload::Vote1 { vote, .. } => PcEvent::Vote1Received(vote),
            VpcMsgPayload::Vote2 { vote, .. } => PcEvent::Vote2Received(vote),
            VpcMsgPayload::Vote3 { vote, .. } => PcEvent::Vote3Received(vote),
        };
        let pc_effects = view_state.vpc.handle(pc_event);
        self.translate_pc_effects(view, pc_effects)
    }

    fn translate_pc_effects(&mut self, view: SpcView, pc_effects: Vec<PcEffect>) -> Vec<SpcEffect> {
        let mut out = vec![];
        for effect in pc_effects {
            match effect {
                PcEffect::SignAndBroadcastVote1 { v_in } => {
                    out.push(SpcEffect::SignAndBroadcastPcVote1 { view, v_in });
                }
                PcEffect::SignAndBroadcastVote2 { qc1 } => {
                    out.push(SpcEffect::SignAndBroadcastPcVote2 { view, qc1 });
                }
                PcEffect::SignAndBroadcastVote3 { qc2 } => {
                    out.push(SpcEffect::SignAndBroadcastPcVote3 { view, qc2 });
                }
                PcEffect::EquivocationObserved(ev) => {
                    out.push(SpcEffect::Equivocation { view, evidence: ev });
                }
                PcEffect::Decided(qc3) => {
                    let low = qc3.x_pp().clone();
                    let high = qc3.x_pe().clone();
                    out.extend(self.on_vpc_output_low(view, &low, (*qc3).clone()));
                    out.extend(self.on_vpc_output_high(view, high, *qc3));
                }
            }
        }
        out
    }

    fn on_vpc_output_low(&mut self, view: SpcView, low: &PcVector, proof: PcQc3) -> Vec<SpcEffect> {
        let mut out = vec![];
        // Empty low at view > 1 → record evidence.
        if view.inner() > 1 && low.is_empty() {
            out.push(SpcEffect::EmptyLowEvidence(Box::new(SpcEmptyLowEvidence {
                view,
                proof: proof.clone(),
            })));
        }
        if self.new_commit_broadcast.insert(view) {
            out.push(SpcEffect::BroadcastNewCommit {
                view,
                value: low.clone(),
                proof: Box::new(proof),
            });
            // `commit` walks the parent chain back toward view 1.
            out.extend(self.commit(view, low));
        }
        out
    }

    fn on_vpc_output_high(
        &mut self,
        view: SpcView,
        high: PcVector,
        proof: PcQc3,
    ) -> Vec<SpcEffect> {
        if self.high_output.is_some() {
            return vec![];
        }
        let mut out = vec![];
        if has_parent(view, &high, &self.proposals_by_hash) {
            let triple = SpcHighTriple {
                view,
                value: high.clone(),
                proof: proof.clone(),
            };
            self.update_max_high(triple);
            let Some(next_raw) = view.inner().checked_add(1) else {
                // u32 view counter saturated; honest execution never
                // reaches anywhere near this.
                return out;
            };
            let next = SpcView::new(next_raw);
            let cert = SpcCert::Direct {
                prev_view: view,
                value: high,
                proof,
            };
            // Stash for later retrieval when commit() walks back to
            // view 1 and emits `OutputHigh`.
            self.high_decisive_cert = Some(cert.clone());
            // Self-process: enter view+1 and broadcast. `from = me`
            // because we're the relay for our own proposal-object.
            out.extend(self.enter_view(self.me, next, cert.clone()));
            out.push(SpcEffect::BroadcastNewView {
                view: next,
                cert: Box::new(cert),
            });
        } else {
            // Empty-view path: our high has no known parent. Emit a
            // sign-and-broadcast intent reporting our current
            // `max_high`; the signed message lands back on the FSM
            // via `SpcEvent::EmptyView` and gets pooled toward the
            // `f + 1` indirect-cert quorum the same way peer
            // attestations are.
            let reported = self.max_high.clone();
            let should_broadcast = self
                .views
                .get(&view)
                .is_some_and(|vs| !vs.empty_view_broadcast);
            if let Some(reported) = reported
                && should_broadcast
            {
                if let Some(vs) = self.views.get_mut(&view) {
                    vs.empty_view_broadcast = true;
                }
                out.push(SpcEffect::SignAndBroadcastEmptyView {
                    view,
                    reported: Box::new(reported),
                });
            }
        }
        out
    }

    fn on_new_view(&mut self, from: ValidatorId, view: SpcView, cert: SpcCert) -> Vec<SpcEffect> {
        if !verify_cert(&cert, view, &self.network, &self.spc_ctx, &self.committee) {
            return vec![];
        }
        if view.inner() < self.current_view.inner() {
            return vec![];
        }
        // The cert's parent claim has to resolve in our local
        // `proposals_by_hash` — the FSM-level gate beyond crypto.
        let (prev_view, parent_value) = match &cert {
            SpcCert::Direct {
                prev_view, value, ..
            } => (*prev_view, value.clone()),
            SpcCert::Indirect {
                target_view,
                target_value,
                ..
            } => (*target_view, target_value.clone()),
            // Genesis already rejected by verify_cert above.
            SpcCert::Genesis { .. } => return vec![],
        };
        if !has_parent(prev_view, &parent_value, &self.proposals_by_hash) {
            return vec![];
        }
        self.enter_view(from, view, cert)
    }

    fn on_new_commit(&mut self, view: SpcView, value: &PcVector, proof: PcQc3) -> Vec<SpcEffect> {
        // `new-commit` is self-authenticating via the embedded
        // `PcQc3` whose low is the committed value. Verify under the
        // view's PC context, then walk the parent chain.
        let pc_ctx = pc_context(&self.spc_ctx, view);
        if !verify_qc3(&proof, &self.network, &pc_ctx, &self.committee) {
            return vec![];
        }
        if proof.x_pp() != value {
            return vec![];
        }
        let mut out = vec![];
        if self.new_commit_broadcast.insert(view) {
            out.push(SpcEffect::BroadcastNewCommit {
                view,
                value: value.clone(),
                proof: Box::new(proof),
            });
        }
        out.extend(self.commit(view, value));
        out
    }

    fn enter_view(&mut self, from: ValidatorId, view: SpcView, cert: SpcCert) -> Vec<SpcEffect> {
        if self.high_output.is_some() {
            return vec![];
        }
        if view.inner() < self.current_view.inner() {
            return vec![];
        }
        let entered_new = view.inner() > self.current_view.inner();
        let mut out = vec![];
        if entered_new {
            self.current_view = view;
            // Start the view-timeout timer for view ≥ 2. View 1 is
            // never entered via this path (it's eager at
            // construction), so this branch only fires for views
            // that just got authorised by a cert.
            if view.inner() > 1 {
                out.push(SpcEffect::SetTimer {
                    view,
                    duration: self.view_timeout,
                });
            }
        }

        self.update_max_high(referenced_triple(&cert));

        let po = SpcProposalObject { view, cert };
        let h = hash_proposal_object(&po);
        self.proposals_by_hash.insert(h, po.clone());
        let view_state = self.views.entry(view).or_insert_with(|| {
            ViewState::new(
                self.network.clone(),
                self.epoch,
                view,
                self.committee.clone(),
            )
        });
        // Last-write-wins on `(view, sender)` for proposal objects.
        // The cert authenticates the parent claim, so two distinct
        // valid certs from the "same sender" are valid relays, not
        // equivocation.
        view_state.proposal_objects.insert(from, po);

        // Kick the inner PC once we have all `n` proposal objects
        // (view ≥ 2; view 1 takes the application input directly).
        let n = self.committee.len();
        let ready =
            view.inner() > 1 && !view_state.vpc_input_fed && view_state.proposal_objects.len() == n;
        if ready {
            view_state.vpc_input_fed = true;
            let input = self.compute_view_input(view);
            let view_state = self.views.get_mut(&view).expect("present");
            let pc_effects = view_state.vpc.handle(PcEvent::Input(input));
            out.extend(self.translate_pc_effects(view, pc_effects));
        }
        // `proposals_by_hash` just gained an entry, so previously-
        // buffered empty-views may now pass their `has_parent` check.
        out.extend(self.rescan_pending_empty_views());
        out
    }

    fn on_empty_view(&mut self, msg: SpcEmptyViewMsg) -> Vec<SpcEffect> {
        self.process_empty_view(msg)
    }

    /// Forces `RunVPC(view)` on timer expiry even with a partial
    /// proposal-object buffer. Idempotent if VPC already fired.
    fn on_timer_expired(&mut self, view: SpcView) -> Vec<SpcEffect> {
        if view.inner() <= 1 {
            return vec![];
        }
        let Some(view_state) = self.views.get_mut(&view) else {
            return vec![];
        };
        if view_state.vpc_input_fed {
            return vec![];
        }
        view_state.vpc_input_fed = true;
        let input = self.compute_view_input(view);
        let view_state = self.views.get_mut(&view).expect("present");
        let pc_effects = view_state.vpc.handle(PcEvent::Input(input));
        self.translate_pc_effects(view, pc_effects)
    }

    /// Validate an empty-view, add it to `Q_i,w`, and on reaching
    /// `f + 1` distinct signers build an indirect cert and advance.
    fn process_empty_view(&mut self, msg: SpcEmptyViewMsg) -> Vec<SpcEffect> {
        let view = msg.view;
        if view.inner() < self.current_view.inner() {
            return vec![];
        }
        // Paper requires `w > w_h` — empty-view must skip ahead of
        // the reported high triple's view.
        if view.inner() <= msg.reported.view.inner() {
            return vec![];
        }
        if !verify_empty_view_msg(&msg, &self.network, &self.spc_ctx, &self.committee) {
            return vec![];
        }
        if !has_parent(
            msg.reported.view,
            &msg.reported.value,
            &self.proposals_by_hash,
        ) {
            // Parent ProposalObject hasn't arrived yet. Buffer the
            // empty-view; `rescan_pending_empty_views` retries it
            // after every `enter_view`.
            self.buffer_pending_empty_view(msg);
            return vec![];
        }

        self.update_max_high(msg.reported.clone());

        let view_state = self.views.entry(view).or_insert_with(|| {
            ViewState::new(
                self.network.clone(),
                self.epoch,
                view,
                self.committee.clone(),
            )
        });
        if view_state.indirect_cert_built {
            return vec![];
        }
        if view_state.empty_views.contains_key(&msg.signer) {
            return vec![];
        }
        view_state.empty_views.insert(msg.signer, msg);

        let n = self.committee.len();
        let threshold = byzantine_threshold(n) + 1;
        if view_state.empty_views.len() < threshold {
            return vec![];
        }
        // Quorum reached — build the indirect cert and enter the
        // next view.
        view_state.indirect_cert_built = true;
        let msgs: Vec<SpcEmptyViewMsg> = view_state.empty_views.values().cloned().collect();
        let Some(cert) = build_indirect_cert(view, &msgs, &self.committee) else {
            // Shouldn't happen — the threshold check above guarantees
            // non-empty input and `view + 1` overflow is the only
            // other failure mode (only at u32 saturation).
            return vec![];
        };
        let Some(next_raw) = view.inner().checked_add(1) else {
            return vec![];
        };
        let next = SpcView::new(next_raw);
        // `from = me` because we're the relay for this indirect-cert
        // assembly we just built ourselves.
        let mut out = self.enter_view(self.me, next, cert.clone());
        out.push(SpcEffect::BroadcastNewView {
            view: next,
            cert: Box::new(cert),
        });
        out
    }

    fn buffer_pending_empty_view(&mut self, msg: SpcEmptyViewMsg) {
        let current = self.current_view.inner();
        let view = msg.view.inner();
        if view < current || view > current + MAX_PENDING_EMPTY_VIEW_AHEAD {
            return;
        }
        let bucket = self.pending_empty_views.entry(msg.view).or_default();
        bucket.entry(msg.signer).or_insert(msg);
    }

    /// Drain `pending_empty_views` and re-attempt each entry. Every
    /// `proposals_by_hash` insert must follow with a call here —
    /// `has_parent` flips from false to true when the value's first
    /// non-bottom hash gains a preimage, and entries waiting on that
    /// would otherwise stall. Today only `enter_view` inserts; the
    /// rescan-on-insert is colocated there.
    fn rescan_pending_empty_views(&mut self) -> Vec<SpcEffect> {
        let current = self.current_view;
        self.pending_empty_views
            .retain(|v, _| v.inner() >= current.inner());
        let pending = std::mem::take(&mut self.pending_empty_views);
        let mut out = vec![];
        for (_view, by_sender) in pending {
            for (_sender, msg) in by_sender {
                out.extend(self.process_empty_view(msg));
            }
        }
        out
    }

    fn commit(&mut self, view: SpcView, value: &PcVector) -> Vec<SpcEffect> {
        let mut out = vec![];
        if view.inner() == 1 {
            if self.low_output.is_none() {
                self.low_output = Some(value.clone());
            }
            return out;
        }
        if let Some((parent_view, parent_value)) = parent_of(view, value, &self.proposals_by_hash) {
            if parent_view.inner() == 1 {
                if self.high_output.is_none() {
                    self.high_output = Some(parent_value.clone());
                    let cert = self
                        .high_decisive_cert
                        .clone()
                        .expect("on_vpc_output_high stashes the cert before commit walks here");
                    out.push(SpcEffect::OutputHigh {
                        value: parent_value,
                        cert: Box::new(cert),
                    });
                    // Instance is done: free the proposal table.
                    self.proposals_by_hash.clear();
                }
            } else if parent_view.inner() > 1 {
                out.extend(self.commit(parent_view, &parent_value));
            }
        }
        out
    }

    fn update_max_high(&mut self, triple: SpcHighTriple) {
        let beats = self.max_high.as_ref().is_none_or(|c| triple.view > c.view);
        if beats {
            self.max_high = Some(triple);
        }
    }

    fn compute_view_input(&self, view: SpcView) -> PcVector {
        let view_state = self.views.get(&view).expect("view present");
        let n = self.committee.len();
        let shifts = rank_shift_for_view(view, n);
        // Cyclically shifted ranking: `committee[i + shifts mod n]`.
        let elements: Vec<PcValueElement> = (0..n)
            .map(|i| {
                let validator = self.committee[(i + shifts) % n].0;
                view_state
                    .proposal_objects
                    .get(&validator)
                    .map_or(HASH_BOTTOM, hash_proposal_object)
            })
            .collect();
        PcVector::new(elements)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_types::{
        Bls12381G2Signature, Epoch, PcQc2, PcSignerLengths, PcVote1, PcXpProof, SignerBitfield,
        generate_bls_keypair, spc_context,
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
        spc_context(Epoch::new(1))
    }

    fn dummy_pc_qc3() -> PcQc3 {
        let qc2 = PcQc2::new(
            PcVector::empty(),
            SignerBitfield::new(4),
            generate_bls_keypair().sign_v1(b"unused"),
            PcXpProof::Full,
        );
        PcQc3::new(
            PcVector::empty(),
            qc2,
            None,
            None,
            SignerBitfield::new(4),
            PcSignerLengths::Uniform(0),
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
            target_proof: dummy_pc_qc3(),
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
                proof: dummy_pc_qc3(),
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

    fn bls_sign_unused(sk: &Bls12381G1PrivateKey) -> Bls12381G2Signature {
        sk.sign_v1(b"unused")
    }

    // ─── FSM tests ─────────────────────────────────────────────────────

    use hyperscale_types::bls_keypair_from_seed;

    fn fsm_committee(
        n: usize,
    ) -> (
        Vec<Arc<Bls12381G1PrivateKey>>,
        Vec<(ValidatorId, Bls12381G1PublicKey)>,
    ) {
        let mut sks = Vec::with_capacity(n);
        let mut members = Vec::with_capacity(n);
        for i in 0..n {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let sk = bls_keypair_from_seed(&seed);
            members.push((ValidatorId::new(i as u64), sk.public_key()));
            sks.push(Arc::new(sk));
        }
        (sks, members)
    }

    fn fsm_instance(idx: usize) -> SpcInstance {
        let (_, members) = fsm_committee(4);
        SpcInstance::new(
            net(),
            Epoch::new(1),
            members.clone(),
            members[idx].0,
            Duration::from_millis(100),
        )
    }

    /// Fresh `SpcInstance` constructs with view 1 as current and no
    /// outputs latched.
    #[test]
    fn spc_instance_initial_state() {
        let fsm = fsm_instance(0);
        assert_eq!(fsm.current_view(), SpcView::new(1));
        assert!(fsm.low_output().is_none());
        assert!(fsm.high_output().is_none());
    }

    /// Feeding `Input` at view 1 emits exactly one
    /// `SignAndBroadcastPcVote1` at the local view — the inner PC
    /// surfaces a sign intent as its first effect.
    #[test]
    fn spc_input_emits_vote1_sign_intent() {
        let mut fsm = fsm_instance(0);
        let v = PcVector::new(std::iter::once(PcValueElement::new([7u8; 32])));
        let effects = fsm.handle(SpcEvent::Input(v.clone()));
        assert_eq!(effects.len(), 1);
        let SpcEffect::SignAndBroadcastPcVote1 { view, v_in } = &effects[0] else {
            panic!("expected SignAndBroadcastPcVote1, got {:?}", effects[0]);
        };
        assert_eq!(*view, SpcView::new(1));
        assert_eq!(*v_in, v);
    }

    /// Subsequent `Input` events at view 1 are idempotent — already
    /// fed.
    #[test]
    fn spc_input_idempotent_at_view_one() {
        let mut fsm = fsm_instance(0);
        let v = PcVector::new(std::iter::once(PcValueElement::new([1u8; 32])));
        let _ = fsm.handle(SpcEvent::Input(v.clone()));
        let second = fsm.handle(SpcEvent::Input(v));
        assert!(second.is_empty());
    }

    /// `VpcMsg` for an unknown view is dropped — no buffering, no
    /// effects.
    #[test]
    fn spc_vpc_msg_for_unknown_view_dropped() {
        let mut fsm = fsm_instance(0);
        let (_sks, members) = fsm_committee(4);
        // Build a stub Vote1 from peer 1 under view 99 (we've only
        // entered view 1).
        let dummy = PcVote1::new(
            members[1].0,
            PcVector::empty(),
            vec![Bls12381G2Signature([0u8; 96])],
        );
        let effects = fsm.handle(SpcEvent::VpcMsg(Box::new(VpcMsgPayload::Vote1 {
            view: SpcView::new(99),
            vote: dummy,
        })));
        assert!(effects.is_empty());
    }

    /// `parent_of(view 1, _)` returns `None` — view 1 has no parent.
    /// `has_parent(view 1, _)` returns `true` — the genesis boundary.
    #[test]
    fn parent_helpers_at_view_one() {
        let proposals = BTreeMap::new();
        assert!(parent_of(SpcView::new(1), &PcVector::empty(), &proposals).is_none());
        assert!(has_parent(SpcView::new(1), &PcVector::empty(), &proposals));
    }

    /// `parent_of(view N, _)` returns the cert's parent triple when
    /// the value's first non-bottom hash resolves to a proposal
    /// object in the table.
    #[test]
    fn parent_of_resolves_first_non_bottom_hash() {
        let parent_value = PcVector::new(std::iter::once(PcValueElement::new([0xAB; 32])));
        let cert = SpcCert::Direct {
            prev_view: SpcView::new(2),
            value: parent_value.clone(),
            proof: dummy_pc_qc3(),
        };
        let po = SpcProposalObject {
            view: SpcView::new(3),
            cert,
        };
        let h = hash_proposal_object(&po);
        let mut proposals = BTreeMap::new();
        proposals.insert(h, po);

        // Search vector: [BOTTOM, h] — second element resolves.
        let search = PcVector::new([HASH_BOTTOM, h]);
        let parent = parent_of(SpcView::new(3), &search, &proposals);
        assert_eq!(parent, Some((SpcView::new(2), parent_value)));
    }

    /// `hash_proposal_object` is deterministic + never returns
    /// [`HASH_BOTTOM`] (bottom-collision avoidance gives full
    /// collision resistance against the sentinel).
    #[test]
    fn hash_proposal_object_deterministic_and_avoids_bottom() {
        let po = SpcProposalObject {
            view: SpcView::new(2),
            cert: SpcCert::Direct {
                prev_view: SpcView::new(1),
                value: PcVector::empty(),
                proof: dummy_pc_qc3(),
            },
        };
        let h1 = hash_proposal_object(&po);
        let h2 = hash_proposal_object(&po);
        assert_eq!(h1, h2);
        assert_ne!(h1, HASH_BOTTOM);
    }

    /// `TimerExpired` for view ≤ 1 is a no-op — view 1 has no timer
    /// (input drives it directly).
    #[test]
    fn timer_expiry_at_view_one_is_noop() {
        let mut fsm = fsm_instance(0);
        let effects = fsm.handle(SpcEvent::TimerExpired {
            view: SpcView::new(1),
        });
        assert!(effects.is_empty());
    }

    /// `TimerExpired` for an unknown view is a no-op.
    #[test]
    fn timer_expiry_for_unknown_view_is_noop() {
        let mut fsm = fsm_instance(0);
        let effects = fsm.handle(SpcEvent::TimerExpired {
            view: SpcView::new(42),
        });
        assert!(effects.is_empty());
    }

    /// `EmptyView` whose `view <= reported.view` is rejected — paper
    /// requires `w > w_h` so the skip statement points strictly
    /// forward.
    #[test]
    fn empty_view_with_non_progressing_reported_view_rejected() {
        let mut fsm = fsm_instance(0);
        let (sks, members) = fsm_committee(4);
        let spc_ctx = spc_context(Epoch::new(1));
        let reported = SpcHighTriple {
            view: SpcView::new(5),
            value: PcVector::empty(),
            proof: dummy_pc_qc3(),
        };
        // View 3 < reported view 5 — rejected.
        let msg = sign_empty_view_msg(
            &sks[1],
            members[1].0,
            &net(),
            &spc_ctx,
            SpcView::new(3),
            reported,
        );
        let effects = fsm.handle(SpcEvent::EmptyView(Box::new(msg)));
        assert!(effects.is_empty());
    }
}
