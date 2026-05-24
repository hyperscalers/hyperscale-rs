//! Prefix Consensus inner-consensus vote and QC verifiers.
//!
//! PC is the per-view inner consensus that drives one validator's
//! `v_in_i` input vector through three rounds of attestation, producing
//! a [`PcQc3`] terminal certificate carrying both the certified low
//! (`x_pp`, the mcp of round-3 signers' `x_p_i`) and certified high
//! (`x_pe`, the mce).
//!
//! This module hosts the **verify** side of PC — pure functions over
//! wire types from `hyperscale_types::beacon::pc`. The verify and build
//! sides are deliberately split: callers that only need to validate
//! caller-supplied QCs (SPC, the witness fetch responder) link only the
//! verify side.
//!
//! # Soundness gates encoded in the verifiers
//!
//! - **Signer-set sizing** (`qc.signers.len() == n - f`): strict equality
//!   plus per-party dedup enforces "exactly n-f distinct signers" — any
//!   relaxation to `>= n - f` would let duplicates inflate a sub-quorum.
//! - **Committee membership**: every signer's [`ValidatorId`] must
//!   resolve to a committee position before any BLS pairing is paid.
//!   Three independent reasons: panic-safety against unregistered ids,
//!   state-hygiene against phantom signers crowding out real ones, and
//!   sub-quorum inflation since anyone can mint a BLS keypair.
//! - **Wire-size caps**: [`MAX_VOTE_VECTOR_LEN`] bounds verify cost
//!   (one BLS pairing per prefix sig) against a hostile peer flooding
//!   oversized votes. Enforced by [`BoundedVec`] at decode time and
//!   re-asserted here as a defense against caller-built QCs that bypass
//!   decode.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_types::{
    Bls12381G1PrivateKey, Bls12381G1PublicKey, Bls12381G2Signature, DOMAIN_PC_VOTE1,
    DOMAIN_PC_VOTE2, DOMAIN_PC_VOTE2_LENGTH, DOMAIN_PC_VOTE3, MAX_VOTE_VECTOR_LEN,
    NetworkDefinition, PC_VALUE_ELEMENT_BYTES, PcCompactLenSigner, PcCompactVote, PcDivergingProof,
    PcQc1, PcQc2, PcQc3, PcValueElement, PcVector, PcVote1, PcVote2, PcVote3, PcVoteEquivocation,
    PcVoteRound, PcXpProof, SignerBitfield, Slot, SpcView, ValidatorId,
    aggregate_verify_bls_different_messages, pc_context, pc_vote_signing_message, spc_context,
};

use crate::prefix_ops::{mce, mcp, qc1_certify};

/// Resolve a committee signer's public key, or return `None` if they
/// aren't in the committee. Linear scan — committee sizes are small
/// (≤ a few dozen), so a `BTreeMap` lookup wouldn't pay back its setup
/// cost in the typical case.
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
/// BFT `f = (n - 1) / 3`. Committees too small to tolerate any faults
/// (`n < 4`) return `0`; verifiers that need `n - f` signers rely on
/// the caller having sized the committee correctly.
const fn byzantine_threshold(n: usize) -> usize {
    n.saturating_sub(1) / 3
}

/// Build the per-prefix signing messages for a round-1 or round-2 vote.
/// Returns `|v| + 1` messages, one per prefix length `k ∈ 0..=|v|`,
/// each binding `(network, domain, ctx, v[..k])`.
fn prefix_signing_messages(
    network: &NetworkDefinition,
    domain: &[u8],
    pc_ctx: &[u8],
    v: &PcVector,
) -> Vec<Vec<u8>> {
    (0..=v.len())
        .map(|k| {
            let prefix = PcVector::new(v.iter().take(k).copied());
            pc_vote_signing_message(network, domain, pc_ctx, &prefix)
        })
        .collect()
}

/// Build the canonical signing message for a length attestation:
/// a single-element vector carrying `len` under [`DOMAIN_PC_VOTE2_LENGTH`].
/// Binds a [`PcVote2`] signer to their specific `|x|`, closing the
/// prefix-sig splice attack on [`PcXpProof::ShortWitness`].
fn length_attestation_message(network: &NetworkDefinition, pc_ctx: &[u8], len: usize) -> Vec<u8> {
    let len_element = PcValueElement::new({
        let mut bytes = [0u8; PC_VALUE_ELEMENT_BYTES];
        bytes[..8].copy_from_slice(&(len as u64).to_le_bytes());
        bytes
    });
    let v = PcVector::new(std::iter::once(len_element));
    pc_vote_signing_message(network, DOMAIN_PC_VOTE2_LENGTH, pc_ctx, &v)
}

/// Verify a round-2 length attestation against a signer's pubkey.
pub(crate) fn verify_length_attestation(
    sig: &Bls12381G2Signature,
    pk: &Bls12381G1PublicKey,
    network: &NetworkDefinition,
    pc_ctx: &[u8],
    len: usize,
) -> bool {
    let msg = length_attestation_message(network, pc_ctx, len);
    aggregate_verify_bls_different_messages(&[msg.as_slice()], sig, std::slice::from_ref(pk))
}

// ─── Round 1 ───────────────────────────────────────────────────────────────

/// Verify a single round-1 vote. Pure function over wire types.
pub(crate) fn verify_vote1(
    v1: &PcVote1,
    network: &NetworkDefinition,
    pc_ctx: &[u8],
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    let Some(pk) = pubkey_in_committee(committee, v1.validator()) else {
        return false;
    };
    if v1.v_in().len() > MAX_VOTE_VECTOR_LEN {
        return false;
    }
    if v1.prefix_sigs().len() != v1.v_in().len() + 1 {
        return false;
    }
    let messages_owned = prefix_signing_messages(network, DOMAIN_PC_VOTE1, pc_ctx, v1.v_in());
    let messages: Vec<&[u8]> = messages_owned.iter().map(Vec::as_slice).collect();
    let pks = vec![pk; v1.prefix_sigs().len()];
    let sigs: Vec<Bls12381G2Signature> = v1.prefix_sigs().iter().copied().collect();
    let Ok(agg) = Bls12381G2Signature::aggregate(&sigs, true) else {
        return false;
    };
    aggregate_verify_bls_different_messages(&messages, &agg, &pks)
}

/// Verify a round-1 QC — the certified prefix `x` plus the compact
/// view of every round-1 signer's `v_in_i` relative to `x`.
///
/// Two soundness gates beyond signature verification:
/// 1. `qc1.x_signers.len() == n - f` (with per-party dedup) — see
///    module-level note on signer-set sizing.
/// 2. `qc1_certify(reconstructed_inputs, f) == Some(qc1.x)` — pins
///    `x` to the longest prefix attained by some `(f+1)`-subset of
///    `S_1`'s inputs, forcing it above the all-honest subset's mcp.
#[must_use]
pub fn verify_qc1(
    qc1: &PcQc1,
    network: &NetworkDefinition,
    pc_ctx: &[u8],
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    let n = committee.len();
    let f = byzantine_threshold(n);
    let q = n - f;

    if qc1.x().len() > MAX_VOTE_VECTOR_LEN {
        return false;
    }
    if qc1.x_signers().len() != q {
        return false;
    }

    let mut seen: BTreeSet<ValidatorId> = BTreeSet::new();
    let mut values: Vec<PcVector> = Vec::with_capacity(q);
    let mut pks: Vec<Bls12381G1PublicKey> = Vec::with_capacity(q);
    let mut subset_inputs: Vec<PcVector> = Vec::with_capacity(q);

    for cv in qc1.x_signers().iter() {
        let Some(pk) = pubkey_in_committee(committee, cv.validator()) else {
            return false;
        };
        if !seen.insert(cv.validator()) {
            return false;
        }
        let Some(v_prime) = reconstruct_compact_vote(cv, qc1.x()) else {
            return false;
        };
        subset_inputs.push(v_prime.clone());
        values.push(v_prime);
        pks.push(pk);
    }

    let messages_owned: Vec<Vec<u8>> = values
        .iter()
        .map(|v| pc_vote_signing_message(network, DOMAIN_PC_VOTE1, pc_ctx, v))
        .collect();
    let messages: Vec<&[u8]> = messages_owned.iter().map(Vec::as_slice).collect();
    if !aggregate_verify_bls_different_messages(&messages, &qc1.x_agg_sig(), &pks) {
        return false;
    }

    qc1_certify(&subset_inputs, f).as_ref() == Some(qc1.x())
}

/// Reconstruct a signer's `v'_i = mcp(v_in_i, x) ++ [divergent?]` from
/// the compact encoding. Returns `None` when the encoding is structurally
/// invalid (`shared_len > |x|`, or `divergent.is_some()` and the divergent
/// element coincides with `x[shared_len]` — which would collapse to a
/// non-divergent vote and fails uniqueness).
fn reconstruct_compact_vote(cv: &PcCompactVote, x: &PcVector) -> Option<PcVector> {
    let shared_len = cv.shared_len() as usize;
    if shared_len > x.len() {
        return None;
    }
    let shared = x.as_slice()[..shared_len].iter().copied();
    Some(match cv.divergent() {
        None => PcVector::new(shared),
        Some(d) => {
            // The compact encoding is unique only if `d` actually
            // diverges from `x[shared_len]` (when the latter exists).
            if let Some(x_at) = x.as_slice().get(shared_len)
                && x_at == d
            {
                return None;
            }
            PcVector::new(shared.chain(std::iter::once(*d)))
        }
    })
}

// ─── Round 2 ───────────────────────────────────────────────────────────────

/// Verify a single round-2 vote — `(x, prefix_sigs, embedded qc1,
/// length_attestation)`. Calls into [`verify_qc1`] for the embedded
/// round-1 QC; recurses indirectly through
/// [`PcXpProof::ShortWitness`] in [`verify_qc2`].
pub(crate) fn verify_vote2(
    v2: &PcVote2,
    network: &NetworkDefinition,
    pc_ctx: &[u8],
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    let Some(pk) = pubkey_in_committee(committee, v2.validator()) else {
        return false;
    };
    if v2.x().len() > MAX_VOTE_VECTOR_LEN {
        return false;
    }
    if v2.prefix_sigs().len() != v2.x().len() + 1 {
        return false;
    }
    if !verify_qc1(v2.qc1(), network, pc_ctx, committee) {
        return false;
    }
    // Vote2's `x` must be the QC1Certify output of its embedded QC1.
    if v2.x() != v2.qc1().x() {
        return false;
    }
    if !verify_length_attestation(&v2.length_attestation(), &pk, network, pc_ctx, v2.x().len()) {
        return false;
    }
    let messages_owned = prefix_signing_messages(network, DOMAIN_PC_VOTE2, pc_ctx, v2.x());
    let messages: Vec<&[u8]> = messages_owned.iter().map(Vec::as_slice).collect();
    let pks = vec![pk; v2.prefix_sigs().len()];
    let sigs: Vec<Bls12381G2Signature> = v2.prefix_sigs().iter().copied().collect();
    let Ok(agg) = Bls12381G2Signature::aggregate(&sigs, true) else {
        return false;
    };
    aggregate_verify_bls_different_messages(&messages, &agg, &pks)
}

/// Verify a round-2 QC — the multi-sig over `x_p` plus the witness
/// `π` that `x_p` is the actual mcp of the round-2 quorum's `x` values.
///
/// `π` handling branches three ways: [`PcXpProof::Full`] is the all-equal
/// case (every signer's `x = x_p`); [`PcXpProof::Diverging`] carries
/// two witnesses with divergent extensions plus their backing QC1s;
/// [`PcXpProof::ShortWitness`] embeds an entire [`PcVote2`] whose `x`
/// equals `x_p`.
#[must_use]
pub fn verify_qc2(
    qc2: &PcQc2,
    network: &NetworkDefinition,
    pc_ctx: &[u8],
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    let n = committee.len();
    let f = byzantine_threshold(n);
    let q = n - f;

    if qc2.x_p().len() > MAX_VOTE_VECTOR_LEN {
        return false;
    }
    if qc2.signers().count() != q {
        return false;
    }
    let signer_indices: Vec<usize> = qc2.signers().set_indices().collect();
    if signer_indices.iter().any(|&i| i >= n) {
        return false;
    }
    let signer_pks: Vec<Bls12381G1PublicKey> =
        signer_indices.iter().map(|&i| committee[i].1).collect();
    let signer_ids: BTreeSet<ValidatorId> =
        signer_indices.iter().map(|&i| committee[i].0).collect();

    let x_p_message = pc_vote_signing_message(network, DOMAIN_PC_VOTE2, pc_ctx, qc2.x_p());
    let x_p_messages: Vec<&[u8]> = std::iter::repeat_n(x_p_message.as_slice(), q).collect();
    if !aggregate_verify_bls_different_messages(&x_p_messages, &qc2.multi_sig(), &signer_pks) {
        return false;
    }

    match qc2.pi() {
        PcXpProof::Full { length_multi_sig } => {
            let len_msg = length_attestation_message(network, pc_ctx, qc2.x_p().len());
            let len_messages: Vec<&[u8]> = std::iter::repeat_n(len_msg.as_slice(), q).collect();
            aggregate_verify_bls_different_messages(&len_messages, length_multi_sig, &signer_pks)
        }
        PcXpProof::Diverging(proof) => {
            verify_diverging_proof(proof, qc2, &signer_ids, network, pc_ctx, committee)
        }
        PcXpProof::ShortWitness { witness } => {
            if !signer_ids.contains(&witness.validator()) {
                return false;
            }
            if witness.x() != qc2.x_p() {
                return false;
            }
            verify_vote2(witness, network, pc_ctx, committee)
        }
    }
}

fn verify_diverging_proof(
    proof: &PcDivergingProof,
    qc2: &PcQc2,
    signer_ids: &BTreeSet<ValidatorId>,
    network: &NetworkDefinition,
    pc_ctx: &[u8],
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    if proof.j == proof.k || proof.j_divergent == proof.k_divergent {
        return false;
    }
    if !signer_ids.contains(&proof.j) || !signer_ids.contains(&proof.k) {
        return false;
    }
    let (Some(pk_j), Some(pk_k)) = (
        pubkey_in_committee(committee, proof.j),
        pubkey_in_committee(committee, proof.k),
    ) else {
        return false;
    };
    if !verify_qc1(&proof.qc1_j, network, pc_ctx, committee)
        || !verify_qc1(&proof.qc1_k, network, pc_ctx, committee)
    {
        return false;
    }
    // Each witness's qc1.x must extend x_p ++ [divergent] — the qc1
    // anchors the divergent extension to a real round-1 quorum.
    let mut j_extended: Vec<PcValueElement> = qc2.x_p().iter().copied().collect();
    j_extended.push(proof.j_divergent);
    let j_vec = PcVector::new(j_extended);
    let mut k_extended: Vec<PcValueElement> = qc2.x_p().iter().copied().collect();
    k_extended.push(proof.k_divergent);
    let k_vec = PcVector::new(k_extended);
    if !j_vec.is_prefix_of(proof.qc1_j.x()) || !k_vec.is_prefix_of(proof.qc1_k.x()) {
        return false;
    }
    let j_msg = pc_vote_signing_message(network, DOMAIN_PC_VOTE2, pc_ctx, &j_vec);
    if !aggregate_verify_bls_different_messages(&[j_msg.as_slice()], &proof.j_sig, &[pk_j]) {
        return false;
    }
    let k_msg = pc_vote_signing_message(network, DOMAIN_PC_VOTE2, pc_ctx, &k_vec);
    aggregate_verify_bls_different_messages(&[k_msg.as_slice()], &proof.k_sig, &[pk_k])
}

// ─── Round 3 ───────────────────────────────────────────────────────────────

/// Verify a single round-3 vote — `(x_p, sig_xp, embedded qc2)`. The
/// signer's individual sig over `x_p` plus the embedded QC2 binding
/// `x_p` to a real round-2 quorum.
pub(crate) fn verify_vote3(
    v3: &PcVote3,
    network: &NetworkDefinition,
    pc_ctx: &[u8],
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    let Some(pk) = pubkey_in_committee(committee, v3.validator()) else {
        return false;
    };
    let msg = pc_vote_signing_message(network, DOMAIN_PC_VOTE3, pc_ctx, v3.x_p());
    if !aggregate_verify_bls_different_messages(&[msg.as_slice()], &v3.sig_xp(), &[pk]) {
        return false;
    }
    if !verify_qc2(v3.qc2(), network, pc_ctx, committee) {
        return false;
    }
    v3.x_p() == v3.qc2().x_p()
}

/// Verify a round-3 QC — the terminal certificate.
///
/// Carries both endpoints `(x_pp, x_pe)` of the round-3 quorum's
/// `x_p` distribution, the per-signer `|x_p_i|`s, and an aggregate
/// sig binding each signer to their `x_p_i = x_pe[..len_i]`.
///
/// Five soundness gates: (1) `x_pp ⪯ x_pe`; (2) embedded QC2s for both
/// endpoints valid; (3) endpoint values match the QC2s' `x_p`; (4)
/// `all_signers.len() == n - f` with dedup; (5) min/max of signer
/// lengths equal `|x_pp|` and `|x_pe|` respectively — `x_pp` is the
/// shortest of the round-3 signers' `x_p_i`, `x_pe` the longest.
#[must_use]
pub fn verify_qc3(
    qc3: &PcQc3,
    network: &NetworkDefinition,
    pc_ctx: &[u8],
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    let n = committee.len();
    let f = byzantine_threshold(n);
    let q = n - f;

    let x_pe = qc3.x_pe();
    let qc2_xpe = qc3.qc2_xpe();
    if x_pe.len() > MAX_VOTE_VECTOR_LEN {
        return false;
    }
    if !qc3.x_pp().is_prefix_of(x_pe) {
        return false;
    }
    if !verify_qc2(qc3.qc2_xpp(), network, pc_ctx, committee) {
        return false;
    }
    if !verify_qc2(qc2_xpe, network, pc_ctx, committee) {
        return false;
    }
    if qc3.qc2_xpp().x_p() != qc3.x_pp() {
        return false;
    }
    if qc2_xpe.x_p() != x_pe {
        return false;
    }
    if qc3.all_signers().len() != q {
        return false;
    }

    let mut seen: BTreeSet<ValidatorId> = BTreeSet::new();
    let mut values: Vec<PcVector> = Vec::with_capacity(q);
    let mut pks: Vec<Bls12381G1PublicKey> = Vec::with_capacity(q);
    let mut min_len = usize::MAX;
    let mut max_len = 0usize;
    for signer in qc3.all_signers().iter() {
        let Some(pk) = pubkey_in_committee(committee, signer.validator) else {
            return false;
        };
        if !seen.insert(signer.validator) {
            return false;
        }
        let len = signer.prefix_len as usize;
        if len > x_pe.len() || len < qc3.x_pp().len() {
            return false;
        }
        min_len = min_len.min(len);
        max_len = max_len.max(len);
        values.push(PcVector::new(x_pe.as_slice()[..len].iter().copied()));
        pks.push(pk);
    }
    if min_len != qc3.x_pp().len() || max_len != x_pe.len() {
        return false;
    }

    let messages_owned: Vec<Vec<u8>> = values
        .iter()
        .map(|v| pc_vote_signing_message(network, DOMAIN_PC_VOTE3, pc_ctx, v))
        .collect();
    let messages: Vec<&[u8]> = messages_owned.iter().map(Vec::as_slice).collect();
    aggregate_verify_bls_different_messages(&messages, &qc3.agg_sig(), &pks)
}

// ─── Equivocation ──────────────────────────────────────────────────────────

/// Verify that a [`PcVoteEquivocation`] is a genuine double-sign by
/// the same validator at the same `(slot, view, round)`.
///
/// Returns `true` only when:
/// 1. `value_a != value_b` (otherwise no contradiction).
/// 2. Both signatures verify under the validator's committee pubkey
///    against the canonical signing message for `(network, round-tag,
///    pc_context(slot, view), value)`.
///
/// The validator must be in `committee`; non-members are rejected
/// before any pairing. Round-3 sigs are individual sigs over `x_p`
/// (the prototype's `sig_xp`), so the verifier treats all three
/// rounds uniformly — only the domain tag varies.
#[must_use]
pub fn verify_vote_equivocation(
    ev: &PcVoteEquivocation,
    network: &NetworkDefinition,
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    if ev.value_a == ev.value_b {
        return false;
    }
    let Some(pk) = pubkey_in_committee(committee, ev.validator) else {
        return false;
    };
    let domain = match ev.round {
        PcVoteRound::Vote1 => DOMAIN_PC_VOTE1,
        PcVoteRound::Vote2 => DOMAIN_PC_VOTE2,
        PcVoteRound::Vote3 => DOMAIN_PC_VOTE3,
    };
    let spc_ctx = spc_context(ev.slot);
    let ctx = pc_context(&spc_ctx, ev.view);
    let msg_a = pc_vote_signing_message(network, domain, &ctx, &ev.value_a);
    let msg_b = pc_vote_signing_message(network, domain, &ctx, &ev.value_b);
    aggregate_verify_bls_different_messages(&[msg_a.as_slice()], &ev.sig_a, &[pk])
        && aggregate_verify_bls_different_messages(&[msg_b.as_slice()], &ev.sig_b, &[pk])
}

// ─── Signing ───────────────────────────────────────────────────────────────

/// Sign one signer's round-1 vote — produces `|v_in| + 1` prefix
/// signatures over `v_in[..k]` for `k ∈ 0..=|v_in|`, packaged as a
/// `PcVote1`.
#[must_use]
pub fn sign_vote1(
    sk: &Bls12381G1PrivateKey,
    validator: ValidatorId,
    network: &NetworkDefinition,
    pc_ctx: &[u8],
    v_in: PcVector,
) -> PcVote1 {
    let prefix_sigs = sign_all_prefixes(sk, network, pc_ctx, &v_in, DOMAIN_PC_VOTE1);
    PcVote1::new(validator, v_in, prefix_sigs)
}

/// Sign one signer's round-2 vote.
///
/// `x` is derived from `qc1` so the `v2.x == v2.qc1.x` soundness
/// invariant is unforgeable at the source. The length attestation
/// pins `|x|`, closing the prefix-sig splice attack on
/// [`PcXpProof::ShortWitness`] verification.
#[must_use]
pub fn sign_vote2(
    sk: &Bls12381G1PrivateKey,
    validator: ValidatorId,
    network: &NetworkDefinition,
    pc_ctx: &[u8],
    qc1: PcQc1,
) -> PcVote2 {
    let x = qc1.x().clone();
    let prefix_sigs = sign_all_prefixes(sk, network, pc_ctx, &x, DOMAIN_PC_VOTE2);
    let length_attestation = sk.sign_v1(&length_attestation_message(network, pc_ctx, x.len()));
    PcVote2::new(validator, x, prefix_sigs, qc1, length_attestation)
}

/// Sign one signer's round-3 vote.
///
/// `x_p` is derived from `qc2`, and the individual sig over `x_p`
/// rides separately from the per-prefix fan-out used in rounds 1/2
/// (round 3 only needs the single `x_p` commitment).
#[must_use]
pub fn sign_vote3(
    sk: &Bls12381G1PrivateKey,
    validator: ValidatorId,
    network: &NetworkDefinition,
    pc_ctx: &[u8],
    qc2: PcQc2,
) -> PcVote3 {
    let x_p = qc2.x_p().clone();
    let sig_xp = sk.sign_v1(&pc_vote_signing_message(
        network,
        DOMAIN_PC_VOTE3,
        pc_ctx,
        &x_p,
    ));
    PcVote3::new(validator, x_p, sig_xp, qc2)
}

/// Produce all `|v| + 1` prefix signatures, one per length `k ∈ 0..=|v|`.
fn sign_all_prefixes(
    sk: &Bls12381G1PrivateKey,
    network: &NetworkDefinition,
    pc_ctx: &[u8],
    v: &PcVector,
    domain: &[u8],
) -> Vec<Bls12381G2Signature> {
    (0..=v.len())
        .map(|k| {
            let prefix = PcVector::new(v.iter().take(k).copied());
            sk.sign_v1(&pc_vote_signing_message(network, domain, pc_ctx, &prefix))
        })
        .collect()
}

// ─── Build ─────────────────────────────────────────────────────────────────

/// Assemble a [`PcQc1`] from a round-1 quorum.
///
/// # Panics
///
/// Panics if `votes.len() < f + 1` (where `f = (n - 1) / 3`) — the
/// caller is the FSM, which guarantees full `n - f` quorums.
#[must_use]
pub fn build_qc1(votes: &[&PcVote1], n: usize) -> PcQc1 {
    let f = byzantine_threshold(n);
    let raw_inputs: Vec<PcVector> = votes.iter().map(|v| v.v_in().clone()).collect();
    let x = qc1_certify(&raw_inputs, f).expect("build_qc1 caller guarantees votes.len() >= f+1");

    // Dedup by validator: the FSM supplies distinct senders, but a
    // downstream caller could pass duplicates. A silent skip yields a
    // short `x_signers` that the verifier rejects for size; cheaper
    // than panicking on a malformed inbox.
    let mut seen: BTreeSet<ValidatorId> = BTreeSet::new();
    let mut x_signers: Vec<PcCompactVote> = Vec::with_capacity(votes.len());
    let mut x_sigs: Vec<Bls12381G2Signature> = Vec::with_capacity(votes.len());
    for v1 in votes {
        if !seen.insert(v1.validator()) {
            continue;
        }
        let cv = compact_vote_for(v1.validator(), v1.v_in(), &x);
        let sig_idx = cv.shared_len() as usize + usize::from(cv.divergent().is_some());
        let sig = v1
            .prefix_sigs()
            .get(sig_idx)
            .copied()
            .expect("vote-1 carries |v_in|+1 prefix sigs; sig_idx ≤ |v_in|");
        x_signers.push(cv);
        x_sigs.push(sig);
    }
    let x_agg_sig = Bls12381G2Signature::aggregate(&x_sigs, true).expect("non-empty signers");
    PcQc1::new(x, x_signers, x_agg_sig)
}

/// Assemble a [`PcQc2`] from a round-2 quorum.
///
/// `committee` is required to resolve `ValidatorId`s to bitfield
/// positions for [`PcQc2::signers`].
///
/// # Panics
///
/// Panics if `votes` is empty, or if any signer in `votes` is not
/// present in `committee`.
#[must_use]
pub fn build_qc2(votes: &[&PcVote2], committee: &[(ValidatorId, Bls12381G1PublicKey)]) -> PcQc2 {
    let n = committee.len();
    let xs: Vec<PcVector> = votes.iter().map(|v| v.x().clone()).collect();
    let x_p = mcp(&xs).expect("build_qc2 caller guarantees non-empty votes");

    // Pull each signer's prefix sig at index |x_p| — covers x[..|x_p|]
    // = x_p (since every x extends x_p).
    let mut signers_bf = SignerBitfield::new(n);
    let mut sigs: Vec<Bls12381G2Signature> = Vec::with_capacity(votes.len());
    for v2 in votes {
        let pos = committee
            .iter()
            .position(|(id, _)| *id == v2.validator())
            .expect("vote-2 signer must be in committee");
        signers_bf.set(pos);
        let sig = v2
            .prefix_sigs()
            .get(x_p.len())
            .copied()
            .expect("vote-2 carries |x|+1 prefix sigs; index ≤ |x_p| ≤ |x|");
        sigs.push(sig);
    }
    let multi_sig = Bls12381G2Signature::aggregate(&sigs, true).expect("non-empty signers");

    // π proof. Three branches:
    //   - Full: every signer's `x` equals `x_p` exactly.
    //   - Diverging: at least two signers' `x` extend past `|x_p|`
    //     with different elements at position `|x_p|`.
    //   - ShortWitness: at least one signer's `|x| = |x_p|`, while
    //     extending signers all agree at position `|x_p|`.
    let pi = build_xp_proof(votes, &x_p);

    PcQc2::new(x_p, signers_bf, multi_sig, pi)
}

fn build_xp_proof(votes: &[&PcVote2], x_p: &PcVector) -> PcXpProof {
    let input_len = votes.first().map_or(0, |v| v.x().len());
    let all_equal_length = !votes.is_empty()
        && x_p.len() == input_len
        && votes.iter().all(|v| v.x().len() == input_len);
    if all_equal_length {
        let length_sigs: Vec<Bls12381G2Signature> =
            votes.iter().map(|v| v.length_attestation()).collect();
        let length_multi_sig =
            Bls12381G2Signature::aggregate(&length_sigs, true).expect("non-empty signers");
        return PcXpProof::Full { length_multi_sig };
    }

    let pos = x_p.len();
    let mut extending = votes.iter().filter(|v| v.x().len() > pos);
    let j_vote = extending
        .next()
        .expect("|x_p| < every-extending implies some voter extends past pos");
    let j_div = j_vote.x().as_slice()[pos];
    if let Some(k_vote) = extending.find(|v| v.x().as_slice()[pos] != j_div) {
        let sig_idx = pos + 1;
        let j_sig = j_vote
            .prefix_sigs()
            .get(sig_idx)
            .copied()
            .expect("prefix_sigs has |x|+1 entries; index ≤ |x|");
        let k_sig = k_vote
            .prefix_sigs()
            .get(sig_idx)
            .copied()
            .expect("prefix_sigs has |x|+1 entries; index ≤ |x|");
        return PcXpProof::Diverging(Box::new(PcDivergingProof {
            j: j_vote.validator(),
            j_divergent: j_div,
            j_sig,
            qc1_j: j_vote.qc1().clone(),
            k: k_vote.validator(),
            k_divergent: k_vote.x().as_slice()[pos],
            k_sig,
            qc1_k: k_vote.qc1().clone(),
        }));
    }

    // All extending votes agree at position |x_p|. The mcp is
    // constrained from below by a short voter whose |x| = |x_p|.
    let short = votes
        .iter()
        .find(|v| v.x().len() == pos)
        .expect("Full didn't fire and Diverging unavailable ⇒ some |x| = |x_p|");
    PcXpProof::ShortWitness {
        witness: Box::new((*short).clone()),
    }
}

/// Assemble a [`PcQc3`] from a round-3 quorum.
///
/// Endpoints `(x_pp, x_pe)` get dedup-encoded when they coincide (the
/// common case: every signer's `x_p` equal). The verifier resolves
/// the dedup via [`PcQc3::x_pe`] / [`PcQc3::qc2_xpe`].
///
/// # Panics
///
/// Panics if `votes` is empty.
#[must_use]
#[allow(clippy::similar_names)] // x_pp / x_pe / qc2_xpp / qc2_xpe match PcQc3's wire-type field names
pub fn build_qc3(votes: &[&PcVote3]) -> PcQc3 {
    let x_ps: Vec<PcVector> = votes.iter().map(|v| v.x_p().clone()).collect();
    let x_pp = mcp(&x_ps).expect("build_qc3 caller guarantees non-empty votes");
    let x_pe = mce(&x_ps).expect("round-3 x_p values mutually extend");

    let qc2_xpp = votes
        .iter()
        .find(|v| v.x_p() == &x_pp)
        .map(|v| v.qc2().clone())
        .expect("x_pp is some vote's x_p");
    let qc2_xpe_full = votes
        .iter()
        .find(|v| v.x_p() == &x_pe)
        .map(|v| v.qc2().clone())
        .expect("x_pe is some vote's x_p");

    let mut all_signers: Vec<PcCompactLenSigner> = Vec::with_capacity(votes.len());
    let mut sig_bytes: Vec<Bls12381G2Signature> = Vec::with_capacity(votes.len());
    for v in votes {
        let prefix_len = u32::try_from(v.x_p().len()).unwrap_or(u32::MAX);
        all_signers.push(PcCompactLenSigner::new(v.validator(), prefix_len));
        sig_bytes.push(v.sig_xp());
    }
    let agg_sig = Bls12381G2Signature::aggregate(&sig_bytes, true).expect("non-empty signers");

    let x_pe_dedup = (x_pp != x_pe).then_some(x_pe);
    let qc2_xpe_dedup = (qc2_xpp != qc2_xpe_full).then_some(qc2_xpe_full);

    PcQc3::new(
        x_pp,
        qc2_xpp,
        x_pe_dedup,
        qc2_xpe_dedup,
        all_signers,
        agg_sig,
    )
}

/// Compact-encode `v_in` relative to the canonical `x`. The encoding
/// captures the deviation point (length of the maximum common prefix)
/// and the first divergent element when `v_in` is not itself a prefix
/// of `x`.
fn compact_vote_for(validator: ValidatorId, v_in: &PcVector, x: &PcVector) -> PcCompactVote {
    if v_in.as_slice() == x.as_slice() {
        let shared_len = u32::try_from(v_in.len()).unwrap_or(u32::MAX);
        return PcCompactVote::new(validator, shared_len, None);
    }
    let shared = mcp_two(v_in, x);
    let divergent = v_in.as_slice().get(shared).copied();
    let shared_len = u32::try_from(shared).unwrap_or(u32::MAX);
    PcCompactVote::new(validator, shared_len, divergent)
}

/// Length of the maximum common prefix of two vectors.
fn mcp_two(a: &PcVector, b: &PcVector) -> usize {
    let n = a.len().min(b.len());
    let mut k = 0;
    while k < n && a.as_slice()[k] == b.as_slice()[k] {
        k += 1;
    }
    k
}

// ─── FSM ───────────────────────────────────────────────────────────────────

/// What `PcInstance::handle` tells its parent.
///
/// Sub-machine-local — the parent (SPC) drains these and lifts them
/// into either internal state mutations or further effects bubbling
/// up to MSC and the `BeaconCoordinator`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcEffect {
    /// Broadcast a freshly-signed round-1 vote.
    BroadcastVote1(Box<PcVote1>),
    /// Broadcast a freshly-signed round-2 vote.
    BroadcastVote2(Box<PcVote2>),
    /// Broadcast a freshly-signed round-3 vote.
    BroadcastVote3(Box<PcVote3>),
    /// Slim wire-form evidence that a peer double-signed at the same
    /// `(slot, view, round)`. The parent assembles this into beacon
    /// witnesses for inclusion in a future beacon proposal.
    EquivocationObserved(Box<PcVoteEquivocation>),
    /// Round-3 quorum reached — terminal cert ready. The parent reads
    /// the certified low (`qc3.x_pp`) and high (`qc3.x_pe`) out of
    /// the embedded QC.
    Decided(Box<PcQc3>),
}

/// Events `PcInstance::handle` consumes.
#[derive(Debug, Clone)]
pub enum PcEvent {
    /// The local validator's input vector. Idempotent: subsequent
    /// inputs after the first are dropped.
    Input(PcVector),
    /// A peer's round-1 vote arrived. The IO layer is responsible for
    /// the sender-to-validator authentication check before dispatch.
    Vote1Received(PcVote1),
    /// A peer's round-2 vote arrived.
    Vote2Received(Box<PcVote2>),
    /// A peer's round-3 vote arrived.
    Vote3Received(Box<PcVote3>),
}

/// One inner-PC FSM instance, scoped to a single `(slot, view)`.
///
/// SPC owns one `PcInstance` per view it drives; MSC owns one
/// `SpcInstance` per slot. The FSM is synchronous — every event-
/// handler invocation returns the full set of effects that follow,
/// and the parent drains them.
pub struct PcInstance {
    network: NetworkDefinition,
    slot: Slot,
    view: SpcView,
    pc_ctx: Vec<u8>,
    committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    me: ValidatorId,
    me_sk: Arc<Bls12381G1PrivateKey>,

    vote1_pool: BTreeMap<ValidatorId, PcVote1>,
    vote2_pool: BTreeMap<ValidatorId, PcVote2>,
    vote3_pool: BTreeMap<ValidatorId, PcVote3>,

    input: Option<PcVector>,
    sent_vote2: bool,
    sent_vote3: bool,
    decided: bool,
}

impl PcInstance {
    /// Construct a fresh PC instance for `(slot, view)`.
    ///
    /// # Panics
    ///
    /// Panics if `committee.len() < 4` — PC requires `n >= 3f + 1`
    /// and `f = (n - 1) / 3`, which collapses to `n >= 4`.
    #[must_use]
    pub fn new(
        network: NetworkDefinition,
        slot: Slot,
        view: SpcView,
        committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
        me: ValidatorId,
        me_sk: Arc<Bls12381G1PrivateKey>,
    ) -> Self {
        assert!(
            committee.len() >= 4,
            "PC requires n >= 4 (3f + 1 with f = 1); got n = {}",
            committee.len()
        );
        let pc_ctx = pc_context(&spc_context(slot), view);
        Self {
            network,
            slot,
            view,
            pc_ctx,
            committee,
            me,
            me_sk,
            vote1_pool: BTreeMap::new(),
            vote2_pool: BTreeMap::new(),
            vote3_pool: BTreeMap::new(),
            input: None,
            sent_vote2: false,
            sent_vote3: false,
            decided: false,
        }
    }

    /// Whether the local validator's input has been set.
    #[must_use]
    pub const fn has_input(&self) -> bool {
        self.input.is_some()
    }

    /// Whether the FSM has emitted a `Decided` effect (round-3 quorum
    /// reached at least once).
    #[must_use]
    pub const fn is_decided(&self) -> bool {
        self.decided
    }

    /// Process one event; returns the resulting effects, possibly
    /// empty.
    pub fn handle(&mut self, event: PcEvent) -> Vec<PcEffect> {
        match event {
            PcEvent::Input(v) => self.on_input(v),
            PcEvent::Vote1Received(vote) => self.on_vote1(vote),
            PcEvent::Vote2Received(vote) => self.on_vote2(*vote),
            PcEvent::Vote3Received(vote) => self.on_vote3(*vote),
        }
    }

    const fn quorum(&self) -> usize {
        let n = self.committee.len();
        n - byzantine_threshold(n)
    }

    fn on_input(&mut self, v: PcVector) -> Vec<PcEffect> {
        if self.input.is_some() {
            return vec![];
        }
        let vote1 = sign_vote1(&self.me_sk, self.me, &self.network, &self.pc_ctx, v.clone());
        self.input = Some(v);
        self.vote1_pool.insert(self.me, vote1.clone());
        let mut effects = vec![PcEffect::BroadcastVote1(Box::new(vote1))];
        effects.extend(self.maybe_advance_to_round2());
        effects
    }

    fn on_vote1(&mut self, v1: PcVote1) -> Vec<PcEffect> {
        if !verify_vote1(&v1, &self.network, &self.pc_ctx, &self.committee) {
            return vec![];
        }
        let from = v1.validator();
        if let Some(existing) = self.vote1_pool.get(&from) {
            if existing.v_in() == v1.v_in() {
                return vec![];
            }
            return vec![PcEffect::EquivocationObserved(Box::new(
                self.equivocation_wire(
                    from,
                    PcVoteRound::Vote1,
                    existing.v_in().clone(),
                    prefix_top_sig(existing),
                    v1.v_in().clone(),
                    prefix_top_sig(&v1),
                ),
            ))];
        }
        self.vote1_pool.insert(from, v1);
        self.maybe_advance_to_round2()
    }

    fn on_vote2(&mut self, v2: PcVote2) -> Vec<PcEffect> {
        if !verify_vote2(&v2, &self.network, &self.pc_ctx, &self.committee) {
            return vec![];
        }
        let from = v2.validator();
        if let Some(existing) = self.vote2_pool.get(&from) {
            // Vote2's signed payload is `x` — different `qc1` aggregations
            // are honest re-aggregations, not equivocation.
            if existing.x() == v2.x() {
                return vec![];
            }
            return vec![PcEffect::EquivocationObserved(Box::new(
                self.equivocation_wire(
                    from,
                    PcVoteRound::Vote2,
                    existing.x().clone(),
                    vote2_top_sig(existing),
                    v2.x().clone(),
                    vote2_top_sig(&v2),
                ),
            ))];
        }
        self.vote2_pool.insert(from, v2);
        self.maybe_advance_to_round3()
    }

    fn on_vote3(&mut self, v3: PcVote3) -> Vec<PcEffect> {
        if !verify_vote3(&v3, &self.network, &self.pc_ctx, &self.committee) {
            return vec![];
        }
        let from = v3.validator();
        if let Some(existing) = self.vote3_pool.get(&from) {
            // Vote3's signed payload is `x_p` — different `qc2`s are
            // honest re-aggregations, not equivocation.
            if existing.x_p() == v3.x_p() {
                return vec![];
            }
            return vec![PcEffect::EquivocationObserved(Box::new(
                self.equivocation_wire(
                    from,
                    PcVoteRound::Vote3,
                    existing.x_p().clone(),
                    existing.sig_xp(),
                    v3.x_p().clone(),
                    v3.sig_xp(),
                ),
            ))];
        }
        self.vote3_pool.insert(from, v3);
        self.maybe_finalize()
    }

    fn maybe_advance_to_round2(&mut self) -> Vec<PcEffect> {
        if self.sent_vote2 || self.vote1_pool.len() < self.quorum() {
            return vec![];
        }
        let q = self.quorum();
        let n = self.committee.len();
        let vote1s: Vec<&PcVote1> = self.vote1_pool.values().take(q).collect();
        let qc1 = build_qc1(&vote1s, n);
        let our_vote2 = sign_vote2(&self.me_sk, self.me, &self.network, &self.pc_ctx, qc1);
        self.sent_vote2 = true;
        self.vote2_pool.insert(self.me, our_vote2.clone());
        let mut effects = vec![PcEffect::BroadcastVote2(Box::new(our_vote2))];
        effects.extend(self.maybe_advance_to_round3());
        effects
    }

    fn maybe_advance_to_round3(&mut self) -> Vec<PcEffect> {
        if self.sent_vote3 || self.vote2_pool.len() < self.quorum() {
            return vec![];
        }
        let q = self.quorum();
        let vote2s: Vec<&PcVote2> = self.vote2_pool.values().take(q).collect();
        let qc2 = build_qc2(&vote2s, &self.committee);
        let our_vote3 = sign_vote3(&self.me_sk, self.me, &self.network, &self.pc_ctx, qc2);
        self.sent_vote3 = true;
        self.vote3_pool.insert(self.me, our_vote3.clone());
        let mut effects = vec![PcEffect::BroadcastVote3(Box::new(our_vote3))];
        effects.extend(self.maybe_finalize());
        effects
    }

    fn maybe_finalize(&mut self) -> Vec<PcEffect> {
        if self.decided || self.vote3_pool.len() < self.quorum() {
            return vec![];
        }
        let q = self.quorum();
        let vote3s: Vec<&PcVote3> = self.vote3_pool.values().take(q).collect();
        let qc3 = build_qc3(&vote3s);
        self.decided = true;
        vec![PcEffect::Decided(Box::new(qc3))]
    }

    const fn equivocation_wire(
        &self,
        equivocator: ValidatorId,
        round: PcVoteRound,
        value_a: PcVector,
        sig_a: Bls12381G2Signature,
        value_b: PcVector,
        sig_b: Bls12381G2Signature,
    ) -> PcVoteEquivocation {
        PcVoteEquivocation {
            validator: equivocator,
            slot: self.slot,
            view: self.view,
            round,
            value_a,
            sig_a,
            value_b,
            sig_b,
        }
    }
}

/// Pull the round-1 vote's "primary" sig — the sig over the full
/// `v_in` vector, sitting at `prefix_sigs[v_in.len()]`. This is the
/// sig the slim wire form carries.
fn prefix_top_sig(v: &PcVote1) -> Bls12381G2Signature {
    v.prefix_sigs()[v.v_in().len()]
}

/// Pull the round-2 vote's "primary" sig — the sig over the full
/// `x` vector at `prefix_sigs[x.len()]`.
fn vote2_top_sig(v: &PcVote2) -> Bls12381G2Signature {
    v.prefix_sigs()[v.x().len()]
}

#[cfg(test)]
mod tests {
    //! Structural-rejection smoke tests for the verifier gates.

    use hyperscale_types::{
        PC_VALUE_ELEMENT_BYTES, PcCompactLenSigner, PcCompactVote, PcQc1, PcQc2, PcQc3,
        PcValueElement, PcVector, PcXpProof, SignerBitfield, generate_bls_keypair,
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

    fn elem(b: u8) -> PcValueElement {
        PcValueElement::new([b; PC_VALUE_ELEMENT_BYTES])
    }

    fn ctx() -> Vec<u8> {
        // Standalone test context — real callers use `spc_context(slot)`
        // followed by `pc_context(spc_ctx, view)`, but the verifier
        // doesn't care about its internal shape so long as it agrees
        // with the signer.
        vec![1, 2, 3, 4]
    }

    /// QC1 with the wrong signer-set size (≠ n - f) must be rejected
    /// before any BLS pairing — this is the signer-set-sizing gate.
    #[test]
    fn verify_qc1_rejects_wrong_signer_count() {
        let c = committee(4);
        // n=4, f=1, q=3 — supply only 2 signers.
        let qc1 = PcQc1::new(
            PcVector::new(std::iter::once(elem(1))),
            vec![
                PcCompactVote::new(ValidatorId::new(0), 1, None),
                PcCompactVote::new(ValidatorId::new(1), 1, None),
            ],
            generate_bls_keypair().sign_v1(b"unused"),
        );
        assert!(!verify_qc1(&qc1, &net(), &ctx(), &c));
    }

    /// QC1 carrying a non-committee `ValidatorId` in its signer list
    /// must be rejected — this is the committee-membership gate.
    #[test]
    fn verify_qc1_rejects_non_committee_signer() {
        let c = committee(4);
        let qc1 = PcQc1::new(
            PcVector::empty(),
            vec![
                PcCompactVote::new(ValidatorId::new(0), 0, None),
                PcCompactVote::new(ValidatorId::new(1), 0, None),
                // 999 is outside the committee.
                PcCompactVote::new(ValidatorId::new(999), 0, None),
            ],
            generate_bls_keypair().sign_v1(b"unused"),
        );
        assert!(!verify_qc1(&qc1, &net(), &ctx(), &c));
    }

    /// QC1 with a duplicate signer must be rejected — closes the
    /// sub-quorum-inflation path.
    #[test]
    fn verify_qc1_rejects_duplicate_signer() {
        let c = committee(4);
        let qc1 = PcQc1::new(
            PcVector::empty(),
            vec![
                PcCompactVote::new(ValidatorId::new(0), 0, None),
                PcCompactVote::new(ValidatorId::new(1), 0, None),
                // Duplicate of validator 1.
                PcCompactVote::new(ValidatorId::new(1), 0, None),
            ],
            generate_bls_keypair().sign_v1(b"unused"),
        );
        assert!(!verify_qc1(&qc1, &net(), &ctx(), &c));
    }

    /// QC2 with the wrong signer-bitfield count (≠ n - f) must be
    /// rejected before any BLS pairing.
    #[test]
    fn verify_qc2_rejects_wrong_signer_count() {
        let c = committee(4);
        let mut bf = SignerBitfield::new(4);
        bf.set(0);
        bf.set(1);
        // Only 2 of expected 3.
        let qc2 = PcQc2::new(
            PcVector::empty(),
            bf,
            generate_bls_keypair().sign_v1(b"unused"),
            PcXpProof::Full {
                length_multi_sig: generate_bls_keypair().sign_v1(b"unused"),
            },
        );
        assert!(!verify_qc2(&qc2, &net(), &ctx(), &c));
    }

    /// QC2 with a signer-bitfield bit set outside the committee range
    /// must be rejected.
    #[test]
    fn verify_qc2_rejects_out_of_range_bitfield() {
        let c = committee(4);
        // Size 8 bitfield (bigger than committee) with bit at index 7
        // — outside the n=4 committee range.
        let mut bf = SignerBitfield::new(8);
        bf.set(0);
        bf.set(1);
        bf.set(7);
        let qc2 = PcQc2::new(
            PcVector::empty(),
            bf,
            generate_bls_keypair().sign_v1(b"unused"),
            PcXpProof::Full {
                length_multi_sig: generate_bls_keypair().sign_v1(b"unused"),
            },
        );
        assert!(!verify_qc2(&qc2, &net(), &ctx(), &c));
    }

    /// QC3 must reject `x_pp` that isn't a prefix of `x_pe` — the
    /// foundational structural invariant.
    #[test]
    fn verify_qc3_rejects_non_prefix_endpoints() {
        let c = committee(4);
        // x_pp = [2], x_pe = [1] — not a prefix.
        let qc3 = PcQc3::new(
            PcVector::new(std::iter::once(elem(2))),
            dummy_qc2(),
            Some(PcVector::new(std::iter::once(elem(1)))),
            Some(dummy_qc2()),
            vec![PcCompactLenSigner::new(ValidatorId::new(0), 1)],
            generate_bls_keypair().sign_v1(b"unused"),
        );
        assert!(!verify_qc3(&qc3, &net(), &ctx(), &c));
    }

    /// QC3 with `all_signers.len() ≠ n - f` is rejected for size
    /// — even before signature checks.
    #[test]
    fn verify_qc3_rejects_wrong_signer_count() {
        let c = committee(4);
        let qc3 = PcQc3::new(
            PcVector::empty(),
            dummy_qc2(),
            None,
            None,
            // Expected 3, supplied 2.
            vec![
                PcCompactLenSigner::new(ValidatorId::new(0), 0),
                PcCompactLenSigner::new(ValidatorId::new(1), 0),
            ],
            generate_bls_keypair().sign_v1(b"unused"),
        );
        assert!(!verify_qc3(&qc3, &net(), &ctx(), &c));
    }

    /// `reconstruct_compact_vote` rejects an encoding where the
    /// "divergent" element coincides with `x[shared_len]`. Such an
    /// encoding would be non-unique (could equally be encoded as
    /// `shared_len + 1, divergent = x[shared_len + 1]?`).
    #[test]
    fn reconstruct_compact_vote_rejects_non_unique_divergent() {
        let x = PcVector::new([elem(1), elem(2)]);
        // Diverges at position 0 but the "divergent" element IS x[0].
        let cv = PcCompactVote::new(ValidatorId::new(0), 0, Some(elem(1)));
        assert!(reconstruct_compact_vote(&cv, &x).is_none());
    }

    /// `verify_vote_equivocation` rejects evidence where both sides
    /// carry the same value — no actual contradiction.
    #[test]
    fn verify_vote_equivocation_rejects_same_value() {
        use hyperscale_types::{PcVoteEquivocation, PcVoteRound, Slot, SpcView};
        let c = committee(4);
        let v = PcVector::new(std::iter::once(elem(1)));
        let ev = PcVoteEquivocation {
            validator: ValidatorId::new(0),
            slot: Slot::new(1),
            view: SpcView::new(0),
            round: PcVoteRound::Vote1,
            value_a: v.clone(),
            sig_a: generate_bls_keypair().sign_v1(b"unused"),
            value_b: v,
            sig_b: generate_bls_keypair().sign_v1(b"unused"),
        };
        assert!(!verify_vote_equivocation(&ev, &net(), &c));
    }

    /// `verify_vote_equivocation` rejects evidence naming a non-
    /// committee validator before any pairing.
    #[test]
    fn verify_vote_equivocation_rejects_non_committee_validator() {
        use hyperscale_types::{PcVoteEquivocation, PcVoteRound, Slot, SpcView};
        let c = committee(4);
        let ev = PcVoteEquivocation {
            validator: ValidatorId::new(999),
            slot: Slot::new(1),
            view: SpcView::new(0),
            round: PcVoteRound::Vote1,
            value_a: PcVector::new(std::iter::once(elem(1))),
            sig_a: generate_bls_keypair().sign_v1(b"unused"),
            value_b: PcVector::new(std::iter::once(elem(2))),
            sig_b: generate_bls_keypair().sign_v1(b"unused"),
        };
        assert!(!verify_vote_equivocation(&ev, &net(), &c));
    }

    /// Length attestation message must differ across `len` values to
    /// stop length-splice attacks.
    #[test]
    fn length_attestation_message_differs_across_lengths() {
        let a = length_attestation_message(&net(), &ctx(), 0);
        let b = length_attestation_message(&net(), &ctx(), 1);
        let c = length_attestation_message(&net(), &ctx(), 17);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    fn dummy_qc2() -> PcQc2 {
        PcQc2::new(
            PcVector::empty(),
            SignerBitfield::new(4),
            generate_bls_keypair().sign_v1(b"unused"),
            PcXpProof::Full {
                length_multi_sig: generate_bls_keypair().sign_v1(b"unused"),
            },
        )
    }

    // ─── FSM tests ─────────────────────────────────────────────────────

    use hyperscale_types::{Slot, SpcView, bls_keypair_from_seed};

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
            let pk = sk.public_key();
            members.push((ValidatorId::new(i as u64), pk));
            sks.push(Arc::new(sk));
        }
        (sks, members)
    }

    fn fsm_instance(idx: usize) -> PcInstance {
        let (sks, members) = fsm_committee(4);
        PcInstance::new(
            net(),
            Slot::new(1),
            SpcView::new(0),
            members.clone(),
            members[idx].0,
            Arc::clone(&sks[idx]),
        )
    }

    /// `PcInstance::new` panics when the committee is too small for
    /// any BFT (`n < 4`). Enforces the `n >= 3f + 1` precondition at
    /// construction so the FSM never enters a state where `quorum()`
    /// is undefined.
    #[test]
    #[should_panic(expected = "PC requires n >= 4")]
    fn pc_instance_rejects_undersized_committee() {
        let (sks, members) = fsm_committee(3);
        let _ = PcInstance::new(
            net(),
            Slot::new(1),
            SpcView::new(0),
            members,
            ValidatorId::new(0),
            Arc::clone(&sks[0]),
        );
    }

    /// First `Input` event emits a `BroadcastVote1` and seeds the
    /// local vote-1 pool. Subsequent inputs are idempotent.
    #[test]
    fn pc_input_emits_single_broadcast_then_idempotent() {
        let mut fsm = fsm_instance(0);
        let v = PcVector::new(std::iter::once(elem(7)));
        let effects = fsm.handle(PcEvent::Input(v.clone()));
        assert_eq!(effects.len(), 1);
        assert!(matches!(effects[0], PcEffect::BroadcastVote1(_)));
        assert!(fsm.has_input());

        // Second input — already set, no effects.
        let effects2 = fsm.handle(PcEvent::Input(v));
        assert!(effects2.is_empty());
    }

    /// Two distinct round-1 votes from the same peer (different
    /// `v_in`) trigger `EquivocationObserved`. Both sides individually
    /// verify; the FSM's pool collision is what surfaces it.
    #[test]
    fn pc_observes_round1_equivocation() {
        let (sks, members) = fsm_committee(4);
        let mut fsm = PcInstance::new(
            net(),
            Slot::new(1),
            SpcView::new(0),
            members.clone(),
            members[0].0,
            Arc::clone(&sks[0]),
        );

        // Two distinct v_ins signed by validator 1 (the equivocator).
        let pc_ctx_bytes = pc_context(&spc_context(Slot::new(1)), SpcView::new(0));
        let v_a = PcVector::new(std::iter::once(elem(1)));
        let v_b = PcVector::new(std::iter::once(elem(2)));
        let vote_a = sign_vote1(&sks[1], members[1].0, &net(), &pc_ctx_bytes, v_a);
        let vote_b = sign_vote1(&sks[1], members[1].0, &net(), &pc_ctx_bytes, v_b);

        let effects_a = fsm.handle(PcEvent::Vote1Received(vote_a));
        assert!(effects_a.is_empty(), "first vote pools without effect");
        let effects_b = fsm.handle(PcEvent::Vote1Received(vote_b));
        let [PcEffect::EquivocationObserved(ev)] = effects_b.as_slice() else {
            panic!("expected EquivocationObserved, got {effects_b:?}");
        };
        assert_eq!(ev.validator, members[1].0);
        assert_eq!(ev.round, PcVoteRound::Vote1);
    }
}
