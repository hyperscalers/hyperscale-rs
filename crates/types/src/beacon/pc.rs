//! Prefix Consensus (PC) vote and QC wire types.
//!
//! PC is the inner three-round protocol that drives one epoch's committee
//! from individual input vectors to a single certified
//! `(certified_low, certified_high)` pair. Every honest committee
//! member's input vector is a sequence of [`PcValueElement`]s; PC's job
//! is to attain agreement on the maximum common prefix the committee
//! could collectively endorse, witnessed by an aggregate signature.
//!
//! These types describe the *wire form* of votes and QCs at each round.
//! Verification, multi-sig assembly, and the protocol state machine
//! live in the beacon crate.

use std::collections::BTreeSet;

use sbor::prelude::*;
use thiserror::Error;

use crate::beacon::prefix_ops::{mce, mcp, qc1_certify};
use crate::primitives::signer_bitfield::MAX_VALIDATORS;
use crate::{
    Bls12381G1PrivateKey, Bls12381G1PublicKey, Bls12381G2Signature, BoundedVec, DOMAIN_PC_VOTE1,
    DOMAIN_PC_VOTE2, DOMAIN_PC_VOTE2_LENGTH, DOMAIN_PC_VOTE3, Epoch, MAX_PREFIX_SIGS,
    MAX_VOTE_VECTOR_LEN, NetworkDefinition, PcContext, PositionalBundle, SignerBitfield,
    SpcNewCommitMsg, SpcView, ValidatorId, Verifiable, Verified, Verify,
    aggregate_verify_bls_different_messages, pc_context, pc_vote_signing_message, spc_context,
};

// ── ValueElement and Vector ──────────────────────────────────────────────────

/// Wire size of a single [`PcValueElement`] in bytes.
pub const PC_VALUE_ELEMENT_BYTES: usize = 32;

/// One element of a PC input vector.
///
/// Opaque 32-byte payload; the beacon application packs proposal
/// commitments here. 32 bytes is wide enough to hold a full BLAKE3
/// digest so committed vectors retain the hash function's collision
/// resistance (~2^128 birthday work for the 32-byte digest) rather
/// than the ~2^32 a truncated `u64` would give.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, BasicSbor)]
#[sbor(transparent)]
pub struct PcValueElement([u8; PC_VALUE_ELEMENT_BYTES]);

impl PcValueElement {
    /// All-zero element. Used as the `HASH_BOTTOM` sentinel in
    /// view-1 PC inputs when a proposal slot is absent.
    pub const ZERO: Self = Self([0u8; PC_VALUE_ELEMENT_BYTES]);

    /// Build a `PcValueElement` from a raw 32-byte array.
    #[must_use]
    pub const fn new(bytes: [u8; PC_VALUE_ELEMENT_BYTES]) -> Self {
        Self(bytes)
    }

    /// Pack a 64-bit view number into a `PcValueElement`. Used by SPC's
    /// `skip_target` encoding to pin empty-view skip statements to a
    /// specific `(empty_view, reported_view)` pair.
    #[must_use]
    pub const fn from_view_number(n: u64) -> Self {
        let mut bytes = [0u8; PC_VALUE_ELEMENT_BYTES];
        let le = n.to_le_bytes();
        let mut i = 0;
        while i < 8 {
            bytes[i] = le[i];
            i += 1;
        }
        Self(bytes)
    }

    /// Get the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PC_VALUE_ELEMENT_BYTES] {
        &self.0
    }
}

/// A PC input vector — a bounded ordered sequence of [`PcValueElement`]s.
///
/// PC's safety property guarantees a finalized epoch's certified low /
/// high pair are both prefixes of every honest committee member's
/// committed vector ("Lemma 3.1"). Carrying the full vector at every
/// round (rather than a hash) lets verifiers run the prefix-consistency
/// arithmetic without having to fetch additional preimages.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
#[sbor(transparent)]
pub struct PcVector(BoundedVec<PcValueElement, MAX_VOTE_VECTOR_LEN>);

impl PcVector {
    /// Empty vector.
    #[must_use]
    pub const fn empty() -> Self {
        Self(BoundedVec::new())
    }

    /// Build a `PcVector` from an iterator of elements.
    ///
    /// # Panics
    ///
    /// Panics if the collected length exceeds [`MAX_VOTE_VECTOR_LEN`].
    #[must_use]
    pub fn new<I: IntoIterator<Item = PcValueElement>>(elements: I) -> Self {
        Self(elements.into_iter().collect::<Vec<_>>().into())
    }

    /// Number of elements in the vector.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the vector is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrow the elements as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[PcValueElement] {
        &self.0
    }

    /// Iterate over the elements.
    pub fn iter(&self) -> impl Iterator<Item = &PcValueElement> + '_ {
        self.0.iter()
    }

    /// Whether `self` is a prefix of `other` (possibly equal).
    ///
    /// Paper notation: `self ⪯ other`.
    #[must_use]
    pub fn is_prefix_of(&self, other: &Self) -> bool {
        self.len() <= other.len() && self.as_slice() == &other.as_slice()[..self.len()]
    }

    /// Whether `self` and `other` are *consistent* — one is a prefix of
    /// the other.
    #[must_use]
    pub fn is_consistent_with(&self, other: &Self) -> bool {
        let n = self.len().min(other.len());
        self.as_slice()[..n] == other.as_slice()[..n]
    }
}

impl<'a> IntoIterator for &'a PcVector {
    type Item = &'a PcValueElement;
    type IntoIter = std::slice::Iter<'a, PcValueElement>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

// ── Round-1 ──────────────────────────────────────────────────────────────────

/// Round-1 vote — a signer's input vector with an `L+1` prefix-sig
/// fan-out (one signature per prefix of `v_in`, including the empty
/// prefix epoch).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct PcVote1 {
    validator: ValidatorId,
    v_in: PcVector,
    /// `prefix_sigs[k]` is the signer's BLS sig over `v_in[..k]`.
    /// Length is `v_in.len() + 1`.
    prefix_sigs: BoundedVec<Bls12381G2Signature, MAX_PREFIX_SIGS>,
}

impl PcVote1 {
    /// Build a `PcVote1` from its parts.
    ///
    /// # Panics
    ///
    /// Panics if `prefix_sigs.len() > MAX_PREFIX_SIGS`.
    #[must_use]
    pub fn new(
        validator: ValidatorId,
        v_in: PcVector,
        prefix_sigs: Vec<Bls12381G2Signature>,
    ) -> Self {
        Self {
            validator,
            v_in,
            prefix_sigs: prefix_sigs.into(),
        }
    }

    /// Validator that cast this vote.
    #[must_use]
    pub const fn validator(&self) -> ValidatorId {
        self.validator
    }

    /// Signer's input vector for the epoch.
    #[must_use]
    pub const fn v_in(&self) -> &PcVector {
        &self.v_in
    }

    /// Per-prefix BLS signatures over `v_in[..k]`, indexed by prefix length.
    #[must_use]
    pub const fn prefix_sigs(&self) -> &BoundedVec<Bls12381G2Signature, MAX_PREFIX_SIGS> {
        &self.prefix_sigs
    }
}

/// Compact representation of a signer's round-1 vote inside a [`PcQc1`].
///
/// Instead of carrying the full reconstructed `v'_i`, encode the
/// deviation from the canonical `x` as a single `(shared_len,
/// divergent)` pair: `shared_len` is how many leading elements of
/// `v_in_i` agree with `x` (always in `[0, |x|]`), and `divergent` is
/// the first element past `shared_len` when one exists, `None` when
/// `v_in_i` is a prefix of `x`.
///
/// Validator identity is carried positionally by the enclosing
/// [`PositionalBundle`] in [`PcQc1::x_signers`].
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct PcCompactVote {
    /// `|mcp(v_in_i, x)|` — fixed-width on the wire across host word
    /// sizes; bounded above by [`MAX_VOTE_VECTOR_LEN`].
    shared_len: u32,
    /// First divergent element of `v_in_i` past `shared_len`. `None`
    /// iff `v_in_i` is a prefix of `x`.
    divergent: Option<PcValueElement>,
}

impl PcCompactVote {
    /// Build a `PcCompactVote` from its parts.
    #[must_use]
    pub const fn new(shared_len: u32, divergent: Option<PcValueElement>) -> Self {
        Self {
            shared_len,
            divergent,
        }
    }

    /// Length of the maximum common prefix between the signer's
    /// `v_in_i` and the canonical `x`.
    #[must_use]
    pub const fn shared_len(&self) -> u32 {
        self.shared_len
    }

    /// First divergent element of `v_in_i` past `shared_len`, if any.
    #[must_use]
    pub const fn divergent(&self) -> Option<&PcValueElement> {
        self.divergent.as_ref()
    }
}

/// Round-1 QC: the certified prefix `x` together with a compact view of
/// every round-1 signer's `v_in_i` relative to `x`, aggregated into a
/// single BLS signature.
///
/// `x` is the longest prefix attained by some `(f+1)`-subset of
/// round-1's signer set; the verifier reconstructs each signer's
/// `v'_i` from the compact encoding and re-runs the max-subset check
/// over all `n-f` signers. Carrying the full signer set (not just the
/// achieving `(f+1)`-subset) is load-bearing for soundness.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct PcQc1 {
    x: PcVector,
    /// Round-1 quorum (`n - f` signers), each compact-encoded against
    /// `x`. Validator identity is positional in the bundle's bitfield.
    x_signers: PositionalBundle<PcCompactVote>,
    /// Aggregate over each signer's `sig_i(v'_i)` — different-messages
    /// aggregate, since each `v'_i` may be a different length.
    x_agg_sig: Bls12381G2Signature,
}

impl PcQc1 {
    /// Build a `PcQc1` from its parts.
    #[must_use]
    pub const fn new(
        x: PcVector,
        x_signers: PositionalBundle<PcCompactVote>,
        x_agg_sig: Bls12381G2Signature,
    ) -> Self {
        Self {
            x,
            x_signers,
            x_agg_sig,
        }
    }

    /// Certified prefix.
    #[must_use]
    pub const fn x(&self) -> &PcVector {
        &self.x
    }

    /// Compact round-1 signer set, paired with positional validator ids.
    #[must_use]
    pub const fn x_signers(&self) -> &PositionalBundle<PcCompactVote> {
        &self.x_signers
    }

    /// Different-messages BLS aggregate over the signers' `sig_i(v'_i)`.
    #[must_use]
    pub const fn x_agg_sig(&self) -> Bls12381G2Signature {
        self.x_agg_sig
    }
}

// ── Round-2 ──────────────────────────────────────────────────────────────────

/// Round-2 vote — carries the certified prefix `x` from the signer's
/// own [`PcQc1`], prefix sigs over `x`, the [`PcQc1`] itself, and an
/// explicit length attestation.
///
/// The length attestation pins each signer's `|x|` so a third-party
/// prover can't splice their prefix sigs to forge a shorter-`x` claim.
/// Required by `XpProof::ShortWitness` verification.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct PcVote2 {
    validator: ValidatorId,
    x: PcVector,
    /// `prefix_sigs[k]` is `sig_validator(x[..k])`. Length `|x| + 1`.
    prefix_sigs: BoundedVec<Bls12381G2Signature, MAX_PREFIX_SIGS>,
    /// Embedded round-1 QC. Wire decode lands as `Verifiable::Unverified`;
    /// locally-signed votes from `Verified::<PcVote2>::sign_local` carry
    /// the marker so the round-2 verifier short-circuits the embedded
    /// QC check.
    qc1: Verifiable<PcQc1>,
    /// `sig_validator([x.len()])` under the round-2 length tag. Binds
    /// the signer to their specific `x` length.
    length_attestation: Bls12381G2Signature,
}

impl PcVote2 {
    /// Build a `PcVote2` from its parts. Accepts either a raw `PcQc1`
    /// or a `Verified<PcQc1>` for `qc1` — the wrapper preserves the
    /// marker for the round-2 verifier's short-circuit.
    ///
    /// # Panics
    ///
    /// Panics if `prefix_sigs.len() > MAX_PREFIX_SIGS`.
    #[must_use]
    pub fn new(
        validator: ValidatorId,
        x: PcVector,
        prefix_sigs: Vec<Bls12381G2Signature>,
        qc1: impl Into<Verifiable<PcQc1>>,
        length_attestation: Bls12381G2Signature,
    ) -> Self {
        Self {
            validator,
            x,
            prefix_sigs: prefix_sigs.into(),
            qc1: qc1.into(),
            length_attestation,
        }
    }

    /// Validator that cast this vote.
    #[must_use]
    pub const fn validator(&self) -> ValidatorId {
        self.validator
    }

    /// Certified prefix from this validator's `PcQc1`.
    #[must_use]
    pub const fn x(&self) -> &PcVector {
        &self.x
    }

    /// Per-prefix BLS signatures over `x[..k]`, indexed by prefix length.
    #[must_use]
    pub const fn prefix_sigs(&self) -> &BoundedVec<Bls12381G2Signature, MAX_PREFIX_SIGS> {
        &self.prefix_sigs
    }

    /// Round-1 QC anchoring this validator's `x` (raw view, regardless
    /// of verification state).
    #[must_use]
    pub fn qc1(&self) -> &PcQc1 {
        self.qc1.as_unverified()
    }

    /// Embedded round-1 QC including its verification marker. The
    /// round-2 verifier inspects this directly to short-circuit when
    /// already verified.
    #[must_use]
    pub const fn qc1_verifiable(&self) -> &Verifiable<PcQc1> {
        &self.qc1
    }

    /// Signature binding the validator to their `|x|`.
    #[must_use]
    pub const fn length_attestation(&self) -> Bls12381G2Signature {
        self.length_attestation
    }
}

/// Detailed payload for [`PcXpProof::Diverging`]. Boxed inside the
/// enum variant so the enum's stack size stays balanced with the
/// other variants.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct PcDivergingProof {
    /// First diverging signer.
    pub j: ValidatorId,
    /// First diverging signer's value at position `|x_p|`.
    pub j_divergent: PcValueElement,
    /// Round-1 QC anchoring the first diverging signer's full `x`.
    pub qc1_j: PcQc1,
    /// Second diverging signer.
    pub k: ValidatorId,
    /// Second diverging signer's value at position `|x_p|`.
    pub k_divergent: PcValueElement,
    /// Round-1 QC anchoring the second diverging signer's full `x`.
    pub qc1_k: PcQc1,
    /// Different-messages aggregate of j's sig over `x_p ++ [j_divergent]`
    /// and k's sig over `x_p ++ [k_divergent]`.
    pub combined_sig: Bls12381G2Signature,
}

/// Witness that `PcQc2.x_p` is the actual mcp of the round-2 quorum's
/// `x` values.
///
/// Required because the multi-sig alone only proves `n - f` signers
/// signed `x_p` — it doesn't prove `x_p` is the *longest* prefix they
/// all agree on.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub enum PcXpProof {
    /// Every signer's `x` equals `x_p` exactly. The cert's
    /// [`PcQc2::combined_sig`] folds the per-signer `[|x_p|]` length
    /// attestation into the `x_p` multi-sig under a different-messages
    /// aggregate, so the verifier reconstructs both sets of signing
    /// bytes from the bitfield + `x_p` alone.
    Full,
    /// `|x_p| < L`: at least two signers' `x` values diverge at
    /// position `|x_p|`. Each witness contributes a prefix sig over
    /// `x_p ++ [divergent]` plus a `PcQc1` certifying their full `x`.
    Diverging(Box<PcDivergingProof>),
    /// `|x_p| < L`, all extending signers agree at position `|x_p|`,
    /// but at least one signer's `x` has length exactly `|x_p|`. The
    /// witness is the entire `PcVote2` of such a "short" signer.
    /// The witness's `length_attestation` closes the prefix-sig splice
    /// attack.
    ShortWitness {
        /// A signer whose `x = x_p` exactly.
        witness: Box<PcVote2>,
    },
}

/// Round-2 QC: maximum common prefix of `x` values across the round-2
/// quorum, plus a combined multi-sig and a witness that `x_p` is in
/// fact the mcp.
///
/// `combined_sig` semantics depend on `pi`:
/// - [`PcXpProof::Full`]: different-messages aggregate of every signer's
///   `sig(x_p)` and `sig([|x_p|])` — the length attestation is folded
///   in so the verifier can bind each signer to `x_i = x_p` from one
///   sig instead of two.
/// - [`PcXpProof::Diverging`] / [`PcXpProof::ShortWitness`]:
///   same-message multi-sig over `x_p` only; the witness contributes
///   the length-binding evidence separately.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct PcQc2 {
    x_p: PcVector,
    /// `n - f` signers in the quorum (positional against the
    /// committee enumeration).
    signers: SignerBitfield,
    /// BLS aggregate signature. Coverage depends on [`PcQc2::pi`] —
    /// see the type-level comment.
    combined_sig: Bls12381G2Signature,
    /// Proof that `x_p` is in fact the mcp.
    pi: PcXpProof,
}

impl PcQc2 {
    /// Build a `PcQc2` from its parts.
    #[must_use]
    pub const fn new(
        x_p: PcVector,
        signers: SignerBitfield,
        combined_sig: Bls12381G2Signature,
        pi: PcXpProof,
    ) -> Self {
        Self {
            x_p,
            signers,
            combined_sig,
            pi,
        }
    }

    /// Maximum common prefix the round-2 quorum agreed on.
    #[must_use]
    pub const fn x_p(&self) -> &PcVector {
        &self.x_p
    }

    /// Bitfield of round-2 quorum signers.
    #[must_use]
    pub const fn signers(&self) -> &SignerBitfield {
        &self.signers
    }

    /// Combined BLS signature; see the type-level comment for what it
    /// covers per `pi` variant.
    #[must_use]
    pub const fn combined_sig(&self) -> Bls12381G2Signature {
        self.combined_sig
    }

    /// Witness that `x_p` is the mcp of the quorum's `x` values.
    #[must_use]
    pub const fn pi(&self) -> &PcXpProof {
        &self.pi
    }
}

// ── Round-3 ──────────────────────────────────────────────────────────────────

/// Round-3 vote — carries the certified mcp `x_p` from a [`PcQc2`],
/// the signer's individual sig over `x_p`, and the [`PcQc2`] itself.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct PcVote3 {
    validator: ValidatorId,
    x_p: PcVector,
    sig_xp: Bls12381G2Signature,
    /// Embedded round-2 QC. Wire decode lands as `Verifiable::Unverified`;
    /// locally-signed votes from `Verified::<PcVote3>::sign_local` carry
    /// the marker so the round-3 verifier short-circuits the embedded
    /// QC check.
    qc2: Verifiable<PcQc2>,
}

impl PcVote3 {
    /// Build a `PcVote3` from its parts. Accepts either a raw `PcQc2`
    /// or a `Verified<PcQc2>` for `qc2`.
    #[must_use]
    pub fn new(
        validator: ValidatorId,
        x_p: PcVector,
        sig_xp: Bls12381G2Signature,
        qc2: impl Into<Verifiable<PcQc2>>,
    ) -> Self {
        Self {
            validator,
            x_p,
            sig_xp,
            qc2: qc2.into(),
        }
    }

    /// Validator that cast this vote.
    #[must_use]
    pub const fn validator(&self) -> ValidatorId {
        self.validator
    }

    /// Certified mcp from the carried `PcQc2`.
    #[must_use]
    pub const fn x_p(&self) -> &PcVector {
        &self.x_p
    }

    /// Validator's individual sig over `x_p`.
    #[must_use]
    pub const fn sig_xp(&self) -> Bls12381G2Signature {
        self.sig_xp
    }

    /// Round-2 QC anchoring `x_p` (raw view, regardless of
    /// verification state).
    #[must_use]
    pub fn qc2(&self) -> &PcQc2 {
        self.qc2.as_unverified()
    }

    /// Embedded round-2 QC including its verification marker. The
    /// round-3 verifier inspects this directly to short-circuit when
    /// already verified.
    #[must_use]
    pub const fn qc2_verifiable(&self) -> &Verifiable<PcQc2> {
        &self.qc2
    }
}

/// Per-signer prefix-length encoding for [`PcQc3`].
///
/// By "Lemma 3.1" every round-3 signer's `x_p_i` extends the others, so
/// each `x_p_i = x_pe[..len_i]` is fully recovered from `x_pe` plus
/// `len_i`. In the steady state every signer agrees on the same `len`
/// and the encoding collapses to a single `u32`; otherwise the
/// per-signer lengths ride in set-bit order matching the parent
/// bundle's bitfield.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub enum PcSignerLengths {
    /// Every signer's `|x_p_i|` equals this value. Common case.
    Uniform(u32),
    /// One `|x_p_i|` per signer, in the parent bundle's set-bit order.
    /// Length must equal the bitfield's `count_ones()`.
    PerSigner(BoundedVec<u32, MAX_VALIDATORS>),
}

impl PcSignerLengths {
    /// Pick the most compact encoding for a sequence of per-signer
    /// lengths, in set-bit order.
    ///
    /// # Panics
    ///
    /// Panics if `lens.is_empty()`. The caller (round-3 quorum
    /// assembly) always supplies at least `f + 1` lengths.
    #[must_use]
    pub fn from_per_signer(lens: Vec<u32>) -> Self {
        assert!(
            !lens.is_empty(),
            "PcSignerLengths: at least one length required",
        );
        let first = lens[0];
        if lens.iter().all(|l| *l == first) {
            Self::Uniform(first)
        } else {
            Self::PerSigner(lens.into())
        }
    }

    /// Return the `i`-th signer's `|x_p_i|`. `None` when out of range
    /// for the per-signer encoding; always `Some(uniform)` for the
    /// uniform encoding regardless of `i`.
    #[must_use]
    pub fn get(&self, i: usize) -> Option<u32> {
        match self {
            Self::Uniform(l) => Some(*l),
            Self::PerSigner(lens) => lens.get(i).copied(),
        }
    }

    /// Length of the per-signer vector under the `PerSigner` encoding,
    /// or `None` when the uniform encoding has no explicit count.
    #[must_use]
    pub const fn explicit_count(&self) -> Option<usize> {
        match self {
            Self::Uniform(_) => None,
            Self::PerSigner(lens) => Some(lens.len()),
        }
    }
}

/// Terminal certificate. Carries both endpoints of the round-3 quorum's
/// `x_p` distribution: `x_pp = mcp(x_p_i)` is the certified low,
/// `x_pe = mce(x_p_i)` the certified high.
///
/// Endpoints are dedup-encoded when they coincide (the common case:
/// every signer's `x_p` equal). [`PcQc3::x_pe`] /
/// [`PcQc3::qc2_xpe`] resolve the dedup encoding back to the live
/// reference.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct PcQc3 {
    x_pp: PcVector,
    /// `PcQc2` contributed by the round-3 vote that attained `x_pp`.
    /// Wire decode lands `Verifiable::Unverified`; locally-aggregated
    /// QC3s carry the marker so the round-3 QC verifier short-circuits.
    qc2_xpp: Verifiable<PcQc2>,
    /// `None` is dedup-encoding for "same as `x_pp`".
    x_pe: Option<PcVector>,
    /// `None` is dedup-encoding for "same as `qc2_xpp`".
    qc2_xpe: Option<Verifiable<PcQc2>>,
    /// Round-3 signer bitfield (positional against the committee).
    all_signers: SignerBitfield,
    /// `|x_p_i|` for every signer in `all_signers`, in set-bit order;
    /// collapsed to a single value when all signers agreed.
    signer_lengths: PcSignerLengths,
    /// Aggregate over `sig_i(x_p_i)` for every signer in `all_signers`.
    agg_sig: Bls12381G2Signature,
}

impl PcQc3 {
    /// Build a `PcQc3` from its parts. Accepts either raw `PcQc2`s or
    /// `Verified<PcQc2>`s for `qc2_xpp` / `qc2_xpe`.
    #[must_use]
    #[allow(clippy::similar_names)] // paper notation: x_pp / x_pe and qc2_xpp / qc2_xpe
    pub fn new(
        x_pp: PcVector,
        qc2_xpp: impl Into<Verifiable<PcQc2>>,
        x_pe: Option<PcVector>,
        qc2_xpe: Option<Verifiable<PcQc2>>,
        all_signers: SignerBitfield,
        signer_lengths: PcSignerLengths,
        agg_sig: Bls12381G2Signature,
    ) -> Self {
        Self {
            x_pp,
            qc2_xpp: qc2_xpp.into(),
            x_pe,
            qc2_xpe,
            all_signers,
            signer_lengths,
            agg_sig,
        }
    }

    /// Certified low: the mcp of the round-3 quorum's `x_p_i` values.
    #[must_use]
    pub const fn x_pp(&self) -> &PcVector {
        &self.x_pp
    }

    /// `PcQc2` for the round-3 vote that attained `x_pp` (raw view).
    #[must_use]
    pub fn qc2_xpp(&self) -> &PcQc2 {
        self.qc2_xpp.as_unverified()
    }

    /// Embedded `PcQc2` for `x_pp` including its verification marker.
    #[must_use]
    pub const fn qc2_xpp_verifiable(&self) -> &Verifiable<PcQc2> {
        &self.qc2_xpp
    }

    /// Certified high — resolves dedup encoding. Returns `x_pp` when
    /// the high coincides with the low (the common case).
    #[must_use]
    pub fn x_pe(&self) -> &PcVector {
        self.x_pe.as_ref().unwrap_or(&self.x_pp)
    }

    /// `PcQc2` for the certified high — resolves dedup encoding.
    /// Returns `qc2_xpp` when the high coincides with the low.
    #[must_use]
    pub fn qc2_xpe(&self) -> &PcQc2 {
        self.qc2_xpe
            .as_ref()
            .map_or_else(|| self.qc2_xpp.as_unverified(), Verifiable::as_unverified)
    }

    /// Embedded `PcQc2` for `x_pe` including its verification marker.
    /// Resolves dedup encoding — returns the `x_pp` slot when high
    /// coincides with low.
    #[must_use]
    pub const fn qc2_xpe_verifiable(&self) -> &Verifiable<PcQc2> {
        match &self.qc2_xpe {
            Some(v) => v,
            None => &self.qc2_xpp,
        }
    }

    /// Round-3 signer bitfield, positional against the committee.
    #[must_use]
    pub const fn all_signers(&self) -> &SignerBitfield {
        &self.all_signers
    }

    /// Per-signer prefix-length encoding, in set-bit order.
    #[must_use]
    pub const fn signer_lengths(&self) -> &PcSignerLengths {
        &self.signer_lengths
    }

    /// Different-messages aggregate over the signers' `sig_i(x_p_i)`.
    #[must_use]
    pub const fn agg_sig(&self) -> Bls12381G2Signature {
        self.agg_sig
    }
}

// ── Equivocation ─────────────────────────────────────────────────────────────

/// Which PC round a [`PcVoteEquivocation`] references.
///
/// Determines the BLS signing tag the verifier uses to reconstruct the
/// canonical message bytes for each side of the evidence.
///
/// No `Vote2Length` variant: the length attestation signs a length-1
/// vector whose single element is `x.len()`, and is emitted alongside
/// each [`PcVote2`]. Equivocating on the length therefore implies
/// equivocating on the [`PcVote2`] value (different lengths ⇒ different
/// vectors), so any length-attestation double-sign is already captured
/// by the [`Self::Vote2`] flavor's value-inequality check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, BasicSbor)]
pub enum PcVoteRound {
    /// Equivocation on a [`PcVote1`].
    Vote1,
    /// Equivocation on a [`PcVote2`].
    Vote2,
    /// Equivocation on a [`PcVote3`].
    Vote3,
}

/// Self-authenticating evidence that a single validator double-signed
/// at the same `(epoch, view, round)` of the inner Prefix Consensus.
///
/// Carries two `(value, sig)` pairs the equivocator signed at the same
/// round. The slim wire form — fat votes don't need to ride into the
/// beacon's jail mechanism, just the cryptographic minimum that
/// reconstructs the canonical signing bytes and runs BLS verify under
/// the equivocator's pubkey. Both sides must verify and the values
/// must differ.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct PcVoteEquivocation {
    /// Validator that double-signed.
    pub validator: ValidatorId,
    /// Epoch the inner Prefix Consensus instance belongs to.
    pub epoch: Epoch,
    /// SPC view at which the instance was running.
    pub view: SpcView,
    /// Round of the inner Prefix Consensus at which the double-sign
    /// occurred — selects the BLS signing tag.
    pub round: PcVoteRound,
    /// First side's signed value.
    pub value_a: PcVector,
    /// First side's BLS signature over the canonical signing bytes
    /// for `value_a` under the tag implied by `round`.
    pub sig_a: Bls12381G2Signature,
    /// Second side's signed value (must differ from `value_a`).
    pub value_b: PcVector,
    /// Second side's BLS signature over the canonical signing bytes
    /// for `value_b` under the tag implied by `round`.
    pub sig_b: Bls12381G2Signature,
}

// ── Verify ───────────────────────────────────────────────────────────────────

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
    pc_ctx: &PcContext,
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
fn length_attestation_message(
    network: &NetworkDefinition,
    pc_ctx: &PcContext,
    len: usize,
) -> Vec<u8> {
    let len_element = PcValueElement::new({
        let mut bytes = [0u8; PC_VALUE_ELEMENT_BYTES];
        bytes[..8].copy_from_slice(&(len as u64).to_le_bytes());
        bytes
    });
    let v = PcVector::new(std::iter::once(len_element));
    pc_vote_signing_message(network, DOMAIN_PC_VOTE2_LENGTH, pc_ctx, &v)
}

/// Verify a round-2 length attestation against a signer's pubkey.
fn verify_length_attestation(
    sig: &Bls12381G2Signature,
    pk: &Bls12381G1PublicKey,
    network: &NetworkDefinition,
    pc_ctx: &PcContext,
    len: usize,
) -> bool {
    let msg = length_attestation_message(network, pc_ctx, len);
    aggregate_verify_bls_different_messages(&[msg.as_slice()], sig, std::slice::from_ref(pk))
}

// ─── Round 1 ───────────────────────────────────────────────────────────────

/// Verify a single round-1 vote. Pure function over wire types.
///
/// # Errors
///
/// Returns a [`PcVote1VerifyError`] variant naming the failing predicate.
pub fn verify_vote1(
    v1: &PcVote1,
    network: &NetworkDefinition,
    pc_ctx: &PcContext,
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> Result<(), PcVote1VerifyError> {
    let Some(pk) = pubkey_in_committee(committee, v1.validator()) else {
        return Err(PcVote1VerifyError::SignerNotInCommittee);
    };
    if v1.v_in().len() > MAX_VOTE_VECTOR_LEN {
        return Err(PcVote1VerifyError::VoteVectorTooLong);
    }
    if v1.prefix_sigs().len() != v1.v_in().len() + 1 {
        return Err(PcVote1VerifyError::PrefixSigCountMismatch);
    }
    let messages_owned = prefix_signing_messages(network, DOMAIN_PC_VOTE1, pc_ctx, v1.v_in());
    let messages: Vec<&[u8]> = messages_owned.iter().map(Vec::as_slice).collect();
    let pks = vec![pk; v1.prefix_sigs().len()];
    let sigs: Vec<Bls12381G2Signature> = v1.prefix_sigs().iter().copied().collect();
    let agg = Bls12381G2Signature::aggregate(&sigs, true)
        .map_err(|_| PcVote1VerifyError::BadSignatureAggregate)?;
    if aggregate_verify_bls_different_messages(&messages, &agg, &pks) {
        Ok(())
    } else {
        Err(PcVote1VerifyError::BadSignature)
    }
}

/// Verify a round-1 QC — the certified prefix `x` plus the compact
/// view of every round-1 signer's `v_in_i` relative to `x`.
///
/// Two soundness gates beyond signature verification:
/// 1. `qc1.x_signers.len() == n - f` (with per-party dedup) — enforces
///    "exactly n-f distinct signers"; any relaxation to `>= n - f`
///    would let duplicates inflate a sub-quorum.
/// 2. `qc1_certify(reconstructed_inputs, f) == Some(qc1.x)` — pins
///    `x` to the longest prefix attained by some `(f+1)`-subset of
///    `S_1`'s inputs, forcing it above the all-honest subset's mcp.
///
/// # Errors
///
/// Returns a [`PcQc1VerifyError`] variant naming the failing predicate.
pub fn verify_qc1(
    qc1: &PcQc1,
    network: &NetworkDefinition,
    pc_ctx: &PcContext,
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> Result<(), PcQc1VerifyError> {
    let n = committee.len();
    let f = byzantine_threshold(n);
    let q = n - f;

    if qc1.x().len() > MAX_VOTE_VECTOR_LEN {
        return Err(PcQc1VerifyError::CertifiedVectorTooLong);
    }
    if qc1.x_signers().len() != q {
        return Err(PcQc1VerifyError::SignerCountMismatch);
    }

    let mut seen: BTreeSet<usize> = BTreeSet::new();
    let mut values: Vec<PcVector> = Vec::with_capacity(q);
    let mut pks: Vec<Bls12381G1PublicKey> = Vec::with_capacity(q);
    let mut subset_inputs: Vec<PcVector> = Vec::with_capacity(q);

    for (idx, cv) in qc1.x_signers().iter() {
        let Some((_, pk)) = committee.get(idx) else {
            return Err(PcQc1VerifyError::SignerOutOfRange);
        };
        if !seen.insert(idx) {
            return Err(PcQc1VerifyError::DuplicateSigner);
        }
        let Some(v_prime) = reconstruct_compact_vote(cv, qc1.x()) else {
            return Err(PcQc1VerifyError::MalformedCompactVote);
        };
        subset_inputs.push(v_prime.clone());
        values.push(v_prime);
        pks.push(*pk);
    }

    let messages_owned: Vec<Vec<u8>> = values
        .iter()
        .map(|v| pc_vote_signing_message(network, DOMAIN_PC_VOTE1, pc_ctx, v))
        .collect();
    let messages: Vec<&[u8]> = messages_owned.iter().map(Vec::as_slice).collect();
    if !aggregate_verify_bls_different_messages(&messages, &qc1.x_agg_sig(), &pks) {
        return Err(PcQc1VerifyError::BadAggregateSignature);
    }

    if qc1_certify(&subset_inputs, f).as_ref() == Some(qc1.x()) {
        Ok(())
    } else {
        Err(PcQc1VerifyError::CertifyMismatch)
    }
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
/// length_attestation)`.
///
/// Calls into [`verify_qc1`] for the embedded round-1 QC; recurses
/// indirectly through [`PcXpProof::ShortWitness`] in [`verify_qc2`].
///
/// # Errors
///
/// Returns a [`PcVote2VerifyError`] variant naming the failing predicate.
pub fn verify_vote2(
    v2: &PcVote2,
    network: &NetworkDefinition,
    pc_ctx: &PcContext,
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> Result<(), PcVote2VerifyError> {
    let Some(pk) = pubkey_in_committee(committee, v2.validator()) else {
        return Err(PcVote2VerifyError::SignerNotInCommittee);
    };
    if v2.x().len() > MAX_VOTE_VECTOR_LEN {
        return Err(PcVote2VerifyError::VoteVectorTooLong);
    }
    if v2.prefix_sigs().len() != v2.x().len() + 1 {
        return Err(PcVote2VerifyError::PrefixSigCountMismatch);
    }
    // Embedded QC1: trust the marker when set (sealed construction); otherwise
    // run the full predicate. Same shape as the round-3 / QC-3 composite gates.
    if v2.qc1_verifiable().verified().is_none() {
        verify_qc1(v2.qc1(), network, pc_ctx, committee)
            .map_err(|_| PcVote2VerifyError::EmbeddedQc1Rejected)?;
    }
    // Vote2's `x` must be the QC1Certify output of its embedded QC1.
    if v2.x() != v2.qc1().x() {
        return Err(PcVote2VerifyError::XMismatch);
    }
    if !verify_length_attestation(&v2.length_attestation(), &pk, network, pc_ctx, v2.x().len()) {
        return Err(PcVote2VerifyError::BadLengthAttestation);
    }
    let messages_owned = prefix_signing_messages(network, DOMAIN_PC_VOTE2, pc_ctx, v2.x());
    let messages: Vec<&[u8]> = messages_owned.iter().map(Vec::as_slice).collect();
    let pks = vec![pk; v2.prefix_sigs().len()];
    let sigs: Vec<Bls12381G2Signature> = v2.prefix_sigs().iter().copied().collect();
    let agg = Bls12381G2Signature::aggregate(&sigs, true)
        .map_err(|_| PcVote2VerifyError::BadSignatureAggregate)?;
    if aggregate_verify_bls_different_messages(&messages, &agg, &pks) {
        Ok(())
    } else {
        Err(PcVote2VerifyError::BadSignature)
    }
}

/// Verify a round-2 QC — the multi-sig over `x_p` plus the witness
/// `π` that `x_p` is the actual mcp of the round-2 quorum's `x` values.
///
/// `π` handling branches three ways: [`PcXpProof::Full`] is the all-equal
/// case (every signer's `x = x_p`); [`PcXpProof::Diverging`] carries
/// two witnesses with divergent extensions plus their backing QC1s;
/// [`PcXpProof::ShortWitness`] embeds an entire [`PcVote2`] whose `x`
/// equals `x_p`.
///
/// # Errors
///
/// Returns a [`PcQc2VerifyError`] variant naming the failing predicate.
pub fn verify_qc2(
    qc2: &PcQc2,
    network: &NetworkDefinition,
    pc_ctx: &PcContext,
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> Result<(), PcQc2VerifyError> {
    let n = committee.len();
    let f = byzantine_threshold(n);
    let q = n - f;

    if qc2.x_p().len() > MAX_VOTE_VECTOR_LEN {
        return Err(PcQc2VerifyError::CertifiedVectorTooLong);
    }
    if qc2.signers().count() != q {
        return Err(PcQc2VerifyError::SignerCountMismatch);
    }
    let signer_indices: Vec<usize> = qc2.signers().set_indices().collect();
    if signer_indices.iter().any(|&i| i >= n) {
        return Err(PcQc2VerifyError::SignerOutOfRange);
    }
    let signer_pks: Vec<Bls12381G1PublicKey> =
        signer_indices.iter().map(|&i| committee[i].1).collect();
    let signer_ids: BTreeSet<ValidatorId> =
        signer_indices.iter().map(|&i| committee[i].0).collect();

    let x_p_message = pc_vote_signing_message(network, DOMAIN_PC_VOTE2, pc_ctx, qc2.x_p());

    match qc2.pi() {
        PcXpProof::Full => {
            // Full case: combined_sig folds per-signer sig(x_p) + sig([|x_p|]).
            // Build interleaved (message, pubkey) pairs so the different-
            // messages aggregate verifies both attestations in one call.
            let len_msg = length_attestation_message(network, pc_ctx, qc2.x_p().len());
            let mut messages: Vec<&[u8]> = Vec::with_capacity(2 * q);
            let mut pks: Vec<Bls12381G1PublicKey> = Vec::with_capacity(2 * q);
            for pk in &signer_pks {
                messages.push(x_p_message.as_slice());
                pks.push(*pk);
                messages.push(len_msg.as_slice());
                pks.push(*pk);
            }
            if aggregate_verify_bls_different_messages(&messages, &qc2.combined_sig(), &pks) {
                Ok(())
            } else {
                Err(PcQc2VerifyError::BadCombinedSignature)
            }
        }
        PcXpProof::Diverging(proof) => {
            let x_p_messages: Vec<&[u8]> = std::iter::repeat_n(x_p_message.as_slice(), q).collect();
            if !aggregate_verify_bls_different_messages(
                &x_p_messages,
                &qc2.combined_sig(),
                &signer_pks,
            ) {
                return Err(PcQc2VerifyError::BadCombinedSignature);
            }
            if verify_diverging_proof(proof, qc2, &signer_ids, network, pc_ctx, committee) {
                Ok(())
            } else {
                Err(PcQc2VerifyError::BadDivergingProof)
            }
        }
        PcXpProof::ShortWitness { witness } => {
            let x_p_messages: Vec<&[u8]> = std::iter::repeat_n(x_p_message.as_slice(), q).collect();
            if !aggregate_verify_bls_different_messages(
                &x_p_messages,
                &qc2.combined_sig(),
                &signer_pks,
            ) {
                return Err(PcQc2VerifyError::BadCombinedSignature);
            }
            if !signer_ids.contains(&witness.validator()) {
                return Err(PcQc2VerifyError::BadShortWitnessLinkage);
            }
            if witness.x() != qc2.x_p() {
                return Err(PcQc2VerifyError::BadShortWitnessLinkage);
            }
            verify_vote2(witness, network, pc_ctx, committee)
                .map_err(|_| PcQc2VerifyError::BadShortWitness)
        }
    }
}

fn verify_diverging_proof(
    proof: &PcDivergingProof,
    qc2: &PcQc2,
    signer_ids: &BTreeSet<ValidatorId>,
    network: &NetworkDefinition,
    pc_ctx: &PcContext,
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
    if verify_qc1(&proof.qc1_j, network, pc_ctx, committee).is_err()
        || verify_qc1(&proof.qc1_k, network, pc_ctx, committee).is_err()
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
    let k_msg = pc_vote_signing_message(network, DOMAIN_PC_VOTE2, pc_ctx, &k_vec);
    aggregate_verify_bls_different_messages(
        &[j_msg.as_slice(), k_msg.as_slice()],
        &proof.combined_sig,
        &[pk_j, pk_k],
    )
}

// ─── Round 3 ───────────────────────────────────────────────────────────────

/// Verify a single round-3 vote — `(x_p, sig_xp, embedded qc2)`. The
/// signer's individual sig over `x_p` plus the embedded QC2 binding
/// `x_p` to a real round-2 quorum.
///
/// # Errors
///
/// Returns a [`PcVote3VerifyError`] variant naming the failing predicate.
pub fn verify_vote3(
    v3: &PcVote3,
    network: &NetworkDefinition,
    pc_ctx: &PcContext,
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> Result<(), PcVote3VerifyError> {
    let Some(pk) = pubkey_in_committee(committee, v3.validator()) else {
        return Err(PcVote3VerifyError::SignerNotInCommittee);
    };
    let msg = pc_vote_signing_message(network, DOMAIN_PC_VOTE3, pc_ctx, v3.x_p());
    if !aggregate_verify_bls_different_messages(&[msg.as_slice()], &v3.sig_xp(), &[pk]) {
        return Err(PcVote3VerifyError::BadSignatureOverXp);
    }
    if v3.qc2_verifiable().verified().is_none() {
        verify_qc2(v3.qc2(), network, pc_ctx, committee)
            .map_err(|_| PcVote3VerifyError::EmbeddedQc2Rejected)?;
    }
    if v3.x_p() == v3.qc2().x_p() {
        Ok(())
    } else {
        Err(PcVote3VerifyError::XpMismatch)
    }
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
///
/// # Errors
///
/// Returns a [`PcQc3VerifyError`] variant naming the failing predicate.
pub fn verify_qc3(
    qc3: &PcQc3,
    network: &NetworkDefinition,
    pc_ctx: &PcContext,
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> Result<(), PcQc3VerifyError> {
    let n = committee.len();
    let f = byzantine_threshold(n);
    let q = n - f;

    let x_pe = qc3.x_pe();
    let qc2_xpe = qc3.qc2_xpe();
    if x_pe.len() > MAX_VOTE_VECTOR_LEN {
        return Err(PcQc3VerifyError::CertifiedVectorTooLong);
    }
    if !qc3.x_pp().is_prefix_of(x_pe) {
        return Err(PcQc3VerifyError::XppNotPrefixOfXpe);
    }
    if qc3.qc2_xpp_verifiable().verified().is_none() {
        verify_qc2(qc3.qc2_xpp(), network, pc_ctx, committee)
            .map_err(|_| PcQc3VerifyError::EmbeddedQc2XppRejected)?;
    }
    if qc3.qc2_xpe_verifiable().verified().is_none() {
        verify_qc2(qc2_xpe, network, pc_ctx, committee)
            .map_err(|_| PcQc3VerifyError::EmbeddedQc2XpeRejected)?;
    }
    if qc3.qc2_xpp().x_p() != qc3.x_pp() {
        return Err(PcQc3VerifyError::XppMismatch);
    }
    if qc2_xpe.x_p() != x_pe {
        return Err(PcQc3VerifyError::XpeMismatch);
    }
    if qc3.all_signers().count_ones() != q {
        return Err(PcQc3VerifyError::SignerCountMismatch);
    }
    // PerSigner encoding's length vector must match popcount.
    if let Some(explicit) = qc3.signer_lengths().explicit_count()
        && explicit != q
    {
        return Err(PcQc3VerifyError::SignerLengthsCountMismatch);
    }

    let mut values: Vec<PcVector> = Vec::with_capacity(q);
    let mut pks: Vec<Bls12381G1PublicKey> = Vec::with_capacity(q);
    let mut min_len = usize::MAX;
    let mut max_len = 0usize;
    for (k, idx) in qc3.all_signers().set_indices().enumerate() {
        let Some((_, pk)) = committee.get(idx) else {
            return Err(PcQc3VerifyError::SignerOutOfRange);
        };
        let Some(len_u32) = qc3.signer_lengths().get(k) else {
            return Err(PcQc3VerifyError::MissingSignerLength);
        };
        let len = len_u32 as usize;
        if len > x_pe.len() || len < qc3.x_pp().len() {
            return Err(PcQc3VerifyError::LengthOutOfRange);
        }
        min_len = min_len.min(len);
        max_len = max_len.max(len);
        values.push(PcVector::new(x_pe.as_slice()[..len].iter().copied()));
        pks.push(*pk);
    }
    if min_len != qc3.x_pp().len() || max_len != x_pe.len() {
        return Err(PcQc3VerifyError::MinMaxLengthMismatch);
    }

    let messages_owned: Vec<Vec<u8>> = values
        .iter()
        .map(|v| pc_vote_signing_message(network, DOMAIN_PC_VOTE3, pc_ctx, v))
        .collect();
    let messages: Vec<&[u8]> = messages_owned.iter().map(Vec::as_slice).collect();
    if aggregate_verify_bls_different_messages(&messages, &qc3.agg_sig(), &pks) {
        Ok(())
    } else {
        Err(PcQc3VerifyError::BadAggregateSignature)
    }
}

// ─── Equivocation ──────────────────────────────────────────────────────────

/// Verify that a [`PcVoteEquivocation`] is a genuine double-sign by
/// the same validator at the same `(epoch, view, round)`.
///
/// Returns `Ok(())` only when:
/// 1. `value_a != value_b` (otherwise no contradiction).
/// 2. Both signatures verify under the validator's committee pubkey
///    against the canonical signing message for `(network, round-tag,
///    pc_context(epoch, view), value)`.
///
/// The validator must be in `committee`; non-members are rejected
/// before any pairing. Round-3 sigs are individual sigs over `x_p`
/// (the prototype's `sig_xp`), so the verifier treats all three
/// rounds uniformly — only the domain tag varies.
///
/// # Errors
///
/// Returns a [`PcVoteEquivocationVerifyError`] variant naming the failing predicate.
pub fn verify_vote_equivocation(
    ev: &PcVoteEquivocation,
    network: &NetworkDefinition,
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> Result<(), PcVoteEquivocationVerifyError> {
    if ev.value_a == ev.value_b {
        return Err(PcVoteEquivocationVerifyError::ValuesEqual);
    }
    let Some(pk) = pubkey_in_committee(committee, ev.validator) else {
        return Err(PcVoteEquivocationVerifyError::SignerNotInCommittee);
    };
    let domain = match ev.round {
        PcVoteRound::Vote1 => DOMAIN_PC_VOTE1,
        PcVoteRound::Vote2 => DOMAIN_PC_VOTE2,
        PcVoteRound::Vote3 => DOMAIN_PC_VOTE3,
    };
    let spc_ctx = spc_context(ev.epoch);
    let ctx = pc_context(&spc_ctx, ev.view);
    let msg_a = pc_vote_signing_message(network, domain, &ctx, &ev.value_a);
    let msg_b = pc_vote_signing_message(network, domain, &ctx, &ev.value_b);
    if aggregate_verify_bls_different_messages(&[msg_a.as_slice()], &ev.sig_a, &[pk])
        && aggregate_verify_bls_different_messages(&[msg_b.as_slice()], &ev.sig_b, &[pk])
    {
        Ok(())
    } else {
        Err(PcVoteEquivocationVerifyError::BadSignature)
    }
}

// ── Sign ────────────────────────────────────────────────────────────────────

/// Sign one signer's round-1 vote — produces `|v_in| + 1` prefix
/// signatures over `v_in[..k]` for `k ∈ 0..=|v_in|`, packaged as a
/// `PcVote1`.
#[must_use]
pub fn sign_vote1(
    sk: &Bls12381G1PrivateKey,
    validator: ValidatorId,
    network: &NetworkDefinition,
    pc_ctx: &PcContext,
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
///
/// Accepts either a raw `PcQc1` or a `Verified<PcQc1>` — the wrapper
/// preserves the marker through `PcVote2.qc1`.
#[must_use]
pub fn sign_vote2(
    sk: &Bls12381G1PrivateKey,
    validator: ValidatorId,
    network: &NetworkDefinition,
    pc_ctx: &PcContext,
    qc1: impl Into<Verifiable<PcQc1>>,
) -> PcVote2 {
    let qc1: Verifiable<PcQc1> = qc1.into();
    let x = qc1.x().clone();
    let prefix_sigs = sign_all_prefixes(sk, network, pc_ctx, &x, DOMAIN_PC_VOTE2);
    let length_attestation = sk.sign_v1(&length_attestation_message(network, pc_ctx, x.len()));
    PcVote2::new(validator, x, prefix_sigs, qc1, length_attestation)
}

/// Sign one signer's round-3 vote.
///
/// `x_p` is derived from `qc2`, and the individual sig over `x_p`
/// rides separately from the per-prefix fan-out used in rounds 1/2
/// (round 3 only needs the single `x_p` commitment). Accepts either
/// a raw `PcQc2` or a `Verified<PcQc2>`.
#[must_use]
pub fn sign_vote3(
    sk: &Bls12381G1PrivateKey,
    validator: ValidatorId,
    network: &NetworkDefinition,
    pc_ctx: &PcContext,
    qc2: impl Into<Verifiable<PcQc2>>,
) -> PcVote3 {
    let qc2: Verifiable<PcQc2> = qc2.into();
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
    pc_ctx: &PcContext,
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

// ── Build ───────────────────────────────────────────────────────────────────

/// Assemble a [`PcQc1`] from a round-1 quorum.
///
/// `committee` is required to resolve `ValidatorId`s to bitfield
/// positions for the [`PositionalBundle`] wrapping the signers.
///
/// # Panics
///
/// Panics if `votes.len() < f + 1` (where `f = (n - 1) / 3`) — the
/// caller is the FSM, which guarantees full `n - f` quorums. Panics
/// if any signer in `votes` is not present in `committee`.
#[must_use]
pub fn build_qc1(votes: &[&PcVote1], committee: &[(ValidatorId, Bls12381G1PublicKey)]) -> PcQc1 {
    let n = committee.len();
    let f = byzantine_threshold(n);
    let raw_inputs: Vec<PcVector> = votes.iter().map(|v| v.v_in().clone()).collect();
    let x = qc1_certify(&raw_inputs, f).expect("build_qc1 caller guarantees votes.len() >= f+1");

    // Dedup by position: the FSM supplies distinct senders, but a
    // downstream caller could pass duplicates. A silent skip yields a
    // short `x_signers` that the verifier rejects for size; cheaper
    // than panicking on a malformed inbox.
    let mut signers_bf = SignerBitfield::new(n);
    let mut indexed: Vec<(usize, PcCompactVote, Bls12381G2Signature)> =
        Vec::with_capacity(votes.len());
    for v1 in votes {
        let pos = committee
            .iter()
            .position(|(id, _)| *id == v1.validator())
            .expect("build_qc1: vote signer not in committee");
        if signers_bf.is_set(pos) {
            continue;
        }
        signers_bf.set(pos);
        let cv = compact_vote_for(v1.v_in(), &x);
        let sig_idx = cv.shared_len() as usize + usize::from(cv.divergent().is_some());
        let sig = v1
            .prefix_sigs()
            .get(sig_idx)
            .copied()
            .expect("vote-1 carries |v_in|+1 prefix sigs; sig_idx ≤ |v_in|");
        indexed.push((pos, cv, sig));
    }
    // Reorder to bitfield set-bit order (ascending position) so the
    // PositionalBundle items line up with `signers.set_indices()`.
    indexed.sort_by_key(|(pos, _, _)| *pos);
    let x_signers_items: Vec<PcCompactVote> = indexed.iter().map(|(_, cv, _)| cv.clone()).collect();
    let x_sigs: Vec<Bls12381G2Signature> = indexed.iter().map(|(_, _, sig)| *sig).collect();
    let x_agg_sig = Bls12381G2Signature::aggregate(&x_sigs, true).expect("non-empty signers");
    PcQc1::new(
        x,
        PositionalBundle::new(signers_bf, x_signers_items),
        x_agg_sig,
    )
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
    let mut x_p_sigs: Vec<Bls12381G2Signature> = Vec::with_capacity(votes.len());
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
        x_p_sigs.push(sig);
    }

    // π proof. Three branches:
    //   - Full: every signer's `x` equals `x_p` exactly — combined_sig
    //     folds per-signer sig(x_p) + sig([|x_p|]).
    //   - Diverging: at least two signers' `x` extend past `|x_p|`
    //     with different elements at position `|x_p|`.
    //   - ShortWitness: at least one signer's `|x| = |x_p|`, while
    //     extending signers all agree at position `|x_p|`.
    let pi = build_xp_proof(votes, &x_p);
    let combined_sig = match &pi {
        PcXpProof::Full => {
            let mut all_sigs = x_p_sigs;
            for v2 in votes {
                all_sigs.push(v2.length_attestation());
            }
            Bls12381G2Signature::aggregate(&all_sigs, true).expect("non-empty signers")
        }
        PcXpProof::Diverging(_) | PcXpProof::ShortWitness { .. } => {
            Bls12381G2Signature::aggregate(&x_p_sigs, true).expect("non-empty signers")
        }
    };

    PcQc2::new(x_p, signers_bf, combined_sig, pi)
}

fn build_xp_proof(votes: &[&PcVote2], x_p: &PcVector) -> PcXpProof {
    let input_len = votes.first().map_or(0, |v| v.x().len());
    let all_equal_length = !votes.is_empty()
        && x_p.len() == input_len
        && votes.iter().all(|v| v.x().len() == input_len);
    if all_equal_length {
        return PcXpProof::Full;
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
        let combined_sig =
            Bls12381G2Signature::aggregate(&[j_sig, k_sig], true).expect("two non-zero sigs");
        return PcXpProof::Diverging(Box::new(PcDivergingProof {
            j: j_vote.validator(),
            j_divergent: j_div,
            qc1_j: j_vote.qc1().clone(),
            k: k_vote.validator(),
            k_divergent: k_vote.x().as_slice()[pos],
            qc1_k: k_vote.qc1().clone(),
            combined_sig,
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
/// `committee` is required to resolve `ValidatorId`s to bitfield
/// positions. Endpoints `(x_pp, x_pe)` get dedup-encoded when they
/// coincide (the common case: every signer's `x_p` equal). The
/// verifier resolves the dedup via [`PcQc3::x_pe`] /
/// [`PcQc3::qc2_xpe`].
///
/// # Panics
///
/// Panics if `votes` is empty, or if any signer in `votes` is not
/// present in `committee`.
#[must_use]
#[allow(clippy::similar_names)] // x_pp / x_pe / qc2_xpp / qc2_xpe match PcQc3's wire-type field names
pub fn build_qc3(votes: &[&PcVote3], committee: &[(ValidatorId, Bls12381G1PublicKey)]) -> PcQc3 {
    let x_ps: Vec<PcVector> = votes.iter().map(|v| v.x_p().clone()).collect();
    let x_pp = mcp(&x_ps).expect("build_qc3 caller guarantees non-empty votes");
    let x_pe = mce(&x_ps).expect("round-3 x_p values mutually extend");

    let qc2_xpp = votes
        .iter()
        .find(|v| v.x_p() == &x_pp)
        .map(|v| v.qc2_verifiable().clone())
        .expect("x_pp is some vote's x_p");
    let qc2_xpe_full = votes
        .iter()
        .find(|v| v.x_p() == &x_pe)
        .map(|v| v.qc2_verifiable().clone())
        .expect("x_pe is some vote's x_p");

    let n = committee.len();
    let mut all_signers = SignerBitfield::new(n);
    let mut indexed: Vec<(usize, u32, Bls12381G2Signature)> = Vec::with_capacity(votes.len());
    for v in votes {
        let pos = committee
            .iter()
            .position(|(id, _)| *id == v.validator())
            .expect("build_qc3: vote signer not in committee");
        if all_signers.is_set(pos) {
            continue;
        }
        all_signers.set(pos);
        let prefix_len = u32::try_from(v.x_p().len()).unwrap_or(u32::MAX);
        indexed.push((pos, prefix_len, v.sig_xp()));
    }
    indexed.sort_by_key(|(pos, _, _)| *pos);
    let lens: Vec<u32> = indexed.iter().map(|(_, l, _)| *l).collect();
    let sig_bytes: Vec<Bls12381G2Signature> = indexed.iter().map(|(_, _, s)| *s).collect();
    let signer_lengths = PcSignerLengths::from_per_signer(lens);
    let agg_sig = Bls12381G2Signature::aggregate(&sig_bytes, true).expect("non-empty signers");

    let x_pe_dedup = (x_pp != x_pe).then_some(x_pe);
    let qc2_xpe_dedup = (qc2_xpp != qc2_xpe_full).then_some(qc2_xpe_full);

    PcQc3::new(
        x_pp,
        qc2_xpp,
        x_pe_dedup,
        qc2_xpe_dedup,
        all_signers,
        signer_lengths,
        agg_sig,
    )
}

/// Compact-encode `v_in` relative to the canonical `x`. The encoding
/// captures the deviation point (length of the maximum common prefix)
/// and the first divergent element when `v_in` is not itself a prefix
/// of `x`.
fn compact_vote_for(v_in: &PcVector, x: &PcVector) -> PcCompactVote {
    if v_in.as_slice() == x.as_slice() {
        let shared_len = u32::try_from(v_in.len()).unwrap_or(u32::MAX);
        return PcCompactVote::new(shared_len, None);
    }
    let shared = mcp_two(v_in, x);
    let divergent = v_in.as_slice().get(shared).copied();
    let shared_len = u32::try_from(shared).unwrap_or(u32::MAX);
    PcCompactVote::new(shared_len, divergent)
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

// ── Typestate ──────────────────────────────────────────────────────────────

/// Shared verification context for all PC vote / QC predicates.
///
/// Bundles the per-instance binding context (`network`, `pc_ctx`) with
/// the committee that every signer must be drawn from. The Verify impls
/// for [`PcVote1`] / [`PcVote2`] / [`PcVote3`] / [`PcQc1`] / [`PcQc2`] /
/// [`PcQc3`] all take this context.
#[derive(Debug, Clone, Copy)]
pub struct PcVoteVerifyContext<'a> {
    /// Network the signer was bound to.
    pub network: &'a NetworkDefinition,
    /// Canonical signing context for this `(epoch, view)`.
    pub pc_ctx: &'a PcContext,
    /// Committee membership and pubkeys.
    pub committee: &'a [(ValidatorId, Bls12381G1PublicKey)],
}

/// Verification context for [`PcVoteEquivocation`].
///
/// The evidence carries its own `(epoch, view, round)`, so only the
/// network binding and committee are needed externally.
#[derive(Debug, Clone, Copy)]
pub struct PcVoteEquivocationContext<'a> {
    /// Network the equivocator was bound to.
    pub network: &'a NetworkDefinition,
    /// Committee membership and pubkeys.
    pub committee: &'a [(ValidatorId, Bls12381G1PublicKey)],
}

/// Failure modes of a round-1 vote.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PcVote1VerifyError {
    /// `validator` is not in the verifier's committee.
    #[error("signer not in committee")]
    SignerNotInCommittee,
    /// `v_in.len() > MAX_VOTE_VECTOR_LEN`.
    #[error("vote vector exceeds MAX_VOTE_VECTOR_LEN")]
    VoteVectorTooLong,
    /// `prefix_sigs.len() != v_in.len() + 1`.
    #[error("prefix-sig count does not match v_in.len() + 1")]
    PrefixSigCountMismatch,
    /// Per-prefix sig aggregation produced an invalid element.
    #[error("prefix-sig aggregation failed")]
    BadSignatureAggregate,
    /// Aggregate BLS check rejected the prefix-sig bundle.
    #[error("prefix-sig aggregate did not verify under signer pubkey")]
    BadSignature,
}

/// Failure modes of a round-1 QC.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PcQc1VerifyError {
    /// `x.len() > MAX_VOTE_VECTOR_LEN`.
    #[error("certified vector exceeds MAX_VOTE_VECTOR_LEN")]
    CertifiedVectorTooLong,
    /// `x_signers.len() != n - f`.
    #[error("signer count does not match n - f")]
    SignerCountMismatch,
    /// A signer index points outside the committee.
    #[error("signer index out of committee range")]
    SignerOutOfRange,
    /// Duplicate signer index in `x_signers`.
    #[error("duplicate signer in x_signers")]
    DuplicateSigner,
    /// A compact-vote encoding did not reconstruct cleanly.
    #[error("malformed compact-vote encoding")]
    MalformedCompactVote,
    /// Aggregate BLS check rejected the prefix-sig bundle.
    #[error("x-aggregate signature did not verify")]
    BadAggregateSignature,
    /// `qc1_certify` of the reconstructed inputs did not produce `qc1.x`.
    #[error("qc1_certify output does not match qc1.x")]
    CertifyMismatch,
}

/// Failure modes of a round-2 vote.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PcVote2VerifyError {
    /// `validator` is not in the verifier's committee.
    #[error("signer not in committee")]
    SignerNotInCommittee,
    /// `x.len() > MAX_VOTE_VECTOR_LEN`.
    #[error("vote vector exceeds MAX_VOTE_VECTOR_LEN")]
    VoteVectorTooLong,
    /// `prefix_sigs.len() != x.len() + 1`.
    #[error("prefix-sig count does not match x.len() + 1")]
    PrefixSigCountMismatch,
    /// Embedded round-1 QC did not verify.
    #[error("embedded qc1 rejected")]
    EmbeddedQc1Rejected,
    /// `v2.x` does not match `qc1.x`.
    #[error("v2.x does not match embedded qc1.x")]
    XMismatch,
    /// Length-attestation sig did not verify.
    #[error("length-attestation signature did not verify")]
    BadLengthAttestation,
    /// Per-prefix sig aggregation produced an invalid element.
    #[error("prefix-sig aggregation failed")]
    BadSignatureAggregate,
    /// Aggregate BLS check rejected the prefix-sig bundle.
    #[error("prefix-sig aggregate did not verify under signer pubkey")]
    BadSignature,
}

/// Failure modes of a round-2 QC.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PcQc2VerifyError {
    /// `x_p.len() > MAX_VOTE_VECTOR_LEN`.
    #[error("certified vector exceeds MAX_VOTE_VECTOR_LEN")]
    CertifiedVectorTooLong,
    /// `signers.count() != n - f`.
    #[error("signer count does not match n - f")]
    SignerCountMismatch,
    /// A signer index points outside the committee.
    #[error("signer index out of committee range")]
    SignerOutOfRange,
    /// Combined-sig aggregate BLS check rejected the bundle.
    #[error("combined signature did not verify")]
    BadCombinedSignature,
    /// `Diverging` witness substructure did not validate (bad indices,
    /// inner QC1, or witness sig).
    #[error("diverging-proof witness did not validate")]
    BadDivergingProof,
    /// `ShortWitness` validator not in this QC's signer set, or
    /// witness `x` does not match this QC's `x_p`.
    #[error("short-witness linkage to qc.signers/x_p failed")]
    BadShortWitnessLinkage,
    /// Embedded short-witness vote did not verify.
    #[error("short-witness vote rejected")]
    BadShortWitness,
}

/// Failure modes of a round-3 vote.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PcVote3VerifyError {
    /// `validator` is not in the verifier's committee.
    #[error("signer not in committee")]
    SignerNotInCommittee,
    /// Signer's individual sig over `x_p` did not verify.
    #[error("signature over x_p did not verify")]
    BadSignatureOverXp,
    /// Embedded round-2 QC did not verify.
    #[error("embedded qc2 rejected")]
    EmbeddedQc2Rejected,
    /// `v3.x_p` does not match `qc2.x_p`.
    #[error("v3.x_p does not match embedded qc2.x_p")]
    XpMismatch,
}

/// Failure modes of a round-3 QC.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PcQc3VerifyError {
    /// `x_pe.len() > MAX_VOTE_VECTOR_LEN`.
    #[error("certified vector exceeds MAX_VOTE_VECTOR_LEN")]
    CertifiedVectorTooLong,
    /// `x_pp` is not a prefix of `x_pe`.
    #[error("x_pp is not a prefix of x_pe")]
    XppNotPrefixOfXpe,
    /// Embedded `qc2_xpp` did not verify.
    #[error("embedded qc2_xpp rejected")]
    EmbeddedQc2XppRejected,
    /// Embedded `qc2_xpe` did not verify.
    #[error("embedded qc2_xpe rejected")]
    EmbeddedQc2XpeRejected,
    /// `qc2_xpp.x_p` does not match `qc3.x_pp`.
    #[error("qc2_xpp.x_p does not match qc3.x_pp")]
    XppMismatch,
    /// `qc2_xpe.x_p` does not match `qc3.x_pe`.
    #[error("qc2_xpe.x_p does not match qc3.x_pe")]
    XpeMismatch,
    /// `all_signers.count_ones() != n - f`.
    #[error("signer count does not match n - f")]
    SignerCountMismatch,
    /// `PerSigner` explicit length vector has wrong cardinality.
    #[error("per-signer length count does not match signer count")]
    SignerLengthsCountMismatch,
    /// A signer index points outside the committee.
    #[error("signer index out of committee range")]
    SignerOutOfRange,
    /// `signer_lengths.get(k)` returned `None`.
    #[error("missing signer length")]
    MissingSignerLength,
    /// A signer's claimed length is outside `[|x_pp|, |x_pe|]`.
    #[error("signer length outside [|x_pp|, |x_pe|]")]
    LengthOutOfRange,
    /// `min(lengths) != |x_pp|` or `max(lengths) != |x_pe|`.
    #[error("min/max signer length does not match x_pp/x_pe lengths")]
    MinMaxLengthMismatch,
    /// Aggregate BLS check rejected the per-signer sig bundle.
    #[error("aggregate signature did not verify")]
    BadAggregateSignature,
}

/// Failure modes of vote-equivocation evidence.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PcVoteEquivocationVerifyError {
    /// `value_a == value_b` — no contradiction.
    #[error("value_a equals value_b — no contradiction")]
    ValuesEqual,
    /// `validator` is not in the verifier's committee.
    #[error("equivocator not in committee")]
    SignerNotInCommittee,
    /// One or both sigs did not verify under the validator's pubkey.
    #[error("equivocation signature did not verify")]
    BadSignature,
}

impl Verify<&PcVoteVerifyContext<'_>> for PcVote1 {
    type Error = PcVote1VerifyError;

    fn verify(&self, ctx: &PcVoteVerifyContext<'_>) -> Result<Verified<Self>, Self::Error> {
        verify_vote1(self, ctx.network, ctx.pc_ctx, ctx.committee)?;
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verify<&PcVoteVerifyContext<'_>> for PcQc1 {
    type Error = PcQc1VerifyError;

    fn verify(&self, ctx: &PcVoteVerifyContext<'_>) -> Result<Verified<Self>, Self::Error> {
        verify_qc1(self, ctx.network, ctx.pc_ctx, ctx.committee)?;
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verify<&PcVoteVerifyContext<'_>> for PcVote2 {
    type Error = PcVote2VerifyError;

    fn verify(&self, ctx: &PcVoteVerifyContext<'_>) -> Result<Verified<Self>, Self::Error> {
        verify_vote2(self, ctx.network, ctx.pc_ctx, ctx.committee)?;
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verify<&PcVoteVerifyContext<'_>> for PcQc2 {
    type Error = PcQc2VerifyError;

    fn verify(&self, ctx: &PcVoteVerifyContext<'_>) -> Result<Verified<Self>, Self::Error> {
        verify_qc2(self, ctx.network, ctx.pc_ctx, ctx.committee)?;
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verify<&PcVoteVerifyContext<'_>> for PcVote3 {
    type Error = PcVote3VerifyError;

    fn verify(&self, ctx: &PcVoteVerifyContext<'_>) -> Result<Verified<Self>, Self::Error> {
        verify_vote3(self, ctx.network, ctx.pc_ctx, ctx.committee)?;
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verify<&PcVoteVerifyContext<'_>> for PcQc3 {
    type Error = PcQc3VerifyError;

    fn verify(&self, ctx: &PcVoteVerifyContext<'_>) -> Result<Verified<Self>, Self::Error> {
        verify_qc3(self, ctx.network, ctx.pc_ctx, ctx.committee)?;
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verify<&PcVoteEquivocationContext<'_>> for PcVoteEquivocation {
    type Error = PcVoteEquivocationVerifyError;

    fn verify(&self, ctx: &PcVoteEquivocationContext<'_>) -> Result<Verified<Self>, Self::Error> {
        verify_vote_equivocation(self, ctx.network, ctx.committee)?;
        Ok(Verified::new_unchecked(self.clone()))
    }
}

// ── Named gates ────────────────────────────────────────────────────────────

impl Verified<PcVote1> {
    /// Sign a round-1 vote locally. The result is verified by
    /// construction — the signer's own sigs hold by definition under
    /// the private key.
    #[must_use]
    pub fn sign_local(
        sk: &Bls12381G1PrivateKey,
        validator: ValidatorId,
        network: &NetworkDefinition,
        pc_ctx: &PcContext,
        v_in: PcVector,
    ) -> Self {
        Self::new_unchecked(sign_vote1(sk, validator, network, pc_ctx, v_in))
    }
}

impl Verified<PcVote2> {
    /// Sign a round-2 vote locally, anchored on a verified round-1 QC.
    /// The embedded `qc1` carries its `Verified` marker through into
    /// the produced `PcVote2`, so re-verification short-circuits.
    #[must_use]
    pub fn sign_local(
        sk: &Bls12381G1PrivateKey,
        validator: ValidatorId,
        network: &NetworkDefinition,
        pc_ctx: &PcContext,
        qc1: Verified<PcQc1>,
    ) -> Self {
        Self::new_unchecked(sign_vote2(sk, validator, network, pc_ctx, qc1))
    }
}

impl Verified<PcVote3> {
    /// Sign a round-3 vote locally, anchored on a verified round-2 QC.
    #[must_use]
    pub fn sign_local(
        sk: &Bls12381G1PrivateKey,
        validator: ValidatorId,
        network: &NetworkDefinition,
        pc_ctx: &PcContext,
        qc2: Verified<PcQc2>,
    ) -> Self {
        Self::new_unchecked(sign_vote3(sk, validator, network, pc_ctx, qc2))
    }
}

impl Verified<PcQc1> {
    /// Aggregate a round-1 quorum into a verified QC. Trust source: the
    /// inputs are `Verified<PcVote1>` (each individual signature
    /// already checked), and [`build_qc1`] runs the deterministic
    /// aggregation matching the verifier's reconstruction.
    #[must_use]
    pub fn from_verified_votes(
        votes: &[&Verified<PcVote1>],
        committee: &[(ValidatorId, Bls12381G1PublicKey)],
    ) -> Self {
        let raw: Vec<&PcVote1> = votes.iter().map(|v| AsRef::as_ref(*v)).collect();
        Self::new_unchecked(build_qc1(&raw, committee))
    }
}

impl Verified<PcQc2> {
    /// Aggregate a round-2 quorum into a verified QC.
    #[must_use]
    pub fn from_verified_votes(
        votes: &[&Verified<PcVote2>],
        committee: &[(ValidatorId, Bls12381G1PublicKey)],
    ) -> Self {
        let raw: Vec<&PcVote2> = votes.iter().map(|v| AsRef::as_ref(*v)).collect();
        Self::new_unchecked(build_qc2(&raw, committee))
    }
}

impl Verified<PcQc3> {
    /// Aggregate a round-3 quorum into the verified terminal QC. The
    /// embedded `qc2_xpp` / `qc2_xpe` slots inherit the `Verified`
    /// marker carried on the input votes' embedded `qc2` fields.
    #[must_use]
    pub fn from_verified_votes(
        votes: &[&Verified<PcVote3>],
        committee: &[(ValidatorId, Bls12381G1PublicKey)],
    ) -> Self {
        let raw: Vec<&PcVote3> = votes.iter().map(|v| AsRef::as_ref(*v)).collect();
        Self::new_unchecked(build_qc3(&raw, committee))
    }

    /// Lift the inner proof out of a verified new-commit message. The
    /// outer verify persists the upgraded marker into the inner
    /// `Verifiable<PcQc3>`, so the inner unwraps to a `Verified<PcQc3>`
    /// directly without re-running the predicate.
    ///
    /// # Panics
    ///
    /// Panics if the inner proof's marker isn't live — every
    /// `Verified<SpcNewCommitMsg>` construction path (the verify impl
    /// and [`Verified::<SpcNewCommitMsg>::from_verified_proof`]) lands
    /// the inner in `Verifiable::Verified`.
    #[must_use]
    pub fn from_verified_new_commit(msg: Verified<SpcNewCommitMsg>) -> Self {
        msg.into_inner()
            .proof
            .into_verified()
            .expect("Verified<SpcNewCommitMsg> persists its inner proof marker")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_value(n: u8) -> PcValueElement {
        PcValueElement::new([n; PC_VALUE_ELEMENT_BYTES])
    }

    fn sample_vector(len: u8) -> PcVector {
        PcVector::new((0..len).map(sample_value))
    }

    fn sample_sig(n: u8) -> Bls12381G2Signature {
        Bls12381G2Signature([n; 96])
    }

    fn sample_qc1() -> PcQc1 {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        PcQc1::new(
            sample_vector(3),
            PositionalBundle::new(
                signers,
                vec![
                    PcCompactVote::new(3, None),
                    PcCompactVote::new(2, Some(sample_value(99))),
                ],
            ),
            sample_sig(0xAA),
        )
    }

    fn sample_qc2() -> PcQc2 {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        PcQc2::new(sample_vector(2), signers, sample_sig(0xBB), PcXpProof::Full)
    }

    #[test]
    fn pc_vector_prefix_relations() {
        let empty = PcVector::empty();
        let v3 = sample_vector(3);
        let v5 = sample_vector(5);
        let v5b = PcVector::new((0..5u8).map(|i| sample_value(if i < 3 { i } else { 99 })));

        assert!(empty.is_prefix_of(&v3));
        assert!(v3.is_prefix_of(&v3));
        assert!(v3.is_prefix_of(&v5));
        assert!(!v5.is_prefix_of(&v3));

        assert!(v3.is_consistent_with(&v3));
        assert!(v3.is_consistent_with(&v5));
        assert!(v5.is_consistent_with(&v3));
        assert!(v3.is_consistent_with(&v5b));
        assert!(!v5.is_consistent_with(&v5b)); // diverge at index 3
    }

    #[test]
    fn vote1_sbor_round_trip() {
        let v = PcVote1::new(
            ValidatorId::new(7),
            sample_vector(3),
            vec![sample_sig(1), sample_sig(2), sample_sig(3), sample_sig(4)],
        );
        let bytes = basic_encode(&v).unwrap();
        let decoded: PcVote1 = basic_decode(&bytes).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn vote2_sbor_round_trip() {
        let v = PcVote2::new(
            ValidatorId::new(7),
            sample_vector(2),
            vec![sample_sig(1), sample_sig(2), sample_sig(3)],
            sample_qc1(),
            sample_sig(0x55),
        );
        let bytes = basic_encode(&v).unwrap();
        let decoded: PcVote2 = basic_decode(&bytes).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn vote3_sbor_round_trip() {
        let v = PcVote3::new(
            ValidatorId::new(7),
            sample_vector(2),
            sample_sig(0x77),
            sample_qc2(),
        );
        let bytes = basic_encode(&v).unwrap();
        let decoded: PcVote3 = basic_decode(&bytes).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn qc1_sbor_round_trip() {
        let qc = sample_qc1();
        let bytes = basic_encode(&qc).unwrap();
        let decoded: PcQc1 = basic_decode(&bytes).unwrap();
        assert_eq!(qc, decoded);
    }

    #[test]
    fn qc2_sbor_round_trip_all_xp_proof_variants() {
        let bitfield = {
            let mut b = SignerBitfield::new(4);
            b.set(0);
            b.set(1);
            b.set(2);
            b
        };

        let variants = vec![
            PcXpProof::Full,
            PcXpProof::Diverging(Box::new(PcDivergingProof {
                j: ValidatorId::new(0),
                j_divergent: sample_value(11),
                qc1_j: sample_qc1(),
                k: ValidatorId::new(1),
                k_divergent: sample_value(22),
                qc1_k: sample_qc1(),
                combined_sig: sample_sig(0xBB),
            })),
            PcXpProof::ShortWitness {
                witness: Box::new(PcVote2::new(
                    ValidatorId::new(2),
                    sample_vector(2),
                    vec![sample_sig(1), sample_sig(2), sample_sig(3)],
                    sample_qc1(),
                    sample_sig(0x55),
                )),
            },
        ];

        for pi in variants {
            let qc = PcQc2::new(sample_vector(2), bitfield.clone(), sample_sig(0xDD), pi);
            let bytes = basic_encode(&qc).unwrap();
            let decoded: PcQc2 = basic_decode(&bytes).unwrap();
            assert_eq!(qc, decoded);
        }
    }

    fn signers_bitfield(num_validators: usize, set: &[usize]) -> SignerBitfield {
        let mut bf = SignerBitfield::new(num_validators);
        for &i in set {
            bf.set(i);
        }
        bf
    }

    #[test]
    fn qc3_dedup_encoding_resolves_to_low_when_high_is_none() {
        let qc = PcQc3::new(
            sample_vector(2),
            sample_qc2(),
            None,
            None,
            signers_bitfield(4, &[0]),
            PcSignerLengths::Uniform(2),
            sample_sig(0xEE),
        );
        assert_eq!(qc.x_pe(), qc.x_pp());
        assert_eq!(qc.qc2_xpe(), qc.qc2_xpp());
    }

    #[test]
    fn qc3_dedup_encoding_resolves_to_high_when_some() {
        let high = sample_vector(3);
        let high_qc2 = {
            let mut signers = SignerBitfield::new(4);
            signers.set(0);
            PcQc2::new(high.clone(), signers, sample_sig(0x33), PcXpProof::Full)
        };
        let qc = PcQc3::new(
            sample_vector(2),
            sample_qc2(),
            Some(high.clone()),
            Some(Verifiable::from(high_qc2.clone())),
            signers_bitfield(4, &[0, 1]),
            PcSignerLengths::PerSigner(vec![2u32, 3].into()),
            sample_sig(0xEE),
        );
        assert_eq!(qc.x_pe(), &high);
        assert_eq!(qc.qc2_xpe(), &high_qc2);
    }

    #[test]
    fn qc3_sbor_round_trip() {
        let qc = PcQc3::new(
            sample_vector(2),
            sample_qc2(),
            Some(sample_vector(3)),
            None,
            signers_bitfield(4, &[0, 1]),
            PcSignerLengths::PerSigner(vec![2u32, 3].into()),
            sample_sig(0xEE),
        );
        let bytes = basic_encode(&qc).unwrap();
        let decoded: PcQc3 = basic_decode(&bytes).unwrap();
        assert_eq!(qc, decoded);
    }

    #[test]
    fn signer_lengths_collapses_to_uniform_when_all_equal() {
        let lens = PcSignerLengths::from_per_signer(vec![3, 3, 3]);
        assert!(matches!(lens, PcSignerLengths::Uniform(3)));
    }

    #[test]
    fn signer_lengths_keeps_per_signer_when_divergent() {
        let lens = PcSignerLengths::from_per_signer(vec![2, 3, 3]);
        assert!(matches!(lens, PcSignerLengths::PerSigner(_)));
        assert_eq!(lens.get(0), Some(2));
        assert_eq!(lens.get(1), Some(3));
        assert_eq!(lens.explicit_count(), Some(3));
    }

    #[test]
    fn uniform_signer_lengths_returns_same_value_for_any_index() {
        let lens = PcSignerLengths::Uniform(5);
        assert_eq!(lens.get(0), Some(5));
        assert_eq!(lens.get(10), Some(5));
        assert_eq!(lens.explicit_count(), None);
    }

    #[test]
    fn value_element_sbor_transparent() {
        let raw: [u8; PC_VALUE_ELEMENT_BYTES] = [0xAB; PC_VALUE_ELEMENT_BYTES];
        let wrapped = PcValueElement::new(raw);
        let raw_bytes = basic_encode(&raw).unwrap();
        let wrapped_bytes = basic_encode(&wrapped).unwrap();
        assert_eq!(raw_bytes, wrapped_bytes);
    }

    #[test]
    fn pc_vector_sbor_transparent() {
        let inner: BoundedVec<PcValueElement, MAX_VOTE_VECTOR_LEN> =
            (0..3u8).map(sample_value).collect::<Vec<_>>().into();
        let wrapped = PcVector(inner.clone());
        let inner_bytes = basic_encode(&inner).unwrap();
        let wrapped_bytes = basic_encode(&wrapped).unwrap();
        assert_eq!(inner_bytes, wrapped_bytes);
    }

    #[test]
    fn pc_vote_equivocation_sbor_round_trip_all_rounds() {
        for round in [PcVoteRound::Vote1, PcVoteRound::Vote2, PcVoteRound::Vote3] {
            let e = PcVoteEquivocation {
                validator: ValidatorId::new(7),
                epoch: Epoch::new(42),
                view: SpcView::new(3),
                round,
                value_a: sample_vector(2),
                sig_a: sample_sig(0x11),
                value_b: sample_vector(3),
                sig_b: sample_sig(0x22),
            };
            let bytes = basic_encode(&e).unwrap();
            let decoded: PcVoteEquivocation = basic_decode(&bytes).unwrap();
            assert_eq!(e, decoded);
        }
    }

    #[test]
    fn pc_vote_round_sbor_round_trip_all_variants() {
        for r in [PcVoteRound::Vote1, PcVoteRound::Vote2, PcVoteRound::Vote3] {
            let bytes = basic_encode(&r).unwrap();
            let decoded: PcVoteRound = basic_decode(&bytes).unwrap();
            assert_eq!(r, decoded);
        }
    }
}
