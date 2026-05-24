//! Prefix Consensus (PC) vote and QC wire types.
//!
//! PC is the inner three-round protocol that drives one slot's committee
//! from individual input vectors to a single certified
//! `(certified_low, certified_high)` pair. Every honest committee
//! member's input vector is a sequence of [`PcValueElement`]s; PC's job
//! is to attain agreement on the maximum common prefix the committee
//! could collectively endorse, witnessed by an aggregate signature.
//!
//! These types describe the *wire form* of votes and QCs at each round.
//! Verification, multi-sig assembly, and the protocol state machine
//! live in the beacon crate.

use sbor::prelude::*;

use crate::primitives::signer_bitfield::MAX_VALIDATORS;
use crate::{
    Bls12381G2Signature, BoundedVec, MAX_PREFIX_SIGS, MAX_VOTE_VECTOR_LEN, SignerBitfield, Slot,
    SpcView, ValidatorId,
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
pub struct PcValueElement(pub [u8; PC_VALUE_ELEMENT_BYTES]);

impl PcValueElement {
    /// All-zero element.
    pub const ZERO: Self = Self([0u8; PC_VALUE_ELEMENT_BYTES]);

    /// Build a `PcValueElement` from a raw 32-byte array.
    #[must_use]
    pub const fn new(bytes: [u8; PC_VALUE_ELEMENT_BYTES]) -> Self {
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
/// PC's safety property guarantees a finalized slot's certified low /
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
/// prefix slot).
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

    /// Signer's input vector for the slot.
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
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct PcCompactVote {
    validator: ValidatorId,
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
    pub const fn new(
        validator: ValidatorId,
        shared_len: u32,
        divergent: Option<PcValueElement>,
    ) -> Self {
        Self {
            validator,
            shared_len,
            divergent,
        }
    }

    /// Signer this compact vote represents.
    #[must_use]
    pub const fn validator(&self) -> ValidatorId {
        self.validator
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
    /// `x`.
    x_signers: BoundedVec<PcCompactVote, MAX_VALIDATORS>,
    /// Aggregate over each signer's `sig_i(v'_i)` — different-messages
    /// aggregate, since each `v'_i` may be a different length.
    x_agg_sig: Bls12381G2Signature,
}

impl PcQc1 {
    /// Build a `PcQc1` from its parts.
    ///
    /// # Panics
    ///
    /// Panics if `x_signers.len() > MAX_VALIDATORS`.
    #[must_use]
    pub fn new(x: PcVector, x_signers: Vec<PcCompactVote>, x_agg_sig: Bls12381G2Signature) -> Self {
        Self {
            x,
            x_signers: x_signers.into(),
            x_agg_sig,
        }
    }

    /// Certified prefix.
    #[must_use]
    pub const fn x(&self) -> &PcVector {
        &self.x
    }

    /// Compact round-1 signer set.
    #[must_use]
    pub const fn x_signers(&self) -> &BoundedVec<PcCompactVote, MAX_VALIDATORS> {
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
    qc1: PcQc1,
    /// `sig_validator([x.len()])` under the round-2 length tag. Binds
    /// the signer to their specific `x` length.
    length_attestation: Bls12381G2Signature,
}

impl PcVote2 {
    /// Build a `PcVote2` from its parts.
    ///
    /// # Panics
    ///
    /// Panics if `prefix_sigs.len() > MAX_PREFIX_SIGS`.
    #[must_use]
    pub fn new(
        validator: ValidatorId,
        x: PcVector,
        prefix_sigs: Vec<Bls12381G2Signature>,
        qc1: PcQc1,
        length_attestation: Bls12381G2Signature,
    ) -> Self {
        Self {
            validator,
            x,
            prefix_sigs: prefix_sigs.into(),
            qc1,
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

    /// Round-1 QC anchoring this validator's `x`.
    #[must_use]
    pub const fn qc1(&self) -> &PcQc1 {
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
    /// First diverging signer's prefix sig over `x_p ++ [j_divergent]`.
    pub j_sig: Bls12381G2Signature,
    /// Round-1 QC anchoring the first diverging signer's full `x`.
    pub qc1_j: PcQc1,
    /// Second diverging signer.
    pub k: ValidatorId,
    /// Second diverging signer's value at position `|x_p|`.
    pub k_divergent: PcValueElement,
    /// Second diverging signer's prefix sig over `x_p ++ [k_divergent]`.
    pub k_sig: Bls12381G2Signature,
    /// Round-1 QC anchoring the second diverging signer's full `x`.
    pub qc1_k: PcQc1,
}

/// Witness that `PcQc2.x_p` is the actual mcp of the round-2 quorum's
/// `x` values.
///
/// Required because the multi-sig alone only proves `n - f` signers
/// signed `x_p` — it doesn't prove `x_p` is the *longest* prefix they
/// all agree on.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub enum PcXpProof {
    /// Every signer's `x` equals `x_p` exactly. The `x_p` multi-sig
    /// proves `x_p ⪯ x_i`; the length multi-sig pins each `|x_i|` to
    /// `|x_p|`, so combined they bind `x_i = x_p`.
    Full {
        /// Multi-sig over `[|x_p|]` from every signer in `S₂` under
        /// the round-2 length tag.
        length_multi_sig: Bls12381G2Signature,
    },
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
/// quorum, plus the multi-sig over that prefix and a witness that it
/// is in fact the mcp.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct PcQc2 {
    x_p: PcVector,
    /// `n - f` signers in the quorum (positional against the
    /// committee enumeration).
    signers: SignerBitfield,
    /// BLS multi-sig over `x_p` by every signer in `signers`.
    multi_sig: Bls12381G2Signature,
    /// Proof that `x_p` is in fact the mcp.
    pi: PcXpProof,
}

impl PcQc2 {
    /// Build a `PcQc2` from its parts.
    #[must_use]
    pub const fn new(
        x_p: PcVector,
        signers: SignerBitfield,
        multi_sig: Bls12381G2Signature,
        pi: PcXpProof,
    ) -> Self {
        Self {
            x_p,
            signers,
            multi_sig,
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

    /// Multi-sig over `x_p`.
    #[must_use]
    pub const fn multi_sig(&self) -> Bls12381G2Signature {
        self.multi_sig
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
    qc2: PcQc2,
}

impl PcVote3 {
    /// Build a `PcVote3` from its parts.
    #[must_use]
    pub const fn new(
        validator: ValidatorId,
        x_p: PcVector,
        sig_xp: Bls12381G2Signature,
        qc2: PcQc2,
    ) -> Self {
        Self {
            validator,
            x_p,
            sig_xp,
            qc2,
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

    /// Round-2 QC anchoring `x_p`.
    #[must_use]
    pub const fn qc2(&self) -> &PcQc2 {
        &self.qc2
    }
}

/// One round-3 signer's `(validator, |x_p_i|)` pair.
///
/// By "Lemma 3.1" every round-3 signer's `x_p_i` extends the others,
/// so the longest `x_pe` plus a length per signer fully recovers each
/// `x_p_i = x_pe[..len_i]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BasicSbor)]
pub struct PcCompactLenSigner {
    /// Round-3 signer.
    pub validator: ValidatorId,
    /// Length of this signer's certified prefix `x_p_i`. Bounded above
    /// by `MAX_VOTE_VECTOR_LEN`.
    pub prefix_len: u32,
}

impl PcCompactLenSigner {
    /// Build a `PcCompactLenSigner` from its parts.
    #[must_use]
    pub const fn new(validator: ValidatorId, prefix_len: u32) -> Self {
        Self {
            validator,
            prefix_len,
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
    qc2_xpp: PcQc2,
    /// `None` is dedup-encoding for "same as `x_pp`".
    x_pe: Option<PcVector>,
    /// `None` is dedup-encoding for "same as `qc2_xpp`".
    qc2_xpe: Option<PcQc2>,
    /// `(validator, |x_p_i|)` for *every* signer in the round-3 quorum.
    all_signers: BoundedVec<PcCompactLenSigner, MAX_VALIDATORS>,
    /// Aggregate over `sig_i(x_p_i)` for every signer in `all_signers`.
    agg_sig: Bls12381G2Signature,
}

impl PcQc3 {
    /// Build a `PcQc3` from its parts.
    ///
    /// # Panics
    ///
    /// Panics if `all_signers.len() > MAX_VALIDATORS`.
    #[must_use]
    #[allow(clippy::similar_names)] // paper notation: x_pp / x_pe and qc2_xpp / qc2_xpe
    pub fn new(
        x_pp: PcVector,
        qc2_xpp: PcQc2,
        x_pe: Option<PcVector>,
        qc2_xpe: Option<PcQc2>,
        all_signers: Vec<PcCompactLenSigner>,
        agg_sig: Bls12381G2Signature,
    ) -> Self {
        Self {
            x_pp,
            qc2_xpp,
            x_pe,
            qc2_xpe,
            all_signers: all_signers.into(),
            agg_sig,
        }
    }

    /// Certified low: the mcp of the round-3 quorum's `x_p_i` values.
    #[must_use]
    pub const fn x_pp(&self) -> &PcVector {
        &self.x_pp
    }

    /// `PcQc2` for the round-3 vote that attained `x_pp`.
    #[must_use]
    pub const fn qc2_xpp(&self) -> &PcQc2 {
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
        self.qc2_xpe.as_ref().unwrap_or(&self.qc2_xpp)
    }

    /// `(validator, |x_p_i|)` for every signer in the round-3 quorum.
    #[must_use]
    pub const fn all_signers(&self) -> &BoundedVec<PcCompactLenSigner, MAX_VALIDATORS> {
        &self.all_signers
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
/// at the same `(slot, view, round)` of the inner Prefix Consensus.
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
    /// Slot the inner Prefix Consensus instance belongs to.
    pub slot: Slot,
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
        PcQc1::new(
            sample_vector(3),
            vec![
                PcCompactVote::new(ValidatorId::new(0), 3, None),
                PcCompactVote::new(ValidatorId::new(1), 2, Some(sample_value(99))),
            ],
            sample_sig(0xAA),
        )
    }

    fn sample_qc2() -> PcQc2 {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        PcQc2::new(
            sample_vector(2),
            signers,
            sample_sig(0xBB),
            PcXpProof::Full {
                length_multi_sig: sample_sig(0xCC),
            },
        )
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
            PcXpProof::Full {
                length_multi_sig: sample_sig(0xAA),
            },
            PcXpProof::Diverging(Box::new(PcDivergingProof {
                j: ValidatorId::new(0),
                j_divergent: sample_value(11),
                j_sig: sample_sig(0xBB),
                qc1_j: sample_qc1(),
                k: ValidatorId::new(1),
                k_divergent: sample_value(22),
                k_sig: sample_sig(0xCC),
                qc1_k: sample_qc1(),
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

    #[test]
    fn qc3_dedup_encoding_resolves_to_low_when_high_is_none() {
        let qc = PcQc3::new(
            sample_vector(2),
            sample_qc2(),
            None,
            None,
            vec![PcCompactLenSigner::new(ValidatorId::new(0), 2)],
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
            PcQc2::new(
                high.clone(),
                signers,
                sample_sig(0x33),
                PcXpProof::Full {
                    length_multi_sig: sample_sig(0x44),
                },
            )
        };
        let qc = PcQc3::new(
            sample_vector(2),
            sample_qc2(),
            Some(high.clone()),
            Some(high_qc2.clone()),
            vec![
                PcCompactLenSigner::new(ValidatorId::new(0), 2),
                PcCompactLenSigner::new(ValidatorId::new(1), 3),
            ],
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
            vec![
                PcCompactLenSigner::new(ValidatorId::new(0), 2),
                PcCompactLenSigner::new(ValidatorId::new(1), 3),
            ],
            sample_sig(0xEE),
        );
        let bytes = basic_encode(&qc).unwrap();
        let decoded: PcQc3 = basic_decode(&bytes).unwrap();
        assert_eq!(qc, decoded);
    }

    #[test]
    fn value_element_sbor_transparent() {
        let raw: [u8; PC_VALUE_ELEMENT_BYTES] = [0xAB; PC_VALUE_ELEMENT_BYTES];
        let wrapped = PcValueElement(raw);
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
                slot: Slot::new(42),
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
