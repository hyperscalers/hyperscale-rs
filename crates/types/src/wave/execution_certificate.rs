//! [`ExecutionCertificate`] — aggregated 2f+1 BLS signature over a wave's
//! per-tx outcomes.
//!
//! [`ExecutionCertificate`] is the raw wire form. Its verified form is
//! `Verified<ExecutionCertificate>`; predicate at
//! [`impl Verify<&ExecutionCertificateContext<'_>>`](Verify::verify) below.

use std::collections::HashMap;
use std::fmt::{self, Debug, Formatter};

use sbor::prelude::*;
use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, TypeKind, ValueKind,
};
use thiserror::Error;

use crate::sbor_codec::decode_bounded_vec;
use crate::{
    BlockHeight, Bls12381G1PublicKey, Bls12381G2Signature, ExecutionVote, GlobalReceiptRoot, Hash,
    MAX_TXS_PER_BLOCK, NetworkDefinition, RETENTION_HORIZON, ShardId, SignerBitfield, TxOutcome,
    ValidatorId, Verified, Verify, WaveId, WeightedTimestamp, compute_global_receipt_root,
    exec_vote_message, verify_bls12381_v1, zero_bls_signature,
};

/// Aggregated certificate for an execution wave.
///
/// Contains the BLS aggregated signature from 2f+1 validators plus per-tx
/// outcomes so remote shards can extract individual transaction results.
pub struct ExecutionCertificate {
    wave_id: WaveId,
    vote_anchor_ts: WeightedTimestamp,
    global_receipt_root: GlobalReceiptRoot,
    tx_outcomes: Vec<TxOutcome>,
    aggregated_signature: Bls12381G2Signature,
    signers: SignerBitfield,
    /// Cached SBOR-encoded bytes. Populated at construction or after
    /// deserialization to avoid re-serialization on storage writes.
    cached_sbor: Option<Vec<u8>>,
}

impl Debug for ExecutionCertificate {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutionCertificate")
            .field("wave_id", &self.wave_id)
            .field("vote_anchor_ts", &self.vote_anchor_ts)
            .field("global_receipt_root", &self.global_receipt_root)
            .field("tx_outcomes", &self.tx_outcomes)
            .field("aggregated_signature", &self.aggregated_signature)
            .field("signers", &self.signers)
            .finish_non_exhaustive()
    }
}

impl Clone for ExecutionCertificate {
    fn clone(&self) -> Self {
        Self {
            wave_id: self.wave_id.clone(),
            vote_anchor_ts: self.vote_anchor_ts,
            global_receipt_root: self.global_receipt_root,
            tx_outcomes: self.tx_outcomes.clone(),
            aggregated_signature: self.aggregated_signature,
            signers: self.signers.clone(),
            cached_sbor: self.cached_sbor.clone(),
        }
    }
}

impl PartialEq for ExecutionCertificate {
    fn eq(&self, other: &Self) -> bool {
        self.wave_id == other.wave_id
            && self.vote_anchor_ts == other.vote_anchor_ts
            && self.global_receipt_root == other.global_receipt_root
            && self.tx_outcomes == other.tx_outcomes
            && self.aggregated_signature == other.aggregated_signature
            && self.signers == other.signers
    }
}

impl Eq for ExecutionCertificate {}

// Manual SBOR: cached_sbor is derived, not serialized.
impl<E: Encoder<NoCustomValueKind>> Encode<NoCustomValueKind, E> for ExecutionCertificate {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_size(6)?;
        encoder.encode(&self.wave_id)?;
        encoder.encode(&self.vote_anchor_ts)?;
        encoder.encode(&self.global_receipt_root)?;
        encoder.encode(&self.tx_outcomes)?;
        encoder.encode(&self.aggregated_signature)?;
        encoder.encode(&self.signers)?;
        Ok(())
    }
}

impl<D: Decoder<NoCustomValueKind>> Decode<NoCustomValueKind, D> for ExecutionCertificate {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 6 {
            return Err(DecodeError::UnexpectedSize {
                expected: 6,
                actual: length,
            });
        }
        let wave_id: WaveId = decoder.decode()?;
        let vote_anchor_ts: WeightedTimestamp = decoder.decode()?;
        let global_receipt_root: GlobalReceiptRoot = decoder.decode()?;
        let tx_outcomes = decode_bounded_vec::<_, TxOutcome>(decoder, MAX_TXS_PER_BLOCK)?;
        let aggregated_signature: Bls12381G2Signature = decoder.decode()?;
        let signers: SignerBitfield = decoder.decode()?;
        // The BLS aggregate only commits to (global_receipt_root, tx_count),
        // not to tx_outcomes content. Without this check a Byzantine
        // aggregator could ship a signature-valid EC whose outcomes don't
        // hash to the signed root, slipping bogus per-tx results past every
        // downstream consumer (gossip ingress, fetch ingress, FinalizedWave
        // admission).
        if compute_global_receipt_root(&tx_outcomes) != global_receipt_root {
            return Err(DecodeError::InvalidCustomValue);
        }
        let mut ec = Self {
            wave_id,
            vote_anchor_ts,
            global_receipt_root,
            tx_outcomes,
            aggregated_signature,
            signers,
            cached_sbor: None,
        };
        ec.populate_cached_sbor();
        Ok(ec)
    }
}

impl Categorize<NoCustomValueKind> for ExecutionCertificate {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Tuple
    }
}

impl Describe<NoCustomTypeKind> for ExecutionCertificate {
    const TYPE_ID: RustTypeId = RustTypeId::novel_with_code("ExecutionCertificate", &[], &[]);

    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        TypeData::unnamed(TypeKind::Any)
    }
}

impl ExecutionCertificate {
    /// Create a new execution certificate.
    #[must_use]
    pub fn new(
        wave_id: WaveId,
        vote_anchor_ts: WeightedTimestamp,
        global_receipt_root: GlobalReceiptRoot,
        tx_outcomes: Vec<TxOutcome>,
        aggregated_signature: Bls12381G2Signature,
        signers: SignerBitfield,
    ) -> Self {
        let mut ec = Self {
            wave_id,
            vote_anchor_ts,
            global_receipt_root,
            tx_outcomes,
            aggregated_signature,
            signers,
            cached_sbor: None,
        };
        ec.populate_cached_sbor();
        ec
    }

    /// Self-contained wave identifier (shard + height + remote dependencies).
    #[must_use]
    pub const fn wave_id(&self) -> &WaveId {
        &self.wave_id
    }

    /// Consensus height at which quorum was reached.
    ///
    /// Must match the `vote_anchor_ts` in the aggregated votes. Needed to
    /// reconstruct the BLS signing message for signature verification.
    #[must_use]
    pub const fn vote_anchor_ts(&self) -> WeightedTimestamp {
        self.vote_anchor_ts
    }

    /// Merkle root over per-tx outcome leaves.
    #[must_use]
    pub const fn global_receipt_root(&self) -> GlobalReceiptRoot {
        self.global_receipt_root
    }

    /// Per-transaction outcomes (in wave order = block order).
    #[must_use]
    pub const fn tx_outcomes(&self) -> &Vec<TxOutcome> {
        &self.tx_outcomes
    }

    /// BLS aggregated signature from 2f+1 validators.
    #[must_use]
    pub const fn aggregated_signature(&self) -> Bls12381G2Signature {
        self.aggregated_signature
    }

    /// Which validators signed (bitfield indexed by committee position).
    #[must_use]
    pub const fn signers(&self) -> &SignerBitfield {
        &self.signers
    }

    /// The shard that produced this certificate.
    #[must_use]
    pub const fn shard_id(&self) -> ShardId {
        self.wave_id.shard_id()
    }

    /// Deadline past which this certificate is provably useless on every shard.
    ///
    /// Anchored on `vote_anchor_ts` — the wave's BFT-authenticated commit
    /// timestamp. Past `vote_anchor_ts + RETENTION_HORIZON` every tx in the
    /// wave has expired its `validity_range` and terminated (success or
    /// abort), so no shard can still reference this EC.
    #[must_use]
    pub fn deadline(&self) -> WeightedTimestamp {
        self.vote_anchor_ts.plus(RETENTION_HORIZON)
    }

    /// Block height (the block containing the wave's transactions).
    #[must_use]
    pub const fn block_height(&self) -> BlockHeight {
        self.wave_id.block_height()
    }

    /// Pre-serialized SBOR bytes, if available.
    #[must_use]
    pub fn cached_sbor_bytes(&self) -> Option<&[u8]> {
        self.cached_sbor.as_deref()
    }

    /// Content hash over the full wire encoding (including
    /// `aggregated_signature` and `signers`). Distinguishes byte-identical
    /// retransmits — useful as an in-flight dedup key — while still treating
    /// different aggregations of the same logical EC as distinct, so a peer
    /// supplying a valid aggregation after a bad one isn't dropped.
    ///
    /// # Panics
    ///
    /// Panics if SBOR encoding fails — closed type, infallible in practice.
    #[must_use]
    pub fn wire_hash(&self) -> Hash {
        self.cached_sbor.as_deref().map_or_else(
            || {
                let bytes = basic_encode(self).expect("EC SBOR encoding must succeed");
                Hash::from_parts(&[&bytes])
            },
            |bytes| Hash::from_parts(&[bytes]),
        )
    }

    fn populate_cached_sbor(&mut self) {
        self.cached_sbor = Some(basic_encode(self).expect("EC SBOR encoding must succeed"));
    }

    /// Build the canonical signing message used by every constituent vote
    /// (and the aggregated certificate).
    ///
    /// Same message as [`ExecutionVote::signing_message`]; reconstructed
    /// from the EC's own fields so verifiers don't need a vote sample.
    #[must_use]
    pub fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        exec_vote_message(
            network,
            self.vote_anchor_ts,
            &self.wave_id,
            self.shard_id(),
            &self.global_receipt_root,
            u32::try_from(self.tx_outcomes.len()).unwrap_or(u32::MAX),
        )
    }
}

/// Inputs the [`ExecutionCertificate`] verifier reads against. Borrows
/// everything; nothing is consumed.
#[derive(Debug, Clone, Copy)]
pub struct ExecutionCertificateContext<'a> {
    /// Network identifier — feeds the domain-separated signing message.
    pub network: &'a NetworkDefinition,
    /// Committee public keys in committee order. The certificate's
    /// `signers` bitfield indexes into this slice.
    pub public_keys: &'a [Bls12381G1PublicKey],
}

/// Failure modes of [`ExecutionCertificate`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ExecutionCertificateVerifyError {
    /// `signers` bitfield is empty but `aggregated_signature` is not the
    /// zero signature. An empty signer set must be paired with the zero
    /// signature; any other pairing is ill-formed.
    #[error("empty signer set paired with non-zero aggregated signature")]
    EmptySignersWithNonZeroSignature,
    /// The aggregated BLS signature did not validate against the
    /// aggregated public key derived from `signers` over the canonical
    /// signing message. Also covers public-key aggregation failures.
    #[error("aggregated BLS signature invalid")]
    BadAggregatedSignature,
}

/// Construction asserts: the aggregated BLS signature validates against
/// the public key formed by aggregating `public_keys[i]` for every `i`
/// set in `signers`, over the canonical [`exec_vote_message`] derived
/// from the certificate's `(vote_anchor_ts, wave_id, shard_id,
/// global_receipt_root, tx_count)`. Empty signer sets must carry the
/// zero signature.
///
/// Construction goes through one of three gates:
///
/// - [`<ExecutionCertificate as Verify>::verify`](Verify::verify) —
///   runs the predicate against a committee public-key vector.
/// - [`Verified::<ExecutionCertificate>::aggregate`] — builds the
///   certificate from a quorum of verified votes; the predicate holds
///   by construction (each verified vote's signature aggregates into
///   the certificate's signature, the signers bitfield mirrors the
///   committee indices of those voters).
/// - [`Verified::<ExecutionCertificate>::from_persisted`] — re-wraps
///   a certificate that satisfied the predicate at write time.
impl Verify<&ExecutionCertificateContext<'_>> for ExecutionCertificate {
    type Error = ExecutionCertificateVerifyError;

    fn verify(&self, ctx: &ExecutionCertificateContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let signer_keys: Vec<Bls12381G1PublicKey> = ctx
            .public_keys
            .iter()
            .enumerate()
            .filter(|(i, _)| self.signers.is_set(*i))
            .map(|(_, pk)| *pk)
            .collect();

        if signer_keys.is_empty() {
            if self.aggregated_signature == zero_bls_signature() {
                return Ok(Verified::new_unchecked(self.clone()));
            }
            return Err(ExecutionCertificateVerifyError::EmptySignersWithNonZeroSignature);
        }

        let aggregated_pk = Bls12381G1PublicKey::aggregate(&signer_keys, false)
            .map_err(|_| ExecutionCertificateVerifyError::BadAggregatedSignature)?;
        let message = self.signing_message(ctx.network);
        if !verify_bls12381_v1(&message, &aggregated_pk, &self.aggregated_signature) {
            return Err(ExecutionCertificateVerifyError::BadAggregatedSignature);
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verified<ExecutionCertificate> {
    /// Build a [`Verified<ExecutionCertificate>`] from a quorum of
    /// verified votes.
    ///
    /// The caller is responsible for the quorum-power check; this gate
    /// only asserts the predicate (signature aggregation + signer-bit
    /// mapping). Every input vote is assumed to share the same signing
    /// message — the `VoteTracker` bucketing key `(global_receipt_root,
    /// vote_anchor_ts)` plus the per-wave `wave_id` and `shard_id`
    /// uniquely determine that message, so a single bucket's contents
    /// satisfy this contract by construction.
    ///
    /// Validators not in `committee` contribute their signature to the
    /// aggregate but no bit to `signers`; the resulting EC would fail
    /// verify. The caller filters non-committee voters upstream.
    ///
    /// # Panics
    ///
    /// Panics if `votes` is empty, or if BLS aggregation of the
    /// individually-verified signatures fails — both indicate an
    /// upstream invariant violation (predicate bypass, sub-quorum
    /// input, or BLS library bug).
    #[must_use]
    pub fn aggregate(
        wave_id: &WaveId,
        global_receipt_root: GlobalReceiptRoot,
        votes: &[Verified<ExecutionVote>],
        committee: &[ValidatorId],
    ) -> Self {
        let tx_outcomes = votes
            .iter()
            .find(|v| compute_global_receipt_root(v.tx_outcomes()) == global_receipt_root)
            .map(|v| v.tx_outcomes().to_vec())
            .expect("verified votes guarantee at least one with matching outcomes");

        let mut seen_validators: std::collections::HashSet<ValidatorId> =
            std::collections::HashSet::new();
        let unique_votes: Vec<&Verified<ExecutionVote>> = votes
            .iter()
            .filter(|vote| seen_validators.insert(vote.validator()))
            .collect();

        let bls_signatures: Vec<Bls12381G2Signature> =
            unique_votes.iter().map(|vote| vote.signature()).collect();
        let aggregated_signature = if bls_signatures.is_empty() {
            zero_bls_signature()
        } else {
            Bls12381G2Signature::aggregate(&bls_signatures, true)
                .expect("aggregation of upstream-verified BLS signatures cannot fail")
        };

        let committee_index: HashMap<ValidatorId, usize> = committee
            .iter()
            .enumerate()
            .map(|(idx, &vid)| (vid, idx))
            .collect();
        let mut signers = SignerBitfield::new(committee.len());
        for vote in &unique_votes {
            if let Some(&idx) = committee_index.get(&vote.validator()) {
                signers.set(idx);
            }
        }

        let vote_anchor_ts = votes
            .first()
            .map_or(WeightedTimestamp::ZERO, |v| v.vote_anchor_ts());

        // SAFETY: every input vote satisfies the `ExecutionVote`
        // predicate against its own pubkey for the shared signing
        // message determined by `(vote_anchor_ts, wave_id,
        // shard_id, global_receipt_root, tx_count)`. Aggregating
        // those signatures and mirroring the committee indices in
        // `signers` produces an EC whose predicate is structurally
        // equivalent: the aggregated pubkey at verify time recombines
        // the same per-validator pubkeys, and BLS aggregate-verify
        // succeeds.
        Self::new_unchecked(ExecutionCertificate::new(
            wave_id.clone(),
            vote_anchor_ts,
            global_receipt_root,
            tx_outcomes,
            aggregated_signature,
            signers,
        ))
    }

    /// Re-wrap a certificate that satisfied the predicate at write
    /// time. ECs ride into storage embedded inside `Verified<FinalizedWave>`
    /// values inside the `Verified<CertifiedBlock>` argument to
    /// `commit_block`, so unverified ECs can't reach the write path.
    /// Storage rehydration paths use this gate to avoid re-running BLS
    /// aggregation on every load.
    #[must_use]
    pub const fn from_persisted(cert: ExecutionCertificate) -> Self {
        // SAFETY: the certificate's predicate held at write time;
        // storage is the trust source. Mirrors
        // `Verified::<QuorumCertificate>::from_persisted` on the
        // shard side.
        Self::new_unchecked(cert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BlockHash, BlockHeight, Bls12381G1PrivateKey, ExecutionOutcome, GlobalReceiptHash, TxHash,
        generate_bls_keypair,
    };

    fn outcome(seed: u8) -> TxOutcome {
        TxOutcome::new(
            TxHash::from_raw(Hash::from_bytes(&[seed; 4])),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(&[seed + 100; 4])),
            },
        )
    }

    fn wave_id() -> WaveId {
        WaveId::new(
            ShardId::leaf(1, 0),
            BlockHeight::new(7),
            std::iter::once(ShardId::leaf(1, 1)).collect(),
        )
    }

    /// Build a signed vote with the given signing key. Used for fixture
    /// construction; the resulting `Verified<ExecutionVote>` would also
    /// satisfy `<ExecutionVote as Verify>::verify` against `sk.public_key()`.
    fn signed_vote(
        net: &NetworkDefinition,
        sk: &Bls12381G1PrivateKey,
        validator: u64,
        outcomes: Vec<TxOutcome>,
    ) -> Verified<ExecutionVote> {
        Verified::<ExecutionVote>::sign_local(
            net,
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            BlockHeight::new(7),
            WeightedTimestamp::from_millis(11),
            wave_id(),
            ShardId::leaf(1, 0),
            outcomes,
            ValidatorId::new(validator),
            sk,
        )
    }

    /// Aggregate produces an EC whose predicate verifies against the
    /// matching committee public keys — the canonical sign-then-verify
    /// round trip across the typed gates.
    #[test]
    fn aggregate_roundtrips_through_verify() {
        let net = NetworkDefinition::simulator();
        let committee: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let sks: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let pks: Vec<Bls12381G1PublicKey> =
            sks.iter().map(Bls12381G1PrivateKey::public_key).collect();
        let outcomes = vec![outcome(1), outcome(2)];
        let root = compute_global_receipt_root(&outcomes);

        let votes: Vec<Verified<ExecutionVote>> = (0..4)
            .map(|i| signed_vote(&net, &sks[usize::try_from(i).unwrap()], i, outcomes.clone()))
            .collect();

        let cert =
            Verified::<ExecutionCertificate>::aggregate(&wave_id(), root, &votes, &committee);

        let ctx = ExecutionCertificateContext {
            network: &net,
            public_keys: &pks,
        };
        let raw = cert.into_inner();
        raw.verify(&ctx)
            .expect("aggregate output must satisfy its own predicate");
    }

    /// A certificate whose `aggregated_signature` was tampered with
    /// fails the BLS check; the verifier returns `BadAggregatedSignature`.
    #[test]
    fn verify_rejects_bad_aggregated_signature() {
        let net = NetworkDefinition::simulator();
        let committee: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let sks: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let pks: Vec<Bls12381G1PublicKey> =
            sks.iter().map(Bls12381G1PrivateKey::public_key).collect();
        let outcomes = vec![outcome(1)];
        let root = compute_global_receipt_root(&outcomes);

        let votes: Vec<Verified<ExecutionVote>> = (0..4)
            .map(|i| signed_vote(&net, &sks[usize::try_from(i).unwrap()], i, outcomes.clone()))
            .collect();
        let cert =
            Verified::<ExecutionCertificate>::aggregate(&wave_id(), root, &votes, &committee)
                .into_inner();

        let tampered = ExecutionCertificate::new(
            cert.wave_id().clone(),
            cert.vote_anchor_ts(),
            cert.global_receipt_root(),
            cert.tx_outcomes().clone(),
            Bls12381G2Signature([0xFF; 96]),
            cert.signers().clone(),
        );

        let ctx = ExecutionCertificateContext {
            network: &net,
            public_keys: &pks,
        };
        assert_eq!(
            tampered.verify(&ctx),
            Err(ExecutionCertificateVerifyError::BadAggregatedSignature)
        );
    }

    /// A certificate with an empty signer set but a non-zero aggregated
    /// signature is ill-formed and rejected before the BLS check runs.
    #[test]
    fn verify_rejects_empty_signers_with_nonzero_signature() {
        let net = NetworkDefinition::simulator();
        let pks: Vec<Bls12381G1PublicKey> = (0..4)
            .map(|_| generate_bls_keypair().public_key())
            .collect();

        let outcomes = vec![outcome(1)];
        let root = compute_global_receipt_root(&outcomes);
        let cert = ExecutionCertificate::new(
            wave_id(),
            WeightedTimestamp::from_millis(11),
            root,
            outcomes,
            Bls12381G2Signature([0xAA; 96]),
            SignerBitfield::new(4),
        );

        let ctx = ExecutionCertificateContext {
            network: &net,
            public_keys: &pks,
        };
        assert_eq!(
            cert.verify(&ctx),
            Err(ExecutionCertificateVerifyError::EmptySignersWithNonZeroSignature)
        );
    }

    /// A certificate with an empty signer set and the zero signature is
    /// well-formed (this is the "no validators voted" shape) and
    /// verifies.
    #[test]
    fn verify_accepts_empty_signers_with_zero_signature() {
        let net = NetworkDefinition::simulator();
        let pks: Vec<Bls12381G1PublicKey> = (0..4)
            .map(|_| generate_bls_keypair().public_key())
            .collect();

        let outcomes = vec![outcome(1)];
        let root = compute_global_receipt_root(&outcomes);
        let cert = ExecutionCertificate::new(
            wave_id(),
            WeightedTimestamp::from_millis(11),
            root,
            outcomes,
            zero_bls_signature(),
            SignerBitfield::new(4),
        );

        let ctx = ExecutionCertificateContext {
            network: &net,
            public_keys: &pks,
        };
        cert.verify(&ctx)
            .expect("empty signers + zero signature must verify");
    }

    /// Aggregation maps each voter to their committee index in the
    /// signer bitfield; non-voters' bits stay clear. Catches bitfield
    /// off-by-one regressions in `Verified::<EC>::aggregate`.
    #[test]
    fn aggregate_produces_signer_bitfield_in_committee_order() {
        let net = NetworkDefinition::simulator();
        let committee: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let sk1 = generate_bls_keypair();
        let sk3 = generate_bls_keypair();
        let outcomes = vec![outcome(1)];
        let root = compute_global_receipt_root(&outcomes);

        let votes = vec![
            signed_vote(&net, &sk1, 1, outcomes.clone()),
            signed_vote(&net, &sk3, 3, outcomes.clone()),
        ];

        let cert =
            Verified::<ExecutionCertificate>::aggregate(&wave_id(), root, &votes, &committee)
                .into_inner();
        assert!(cert.signers().is_set(1));
        assert!(cert.signers().is_set(3));
        assert!(!cert.signers().is_set(0));
        assert!(!cert.signers().is_set(2));
        assert_eq!(cert.tx_outcomes(), &outcomes);
    }

    /// Duplicate votes from the same validator collapse to a single
    /// signer bit and a single signature contribution.
    #[test]
    fn aggregate_dedups_votes_from_same_validator() {
        let net = NetworkDefinition::simulator();
        let committee = vec![ValidatorId::new(0), ValidatorId::new(1)];
        let sk0 = generate_bls_keypair();
        let outcomes = vec![outcome(1)];
        let root = compute_global_receipt_root(&outcomes);

        let votes = vec![
            signed_vote(&net, &sk0, 0, outcomes.clone()),
            signed_vote(&net, &sk0, 0, outcomes),
        ];

        let cert =
            Verified::<ExecutionCertificate>::aggregate(&wave_id(), root, &votes, &committee)
                .into_inner();
        assert!(cert.signers().is_set(0));
        assert!(!cert.signers().is_set(1));
        assert_eq!(cert.signers().count_ones(), 1);
    }

    /// An EC verified against a public-key slice that doesn't match the
    /// signing committee fails the BLS check.
    #[test]
    fn verify_rejects_wrong_public_keys() {
        let net = NetworkDefinition::simulator();
        let committee = vec![ValidatorId::new(0), ValidatorId::new(1)];
        let sk0 = generate_bls_keypair();
        let sk1 = generate_bls_keypair();
        let outcomes = vec![outcome(1)];
        let root = compute_global_receipt_root(&outcomes);

        let votes = vec![
            signed_vote(&net, &sk0, 0, outcomes.clone()),
            signed_vote(&net, &sk1, 1, outcomes),
        ];
        let cert =
            Verified::<ExecutionCertificate>::aggregate(&wave_id(), root, &votes, &committee)
                .into_inner();

        let wrong_pks: Vec<Bls12381G1PublicKey> = (0..2)
            .map(|_| generate_bls_keypair().public_key())
            .collect();
        let ctx = ExecutionCertificateContext {
            network: &net,
            public_keys: &wrong_pks,
        };
        assert_eq!(
            cert.verify(&ctx),
            Err(ExecutionCertificateVerifyError::BadAggregatedSignature)
        );
    }
}
