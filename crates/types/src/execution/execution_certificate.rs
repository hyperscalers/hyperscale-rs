//! [`ExecutionCertificate`] — aggregated 2f+1 signature over a tick's
//! per-tx outcomes.
//!
//! [`ExecutionCertificate`] is the raw wire form. Its verified form is
//! `Verified<ExecutionCertificate>`; predicate at
//! [`impl Verify<&ExecutionCertificateContext<'_>>`](Verify::verify) below.

use std::collections::{HashMap, HashSet};
use std::fmt::{self, Debug, Formatter};

use hyperscale_crypto::{ConsensusSignature, Verifier};
use hyperscale_hbor::error::{DecodeError as HborDecodeError, EncodeError as HborEncodeError};
use hyperscale_hbor::{
    Decoder as HborDecoder, Encoder as HborEncoder, HborDecode, HborEncode, HborWidth, Sink,
    bounded as hbor_bounded, to_vec as hbor_to_vec, varint,
};
use thiserror::Error;

use crate::{
    AggregateSignature, BlockHeight, ConsensusPublicKey, ExecutionOutcome, ExecutionVote,
    ExecutionVoteMessage, GlobalReceiptRoot, Hash, MAX_TXS_PER_BLOCK, NetworkDefinition,
    RETENTION_HORIZON, ShardId, SignerBitfield, TickId, TransactionDecision, TxHash, TxOutcome,
    ValidatorId, Verified, Verify, WeightedTimestamp, compute_global_receipt_root,
    compute_sparse_proof, signed_bytes, tx_outcome_leaf, verify_sparse_inclusion,
};

/// Domain tag separating a certificate's attested digest from every
/// other preimage the codebase hashes.
const CERTIFICATE_DIGEST_TAG: &[u8] = b"hyperscale.execution_certificate.attested.v1";

/// What a certificate says of one transaction, as a counterpart hears
/// it.
///
/// Neither is evidence the chain keeps. A refusal is the counterpart's
/// verdict, which the mempool reports; what licenses taking the
/// crossing back is the claim cell the refusing core never wrote,
/// proved absent past the deadline. A claiming success is a cue: it
/// says the counterpart's execution went through, not that it wrote the
/// claim the success promises — its own finalization can still be
/// refused afterwards — so what the retirement stands on is the claim
/// cell proved present, and the certificate only opens the question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spoken {
    /// The counterpart refused it: a rejection or an abort.
    Refused(TransactionDecision),
    /// The counterpart's execution claimed, in a role that claims.
    Claimed {
        /// The vote anchor the certificate speaks at.
        at: WeightedTimestamp,
    },
}

/// Aggregated certificate for an execution tick.
///
/// Contains the signature aggregated signature from 2f+1 validators plus per-tx
/// outcomes so remote shards can extract individual transaction results.
///
/// # Copies carry what their holder is party to
///
/// The signed value is `global_receipt_root`, a merkle root over the whole
/// tick's outcome leaves, so a copy can carry any subset of them and still
/// prove itself: the leaves it holds plus [`Self::proof`] rebuild the
/// signed root. The producing shard is party to its entire tick, so its
/// own copy carries every leaf and needs no proof; a copy sent to a
/// participating shard carries the outcomes naming that shard, and its
/// size follows that shard's stake in the tick rather than the tick's.
///
/// One rule covers both: `tx_count` is the tick's leaf count whatever the
/// copy holds, and decoding rebuilds the root from the carried leaves at
/// their stated indices. A complete copy is the case where those are all
/// of them and the proof is empty, which is why it needs no marker.
pub struct ExecutionCertificate {
    tick_id: TickId,
    vote_anchor_ts: WeightedTimestamp,
    global_receipt_root: GlobalReceiptRoot,
    /// Leaf count of the receipt tree — the whole tick's outcome count,
    /// not this copy's. Signed, so a copy cannot restate the tree it is
    /// proving against.
    tx_count: u32,
    /// Receipt-tree leaf index of each carried outcome, ascending and
    /// distinct. Parallel to `tx_outcomes`.
    leaf_indices: Vec<u32>,
    tx_outcomes: Vec<TxOutcome>,
    /// Sibling nodes covering the leaves this copy does not carry. Empty
    /// on a complete copy.
    proof: Vec<Hash>,
    aggregated_signature: AggregateSignature,
    signers: SignerBitfield,
    /// Cached HBOR-encoded bytes. Populated at construction or after
    /// deserialization to avoid re-serialization on storage writes.
    cached_bytes: Option<Vec<u8>>,
}

impl Debug for ExecutionCertificate {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutionCertificate")
            .field("tick_id", &self.tick_id)
            .field("vote_anchor_ts", &self.vote_anchor_ts)
            .field("global_receipt_root", &self.global_receipt_root)
            .field("tx_count", &self.tx_count)
            .field("leaf_indices", &self.leaf_indices)
            .field("tx_outcomes", &self.tx_outcomes)
            .field("proof", &self.proof.len())
            .field("aggregated_signature", &self.aggregated_signature)
            .field("signers", &self.signers)
            .finish_non_exhaustive()
    }
}

impl Clone for ExecutionCertificate {
    fn clone(&self) -> Self {
        Self {
            tick_id: self.tick_id,
            vote_anchor_ts: self.vote_anchor_ts,
            global_receipt_root: self.global_receipt_root,
            tx_count: self.tx_count,
            leaf_indices: self.leaf_indices.clone(),
            tx_outcomes: self.tx_outcomes.clone(),
            proof: self.proof.clone(),
            aggregated_signature: self.aggregated_signature,
            signers: self.signers.clone(),
            cached_bytes: self.cached_bytes.clone(),
        }
    }
}

impl PartialEq for ExecutionCertificate {
    fn eq(&self, other: &Self) -> bool {
        self.tick_id == other.tick_id
            && self.vote_anchor_ts == other.vote_anchor_ts
            && self.global_receipt_root == other.global_receipt_root
            && self.tx_count == other.tx_count
            && self.leaf_indices == other.leaf_indices
            && self.tx_outcomes == other.tx_outcomes
            && self.proof == other.proof
            && self.aggregated_signature == other.aggregated_signature
            && self.signers == other.signers
    }
}

impl Eq for ExecutionCertificate {}

// Manual codec: cached_bytes is derived, not serialized.
//
// The decode side rebuilds the receipt root from the leaves this copy
// carries, at their stated indices, plus the proof. The signature
// aggregate only commits to (global_receipt_root, tx_count), not to
// tx_outcomes content; without this check a Byzantine aggregator could
// ship a signature-valid EC whose outcomes don't belong under the signed
// root, slipping bogus per-tx results past every downstream consumer
// (gossip ingress, fetch ingress, Finalization admission).
//
// A complete copy carries no index list: its leaves are `0..tx_count` by
// definition, which the two cases can never confuse because a partial
// copy holds strictly fewer. Padding is derived on both sides, so a
// complete copy also carries no proof — its wire form is today's plus the
// leaf count.

impl HborWidth for ExecutionCertificate {
    const MIN_ENCODED_LEN: usize = 1;
}

/// Encode ascending leaf indices as gaps: the first index, then each
/// subsequent one less its predecessor and the step between them, so a
/// run of consecutive leaves costs one byte apiece.
fn encode_leaf_indices(indices: &[u32]) -> Result<Vec<u8>, HborEncodeError> {
    let mut bytes = Vec::with_capacity(indices.len());
    let mut previous: Option<u32> = None;
    for &index in indices {
        let gap = previous.map_or(index, |prior| index.saturating_sub(prior).saturating_sub(1));
        varint::write(&mut bytes, gap as usize)?;
        previous = Some(index);
    }
    Ok(bytes)
}

/// Inverse of [`encode_leaf_indices`]. Requires the blob to hold exactly
/// `count` gaps and to be consumed exactly, so one index set has one
/// encoding.
fn decode_leaf_indices(mut bytes: &[u8], count: usize) -> Result<Vec<u32>, HborDecodeError> {
    let mut indices = Vec::with_capacity(count);
    let mut previous: Option<u32> = None;
    for _ in 0..count {
        let (gap, consumed) = varint::read(bytes)?;
        bytes = &bytes[consumed..];
        let gap = u32::try_from(gap)
            .map_err(|_| HborDecodeError::FailedValidation("leaf index gap out of range"))?;
        let index = match previous {
            None => gap,
            Some(prior) => prior
                .checked_add(gap)
                .and_then(|sum| sum.checked_add(1))
                .ok_or(HborDecodeError::FailedValidation("leaf index out of range"))?,
        };
        indices.push(index);
        previous = Some(index);
    }
    if bytes.is_empty() {
        Ok(indices)
    } else {
        Err(HborDecodeError::FailedValidation(
            "trailing bytes after the leaf index list",
        ))
    }
}

impl HborEncode for ExecutionCertificate {
    fn encode<S: Sink>(&self, encoder: &mut HborEncoder<S>) -> Result<(), HborEncodeError> {
        encoder.nested(&self.tick_id)?;
        encoder.nested(&self.vote_anchor_ts)?;
        encoder.nested(&self.global_receipt_root)?;
        encoder.nested(&self.tx_count)?;
        hbor_bounded::check_encoded_len("tx_outcomes", self.tx_outcomes.len(), MAX_TXS_PER_BLOCK)?;
        encoder.nested(&self.tx_outcomes)?;
        if self.is_complete() {
            encoder.write_sized(&[])?;
        } else {
            encoder.write_sized(&encode_leaf_indices(&self.leaf_indices)?)?;
        }
        hbor_bounded::check_encoded_len("proof", self.proof.len(), MAX_TXS_PER_BLOCK)?;
        encoder.nested(&self.proof)?;
        encoder.nested(&self.aggregated_signature)?;
        encoder.nested(&self.signers)
    }
}

impl HborDecode for ExecutionCertificate {
    fn decode(decoder: &mut HborDecoder<'_>) -> Result<Self, HborDecodeError> {
        let tick_id: TickId = decoder.nested()?;
        let vote_anchor_ts: WeightedTimestamp = decoder.nested()?;
        let global_receipt_root: GlobalReceiptRoot = decoder.nested()?;
        let tx_count: u32 = decoder.nested()?;
        let tx_outcomes: Vec<TxOutcome> = decoder
            .descend(|decoder| hbor_bounded::decode_bounded_vec(decoder, MAX_TXS_PER_BLOCK))?;
        let index_len = decoder.read_len(1)?;
        let index_bytes = decoder.read_slice(index_len)?;
        let proof: Vec<Hash> = decoder
            .descend(|decoder| hbor_bounded::decode_bounded_vec(decoder, MAX_TXS_PER_BLOCK))?;
        let aggregated_signature: AggregateSignature = decoder.nested()?;
        let signers: SignerBitfield = decoder.nested()?;

        if tx_count as usize > MAX_TXS_PER_BLOCK {
            return Err(HborDecodeError::FailedValidation(
                "tx count exceeds the per-block cap",
            ));
        }
        let complete = tx_outcomes.len() == tx_count as usize;
        let leaf_indices = if complete {
            if !index_bytes.is_empty() {
                return Err(HborDecodeError::FailedValidation(
                    "a complete certificate carries no leaf index list",
                ));
            }
            (0..tx_count).collect()
        } else {
            decode_leaf_indices(index_bytes, tx_outcomes.len())?
        };

        let claimed: Vec<(u32, Hash)> = leaf_indices
            .iter()
            .copied()
            .zip(tx_outcomes.iter().map(tx_outcome_leaf))
            .collect();
        if !verify_sparse_inclusion(
            global_receipt_root.into_raw(),
            &claimed,
            tx_count as usize,
            &proof,
        ) {
            return Err(HborDecodeError::FailedValidation(
                "tx outcomes do not prove against the signed receipt root",
            ));
        }

        let mut ec = Self {
            tick_id,
            vote_anchor_ts,
            global_receipt_root,
            tx_count,
            leaf_indices,
            tx_outcomes,
            proof,
            aggregated_signature,
            signers,
            cached_bytes: None,
        };
        ec.populate_cached_bytes();
        Ok(ec)
    }
}

impl ExecutionCertificate {
    /// Create a new execution certificate.
    #[must_use]
    pub fn new(
        tick_id: TickId,
        vote_anchor_ts: WeightedTimestamp,
        global_receipt_root: GlobalReceiptRoot,
        tx_outcomes: Vec<TxOutcome>,
        aggregated_signature: AggregateSignature,
        signers: SignerBitfield,
    ) -> Self {
        let tx_count = u32::try_from(tx_outcomes.len()).unwrap_or(u32::MAX);
        let mut ec = Self {
            tick_id,
            vote_anchor_ts,
            global_receipt_root,
            tx_count,
            leaf_indices: (0..tx_count).collect(),
            tx_outcomes,
            proof: Vec::new(),
            aggregated_signature,
            signers,
            cached_bytes: None,
        };
        ec.populate_cached_bytes();
        ec
    }

    /// The copy of this certificate a shard party to `keep` needs: the
    /// outcomes naming those transactions, plus a proof binding them to
    /// the same signed root.
    ///
    /// Neither the signed root nor the signature moves, so the projection
    /// verifies under the same committee as the certificate it came from
    /// — which is what lets a recipient be sent its own stake in a tick
    /// rather than the whole of it.
    ///
    /// Returns `None` when this copy carries no outcome for any named
    /// transaction: a certificate proving nothing about the recipient's
    /// transactions is not worth sending, and an empty claim does not
    /// verify.
    ///
    /// # Panics
    ///
    /// Panics on a copy that is not itself complete. Building the proof
    /// reads sibling nodes off the whole receipt tree, which only the
    /// producing shard's copy carries.
    #[must_use]
    pub fn project_to(&self, keep: &HashSet<TxHash>) -> Option<Self> {
        assert!(
            self.is_complete(),
            "only a complete certificate can be projected"
        );
        let (leaf_indices, tx_outcomes): (Vec<u32>, Vec<TxOutcome>) = self
            .leaf_indices
            .iter()
            .zip(self.tx_outcomes.iter())
            .filter(|(_, outcome)| keep.contains(&outcome.tx_hash()))
            .map(|(&index, outcome)| (index, outcome.clone()))
            .unzip();
        if tx_outcomes.is_empty() {
            return None;
        }

        let leaves: Vec<Hash> = self.tx_outcomes.iter().map(tx_outcome_leaf).collect();
        let proof = compute_sparse_proof(&leaves, &leaf_indices);
        let mut ec = Self {
            tick_id: self.tick_id,
            vote_anchor_ts: self.vote_anchor_ts,
            global_receipt_root: self.global_receipt_root,
            tx_count: self.tx_count,
            leaf_indices,
            tx_outcomes,
            proof,
            aggregated_signature: self.aggregated_signature,
            signers: self.signers.clone(),
            cached_bytes: None,
        };
        ec.populate_cached_bytes();
        Some(ec)
    }

    /// Number of outcomes in the whole tick, however many this copy
    /// carries. The receipt tree's leaf count.
    #[must_use]
    pub const fn tx_count(&self) -> u32 {
        self.tx_count
    }

    /// Whether this copy carries every outcome of its tick.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.tx_outcomes.len() == self.tx_count as usize
    }

    /// Receipt-tree leaf index of each carried outcome, parallel to
    /// [`Self::tx_outcomes`].
    #[must_use]
    pub fn leaf_indices(&self) -> &[u32] {
        &self.leaf_indices
    }

    /// Whether this copy carries an outcome for `tx_hash`. A transaction
    /// of the tick this copy leaves out answers `false` — the certificate
    /// says nothing about it.
    #[must_use]
    pub fn covers(&self, tx_hash: &TxHash) -> bool {
        self.tx_outcomes
            .iter()
            .any(|outcome| &outcome.tx_hash() == tx_hash)
    }

    /// Self-contained tick identifier (shard + height + remote dependencies).
    #[must_use]
    pub const fn tick_id(&self) -> &TickId {
        &self.tick_id
    }

    /// Consensus height at which quorum was reached.
    ///
    /// Must match the `vote_anchor_ts` in the aggregated votes. Needed to
    /// reconstruct the signing message for signature verification.
    #[must_use]
    pub const fn vote_anchor_ts(&self) -> WeightedTimestamp {
        self.vote_anchor_ts
    }

    /// Merkle root over per-tx outcome leaves.
    #[must_use]
    pub const fn global_receipt_root(&self) -> GlobalReceiptRoot {
        self.global_receipt_root
    }

    /// Per-transaction outcomes (in tick order = block order).
    #[must_use]
    pub const fn tx_outcomes(&self) -> &Vec<TxOutcome> {
        &self.tx_outcomes
    }

    /// What this certificate says of each transaction, as a counterpart
    /// hears it.
    ///
    /// A success speaks only in a role that claims. A leg's success is
    /// its own side going through, which says nothing about the crossings
    /// it consumed — and an issuer that heard it as an acceptance would
    /// take it for the claim its record is held for. A refusal speaks
    /// whatever the role, since a member that could not do its part ends
    /// the transaction on its shard.
    pub fn verdicts(&self) -> impl Iterator<Item = (TxHash, Spoken)> + '_ {
        let at = self.vote_anchor_ts;
        self.tx_outcomes.iter().filter_map(move |outcome| {
            let spoken = match outcome.outcome() {
                ExecutionOutcome::Succeeded { .. } => outcome
                    .role()
                    .success_claims()
                    .then_some(Spoken::Claimed { at })?,
                ExecutionOutcome::Failed => Spoken::Refused(TransactionDecision::Reject),
                ExecutionOutcome::Aborted => Spoken::Refused(TransactionDecision::Aborted),
            };
            Some((outcome.tx_hash(), spoken))
        })
    }

    /// signature aggregated signature from 2f+1 validators.
    #[must_use]
    pub const fn aggregated_signature(&self) -> AggregateSignature {
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
        self.tick_id.shard_id()
    }

    /// Deadline past which this certificate is provably useless on every shard.
    ///
    /// Anchored on `vote_anchor_ts` — the tick's BFT-authenticated commit
    /// timestamp. Past `vote_anchor_ts + RETENTION_HORIZON` every tx in the
    /// tick has expired its `validity_range` and terminated (success or
    /// abort), so no shard can still reference this EC.
    #[must_use]
    pub fn deadline(&self) -> WeightedTimestamp {
        self.vote_anchor_ts.plus(RETENTION_HORIZON)
    }

    /// Block height (the block containing the tick's transactions).
    #[must_use]
    pub const fn block_height(&self) -> BlockHeight {
        self.tick_id.block_height()
    }

    /// Pre-serialized wire bytes, if available.
    #[must_use]
    pub fn cached_wire_bytes(&self) -> Option<&[u8]> {
        self.cached_bytes.as_deref()
    }

    /// Content hash over the full wire encoding (including
    /// `aggregated_signature` and `signers`). Distinguishes byte-identical
    /// retransmits — useful as an in-flight dedup key — while still treating
    /// different aggregations of the same logical EC as distinct, so a peer
    /// supplying a valid aggregation after a bad one isn't dropped.
    ///
    /// # Panics
    ///
    /// Panics if HBOR encoding fails — closed type, infallible in practice.
    #[must_use]
    pub fn wire_hash(&self) -> Hash {
        self.cached_bytes.as_deref().map_or_else(
            || {
                let bytes = hbor_to_vec(self).expect("EC HBOR encoding must succeed");
                Hash::from_parts(&[&bytes])
            },
            |bytes| Hash::from_parts(&[bytes]),
        )
    }

    /// Digest over what the committee signed, and nothing a copy varies.
    ///
    /// [`Self::wire_hash`] deliberately separates different aggregations
    /// and different projections of one logical certificate, which makes
    /// it the wrong name for a fact two shards have to agree on: a copy
    /// carries only the outcomes naming its receiver, and two assemblers
    /// may aggregate different quorums of the same votes. What survives
    /// both is the signed identity — the tick, the anchor the votes were
    /// cast at, the receipt root they attest and the leaf count that root
    /// covers — so that is what a claim to a counterpart's verdict names.
    #[must_use]
    pub fn attested_digest(&self) -> Hash {
        Hash::from_parts(&[
            CERTIFICATE_DIGEST_TAG,
            &self.tick_id.shard_id().to_le_bytes(),
            &self.tick_id.block_height().inner().to_le_bytes(),
            &self.vote_anchor_ts.as_millis().to_le_bytes(),
            self.global_receipt_root.as_raw().as_bytes(),
            &self.tx_count.to_le_bytes(),
        ])
    }

    fn populate_cached_bytes(&mut self) {
        self.cached_bytes = Some(hbor_to_vec(self).expect("EC HBOR encoding must succeed"));
    }

    /// Build the canonical signing message used by every constituent vote
    /// (and the aggregated certificate).
    ///
    /// Same message as [`ExecutionVote::signing_message`]; reconstructed
    /// from the EC's own fields so verifiers don't need a vote sample.
    #[must_use]
    pub fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        signed_bytes(
            &ExecutionVoteMessage {
                vote_anchor_ts: self.vote_anchor_ts,
                tick_id: self.tick_id,
                shard_group: self.shard_id(),
                global_receipt_root: self.global_receipt_root,
                tx_count: self.tx_count,
            },
            network,
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
    pub public_keys: &'a [ConsensusPublicKey],
    /// Scheme verifier the aggregate check runs through.
    pub verifier: &'a dyn Verifier,
}

/// Failure modes of [`ExecutionCertificate`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ExecutionCertificateVerifyError {
    /// `signers` bitfield is empty but `aggregated_signature` is not the
    /// zero signature. An empty signer set must be paired with the zero
    /// signature; any other pairing is ill-formed.
    #[error("empty signer set paired with non-zero aggregated signature")]
    EmptySignersWithNonZeroSignature,
    /// The aggregated signature did not validate against the
    /// aggregated public key derived from `signers` over the canonical
    /// signing message. Also covers public-key aggregation failures.
    #[error("aggregated signature invalid")]
    BadAggregatedSignature,
}

/// Construction asserts: the aggregated signature validates against
/// the public key formed by aggregating `public_keys[i]` for every `i`
/// set in `signers`, over the canonical [`ExecutionVoteMessage`] derived
/// from the certificate's `(vote_anchor_ts, tick_id, shard_id,
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
        let signer_keys: Vec<ConsensusPublicKey> = ctx
            .public_keys
            .iter()
            .enumerate()
            .filter(|(i, _)| self.signers.is_set(*i))
            .map(|(_, pk)| *pk)
            .collect();

        if signer_keys.is_empty() {
            if self.aggregated_signature == AggregateSignature::ZERO {
                return Ok(Verified::new_unchecked(self.clone()));
            }
            return Err(ExecutionCertificateVerifyError::EmptySignersWithNonZeroSignature);
        }

        let message = self.signing_message(ctx.network);
        if !ctx.verifier.verify_aggregate_same_message(
            &message,
            &self.aggregated_signature,
            &signer_keys,
        ) {
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
    /// vote_anchor_ts)` plus the per-tick `tick_id` and `shard_id`
    /// uniquely determine that message, so a single bucket's contents
    /// satisfy this contract by construction.
    ///
    /// Validators not in `committee` contribute their signature to the
    /// aggregate but no bit to `signers`; the resulting EC would fail
    /// verify. The caller filters non-committee voters upstream.
    ///
    /// # Panics
    ///
    /// Panics if `votes` is empty, or if signature aggregation of the
    /// individually-verified signatures fails — both indicate an
    /// upstream invariant violation (predicate bypass, sub-quorum
    /// input, or scheme library bug).
    #[must_use]
    pub fn aggregate(
        verifier: &dyn Verifier,
        tick_id: &TickId,
        global_receipt_root: GlobalReceiptRoot,
        votes: &[Verified<ExecutionVote>],
        committee: &[ValidatorId],
    ) -> Self {
        let tx_outcomes = votes
            .iter()
            .find(|v| compute_global_receipt_root(v.tx_outcomes()) == global_receipt_root)
            .map(|v| v.tx_outcomes().to_vec())
            .expect("verified votes guarantee at least one with matching outcomes");

        let committee_index: HashMap<ValidatorId, usize> = committee
            .iter()
            .enumerate()
            .map(|(idx, &vid)| (vid, idx))
            .collect();

        let mut seen_validators: HashSet<ValidatorId> = HashSet::new();
        let mut unique_votes: Vec<&Verified<ExecutionVote>> = votes
            .iter()
            .filter(|vote| seen_validators.insert(vote.validator()))
            .collect();
        // Fold in bitfield (committee-position) order — the verifier
        // recomputes the aggregate in set-bit order, and order-sensitive
        // schemes require the fold to match.
        unique_votes.sort_by_key(|vote| {
            committee_index
                .get(&vote.validator())
                .copied()
                .unwrap_or(usize::MAX)
        });

        let signatures: Vec<ConsensusSignature> =
            unique_votes.iter().map(|vote| vote.signature()).collect();
        let aggregated_signature = if signatures.is_empty() {
            AggregateSignature::ZERO
        } else {
            verifier
                .aggregate(&signatures)
                .expect("aggregation of upstream-verified signatures cannot fail")
        };
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
        // message determined by `(vote_anchor_ts, tick_id,
        // shard_id, global_receipt_root, tx_count)`. Aggregating
        // those signatures and mirroring the committee indices in
        // `signers` produces an EC whose predicate is structurally
        // equivalent: the aggregated pubkey at verify time recombines
        // the same per-validator pubkeys, and signature aggregate-verify
        // succeeds.
        Self::new_unchecked(ExecutionCertificate::new(
            *tick_id,
            vote_anchor_ts,
            global_receipt_root,
            tx_outcomes,
            aggregated_signature,
            signers,
        ))
    }

    /// The projection of this certificate a shard party to `keep`
    /// needs, carrying the verification marker through.
    ///
    /// Trust source: [`ExecutionCertificate::project_to`] moves neither
    /// the signed root nor the aggregated signature nor the signer set,
    /// so the predicate that held for the certificate it came from holds
    /// unchanged for the projection.
    ///
    /// # Panics
    ///
    /// Panics on a certificate that is not itself complete; see
    /// [`ExecutionCertificate::project_to`].
    #[must_use]
    pub fn project_to(&self, keep: &HashSet<TxHash>) -> Option<Self> {
        // SAFETY: the projection carries the same `(vote_anchor_ts,
        // tick_id, shard_id, global_receipt_root, tx_count)` signing
        // message and the same aggregate, so aggregate-verify against
        // the same committee succeeds exactly as it did before.
        (**self).project_to(keep).map(Self::new_unchecked)
    }

    /// Re-wrap a certificate that satisfied the predicate at write
    /// time. ECs ride into storage embedded inside `Verified<Finalization>`
    /// values inside the `Verified<CertifiedBlock>` argument to the
    /// prepared commit, so unverified ECs can't reach the write path.
    /// Storage rehydration paths use this gate to avoid re-running
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
    use hyperscale_crypto::Signer;
    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};
    use hyperscale_hbor::from_slice as hbor_from_slice;

    use super::*;
    use crate::{BlockHash, BlockHeight, ExecutionOutcome, GlobalReceiptHash, Role, TxHash};

    fn outcome(seed: u8) -> TxOutcome {
        TxOutcome::new(
            TxHash::from(Hash::from_bytes(&[seed; 4])),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(&[b'r', seed])),
            },
        )
    }

    fn tick_id() -> TickId {
        TickId::new(ShardId::leaf(1, 0), BlockHeight::new(7))
    }

    /// Build a signed vote with the given signing key. Used for fixture
    /// construction; the resulting `Verified<ExecutionVote>` would also
    /// satisfy `<ExecutionVote as Verify>::verify` against `sk.public_key()`.
    fn signed_vote(
        net: &NetworkDefinition,
        sk: &BlsSigner,
        validator: u64,
        outcomes: Vec<TxOutcome>,
    ) -> Verified<ExecutionVote> {
        Verified::<ExecutionVote>::sign_local(
            net,
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            BlockHeight::new(7),
            WeightedTimestamp::from_millis(11),
            tick_id(),
            ShardId::leaf(1, 0),
            outcomes,
            ValidatorId::new(validator),
            sk,
        )
        .expect("sign")
    }

    /// Aggregate produces an EC whose predicate verifies against the
    /// matching committee public keys — the canonical sign-then-verify
    /// round trip across the typed gates.
    #[test]
    fn aggregate_roundtrips_through_verify() {
        let net = NetworkDefinition::simulator();
        let committee: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let sks: Vec<BlsSigner> = (0..4).map(|_| BlsSigner::generate()).collect();
        let pks: Vec<ConsensusPublicKey> = sks.iter().map(BlsSigner::public_key).collect();
        let outcomes = vec![outcome(1), outcome(2)];
        let root = compute_global_receipt_root(&outcomes);

        let votes: Vec<Verified<ExecutionVote>> = (0..4)
            .map(|i| signed_vote(&net, &sks[usize::try_from(i).unwrap()], i, outcomes.clone()))
            .collect();

        let cert = Verified::<ExecutionCertificate>::aggregate(
            &BlsVerifier,
            &tick_id(),
            root,
            &votes,
            &committee,
        );

        let ctx = ExecutionCertificateContext {
            verifier: &BlsVerifier,
            network: &net,
            public_keys: &pks,
        };
        let raw = cert.into_inner();
        raw.verify(&ctx)
            .expect("aggregate output must satisfy its own predicate");
    }

    /// A certificate whose `aggregated_signature` was tampered with
    /// fails the signature check; the verifier returns `BadAggregatedSignature`.
    #[test]
    fn verify_rejects_bad_aggregated_signature() {
        let net = NetworkDefinition::simulator();
        let committee: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let sks: Vec<BlsSigner> = (0..4).map(|_| BlsSigner::generate()).collect();
        let pks: Vec<ConsensusPublicKey> = sks.iter().map(BlsSigner::public_key).collect();
        let outcomes = vec![outcome(1)];
        let root = compute_global_receipt_root(&outcomes);

        let votes: Vec<Verified<ExecutionVote>> = (0..4)
            .map(|i| signed_vote(&net, &sks[usize::try_from(i).unwrap()], i, outcomes.clone()))
            .collect();
        let cert = Verified::<ExecutionCertificate>::aggregate(
            &BlsVerifier,
            &tick_id(),
            root,
            &votes,
            &committee,
        )
        .into_inner();

        let tampered = ExecutionCertificate::new(
            *cert.tick_id(),
            cert.vote_anchor_ts(),
            cert.global_receipt_root(),
            cert.tx_outcomes().clone(),
            AggregateSignature::new([0xFF; 96]),
            cert.signers().clone(),
        );

        let ctx = ExecutionCertificateContext {
            verifier: &BlsVerifier,
            network: &net,
            public_keys: &pks,
        };
        assert_eq!(
            tampered.verify(&ctx),
            Err(ExecutionCertificateVerifyError::BadAggregatedSignature)
        );
    }

    /// A certificate with an empty signer set but a non-zero aggregated
    /// signature is ill-formed and rejected before the signature check runs.
    #[test]
    fn verify_rejects_empty_signers_with_nonzero_signature() {
        let net = NetworkDefinition::simulator();
        let pks: Vec<ConsensusPublicKey> =
            (0..4).map(|_| BlsSigner::generate().public_key()).collect();

        let outcomes = vec![outcome(1)];
        let root = compute_global_receipt_root(&outcomes);
        let cert = ExecutionCertificate::new(
            tick_id(),
            WeightedTimestamp::from_millis(11),
            root,
            outcomes,
            AggregateSignature::new([0xAA; 96]),
            SignerBitfield::new(4),
        );

        let ctx = ExecutionCertificateContext {
            verifier: &BlsVerifier,
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
        let pks: Vec<ConsensusPublicKey> =
            (0..4).map(|_| BlsSigner::generate().public_key()).collect();

        let outcomes = vec![outcome(1)];
        let root = compute_global_receipt_root(&outcomes);
        let cert = ExecutionCertificate::new(
            tick_id(),
            WeightedTimestamp::from_millis(11),
            root,
            outcomes,
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        );

        let ctx = ExecutionCertificateContext {
            verifier: &BlsVerifier,
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
        let sk1 = BlsSigner::generate();
        let sk3 = BlsSigner::generate();
        let outcomes = vec![outcome(1)];
        let root = compute_global_receipt_root(&outcomes);

        let votes = vec![
            signed_vote(&net, &sk1, 1, outcomes.clone()),
            signed_vote(&net, &sk3, 3, outcomes.clone()),
        ];

        let cert = Verified::<ExecutionCertificate>::aggregate(
            &BlsVerifier,
            &tick_id(),
            root,
            &votes,
            &committee,
        )
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
        let sk0 = BlsSigner::generate();
        let outcomes = vec![outcome(1)];
        let root = compute_global_receipt_root(&outcomes);

        let votes = vec![
            signed_vote(&net, &sk0, 0, outcomes.clone()),
            signed_vote(&net, &sk0, 0, outcomes),
        ];

        let cert = Verified::<ExecutionCertificate>::aggregate(
            &BlsVerifier,
            &tick_id(),
            root,
            &votes,
            &committee,
        )
        .into_inner();
        assert!(cert.signers().is_set(0));
        assert!(!cert.signers().is_set(1));
        assert_eq!(cert.signers().count_ones(), 1);
    }

    /// An EC whose outcomes' `work` was mutated after the root was
    /// fixed fails the decode-side receipt-root recompute — the leaf
    /// covers work, so an aggregator cannot ship a signature-valid EC
    /// with forged work.
    #[test]
    fn decode_rejects_tampered_work() {
        let outcomes = vec![TxOutcome::attesting(
            TxHash::from(Hash::from_bytes(b"worked-tx")),
            ExecutionOutcome::Aborted,
            7,
        )];
        let root = compute_global_receipt_root(&outcomes);

        let forged: Vec<TxOutcome> = outcomes
            .iter()
            .map(|o| TxOutcome::attesting(o.tx_hash(), o.outcome().clone(), 999))
            .collect();
        let cert = ExecutionCertificate::new(
            tick_id(),
            WeightedTimestamp::from_millis(11),
            root,
            forged,
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        );

        let bytes = hbor_to_vec(&cert).expect("encode");
        let err = hbor_from_slice::<ExecutionCertificate>(&bytes)
            .expect_err("tampered work must fail the receipt-root recompute");
        assert!(matches!(err, HborDecodeError::FailedValidation(_)));
    }

    /// An EC verified against a public-key slice that doesn't match the
    /// signing committee fails the signature check.
    #[test]
    fn verify_rejects_wrong_public_keys() {
        let net = NetworkDefinition::simulator();
        let committee = vec![ValidatorId::new(0), ValidatorId::new(1)];
        let sk0 = BlsSigner::generate();
        let sk1 = BlsSigner::generate();
        let outcomes = vec![outcome(1)];
        let root = compute_global_receipt_root(&outcomes);

        let votes = vec![
            signed_vote(&net, &sk0, 0, outcomes.clone()),
            signed_vote(&net, &sk1, 1, outcomes),
        ];
        let cert = Verified::<ExecutionCertificate>::aggregate(
            &BlsVerifier,
            &tick_id(),
            root,
            &votes,
            &committee,
        )
        .into_inner();

        let wrong_pks: Vec<ConsensusPublicKey> =
            (0..2).map(|_| BlsSigner::generate().public_key()).collect();
        let ctx = ExecutionCertificateContext {
            verifier: &BlsVerifier,
            network: &net,
            public_keys: &wrong_pks,
        };
        assert_eq!(
            cert.verify(&ctx),
            Err(ExecutionCertificateVerifyError::BadAggregatedSignature)
        );
    }

    /// A complete certificate round-trips and stays complete: its wire
    /// form carries no index list and no proof, which is what keeps the
    /// producing shard's own copy the cheap case.
    #[test]
    fn a_complete_certificate_carries_no_index_list_or_proof() {
        let outcomes = vec![outcome(1), outcome(2), outcome(3)];
        let root = compute_global_receipt_root(&outcomes);
        let cert = ExecutionCertificate::new(
            tick_id(),
            WeightedTimestamp::from_millis(11),
            root,
            outcomes.clone(),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        );
        assert!(cert.is_complete());
        assert!(cert.proof.is_empty());

        let decoded: ExecutionCertificate =
            hbor_from_slice(&hbor_to_vec(&cert).expect("encode")).expect("decode");
        assert_eq!(decoded, cert);
        assert_eq!(decoded.tx_outcomes(), &outcomes);
    }

    /// A projection carries the recipient's outcomes and nothing else,
    /// still proves against the same signed root, and still reports the
    /// whole tick's leaf count.
    #[test]
    fn a_projection_carries_only_the_named_transactions() {
        let outcomes: Vec<TxOutcome> = (1..=8).map(outcome).collect();
        let root = compute_global_receipt_root(&outcomes);
        let cert = ExecutionCertificate::new(
            tick_id(),
            WeightedTimestamp::from_millis(11),
            root,
            outcomes.clone(),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        );

        let keep: HashSet<TxHash> = [outcomes[2].tx_hash(), outcomes[5].tx_hash()]
            .into_iter()
            .collect();
        let projected = cert.project_to(&keep).expect("two outcomes kept");

        assert!(!projected.is_complete());
        assert_eq!(projected.tx_count(), 8);
        assert_eq!(projected.leaf_indices(), &[2, 5]);
        assert_eq!(
            projected.tx_outcomes(),
            &vec![outcomes[2].clone(), outcomes[5].clone()]
        );
        assert_eq!(projected.global_receipt_root(), root);

        let decoded: ExecutionCertificate =
            hbor_from_slice(&hbor_to_vec(&projected).expect("encode")).expect("decode");
        assert_eq!(decoded, projected);
    }

    /// A projection of the whole tick is the complete certificate again —
    /// the two are one shape, not two.
    #[test]
    fn projecting_to_every_transaction_reproduces_the_complete_copy() {
        let outcomes: Vec<TxOutcome> = (1..=5).map(outcome).collect();
        let cert = ExecutionCertificate::new(
            tick_id(),
            WeightedTimestamp::from_millis(11),
            compute_global_receipt_root(&outcomes),
            outcomes.clone(),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        );
        let keep: HashSet<TxHash> = outcomes.iter().map(TxOutcome::tx_hash).collect();
        assert_eq!(cert.project_to(&keep).expect("all kept"), cert);
    }

    /// A success speaks an acceptance only in a role that claims what
    /// crossed to it. A leg's success is its own side going through, and
    /// an issuer that heard it as an acceptance would take it for the
    /// claim its record is held for — which on a shard that is both a
    /// caller and a recipient of one swap is every swap.
    #[test]
    fn only_a_claiming_success_speaks_an_acceptance() {
        let outcomes = vec![
            outcome(1).as_role(Role::Delivery),
            outcome(2).as_role(Role::Leg),
            outcome(3).as_role(Role::Core),
            TxOutcome::new(
                TxHash::from(Hash::from_bytes(&[4u8; 4])),
                ExecutionOutcome::Failed,
            )
            .as_role(Role::Leg),
        ];
        let spoken: Vec<(TxHash, Spoken)> = ExecutionCertificate::new(
            tick_id(),
            WeightedTimestamp::from_millis(11),
            compute_global_receipt_root(&outcomes),
            outcomes.clone(),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        )
        .verdicts()
        .collect();

        assert_eq!(
            spoken
                .iter()
                .map(|(tx_hash, _)| *tx_hash)
                .collect::<Vec<_>>(),
            vec![
                outcomes[0].tx_hash(),
                outcomes[2].tx_hash(),
                outcomes[3].tx_hash()
            ],
            "the leg's success says nothing; its refusal still ends the transaction here",
        );
        assert!(matches!(spoken[0].1, Spoken::Claimed { .. }));
        assert!(matches!(spoken[1].1, Spoken::Claimed { .. }));
        assert!(matches!(
            spoken[2].1,
            Spoken::Refused(TransactionDecision::Reject)
        ));
    }

    /// A recipient party to nothing in the tick gets no certificate: an
    /// empty claim proves nothing and would not verify.
    #[test]
    fn projecting_to_nothing_yields_no_certificate() {
        let outcomes = vec![outcome(1)];
        let cert = ExecutionCertificate::new(
            tick_id(),
            WeightedTimestamp::from_millis(11),
            compute_global_receipt_root(&outcomes),
            outcomes,
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        );
        assert!(cert.project_to(&HashSet::new()).is_none());
    }

    /// A projection is smaller than the certificate it came from once the
    /// tick is bigger than the recipient's share of it — the whole point
    /// of sending one.
    #[test]
    fn a_projection_is_smaller_than_the_tick_it_came_from() {
        let outcomes: Vec<TxOutcome> = (0..64).map(outcome).collect();
        let cert = ExecutionCertificate::new(
            tick_id(),
            WeightedTimestamp::from_millis(11),
            compute_global_receipt_root(&outcomes),
            outcomes.clone(),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        );
        let keep: HashSet<TxHash> = std::iter::once(outcomes[9].tx_hash()).collect();
        let projected = cert.project_to(&keep).expect("one outcome kept");

        let whole = hbor_to_vec(&cert).expect("encode").len();
        let part = hbor_to_vec(&projected).expect("encode").len();
        assert!(
            part * 4 < whole,
            "a single-transaction projection of a 64-transaction tick must be far \
             smaller: {part} against {whole}"
        );
    }

    /// A forged outcome swapped into a projection fails the decode-side
    /// rebuild: the leaf it hashes to does not sit under the signed root.
    #[test]
    fn decode_rejects_a_forged_outcome_in_a_projection() {
        let outcomes: Vec<TxOutcome> = (1..=8).map(outcome).collect();
        let cert = ExecutionCertificate::new(
            tick_id(),
            WeightedTimestamp::from_millis(11),
            compute_global_receipt_root(&outcomes),
            outcomes.clone(),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        );
        let keep: HashSet<TxHash> = std::iter::once(outcomes[2].tx_hash()).collect();
        let mut projected = cert.project_to(&keep).expect("one outcome kept");

        projected.tx_outcomes[0] = outcome(200);
        projected.populate_cached_bytes();
        let bytes = hbor_to_vec(&projected).expect("encode");
        let err = hbor_from_slice::<ExecutionCertificate>(&bytes)
            .expect_err("a forged outcome must fail the rebuild");
        assert!(matches!(err, HborDecodeError::FailedValidation(_)));
    }

    /// A projection whose outcome is moved to another leaf index fails
    /// even though the outcome itself is honest — position is part of
    /// what the root commits to.
    #[test]
    fn decode_rejects_an_outcome_claimed_at_the_wrong_leaf() {
        let outcomes: Vec<TxOutcome> = (1..=8).map(outcome).collect();
        let cert = ExecutionCertificate::new(
            tick_id(),
            WeightedTimestamp::from_millis(11),
            compute_global_receipt_root(&outcomes),
            outcomes.clone(),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        );
        let keep: HashSet<TxHash> = std::iter::once(outcomes[2].tx_hash()).collect();
        let mut projected = cert.project_to(&keep).expect("one outcome kept");

        projected.leaf_indices[0] = 3;
        projected.populate_cached_bytes();
        let bytes = hbor_to_vec(&projected).expect("encode");
        let err = hbor_from_slice::<ExecutionCertificate>(&bytes)
            .expect_err("a relocated outcome must fail the rebuild");
        assert!(matches!(err, HborDecodeError::FailedValidation(_)));
    }

    /// A copy that understates the tick's leaf count is refused: the
    /// count is signed, and a copy free to restate it could prove its
    /// outcomes against a tree the committee never attested.
    #[test]
    fn decode_rejects_a_restated_leaf_count() {
        let outcomes: Vec<TxOutcome> = (1..=8).map(outcome).collect();
        let cert = ExecutionCertificate::new(
            tick_id(),
            WeightedTimestamp::from_millis(11),
            compute_global_receipt_root(&outcomes),
            outcomes.clone(),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        );
        let keep: HashSet<TxHash> = std::iter::once(outcomes[0].tx_hash()).collect();
        let mut projected = cert.project_to(&keep).expect("one outcome kept");

        projected.tx_count = 4;
        projected.populate_cached_bytes();
        let bytes = hbor_to_vec(&projected).expect("encode");
        let err = hbor_from_slice::<ExecutionCertificate>(&bytes)
            .expect_err("a restated leaf count must fail the rebuild");
        assert!(matches!(err, HborDecodeError::FailedValidation(_)));
    }

    /// A complete copy may not also carry an index list: that would be a
    /// second encoding of a claim that already has one.
    #[test]
    fn decode_rejects_a_complete_copy_carrying_indices() {
        let outcomes: Vec<TxOutcome> = (1..=4).map(outcome).collect();
        let cert = ExecutionCertificate::new(
            tick_id(),
            WeightedTimestamp::from_millis(11),
            compute_global_receipt_root(&outcomes),
            outcomes,
            // Distinctive so the encoded signature can be located below.
            AggregateSignature::new([0xAB; 96]),
            SignerBitfield::new(4),
        );
        // Re-encode by hand with the index list a complete copy omits:
        // the empty blob length and the empty proof length are the two
        // bytes immediately before the signature.
        let mut forged = hbor_to_vec(&cert).expect("encode");
        let marker = hbor_to_vec(&cert.aggregated_signature).expect("encode");
        let at = forged
            .windows(marker.len())
            .position(|window| window == marker.as_slice())
            .expect("signature must appear in the encoding");
        let blob_at = at - 2;
        assert_eq!(forged[blob_at..at], [0, 0], "empty index blob, empty proof");
        forged.splice(blob_at..=blob_at, [4u8, 0, 0, 0, 0]);
        let err = hbor_from_slice::<ExecutionCertificate>(&forged)
            .expect_err("a complete copy carrying indices must be refused");
        assert!(matches!(err, HborDecodeError::FailedValidation(_)));
    }
}
