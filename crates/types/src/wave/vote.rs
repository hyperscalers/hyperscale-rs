//! Per-validator [`ExecutionVote`] over an entire wave's transactions.
//!
//! [`ExecutionVote`] is the raw wire form. Its verified form is
//! `Verified<ExecutionVote>`; predicate at
//! [`impl Verify<&ExecutionVoteContext<'_>>`](Verify::verify) below.

use std::collections::HashMap;

use sbor::prelude::BasicSbor;
use thiserror::Error;

use crate::{
    BlockHash, BlockHeight, Bls12381G1PrivateKey, Bls12381G1PublicKey, Bls12381G2Signature,
    BoundedVec, GlobalReceiptRoot, MAX_TXS_PER_BLOCK, NetworkDefinition, ShardId, TxOutcome,
    ValidatorId, Verified, Verify, WaveId, WeightedTimestamp, batch_verify_bls_same_message,
    compute_global_receipt_root, exec_vote_message, verify_bls12381_v1,
};

/// A validator's vote on all transactions in an execution wave.
///
/// One vote covers all transactions sharing the same provision dependency set,
/// with `global_receipt_root` being a padded merkle root over per-tx leaf hashes
/// where each leaf = `H(tx_hash` || `receipt_hash` || `success_byte`).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ExecutionVote {
    block_hash: BlockHash,
    block_height: BlockHeight,
    vote_anchor_ts: WeightedTimestamp,
    wave_id: WaveId,
    shard_id: ShardId,
    global_receipt_root: GlobalReceiptRoot,
    tx_count: u32,
    tx_outcomes: BoundedVec<TxOutcome, MAX_TXS_PER_BLOCK>,
    validator: ValidatorId,
    signature: Bls12381G2Signature,
}

impl ExecutionVote {
    /// Build an `ExecutionVote` from its parts.
    ///
    /// # Panics
    ///
    /// Panics if `tx_outcomes.len() > MAX_TXS_PER_BLOCK`.
    #[allow(clippy::too_many_arguments)] // mirrors the 10 stored fields
    #[must_use]
    pub fn new(
        block_hash: BlockHash,
        block_height: BlockHeight,
        vote_anchor_ts: WeightedTimestamp,
        wave_id: WaveId,
        shard_id: ShardId,
        global_receipt_root: GlobalReceiptRoot,
        tx_count: u32,
        tx_outcomes: Vec<TxOutcome>,
        validator: ValidatorId,
        signature: Bls12381G2Signature,
    ) -> Self {
        Self {
            block_hash,
            block_height,
            vote_anchor_ts,
            wave_id,
            shard_id,
            global_receipt_root,
            tx_count,
            tx_outcomes: tx_outcomes.into(),
            validator,
            signature,
        }
    }

    /// Block this wave belongs to.
    #[must_use]
    pub const fn block_hash(&self) -> BlockHash {
        self.block_hash
    }

    /// Block height (the block containing the wave's transactions).
    #[must_use]
    pub const fn block_height(&self) -> BlockHeight {
        self.block_height
    }

    /// BFT-authenticated anchor at which this vote was cast.
    ///
    /// Validators vote at each block commit where the wave is complete.
    /// Including `vote_anchor_ts` in the BLS-signed message prevents
    /// cross-height aggregation, ensuring that if an abort intent changes
    /// the `global_receipt_root` between heights, stale votes cannot combine.
    #[must_use]
    pub const fn vote_anchor_ts(&self) -> WeightedTimestamp {
        self.vote_anchor_ts
    }

    /// Which wave within the block.
    #[must_use]
    pub const fn wave_id(&self) -> &WaveId {
        &self.wave_id
    }

    /// Which shard produced this vote.
    #[must_use]
    pub const fn shard_id(&self) -> ShardId {
        self.shard_id
    }

    /// Merkle root over per-tx outcome leaves.
    #[must_use]
    pub const fn global_receipt_root(&self) -> GlobalReceiptRoot {
        self.global_receipt_root
    }

    /// Number of transactions in this wave.
    #[must_use]
    pub const fn tx_count(&self) -> u32 {
        self.tx_count
    }

    /// Per-tx execution outcomes in wave order.
    ///
    /// Carried alongside the vote so any aggregator can extract `tx_outcomes`
    /// directly from quorum votes when building the EC. Not included in the
    /// BLS-signed message (`global_receipt_root` already commits to the content).
    /// This avoids relying on each aggregator's local accumulator, which may
    /// have diverged due to different abort timing.
    #[must_use]
    pub fn tx_outcomes(&self) -> &[TxOutcome] {
        &self.tx_outcomes
    }

    /// Validator who cast this vote.
    #[must_use]
    pub const fn validator(&self) -> ValidatorId {
        self.validator
    }

    /// BLS signature over the vote signing message.
    #[must_use]
    pub const fn signature(&self) -> Bls12381G2Signature {
        self.signature
    }

    /// Decompose into the raw fields, in struct-declaration order.
    #[allow(clippy::type_complexity)] // mirrors the 10 stored fields
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        BlockHash,
        BlockHeight,
        WeightedTimestamp,
        WaveId,
        ShardId,
        GlobalReceiptRoot,
        u32,
        Vec<TxOutcome>,
        ValidatorId,
        Bls12381G2Signature,
    ) {
        (
            self.block_hash,
            self.block_height,
            self.vote_anchor_ts,
            self.wave_id,
            self.shard_id,
            self.global_receipt_root,
            self.tx_count,
            self.tx_outcomes.into_inner(),
            self.validator,
            self.signature,
        )
    }

    /// Build the canonical signing message for this vote.
    ///
    /// Uses `DOMAIN_EXEC_VOTE` tag for domain separation. Same message
    /// used for `ExecutionCertificate` aggregated signature verification.
    #[must_use]
    pub fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        exec_vote_message(
            network,
            self.vote_anchor_ts,
            &self.wave_id,
            self.shard_id,
            &self.global_receipt_root,
            self.tx_count,
        )
    }
}

/// Inputs the [`ExecutionVote`] verifier reads against. Borrows
/// everything; nothing is consumed.
#[derive(Debug, Clone, Copy)]
pub struct ExecutionVoteContext<'a> {
    /// Network identifier — feeds the domain-separated signing message.
    pub network: &'a NetworkDefinition,
    /// BLS public key of the validator who cast this vote.
    pub voter_public_key: &'a Bls12381G1PublicKey,
}

/// Failure modes of [`ExecutionVote`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ExecutionVoteVerifyError {
    /// `tx_outcomes` does not hash to the claimed `global_receipt_root`.
    ///
    /// The BLS signature covers `(root, count)` but not the unsigned
    /// `tx_outcomes` payload, so a Byzantine validator could otherwise
    /// ship tampered outcomes alongside an honest signed root. Catching
    /// the binding mismatch here keeps the verified-vote invariant
    /// tight: every `Verified<ExecutionVote>` has outcomes that
    /// produce its claimed root.
    #[error("tx_outcomes do not hash to the claimed global_receipt_root")]
    OutcomesRootMismatch,
    /// The BLS signature did not validate against the voter's public
    /// key for the vote's domain-separated signing message.
    #[error("BLS signature invalid")]
    InvalidSignature,
}

/// Construction asserts both halves of the execution-vote predicate:
///
/// 1. `compute_global_receipt_root(self.tx_outcomes()) ==
///    self.global_receipt_root()` — binds the unsigned outcomes
///    payload to the signed root.
/// 2. The BLS signature validates against the voter's public key for
///    the canonical [`exec_vote_message`].
///
/// Construction goes through one of three gates:
///
/// - [`<ExecutionVote as Verify>::verify`](Verify::verify) — runs
///   both checks against a single voter.
/// - [`Verified::<ExecutionVote>::verify_batch`] — runs the same
///   predicate over a heterogeneous batch (votes may have different
///   signing messages); uses the BLS same-message batch optimisation
///   per signing-message group, with individual-verify fallback when
///   the group's batch verify fails.
/// - [`Verified::<ExecutionVote>::sign_local`] — signs a fresh vote
///   with the caller's key; the act of signing is the predicate
///   witness, and the matching outcomes/root are supplied by the
///   caller.
impl Verify<&ExecutionVoteContext<'_>> for ExecutionVote {
    type Error = ExecutionVoteVerifyError;

    fn verify(&self, ctx: &ExecutionVoteContext<'_>) -> Result<Verified<Self>, Self::Error> {
        if compute_global_receipt_root(self.tx_outcomes()) != self.global_receipt_root {
            return Err(ExecutionVoteVerifyError::OutcomesRootMismatch);
        }
        let message = self.signing_message(ctx.network);
        if !verify_bls12381_v1(&message, ctx.voter_public_key, &self.signature) {
            return Err(ExecutionVoteVerifyError::InvalidSignature);
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verified<ExecutionVote> {
    /// Sign a fresh [`ExecutionVote`] with `signing_key` and return its
    /// verified form.
    ///
    /// The predicate holds by construction: the outcomes are supplied
    /// by the caller and the `global_receipt_root` is derived from
    /// them via [`compute_global_receipt_root`], so the binding check
    /// is trivially satisfied. The BLS signature over the canonical
    /// [`exec_vote_message`] is produced from `signing_key` inside
    /// this call, so any later
    /// [`<ExecutionVote as Verify>::verify`](Verify::verify) call
    /// against the matching public key would succeed.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // matches the ExecutionVote field set
    pub fn sign_local(
        network: &NetworkDefinition,
        block_hash: BlockHash,
        block_height: BlockHeight,
        vote_anchor_ts: WeightedTimestamp,
        wave_id: WaveId,
        shard_id: ShardId,
        tx_outcomes: Vec<TxOutcome>,
        validator: ValidatorId,
        signing_key: &Bls12381G1PrivateKey,
    ) -> Self {
        let global_receipt_root = compute_global_receipt_root(&tx_outcomes);
        let tx_count = u32::try_from(tx_outcomes.len()).unwrap_or(u32::MAX);
        let message = exec_vote_message(
            network,
            vote_anchor_ts,
            &wave_id,
            shard_id,
            &global_receipt_root,
            tx_count,
        );
        let signature = signing_key.sign_v1(&message);
        // SAFETY: outcomes-root binding holds by construction
        // (root is derived from `tx_outcomes` above); BLS signature
        // is produced by `signing_key` over the canonical
        // `exec_vote_message`, which is exactly the verify
        // predicate's check against this voter's matching pubkey.
        Self::new_unchecked(ExecutionVote::new(
            block_hash,
            block_height,
            vote_anchor_ts,
            wave_id,
            shard_id,
            global_receipt_root,
            tx_count,
            tx_outcomes,
            validator,
            signature,
        ))
    }

    /// Verify a heterogeneous batch of `(vote, pubkey, power)` triples.
    ///
    /// Each vote's signing message is derived from its own fields —
    /// different `(vote_anchor_ts, wave_id, global_receipt_root,
    /// tx_count)` produce different signing messages — so the batch
    /// is internally grouped by signing message before running the
    /// BLS same-message batch optimisation per group. On per-group
    /// batch failure the implementation falls back to individual
    /// [`Verify::verify`] calls so a single forged signature doesn't
    /// poison the whole group.
    ///
    /// Votes whose `tx_outcomes` don't hash to their claimed
    /// `global_receipt_root` are dropped before signature
    /// verification: the BLS signature only commits to `(root,
    /// tx_count)`, so a vote that signs an honest root while
    /// shipping tampered outcomes is self-inconsistent. Filtering
    /// here (rather than defending at aggregation) keeps the
    /// verified-vote invariant tight.
    ///
    /// Returns the verified votes that passed both predicate halves. Output
    /// order is implementation-defined (groupings are hashed, not the input
    /// order).
    #[must_use]
    pub fn verify_batch(
        network: &NetworkDefinition,
        votes: Vec<(ExecutionVote, Bls12381G1PublicKey)>,
    ) -> Vec<Self> {
        let votes: Vec<_> = votes
            .into_iter()
            .filter(|(v, _)| compute_global_receipt_root(v.tx_outcomes()) == v.global_receipt_root)
            .collect();

        if votes.is_empty() {
            return Vec::new();
        }

        let mut by_message: HashMap<Vec<u8>, Vec<(ExecutionVote, Bls12381G1PublicKey)>> =
            HashMap::new();
        for (vote, pk) in votes {
            let msg = vote.signing_message(network);
            by_message.entry(msg).or_default().push((vote, pk));
        }

        let mut verified: Vec<Self> = Vec::new();

        for (message, group) in by_message {
            let signatures: Vec<Bls12381G2Signature> =
                group.iter().map(|(v, _)| v.signature()).collect();
            let pubkeys: Vec<Bls12381G1PublicKey> = group.iter().map(|(_, pk)| *pk).collect();

            if group.len() >= 2 && batch_verify_bls_same_message(&message, &signatures, &pubkeys) {
                // SAFETY: outcomes-root binding was filtered above;
                // BLS same-message batch verify just confirmed every
                // signature in this group against its paired pubkey.
                for (vote, _) in group {
                    verified.push(Self::new_unchecked(vote));
                }
            } else {
                for (vote, pk) in group {
                    if verify_bls12381_v1(&message, &pk, &vote.signature()) {
                        // SAFETY: outcomes-root binding was filtered
                        // above; individual BLS verify just ran the
                        // signature half of the predicate.
                        verified.push(Self::new_unchecked(vote));
                    }
                }
            }
        }

        verified
    }
}

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, Categorize, DecodeError, Encoder,
        NoCustomValueKind, ValueKind, VecEncoder, basic_decode, basic_encode,
    };

    use super::*;
    use crate::{ExecutionOutcome, GlobalReceiptHash, Hash, TxHash, generate_bls_keypair};

    fn sample_outcome(seed: u8) -> TxOutcome {
        TxOutcome::new(
            TxHash::from_raw(Hash::from_bytes(&[seed; 4])),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(&[seed + 1; 4])),
            },
        )
    }

    fn sample_vote() -> ExecutionVote {
        let outcomes = vec![sample_outcome(1), sample_outcome(2)];
        ExecutionVote::new(
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            BlockHeight::new(7),
            WeightedTimestamp::from_millis(11),
            WaveId::new(
                ShardId::leaf(1, 0),
                BlockHeight::new(7),
                std::iter::once(ShardId::leaf(1, 1)).collect(),
            ),
            ShardId::leaf(1, 0),
            GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root")),
            u32::try_from(outcomes.len()).unwrap(),
            outcomes,
            ValidatorId::new(3),
            Bls12381G2Signature([0u8; 96]),
        )
    }

    #[test]
    fn sbor_roundtrip() {
        let vote = sample_vote();
        let bytes = basic_encode(&vote).unwrap();
        let decoded: ExecutionVote = basic_decode(&bytes).unwrap();
        assert_eq!(decoded, vote);
    }

    fn sign_sample_vote(
        network: &NetworkDefinition,
        outcomes: Vec<TxOutcome>,
        validator: u64,
        signing_key: &Bls12381G1PrivateKey,
    ) -> ExecutionVote {
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"block"));
        let block_height = BlockHeight::new(7);
        let vote_anchor_ts = WeightedTimestamp::from_millis(11);
        let wave_id = WaveId::new(
            ShardId::leaf(1, 0),
            BlockHeight::new(7),
            std::iter::once(ShardId::leaf(1, 1)).collect(),
        );
        let shard_id = ShardId::leaf(1, 0);
        let global_receipt_root = compute_global_receipt_root(&outcomes);
        let tx_count = u32::try_from(outcomes.len()).unwrap();
        let message = exec_vote_message(
            network,
            vote_anchor_ts,
            &wave_id,
            shard_id,
            &global_receipt_root,
            tx_count,
        );
        let signature = signing_key.sign_v1(&message);
        ExecutionVote::new(
            block_hash,
            block_height,
            vote_anchor_ts,
            wave_id,
            shard_id,
            global_receipt_root,
            tx_count,
            outcomes,
            ValidatorId::new(validator),
            signature,
        )
    }

    /// Honest vote: outcomes hash to the claimed root and the BLS
    /// signature validates against the voter's key.
    #[test]
    fn verify_accepts_honest_vote() {
        let net = NetworkDefinition::simulator();
        let sk = generate_bls_keypair();
        let pk = sk.public_key();
        let vote = sign_sample_vote(&net, vec![sample_outcome(1), sample_outcome(2)], 3, &sk);

        let ctx = ExecutionVoteContext {
            network: &net,
            voter_public_key: &pk,
        };
        let verified = vote.verify(&ctx).expect("honest vote must verify");
        assert_eq!(verified.as_ref().validator(), ValidatorId::new(3));
    }

    /// Outcomes whose merkle root doesn't match the claimed
    /// `global_receipt_root` are rejected before the BLS check runs.
    #[test]
    fn verify_rejects_outcomes_root_mismatch() {
        let net = NetworkDefinition::simulator();
        let sk = generate_bls_keypair();
        let pk = sk.public_key();
        let honest = sign_sample_vote(&net, vec![sample_outcome(1)], 3, &sk);

        // Swap in a wrong root while leaving the (honestly-signed)
        // signature intact: the predicate's first half must catch it.
        let (
            block_hash,
            block_height,
            vote_anchor_ts,
            wave_id,
            shard_id,
            _root,
            tx_count,
            tx_outcomes,
            validator,
            signature,
        ) = honest.into_parts();
        let bogus_root = GlobalReceiptRoot::from_raw(Hash::from_bytes(b"bogus"));
        assert_ne!(bogus_root, compute_global_receipt_root(&tx_outcomes));
        let tampered = ExecutionVote::new(
            block_hash,
            block_height,
            vote_anchor_ts,
            wave_id,
            shard_id,
            bogus_root,
            tx_count,
            tx_outcomes,
            validator,
            signature,
        );

        let ctx = ExecutionVoteContext {
            network: &net,
            voter_public_key: &pk,
        };
        assert_eq!(
            tampered.verify(&ctx),
            Err(ExecutionVoteVerifyError::OutcomesRootMismatch)
        );
    }

    /// A vote signed by one key but presented with a different
    /// public key fails the BLS check.
    #[test]
    fn verify_rejects_bad_signature() {
        let net = NetworkDefinition::simulator();
        let signer = generate_bls_keypair();
        let intruder = generate_bls_keypair();
        let vote = sign_sample_vote(&net, vec![sample_outcome(1)], 3, &signer);

        let intruder_pk = intruder.public_key();
        let ctx = ExecutionVoteContext {
            network: &net,
            voter_public_key: &intruder_pk,
        };
        assert_eq!(
            vote.verify(&ctx),
            Err(ExecutionVoteVerifyError::InvalidSignature)
        );
    }

    /// All-valid batch verifies via the fast path and surfaces every
    /// vote with its paired power.
    #[test]
    fn verify_batch_all_valid_returns_all_verified() {
        let net = NetworkDefinition::simulator();
        let outcomes = vec![sample_outcome(7), sample_outcome(8)];

        let votes: Vec<_> = (0..3u64)
            .map(|i| {
                let sk = generate_bls_keypair();
                let pk = sk.public_key();
                let vote = sign_sample_vote(&net, outcomes.clone(), i, &sk);
                (vote, pk)
            })
            .collect();

        let verified = Verified::<ExecutionVote>::verify_batch(&net, votes);
        assert_eq!(verified.len(), 3);
    }

    /// One forged signature in the batch triggers the per-vote
    /// fallback: every honest vote still surfaces, the forged one
    /// is silently dropped.
    #[test]
    fn verify_batch_falls_back_and_drops_only_the_forged_vote() {
        let net = NetworkDefinition::simulator();
        let outcomes = vec![sample_outcome(9), sample_outcome(10)];

        let mut votes: Vec<(ExecutionVote, Bls12381G1PublicKey)> = (0..3u64)
            .map(|i| {
                let sk = generate_bls_keypair();
                let pk = sk.public_key();
                let vote = sign_sample_vote(&net, outcomes.clone(), i, &sk);
                (vote, pk)
            })
            .collect();

        let intruder_pk = generate_bls_keypair().public_key();
        votes[1].1 = intruder_pk;

        let verified = Verified::<ExecutionVote>::verify_batch(&net, votes);
        assert_eq!(verified.len(), 2);
    }

    /// Outcomes/root binding is enforced at intake: a vote with
    /// tampered outcomes is dropped before signature verification
    /// even runs.
    #[test]
    fn verify_batch_drops_outcomes_root_mismatch() {
        let net = NetworkDefinition::simulator();
        let sk = generate_bls_keypair();
        let pk = sk.public_key();
        let vote = sign_sample_vote(&net, vec![sample_outcome(11)], 0, &sk);

        let (
            block_hash,
            block_height,
            vote_anchor_ts,
            wave_id,
            shard_id,
            _root,
            tx_count,
            tx_outcomes,
            validator,
            signature,
        ) = vote.into_parts();
        let tampered = ExecutionVote::new(
            block_hash,
            block_height,
            vote_anchor_ts,
            wave_id,
            shard_id,
            GlobalReceiptRoot::from_raw(Hash::from_bytes(b"bogus")),
            tx_count,
            tx_outcomes,
            validator,
            signature,
        );

        let verified = Verified::<ExecutionVote>::verify_batch(&net, vec![(tampered, pk)]);
        assert!(verified.is_empty());
    }

    /// Empty input produces an empty output.
    #[test]
    fn verify_batch_empty_input_returns_empty() {
        let net = NetworkDefinition::simulator();
        let verified = Verified::<ExecutionVote>::verify_batch(&net, Vec::new());
        assert!(verified.is_empty());
    }

    /// `sign_local` produces a verified vote whose later `verify`
    /// against the matching pubkey passes — closing the
    /// sign-then-verify loop.
    #[test]
    fn sign_local_roundtrips_through_verify() {
        let net = NetworkDefinition::simulator();
        let sk = generate_bls_keypair();
        let pk = sk.public_key();

        let verified = Verified::<ExecutionVote>::sign_local(
            &net,
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            BlockHeight::new(7),
            WeightedTimestamp::from_millis(11),
            WaveId::new(
                ShardId::leaf(1, 0),
                BlockHeight::new(7),
                std::iter::once(ShardId::leaf(1, 1)).collect(),
            ),
            ShardId::leaf(1, 0),
            vec![sample_outcome(1)],
            ValidatorId::new(3),
            &sk,
        );

        let ctx = ExecutionVoteContext {
            network: &net,
            voter_public_key: &pk,
        };
        let raw = verified.into_inner();
        raw.verify(&ctx)
            .expect("sign_local output must satisfy its own predicate");
    }

    /// Hand-roll a vote whose `tx_outcomes` count exceeds the cap and verify
    /// decode rejects it before iterating.
    #[test]
    fn decode_rejects_oversized_tx_outcomes() {
        let vote = sample_vote();
        let mut buf = Vec::with_capacity(128);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(10).unwrap();
        enc.encode(&vote.block_hash).unwrap();
        enc.encode(&vote.block_height).unwrap();
        enc.encode(&vote.vote_anchor_ts).unwrap();
        enc.encode(&vote.wave_id).unwrap();
        enc.encode(&vote.shard_id).unwrap();
        enc.encode(&vote.global_receipt_root).unwrap();
        enc.encode(&vote.tx_count).unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(TxOutcome::value_kind()).unwrap();
        enc.write_size(MAX_TXS_PER_BLOCK + 1).unwrap();
        let err = basic_decode::<ExecutionVote>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_TXS_PER_BLOCK,
                actual,
            } if actual == MAX_TXS_PER_BLOCK + 1
        ));
    }
}
