//! Per-validator [`ExecutionVote`] over an entire tick's transactions.
//!
//! [`ExecutionVote`] is the raw wire form. Its verified form is
//! `Verified<ExecutionVote>`; predicate at
//! [`impl Verify<&ExecutionVoteContext<'_>>`](Verify::verify) below.

use std::collections::HashMap;

use hyperscale_crypto::{SignError, Signer, Verifier};
use hyperscale_hbor::Hbor;
use thiserror::Error;

use crate::{
    BlockHash, BlockHeight, ConsensusPublicKey, ConsensusSignature, ExecutionVoteMessage,
    GlobalReceiptRoot, MAX_TXS_PER_BLOCK, NetworkDefinition, ShardId, TickId, TxOutcome,
    ValidatorId, Verified, Verify, WeightedTimestamp, compute_global_receipt_root, signed_bytes,
};

/// A validator's vote on all transactions in an execution tick.
///
/// One vote covers all transactions sharing the same provision dependency
/// set, with `global_receipt_root` being a padded merkle root over per-tx
/// leaf hashes ([`tx_outcome_leaf`]: outcome-tagged, extended by the
/// attested work and any settled fee receipt under their own domain tags).
///
/// [`tx_outcome_leaf`]: crate::tx_outcome_leaf
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct ExecutionVote {
    block_hash: BlockHash,
    block_height: BlockHeight,
    vote_anchor_ts: WeightedTimestamp,
    tick_id: TickId,
    shard_id: ShardId,
    global_receipt_root: GlobalReceiptRoot,
    tx_count: u32,
    #[hbor(max = MAX_TXS_PER_BLOCK)]
    tx_outcomes: Vec<TxOutcome>,
    validator: ValidatorId,
    signature: ConsensusSignature,
}

impl ExecutionVote {
    /// Build an `ExecutionVote` from its parts.
    ///
    /// # Panics
    ///
    /// Panics if `tx_outcomes.len() > MAX_TXS_PER_BLOCK`.
    #[allow(clippy::too_many_arguments)] // mirrors the 10 stored fields
    #[must_use]
    pub const fn new(
        block_hash: BlockHash,
        block_height: BlockHeight,
        vote_anchor_ts: WeightedTimestamp,
        tick_id: TickId,
        shard_id: ShardId,
        global_receipt_root: GlobalReceiptRoot,
        tx_count: u32,
        tx_outcomes: Vec<TxOutcome>,
        validator: ValidatorId,
        signature: ConsensusSignature,
    ) -> Self {
        Self {
            block_hash,
            block_height,
            vote_anchor_ts,
            tick_id,
            shard_id,
            global_receipt_root,
            tx_count,
            tx_outcomes,
            validator,
            signature,
        }
    }

    /// Block this tick belongs to.
    #[must_use]
    pub const fn block_hash(&self) -> BlockHash {
        self.block_hash
    }

    /// Block height (the block containing the tick's transactions).
    #[must_use]
    pub const fn block_height(&self) -> BlockHeight {
        self.block_height
    }

    /// BFT-authenticated anchor at which this vote was cast.
    ///
    /// Validators vote at each block commit where the tick is complete.
    /// Including `vote_anchor_ts` in the signed message prevents
    /// cross-height aggregation, ensuring that if an abort intent changes
    /// the `global_receipt_root` between heights, stale votes cannot combine.
    #[must_use]
    pub const fn vote_anchor_ts(&self) -> WeightedTimestamp {
        self.vote_anchor_ts
    }

    /// Which tick within the block.
    #[must_use]
    pub const fn tick_id(&self) -> &TickId {
        &self.tick_id
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

    /// Number of transactions in this tick.
    #[must_use]
    pub const fn tx_count(&self) -> u32 {
        self.tx_count
    }

    /// Per-tx execution outcomes in tick order.
    ///
    /// Carried alongside the vote so any aggregator can extract `tx_outcomes`
    /// directly from quorum votes when building the EC. Not included in the
    /// signed message (`global_receipt_root` already commits to the content).
    /// This avoids relying on each aggregator's local accumulator, which may
    /// have diverged due to different abort timing.
    #[must_use]
    pub(crate) fn tx_outcomes(&self) -> &[TxOutcome] {
        &self.tx_outcomes
    }

    /// Validator who cast this vote.
    #[must_use]
    pub const fn validator(&self) -> ValidatorId {
        self.validator
    }

    /// signature over the vote signing message.
    #[must_use]
    pub(crate) const fn signature(&self) -> ConsensusSignature {
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
        TickId,
        ShardId,
        GlobalReceiptRoot,
        u32,
        Vec<TxOutcome>,
        ValidatorId,
        ConsensusSignature,
    ) {
        (
            self.block_hash,
            self.block_height,
            self.vote_anchor_ts,
            self.tick_id,
            self.shard_id,
            self.global_receipt_root,
            self.tx_count,
            self.tx_outcomes,
            self.validator,
            self.signature,
        )
    }

    /// Build the canonical signing message for this vote.
    ///
    /// The [`ExecutionVoteMessage`] domain separates it from every other signature. Same message
    /// used for `ExecutionCertificate` aggregated signature verification.
    #[must_use]
    pub(crate) fn signing_message(&self, network: &NetworkDefinition) -> Vec<u8> {
        signed_bytes(
            &ExecutionVoteMessage {
                vote_anchor_ts: self.vote_anchor_ts,
                tick_id: self.tick_id,
                shard_group: self.shard_id,
                global_receipt_root: self.global_receipt_root,
                tx_count: self.tx_count,
            },
            network,
        )
    }
}

/// Inputs the [`ExecutionVote`] verifier reads against. Borrows
/// everything; nothing is consumed.
#[derive(Debug, Clone, Copy)]
pub struct ExecutionVoteContext<'a> {
    /// Network identifier — feeds the domain-separated signing message.
    pub(crate) network: &'a NetworkDefinition,
    /// Public key of the validator who cast this vote.
    pub(crate) voter_public_key: &'a ConsensusPublicKey,
    /// Scheme verifier the signature check runs through.
    pub(crate) verifier: &'a dyn Verifier,
}

/// Failure modes of [`ExecutionVote`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ExecutionVoteVerifyError {
    /// `tx_outcomes` does not hash to the claimed `global_receipt_root`.
    ///
    /// The signature covers `(root, count)` but not the unsigned
    /// `tx_outcomes` payload, so a Byzantine validator could otherwise
    /// ship tampered outcomes alongside an honest signed root. Catching
    /// the binding mismatch here keeps the verified-vote invariant
    /// tight: every `Verified<ExecutionVote>` has outcomes that
    /// produce its claimed root.
    #[error("tx_outcomes do not hash to the claimed global_receipt_root")]
    OutcomesRootMismatch,
    /// The signature did not validate against the voter's public
    /// key for the vote's domain-separated signing message.
    #[error("signature invalid")]
    InvalidSignature,
}

/// Construction asserts both halves of the execution-vote predicate:
///
/// 1. `compute_global_receipt_root(self.tx_outcomes()) ==
///    self.global_receipt_root()` — binds the unsigned outcomes
///    payload to the signed root.
/// 2. The signature validates against the voter's public key for
///    the canonical [`ExecutionVoteMessage`].
///
/// Construction goes through one of three gates:
///
/// - [`<ExecutionVote as Verify>::verify`](Verify::verify) — runs
///   both checks against a single voter.
/// - [`Verified::<ExecutionVote>::verify_batch`] — runs the same
///   predicate over a heterogeneous batch (votes may have different
///   signing messages); uses the same-message batch optimisation
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
        if !ctx
            .verifier
            .verify(ctx.voter_public_key, &message, &self.signature)
        {
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
    /// is trivially satisfied. The signature over the canonical
    /// [`ExecutionVoteMessage`] is produced by `signer` inside this
    /// call, so any later
    /// [`<ExecutionVote as Verify>::verify`](Verify::verify) call
    /// against the matching public key would succeed.
    ///
    /// # Errors
    ///
    /// Propagates [`SignError`] when the signer cannot sign.
    #[allow(clippy::too_many_arguments)] // matches the ExecutionVote field set
    pub fn sign_local(
        network: &NetworkDefinition,
        block_hash: BlockHash,
        block_height: BlockHeight,
        vote_anchor_ts: WeightedTimestamp,
        tick_id: TickId,
        shard_id: ShardId,
        tx_outcomes: Vec<TxOutcome>,
        validator: ValidatorId,
        signer: &dyn Signer,
    ) -> Result<Self, SignError> {
        let global_receipt_root = compute_global_receipt_root(&tx_outcomes);
        let tx_count = u32::try_from(tx_outcomes.len()).unwrap_or(u32::MAX);
        let message = signed_bytes(
            &ExecutionVoteMessage {
                vote_anchor_ts,
                tick_id,
                shard_group: shard_id,
                global_receipt_root,
                tx_count,
            },
            network,
        );
        let signature = signer.sign(&message)?;
        // SAFETY: outcomes-root binding holds by construction
        // (root is derived from `tx_outcomes` above); the signature
        // is produced by `signer` over the canonical
        // `ExecutionVoteMessage`, which is exactly the verify
        // predicate's check against this voter's matching pubkey.
        Ok(Self::new_unchecked(ExecutionVote::new(
            block_hash,
            block_height,
            vote_anchor_ts,
            tick_id,
            shard_id,
            global_receipt_root,
            tx_count,
            tx_outcomes,
            validator,
            signature,
        )))
    }

    /// Verify a heterogeneous batch of `(vote, pubkey, power)` triples.
    ///
    /// Each vote's signing message is derived from its own fields —
    /// different `(vote_anchor_ts, tick_id, global_receipt_root,
    /// tx_count)` produce different signing messages — so the batch
    /// is internally grouped by signing message before running the
    /// same-message batch optimisation per group. On per-group
    /// batch failure the implementation falls back to individual
    /// [`Verify::verify`] calls so a single forged signature doesn't
    /// poison the whole group.
    ///
    /// Votes whose `tx_outcomes` don't hash to their claimed
    /// `global_receipt_root` are dropped before signature
    /// verification: the signature only commits to `(root,
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
        verifier: &dyn Verifier,
        network: &NetworkDefinition,
        votes: Vec<(ExecutionVote, ConsensusPublicKey)>,
    ) -> Vec<Self> {
        let votes: Vec<_> = votes
            .into_iter()
            .filter(|(v, _)| compute_global_receipt_root(v.tx_outcomes()) == v.global_receipt_root)
            .collect();

        if votes.is_empty() {
            return Vec::new();
        }

        let mut by_message: HashMap<Vec<u8>, Vec<(ExecutionVote, ConsensusPublicKey)>> =
            HashMap::new();
        for (vote, pk) in votes {
            let msg = vote.signing_message(network);
            by_message.entry(msg).or_default().push((vote, pk));
        }

        let mut accepted: Vec<Self> = Vec::new();

        for (message, group) in by_message {
            let messages: Vec<&[u8]> = vec![message.as_slice(); group.len()];
            let signatures: Vec<ConsensusSignature> =
                group.iter().map(|(v, _)| v.signature()).collect();
            let pubkeys: Vec<ConsensusPublicKey> = group.iter().map(|(_, pk)| *pk).collect();

            // SAFETY: outcomes-root binding was filtered above; the
            // scheme batch verify confirms each signature in this group
            // against its paired pubkey, which is the signature half of
            // the predicate.
            let verdicts = verifier.batch_verify(&messages, &signatures, &pubkeys);
            for ((vote, _), ok) in group.into_iter().zip(verdicts) {
                if ok {
                    accepted.push(Self::new_unchecked(vote));
                }
            }
        }

        accepted
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};
    use hyperscale_hbor::{
        DecodeError, from_slice as hbor_from_slice, to_vec as hbor_to_vec, varint,
    };

    use super::*;
    use crate::{ExecutionOutcome, GlobalReceiptHash, Hash, TxHash};

    fn sample_outcome(seed: u8) -> TxOutcome {
        TxOutcome::new(
            TxHash::from(Hash::from_bytes(&[seed; 4])),
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
            TickId::new(ShardId::leaf(1, 0), BlockHeight::new(7)),
            ShardId::leaf(1, 0),
            GlobalReceiptRoot::from_raw(Hash::from_bytes(b"root")),
            u32::try_from(outcomes.len()).unwrap(),
            outcomes,
            ValidatorId::new(3),
            ConsensusSignature::new([0u8; 96]),
        )
    }

    #[test]
    fn hbor_roundtrip() {
        let vote = sample_vote();
        let bytes = hbor_to_vec(&vote).unwrap();
        let decoded: ExecutionVote = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded, vote);
    }

    fn sign_sample_vote(
        network: &NetworkDefinition,
        outcomes: Vec<TxOutcome>,
        validator: u64,
        signer: &BlsSigner,
    ) -> ExecutionVote {
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"block"));
        let block_height = BlockHeight::new(7);
        let vote_anchor_ts = WeightedTimestamp::from_millis(11);
        let tick_id = TickId::new(ShardId::leaf(1, 0), BlockHeight::new(7));
        let shard_id = ShardId::leaf(1, 0);
        let global_receipt_root = compute_global_receipt_root(&outcomes);
        let tx_count = u32::try_from(outcomes.len()).unwrap();
        let message = signed_bytes(
            &ExecutionVoteMessage {
                vote_anchor_ts,
                tick_id,
                shard_group: shard_id,
                global_receipt_root,
                tx_count,
            },
            network,
        );
        let signature = signer.sign(&message).expect("sign");
        ExecutionVote::new(
            block_hash,
            block_height,
            vote_anchor_ts,
            tick_id,
            shard_id,
            global_receipt_root,
            tx_count,
            outcomes,
            ValidatorId::new(validator),
            signature,
        )
    }

    /// Honest vote: outcomes hash to the claimed root and the
    /// signature validates against the voter's key.
    #[test]
    fn verify_accepts_honest_vote() {
        let net = NetworkDefinition::simulator();
        let signer = BlsSigner::generate();
        let vote = sign_sample_vote(&net, vec![sample_outcome(1), sample_outcome(2)], 3, &signer);

        let ctx = ExecutionVoteContext {
            verifier: &BlsVerifier,
            network: &net,
            voter_public_key: &signer.public_key(),
        };
        let verified = vote.verify(&ctx).expect("honest vote must verify");
        assert_eq!(verified.as_ref().validator(), ValidatorId::new(3));
    }

    /// Outcomes whose merkle root doesn't match the claimed
    /// `global_receipt_root` are rejected before the signature check runs.
    #[test]
    fn verify_rejects_outcomes_root_mismatch() {
        let net = NetworkDefinition::simulator();
        let signer = BlsSigner::generate();
        let honest = sign_sample_vote(&net, vec![sample_outcome(1)], 3, &signer);

        // Swap in a wrong root while leaving the (honestly-signed)
        // signature intact: the predicate's first half must catch it.
        let (
            block_hash,
            block_height,
            vote_anchor_ts,
            tick_id,
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
            tick_id,
            shard_id,
            bogus_root,
            tx_count,
            tx_outcomes,
            validator,
            signature,
        );

        let ctx = ExecutionVoteContext {
            verifier: &BlsVerifier,
            network: &net,
            voter_public_key: &signer.public_key(),
        };
        assert_eq!(
            tampered.verify(&ctx),
            Err(ExecutionVoteVerifyError::OutcomesRootMismatch)
        );
    }

    /// A vote signed by one key but presented with a different
    /// public key fails the signature check.
    #[test]
    fn verify_rejects_bad_signature() {
        let net = NetworkDefinition::simulator();
        let signer = BlsSigner::generate();
        let intruder = BlsSigner::generate();
        let vote = sign_sample_vote(&net, vec![sample_outcome(1)], 3, &signer);

        let ctx = ExecutionVoteContext {
            verifier: &BlsVerifier,
            network: &net,
            voter_public_key: &intruder.public_key(),
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
                let signer = BlsSigner::generate();
                let pk = signer.public_key();
                let vote = sign_sample_vote(&net, outcomes.clone(), i, &signer);
                (vote, pk)
            })
            .collect();

        let verified = Verified::<ExecutionVote>::verify_batch(&BlsVerifier, &net, votes);
        assert_eq!(verified.len(), 3);
    }

    /// One forged signature in the batch triggers the per-vote
    /// fallback: every honest vote still surfaces, the forged one
    /// is silently dropped.
    #[test]
    fn verify_batch_falls_back_and_drops_only_the_forged_vote() {
        let net = NetworkDefinition::simulator();
        let outcomes = vec![sample_outcome(9), sample_outcome(10)];

        let mut votes: Vec<(ExecutionVote, ConsensusPublicKey)> = (0..3u64)
            .map(|i| {
                let signer = BlsSigner::generate();
                let pk = signer.public_key();
                let vote = sign_sample_vote(&net, outcomes.clone(), i, &signer);
                (vote, pk)
            })
            .collect();

        let intruder_pk = BlsSigner::generate().public_key();
        votes[1].1 = intruder_pk;

        let verified = Verified::<ExecutionVote>::verify_batch(&BlsVerifier, &net, votes);
        assert_eq!(verified.len(), 2);
    }

    /// Outcomes/root binding is enforced at intake: a vote with
    /// tampered outcomes is dropped before signature verification
    /// even runs.
    #[test]
    fn verify_batch_drops_outcomes_root_mismatch() {
        let net = NetworkDefinition::simulator();
        let signer = BlsSigner::generate();
        let vote = sign_sample_vote(&net, vec![sample_outcome(11)], 0, &signer);

        let (
            block_hash,
            block_height,
            vote_anchor_ts,
            tick_id,
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
            tick_id,
            shard_id,
            GlobalReceiptRoot::from_raw(Hash::from_bytes(b"bogus")),
            tx_count,
            tx_outcomes,
            validator,
            signature,
        );

        let verified = Verified::<ExecutionVote>::verify_batch(
            &BlsVerifier,
            &net,
            vec![(tampered, signer.public_key())],
        );
        assert!(verified.is_empty());
    }

    /// Empty input produces an empty output.
    #[test]
    fn verify_batch_empty_input_returns_empty() {
        let net = NetworkDefinition::simulator();
        let verified = Verified::<ExecutionVote>::verify_batch(&BlsVerifier, &net, Vec::new());
        assert!(verified.is_empty());
    }

    /// `sign_local` produces a verified vote whose later `verify`
    /// against the matching pubkey passes — closing the
    /// sign-then-verify loop.
    #[test]
    fn sign_local_roundtrips_through_verify() {
        let net = NetworkDefinition::simulator();
        let signer = BlsSigner::generate();

        let verified = Verified::<ExecutionVote>::sign_local(
            &net,
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            BlockHeight::new(7),
            WeightedTimestamp::from_millis(11),
            TickId::new(ShardId::leaf(1, 0), BlockHeight::new(7)),
            ShardId::leaf(1, 0),
            vec![sample_outcome(1)],
            ValidatorId::new(3),
            &signer,
        )
        .expect("sign");

        let ctx = ExecutionVoteContext {
            verifier: &BlsVerifier,
            network: &net,
            voter_public_key: &signer.public_key(),
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
        let mut buf = Vec::new();
        for part in [
            hbor_to_vec(&vote.block_hash).unwrap(),
            hbor_to_vec(&vote.block_height).unwrap(),
            hbor_to_vec(&vote.vote_anchor_ts).unwrap(),
            hbor_to_vec(&vote.tick_id).unwrap(),
            hbor_to_vec(&vote.shard_id).unwrap(),
            hbor_to_vec(&vote.global_receipt_root).unwrap(),
            hbor_to_vec(&vote.tx_count).unwrap(),
        ] {
            buf.extend_from_slice(&part);
        }
        varint::write(&mut buf, MAX_TXS_PER_BLOCK + 1).unwrap();
        buf.extend(std::iter::repeat_n(0u8, (MAX_TXS_PER_BLOCK + 1) * 128));
        let err = hbor_from_slice::<ExecutionVote>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_TXS_PER_BLOCK && actual == MAX_TXS_PER_BLOCK + 1
        ));
    }
}
