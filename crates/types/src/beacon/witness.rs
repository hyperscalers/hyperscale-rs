//! Beacon-chain shard-witness types.
//!
//! A [`ShardWitness`] lifts one event from a shard's VM — validator
//! registrations, stake adjustments, missed-proposal observations —
//! via that shard's monotonic beacon-witness accumulator, carrying a
//! [`ShardWitnessProof`] for provenance. A
//! [`BeaconProposal`](crate::BeaconProposal) carries a list of these
//! alongside its equivocation evidence (a
//! [`PcVoteEquivocation`](crate::PcVoteEquivocation), which is
//! self-authenticating from its embedded BLS sigs).

use sbor::prelude::*;
use thiserror::Error;

use crate::{
    BlockHash, BlockHeader, BlockHeight, Bls12381G1PublicKey, BoundedVec, CertifiedBlockHeader,
    Hash, LeafIndex, MAX_WITNESS_PROOF_DEPTH, ParamVote, Round, ShardId, Stake, StakePoolId,
    ValidatorId, Verified, Verify, verify_merkle_inclusion,
};

/// Domain tag for accumulator leaf hashing.
///
/// Tag-prefixing the SBOR encoding of the payload prevents the leaf
/// hash from colliding with an internal merkle node (the merkle helpers
/// pad with [`Hash::ZERO`] and combine sibling pairs without per-level
/// domain separation, so every leaf encoder in this codebase must
/// domain-tag its input).
pub const SHARD_WITNESS_LEAF_DOMAIN_TAG: &[u8] = b"hyperscale-shard-witness-leaf-v1";

/// What the shard observed and reported to the beacon.
///
/// Split by source: receipt-emitted variants are the engine's projection
/// of executing a transaction; consensus-derived variants are produced by
/// the shard runtime from its own BFT state; included variants come from
/// system inputs the proposer pulled into the block.
///
/// Provenance fields (shard, leaf-index, Merkle path) live in
/// [`ShardWitnessProof`].
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub enum ShardWitnessPayload {
    /// A net deposit landed for `pool_id`. Increases the pool's
    /// `total_stake`. If `pool_id` is unknown, creates the pool entry.
    StakeDeposit {
        /// Pool receiving the deposit.
        pool_id: StakePoolId,
        /// Aggregate amount added; delegator-level accounting lives on
        /// the shard.
        amount: Stake,
    },
    /// A withdrawal request was placed against `pool_id`. Appends a
    /// pending-withdrawal entry; `total_stake` is unchanged until the
    /// unbonding window completes, but `effective_stake` drops
    /// immediately and blocks new registrations relying on the
    /// withdrawn amount.
    StakeWithdraw {
        /// Pool the withdrawal targets.
        pool_id: StakePoolId,
        /// Amount the withdrawal removes from effective stake
        /// immediately and from total stake on unbonding completion.
        amount: Stake,
    },
    /// The pool registers a new validator node. The published pubkey
    /// is carried on the witness so the beacon can verify the
    /// validator's signed outputs without a side-channel registry.
    /// Rejected by `apply_epoch` if the pool's effective stake doesn't
    /// support another activation at the current dynamic `min_stake`.
    RegisterValidator {
        /// Pool that operates this validator.
        pool_id: StakePoolId,
        /// Identifier the validator will be known by.
        validator_id: ValidatorId,
        /// 48-byte compressed BLS pubkey.
        pubkey: Bls12381G1PublicKey,
    },
    /// The pool operator deactivates one of their validator nodes.
    /// Transitions the validator out of any active role; if currently
    /// on a shard, frees the epoch for a pool draw.
    DeactivateValidator {
        /// Validator being deactivated.
        validator_id: ValidatorId,
    },
    /// Validator took an unjail action on the staking contract.
    /// Beacon-side: if currently jailed under a fault-cause reason,
    /// the cooldown has elapsed, and the pool can still support the
    /// additional active epoch at the current dynamic `min_stake`,
    /// transition back to the pool. Otherwise silently dropped.
    /// Equivocation jails are never unjailed.
    Unjail {
        /// Validator requesting unjail.
        id: ValidatorId,
    },
    /// A stake pool cast or cleared its network-parameter vote. Recorded
    /// into [`BeaconState::param_votes`](crate::BeaconState); the
    /// per-epoch tally applies any proposal a stake majority backs at its
    /// activation epoch. Rides the system-transaction rail like the
    /// staking variants — the beacon trusts the committee-attested witness
    /// that `pool` voted this way and weights the tally by `pool`'s stake,
    /// with the signer's authority over the pool enforced in the VM.
    ParamVote(ParamVote),
    /// A validator on a shard has signalled they've finished syncing
    /// the shard's state. Transitions the validator to ready;
    /// silently dropped if the validator's status doesn't match.
    Ready {
        /// Validator marking themselves ready.
        id: ValidatorId,
    },
    /// The proposer scheduled for `(height, round)` failed to deliver a
    /// valid block within the view-change timeout; the round was skipped
    /// and a later round committed `height`. Emitted by the shard runtime
    /// at every fallback commit — one witness per skipped round, derived
    /// deterministically from `(parent_round, header.round)` and the
    /// shard's leader schedule. Beacon side aggregates these into a
    /// per-validator sliding-window counter and jails the validator under
    /// a Performance reason once the threshold is crossed.
    MissedProposal {
        /// Validator who was the expected proposer at `(height, round)`.
        proposer_id: ValidatorId,
        /// Height the missed round was attempting.
        height: BlockHeight,
        /// Round the missed proposer was scheduled for.
        round: Round,
    },
    /// The shard's committed substate byte total reached the split
    /// threshold. Derived from the manifest's reshape assertion, which
    /// replicas validate against their own count — so the witness
    /// arrives committee-attested. The beacon admits it (pool gate,
    /// `MAX_SHARDS`, active-leaf target) and schedules the split.
    ScheduleSplit {
        /// Shard asserting the split — always the witness's source
        /// shard today; explicit so the payload stays valid if
        /// emission ever moves off-shard.
        shard: ShardId,
    },
    /// The shard's committed substate byte total fell below the merge
    /// threshold. The beacon parks the assertion until the sibling's
    /// matching half folds, then schedules the merge under `parent`.
    ScheduleMerge {
        /// Parent the merged shard reforms under — always the source
        /// shard's own parent today; explicit for the same reason as
        /// [`Self::ScheduleSplit::shard`].
        parent: ShardId,
    },
    /// A cohort observer finished syncing its assigned pending child
    /// of the source shard and is ready for the reshape to execute.
    /// Rides the source shard's chain like [`Self::Ready`]; the beacon
    /// folds it into the pending reshape's per-child readiness, which
    /// gates execution. The target child is implied — reshapes never
    /// overlap, so the source shard names the pending record and the
    /// cohort seat names the child.
    ReshapeReady {
        /// Observer signalling sync completion.
        validator: ValidatorId,
    },
}

impl ShardWitnessPayload {
    /// Canonical accumulator leaf hash for this payload.
    ///
    /// Produces `BLAKE3(SHARD_WITNESS_LEAF_DOMAIN_TAG ‖ sbor_encode(self))`.
    /// Both the shard runtime (when computing
    /// [`BeaconWitnessRoot`](crate::BeaconWitnessRoot)) and the fetch
    /// responder (when constructing inclusion proofs) call this — the
    /// hash is the protocol-defined leaf format, not an
    /// implementation detail of either site.
    ///
    /// # Panics
    ///
    /// Panics if SBOR encoding fails. `ShardWitnessPayload` is a
    /// closed SBOR type and encoding is infallible in practice.
    #[must_use]
    pub fn leaf_hash(&self) -> Hash {
        let encoded = basic_encode(self).expect("ShardWitnessPayload SBOR encode is infallible");
        Hash::from_parts(&[SHARD_WITNESS_LEAF_DOMAIN_TAG, &encoded])
    }
}

/// Receipt-emittable subset of [`ShardWitnessPayload`].
///
/// Covers only the variants the engine surfaces from executing a
/// transaction. The two consensus-derived variants
/// ([`ShardWitnessPayload::MissedProposal`], [`ShardWitnessPayload::Ready`])
/// are deliberately absent: the receipt path can't observe them, and
/// admitting them in this enum would invite a type-level bug where a
/// receipt synthesised a witness that belongs to a different source.
///
/// Conversion to [`ShardWitnessPayload`] is total; see the `From` impl.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub enum BeaconWitnessEvent {
    /// Mirrors [`ShardWitnessPayload::StakeDeposit`].
    StakeDeposit {
        /// Pool receiving the deposit.
        pool_id: StakePoolId,
        /// Aggregate amount added.
        amount: Stake,
    },
    /// Mirrors [`ShardWitnessPayload::StakeWithdraw`].
    StakeWithdraw {
        /// Pool the withdrawal targets.
        pool_id: StakePoolId,
        /// Amount the withdrawal removes from effective stake immediately
        /// and from total stake on unbonding completion.
        amount: Stake,
    },
    /// Mirrors [`ShardWitnessPayload::RegisterValidator`].
    RegisterValidator {
        /// Pool that operates this validator.
        pool_id: StakePoolId,
        /// Identifier the validator will be known by.
        validator_id: ValidatorId,
        /// 48-byte compressed BLS pubkey.
        pubkey: Bls12381G1PublicKey,
    },
    /// Mirrors [`ShardWitnessPayload::DeactivateValidator`].
    DeactivateValidator {
        /// Validator being deactivated.
        validator_id: ValidatorId,
    },
    /// Mirrors [`ShardWitnessPayload::Unjail`].
    Unjail {
        /// Validator requesting unjail.
        id: ValidatorId,
    },
    /// Mirrors [`ShardWitnessPayload::ParamVote`].
    ParamVote(ParamVote),
}

impl From<BeaconWitnessEvent> for ShardWitnessPayload {
    fn from(event: BeaconWitnessEvent) -> Self {
        match event {
            BeaconWitnessEvent::StakeDeposit { pool_id, amount } => {
                Self::StakeDeposit { pool_id, amount }
            }
            BeaconWitnessEvent::StakeWithdraw { pool_id, amount } => {
                Self::StakeWithdraw { pool_id, amount }
            }
            BeaconWitnessEvent::RegisterValidator {
                pool_id,
                validator_id,
                pubkey,
            } => Self::RegisterValidator {
                pool_id,
                validator_id,
                pubkey,
            },
            BeaconWitnessEvent::DeactivateValidator { validator_id } => {
                Self::DeactivateValidator { validator_id }
            }
            BeaconWitnessEvent::Unjail { id } => Self::Unjail { id },
            BeaconWitnessEvent::ParamVote(vote) => Self::ParamVote(vote),
        }
    }
}

/// Provenance for a [`ShardWitness`] — a Merkle inclusion proof
/// against the source shard's beacon-witness accumulator root, paired
/// with the committed block whose header carries that root.
///
/// Verifying:
/// 1. Look up the shard's committed block at `committed_block_hash`
///    (delivered via the existing `CertifiedBlockHeaderGossip` path)
///    and read its [`BeaconWitnessRoot`](crate::BeaconWitnessRoot).
/// 2. Hash the witness payload to obtain the leaf.
/// 3. Walk `siblings` from leaf to root using `leaf_index`'s bit
///    decomposition to determine left/right at each level.
/// 4. Compare against the committed root.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ShardWitnessProof {
    /// Shard that emitted the witness.
    pub shard_id: ShardId,
    /// Hash of the source shard's committed block whose header carries
    /// the accumulator root this proof verifies against.
    pub committed_block_hash: BlockHash,
    /// Position of the witness in the shard's monotonic
    /// beacon-witness accumulator — the global leaf identity. The
    /// merkle path verifies at the window-relative position
    /// `leaf_index - header.beacon_witness_base()`.
    pub leaf_index: LeafIndex,
    /// Sibling hashes along the path from leaf to root, leaf-side
    /// first. Length equals the witness window's depth at
    /// `committed_block_hash`.
    pub siblings: BoundedVec<Hash, MAX_WITNESS_PROOF_DEPTH>,
}

/// A shard-emitted observation paired with proof of origin.
///
/// `payload` is the beacon-relevant fact; `proof` says where it came
/// from.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ShardWitness {
    /// What the shard observed.
    pub payload: ShardWitnessPayload,
    /// Where it came from.
    pub proof: ShardWitnessProof,
}

impl ShardWitness {
    /// Whether this witness's merkle proof places it at the claimed leaf
    /// index in `header`'s beacon-witness accumulator — the raw-`BlockHeader`
    /// form of the [`Verify`] predicate. The boundary fold and received-block
    /// validation use this against a contribution's `boundary_header`, which
    /// is already authenticated by its canonical-QC binding
    /// (`hash(boundary_header) == qc.block_hash`), so no
    /// `Verified<CertifiedBlockHeader>` is in hand. The shard and
    /// anchor-block-hash must match the header, the leaf index must sit
    /// inside the header's witness window and fit the merkle helper's
    /// `u32` width once rebased, and the path from `payload.leaf_hash()`
    /// must reach `header.beacon_witness_root()` at the window-relative
    /// position `leaf_index - beacon_witness_base`.
    #[must_use]
    pub fn merkle_includes_in(&self, header: &BlockHeader) -> bool {
        if self.proof.shard_id != header.shard_id() {
            return false;
        }
        if self.proof.committed_block_hash != header.hash() {
            return false;
        }
        let base = header.beacon_witness_base().inner();
        if self.proof.leaf_index.inner() < base {
            return false;
        }
        let Ok(position) = u32::try_from(self.proof.leaf_index.inner() - base) else {
            return false;
        };
        verify_merkle_inclusion(
            *header.beacon_witness_root().as_raw(),
            self.payload.leaf_hash(),
            &self.proof.siblings,
            position,
        )
    }
}

/// Failure modes of a [`ShardWitness`].
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ShardWitnessVerifyError {
    /// `proof.shard_id != ctx.header().shard_id()`.
    #[error("witness shard_id does not match header shard")]
    ShardIdMismatch,
    /// `proof.committed_block_hash != ctx.block_hash()`.
    #[error("witness committed_block_hash does not match header block hash")]
    BlockHashMismatch,
    /// `proof.leaf_index` sits below the header's witness window base —
    /// the windowed root commits nothing at that position.
    #[error("leaf_index below the header's witness window")]
    LeafBelowWindow,
    /// The window-relative position exceeds the merkle helper's `u32`
    /// index width.
    #[error("leaf_index exceeds u32")]
    LeafIndexOverflow,
    /// Merkle inclusion check against `header.beacon_witness_root()` failed.
    #[error("merkle inclusion against header.beacon_witness_root failed")]
    BadInclusion,
}

/// Shard-witness predicate: the witness's claimed `shard_id` and
/// `committed_block_hash` match the verified header, `leaf_index` fits
/// in the merkle helper's `u32` index width, and the merkle path from
/// `payload.leaf_hash()` reaches `header.beacon_witness_root()`.
///
/// Trust source: the verified header carries 2f+1 source-shard
/// validators' BFT attestation over `beacon_witness_root`. A valid
/// inclusion proof against that root transitively attests the witness.
impl Verify<&Verified<CertifiedBlockHeader>> for ShardWitness {
    type Error = ShardWitnessVerifyError;

    fn verify(&self, ctx: &Verified<CertifiedBlockHeader>) -> Result<Verified<Self>, Self::Error> {
        let header = ctx.header();
        if self.proof.shard_id != header.shard_id() {
            return Err(ShardWitnessVerifyError::ShardIdMismatch);
        }
        if self.proof.committed_block_hash != ctx.block_hash() {
            return Err(ShardWitnessVerifyError::BlockHashMismatch);
        }
        let base = header.beacon_witness_base().inner();
        if self.proof.leaf_index.inner() < base {
            return Err(ShardWitnessVerifyError::LeafBelowWindow);
        }
        let position = u32::try_from(self.proof.leaf_index.inner() - base)
            .map_err(|_| ShardWitnessVerifyError::LeafIndexOverflow)?;
        if !verify_merkle_inclusion(
            *header.beacon_witness_root().as_raw(),
            self.payload.leaf_hash(),
            &self.proof.siblings,
            position,
        ) {
            return Err(ShardWitnessVerifyError::BadInclusion);
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_param_vote() -> ParamVote {
        use crate::{Epoch, NetworkParams, ParamProposal, ReshapeThresholds};
        ParamVote {
            pool: StakePoolId::new(5),
            proposal: Some(ParamProposal {
                params: NetworkParams {
                    reshape_thresholds: ReshapeThresholds { split_bytes: 4_096 },
                },
                activate_at: Epoch::new(9),
            }),
        }
    }

    fn sample_shard_witness() -> ShardWitness {
        ShardWitness {
            payload: ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(1),
                amount: Stake::from_whole_tokens(1_000_000),
            },
            proof: ShardWitnessProof {
                shard_id: ShardId::ROOT,
                committed_block_hash: BlockHash::ZERO,
                leaf_index: LeafIndex::new(42),
                siblings: Vec::new().into(),
            },
        }
    }

    #[test]
    fn shard_witness_payload_sbor_round_trip_all_variants() {
        let pubkey = Bls12381G1PublicKey([0xAB; 48]);
        let payloads = vec![
            ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(1),
                amount: Stake::from_whole_tokens(100),
            },
            ShardWitnessPayload::StakeWithdraw {
                pool_id: StakePoolId::new(2),
                amount: Stake::from_whole_tokens(50),
            },
            ShardWitnessPayload::RegisterValidator {
                pool_id: StakePoolId::new(3),
                validator_id: ValidatorId::new(7),
                pubkey,
            },
            ShardWitnessPayload::DeactivateValidator {
                validator_id: ValidatorId::new(8),
            },
            ShardWitnessPayload::Unjail {
                id: ValidatorId::new(10),
            },
            ShardWitnessPayload::Ready {
                id: ValidatorId::new(11),
            },
            ShardWitnessPayload::MissedProposal {
                proposer_id: ValidatorId::new(12),
                height: BlockHeight::new(99),
                round: Round::new(3),
            },
            ShardWitnessPayload::ScheduleSplit {
                shard: ShardId::leaf(2, 0b01),
            },
            ShardWitnessPayload::ScheduleMerge {
                parent: ShardId::leaf(1, 0b1),
            },
            ShardWitnessPayload::ReshapeReady {
                validator: ValidatorId::new(13),
            },
            ShardWitnessPayload::ParamVote(sample_param_vote()),
        ];
        for p in payloads {
            let bytes = basic_encode(&p).unwrap();
            let decoded: ShardWitnessPayload = basic_decode(&bytes).unwrap();
            assert_eq!(p, decoded);
        }
    }

    #[test]
    fn shard_witness_sbor_round_trip() {
        let w = sample_shard_witness();
        let bytes = basic_encode(&w).unwrap();
        let decoded: ShardWitness = basic_decode(&bytes).unwrap();
        assert_eq!(w, decoded);
    }

    /// A header whose root commits the window `[base, count)`: a proof
    /// built at the window-relative position verifies under its global
    /// `leaf_index`, and an index below the base is rejected outright.
    #[test]
    fn proof_positions_rebase_against_the_header_window() {
        use crate::{
            BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHeader, CertificateRoot, ChainOrigin,
            InFlightCount, LocalReceiptRoot, ProposerTimestamp, ProvisionsRoot, QuorumCertificate,
            Round, StateRoot, TransactionRoot, compute_merkle_root_with_proof,
        };

        let base = 5u64;
        let payloads: Vec<ShardWitnessPayload> = (0..3)
            .map(|i| ShardWitnessPayload::Ready {
                id: ValidatorId::new(i),
            })
            .collect();
        let window: Vec<Hash> = payloads
            .iter()
            .map(ShardWitnessPayload::leaf_hash)
            .collect();
        let (root, _, _) = compute_merkle_root_with_proof(&window, 0);

        let header = BlockHeader::new(
            ShardId::ROOT,
            BlockHeight::new(9),
            BlockHash::ZERO,
            QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT),
            ValidatorId::new(0),
            ProposerTimestamp::ZERO,
            Round::INITIAL,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::from_raw(root),
            BeaconWitnessLeafCount::new(base + window.len() as u64),
            BeaconWitnessLeafCount::new(base),
            None,
            None,
        );

        // Global leaf 6 sits at window position 1.
        let (_, siblings, _) = compute_merkle_root_with_proof(&window, 1);
        let witness = ShardWitness {
            payload: payloads[1].clone(),
            proof: ShardWitnessProof {
                shard_id: ShardId::ROOT,
                committed_block_hash: header.hash(),
                leaf_index: LeafIndex::new(base + 1),
                siblings: siblings.into(),
            },
        };
        assert!(witness.merkle_includes_in(&header));

        // The same path under an un-rebased (global) position fails.
        let mut global_position = witness.clone();
        global_position.proof.leaf_index = LeafIndex::new(1);
        assert!(!global_position.merkle_includes_in(&header));

        // An index below the window can't prove into the windowed root.
        let mut below_window = witness;
        below_window.proof.leaf_index = LeafIndex::new(base - 1);
        assert!(!below_window.merkle_includes_in(&header));
    }

    #[test]
    fn beacon_witness_event_sbor_round_trip_all_variants() {
        let pubkey = Bls12381G1PublicKey([0xCD; 48]);
        let events = vec![
            BeaconWitnessEvent::StakeDeposit {
                pool_id: StakePoolId::new(1),
                amount: Stake::from_whole_tokens(100),
            },
            BeaconWitnessEvent::StakeWithdraw {
                pool_id: StakePoolId::new(2),
                amount: Stake::from_whole_tokens(50),
            },
            BeaconWitnessEvent::RegisterValidator {
                pool_id: StakePoolId::new(3),
                validator_id: ValidatorId::new(7),
                pubkey,
            },
            BeaconWitnessEvent::DeactivateValidator {
                validator_id: ValidatorId::new(8),
            },
            BeaconWitnessEvent::Unjail {
                id: ValidatorId::new(10),
            },
            BeaconWitnessEvent::ParamVote(sample_param_vote()),
            // The clear case carries no proposal.
            BeaconWitnessEvent::ParamVote(ParamVote {
                pool: StakePoolId::new(5),
                proposal: None,
            }),
        ];
        for e in events {
            let bytes = basic_encode(&e).unwrap();
            let decoded: BeaconWitnessEvent = basic_decode(&bytes).unwrap();
            assert_eq!(e, decoded);
        }
    }

    #[test]
    fn beacon_witness_event_converts_to_shard_witness_payload() {
        let pubkey = Bls12381G1PublicKey([0xEF; 48]);
        let cases: Vec<(BeaconWitnessEvent, ShardWitnessPayload)> = vec![
            (
                BeaconWitnessEvent::StakeDeposit {
                    pool_id: StakePoolId::new(1),
                    amount: Stake::from_whole_tokens(100),
                },
                ShardWitnessPayload::StakeDeposit {
                    pool_id: StakePoolId::new(1),
                    amount: Stake::from_whole_tokens(100),
                },
            ),
            (
                BeaconWitnessEvent::StakeWithdraw {
                    pool_id: StakePoolId::new(2),
                    amount: Stake::from_whole_tokens(50),
                },
                ShardWitnessPayload::StakeWithdraw {
                    pool_id: StakePoolId::new(2),
                    amount: Stake::from_whole_tokens(50),
                },
            ),
            (
                BeaconWitnessEvent::RegisterValidator {
                    pool_id: StakePoolId::new(3),
                    validator_id: ValidatorId::new(7),
                    pubkey,
                },
                ShardWitnessPayload::RegisterValidator {
                    pool_id: StakePoolId::new(3),
                    validator_id: ValidatorId::new(7),
                    pubkey,
                },
            ),
            (
                BeaconWitnessEvent::DeactivateValidator {
                    validator_id: ValidatorId::new(8),
                },
                ShardWitnessPayload::DeactivateValidator {
                    validator_id: ValidatorId::new(8),
                },
            ),
            (
                BeaconWitnessEvent::Unjail {
                    id: ValidatorId::new(10),
                },
                ShardWitnessPayload::Unjail {
                    id: ValidatorId::new(10),
                },
            ),
            (
                BeaconWitnessEvent::ParamVote(sample_param_vote()),
                ShardWitnessPayload::ParamVote(sample_param_vote()),
            ),
        ];
        for (event, expected) in cases {
            assert_eq!(ShardWitnessPayload::from(event), expected);
        }
    }
}
