//! Beacon-chain shard-witness types.
//!
//! A [`ShardWitnessPayload`] is one event lifted from a shard's VM —
//! validator registrations, stake adjustments, missed-proposal
//! observations — appended as a leaf to that shard's monotonic
//! beacon-witness accumulator. Provenance is positional rather than
//! per-leaf: a
//! [`ShardEpochContribution`](crate::ShardEpochContribution) carries a
//! contiguous run of payloads with one range proof lifting them to the
//! boundary header's
//! [`BeaconWitnessRoot`](crate::BeaconWitnessRoot), so a payload cannot
//! claim a position the fold didn't ask for.

use hyperscale_hbor::{Hbor, to_vec as hbor_to_vec};

use crate::{
    BlockHeight, ConsensusPublicKey, ConsensusSignature, Epoch, Hash, ParamVote, Round, ShardId,
    Stake, StakePoolId, ValidatorId,
};

/// Domain tag for accumulator leaf hashing.
///
/// Tag-prefixing the HBOR encoding of the payload prevents the leaf
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
/// Provenance is carried by the enclosing chunk, not the payload: the
/// source shard comes from the boundary header and the leaf position from
/// the chunk's range.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
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
    /// support another activation at the current dynamic `min_stake`,
    /// or if `possession_proof` fails to prove possession of `pubkey`.
    RegisterValidator {
        /// Pool that operates this validator.
        pool_id: StakePoolId,
        /// Identifier the validator will be known by.
        validator_id: ValidatorId,
        /// 48-byte consensus public key.
        pubkey: ConsensusPublicKey,
        /// Proof-of-possession: the registrant's signature over
        /// `validator_possession_proof_message(network, validator_id, pubkey)` under
        /// `pubkey` itself. Verified by the beacon fold before the key
        /// enters the registry — the rogue-key defense every
        /// aggregate-signature verifier relies on.
        possession_proof: ConsensusSignature,
    },
    /// The pool operator deactivates one of their validator nodes.
    /// Transitions the validator out of any active role; if currently
    /// on a shard, frees the epoch for a pool draw. Dropped unless the
    /// named validator belongs to `pool_id`.
    DeactivateValidator {
        /// Pool speaking, and the one the validator must belong to.
        pool_id: StakePoolId,
        /// Validator being deactivated.
        validator_id: ValidatorId,
    },
    /// Validator took an unjail action on the staking contract.
    /// Beacon-side: if currently jailed under a fault-cause reason,
    /// the cooldown has elapsed, and the pool can still support the
    /// additional active epoch at the current dynamic `min_stake`,
    /// transition back to the pool. Otherwise silently dropped.
    /// A revoked key is never restored. Dropped unless the named
    /// validator belongs to `pool_id`.
    Unjail {
        /// Pool speaking, and the one the validator must belong to.
        pool_id: StakePoolId,
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
        /// The epoch the asserting block's committee is anchored in.
        ///
        /// What separates one assertion from the next. The shard's
        /// window dedup suppresses a leaf the window already carries,
        /// so a payload naming only its subject is one leaf for the
        /// life of the shard: the shard states its load once ever, and
        /// an assertion the beacon happened not to fold silences every
        /// one after it. The window is trimmed at a base resolved from
        /// this same anchor, so the two move together.
        epoch: Epoch,
    },
    /// The shard's committed substate byte total fell below the merge
    /// threshold. The beacon parks the assertion until the sibling's
    /// matching half folds, then schedules the merge under `parent`.
    ScheduleMerge {
        /// Parent the merged shard reforms under — always the source
        /// shard's own parent today; explicit for the same reason as
        /// [`Self::ScheduleSplit::shard`].
        parent: ShardId,
        /// The epoch the assertion was made in, for the reason
        /// [`Self::ScheduleSplit::epoch`] carries it.
        epoch: Epoch,
    },
    /// A cohort observer finished syncing its assigned pending child
    /// of the source shard and is ready for the reshape to execute.
    /// Rides the source shard's chain like [`Self::Ready`]; the beacon
    /// folds it into the pending reshape's per-child readiness, which
    /// gates execution. The source shard names the pending record; the
    /// attested `child` — carried up from the emitter's signed
    /// [`ReadySignal`](crate::ReadySignal) — names which successor the
    /// emitter synced. The fold credits the readiness only to a seat whose
    /// target equals `child`, so a signal retained across a reshape lapse
    /// cannot mark a seat the emitter re-staffed onto but never synced.
    ReshapeReady {
        /// Observer signalling sync completion.
        validator: ValidatorId,
        /// Successor shard the emitter attests it synced (a split child,
        /// or the child a merge keeper runs).
        child: ShardId,
    },
}

impl ShardWitnessPayload {
    /// Canonical accumulator leaf hash for this payload.
    ///
    /// Produces `BLAKE3(SHARD_WITNESS_LEAF_DOMAIN_TAG ‖ encode(self))`.
    /// Both the shard runtime (when computing
    /// [`BeaconWitnessRoot`](crate::BeaconWitnessRoot)) and the fetch
    /// responder (when constructing inclusion proofs) call this — the
    /// hash is the protocol-defined leaf format, not an
    /// implementation detail of either site.
    ///
    /// # Panics
    ///
    /// Panics if HBOR encoding fails. `ShardWitnessPayload` is a
    /// closed wire type and encoding is infallible in practice.
    #[must_use]
    pub fn leaf_hash(&self) -> Hash {
        let encoded = hbor_to_vec(self).expect("ShardWitnessPayload HBOR encode is infallible");
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
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
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
        /// 48-byte consensus public key.
        pubkey: ConsensusPublicKey,
        /// Proof-of-possession of `pubkey`; see
        /// [`ShardWitnessPayload::RegisterValidator`].
        possession_proof: ConsensusSignature,
    },
    /// Mirrors [`ShardWitnessPayload::DeactivateValidator`].
    DeactivateValidator {
        /// Pool speaking, and the one the validator must belong to.
        pool_id: StakePoolId,
        /// Validator being deactivated.
        validator_id: ValidatorId,
    },
    /// Mirrors [`ShardWitnessPayload::Unjail`].
    Unjail {
        /// Pool speaking, and the one the validator must belong to.
        pool_id: StakePoolId,
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
                possession_proof,
            } => Self::RegisterValidator {
                pool_id,
                validator_id,
                pubkey,
                possession_proof,
            },
            BeaconWitnessEvent::DeactivateValidator {
                pool_id,
                validator_id,
            } => Self::DeactivateValidator {
                pool_id,
                validator_id,
            },
            BeaconWitnessEvent::Unjail { pool_id, id } => Self::Unjail { pool_id, id },
            BeaconWitnessEvent::ParamVote(vote) => Self::ParamVote(vote),
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;

    fn sample_param_vote() -> ParamVote {
        use crate::{Epoch, NetworkParams, ParamProposal, ReshapeThresholds};
        ParamVote {
            pool: StakePoolId::new(5),
            proposal: Some(ParamProposal {
                params: NetworkParams {
                    reshape_thresholds: ReshapeThresholds {
                        split_bytes: 4_096,
                        split_fullness: u32::MAX,
                    },
                    ..NetworkParams::default()
                },
                activate_at: Epoch::new(9),
            }),
        }
    }

    #[test]
    fn shard_witness_payload_hbor_round_trip_all_variants() {
        let pubkey = ConsensusPublicKey::new([0xAB; 48]);
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
                possession_proof: ConsensusSignature::new([0xAB; 96]),
            },
            ShardWitnessPayload::DeactivateValidator {
                pool_id: StakePoolId::new(3),
                validator_id: ValidatorId::new(8),
            },
            ShardWitnessPayload::Unjail {
                pool_id: StakePoolId::new(3),
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
                epoch: Epoch::new(9),
            },
            ShardWitnessPayload::ScheduleMerge {
                parent: ShardId::leaf(1, 0b1),
                epoch: Epoch::new(9),
            },
            ShardWitnessPayload::ReshapeReady {
                validator: ValidatorId::new(13),
                child: ShardId::leaf(2, 0b01),
            },
            ShardWitnessPayload::ParamVote(sample_param_vote()),
        ];
        for p in payloads {
            let bytes = hbor_to_vec(&p).unwrap();
            let decoded: ShardWitnessPayload = hbor_from_slice(&bytes).unwrap();
            assert_eq!(p, decoded);
        }
    }

    #[test]
    fn beacon_witness_event_hbor_round_trip_all_variants() {
        let pubkey = ConsensusPublicKey::new([0xCD; 48]);
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
                possession_proof: ConsensusSignature::new([0xCD; 96]),
            },
            BeaconWitnessEvent::DeactivateValidator {
                pool_id: StakePoolId::new(3),
                validator_id: ValidatorId::new(8),
            },
            BeaconWitnessEvent::Unjail {
                pool_id: StakePoolId::new(3),
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
            let bytes = hbor_to_vec(&e).unwrap();
            let decoded: BeaconWitnessEvent = hbor_from_slice(&bytes).unwrap();
            assert_eq!(e, decoded);
        }
    }

    #[test]
    fn beacon_witness_event_converts_to_shard_witness_payload() {
        let pubkey = ConsensusPublicKey::new([0xEF; 48]);
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
                    possession_proof: ConsensusSignature::new([0xEF; 96]),
                },
                ShardWitnessPayload::RegisterValidator {
                    pool_id: StakePoolId::new(3),
                    validator_id: ValidatorId::new(7),
                    pubkey,
                    possession_proof: ConsensusSignature::new([0xEF; 96]),
                },
            ),
            (
                BeaconWitnessEvent::DeactivateValidator {
                    pool_id: StakePoolId::new(3),
                    validator_id: ValidatorId::new(8),
                },
                ShardWitnessPayload::DeactivateValidator {
                    pool_id: StakePoolId::new(3),
                    validator_id: ValidatorId::new(8),
                },
            ),
            (
                BeaconWitnessEvent::Unjail {
                    pool_id: StakePoolId::new(3),
                    id: ValidatorId::new(10),
                },
                ShardWitnessPayload::Unjail {
                    pool_id: StakePoolId::new(3),
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
