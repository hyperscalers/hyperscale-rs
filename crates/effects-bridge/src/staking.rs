//! The stake pool's events read as beacon facts.
//!
//! The beacon's control plane consumes lifecycle facts — a pool gained
//! stake, a pool lost stake, a pool took on a validator — and the stake
//! pool package emits them as ordinary events. This module is the
//! whole of the trust boundary between those two statements: emission is
//! unprivileged, and every layer past this one is mechanical, so what a
//! witness is allowed to be is decided here and nowhere else.
//!
//! Three things must hold before an event is read as a fact, and they are
//! independent:
//!
//! 1. **The emitter is a recognised pool.** A pool the network folds stake
//!    for is one it was told about, not one that turned up. Anyone may
//!    instantiate the stake pool package; only recognised instances speak
//!    to the beacon.
//! 2. **The emitter runs the stake pool's code.** The registry says which
//!    instances count; the instance registry says what code each one runs.
//!    Checking both means neither alone is load-bearing for the other's
//!    claim.
//! 3. **The payload is exactly the shape its event index declares** — a
//!    total decode per index, with trailing bytes as fatal as missing
//!    ones.
//!
//! Across all of them one rule holds: **the subject of a fact is its
//! emitter, never its payload.** The kernel stamps an emitter from the
//! invocation, so the pool a fact concerns is the instance that produced
//! it and no instance can name another. A payload carries the object of
//! the action — an amount, a validator — and never a pool. That is what
//! makes the warrant behind a fact "this package's code produced it"
//! rather than "someone wrote it down".
//!
//! A validator is an object a payload *can* get wrong, because a pool may
//! name one another pool operates. Nothing here can tell: which pool owns
//! a validator is beacon state, and this runs on a shard. The fact
//! carries its emitting pool and the fold refuses a validator that is not
//! that pool's.

use std::collections::BTreeMap;

use hyperscale_hbor::from_slice;
use hyperscale_types::{
    BeaconWitnessEvent, ConsensusPublicKey, ConsensusSignature, Epoch, Event, NetworkParams,
    ParamProposal, ParamVote, ReshapeThresholds, Stake, StakePoolId, ValidatorId,
};
use hyperscale_vm_effects::{ChainRecords, PackageHash};
use hyperscale_vm_stdlib::staking as pool;
use hyperscale_vm_types::{Address, ComponentAddr};

/// The stake pool's event table, by the index its guest emits.
///
/// The order is the package's contract: `staking_metadata` declares the
/// names and the guest emits against them. A package is immutable and
/// content-addressed, so an index can never come to mean something else.
const STAKED: u32 = 0;
const UNSTAKED: u32 = 1;
const VALIDATOR_REGISTERED: u32 = 2;
const VALIDATOR_DEACTIVATED: u32 = 3;
const VALIDATOR_UNJAILED: u32 = 4;
const PARAM_VOTE_CAST: u32 = 5;
const PARAM_VOTE_CLEARED: u32 = 6;

/// The stake pools the beacon folds for: the instance address a fact must
/// come from, and the identifier it is folded under.
///
/// Genesis seeds it. A pool joining later is a governance act — the same
/// channel that admits a validator — because admitting a pool is admitting
/// a new source of beacon facts, which is not something a transaction
/// should be able to do on its own.
#[derive(Clone, Debug, Default)]
pub struct PoolRegistry {
    pools: BTreeMap<Address, StakePoolId>,
}

impl PoolRegistry {
    /// An empty registry: no instance speaks to the beacon.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pools: BTreeMap::new(),
        }
    }

    /// Recognise `address` as the pool the beacon folds under `id`.
    pub fn register(&mut self, address: impl Into<Address>, id: StakePoolId) {
        self.pools.insert(address.into(), id);
    }

    /// The pool `address` is recognised as, if any.
    #[must_use]
    pub fn pool_of(&self, address: impl Into<Address>) -> Option<StakePoolId> {
        self.pools.get(&address.into()).copied()
    }

    /// Whether any pool is recognised — the cheap guard that keeps a
    /// network with no staking surface from walking every event.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pools.is_empty()
    }
}

/// The beacon fact `event` records, or `None` if it is not one.
///
/// Total and side-effect-free: every rejection is a `None`, so a
/// malformed or unrecognised event is simply not a fact rather than an
/// error some caller has to decide what to do with. That matters because
/// this runs on the execution path, where a verdict that varied by caller
/// would vary by replica.
#[must_use]
pub fn witness_from_event(
    event: &Event,
    pools: &PoolRegistry,
    chain: &dyn ChainRecords,
    staking_package: PackageHash,
) -> Option<BeaconWitnessEvent> {
    let pool_id = pools.pool_of(event.emitter)?;
    // The registry says this instance counts; the instance registry says
    // what code it runs. A recognised address running someone else's code
    // is a genesis defect rather than a runtime condition, and it stays a
    // refusal rather than a panic because the execution path cannot take
    // a view on which of two authorities is wrong.
    // An emitter is whatever ran, so its class is checked here rather
    // than assumed: only a component emits a pool's events.
    let emitter = ComponentAddr::try_from(event.emitter).ok()?;
    if chain.instance(emitter.into())?.package != staking_package {
        return None;
    }
    // Decoded through the emitting package's own event types, so what
    // this reads is what that package says it wrote. A payload that does
    // not decode is a package whose code and metadata disagree — its
    // author's defect, and not a fact.
    let payload = event.payload.as_slice();
    match event.event_type {
        STAKED => {
            from_slice(payload)
                .ok()
                .map(|staked: pool::Staked| BeaconWitnessEvent::StakeDeposit {
                    pool_id,
                    amount: Stake::from_quanta(staked.amount.subunits()),
                })
        }
        UNSTAKED => from_slice(payload).ok().map(|unstaked: pool::Unstaked| {
            BeaconWitnessEvent::StakeWithdraw {
                pool_id,
                amount: Stake::from_quanta(unstaked.amount.subunits()),
            }
        }),
        VALIDATOR_REGISTERED => {
            from_slice(payload)
                .ok()
                .map(|registered: pool::ValidatorRegistered| {
                    BeaconWitnessEvent::RegisterValidator {
                        pool_id,
                        validator_id: ValidatorId::new(registered.validator_id),
                        pubkey: ConsensusPublicKey::new(registered.pubkey),
                        possession_proof: ConsensusSignature::new(registered.possession_proof),
                    }
                })
        }
        VALIDATOR_DEACTIVATED => {
            from_slice(payload)
                .ok()
                .map(|stood_down: pool::ValidatorDeactivated| {
                    BeaconWitnessEvent::DeactivateValidator {
                        pool_id,
                        validator_id: ValidatorId::new(stood_down.validator_id),
                    }
                })
        }
        VALIDATOR_UNJAILED => from_slice(payload)
            .ok()
            .map(
                |asked: pool::ValidatorUnjailed| BeaconWitnessEvent::Unjail {
                    pool_id,
                    id: ValidatorId::new(asked.validator_id),
                },
            ),
        PARAM_VOTE_CAST => from_slice(payload).ok().map(|cast: pool::ParamVoteCast| {
            BeaconWitnessEvent::ParamVote(ParamVote {
                pool: pool_id,
                proposal: Some(proposal_of(&cast.0)),
            })
        }),
        // A pool backing nothing says so with nothing.
        PARAM_VOTE_CLEARED if payload.is_empty() => {
            Some(BeaconWitnessEvent::ParamVote(ParamVote {
                pool: pool_id,
                proposal: None,
            }))
        }
        _ => None,
    }
}

/// The parameter change a cast backs, as the pool's own vote records it.
///
/// Whether the values are *admissible* is the fold's to judge, and it
/// does: bounds and a live activation epoch are checked where the vote is
/// recorded.
const fn proposal_of(vote: &pool::ParamVote) -> ParamProposal {
    ParamProposal {
        params: NetworkParams {
            reshape_thresholds: ReshapeThresholds {
                split_bytes: vote.split_bytes,
            },
            impound_epochs: vote.impound_epochs,
        },
        activate_at: Epoch::new(vote.activate_at),
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::CONSENSUS_PUBLIC_KEY_BYTES;
    use hyperscale_vm_effects::{Hash32, InstanceMeta, InstanceRegistry, Records};
    use hyperscale_vm_types::{Address, ComponentAddr};

    use super::*;
    use crate::ProtocolHasher;

    const POOL_ID: u32 = 7;

    fn package(tag: u8) -> PackageHash {
        PackageHash(Hash32([tag; 32]))
    }

    fn instance(instances: &mut InstanceRegistry, salt: u8) -> ComponentAddr {
        instances.create(
            &ProtocolHasher,
            InstanceMeta {
                package: package(1),
                config: Vec::new(),
                salt: Hash32([salt; 32]),
            },
        )
    }

    fn world() -> (PoolRegistry, Records, ComponentAddr, ComponentAddr) {
        let mut chain = Records::new();
        let pool = instance(&mut chain.instances, 1);
        let impostor = instance(&mut chain.instances, 2);
        let mut pools = PoolRegistry::new();
        pools.register(pool, StakePoolId::new(POOL_ID));
        (pools, chain, pool, impostor)
    }

    fn event(emitter: impl Into<Address>, event_type: u32, amount: u128) -> Event {
        Event {
            emitter: emitter.into(),
            event_type,
            payload: amount.to_le_bytes().to_vec(),
        }
    }

    #[test]
    fn a_recognised_pools_events_read_as_beacon_facts() {
        let (pools, instances, pool, _impostor) = world();
        assert_eq!(
            witness_from_event(&event(pool, STAKED, 500), &pools, &instances, package(1)),
            Some(BeaconWitnessEvent::StakeDeposit {
                pool_id: StakePoolId::new(POOL_ID),
                amount: Stake::from_quanta(500),
            }),
        );
        assert_eq!(
            witness_from_event(&event(pool, UNSTAKED, 40), &pools, &instances, package(1)),
            Some(BeaconWitnessEvent::StakeWithdraw {
                pool_id: StakePoolId::new(POOL_ID),
                amount: Stake::from_quanta(40),
            }),
        );
    }

    /// The whole point of the registry: running the pool's code is not
    /// enough. An unrecognised instance of the very same package — which
    /// anyone may create — speaks to nobody.
    #[test]
    fn an_unrecognised_instance_of_the_same_package_is_not_a_pool() {
        let (pools, instances, _pool, impostor) = world();
        assert_eq!(
            witness_from_event(
                &event(impostor, STAKED, 1_000_000),
                &pools,
                &instances,
                package(1)
            ),
            None,
        );
    }

    /// And the converse: a recognised address running code that is not the
    /// pool's speaks to nobody either, so neither authority is trusted to
    /// carry the other's claim.
    #[test]
    fn a_recognised_address_running_other_code_is_not_a_pool() {
        let (pools, instances, pool, _impostor) = world();
        assert_eq!(
            witness_from_event(&event(pool, STAKED, 500), &pools, &instances, package(2)),
            None,
        );
    }

    const VALIDATOR: u64 = 42;
    const PUBKEY: [u8; CONSENSUS_PUBLIC_KEY_BYTES] = [0xC1; CONSENSUS_PUBLIC_KEY_BYTES];
    const PROOF: [u8; 96] = [0xC2; 96];

    /// The bytes the pool's guest concatenates for a registration.
    fn registration_payload() -> Vec<u8> {
        let mut payload = VALIDATOR.to_le_bytes().to_vec();
        payload.extend_from_slice(&PUBKEY);
        payload.extend_from_slice(&PROOF);
        payload
    }

    fn raw(emitter: impl Into<Address>, event_type: u32, payload: Vec<u8>) -> Event {
        Event {
            emitter: emitter.into(),
            event_type,
            payload,
        }
    }

    #[test]
    fn a_recognised_pools_operator_actions_read_as_beacon_facts() {
        let (pools, instances, pool, _impostor) = world();
        let pool_id = StakePoolId::new(POOL_ID);
        assert_eq!(
            witness_from_event(
                &raw(pool, VALIDATOR_REGISTERED, registration_payload()),
                &pools,
                &instances,
                package(1)
            ),
            Some(BeaconWitnessEvent::RegisterValidator {
                pool_id,
                validator_id: ValidatorId::new(VALIDATOR),
                pubkey: ConsensusPublicKey::new(PUBKEY),
                possession_proof: ConsensusSignature::new(PROOF),
            }),
        );
        let named = VALIDATOR.to_le_bytes().to_vec();
        assert_eq!(
            witness_from_event(
                &raw(pool, VALIDATOR_DEACTIVATED, named.clone()),
                &pools,
                &instances,
                package(1)
            ),
            Some(BeaconWitnessEvent::DeactivateValidator {
                pool_id,
                validator_id: ValidatorId::new(VALIDATOR),
            }),
        );
        assert_eq!(
            witness_from_event(
                &raw(pool, VALIDATOR_UNJAILED, named),
                &pools,
                &instances,
                package(1)
            ),
            Some(BeaconWitnessEvent::Unjail {
                pool_id,
                id: ValidatorId::new(VALIDATOR),
            }),
        );
    }

    /// The pool a fact concerns is never a field of it. An operator
    /// action carries a validator and its consensus material and nothing
    /// that names a pool, so the emitter stamp is the only thing that
    /// could have said which pool spoke.
    #[test]
    fn an_operator_action_is_folded_under_its_emitter() {
        let (mut pools, instances, _pool, impostor) = world();
        pools.register(impostor, StakePoolId::new(POOL_ID + 1));
        let event = raw(impostor, VALIDATOR_REGISTERED, registration_payload());
        let Some(BeaconWitnessEvent::RegisterValidator { pool_id, .. }) =
            witness_from_event(&event, &pools, &instances, package(1))
        else {
            panic!("a recognised emitter's registration is a fact");
        };
        assert_eq!(pool_id, StakePoolId::new(POOL_ID + 1));
    }

    /// Trailing bytes are as fatal as missing ones: the decode is total
    /// per index, so a payload that is nearly right is not a fact.
    #[test]
    fn an_operator_payload_of_the_wrong_width_is_not_a_fact() {
        let (pools, instances, pool, _impostor) = world();
        let mut long = registration_payload();
        long.push(0);
        let mut short = registration_payload();
        short.pop();
        for payload in [long, short, Vec::new(), VALIDATOR.to_le_bytes().to_vec()] {
            assert_eq!(
                witness_from_event(
                    &raw(pool, VALIDATOR_REGISTERED, payload),
                    &pools,
                    &instances,
                    package(1)
                ),
                None,
            );
        }
        for payload in [vec![1; 7], vec![1; 9], Vec::new()] {
            for event_type in [VALIDATOR_DEACTIVATED, VALIDATOR_UNJAILED] {
                assert_eq!(
                    witness_from_event(
                        &raw(pool, event_type, payload.clone()),
                        &pools,
                        &instances,
                        package(1)
                    ),
                    None,
                );
            }
        }
    }

    /// The governed parameters, in the order the package declares them.
    const SPLIT_BYTES: u64 = 9_000;
    const IMPOUND_EPOCHS: u64 = 30;
    const ACTIVATE_AT: u64 = 12;

    fn cast_payload() -> Vec<u8> {
        let mut payload = SPLIT_BYTES.to_le_bytes().to_vec();
        payload.extend_from_slice(&IMPOUND_EPOCHS.to_le_bytes());
        payload.extend_from_slice(&ACTIVATE_AT.to_le_bytes());
        payload
    }

    #[test]
    fn a_cast_vote_reads_as_the_proposal_it_backs() {
        let (pools, instances, pool, _impostor) = world();
        assert_eq!(
            witness_from_event(
                &raw(pool, PARAM_VOTE_CAST, cast_payload()),
                &pools,
                &instances,
                package(1)
            ),
            Some(BeaconWitnessEvent::ParamVote(ParamVote {
                pool: StakePoolId::new(POOL_ID),
                proposal: Some(ParamProposal {
                    params: NetworkParams {
                        reshape_thresholds: ReshapeThresholds {
                            split_bytes: SPLIT_BYTES
                        },
                        impound_epochs: IMPOUND_EPOCHS,
                    },
                    activate_at: Epoch::new(ACTIVATE_AT),
                }),
            })),
        );
    }

    /// A pool backing nothing says so with nothing: an empty payload is
    /// the cleared vote, and any other payload on that index is not a
    /// fact at all.
    #[test]
    fn a_cleared_vote_carries_no_proposal_and_no_bytes() {
        let (pools, instances, pool, _impostor) = world();
        assert_eq!(
            witness_from_event(
                &raw(pool, PARAM_VOTE_CLEARED, Vec::new()),
                &pools,
                &instances,
                package(1)
            ),
            Some(BeaconWitnessEvent::ParamVote(ParamVote {
                pool: StakePoolId::new(POOL_ID),
                proposal: None,
            })),
        );
        assert_eq!(
            witness_from_event(
                &raw(pool, PARAM_VOTE_CLEARED, cast_payload()),
                &pools,
                &instances,
                package(1)
            ),
            None,
        );
    }

    /// Out-of-bounds values still read as a proposal here. Whether a
    /// proposal may be recorded is the fold's judgement, made against
    /// state this side cannot see; reading is not admitting.
    #[test]
    fn a_vote_the_fold_will_reject_still_reads_as_a_vote() {
        let (pools, instances, pool, _impostor) = world();
        let mut payload = 0u64.to_le_bytes().to_vec();
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.extend_from_slice(&0u64.to_le_bytes());
        let Some(BeaconWitnessEvent::ParamVote(vote)) = witness_from_event(
            &raw(pool, PARAM_VOTE_CAST, payload),
            &pools,
            &instances,
            package(1),
        ) else {
            panic!("a well-formed payload is a fact whatever it proposes");
        };
        assert!(
            vote.proposal
                .expect("a cast carries a proposal")
                .params
                .validate()
                .is_err(),
        );
    }

    #[test]
    fn a_vote_payload_of_the_wrong_width_is_not_a_fact() {
        let (pools, instances, pool, _impostor) = world();
        let mut long = cast_payload();
        long.push(0);
        let mut short = cast_payload();
        short.pop();
        for payload in [long, short, Vec::new(), vec![0; 16]] {
            assert_eq!(
                witness_from_event(
                    &raw(pool, PARAM_VOTE_CAST, payload),
                    &pools,
                    &instances,
                    package(1)
                ),
                None,
            );
        }
    }

    #[test]
    fn an_event_the_table_does_not_declare_is_not_a_fact() {
        let (pools, instances, pool, _impostor) = world();
        assert_eq!(
            witness_from_event(&event(pool, 7, 500), &pools, &instances, package(1)),
            None,
        );
    }

    #[test]
    fn a_payload_that_is_not_an_amount_cell_is_not_a_fact() {
        let (pools, instances, pool, _impostor) = world();
        for payload in [Vec::new(), vec![1; 8], vec![1; 17]] {
            let event = Event {
                emitter: pool.into(),
                event_type: STAKED,
                payload,
            };
            assert_eq!(
                witness_from_event(&event, &pools, &instances, package(1)),
                None,
            );
        }
    }

    /// An empty registry is the state every network starts in and the one
    /// a network without staking stays in: nothing is a fact.
    #[test]
    fn an_empty_registry_recognises_nothing() {
        let (_, instances, pool, _impostor) = world();
        let pools = PoolRegistry::new();
        assert!(pools.is_empty());
        assert_eq!(
            witness_from_event(&event(pool, STAKED, 500), &pools, &instances, package(1)),
            None,
        );
    }
}
