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
//! 1. **The emitter runs the stake pool's code.** The instance registry
//!    says what code each component runs, and only the stake pool package
//!    emits these facts.
//! 2. **The emitter stakes the protocol resource.** A pool's staked
//!    resource is its configuration, so an instance of the very same code
//!    staking a worthless token is not a pool: its deposits are not stake.
//!    The configuration is exactly the protocol resource and the founder,
//!    nothing more and nothing less.
//! 3. **The payload is exactly the shape its event index declares** — a
//!    total decode per index, with trailing bytes as fatal as missing
//!    ones.
//!
//! Anyone may found a pool: these are the whole of what makes one, and
//! the beacon's minimum stake decides what a pool can seat.
//!
//! Across all of them one rule holds: **the subject of a fact is its
//! emitter, never its payload.** The kernel stamps an emitter from the
//! invocation, so the pool a fact concerns is the instance that produced
//! it and no instance can name another, and its identifier is the
//! emitter's address. A payload carries the object of
//! the action — an amount, a validator — and never a pool. That is what
//! makes the warrant behind a fact "this package's code produced it"
//! rather than "someone wrote it down".
//!
//! A validator is an object a payload *can* get wrong, because a pool may
//! name one another pool operates. Nothing here can tell: which pool owns
//! a validator is beacon state, and this runs on a shard. The fact
//! carries its emitting pool and the fold refuses a validator that is not
//! that pool's.

use hyperscale_hbor::from_slice;
use hyperscale_types::{
    BeaconWitnessEvent, ConsensusPublicKey, ConsensusSignature, Epoch, Event, NetworkParams,
    ParamProposal, ParamVote, ReshapeThresholds, Stake, StakePoolId, ValidatorId,
};
use hyperscale_vm_effects::{ChainRecords, PackageHash, Value};
use hyperscale_vm_stdlib::staking as pool;
use hyperscale_vm_types::{ComponentAddr, PriceBounds};

use crate::PROTOCOL_RESOURCE;

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
    chain: &dyn ChainRecords,
    staking_package: PackageHash,
) -> Option<BeaconWitnessEvent> {
    // An emitter is whatever ran, so its class is checked here rather
    // than assumed: only a component emits a pool's events.
    let emitter = ComponentAddr::try_from(event.emitter).ok()?;
    let record = chain.instance(emitter.into())?;
    if record.package != staking_package || !stakes_protocol_resource(&record.config) {
        return None;
    }
    let pool_id = StakePoolId::of(emitter);
    // Decoded through the emitting package's own event types, so what
    // this reads is what that package says it wrote. A payload that does
    // not decode is a package whose code and metadata disagree — its
    // author's defect, and not a fact.
    let payload = &event.payload[..];
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

/// Whether a stake pool's configuration stakes the protocol resource: the
/// resource first, then the founder, and nothing else.
fn stakes_protocol_resource(config: &[Value]) -> bool {
    matches!(
        config,
        [Value::Address(staked), Value::Address(_)] if *staked == PROTOCOL_RESOURCE.address()
    )
}

/// The parameter change a cast backs, as the pool's own vote records it.
///
/// Whether the values are *admissible* is the fold's to judge, and it
/// does: bounds and a live activation epoch are checked where the vote is
/// recorded.
///
/// A vote names the whole parameter set, because the tally buckets by it
/// and two pools agree only if they agree on every row — so every
/// governed row is one the pool's vocabulary carries, and the literal
/// below is what makes the compiler ask again the next time one is
/// added.
///
/// The price band widens to the per-row interval here: a pool states how
/// far a price may travel from the reference table and the bounds are
/// that band applied to each row, so what the vote says is policy and
/// what the rows are worth against each other stays measurement.
const fn proposal_of(vote: &pool::ParamVote) -> ParamProposal {
    ParamProposal {
        params: NetworkParams {
            reshape_thresholds: ReshapeThresholds {
                split_bytes: vote.split_bytes,
                split_fullness: basis_points(vote.split_fullness),
            },
            impound_epochs: vote.impound_epochs,
            price_bounds: PriceBounds::band(
                basis_points(vote.price_floor_bp),
                basis_points(vote.price_ceiling_bp),
            ),
        },
        activate_at: Epoch::new(vote.activate_at),
    }
}

/// A pool's basis-point figure, narrowed to what a band takes.
///
/// A figure past the width saturates rather than wrapping: the fold
/// judges the resulting bounds on their own terms, and a wrapped one
/// would read as a band nobody voted for rather than as an
/// inadmissible one.
const fn basis_points(stated: u64) -> u32 {
    if stated > u32::MAX as u64 {
        u32::MAX
    } else {
        #[allow(clippy::cast_possible_truncation)] // guarded on the line above
        {
            stated as u32
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{Bytes, Capped};
    use hyperscale_types::CONSENSUS_PUBLIC_KEY_BYTES;
    use hyperscale_vm_effects::{Hash32, InstanceMeta, InstanceRegistry, Records};
    use hyperscale_vm_types::{Address, ComponentAddr, PrincipalAddr, ResourceAddr};

    use super::*;
    use crate::ProtocolHasher;

    fn package(tag: u8) -> PackageHash {
        PackageHash(Hash32([tag; 32]))
    }

    /// A resource that is not the protocol's.
    const WORTHLESS: ResourceAddr = ResourceAddr::new([0xEE; 31]);
    /// Who founded a test pool; any address does.
    const FOUNDER: PrincipalAddr = PrincipalAddr::new([0xF0; 31]);

    /// An instance of package 1 staking `staked`.
    fn instance(instances: &mut InstanceRegistry, salt: u8, staked: ResourceAddr) -> ComponentAddr {
        instances.create(
            &ProtocolHasher,
            InstanceMeta {
                package: package(1),
                config: Capped::new(vec![
                    Value::Address(staked.address()),
                    Value::Address(FOUNDER.address()),
                ])
                .unwrap(),
                salt: Hash32([salt; 32]),
            },
        )
    }

    /// A pool on the protocol resource, and an impostor running the same
    /// code over a worthless one.
    fn world() -> (Records, ComponentAddr, ComponentAddr) {
        let mut chain = Records::new();
        let pool = instance(&mut chain.instances, 1, *PROTOCOL_RESOURCE);
        let impostor = instance(&mut chain.instances, 2, WORTHLESS);
        (chain, pool, impostor)
    }

    fn event(emitter: impl Into<Address>, event_type: u32, amount: u128) -> Event {
        Event {
            emitter: emitter.into(),
            event_type,
            payload: Bytes::from_array(amount.to_le_bytes()),
        }
    }

    #[test]
    fn any_instance_running_the_pool_on_the_protocol_resource_is_a_pool() {
        let (instances, pool, _impostor) = world();
        assert_eq!(
            witness_from_event(&event(pool, STAKED, 500), &instances, package(1)),
            Some(BeaconWitnessEvent::StakeDeposit {
                pool_id: StakePoolId::of(pool),
                amount: Stake::from_quanta(500),
            }),
        );
        assert_eq!(
            witness_from_event(&event(pool, UNSTAKED, 40), &instances, package(1)),
            Some(BeaconWitnessEvent::StakeWithdraw {
                pool_id: StakePoolId::of(pool),
                amount: Stake::from_quanta(40),
            }),
        );
    }

    /// Running the pool's code is not enough: an instance of the very same
    /// package staking another resource takes deposits that are not stake,
    /// so it speaks to nobody.
    #[test]
    fn an_instance_staking_another_resource_is_not_a_pool() {
        let (instances, _pool, impostor) = world();
        assert_eq!(
            witness_from_event(&event(impostor, STAKED, 1_000_000), &instances, package(1)),
            None,
        );
    }

    /// And the converse: the protocol resource configured on code that is
    /// not the pool's speaks to nobody either.
    #[test]
    fn an_instance_running_other_code_is_not_a_pool() {
        let (instances, pool, _impostor) = world();
        assert_eq!(
            witness_from_event(&event(pool, STAKED, 500), &instances, package(2)),
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
            payload: payload
                .try_into()
                .expect("a payload the kernel carried fits its cap"),
        }
    }

    #[test]
    fn a_pools_operator_actions_read_as_beacon_facts() {
        let (instances, pool, _impostor) = world();
        let pool_id = StakePoolId::of(pool);
        assert_eq!(
            witness_from_event(
                &raw(pool, VALIDATOR_REGISTERED, registration_payload()),
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
        let (mut instances, _pool, _impostor) = world();
        let other = instance(&mut instances.instances, 3, *PROTOCOL_RESOURCE);
        let event = raw(other, VALIDATOR_REGISTERED, registration_payload());
        let Some(BeaconWitnessEvent::RegisterValidator { pool_id, .. }) =
            witness_from_event(&event, &instances, package(1))
        else {
            panic!("a pool's registration is a fact");
        };
        assert_eq!(pool_id, StakePoolId::of(other));
    }

    /// Trailing bytes are as fatal as missing ones: the decode is total
    /// per index, so a payload that is nearly right is not a fact.
    #[test]
    fn an_operator_payload_of_the_wrong_width_is_not_a_fact() {
        let (instances, pool, _impostor) = world();
        let mut long = registration_payload();
        long.push(0);
        let mut short = registration_payload();
        short.pop();
        for payload in [long, short, Vec::new(), VALIDATOR.to_le_bytes().to_vec()] {
            assert_eq!(
                witness_from_event(
                    &raw(pool, VALIDATOR_REGISTERED, payload),
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
    /// The fullness predicate off, which is what a vote about bytes
    /// says about load.
    const SPLIT_FULLNESS: u64 = u32::MAX as u64;
    const IMPOUND_EPOCHS: u64 = 30;
    const FLOOR_BP: u64 = 5_000;
    const CEILING_BP: u64 = 20_000;
    const ACTIVATE_AT: u64 = 12;

    fn cast_payload() -> Vec<u8> {
        [
            SPLIT_BYTES,
            SPLIT_FULLNESS,
            IMPOUND_EPOCHS,
            FLOOR_BP,
            CEILING_BP,
            ACTIVATE_AT,
        ]
        .iter()
        .flat_map(|field| field.to_le_bytes())
        .collect()
    }

    #[test]
    fn a_cast_vote_reads_as_the_proposal_it_backs() {
        let (instances, pool, _impostor) = world();
        assert_eq!(
            witness_from_event(
                &raw(pool, PARAM_VOTE_CAST, cast_payload()),
                &instances,
                package(1)
            ),
            Some(BeaconWitnessEvent::ParamVote(ParamVote {
                pool: StakePoolId::of(pool),
                proposal: Some(ParamProposal {
                    params: NetworkParams {
                        reshape_thresholds: ReshapeThresholds {
                            split_bytes: SPLIT_BYTES,
                            split_fullness: u32::MAX,
                        },
                        impound_epochs: IMPOUND_EPOCHS,
                        price_bounds: PriceBounds::band(
                            basis_points(FLOOR_BP),
                            basis_points(CEILING_BP),
                        ),
                    },
                    activate_at: Epoch::new(ACTIVATE_AT),
                }),
            })),
        );
    }

    /// The band a pool votes is what opens the controller: an even band
    /// pins every row where the reference table put it, and a wider one
    /// gives each row room to move on both sides.
    ///
    /// The rail end to end, since a chain is born pinned — without a
    /// vote that widens an interval the controller has nothing to do.
    #[test]
    fn the_band_a_pool_votes_is_what_opens_the_controller() {
        let (instances, pool, _impostor) = world();
        let bounds = |floor: u64, ceiling: u64| {
            let payload = [
                SPLIT_BYTES,
                SPLIT_FULLNESS,
                IMPOUND_EPOCHS,
                floor,
                ceiling,
                ACTIVATE_AT,
            ]
            .iter()
            .flat_map(|field| field.to_le_bytes())
            .collect();
            match witness_from_event(&raw(pool, PARAM_VOTE_CAST, payload), &instances, package(1)) {
                Some(BeaconWitnessEvent::ParamVote(vote)) => {
                    vote.proposal
                        .expect("a cast backs a proposal")
                        .params
                        .price_bounds
                }
                other => panic!("a cast reads as a vote: {other:?}"),
            }
        };

        let pinned = bounds(10_000, 10_000);
        assert_eq!(pinned, PriceBounds::GENESIS);
        assert_eq!(pinned.floor, pinned.ceiling, "a pinned row cannot move");

        let open = bounds(5_000, 20_000);
        assert!(open.well_formed());
        assert!(open.floor.compute < open.ceiling.compute);
        assert_eq!(
            open.floor.retention,
            PriceBounds::GENESIS.floor.retention / 2
        );
        assert_eq!(
            open.ceiling.retention,
            PriceBounds::GENESIS.ceiling.retention * 2
        );

        // A band the fold must never activate: a floor at nothing prices
        // a dimension free, which `validate` is what refuses.
        assert!(!bounds(0, 10_000).well_formed());
    }

    /// A pool backing nothing says so with nothing: an empty payload is
    /// the cleared vote, and any other payload on that index is not a
    /// fact at all.
    #[test]
    fn a_cleared_vote_carries_no_proposal_and_no_bytes() {
        let (instances, pool, _impostor) = world();
        assert_eq!(
            witness_from_event(
                &raw(pool, PARAM_VOTE_CLEARED, Vec::new()),
                &instances,
                package(1)
            ),
            Some(BeaconWitnessEvent::ParamVote(ParamVote {
                pool: StakePoolId::of(pool),
                proposal: None,
            })),
        );
        assert_eq!(
            witness_from_event(
                &raw(pool, PARAM_VOTE_CLEARED, cast_payload()),
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
        let (instances, pool, _impostor) = world();
        let payload = [0u64; 6]
            .iter()
            .flat_map(|field| field.to_le_bytes())
            .collect();
        let Some(BeaconWitnessEvent::ParamVote(vote)) =
            witness_from_event(&raw(pool, PARAM_VOTE_CAST, payload), &instances, package(1))
        else {
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
        let (instances, pool, _impostor) = world();
        let mut long = cast_payload();
        long.push(0);
        let mut short = cast_payload();
        short.pop();
        for payload in [long, short, Vec::new(), vec![0; 16]] {
            assert_eq!(
                witness_from_event(&raw(pool, PARAM_VOTE_CAST, payload), &instances, package(1)),
                None,
            );
        }
    }

    #[test]
    fn an_event_the_table_does_not_declare_is_not_a_fact() {
        let (instances, pool, _impostor) = world();
        assert_eq!(
            witness_from_event(&event(pool, 7, 500), &instances, package(1)),
            None,
        );
    }

    #[test]
    fn a_payload_that_is_not_an_amount_cell_is_not_a_fact() {
        let (instances, pool, _impostor) = world();
        for payload in [Vec::new(), vec![1; 8], vec![1; 17]] {
            let event = Event {
                emitter: pool.into(),
                event_type: STAKED,
                payload: payload.try_into().unwrap(),
            };
            assert_eq!(witness_from_event(&event, &instances, package(1)), None,);
        }
    }

    /// An emitter the chain holds no record for runs no code anyone can
    /// name: nothing it emits is a fact.
    #[test]
    fn an_instance_the_chain_does_not_hold_is_not_a_pool() {
        let (_, pool, _impostor) = world();
        assert_eq!(
            witness_from_event(&event(pool, STAKED, 500), &Records::new(), package(1)),
            None,
        );
    }
}
