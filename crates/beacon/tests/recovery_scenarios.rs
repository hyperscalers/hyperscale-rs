//! Recovery-flow integration scenarios for the beacon chain.
//!
//! Exercises the end-to-end recovery path: a stalled committee, a
//! cert-bearing block, exclusion-aware committee resampling, and chain
//! continuation. Uses only the public API of `hyperscale_beacon` plus
//! the wire types — these tests double as usage documentation.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_beacon::constants::{BEACON_SIGNER_COUNT, MIN_STAKE_FLOOR};
use hyperscale_beacon::recovery::select_winning_block;
use hyperscale_beacon::state::{ApplyEpochInput, apply_epoch};
use hyperscale_types::{
    BeaconBlock, BeaconBlockHash, BeaconCert, BeaconState, Bls12381G1PrivateKey,
    Bls12381G1PublicKey, Bls12381G2Signature, CertifiedBeaconBlock, Epoch, Hash, NetworkDefinition,
    Randomness, RecoveryCertificate, RecoveryRound, ShardCommittee, ShardGroupId, SignerBitfield,
    SkipEpochCert, Stake, StakePool, StakePoolId, TransitionCause, ValidatorId, ValidatorRecord,
    ValidatorStatus, aggregate_verify_bls_different_messages, bls_keypair_from_seed,
    recovery_request_message,
};

const fn net() -> NetworkDefinition {
    NetworkDefinition::simulator()
}

fn keypair(seed: u64) -> Bls12381G1PrivateKey {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&seed.to_le_bytes());
    bls_keypair_from_seed(&s)
}

fn pubkey(seed: u64) -> Bls12381G1PublicKey {
    keypair(seed).public_key()
}

/// Build a state with `n` validators all `OnShard { ready: true }` on
/// shard 0, in a single pool with generous stake. Validator id `i` has
/// the keypair `keypair(i)`.
fn ready_state(n: u64) -> BeaconState {
    let pool_id = StakePoolId::new(0);
    let shard = ShardGroupId::new(0);

    let mut validators = BTreeMap::new();
    let mut pool_validators = BTreeSet::new();
    let mut members = Vec::new();
    for i in 0..n {
        let id = ValidatorId::new(i);
        members.push(id);
        pool_validators.insert(id);
        validators.insert(
            id,
            ValidatorRecord {
                id,
                pool: pool_id,
                status: ValidatorStatus::OnShard {
                    shard,
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
                registered_at_epoch: Epoch::GENESIS,
                pubkey: pubkey(i),
            },
        );
    }

    let mut pools = BTreeMap::new();
    pools.insert(
        pool_id,
        StakePool {
            id: pool_id,
            // Generous so `min_stake` stays at floor across epochs.
            total_stake: Stake::from_attos(u128::from(n) * MIN_STAKE_FLOOR.attos() * 4),
            validators: pool_validators,
            pending_withdrawals: Vec::new(),
        },
    );

    let mut shard_committees = BTreeMap::new();
    shard_committees.insert(shard, ShardCommittee { members });

    BeaconState {
        current_epoch: Epoch::GENESIS,
        validators,
        pools,
        randomness: Randomness::new([0x42; 32]),
        committee: Vec::new(),
        shard_committees,
        consumed_through: BTreeMap::new(),
        last_recovery_cert: None,
        miss_counters: BTreeMap::new(),
    }
}

/// Build a recovery cert signed by the first `signer_count` validators
/// against the current active pool of `pool_size`.
fn build_cert(
    pool_size: usize,
    signer_count: usize,
    anchor: BeaconBlockHash,
    anchor_epoch: Epoch,
    round: RecoveryRound,
    excluded: Vec<ValidatorId>,
) -> RecoveryCertificate {
    let keys: Vec<Bls12381G1PrivateKey> = (0..pool_size).map(|i| keypair(i as u64)).collect();
    let msg = recovery_request_message(&net(), &anchor, anchor_epoch, round);
    let sigs: Vec<Bls12381G2Signature> = keys
        .iter()
        .take(signer_count)
        .map(|sk| sk.sign_v1(&msg))
        .collect();
    let aggregate_sig = Bls12381G2Signature::aggregate(&sigs, true).expect("aggregate succeeds");
    let mut signers = SignerBitfield::new(pool_size);
    for i in 0..signer_count {
        signers.set(i);
    }
    RecoveryCertificate::new(
        anchor,
        anchor_epoch,
        round,
        excluded,
        signers,
        aggregate_sig,
    )
}

/// End-to-end catchup: chain advances normally, recovery cert lands at
/// epoch 4 after a stall, committee is resampled under the recovery
/// rule, then chain continues normally.
#[test]
fn catchup_brings_chain_forward_after_committee_stall() {
    let mut state = ready_state(7);

    // Three normal epochs.
    for e in 1u64..=3 {
        let effects = apply_epoch(
            &mut state,
            &net(),
            Epoch::new(e),
            ApplyEpochInput::Normal {
                committed: &[],
                recovery_cert: None,
            },
        );
        let transition = effects
            .beacon_committee_transition
            .expect("normal epoch always emits a committee transition");
        assert_eq!(
            transition.cause,
            TransitionCause::NaturalShuffle,
            "epoch {e}: expected NaturalShuffle cause on normal apply"
        );
    }
    assert!(state.last_recovery_cert.is_none());

    // Epoch 4: original committee stalls; recovery cert at round 0
    // assembled by the active-duty pool (7 validators, quorum 6).
    let anchor = BeaconBlockHash::from_raw(Hash::from_bytes(b"stall-anchor"));
    let cert = build_cert(
        7,
        7,
        anchor,
        Epoch::new(3),
        RecoveryRound::new(0),
        Vec::new(),
    );
    let effects = apply_epoch(
        &mut state,
        &net(),
        Epoch::new(4),
        ApplyEpochInput::Normal {
            committed: &[],
            recovery_cert: Some(&cert),
        },
    );

    let transition = effects
        .beacon_committee_transition
        .expect("recovery epoch emits a transition");
    assert_eq!(transition.cause, TransitionCause::Recovery);
    assert_eq!(transition.at_slot, Epoch::new(4));
    assert_eq!(
        state
            .last_recovery_cert
            .as_ref()
            .map(RecoveryCertificate::recovery_round),
        Some(RecoveryRound::new(0)),
    );
    assert_eq!(state.committee.len(), BEACON_SIGNER_COUNT);

    // Chain continues normally at epoch 5 (no cert).
    let effects = apply_epoch(
        &mut state,
        &net(),
        Epoch::new(5),
        ApplyEpochInput::Normal {
            committed: &[],
            recovery_cert: None,
        },
    );
    let transition = effects
        .beacon_committee_transition
        .expect("post-recovery epoch emits a transition");
    assert_eq!(transition.cause, TransitionCause::NaturalShuffle);
    // last_recovery_cert persists — the runner uses it for the next
    // monotonicity check at the same anchor.
    assert_eq!(
        state
            .last_recovery_cert
            .as_ref()
            .map(RecoveryCertificate::recovery_round),
        Some(RecoveryRound::new(0)),
    );
}

/// Pathological case: multiple recovery rounds happen off-chain at the
/// same anchor (round 0 fails, round 1 fails, round 2 succeeds). Only
/// the final cert lands on-chain, carrying the cumulative exclusions
/// of every failed round.
#[test]
fn cumulative_exclusions_via_high_round_cert() {
    let mut state = ready_state(10);
    let anchor = BeaconBlockHash::from_raw(Hash::from_bytes(b"path-anchor"));

    let excluded = vec![
        ValidatorId::new(0),
        ValidatorId::new(1),
        ValidatorId::new(2),
        ValidatorId::new(3),
    ];
    let cert = build_cert(
        10,
        10,
        anchor,
        Epoch::GENESIS,
        RecoveryRound::new(2),
        excluded.clone(),
    );

    apply_epoch(
        &mut state,
        &net(),
        Epoch::new(1),
        ApplyEpochInput::Normal {
            committed: &[],
            recovery_cert: Some(&cert),
        },
    );

    assert_eq!(
        state
            .last_recovery_cert
            .as_ref()
            .map(RecoveryCertificate::recovery_round),
        Some(RecoveryRound::new(2)),
    );
    for ex in &excluded {
        assert!(
            !state.committee.contains(ex),
            "excluded validator {ex:?} landed in the resampled committee"
        );
    }
    assert_eq!(state.committee.len(), BEACON_SIGNER_COUNT);
}

/// Stale-round replay: a cert at a lower round than `state.last_recovery_cert`
/// for the same anchor is silently dropped. State does not advance to
/// the stale cert; the higher-round cert remains canonical.
#[test]
fn stale_round_replay_at_same_anchor_is_dropped() {
    let mut state = ready_state(7);
    let anchor = BeaconBlockHash::from_raw(Hash::from_bytes(b"replay-anchor"));

    let high = build_cert(
        7,
        7,
        anchor,
        Epoch::GENESIS,
        RecoveryRound::new(3),
        Vec::new(),
    );
    apply_epoch(
        &mut state,
        &net(),
        Epoch::new(1),
        ApplyEpochInput::Normal {
            committed: &[],
            recovery_cert: Some(&high),
        },
    );
    assert_eq!(
        state
            .last_recovery_cert
            .as_ref()
            .map(RecoveryCertificate::recovery_round),
        Some(RecoveryRound::new(3)),
    );

    let stale_round = build_cert(
        7,
        7,
        anchor,
        Epoch::GENESIS,
        RecoveryRound::new(1),
        Vec::new(),
    );
    let effects = apply_epoch(
        &mut state,
        &net(),
        Epoch::new(2),
        ApplyEpochInput::Normal {
            committed: &[],
            recovery_cert: Some(&stale_round),
        },
    );
    let transition = effects.beacon_committee_transition.unwrap();
    assert_eq!(transition.cause, TransitionCause::NaturalShuffle);
    assert_eq!(
        state
            .last_recovery_cert
            .as_ref()
            .map(RecoveryCertificate::recovery_round),
        Some(RecoveryRound::new(3)),
    );
}

/// Block-selection race: at the same epoch, a cert-bearing block (the
/// recovery committee's output) wins over a no-cert block (a slow
/// original committee finally proposing). Pinned by the rule's
/// determinism — both honest validators converge regardless of network
/// arrival order. Block-cert verification isn't this rule's
/// responsibility, so a `Genesis` placeholder cert suffices.
#[test]
fn cert_bearing_block_wins_against_competing_no_cert_block() {
    let cert = build_cert(
        7,
        7,
        BeaconBlockHash::from_raw(Hash::from_bytes(b"race-anchor")),
        Epoch::GENESIS,
        RecoveryRound::new(0),
        Vec::new(),
    );

    // Both blocks are Skip-shaped to satisfy the wrapper's cert-body
    // pairing invariant cheaply — select_winning_block only inspects
    // the wrapper's `recovery_cert` side-data and the block hash.
    let skip_placeholder = || {
        SkipEpochCert::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"skip-anchor")),
            Epoch::new(1),
            SignerBitfield::new(4),
            Bls12381G2Signature([0u8; 96]),
        )
    };

    let cert_block = CertifiedBeaconBlock::new_unchecked(
        BeaconBlock::skip(
            Epoch::new(1),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"prev-cert")),
        ),
        BeaconCert::Skip(skip_placeholder()),
        Some(cert),
    );

    let original_block = CertifiedBeaconBlock::new_unchecked(
        BeaconBlock::skip(
            Epoch::new(1),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"prev-orig")),
        ),
        BeaconCert::Skip(skip_placeholder()),
        None,
    );

    assert_eq!(
        select_winning_block(&cert_block, &original_block).block_hash(),
        cert_block.block_hash(),
    );
    assert_eq!(
        select_winning_block(&original_block, &cert_block).block_hash(),
        cert_block.block_hash(),
    );
}

/// A signed `RecoveryRequest` message must reject when re-verified
/// against a different network's domain — cross-network replay
/// defense on the recovery path. Pin the property at the signing
/// layer so a future caller that bypasses `verify_recovery_cert`
/// still inherits cross-network rejection from the message builder.
#[test]
fn recovery_request_rejected_under_different_network() {
    let sk = keypair(1);
    let pk = sk.public_key();
    let anchor = BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor-recovery"));
    let epoch = Epoch::new(5);
    let round = RecoveryRound::new(0);

    let msg_sim = recovery_request_message(&net(), &anchor, epoch, round);
    let sig = sk.sign_v1(&msg_sim);

    // Signature verifies under the network the message was built for.
    assert!(aggregate_verify_bls_different_messages(
        &[msg_sim.as_slice()],
        &sig,
        &[pk],
    ));
    // Same signature against the mainnet-rebuilt message — different
    // bytes by the network-id byte — must reject.
    let msg_other = recovery_request_message(&NetworkDefinition::mainnet(), &anchor, epoch, round);
    assert!(!aggregate_verify_bls_different_messages(
        &[msg_other.as_slice()],
        &sig,
        &[pk],
    ));
}
