//! Public-API contract tests for `ShardCoordinator`.
//!
//! These tests see only the crate's public surface (`use hyperscale_shard::...`),
//! so any regression in the documented API is caught here rather than by
//! inline tests that can reach into private fields.

use std::sync::Arc;

use hyperscale_crypto_bls::BlsVerifier;
use hyperscale_shard::{ShardConsensusConfig, ShardCoordinator, ShardMemoryStats, ShardStats};
use hyperscale_storage::{RecoveredState, SafeVoteRegisterStore};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::test_utils::TestCommittee;
use hyperscale_types::{
    BlockHeight, IDLE_PROPOSAL_INTERVAL, LocalTimestamp, Round, SafeVoteRegisters, ShardId,
    TopologySchedule, VIEW_CHANGE_TIMEOUT_DEFAULT, ValidatorId, VotePosition, shard_prefix_path,
};

fn fresh_coordinator(config: ShardConsensusConfig) -> ShardCoordinator {
    fresh_coordinator_with_topology(config).0
}

fn fresh_coordinator_with_topology(
    config: ShardConsensusConfig,
) -> (ShardCoordinator, TopologySchedule) {
    let topology_schedule =
        TopologySchedule::single(Arc::new(TestCommittee::new(4, 42).topology_snapshot(1)));
    let coordinator = signed_by(&topology_schedule, ValidatorId::new(0), config);
    (coordinator, topology_schedule)
}

/// A fresh replica with `me` attached and no durable record.
fn signed_by(
    topology_schedule: &TopologySchedule,
    me: ValidatorId,
    config: ShardConsensusConfig,
) -> ShardCoordinator {
    let mut coordinator = ShardCoordinator::new(
        Arc::new(BlsVerifier),
        ShardId::ROOT,
        config,
        RecoveredState::default(),
    );
    let _ = coordinator.attach_signer(topology_schedule, me, None, Round::INITIAL);
    coordinator
}

#[test]
fn fresh_coordinator_reports_genesis_chain_state() {
    let coordinator = fresh_coordinator(ShardConsensusConfig::default());

    assert_eq!(coordinator.committed_height(), BlockHeight::GENESIS);
    assert!(coordinator.latest_qc().is_none());
    // Rounds increase per block: the genesis QC is round 0, so the first block
    // is proposed in round 1 — the fresh view.
    assert_eq!(coordinator.view(), Round::new(1));
    assert!(!coordinator.is_block_syncing());
}

/// The first round is the one after the genesis QC, whose leader may
/// hold an empty block for the idle interval.
#[test]
fn current_view_change_timeout_at_initial_round_is_the_default_and_the_idle_allowance() {
    let coordinator = fresh_coordinator(ShardConsensusConfig::default());

    assert_eq!(
        coordinator.current_view_change_timeout(),
        VIEW_CHANGE_TIMEOUT_DEFAULT + IDLE_PROPOSAL_INTERVAL
    );
}

#[test]
fn memory_stats_reports_all_zeros_for_fresh_coordinator() {
    let coordinator = fresh_coordinator(ShardConsensusConfig::default());
    let ShardMemoryStats {
        pending_blocks,
        vote_sets,
        pending_commits,
        pending_commits_awaiting_data,
        received_votes_by_height,
        dedup_window_complete,
        committed_resolution_lookup,
        committed_provision_lookup,
        pending_qc_verifications,
        verified_qcs,
        pending_state_root_verifications,
        buffered_synced_blocks,
        pending_synced_block_verifications,
        pending_assemblies,
    } = coordinator.memory_stats();

    assert_eq!(pending_blocks, 0);
    assert_eq!(vote_sets, 0);
    assert_eq!(pending_commits, 0);
    assert_eq!(pending_commits_awaiting_data, 0);
    assert_eq!(received_votes_by_height, 0);
    assert!(
        dedup_window_complete,
        "a chain with no committed tip has nothing beneath it to have missed",
    );
    assert_eq!(committed_resolution_lookup, 0);
    assert_eq!(committed_provision_lookup, 0);
    assert_eq!(pending_qc_verifications, 0);
    assert_eq!(verified_qcs, 0);
    assert_eq!(pending_state_root_verifications, 0);
    assert_eq!(buffered_synced_blocks, 0);
    assert_eq!(pending_synced_block_verifications, 0);
    assert_eq!(pending_assemblies, 0);
}

#[test]
fn stats_reports_initial_defaults() {
    let coordinator = fresh_coordinator(ShardConsensusConfig::default());
    let ShardStats {
        view_changes,
        view_syncs,
        current_round,
        committed_height,
        delay_estimate,
        base_timeout,
    } = coordinator.stats();

    assert_eq!(view_changes, 0);
    assert_eq!(view_syncs, 0);
    assert_eq!(current_round, Round::new(1).inner());
    assert_eq!(committed_height, BlockHeight::GENESIS);
    assert_eq!(delay_estimate, None);
    assert_eq!(base_timeout, VIEW_CHANGE_TIMEOUT_DEFAULT);
}

#[test]
fn is_current_proposer_matches_topology() {
    let committee = TestCommittee::new(4, 42);

    // At round 1 the proposer rotation picks committee[1 % 4] = V1.
    // Each validator's coordinator should answer `is_current_proposer` consistently
    // with `topology_schedule.proposer_for(shard, round) == me` for that validator.
    for local_idx in 0_u32..4 {
        let topology_schedule = TopologySchedule::single(Arc::new(committee.topology_snapshot(1)));
        let me = ValidatorId::new(u64::from(local_idx));
        let local_shard = ShardId::ROOT;
        let coordinator = signed_by(&topology_schedule, me, ShardConsensusConfig::default());
        // Fresh coordinator: latest_qc is None → next height = committed_height + 1 = 1.
        // Rounds increase per block, so the fresh view is round 1.
        let expected = topology_schedule
            .head()
            .proposer_for(local_shard, Round::new(1))
            == me;
        assert_eq!(
            coordinator.is_current_proposer(&topology_schedule),
            expected,
            "V{local_idx}: is_current_proposer must agree with proposer_for"
        );
    }
}

#[test]
fn will_propose_next_is_true_for_exactly_one_validator_in_fresh_committee() {
    // Fresh committee: no votes recorded, so `will_propose_next` reduces to
    // "am I the proposer for the next height?" Exactly one validator answers
    // true across the committee rotation.
    let committee = TestCommittee::new(4, 42);
    let mut proposers = 0usize;
    for local_idx in 0_u32..4 {
        let topology_schedule = TopologySchedule::single(Arc::new(committee.topology_snapshot(1)));
        let coordinator = signed_by(
            &topology_schedule,
            ValidatorId::new(u64::from(local_idx)),
            ShardConsensusConfig::default(),
        );
        if coordinator.will_propose_next(&topology_schedule) {
            proposers += 1;
        }
    }
    assert_eq!(
        proposers, 1,
        "exactly one validator must report will_propose_next in a fresh committee"
    );
}

#[test]
fn on_block_persisted_returns_no_actions_when_not_syncing() {
    let (mut coordinator, topology_schedule) =
        fresh_coordinator_with_topology(ShardConsensusConfig::default());

    let actions = coordinator.on_block_persisted(&topology_schedule, BlockHeight::new(1), 0, None);
    assert!(actions.is_empty());
    assert!(!coordinator.is_block_syncing());
}

#[test]
fn check_round_timeout_does_not_fire_without_recorded_activity() {
    let (mut coordinator, topology_schedule) =
        fresh_coordinator_with_topology(ShardConsensusConfig::default());

    // A fresh coordinator has no leader-activity timestamp; `check_round_timeout`
    // must not fire a view change because there's no baseline to time-out
    // against.
    coordinator.set_time(LocalTimestamp::from_millis(3_600_000));
    assert!(
        coordinator
            .check_round_timeout(&topology_schedule)
            .is_none()
    );
}

/// A signer's durable record floors the registers it attaches with: the
/// coordinator must never sign below a position the record says it
/// already consumed.
#[test]
fn recovered_registers_floor_boot_values() {
    let me = ValidatorId::new(0);
    let store = SimShardStorage::new(shard_prefix_path(ShardId::ROOT));
    store.persist_vote_position(me, &consumed(3, 7));
    let (mut coordinator, topology_schedule) =
        unsigned_coordinator_with_topology(ShardConsensusConfig::default());

    let _ = coordinator.attach_signer(
        &topology_schedule,
        me,
        store.safe_vote_registers(me),
        Round::INITIAL,
    );

    let position = coordinator.position(me).expect("attached");
    assert_eq!(position.locked_round, Round::new(3));
    assert_eq!(position.last_voted_round, Round::new(7));
}

/// Register records are per validator: another validator's record on the
/// same (shared, co-hosted) store does not reach this signer's registers.
#[test]
fn recovered_registers_of_other_validators_are_ignored() {
    let me = ValidatorId::new(0);
    let store = SimShardStorage::new(shard_prefix_path(ShardId::ROOT));
    store.persist_vote_position(ValidatorId::new(9), &consumed(3, 7));
    let (mut coordinator, topology_schedule) =
        unsigned_coordinator_with_topology(ShardConsensusConfig::default());

    let _ = coordinator.attach_signer(
        &topology_schedule,
        me,
        store.safe_vote_registers(me),
        Round::INITIAL,
    );

    // No record for this validator and no recovered QC: both registers
    // boot at the genesis QC's round.
    let position = coordinator.position(me).expect("attached");
    assert_eq!(position.locked_round, Round::INITIAL);
    assert_eq!(position.last_voted_round, Round::INITIAL);
}

fn unsigned_coordinator_with_topology(
    config: ShardConsensusConfig,
) -> (ShardCoordinator, TopologySchedule) {
    let topology_schedule =
        TopologySchedule::single(Arc::new(TestCommittee::new(4, 42).topology_snapshot(1)));
    let coordinator = ShardCoordinator::new(
        Arc::new(BlsVerifier),
        ShardId::ROOT,
        config,
        RecoveredState::default(),
    );
    (coordinator, topology_schedule)
}

/// A position whose signer locked at `locked` and voted through `voted`.
const fn consumed(locked: u64, voted: u64) -> VotePosition {
    VotePosition {
        registers: SafeVoteRegisters {
            locked_round: Round::new(locked),
            last_voted_round: Round::new(voted),
            high_qc: None,
            high_tc: None,
        },
        justification: Vec::new(),
    }
}
