//! Public-API contract tests for `ShardCoordinator`.
//!
//! These tests see only the crate's public surface (`use hyperscale_shard::...`),
//! so any regression in the documented API is caught here rather than by
//! inline tests that can reach into private fields.

use hyperscale_shard::{ShardConsensusConfig, ShardCoordinator, ShardMemoryStats, ShardStats};
use hyperscale_storage::RecoveredState;
use hyperscale_test_helpers::TestCommittee;
use hyperscale_types::{
    BlockHeight, LocalTimestamp, Round, ShardGroupId, TopologySnapshot, VIEW_CHANGE_TIMEOUT,
    ValidatorId,
};

fn fresh_coordinator(config: ShardConsensusConfig) -> ShardCoordinator {
    ShardCoordinator::new(
        ValidatorId::new(0),
        ShardGroupId::new(0),
        config,
        RecoveredState::default(),
    )
}

fn fresh_coordinator_with_topology(
    config: ShardConsensusConfig,
) -> (ShardCoordinator, TopologySnapshot) {
    let topology = TestCommittee::new(4, 42).topology_snapshot(1);
    (fresh_coordinator(config), topology)
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

#[test]
fn current_view_change_timeout_at_initial_round_is_protocol_base() {
    let coordinator = fresh_coordinator(ShardConsensusConfig::default());

    assert_eq!(
        coordinator.current_view_change_timeout(),
        VIEW_CHANGE_TIMEOUT
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
        voted_heights,
        received_votes_by_height,
        committed_tx_lookup,
        committed_cert_lookup,
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
    assert_eq!(voted_heights, 0);
    assert_eq!(received_votes_by_height, 0);
    assert_eq!(committed_tx_lookup, 0);
    assert_eq!(committed_cert_lookup, 0);
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
    } = coordinator.stats();

    assert_eq!(view_changes, 0);
    assert_eq!(view_syncs, 0);
    assert_eq!(current_round, Round::new(1).inner());
    assert_eq!(committed_height, BlockHeight::GENESIS);
}

#[test]
fn is_current_proposer_matches_topology() {
    let committee = TestCommittee::new(4, 42);

    // At round 1 the proposer rotation picks committee[1 % 4] = V1.
    // Each validator's coordinator should answer `is_current_proposer` consistently
    // with `topology.proposer_for(shard, round) == me` for that validator.
    for local_idx in 0_u32..4 {
        let topology = committee.topology_snapshot(1);
        let me = ValidatorId::new(u64::from(local_idx));
        let local_shard = ShardGroupId::new(0);
        let coordinator = ShardCoordinator::new(
            me,
            local_shard,
            ShardConsensusConfig::default(),
            RecoveredState::default(),
        );
        // Fresh coordinator: latest_qc is None → next height = committed_height + 1 = 1.
        // Rounds increase per block, so the fresh view is round 1.
        let expected = topology.proposer_for(local_shard, Round::new(1)) == me;
        assert_eq!(
            coordinator.is_current_proposer(&topology),
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
        let topology = committee.topology_snapshot(1);
        let coordinator = ShardCoordinator::new(
            ValidatorId::new(u64::from(local_idx)),
            ShardGroupId::new(0),
            ShardConsensusConfig::default(),
            RecoveredState::default(),
        );
        if coordinator.will_propose_next(&topology) {
            proposers += 1;
        }
    }
    assert_eq!(
        proposers, 1,
        "exactly one validator must report will_propose_next in a fresh committee"
    );
}

#[test]
fn proposal_parent_block_hash_falls_back_to_committed_hash_without_qc() {
    let coordinator = fresh_coordinator(ShardConsensusConfig::default());

    assert!(coordinator.latest_qc().is_none());
    assert_eq!(
        coordinator.proposal_parent_block_hash(),
        coordinator.committed_hash()
    );
}

#[test]
fn on_block_persisted_returns_no_actions_when_not_syncing() {
    let (mut coordinator, _topology) =
        fresh_coordinator_with_topology(ShardConsensusConfig::default());

    let actions = coordinator.on_block_persisted(BlockHeight::new(1));
    assert!(actions.is_empty());
    assert!(!coordinator.is_block_syncing());
}

#[test]
fn check_round_timeout_does_not_fire_without_recorded_activity() {
    let (mut coordinator, topology) =
        fresh_coordinator_with_topology(ShardConsensusConfig::default());

    // A fresh coordinator has no leader-activity timestamp; `check_round_timeout`
    // must not fire a view change because there's no baseline to time-out
    // against.
    coordinator.set_time(LocalTimestamp::from_millis(3_600_000));
    assert!(coordinator.check_round_timeout(&topology).is_none());
}
