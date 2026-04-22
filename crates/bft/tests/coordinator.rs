//! Public-API contract tests for `BftCoordinator`.
//!
//! These tests see only the crate's public surface (`use hyperscale_bft::...`),
//! so any regression in the documented API is caught here rather than by
//! inline tests that can reach into private fields.

use hyperscale_bft::{BftConfig, BftCoordinator, BftMemoryStats, BftStats, RecoveredState};
use hyperscale_test_helpers::TestCommittee;
use hyperscale_types::{BlockHeight, Round, TopologySnapshot, ValidatorInfo, ValidatorSet};
use std::time::Duration;

fn test_topology(committee: &TestCommittee, local_idx: usize) -> TopologySnapshot {
    let validators: Vec<ValidatorInfo> = (0..committee.size())
        .map(|i| ValidatorInfo {
            validator_id: committee.validator_id(i),
            public_key: *committee.public_key(i),
            voting_power: 1,
        })
        .collect();
    let validator_set = ValidatorSet::new(validators);
    TopologySnapshot::new(committee.validator_id(local_idx), 1, validator_set)
}

fn fresh_coordinator(config: BftConfig) -> BftCoordinator {
    BftCoordinator::new(0, config, RecoveredState::default())
}

fn fresh_coordinator_with_topology(config: BftConfig) -> (BftCoordinator, TopologySnapshot) {
    let committee = TestCommittee::new(4, 42);
    let topology = test_topology(&committee, 0);
    (fresh_coordinator(config), topology)
}

#[test]
fn fresh_coordinator_reports_genesis_chain_state() {
    let coordinator = fresh_coordinator(BftConfig::default());

    assert_eq!(coordinator.committed_height(), BlockHeight::GENESIS);
    assert!(coordinator.latest_qc().is_none());
    assert_eq!(coordinator.view(), Round::INITIAL);
    assert!(!coordinator.is_syncing());
}

#[test]
fn current_view_change_timeout_reflects_config() {
    let config = BftConfig::default()
        .with_view_change_timeout(Duration::from_secs(7))
        .with_view_change_timeout_increment(Duration::ZERO);
    let coordinator = fresh_coordinator(config);

    assert_eq!(
        coordinator.current_view_change_timeout(),
        Duration::from_secs(7)
    );
}

#[test]
fn memory_stats_reports_all_zeros_for_fresh_coordinator() {
    let coordinator = fresh_coordinator(BftConfig::default());
    let BftMemoryStats {
        pending_blocks,
        vote_sets,
        certified_blocks,
        pending_commits,
        pending_commits_awaiting_data,
        voted_heights,
        received_votes_by_height,
        committed_tx_lookup,
        recently_committed_txs,
        recently_committed_certs,
        pending_qc_verifications,
        verified_qcs,
        pending_state_root_verifications,
        buffered_synced_blocks,
        pending_synced_block_verifications,
    } = coordinator.memory_stats();

    assert_eq!(pending_blocks, 0);
    assert_eq!(vote_sets, 0);
    assert_eq!(certified_blocks, 0);
    assert_eq!(pending_commits, 0);
    assert_eq!(pending_commits_awaiting_data, 0);
    assert_eq!(voted_heights, 0);
    assert_eq!(received_votes_by_height, 0);
    assert_eq!(committed_tx_lookup, 0);
    assert_eq!(recently_committed_txs, 0);
    assert_eq!(recently_committed_certs, 0);
    assert_eq!(pending_qc_verifications, 0);
    assert_eq!(verified_qcs, 0);
    assert_eq!(pending_state_root_verifications, 0);
    assert_eq!(buffered_synced_blocks, 0);
    assert_eq!(pending_synced_block_verifications, 0);
}

#[test]
fn stats_reports_initial_defaults() {
    let coordinator = fresh_coordinator(BftConfig::default());
    let BftStats {
        view_changes,
        current_round,
        committed_height,
    } = coordinator.stats();

    assert_eq!(view_changes, 0);
    assert_eq!(current_round, Round::INITIAL.0);
    assert_eq!(committed_height, BlockHeight::GENESIS);
}

#[test]
fn is_current_proposer_matches_topology() {
    let committee = TestCommittee::new(4, 42);

    // At height 1, round 0 the proposer rotation picks committee[(1+0) % 4] = V1.
    // Each validator's coordinator should answer `is_current_proposer` consistently
    // with `topology.should_propose(height, round)` for that validator.
    for local_idx in 0..4 {
        let topology = test_topology(&committee, local_idx);
        let coordinator = BftCoordinator::new(
            local_idx as u32,
            BftConfig::default(),
            RecoveredState::default(),
        );
        // Fresh coordinator: latest_qc is None → next height = committed_height + 1 = 1.
        // view = Round::INITIAL = Round(0).
        let expected = topology.should_propose(BlockHeight(1), Round::INITIAL);
        assert_eq!(
            coordinator.is_current_proposer(&topology),
            expected,
            "V{}: is_current_proposer must agree with topology.should_propose",
            local_idx
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
    for local_idx in 0..4 {
        let topology = test_topology(&committee, local_idx);
        let coordinator = BftCoordinator::new(
            local_idx as u32,
            BftConfig::default(),
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
fn proposal_parent_hash_falls_back_to_committed_hash_without_qc() {
    let coordinator = fresh_coordinator(BftConfig::default());

    assert!(coordinator.latest_qc().is_none());
    assert_eq!(
        coordinator.proposal_parent_hash(),
        coordinator.committed_hash()
    );
}

#[test]
fn on_block_persisted_returns_no_actions_when_not_syncing() {
    let (mut coordinator, topology) = fresh_coordinator_with_topology(BftConfig::default());

    let actions = coordinator.on_block_persisted(&topology, BlockHeight(1));
    assert!(actions.is_empty());
    assert!(!coordinator.is_syncing());
}

#[test]
fn check_round_timeout_does_not_fire_without_recorded_activity() {
    let (mut coordinator, topology) = fresh_coordinator_with_topology(BftConfig::default());

    // A fresh coordinator has no leader-activity timestamp; `check_round_timeout`
    // must not fire a view change because there's no baseline to time-out
    // against.
    coordinator.set_time(Duration::from_secs(3600));
    assert!(coordinator.check_round_timeout(&topology).is_none());
}
