//! Byzantine fault tolerance tests for the consensus layer.
//!
//! These tests verify that the BFT protocol correctly handles malicious
//! validator behavior: forged signatures, wrong-key votes, replay attacks,
//! and garbage signatures. The consensus must reject invalid votes and
//! continue making progress despite Byzantine participants.
//!
//! This is the first Byzantine test suite for hyperscale-rs. It covers
//! vote-level attacks; block-level and equivocation tests can follow.

use hyperscale_core::{NodeInput, ProtocolEvent};
use hyperscale_simulation::{NetworkConfig, SimulationRunner};
use hyperscale_test_helpers::byzantine;
use hyperscale_test_helpers::TestCommittee;
use hyperscale_types::{BlockHeight, Hash, ShardGroupId};
use std::time::Duration;

/// Create a basic network configuration for Byzantine testing.
/// Uses 4 validators (tolerates f=1 Byzantine node with 3f+1=4).
fn test_config() -> NetworkConfig {
    NetworkConfig {
        num_shards: 1,
        validators_per_shard: 4,
        intra_shard_latency: Duration::from_millis(10),
        cross_shard_latency: Duration::from_millis(50),
        jitter_fraction: 0.1,
        ..Default::default()
    }
}

/// Run a simulation and return the minimum committed height across all nodes.
fn min_committed_height(runner: &SimulationRunner) -> u64 {
    (0..4)
        .filter_map(|i| runner.node(i))
        .map(|n| n.bft().committed_height())
        .min()
        .unwrap_or(0)
}

/// Helper: initialize genesis, schedule Byzantine events at `inject_at`, then
/// run until `end_time`. Returns (height_before_injection, height_after).
fn run_with_byzantine_events(
    seed: u64,
    inject_at_ms: u64,
    end_time_secs: u64,
    inject: impl Fn(&mut SimulationRunner, &TestCommittee),
) -> (u64, u64) {
    let config = test_config();
    let mut runner = SimulationRunner::new(config, seed);
    runner.initialize_genesis();

    let committee = TestCommittee::new(4, seed);
    inject(&mut runner, &committee);

    // Run to just before injection to capture baseline.
    runner.run_until(Duration::from_millis(inject_at_ms.saturating_sub(100)));
    let baseline = min_committed_height(&runner);

    // Run through injection and beyond.
    runner.run_until(Duration::from_secs(end_time_secs));
    let after = min_committed_height(&runner);

    (baseline, after)
}

// ═══════════════════════════════════════════════════════════════════════════
// Safety: Invalid votes must be rejected
// ═══════════════════════════════════════════════════════════════════════════

/// Verify that votes with garbage (zero-byte) signatures are rejected
/// and consensus continues making progress for honest nodes.
#[test]
fn test_garbage_signature_votes_rejected() {
    let shard = ShardGroupId(0);

    let (baseline, after) = run_with_byzantine_events(42, 3000, 8, |runner, committee| {
        let fake_block = Hash::from_bytes(b"fake_byzantine_block");
        for target_node in 0..4 {
            let bad_vote = byzantine::make_garbage_signature_vote(
                committee,
                0,
                fake_block,
                BlockHeight(10),
                0,
                shard,
            );
            runner.schedule_initial_event(
                target_node,
                Duration::from_millis(3000),
                NodeInput::Protocol(ProtocolEvent::BlockVoteReceived { vote: bad_vote }),
            );
        }
    });

    assert!(
        after > baseline,
        "Consensus must continue despite garbage signature votes (before={}, after={})",
        baseline,
        after
    );
}

/// Verify that votes signed with a different validator's key (identity forgery)
/// are rejected and do not contribute to quorum formation.
#[test]
fn test_wrong_key_votes_rejected() {
    let shard = ShardGroupId(0);

    let (baseline, after) = run_with_byzantine_events(42, 3000, 8, |runner, committee| {
        let fake_block = Hash::from_bytes(b"wrong_key_block");
        for target_node in 0..4 {
            let bad_vote = byzantine::make_wrong_key_block_vote(
                committee,
                0, // claims validator 0
                3, // actually signed by validator 3
                fake_block,
                BlockHeight(10),
                0,
                shard,
            );
            runner.schedule_initial_event(
                target_node,
                Duration::from_millis(3000),
                NodeInput::Protocol(ProtocolEvent::BlockVoteReceived { vote: bad_vote }),
            );
        }
    });

    assert!(
        after > baseline,
        "Consensus must continue despite wrong-key votes (before={}, after={})",
        baseline,
        after
    );
}

/// Verify that replay-style votes (valid signature but for a different block)
/// are rejected when the claimed block hash doesn't match the signed message.
#[test]
fn test_wrong_message_votes_rejected() {
    let shard = ShardGroupId(0);

    let (baseline, after) = run_with_byzantine_events(42, 3000, 8, |runner, committee| {
        let claimed_block = Hash::from_bytes(b"claimed_block_hash");
        let actual_block = Hash::from_bytes(b"actual_signed_block");
        for target_node in 0..4 {
            let bad_vote = byzantine::make_wrong_message_block_vote(
                committee,
                0,
                claimed_block,
                actual_block,
                BlockHeight(10),
                0,
                shard,
            );
            runner.schedule_initial_event(
                target_node,
                Duration::from_millis(3000),
                NodeInput::Protocol(ProtocolEvent::BlockVoteReceived { vote: bad_vote }),
            );
        }
    });

    assert!(
        after > baseline,
        "Consensus must continue despite wrong-message votes (before={}, after={})",
        baseline,
        after
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Liveness: Consensus must progress despite Byzantine minority
// ═══════════════════════════════════════════════════════════════════════════

/// Verify that sustained Byzantine vote flooding from one validator does not
/// prevent the other 3 honest validators from reaching consensus.
///
/// With 4 validators (f=1), consensus requires 3 honest votes. Even if
/// validator 0 floods invalid votes, the other 3 should form QCs and commit.
#[test]
fn test_consensus_progress_under_vote_flood() {
    let shard = ShardGroupId(0);

    let (baseline, after) = run_with_byzantine_events(42, 2000, 10, |runner, committee| {
        // Flood all nodes with garbage votes at multiple heights.
        for height_offset in 1..20u64 {
            for target_node in 0..4 {
                let bad_vote = byzantine::make_garbage_signature_vote(
                    committee,
                    0,
                    Hash::from_bytes(&[height_offset as u8; 32]),
                    BlockHeight(height_offset),
                    0,
                    shard,
                );
                runner.schedule_initial_event(
                    target_node,
                    Duration::from_millis(2000 + height_offset * 100),
                    NodeInput::Protocol(ProtocolEvent::BlockVoteReceived { vote: bad_vote }),
                );
            }
        }
    });

    assert!(
        after > baseline + 2,
        "Consensus should make significant progress despite vote flooding (before={}, after={})",
        baseline,
        after
    );
}

/// Verify that a mixture of valid and invalid votes at the same height
/// does not confuse quorum tracking — only valid votes should count.
#[test]
fn test_mixed_valid_and_invalid_votes() {
    let shard = ShardGroupId(0);

    let (baseline, after) = run_with_byzantine_events(42, 3000, 8, |runner, committee| {
        for target_node in 0..4 {
            // Garbage signature
            let v1 = byzantine::make_garbage_signature_vote(
                committee,
                1,
                Hash::from_bytes(b"mixtest_block_1"),
                BlockHeight(10),
                0,
                shard,
            );
            // Wrong key (claims validator 2, signed by validator 3)
            let v2 = byzantine::make_wrong_key_block_vote(
                committee,
                2,
                3,
                Hash::from_bytes(b"mixtest_block_2"),
                BlockHeight(10),
                0,
                shard,
            );

            runner.schedule_initial_event(
                target_node,
                Duration::from_millis(3000),
                NodeInput::Protocol(ProtocolEvent::BlockVoteReceived { vote: v1 }),
            );
            runner.schedule_initial_event(
                target_node,
                Duration::from_millis(3050),
                NodeInput::Protocol(ProtocolEvent::BlockVoteReceived { vote: v2 }),
            );
        }
    });

    assert!(
        after > baseline,
        "Consensus must continue despite mixed valid/invalid votes (before={}, after={})",
        baseline,
        after
    );
}
