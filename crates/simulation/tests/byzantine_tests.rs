//! Byzantine fault tolerance tests for the consensus layer.
//!
//! Verifies that the BFT protocol correctly handles malicious validator
//! behavior: forged signatures, wrong-key votes, replay attacks, and
//! garbage signatures. Consensus must reject invalid votes and continue
//! making progress despite Byzantine participants.

use hyperscale_core::{NodeInput, ProtocolEvent};
use hyperscale_simulation::{NetworkConfig, SimulationRunner};
use hyperscale_test_helpers::byzantine;
use hyperscale_test_helpers::TestCommittee;
use hyperscale_types::{BlockHeight, Hash, ShardGroupId};
use std::time::Duration;

/// 4 validators (tolerates f=1 Byzantine with 3f+1=4).
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

/// Minimum committed height across all nodes.
fn min_committed_height(runner: &SimulationRunner) -> u64 {
    (0..4)
        .filter_map(|i| runner.node(i))
        .map(|n| n.bft().committed_height())
        .min()
        .unwrap_or(0)
}

/// Initialize genesis, schedule Byzantine events, run, return (baseline, final) heights.
fn run_with_byzantine_events(
    seed: u64,
    inject_at_ms: u64,
    end_time_secs: u64,
    inject: impl Fn(&mut SimulationRunner, &TestCommittee),
) -> (u64, u64) {
    let mut runner = SimulationRunner::new(test_config(), seed);
    runner.initialize_genesis();

    let committee = TestCommittee::new(4, seed);
    inject(&mut runner, &committee);

    // Capture baseline just before injection.
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

#[test]
fn test_garbage_signature_votes_rejected() {
    let shard = ShardGroupId(0);
    let (baseline, after) = run_with_byzantine_events(42, 3000, 8, |runner, committee| {
        for target in 0..4 {
            let vote = byzantine::make_garbage_signature_vote(
                committee,
                0,
                Hash::from_bytes(b"fake_block"),
                BlockHeight(10),
                0,
                shard,
            );
            runner.schedule_initial_event(
                target,
                Duration::from_millis(3000),
                NodeInput::Protocol(ProtocolEvent::BlockVoteReceived { vote }),
            );
        }
    });
    assert!(
        after > baseline,
        "Consensus must continue despite garbage signatures (before={baseline}, after={after})"
    );
}

#[test]
fn test_wrong_key_votes_rejected() {
    let shard = ShardGroupId(0);
    let (baseline, after) = run_with_byzantine_events(42, 3000, 8, |runner, committee| {
        for target in 0..4 {
            let vote = byzantine::make_wrong_key_block_vote(
                committee,
                0, // claims validator 0
                3, // signed by validator 3
                Hash::from_bytes(b"forged_block"),
                BlockHeight(10),
                0,
                shard,
            );
            runner.schedule_initial_event(
                target,
                Duration::from_millis(3000),
                NodeInput::Protocol(ProtocolEvent::BlockVoteReceived { vote }),
            );
        }
    });
    assert!(
        after > baseline,
        "Consensus must continue despite wrong-key votes (before={baseline}, after={after})"
    );
}

#[test]
fn test_wrong_message_votes_rejected() {
    let shard = ShardGroupId(0);
    let (baseline, after) = run_with_byzantine_events(42, 3000, 8, |runner, committee| {
        for target in 0..4 {
            let vote = byzantine::make_wrong_message_block_vote(
                committee,
                0,
                Hash::from_bytes(b"claimed_block"),
                Hash::from_bytes(b"actual_signed"),
                BlockHeight(10),
                0,
                shard,
            );
            runner.schedule_initial_event(
                target,
                Duration::from_millis(3000),
                NodeInput::Protocol(ProtocolEvent::BlockVoteReceived { vote }),
            );
        }
    });
    assert!(
        after > baseline,
        "Consensus must continue despite wrong-message votes (before={baseline}, after={after})"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Liveness: Consensus must progress despite Byzantine minority
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_consensus_progress_under_vote_flood() {
    let shard = ShardGroupId(0);
    let (baseline, after) = run_with_byzantine_events(42, 2000, 10, |runner, committee| {
        for height in 1..20u64 {
            for target in 0..4 {
                let vote = byzantine::make_garbage_signature_vote(
                    committee,
                    0,
                    Hash::from_bytes(&[height as u8; 32]),
                    BlockHeight(height),
                    0,
                    shard,
                );
                runner.schedule_initial_event(
                    target,
                    Duration::from_millis(2000 + height * 100),
                    NodeInput::Protocol(ProtocolEvent::BlockVoteReceived { vote }),
                );
            }
        }
    });
    assert!(
        after > baseline + 2,
        "Consensus should progress despite flooding (before={baseline}, after={after})"
    );
}

#[test]
fn test_mixed_valid_and_invalid_votes() {
    let shard = ShardGroupId(0);
    let (baseline, after) = run_with_byzantine_events(42, 3000, 8, |runner, committee| {
        for target in 0..4 {
            let v1 = byzantine::make_garbage_signature_vote(
                committee,
                1,
                Hash::from_bytes(b"mix_block_1"),
                BlockHeight(10),
                0,
                shard,
            );
            let v2 = byzantine::make_wrong_key_block_vote(
                committee,
                2,
                3,
                Hash::from_bytes(b"mix_block_2"),
                BlockHeight(10),
                0,
                shard,
            );
            runner.schedule_initial_event(
                target,
                Duration::from_millis(3000),
                NodeInput::Protocol(ProtocolEvent::BlockVoteReceived { vote: v1 }),
            );
            runner.schedule_initial_event(
                target,
                Duration::from_millis(3050),
                NodeInput::Protocol(ProtocolEvent::BlockVoteReceived { vote: v2 }),
            );
        }
    });
    assert!(
        after > baseline,
        "Consensus must continue despite mixed votes (before={baseline}, after={after})"
    );
}
