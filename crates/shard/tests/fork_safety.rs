//! Conflicting-QC (fork-precursor) reproduction for the shard consensus
//! vote-unlock + commit rule.
//!
//! Under an adversarial — but honest-validator — delivery schedule, two
//! honest coordinators each aggregate a quorum certificate for a
//! *different* block at the same height, and one of them two-chain
//! commits its block. This falsifies the "conflicting blocks cannot both
//! get QCs by quorum intersection" claim in `lib.rs`: the height-level
//! vote lock is released whenever a 2f+1 timeout quorum advances the
//! round — there is still no safe-vote rule binding the new vote to a
//! locked round — so an overlapping honest quorum signs both sibling
//! blocks across rounds. Two conflicting certificates plus one finalized
//! block is already a safety violation.
//!
//! The test pins the current unsafe behaviour. Once the rule is hardened
//! (locked-QC + safe-vote rule + round-contiguous commit) the overlapping
//! quorum can no longer sign both siblings, so only one QC forms at the
//! height; flip the assertions to require that at that point.

mod common;

use std::time::Duration;

use common::{HoldFilter, ShardCoordinatorSim};
use hyperscale_types::{BlockHash, BlockHeight, Round, ValidatorId};

const MAX_STEPS: usize = 5_000;
const PAST_TIMEOUT: Duration = Duration::from_secs(12);

/// Committed `block_hash` at `height` on `replica`, if any.
fn committed_block(
    sim: &ShardCoordinatorSim,
    replica: usize,
    height: BlockHeight,
) -> Option<BlockHash> {
    sim.commits[replica]
        .iter()
        .find(|c| c.height == height)
        .map(|c| c.block_hash)
}

/// n=4 (f=1, quorum=3). Validators are all honest; the adversary is the
/// scheduler. Rounds increase per block, so `proposer_for(round) =
/// committee[round % 4]`.
///
/// Branch A is led by V1 (round 1), branch B by V2 (round 2); V0 and V3 are
/// the swing voters forced into the overlap of every quorum. The schedule:
///
/// 1. V1 proposes A at round 1; V0/V1/V3 vote it; V1 aggregates `QC_A`.
/// 2. A local timeout releases V0/V3's h=1 lock with no QC seen. V2
///    proposes B at round 2; V0/V2/V3 vote it; V2 aggregates `QC_B`. Two QCs
///    now certify sibling blocks A != B at height 1.
/// 3. V1 advances to its next proposer slot (round 5) and proposes A2 (child
///    of A); V0/V3 adopt `QC_A` and vote A2; V1 aggregates `QC_A2` and
///    two-chain-commits A at height 1.
#[test]
fn vote_unlock_admits_conflicting_qcs_at_one_height() {
    let mut sim = ShardCoordinatorSim::new(4, 0xF0_4B);
    let v: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
    let (h1, h2) = (BlockHeight::new(1), BlockHeight::new(2));

    // Branch isolation: V1 (branch A) never sees branch B's headers, V2
    // (branch B) never sees branch A's.
    sim.hold_matching(v[1], HoldFilter::BlockHeaderFromProposer(v[2]));
    sim.hold_matching(v[2], HoldFilter::BlockHeaderFromProposer(v[1]));
    // Per-QC aggregation isolation: each block's votes reach only its
    // intended aggregator, so exactly one QC forms per block.
    let route = |sim: &mut ShardCoordinatorSim, height, round: u64, except: usize| {
        for (idx, &val) in v.iter().enumerate() {
            if idx != except {
                sim.hold_matching(
                    val,
                    HoldFilter::VoteAtHeightRound(height, Round::new(round)),
                );
            }
        }
    };
    route(&mut sim, h1, 1, 1); // A  votes -> V1
    route(&mut sim, h1, 2, 2); // B  votes -> V2
    route(&mut sim, h2, 5, 1); // A2 votes -> V1

    // V1 proposes A@round 1; V0/V1/V3 vote; V1 forms QC_A.
    sim.kick_off();
    sim.run_for_at_most(MAX_STEPS);

    // A round-1 timeout quorum (V0/V2/V3) advances them to round 2 and unlocks
    // V0/V3 at h=1; V2 then auto-proposes B@round 2 in `enter_round`; V0/V2/V3
    // vote it (routed to V2); V2 forms QC_B.
    sim.advance_clock(PAST_TIMEOUT);
    sim.fire_view_change_timer_all();
    sim.run_for_at_most(MAX_STEPS);

    // Two honest replicas now hold QCs for different sibling blocks at the
    // same height — the conflicting-QC safety violation that quorum
    // intersection is supposed to make impossible.
    let qc_a = sim.coordinators[1]
        .latest_qc()
        .cloned()
        .expect("V1 formed QC_A");
    let qc_b = sim.coordinators[2]
        .latest_qc()
        .cloned()
        .expect("V2 formed QC_B");
    assert_eq!(qc_a.height(), h1);
    assert_eq!(qc_b.height(), h1);
    assert_ne!(
        qc_a.block_hash(),
        qc_b.block_hash(),
        "expected QCs for two distinct blocks at height 1, not the same block",
    );

    // Drive the timeout pacemaker forward. The round-2 timeout quorum adopts
    // QC_A as the quorum-max high_qc into V0/V3 (V1 carries it, V0/V3 don't),
    // so branch A wins the swing voters; a child of A then certifies and its
    // QC two-chain-commits A at height 1 while branch B's QC_B is orphaned.
    for _ in 0..4 {
        sim.advance_clock(PAST_TIMEOUT);
        sim.fire_view_change_timer_all();
        sim.run_for_at_most(MAX_STEPS);
    }

    // V1 finalized branch A — one of the two conflicting certified blocks —
    // while V2 still holds QC_B for the orphaned sibling.
    assert_eq!(
        committed_block(&sim, 1, h1),
        Some(qc_a.block_hash()),
        "V1 should have committed branch A at height 1",
    );
    assert_eq!(
        committed_block(&sim, 2, h1),
        None,
        "V2's branch B (QC_B) must never commit at height 1",
    );
}
