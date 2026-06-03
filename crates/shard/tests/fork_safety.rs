//! Fork safety under the HotStuff-2 safe-vote + round-contiguous commit
//! rules.
//!
//! The same adversarial — but honest-validator — delivery schedule that
//! produced a two-node commit fork before the hardening is replayed here.
//! Two honest coordinators still each aggregate a quorum certificate for a
//! *different* sibling block at one height (the safe-vote rule permits both:
//! each extends the genesis QC, so neither sits below any voter's
//! `locked_round`). What changed is the commit: round-contiguous two-chain
//! commit finalizes a block only when a child certifies it in the very next
//! round, so at most one of the two siblings can ever be committed — the
//! chain extends exactly one branch contiguously. The conflicting QCs are a
//! harmless precursor, not a fork.
//!
//! The load-bearing assertion is [`find_fork`]: no two replicas commit
//! different blocks at one height.

mod common;

use std::collections::HashMap;
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

/// Two honest replicas committing different blocks at one height — the
/// agreement violation Phase 3 must make impossible. Returns the offending
/// `(height, block_a, block_b)` if any, else `None`.
fn find_fork(sim: &ShardCoordinatorSim) -> Option<(BlockHeight, BlockHash, BlockHash)> {
    let mut by_height: HashMap<BlockHeight, BlockHash> = HashMap::new();
    for replica in 0..sim.n() {
        for c in &sim.commits[replica] {
            match by_height.get(&c.height) {
                Some(&existing) if existing != c.block_hash => {
                    return Some((c.height, existing, c.block_hash));
                }
                Some(_) => {}
                None => {
                    by_height.insert(c.height, c.block_hash);
                }
            }
        }
    }
    None
}

/// n=4 (f=1, quorum=3). Validators are all honest; the adversary is the
/// scheduler. Rounds increase per block, so `proposer_for(round) =
/// committee[round % 4]`.
///
/// Branch A is led by V1 (round 1), branch B by V2 (round 2); V0 and V3 are
/// the swing voters forced into the overlap of every quorum. The schedule:
///
/// 1. V1 proposes A at round 1; V0/V1/V3 vote it; V1 aggregates `QC_A`.
/// 2. A round-1 timeout quorum advances V0/V2/V3 to round 2. Because A and B
///    both extend the genesis QC, the safe-vote rule lets V0/V3 vote B too;
///    V2 proposes B at round 2 and aggregates `QC_B`. Two QCs now certify
///    sibling blocks A != B at height 1 — the precursor, no longer a fork.
/// 3. The timeout pacemaker adopts the quorum-max `high_qc` (`QC_A`) and the
///    chain extends branch A contiguously, so a direct two-chain over A
///    forms and commits it while B is never certified in a contiguous round.
#[test]
fn safe_vote_and_contiguous_commit_close_the_fork() {
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

    // A round-1 timeout quorum (V0/V2/V3) advances them to round 2; V2 then
    // auto-proposes B@round 2 in `enter_round`. Both siblings extend genesis,
    // so the safe-vote rule lets V0/V3 vote B (routed to V2); V2 forms QC_B.
    sim.advance_clock(PAST_TIMEOUT);
    sim.fire_view_change_timer_all();
    sim.run_for_at_most(MAX_STEPS);

    // Two honest replicas hold QCs for different sibling blocks at one height —
    // the precursor the old vote-unlock turned into a fork. Under the safe-vote
    // rule it is permitted but harmless.
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

    // Drive the timeout pacemaker forward. It adopts the quorum-max high_qc
    // (QC_A) into the swing voters, so the chain extends branch A; a direct
    // two-chain over A then commits it while branch B is never certified in a
    // contiguous round.
    for _ in 0..4 {
        sim.advance_clock(PAST_TIMEOUT);
        sim.fire_view_change_timer_all();
        sim.run_for_at_most(MAX_STEPS);
    }

    // The agreement property: no two replicas committed different blocks at any
    // one height. Branch A finalized; branch B's QC_B is orphaned, never
    // committed by anyone.
    assert!(
        find_fork(&sim).is_none(),
        "two honest replicas committed different blocks at one height: {:?}",
        find_fork(&sim),
    );
    assert_eq!(
        committed_block(&sim, 1, h1),
        Some(qc_a.block_hash()),
        "branch A should have committed at height 1",
    );
    assert_eq!(
        committed_block(&sim, 2, h1),
        None,
        "V2's branch B (QC_B) must never commit at height 1",
    );
}
