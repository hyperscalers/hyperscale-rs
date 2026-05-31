//! End-to-end multi-coordinator integration tests.
//!
//! Drives an n=4 cluster of [`BeaconCoordinator`]s through several
//! epochs and pins the load-bearing invariants of the local commit
//! loop: every replica commits the same block per epoch, advances to a
//! byte-identical [`BeaconState`], and the SPC instance bootstraps the
//! next epoch automatically once `OutputHigh` fires.

mod common;

use std::sync::Arc;

use common::{ByzantineBehaviour, CoordinatorSim};
use hyperscale_core::Action;
use hyperscale_types::{
    BeaconCert, BlockHash, BoundedVec, Epoch, LeafIndex, ShardGroupId, ShardWitness,
    ShardWitnessPayload, ShardWitnessProof, ValidatorId, Witness,
};

/// Three epochs is enough to exercise the closed loop more than once:
/// the first epoch's commit chains into the second epoch's
/// `try_propose`, which only happens correctly if the post-commit
/// committee re-bootstrap and proposal-pool reset are sound.
const TARGET_COMMITS: usize = 3;

/// Step budget tuned to the cost of one epoch's traffic: per epoch
/// every replica fans out 4 proposals plus 3 PC vote rounds, with the
/// SPC cert ride-along on the broadcast block. ~300 deliveries per
/// epoch comfortably under this cap.
const MAX_STEPS: usize = 10_000;

#[test]
fn four_party_cluster_converges_on_per_epoch_state() {
    let mut sim = CoordinatorSim::new(4, 0xC0_0D);
    sim.kick_off();
    let steps = sim.run_until_committed(TARGET_COMMITS, MAX_STEPS);

    let counts: Vec<usize> = sim.commits.iter().map(Vec::len).collect();
    assert!(
        counts.iter().all(|c| *c >= TARGET_COMMITS),
        "not every replica reached {TARGET_COMMITS} commits in {steps} steps: {counts:?}",
    );

    // Per-epoch consensus invariants: every replica committed the
    // same epoch, the same `committed_proposals` set (sorted by
    // validator id), and lands at byte-identical `BeaconState`. The
    // wrapping SPC cert is a different aggregate per replica (each
    // assembles its own QC3 from the first quorum it sees, so the
    // BLS aggregate differs) and therefore the surrounding
    // `block_hash` also differs — but the consensus output and
    // post-apply state are what the chain depends on.
    for e in 0..TARGET_COMMITS {
        let reference = &sim.commits[0][e];
        let expected_epoch = Epoch::new(e as u64 + 1);
        assert_eq!(
            reference.epoch, expected_epoch,
            "replica 0's commit {e} is not at expected epoch {expected_epoch:?}",
        );
        let mut ref_proposals: Vec<_> = reference.block.block().committed_proposals().to_vec();
        ref_proposals.sort_by_key(|(id, _)| id.inner());
        for r in 1..sim.n() {
            let cmp = &sim.commits[r][e];
            assert_eq!(
                cmp.epoch, reference.epoch,
                "replica {r} committed epoch {:?} at slot {e}, expected {:?}",
                cmp.epoch, reference.epoch,
            );
            let mut cmp_proposals: Vec<_> = cmp.block.block().committed_proposals().to_vec();
            cmp_proposals.sort_by_key(|(id, _)| id.inner());
            assert_eq!(
                cmp_proposals, ref_proposals,
                "replica {r} committed proposal set differs from replica 0 at epoch {:?}",
                reference.epoch,
            );
            assert_eq!(
                cmp.state, reference.state,
                "replica {r} state differs from replica 0 at epoch {:?}",
                reference.epoch,
            );
        }
    }
}

#[test]
fn cluster_commits_non_empty_proposal_set_per_epoch() {
    // The two-tier queue ordering is what makes view-1 PC inputs full
    // vectors instead of per-validator singletons. This test pins the
    // resulting protocol property: every committed beacon block carries
    // every honest replica's proposal. If the sim ever regresses to
    // "self-first" delivery, view-1 PC collapses to all-`HASH_BOTTOM`s,
    // `committed_proposals` empties, and this test catches it.
    let mut sim = CoordinatorSim::new(4, 0xBE_AC);
    sim.kick_off();
    sim.run_until_committed(1, MAX_STEPS);

    let first_commit = &sim.commits[0][0];
    assert!(
        matches!(first_commit.block.cert(), BeaconCert::Normal(_)),
        "honest-path commit unexpectedly carries a non-Normal cert",
    );
    assert_eq!(
        first_commit.block.block().committed_proposals().len(),
        sim.n(),
        "committed block dropped proposals — view-1 PC may have collapsed",
    );
    // Tripwire: every dispatched verify must resolve. A non-zero
    // in-flight count after the cluster quiesces means the result
    // path didn't clear a pipeline slot somewhere.
    for r in 0..sim.n() {
        assert_eq!(
            sim.coordinators[r].verifications_in_flight(),
            0,
            "replica {r} leaked verify slots",
        );
    }
}

#[test]
fn adoption_path_advances_non_participating_replica() {
    // Sim A: full honest path → capture the committed block to feed
    // into a stand-alone replica B.
    let seed = 0xADD0;
    let mut sim_a = CoordinatorSim::new(4, seed);
    sim_a.kick_off();
    sim_a.run_until_committed(1, MAX_STEPS);
    let peer_block = Arc::clone(&sim_a.commits[0][0].block);
    let expected_state = sim_a.commits[0][0].state.clone();

    // Sim B: byte-identical setup so the genesis state and committee
    // match. Don't kick off — replica 0 should adopt the broadcast
    // block straight from the inbound handler without ever running its
    // own SPC.
    let mut sim_b = CoordinatorSim::new(4, seed);
    assert!(sim_b.commits[0].is_empty());
    let actions = sim_b.deliver_block_to(0, &peer_block);
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::CommitBeaconBlock { .. })),
        "expected CommitBeaconBlock in {actions:?}",
    );
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastBeaconBlock { .. })),
        "adoption path must not re-broadcast: {actions:?}",
    );
    assert_eq!(sim_b.commits[0].len(), 1);
    let adopted = &sim_b.commits[0][0];
    assert_eq!(adopted.block.block_hash(), peer_block.block_hash());
    assert_eq!(adopted.state, expected_state);
}

// ─── Byzantine + topology-change primitive hooks ──────────────────────────────
//
// These tests prove each adversarial hook fires when set; the protocol-level
// scenarios that exercise the resulting Byzantine state machine paths live in
// the broader sim suite.

#[test]
fn drop_for_consumes_envelopes_addressed_to_target_without_delivery() {
    let mut sim = CoordinatorSim::new(4, 0xD000);
    // Schedule 10 drops for replica 1 — comfortably more than will land
    // during a kick-off-only run, so the counter must end below the
    // budget by however many envelopes the network queue routed there.
    sim.drop_for(ValidatorId::new(1), 10);
    sim.kick_off();
    // Step a few times to drain proposals addressed to replica 1.
    for _ in 0..8 {
        if !sim.step() {
            break;
        }
    }
    assert!(
        sim.drop_counters[1] < 10,
        "drop_for didn't fire — drop_counters[1] = {} (expected < 10)",
        sim.drop_counters[1],
    );
    assert_eq!(
        sim.drop_counters[0], 0,
        "untargeted replica's counter moved"
    );
}

#[test]
fn with_byzantine_equivocate_proposal_fires_once_and_clears() {
    let mut sim = CoordinatorSim::new(4, 0xEBAD);
    sim.with_byzantine(ValidatorId::new(0), ByzantineBehaviour::EquivocateProposal);
    sim.kick_off();
    // Kick-off triggers each replica's epoch-1 `BuildAndBroadcastBeaconProposal`,
    // so the byzantine transform fires inside replica 0's `absorb_one`.
    assert_eq!(
        sim.byzantine_fires[0], 1,
        "equivocating proposer didn't fire on kick-off",
    );
    assert_eq!(
        sim.byzantine_fires[1], 0,
        "byzantine fire counter leaked to a non-flagged replica",
    );
    // Second kick-off-equivalent event would NOT re-fire — the
    // transform is one-shot. Re-flag and verify a second fire is
    // possible.
    sim.with_byzantine(ValidatorId::new(0), ByzantineBehaviour::EquivocateProposal);
    // Drain the queue so a fresh `BuildAndBroadcastBeaconProposal` for
    // epoch 2 surfaces via the natural commit-and-roll-forward path.
    sim.run_until_committed(2, 10_000);
    assert_eq!(
        sim.byzantine_fires[0], 2,
        "re-flagged byzantine didn't fire on the next proposal",
    );
}

#[test]
fn with_byzantine_equivocate_pc_vote1_fires_once() {
    let mut sim = CoordinatorSim::new(4, 0xEBE1);
    sim.with_byzantine(ValidatorId::new(0), ByzantineBehaviour::EquivocatePcVote1);
    sim.kick_off();
    // Run until replica 0 has emitted a round-1 vote — usually within
    // a few steps after the SPC instance bootstraps view 1.
    let mut steps = 0;
    while sim.byzantine_fires[0] == 0 {
        assert!(steps < 200, "byzantine PC vote1 never fired");
        assert!(sim.step(), "sim went quiescent before vote1 emission");
        steps += 1;
    }
    assert_eq!(sim.byzantine_fires[0], 1, "fired more than once");
}

#[test]
fn inject_topology_change_splices_witnesses_into_epoch_one_proposal() {
    let mut sim = CoordinatorSim::new(4, 0xE1C4);
    // Use a Ready witness for validator 0 — purely structural; the
    // assertion is on the witness being present in the committed
    // block's proposal set, not on its semantic effect.
    let witness = Witness::Shard(make_dummy_ready_witness(0));
    sim.inject_topology_change(Epoch::new(1), vec![witness.clone()]);
    sim.kick_off();
    sim.run_until_committed(1, 10_000);

    let commit = &sim.commits[0][0];
    let any_proposal_has_witness = commit
        .block
        .block()
        .committed_proposals()
        .iter()
        .any(|(_, prop)| {
            prop.witnesses()
                .iter()
                .any(|w| matches!(w, Witness::Shard(sw) if sw.proof.leaf_index == witness_leaf_index_of(&witness)))
        });
    assert!(
        any_proposal_has_witness,
        "scheduled witness didn't survive into any committed proposal at epoch 1",
    );
}

const fn make_dummy_ready_witness(leaf_index: u64) -> ShardWitness {
    ShardWitness {
        payload: ShardWitnessPayload::Ready {
            id: ValidatorId::new(0),
        },
        proof: ShardWitnessProof {
            shard_id: ShardGroupId::new(0),
            committed_block_hash: BlockHash::ZERO,
            leaf_index: LeafIndex::new(leaf_index),
            siblings: BoundedVec::new(),
        },
    }
}

fn witness_leaf_index_of(w: &Witness) -> LeafIndex {
    match w {
        Witness::Shard(sw) => sw.proof.leaf_index,
        Witness::Equivocation(_) => panic!("expected a shard witness"),
    }
}

// ─── Byzantine + topology-change scenarios ────────────────────────────────────
//
// Each test exercises one adversarial-or-degraded path end-to-end through the
// coordinator state machine.

/// Scenario 1: a Byzantine proposer broadcasts two beacon proposals at the
/// same epoch with different witness sets. The honest replicas accept the
/// first, reject the second as a duplicate-sender admit, and still converge
/// on a single committed state per epoch.
#[test]
fn equivocating_proposer_does_not_block_consensus() {
    let mut sim = CoordinatorSim::new(4, 0xEC01);
    sim.with_byzantine(ValidatorId::new(0), ByzantineBehaviour::EquivocateProposal);
    sim.kick_off();
    sim.run_until_committed(1, MAX_STEPS);

    assert_eq!(
        sim.byzantine_fires[0], 1,
        "byzantine transform must have fired exactly once",
    );
    let reference = &sim.commits[0][0];
    for r in 1..sim.n() {
        let cmp = &sim.commits[r][0];
        assert_eq!(
            cmp.state, reference.state,
            "replica {r} diverged from replica 0 under proposal equivocation",
        );
    }
}

/// Scenario 2: deafen one replica so it never hears outbound traffic, then
/// verify the remaining `2f + 1` still reach quorum and commit. The deafened
/// replica's own proposals reach the others' inboxes, so quorum on the honest
/// side completes naturally — the deafened replica itself never makes
/// progress.
/// Scenario 2: one replica is silenced (all inbound envelopes dropped) so it
/// never enters its own view 2. Honest view-1 PC completes, replicas enter
/// view 2, and view-2 PC stalls waiting for the silenced replica's `NewView`
/// relay (view ≥ 2 requires all `n` proposal objects before its PC fires).
/// The view-2 timer is the recovery path: firing it forces PC with the
/// partial buffer, the chain advances, and the `2f + 1`-honest set commits
/// without the silenced replica.
#[test]
fn silenced_replica_recovers_via_view_2_timeout() {
    let mut sim = CoordinatorSim::new(4, 0x5113);
    sim.drop_for(ValidatorId::new(3), 10_000);
    sim.kick_off();
    // Drain view-1 PC + the SPC NewView broadcasts that transition the
    // honest replicas into view 2. After this, view 2's PC is created
    // but waiting for `n = 4` proposal objects; only 3 ever arrive.
    sim.run_for_at_most(MAX_STEPS);
    // Fire the view-2 timer on every replica. SPC's `on_timer_expired`
    // forces RunVPC with the partial proposal-object buffer; the three
    // honest replicas' input lines up and view-2 PC closes.
    sim.fire_spc_view_timer_all();
    sim.run_for_at_most(MAX_STEPS);

    for r in 0..3 {
        assert!(
            !sim.commits[r].is_empty(),
            "honest replica {r} failed to commit after view-2 timeout recovery",
        );
    }
    assert!(
        sim.commits[3].is_empty(),
        "silenced replica unexpectedly committed",
    );
    let reference = &sim.commits[0][0];
    for r in 1..3 {
        assert_eq!(
            sim.commits[r][0].state, reference.state,
            "honest replica {r} diverged from replica 0",
        );
    }
}

/// Scenario 4: a witness-driven topology change is spliced into the epoch-1
/// proposal and the effect surfaces in the committed state. Uses a
/// `StakeDeposit` witness rather than `DeactivateValidator`: the sim is
/// pinned at `BEACON_SIGNER_COUNT = 4` and PC requires `n >= 4`, so
/// shrinking the committee mid-test would crash the next-epoch SPC
/// bootstrap. `StakeDeposit` exercises the same flow (witness rides
/// proposal → admitted into block → `apply_epoch` mutates state) without
/// touching the committee size.
#[test]
fn injected_topology_witness_mutates_state_at_commit() {
    use hyperscale_types::{MIN_STAKE_FLOOR, Stake, StakePoolId};

    let mut sim = CoordinatorSim::new(4, 0x7010);
    let pool_id = StakePoolId::new(0);
    let bump = Stake::from_whole_tokens(500);
    let witness = Witness::Shard(ShardWitness {
        payload: ShardWitnessPayload::StakeDeposit {
            pool_id,
            amount: bump,
        },
        proof: ShardWitnessProof {
            shard_id: ShardGroupId::new(0),
            committed_block_hash: BlockHash::ZERO,
            leaf_index: LeafIndex::new(1),
            siblings: BoundedVec::new(),
        },
    });
    sim.inject_topology_change(Epoch::new(1), vec![witness]);
    sim.kick_off();
    sim.run_until_committed(1, MAX_STEPS);

    // Genesis pool stake is `n * MIN_STAKE_FLOOR` per `CoordinatorSim::new`.
    // Post-epoch-1 it should be the genesis stake plus the deposit (and the
    // epoch's rewards emission — which we account for by checking strict
    // inequality rather than equality, since `EMISSIONS_PER_EPOCH` isn't part
    // of the topology-change story this test pins).
    let genesis_stake = Stake::from_attos(4u128 * MIN_STAKE_FLOOR.attos());
    let post = &sim.commits[0][0].state;
    let post_pool = post.pools.get(&pool_id).expect("pool still present");
    assert!(
        post_pool.total_stake >= genesis_stake.saturating_add(bump),
        "StakeDeposit didn't credit pool: post={:?} expected >= {:?}",
        post_pool.total_stake,
        genesis_stake.saturating_add(bump),
    );
    // Every honest replica sees the same post-commit pool state.
    for r in 1..sim.n() {
        let cmp = &sim.commits[r][0].state;
        assert_eq!(
            cmp.pools.get(&pool_id).unwrap().total_stake,
            post_pool.total_stake,
            "replica {r} pool state diverged",
        );
    }
}

// ─── Skip-path integration ─────────────────────────────────────────────

/// Pool-quorum skip drives the chain past an abandoned epoch on every
/// replica.
///
/// All four replicas (which form both the active pool and the beacon
/// committee at n=4) fire the skip trigger at the genesis tip. With
/// quorum = ⌈8/3⌉+1 = 4, the third request hits quorum at every honest
/// node within a network hop of being dispatched; each replica then
/// assembles, broadcasts, and adopts the skip block — converging on a
/// single block hash regardless of which signer subset the local
/// cert holds.
#[test]
fn skip_quorum_drives_chain_past_abandoned_epoch() {
    let mut sim = CoordinatorSim::new(4, 0);
    let n = sim.n();

    let pre_tip = sim.coordinators[0].latest_block().block_hash();
    let pre_epoch = sim.coordinators[0].current_state().current_epoch;
    let skipped_epoch = pre_epoch.next();

    // All n replicas dispatch a SkipRequest at the genesis anchor for
    // the same `epoch_to_skip = pre_epoch.next()`. The sim's
    // `fire_skip_trigger` mirrors what the production runner does on
    // the skip-trigger timer firing: sign, admit locally, fan out.
    for idx in 0..n {
        sim.fire_skip_trigger(idx);
    }
    // Bound by target_commits=1 — once every replica has committed
    // the skip block, stop. Letting the sim run further would push
    // the chain through subsequent autonomous Normal commits and
    // exercise the shuffle path at epoch 16, which is unrelated to
    // what this test pins.
    let _ = sim.run_until_committed(1, MAX_STEPS);

    // Every replica has committed exactly one Skip block at the
    // expected epoch, anchored at the prior tip.
    for r in 0..n {
        let commits = &sim.commits[r];
        assert_eq!(
            commits.len(),
            1,
            "replica {r} expected 1 commit, got {}",
            commits.len(),
        );
        let c = &commits[0];
        assert_eq!(c.epoch, skipped_epoch);
        assert!(
            matches!(c.block.cert(), BeaconCert::Skip(cert) if cert.anchor_hash() == pre_tip),
            "replica {r} commit isn't a Skip cert at pre_tip",
        );
    }

    // All replicas converged on the same block hash even though they
    // may have assembled certs with different signer subsets — the
    // cert lives outside the block hash.
    let canonical_hash = sim.commits[0][0].block.block_hash();
    for r in 1..n {
        assert_eq!(
            sim.commits[r][0].block.block_hash(),
            canonical_hash,
            "replica {r} block hash diverged from replica 0",
        );
    }

    // Skip-cert convergence isn't required to be byte-identical; the
    // adoption rule only insists on block-hash agreement. So this test
    // pins the load-bearing invariant (block hash) but doesn't require
    // cert equality.

    // Post-state advanced by exactly one epoch — that's the load-bearing
    // outcome (chain didn't wedge at the abandoned epoch).
    let post = &sim.commits[0][0].state;
    assert_eq!(post.current_epoch, skipped_epoch);
}

/// Two skips in succession: the first abandons epoch 1, the second
/// abandons epoch 2. Each fully advances the chain — `apply_epoch`
/// rolls randomness and resamples the committee on every transition,
/// so consecutive bad samples just produce consecutive Skip blocks
/// without wedging the chain.
#[test]
fn consecutive_skips_advance_chain() {
    let mut sim = CoordinatorSim::new(4, 0);
    let n = sim.n();

    // First skip: at the genesis tip, abandon epoch 1.
    for idx in 0..n {
        sim.fire_skip_trigger(idx);
    }
    let _ = sim.run_until_committed(1, MAX_STEPS);
    for r in 0..n {
        assert_eq!(
            sim.commits[r].len(),
            1,
            "replica {r} commit count post-skip-1"
        );
        assert_eq!(sim.commits[r][0].epoch, Epoch::new(1));
        assert!(matches!(
            sim.commits[r][0].block.cert(),
            BeaconCert::Skip(_)
        ));
    }
    let post_skip_1_randomness = sim.commits[0][0].state.randomness;

    // Drain any pipelined envelopes from the autonomous Normal flow
    // that may have started after the skip block adoption (each
    // replica bootstraps SPC for epoch 2 and try_proposes). We don't
    // want them to commit yet — second skip should kick in first.
    let _ = sim.run_for_at_most(0);

    // Second skip: from the post-skip-1 tip, abandon epoch 2.
    for idx in 0..n {
        sim.fire_skip_trigger(idx);
    }
    let _ = sim.run_until_committed(2, MAX_STEPS);
    for r in 0..n {
        assert_eq!(
            sim.commits[r].len(),
            2,
            "replica {r} commit count post-skip-2"
        );
        assert_eq!(sim.commits[r][1].epoch, Epoch::new(2));
        assert!(matches!(
            sim.commits[r][1].block.cert(),
            BeaconCert::Skip(_)
        ));
    }
    // Randomness rolled between consecutive skips — pinning the
    // "each skip advances randomness" property.
    let post_skip_2_randomness = sim.commits[0][1].state.randomness;
    assert_ne!(
        post_skip_1_randomness, post_skip_2_randomness,
        "consecutive skips must roll randomness; chain wouldn't converge otherwise",
    );
    // Tripwire: verify pipeline drains after consecutive skips.
    for r in 0..n {
        assert_eq!(
            sim.coordinators[r].verifications_in_flight(),
            0,
            "replica {r} leaked verify slots across two skips",
        );
    }
}

// ─── Missing-proposal fetch path ──────────────────────────────────────────

/// Scenario: replica 1 misses validator 0's `BeaconProposal` gossip,
/// but the other replicas (2 and 3) saw it. SPC's committed
/// `PcVector` carries a non-`ZERO` element at validator 0's position
/// because the ⌈2M/3⌉+1 quorum's input vectors agree. Replica 1's
/// `decode_committed_proposals` returns `Pending`, the coordinator
/// emits `Action::FetchBeaconProposal`, the sim routes the fetch to
/// a peer who has the proposal pooled, and replica 1 admits it +
/// finishes assembly + commits the same block hash as everyone else.
#[test]
fn missed_proposal_gossip_recovers_via_fetch_protocol() {
    let mut sim = CoordinatorSim::new(4, 0xFE7C);
    // Drop validator 0's epoch-1 proposal gossip to replica 1 only.
    // Validators 2 and 3 still receive it, so SPC's committed
    // OutputHigh carries a non-ZERO at position 0.
    sim.block_proposal_from(ValidatorId::new(0), ValidatorId::new(1));
    sim.kick_off();
    sim.run_until_committed(1, MAX_STEPS);

    // Every replica must commit the epoch-1 block; replica 1's commit
    // came through the fetch-recovery path.
    for r in 0..sim.n() {
        assert!(
            !sim.commits[r].is_empty(),
            "replica {r} failed to commit epoch 1 (fetch path may have stalled)",
        );
    }
    // Same committed proposal set across all replicas — pins the
    // invariant that the fetched proposal's content matches what the
    // honest majority committed.
    let mut reference: Vec<_> = sim.commits[0][0]
        .block
        .block()
        .committed_proposals()
        .to_vec();
    reference.sort_by_key(|(id, _)| id.inner());
    for r in 1..sim.n() {
        let mut cmp: Vec<_> = sim.commits[r][0]
            .block
            .block()
            .committed_proposals()
            .to_vec();
        cmp.sort_by_key(|(id, _)| id.inner());
        assert_eq!(
            cmp, reference,
            "replica {r} committed a different proposal set after fetch recovery",
        );
    }
    // Validator 0's proposal is in the committed set on replica 1
    // (the recovery path admitted it). If the fetch had returned None
    // or failed, the committed_proposals would have differed and the
    // assertion above would have caught it — this is a direct check.
    let r1_has_v0 = sim.commits[1][0]
        .block
        .block()
        .committed_proposals()
        .iter()
        .any(|(id, _)| *id == ValidatorId::new(0));
    assert!(
        r1_has_v0,
        "replica 1's committed block omits validator 0's proposal — fetch path didn't admit it",
    );
}
