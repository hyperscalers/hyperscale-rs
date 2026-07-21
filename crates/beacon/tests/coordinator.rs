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
    BeaconBlock, BeaconCert, BeaconProposal, BeaconWitnessLeafCount, Bls12381G2Signature,
    CandidateBeaconBlock, Epoch, Hash, PcQc2, PcQc3, PcSignerLengths, PcValueElement, PcVector,
    PcVoteEquivocation, PcVoteRound, PcXpProof, ShardId, SignerBitfield, SpcCert, SpcView,
    StakePoolId, StateRoot, ValidatorId, ValidatorStatus, Verified, VrfProof, zero_bls_signature,
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
    // "self-first" delivery, view-1 PC collapses to all-bottoms,
    // `committed_proposals` empties, and this test catches it.
    let mut sim = CoordinatorSim::new(4, 0xBE_AC);
    sim.kick_off();
    sim.run_until_committed(1, MAX_STEPS);

    let first_commit = &sim.commits[0][0];
    assert!(
        matches!(first_commit.block.cert(), BeaconCert::Normal { .. }),
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
fn dark_shard_does_not_stall_beacon_commits() {
    // A shard that produces no epoch-boundary crossing (offline / not
    // live) contributes no boundary QC to any proposal. The beacon SPC
    // input is built from committee *proposals*, not shard headers, so a
    // dark shard never blocks the view-1 feed: every epoch still reaches
    // full proposal coverage and commits a Normal block. The dark shard's
    // boundary simply stays parked at the genesis placeholder — it never
    // advances, but it also never wedges the chain.
    let mut sim = CoordinatorSim::new(4, 0x_DA_47);
    sim.kick_off();
    sim.run_until_committed(TARGET_COMMITS, MAX_STEPS);

    for e in 0..TARGET_COMMITS {
        let commit = &sim.commits[0][e];
        assert!(
            matches!(commit.block.cert(), BeaconCert::Normal { .. }),
            "epoch {} fell to a non-Normal cert with the shard dark",
            commit.epoch.inner(),
        );
        assert_eq!(
            commit.block.block().committed_proposals().len(),
            sim.n(),
            "epoch {} dropped proposals — the feed didn't reach full coverage",
            commit.epoch.inner(),
        );
    }

    // The chain advanced through every epoch, yet ROOT (never live) stays
    // at the genesis placeholder — dark, not wedged.
    let last = &sim.commits[0][TARGET_COMMITS - 1];
    assert_eq!(last.epoch, Epoch::new(TARGET_COMMITS as u64));
    let root = last
        .state
        .boundaries
        .get(&ShardId::ROOT)
        .expect("ROOT keeps a boundary record");
    assert_eq!(
        root.last_live_epoch,
        Epoch::GENESIS,
        "a dark shard's boundary must not advance",
    );
    assert_eq!(
        root.state_root,
        StateRoot::ZERO,
        "a dark shard stays at the genesis placeholder",
    );
}

#[test]
fn observed_crossing_records_shard_boundary_through_full_commit() {
    // Drives the whole boundary chain end to end: a shard's observed
    // epoch-boundary crossing → every proposer's `boundary_qcs` → the
    // committed `committed_proposals` → the assembler's `shard_contributions`
    // → the fold's `record_boundaries`. The genesis seed leaves
    // `boundaries[ROOT]` at the `StateRoot::ZERO` placeholder; a real
    // crossing must advance it past that with no recorded miss.
    let mut sim = CoordinatorSim::new(4, 0xB0_4D);

    // ROOT is the single genesis shard. With the default 300_000 ms epoch,
    // a block whose predecessor sits at 299_000 ms and whose own canonical
    // timestamp is 301_000 ms is the first block across the epoch-1 cut.
    let anchor = StateRoot::from_raw(Hash::from_bytes(b"shard-root-anchor"));
    let boundary_hash =
        sim.deliver_boundary_crossing(ShardId::ROOT, 5, 299_000, 301_000, anchor, 3);

    sim.kick_off();
    sim.run_until_committed(1, MAX_STEPS);

    let commit = &sim.commits[0][0];
    assert!(
        matches!(commit.block.cert(), BeaconCert::Normal { .. }),
        "honest-path commit unexpectedly carries a non-Normal cert",
    );
    assert!(
        !commit.block.block().committed_proposals().is_empty(),
        "committed block carries no proposals — boundary QCs never reach the fold",
    );
    assert!(
        commit
            .block
            .block()
            .shard_contributions()
            .contains_key(&ShardId::ROOT),
        "committed block has no ROOT contribution — assembler dropped the boundary",
    );

    let boundary = commit
        .state
        .boundaries
        .get(&ShardId::ROOT)
        .expect("ROOT keeps a boundary record");
    assert_eq!(
        boundary.state_root, anchor,
        "boundary anchor not advanced to the crossing block's state root",
    );
    assert_ne!(
        boundary.state_root,
        StateRoot::ZERO,
        "boundary still sitting at the genesis placeholder",
    );
    assert_eq!(boundary.block_hash, boundary_hash);
    assert_eq!(boundary.witness_leaf_count, BeaconWitnessLeafCount::new(3));
    assert_eq!(boundary.last_live_epoch, Epoch::new(1));
    assert_eq!(
        boundary.consecutive_misses, 0,
        "a live crossing must not register as a miss",
    );

    // The boundary's witnesses actually mutated state at commit, not just
    // advanced the watermark: each of the three `StakeDeposit` payloads
    // (pools 100..103, set by the sim's boundary builder) created its pool
    // through the fold's `apply_contribution_witnesses` step.
    for pool_n in 100..103 {
        assert!(
            commit.state.pools.contains_key(&StakePoolId::new(pool_n)),
            "boundary witness payload didn't mutate state at commit — pool {pool_n} missing",
        );
    }

    // Every replica folds to the same boundary record.
    for r in 1..sim.n() {
        let other = sim.commits[r][0]
            .state
            .boundaries
            .get(&ShardId::ROOT)
            .expect("replica keeps a ROOT boundary");
        assert_eq!(
            *other, *boundary,
            "replica {r} diverged on the recorded ROOT boundary",
        );
    }
}

#[test]
fn forged_boundary_qc_records_no_shard_boundary() {
    // A Byzantine committee member's fabricated boundary QC (signer bits
    // set, signature bogus) must never advance the anchor. Without the
    // admission gate it would: the crossing detector records it, the
    // assembler can back it, and the fold's hash binding accepts it — so a
    // forged QC would write `state_root = anchor`. The 2f+1 admission check
    // makes every honest verifier drop the proposal carrying it, so it
    // can't reach the committed set; the epoch commits empty — skip-shaped —
    // and the boundary carries forward untouched.
    let mut sim = CoordinatorSim::new(4, 0xF0_4D);
    let anchor = StateRoot::from_raw(Hash::from_bytes(b"forged-anchor"));
    sim.deliver_forged_boundary_crossing(ShardId::ROOT, 5, 299_000, 301_000, anchor, 3);
    sim.kick_off();
    sim.run_until_committed(1, MAX_STEPS);

    let commit = &sim.commits[0][0];
    let boundary = commit
        .state
        .boundaries
        .get(&ShardId::ROOT)
        .expect("ROOT boundary stays seeded");
    assert_eq!(
        boundary.state_root,
        StateRoot::ZERO,
        "a forged boundary QC must not advance the anchor",
    );
    assert_eq!(
        boundary.consecutive_misses, 0,
        "an empty commit is skip-shaped: the boundary carries forward untouched",
    );
    assert!(
        !commit
            .block
            .block()
            .shard_contributions()
            .contains_key(&ShardId::ROOT),
        "no contribution should seat for a rejected boundary QC",
    );
    for r in 1..sim.n() {
        let other = sim.commits[r][0]
            .state
            .boundaries
            .get(&ShardId::ROOT)
            .expect("replica keeps a ROOT boundary");
        assert_eq!(
            *other, *boundary,
            "replica {r} diverged on the forged-QC boundary",
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

/// A Byzantine committee member embeds forged equivocation evidence
/// (garbage sigs) naming an honest validator in its VRF-valid proposal.
/// The witness-admission gate keeps the proposal out of honest pools, so
/// it never reaches a `2f + 1` PC quorum and the forged evidence can't
/// bind into the committed `PcVector`: the named validator is never
/// jailed and every replica converges on identical state.
#[test]
fn forged_equivocation_witness_cannot_jail_or_fork() {
    let mut sim = CoordinatorSim::new(4, 0xF047);
    let victim = ValidatorId::new(1);
    let forged = PcVoteEquivocation {
        validator: victim,
        epoch: Epoch::new(1),
        view: SpcView::INITIAL,
        round: PcVoteRound::Vote1,
        value_a: PcVector::new(vec![PcValueElement::new([0x11; 32])]),
        sig_a: zero_bls_signature(),
        value_b: PcVector::new(vec![PcValueElement::new([0x22; 32])]),
        sig_b: zero_bls_signature(),
    };
    sim.inject_equivocations(Epoch::new(1), vec![forged]);
    sim.kick_off();
    sim.run_until_committed(1, MAX_STEPS);

    let reference = &sim.commits[0][0].state;
    for r in 0..sim.n() {
        let state = &sim.commits[r][0].state;
        let record = state
            .validators
            .get(&victim)
            .expect("victim is still a registered validator");
        assert!(
            !matches!(record.status, ValidatorStatus::Jailed { .. }),
            "replica {r} jailed an honest validator on a forged equivocation witness",
        );
        assert_eq!(
            state, reference,
            "replica {r} diverged on a forged equivocation witness",
        );
        let committed_forged = sim.commits[r][0]
            .block
            .block()
            .committed_proposals()
            .iter()
            .any(|(_, p)| !p.equivocations().is_empty());
        assert!(
            !committed_forged,
            "forged equivocation reached the committed block on replica {r}",
        );
    }
}

// ─── Skip-path integration ─────────────────────────────────────────────

/// Pool ratification drives the chain past an abandoned epoch on every
/// replica.
///
/// All four replicas (which form both the active pool and the beacon
/// committee at n=4) fire the ratify timer at the genesis tip, making
/// the canonical skip hash prevotable. With quorum = 4 − ⌊3/3⌋ = 3, the
/// third prevote polkas at every honest node within a network hop;
/// precommits follow, and each replica assembles a `RatifyCert` and
/// adopts the skip block — converging on a single block hash regardless
/// of which signer subset the local cert holds.
#[test]
fn skip_quorum_drives_chain_past_abandoned_epoch() {
    let mut sim = CoordinatorSim::new(4, 0);
    let n = sim.n();

    let pre_tip = sim.coordinators[0].latest_block().block_hash();
    let pre_epoch = sim.coordinators[0].current_state().current_epoch;
    let skipped_epoch = pre_epoch.next();

    // All n replicas prevote the skip hash at the genesis anchor for
    // the same epoch = `pre_epoch.next()`. The sim's `fire_ratify_timer`
    // mirrors what the production runner does on the ratify timer
    // firing: sign, admit locally, fan out. The skip hash only becomes
    // prevotable once the epoch's deadline passes on each tracker's
    // clock, so advance the clocks first.
    sim.pass_skip_deadline();
    for idx in 0..n {
        sim.fire_ratify_timer(idx);
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

    // Ratify-cert convergence isn't required to be byte-identical; the
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
    sim.pass_skip_deadline();
    for idx in 0..n {
        sim.fire_ratify_timer(idx);
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
    sim.pass_skip_deadline();
    for idx in 0..n {
        sim.fire_ratify_timer(idx);
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
/// commit-assembly decode finds the proposal missing, the coordinator
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

/// A partition stalls the beacon instead of forking it: with the
/// pool as the single commit quorum, the committee majority's SPC
/// candidate cannot ratify on its side of a partition (four of
/// thirteen), while the far side — nine non-committee pool validators
/// plus the silenced committee member — reaches the quorum of nine and
/// commits the skip block. On heal, the committee side adopts the
/// certified skip block at tip + 1; nothing halts, no epoch carries
/// two blocks.
#[test]
fn partition_stalls_committee_side_then_skip_settles() {
    const COMMITTEE: usize = 4;
    const POOL: usize = 13;
    let mut sim = CoordinatorSim::new_with_pool(COMMITTEE, POOL, 0xF0_12);
    let ids: Vec<ValidatorId> = (0..POOL as u64).map(ValidatorId::new).collect();

    // Member 3 is cut from all inbound traffic for the SPC phase: it
    // proposes and casts its round-1 vote, but never sees a QC2 — the
    // committee quorum {0,1,2} still certifies a candidate.
    sim.drop_counters[3] = usize::MAX / 2;
    // Candidates, votes, and blocks never cross between the committee
    // majority and the rest.
    sim.partition_blocks_between(&ids[..3], &ids[3..]);

    // The beacon paces to wall-clock and goes quiescent between timer
    // fires; re-kick until the committee side certifies its candidate.
    sim.kick_off();
    for _ in 0..8 {
        sim.run_for_at_most(50_000);
        if (0..3).all(|i| sim.coordinators[i].pending_candidate_hash().is_some()) {
            break;
        }
        // The view timer is what carries a view whose proposal-object
        // coverage is incomplete (member 3 relays nothing); the sim
        // models its wall-clock expiry explicitly.
        sim.fire_spc_view_timer_all();
        sim.kick_off();
    }

    // The committee side holds an SPC-certified candidate but cannot
    // commit it: its side of the partition musters three prevotes
    // against the pool quorum of nine.
    for i in 0..3 {
        assert!(
            sim.coordinators[i].pending_candidate_hash().is_some(),
            "replica {i} never certified the candidate",
        );
        assert!(
            sim.commits[i].is_empty(),
            "replica {i} committed without a pool quorum",
        );
    }

    // The partitioned side reaches its skip deadline and every replica
    // there fires the real wall-clock trigger: prevotes for the skip
    // hash, the polka, precommits, and the commit certificate all
    // assemble within the nine-plus-one members of that side.
    sim.drop_counters[3] = 0;
    sim.pass_skip_deadline();
    for idx in 3..POOL {
        sim.fire_ratify_timer(idx);
    }
    sim.run_for_at_most(50_000);

    let skip = sim.commits[4]
        .last()
        .expect("pool side commits the skip block")
        .clone();
    assert_eq!(skip.epoch, Epoch::new(1));
    let BeaconCert::Skip(cert) = skip.block.cert() else {
        panic!("expected a Skip cert on the partitioned side");
    };
    assert!(
        cert.signer_count() >= 9,
        "commit quorum is 9 of the 13-member active pool",
    );
    for i in 3..POOL {
        assert!(
            matches!(
                sim.commits[i].last().map(|c| c.block.cert()),
                Some(BeaconCert::Skip(_)),
            ),
            "replica {i} did not adopt the skip block",
        );
    }
    // The committee side is still stalled — consistency chosen over
    // availability for the partition minority.
    for i in 0..3 {
        assert!(sim.commits[i].is_empty(), "replica {i} forked");
    }

    // Heal: the certified skip block reaches a committee replica, which
    // adopts it at tip + 1 — convergence, not a halt.
    sim.clear_block_partition();
    let actions = sim.deliver_block_to(0, &skip.block);
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::CommitBeaconBlock { .. })),
        "the healed replica must adopt the skip block; got {actions:?}",
    );
    assert_eq!(
        sim.coordinators[0].latest_block().block_hash(),
        skip.block.block_hash(),
        "both sides converge on the skip block",
    );
}

/// A candidate landing at the skip deadline splits round 1: half the
/// pool prevotes the candidate, half prevotes skip, and neither
/// reaches the quorum of three — the wedge a strict one-vote register
/// could never leave. Nobody precommitted, so nobody is locked, and
/// the round-2 re-prevote converges on the candidate every replica
/// now holds.
#[test]
fn split_round_one_converges_on_the_candidate_in_round_two() {
    let mut sim = CoordinatorSim::new(4, 0x5D_17);
    let genesis_tip = sim.coordinators[0].latest_block().block_hash();

    // An SPC-certified candidate for epoch 1. The cert is a structural
    // placeholder — delivery below bypasses wire verification, and
    // ratification itself never re-checks it; the pool cert is what
    // commits.
    let qc2 = PcQc2::new(
        PcVector::empty(),
        SignerBitfield::new(4),
        Bls12381G2Signature([0x11; 96]),
        PcXpProof::Full,
    );
    let qc3 = PcQc3::new(
        PcVector::empty(),
        qc2,
        None,
        None,
        SignerBitfield::new(4),
        PcSignerLengths::Uniform(0),
        Bls12381G2Signature([0x11; 96]),
    );
    let proposal = BeaconProposal::new(
        std::iter::once((ShardId::ROOT, None)).collect(),
        Vec::new(),
        std::collections::BTreeMap::new(),
        VrfProof::ZERO,
    );
    let candidate = Arc::new(Verified::<CandidateBeaconBlock>::new_unchecked_for_test(
        CandidateBeaconBlock::new(
            BeaconBlock::new(
                Epoch::new(1),
                genesis_tip,
                vec![(ValidatorId::new(0), proposal)],
            ),
            Box::new(SpcCert::Direct {
                prev_view: SpcView::new(1),
                value: PcVector::empty(),
                proof: qc3.into(),
            }),
        ),
    ));
    let candidate_hash = candidate.block_hash();

    // Replicas 0 and 1 see the candidate before their deadline and
    // prevote it in round 1.
    sim.deliver_candidate_to(0, &candidate);
    sim.deliver_candidate_to(1, &candidate);

    // Replicas 2 and 3 hit the deadline first and prevote skip.
    sim.pass_skip_deadline();
    sim.fire_ratify_timer(2);
    sim.fire_ratify_timer(3);
    sim.run_for_at_most(10_000);

    // Round 1 split 2–2 below the quorum of 3: no polka, no lock, no
    // commit anywhere.
    for i in 0..4 {
        assert!(sim.commits[i].is_empty(), "replica {i} committed early");
    }

    // The candidate reaches the late half (its round-1 register is
    // spent, so holding it changes only what round 2 prevotes)...
    sim.deliver_candidate_to(2, &candidate);
    sim.deliver_candidate_to(3, &candidate);

    // ...and the rounds advance. The first fire on replicas 0 and 1 is
    // their deadline edge — registers already spent, no vote — which
    // arms round-timeout semantics for the next fire.
    sim.fire_ratify_timer(0);
    sim.fire_ratify_timer(1);
    // Round timeout on all four: everyone enters round 2 unlocked with
    // the candidate held, re-prevotes it, and the polka, precommits,
    // and commit certificate follow.
    for i in 0..4 {
        sim.fire_ratify_timer(i);
    }
    sim.run_for_at_most(10_000);

    for i in 0..4 {
        let commit = sim.commits[i]
            .last()
            .unwrap_or_else(|| panic!("replica {i} never committed"));
        assert_eq!(commit.epoch, Epoch::new(1));
        assert_eq!(commit.block.block_hash(), candidate_hash);
        assert!(matches!(commit.block.cert(), BeaconCert::Normal { .. }));
    }
}
