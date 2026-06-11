//! Split observer-cohort lifecycle: the admission-time draw, the
//! release that returns a cancelled reshape's cohort to the pool, and
//! the readiness-gated execution that mutates the shard trie.
//!
//! A pending split is staffed before it executes: admission draws a
//! committee-size cohort from the free pool, assigns each member the
//! child it will sync, and carries them on the splitting shard's
//! lookahead committee as `Observing` members — visible to serving and
//! gossip, never to the consensus subset, so the shard's quorum stays
//! at target size for the whole grow. The trie mutates at the first
//! fold where each child's ready membership — its parent half,
//! computed at that fold, plus its ready cohort — reaches quorum; the
//! reshaped trie rides that fold's lookahead, so the children's
//! committees are known a full epoch before their window opens.

use std::collections::BTreeMap;

use blake3::Hasher;
use hyperscale_types::{
    BeaconState, BeaconWitnessLeafCount, BlockHash, BlockHeight, CohortSeat, PendingReshape,
    ShardBoundary, ShardCommittee, ShardId, StateRoot, ValidatorId, ValidatorStatus,
    byzantine_threshold,
};
use rand::RngExt;
use rand_chacha::ChaCha20Rng;

use crate::sampling::prng_from;

/// Domain tag for the cohort draw + child assignment seed. Distinct
/// from the pool-draw and shuffle-exit tags so the three PRNG streams
/// never collide on the same `(randomness, epoch, shard)` input.
const DOMAIN_RESHAPE_COHORT: &[u8] = b"hyperscale-reshape-cohort-v1";

/// Domain tag for the execution-fold parent-half assignment seed.
const DOMAIN_RESHAPE_PARENT_HALF: &[u8] = b"hyperscale-reshape-parent-half-v1";

/// Draw a committee-size observer cohort for the pending split of
/// `target` from the free pool, assigning the first shuffled half to
/// the left child and the rest to the right.
///
/// The caller has already passed the pool gate (`pooled_validators() ≥
/// shard_size`). Each drawn validator becomes `Observing { shard:
/// target }` and joins the target's lookahead committee; the returned
/// seats record the child assignments with `ready: false`.
pub(super) fn draw_split_cohort(
    state: &mut BeaconState,
    target: ShardId,
) -> BTreeMap<ValidatorId, CohortSeat> {
    let mut pool = state.pooled_validators();
    let size = state.chain_config.shard_size as usize;
    debug_assert!(pool.len() >= size, "caller enforces the pool gate");

    let mut prng = reshape_prng(DOMAIN_RESHAPE_COHORT, state, target);
    shuffle(&mut pool, &mut prng);
    pool.truncate(size);

    let (left, right) = target.children();
    let mut cohort = BTreeMap::new();
    for (i, id) in pool.into_iter().enumerate() {
        let child = if i < size.div_ceil(2) { left } else { right };
        cohort.insert(
            id,
            CohortSeat {
                child,
                ready: false,
            },
        );
        state
            .validators
            .get_mut(&id)
            .expect("drawn from the derived pool, must be in validators")
            .status = ValidatorStatus::Observing {
            shard: target,
            placed_at_epoch: state.current_epoch,
        };
        state
            .next_shard_committees
            .entry(target)
            .or_default()
            .members
            .push(id);
    }
    cohort
}

/// Return a cancelled or abandoned reshape's cohort to the pool: each
/// observer leaves the target's lookahead committee and goes back to
/// `Pooled`. Merges carry no cohort and release nothing.
pub(super) fn release_cohort(state: &mut BeaconState, target: ShardId, reshape: &PendingReshape) {
    let PendingReshape::Split { cohort, .. } = reshape else {
        return;
    };
    if let Some(committee) = state.next_shard_committees.get_mut(&target) {
        committee.members.retain(|m| !cohort.contains_key(m));
    }
    for id in cohort.keys() {
        let Some(rec) = state.validators.get_mut(id) else {
            continue;
        };
        if matches!(rec.status, ValidatorStatus::Observing { shard, .. } if shard == target) {
            rec.status = ValidatorStatus::Pooled;
        }
    }
}

/// Execute every pending split whose readiness gate is met, mutating
/// the trie into the lookahead committee set.
///
/// Per pending split, each fold: the parent half is computed here, over
/// the then-current consensus membership (shuffle, refill, and jail
/// replacement ran on the parent through the whole grow, so there are
/// no dangling assignments to repair), and the gate asks that each
/// child's ready membership — its parent half, ready by construction,
/// plus its ready cohort seats — reach `2f+1` of the committee target.
/// On the first fold where both children pass, the parent's lookahead
/// committee is replaced by the two children's: parent-half members
/// keep their ready flag and placement epoch under the new shard,
/// cohort members are placed with the readiness their `ReshapeReady`
/// folded (stragglers complete via the normal `Ready` path after the
/// boundary). The children gain pending placeholder boundary records —
/// the beacon cannot derive child state roots (`r_p` is a one-way hash
/// of them), so the records fill from the parent's final-epoch
/// `split_child_roots` delivery; until then they don't project as
/// snap-sync anchors. The parent's boundary record stays for its
/// terminal-epoch contribution and witness drain.
///
/// Runs after the shuffle step so the assignment reads post-rotation
/// membership and the children first shuffle one epoch after they
/// form; reads the epoch's freshly rolled randomness.
pub(super) fn execute_ready_splits(state: &mut BeaconState) {
    let targets: Vec<ShardId> = state
        .pending_reshapes
        .iter()
        .filter(|(_, r)| matches!(r, PendingReshape::Split { .. }))
        .map(|(target, _)| *target)
        .collect();
    for target in targets {
        try_execute_split(state, target);
    }
}

fn try_execute_split(state: &mut BeaconState, target: ShardId) {
    let Some(PendingReshape::Split { cohort, .. }) = state.pending_reshapes.get(&target) else {
        return;
    };

    // The parent half, assigned over the consensus membership as it
    // stands at this fold — observers are not parent members.
    let mut parent_members: Vec<ValidatorId> = state
        .next_shard_committees
        .get(&target)
        .map(|committee| {
            committee
                .members
                .iter()
                .copied()
                .filter(|id| {
                    matches!(
                        state.validators.get(id).map(|r| r.status),
                        Some(ValidatorStatus::OnShard { shard, .. }) if shard == target
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    parent_members.sort_unstable();
    let mut prng = reshape_prng(DOMAIN_RESHAPE_PARENT_HALF, state, target);
    shuffle(&mut parent_members, &mut prng);
    let (left_half, right_half) = parent_members.split_at(parent_members.len().div_ceil(2));

    // The gate: parent half (ready by construction — the same liveness
    // trust the beacon extends to any committee it forms) plus ready
    // cohort seats, at 2f+1 of the committee target per child.
    let (left, right) = target.children();
    let quorum = 2 * byzantine_threshold(state.chain_config.shard_size as usize) + 1;
    let ready_seats = |child: ShardId| {
        cohort
            .values()
            .filter(|seat| seat.child == child && seat.ready)
            .count()
    };
    if left_half.len() + ready_seats(left) < quorum
        || right_half.len() + ready_seats(right) < quorum
    {
        return;
    }
    tracing::info!(shard = ?target, "Shard split readiness gate met; reshaping the trie");

    let halves = [(left, left_half.to_vec()), (right, right_half.to_vec())];
    let Some(PendingReshape::Split { cohort, .. }) = state.pending_reshapes.remove(&target) else {
        unreachable!("pending split read above");
    };
    state.next_shard_committees.remove(&target);

    for (child, half) in halves {
        // Child committee: the parent half in assignment order, then
        // the cohort half in id order.
        let mut members = half;
        for (id, seat) in &cohort {
            if seat.child == child {
                members.push(*id);
            }
        }

        for id in &members {
            let rec = state
                .validators
                .get_mut(id)
                .expect("members come from committee/cohort state, must be in validators");
            rec.status = match rec.status {
                ValidatorStatus::OnShard {
                    ready,
                    placed_at_epoch,
                    ..
                } => ValidatorStatus::OnShard {
                    shard: child,
                    ready,
                    placed_at_epoch,
                },
                ValidatorStatus::Observing { .. } => ValidatorStatus::OnShard {
                    shard: child,
                    ready: cohort[id].ready,
                    placed_at_epoch: state.current_epoch,
                },
                other => unreachable!("split moved a {other:?} validator"),
            };
            // Placement changed: the per-placement miss scope ends here.
            state.miss_counters.remove(id);
        }

        state
            .next_shard_committees
            .insert(child, ShardCommittee { members });

        // Pending placeholder, the genesis-seeding pattern: a zero
        // block hash keeps it from projecting as a snap-sync anchor.
        state.boundaries.insert(
            child,
            ShardBoundary {
                state_root: StateRoot::ZERO,
                block_hash: BlockHash::ZERO,
                height: BlockHeight::GENESIS,
                witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                last_live_epoch: state.current_epoch,
                consecutive_misses: 0,
            },
        );
    }
}

/// PRNG bound to `(domain, randomness, epoch, shard)` — the seeding
/// discipline every reshape draw shares.
fn reshape_prng(domain: &[u8], state: &BeaconState, shard: ShardId) -> ChaCha20Rng {
    let mut h = Hasher::new();
    h.update(domain);
    h.update(state.randomness.as_bytes());
    h.update(&state.current_epoch.inner().to_le_bytes());
    h.update(&shard.inner().to_le_bytes());
    prng_from(h.finalize().as_bytes())
}

/// Deterministic Fisher–Yates over `ids` driven by `prng`.
fn shuffle(ids: &mut [ValidatorId], prng: &mut ChaCha20Rng) {
    for i in (1..ids.len()).rev() {
        let j = prng.random_range(0..=i);
        ids.swap(i, j);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_types::{Epoch, NodeId, ShardWitnessPayload};

    use super::*;
    use crate::state::test_fixtures::{
        apply_next_epoch, apply_witness_chunk, net, single_pool_state, validator_record,
    };
    use crate::state::witness::apply_shard_payload;

    /// `single_pool_state(4)` — four ready members on `leaf(1, 0)`,
    /// promoted into the active slot too — plus `pooled` free
    /// validators, with a committee target of 4 (quorum 3).
    fn grow_state(pooled: u64) -> BeaconState {
        let mut state = single_pool_state(4);
        state.current_epoch = Epoch::new(5);
        state.chain_config.shard_size = 4;
        state.shard_committees = state.next_shard_committees.clone();
        for i in 0..pooled {
            let id = 1000 + i;
            state.validators.insert(
                ValidatorId::new(id),
                validator_record(id, 0, ValidatorStatus::Pooled),
            );
        }
        state
    }

    fn cohort_of(state: &BeaconState, target: ShardId) -> &BTreeMap<ValidatorId, CohortSeat> {
        let Some(PendingReshape::Split { cohort, .. }) = state.pending_reshapes.get(&target) else {
            panic!("no pending split for {target:?}");
        };
        cohort
    }

    /// An observer from the pending split's cohort assigned to `child`.
    fn observer_for(state: &BeaconState, target: ShardId, child: ShardId) -> ValidatorId {
        *cohort_of(state, target)
            .iter()
            .find(|(_, seat)| seat.child == child)
            .map(|(id, _)| id)
            .expect("cohort halves cover both children")
    }

    fn mark_ready(state: &mut BeaconState, target: ShardId, observer: ValidatorId) {
        apply_shard_payload(
            state,
            target,
            &ShardWitnessPayload::ReshapeReady {
                validator: observer,
            },
        );
    }

    /// The gate holds until *each* child's parent half plus ready
    /// cohort reaches 2f+1 of the committee target; the first fold
    /// where both pass replaces the parent's lookahead committee with
    /// the two children's, partitions the parent membership, seats the
    /// cohort with its folded readiness, and creates pending
    /// placeholder boundary records.
    #[test]
    fn split_executes_only_when_each_child_reaches_quorum() {
        let p = ShardId::leaf(1, 0);
        let (left, right) = p.children();
        let mut state = grow_state(4);
        apply_shard_payload(
            &mut state,
            p,
            &ShardWitnessPayload::ScheduleSplit { shard: p },
        );
        let parent_members: BTreeSet<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let cohort: BTreeMap<ValidatorId, CohortSeat> = cohort_of(&state, p).clone();
        state.miss_counters.insert(ValidatorId::new(0), 2);

        // Nobody ready: each child sees only its parent half (2 < 3).
        execute_ready_splits(&mut state);
        assert!(state.pending_reshapes.contains_key(&p));
        assert!(state.next_shard_committees.contains_key(&p));

        // One child at quorum, the other not: still held.
        let left_observer = observer_for(&state, p, left);
        mark_ready(&mut state, p, left_observer);
        execute_ready_splits(&mut state);
        assert!(state.pending_reshapes.contains_key(&p));

        // Both children at 2 + 1 = 3 of 4: the trie reshapes.
        let right_observer = observer_for(&state, p, right);
        mark_ready(&mut state, p, right_observer);
        execute_ready_splits(&mut state);

        assert!(state.pending_reshapes.is_empty());
        assert!(!state.next_shard_committees.contains_key(&p));
        let left_members = state.next_shard_committees[&left].members.clone();
        let right_members = state.next_shard_committees[&right].members.clone();
        assert_eq!(left_members.len(), 4);
        assert_eq!(right_members.len(), 4);

        // The parent membership partitions across the children —
        // disjoint, complete — and every mover's status follows its
        // committee. Parent halves keep their flags and placement
        // epoch; cohort seats land with their folded readiness, placed
        // at the execution epoch.
        let mut seen: BTreeSet<ValidatorId> = BTreeSet::new();
        for (child, members) in [(left, &left_members), (right, &right_members)] {
            for id in members {
                assert!(seen.insert(*id), "{id:?} appears in both children");
                let status = state.validators[id].status;
                if parent_members.contains(id) {
                    assert_eq!(
                        status,
                        ValidatorStatus::OnShard {
                            shard: child,
                            ready: true,
                            placed_at_epoch: Epoch::GENESIS,
                        },
                    );
                } else {
                    let seat = cohort[id];
                    assert_eq!(seat.child, child);
                    assert_eq!(
                        status,
                        ValidatorStatus::OnShard {
                            shard: child,
                            ready: id == &left_observer || id == &right_observer,
                            placed_at_epoch: Epoch::new(5),
                        },
                    );
                }
            }
        }
        assert_eq!(seen.len(), 8);

        // Movers shed their per-placement miss scope; the children gain
        // pending placeholders that can't project as snap-sync anchors.
        assert!(!state.miss_counters.contains_key(&ValidatorId::new(0)));
        for child in [left, right] {
            let boundary = state.boundaries[&child];
            assert_eq!(boundary.block_hash, BlockHash::ZERO);
            assert_eq!(boundary.last_live_epoch, Epoch::new(5));
        }
    }

    /// A not-yet-ready parent member counts toward the gate (ready by
    /// construction — committee-liveness trust) but carries its real
    /// flag onto the child, completing sync via the normal Ready path.
    #[test]
    fn unready_parent_member_counts_toward_gate_but_keeps_its_flag() {
        let p = ShardId::leaf(1, 0);
        let straggler = ValidatorId::new(3);
        let mut state = grow_state(4);
        state.validators.get_mut(&straggler).unwrap().status = ValidatorStatus::OnShard {
            shard: p,
            ready: false,
            placed_at_epoch: Epoch::new(4),
        };
        apply_shard_payload(
            &mut state,
            p,
            &ShardWitnessPayload::ScheduleSplit { shard: p },
        );
        let observers: Vec<ValidatorId> = cohort_of(&state, p).keys().copied().collect();
        for observer in observers {
            mark_ready(&mut state, p, observer);
        }

        execute_ready_splits(&mut state);

        assert!(state.pending_reshapes.is_empty());
        let ValidatorStatus::OnShard {
            shard,
            ready,
            placed_at_epoch,
        } = state.validators[&straggler].status
        else {
            panic!("straggler must stay placed");
        };
        assert_eq!(shard.parent(), Some(p));
        assert!(!ready);
        assert_eq!(placed_at_epoch, Epoch::new(4));
    }

    /// Two replicas with byte-identical state execute byte-identically
    /// — the parent-half assignment is seeded, not incidental.
    #[test]
    fn execution_is_deterministic_across_replicas() {
        let p = ShardId::leaf(1, 0);
        let mut a = grow_state(4);
        let mut b = grow_state(4);
        for state in [&mut a, &mut b] {
            apply_shard_payload(state, p, &ShardWitnessPayload::ScheduleSplit { shard: p });
            let observers: Vec<ValidatorId> = cohort_of(state, p).keys().copied().collect();
            for observer in observers {
                mark_ready(state, p, observer);
            }
            execute_ready_splits(state);
        }
        assert_eq!(a.next_shard_committees, b.next_shard_committees);
        assert_eq!(a.validators, b.validators);
        assert_eq!(a.boundaries, b.boundaries);
    }

    /// The plan's Phase 2a exit criterion, through the full pipeline:
    /// after the fold that meets the gate, the epoch in flight still
    /// resolves routing against the parent while the lookahead resolves
    /// the two-child partition; the in-flight window's frozen consensus
    /// subset is untouched; the promotion one epoch later activates
    /// both children at full consensus strength.
    #[test]
    fn lookahead_resolves_children_while_active_resolves_parent() {
        let p = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let (left, right) = p.children();
        let mut state = grow_state(4);
        // Staff the sibling so both tries are prefix-complete.
        let mut sibling_members = Vec::new();
        for i in 100..104u64 {
            let id = ValidatorId::new(i);
            sibling_members.push(id);
            state.validators.insert(
                id,
                validator_record(
                    i,
                    0,
                    ValidatorStatus::OnShard {
                        shard: sibling,
                        ready: true,
                        placed_at_epoch: Epoch::GENESIS,
                    },
                ),
            );
        }
        state.next_shard_committees.insert(
            sibling,
            ShardCommittee {
                members: sibling_members,
            },
        );
        state.shard_committees = state.next_shard_committees.clone();
        state.committee = (0u64..4).map(ValidatorId::new).collect();

        // One epoch folds the trigger; admission draws the cohort.
        apply_witness_chunk(
            &mut state,
            0,
            vec![ShardWitnessPayload::ScheduleSplit { shard: p }],
        );
        assert!(state.pending_reshapes.contains_key(&p));
        let consensus_during_grow = state.shard_consensus_members.clone();

        // The next epoch folds every observer's ReshapeReady; the gate
        // fires inside the same apply and the children ride this
        // fold's lookahead.
        let observers: Vec<ValidatorId> = cohort_of(&state, p).keys().copied().collect();
        apply_witness_chunk(
            &mut state,
            0,
            observers
                .iter()
                .map(|v| ShardWitnessPayload::ReshapeReady { validator: *v })
                .collect(),
        );
        assert!(state.pending_reshapes.is_empty());

        let active = state.derive_topology_snapshot(net());
        let lookahead = state.derive_next_topology_snapshot(net());
        for seed in 0..32u8 {
            let node = NodeId([seed; 30]);
            let now = active.shard_for_node_id(&node);
            let next = lookahead.shard_for_node_id(&node);
            if now == p {
                // The parent's traffic remaps to exactly its children.
                assert_eq!(next.parent(), Some(p), "{node:?} routed to {next:?}");
            } else {
                // Anything outside the split is untouched.
                assert_eq!(now, sibling);
                assert_eq!(next, sibling);
            }
            // Re-derivation is deterministic on both sides.
            assert_eq!(
                state
                    .derive_topology_snapshot(net())
                    .shard_for_node_id(&node),
                now
            );
            assert_eq!(
                state
                    .derive_next_topology_snapshot(net())
                    .shard_for_node_id(&node),
                next
            );
        }
        // The in-flight window still runs the parent: its promotion-
        // frozen consensus subset is exactly what the grow froze.
        assert_eq!(state.shard_consensus_members, consensus_during_grow);
        // Pending child placeholders never project as snap-sync anchors.
        assert!(lookahead.boundary(left).is_none());
        assert!(lookahead.boundary(right).is_none());

        // The promotion one epoch later activates both children at
        // full consensus strength: the parent half plus the readied
        // cohort half.
        apply_next_epoch(&mut state, &[]);
        assert!(!state.shard_committees.contains_key(&p));
        for child in [left, right] {
            assert_eq!(state.shard_committees[&child].members.len(), 4);
            assert_eq!(state.shard_consensus_members[&child].len(), 4);
        }
    }
}
