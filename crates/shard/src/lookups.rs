//! Pure topology-derived helpers used by the shard coordinator.
//!
//! Everything here is a free function over `TopologySnapshot` — no mutable
//! state, no async, no dependency on coordinator internals. Moved out of
//! the coordinator so the topology-only parts are unit-testable without a
//! full driver fixture.

use hyperscale_types::{Bls12381G1PublicKey, Round, ShardId, TopologySnapshot, ValidatorId};

/// Recipients for a vote cast in `round`.
///
/// Returns up to `K` distinct proposers for the rounds immediately following
/// (for pipelining) plus this round's proposer (so the proposer can aggregate
/// its own QC without waiting for a later header to deliver it). Excludes self
/// — the coordinator processes its own vote internally.
///
/// `K = 2` provides redundancy: if the primary next proposer crashes before
/// broadcasting its block, the secondary already has the votes and can form
/// the QC on view change without re-collection.
pub fn vote_recipients(
    topology: &TopologySnapshot,
    shard: ShardId,
    me: ValidatorId,
    round: Round,
) -> Vec<ValidatorId> {
    const K: usize = 2;
    let committee_len = topology.committee_for_shard(shard).len();
    let mut recipients = Vec::with_capacity(K + 1);

    let block_proposer = topology.proposer_for(shard, round);
    if block_proposer != me {
        recipients.push(block_proposer);
    }

    let mut next_count = 0;
    for offset in 1..=committee_len as u64 {
        let proposer = topology.proposer_for(shard, round + offset);
        if proposer != me && !recipients.contains(&proposer) {
            recipients.push(proposer);
            next_count += 1;
            if next_count >= K {
                break;
            }
        }
    }

    recipients
}

/// Committee public keys in canonical index order.
///
/// Used when delegating QC signature verification: the runner receives all
/// keys and filters by the QC's `signers` bitfield. Passing the full list
/// in canonical order ensures consistent aggregation across validators.
///
/// # Panics
///
/// Panics if a committee member is absent from the snapshot's validator set.
/// Committees are drawn from registered validators and validator records are
/// never removed, so every member resolves — a miss is a `BeaconState`
/// invariant violation, not a recoverable condition, and failing loud beats
/// silently wedging the shard under a corrupt snapshot.
pub fn committee_public_keys(
    topology: &TopologySnapshot,
    shard: ShardId,
) -> Vec<Bls12381G1PublicKey> {
    topology
        .committee_for_shard(shard)
        .iter()
        .map(|&validator_id| {
            topology.public_key(validator_id).unwrap_or_else(|| {
                panic!(
                    "committee member {validator_id:?} absent from validator set — \
                     BeaconState invariant (committees subset of validators) violated"
                )
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use hyperscale_test_helpers::TestCommittee;
    use hyperscale_types::{NetworkDefinition, ValidatorInfo, ValidatorSet};

    use super::*;

    fn topology_for(committee: &TestCommittee) -> TopologySnapshot {
        let validators: Vec<ValidatorInfo> = (0..committee.size())
            .map(|i| ValidatorInfo {
                validator_id: committee.validator_id(i),
                public_key: *committee.public_key(i),
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        TopologySnapshot::new(NetworkDefinition::simulator(), 1, validator_set)
    }

    // ─── vote_recipients ────────────────────────────────────────────────

    #[test]
    fn vote_recipients_targets_next_proposers() {
        // 4 validators, self = V0. Proposer formula: committee[round % 4].
        let committee = TestCommittee::new(4, 42);
        let topology = topology_for(&committee);
        let me = committee.validator_id(0);
        let shard = ShardId::ROOT;

        // Voting in round 0:
        //   Block proposer: round 0 -> V0 (self, skipped)
        //   Next proposers: V1 (round 1), V2 (round 2)
        assert_eq!(
            vote_recipients(&topology, shard, me, Round::new(0)),
            vec![ValidatorId::new(1), ValidatorId::new(2)]
        );

        // Voting in round 1:
        //   Block proposer: round 1 -> V1 (included)
        //   Next proposers: V2 (round 2), V3 (round 3)
        assert_eq!(
            vote_recipients(&topology, shard, me, Round::new(1)),
            vec![
                ValidatorId::new(1),
                ValidatorId::new(2),
                ValidatorId::new(3)
            ]
        );
    }

    #[test]
    fn vote_recipients_excludes_self() {
        // Self = V0. Voting in round 3:
        //   Block proposer: round 3 -> V3
        //   Next proposers: V0 (round 4, self, skipped), V1 (round 5), V2 (round 6)
        let committee = TestCommittee::new(4, 42);
        let topology = topology_for(&committee);
        let me = committee.validator_id(0);
        let shard = ShardId::ROOT;
        assert_eq!(
            vote_recipients(&topology, shard, me, Round::new(3)),
            vec![
                ValidatorId::new(3),
                ValidatorId::new(1),
                ValidatorId::new(2)
            ]
        );
    }

    #[test]
    fn vote_recipients_respects_current_round() {
        // Self = V0. Voting in round 2:
        //   Block proposer: round 2 -> V2
        //   Next proposers: V3 (round 3), V0 (round 4, self, skipped), V1 (round 5)
        let committee = TestCommittee::new(4, 42);
        let topology = topology_for(&committee);
        let me = committee.validator_id(0);
        let shard = ShardId::ROOT;
        assert_eq!(
            vote_recipients(&topology, shard, me, Round::new(2)),
            vec![
                ValidatorId::new(2),
                ValidatorId::new(3),
                ValidatorId::new(1)
            ]
        );
    }

    #[test]
    fn vote_recipients_empty_when_solo_validator() {
        let committee = TestCommittee::new(1, 42);
        let topology = topology_for(&committee);
        let me = committee.validator_id(0);
        let shard = ShardId::ROOT;
        assert!(vote_recipients(&topology, shard, me, Round::new(0)).is_empty());
    }

    // ─── committee_public_keys ──────────────────────────────────────────

    #[test]
    fn committee_public_keys_returns_all_keys_in_order() {
        let committee = TestCommittee::new(4, 42);
        let topology = topology_for(&committee);
        let shard = ShardId::ROOT;

        let keys = committee_public_keys(&topology, shard);
        assert_eq!(keys.len(), 4);

        // Canonical order: committee[i] corresponds to validator i.
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(key, committee.public_key(i));
        }
    }
}
