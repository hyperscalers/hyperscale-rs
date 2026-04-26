//! Pure topology-derived helpers used by the BFT coordinator.
//!
//! Everything here is a free function over `TopologySnapshot` — no mutable
//! state, no async, no dependency on coordinator internals. Moved out of
//! the coordinator so the topology-only parts are unit-testable without a
//! full driver fixture.

use hyperscale_types::{BlockHeight, Bls12381G1PublicKey, Round, TopologySnapshot, ValidatorId};
use tracing::warn;

/// Recipients for a vote at `(height, round)`.
///
/// Returns up to `K` distinct proposers for the *next* height (for pipelining)
/// plus the current block's proposer (so the proposer can aggregate its own
/// QC without waiting for a later header to deliver it). Excludes self — the
/// coordinator processes its own vote internally.
///
/// `K = 2` provides redundancy: if the primary next proposer crashes before
/// broadcasting its block, the secondary already has the votes and can form
/// the QC on view change without re-collection.
pub fn vote_recipients(
    topology: &TopologySnapshot,
    height: BlockHeight,
    round: Round,
) -> Vec<ValidatorId> {
    const K: usize = 2;
    let committee_len = topology.local_committee().len();
    let self_id = topology.local_validator_id();
    let mut recipients = Vec::with_capacity(K + 1);

    let block_proposer = topology.proposer_for(height, round);
    if block_proposer != self_id {
        recipients.push(block_proposer);
    }

    let mut next_count = 0;
    for offset in 0..committee_len as u64 {
        let proposer = topology.proposer_for(height.next(), round + offset);
        if proposer != self_id && !recipients.contains(&proposer) {
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
/// Returns `None` if any committee index fails to resolve to a public key
/// — a topology corruption indicating the snapshot is unsafe to use.
pub fn committee_public_keys(topology: &TopologySnapshot) -> Option<Vec<Bls12381G1PublicKey>> {
    let committee_size = topology.local_committee_size();
    let mut pubkeys = Vec::with_capacity(committee_size);

    for idx in 0..committee_size {
        if let Some(validator_id) = topology.local_validator_at_index(idx) {
            if let Some(pk) = topology.public_key(validator_id) {
                pubkeys.push(pk);
            } else {
                warn!(validator_id = ?validator_id, "Missing public key for committee member");
                return None;
            }
        } else {
            warn!(idx, "Invalid committee index");
            return None;
        }
    }

    Some(pubkeys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_test_helpers::TestCommittee;
    use hyperscale_types::{ValidatorInfo, ValidatorSet};

    fn topology_for(local_idx: usize, committee: &TestCommittee) -> TopologySnapshot {
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

    // ─── vote_recipients ────────────────────────────────────────────────

    #[test]
    fn vote_recipients_targets_next_proposers() {
        // 4 validators, self = V0. Proposer formula: committee[(height + round) % 4].
        let committee = TestCommittee::new(4, 42);
        let topology = topology_for(0, &committee);

        // Voting at (0, 0):
        //   Block proposer: (0+0)%4 = V0 (self, skipped)
        //   Next proposers for height 1: V1 (round 0), V2 (round 1)
        assert_eq!(
            vote_recipients(&topology, BlockHeight(0), Round(0)),
            vec![ValidatorId(1), ValidatorId(2)]
        );

        // Voting at (1, 0):
        //   Block proposer: V1 (included)
        //   Next proposers: V2 (round 0), V3 (round 1)
        assert_eq!(
            vote_recipients(&topology, BlockHeight(1), Round(0)),
            vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)]
        );
    }

    #[test]
    fn vote_recipients_excludes_self() {
        // Self = V0. Voting at (3, 0):
        //   Block proposer: V3
        //   Next proposers: V0 (self, skipped), V1, V2
        let committee = TestCommittee::new(4, 42);
        let topology = topology_for(0, &committee);
        assert_eq!(
            vote_recipients(&topology, BlockHeight(3), Round(0)),
            vec![ValidatorId(3), ValidatorId(1), ValidatorId(2)]
        );
    }

    #[test]
    fn vote_recipients_respects_current_round() {
        // Self = V0. Voting at (0, 2):
        //   Block proposer: (0+2)%4 = V2
        //   Next proposers: V3 (round 2), V0 (self, skipped), V1 (round 4)
        let committee = TestCommittee::new(4, 42);
        let topology = topology_for(0, &committee);
        assert_eq!(
            vote_recipients(&topology, BlockHeight(0), Round(2)),
            vec![ValidatorId(2), ValidatorId(3), ValidatorId(1)]
        );
    }

    #[test]
    fn vote_recipients_empty_when_solo_validator() {
        let committee = TestCommittee::new(1, 42);
        let topology = topology_for(0, &committee);
        assert!(vote_recipients(&topology, BlockHeight(0), Round(0)).is_empty());
    }

    // ─── committee_public_keys ──────────────────────────────────────────

    #[test]
    fn committee_public_keys_returns_all_keys_in_order() {
        let committee = TestCommittee::new(4, 42);
        let topology = topology_for(0, &committee);

        let keys = committee_public_keys(&topology).expect("topology is well-formed");
        assert_eq!(keys.len(), 4);

        // Canonical order: committee[i] corresponds to validator i.
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(key, committee.public_key(i));
        }
    }
}
