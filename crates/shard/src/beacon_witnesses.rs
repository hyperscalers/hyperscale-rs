//! Per-shard beacon-witness accumulator + leaf-derivation rules.
//!
//! Single owner for everything around the shard's
//! [`BeaconWitnessRoot`](hyperscale_types::BeaconWitnessRoot) commitment
//! on each [`BlockHeader`](hyperscale_types::BlockHeader): the in-memory
//! accumulator, the canonical leaf-derivation rule (receipts →
//! `MissedProposal` → `Ready`), and the post-execution verifier hook
//! that downstream call sites delegate to.
//!
//! The module is intentionally storage-agnostic. Reads and writes
//! against the `beacon_witnesses` column family land alongside the
//! per-block-flow wiring; this module's job is to define the rules
//! and let proposer + verifier share them verbatim.

use std::time::Duration;

use hyperscale_types::{
    BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHeader, BlockHeight, BlockManifest,
    ConsensusReceipt, Hash, ReadySignal, Round, ShardWitnessPayload, StoredReceipt,
    TopologySnapshot, compute_merkle_root,
};

/// Minimum dwell time before a [`ReadySignal`] is eligible to be
/// drained into a block.
///
/// Matches the existing tx-dwell constant — the proposer's pool
/// admission and drain both honour this so a signal has had time to
/// propagate to other committee members before it gets committed.
pub const MIN_READY_SIGNAL_DWELL: Duration = Duration::from_millis(150);

/// Per-shard append-only beacon-witness accumulator.
///
/// Holds the full leaf-hash history so [`Self::root`] and
/// [`Self::preview_append`] can recompute roots without re-reading the
/// source payloads, and so the coordinator can hand the leaves to the
/// verification pipeline for prospective-root checks. Pruning is the
/// runtime layer's job — the accumulator only knows about leaves it
/// currently retains.
#[derive(Debug, Clone, Default)]
pub struct BeaconWitnessAccumulator {
    leaves: Vec<Hash>,
}

impl BeaconWitnessAccumulator {
    /// Construct an empty accumulator.
    #[must_use]
    pub const fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Construct from a pre-existing leaf list — typically the result
    /// of replaying retained leaves out of the `beacon_witnesses`
    /// column family at startup.
    #[must_use]
    pub const fn from_leaves(leaves: Vec<Hash>) -> Self {
        Self { leaves }
    }

    /// Total leaves the accumulator has seen.
    #[must_use]
    pub const fn leaf_count(&self) -> BeaconWitnessLeafCount {
        BeaconWitnessLeafCount::new(self.leaves.len() as u64)
    }

    /// Borrow the full leaf-hash list. Used by the verifier path to
    /// hand a snapshot to the off-thread CPU check without exposing the
    /// internal `Vec` for mutation.
    #[must_use]
    pub fn leaves(&self) -> &[Hash] {
        &self.leaves
    }

    /// Current root.
    #[must_use]
    pub fn root(&self) -> BeaconWitnessRoot {
        BeaconWitnessRoot::from_raw(compute_merkle_root(&self.leaves))
    }

    /// Compute the `(root, leaf_count)` that would result from
    /// appending `new_payloads` without mutating `self`.
    ///
    /// Proposer calls this at block-assembly time to fill the header's
    /// `(beacon_witness_root, beacon_witness_leaf_count)` fields
    /// without committing to the append — block construction may be
    /// rolled back on view change before a successor commits.
    #[must_use]
    pub fn preview_append(
        &self,
        new_payloads: &[ShardWitnessPayload],
    ) -> (BeaconWitnessRoot, BeaconWitnessLeafCount) {
        if new_payloads.is_empty() {
            return (self.root(), self.leaf_count());
        }
        let mut hashes = self.leaves.clone();
        hashes.reserve(new_payloads.len());
        for payload in new_payloads {
            hashes.push(payload.leaf_hash());
        }
        let root = BeaconWitnessRoot::from_raw(compute_merkle_root(&hashes));
        let count = BeaconWitnessLeafCount::new(hashes.len() as u64);
        (root, count)
    }

    /// Append `new_payloads` to the accumulator. Commit-time
    /// counterpart to [`Self::preview_append`].
    pub fn commit_append(&mut self, new_payloads: &[ShardWitnessPayload]) {
        self.leaves.reserve(new_payloads.len());
        for payload in new_payloads {
            self.leaves.push(payload.leaf_hash());
        }
    }
}

/// Walk the rounds `(parent_round, committed_round)` and emit one
/// `MissedProposal` witness per skipped round, identifying the expected
/// proposer via [`TopologySnapshot::proposer_for`].
///
/// Returns `Vec::new()` when `committed_round <= parent_round + 1` (the
/// successful proposer took the first attempt at this height — nothing
/// to report). Used by both the proposer-side derivation and the
/// post-execution verifier so a future change to leader rotation moves
/// both sides simultaneously.
#[must_use]
pub fn missed_proposals_since_prev_commit(
    height: BlockHeight,
    parent_round: Round,
    committed_round: Round,
    topology: &TopologySnapshot,
) -> Vec<ShardWitnessPayload> {
    let mut missed = Vec::new();
    let mut round = parent_round.next();
    while round < committed_round {
        let proposer_id = topology.proposer_for(height, round);
        missed.push(ShardWitnessPayload::MissedProposal {
            proposer_id,
            height,
            round,
        });
        round = round.next();
    }
    missed
}

/// Canonical leaf-derivation rule used by both proposer and verifier.
///
/// Ordering (locked — every honest validator must produce the same
/// `Vec<ShardWitnessPayload>` given the same inputs):
///
/// 1. Receipt-emitted witnesses in receipt-iteration order; within a
///    receipt, in the order the engine recorded them.
/// 2. `MissedProposal` witnesses in ascending round order (the helper
///    already sorts; pass its output verbatim).
/// 3. `Ready` witnesses in ascending `validator_id` order.
#[must_use]
pub fn derive_leaves(
    receipts: &[StoredReceipt],
    missed: Vec<ShardWitnessPayload>,
    ready_signals: &[ReadySignal],
) -> Vec<ShardWitnessPayload> {
    let mut out = Vec::new();
    for receipt in receipts {
        if let ConsensusReceipt::Succeeded {
            beacon_witness_events,
            ..
        } = receipt.consensus.as_ref()
        {
            for event in beacon_witness_events {
                out.push(ShardWitnessPayload::from(event.clone()));
            }
        }
    }
    out.extend(missed);
    let mut sorted: Vec<&ReadySignal> = ready_signals.iter().collect();
    sorted.sort_by_key(|s| s.validator_id());
    for signal in sorted {
        out.push(ShardWitnessPayload::Ready {
            id: signal.validator_id(),
        });
    }
    out
}

/// Post-execution verifier for the block's beacon-witness commitment.
///
/// Re-derives the new payloads from `(receipts, missed, ready_signals)`,
/// applies them against a clone of `parent_accumulator`, and confirms
/// both `header.beacon_witness_root()` and
/// `header.beacon_witness_leaf_count()` agree.
///
/// Called from
/// [`crates/shard/src/action_handlers.rs`](crate::action_handlers)
/// alongside the existing per-block verifiers
/// (`verify_local_receipt_root`, `verify_state_root`). A `false`
/// return aborts the post-execution validation step and rejects the
/// block.
#[must_use]
pub fn derive_and_verify(
    header: &BlockHeader,
    manifest: &BlockManifest,
    receipts: &[StoredReceipt],
    parent_accumulator: &BeaconWitnessAccumulator,
    parent_round: Round,
    topology: &TopologySnapshot,
) -> bool {
    let missed =
        missed_proposals_since_prev_commit(header.height(), parent_round, header.round(), topology);
    let leaves = derive_leaves(receipts, missed, manifest.ready_signals().as_slice());
    let (root, count) = parent_accumulator.preview_append(&leaves);
    root == header.beacon_witness_root() && count == header.beacon_witness_leaf_count()
}

#[cfg(test)]
mod tests {
    use hyperscale_test_helpers::TestCommittee;
    use hyperscale_types::{
        BeaconWitnessRoot, Bls12381G2Signature, Stake, StakePoolId, TopologySnapshot, ValidatorId,
        compute_merkle_root,
    };

    use super::*;

    fn pool_id() -> StakePoolId {
        StakePoolId::new(1)
    }

    fn deposit(amount: u64) -> ShardWitnessPayload {
        ShardWitnessPayload::StakeDeposit {
            pool_id: pool_id(),
            amount: Stake::new(amount),
        }
    }

    fn topology() -> TopologySnapshot {
        TestCommittee::new(4, 7).topology_snapshot(0, 1)
    }

    fn ready_signal_for(validator: u64) -> ReadySignal {
        ReadySignal::new(
            ValidatorId::new(validator),
            BlockHeight::new(1),
            BlockHeight::new(100),
            Bls12381G2Signature([0x42; 96]),
        )
    }

    fn ready_signals(ids: &[u64]) -> Vec<ReadySignal> {
        ids.iter().copied().map(ready_signal_for).collect()
    }

    #[test]
    fn empty_accumulator_is_zero() {
        let acc = BeaconWitnessAccumulator::new();
        assert_eq!(acc.leaf_count(), BeaconWitnessLeafCount::ZERO);
        assert_eq!(acc.root(), BeaconWitnessRoot::ZERO);
    }

    #[test]
    fn preview_then_commit_match() {
        let mut acc = BeaconWitnessAccumulator::new();
        let new_payloads = vec![deposit(100), deposit(200)];

        let (preview_root, preview_count) = acc.preview_append(&new_payloads);
        acc.commit_append(&new_payloads);

        assert_eq!(acc.root(), preview_root);
        assert_eq!(acc.leaf_count(), preview_count);
        assert_eq!(preview_count, BeaconWitnessLeafCount::new(2));
    }

    #[test]
    fn preview_does_not_mutate() {
        let mut acc = BeaconWitnessAccumulator::new();
        acc.commit_append(&[deposit(1)]);
        let snapshot_root = acc.root();
        let snapshot_count = acc.leaf_count();

        let _ = acc.preview_append(&[deposit(2), deposit(3)]);

        assert_eq!(acc.root(), snapshot_root);
        assert_eq!(acc.leaf_count(), snapshot_count);
    }

    /// The all-zero `Hash::ZERO` is used as padding by the merkle
    /// helpers. A legitimate leaf must never collide with it, otherwise
    /// an oversized tree's padding leaves could be confused with real
    /// leaves at proof verification time.
    #[test]
    fn leaf_hash_tag_prevents_padding_collision() {
        let leaf = deposit(0).leaf_hash();
        assert_ne!(leaf, Hash::ZERO);
    }

    #[test]
    fn missed_proposals_empty_when_no_skipped_rounds() {
        let topo = topology();
        let missed = missed_proposals_since_prev_commit(
            BlockHeight::new(5),
            Round::INITIAL,
            Round::INITIAL.next(),
            &topo,
        );
        assert!(missed.is_empty());
    }

    #[test]
    fn missed_proposals_emits_one_per_skipped_round() {
        let topo = topology();
        let parent_round = Round::INITIAL;
        let committed_round = Round::new(parent_round.inner() + 3);
        let missed = missed_proposals_since_prev_commit(
            BlockHeight::new(5),
            parent_round,
            committed_round,
            &topo,
        );
        assert_eq!(missed.len(), 2);
        let rounds: Vec<u64> = missed
            .iter()
            .map(|m| match m {
                ShardWitnessPayload::MissedProposal { round, .. } => round.inner(),
                _ => unreachable!("only MissedProposal expected"),
            })
            .collect();
        assert_eq!(
            rounds,
            vec![
                parent_round.next().inner(),
                parent_round.next().next().inner(),
            ]
        );
    }

    #[test]
    fn derive_leaves_orders_sources_canonically() {
        let topo = topology();
        let missed = missed_proposals_since_prev_commit(
            BlockHeight::new(5),
            Round::INITIAL,
            Round::new(Round::INITIAL.inner() + 2),
            &topo,
        );
        let ready = ready_signals(&[3, 1, 2]);
        let receipts: Vec<StoredReceipt> = Vec::new();

        let leaves = derive_leaves(&receipts, missed, &ready);
        // 1 MissedProposal + 3 Ready (sorted ascending by validator id)
        assert_eq!(leaves.len(), 4);
        assert!(matches!(
            &leaves[0],
            ShardWitnessPayload::MissedProposal { .. }
        ));
        for (i, expected) in [1u64, 2, 3].iter().enumerate() {
            match &leaves[1 + i] {
                ShardWitnessPayload::Ready { id } => assert_eq!(id.inner(), *expected),
                other => panic!("expected Ready, got {other:?}"),
            }
        }
    }

    #[test]
    fn derive_leaves_byte_identical_across_runs() {
        let topo = topology();
        let missed = missed_proposals_since_prev_commit(
            BlockHeight::new(9),
            Round::INITIAL,
            Round::new(Round::INITIAL.inner() + 4),
            &topo,
        );
        let ready = ready_signals(&[7, 2]);
        let receipts: Vec<StoredReceipt> = Vec::new();

        let a = derive_leaves(&receipts, missed.clone(), &ready);
        let b = derive_leaves(&receipts, missed, &ready);
        assert_eq!(a, b);

        let mut acc_a = BeaconWitnessAccumulator::new();
        let mut acc_b = BeaconWitnessAccumulator::new();
        acc_a.commit_append(&a);
        acc_b.commit_append(&b);
        assert_eq!(acc_a.root(), acc_b.root());
    }

    /// Sanity: a single-leaf accumulator's root equals
    /// `compute_merkle_root(&[leaf_hash(payload)])`.
    #[test]
    fn single_leaf_root_matches_leaf_hash_helper() {
        let mut acc = BeaconWitnessAccumulator::new();
        let payload = deposit(42);
        acc.commit_append(std::slice::from_ref(&payload));
        let expected = compute_merkle_root(&[payload.leaf_hash()]);
        assert_eq!(acc.root().into_raw(), expected);
    }
}
