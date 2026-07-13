//! Per-shard beacon-witness accumulator + leaf-derivation rules.
//!
//! Single owner for everything around the shard's
//! [`BeaconWitnessRoot`](hyperscale_types::BeaconWitnessRoot) commitment
//! on each [`BlockHeader`](hyperscale_types::BlockHeader): the in-memory
//! accumulator, the canonical leaf-derivation rule (receipts →
//! `MissedProposal` → readiness → reshape trigger), and the
//! post-execution verifier hook that downstream call sites delegate to.
//!
//! The module is intentionally storage-agnostic. Reads and writes
//! against the `beacon_witnesses` column family land alongside the
//! per-block-flow wiring; this module's job is to define the rules
//! and let proposer + verifier share them verbatim.

use hyperscale_types::{
    BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, Hash, ShardId, ShardWitnessPayload,
    StoredReceipt, TopologySchedule, compute_merkle_root, derive_leaves,
    missed_proposals_since_prev_commit,
};

use crate::pending::PendingBlocks;

/// Per-shard append-only beacon-witness accumulator.
///
/// Holds the retained leaf-hash window so [`Self::root`] and
/// [`Self::preview_append`] can recompute roots without re-reading the
/// source payloads, and so the coordinator can hand the leaves to the
/// verification pipeline for prospective-root checks. `leaves[i]` is
/// the accumulator's absolute leaf `start_index + i`; the merkle root
/// commits the retained window only.
#[derive(Debug, Clone, Default)]
pub struct BeaconWitnessAccumulator {
    /// Absolute index of `leaves[0]`.
    start_index: BeaconWitnessLeafCount,
    leaves: Vec<Hash>,
}

impl BeaconWitnessAccumulator {
    /// Construct an empty accumulator starting at leaf zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            start_index: BeaconWitnessLeafCount::ZERO,
            leaves: Vec::new(),
        }
    }

    /// Construct from a retained leaf window: `leaves[0]` is the
    /// accumulator's absolute leaf `start_index`. Typically the result
    /// of replaying retained leaves out of the `beacon_witnesses`
    /// column family at startup.
    #[must_use]
    pub const fn from_leaves(start_index: BeaconWitnessLeafCount, leaves: Vec<Hash>) -> Self {
        Self {
            start_index,
            leaves,
        }
    }

    /// Absolute index of the first retained leaf.
    #[must_use]
    pub const fn start_index(&self) -> BeaconWitnessLeafCount {
        self.start_index
    }

    /// Total leaves the accumulator has seen — the retained window plus
    /// everything before its start.
    #[must_use]
    pub const fn leaf_count(&self) -> BeaconWitnessLeafCount {
        BeaconWitnessLeafCount::new(self.start_index.inner() + self.leaves.len() as u64)
    }

    /// Borrow the retained leaf-hash window. Used by the verifier path
    /// to hand a snapshot to the off-thread CPU check without exposing
    /// the internal `Vec` for mutation.
    #[must_use]
    pub fn leaves(&self) -> &[Hash] {
        &self.leaves
    }

    /// Root over the retained window.
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
        let count = BeaconWitnessLeafCount::new(self.start_index.inner() + hashes.len() as u64);
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

    /// Drop retained leaves below `base` and advance the window start
    /// to it. A `base` at or below the current start is a no-op — the
    /// window only moves forward.
    pub fn prune_to(&mut self, base: BeaconWitnessLeafCount) {
        let drop = base.inner().saturating_sub(self.start_index.inner());
        if drop == 0 {
            return;
        }
        let drop = usize::try_from(drop)
            .unwrap_or(self.leaves.len())
            .min(self.leaves.len());
        self.leaves.drain(..drop);
        self.start_index = base;
    }
}

/// Snapshot of the beacon-witness accumulator's leaf hashes at the
/// state the supplied parent block would leave behind.
///
/// Returned as `(start_index, leaves)` — `leaves[0]` sits at the
/// absolute leaf index `start_index` (the committed accumulator's own
/// start).
///
/// Walks from `parent_block_hash` back through the pending chain to
/// the committed tip, re-deriving each ancestor's witness-leaf delta
/// from its receipts + manifest's `ready_signals` + missed-round scan,
/// then prepends the committed accumulator's retained window. Each
/// ancestor's leaves resolve against *its own* committee — the schedule
/// entry at the ancestor's `parent_qc.weighted_timestamp()`, matching the
/// commit-time derivation (`committee_of_block`). A pending chain that
/// straddles an epoch boundary therefore reproduces exactly what each
/// block committed, rather than re-deriving an older epoch's
/// missed-proposal leaves under the tip's committee. The result is the
/// input the verifier applies the block's own new leaves to.
///
/// Returns `Err(blocking_hash)` when the walk hits an ancestor that is
/// absent from `pending_blocks`, present but not yet assembled, or whose
/// committee the local beacon schedule can't yet resolve — the snapshot
/// is meaningless until that ancestor's data (or the beacon epoch behind
/// it) arrives. Callers defer the verification keyed on `blocking_hash`
/// and retry once it becomes available.
///
/// # Errors
///
/// `Err(blocking_hash)` for a missing or unassembled ancestor, or one
/// whose committee is unresolvable in `schedule`.
pub fn prospective_parent_witness_leaves(
    accumulator: &BeaconWitnessAccumulator,
    committed_hash: BlockHash,
    parent_block_hash: BlockHash,
    pending_blocks: &PendingBlocks,
    local_shard: ShardId,
    schedule: &TopologySchedule,
) -> Result<(BeaconWitnessLeafCount, Vec<Hash>), BlockHash> {
    let start_index = accumulator.start_index();
    let committed_leaves = accumulator.leaves();
    if parent_block_hash == committed_hash {
        return Ok((start_index, committed_leaves.to_vec()));
    }
    let mut chain_deltas: Vec<Vec<Hash>> = Vec::new();
    let mut current = parent_block_hash;
    while current != committed_hash {
        let Some(pending) = pending_blocks.get(current) else {
            return Err(current);
        };
        let Some(block) = pending.block() else {
            return Err(current);
        };
        let header = block.header();
        // This ancestor's leaves committed under its own committee — the
        // schedule entry at its `parent_qc.weighted_timestamp()`. Resolving
        // it per ancestor (rather than under the walk's tip committee) keeps
        // a boundary-straddling pending chain byte-identical to what each
        // block committed. Recovery-bridged: a halt recovery's bridge block
        // derives its leaves against the fresh committee that proposed it.
        let Some((committee, _)) =
            schedule.at_for_shard_live(local_shard, header.parent_qc().weighted_timestamp())
        else {
            return Err(current);
        };
        let committee = committee.as_ref();
        let receipts: Vec<StoredReceipt> = block
            .certificates()
            .iter()
            .flat_map(|fw| fw.receipts().iter().cloned())
            .collect();
        let missed = missed_proposals_since_prev_commit(
            local_shard,
            header.height(),
            header.parent_qc().round(),
            header.round(),
            committee,
        );
        let new_leaves = derive_leaves(
            local_shard,
            committee,
            &receipts,
            &missed,
            pending.manifest().ready_signals().as_slice(),
            pending
                .manifest()
                .reshape_trigger()
                .and_then(|t| t.to_payload(local_shard)),
        );
        chain_deltas.push(
            new_leaves
                .iter()
                .map(ShardWitnessPayload::leaf_hash)
                .collect(),
        );
        current = header.parent_block_hash();
    }
    let mut leaves = committed_leaves.to_vec();
    for delta in chain_deltas.iter().rev() {
        leaves.extend_from_slice(delta);
    }
    Ok((start_index, leaves))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    use hyperscale_types::test_utils::TestCommittee;
    use hyperscale_types::{
        BeaconWitnessRoot, BlockHeight, Bls12381G2Signature, NetworkDefinition, ReadySignal, Round,
        Stake, StakePoolId, TopologySnapshot, ValidatorId, ValidatorInfo, ValidatorSet,
        WeightedTimestamp, compute_merkle_root,
    };

    use super::*;

    fn pool_id() -> StakePoolId {
        StakePoolId::new(1)
    }

    fn deposit(amount: u64) -> ShardWitnessPayload {
        ShardWitnessPayload::StakeDeposit {
            pool_id: pool_id(),
            amount: Stake::from_whole_tokens(amount),
        }
    }

    fn topology_snapshot() -> TopologySnapshot {
        TestCommittee::new(4, 7).topology_snapshot(1)
    }

    /// [`topology_snapshot`]'s committee with `observer` holding a seat on
    /// ROOT's pending left child.
    fn topology_with_observer(observer: u64) -> TopologySnapshot {
        let committee = TestCommittee::new(4, 7);
        let infos: Vec<ValidatorInfo> = (0..committee.size())
            .map(|i| ValidatorInfo {
                validator_id: committee.validator_id(i),
                public_key: *committee.public_key(i),
            })
            .collect();
        let members: Vec<ValidatorId> = infos.iter().map(|v| v.validator_id).collect();
        let (left, _) = ShardId::ROOT.children();
        TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &ValidatorSet::new(infos),
            HashMap::from([(ShardId::ROOT, members.clone())]),
            HashMap::from([(ShardId::ROOT, members)]),
            HashMap::new(),
            HashMap::new(),
            BTreeMap::from([(
                ShardId::ROOT,
                BTreeMap::from([(ValidatorId::new(observer), left)]),
            )]),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::from([ShardId::ROOT]),
        )
    }

    fn ready_signal_for(validator: u64) -> ReadySignal {
        ReadySignal::new(
            ValidatorId::new(validator),
            ShardId::ROOT,
            WeightedTimestamp::from_millis(1),
            WeightedTimestamp::from_millis(100),
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

    /// `prune_to` drops leaves below the new base and advances the
    /// start; a base at or below the current start is a no-op, so the
    /// window only moves forward.
    #[test]
    fn prune_to_advances_the_window() {
        let mut acc = BeaconWitnessAccumulator::new();
        let payloads: Vec<_> = (1..=4).map(deposit).collect();
        acc.commit_append(&payloads);

        acc.prune_to(BeaconWitnessLeafCount::new(2));
        assert_eq!(acc.start_index(), BeaconWitnessLeafCount::new(2));
        assert_eq!(acc.leaf_count(), BeaconWitnessLeafCount::new(4));
        assert_eq!(
            acc.leaves(),
            &[deposit(3).leaf_hash(), deposit(4).leaf_hash()],
        );
        assert_eq!(
            acc.root(),
            BeaconWitnessRoot::from_raw(compute_merkle_root(acc.leaves())),
        );

        // Backwards or repeated prunes leave the window untouched.
        acc.prune_to(BeaconWitnessLeafCount::new(1));
        assert_eq!(acc.start_index(), BeaconWitnessLeafCount::new(2));
        acc.prune_to(BeaconWitnessLeafCount::new(2));
        assert_eq!(acc.leaf_count(), BeaconWitnessLeafCount::new(4));
    }

    /// A windowed accumulator counts the leaves before its retained
    /// start: `leaf_count = start_index + |window|`, through both the
    /// committed count and the preview, while the root commits the
    /// retained window only.
    #[test]
    fn windowed_accumulator_counts_from_start_index() {
        let window = vec![deposit(1).leaf_hash(), deposit(2).leaf_hash()];
        let acc = BeaconWitnessAccumulator::from_leaves(BeaconWitnessLeafCount::new(5), window);

        assert_eq!(acc.start_index(), BeaconWitnessLeafCount::new(5));
        assert_eq!(acc.leaf_count(), BeaconWitnessLeafCount::new(7));
        assert_eq!(
            acc.root(),
            BeaconWitnessRoot::from_raw(compute_merkle_root(acc.leaves())),
        );

        let (_, preview_count) = acc.preview_append(&[deposit(3)]);
        assert_eq!(preview_count, BeaconWitnessLeafCount::new(8));
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
        let topo = topology_snapshot();
        let missed = missed_proposals_since_prev_commit(
            ShardId::ROOT,
            BlockHeight::new(5),
            Round::INITIAL,
            Round::INITIAL.next(),
            &topo,
        );
        assert!(missed.is_empty());
    }

    #[test]
    fn missed_proposals_emits_one_per_skipped_round() {
        let topo = topology_snapshot();
        let parent_round = Round::INITIAL;
        let committed_round = Round::new(parent_round.inner() + 3);
        let missed = missed_proposals_since_prev_commit(
            ShardId::ROOT,
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
        let topo = topology_snapshot();
        let missed = missed_proposals_since_prev_commit(
            ShardId::ROOT,
            BlockHeight::new(5),
            Round::INITIAL,
            Round::new(Round::INITIAL.inner() + 2),
            &topo,
        );
        let ready = ready_signals(&[3, 1, 2]);
        let receipts: Vec<StoredReceipt> = Vec::new();

        // Validator 2 holds an observer seat: its signal classifies as
        // `ReshapeReady` in the same ascending-id position.
        let leaves = derive_leaves(
            ShardId::ROOT,
            &topology_with_observer(2),
            &receipts,
            &missed,
            &ready,
            Some(ShardWitnessPayload::ScheduleSplit {
                shard: ShardId::ROOT,
            }),
        );
        // 1 MissedProposal + 3 readiness witnesses (sorted ascending by
        // validator id, kind per sender) + the reshape trigger last.
        assert_eq!(leaves.len(), 5);
        assert!(matches!(
            &leaves[0],
            ShardWitnessPayload::MissedProposal { .. }
        ));
        match &leaves[1] {
            ShardWitnessPayload::Ready { id } => assert_eq!(id.inner(), 1),
            other => panic!("expected Ready, got {other:?}"),
        }
        match &leaves[2] {
            ShardWitnessPayload::ReshapeReady { validator, .. } => assert_eq!(validator.inner(), 2),
            other => panic!("expected ReshapeReady, got {other:?}"),
        }
        match &leaves[3] {
            ShardWitnessPayload::Ready { id } => assert_eq!(id.inner(), 3),
            other => panic!("expected Ready, got {other:?}"),
        }
        assert!(matches!(
            &leaves[4],
            ShardWitnessPayload::ScheduleSplit { .. }
        ));
    }

    #[test]
    fn derive_leaves_byte_identical_across_runs() {
        let topo = topology_snapshot();
        let missed = missed_proposals_since_prev_commit(
            ShardId::ROOT,
            BlockHeight::new(9),
            Round::INITIAL,
            Round::new(Round::INITIAL.inner() + 4),
            &topo,
        );
        let ready = ready_signals(&[7, 2]);
        let receipts: Vec<StoredReceipt> = Vec::new();

        let a = derive_leaves(ShardId::ROOT, &topo, &receipts, &missed, &ready, None);
        let b = derive_leaves(ShardId::ROOT, &topo, &receipts, &missed, &ready, None);
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
