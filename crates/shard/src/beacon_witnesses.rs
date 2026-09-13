//! Per-shard beacon-witness accumulator + leaf-derivation rules.
//!
//! Single owner for everything around the shard's
//! [`BeaconWitnessRoot`] commitment
//! on each [`BlockHeader`](hyperscale_types::BlockHeader): the in-memory
//! accumulator, the canonical leaf-derivation rule (receipts →
//! `MissedProposal` → readiness → reshape trigger), and the
//! post-execution verifier hook that downstream call sites delegate to.
//!
//! The module is intentionally storage-agnostic. Reads and writes
//! against the `beacon_witnesses` column family land alongside the
//! per-block-flow wiring; this module's job is to define the rules
//! and let proposer + verifier share them verbatim.

use std::collections::HashMap;
use std::sync::Arc;

use hyperscale_types::{
    BeaconWitnessLeafCount, BeaconWitnessRoot, Block, BlockHash, CertifiedBlock, Hash, ShardId,
    ShardWitnessPayload, StoredReceipt, TopologySchedule, Verified, WeightedTimestamp,
    commit_witness_window, compute_merkle_root, derive_leaves, missed_proposals_since_prev_commit,
};

use crate::pending::{PendingBlock, PendingBlocks};

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
    /// appending `new_payloads` without mutating `self` — the read-only
    /// counterpart to [`Self::commit_append`], deferring to the shared
    /// [`commit_witness_window`] fold so a preview can never drift from
    /// the proposer/verifier window arithmetic.
    #[must_use]
    pub fn preview_append(
        &self,
        new_payloads: &[ShardWitnessPayload],
    ) -> (BeaconWitnessRoot, BeaconWitnessLeafCount) {
        commit_witness_window(&self.leaves, new_payloads, self.start_index)
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
/// from its receipts + carried witness sources + missed-round scan,
/// then prepends the committed accumulator's retained window. Each
/// ancestor's leaves resolve against *its own* committee — the certified
/// binding of its committee anchor (its parent's
/// `parent_qc.weighted_timestamp()`, or `committed_block_anchor_wt` for the
/// ancestor extending the committed tip) and its certifying QC
/// (`parent_qc_wt` for the first ancestor, then each successor's
/// `parent_qc` down the chain), matching the commit-time
/// derivation. A pending chain that straddles an epoch boundary
/// therefore reproduces exactly what each block committed, rather than
/// re-deriving an older epoch's missed-proposal leaves under the tip's
/// committee — and a halt recovery's sync-admitted suffix keeps deriving
/// under the old committee its headers committed, while the bridge
/// blocks derive under the fresh committee that proposed them. The
/// result is the input the verifier applies the block's own new leaves
/// to.
///
/// An ancestor absent from `pending_blocks` falls back to
/// `certified_blocks` — the verified-certified cache where a
/// sync-admitted block sits while its round-contiguous commit is still
/// pending. A halt recovery's fresh committee extends exactly such a
/// tip: the halted suffix arrives by block sync, never as pending
/// gossip, so without the fallback every vote on the first bridge block
/// would park on an ancestor that only that bridge block's own commit
/// could release.
///
/// Returns `Err(blocking_hash)` when the walk hits an ancestor that is
/// held nowhere, present but not yet assembled, or whose committee the
/// local beacon schedule can't yet resolve — the snapshot is
/// meaningless until that ancestor's data (or the beacon epoch behind
/// it) arrives. Callers defer the verification keyed on `blocking_hash`
/// and retry once it becomes available.
///
/// # Errors
///
/// `Err(blocking_hash)` for a missing or unassembled ancestor, or one
/// whose committee is unresolvable in `schedule`.
#[allow(clippy::too_many_arguments)] // the walk threads the caller's full chain-prefix context
pub fn prospective_parent_witness_leaves<S: std::hash::BuildHasher>(
    accumulator: &BeaconWitnessAccumulator,
    committed_hash: BlockHash,
    committed_block_anchor_wt: WeightedTimestamp,
    parent_block_hash: BlockHash,
    parent_qc_wt: WeightedTimestamp,
    pending_blocks: &PendingBlocks,
    certified_blocks: &HashMap<BlockHash, Arc<Verified<CertifiedBlock>>, S>,
    local_shard: ShardId,
    schedule: &TopologySchedule,
) -> Result<(BeaconWitnessLeafCount, Vec<Hash>), BlockHash> {
    let start_index = accumulator.start_index();
    let committed_leaves = accumulator.leaves();
    if parent_block_hash == committed_hash {
        return Ok((start_index, committed_leaves.to_vec()));
    }
    // Descend to the committed tip before deriving anything: a block's
    // committee anchors on its parent, so an ancestor's anchor is only in
    // hand once the walk has reached the block below it.
    let mut chain: Vec<(&Block, WeightedTimestamp)> = Vec::new();
    let mut current = parent_block_hash;
    // The QC certifying `current` — the caller's `parent_qc` for the first
    // ancestor, then each block's own `parent_qc` as the walk descends.
    let mut certifying_wt = parent_qc_wt;
    while current != committed_hash {
        let block: &Block = match pending_blocks.get(current).map(PendingBlock::block) {
            Some(Some(block)) => block,
            // Present but unassembled — the content is on its way through
            // the pending pipeline; wait for it rather than shadow it.
            Some(None) => return Err(current),
            None => match certified_blocks.get(&current) {
                Some(certified) => certified.block(),
                None => return Err(current),
            },
        };
        chain.push((block, certifying_wt));
        certifying_wt = block.header().parent_qc().weighted_timestamp();
        current = block.header().parent_block_hash();
    }
    let mut leaves = committed_leaves.to_vec();
    for (index, (block, certifying_wt)) in chain.iter().enumerate().rev() {
        let header = block.header();
        // This ancestor's leaves committed under its own committee — the
        // certified binding of its committee anchor and its certifying QC.
        // The committee anchor is the parent's own anchor: `chain[index + 1]`
        // is this block's parent, and the walk's last entry extends the
        // committed tip. Resolving it per ancestor (rather than under the
        // walk's tip committee) keeps a boundary-straddling pending chain
        // byte-identical to what each block committed; the certified binding
        // keeps a halt recovery's sync-admitted suffix on the old committee
        // its headers committed while a bridge block resolves the fresh
        // committee that proposed it — stable across replicas however late
        // they walk it.
        let committee_anchor = chain
            .get(index + 1)
            .map_or(committed_block_anchor_wt, |(parent, _)| {
                parent.header().parent_qc().weighted_timestamp()
            });
        let Some((committee, _)) =
            schedule.at_for_shard_certified(local_shard, committee_anchor, *certifying_wt)
        else {
            return Err(block.hash());
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
            block.witness_sources(),
        );
        leaves.extend(new_leaves.iter().map(ShardWitnessPayload::leaf_hash));
    }
    Ok((start_index, leaves))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    use hyperscale_types::test_utils::TestCommittee;
    use hyperscale_types::{
        AggregateSignature, BeaconWitnessRoot, BlockHeader, BlockHeaderParts, BlockHeight,
        ConsensusSignature, Epoch, LocalTimestamp, NetworkDefinition, QuorumCertificate,
        ReadySignal, ReshapeSeat, ReshapeTrigger, Round, SignerBitfield, Stake, StakePoolId,
        TopologySnapshot, ValidatorId, ValidatorInfo, ValidatorSet, VrfProof, WeightedTimestamp,
        WitnessSources, compute_merkle_root,
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
                BTreeMap::from([(
                    ValidatorId::new(observer),
                    ReshapeSeat {
                        shard: left,
                        ready: false,
                    },
                )]),
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
            ConsensusSignature::new([0x42; 96]),
        )
    }

    fn ready_signals(ids: &[u64]) -> Vec<ReadySignal> {
        ids.iter().copied().map(ready_signal_for).collect()
    }

    /// A committee of `ids`, seated on ROOT in that order.
    fn committee_of(ids: &[u64]) -> TopologySnapshot {
        let infos: Vec<ValidatorInfo> = ids
            .iter()
            .map(|&id| ValidatorInfo {
                validator_id: ValidatorId::new(id),
                public_key: *TestCommittee::new(4, id).public_key(0),
            })
            .collect();
        let members: Vec<ValidatorId> = infos.iter().map(|v| v.validator_id).collect();
        TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &ValidatorSet::new(infos),
            HashMap::from([(ShardId::ROOT, members.clone())]),
            HashMap::from([(ShardId::ROOT, members)]),
            HashMap::new(),
            HashMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::from([ShardId::ROOT]),
        )
    }

    /// An empty block at `height` extending `parent_hash`, whose parent QC
    /// carries `anchor_ms` and sits `skipped` rounds below the block's own.
    fn chained(height: BlockHeight, parent_hash: BlockHash, anchor_ms: u64, skipped: u64) -> Block {
        let parent_round = Round::new(height.inner());
        let parent_qc = QuorumCertificate::new(
            parent_hash,
            ShardId::ROOT,
            BlockHeight::new(height.inner() - 1),
            BlockHash::ZERO,
            parent_round,
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(anchor_ms),
        );
        Block::Live {
            header: BlockHeader::new(BlockHeaderParts {
                height,
                parent_block_hash: parent_hash,
                parent_qc: parent_qc.into(),
                round: Round::new(parent_round.inner() + 1 + skipped),
                ..Default::default()
            }),
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        }
    }

    fn hold(pending: &mut PendingBlocks, block: &Block) {
        let mut p = PendingBlock::from_complete_block(block, vec![], vec![], LocalTimestamp::ZERO);
        p.construct_block().expect("complete block constructs");
        pending.insert(p);
    }

    /// The committee a block's leaves derive under must not depend on which
    /// path derives them.
    ///
    /// The prospective walk every proposer and verifier runs resolves each
    /// ancestor from that ancestor's own anchor. The commit that appends the
    /// same block's leaves to the accumulator resolves it from the parent's,
    /// which is where a block's committee lives. Straddle a cut that moves the
    /// round's proposer and one block's `MissedProposal` leaves name two
    /// different validators — so the root a proposer stamps is not the root its
    /// own accumulator ends up holding, and the next block's root is rejected
    /// by every verifier.
    #[test]
    fn a_blocks_leaves_derive_under_one_committee_on_every_path() {
        const ED: u64 = 1_000;
        let shard = ShardId::ROOT;

        let epoch0 = Arc::new(committee_of(&[0, 1, 2, 3]));
        let epoch1 = Arc::new(committee_of(&[10, 11, 12, 13]));
        let mut schedule = TopologySchedule::new(ED, Epoch::new(1), epoch1);
        schedule.insert(Epoch::new(0), Arc::clone(&epoch0));

        // Committed tip C, then A anchored below the cut, then P anchored
        // above it. P skips two rounds, so it carries `MissedProposal` leaves.
        let committed = BlockHash::from_raw(Hash::from_bytes(b"committed-tip"));
        let a = chained(BlockHeight::new(5), committed, ED - 1, 0);
        let p = chained(BlockHeight::new(6), a.hash(), ED + 1, 2);

        let mut pending = PendingBlocks::new();
        hold(&mut pending, &a);
        hold(&mut pending, &p);

        let (_, walked) = prospective_parent_witness_leaves(
            &BeaconWitnessAccumulator::new(),
            committed,
            WeightedTimestamp::from_millis(ED - 2),
            p.hash(),
            WeightedTimestamp::from_millis(ED + 1),
            &pending,
            &HashMap::new(),
            shard,
            &schedule,
        )
        .expect("both ancestors are held");

        // What the commit path derives for P: its committee anchors on A, so
        // it is epoch 0's, however far past the cut P dates itself.
        let missed = missed_proposals_since_prev_commit(
            shard,
            p.height(),
            p.header().parent_qc().round(),
            p.header().round(),
            &epoch0,
        );
        let committed_leaves: Vec<Hash> =
            derive_leaves(shard, &epoch0, &[], &missed, p.witness_sources())
                .iter()
                .map(ShardWitnessPayload::leaf_hash)
                .collect();

        assert_eq!(
            walked, committed_leaves,
            "the walk derived P's leaves under a different committee than its commit will",
        );
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
        let sources = WitnessSources::new(
            ready,
            Some(ReshapeTrigger::Split {
                epoch: Epoch::GENESIS,
            }),
            VrfProof::ZERO,
        );
        let leaves = derive_leaves(
            ShardId::ROOT,
            &topology_with_observer(2),
            &receipts,
            &missed,
            &sources,
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

        let sources = WitnessSources::new(ready, None, VrfProof::ZERO);
        let a = derive_leaves(ShardId::ROOT, &topo, &receipts, &missed, &sources);
        let b = derive_leaves(ShardId::ROOT, &topo, &receipts, &missed, &sources);
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
