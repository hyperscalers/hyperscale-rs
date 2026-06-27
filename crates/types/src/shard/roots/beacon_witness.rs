//! [`BeaconWitnessRoot`] verification, plus the canonical leaf-derivation
//! helpers shared by proposer and verifier.

use thiserror::Error;

use crate::{
    BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHeight, ConsensusReceipt, Hash, ReadySignal,
    ReshapeThresholds, ReshapeTrigger, Round, ShardId, ShardWitnessPayload, StoredReceipt,
    TopologySnapshot, ValidatorId, Verified, Verify, compute_merkle_root,
};

/// Inputs the [`BeaconWitnessRoot`] verifier reads against.
///
/// Re-derives the block's new witness payloads from the three canonical
/// sources (`receipts`, the missed-round walk over
/// `(parent_round, round)`, and `ready_signals`), appends them to
/// `parent_witness_leaves`, and checks the resulting `(root, count)`
/// matches the header's claim.
#[derive(Debug)]
pub struct BeaconWitnessRootContext<'a> {
    /// Header's claimed leaf count after appending this block's new
    /// witness payloads. Verification checks the computed count matches.
    pub expected_leaf_count: BeaconWitnessLeafCount,
    /// Header's claimed beacon-witness window base. Verification checks
    /// it equals the schedule-resolved base for the block's window
    /// (`topology.witness_base(shard)`) — a proposer cannot shift the
    /// window it commits over.
    pub claimed_base: BeaconWitnessLeafCount,
    /// Absolute leaf index of `parent_witness_leaves[0]` — the
    /// committed accumulator's retained-window start. The recomputed
    /// leaf count is `parent_leaves_start + |window + new leaves|`.
    pub parent_leaves_start: BeaconWitnessLeafCount,
    /// Accumulator leaves at the parent block's tip — the window the
    /// new payloads append onto.
    pub parent_witness_leaves: Vec<Hash>,
    /// Round of the parent block — anchors the missed-proposal walk.
    pub parent_round: Round,
    /// Shard the block belongs to — anchors the proposer-rotation
    /// rule for the missed-round walk.
    pub shard: ShardId,
    /// Height of the block being verified.
    pub height: BlockHeight,
    /// Round at which the block was proposed.
    pub round: Round,
    /// Receipts that contribute leaves via `beacon_witness_events`.
    pub receipts: &'a [StoredReceipt],
    /// Ready signals carried on the block's manifest.
    pub ready_signals: &'a [ReadySignal],
    /// The manifest's reshape assertion. Verification recomputes the
    /// load predicate from `substate_bytes` + `thresholds` and rejects
    /// the block when the claim diverges — a committed trigger
    /// therefore carries the committee's quorum behind the load fact.
    pub reshape_trigger: Option<ReshapeTrigger>,
    /// Committed substate byte total behind the parent block's post-state —
    /// the load the predicate evaluates. A function of the block's
    /// ancestry, never of the local commit frontier.
    pub substate_bytes: u64,
    /// Reshape thresholds in force for this network.
    pub thresholds: ReshapeThresholds,
    /// Topology snapshot anchoring the proposer-rotation rule the
    /// missed-round walk reads.
    pub topology_snapshot: &'a TopologySnapshot,
}

/// Failure modes of [`BeaconWitnessRoot`] verification.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum BeaconWitnessRootVerifyError {
    /// Either the recomputed merkle root or the leaf count diverges
    /// from the header's claim — either one fails the block.
    #[error(
        "computed beacon-witness root {computed_root:?}/count {computed_count} ≠ \
         claimed {expected_root:?}/count {expected_count}"
    )]
    Mismatch {
        /// Header's claimed beacon-witness root.
        expected_root: BeaconWitnessRoot,
        /// Root computed by re-deriving leaves and merkle-ing.
        computed_root: BeaconWitnessRoot,
        /// Header's claimed leaf count.
        expected_count: u64,
        /// Count computed from the recomputed leaves.
        computed_count: u64,
    },
    /// The header's claimed window base differs from the
    /// schedule-resolved base for the block's window.
    #[error("claimed beacon-witness base {claimed} ≠ schedule-resolved base {expected}")]
    WindowBaseMismatch {
        /// Header's claimed window base.
        claimed: u64,
        /// Base resolved from the block's schedule entry.
        expected: u64,
    },
    /// The manifest's reshape assertion diverges from the locally
    /// recomputed load predicate — a claimed trigger the load doesn't
    /// justify, an omitted trigger the load demands, or a duplicate of
    /// one already in the window.
    #[error("manifest reshape trigger {claimed:?} ≠ derived {derived:?}")]
    ReshapeTriggerMismatch {
        /// The manifest's claim.
        claimed: Option<ReshapeTrigger>,
        /// The locally derived assertion.
        derived: Option<ReshapeTrigger>,
    },
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
    shard: ShardId,
    height: BlockHeight,
    parent_round: Round,
    committed_round: Round,
    topology_snapshot: &TopologySnapshot,
) -> Vec<ShardWitnessPayload> {
    let mut missed = Vec::new();
    let mut round = parent_round.next();
    while round < committed_round {
        let proposer_id = topology_snapshot.proposer_for(shard, round);
        missed.push(ShardWitnessPayload::MissedProposal {
            proposer_id,
            height,
            round,
        });
        round = round.next();
    }
    missed
}

/// Evaluate the load predicate behind a block's reshape assertion.
///
/// Fires `Split` when the committed substate byte total behind the block's
/// parent state reaches the split threshold, `Merge` when it falls
/// below the merge threshold — except when the would-be trigger's leaf
/// already sits in `window_leaves` (the block's witness window, i.e.
/// this epoch's leaves): the window bases re-freeze each epoch, so an
/// over-threshold shard re-asserts exactly once per epoch until the
/// beacon acts. A merge on the root shard never fires — there is no
/// parent to merge under.
///
/// Pure over its inputs; the proposer fills the manifest from it and
/// every replica recomputes it in [`BeaconWitnessRoot`] verification,
/// so a committed assertion is quorum-backed.
#[must_use]
pub fn derive_reshape_trigger(
    shard: ShardId,
    substate_bytes: u64,
    thresholds: &ReshapeThresholds,
    window_leaves: &[Hash],
) -> Option<ReshapeTrigger> {
    let kind = if substate_bytes >= thresholds.split_bytes {
        ReshapeTrigger::Split
    } else if substate_bytes < thresholds.merge_bytes() {
        ReshapeTrigger::Merge
    } else {
        return None;
    };
    let leaf = kind.to_payload(shard)?.leaf_hash();
    if window_leaves.contains(&leaf) {
        return None;
    }
    Some(kind)
}

/// Canonical leaf-derivation rule used by both proposer and verifier.
///
/// `shard` and `topology` are the block's own shard and the schedule
/// entry its window resolves to — the same pair the missed-proposal
/// walk reads — so every replica classifies ready signals against the
/// same observer set.
///
/// Ordering (locked — every honest validator must produce the same
/// `Vec<ShardWitnessPayload>` given the same inputs):
///
/// 1. Receipt-emitted witnesses in receipt-iteration order; within a
///    receipt, in the order the engine recorded them.
/// 2. `MissedProposal` witnesses in ascending round order (the helper
///    already sorts; pass its output verbatim).
/// 3. One readiness witness per ready signal, in ascending
///    `validator_id` order — `ReshapeReady` for a sender holding an
///    observer seat on this shard's pending split, `Ready` otherwise.
/// 4. The block's reshape trigger, if asserted (at most one).
#[must_use]
pub fn derive_leaves(
    shard: ShardId,
    topology_snapshot: &TopologySnapshot,
    receipts: &[StoredReceipt],
    missed: &[ShardWitnessPayload],
    ready_signals: &[ReadySignal],
    reshape: Option<ShardWitnessPayload>,
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
    out.extend_from_slice(missed);
    let mut sorted: Vec<&ReadySignal> = ready_signals.iter().collect();
    sorted.sort_by_key(|s| s.validator_id());
    for signal in sorted {
        out.push(ready_leaf_payload(
            shard,
            topology_snapshot,
            signal.validator_id(),
        ));
    }
    out.extend(reshape);
    out
}

/// Classify a validator's ready-signal leaf for `shard`: a split observer
/// of this shard, or a merge keeper running it, emits `ReshapeReady`;
/// everyone else emits a plain `Ready`.
///
/// Shared by [`derive_leaves`] and the proposer's per-window dedup, so the
/// leaf a proposer skips as already-committed is byte-identical to the one
/// the fold would apply.
#[must_use]
pub fn ready_leaf_payload(
    shard: ShardId,
    topology_snapshot: &TopologySnapshot,
    id: ValidatorId,
) -> ShardWitnessPayload {
    let reshaping = topology_snapshot
        .reshape_observer_child(shard, id)
        .is_some()
        || topology_snapshot.reshape_keeper_parent(shard, id).is_some();
    if reshaping {
        ShardWitnessPayload::ReshapeReady { validator: id }
    } else {
        ShardWitnessPayload::Ready { id }
    }
}

impl Verified<BeaconWitnessRoot> {
    /// Pipeline-attestation gate for slot prefill. The trust source is
    /// the verification pipeline's per-root tracking: an earlier
    /// verifier run already accepted `root` for this block.
    #[must_use]
    pub const fn from_pipeline_attestation(root: BeaconWitnessRoot) -> Self {
        Self::new_unchecked(root)
    }
}

/// Construction asserts: re-deriving the block's new witness payloads
/// from the receipts + missed-round walk + `ready_signals`, appending to
/// `parent_witness_leaves` trimmed to the block's window base, and
/// merkle-ing the result produces a root that equals the header's
/// claimed [`BeaconWitnessRoot`] **and** a leaf count that equals the
/// header's claimed count.
impl Verify<&BeaconWitnessRootContext<'_>> for BeaconWitnessRoot {
    type Error = BeaconWitnessRootVerifyError;

    fn verify(&self, ctx: &BeaconWitnessRootContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let expected_root = *self;
        let resolved_base = ctx.topology_snapshot.witness_base(ctx.shard);
        if ctx.claimed_base != resolved_base {
            tracing::warn!(
                claimed = ctx.claimed_base.inner(),
                expected = resolved_base.inner(),
                height = ctx.height.inner(),
                "Beacon-witness window base verification FAILED"
            );
            return Err(BeaconWitnessRootVerifyError::WindowBaseMismatch {
                claimed: ctx.claimed_base.inner(),
                expected: resolved_base.inner(),
            });
        }
        let missed = missed_proposals_since_prev_commit(
            ctx.shard,
            ctx.height,
            ctx.parent_round,
            ctx.round,
            ctx.topology_snapshot,
        );

        // The root commits the block's window only: drop parent leaves
        // below the validated base. The base never undercuts the parent
        // window's start (it is bounded by a committed ancestor's count,
        // and pruning follows commits), so the trim is in range for
        // honest local state; a defensive empty window fails the root
        // comparison loudly rather than verifying a misaligned prefix.
        let trim = usize::try_from(
            ctx.claimed_base
                .inner()
                .saturating_sub(ctx.parent_leaves_start.inner()),
        )
        .unwrap_or(usize::MAX);
        let window = ctx.parent_witness_leaves.get(trim..).unwrap_or(&[]);

        // The manifest's reshape assertion must equal the locally
        // recomputed load predicate — including the once-per-window
        // dedup, which scans the same trimmed window the root commits.
        let derived =
            derive_reshape_trigger(ctx.shard, ctx.substate_bytes, &ctx.thresholds, window);
        if derived != ctx.reshape_trigger {
            tracing::warn!(
                claimed = ?ctx.reshape_trigger,
                ?derived,
                substate_bytes = ctx.substate_bytes,
                height = ctx.height.inner(),
                "Reshape trigger verification FAILED"
            );
            return Err(BeaconWitnessRootVerifyError::ReshapeTriggerMismatch {
                claimed: ctx.reshape_trigger,
                derived,
            });
        }
        let new_leaves = derive_leaves(
            ctx.shard,
            ctx.topology_snapshot,
            ctx.receipts,
            &missed,
            ctx.ready_signals,
            derived.and_then(|t| t.to_payload(ctx.shard)),
        );

        let mut leaves = window.to_vec();
        leaves.reserve(new_leaves.len());
        for payload in &new_leaves {
            leaves.push(payload.leaf_hash());
        }
        let computed_root = Self::from_raw(compute_merkle_root(&leaves));
        let computed_count =
            BeaconWitnessLeafCount::new(ctx.claimed_base.inner() + leaves.len() as u64);
        if computed_root != expected_root || computed_count != ctx.expected_leaf_count {
            tracing::warn!(
                ?expected_root,
                ?computed_root,
                expected_count = ctx.expected_leaf_count.inner(),
                computed_count = computed_count.inner(),
                height = ctx.height.inner(),
                round = ctx.round.inner(),
                "Beacon-witness root verification FAILED"
            );
            return Err(BeaconWitnessRootVerifyError::Mismatch {
                expected_root,
                computed_root,
                expected_count: ctx.expected_leaf_count.inner(),
                computed_count: computed_count.inner(),
            });
        }
        Ok(Verified::new_unchecked(expected_root))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    use super::*;
    use crate::{
        NetworkDefinition, ValidatorId, ValidatorInfo, ValidatorSet, generate_bls_keypair,
    };

    /// A snapshot whose `witness_base(shard)` answers `base` for one
    /// validator's single-shard committee, carrying `observers` as the
    /// shard's pending-split cohort.
    fn snapshot_with_observers(
        shard: ShardId,
        base: u64,
        observers: BTreeMap<ValidatorId, ShardId>,
    ) -> TopologySnapshot {
        let validators = vec![ValidatorInfo {
            validator_id: ValidatorId::new(0),
            public_key: generate_bls_keypair().public_key(),
        }];
        let vs = ValidatorSet::new(validators);
        TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &vs,
            HashMap::from([(shard, vec![ValidatorId::new(0)])]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(shard, BeaconWitnessLeafCount::new(base))]),
            BTreeMap::from([(shard, observers)]),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::from([shard]),
        )
    }

    /// [`snapshot_with_observers`] with no cohort.
    fn snapshot_with_base(shard: ShardId, base: u64) -> TopologySnapshot {
        snapshot_with_observers(shard, base, BTreeMap::new())
    }

    /// A single-shard snapshot carrying `keepers` as `shard`'s pending
    /// merge keeper set (each keeper mapped to the parent it reforms).
    fn snapshot_with_keepers(
        shard: ShardId,
        base: u64,
        keepers: BTreeMap<ValidatorId, ShardId>,
    ) -> TopologySnapshot {
        let validators = vec![ValidatorInfo {
            validator_id: ValidatorId::new(0),
            public_key: generate_bls_keypair().public_key(),
        }];
        let vs = ValidatorSet::new(validators);
        TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &vs,
            HashMap::from([(shard, vec![ValidatorId::new(0)])]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(shard, BeaconWitnessLeafCount::new(base))]),
            BTreeMap::new(),
            BTreeMap::from([(shard, keepers)]),
            BTreeMap::new(),
            BTreeSet::from([shard]),
        )
    }

    fn context_with(
        topology_snapshot: &TopologySnapshot,
        shard: ShardId,
        claimed_base: u64,
        parent_witness_leaves: Vec<Hash>,
        expected_leaf_count: u64,
    ) -> BeaconWitnessRootContext<'_> {
        BeaconWitnessRootContext {
            expected_leaf_count: BeaconWitnessLeafCount::new(expected_leaf_count),
            claimed_base: BeaconWitnessLeafCount::new(claimed_base),
            parent_leaves_start: BeaconWitnessLeafCount::ZERO,
            parent_witness_leaves,
            parent_round: Round::INITIAL,
            shard,
            height: BlockHeight::new(5),
            // parent_round.next() — no missed-proposal walk, so the
            // empty committee in the snapshot is never consulted.
            round: Round::INITIAL.next(),
            receipts: &[],
            ready_signals: &[],
            reshape_trigger: None,
            substate_bytes: 0,
            thresholds: ReshapeThresholds::DISABLED,
            topology_snapshot,
        }
    }

    /// The load predicate: split at the threshold, merge below an
    /// eighth of it (never on the root shard), nothing in between, and
    /// at most one assertion per witness window.
    #[test]
    fn reshape_predicate_fires_on_load_and_dedups_per_window() {
        let thresholds = ReshapeThresholds { split_bytes: 100 };
        let child = ShardId::leaf(1, 0);

        assert_eq!(
            derive_reshape_trigger(child, 100, &thresholds, &[]),
            Some(ReshapeTrigger::Split),
        );
        // merge_bytes() == 12; the bound is strict.
        assert_eq!(
            derive_reshape_trigger(child, 11, &thresholds, &[]),
            Some(ReshapeTrigger::Merge),
        );
        assert_eq!(derive_reshape_trigger(child, 12, &thresholds, &[]), None);
        assert_eq!(derive_reshape_trigger(child, 50, &thresholds, &[]), None);
        // The root shard has no parent to merge under.
        assert_eq!(
            derive_reshape_trigger(ShardId::ROOT, 0, &thresholds, &[]),
            None,
        );
        // Disabled thresholds never fire.
        assert_eq!(
            derive_reshape_trigger(child, u64::MAX - 1, &ReshapeThresholds::DISABLED, &[]),
            None,
        );

        // A like trigger already in the window suppresses re-assertion;
        // an unrelated leaf does not.
        let split_leaf = ReshapeTrigger::Split.to_payload(child).unwrap().leaf_hash();
        assert_eq!(
            derive_reshape_trigger(child, 100, &thresholds, &[split_leaf]),
            None,
        );
        assert_eq!(
            derive_reshape_trigger(child, 100, &thresholds, &[Hash::from_bytes(b"other")]),
            Some(ReshapeTrigger::Split),
        );
    }

    /// A manifest asserting a trigger the load doesn't justify fails
    /// verification before any root recomputation.
    #[test]
    fn unjustified_reshape_claim_is_rejected() {
        let shard = ShardId::ROOT;
        let topology_snapshot = snapshot_with_base(shard, 0);
        let mut ctx = context_with(&topology_snapshot, shard, 0, Vec::new(), 0);
        ctx.reshape_trigger = Some(ReshapeTrigger::Split);

        assert_eq!(
            BeaconWitnessRoot::ZERO.verify(&ctx).unwrap_err(),
            BeaconWitnessRootVerifyError::ReshapeTriggerMismatch {
                claimed: Some(ReshapeTrigger::Split),
                derived: None,
            }
        );
    }

    /// A manifest omitting a trigger the load demands fails the same way.
    #[test]
    fn omitted_due_reshape_is_rejected() {
        let shard = ShardId::ROOT;
        let topology_snapshot = snapshot_with_base(shard, 0);
        let mut ctx = context_with(&topology_snapshot, shard, 0, Vec::new(), 0);
        ctx.thresholds = ReshapeThresholds { split_bytes: 10 };
        ctx.substate_bytes = 10;

        assert_eq!(
            BeaconWitnessRoot::ZERO.verify(&ctx).unwrap_err(),
            BeaconWitnessRootVerifyError::ReshapeTriggerMismatch {
                claimed: None,
                derived: Some(ReshapeTrigger::Split),
            }
        );
    }

    /// A justified assertion verifies, with the trigger leaf appended
    /// last and counted.
    #[test]
    fn asserted_reshape_lands_in_the_root() {
        let shard = ShardId::ROOT;
        let topology_snapshot = snapshot_with_base(shard, 2);
        let trigger_leaf = ReshapeTrigger::Split.to_payload(shard).unwrap().leaf_hash();
        let expected_root = BeaconWitnessRoot::from_raw(compute_merkle_root(&[trigger_leaf]));

        let mut ctx = context_with(&topology_snapshot, shard, 2, Vec::new(), 3);
        ctx.parent_leaves_start = BeaconWitnessLeafCount::new(2);
        ctx.thresholds = ReshapeThresholds { split_bytes: 10 };
        ctx.substate_bytes = 11;
        ctx.reshape_trigger = Some(ReshapeTrigger::Split);

        assert!(expected_root.verify(&ctx).is_ok());
    }

    /// A ready signal from a validator holding an observer seat derives
    /// a `ReshapeReady` leaf — and the classification is
    /// consensus-critical: the same signal against a topology without
    /// the seat derives `Ready`, so the root no longer verifies.
    #[test]
    fn observer_signals_classify_as_reshape_ready_leaves() {
        use std::collections::BTreeMap;

        use crate::{ReadySignal, WeightedTimestamp, zero_bls_signature};

        let shard = ShardId::ROOT;
        let observer = ValidatorId::new(0);
        let signals = vec![ReadySignal::new(
            observer,
            WeightedTimestamp::from_millis(0),
            WeightedTimestamp::from_millis(10),
            zero_bls_signature(),
        )];
        let leaf = ShardWitnessPayload::ReshapeReady {
            validator: observer,
        }
        .leaf_hash();
        let expected_root = BeaconWitnessRoot::from_raw(compute_merkle_root(&[leaf]));

        let seated =
            snapshot_with_observers(shard, 0, BTreeMap::from([(observer, ShardId::leaf(1, 0))]));
        let mut ctx = context_with(&seated, shard, 0, Vec::new(), 1);
        ctx.ready_signals = &signals;
        assert!(expected_root.verify(&ctx).is_ok());

        let unseated = snapshot_with_base(shard, 0);
        let mut ctx = context_with(&unseated, shard, 0, Vec::new(), 1);
        ctx.ready_signals = &signals;
        assert!(matches!(
            expected_root.verify(&ctx),
            Err(BeaconWitnessRootVerifyError::Mismatch { .. }),
        ));
    }

    /// A ready signal from a validator holding a merge keeper seat on
    /// this shard also derives a `ReshapeReady` leaf — the keeper has
    /// synced the sibling half.
    #[test]
    fn keeper_signals_classify_as_reshape_ready_leaves() {
        use std::collections::BTreeMap;

        use crate::{ReadySignal, WeightedTimestamp, zero_bls_signature};

        let child = ShardId::leaf(1, 0);
        let parent = ShardId::ROOT;
        let keeper = ValidatorId::new(0);
        let signals = vec![ReadySignal::new(
            keeper,
            WeightedTimestamp::from_millis(0),
            WeightedTimestamp::from_millis(10),
            zero_bls_signature(),
        )];
        let leaf = ShardWitnessPayload::ReshapeReady { validator: keeper }.leaf_hash();
        let expected_root = BeaconWitnessRoot::from_raw(compute_merkle_root(&[leaf]));

        let seated = snapshot_with_keepers(child, 0, BTreeMap::from([(keeper, parent)]));
        let mut ctx = context_with(&seated, child, 0, Vec::new(), 1);
        ctx.ready_signals = &signals;
        assert!(expected_root.verify(&ctx).is_ok());

        // Without the keeper seat the same signal is a plain `Ready`, so
        // the `ReshapeReady` root no longer verifies.
        let unseated = snapshot_with_base(child, 0);
        let mut ctx = context_with(&unseated, child, 0, Vec::new(), 1);
        ctx.ready_signals = &signals;
        assert!(matches!(
            expected_root.verify(&ctx),
            Err(BeaconWitnessRootVerifyError::Mismatch { .. }),
        ));
    }

    /// A header whose claimed window base differs from the
    /// schedule-resolved value fails before any root recomputation — a
    /// proposer cannot shift the window it commits over.
    #[test]
    fn window_base_mismatch_is_rejected() {
        let shard = ShardId::ROOT;
        let topology_snapshot = snapshot_with_base(shard, 2);
        let ctx = context_with(&topology_snapshot, shard, 7, Vec::new(), 0);

        let result = BeaconWitnessRoot::ZERO.verify(&ctx);
        assert_eq!(
            result.unwrap_err(),
            BeaconWitnessRootVerifyError::WindowBaseMismatch {
                claimed: 7,
                expected: 2,
            }
        );
    }

    /// A claim matching the schedule-resolved base passes the window
    /// check and proceeds to the root comparison.
    #[test]
    fn matching_base_passes_window_check() {
        let shard = ShardId::ROOT;
        let topology_snapshot = snapshot_with_base(shard, 2);
        let leaves = vec![Hash::from_bytes(b"a"), Hash::from_bytes(b"b")];
        let expected_root = BeaconWitnessRoot::from_raw(compute_merkle_root(&leaves));
        let mut ctx = context_with(&topology_snapshot, shard, 2, leaves, 4);
        ctx.parent_leaves_start = BeaconWitnessLeafCount::new(2);

        assert!(expected_root.verify(&ctx).is_ok());
    }

    /// A block whose base advanced past the parent window's start trims
    /// the stale prefix before the root recomputation: the root commits
    /// `[base, count)` and the count stays globally cumulative.
    #[test]
    fn parent_window_trims_to_the_block_base() {
        let shard = ShardId::ROOT;
        let topology_snapshot = snapshot_with_base(shard, 2);
        let parent_leaves = vec![
            Hash::from_bytes(b"abs-1"),
            Hash::from_bytes(b"abs-2"),
            Hash::from_bytes(b"abs-3"),
        ];
        // Window after the trim: absolute leaves 2 and 3.
        let expected_root = BeaconWitnessRoot::from_raw(compute_merkle_root(&parent_leaves[1..]));

        let mut ctx = context_with(&topology_snapshot, shard, 2, parent_leaves, 4);
        ctx.parent_leaves_start = BeaconWitnessLeafCount::new(1);

        assert!(expected_root.verify(&ctx).is_ok());

        // The untrimmed full-prefix root no longer verifies.
        let mut stale = context_with(
            &topology_snapshot,
            shard,
            2,
            vec![
                Hash::from_bytes(b"abs-1"),
                Hash::from_bytes(b"abs-2"),
                Hash::from_bytes(b"abs-3"),
            ],
            4,
        );
        stale.parent_leaves_start = BeaconWitnessLeafCount::new(1);
        let full_root =
            BeaconWitnessRoot::from_raw(compute_merkle_root(&stale.parent_witness_leaves));
        assert!(full_root.verify(&stale).is_err());
    }
}
