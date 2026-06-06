//! [`BeaconWitnessRoot`] verification, plus the canonical leaf-derivation
//! helpers shared by proposer and verifier.

use thiserror::Error;

use crate::{
    BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHeight, ConsensusReceipt, Hash, ReadySignal,
    Round, ShardId, ShardWitnessPayload, StoredReceipt, TopologySnapshot, Verified, Verify,
    compute_merkle_root,
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
    /// Accumulator leaves at the parent block's tip — the prefix the
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
    /// Topology snapshot anchoring the proposer-rotation rule the
    /// missed-round walk reads.
    pub topology: &'a TopologySnapshot,
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
    topology: &TopologySnapshot,
) -> Vec<ShardWitnessPayload> {
    let mut missed = Vec::new();
    let mut round = parent_round.next();
    while round < committed_round {
        let proposer_id = topology.proposer_for(shard, round);
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
    missed: &[ShardWitnessPayload],
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
    out.extend_from_slice(missed);
    let mut sorted: Vec<&ReadySignal> = ready_signals.iter().collect();
    sorted.sort_by_key(|s| s.validator_id());
    for signal in sorted {
        out.push(ShardWitnessPayload::Ready {
            id: signal.validator_id(),
        });
    }
    out
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
/// `parent_witness_leaves`, and merkle-ing the result produces a root
/// that equals the header's claimed [`BeaconWitnessRoot`] **and** a
/// leaf count that equals the header's claimed count.
impl Verify<&BeaconWitnessRootContext<'_>> for BeaconWitnessRoot {
    type Error = BeaconWitnessRootVerifyError;

    fn verify(&self, ctx: &BeaconWitnessRootContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let expected_root = *self;
        let missed = missed_proposals_since_prev_commit(
            ctx.shard,
            ctx.height,
            ctx.parent_round,
            ctx.round,
            ctx.topology,
        );
        let new_leaves = derive_leaves(ctx.receipts, &missed, ctx.ready_signals);

        let mut leaves = ctx.parent_witness_leaves.clone();
        leaves.reserve(new_leaves.len());
        for payload in &new_leaves {
            leaves.push(payload.leaf_hash());
        }
        let computed_root = Self::from_raw(compute_merkle_root(&leaves));
        let computed_count = BeaconWitnessLeafCount::new(leaves.len() as u64);
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
