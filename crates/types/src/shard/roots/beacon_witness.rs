//! [`BeaconWitnessRoot`] verification, plus the canonical leaf-derivation
//! helpers shared by proposer and verifier.

use hyperscale_crypto::Verifier;
use thiserror::Error;

use crate::shard::roots::reveal_chain::next_reveal_chain;
use crate::signing::shard_reveal_verify;
use crate::{
    BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHeight, ConsensusReceipt, Epoch, Hash,
    ReadySignal, ReshapeThresholds, ReshapeTrigger, RevealChain, Round, ShardId,
    ShardWitnessPayload, StoredReceipt, TopologySnapshot, ValidatorId, Verified, Verify,
    WitnessSources, compute_merkle_root, vrf_output_from_proof,
};

/// Inputs the [`BeaconWitnessRoot`] verifier reads against.
///
/// Re-derives the block's new witness payloads from the canonical
/// sources (`receipts`, the missed-round walk over
/// `(parent_round, round)`, and the block's carried
/// [`WitnessSources`]), appends them to `parent_witness_leaves`, and
/// checks the resulting `(root, count)` matches the header's claim.
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
    /// Header's claimed reveal chain. Verification recomputes it from
    /// `parent_reveal_chain`, the two anchor epochs, and the block's own
    /// reveal output, and rejects a mismatch — so a proposer can neither
    /// break the chain nor reseed it off an epoch boundary.
    pub claimed_reveal_chain: RevealChain,
    /// Reveal chain on the parent header — what this block's chain extends
    /// when both anchor in the same epoch.
    pub parent_reveal_chain: RevealChain,
    /// Epoch the parent header's committee is drawn from.
    pub parent_committee_anchor_epoch: Epoch,
    /// Epoch the committee of the block being verified is drawn from —
    /// the parent's committee anchor, a hop below this block's own. Differing
    /// from `parent_committee_anchor_epoch` is what reseeds the chain.
    ///
    /// Also what stamps the block's reshape assertion. The window that
    /// assertion is deduped against is trimmed at a base resolved from
    /// the same anchor, so stamping on any other clock would let the two
    /// drift and the dedup outlive the window it was made in.
    pub committee_anchor_epoch: Epoch,
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
    /// The block's carried witness sources. Each claim is re-verified
    /// before its leaf folds: every equivocation entry against the
    /// equivocator's registered key (two signature checks, so the QC attests
    /// the evidence is genuine and the beacon jails on it without
    /// re-verifying), the reshape assertion against the load predicate
    /// recomputed from `substate_bytes` + `thresholds`, and the
    /// randomness reveal as a valid VRF by the block's proposer over
    /// `(network, shard, height)` — an unverified proof would let the
    /// proposer choose its reveal output and grind the epoch seed.
    pub witness_sources: &'a WitnessSources,
    /// Committed substate byte total behind the parent block's post-state —
    /// the load the predicate evaluates. A function of the block's
    /// ancestry, never of the local commit frontier. `None` takes the
    /// predicate out of play — reshaping disabled, or the ancestry
    /// crosses a halt recovery's sync-admitted suffix, where the total
    /// is unknowable until the suffix commits — and the required
    /// assertion is absent: a manifest claiming a trigger anyway is
    /// rejected.
    pub substate_bytes: Option<u64>,
    /// The header's own claim about that total. Verification rejects a
    /// claim that differs from the resolved value, which is what lets the
    /// next block's resolution read this header's field instead of walking
    /// its ancestry: the claim a descendant trusts was checked here.
    pub claimed_substate_bytes: Option<u64>,
    /// Reshape thresholds in force for this network.
    pub thresholds: ReshapeThresholds,
    /// Topology snapshot anchoring the proposer-rotation rule the
    /// missed-round walk reads.
    pub topology_snapshot: &'a TopologySnapshot,
    /// Scheme verifier the randomness-reveal VRF check runs through.
    pub verifier: &'a dyn Verifier,
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
    /// The header's reveal chain is not the one its parent's chain and
    /// this block's reveal output derive — a broken link, or a reseed
    /// claimed without an anchor-epoch change.
    #[error("reveal chain mismatch: claimed {claimed:?}, computed {computed:?}")]
    RevealChainMismatch {
        /// Header's claimed chain.
        claimed: RevealChain,
        /// Chain the shared derivation produces.
        computed: RevealChain,
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
    /// The header's claimed substate byte total differs from the total
    /// resolved locally behind the block's parent state.
    #[error("claimed substate byte total {claimed:?} ≠ resolved {derived:?}")]
    SubstateBytesMismatch {
        /// The header's claim.
        claimed: Option<u64>,
        /// The locally resolved total.
        derived: Option<u64>,
    },
    /// The block's randomness reveal is not a valid VRF by the
    /// block's proposer over `(network, shard, height)`. Its digest is
    /// committed in the root, but an unverified proof would let the proposer
    /// choose the output and grind the seed.
    #[error("randomness reveal is not a valid VRF by the block proposer")]
    RevealInvalid,
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

/// Check the manifest's reshape assertion against the locally recomputed
/// load predicate — including the once-per-epoch dedup, which scans the
/// same trimmed window the root commits.
///
/// A `None` byte total takes the predicate out of play and requires an
/// absent assertion.
///
/// # Errors
///
/// Returns [`BeaconWitnessRootVerifyError::ReshapeTriggerMismatch`] when
/// the claim differs from the recomputed assertion in any part — kind,
/// or the epoch it was made in.
fn verify_reshape_trigger(
    ctx: &BeaconWitnessRootContext<'_>,
    window: &[Hash],
) -> Result<(), BeaconWitnessRootVerifyError> {
    let derived = ctx.substate_bytes.and_then(|bytes| {
        derive_reshape_trigger(
            ctx.shard,
            bytes,
            ctx.topology_snapshot.fullness_of(ctx.shard),
            &ctx.thresholds,
            window,
            ctx.committee_anchor_epoch,
        )
    });
    if derived == ctx.witness_sources.reshape_trigger() {
        return Ok(());
    }
    tracing::warn!(
        claimed = ?ctx.witness_sources.reshape_trigger(),
        ?derived,
        substate_bytes = ?ctx.substate_bytes,
        height = ctx.height.inner(),
        "Reshape trigger verification FAILED"
    );
    Err(BeaconWitnessRootVerifyError::ReshapeTriggerMismatch {
        claimed: ctx.witness_sources.reshape_trigger(),
        derived,
    })
}

/// Evaluate the load predicate behind a block's reshape assertion.
///
/// Fires `Split` when the committed substate byte total behind the block's
/// parent state reaches the split threshold, `Merge` when it falls
/// below the merge threshold — except when the would-be trigger's leaf
/// already sits in `window_leaves`, which suppresses a second assertion
/// of the same thing in the same `epoch`. A merge on the root shard
/// never fires — there is no parent to merge under.
///
/// The epoch is in the leaf, so the suppression cannot outlive the epoch
/// that earned it. Deduping on the subject alone gives a shard one leaf
/// for its whole life, and the window only drains as the beacon folds
/// it — so an assertion the beacon missed would suppress every assertion
/// after it, and a shard unheard once would grow past its threshold in
/// silence forever.
///
/// Pure over its inputs; the proposer fills the manifest from it and
/// every replica recomputes it in [`BeaconWitnessRoot`] verification,
/// so a committed assertion is quorum-backed.
#[must_use]
pub fn derive_reshape_trigger(
    shard: ShardId,
    substate_bytes: u64,
    fullness: u32,
    thresholds: &ReshapeThresholds,
    window_leaves: &[Hash],
    epoch: Epoch,
) -> Option<ReshapeTrigger> {
    // Two ways to be too big, and either asserts the same split: what
    // the shard holds, and what its blocks have been spending. A shard
    // over its byte threshold is one committee serving too much state; a
    // shard over its fullness is one committee serving too much traffic,
    // which the network's own price cannot see.
    let kind = if substate_bytes >= thresholds.split_bytes || fullness >= thresholds.split_fullness
    {
        ReshapeTrigger::Split { epoch }
    } else if substate_bytes < thresholds.merge_bytes() && fullness < thresholds.merge_fullness() {
        // Both, because a merge answers to both: a shard small enough on
        // bytes and busy enough on traffic would fold into a parent that
        // starts idle, carries the sum of what its children carried, and
        // cannot assert a split back until its own mean catches up.
        ReshapeTrigger::Merge { epoch }
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
/// same observer set. `sources` is the block's carried
/// [`WitnessSources`].
///
/// Ordering (locked — every honest validator must produce the same
/// `Vec<ShardWitnessPayload>` given the same inputs):
///
/// 0. Receipt-emitted witnesses in receipt-iteration order; within a
///    receipt, in the order the engine recorded them.
/// 1. `MissedProposal` witnesses in ascending round order (the helper
///    already sorts; pass its output verbatim).
/// 2. One readiness witness per ready signal, in ascending
///    `validator_id` order — `ReshapeReady` for a sender holding an
///    observer seat on this shard's pending split, `Ready` otherwise.
/// 3. The block's reshape trigger, if asserted (at most one).
#[must_use]
pub fn derive_leaves(
    shard: ShardId,
    topology_snapshot: &TopologySnapshot,
    receipts: &[StoredReceipt],
    missed: &[ShardWitnessPayload],
    sources: &WitnessSources,
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
    let mut sorted: Vec<&ReadySignal> = sources.ready_signals().iter().collect();
    sorted.sort_by_key(|s| s.validator_id());
    for signal in sorted {
        out.push(ready_leaf_payload(
            shard,
            topology_snapshot,
            signal.validator_id(),
            signal.shard(),
        ));
    }
    out.extend(sources.reshape_trigger().and_then(|t| t.to_payload(shard)));
    out
}

/// Commit a block's witness window: the parent window extended with the
/// new payloads' leaf hashes, merkle-rooted, with the leaf count
/// continuing from the window `base`.
///
/// The proposer's root finalization and the verifier's recompute both
/// fold through here, so the two sides cannot drift on the window
/// arithmetic.
#[must_use]
pub fn commit_witness_window(
    window: &[Hash],
    new_leaves: &[ShardWitnessPayload],
    base: BeaconWitnessLeafCount,
) -> (BeaconWitnessRoot, BeaconWitnessLeafCount) {
    let mut leaves = Vec::with_capacity(window.len() + new_leaves.len());
    leaves.extend_from_slice(window);
    leaves.extend(new_leaves.iter().map(ShardWitnessPayload::leaf_hash));
    (
        BeaconWitnessRoot::from_raw(compute_merkle_root(&leaves)),
        BeaconWitnessLeafCount::new(base.inner() + leaves.len() as u64),
    )
}

/// Classify a validator's ready-signal leaf for `shard`: a split observer
/// of this shard, or a merge keeper running it, emits `ReshapeReady`;
/// everyone else emits a plain `Ready`.
///
/// `attested` is the shard the emitter signed readiness for — carried into
/// `ReshapeReady` so the fold can match it against the seat's target child.
///
/// Shared by [`derive_leaves`] and the proposer's per-window dedup, so the
/// leaf a proposer skips as already-committed is byte-identical to the one
/// the fold would apply.
#[must_use]
pub fn ready_leaf_payload(
    shard: ShardId,
    topology_snapshot: &TopologySnapshot,
    id: ValidatorId,
    attested: ShardId,
) -> ShardWitnessPayload {
    let reshaping = topology_snapshot
        .reshape_observer_child(shard, id)
        .is_some()
        || topology_snapshot.reshape_keeper_parent(shard, id).is_some();
    if reshaping {
        ShardWitnessPayload::ReshapeReady {
            validator: id,
            child: attested,
        }
    } else {
        ShardWitnessPayload::Ready { id }
    }
}

/// Check the header's claimed substate byte total against the locally
/// resolved value, absence included — the out-of-play total is a claim like
/// any other.
///
/// Runs before the reshape predicate that reads the same quantity, and it is
/// what lets a descendant's one-step recurrence read this header's field
/// instead of walking its ancestry: the claim a descendant trusts was
/// checked here, by this block's own committee.
fn verify_substate_bytes_claim(
    ctx: &BeaconWitnessRootContext<'_>,
) -> Result<(), BeaconWitnessRootVerifyError> {
    if ctx.claimed_substate_bytes != ctx.substate_bytes {
        tracing::warn!(
            claimed = ?ctx.claimed_substate_bytes,
            derived = ?ctx.substate_bytes,
            height = ctx.height.inner(),
            "Substate byte total verification FAILED"
        );
        return Err(BeaconWitnessRootVerifyError::SubstateBytesMismatch {
            claimed: ctx.claimed_substate_bytes,
            derived: ctx.substate_bytes,
        });
    }
    Ok(())
}

/// Check the header's claimed reveal chain against the shared derivation.
///
/// Runs after the reveal proof itself verifies, so the output folded here is
/// the one the block's proposer was bound to produce: the claim can only
/// differ by breaking the link or reseeding without an anchor-epoch change.
fn verify_reveal_chain(
    ctx: &BeaconWitnessRootContext<'_>,
) -> Result<(), BeaconWitnessRootVerifyError> {
    let computed = next_reveal_chain(
        ctx.parent_reveal_chain,
        ctx.parent_committee_anchor_epoch,
        ctx.committee_anchor_epoch,
        vrf_output_from_proof(ctx.witness_sources.randomness_reveal()),
    );
    if ctx.claimed_reveal_chain != computed {
        tracing::warn!(
            claimed = ?ctx.claimed_reveal_chain,
            ?computed,
            height = ctx.height.inner(),
            "Reveal chain verification FAILED"
        );
        return Err(BeaconWitnessRootVerifyError::RevealChainMismatch {
            claimed: ctx.claimed_reveal_chain,
            computed,
        });
    }
    Ok(())
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
/// from the receipts + missed-round walk + carried witness sources,
/// appending to `parent_witness_leaves` trimmed to the block's window
/// base, and merkle-ing the result produces a root that equals the
/// header's claimed [`BeaconWitnessRoot`] **and** a leaf count that
/// equals the header's claimed count.
impl Verify<&BeaconWitnessRootContext<'_>> for BeaconWitnessRoot {
    type Error = BeaconWitnessRootVerifyError;

    fn verify(&self, ctx: &BeaconWitnessRootContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let expected_root = *self;

        // The reveal feeds the block's `reveal_chain`, checked below
        // below. Gate on the proof being a genuine VRF by the block's
        // proposer first: an unverified proof would let the proposer
        // choose its reveal output and grind the epoch seed. Checked here,
        // inside the shared verifier, so no call site can fold an
        // unverified reveal.
        let proposer = ctx.topology_snapshot.proposer_for(ctx.shard, ctx.round);
        let reveal_ok = ctx
            .topology_snapshot
            .public_key(proposer)
            .is_some_and(|pk| {
                shard_reveal_verify(
                    ctx.verifier,
                    &pk,
                    ctx.topology_snapshot.network(),
                    ctx.shard,
                    ctx.height,
                    ctx.witness_sources.randomness_reveal(),
                )
            });
        if !reveal_ok {
            tracing::warn!(
                height = ctx.height.inner(),
                round = ctx.round.inner(),
                "Randomness reveal signature verification FAILED"
            );
            return Err(BeaconWitnessRootVerifyError::RevealInvalid);
        }

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

        verify_reveal_chain(ctx)?;
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

        verify_substate_bytes_claim(ctx)?;

        verify_reshape_trigger(ctx, window)?;
        let new_leaves = derive_leaves(
            ctx.shard,
            ctx.topology_snapshot,
            ctx.receipts,
            &missed,
            ctx.witness_sources,
        );

        let (computed_root, computed_count) =
            commit_witness_window(window, &new_leaves, ctx.claimed_base);
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

    use hyperscale_crypto::Signer;
    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};

    use super::*;
    use crate::{
        ConsensusSignature, NetworkDefinition, ReshapeSeat, ValidatorId, ValidatorInfo,
        ValidatorSet, VrfOutput, VrfProof, extend_reveal_chain, shard_reveal_sign,
    };

    /// The single committee member's key. Deterministic so a test can both
    /// seat its public key on the snapshot and sign a valid reveal with the
    /// matching secret — the block's proposer (`proposer_for` over the
    /// one-member committee) is always this validator.
    fn proposer_sk() -> BlsSigner {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&7u64.to_le_bytes());
        BlsSigner::from_seed(&seed)
    }

    /// A valid reveal for `shard` at the height `context_with` verifies at,
    /// signed by the proposer key seated on the test snapshots.
    fn signed_reveal(shard: ShardId) -> VrfProof {
        shard_reveal_sign(
            &proposer_sk(),
            &NetworkDefinition::simulator(),
            shard,
            BlockHeight::new(5),
        )
        .expect("sign")
    }

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
            public_key: proposer_sk().public_key(),
        }];
        let vs = ValidatorSet::new(validators);
        TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &vs,
            HashMap::from([(shard, vec![ValidatorId::new(0)])]),
            HashMap::from([(shard, vec![ValidatorId::new(0)])]),
            HashMap::new(),
            HashMap::from([(shard, BeaconWitnessLeafCount::new(base))]),
            BTreeMap::from([(shard, seats(observers))]),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::from([shard]),
        )
    }

    /// Cohort seats for a fixture that cares only about placement — the
    /// classification these tests exercise reads the shard, never `ready`.
    fn seats(placements: BTreeMap<ValidatorId, ShardId>) -> BTreeMap<ValidatorId, ReshapeSeat> {
        placements
            .into_iter()
            .map(|(id, shard)| {
                (
                    id,
                    ReshapeSeat {
                        shard,
                        ready: false,
                    },
                )
            })
            .collect()
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
            public_key: proposer_sk().public_key(),
        }];
        let vs = ValidatorSet::new(validators);
        TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &vs,
            HashMap::from([(shard, vec![ValidatorId::new(0)])]),
            HashMap::from([(shard, vec![ValidatorId::new(0)])]),
            HashMap::new(),
            HashMap::from([(shard, BeaconWitnessLeafCount::new(base))]),
            BTreeMap::new(),
            BTreeMap::from([(shard, seats(keepers))]),
            BTreeMap::new(),
            BTreeSet::from([shard]),
        )
    }

    /// Witness sources with a valid reveal for `shard` and nothing else —
    /// the baseline every `context_with` test customizes from.
    fn empty_sources(shard: ShardId) -> WitnessSources {
        WitnessSources::new(Vec::new(), None, signed_reveal(shard))
    }

    fn context_with<'a>(
        topology_snapshot: &'a TopologySnapshot,
        witness_sources: &'a WitnessSources,
        shard: ShardId,
        claimed_base: u64,
        parent_witness_leaves: Vec<Hash>,
        expected_leaf_count: u64,
    ) -> BeaconWitnessRootContext<'a> {
        BeaconWitnessRootContext {
            verifier: &BlsVerifier,
            expected_leaf_count: BeaconWitnessLeafCount::new(expected_leaf_count),
            claimed_base: BeaconWitnessLeafCount::new(claimed_base),
            // Same anchor epoch on both sides, so the fixture's claimed
            // chain is the parent's extended by this block's reveal.
            claimed_reveal_chain: next_reveal_chain(
                RevealChain::ZERO,
                Epoch::GENESIS,
                Epoch::GENESIS,
                vrf_output_from_proof(witness_sources.randomness_reveal()),
            ),
            parent_reveal_chain: RevealChain::ZERO,
            parent_committee_anchor_epoch: Epoch::GENESIS,
            committee_anchor_epoch: Epoch::GENESIS,
            parent_leaves_start: BeaconWitnessLeafCount::ZERO,
            parent_witness_leaves,
            parent_round: Round::INITIAL,
            shard,
            height: BlockHeight::new(5),
            // parent_round.next() — no missed-proposal walk. The reveal
            // check resolves the proposer as the snapshot's sole committee
            // member (validator 0), whose key signs `signed_reveal`.
            round: Round::INITIAL.next(),
            receipts: &[],
            witness_sources,
            substate_bytes: None,
            claimed_substate_bytes: None,
            thresholds: ReshapeThresholds::DISABLED,
            topology_snapshot,
        }
    }

    /// A shard running near its caps splits on that alone, whatever it
    /// holds — and a shard under the fraction is judged on its bytes as
    /// before, so the fullness arm adds a way to be too big rather than
    /// changing what the byte arm says.
    #[test]
    fn a_full_shard_splits_on_its_load_whatever_it_holds() {
        let thresholds = ReshapeThresholds {
            split_bytes: 100,
            split_fullness: 7_500,
        };
        let child = ShardId::leaf(1, 0);
        let split = Some(ReshapeTrigger::Split {
            epoch: Epoch::GENESIS,
        });

        // Holding almost nothing — which on the byte arm alone asserts a
        // merge — but running at three quarters of its caps.
        assert_eq!(
            derive_reshape_trigger(child, 0, 7_500, &thresholds, &[], Epoch::GENESIS),
            split,
        );
        assert_eq!(
            derive_reshape_trigger(child, 50, 7_500, &thresholds, &[], Epoch::GENESIS),
            split,
        );
        // A hair under is the byte arm's verdict, unchanged.
        assert_eq!(
            derive_reshape_trigger(child, 50, 7_499, &thresholds, &[], Epoch::GENESIS),
            None
        );
        // But a shard that busy does not merge either: a merge answers
        // to both dimensions, and one folding at three quarters of its
        // caps lands in a parent that starts idle and carries the sum.
        assert_eq!(
            derive_reshape_trigger(child, 0, 7_499, &thresholds, &[], Epoch::GENESIS),
            None
        );
        // Quiet as well as small is what merges — under the split
        // threshold's eighth, the dampener the bytes answer to.
        assert_eq!(
            derive_reshape_trigger(child, 0, 936, &thresholds, &[], Epoch::GENESIS),
            Some(ReshapeTrigger::Merge {
                epoch: Epoch::GENESIS
            }),
        );
        assert_eq!(
            derive_reshape_trigger(child, 0, 937, &thresholds, &[], Epoch::GENESIS),
            None,
            "and an eighth exactly is already too busy to fold"
        );
        // And a shard whose pools voted the predicate off never trips it,
        // however full it runs.
        assert_eq!(
            derive_reshape_trigger(
                child,
                50,
                u32::from(u16::MAX),
                &ReshapeThresholds {
                    split_fullness: u32::MAX,
                    ..thresholds
                },
                &[],
                Epoch::GENESIS
            ),
            None
        );
    }

    /// The load predicate: split at the threshold, merge below an
    /// eighth of it (never on the root shard), nothing in between, and
    /// at most one assertion per witness window.
    #[test]
    fn reshape_predicate_fires_on_load_and_dedups_per_window() {
        let thresholds = ReshapeThresholds {
            split_bytes: 100,
            split_fullness: u32::MAX,
        };
        let child = ShardId::leaf(1, 0);

        assert_eq!(
            derive_reshape_trigger(child, 100, 0, &thresholds, &[], Epoch::GENESIS),
            Some(ReshapeTrigger::Split {
                epoch: Epoch::GENESIS
            }),
        );
        // merge_bytes() == 12; the bound is strict.
        assert_eq!(
            derive_reshape_trigger(child, 11, 0, &thresholds, &[], Epoch::GENESIS),
            Some(ReshapeTrigger::Merge {
                epoch: Epoch::GENESIS
            }),
        );
        assert_eq!(
            derive_reshape_trigger(child, 12, 0, &thresholds, &[], Epoch::GENESIS),
            None
        );
        assert_eq!(
            derive_reshape_trigger(child, 50, 0, &thresholds, &[], Epoch::GENESIS),
            None
        );
        // The root shard has no parent to merge under.
        assert_eq!(
            derive_reshape_trigger(ShardId::ROOT, 0, 0, &thresholds, &[], Epoch::GENESIS),
            None,
        );
        // Disabled thresholds never fire.
        assert_eq!(
            derive_reshape_trigger(
                child,
                u64::MAX - 1,
                0,
                &ReshapeThresholds::DISABLED,
                &[],
                Epoch::GENESIS
            ),
            None,
        );

        // A like trigger already in the window suppresses re-assertion;
        // an unrelated leaf does not.
        let split_leaf = ReshapeTrigger::Split {
            epoch: Epoch::GENESIS,
        }
        .to_payload(child)
        .unwrap()
        .leaf_hash();
        assert_eq!(
            derive_reshape_trigger(child, 100, 0, &thresholds, &[split_leaf], Epoch::GENESIS),
            None,
        );
        assert_eq!(
            derive_reshape_trigger(
                child,
                100,
                0,
                &thresholds,
                &[Hash::from_bytes(b"other")],
                Epoch::GENESIS,
            ),
            Some(ReshapeTrigger::Split {
                epoch: Epoch::GENESIS
            }),
        );
    }

    /// A manifest asserting a trigger the load doesn't justify fails
    /// verification before any root recomputation.
    #[test]
    fn unjustified_reshape_claim_is_rejected() {
        let shard = ShardId::ROOT;
        let topology_snapshot = snapshot_with_base(shard, 0);
        let ws = WitnessSources::new(
            Vec::new(),
            Some(ReshapeTrigger::Split {
                epoch: Epoch::GENESIS,
            }),
            signed_reveal(shard),
        );
        let ctx = context_with(&topology_snapshot, &ws, shard, 0, Vec::new(), 0);

        assert_eq!(
            BeaconWitnessRoot::ZERO.verify(&ctx).unwrap_err(),
            BeaconWitnessRootVerifyError::ReshapeTriggerMismatch {
                claimed: Some(ReshapeTrigger::Split {
                    epoch: Epoch::GENESIS
                }),
                derived: None,
            }
        );
    }

    /// A manifest omitting a trigger the load demands fails the same way.
    #[test]
    fn omitted_due_reshape_is_rejected() {
        let shard = ShardId::ROOT;
        let topology_snapshot = snapshot_with_base(shard, 0);
        let ws = empty_sources(shard);
        let mut ctx = context_with(&topology_snapshot, &ws, shard, 0, Vec::new(), 0);
        ctx.thresholds = ReshapeThresholds {
            split_bytes: 10,
            split_fullness: u32::MAX,
        };
        ctx.substate_bytes = Some(10);
        ctx.claimed_substate_bytes = Some(10);

        assert_eq!(
            BeaconWitnessRoot::ZERO.verify(&ctx).unwrap_err(),
            BeaconWitnessRootVerifyError::ReshapeTriggerMismatch {
                claimed: None,
                derived: Some(ReshapeTrigger::Split {
                    epoch: Epoch::GENESIS
                }),
            }
        );
    }

    /// A byte total that is out of play — the ancestry crosses a halt
    /// recovery's sync-admitted suffix — requires an absent assertion:
    /// the same over-threshold claim that verifies with a resolved total
    /// is rejected without one.
    #[test]
    fn out_of_play_byte_total_rejects_any_claimed_trigger() {
        let shard = ShardId::ROOT;
        let topology_snapshot = snapshot_with_base(shard, 0);
        let ws = WitnessSources::new(
            Vec::new(),
            Some(ReshapeTrigger::Split {
                epoch: Epoch::GENESIS,
            }),
            signed_reveal(shard),
        );
        let mut ctx = context_with(&topology_snapshot, &ws, shard, 0, Vec::new(), 0);
        ctx.thresholds = ReshapeThresholds {
            split_bytes: 10,
            split_fullness: u32::MAX,
        };
        ctx.substate_bytes = None;

        assert_eq!(
            BeaconWitnessRoot::ZERO.verify(&ctx).unwrap_err(),
            BeaconWitnessRootVerifyError::ReshapeTriggerMismatch {
                claimed: Some(ReshapeTrigger::Split {
                    epoch: Epoch::GENESIS
                }),
                derived: None,
            }
        );
    }

    /// A justified assertion verifies, with the trigger leaf appended
    /// last and counted.
    #[test]
    fn asserted_reshape_lands_in_the_root() {
        let shard = ShardId::ROOT;
        let topology_snapshot = snapshot_with_base(shard, 2);
        let trigger_leaf = ReshapeTrigger::Split {
            epoch: Epoch::GENESIS,
        }
        .to_payload(shard)
        .unwrap()
        .leaf_hash();
        let expected_root = BeaconWitnessRoot::from_raw(compute_merkle_root(&[trigger_leaf]));

        let ws = WitnessSources::new(
            Vec::new(),
            Some(ReshapeTrigger::Split {
                epoch: Epoch::GENESIS,
            }),
            signed_reveal(shard),
        );
        let mut ctx = context_with(&topology_snapshot, &ws, shard, 2, Vec::new(), 3);
        ctx.parent_leaves_start = BeaconWitnessLeafCount::new(2);
        ctx.thresholds = ReshapeThresholds {
            split_bytes: 10,
            split_fullness: u32::MAX,
        };
        ctx.substate_bytes = Some(11);
        ctx.claimed_substate_bytes = Some(11);

        assert!(expected_root.verify(&ctx).is_ok());
    }

    /// The header's byte-total claim is checked against the local
    /// resolution before the predicate that reads it, in both directions: a
    /// claimed value where none resolves, and a value that simply differs.
    /// This is the check a descendant's one-step recurrence relies on.
    #[test]
    fn a_substate_byte_claim_that_diverges_is_rejected() {
        let shard = ShardId::ROOT;
        let topology_snapshot = snapshot_with_base(shard, 0);
        let ws = empty_sources(shard);

        // Claimed where nothing resolves — the out-of-play case a proposer
        // must state rather than paper over.
        let mut invented = context_with(&topology_snapshot, &ws, shard, 0, Vec::new(), 0);
        invented.claimed_substate_bytes = Some(4_096);
        assert_eq!(
            BeaconWitnessRoot::ZERO.verify(&invented).unwrap_err(),
            BeaconWitnessRootVerifyError::SubstateBytesMismatch {
                claimed: Some(4_096),
                derived: None,
            }
        );

        // Resolved but understated.
        let mut understated = context_with(&topology_snapshot, &ws, shard, 0, Vec::new(), 0);
        understated.substate_bytes = Some(8_192);
        understated.claimed_substate_bytes = Some(8_191);
        assert_eq!(
            BeaconWitnessRoot::ZERO.verify(&understated).unwrap_err(),
            BeaconWitnessRootVerifyError::SubstateBytesMismatch {
                claimed: Some(8_191),
                derived: Some(8_192),
            }
        );
    }

    /// A ready signal from a validator holding an observer seat derives
    /// a `ReshapeReady` leaf — and the classification is
    /// consensus-critical: the same signal against a topology without
    /// the seat derives `Ready`, so the root no longer verifies.
    #[test]
    fn observer_signals_classify_as_reshape_ready_leaves() {
        use std::collections::BTreeMap;

        use crate::{ReadySignal, WeightedTimestamp};

        let shard = ShardId::ROOT;
        let observer = ValidatorId::new(0);
        let child = ShardId::leaf(1, 0);
        let signals = vec![ReadySignal::new(
            observer,
            child,
            WeightedTimestamp::from_millis(0),
            WeightedTimestamp::from_millis(10),
            ConsensusSignature::ZERO,
        )];
        let leaf = ShardWitnessPayload::ReshapeReady {
            validator: observer,
            child,
        }
        .leaf_hash();
        let expected_root = BeaconWitnessRoot::from_raw(compute_merkle_root(&[leaf]));

        let ws = WitnessSources::new(signals, None, signed_reveal(shard));
        let seated = snapshot_with_observers(shard, 0, BTreeMap::from([(observer, child)]));
        let ctx = context_with(&seated, &ws, shard, 0, Vec::new(), 1);
        assert!(expected_root.verify(&ctx).is_ok());

        let unseated = snapshot_with_base(shard, 0);
        let ctx = context_with(&unseated, &ws, shard, 0, Vec::new(), 1);
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

        use crate::{ReadySignal, WeightedTimestamp};

        let child = ShardId::leaf(1, 0);
        let parent = ShardId::ROOT;
        let keeper = ValidatorId::new(0);
        let signals = vec![ReadySignal::new(
            keeper,
            child,
            WeightedTimestamp::from_millis(0),
            WeightedTimestamp::from_millis(10),
            ConsensusSignature::ZERO,
        )];
        let leaf = ShardWitnessPayload::ReshapeReady {
            validator: keeper,
            child,
        }
        .leaf_hash();
        let expected_root = BeaconWitnessRoot::from_raw(compute_merkle_root(&[leaf]));

        let ws = WitnessSources::new(signals, None, signed_reveal(child));
        let seated = snapshot_with_keepers(child, 0, BTreeMap::from([(keeper, parent)]));
        let ctx = context_with(&seated, &ws, child, 0, Vec::new(), 1);
        assert!(expected_root.verify(&ctx).is_ok());

        // Without the keeper seat the same signal is a plain `Ready`, so
        // the `ReshapeReady` root no longer verifies.
        let unseated = snapshot_with_base(child, 0);
        let ctx = context_with(&unseated, &ws, child, 0, Vec::new(), 1);
        assert!(matches!(
            expected_root.verify(&ctx),
            Err(BeaconWitnessRootVerifyError::Mismatch { .. }),
        ));
    }

    /// A reveal that isn't a valid VRF by the block's proposer fails
    /// before any root work — the digest feeds the chain, so an unverified
    /// proof would let the proposer choose the output and grind the seed.
    /// Both a zero sentinel and a reveal signed by the wrong key reject.
    /// The chain must be the one the parent's chain and this block's reveal
    /// derive: a broken link is rejected, and so is a reseed claimed while
    /// both sides anchor in the same epoch.
    #[test]
    fn a_reveal_chain_that_is_not_derived_is_rejected() {
        let shard = ShardId::ROOT;
        let snapshot = snapshot_with_base(shard, 0);
        let sources = empty_sources(shard);
        let mut ctx = context_with(&snapshot, &sources, shard, 0, Vec::new(), 0);

        // Baseline: the fixture's claimed chain is the derived one.
        let root = commit_witness_window(
            &[],
            &derive_leaves(shard, &snapshot, &[], &[], &sources),
            BeaconWitnessLeafCount::ZERO,
        )
        .0;
        assert!(root.verify(&ctx).is_ok());

        // A link off a different predecessor.
        ctx.claimed_reveal_chain = extend_reveal_chain(
            RevealChain::from_raw(Hash::from_bytes(b"other")),
            VrfOutput::ZERO,
        );
        assert!(matches!(
            root.verify(&ctx),
            Err(BeaconWitnessRootVerifyError::RevealChainMismatch { .. })
        ));

        // A reseed claimed without an anchor-epoch change: the parent chain
        // is non-zero, so seeding fresh is not what the derivation produces.
        let mut reseeding = context_with(&snapshot, &sources, shard, 0, Vec::new(), 0);
        reseeding.parent_reveal_chain = RevealChain::from_raw(Hash::from_bytes(b"parent"));
        assert!(matches!(
            root.verify(&reseeding),
            Err(BeaconWitnessRootVerifyError::RevealChainMismatch { .. })
        ));
    }

    #[test]
    fn invalid_reveal_is_rejected() {
        let shard = ShardId::ROOT;
        let topology_snapshot = snapshot_with_base(shard, 0);

        let zero_ws = WitnessSources::new(Vec::new(), None, VrfProof::ZERO);
        let zero = context_with(&topology_snapshot, &zero_ws, shard, 0, Vec::new(), 0);
        assert_eq!(
            BeaconWitnessRoot::ZERO.verify(&zero).unwrap_err(),
            BeaconWitnessRootVerifyError::RevealInvalid,
        );

        // A well-formed reveal by a non-proposer key is rejected too — the
        // check binds the proof to the block proposer's key, not merely to
        // "some valid VRF".
        let mut wrong_seed = [0u8; 32];
        wrong_seed[..8].copy_from_slice(&99u64.to_le_bytes());
        let impostor = BlsSigner::from_seed(&wrong_seed);
        let impostor_reveal = shard_reveal_sign(
            &impostor,
            &NetworkDefinition::simulator(),
            shard,
            BlockHeight::new(5),
        )
        .expect("sign");
        let wrong_ws = WitnessSources::new(Vec::new(), None, impostor_reveal);
        let wrong_key = context_with(&topology_snapshot, &wrong_ws, shard, 0, Vec::new(), 0);
        assert_eq!(
            BeaconWitnessRoot::ZERO.verify(&wrong_key).unwrap_err(),
            BeaconWitnessRootVerifyError::RevealInvalid,
        );
    }

    /// A header whose claimed window base differs from the
    /// schedule-resolved value fails before any root recomputation — a
    /// proposer cannot shift the window it commits over.
    #[test]
    fn window_base_mismatch_is_rejected() {
        let shard = ShardId::ROOT;
        let topology_snapshot = snapshot_with_base(shard, 2);
        let ws = empty_sources(shard);
        let ctx = context_with(&topology_snapshot, &ws, shard, 7, Vec::new(), 0);

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
        let expected_leaves = leaves.clone();
        let expected_root = BeaconWitnessRoot::from_raw(compute_merkle_root(&expected_leaves));
        let ws = empty_sources(shard);
        let mut ctx = context_with(&topology_snapshot, &ws, shard, 2, leaves, 4);
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
        // Window after the trim: absolute leaves 2 and 3, then the block's
        // own randomness reveal.
        let expected_leaves = parent_leaves[1..].to_vec();
        let expected_root = BeaconWitnessRoot::from_raw(compute_merkle_root(&expected_leaves));

        let ws = empty_sources(shard);
        let mut ctx = context_with(&topology_snapshot, &ws, shard, 2, parent_leaves, 4);
        ctx.parent_leaves_start = BeaconWitnessLeafCount::new(1);

        assert!(expected_root.verify(&ctx).is_ok());

        // The untrimmed full-prefix root no longer verifies.
        let mut stale = context_with(
            &topology_snapshot,
            &ws,
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
