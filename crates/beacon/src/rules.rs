//! Pure consensus rules over committed data.
//!
//! The per-shard boundary predicates the **producer, receiver-verifier, and
//! fold must agree on byte-for-byte**: which committed QC governs a shard's
//! boundary, whether a block is a genuine epoch crossing, the witness-chunk
//! bounds, and chunk well-formedness. Pure over committed-data shapes
//! ([`BeaconState`], [`BeaconBlock`], proposals, QCs, headers, witnesses) —
//! imports only [`hyperscale_types`], with no node-local state and no
//! topology, so the fold ([`crate::state`]) and the coordinator share one
//! definition and can't drift.

use std::collections::BTreeMap;

use hyperscale_types::{
    BeaconBlock, BeaconProposal, BeaconState, BlockHash, BlockHeader, EpochWindows,
    MAX_WITNESSES_PER_SHARD, QuorumCertificate, ShardId, ShardWitness, Verifiable,
};

/// Witness chunk bounds for one shard's boundary: `prior` is the applied
/// watermark and `chunk_end = min(prior + MAX_WITNESSES_PER_SHARD,
/// boundary_count)`, clamped so a boundary whose count regressed below
/// `prior` yields the empty range `(prior, prior)`. The proposer's chunk
/// sourcing, the received-block check, and the fold all derive the range
/// here, so they can't drift on which leaves a contribution carries.
#[must_use]
pub(crate) fn chunk_bounds(prior: u64, boundary_count: u64) -> (u64, u64) {
    let chunk_end = prior
        .saturating_add(MAX_WITNESSES_PER_SHARD as u64)
        .min(boundary_count.max(prior));
    (prior, chunk_end)
}

/// The witness chunk bounds for `shard` against `boundary_header`.
///
/// Reads the applied watermark from `state.boundaries` and the boundary's
/// accumulator count from the header, then derives the range via
/// [`chunk_bounds`].
#[must_use]
pub(crate) fn witness_chunk_bounds(
    state: &BeaconState,
    shard: ShardId,
    boundary_header: &BlockHeader,
) -> (u64, u64) {
    let prior = state.fold_watermark(shard);
    chunk_bounds(prior, boundary_header.beacon_witness_leaf_count().inner())
}

/// Whether `shard`'s recorded boundary is a live (non-terminal) record
/// already pinned to `block_hash`: the crossing is folded, so a committed
/// re-fold of it is a backlog drain, not a fresh liveness observation —
/// it must not reset the miss counter, refresh the live epoch, or release
/// a pending recovery. Terminal records are exempt: a merge child's
/// folded terminal keeps re-folding (and re-sourcing) until its parent
/// composes.
#[must_use]
pub(crate) fn crossing_already_recorded(
    state: &BeaconState,
    shard: ShardId,
    block_hash: BlockHash,
) -> bool {
    state
        .boundaries
        .get(&shard)
        .is_some_and(|b| b.terminal_epoch.is_none() && b.block_hash == block_hash)
}

/// Whether the recorded live crossing is fully folded — recorded per
/// [`crossing_already_recorded`] with its witness chunk drained
/// (`prior == chunk_end`). The proposer stops sourcing exactly what the
/// fold would read as a carried-nothing re-fold, so both sides read this
/// one rule: sourcing past it would keep re-folding data already
/// consumed, and stopping short of it would park the witness backlog.
#[must_use]
pub(crate) fn crossing_fully_folded(
    state: &BeaconState,
    shard: ShardId,
    boundary_header: &BlockHeader,
) -> bool {
    let (prior, chunk_end) = witness_chunk_bounds(state, shard, boundary_header);
    crossing_already_recorded(state, shard, boundary_header.hash()) && prior == chunk_end
}

/// Whether `witnesses` are exactly the contiguous, ascending 0-based leaf
/// range `[prior, chunk_end)`, each merkle-proving into
/// `boundary_header.beacon_witness_root()`. The shared shape check behind
/// both the fold's `apply_contribution_witnesses` and the received-block
/// [`contributions_well_formed`], so producer and verifier can't drift.
#[must_use]
pub(crate) fn contribution_chunk_valid(
    boundary_header: &BlockHeader,
    witnesses: &[ShardWitness],
    prior: u64,
    chunk_end: u64,
) -> bool {
    let Ok(expected_len) = usize::try_from(chunk_end.saturating_sub(prior)) else {
        return false;
    };
    if witnesses.len() != expected_len {
        return false;
    }
    for (offset, witness) in witnesses.iter().enumerate() {
        if witness.proof.leaf_index.inner() != prior + offset as u64 {
            return false;
        }
        if !witness.merkle_includes_in(boundary_header) {
            return false;
        }
    }
    true
}

/// Per-shard canonical boundary QC across a committed proposal set: the
/// entry with the highest `(weighted_timestamp, block_hash)`, breaking
/// ties on the hash so the choice is total and identical on every node.
///
/// The shared selection the assembler projects into `shard_contributions`,
/// the receiver re-derives to validate one, and the fold binds against —
/// so all three agree on which QC governs each shard. Every committed
/// boundary QC is a genuine crossing (enforced at proposal admission), so
/// the highest-timestamp pick can't be inflated by a forged entry.
#[must_use]
pub(crate) fn canonical_boundary_qcs<'a>(
    proposals: impl Iterator<Item = &'a BeaconProposal>,
) -> BTreeMap<ShardId, &'a QuorumCertificate> {
    let mut canonical: BTreeMap<ShardId, &QuorumCertificate> = BTreeMap::new();
    for proposal in proposals {
        for (shard, opt) in proposal.boundary_qcs().iter() {
            let Some(qc) = opt.as_ref().map(Verifiable::as_unverified) else {
                continue;
            };
            canonical
                .entry(*shard)
                .and_modify(|cur| {
                    if (qc.weighted_timestamp().as_millis(), qc.block_hash())
                        > (cur.weighted_timestamp().as_millis(), cur.block_hash())
                    {
                        *cur = qc;
                    }
                })
                .or_insert(qc);
        }
    }
    canonical
}

/// Whether `boundary_header` is the first block across the epoch cut `qc`
/// attests: its predecessor sits at or before the largest epoch boundary
/// below the block's own weighted timestamp (`qc.wt`). Pure over the
/// chain's epoch windows — the fold applies the same test.
#[must_use]
pub(crate) fn is_boundary_crossing(
    boundary_header: &BlockHeader,
    qc: &QuorumCertificate,
    windows: EpochWindows,
) -> bool {
    windows.is_crossing(
        boundary_header.parent_qc().weighted_timestamp(),
        qc.weighted_timestamp(),
    )
}

/// Whether `block`'s shard contributions are the faithful canonical
/// projection of its cert-bound committed boundary QCs.
///
/// Exactly one contribution per shard that has a committed QC, each binding
/// by hash to that shard's canonical committed QC, forming a genuine
/// epoch-boundary crossing, and carrying exactly the witness chunk
/// `[prior, chunk_end)` (merkle-proven against the boundary root).
/// Deterministic — a pure function of the committed proposals, the
/// contributions, and the parent `BeaconState` watermark, with no topology
/// lookup — so every honest node reaches the same verdict on the same
/// block and a Byzantine assembler's variant (a fabricated, stale, extra,
/// omitted, or short-witnessed contribution) is rejected identically
/// everywhere.
#[must_use]
pub(crate) fn contributions_well_formed(state: &BeaconState, block: &BeaconBlock) -> bool {
    let canonical = canonical_boundary_qcs(block.committed_proposals().iter().map(|(_, p)| p));
    let contributions = block.shard_contributions();
    if contributions.len() != canonical.len() {
        return false;
    }
    let windows = state.chain_config.epoch_windows();
    canonical.into_iter().all(|(shard, qc)| {
        contributions.get(&shard).is_some_and(|contribution| {
            let header = &contribution.boundary_header;
            if header.hash() != qc.block_hash() || !is_boundary_crossing(header, qc, windows) {
                return false;
            }
            let (prior, chunk_end) = witness_chunk_bounds(state, shard, header);
            contribution_chunk_valid(header, &contribution.witnesses, prior, chunk_end)
        })
    })
}
