//! Pure consensus rules over committed data.
//!
//! The per-shard boundary predicates the **producer, receiver-verifier, and
//! fold must agree on byte-for-byte**: which committed QC governs a shard's
//! boundary, whether a block is a genuine epoch crossing, the witness-chunk
//! bounds, and chunk well-formedness. Pure over committed-data shapes
//! ([`BeaconState`], [`BeaconBlock`], proposals, QCs, headers, witnesses) —
//! imports only [`hyperscale_types`] and the wire encoding, with no
//! node-local state and no topology, so the fold ([`crate::state`]) and
//! the coordinator share one definition and can't drift.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use hyperscale_hbor::to_vec as hbor_to_vec;
use hyperscale_types::{
    BeaconBlock, BeaconProposal, BeaconState, BlockHash, BlockHeader, Epoch, EpochWindows, Hash,
    MAX_WITNESSES_PER_SHARD, QuorumCertificate, ShardId, ShardWitnessPayload, Verifiable,
    verify_range_inclusion,
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
    // A mark for a cut that hasn't arrived yet describes a chain that is
    // still live and producing, so it re-sources and re-folds its recorded
    // crossing like any other — only a chain that has actually terminated
    // takes the exemption.
    let scheduled_unapplied = state.terminal_scheduled_unapplied(shard);
    state.boundaries.get(&shard).is_some_and(|b| {
        (b.terminal_epoch.is_none() || scheduled_unapplied) && b.block_hash == block_hash
    })
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

/// Whether `payloads` are exactly the leaf range `[prior, chunk_end)` of
/// `boundary_header`'s witness window, with `range_proof` lifting them to
/// `boundary_header.beacon_witness_root()`. The shared shape check behind
/// both the fold's `apply_contribution_witnesses` and the received-block
/// [`contributions_well_formed`], so producer and verifier can't drift.
///
/// Contiguity and leaf ordering are structural: positions come from the
/// range, so a gapped or reordered run reaches a different root rather
/// than failing a per-element index check. An empty range carries an
/// empty proof — a contribution can't spend block bytes on a chunk that
/// claims nothing.
#[must_use]
pub(crate) fn contribution_chunk_valid(
    boundary_header: &BlockHeader,
    payloads: &[ShardWitnessPayload],
    range_proof: &[Hash],
    prior: u64,
    chunk_end: u64,
) -> bool {
    let Ok(expected_len) = usize::try_from(chunk_end.saturating_sub(prior)) else {
        return false;
    };
    if payloads.len() != expected_len {
        return false;
    }
    if expected_len == 0 {
        return range_proof.is_empty();
    }
    let Some((lo, window_len)) = window_position(boundary_header, prior) else {
        return false;
    };
    let leaves: Vec<Hash> = payloads
        .iter()
        .map(ShardWitnessPayload::leaf_hash)
        .collect();
    verify_range_inclusion(
        *boundary_header.beacon_witness_root().as_raw(),
        &leaves,
        lo,
        window_len,
        range_proof,
    )
}

/// Resolve `leaf_index` against `boundary_header`'s witness window as
/// `(window-relative position, window length)`. `None` when the leaf sits
/// below the window's base or either value overflows the merkle helpers'
/// width.
#[must_use]
pub(crate) fn window_position(
    boundary_header: &BlockHeader,
    leaf_index: u64,
) -> Option<(usize, usize)> {
    let base = boundary_header.beacon_witness_base().inner();
    let count = boundary_header.beacon_witness_leaf_count().inner();
    let lo = usize::try_from(leaf_index.checked_sub(base)?).ok()?;
    let window_len = usize::try_from(count.saturating_sub(base)).ok()?;
    Some((lo, window_len))
}

/// Per-shard canonical boundary QC across a committed proposal set: the
/// entry that [`outranks`] every other, a function of the set and never
/// of the order its proposals are held in.
///
/// The shared selection the assembler projects into `shard_contributions`,
/// the receiver re-derives to validate one, and the fold binds against —
/// so all three agree on which QC governs each shard.
#[must_use]
pub(crate) fn canonical_boundary_qcs<'a>(
    proposals: impl Iterator<Item = &'a BeaconProposal>,
) -> BTreeMap<ShardId, &'a QuorumCertificate> {
    let mut canonical: BTreeMap<ShardId, &QuorumCertificate> = BTreeMap::new();
    for proposal in proposals {
        for (shard, opt) in proposal.boundary_qcs() {
            let Some(qc) = opt.as_ref().map(Verifiable::as_unverified) else {
                continue;
            };
            canonical
                .entry(*shard)
                .and_modify(|cur| {
                    if outranks(qc, cur) {
                        *cur = qc;
                    }
                })
                .or_insert(qc);
        }
    }
    canonical
}

/// Whether `qc` stands ahead of `cur` as their shard's canonical boundary
/// QC: the one over the higher `(height, block_hash)`, and between two
/// over one block the later dated.
///
/// A chain's crossings climb in height, so the highest is the newest, and
/// a certificate's height and block hash are what its signers signed. Its
/// weighted timestamp is not: a copy of an older crossing's certificate
/// can be dated above a newer one's, so the date orders nothing between
/// two blocks. The hash breaks a tie in height, which is a fork of the
/// shard's chain.
///
/// Every committed boundary QC cleared proposal admission, which lets one
/// certificate stand over a boundary block that is not a terminal, so two
/// entries over one block differ only where it is a terminal. Any genuine
/// certificate over a committed terminal is admitted, and a member can
/// offer the same signers beside another date. The latest dated stands:
/// an entry dated early cannot displace an honest reporter's, and
/// [`contributed_epoch`] refuses the canonical entry dated below the
/// terminal's own anchor, so the record a node joining the ended chain
/// adopts is never dated below the block it certifies. Two entries under
/// one date differ in their signers, and their encodings order them.
fn outranks(qc: &QuorumCertificate, cur: &QuorumCertificate) -> bool {
    let key = |qc: &QuorumCertificate| (qc.height(), qc.block_hash(), qc.weighted_timestamp());
    match key(qc).cmp(&key(cur)) {
        Ordering::Equal => qc != cur && encoded(qc) > encoded(cur),
        order => order.is_gt(),
    }
}

/// `qc`'s wire bytes, which order two certificates that differ at all.
fn encoded(qc: &QuorumCertificate) -> Vec<u8> {
    hbor_to_vec(qc).expect("a certificate decoded from a committed proposal encodes")
}

/// The epoch `header`, certified by `qc`, is `shard`'s contribution for,
/// or `None` when it is none.
///
/// A crossing header, the first block certified past an epoch boundary,
/// contributes for the boundary its QC crosses. A shard's terminal is the
/// first block whose parent QC lands past its cut, since the block before
/// it cannot know it is the last; it alone carries the terminal settled
/// root, and it contributes for the boundary its parent QC crossed. The
/// crossing past a shard's terminal epoch is the block before its
/// terminal, which contributes nothing.
///
/// A shard the state holds no boundary record of contributes nothing at
/// all. Every seated shard carries a record from the fold that seats it —
/// genesis seeds one per shard, and a reshape leaves a placeholder under
/// each id it forms — and keeps it until its chain has ended and its
/// terminal evidence has expired. A shard without one has therefore left,
/// and a crossing of its ended chain, however genuine its QC, is a replay:
/// folded, it would write a record under the id that carries no terminal
/// mark and so never drops, and apply the crossing's witness chunk over
/// from the first leaf.
///
/// Pure over the chain's epoch windows and the shard's boundary record —
/// the proposer's admission, the receiver's gate and the fold apply the
/// same test, each before the fold moves any record.
///
/// A header's parent QC is covered by the header's hash, so its date is
/// one a committed block embeds. For a block that is not a terminal
/// `qc`'s date decides the crossing, and proposal admission lets `qc`
/// stand over such a block only where it is the certificate the block's
/// committed child embeds. The receiver's gate and the fold hold the
/// header and `qc` alone, so they take that from admission: they bind
/// `qc` to the header by hash and repeat this arithmetic, and cannot
/// repeat the comparison with the child.
///
/// A terminal's `qc` places nothing, and no committed block need embed
/// it, so its date is whatever its proposer wrote. It is held to the one
/// bound a committed block gives: the terminal's own anchor. An
/// aggregation clamps every vote to the voted block's anchor and a voter
/// refuses a child whose parent QC regresses below it, so every
/// certificate a chain forms or embeds over the terminal sits at or above
/// the anchor, and one below it is a copy under a rewritten date. A block
/// extending the recorded certificate would be anchored below its parent.
#[must_use]
pub(crate) fn contributed_epoch(
    state: &BeaconState,
    shard: ShardId,
    header: &BlockHeader,
    qc: &QuorumCertificate,
    windows: EpochWindows,
) -> Option<Epoch> {
    let record = state.boundaries.get(&shard)?;
    if header.settled_txs_root().is_some() {
        let anchor = header.parent_qc().weighted_timestamp();
        if qc.weighted_timestamp() < anchor {
            return None;
        }
        return windows.terminal_crossing_epoch(anchor);
    }
    let crossed = windows.crossing_epoch(
        header.parent_qc().weighted_timestamp(),
        qc.weighted_timestamp(),
    )?;
    let past_terminal = record
        .terminal_epoch
        .is_some_and(|terminal| crossed > terminal);
    (!past_terminal).then_some(crossed)
}

/// Whether `header` is a block `shard`'s recorded boundary has left
/// behind: a different block at or below the recorded height.
///
/// A chain's crossings climb in height, and nothing else orders two of
/// them for the fold. An older crossing is as genuine as the newest, its
/// certificate's weighted timestamp rides outside the aggregate signature,
/// and its witness count equals the recorded watermark whenever the shard
/// wrote no leaf in between. What reads the record — a recovery's attested
/// frontier, the published windows, the retention floor a snap sync
/// assembles against, a terminal's evidence — holds what an earlier fold
/// recorded, so the record moves only to a higher block. Two blocks at
/// one height are a fork of the chain, and the first recorded stands.
///
/// A zero-hash placeholder names no block, and holds the height its
/// shard's chain begins above. Genesis seeds one at height zero, which
/// every block of a chain sits above. A reshape leaves one at the height
/// recorded for the shard it ends, the higher of the two for a merge. A
/// successor continues its predecessors' height line from their terminals,
/// so its genesis and every block after it sit above that height, whether
/// or not the fold ever seeds the genesis. A chain that ran under the same
/// id before sits at or below it: the id is taken up again only once that
/// chain's record has dropped, which waits on its successors producing,
/// and every chain over its keys since has continued the height line from
/// its terminal. Its crossings are as genuine as any, and taken over the
/// placeholder one would stand as the shard's record, mark the shard
/// produced with nothing committed, and apply a witness window from its
/// first leaf again.
///
/// A reshape successor's seeded genesis and a recovery's fresh committee
/// both extend the recorded block, so their crossings sit above it.
///
/// The proposer's sourcing, admission and the fold apply the same test.
#[must_use]
pub(crate) fn behind_recorded_boundary(
    state: &BeaconState,
    shard: ShardId,
    header: &BlockHeader,
) -> bool {
    state.boundaries.get(&shard).is_some_and(|record| {
        header.height() <= record.height && header.hash() != record.block_hash
    })
}

/// Whether `header`, certified by `qc`, is a crossing on a branch one of
/// `shard`'s recoveries discarded: some recovery in the shard's history
/// has it certified below the window before its bridge, at a height above
/// its attested frontier.
///
/// Every block the recovered chain certifies above the frontier is
/// certified at or past the window before the bridge: its bridge crossing
/// there, since its committee resolves through the bridge only from that
/// window on, and every later block past it. A crossing above the
/// frontier certified earlier is a replaced committee's, on a branch the
/// recovered chain does not extend, and its certificate verifies under
/// that committee's keys once the recovery is no longer pending.
///
/// Reads the date `qc` carries, as [`contributed_epoch`] does, and not
/// the header's anchor: a contribution's anchor sits at or below its
/// certificate's date, so one certified below the band's edge is anchored
/// below the bridge too.
///
/// A recovery's clear leaves the verdict unchanged. A later stamping
/// widens the band to the newer bridge. The history keeps only its newest
/// bindings, and the newest covers what an evicted one did: its frontier
/// is no lower and its bridge is later, and a crossing at or below its
/// frontier is behind the recorded boundary.
///
/// The proposer's sourcing, admission and the fold apply the same test.
#[must_use]
pub(crate) fn in_discarded_recovery_band(
    state: &BeaconState,
    shard: ShardId,
    header: &BlockHeader,
    qc: &QuorumCertificate,
) -> bool {
    let certified = state
        .chain_config
        .epoch_windows()
        .epoch_for(qc.weighted_timestamp());
    state.recoveries.get(&shard).is_some_and(|history| {
        history.iter().any(|binding| {
            certified.next() < binding.bridge() && header.height() > binding.attested_frontier
        })
    })
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
            if header.hash() != qc.block_hash()
                || contributed_epoch(state, shard, header, qc, windows).is_none()
            {
                return false;
            }
            let (prior, chunk_end) = witness_chunk_bounds(state, shard, header);
            contribution_chunk_valid(
                header,
                &contribution.payloads,
                &contribution.range_proof,
                prior,
                chunk_end,
            )
        })
    })
}
