//! Per-shard boundary-QC admission and assembly against local sync state.
//!
//! The boundary-QC operations that need node-local runtime — the synced
//! source-shard headers and witness pool in [`ShardSourceTracker`] and the
//! committee history in [`TopologySchedule`]. The pure predicates these
//! build on (canonical-QC selection, the crossing check, chunk bounds and
//! well-formedness) live in [`crate::rules`]; this module is their
//! runtime-coupled consumer:
//!
//! - **Admission** ([`proposal_boundary_qcs_admissible`]): does a peer's
//!   proposed boundary QC authenticate as a genuine `2f+1` crossing of the
//!   governing shard committee, resolved against the topology history?
//! - **Assembly** ([`source_boundary_qcs`], [`build_shard_contributions`]):
//!   the proposer's chunk-coupled QC sourcing and the assembler's canonical
//!   contribution projection, against the local witness pool.

use std::collections::BTreeMap;

use hyperscale_types::{
    BeaconProposal, BeaconState, BlockHash, BlockHeader, NetworkDefinition, QcContext,
    QuorumCertificate, ScheduleLookup, ShardEpochContribution, ShardId, TopologySchedule,
    ValidatorId, Verified, Verify,
};
use tracing::{debug, warn};

use crate::rules;
use crate::shard_source::ShardSourceTracker;

/// Whether every boundary QC a peer proposes is admissible.
///
/// A `Some` entry must name a boundary block this node has synced, that
/// block's canonical QC must be a genuine `2f+1` of the governing shard
/// committee, and the block must be a real epoch-boundary crossing.
/// Unverifiable entries make the whole proposal inadmissible — this vnode
/// abstains, exactly as it does for an unverifiable witness, and the
/// one-honest-reporter rule covers a crossing this node hasn't yet seen.
/// Gating the vote keeps forged QCs out of the committed set: a committed
/// boundary QC carries `≥ f+1` honest verifiers, so the fold trusts what
/// commits.
#[must_use]
pub fn proposal_boundary_qcs_admissible(
    proposal: &Verified<BeaconProposal>,
    state: &BeaconState,
    shard_source: &ShardSourceTracker,
    topology: &TopologySchedule,
    network: &NetworkDefinition,
) -> bool {
    proposal.boundary_qcs().iter().all(|(shard, opt)| {
        // A boundary QC's verification marker, when present, is only ever
        // BFT-transitive: the QC rides inside a `Verified<CertifiedBlockHeader>`
        // whose `parent_qc` is hash-bound to the header but never
        // signature-checked (`from_qc_attestation`). Admission therefore drops
        // the marker and re-verifies the QC's `2f+1` against the governing
        // committee, keeping beacon safety independent of the shard-sync trust
        // path — never trust the marker to skip this gate.
        opt.as_ref().is_none_or(|qc| {
            boundary_qc_admissible(
                *shard,
                qc.as_unverified(),
                state,
                shard_source,
                topology,
                network,
            )
        })
    })
}

/// Source this proposer's per-shard boundary QCs: each active shard's most
/// recently observed epoch-boundary crossing **whose witness chunk is in
/// hand**.
///
/// The witness-availability coupling: a shard is reported only if the
/// local node holds the chunk `[prior, chunk_end)` anchored to that
/// crossing's boundary block, so a committed boundary QC always implies
/// its witnesses are assemblable. Shards with no observed crossing — or an
/// observed crossing whose chunk hasn't fetched yet — are absent; one
/// honest reporter is enough to mark a shard live, so partial coverage is
/// fine.
#[must_use]
pub fn source_boundary_qcs(
    state: &BeaconState,
    shard_source: &ShardSourceTracker,
) -> BTreeMap<ShardId, Option<QuorumCertificate>> {
    state
        .shard_committees
        .keys()
        .filter_map(|shard| {
            let crossing = shard_source.latest_crossing(*shard)?;
            let qc = crossing.canonical_qc();
            let (prior, chunk_end) =
                rules::witness_chunk_bounds(state, *shard, crossing.boundary_header());
            // Coupling: only report a shard whose chunk we can supply.
            shard_source
                .has_witness_chunk(*shard, qc.block_hash(), prior, chunk_end)
                .then(|| (*shard, Some(qc.clone())))
        })
        .collect()
}

/// Assemble this epoch's per-shard boundary contributions — the canonical
/// projection of the committed proposals' boundary QCs.
///
/// Per shard, [`rules::canonical_boundary_qcs`] selects the highest-weighted
/// committed QC, and this seats the header for the block it names, pulled
/// from the local crossing tracker or header window. Every committed
/// boundary QC is a genuine `2f+1` crossing (enforced at proposal
/// admission), so the projection is a pure function of the cert-bound
/// committed proposals — every honest assembler that can back it builds
/// the byte-identical map.
///
/// Returns `None` to **defer** when a committed boundary's source header
/// isn't held locally: a block that omitted that shard would diverge from
/// a fully-synced peer's, so the local node waits for the peer's gossiped
/// block rather than assemble an incomplete one.
#[must_use]
pub fn build_shard_contributions(
    state: &BeaconState,
    shard_source: &ShardSourceTracker,
    committed: &[(ValidatorId, Verified<BeaconProposal>)],
) -> Option<BTreeMap<ShardId, ShardEpochContribution>> {
    let canonical = rules::canonical_boundary_qcs(committed.iter().map(|(_, p)| &**p));
    let mut contributions = BTreeMap::new();
    for (shard, qc) in canonical {
        let boundary_header = boundary_header_for(shard_source, shard, qc.block_hash())?.clone();
        let (prior, chunk_end) = rules::witness_chunk_bounds(state, shard, &boundary_header);
        // Defer the whole block if the chunk isn't in hand — a
        // fully-synced peer will assemble and gossip it.
        let witnesses = shard_source.witness_chunk(shard, qc.block_hash(), prior, chunk_end)?;
        contributions.insert(
            shard,
            ShardEpochContribution {
                boundary_header,
                witnesses: witnesses.into(),
            },
        );
    }
    Some(contributions)
}

/// Whether a single peer-proposed boundary QC clears admission: the local
/// node holds the boundary block, the QC authenticates as a genuine `2f+1`
/// of the governing shard committee, and the block is a real
/// epoch-boundary crossing.
fn boundary_qc_admissible(
    shard: ShardId,
    qc: &QuorumCertificate,
    state: &BeaconState,
    shard_source: &ShardSourceTracker,
    topology: &TopologySchedule,
    network: &NetworkDefinition,
) -> bool {
    let Some(header) = boundary_header_for(shard_source, shard, qc.block_hash()) else {
        return false;
    };
    boundary_qc_authentic(shard, header, qc, topology, network)
        && rules::is_boundary_crossing(header, qc, state.chain_config.epoch_duration_ms)
}

/// The locally-held header for `block_hash` in `shard`, via the
/// tracker's crossings-then-window lookup. `None` when the node hasn't
/// synced the block.
fn boundary_header_for(
    shard_source: &ShardSourceTracker,
    shard: ShardId,
    block_hash: BlockHash,
) -> Option<&BlockHeader> {
    shard_source
        .verified_header_by_block_hash(shard, block_hash)
        .map(|h| h.header())
}

/// Whether `qc` is a genuine `2f+1` quorum of the committee that governed
/// `boundary_header`, and commits exactly that block.
///
/// The committee is resolved at the boundary block's parent-QC weighted
/// timestamp — the window the block was produced in — through the
/// [`TopologySchedule`], which retains historical committees the live
/// `BeaconState` no longer holds (a tracked crossing can lag the tip by up
/// to a few epochs). An unresolvable epoch fails closed either way: a
/// not-yet-committed one is this node lagging the proposer (abstain and let
/// it catch up), a below-floor one marks a crossing every consumer frontier
/// has passed.
fn boundary_qc_authentic(
    shard: ShardId,
    boundary_header: &BlockHeader,
    qc: &QuorumCertificate,
    topology: &TopologySchedule,
    network: &NetworkDefinition,
) -> bool {
    if qc.block_hash() != boundary_header.hash() {
        return false;
    }
    let snapshot = match topology.lookup(boundary_header.parent_qc().weighted_timestamp()) {
        ScheduleLookup::Committee(snapshot) => snapshot,
        ScheduleLookup::NotYetCommitted => {
            debug!(
                shard = shard.inner(),
                "Boundary QC's committee epoch not committed yet — abstaining"
            );
            return false;
        }
        ScheduleLookup::Evicted => {
            warn!(
                shard = shard.inner(),
                "Boundary QC's committee epoch is below the schedule floor — abstaining"
            );
            return false;
        }
    };
    let committee = snapshot.committee_for_shard(shard);
    if committee.is_empty() {
        return false;
    }
    let mut public_keys = Vec::with_capacity(committee.len());
    for id in committee {
        let Some(pk) = snapshot.public_key(*id) else {
            return false;
        };
        public_keys.push(pk);
    }
    qc.verify(&QcContext {
        network,
        public_keys: &public_keys,
        quorum_threshold: snapshot.quorum_threshold_for_shard(shard),
    })
    .is_ok()
}
