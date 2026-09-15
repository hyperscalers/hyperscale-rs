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

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_types::{
    BeaconProposal, BeaconState, BlockHash, BlockHeader, NetworkDefinition, QcContext,
    QuorumCertificate, ScheduleLookup, ShardEpochContribution, ShardId, TopologySchedule,
    ValidatorId, Verified, Verifier, Verify,
};
use tracing::{debug, warn};

use crate::rules;
use crate::shard_source::ShardSourceTracker;

/// Whether every boundary QC a peer proposes is admissible.
///
/// A `Some` entry must name a boundary block this node has synced *and
/// established the commit of*, that block's canonical QC must be a
/// genuine `2f+1` of the governing shard committee, and the block must
/// be a real epoch-boundary crossing.
/// Unverifiable entries make the whole proposal inadmissible — this vnode
/// abstains, exactly as it does for an unverifiable witness, and the
/// one-honest-reporter rule covers a crossing this node hasn't yet seen.
/// Gating the vote keeps forged QCs out of the committed set: a committed
/// boundary QC carries `≥ f+1` honest verifiers, so the fold trusts what
/// commits.
#[must_use]
pub(crate) fn proposal_boundary_qcs_admissible(
    verifier: &dyn Verifier,
    proposal: &Verified<BeaconProposal>,
    state: &BeaconState,
    shard_source: &ShardSourceTracker,
    topology_schedule: &TopologySchedule,
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
                verifier,
                *shard,
                qc.as_unverified(),
                state,
                shard_source,
                topology_schedule,
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
///
/// A terminated shard's record lingers past its final epoch — to carry the
/// terminal contribution to the fold and project its settled-transaction root —
/// so its terminal crossing stays sourced until the fold consumes it. Once
/// a split parent's terminal has folded (the boundary record names it, its
/// children seeded), re-sourcing only forces every beacon member that never
/// synced the dead parent to abstain on the whole proposal, so it stops. A
/// merge child keeps sourcing its folded terminal: the parent composes only
/// when both children's terminals are recorded in one fold.
#[must_use]
pub(crate) fn source_boundary_qcs(
    state: &BeaconState,
    shard_source: &ShardSourceTracker,
) -> BTreeMap<ShardId, Option<QuorumCertificate>> {
    let sourced: BTreeSet<ShardId> = state
        .shard_committees
        .keys()
        .copied()
        .chain(
            state
                .boundaries
                .iter()
                .filter(|(_, b)| b.terminal_epoch.is_some())
                .map(|(shard, _)| *shard),
        )
        .collect();
    sourced
        .into_iter()
        .filter_map(|shard| {
            let watermark = state.fold_watermark(shard);
            let crossing = shard_source.next_crossing_to_source(shard, watermark)?;
            let qc = crossing.canonical_qc();
            let split_parent_terminal = crossing.boundary_header().split_child_roots().is_some();
            let folded = state
                .boundaries
                .get(&shard)
                .is_some_and(|b| b.terminal_epoch.is_some() && b.block_hash == qc.block_hash());
            if split_parent_terminal && folded {
                return None;
            }
            // A live shard's fully folded crossing carries nothing new.
            // Re-sourcing it keeps the fold re-consuming stale data, and
            // once the crossing's window ages below the schedule floor it
            // forces every verifier to abstain on any proposal carrying
            // it, parking the beacon on the skip path. Terminal records
            // are exempt as above: a merge child's folded terminal keeps
            // sourcing until its parent composes.
            if rules::crossing_fully_folded(state, shard, crossing.boundary_header()) {
                return None;
            }
            let (prior, chunk_end) =
                rules::witness_chunk_bounds(state, shard, crossing.boundary_header());
            // Coupling: only report a shard whose chunk we can supply.
            shard_source
                .has_witness_chunk(shard, qc.block_hash(), prior, chunk_end)
                .then(|| (shard, Some(qc.clone())))
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
pub(crate) fn build_shard_contributions(
    state: &BeaconState,
    shard_source: &ShardSourceTracker,
    committed: &[(ValidatorId, Verified<BeaconProposal>)],
) -> Option<BTreeMap<ShardId, ShardEpochContribution>> {
    let canonical = rules::canonical_boundary_qcs(committed.iter().map(|(_, p)| &**p));
    let mut contributions = BTreeMap::new();
    for (shard, qc) in canonical {
        // Defer the whole block if the header or its witness chunk isn't in
        // hand — a fully-synced peer will assemble and gossip it. The defer
        // is liveness-critical (a member that always defers never assembles),
        // so it names what it waits for.
        let Some(boundary_header) = boundary_header_for(shard_source, shard, qc.block_hash())
        else {
            warn!(
                shard = shard.inner(),
                block_hash = ?qc.block_hash(),
                "deferring candidate assembly — a committed boundary's header \
                 isn't synced locally; awaiting a fully-synced peer's candidate"
            );
            return None;
        };
        let boundary_header = boundary_header.clone();
        let (prior, chunk_end) = rules::witness_chunk_bounds(state, shard, &boundary_header);
        let Some((payloads, range_proof)) =
            shard_source.witness_chunk(shard, qc.block_hash(), prior, chunk_end)
        else {
            warn!(
                shard = shard.inner(),
                block_hash = ?qc.block_hash(),
                chunk_base = prior,
                chunk_end = chunk_end,
                "deferring candidate assembly — a committed boundary's witness \
                 chunk isn't in hand; awaiting a fully-synced peer's candidate"
            );
            return None;
        };
        contributions.insert(
            shard,
            ShardEpochContribution {
                boundary_header,
                payloads,
                range_proof,
            },
        );
    }
    Some(contributions)
}

/// Whether a single peer-proposed boundary QC clears admission: the local
/// node holds the boundary block and has established its commit, the QC
/// authenticates as a genuine `2f+1` of the governing shard committee,
/// and the block is a real epoch-boundary crossing.
fn boundary_qc_admissible(
    verifier: &dyn Verifier,
    shard: ShardId,
    qc: &QuorumCertificate,
    state: &BeaconState,
    shard_source: &ShardSourceTracker,
    topology_schedule: &TopologySchedule,
    network: &NetworkDefinition,
) -> bool {
    let Some(header) = boundary_header_for(shard_source, shard, qc.block_hash()) else {
        // Liveness-critical abstention: a member that never syncs this
        // header abstains from every proposal carrying the QC. Bounded to
        // one evaluation per proposer per epoch by the admission dedup.
        warn!(
            shard = shard.inner(),
            block_hash = ?qc.block_hash(),
            "abstaining from proposal admission — the proposed boundary QC's \
             block isn't synced locally"
        );
        return false;
    };
    // A 2f+1 QC proves availability, not commitment: a shard can halt
    // with its crossing block certified yet never committed, and a
    // boundary folded from it would anchor recovery on state no member's
    // committed chain can serve. Same abstention posture as the sync
    // gate above — the members whose windows hold the two-chain carry
    // the fold.
    if !shard_source.commit_established(shard, header) {
        warn!(
            shard = shard.inner(),
            block_hash = ?qc.block_hash(),
            "abstaining from proposal admission — the proposed boundary \
             block's commit isn't locally established"
        );
        return false;
    }
    boundary_qc_authentic(
        verifier,
        shard,
        header,
        qc,
        shard_source,
        topology_schedule,
        network,
    ) && rules::is_boundary_crossing(header, qc, state.chain_config.epoch_windows())
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
/// The committee anchors on the boundary block's *parent*: the lookup keys
/// on the parent header's own parent-QC weighted timestamp, read from the
/// same tracker window the boundary itself was looked up from. When the
/// parent isn't held, the boundary's own anchor stands in — the same window
/// except when the crossing follows an epoch-length stall, and abstention
/// is already this path's failure mode: the nodes that do hold the parent
/// carry the fold. The [`TopologySchedule`] retains historical committees
/// the live `BeaconState` no longer holds (a tracked crossing can lag the
/// tip by up to a few epochs). An unresolvable epoch fails closed either
/// way: a not-yet-committed one is this node lagging the proposer (abstain
/// and let it catch up), a below-floor one marks a crossing every consumer
/// frontier has passed.
///
/// Resolution is terminal-clamped and recovery-bridged
/// (`lookup_for_shard_certified`): a splitting shard's terminal crossing
/// can be anchored exactly on (or past) its cut — `is_boundary_crossing`
/// is parent-inclusive at the cut — and the anchor's half-open window no
/// longer carries the shard; the block is still proposed and signed by
/// the shard's final-epoch committee, the same resolution its own
/// replicas applied when voting it, so the QC must verify against that
/// committee. A halt recovery's bridge block — the crossing that
/// completes the recovery — is anchored below the bridge window but
/// certified at or past it, and verifies against the fresh committee.
fn boundary_qc_authentic(
    verifier: &dyn Verifier,
    shard: ShardId,
    boundary_header: &BlockHeader,
    qc: &QuorumCertificate,
    shard_source: &ShardSourceTracker,
    topology_schedule: &TopologySchedule,
    network: &NetworkDefinition,
) -> bool {
    if qc.block_hash() != boundary_header.hash() {
        return false;
    }
    let committee_anchor_wt = shard_source.parent_header(boundary_header).map_or_else(
        || boundary_header.parent_qc().weighted_timestamp(),
        |parent| parent.parent_qc().weighted_timestamp(),
    );
    // The only legitimate boundary crossing during a halt recovery is the
    // fresh committee's — the one that completes the recovery, which
    // re-binds (a stale anchor certified at or past the bridge) or anchors
    // at a current window. The halted suffix has no epoch crossing of its
    // own, so a crossing the fenced lookup rejects is the orphan a
    // beyond-f cohort forged extending the halted tip. Folding it would
    // clear the recovery and drop the cross-shard freeze.
    let snapshot = match topology_schedule.lookup_for_shard_certified_fenced(
        shard,
        committee_anchor_wt,
        qc.weighted_timestamp(),
    ) {
        None => {
            warn!(
                shard = shard.inner(),
                "Rejecting boundary QC that resolves the retained committee during a halt recovery"
            );
            return false;
        }
        Some((ScheduleLookup::Committee(snapshot), _)) => snapshot,
        Some((ScheduleLookup::NotYetCommitted, _)) => {
            debug!(
                shard = shard.inner(),
                "Boundary QC's committee epoch not committed yet — abstaining"
            );
            return false;
        }
        Some((ScheduleLookup::Evicted, _)) => {
            warn!(
                shard = shard.inner(),
                anchor_epoch = topology_schedule.epoch_for(committee_anchor_wt).inner(),
                qc_epoch = topology_schedule.epoch_for(qc.weighted_timestamp()).inner(),
                "Boundary QC's committee epoch is below the schedule floor — abstaining"
            );
            return false;
        }
    };
    let committee = snapshot.consensus_committee_for_shard(shard);
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
        verifier,
        network,
        public_keys: &public_keys,
        quorum_threshold: snapshot.quorum_threshold_for_shard(shard),
    })
    .is_ok()
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use hyperscale_crypto_bls::BlsVerifier;
    use hyperscale_types::test_utils::TestCommittee;
    use hyperscale_types::{
        AggregateSignature, BlockHeaderParts, BlockHeight, BlockVote, CertifiedBlockHeader, Epoch,
        ProposerTimestamp, Round, SignerBitfield, WeightedTimestamp,
    };

    use super::*;

    const ED: u64 = 1_000;
    const SHARD: ShardId = ShardId::ROOT;

    /// A header at `height` extending `parent_hash`, whose parent QC carries
    /// `anchor_ms` — the block's own position on the weighted-time grid.
    fn chained_header(
        height: u64,
        round: u64,
        parent_hash: BlockHash,
        anchor_ms: u64,
    ) -> BlockHeader {
        let parent_qc = QuorumCertificate::new(
            parent_hash,
            SHARD,
            BlockHeight::new(height.saturating_sub(1)),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(anchor_ms),
        );
        BlockHeader::new(BlockHeaderParts {
            shard_id: SHARD,
            height: BlockHeight::new(height),
            parent_block_hash: parent_hash,
            parent_qc: parent_qc.into(),
            timestamp: ProposerTimestamp::from_millis(0),
            round: Round::new(round),
            ..Default::default()
        })
    }

    /// A genuine 2f+1 QC over `header`, signed by `committee`'s first three
    /// seats, whose weighted timestamp lands at `wt_ms`.
    fn signed_qc(committee: &TestCommittee, header: &BlockHeader, wt_ms: u64) -> QuorumCertificate {
        let hash = header.hash();
        let votes: Vec<(usize, Verified<BlockVote>)> = (0..3)
            .map(|i| {
                let vote = BlockVote::new(
                    &NetworkDefinition::simulator(),
                    hash,
                    header.parent_block_hash(),
                    SHARD,
                    header.height(),
                    Round::INITIAL,
                    ValidatorId::new(i as u64),
                    committee.signer(i).as_ref(),
                    ProposerTimestamp::from_millis(wt_ms),
                )
                .expect("vote signs");
                (i, Verified::new_unchecked_for_test(vote))
            })
            .collect();
        Verified::<QuorumCertificate>::from_verified_votes(
            &BlsVerifier,
            hash,
            SHARD,
            header.height(),
            Round::INITIAL,
            header.parent_block_hash(),
            header.parent_qc().weighted_timestamp(),
            &votes,
        )
        .expect("aggregates over a non-empty vote set")
        .into_inner()
    }

    /// A boundary QC is signed by the boundary block's committee, which
    /// anchors on the block's *parent* — so a crossing that follows an
    /// epoch-length stall (consecutive anchors straddling an extra cut)
    /// verifies under the earlier window, resolved through the parent
    /// header the tracker already holds. Without the parent held, the
    /// block's own anchor stands in and resolves the later window, whose
    /// rotated keys reject the QC — the node abstains, and the nodes that
    /// do hold the parent carry the fold.
    #[test]
    fn a_boundary_qc_verifies_under_the_committee_its_parent_anchors() {
        let committee_a = TestCommittee::new(4, 1);
        let committee_b = TestCommittee::new(4, 2);
        let mut schedule = TopologySchedule::new(
            ED,
            Epoch::new(2),
            Arc::new(committee_b.topology_snapshot(1)),
        );
        schedule.insert(Epoch::new(0), Arc::new(committee_a.topology_snapshot(1)));
        schedule.insert(Epoch::new(1), Arc::new(committee_b.topology_snapshot(1)));

        // The parent anchors in epoch 0; the chain then stalls a full
        // window, so the boundary block's own anchor lands in epoch 1. Its
        // committee is epoch 0's — the window its parent anchors in.
        let parent = chained_header(9, 9, BlockHash::ZERO, ED - 1);
        let boundary = chained_header(10, 10, parent.hash(), ED + 1);
        let qc = signed_qc(&committee_a, &boundary, ED + 2);

        let mut shard_source = ShardSourceTracker::new();
        shard_source.on_verified_source_header(Arc::new(Verified::new_unchecked_for_test(
            CertifiedBlockHeader::new(parent, boundary.parent_qc().clone()),
        )));

        assert!(
            boundary_qc_authentic(
                &BlsVerifier,
                SHARD,
                &boundary,
                &qc,
                &shard_source,
                &schedule,
                &NetworkDefinition::simulator(),
            ),
            "the boundary QC must verify under the window its parent anchors, not the one it \
             dates itself into",
        );

        assert!(
            !boundary_qc_authentic(
                &BlsVerifier,
                SHARD,
                &boundary,
                &qc,
                &ShardSourceTracker::new(),
                &schedule,
                &NetworkDefinition::simulator(),
            ),
            "without the parent held, the fallback resolves the block's own window and its \
             rotated keys reject the QC — abstention, not mis-acceptance",
        );
    }

    /// A boundary QC over a certified-but-uncommitted block is
    /// inadmissible. A 2f+1 QC proves availability, not commitment: a
    /// shard can halt with its epoch-crossing block certified yet never
    /// committed, and a boundary folded from it would anchor recovery on
    /// state no member's committed chain can serve. Admission demands
    /// local commit evidence — a round-contiguous certified descendant
    /// pair — and abstains without it.
    #[test]
    fn an_uncommitted_boundary_qc_is_inadmissible() {
        use hyperscale_types::{BeaconChainConfig, BeaconState};

        let committee = TestCommittee::new(4, 1);
        let snapshot = Arc::new(committee.topology_snapshot(1));
        let mut schedule = TopologySchedule::new(ED, Epoch::new(1), Arc::clone(&snapshot));
        schedule.insert(Epoch::new(0), snapshot);
        let state = BeaconState::empty(BeaconChainConfig {
            epoch_duration_ms: ED,
            ..BeaconChainConfig::default()
        });

        let boundary = chained_header(10, 10, BlockHash::ZERO, ED - 1);
        let qc = signed_qc(&committee, &boundary, ED + 1);
        let held = |child: &BlockHeader| {
            let child_qc = QuorumCertificate::new(
                child.hash(),
                SHARD,
                child.height(),
                child.parent_block_hash(),
                Round::INITIAL,
                SignerBitfield::empty(),
                AggregateSignature::ZERO,
                WeightedTimestamp::from_millis(ED + 2),
            );
            let mut t = ShardSourceTracker::new();
            t.on_verified_source_header(Arc::new(Verified::new_unchecked_for_test(
                CertifiedBlockHeader::new(boundary.clone(), qc.clone()),
            )));
            t.on_verified_source_header(Arc::new(Verified::new_unchecked_for_test(
                CertifiedBlockHeader::new(child.clone(), child_qc),
            )));
            t
        };
        let admissible = |t: &ShardSourceTracker| {
            boundary_qc_admissible(
                &BlsVerifier,
                SHARD,
                &qc,
                &state,
                t,
                &schedule,
                &NetworkDefinition::simulator(),
            )
        };

        // A child that certifies the boundary across a round gap — a view
        // change between them — leaves it uncommitted.
        let gapped = chained_header(11, 12, boundary.hash(), ED + 2);
        assert!(
            !admissible(&held(&gapped)),
            "a certified-but-uncommitted boundary QC must not clear admission",
        );

        // The round-contiguous child direct-commits the boundary.
        let contiguous = chained_header(11, 11, boundary.hash(), ED + 2);
        assert!(
            admissible(&held(&contiguous)),
            "the same QC clears admission once the two-chain commits its block",
        );
    }
}
