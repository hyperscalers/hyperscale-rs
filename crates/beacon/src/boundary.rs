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

use hyperscale_hbor::Capped;
use hyperscale_types::{
    BeaconProposal, BeaconState, BlockHash, BlockHeader, BlockHeight, LocalTimestamp,
    MAX_TIMESTAMP_DELAY, MAX_TIMESTAMP_RUSH, NetworkDefinition, QcContext, QuorumCertificate,
    ScheduleLookup, ShardEpochContribution, ShardId, TopologySchedule, ValidatorId, Verified,
    Verifier, Verify,
};
use tracing::{debug, warn};

use crate::rules;
use crate::shard_source::{ObservedCrossing, ShardSourceTracker};

/// Whether every boundary QC a peer proposes is admissible.
///
/// A `Some` entry must name a boundary block this node has synced, it
/// must be the certificate the shard's committed chain lets stand over
/// that block ([`certificate_stands`]), a genuine `2f+1` of the governing
/// shard committee, and the block must be a real epoch-boundary crossing.
/// A terminal's must not be dated past what `now`, this member's clock,
/// allows ([`terminal_dated_past_the_clock`]).
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
    now: LocalTimestamp,
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
            let qc = qc.as_unverified();
            boundary_qc_admissible(
                verifier,
                *shard,
                qc,
                state,
                shard_source,
                topology_schedule,
                network,
            ) && !terminal_dated_past_the_clock(shard_source, *shard, qc, now)
        })
    })
}

/// The blocks `proposal`'s boundaries need that this node cannot judge
/// them without, as `(shard, height)`: a boundary whose header is not held
/// here, the block whose commit decides which certificate stands over a
/// held one ([`certificate_stands`]) — a terminal itself, any other
/// boundary's child — and a held boundary's parent, which names the
/// committee that signed it. An abstention on such a proposal is for want
/// of local state, not a verdict on it — each block is fetchable, and its
/// commit provable, from the shard. A chain commits one block per height,
/// so the height names the block.
#[must_use]
pub(crate) fn awaited_boundaries(
    proposal: &BeaconProposal,
    shard_source: &ShardSourceTracker,
) -> Vec<(ShardId, BlockHeight)> {
    let mut awaited = Vec::new();
    for (shard, opt) in proposal.boundary_qcs() {
        let Some(qc) = opt.as_ref() else {
            continue;
        };
        let qc = qc.as_unverified();
        let Some(header) = boundary_header_for(shard_source, *shard, qc.block_hash()) else {
            awaited.push((*shard, qc.height()));
            continue;
        };
        if certificate_stands(shard_source, *shard, header, qc).is_none() {
            let deciding = if header.settled_txs_root().is_some() {
                header.height()
            } else {
                header.height().next()
            };
            awaited.push((*shard, deciding));
        }
        if !header.parent_qc().is_genesis()
            && shard_source.parent_header(header).is_none()
            && let Some(parent_height) = header.height().prev()
        {
            awaited.push((*shard, parent_height));
        }
    }
    awaited
}

/// Whether the shard's committed chain lets `qc` stand as the certificate
/// over boundary block `header`, or `None` while the commit that decides
/// it is not established here.
///
/// A crossing is dated by the certificate a committed block embeds over
/// its parent, and by no other copy: a certificate's weighted timestamp
/// rides outside its signature, so the same signers verify beside any
/// date.
///
/// - A boundary block's date is its certificate's, and decides whether it
///   crosses, which epoch it contributes for and which committee signed
///   it. Only the certificate its committed child embeds stands
///   ([`ShardSourceTracker::committed_certificate`]).
/// - A terminal is the committed block of its own crossing: the
///   certificate it embeds over the block before it dates the boundary it
///   contributes for, so its own commit decides. Any certificate over it
///   stands, as proof that it was certified. A chain stops certifying
///   once its committed blocks prove its terminal committed, so the
///   commit of the block above a terminal need never reach an observer.
///   No committed block fixes that certificate's date, so admission
///   bounds it instead: [`rules::contributed_epoch`] from below by the
///   terminal's anchor, [`terminal_dated_past_the_clock`] from above.
fn certificate_stands(
    shard_source: &ShardSourceTracker,
    shard: ShardId,
    header: &BlockHeader,
    qc: &QuorumCertificate,
) -> Option<bool> {
    if header.settled_txs_root().is_some() {
        return shard_source
            .commit_established(shard, header)
            .then_some(true);
    }
    shard_source
        .committed_certificate(shard, header)
        .map(|committed| committed == qc)
}

/// Whether `qc` certifies a terminal held here and is dated further ahead
/// of this member's clock than an honestly aggregated certificate can be.
///
/// A weighted timestamp is the median of a quorum's vote clocks, held at
/// or above the voted block's anchor, and a voter refuses a block whose
/// anchor leads its own clock by more than the skew envelope. A
/// certificate a chain formed therefore leads an honest clock by at most
/// that envelope when it forms, and by less at any later reading.
///
/// Read for a terminal's certificate alone, whose date no committed block
/// fixes and which the fold records for a node joining the ended chain to
/// extend. At least one honest member admits what commits, so the
/// recorded date leads that member's clock by at most the envelope;
/// a date further out would have every voter refuse the block extending
/// it. Below this bound and above the terminal's anchor the date is its
/// proposer's to write.
fn terminal_dated_past_the_clock(
    shard_source: &ShardSourceTracker,
    shard: ShardId,
    qc: &QuorumCertificate,
    now: LocalTimestamp,
) -> bool {
    let reach =
        u64::try_from((MAX_TIMESTAMP_DELAY + MAX_TIMESTAMP_RUSH).as_millis()).unwrap_or(u64::MAX);
    let past = qc.weighted_timestamp().as_millis() > now.as_millis().saturating_add(reach)
        && boundary_header_for(shard_source, shard, qc.block_hash())
            .is_some_and(|header| header.settled_txs_root().is_some());
    if past {
        warn!(
            shard = shard.inner(),
            block_hash = ?qc.block_hash(),
            "Rejecting terminal boundary QC dated past the local clock"
        );
    }
    past
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
            let crossing = crossing_to_source(state, shard_source, shard)?;
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

/// The crossing `shard`'s boundary QC and witness chunk are sourced from:
/// the tracker's pick against the fold watermark, among the crossings the
/// fold would take as a contribution — the test admission applies.
pub(crate) fn crossing_to_source<'a>(
    state: &BeaconState,
    shard_source: &'a ShardSourceTracker,
    shard: ShardId,
) -> Option<&'a ObservedCrossing> {
    let windows = state.chain_config.epoch_windows();
    shard_source.next_crossing_to_source(shard, state.fold_watermark(shard), |crossing| {
        rules::contributed_epoch(
            state,
            shard,
            crossing.boundary_header(),
            crossing.canonical_qc(),
            windows,
        )
        .is_some()
            && !rules::behind_recorded_boundary(state, shard, crossing.boundary_header())
            && !rules::in_discarded_recovery_band(
                state,
                shard,
                crossing.boundary_header(),
                crossing.canonical_qc(),
            )
    })
}

/// Assemble this epoch's per-shard boundary contributions — the canonical
/// projection of the committed proposals' boundary QCs.
///
/// Per shard, [`rules::canonical_boundary_qcs`] selects the committed QC
/// over the highest block, and this seats the header for the block it
/// names, pulled from the local crossing tracker or header window. Every
/// committed boundary QC is a genuine `2f+1` crossing (enforced at
/// proposal admission), so the projection is a pure function of the
/// cert-bound committed proposals — every honest assembler that can back
/// it builds the byte-identical map.
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
                payloads: Capped::new(payloads)
                    .expect("a list under the cap its source already met"),
                range_proof: Capped::new(range_proof)
                    .expect("a list under the cap its source already met"),
            },
        );
    }
    Some(contributions)
}

/// Whether a single peer-proposed boundary QC clears admission: the local
/// node holds the boundary block, the QC is the certificate the shard's
/// committed chain lets stand over it ([`certificate_stands`]), it
/// authenticates as a genuine `2f+1` of the governing shard committee,
/// and the block is a real epoch-boundary crossing the shard's recorded
/// boundary has not left behind.
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
    // gate above — the members whose windows hold the commit carry the
    // fold.
    match certificate_stands(shard_source, shard, header, qc) {
        None => {
            warn!(
                shard = shard.inner(),
                block_hash = ?qc.block_hash(),
                "abstaining from proposal admission — the commit that dates the \
                 proposed boundary block isn't locally established"
            );
            return false;
        }
        Some(false) => {
            warn!(
                shard = shard.inner(),
                block_hash = ?qc.block_hash(),
                "Rejecting boundary QC that is not the certificate the block's committed child embeds"
            );
            return false;
        }
        Some(true) => {}
    }
    // A crossing the recorded boundary has left behind is genuine and
    // committed, and the fold takes nothing from it. A vote for it lets it
    // stand as the shard's canonical QC wherever no newer crossing is
    // proposed beside it, and the shard then reads as having missed the
    // fold.
    if rules::behind_recorded_boundary(state, shard, header) {
        warn!(
            shard = shard.inner(),
            block_hash = ?qc.block_hash(),
            "Rejecting boundary QC for a block the shard's recorded boundary has left behind"
        );
        return false;
    }
    // A crossing on a branch a recovery discarded verifies under the
    // committee it replaced once the recovery clears; recorded, it would
    // stand above the recovered chain's own crossings.
    if rules::in_discarded_recovery_band(state, shard, header, qc) {
        warn!(
            shard = shard.inner(),
            block_hash = ?qc.block_hash(),
            "Rejecting boundary QC for a crossing on a branch a recovery discarded"
        );
        return false;
    }
    rules::contributed_epoch(state, shard, header, qc, state.chain_config.epoch_windows()).is_some()
        && boundary_qc_authentic(
            verifier,
            shard,
            header,
            qc,
            shard_source,
            topology_schedule,
            network,
        )
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
/// except when the crossing follows an epoch-length stall. A failure then is
/// an abstention for want of the parent, which [`awaited_boundaries`] names
/// so the member asks for it and judges the proposal again. The [`TopologySchedule`] retains historical committees
/// the live `BeaconState` no longer holds (a tracked crossing can lag the
/// tip by up to a few epochs). An unresolvable epoch fails closed either
/// way: a not-yet-committed one is this node lagging the proposer (abstain
/// and let it catch up), a below-floor one marks a crossing every consumer
/// frontier has passed.
///
/// Resolution is terminal-clamped and recovery-bridged
/// (`lookup_for_shard_certified`): a splitting shard's terminal crossing
/// can be anchored exactly on its cut — a crossing is parent-inclusive at
/// the cut — and a terminal is anchored past it, where the anchor's
/// half-open window no longer carries the shard; the block is still
/// proposed and signed by
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

    use std::collections::BTreeMap;
    use std::iter;
    use std::sync::Arc;

    use hyperscale_crypto_bls::BlsVerifier;
    use hyperscale_types::test_utils::TestCommittee;
    use hyperscale_types::{
        AggregateSignature, BeaconChainConfig, BeaconWitnessLeafCount, BlockHeaderParts,
        BlockHeight, BlockVote, CertifiedBlockHeader, Epoch, EpochWindows, Hash, ProposerTimestamp,
        RecoveryBinding, RecoveryCause, Round, SettledTxsRoot, ShardBoundary, ShardRecovery,
        SignerBitfield, VrfProof, WeightedTimestamp,
    };

    use super::*;
    use crate::state::test_fixtures::{genesis_boundary, live_boundary};

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

    /// The block at `parent`'s next height, in `round`, embedding `parent_qc`
    /// as its certificate over `parent`.
    fn child_embedding(
        parent: &BlockHeader,
        parent_qc: &QuorumCertificate,
        round: u64,
    ) -> BlockHeader {
        BlockHeader::new(BlockHeaderParts {
            shard_id: SHARD,
            height: parent.height().next(),
            parent_block_hash: parent.hash(),
            parent_qc: parent_qc.clone().into(),
            timestamp: ProposerTimestamp::from_millis(0),
            round: Round::new(round),
            ..Default::default()
        })
    }

    /// An unsigned certificate over `header` dated `wt_ms`: what a block
    /// above it embeds where only the chain's shape is under test.
    fn unsigned_qc(header: &BlockHeader, wt_ms: u64) -> QuorumCertificate {
        QuorumCertificate::new(
            header.hash(),
            SHARD,
            header.height(),
            header.parent_block_hash(),
            Round::INITIAL,
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(wt_ms),
        )
    }

    /// `header` as a tracker holds it, under a stand-in certificate.
    fn held(header: &BlockHeader) -> Verified<CertifiedBlockHeader> {
        Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
            header.clone(),
            unsigned_qc(header, 0),
        ))
    }

    /// A tracker that followed `headers` in order.
    fn following(headers: &[&BlockHeader]) -> ShardSourceTracker {
        let mut tracker = ShardSourceTracker::new();
        for header in headers {
            tracker.on_verified_source_header(held(header));
            tracker.observe_crossing(SHARD, EpochWindows::new(0, ED));
        }
        tracker
    }

    /// `qc`'s signers and signature under another weighted timestamp.
    fn redated(qc: &QuorumCertificate, wt_ms: u64) -> QuorumCertificate {
        QuorumCertificate::new(
            qc.block_hash(),
            qc.shard_id(),
            qc.height(),
            qc.parent_block_hash(),
            qc.round(),
            qc.signers().clone(),
            qc.aggregated_signature(),
            WeightedTimestamp::from_millis(wt_ms),
        )
    }

    /// A state over one live shard and the schedule that resolves
    /// `committee` for its first two epochs.
    fn live_shard(committee: &TestCommittee) -> (BeaconState, TopologySchedule) {
        let snapshot = Arc::new(committee.topology_snapshot(1));
        let mut schedule = TopologySchedule::new(
            EpochWindows::new(0, ED),
            Epoch::new(1),
            Arc::clone(&snapshot),
        );
        schedule.insert(Epoch::new(0), snapshot);
        let mut state = BeaconState::empty(BeaconChainConfig {
            epoch_duration_ms: ED,
            ..BeaconChainConfig::at_unix_epoch()
        });
        state.boundaries.insert(SHARD, genesis_boundary());
        (state, schedule)
    }

    /// Whether `qc` clears admission for `SHARD` against `tracker`.
    fn admits(
        tracker: &ShardSourceTracker,
        state: &BeaconState,
        schedule: &TopologySchedule,
        qc: &QuorumCertificate,
    ) -> bool {
        admits_at(LocalTimestamp::ZERO, tracker, state, schedule, qc)
    }

    /// [`admits`] on a member whose clock reads `now`.
    fn admits_at(
        now: LocalTimestamp,
        tracker: &ShardSourceTracker,
        state: &BeaconState,
        schedule: &TopologySchedule,
        qc: &QuorumCertificate,
    ) -> bool {
        proposal_boundary_qcs_admissible(
            &BlsVerifier,
            &Verified::new_unchecked_for_test(proposing(qc)),
            state,
            tracker,
            schedule,
            &NetworkDefinition::simulator(),
            now,
        )
    }

    /// A proposal reporting `qc` as `SHARD`'s boundary.
    fn proposing(qc: &QuorumCertificate) -> BeaconProposal {
        BeaconProposal::new(
            iter::once((SHARD, Some(qc.clone()))).collect(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            VrfProof::ZERO,
        )
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
            EpochWindows::new(0, ED),
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
        shard_source.on_verified_source_header(Verified::new_unchecked_for_test(
            CertifiedBlockHeader::new(parent, boundary.parent_qc().clone()),
        ));

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

    /// A held boundary whose parent is not held names that parent among
    /// the blocks it awaits, so the member asks for it rather than settle
    /// for the fallback; once proven, the parent names the committee and the
    /// QC verifies.
    #[test]
    fn a_boundary_without_its_parent_awaits_it_and_verifies_once_proven() {
        let committee_a = TestCommittee::new(4, 1);
        let committee_b = TestCommittee::new(4, 2);
        let mut schedule = TopologySchedule::new(
            EpochWindows::new(0, ED),
            Epoch::new(2),
            Arc::new(committee_b.topology_snapshot(1)),
        );
        schedule.insert(Epoch::new(0), Arc::new(committee_a.topology_snapshot(1)));
        schedule.insert(Epoch::new(1), Arc::new(committee_b.topology_snapshot(1)));

        let parent = chained_header(9, 9, BlockHash::ZERO, ED - 1);
        let boundary = chained_header(10, 10, parent.hash(), ED + 1);
        let qc = signed_qc(&committee_a, &boundary, ED + 2);
        let parent_slot = (SHARD, BlockHeight::new(9));

        let mut shard_source = ShardSourceTracker::new();
        shard_source.on_verified_source_header(Verified::new_unchecked_for_test(
            CertifiedBlockHeader::new(boundary.clone(), qc.clone()),
        ));
        let proposal = proposing(&qc);
        assert!(
            awaited_boundaries(&proposal, &shard_source).contains(&parent_slot),
            "the missing parent is asked for",
        );

        shard_source.admit_proven_boundary(Verified::new_unchecked_for_test(
            CertifiedBlockHeader::new(parent, boundary.parent_qc().clone()),
        ));
        assert!(!awaited_boundaries(&proposal, &shard_source).contains(&parent_slot));
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
            "the proven parent names the window that signed the boundary",
        );
    }

    /// A boundary QC over a certified-but-uncommitted block is
    /// inadmissible. A 2f+1 QC proves availability, not commitment: a
    /// shard can halt with its epoch-crossing block certified yet never
    /// committed, and a boundary folded from it would anchor recovery on
    /// state no member's committed chain can serve. Admission demands
    /// local commit evidence — a round-contiguous certified descendant
    /// pair — and abstains without it. The evidence it demands is the
    /// commit of the child that embeds the certificate: a certified child
    /// commits the boundary block and can still be orphaned, taking its
    /// reading of the block's date with it.
    #[test]
    fn an_uncommitted_boundary_qc_is_inadmissible() {
        let committee = TestCommittee::new(4, 1);
        let (state, schedule) = live_shard(&committee);

        let boundary = chained_header(10, 10, BlockHash::ZERO, ED - 1);
        let qc = signed_qc(&committee, &boundary, ED + 1);
        let admissible =
            |headers: &[&BlockHeader]| admits(&following(headers), &state, &schedule, &qc);

        // A child that certifies the boundary across a round gap — a view
        // change between them — leaves it uncommitted.
        let gapped = child_embedding(&boundary, &qc, 12);
        assert!(
            !admissible(&[&boundary, &gapped]),
            "a certified-but-uncommitted boundary QC must not clear admission",
        );

        // The round-contiguous child direct-commits the boundary, and is
        // itself only certified.
        let contiguous = child_embedding(&boundary, &qc, 11);
        assert!(
            !admissible(&[&boundary, &contiguous]),
            "a QC read from a certified-but-uncommitted child must not clear admission",
        );

        // The next round-contiguous block commits the child.
        let above = child_embedding(&contiguous, &unsigned_qc(&contiguous, ED + 2), 12);
        assert!(
            admissible(&[&boundary, &contiguous, &above]),
            "the same QC clears admission once the two-chain commits the child embedding it",
        );
    }

    /// A committed crossing at height 10 — anchored short of the first cut
    /// and certified past it — with the tracker that observed it, the QC
    /// its committee signed, and a state and schedule that resolve them.
    fn observed_crossing() -> (
        ShardSourceTracker,
        BlockHeader,
        QuorumCertificate,
        BeaconState,
        TopologySchedule,
    ) {
        let committee = TestCommittee::new(4, 1);
        let (state, schedule) = live_shard(&committee);

        let boundary = chained_header(10, 10, BlockHash::ZERO, ED - 1);
        let qc = signed_qc(&committee, &boundary, ED + 1);
        let child = child_embedding(&boundary, &qc, 11);
        let above = child_embedding(&child, &unsigned_qc(&child, ED + 2), 12);
        let tracker = following(&[&boundary, &child, &above]);
        (tracker, boundary, qc, state, schedule)
    }

    /// `state` with `SHARD`'s boundary recorded on `block_hash` at `height`.
    fn recording(mut state: BeaconState, block_hash: BlockHash, height: u64) -> BeaconState {
        state.boundaries.insert(
            SHARD,
            ShardBoundary {
                block_hash,
                height: BlockHeight::new(height),
                ..live_boundary(0)
            },
        );
        state
    }

    /// A boundary QC for a block the shard's recorded boundary has left
    /// behind is inadmissible, genuine and committed though it is: a
    /// different block at or below the recorded height, a zero-hash
    /// placeholder's among them. The recorded block itself stays
    /// admissible, as does any block above the record.
    #[test]
    fn a_crossing_behind_the_recorded_boundary_is_inadmissible() {
        let (tracker, boundary, qc, state, schedule) = observed_crossing();
        let other = BlockHash::from_raw(Hash::from_bytes(b"another block"));
        let admissible = |state: &BeaconState| {
            boundary_qc_admissible(
                &BlsVerifier,
                SHARD,
                &qc,
                state,
                &tracker,
                &schedule,
                &NetworkDefinition::simulator(),
            )
        };

        assert!(
            admissible(&state),
            "a first crossing over the genesis record is admissible"
        );
        assert!(
            admissible(&recording(state.clone(), other, 9)),
            "a crossing above the record is admissible",
        );
        assert!(
            admissible(&recording(state.clone(), boundary.hash(), 10)),
            "the recorded block itself is admissible",
        );
        assert!(
            admissible(&recording(state.clone(), BlockHash::ZERO, 9)),
            "a crossing above the height a placeholder holds is admissible",
        );
        assert!(
            !admissible(&recording(state.clone(), BlockHash::ZERO, 10)),
            "a crossing at the height a placeholder holds must not clear admission",
        );
        assert!(
            !admissible(&recording(state.clone(), other, 20)),
            "a crossing below the record must not clear admission",
        );
        assert!(
            !admissible(&recording(state, other, 10)),
            "a different block at the recorded height must not clear admission",
        );
    }

    /// A tracker that has not observed the crossing the fold recorded
    /// holds an older one as its latest, and sources nothing from it.
    #[test]
    fn a_tracker_behind_the_fold_sources_no_crossing_behind_the_record() {
        let (tracker, boundary, _, state, _) = observed_crossing();
        let other = BlockHash::from_raw(Hash::from_bytes(b"another block"));

        let sourced = crossing_to_source(&state, &tracker, SHARD)
            .expect("the tracker's only crossing is sourced over the genesis record");
        assert_eq!(sourced.boundary_header().hash(), boundary.hash());

        let ahead = recording(state, other, 20);
        assert!(crossing_to_source(&ahead, &tracker, SHARD).is_none());
    }

    /// A boundary QC that restates a committed block's certifying timestamp
    /// is inadmissible. The weighted timestamp rides outside the aggregate
    /// signature, so the genuine signers and signature verify under any
    /// value a proposer writes beside them; the certificate the shard's
    /// chain fixed for the block is the one its committed child embeds as
    /// `parent_qc`. A block certified short of the cut is no crossing, and
    /// a copy of its certificate dated past the cut must not make it one.
    ///
    /// The member here holds the block and one certified child, whose own
    /// commit nothing yet establishes: no certificate stands over the
    /// block, so either copy is refused for want of state, naming the
    /// child's height. The verdict a member reaches once the child commits
    /// is [`a_redated_boundary_qc_is_refused_against_its_committed_child`].
    #[test]
    fn a_boundary_qc_dated_past_its_committed_certificate_is_inadmissible() {
        let committee = TestCommittee::new(4, 1);
        let snapshot = Arc::new(committee.topology_snapshot(1));
        let mut schedule = TopologySchedule::new(
            EpochWindows::new(0, ED),
            Epoch::new(1),
            Arc::clone(&snapshot),
        );
        schedule.insert(Epoch::new(0), snapshot);
        let mut state = BeaconState::empty(BeaconChainConfig {
            epoch_duration_ms: ED,
            ..BeaconChainConfig::at_unix_epoch()
        });
        state.boundaries.insert(SHARD, genesis_boundary());

        // The block anchors and certifies inside epoch 0: its certificate
        // lands short of the cut at `ED`, so it crosses nothing.
        let block = chained_header(10, 10, BlockHash::ZERO, ED - 200);
        let committed_qc = signed_qc(&committee, &block, ED - 100);
        assert!(committed_qc.weighted_timestamp().as_millis() < ED);

        // The round-contiguous child embeds that certificate and commits
        // the block.
        let child = BlockHeader::new(BlockHeaderParts {
            shard_id: SHARD,
            height: BlockHeight::new(11),
            parent_block_hash: block.hash(),
            parent_qc: committed_qc.clone().into(),
            timestamp: ProposerTimestamp::from_millis(0),
            round: Round::new(11),
            ..Default::default()
        });
        let child_qc = QuorumCertificate::new(
            child.hash(),
            SHARD,
            child.height(),
            child.parent_block_hash(),
            Round::INITIAL,
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(ED - 50),
        );
        let mut shard_source = ShardSourceTracker::new();
        shard_source.on_verified_source_header(Verified::new_unchecked_for_test(
            CertifiedBlockHeader::new(block.clone(), committed_qc.clone()),
        ));
        shard_source.on_verified_source_header(Verified::new_unchecked_for_test(
            CertifiedBlockHeader::new(child, child_qc),
        ));
        shard_source.observe_crossing(SHARD, EpochWindows::new(0, ED));
        assert!(shard_source.commit_established(SHARD, &block));
        assert!(
            shard_source.latest_crossing(SHARD).is_none(),
            "the committed chain records no crossing at this block",
        );

        let admissible = |qc: &QuorumCertificate| {
            boundary_qc_admissible(
                &BlsVerifier,
                SHARD,
                qc,
                &state,
                &shard_source,
                &schedule,
                &NetworkDefinition::simulator(),
            )
        };
        assert!(
            !admissible(&committed_qc),
            "the committed certificate lands short of the cut, so the block is no crossing",
        );

        // The same signers and signature, dated just past the cut.
        let redated = QuorumCertificate::new(
            committed_qc.block_hash(),
            committed_qc.shard_id(),
            committed_qc.height(),
            committed_qc.parent_block_hash(),
            committed_qc.round(),
            committed_qc.signers().clone(),
            committed_qc.aggregated_signature(),
            WeightedTimestamp::from_millis(ED + 1),
        );
        assert!(
            !admissible(&redated),
            "a certificate dated apart from the one the committed child embeds must not clear \
             admission",
        );
        for qc in [&committed_qc, &redated] {
            assert_eq!(
                awaited_boundaries(&proposing(qc), &shard_source),
                vec![(SHARD, BlockHeight::new(11))],
                "the refusal waits on the child's commit",
            );
        }
    }

    /// A boundary QC stands only as the certificate the block's committed
    /// child embeds. With that child's commit established, a copy under
    /// any other date is refused as a verdict, not for want of state: one
    /// that dates a block short of the cut past it, one that dates it
    /// fifty windows on, and one that moves a genuine crossing's date.
    #[test]
    fn a_redated_boundary_qc_is_refused_against_its_committed_child() {
        let committee = TestCommittee::new(4, 1);
        let (state, schedule) = live_shard(&committee);

        let short = chained_header(10, 10, BlockHash::ZERO, ED - 200);
        let short_qc = signed_qc(&committee, &short, ED - 100);
        let child = child_embedding(&short, &short_qc, 11);
        let above = child_embedding(&child, &unsigned_qc(&child, ED - 50), 12);
        let tracker = following(&[&short, &child, &above]);
        assert_eq!(
            tracker.committed_certificate(SHARD, &short),
            Some(&short_qc)
        );
        assert!(tracker.latest_crossing(SHARD).is_none());
        for wt_ms in [ED - 100, ED + 1, 50 * ED + 1] {
            let copy = redated(&short_qc, wt_ms);
            assert!(
                !admits(&tracker, &state, &schedule, &copy),
                "a block certified short of the cut is no crossing under a copy dated {wt_ms}",
            );
            assert!(
                awaited_boundaries(&proposing(&copy), &tracker).is_empty(),
                "the refusal is a verdict: nothing is awaited",
            );
        }

        let (tracker, _, qc, state, schedule) = observed_crossing();
        assert!(admits(&tracker, &state, &schedule, &qc));
        for wt_ms in [ED + 2, ED + 500, 50 * ED + 1] {
            assert!(
                !admits(&tracker, &state, &schedule, &redated(&qc, wt_ms)),
                "a genuine crossing's certificate is refused under the date {wt_ms}",
            );
        }
    }

    /// A far-dated copy of an older block's certificate does not outrank
    /// an honest certificate of a newer block: the canonical choice
    /// follows the heights the signers signed.
    #[test]
    fn a_far_dated_copy_of_an_older_block_does_not_outrank_a_newer_boundary() {
        let committee = TestCommittee::new(4, 1);
        let older = chained_header(10, 10, BlockHash::ZERO, ED - 200);
        let older_qc = signed_qc(&committee, &older, ED + 1);
        let newer = chained_header(20, 20, BlockHash::ZERO, 2 * ED - 1);
        let newer_qc = signed_qc(&committee, &newer, 2 * ED + 1);

        let (honest, byzantine) = (proposing(&newer_qc), proposing(&redated(&older_qc, 9 * ED)));
        for order in [[&honest, &byzantine], [&byzantine, &honest]] {
            let canonical = rules::canonical_boundary_qcs(order.into_iter());
            assert_eq!(canonical[&SHARD].block_hash(), newer.hash());
        }
    }

    /// A Byzantine leader of the round after a crossing block proposes a
    /// child embedding its own aggregate and keeps the child's certificate
    /// to itself; the round times out and the chain commits another child
    /// embedding another aggregate. Handed the orphan and its certificate
    /// first, a member dates the block by nothing: it admits neither
    /// aggregate and names the block whose commit would decide. Once the
    /// committed child reaches it, it reads what a member that never saw
    /// the orphan reads, and an orphan heard afterwards moves nothing.
    #[test]
    fn an_orphaned_child_dates_no_boundary() {
        let committee = TestCommittee::new(4, 1);
        let (state, schedule) = live_shard(&committee);

        let boundary = chained_header(10, 10, BlockHash::ZERO, ED - 1);
        let orphaned_qc = signed_qc(&committee, &boundary, ED + 1);
        let committed_qc = signed_qc(&committee, &boundary, ED + 3);
        let orphan = child_embedding(&boundary, &orphaned_qc, 11);
        let kept = child_embedding(&boundary, &committed_qc, 12);
        let above = child_embedding(&kept, &unsigned_qc(&kept, ED + 4), 13);

        let mut handed_the_orphan = following(&[&boundary, &orphan]);
        assert!(handed_the_orphan.commit_established(SHARD, &boundary));
        for qc in [&orphaned_qc, &committed_qc] {
            assert!(
                !admits(&handed_the_orphan, &state, &schedule, qc),
                "no certificate stands while only an uncommitted child embeds one",
            );
            assert_eq!(
                awaited_boundaries(&proposing(qc), &handed_the_orphan),
                vec![(SHARD, BlockHeight::new(11))],
                "the abstention names the child whose commit decides",
            );
        }
        assert!(crossing_to_source(&state, &handed_the_orphan, SHARD).is_none());

        let mut followed_the_chain = following(&[&boundary, &kept, &above]);
        for header in [&kept, &above] {
            handed_the_orphan.on_verified_source_header(held(header));
            handed_the_orphan.observe_crossing(SHARD, EpochWindows::new(0, ED));
        }
        followed_the_chain.on_verified_source_header(held(&orphan));
        followed_the_chain.observe_crossing(SHARD, EpochWindows::new(0, ED));
        for tracker in [&handed_the_orphan, &followed_the_chain] {
            assert!(admits(tracker, &state, &schedule, &committed_qc));
            assert!(!admits(tracker, &state, &schedule, &orphaned_qc));
            let sourced =
                crossing_to_source(&state, tracker, SHARD).expect("the crossing is sourced");
            assert_eq!(sourced.canonical_qc(), &committed_qc);
        }
    }

    /// The committed child need not be committed by the block above it:
    /// a view change there leaves its commit to a later two-chain. A
    /// member holding an orphan in the child's slot beneath that chain
    /// dates the boundary by nothing, and reads the chain's certificate
    /// once the committed child is seated.
    #[test]
    fn a_round_gap_above_the_committed_child_leaves_the_orphan_dating_nothing() {
        let committee = TestCommittee::new(4, 1);
        let (state, schedule) = live_shard(&committee);

        let boundary = chained_header(10, 10, BlockHash::ZERO, ED - 1);
        let orphaned_qc = signed_qc(&committee, &boundary, ED + 1);
        let committed_qc = signed_qc(&committee, &boundary, ED + 3);
        let orphan = child_embedding(&boundary, &orphaned_qc, 11);
        let kept = child_embedding(&boundary, &committed_qc, 12);
        let gapped = child_embedding(&kept, &unsigned_qc(&kept, ED + 4), 14);
        let pair = child_embedding(&gapped, &unsigned_qc(&gapped, ED + 5), 15);

        let mut tracker = following(&[&boundary, &orphan, &gapped, &pair]);
        assert!(tracker.commit_established(SHARD, &boundary));
        assert!(tracker.commit_established(SHARD, &gapped));
        for qc in [&orphaned_qc, &committed_qc] {
            assert!(
                !admits(&tracker, &state, &schedule, qc),
                "the orphan beneath the committed chain dates nothing",
            );
        }
        assert!(tracker.latest_crossing(SHARD).is_none());

        tracker.on_verified_source_header(held(&kept));
        tracker.observe_crossing(SHARD, EpochWindows::new(0, ED));
        assert!(admits(&tracker, &state, &schedule, &committed_qc));
        assert!(!admits(&tracker, &state, &schedule, &orphaned_qc));
    }

    /// A boundary the shard proved on this member's ask is committed
    /// under whichever certified child the proof ran through, an orphan
    /// included. It is admitted under the certificate a child proven in
    /// its own right embeds, and until then stays awaited.
    #[test]
    fn a_boundary_proven_beside_an_orphan_takes_no_certificate_from_it() {
        let committee = TestCommittee::new(4, 1);
        let (state, schedule) = live_shard(&committee);

        let boundary = chained_header(10, 10, BlockHash::ZERO, ED - 1);
        let orphaned_qc = signed_qc(&committee, &boundary, ED + 1);
        let committed_qc = signed_qc(&committee, &boundary, ED + 3);
        let orphan = child_embedding(&boundary, &orphaned_qc, 11);
        let kept = child_embedding(&boundary, &committed_qc, 12);

        let mut tracker = following(&[&orphan]);
        tracker.admit_proven_boundary(held(&boundary));
        assert!(tracker.commit_established(SHARD, &boundary));
        for qc in [&orphaned_qc, &committed_qc] {
            assert!(
                !admits(&tracker, &state, &schedule, qc),
                "the block held above a proven boundary dates nothing",
            );
            assert_eq!(
                awaited_boundaries(&proposing(qc), &tracker),
                vec![(SHARD, BlockHeight::new(11))],
            );
        }

        tracker.admit_proven_boundary(held(&kept));
        assert!(admits(&tracker, &state, &schedule, &committed_qc));
        assert!(!admits(&tracker, &state, &schedule, &orphaned_qc));
        assert!(
            !admits(
                &tracker,
                &state,
                &schedule,
                &redated(&committed_qc, ED + 700)
            ),
            "the proven child's certificate stands under its own date alone",
        );
        assert!(awaited_boundaries(&proposing(&committed_qc), &tracker).is_empty());
    }

    /// A terminal dates its own crossing: the certificate it embeds over
    /// the block before it is the date, and its own commit is what
    /// admission establishes. No committed block need embed a certificate
    /// over the terminal, since its chain stops once the terminal's commit
    /// is proven, so any genuine one stands — the one the coast block
    /// embeds, another aggregate under another date, and both again where
    /// an orphaned coast block holds the slot. The block before the
    /// terminal contributes nothing.
    #[test]
    fn a_terminal_stands_on_its_own_commit_under_any_genuine_certificate() {
        let committee = TestCommittee::new(4, 1);
        let (mut state, schedule) = live_shard(&committee);
        state.boundaries.insert(
            SHARD,
            ShardBoundary {
                terminal_epoch: Some(Epoch::new(0)),
                ..genesis_boundary()
            },
        );

        let crossing = chained_header(10, 10, BlockHash::ZERO, ED - 1);
        let crossing_qc = signed_qc(&committee, &crossing, ED + 1);
        let terminal = BlockHeader::new(BlockHeaderParts {
            terminal_settled_txs: Some(SettledTxsRoot::ZERO),
            ..child_embedding(&crossing, &crossing_qc, 11).into_parts()
        });
        let terminal_qc = signed_qc(&committee, &terminal, ED + 2);
        let other_qc = signed_qc(&committee, &terminal, ED + 9);
        let coast = child_embedding(&terminal, &terminal_qc, 12);
        let orphaned_coast = child_embedding(&terminal, &other_qc, 12);

        let uncommitted = following(&[&crossing, &terminal]);
        assert!(!admits(&uncommitted, &state, &schedule, &terminal_qc));
        assert_eq!(
            awaited_boundaries(&proposing(&terminal_qc), &uncommitted),
            vec![(SHARD, BlockHeight::new(11))],
            "a terminal awaits its own commit",
        );

        for above in [&coast, &orphaned_coast] {
            let tracker = following(&[&crossing, &terminal, above]);
            let sourced =
                crossing_to_source(&state, &tracker, SHARD).expect("the terminal is the crossing");
            assert_eq!(sourced.boundary_header().hash(), terminal.hash());
            assert!(tracker.committed_certificate(SHARD, &terminal).is_none());
            for qc in [&terminal_qc, &other_qc] {
                assert!(
                    admits(&tracker, &state, &schedule, qc),
                    "a committed terminal stands under any genuine certificate over it",
                );
            }
            assert!(
                !admits(&tracker, &state, &schedule, &crossing_qc),
                "the block before the terminal contributes nothing",
            );
        }
    }

    /// A committed terminal under the certificate its coast block embeds:
    /// the state that marks the shard terminating, the schedule, the
    /// tracker, the blocks below and at the terminal, and the certificate.
    fn committed_terminal() -> (
        BeaconState,
        TopologySchedule,
        ShardSourceTracker,
        BlockHeader,
        BlockHeader,
        QuorumCertificate,
    ) {
        let committee = TestCommittee::new(4, 1);
        let (mut state, schedule) = live_shard(&committee);
        state.boundaries.insert(
            SHARD,
            ShardBoundary {
                terminal_epoch: Some(Epoch::new(0)),
                ..genesis_boundary()
            },
        );
        let crossing = chained_header(10, 10, BlockHash::ZERO, ED - 1);
        let crossing_qc = signed_qc(&committee, &crossing, ED + 1);
        let terminal = BlockHeader::new(BlockHeaderParts {
            terminal_settled_txs: Some(SettledTxsRoot::ZERO),
            ..child_embedding(&crossing, &crossing_qc, 11).into_parts()
        });
        let terminal_qc = signed_qc(&committee, &terminal, ED + 2);
        let coast = child_embedding(&terminal, &terminal_qc, 12);
        let tracker = following(&[&crossing, &terminal, &coast]);
        (state, schedule, tracker, crossing, terminal, terminal_qc)
    }

    /// A terminal's anchor is the date of the certificate it embeds, which
    /// its hash covers, and an aggregation holds every vote at or above
    /// it. A copy of a terminal's certificate dated below the anchor is
    /// refused, and a member whose coast block embeds one sources nothing
    /// from it; a copy dated at the anchor stands.
    #[test]
    fn a_terminal_certificate_dated_below_its_anchor_is_inadmissible() {
        let (state, schedule, tracker, crossing, terminal, terminal_qc) = committed_terminal();
        let anchor = terminal.parent_qc().weighted_timestamp().as_millis();
        assert!(admits(&tracker, &state, &schedule, &terminal_qc));

        let below = redated(&terminal_qc, anchor - 1);
        assert!(!admits(&tracker, &state, &schedule, &below));
        assert!(
            awaited_boundaries(&proposing(&below), &tracker).is_empty(),
            "a refusal on the date is a verdict, and asks for nothing",
        );
        assert!(admits(
            &tracker,
            &state,
            &schedule,
            &redated(&terminal_qc, anchor),
        ));

        let regressing = child_embedding(&terminal, &below, 12);
        let holding_it = following(&[&crossing, &terminal, &regressing]);
        assert!(holding_it.commit_established(SHARD, &terminal));
        assert!(crossing_to_source(&state, &holding_it, SHARD).is_none());
    }

    /// Nothing a committed block embeds bounds a terminal's certificate
    /// from above, so admission holds its date to this member's clock: a
    /// copy dated further ahead than an honest aggregation's can run is
    /// refused, and one at the edge of that reach stands.
    #[test]
    fn a_terminal_certificate_dated_past_the_clock_is_inadmissible() {
        let (state, schedule, tracker, _, _, terminal_qc) = committed_terminal();
        let now = LocalTimestamp::from_millis(ED + 5);
        let reach = u64::try_from((MAX_TIMESTAMP_DELAY + MAX_TIMESTAMP_RUSH).as_millis())
            .expect("the reach fits");
        let edge = ED + 5 + reach;

        assert!(admits_at(
            now,
            &tracker,
            &state,
            &schedule,
            &redated(&terminal_qc, edge),
        ));
        let ahead = redated(&terminal_qc, edge + 1);
        assert!(!admits_at(now, &tracker, &state, &schedule, &ahead));
        assert!(
            awaited_boundaries(&proposing(&ahead), &tracker).is_empty(),
            "a refusal on the date is a verdict, and asks for nothing",
        );
        assert!(admits_at(
            LocalTimestamp::from_millis(ED + 6),
            &tracker,
            &state,
            &schedule,
            &ahead,
        ));
    }

    /// A live boundary's certificate is the one its committed child
    /// embeds, whose date the child's voters held to their own clocks.
    /// Admission reads no clock for it.
    #[test]
    fn a_live_boundary_certificate_is_admitted_whatever_the_clock_reads() {
        let committee = TestCommittee::new(4, 1);
        let (state, schedule) = live_shard(&committee);
        let reach = u64::try_from((MAX_TIMESTAMP_DELAY + MAX_TIMESTAMP_RUSH).as_millis())
            .expect("the reach fits");
        let certified_ms = 2 * reach;
        let boundary = chained_header(10, 10, BlockHash::ZERO, ED - 1);
        let qc = signed_qc(&committee, &boundary, certified_ms);
        let child = child_embedding(&boundary, &qc, 11);
        let above = child_embedding(&child, &unsigned_qc(&child, certified_ms + 1), 12);
        let tracker = following(&[&boundary, &child, &above]);
        for now in [0, certified_ms, u64::MAX] {
            assert!(admits_at(
                LocalTimestamp::from_millis(now),
                &tracker,
                &state,
                &schedule,
                &qc,
            ));
        }
    }

    /// A schedule seating each committee over its run of windows, every
    /// window retained, with a head carrying `bindings` as `SHARD`'s
    /// recovery history and `pending` as its recovery in flight.
    fn schedule_over(
        eras: &[(&TestCommittee, std::ops::Range<u64>)],
        bindings: Vec<RecoveryBinding>,
        pending: Option<ShardRecovery>,
    ) -> TopologySchedule {
        let (newest, newest_windows) = eras.last().expect("at least one era");
        let head_epoch = Epoch::new(newest_windows.end - 1);
        let head = Arc::new(
            newest
                .topology_snapshot(1)
                .with_recoveries(iter::once((SHARD, bindings)).collect())
                .with_pending_recoveries(pending.into_iter().map(|r| (SHARD, r)).collect()),
        );
        let mut schedule =
            TopologySchedule::new(EpochWindows::new(0, ED), head_epoch, Arc::clone(&head));
        for (committee, windows) in eras {
            let snapshot = Arc::new(committee.topology_snapshot(1));
            for epoch in windows.clone() {
                schedule.insert(Epoch::new(epoch), Arc::clone(&snapshot));
            }
        }
        schedule.insert(head_epoch, head);
        schedule
    }

    /// A halt recovery stamped at `rotated_at` over `frontier`.
    fn recovery(rotated_at: u64, frontier: u64) -> ShardRecovery {
        ShardRecovery {
            cause: RecoveryCause::Halt,
            rotated_at: Epoch::new(rotated_at),
            retained: Vec::new(),
            attested_frontier: BlockHeight::new(frontier),
        }
    }

    /// Its binding in the shard's history.
    fn binding(rotated_at: u64, frontier: u64, completed: bool) -> RecoveryBinding {
        RecoveryBinding {
            rotated_at: Epoch::new(rotated_at),
            attested_frontier: BlockHeight::new(frontier),
            completed,
        }
    }

    /// A committed crossing at `height` anchored at `anchor_ms`, extending
    /// `parent`, under the certificate `committee` dates `certified_ms`:
    /// the tracker that followed it and its two-chain, and the certificate.
    fn committed_crossing(
        committee: &TestCommittee,
        height: u64,
        parent: BlockHash,
        anchor_ms: u64,
        certified_ms: u64,
    ) -> (ShardSourceTracker, BlockHeader, QuorumCertificate) {
        let crossing = chained_header(height, height, parent, anchor_ms);
        let qc = signed_qc(committee, &crossing, certified_ms);
        let child = child_embedding(&crossing, &qc, height + 1);
        let above = child_embedding(&child, &unsigned_qc(&child, certified_ms + 1), height + 2);
        (following(&[&crossing, &child, &above]), crossing, qc)
    }

    /// `state` with `bindings` as `SHARD`'s recovery history.
    fn with_history(mut state: BeaconState, bindings: Vec<RecoveryBinding>) -> BeaconState {
        state.recoveries.insert(SHARD, bindings);
        state
    }

    /// A recovery stamped at epoch 9 (bridge 10) over the frontier at
    /// height 8 replaced the committee that halted at the tip it harvested,
    /// height 10. The fresh committee's bridge crossing at 12, anchored on
    /// the stale tip and certified past the bridge, folds and clears the
    /// recovery. The retained cohort, beyond f, extends the same tip with
    /// a branch the recovery discarded, and certifies a crossing on it at
    /// 14: anchored and certified two windows below the bridge, under its
    /// own keys. Refused while the recovery is pending and after it
    /// clears, or every later fresh crossing at or below 14 would read as
    /// behind it.
    ///
    /// Every window is retained, as on a member whose floor another
    /// shard's stale record pins below the band.
    #[test]
    fn a_discarded_branchs_crossing_above_the_record_is_not_folded_after_the_clear() {
        let replaced = TestCommittee::new(4, 1);
        let fresh = TestCommittee::new(4, 2);
        let eras = [(&replaced, 0..10), (&fresh, 10..12)];
        let pending = schedule_over(&eras, vec![binding(9, 8, false)], Some(recovery(9, 8)));
        let cleared = schedule_over(&eras, vec![binding(9, 8, true)], None);
        let (state, _) = live_shard(&replaced);
        let stamped = with_history(state.clone(), vec![binding(9, 8, false)]);

        let tip = chained_header(10, 10, BlockHash::ZERO, 1_500);
        let (bridge_tracker, bridge, bridge_qc) =
            committed_crossing(&fresh, 12, tip.hash(), 1_900, 10_100);
        assert!(
            admits(&bridge_tracker, &stamped, &pending, &bridge_qc),
            "the bridge crossing verifies under the fresh committee and clears the recovery",
        );
        let state = with_history(
            recording(state, bridge.hash(), 12),
            vec![binding(9, 8, true)],
        );
        assert!(admits(&bridge_tracker, &state, &cleared, &bridge_qc));

        let (fresh_tracker, _, fresh_qc) =
            committed_crossing(&fresh, 20, BlockHash::ZERO, 10_900, 11_100);
        assert!(
            admits(&fresh_tracker, &state, &cleared, &fresh_qc),
            "the fresh committee's next crossing is admitted",
        );

        let (orphan_tracker, _, orphan_qc) =
            committed_crossing(&replaced, 14, tip.hash(), 4_900, 5_100);
        assert!(
            !admits(&orphan_tracker, &stamped, &pending, &orphan_qc),
            "the discarded branch's crossing is refused while the recovery is pending",
        );
        assert!(
            !admits(&orphan_tracker, &state, &cleared, &orphan_qc),
            "the discarded branch's crossing must not be admitted after the clear",
        );
    }

    /// A first recovery (stamped at 9, bridge 10) seats a committee whose
    /// crossings never reach the beacon: a partition keeps them out for
    /// more than the halt threshold, so a second recovery is stamped at 29
    /// (bridge 30) over the same frontier, 8, and the committee it seats
    /// harvests a tip below the first committee's production. That
    /// committee was honest, and its chain above the second harvest is
    /// discarded. The second fresh committee's bridge crossing at 15 folds
    /// and clears the second recovery. The first committee's crossing at
    /// 60, anchored and certified in its own windows below the second
    /// bridge, verifies under its keys; refused while the second recovery
    /// is pending, the beacon must still not take it after the clear.
    ///
    /// Every window is retained, as on a member whose floor another
    /// shard's stale record pins below the band.
    #[test]
    fn a_chained_recoverys_discarded_crossing_is_not_recorded_after_it_clears() {
        let halted = TestCommittee::new(4, 1);
        let first = TestCommittee::new(4, 2);
        let second = TestCommittee::new(4, 3);
        let eras = [(&halted, 0..10), (&first, 10..30), (&second, 30..32)];
        let stamped_history = vec![binding(9, 8, false), binding(29, 8, false)];
        let cleared_history = vec![binding(9, 8, false), binding(29, 8, true)];
        let pending = schedule_over(&eras, stamped_history.clone(), Some(recovery(29, 8)));
        let cleared = schedule_over(&eras, cleared_history.clone(), None);
        let (state, _) = live_shard(&halted);
        let stamped = with_history(state.clone(), stamped_history);

        let (bridge_tracker, bridge, bridge_qc) =
            committed_crossing(&second, 15, BlockHash::ZERO, 1_900, 30_100);
        assert!(
            admits(&bridge_tracker, &stamped, &pending, &bridge_qc),
            "the second bridge crossing verifies under the second fresh committee",
        );
        let state = with_history(recording(state, bridge.hash(), 15), cleared_history);
        assert!(admits(&bridge_tracker, &state, &cleared, &bridge_qc));

        let (discarded_tracker, _, discarded_qc) =
            committed_crossing(&first, 60, BlockHash::ZERO, 20_900, 21_100);
        assert!(
            !admits(&discarded_tracker, &stamped, &pending, &discarded_qc),
            "the first committee's crossing is refused while the second recovery is pending",
        );
        assert!(
            !admits(&discarded_tracker, &state, &cleared, &discarded_qc),
            "the first committee's discarded crossing must not be admitted after the clear",
        );
    }

    /// The fold that clears a recovery lifts the shard's live epoch past
    /// the bridge, and a member whose floor nothing else holds evicts the
    /// windows below it: a discarded branch's crossing resolves no
    /// committee there. A second shard whose record is stale holds the
    /// floor below the band, and the crossing's committee resolves; it is
    /// refused all the same.
    #[test]
    fn a_discarded_branchs_crossing_is_refused_wherever_the_floor_sits() {
        use hyperscale_types::{RETENTION_HORIZON, ShardCommittee};

        use crate::coordinator::retention_floor;

        let replaced = TestCommittee::new(4, 1);
        let fresh = TestCommittee::new(4, 2);
        let eras = [(&replaced, 0..10), (&fresh, 10..12)];
        let tip = chained_header(10, 10, BlockHash::ZERO, 1_500);
        let (tracker, orphan, orphan_qc) =
            committed_crossing(&replaced, 14, tip.hash(), 4_900, 5_100);

        let (state, _) = live_shard(&replaced);
        let mut state = with_history(state, vec![binding(9, 8, true)]);
        state.current_epoch = Epoch::new(11);
        state.boundaries.insert(
            SHARD,
            ShardBoundary {
                block_hash: BlockHash::from_raw(Hash::from_bytes(b"bridge")),
                height: BlockHeight::new(12),
                last_live_epoch: Epoch::new(11),
                ..live_boundary(0)
            },
        );
        state.shard_committees.insert(
            SHARD,
            ShardCommittee {
                members: Vec::new(),
            },
        );
        // The artifact horizon inside the current window, as a production
        // epoch's length places it.
        let horizon_ms = u64::try_from(RETENTION_HORIZON.as_millis()).expect("the horizon fits");
        let now = LocalTimestamp::from_millis(11_500 + horizon_ms);

        let mut unpinned = schedule_over(&eras, vec![binding(9, 8, true)], None);
        let floor = retention_floor(&state, None, now);
        unpinned.evict_below(floor);
        assert!(
            !admits(&tracker, &state, &unpinned, &orphan_qc),
            "the band's windows are below the floor {floor:?}",
        );

        let lagging = ShardId::leaf(1, 1);
        state.shard_committees.insert(
            lagging,
            ShardCommittee {
                members: Vec::new(),
            },
        );
        state.boundaries.insert(
            lagging,
            ShardBoundary {
                last_live_epoch: Epoch::new(2),
                ..live_boundary(0)
            },
        );
        let mut pinned = schedule_over(&eras, vec![binding(9, 8, true)], None);
        let floor = retention_floor(&state, None, now);
        pinned.evict_below(floor);
        assert!(
            boundary_qc_authentic(
                &BlsVerifier,
                SHARD,
                &orphan,
                &orphan_qc,
                &tracker,
                &pinned,
                &NetworkDefinition::simulator(),
            ),
            "a stale record elsewhere pins the floor at {floor:?}, and the committee resolves",
        );
        assert!(
            !admits(&tracker, &state, &pinned, &orphan_qc),
            "the crossing is refused as discarded, not for want of its committee",
        );
    }

    /// A tracker can hold a discarded branch's crossing: the remote-header
    /// path verifies its header under the replaced committee once the
    /// recovery clears. With a witness leaf the fresh chain has not
    /// written it is the newest crossing with unfolded leaves; the
    /// proposer passes over it and sources the fresh committee's crossing,
    /// so no honest proposal carries what every voter refuses.
    #[test]
    fn a_discarded_branchs_crossing_with_unfolded_leaves_is_not_sourced() {
        let replaced = TestCommittee::new(4, 1);
        let fresh = TestCommittee::new(4, 2);
        let (state, _) = live_shard(&replaced);
        let state = with_history(
            recording(state, BlockHash::from_raw(Hash::from_bytes(b"bridge")), 12),
            vec![binding(9, 8, true)],
        );

        let tip = chained_header(10, 10, BlockHash::ZERO, 1_500);
        let orphan = BlockHeader::new(BlockHeaderParts {
            beacon_witness_leaf_count: BeaconWitnessLeafCount::new(1),
            ..chained_header(14, 14, tip.hash(), 4_900).into_parts()
        });
        let orphan_qc = signed_qc(&replaced, &orphan, 5_100);
        let orphan_child = child_embedding(&orphan, &orphan_qc, 15);
        let orphan_above = child_embedding(&orphan_child, &unsigned_qc(&orphan_child, 5_200), 16);
        let next = chained_header(20, 20, BlockHash::ZERO, 10_900);
        let next_qc = signed_qc(&fresh, &next, 11_100);
        let next_child = child_embedding(&next, &next_qc, 21);
        let next_above = child_embedding(&next_child, &unsigned_qc(&next_child, 11_200), 22);
        let tracker = following(&[
            &orphan,
            &orphan_child,
            &orphan_above,
            &next,
            &next_child,
            &next_above,
        ]);

        let sourced = crossing_to_source(&state, &tracker, SHARD).expect("a crossing is sourced");
        assert_eq!(sourced.boundary_header().hash(), next.hash());
    }

    /// The window before a bridge is outside the band and is judged by the
    /// committee its certificate resolves. With the recovery stamped at 9
    /// (bridge 10), a fresh bridge crossing certified in window 9 is
    /// admitted while the recovery is pending and after it clears. An
    /// orphan the replaced committee certifies in the same window is
    /// outside the band too, and after the clear the certified lookup
    /// bridges it to the fresh committee, whose keys refuse it.
    #[test]
    fn a_crossing_certified_in_the_window_before_the_bridge_is_judged_by_its_committee() {
        let replaced = TestCommittee::new(4, 1);
        let fresh = TestCommittee::new(4, 2);
        let eras = [(&replaced, 0..10), (&fresh, 10..12)];
        let pending = schedule_over(&eras, vec![binding(9, 8, false)], Some(recovery(9, 8)));
        let cleared = schedule_over(&eras, vec![binding(9, 8, true)], None);
        let (state, _) = live_shard(&replaced);
        let stamped = with_history(state.clone(), vec![binding(9, 8, false)]);
        let tip = chained_header(10, 10, BlockHash::ZERO, 1_500);

        let (bridge_tracker, bridge, bridge_qc) =
            committed_crossing(&fresh, 12, tip.hash(), 1_900, 9_100);
        assert!(!rules::in_discarded_recovery_band(
            &stamped, SHARD, &bridge, &bridge_qc
        ));
        assert!(admits(&bridge_tracker, &stamped, &pending, &bridge_qc));
        let state = with_history(
            recording(state, bridge.hash(), 12),
            vec![binding(9, 8, true)],
        );
        assert!(admits(&bridge_tracker, &state, &cleared, &bridge_qc));

        let (orphan_tracker, orphan, orphan_qc) =
            committed_crossing(&replaced, 14, tip.hash(), 4_900, 9_100);
        assert!(!rules::in_discarded_recovery_band(
            &state, SHARD, &orphan, &orphan_qc
        ));
        assert!(!admits(&orphan_tracker, &state, &cleared, &orphan_qc));
    }

    /// A chained recovery's first committee, cut off from the beacon, keeps
    /// certifying into the window before the second bridge (30) and past
    /// it. None of those crossings is in the band; each is bridged to the
    /// second committee, whose keys refuse it.
    #[test]
    fn a_chained_first_committee_certifying_past_the_band_is_refused_by_its_successor() {
        let halted = TestCommittee::new(4, 1);
        let first = TestCommittee::new(4, 2);
        let second = TestCommittee::new(4, 3);
        let eras = [(&halted, 0..10), (&first, 10..30), (&second, 30..32)];
        let history = vec![binding(9, 8, false), binding(29, 8, true)];
        let cleared = schedule_over(&eras, history.clone(), None);
        let (state, _) = live_shard(&halted);
        let state = with_history(
            recording(state, BlockHash::from_raw(Hash::from_bytes(b"bridge")), 15),
            history,
        );
        for (anchor_ms, certified_ms) in [(20_900, 29_100), (28_900, 30_100), (30_100, 31_100)] {
            let (tracker, header, qc) =
                committed_crossing(&first, 60, BlockHash::ZERO, anchor_ms, certified_ms);
            assert!(!rules::in_discarded_recovery_band(
                &state, SHARD, &header, &qc
            ));
            assert!(
                !admits(&tracker, &state, &cleared, &qc),
                "the first committee's crossing at {anchor_ms}/{certified_ms} is refused",
            );
        }
    }

    /// The history keeps only its newest bindings. With the first of five
    /// recoveries over one frontier aged out, a crossing in its band is
    /// still in the band of the newest.
    #[test]
    fn a_band_whose_binding_aged_out_is_covered_by_a_newer_one() {
        let replaced = TestCommittee::new(4, 1);
        let (state, _) = live_shard(&replaced);
        let state = with_history(
            recording(state, BlockHash::from_raw(Hash::from_bytes(b"bridge")), 12),
            vec![
                binding(29, 8, false),
                binding(49, 8, false),
                binding(69, 8, false),
                binding(89, 8, true),
            ],
        );
        let tip = chained_header(10, 10, BlockHash::ZERO, 1_500);
        let (_, orphan, orphan_qc) = committed_crossing(&replaced, 14, tip.hash(), 4_900, 5_100);
        assert!(rules::in_discarded_recovery_band(
            &state, SHARD, &orphan, &orphan_qc
        ));
    }
}
