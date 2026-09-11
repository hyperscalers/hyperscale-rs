//! Per-shard source tracking for beacon proposals.
//!
//! Holds the beacon's verified view of each source shard, everything a
//! proposer draws on to build a `BeaconProposal` and an epoch's
//! `shard_contributions`:
//!
//! - recent verified headers — the verify context for inbound witness
//!   chunks and the input to crossing detection;
//! - observed epoch-boundary crossings — the per-shard anchors the
//!   proposer reports in `boundary_qcs`;
//! - per-anchor witness chunks — verified witnesses for a boundary
//!   block's accumulator range, keyed by the boundary block they prove
//!   against (the accumulator is append-only, so a leaf's merkle path is
//!   root-specific — a witness only counts toward the boundary block it
//!   was fetched against).

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_types::{
    BlockHash, BlockHeader, BlockHeight, CertifiedBlockHeader, CommitProof, Epoch, EpochWindows,
    Hash, LeafIndex, QuorumCertificate, ShardId, ShardWitnessPayload, Verified,
};

/// How many recent epoch-boundary crossings to retain per shard. The
/// proposer reports the latest; a small history covers the spread of
/// "latest observed" across beacon committee members so a node can seat
/// the contribution for whichever crossing committed.
const MAX_RETAINED_CROSSINGS_PER_SHARD: usize = 4;

/// How many recent verified headers to retain per shard. Crossing
/// detection reads consecutive `(B, C)` pairs near the tip and inbound
/// verification reads the most recent headers; a boundary block's own
/// header is retained separately on its [`ObservedCrossing`], so the
/// sliding window only needs to cover tip-adjacent work.
const MAX_RETAINED_HEADERS_PER_SHARD: usize = 8;

/// A shard's observed crossing of an epoch boundary.
///
/// `boundary_header` is the first block `B` whose weighted timestamp
/// lands past the boundary; `canonical_qc` is the QC over `B` read from
/// its child (`C.parent_qc`) — hash-pinned, so every node that observes
/// the crossing selects the identical QC. Recorded only once `B`'s
/// *commit* is established ([`ShardSourceTracker::commit_established`]),
/// while the evidence is fresh near the shard tip, so it survives header
/// pruning.
#[derive(Debug, Clone)]
pub struct ObservedCrossing {
    boundary_header: Arc<Verified<CertifiedBlockHeader>>,
    canonical_qc: QuorumCertificate,
}

impl ObservedCrossing {
    /// The boundary block's header — its `state_root` is the snap-sync
    /// anchor and its `beacon_witness_root` authenticates the chunk.
    #[must_use]
    pub fn boundary_header(&self) -> &BlockHeader {
        self.boundary_header.header()
    }

    /// The canonical QC over the boundary block.
    #[must_use]
    pub const fn canonical_qc(&self) -> &QuorumCertificate {
        &self.canonical_qc
    }
}

/// A boundary block's verified witness chunk: the contiguous leaf run
/// starting at `lo`, with the flanking nodes that lift it to that block's
/// `beacon_witness_root`.
///
/// Chunks admit and evict whole. A range proof only verifies for the run
/// it names, so half a chunk proves nothing and there is no partial state
/// worth holding — a short or unverifiable response is dropped and the
/// range re-requested against another peer.
#[derive(Debug)]
struct AnchorChunk {
    lo: u64,
    payloads: Vec<ShardWitnessPayload>,
    range_proof: Vec<Hash>,
}

impl AnchorChunk {
    /// End of the run, exclusive.
    const fn hi(&self) -> u64 {
        self.lo + self.payloads.len() as u64
    }

    /// Whether this chunk is exactly the run `[prior, chunk_end)`.
    const fn covers(&self, prior: u64, chunk_end: u64) -> bool {
        self.lo == prior && self.hi() == chunk_end
    }
}

/// A witness-chunk fetch id: the anchor plus the run it covers. The whole
/// run is one fetch, so cancellation and dedup key on the range rather
/// than on individual leaves.
pub type ChunkFetchId = (ShardId, BlockHeight, BlockHash, LeafIndex, LeafIndex);

/// Per-shard source tracking.
///
/// - `shard_headers` — verified source-shard headers, a sliding window of
///   the most recent per shard (bounded by
///   [`MAX_RETAINED_HEADERS_PER_SHARD`]). Populated from every verified
///   remote header regardless of committee membership; needed by
///   off-committee vnodes to verify inbound `BeaconBlock`s' witness merkle
///   paths and as crossing-detection input.
/// - `boundary_crossings` — observed epoch-boundary crossings per shard,
///   keyed by the crossed epoch (bounded by
///   [`MAX_RETAINED_CROSSINGS_PER_SHARD`]), retained past header pruning so
///   the proposer can report a crossing long after its headers age out.
/// - `witness_chunks` — one verified leaf run per anchor boundary block
///   `(shard, block_hash)`. A range proof verifies against one block's
///   `beacon_witness_root`, so a chunk counts only toward that boundary.
///   Empty when the local validator is off-committee.
/// - `pending_fetches` — outstanding chunk-fetch dedup per anchor.
#[derive(Debug, Default)]
pub struct ShardSourceTracker {
    shard_headers: BTreeMap<ShardId, BTreeMap<BlockHeight, Arc<Verified<CertifiedBlockHeader>>>>,
    boundary_crossings: BTreeMap<ShardId, BTreeMap<Epoch, ObservedCrossing>>,
    witness_chunks: BTreeMap<(ShardId, BlockHash), AnchorChunk>,
    pending_fetches: BTreeMap<(ShardId, BlockHash), PendingFetch>,
}

/// An anchor's outstanding chunk fetch. Carries the boundary block
/// `height` alongside the in-flight run so an eviction can name the
/// cancelled fetch as the [`ChunkFetchId`] the runner's
/// `FetchIds::ShardWitnesses` handler matches against.
#[derive(Debug)]
struct PendingFetch {
    height: BlockHeight,
    lo: u64,
    hi: u64,
}

impl ShardSourceTracker {
    /// Empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a verified source-shard header. Called by the coordinator
    /// from `on_verified_source_header` for every active shard (on- or
    /// off-committee) — remote shards via the remote-header path, the
    /// local shard from its own commit stream. The shard's window keeps
    /// only its most recent [`MAX_RETAINED_HEADERS_PER_SHARD`] heights;
    /// a boundary block needed past the window is retained on its
    /// [`ObservedCrossing`].
    pub fn on_verified_source_header(
        &mut self,
        certified_header: Arc<Verified<CertifiedBlockHeader>>,
    ) {
        let header = certified_header.header();
        let shard = header.shard_id();
        let height = header.height();
        let headers = self.shard_headers.entry(shard).or_default();
        headers.insert(height, certified_header);
        while headers.len() > MAX_RETAINED_HEADERS_PER_SHARD {
            headers.pop_first();
        }
    }

    /// `header`'s parent, when the shard's header window or retained
    /// crossings hold it — keyed at the height below `header`'s own and
    /// pinned by the parent hash the header names, so a sibling at the slot
    /// never matches. What resolves the committee that signed a QC over
    /// `header`'s block: a block's committee anchors on its parent.
    #[must_use]
    pub fn parent_header(&self, header: &BlockHeader) -> Option<&BlockHeader> {
        let shard = header.shard_id();
        let parent_height = header.height().prev()?;
        let parent_hash = header.parent_block_hash();
        self.shard_headers
            .get(&shard)
            .and_then(|window| window.get(&parent_height))
            .filter(|held| held.block_hash() == parent_hash)
            .or_else(|| {
                self.boundary_crossings.get(&shard).and_then(|per_shard| {
                    per_shard
                        .values()
                        .map(|crossing| &crossing.boundary_header)
                        .find(|held| held.block_hash() == parent_hash)
                })
            })
            .map(|held| held.header())
    }

    /// Whether `boundary`'s *commit* on `shard` is locally established: a
    /// recorded crossing already names it (this check gated the record),
    /// or the header window holds a round-contiguous certified two-chain
    /// at or above it whose parent-hash ancestry descends to it —
    /// [`CommitProof`]'s structural rule, assembled from headers whose
    /// signatures were verified on arrival. A bare 2f+1 QC proves
    /// availability, not commitment, so this is what separates a crossing
    /// the shard's chain durably reached from one it merely certified.
    #[must_use]
    pub fn commit_established(&self, shard: ShardId, boundary: &BlockHeader) -> bool {
        let boundary_hash = boundary.hash();
        if self
            .boundary_crossings
            .get(&shard)
            .is_some_and(|per_shard| {
                per_shard
                    .values()
                    .any(|crossing| crossing.boundary_header.block_hash() == boundary_hash)
            })
        {
            return true;
        }
        let Some(headers) = self.shard_headers.get(&shard) else {
            return false;
        };
        headers.range(boundary.height()..).any(|(height, x)| {
            let Some(y) = headers.get(&height.next()) else {
                return false;
            };
            // The ancestry walk from `x`'s parent down to `boundary`,
            // pulled by height; `verify_structure` pins every link by
            // hash, so a sibling occupying a slot fails closed.
            let mut ancestry: Vec<BlockHeader> = Vec::new();
            let mut link_height = height.prev();
            while let Some(h) = link_height {
                if h < boundary.height() {
                    break;
                }
                let Some(link) = headers.get(&h) else {
                    return false;
                };
                ancestry.push(link.header().clone());
                link_height = h.prev();
            }
            let proof = CommitProof::new((***x).clone(), (***y).clone(), None, ancestry);
            proof.verify_structure().is_ok() && proof.proven_block_hash() == boundary_hash
        })
    }

    /// Admit a verified chunk — the run `[lo, lo + payloads.len())` against
    /// `anchor` — and clear the matching pending-fetch entry. Replaces any
    /// chunk already held for the anchor: a later fetch is issued only for
    /// a range the fold now wants, so the fresher run is the useful one.
    pub fn admit_chunk(
        &mut self,
        shard: ShardId,
        anchor: BlockHash,
        lo: u64,
        payloads: Vec<ShardWitnessPayload>,
        range_proof: Vec<Hash>,
    ) {
        self.witness_chunks.insert(
            (shard, anchor),
            AnchorChunk {
                lo,
                payloads,
                range_proof,
            },
        );
        self.pending_fetches.remove(&(shard, anchor));
    }

    /// Record the chunk fetch `[lo, hi)` against `anchor` as in flight, for
    /// the boundary block at `block_height`. A pending entry for a
    /// different run is replaced: the fold has moved on, so the older
    /// request's response is no longer wanted. The height is retained so a
    /// later eviction can hand the runner the exact id to cancel.
    ///
    /// Bookkeeping only — dispatch dedup belongs to the runner's fetch,
    /// which drops ids it already tracks. Gating re-issue on this record
    /// would strand a run whose response arrived but failed verification:
    /// the runner has already released its slot by then.
    pub fn register_pending_fetch(
        &mut self,
        shard: ShardId,
        block_height: BlockHeight,
        anchor: BlockHash,
        lo: u64,
        hi: u64,
    ) {
        if self.has_witness_chunk(shard, anchor, lo, hi) {
            return;
        }
        self.pending_fetches.insert(
            (shard, anchor),
            PendingFetch {
                height: block_height,
                lo,
                hi,
            },
        );
    }

    /// Whether the chunk `[prior, chunk_end)` anchored to `anchor` is held
    /// — the presence check behind the proposer's witness-availability
    /// coupling, without cloning the payloads. An empty range is trivially
    /// held.
    #[must_use]
    pub fn has_witness_chunk(
        &self,
        shard: ShardId,
        anchor: BlockHash,
        prior: u64,
        chunk_end: u64,
    ) -> bool {
        if chunk_end <= prior {
            return true;
        }
        self.witness_chunks
            .get(&(shard, anchor))
            .is_some_and(|chunk| chunk.covers(prior, chunk_end))
    }

    /// The witness chunk `[prior, chunk_end)` anchored to `anchor` as
    /// `(payloads, range proof)`, or `None` if the run isn't held (the
    /// assembler defers). An empty range (`chunk_end <= prior`) returns an
    /// empty run with an empty proof.
    #[must_use]
    pub fn witness_chunk(
        &self,
        shard: ShardId,
        anchor: BlockHash,
        prior: u64,
        chunk_end: u64,
    ) -> Option<(Vec<ShardWitnessPayload>, Vec<Hash>)> {
        if chunk_end <= prior {
            return Some((Vec::new(), Vec::new()));
        }
        let chunk = self.witness_chunks.get(&(shard, anchor))?;
        if !chunk.covers(prior, chunk_end) {
            return None;
        }
        Some((chunk.payloads.clone(), chunk.range_proof.clone()))
    }

    /// Drop witnesses and pending fetches for `shard` below the applied
    /// watermark `consumed` (leaf index `< consumed`), across every
    /// anchor. Called from the coordinator's `adopt_block` once a
    /// boundary fold advances `boundaries[shard].witness_leaf_count`.
    /// Empty per-anchor maps are removed.
    ///
    /// Returns the in-flight fetch ids that were dropped, so the caller can
    /// cancel them via `FetchIds::ShardWitnesses` — the witness is now
    /// consumed on-chain and a future contribution can't include it, so the
    /// runner's in-flight slot should release rather than pin on a payload
    /// the tracker would only evict on arrival.
    pub fn evict_consumed(&mut self, shard: ShardId, consumed: u64) -> Vec<ChunkFetchId> {
        self.witness_chunks
            .retain(|(s, _), chunk| *s != shard || chunk.lo >= consumed);
        let mut abandoned = Vec::new();
        self.pending_fetches.retain(|(s, anchor), pending| {
            if *s != shard || pending.lo >= consumed {
                return true;
            }
            abandoned.push(pending_id(*s, *anchor, pending));
            false
        });
        abandoned
    }

    /// Record any epoch-boundary crossing visible in `shard`'s header
    /// window whose boundary block's *commit* is established
    /// ([`Self::commit_established`]) — a certified crossing alone is not
    /// enough, since a shard can halt with its crossing block certified
    /// but never committed, and a boundary folded from it would anchor
    /// recovery on state no member's committed chain can serve. The whole
    /// window is rescanned (it is small), so a crossing detected before
    /// its commit evidence arrived is recorded by the insert that
    /// completes the two-chain. A recorded crossing is stored keyed by
    /// the crossed epoch and retained past header pruning (bounded by
    /// [`MAX_RETAINED_CROSSINGS_PER_SHARD`]), so the proposer can report
    /// it well after its headers leave the window.
    pub fn observe_crossing(&mut self, shard: ShardId, epoch_duration_ms: u64) {
        let windows = EpochWindows::new(epoch_duration_ms);
        let found: Vec<(Epoch, ObservedCrossing)> = {
            let Some(headers) = self.shard_headers.get(&shard) else {
                return;
            };
            headers
                .iter()
                .filter_map(|(height, b)| {
                    let c = headers.get(&height.next())?;
                    let (epoch, crossing) = detect_crossing(b, c, windows)?;
                    self.commit_established(shard, crossing.boundary_header())
                        .then_some((epoch, crossing))
                })
                .collect()
        };
        for (epoch, crossing) in found {
            let per_shard = self.boundary_crossings.entry(shard).or_default();
            per_shard.insert(epoch, crossing);
            while per_shard.len() > MAX_RETAINED_CROSSINGS_PER_SHARD {
                let Some(oldest) = per_shard.keys().next().copied() else {
                    break;
                };
                per_shard.remove(&oldest);
            }
        }
    }

    /// The shard's most recently observed epoch-boundary crossing, if any.
    /// The proposer reports this in its `boundary_qcs`.
    #[must_use]
    pub fn latest_crossing(&self, shard: ShardId) -> Option<&ObservedCrossing> {
        self.boundary_crossings.get(&shard)?.values().next_back()
    }

    /// The crossing the beacon should source next for `shard`, given the
    /// fold's current `watermark` (`boundaries[shard].witness_leaf_count`).
    ///
    /// Returns the **newest crossing with unfolded leaves** (`count >
    /// watermark`). Anchoring the chunk at the newest crossing keeps the
    /// fold live at any lag:
    ///
    /// - The chunk `[watermark, min(watermark + cap, count))` always proves
    ///   into its root: a header's witness window base is the applied
    ///   watermark frozen at its window's open, and the watermark is
    ///   monotone, so a later crossing's window covers every unfolded leaf.
    /// - Its QC always authenticates: verifiers resolve the boundary
    ///   committee through the topology schedule, whose consumer-derived
    ///   floor tracks the shard's `last_live_epoch` — a lagging crossing's
    ///   committee ages below that floor and every verifier abstains,
    ///   freezing the fold exactly when it most needs to advance.
    /// - One chunk can span several lagging crossings' leaves, so a fold
    ///   that fell behind a burst of governance leaves catches up at the
    ///   chunk cap per epoch rather than one crossing per epoch — which
    ///   could not outrun a shard emitting them faster than that.
    ///
    /// Skipping the crossings in between costs their epochs' randomness:
    /// each carries a per-epoch `reveal_chain`, and nothing carries an
    /// unfolded epoch's reveals forward, so the loss is one epoch of shard
    /// entropy per epoch of lag. That is the trade this rule takes — a
    /// bounded, self-healing entropy reduction against a fold that freezes.
    /// Sourcing the *oldest* unfolded crossing instead would close every
    /// epoch, but it drains one crossing per epoch, so lag never clears;
    /// once the lag exceeds the schedule's retention the crossing's own
    /// committee falls below the consumer floor and the fold stops for
    /// good. The seed still mixes prior randomness and every shard that did
    /// cross, so a skipped epoch reduces the entropy folded, never the
    /// seed's determinism or the fence's reach.
    ///
    /// When every retained crossing is folded (`count <= watermark`) it falls
    /// back to the latest, so a terminated shard's folded terminal keeps being
    /// sourced for merge composition — the caller's `crossing_fully_folded`
    /// gate drops it for a live shard.
    #[must_use]
    pub fn next_crossing_to_source(
        &self,
        shard: ShardId,
        watermark: u64,
    ) -> Option<&ObservedCrossing> {
        let per_shard = self.boundary_crossings.get(&shard)?;
        per_shard
            .values()
            .rev()
            .find(|c| c.boundary_header().beacon_witness_leaf_count().inner() > watermark)
            .or_else(|| per_shard.values().next_back())
    }

    /// Called by the coordinator when a commit rotates the local
    /// validator off the beacon committee. Drops witness chunks and
    /// pending fetches — off-committee vnodes neither propose nor fetch —
    /// but keeps `shard_headers` so a vnode drawn back onto the committee
    /// admits boundary QCs immediately instead of abstaining until fresh
    /// headers arrive.
    ///
    /// Returns the in-flight fetch ids that were dropped, so the caller
    /// can cancel them via `FetchIds::ShardWitnesses` — same contract
    /// as [`Self::evict_consumed`], keeping the runner's fetch slots from
    /// pinning on payloads no longer wanted.
    pub fn evicted_from_committee(&mut self) -> Vec<ChunkFetchId> {
        self.witness_chunks.clear();
        std::mem::take(&mut self.pending_fetches)
            .into_iter()
            .map(|((shard, anchor), pending)| pending_id(shard, anchor, &pending))
            .collect()
    }

    /// Look up the verified source-shard header by `committed_block_hash`.
    /// Linear scan over the shard's stored headers — bounded by the
    /// sliding window held in `shard_headers`.
    fn find_header_by_block_hash(
        &self,
        shard: ShardId,
        block_hash: BlockHash,
    ) -> Option<&Arc<Verified<CertifiedBlockHeader>>> {
        self.shard_headers
            .get(&shard)?
            .values()
            .find(|h| h.block_hash() == block_hash)
    }

    /// Look up the verified header for `block_hash`, checking retained
    /// crossings first (a boundary block survives header pruning on its
    /// [`ObservedCrossing`]) then the sliding header window. Used to verify
    /// inbound witnesses against their anchor boundary block's root.
    #[must_use]
    pub fn verified_header_by_block_hash(
        &self,
        shard: ShardId,
        block_hash: BlockHash,
    ) -> Option<&Arc<Verified<CertifiedBlockHeader>>> {
        if let Some(crossing) = self.boundary_crossings.get(&shard).and_then(|per_shard| {
            per_shard
                .values()
                .find(|c| c.boundary_header.block_hash() == block_hash)
        }) {
            return Some(&crossing.boundary_header);
        }
        self.find_header_by_block_hash(shard, block_hash)
    }
}

/// If `c` is `b`'s committed child and `b` is the first block across an
/// epoch boundary — its predecessor at/before the boundary, `b` itself
/// past it — return that crossing keyed by the crossed epoch. `b`'s own
/// weighted timestamp is read canonically from `c.parent_qc`, so the
/// crossed epoch and QC are identical on every node that sees the pair.
fn detect_crossing(
    b: &Arc<Verified<CertifiedBlockHeader>>,
    c: &Arc<Verified<CertifiedBlockHeader>>,
    windows: EpochWindows,
) -> Option<(Epoch, ObservedCrossing)> {
    let canonical_qc = c.header().parent_qc();
    if canonical_qc.block_hash() != b.block_hash() {
        return None;
    }
    let epoch = windows.crossing_epoch(
        b.header().parent_qc().weighted_timestamp(),
        canonical_qc.weighted_timestamp(),
    )?;
    Some((
        epoch,
        ObservedCrossing {
            boundary_header: Arc::clone(b),
            canonical_qc: canonical_qc.clone(),
        },
    ))
}

// Flat accessors; names are the documentation.
#[allow(missing_docs)]
impl ShardSourceTracker {
    #[must_use]
    pub fn header(
        &self,
        shard: ShardId,
        height: BlockHeight,
    ) -> Option<&Arc<Verified<CertifiedBlockHeader>>> {
        self.shard_headers.get(&shard)?.get(&height)
    }

    #[must_use]
    pub fn chunk_len(&self, shard: ShardId, anchor: BlockHash) -> usize {
        self.witness_chunks
            .get(&(shard, anchor))
            .map_or(0, |chunk| chunk.payloads.len())
    }

    #[must_use]
    pub fn total_chunk_len(&self) -> usize {
        self.witness_chunks
            .values()
            .map(|chunk| chunk.payloads.len())
            .sum()
    }

    #[must_use]
    pub fn is_pending_fetch(&self, shard: ShardId, anchor: BlockHash, lo: u64, hi: u64) -> bool {
        self.pending_fetches
            .get(&(shard, anchor))
            .is_some_and(|pending| pending.lo == lo && pending.hi == hi)
    }
}

/// The cancellable fetch id for an in-flight chunk request.
const fn pending_id(shard: ShardId, anchor: BlockHash, pending: &PendingFetch) -> ChunkFetchId {
    (
        shard,
        pending.height,
        anchor,
        LeafIndex::new(pending.lo),
        LeafIndex::new(pending.hi),
    )
}

#[cfg(test)]
mod tests {

    use hyperscale_types::{
        AggregateSignature, BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeader,
        BlockHeaderParts, BlockHeight, CertifiedBlockHeader, Hash, LeafIndex, QuorumCertificate,
        Round, ShardId, ShardWitnessPayload, SignerBitfield, Stake, StakePoolId, Verified,
        WeightedTimestamp,
    };

    use super::*;

    fn shard(n: u64) -> ShardId {
        ShardId::leaf(1, n)
    }

    /// Build a verified header that links to its parent: its `parent_qc`
    /// names `parent_hash` and carries `parent_wt` (the parent's canonical
    /// weighted timestamp). Chaining two of these lets `detect_crossing`
    /// recognise a real `(B, C)` parent/child pair; a round-contiguous
    /// child (`round == parent round + 1`) additionally direct-commits its
    /// parent, which the crossing recorder demands as commit evidence.
    fn linked_header(
        s: ShardId,
        height: u64,
        round: u64,
        parent_hash: BlockHash,
        parent_wt: u64,
        leaf_count: u64,
    ) -> Arc<Verified<CertifiedBlockHeader>> {
        let parent_qc = QuorumCertificate::new(
            parent_hash,
            s,
            BlockHeight::new(height.saturating_sub(1)),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(parent_wt),
        );
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: s,
            height: BlockHeight::new(height),
            parent_block_hash: parent_hash,
            parent_qc: parent_qc.into(),
            round: Round::new(round),
            beacon_witness_root: BeaconWitnessRoot::from_raw(Hash::from_bytes(
                format!("r-{s:?}-{height}").as_bytes(),
            )),
            beacon_witness_leaf_count: BeaconWitnessLeafCount::new(leaf_count),
            ..Default::default()
        });
        let block_hash = header.hash();
        let qc = QuorumCertificate::new(
            block_hash,
            s,
            BlockHeight::new(height),
            parent_hash,
            Round::INITIAL,
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(parent_wt),
        );
        Arc::new(Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
            header, qc,
        )))
    }

    /// Record a verified header and detect any crossing it completes.
    fn note(t: &mut ShardSourceTracker, h: &Arc<Verified<CertifiedBlockHeader>>, dur: u64) {
        t.on_verified_source_header(Arc::clone(h));
        t.observe_crossing(h.header().shard_id(), dur);
    }

    /// `n` distinct deposit payloads — content the chunk helpers can hash
    /// into leaves. The tracker never verifies them, so any distinct run
    /// exercises the coverage bookkeeping.
    fn payloads(n: u64) -> Vec<ShardWitnessPayload> {
        (0..n)
            .map(|i| ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(u32::try_from(i).unwrap_or(u32::MAX)),
                amount: Stake::from_whole_tokens(1),
            })
            .collect()
    }

    fn anchor(n: u64) -> BlockHash {
        BlockHash::from_raw(Hash::from_bytes(format!("anchor-{n}").as_bytes()))
    }

    #[test]
    fn empty_after_new() {
        let t = ShardSourceTracker::new();
        assert!(t.header(shard(0), BlockHeight::new(0)).is_none());
        assert_eq!(t.chunk_len(shard(0), anchor(0)), 0);
    }

    #[test]
    fn admit_chunk_lands_whole_and_clears_pending() {
        let mut t = ShardSourceTracker::new();
        t.register_pending_fetch(shard(0), BlockHeight::new(5), anchor(1), 3, 6);
        assert!(t.is_pending_fetch(shard(0), anchor(1), 3, 6));
        t.admit_chunk(shard(0), anchor(1), 3, payloads(3), Vec::new());
        assert_eq!(t.chunk_len(shard(0), anchor(1)), 3);
        assert!(!t.is_pending_fetch(shard(0), anchor(1), 3, 6));
    }

    /// A run the fold has moved on to replaces the stale pending entry, and
    /// a run already pooled records nothing — there is no id to cancel.
    #[test]
    fn register_pending_fetch_supersedes_and_skips_held_runs() {
        let mut t = ShardSourceTracker::new();
        let h = BlockHeight::new(5);
        t.register_pending_fetch(shard(0), h, anchor(1), 3, 6);
        assert!(t.is_pending_fetch(shard(0), anchor(1), 3, 6));

        // A different run supersedes: the fold advanced, so the older
        // request's response is no longer wanted.
        t.register_pending_fetch(shard(0), h, anchor(1), 6, 9);
        assert!(t.is_pending_fetch(shard(0), anchor(1), 6, 9));
        assert!(!t.is_pending_fetch(shard(0), anchor(1), 3, 6));

        // A run already pooled records nothing.
        t.admit_chunk(shard(0), anchor(2), 6, payloads(3), Vec::new());
        t.register_pending_fetch(shard(0), h, anchor(2), 6, 9);
        assert!(!t.is_pending_fetch(shard(0), anchor(2), 6, 9));
    }

    /// The chunk reads back only for the exact run it covers: a wider or
    /// narrower range, or a different anchor, defers. An empty range is
    /// trivially available.
    #[test]
    fn witness_chunk_returns_only_the_covered_run() {
        let mut t = ShardSourceTracker::new();
        assert_eq!(
            t.witness_chunk(shard(0), anchor(1), 4, 4)
                .map(|(p, proof)| (p.len(), proof.len())),
            Some((0, 0)),
        );

        t.admit_chunk(shard(0), anchor(1), 4, payloads(2), Vec::new());
        let (chunk, proof) = t
            .witness_chunk(shard(0), anchor(1), 4, 6)
            .expect("chunk present");
        assert_eq!(chunk.len(), 2);
        assert!(proof.is_empty());

        // A wider range than the chunk covers — the run can't be proven.
        assert!(t.witness_chunk(shard(0), anchor(1), 4, 7).is_none());
        // A narrower one likewise: the proof is scoped to the whole run.
        assert!(t.witness_chunk(shard(0), anchor(1), 4, 5).is_none());
        // The wrong anchor has nothing.
        assert!(t.witness_chunk(shard(0), anchor(2), 4, 6).is_none());
    }

    #[test]
    fn evict_consumed_drops_chunks_below_watermark() {
        let mut t = ShardSourceTracker::new();
        t.admit_chunk(shard(0), anchor(1), 0, payloads(5), Vec::new());
        t.evict_consumed(shard(0), 3);
        assert_eq!(t.total_chunk_len(), 0);

        // A chunk starting at or above the watermark survives.
        t.admit_chunk(shard(0), anchor(2), 3, payloads(2), Vec::new());
        t.evict_consumed(shard(0), 3);
        assert!(t.witness_chunk(shard(0), anchor(2), 3, 5).is_some());
    }

    /// Eviction hands back the in-flight fetches it dropped — full
    /// `(shard, height, anchor, lo, hi)` ids — so the coordinator can
    /// cancel them via `FetchIds::ShardWitnesses`. A run starting at or
    /// above the watermark stays in flight.
    #[test]
    fn evict_consumed_returns_abandoned_in_flight_fetches() {
        let mut t = ShardSourceTracker::new();
        let height = BlockHeight::new(5);
        t.register_pending_fetch(shard(0), height, anchor(1), 0, 2);
        t.register_pending_fetch(shard(0), height, anchor(2), 3, 5);

        let abandoned = t.evict_consumed(shard(0), 3);
        assert_eq!(
            abandoned,
            vec![(
                shard(0),
                height,
                anchor(1),
                LeafIndex::new(0),
                LeafIndex::new(2),
            )],
        );
        assert!(t.is_pending_fetch(shard(0), anchor(2), 3, 5));
        assert!(!t.is_pending_fetch(shard(0), anchor(1), 0, 2));
    }

    /// A `(B, C)` parent/child pair straddling an epoch boundary records a
    /// crossing: `B` at predecessor-wt 900 (≤ the 1000 boundary) and own
    /// canonical wt 1500 (read from `C.parent_qc`, past 1000) is the first
    /// block across epoch 1.
    #[test]
    fn observe_crossing_records_first_block_across_boundary() {
        let mut t = ShardSourceTracker::new();
        let b = linked_header(shard(0), 2, 1, BlockHash::ZERO, 900, 7);
        let c = linked_header(shard(0), 3, 2, b.block_hash(), 1_500, 7);
        note(&mut t, &b, 1_000);
        note(&mut t, &c, 1_000);
        let crossing = t.latest_crossing(shard(0)).expect("crossing observed");
        assert_eq!(
            crossing.canonical_qc().weighted_timestamp(),
            WeightedTimestamp::from_millis(1_500),
        );
        assert_eq!(crossing.canonical_qc().block_hash(), b.block_hash());
        assert_eq!(crossing.boundary_header().hash(), b.block_hash());
    }

    /// A `(B, C)` pair whose rounds gap — a view change between them —
    /// leaves `B` certified but not committed, so no crossing is recorded:
    /// a boundary folded from it would anchor recovery on state no
    /// member's committed chain can ever serve.
    #[test]
    fn observe_crossing_demands_commit_evidence() {
        let mut t = ShardSourceTracker::new();
        let b = linked_header(shard(0), 2, 1, BlockHash::ZERO, 900, 7);
        let c = linked_header(shard(0), 3, 3, b.block_hash(), 1_500, 7);
        note(&mut t, &b, 1_000);
        note(&mut t, &c, 1_000);
        assert!(
            t.latest_crossing(shard(0)).is_none(),
            "a certified-but-uncommitted boundary block must not record a crossing",
        );
    }

    /// A round gap directly above the boundary block still records once a
    /// later round-contiguous pair direct-commits a descendant: the parent
    /// hash chain descending from the committed block pins the boundary
    /// block beneath it.
    #[test]
    fn observe_crossing_accepts_commit_via_later_two_chain() {
        let mut t = ShardSourceTracker::new();
        let b = linked_header(shard(0), 2, 1, BlockHash::ZERO, 900, 7);
        let c = linked_header(shard(0), 3, 3, b.block_hash(), 1_500, 7);
        let d = linked_header(shard(0), 4, 4, c.block_hash(), 1_600, 7);
        note(&mut t, &b, 1_000);
        note(&mut t, &c, 1_000);
        assert!(t.latest_crossing(shard(0)).is_none());
        note(&mut t, &d, 1_000);
        let crossing = t
            .latest_crossing(shard(0))
            .expect("the (C, D) two-chain commits C, whose ancestry pins B");
        assert_eq!(crossing.boundary_header().hash(), b.block_hash());
        assert_eq!(crossing.canonical_qc().block_hash(), b.block_hash());
    }

    /// A pair wholly inside one epoch (predecessor 1200 and own wt 1500,
    /// both past the 1000 boundary) is not a crossing.
    #[test]
    fn observe_crossing_ignores_within_epoch_pair() {
        let mut t = ShardSourceTracker::new();
        let b = linked_header(shard(0), 2, 1, BlockHash::ZERO, 1_200, 0);
        let c = linked_header(shard(0), 3, 2, b.block_hash(), 1_500, 0);
        note(&mut t, &b, 1_000);
        note(&mut t, &c, 1_000);
        assert!(t.latest_crossing(shard(0)).is_none());
    }

    /// A boundary block's header stays retrievable by hash via its
    /// retained crossing even after the sliding header window prunes it
    /// — the lookup the assembler and admission gate rely on. Unknown
    /// shards/hashes resolve to nothing.
    #[test]
    fn verified_header_lookup_survives_header_pruning_via_crossing() {
        let mut t = ShardSourceTracker::new();
        let b = linked_header(shard(0), 2, 1, BlockHash::ZERO, 900, 0);
        let c = linked_header(shard(0), 3, 2, b.block_hash(), 1_500, 0);
        note(&mut t, &b, 1_000);
        note(&mut t, &c, 1_000);
        // Push the boundary block out of the sliding header window.
        for height in 4..=(MAX_RETAINED_HEADERS_PER_SHARD as u64 + 4) {
            t.on_verified_source_header(linked_header(
                shard(0),
                height,
                height,
                BlockHash::ZERO,
                1_600,
                0,
            ));
        }
        assert!(t.header(shard(0), BlockHeight::new(2)).is_none());

        let held = t
            .verified_header_by_block_hash(shard(0), b.block_hash())
            .expect("boundary header retained on its crossing");
        assert_eq!(held.block_hash(), b.block_hash());
        assert!(
            t.verified_header_by_block_hash(shard(0), BlockHash::ZERO)
                .is_none()
        );
        assert!(
            t.verified_header_by_block_hash(shard(1), b.block_hash())
                .is_none()
        );
    }

    #[test]
    fn insertion_bounds_the_window() {
        let mut t = ShardSourceTracker::new();
        for height in 1..=(MAX_RETAINED_HEADERS_PER_SHARD as u64 + 3) {
            t.on_verified_source_header(linked_header(
                shard(0),
                height,
                height,
                BlockHash::ZERO,
                0,
                0,
            ));
        }
        // Oldest heights dropped; the window holds the most recent set.
        assert!(t.header(shard(0), BlockHeight::new(1)).is_none());
        assert!(
            t.header(
                shard(0),
                BlockHeight::new(MAX_RETAINED_HEADERS_PER_SHARD as u64 + 3)
            )
            .is_some()
        );
    }

    #[test]
    fn evicted_from_committee_clears_chunks_keeps_headers() {
        let mut t = ShardSourceTracker::new();
        t.on_verified_source_header(linked_header(shard(0), 1, 1, BlockHash::ZERO, 0, 0));
        t.admit_chunk(shard(0), anchor(1), 0, payloads(1), Vec::new());
        t.register_pending_fetch(shard(0), BlockHeight::new(5), anchor(2), 1, 3);
        let abandoned = t.evicted_from_committee();
        assert_eq!(t.total_chunk_len(), 0);
        assert!(!t.is_pending_fetch(shard(0), anchor(2), 1, 3));
        assert!(t.header(shard(0), BlockHeight::new(1)).is_some());
        // The in-flight fetch comes back as a cancellable id.
        assert_eq!(
            abandoned,
            vec![(
                shard(0),
                BlockHeight::new(5),
                anchor(2),
                LeafIndex::new(1),
                LeafIndex::new(3),
            )],
        );
    }
}
