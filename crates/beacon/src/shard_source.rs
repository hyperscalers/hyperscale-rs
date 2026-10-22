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
use std::iter;
use std::sync::Arc;

use hyperscale_hbor::Capped;
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
/// A crossing is read off a block `C` whose own commit is established
/// ([`ShardSourceTracker::commit_established`]): the certificate `C`
/// embeds over its parent `B` is the one date the shard's chain holds for
/// `B`, and a crossing is recorded where that date is the first past a
/// boundary. Recorded while the evidence is fresh near the shard tip, so
/// it survives header pruning.
///
/// `boundary_header` is `B`, and `canonical_qc` the certificate `C`
/// embeds over it: one value on every node, since a block has one
/// committed child. Where `C` carries the terminal settled root,
/// `boundary_header` is `C` itself, the block that dates its own
/// crossing, and `canonical_qc` is the certificate the block held above
/// `C` embeds over it: a proof that `C` was certified, read from a block
/// whose own commit an observer need never be shown.
///
/// `boundary_parent` is the boundary block's parent, where the window
/// held it when the crossing was read. A block's committee anchors on its
/// parent, so it names the committee that signed `canonical_qc`; kept
/// beside the crossing, it spares every member that read the crossing
/// live a commit-proof ask for it, which a member's own shard never
/// answers.
#[derive(Debug, Clone)]
pub struct ObservedCrossing {
    boundary_header: Arc<Verified<CertifiedBlockHeader>>,
    canonical_qc: QuorumCertificate,
    boundary_parent: Option<Arc<Verified<CertifiedBlockHeader>>>,
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
/// - `proven_boundaries` — blocks this node asked the shard to prove for
///   a boundary a peer's proposal named — the boundary block, its parent
///   or its committed child — held with their commit proven outside the
///   header window. Bounded by the asks, and cleared by the coordinator
///   every epoch.
#[derive(Debug, Default)]
pub struct ShardSourceTracker {
    shard_headers: BTreeMap<ShardId, BTreeMap<BlockHeight, Arc<Verified<CertifiedBlockHeader>>>>,
    boundary_crossings: BTreeMap<ShardId, BTreeMap<Epoch, ObservedCrossing>>,
    witness_chunks: BTreeMap<(ShardId, BlockHash), AnchorChunk>,
    pending_fetches: BTreeMap<(ShardId, BlockHash), PendingFetch>,
    proven_boundaries: BTreeMap<(ShardId, BlockHash), Arc<Verified<CertifiedBlockHeader>>>,
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
    /// for every active shard (on- or off-committee) — remote shards via
    /// the remote-header path, the local shard from its own certified
    /// blocks and commit stream. The shard's window keeps only its most
    /// recent [`MAX_RETAINED_HEADERS_PER_SHARD`] heights; a boundary block
    /// needed past the window is retained on its [`ObservedCrossing`].
    ///
    /// A header is certified, not committed, so a sibling that lost its
    /// round can arrive for a height already held. A chain commits one
    /// block per height: a held block whose commit the window proves
    /// keeps its slot, and any other block at that height is the loser.
    /// A block already held is recorded once: a second report of it
    /// keeps the copy first held.
    pub fn on_verified_source_header(
        &mut self,
        certified_header: Arc<Verified<CertifiedBlockHeader>>,
    ) {
        let header = certified_header.header();
        let shard = header.shard_id();
        let height = header.height();
        let headers = self.shard_headers.entry(shard).or_default();
        if headers.get(&height).is_some_and(|held| {
            held.block_hash() == certified_header.block_hash()
                || window_commits(headers, held.header())
        }) {
            return;
        }
        headers.insert(height, certified_header);
        while headers.len() > MAX_RETAINED_HEADERS_PER_SHARD {
            headers.pop_first();
        }
    }

    /// Hold a block whose commit the shard proved on this node's ask: it
    /// is found by [`Self::verified_header_by_block_hash`], its commit is
    /// established, and the certificate it embeds over its parent is that
    /// parent's [`Self::committed_certificate`].
    pub fn admit_proven_boundary(&mut self, certified_header: Arc<Verified<CertifiedBlockHeader>>) {
        let key = (certified_header.shard_id(), certified_header.block_hash());
        self.proven_boundaries.insert(key, certified_header);
    }

    /// Drop every proven boundary: they were asked for one epoch's
    /// proposals.
    pub fn clear_proven_boundaries(&mut self) {
        self.proven_boundaries.clear();
    }

    /// `header`'s parent, when the shard's header window, retained
    /// crossings or proven boundaries hold it — keyed at the height below
    /// `header`'s own and pinned by the parent hash the header names, so a
    /// sibling at the slot never matches. What resolves the committee that
    /// signed a QC over `header`'s block: a block's committee anchors on its
    /// parent.
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
                        .flat_map(|crossing| {
                            iter::once(&crossing.boundary_header)
                                .chain(crossing.boundary_parent.as_ref())
                        })
                        .find(|held| held.block_hash() == parent_hash)
                })
            })
            .or_else(|| self.proven_boundaries.get(&(shard, parent_hash)))
            .map(|held| held.header())
    }

    /// Whether `block`'s *commit* on `shard` is locally established: the
    /// shard proved it on this node's ask, a recorded crossing already
    /// names it (this check gated the record), or the header window holds
    /// its commit ([`window_commits`]). A bare 2f+1 QC proves
    /// availability, not commitment, so this is what separates a block the
    /// shard's chain durably reached from one it merely certified.
    ///
    /// # Panics
    ///
    /// If a list written out here is past the cap its type states.
    #[must_use]
    pub fn commit_established(&self, shard: ShardId, block: &BlockHeader) -> bool {
        let block_hash = block.hash();
        self.proven_boundaries.contains_key(&(shard, block_hash))
            || self
                .boundary_crossings
                .get(&shard)
                .is_some_and(|per_shard| {
                    per_shard
                        .values()
                        .any(|crossing| crossing.boundary_header.block_hash() == block_hash)
                })
            || self
                .shard_headers
                .get(&shard)
                .is_some_and(|headers| window_commits(headers, block))
    }

    /// The certificate `shard`'s committed chain holds over `block`: the
    /// one `block`'s child embeds as `parent_qc`, read only from a child
    /// whose own commit is established. `None` until such a child is
    /// held.
    ///
    /// A certificate's weighted timestamp is the median of its voters'
    /// clocks and rides outside the aggregate signature, so two honest
    /// aggregations over one block date it apart, and any holder can
    /// write another date beside the same signers. A child covers the
    /// certificate it embeds with its own hash, date included; but a
    /// block can have several certified children, each embedding its own
    /// aggregate, and any one of them certified commits `block`. A chain
    /// commits one block per height, so the child whose own commit is
    /// established is the same block on every node, and the certificate
    /// it embeds is the one reading of `block`'s certifying time that no
    /// two nodes can be handed differently.
    ///
    /// The child is the block the shard proved on this node's ask, or the
    /// one in the window slot above `block` whose commit the window
    /// holds. A recorded crossing keeps the certificate past both. A
    /// terminal's record keeps none: the certificate beside it was read
    /// from a block whose own commit this node need never be shown.
    ///
    /// # Panics
    ///
    /// If a list written out here is past the cap its type states.
    #[must_use]
    pub(crate) fn committed_certificate(
        &self,
        shard: ShardId,
        block: &BlockHeader,
    ) -> Option<&QuorumCertificate> {
        let block_hash = block.hash();
        if block.settled_txs_root().is_none()
            && let Some(crossing) = self.boundary_crossings.get(&shard).and_then(|per_shard| {
                per_shard
                    .values()
                    .find(|crossing| crossing.boundary_header.block_hash() == block_hash)
            })
        {
            return Some(&crossing.canonical_qc);
        }
        let proven_child = self
            .proven_boundaries
            .iter()
            .filter(|((proven_shard, _), _)| *proven_shard == shard)
            .find_map(|(_, proven)| embedded_certificate(block_hash, proven.header()));
        proven_child.or_else(|| {
            let headers = self.shard_headers.get(&shard)?;
            let child = headers.get(&block.height().next())?.header();
            let certificate = embedded_certificate(block_hash, child)?;
            window_commits(headers, child).then_some(certificate)
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

    /// Drop everything held for each shard `departed` answers `true`
    /// for — headers, crossings, witness chunks and pending fetches.
    ///
    /// The tracker fills from every verified source header and never
    /// sheds a shard otherwise, so a shard whose chain has ended keeps
    /// its window for the life of the process. The caller states which
    /// shards those are; the bound that makes the answer safe is the
    /// handoff evidence expiry, past which the beacon's own boundary
    /// record is dropped and no proposer sources the shard again.
    ///
    /// Returns the in-flight fetch ids that were dropped, so the caller
    /// can cancel them — same contract as [`Self::evict_consumed`].
    pub fn retire_departed(&mut self, departed: impl Fn(ShardId) -> bool) -> Vec<ChunkFetchId> {
        let shards: Vec<ShardId> = self
            .shard_headers
            .keys()
            .chain(self.boundary_crossings.keys())
            .copied()
            .filter(|shard| departed(*shard))
            .collect();
        let mut abandoned = Vec::new();
        for shard in shards {
            self.shard_headers.remove(&shard);
            self.boundary_crossings.remove(&shard);
            self.witness_chunks.retain(|(s, _), _| *s != shard);
            self.pending_fetches.retain(|(s, anchor), pending| {
                if *s != shard {
                    return true;
                }
                abandoned.push(pending_id(*s, *anchor, pending));
                false
            });
        }
        abandoned
    }

    /// Record any epoch-boundary crossing visible in `shard`'s header
    /// window that is read off a block whose own *commit* is established
    /// ([`Self::commit_established`]). A certified block is not enough,
    /// for two reasons. A shard can halt with its crossing block certified
    /// but never committed, and a boundary folded from it would anchor
    /// recovery on state no member's committed chain can serve. And a
    /// certified child that its chain went on to orphan dates its parent
    /// by an aggregate no other node need hold. The whole
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
                    let d = headers.get(&height.next().next());
                    let (epoch, mut crossing) = detect_crossing(b, c, d, windows)?;
                    if !self.commit_established(shard, c.header()) {
                        return None;
                    }
                    let boundary = crossing.boundary_header.header();
                    crossing.boundary_parent = boundary
                        .height()
                        .prev()
                        .and_then(|parent_height| headers.get(&parent_height))
                        .filter(|parent| parent.block_hash() == boundary.parent_block_hash())
                        .cloned();
                    Some((epoch, crossing))
                })
                .collect()
        };
        for (epoch, mut crossing) in found {
            let per_shard = self.boundary_crossings.entry(shard).or_default();
            // A re-read after the parent left the window keeps the parent
            // the first read held.
            if crossing.boundary_parent.is_none()
                && let Some(held) = per_shard.get(&epoch).filter(|held| {
                    held.boundary_header.block_hash() == crossing.boundary_header.block_hash()
                })
            {
                crossing.boundary_parent.clone_from(&held.boundary_parent);
            }
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
    ///
    /// Only crossings `contributes` accepts are candidates. A terminating
    /// chain coasts past its terminal until its committed chain proves the
    /// terminal committed, and a coast long enough to cross another boundary
    /// records a crossing newer than the terminal that no fold admits; sourcing it would have every
    /// verifier abstain on the proposal carrying it.
    #[must_use]
    pub fn next_crossing_to_source(
        &self,
        shard: ShardId,
        watermark: u64,
        contributes: impl Fn(&ObservedCrossing) -> bool,
    ) -> Option<&ObservedCrossing> {
        let per_shard = self.boundary_crossings.get(&shard)?;
        let mut candidates = per_shard.values().rev().filter(|c| contributes(c));
        let latest = candidates.clone().next();
        candidates
            .find(|c| c.boundary_header().beacon_witness_leaf_count().inner() > watermark)
            .or(latest)
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
    /// [`ObservedCrossing`]), then the proven boundaries, then the sliding
    /// header window. Used to verify inbound witnesses against their
    /// anchor boundary block's root.
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
        if let Some(proven) = self.proven_boundaries.get(&(shard, block_hash)) {
            return Some(proven);
        }
        self.find_header_by_block_hash(shard, block_hash)
    }
}

/// Whether `headers` hold `block`'s commit: a round-contiguous certified
/// two-chain at or above it whose parent-hash ancestry descends to it —
/// [`CommitProof`]'s structural rule, assembled from headers whose
/// signatures were verified on arrival.
///
/// # Panics
///
/// If a list written out here is past the cap its type states.
fn window_commits(
    headers: &BTreeMap<BlockHeight, Arc<Verified<CertifiedBlockHeader>>>,
    block: &BlockHeader,
) -> bool {
    let block_hash = block.hash();
    headers.range(block.height()..).any(|(height, x)| {
        let Some(y) = headers.get(&height.next()) else {
            return false;
        };
        // The ancestry walk from `x`'s parent down to `block`, pulled by
        // height; `verify_structure` pins every link by hash, so a
        // sibling occupying a slot fails closed.
        let mut ancestry: Vec<BlockHeader> = Vec::new();
        let mut link_height = height.prev();
        while let Some(h) = link_height {
            if h < block.height() {
                break;
            }
            let Some(link) = headers.get(&h) else {
                return false;
            };
            ancestry.push(link.header().clone());
            link_height = h.prev();
        }
        let proof = CommitProof::new(
            (***x).clone(),
            (***y).clone(),
            None,
            Capped::new(ancestry).expect("an ancestry written out in a test"),
        );
        proof.verify_structure().is_ok() && proof.proven_block_hash() == block_hash
    })
}

/// The certificate `child` embeds over the block `parent_hash` names,
/// where `child` extends that block.
fn embedded_certificate(parent_hash: BlockHash, child: &BlockHeader) -> Option<&QuorumCertificate> {
    let embedded = child.parent_qc();
    (child.parent_block_hash() == parent_hash && embedded.block_hash() == parent_hash)
        .then_some(embedded)
}

/// The crossing `c` dates for its parent `b`, keyed by the crossed epoch:
/// `b`'s predecessor certified at or before a boundary and `b` itself, by
/// the certificate `c` embeds over it, past it. The caller holds the
/// reading to `c`'s own commit.
///
/// The boundary block is `b`. Where `c` carries the terminal settled
/// root, `c` is its chain's terminal — the first block past the cut,
/// which `b` could not know it was — and the boundary block is `c`,
/// beside the certificate `d` embeds over it, once `d` is held.
fn detect_crossing(
    b: &Arc<Verified<CertifiedBlockHeader>>,
    c: &Arc<Verified<CertifiedBlockHeader>>,
    d: Option<&Arc<Verified<CertifiedBlockHeader>>>,
    windows: EpochWindows,
) -> Option<(Epoch, ObservedCrossing)> {
    let dating_qc = embedded_certificate(b.block_hash(), c.header())?;
    let epoch = windows.crossing_epoch(
        b.header().parent_qc().weighted_timestamp(),
        dating_qc.weighted_timestamp(),
    )?;
    if c.header().settled_txs_root().is_none() {
        return Some((
            epoch,
            ObservedCrossing {
                boundary_header: Arc::clone(b),
                canonical_qc: dating_qc.clone(),
                boundary_parent: None,
            },
        ));
    }
    let terminal_qc = embedded_certificate(c.block_hash(), d?.header())?;
    Some((
        epoch,
        ObservedCrossing {
            boundary_header: Arc::clone(c),
            canonical_qc: terminal_qc.clone(),
            boundary_parent: None,
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
        Round, SettledTxsRoot, ShardId, ShardWitnessPayload, SignerBitfield, Stake, StakePoolId,
        Verified, WeightedTimestamp,
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
        linked_header_settling(s, height, round, parent_hash, parent_wt, leaf_count, None)
    }

    /// [`linked_header`] carrying `terminal_settled_txs`, as a chain's
    /// terminal alone does.
    fn linked_header_settling(
        s: ShardId,
        height: u64,
        round: u64,
        parent_hash: BlockHash,
        parent_wt: u64,
        leaf_count: u64,
        terminal_settled_txs: Option<SettledTxsRoot>,
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
            terminal_settled_txs,
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

    /// A certified header can be a sibling that lost its round. One that
    /// arrives for a height whose held block the window proves committed
    /// leaves that block in its slot; one beside a held block whose commit
    /// is not yet proven takes the slot.
    #[test]
    fn a_losing_sibling_never_displaces_a_committed_block() {
        let mut t = ShardSourceTracker::new();
        let b = linked_header(shard(0), 2, 1, BlockHash::ZERO, 900, 7);
        let c = linked_header(shard(0), 3, 2, b.block_hash(), 1_000, 7);
        let sibling = linked_header(shard(0), 2, 4, BlockHash::ZERO, 950, 7);
        assert_ne!(sibling.block_hash(), b.block_hash());

        t.on_verified_source_header(Arc::clone(&sibling));
        t.on_verified_source_header(Arc::clone(&b));
        assert_eq!(
            t.header(shard(0), BlockHeight::new(2))
                .map(|held| held.block_hash()),
            Some(b.block_hash()),
            "an unproven block yields its slot",
        );

        t.on_verified_source_header(Arc::clone(&c));
        t.on_verified_source_header(Arc::clone(&sibling));
        assert_eq!(
            t.header(shard(0), BlockHeight::new(2))
                .map(|held| held.block_hash()),
            Some(b.block_hash()),
            "a committed block keeps its slot",
        );
        assert!(t.commit_established(shard(0), b.header()));
    }

    /// The boundary block's parent names the committee that signed it.
    /// A crossing read while the window held that parent keeps it, so the
    /// committee still resolves once the chain has moved the window past
    /// both: no member that read the crossing live has to ask the shard
    /// for it, and a member's own shard answers no such ask.
    #[test]
    fn a_crossing_keeps_the_parent_that_names_its_committee() {
        let mut t = ShardSourceTracker::new();
        let a = linked_header(shard(0), 1, 0, BlockHash::ZERO, 800, 7);
        let b = linked_header(shard(0), 2, 1, a.block_hash(), 900, 7);
        let c = linked_header(shard(0), 3, 2, b.block_hash(), 1_500, 7);
        let mut tip = linked_header(shard(0), 4, 3, c.block_hash(), 1_600, 7);
        for header in [&a, &b, &c, &tip] {
            note(&mut t, header, 1_000);
        }
        let crossing = t.latest_crossing(shard(0)).expect("crossing observed");
        assert_eq!(crossing.boundary_header().hash(), b.block_hash());

        for height in 5..20 {
            tip = linked_header(shard(0), height, height - 1, tip.block_hash(), 1_700, 7);
            note(&mut t, &tip, 1_000);
        }
        assert!(t.header(shard(0), BlockHeight::new(1)).is_none());
        assert_eq!(
            t.parent_header(b.header()).map(BlockHeader::hash),
            Some(a.block_hash()),
        );
    }

    /// A `(B, C)` parent/child pair straddling an epoch boundary records a
    /// crossing once `C`'s own commit is established: `B` at
    /// predecessor-wt 900 (≤ the 1000 boundary) and own canonical wt 1500
    /// (read from `C.parent_qc`, past 1000) is the first block across
    /// epoch 1. The pair alone commits `B` and records nothing, since `C`
    /// may yet be orphaned and the certificate it embeds with it.
    #[test]
    fn observe_crossing_records_first_block_across_boundary() {
        let mut t = ShardSourceTracker::new();
        let b = linked_header(shard(0), 2, 1, BlockHash::ZERO, 900, 7);
        let c = linked_header(shard(0), 3, 2, b.block_hash(), 1_500, 7);
        let d = linked_header(shard(0), 4, 3, c.block_hash(), 1_600, 7);
        note(&mut t, &b, 1_000);
        note(&mut t, &c, 1_000);
        assert!(t.commit_established(shard(0), b.header()));
        assert!(
            t.latest_crossing(shard(0)).is_none(),
            "the crossing waits for the commit of the child that dates it",
        );
        assert!(t.committed_certificate(shard(0), b.header()).is_none());
        note(&mut t, &d, 1_000);
        assert_eq!(
            t.committed_certificate(shard(0), b.header()),
            Some(c.header().parent_qc()),
        );
        let crossing = t.latest_crossing(shard(0)).expect("crossing observed");
        assert_eq!(
            crossing.canonical_qc().weighted_timestamp(),
            WeightedTimestamp::from_millis(1_500),
        );
        assert_eq!(crossing.canonical_qc().block_hash(), b.block_hash());
        assert_eq!(crossing.boundary_header().hash(), b.block_hash());
    }

    /// Where the first block past the boundary carries the terminal
    /// settled root, it is its chain's terminal: the crossing recorded is
    /// that block, certified by its successor's parent QC, once the
    /// successor is held and commits it — never the block before it.
    #[test]
    fn observe_crossing_records_the_terminal_past_the_cut() {
        let mut t = ShardSourceTracker::new();
        let b = linked_header(shard(0), 2, 1, BlockHash::ZERO, 900, 7);
        let c = linked_header_settling(
            shard(0),
            3,
            2,
            b.block_hash(),
            1_500,
            7,
            Some(SettledTxsRoot::ZERO),
        );
        note(&mut t, &b, 1_000);
        note(&mut t, &c, 1_000);
        assert!(
            t.latest_crossing(shard(0)).is_none(),
            "the terminal waits for the QC its successor carries",
        );
        let d = linked_header(shard(0), 4, 3, c.block_hash(), 1_600, 7);
        note(&mut t, &d, 1_000);
        let crossing = t.latest_crossing(shard(0)).expect("terminal observed");
        assert_eq!(crossing.boundary_header().hash(), c.block_hash());
        assert_eq!(crossing.canonical_qc().block_hash(), c.block_hash());
        assert_eq!(
            crossing.canonical_qc().weighted_timestamp(),
            WeightedTimestamp::from_millis(1_600),
        );
    }

    /// A chain that coasts past its terminal into the next epoch records a
    /// crossing newer than the terminal. A caller that refuses it is
    /// handed the terminal, whatever the watermark says of either.
    #[test]
    fn next_crossing_to_source_passes_over_a_refused_crossing() {
        let mut t = ShardSourceTracker::new();
        let b = linked_header(shard(0), 2, 1, BlockHash::ZERO, 900, 7);
        let terminal = linked_header_settling(
            shard(0),
            3,
            2,
            b.block_hash(),
            1_500,
            7,
            Some(SettledTxsRoot::ZERO),
        );
        let coast = linked_header(shard(0), 4, 3, terminal.block_hash(), 1_600, 7);
        let across = linked_header(shard(0), 5, 4, coast.block_hash(), 2_500, 7);
        let above = linked_header(shard(0), 6, 5, across.block_hash(), 2_600, 7);
        for header in [&b, &terminal, &coast, &across, &above] {
            note(&mut t, header, 1_000);
        }
        let terminal_only = |c: &ObservedCrossing| c.boundary_header().settled_txs_root().is_some();
        for watermark in [0, 7] {
            assert_eq!(
                t.next_crossing_to_source(shard(0), watermark, |_| true)
                    .map(|c| c.boundary_header().hash()),
                Some(coast.block_hash()),
                "the coast crossing is the newest",
            );
            assert_eq!(
                t.next_crossing_to_source(shard(0), watermark, terminal_only)
                    .map(|c| c.boundary_header().hash()),
                Some(terminal.block_hash()),
            );
        }
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

    /// A block's certified children each embed their own aggregate over
    /// it, and one certified child is enough to commit the block. The
    /// tracker reads the block's certificate from none of them until one
    /// has its own commit established, so a child its chain orphaned
    /// dates nothing, whether it is heard first or last. Here the orphan
    /// dates the block short of the boundary and the committed child past
    /// it.
    #[test]
    fn an_orphaned_child_dates_no_crossing() {
        let mut t = ShardSourceTracker::new();
        let b = linked_header(shard(0), 2, 1, BlockHash::ZERO, 900, 7);
        let orphan = linked_header(shard(0), 3, 2, b.block_hash(), 999, 7);
        let committed = linked_header(shard(0), 3, 3, b.block_hash(), 1_500, 7);
        let above = linked_header(shard(0), 4, 4, committed.block_hash(), 1_600, 7);

        note(&mut t, &b, 1_000);
        note(&mut t, &orphan, 1_000);
        assert!(
            t.commit_established(shard(0), b.header()),
            "the round-contiguous orphan commits its parent",
        );
        assert!(!t.commit_established(shard(0), orphan.header()));
        assert!(
            t.committed_certificate(shard(0), b.header()).is_none(),
            "a child whose own commit is not established dates nothing",
        );

        // The committed chain's later blocks never establish the orphan.
        note(&mut t, &above, 1_000);
        assert!(!t.commit_established(shard(0), orphan.header()));
        assert!(t.committed_certificate(shard(0), b.header()).is_none());
        assert!(t.latest_crossing(shard(0)).is_none());

        // The committed child takes the slot, and its certificate stands.
        note(&mut t, &committed, 1_000);
        assert_eq!(
            t.committed_certificate(shard(0), b.header()),
            Some(committed.header().parent_qc()),
        );
        let crossing = t.latest_crossing(shard(0)).expect("crossing observed");
        assert_eq!(crossing.boundary_header().hash(), b.block_hash());
        assert_eq!(crossing.canonical_qc(), committed.header().parent_qc());

        // The orphan heard last takes the slot back and moves nothing.
        note(&mut t, &orphan, 1_000);
        assert_eq!(
            t.committed_certificate(shard(0), b.header()),
            Some(committed.header().parent_qc()),
        );
    }

    /// The committed child's own commit can rest on a later two-chain: a
    /// view change above it leaves no round-contiguous pair at its height.
    /// While an orphan holds the slot the later chain links to neither,
    /// and the block is dated by nothing; once the committed child is
    /// seated, the later pair establishes it.
    #[test]
    fn a_round_gap_above_the_committed_child_dates_no_crossing_by_the_orphan() {
        let mut t = ShardSourceTracker::new();
        let b = linked_header(shard(0), 2, 1, BlockHash::ZERO, 900, 7);
        let orphan = linked_header(shard(0), 3, 2, b.block_hash(), 1_400, 7);
        let committed = linked_header(shard(0), 3, 3, b.block_hash(), 1_500, 7);
        let gapped = linked_header(shard(0), 4, 5, committed.block_hash(), 1_600, 7);
        let pair = linked_header(shard(0), 5, 6, gapped.block_hash(), 1_700, 7);

        for header in [&b, &orphan, &gapped, &pair] {
            note(&mut t, header, 1_000);
        }
        assert!(t.commit_established(shard(0), b.header()));
        assert!(
            t.committed_certificate(shard(0), b.header()).is_none(),
            "the orphan in the slot dates nothing",
        );
        assert!(t.latest_crossing(shard(0)).is_none());

        note(&mut t, &committed, 1_000);
        assert!(t.commit_established(shard(0), committed.header()));
        let crossing = t.latest_crossing(shard(0)).expect("crossing observed");
        assert_eq!(crossing.boundary_header().hash(), b.block_hash());
        assert_eq!(
            crossing.canonical_qc().weighted_timestamp(),
            WeightedTimestamp::from_millis(1_500),
        );
    }

    /// A block the shard proved on this node's ask is committed, and so
    /// is whichever certified child the proof ran through; that child may
    /// be an orphan. The proven block's certificate is read from a child
    /// the shard proved in its own right, never from the block held above
    /// it.
    #[test]
    fn a_proven_boundary_takes_its_certificate_from_a_proven_child_alone() {
        let mut t = ShardSourceTracker::new();
        let b = linked_header(shard(0), 2, 1, BlockHash::ZERO, 900, 7);
        let orphan = linked_header(shard(0), 3, 2, b.block_hash(), 1_400, 7);
        let committed = linked_header(shard(0), 3, 3, b.block_hash(), 1_500, 7);
        let unrelated = linked_header(shard(0), 3, 4, BlockHash::ZERO, 1_450, 7);

        note(&mut t, &orphan, 1_000);
        t.admit_proven_boundary(Arc::clone(&b));
        assert!(t.commit_established(shard(0), b.header()));
        assert!(
            t.committed_certificate(shard(0), b.header()).is_none(),
            "the block held above a proven boundary dates nothing",
        );

        t.admit_proven_boundary(unrelated);
        assert!(t.committed_certificate(shard(0), b.header()).is_none());

        t.admit_proven_boundary(Arc::clone(&committed));
        assert_eq!(
            t.committed_certificate(shard(0), b.header()),
            Some(committed.header().parent_qc()),
        );
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
        let d = linked_header(shard(0), 4, 3, c.block_hash(), 1_600, 0);
        note(&mut t, &b, 1_000);
        note(&mut t, &c, 1_000);
        note(&mut t, &d, 1_000);
        // Push the boundary block out of the sliding header window.
        for height in 5..=(MAX_RETAINED_HEADERS_PER_SHARD as u64 + 4) {
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
