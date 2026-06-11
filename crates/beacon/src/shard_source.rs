//! Per-shard source tracking for beacon proposals.
//!
//! Holds the beacon's verified view of each source shard, everything a
//! proposer draws on to build a `BeaconProposal` and an epoch's
//! `shard_contributions`:
//!
//! - recent verified headers — the verify context for inbound
//!   `BeaconBlock`s and `ShardWitness`es and the input to crossing
//!   detection;
//! - observed epoch-boundary crossings — the per-shard anchors the
//!   proposer reports in `boundary_qcs`;
//! - per-anchor witness chunks — verified witnesses for a boundary
//!   block's accumulator range, keyed by the boundary block they prove
//!   against (the accumulator is append-only, so a leaf's merkle path is
//!   root-specific — a witness only counts toward the boundary block it
//!   was fetched against).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_types::{
    BlockHash, BlockHeader, BlockHeight, CertifiedBlockHeader, Epoch, LeafIndex, QuorumCertificate,
    ShardId, ShardWitness, Verified,
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
/// `boundary_header` is the first committed block `B` whose weighted
/// timestamp lands past the boundary; `canonical_qc` is the QC over `B`
/// read from `B`'s committed child (`C.parent_qc`) — hash-pinned, so every
/// node that observes the crossing selects the identical QC. Recorded when
/// the `(B, C)` pair is fresh near the shard tip, so it survives header
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

/// A boundary block's verified witness chunk, keyed by leaf index. A
/// witness proves against one block's `beacon_witness_root`, so each chunk
/// is scoped to a single `(shard, anchor block hash)`.
type AnchorChunk = BTreeMap<LeafIndex, Arc<Verified<ShardWitness>>>;

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
/// - `witness_chunks` — verified witnesses keyed by their anchor boundary
///   block `(shard, block_hash)` then leaf index. A witness proves against
///   one block's `beacon_witness_root`, so it counts only toward that
///   boundary. Empty when the local validator is off-committee.
/// - `pending_fetches` — outstanding witness-fetch dedup per anchor.
#[derive(Debug, Default)]
pub struct ShardSourceTracker {
    shard_headers: BTreeMap<ShardId, BTreeMap<BlockHeight, Arc<Verified<CertifiedBlockHeader>>>>,
    boundary_crossings: BTreeMap<ShardId, BTreeMap<Epoch, ObservedCrossing>>,
    witness_chunks: BTreeMap<(ShardId, BlockHash), AnchorChunk>,
    pending_fetches: BTreeMap<(ShardId, BlockHash), PendingFetch>,
}

/// An anchor's outstanding witness fetch. Carries the boundary block
/// `height` alongside the in-flight `leaves` so an eviction can name each
/// cancelled leaf as the `(shard, height, block_hash, leaf)` id the
/// runner's `FetchAbandon::ShardWitnesses` handler matches against.
#[derive(Debug)]
struct PendingFetch {
    height: BlockHeight,
    leaves: BTreeSet<LeafIndex>,
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
    /// local shard from its own commit stream.
    pub fn on_verified_source_header(
        &mut self,
        certified_header: Arc<Verified<CertifiedBlockHeader>>,
    ) {
        let header = certified_header.header();
        let shard = header.shard_id();
        let height = header.height();
        self.shard_headers
            .entry(shard)
            .or_default()
            .insert(height, certified_header);
    }

    /// Admit a verified witness into the chunk for its anchor boundary
    /// block (`witness.proof.committed_block_hash`). Clears the matching
    /// pending-fetch entry.
    pub fn admit_witness(&mut self, witness: Arc<Verified<ShardWitness>>) {
        let shard = witness.proof.shard_id;
        let anchor = witness.proof.committed_block_hash;
        let leaf = witness.proof.leaf_index;
        self.witness_chunks
            .entry((shard, anchor))
            .or_default()
            .insert(leaf, witness);
        if let Some(pending) = self.pending_fetches.get_mut(&(shard, anchor)) {
            pending.leaves.remove(&leaf);
        }
    }

    /// Mark a `(shard, anchor, leaf)` witness fetch in flight against the
    /// boundary block at `block_height`. Returns `true` if newly inserted,
    /// `false` if already pooled or already tracked — the caller treats
    /// `false` as "don't redispatch." The height is retained so a later
    /// eviction can hand the runner the exact in-flight fetch id to cancel.
    pub fn register_pending_fetch(
        &mut self,
        shard: ShardId,
        block_height: BlockHeight,
        anchor: BlockHash,
        leaf: LeafIndex,
    ) -> bool {
        let already_pooled = self
            .witness_chunks
            .get(&(shard, anchor))
            .is_some_and(|m| m.contains_key(&leaf));
        if already_pooled {
            return false;
        }
        self.pending_fetches
            .entry((shard, anchor))
            .or_insert_with(|| PendingFetch {
                height: block_height,
                leaves: BTreeSet::new(),
            })
            .leaves
            .insert(leaf)
    }

    /// Whether every leaf of the chunk `[prior, chunk_end)` anchored to
    /// `anchor` is held — the presence check behind the proposer's
    /// witness-availability coupling, without cloning the payloads. An
    /// empty range is trivially held.
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
        let Some(map) = self.witness_chunks.get(&(shard, anchor)) else {
            return false;
        };
        (prior..chunk_end).all(|leaf| map.contains_key(&LeafIndex::new(leaf)))
    }

    /// The contiguous witness chunk `[prior, chunk_end)` anchored to
    /// `anchor`, in leaf-index order, or `None` if any leaf in the range
    /// isn't held yet (the assembler defers). An empty range
    /// (`chunk_end <= prior`) returns an empty vec.
    #[must_use]
    pub fn witness_chunk(
        &self,
        shard: ShardId,
        anchor: BlockHash,
        prior: u64,
        chunk_end: u64,
    ) -> Option<Vec<ShardWitness>> {
        if chunk_end <= prior {
            return Some(Vec::new());
        }
        let map = self.witness_chunks.get(&(shard, anchor))?;
        let mut out = Vec::with_capacity(usize::try_from(chunk_end - prior).unwrap_or(0));
        for leaf in prior..chunk_end {
            let witness = map.get(&LeafIndex::new(leaf))?;
            out.push(witness.as_ref().as_ref().clone());
        }
        Some(out)
    }

    /// Drop witnesses and pending fetches for `shard` below the applied
    /// watermark `consumed` (leaf index `< consumed`), across every
    /// anchor. Called from the coordinator's `adopt_block` once a
    /// boundary fold advances `boundaries[shard].witness_leaf_count`.
    /// Empty per-anchor maps are removed.
    ///
    /// Returns the in-flight fetch ids that were dropped, so the caller can
    /// cancel them via `FetchAbandon::ShardWitnesses` — the witness is now
    /// consumed on-chain and a future contribution can't include it, so the
    /// runner's in-flight slot should release rather than pin on a payload
    /// the tracker would only evict on arrival.
    pub fn evict_consumed(
        &mut self,
        shard: ShardId,
        consumed: u64,
    ) -> Vec<(ShardId, BlockHeight, BlockHash, LeafIndex)> {
        self.witness_chunks.retain(|(s, _), leaves| {
            if *s == shard {
                leaves.retain(|leaf, _| leaf.inner() >= consumed);
                !leaves.is_empty()
            } else {
                true
            }
        });
        let mut abandoned = Vec::new();
        self.pending_fetches.retain(|(s, anchor), pending| {
            if *s != shard {
                return true;
            }
            pending.leaves.retain(|leaf| {
                if leaf.inner() < consumed {
                    abandoned.push((*s, pending.height, *anchor, *leaf));
                    false
                } else {
                    true
                }
            });
            !pending.leaves.is_empty()
        });
        abandoned
    }

    /// Bound `shard_headers` to a sliding window of the most recent
    /// [`MAX_RETAINED_HEADERS_PER_SHARD`] heights per shard. Boundary
    /// block headers needed past the window are retained on their
    /// [`ObservedCrossing`]. Called from `adopt_block`.
    pub fn prune_stale_headers(&mut self) {
        for headers in self.shard_headers.values_mut() {
            while headers.len() > MAX_RETAINED_HEADERS_PER_SHARD {
                let Some(oldest) = headers.keys().next().copied() else {
                    break;
                };
                headers.remove(&oldest);
            }
        }
    }

    /// Record any epoch-boundary crossing made visible by the verified
    /// header just inserted at `(shard, height)`. The inserted header can
    /// be the child `C` of an earlier `B`, or the parent `B` of a `C` that
    /// arrived first, so both consecutive pairs are checked. A detected
    /// crossing is stored keyed by the crossed epoch and retained past
    /// header pruning (bounded by [`MAX_RETAINED_CROSSINGS_PER_SHARD`]),
    /// so the proposer can report it well after `(B, C)` leave the window.
    pub fn observe_crossing(
        &mut self,
        shard: ShardId,
        height: BlockHeight,
        epoch_duration_ms: u64,
    ) {
        let found: Vec<(Epoch, ObservedCrossing)> = {
            let Some(headers) = self.shard_headers.get(&shard) else {
                return;
            };
            let prev = height.inner().checked_sub(1).map(BlockHeight::new);
            [(prev, height), (Some(height), height.next())]
                .into_iter()
                .filter_map(|(b_height, c_height)| {
                    let b = headers.get(&b_height?)?;
                    let c = headers.get(&c_height)?;
                    detect_crossing(b, c, epoch_duration_ms)
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

    /// Called by the coordinator when a commit rotates the local
    /// validator off the beacon committee. Drops witness chunks and
    /// pending fetches — off-committee vnodes neither propose nor fetch —
    /// but keeps `shard_headers` since the vnode still needs them to
    /// verify incoming `BeaconBlock`s.
    ///
    /// Returns the in-flight fetch ids that were dropped, so the caller
    /// can cancel them via `FetchAbandon::ShardWitnesses` — same contract
    /// as [`Self::evict_consumed`], keeping the runner's fetch slots from
    /// pinning on payloads no longer wanted.
    pub fn evicted_from_committee(&mut self) -> Vec<(ShardId, BlockHeight, BlockHash, LeafIndex)> {
        self.witness_chunks.clear();
        let mut abandoned = Vec::new();
        for ((shard, anchor), pending) in std::mem::take(&mut self.pending_fetches) {
            for leaf in pending.leaves {
                abandoned.push((shard, pending.height, anchor, leaf));
            }
        }
        abandoned
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
    epoch_duration_ms: u64,
) -> Option<(Epoch, ObservedCrossing)> {
    if epoch_duration_ms == 0 {
        return None;
    }
    let canonical_qc = c.header().parent_qc();
    if canonical_qc.block_hash() != b.block_hash() {
        return None;
    }
    let b_wt = canonical_qc.weighted_timestamp().as_millis();
    let b_pred_wt = b.header().parent_qc().weighted_timestamp().as_millis();
    // The largest epoch boundary strictly below `b`'s weighted timestamp.
    let k = b_wt.checked_sub(1)? / epoch_duration_ms;
    if k == 0 {
        return None;
    }
    let cut = k * epoch_duration_ms;
    (b_pred_wt <= cut).then(|| {
        (
            Epoch::new(k),
            ObservedCrossing {
                boundary_header: Arc::clone(b),
                canonical_qc: canonical_qc.clone(),
            },
        )
    })
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
            .map_or(0, BTreeMap::len)
    }

    #[must_use]
    pub fn total_chunk_len(&self) -> usize {
        self.witness_chunks.values().map(BTreeMap::len).sum()
    }

    #[must_use]
    pub fn is_pending_fetch(&self, shard: ShardId, anchor: BlockHash, leaf: LeafIndex) -> bool {
        self.pending_fetches
            .get(&(shard, anchor))
            .is_some_and(|pending| pending.leaves.contains(&leaf))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_types::{
        BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeader, BlockHeight, BoundedVec,
        CertificateRoot, CertifiedBlockHeader, Hash, InFlightCount, LeafIndex, LocalReceiptRoot,
        ProposerTimestamp, ProvisionsRoot, QuorumCertificate, Round, ShardId, ShardWitness,
        ShardWitnessPayload, ShardWitnessProof, SignerBitfield, Stake, StakePoolId, StateRoot,
        TransactionRoot, ValidatorId, Verified, WeightedTimestamp, zero_bls_signature,
    };

    use super::*;

    fn shard(n: u64) -> ShardId {
        ShardId::leaf(1, n)
    }

    /// Build a verified header that links to its parent: its `parent_qc`
    /// names `parent_hash` and carries `parent_wt` (the parent's canonical
    /// weighted timestamp). Chaining two of these lets `detect_crossing`
    /// recognise a real `(B, C)` parent/child pair.
    fn linked_header(
        s: ShardId,
        height: u64,
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
            zero_bls_signature(),
            WeightedTimestamp::from_millis(parent_wt),
        );
        let header = BlockHeader::new(
            s,
            BlockHeight::new(height),
            parent_hash,
            parent_qc,
            ValidatorId::new(0),
            ProposerTimestamp::ZERO,
            Round::INITIAL,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::from_raw(Hash::from_bytes(format!("r-{s:?}-{height}").as_bytes())),
            BeaconWitnessLeafCount::new(leaf_count),
            BeaconWitnessLeafCount::ZERO,
        );
        let block_hash = header.hash();
        let qc = QuorumCertificate::new(
            block_hash,
            s,
            BlockHeight::new(height),
            parent_hash,
            Round::INITIAL,
            SignerBitfield::new(4),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(parent_wt),
        );
        Arc::new(Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
            header, qc,
        )))
    }

    /// Record a verified header and detect any crossing it completes.
    fn note(t: &mut ShardSourceTracker, h: &Arc<Verified<CertifiedBlockHeader>>, dur: u64) {
        t.on_verified_source_header(Arc::clone(h));
        t.observe_crossing(h.header().shard_id(), h.header().height(), dur);
    }

    fn witness(s: ShardId, anchor: BlockHash, leaf: u64) -> Arc<Verified<ShardWitness>> {
        Arc::new(Verified::new_unchecked_for_test(ShardWitness {
            payload: ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(0),
                amount: Stake::from_whole_tokens(1),
            },
            proof: ShardWitnessProof {
                shard_id: s,
                committed_block_hash: anchor,
                leaf_index: LeafIndex::new(leaf),
                siblings: BoundedVec::new(),
            },
        }))
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
    fn admit_witness_lands_in_chunk_and_clears_pending() {
        let mut t = ShardSourceTracker::new();
        assert!(t.register_pending_fetch(
            shard(0),
            BlockHeight::new(5),
            anchor(1),
            LeafIndex::new(3)
        ));
        assert!(t.is_pending_fetch(shard(0), anchor(1), LeafIndex::new(3)));
        t.admit_witness(witness(shard(0), anchor(1), 3));
        assert_eq!(t.chunk_len(shard(0), anchor(1)), 1);
        assert!(!t.is_pending_fetch(shard(0), anchor(1), LeafIndex::new(3)));
    }

    #[test]
    fn register_pending_fetch_is_idempotent_and_rejects_when_pooled() {
        let mut t = ShardSourceTracker::new();
        assert!(t.register_pending_fetch(
            shard(0),
            BlockHeight::new(5),
            anchor(1),
            LeafIndex::new(3)
        ));
        assert!(!t.register_pending_fetch(
            shard(0),
            BlockHeight::new(5),
            anchor(1),
            LeafIndex::new(3)
        ));
        t.admit_witness(witness(shard(0), anchor(1), 5));
        assert!(!t.register_pending_fetch(
            shard(0),
            BlockHeight::new(5),
            anchor(1),
            LeafIndex::new(5)
        ));
    }

    #[test]
    fn witness_chunk_returns_contiguous_range_or_none_on_gap() {
        let mut t = ShardSourceTracker::new();
        // Empty range is trivially available.
        assert_eq!(
            t.witness_chunk(shard(0), anchor(1), 4, 4).map(|c| c.len()),
            Some(0),
        );
        // Seat leaves 4 and 5 (the chunk [4, 6)).
        t.admit_witness(witness(shard(0), anchor(1), 4));
        t.admit_witness(witness(shard(0), anchor(1), 5));
        let chunk = t
            .witness_chunk(shard(0), anchor(1), 4, 6)
            .expect("chunk present");
        let indices: Vec<u64> = chunk.iter().map(|w| w.proof.leaf_index.inner()).collect();
        assert_eq!(indices, vec![4, 5]);
        // A gap (leaf 6 missing) defers.
        assert!(t.witness_chunk(shard(0), anchor(1), 4, 7).is_none());
        // The wrong anchor has nothing.
        assert!(t.witness_chunk(shard(0), anchor(2), 4, 6).is_none());
    }

    #[test]
    fn evict_consumed_drops_below_watermark() {
        let mut t = ShardSourceTracker::new();
        for leaf in 0..5u64 {
            t.admit_witness(witness(shard(0), anchor(1), leaf));
        }
        t.evict_consumed(shard(0), 3);
        // Leaves 0..3 dropped; 3, 4 remain.
        assert_eq!(t.chunk_len(shard(0), anchor(1)), 2);
        assert!(t.witness_chunk(shard(0), anchor(1), 3, 5).is_some());
        assert!(t.witness_chunk(shard(0), anchor(1), 0, 5).is_none());
    }

    #[test]
    fn evict_consumed_removes_emptied_anchor() {
        let mut t = ShardSourceTracker::new();
        t.admit_witness(witness(shard(0), anchor(1), 0));
        t.evict_consumed(shard(0), 1);
        assert_eq!(t.total_chunk_len(), 0);
    }

    /// Eviction hands back the in-flight fetches it dropped — full
    /// `(shard, height, anchor, leaf)` ids — so the coordinator can cancel
    /// them via `FetchAbandon::ShardWitnesses`. Leaves at or above the
    /// watermark stay in flight.
    #[test]
    fn evict_consumed_returns_abandoned_in_flight_fetches() {
        let mut t = ShardSourceTracker::new();
        let height = BlockHeight::new(5);
        let a = anchor(1);
        for leaf in 0..3u64 {
            t.register_pending_fetch(shard(0), height, a, LeafIndex::new(leaf));
        }
        let abandoned = t.evict_consumed(shard(0), 2);
        assert_eq!(
            abandoned,
            vec![
                (shard(0), height, a, LeafIndex::new(0)),
                (shard(0), height, a, LeafIndex::new(1)),
            ],
        );
        assert!(t.is_pending_fetch(shard(0), a, LeafIndex::new(2)));
        assert!(!t.is_pending_fetch(shard(0), a, LeafIndex::new(0)));
    }

    /// A `(B, C)` parent/child pair straddling an epoch boundary records a
    /// crossing: `B` at predecessor-wt 900 (≤ the 1000 boundary) and own
    /// canonical wt 1500 (read from `C.parent_qc`, past 1000) is the first
    /// block across epoch 1.
    #[test]
    fn observe_crossing_records_first_block_across_boundary() {
        let mut t = ShardSourceTracker::new();
        let b = linked_header(shard(0), 2, BlockHash::ZERO, 900, 7);
        let c = linked_header(shard(0), 3, b.block_hash(), 1_500, 7);
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

    /// A pair wholly inside one epoch (predecessor 1200 and own wt 1500,
    /// both past the 1000 boundary) is not a crossing.
    #[test]
    fn observe_crossing_ignores_within_epoch_pair() {
        let mut t = ShardSourceTracker::new();
        let b = linked_header(shard(0), 2, BlockHash::ZERO, 1_200, 0);
        let c = linked_header(shard(0), 3, b.block_hash(), 1_500, 0);
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
        let b = linked_header(shard(0), 2, BlockHash::ZERO, 900, 0);
        let c = linked_header(shard(0), 3, b.block_hash(), 1_500, 0);
        note(&mut t, &b, 1_000);
        note(&mut t, &c, 1_000);
        // Push the boundary block out of the sliding header window.
        for height in 4..=(MAX_RETAINED_HEADERS_PER_SHARD as u64 + 4) {
            t.on_verified_source_header(linked_header(shard(0), height, BlockHash::ZERO, 1_600, 0));
        }
        t.prune_stale_headers();
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
    fn prune_stale_headers_bounds_the_window() {
        let mut t = ShardSourceTracker::new();
        for height in 1..=(MAX_RETAINED_HEADERS_PER_SHARD as u64 + 3) {
            t.on_verified_source_header(linked_header(shard(0), height, BlockHash::ZERO, 0, 0));
        }
        t.prune_stale_headers();
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
        t.on_verified_source_header(linked_header(shard(0), 1, BlockHash::ZERO, 0, 0));
        t.admit_witness(witness(shard(0), anchor(1), 0));
        t.register_pending_fetch(shard(0), BlockHeight::new(5), anchor(1), LeafIndex::new(1));
        let abandoned = t.evicted_from_committee();
        assert_eq!(t.total_chunk_len(), 0);
        assert!(!t.is_pending_fetch(shard(0), anchor(1), LeafIndex::new(1)));
        assert!(t.header(shard(0), BlockHeight::new(1)).is_some());
        // The in-flight fetch comes back as a cancellable id.
        assert_eq!(
            abandoned,
            vec![(shard(0), BlockHeight::new(5), anchor(1), LeafIndex::new(1))],
        );
    }
}
