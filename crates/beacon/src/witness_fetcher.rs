//! Per-shard witness tracking for beacon proposals.
//!
//! Holds the per-shard verified headers a beacon proposer needs to
//! decide eligibility (which leaves are includable in epoch E) and
//! readiness (have all active shards crossed E's time boundary?), plus
//! the pool of verified witnesses ready for proposal inclusion.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_types::{
    BeaconWitnessLeafCount, BlockHash, BlockHeight, CertifiedBlockHeader, LeafIndex, ShardGroupId,
    ShardWitness, Verified, WeightedTimestamp,
};

/// Per-shard witness tracking.
///
/// Four internal maps:
///
/// - `shard_headers` — verified source-shard headers, one per
///   committed block, populated from every verified remote header
///   regardless of committee membership; needed by off-committee vnodes
///   to verify incoming `BeaconBlock`s' witness Merkle paths and used
///   as the verify context for inbound [`ShardWitness`]es.
/// - `pool` — verified witnesses ready for inclusion. Empty when the
///   local validator is off-committee. `drain_for_proposal` clones
///   eligible entries out without removing them; physical eviction
///   happens only when [`notify_consumed_advanced`](Self::notify_consumed_advanced)
///   advances past a leaf index. This keeps witnesses available for a
///   future proposal if the current epoch's block doesn't commit
///   (e.g. SPC fails to reach `OutputHigh`, or the epoch is skipped).
/// - `pending_in_proposal` — leaves the local proposer has drained
///   into a proposal but not yet seen committed. Mirrors the eviction
///   path of `pool`.
/// - `pending_fetches` — outstanding fetch dedup mapping each leaf to
///   the `(anchor_height, anchor_hash)` it was issued against, so
///   eviction can hand the matching ids to `FetchAbandon::ShardWitnesses`.
///   Empty when off-committee.
#[derive(Debug, Default)]
pub struct ShardWitnessFetchTracker {
    shard_headers:
        BTreeMap<ShardGroupId, BTreeMap<BlockHeight, Arc<Verified<CertifiedBlockHeader>>>>,
    pool: BTreeMap<ShardGroupId, BTreeMap<LeafIndex, Arc<Verified<ShardWitness>>>>,
    pending_in_proposal: BTreeMap<ShardGroupId, BTreeSet<LeafIndex>>,
    pending_fetches: BTreeMap<ShardGroupId, BTreeMap<LeafIndex, (BlockHeight, BlockHash)>>,
}

impl ShardWitnessFetchTracker {
    /// Empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a verified source-shard header. Called by the coordinator
    /// from `on_verified_remote_header` for every active shard (on- or
    /// off-committee).
    pub fn on_verified_remote_header(
        &mut self,
        certified_header: Arc<Verified<CertifiedBlockHeader>>,
    ) {
        let header = certified_header.header();
        let shard = header.shard_group_id();
        let height = header.height();
        self.shard_headers
            .entry(shard)
            .or_default()
            .insert(height, certified_header);
    }

    /// Admit a verified witness into the pool.
    pub fn admit_witness(&mut self, witness: Arc<Verified<ShardWitness>>) {
        let shard = witness.proof.shard_id;
        let leaf = witness.proof.leaf_index;
        self.pool.entry(shard).or_default().insert(leaf, witness);
        if let Some(map) = self.pending_fetches.get_mut(&shard) {
            map.remove(&leaf);
        }
    }

    /// Mark a `(shard, leaf_index)` fetch as in-flight against the
    /// `(anchor_height, anchor_hash)` it was issued against. Returns
    /// `true` if newly inserted, `false` if already tracked or already
    /// in the pool — the caller treats `false` as "don't redispatch."
    /// The anchor is retained so [`notify_consumed_advanced`] can
    /// surface the exact id tuple for `FetchAbandon::ShardWitnesses`.
    pub fn register_pending_fetch(
        &mut self,
        shard: ShardGroupId,
        leaf_index: LeafIndex,
        anchor_height: BlockHeight,
        anchor_hash: BlockHash,
    ) -> bool {
        let already_pooled = self
            .pool
            .get(&shard)
            .is_some_and(|m| m.contains_key(&leaf_index));
        if already_pooled {
            return false;
        }
        self.pending_fetches
            .entry(shard)
            .or_default()
            .insert(leaf_index, (anchor_height, anchor_hash))
            .is_none()
    }

    /// Drain witnesses eligible for inclusion in an epoch whose time
    /// window ends at `epoch_end_wt`. For each shard, takes leaves
    /// from the pool with `leaf_index` strictly greater than the
    /// shard's `consumed_through` watermark and `≤` the largest
    /// `beacon_witness_leaf_count` from any header whose
    /// `weighted_timestamp ≤ epoch_end_wt`.
    ///
    /// Mark-not-remove: returned `Arc`s are clones; the witnesses stay
    /// in the pool until [`notify_consumed_advanced`](Self::notify_consumed_advanced)
    /// evicts them after `consumed_through` advances on-chain. A second
    /// drain at the same watermark returns the same set — so a proposer
    /// whose block doesn't commit (e.g. SPC stall, epoch skipped) can
    /// re-propose the same witnesses without re-fetching from shards.
    /// Drained leaves are recorded in `pending_in_proposal`.
    pub fn drain_for_proposal(
        &mut self,
        epoch_end_wt: WeightedTimestamp,
        consumed_through: &BTreeMap<ShardGroupId, LeafIndex>,
    ) -> Vec<Arc<Verified<ShardWitness>>> {
        let mut out = Vec::new();
        for (shard, headers) in &self.shard_headers {
            let Some(max_eligible) = max_eligible_leaf_count(headers, epoch_end_wt) else {
                continue;
            };
            let watermark = consumed_through
                .get(shard)
                .copied()
                .unwrap_or(LeafIndex::new(0));
            let Some(pool_for_shard) = self.pool.get(shard) else {
                continue;
            };
            let drained: Vec<(LeafIndex, Arc<Verified<ShardWitness>>)> = pool_for_shard
                .range(..)
                .filter(|(idx, _)| {
                    idx.inner() > watermark.inner() && idx.inner() <= max_eligible.inner()
                })
                .map(|(idx, w)| (*idx, Arc::clone(w)))
                .collect();
            if drained.is_empty() {
                continue;
            }
            let pip_for_shard = self.pending_in_proposal.entry(*shard).or_default();
            for (idx, w) in drained {
                pip_for_shard.insert(idx);
                out.push(w);
            }
        }
        out
    }

    /// On-chain `consumed_through[shard]` has advanced to `new_watermark`.
    /// Evict pool, `pending_in_proposal`, and `pending_fetches` entries
    /// at-or-below the new watermark — witnesses past their consumed
    /// leaf are stale and can't appear in a future proposal.
    /// `O(log n + evicted)` via `BTreeMap::split_off`. Idempotent:
    /// calling with a non-advancing watermark is a no-op.
    ///
    /// Returns the evicted in-flight ids so the caller can hand them to
    /// `FetchAbandon::ShardWitnesses`. Empty when no fetch was pending
    /// at-or-below the new watermark.
    pub fn notify_consumed_advanced(
        &mut self,
        shard: ShardGroupId,
        new_watermark: LeafIndex,
    ) -> Vec<(ShardGroupId, BlockHeight, BlockHash, LeafIndex)> {
        let cutoff = LeafIndex::new(new_watermark.inner().saturating_add(1));
        if let Some(pool_for_shard) = self.pool.get_mut(&shard) {
            let above = pool_for_shard.split_off(&cutoff);
            *pool_for_shard = above;
        }
        if let Some(pip_for_shard) = self.pending_in_proposal.get_mut(&shard) {
            let above = pip_for_shard.split_off(&cutoff);
            *pip_for_shard = above;
        }
        let mut evicted = Vec::new();
        if let Some(pf_for_shard) = self.pending_fetches.get_mut(&shard) {
            let above = pf_for_shard.split_off(&cutoff);
            let stale = std::mem::replace(pf_for_shard, above);
            for (leaf, (height, hash)) in stale {
                evicted.push((shard, height, hash, leaf));
            }
        }
        evicted
    }

    /// Whether the local proposer can build an epoch's contribution:
    /// every shard in `active_shards` must have at least one observed
    /// header whose `weighted_timestamp` is strictly past
    /// `epoch_end_wt`, which proves no further headers from that shard
    /// can land inside the current epoch's window.
    #[must_use]
    pub fn is_ready_to_propose(
        &self,
        active_shards: &[ShardGroupId],
        epoch_end_wt: WeightedTimestamp,
    ) -> bool {
        active_shards.iter().all(|shard| {
            self.shard_headers.get(shard).is_some_and(|headers| {
                headers
                    .values()
                    .any(|h| h.qc().weighted_timestamp().as_millis() > epoch_end_wt.as_millis())
            })
        })
    }

    /// Called when the local validator is removed from the beacon
    /// committee. Drops the pool, pending-fetch, and in-proposal state;
    /// keeps `shard_headers` since the vnode still needs them to verify
    /// incoming `BeaconBlock`s.
    pub fn evicted_from_committee(&mut self) {
        self.pool.clear();
        self.pending_in_proposal.clear();
        self.pending_fetches.clear();
    }

    /// Look up the verified source-shard header by `committed_block_hash`.
    /// Linear scan over the shard's stored headers — bounded by the
    /// sliding window held in `shard_headers`.
    #[must_use]
    pub fn find_header_by_block_hash(
        &self,
        shard: ShardGroupId,
        block_hash: BlockHash,
    ) -> Option<&Arc<Verified<CertifiedBlockHeader>>> {
        self.shard_headers
            .get(&shard)?
            .values()
            .find(|h| h.block_hash() == block_hash)
    }
}

/// Largest `beacon_witness_leaf_count` from headers whose
/// `weighted_timestamp` is at or before `epoch_end_wt`. `None` if no
/// such header exists yet.
fn max_eligible_leaf_count(
    headers: &BTreeMap<BlockHeight, Arc<Verified<CertifiedBlockHeader>>>,
    epoch_end_wt: WeightedTimestamp,
) -> Option<BeaconWitnessLeafCount> {
    headers
        .values()
        .filter(|h| h.qc().weighted_timestamp().as_millis() <= epoch_end_wt.as_millis())
        .map(|h| h.header().beacon_witness_leaf_count())
        .max()
}

// Flat accessors; names are the documentation.
#[allow(missing_docs)]
impl ShardWitnessFetchTracker {
    #[must_use]
    pub fn header(
        &self,
        shard: ShardGroupId,
        height: BlockHeight,
    ) -> Option<&Arc<Verified<CertifiedBlockHeader>>> {
        self.shard_headers.get(&shard)?.get(&height)
    }

    #[must_use]
    pub fn pool_len(&self, shard: ShardGroupId) -> usize {
        self.pool.get(&shard).map_or(0, BTreeMap::len)
    }

    #[must_use]
    pub fn total_pool_len(&self) -> usize {
        self.pool.values().map(BTreeMap::len).sum()
    }

    #[must_use]
    pub fn pending_fetches_len(&self, shard: ShardGroupId) -> usize {
        self.pending_fetches.get(&shard).map_or(0, BTreeMap::len)
    }

    #[must_use]
    pub fn is_pending_fetch(&self, shard: ShardGroupId, leaf_index: LeafIndex) -> bool {
        self.pending_fetches
            .get(&shard)
            .is_some_and(|m| m.contains_key(&leaf_index))
    }

    #[must_use]
    pub fn pending_in_proposal_len(&self, shard: ShardGroupId) -> usize {
        self.pending_in_proposal
            .get(&shard)
            .map_or(0, BTreeSet::len)
    }

    #[must_use]
    pub fn is_pending_in_proposal(&self, shard: ShardGroupId, leaf_index: LeafIndex) -> bool {
        self.pending_in_proposal
            .get(&shard)
            .is_some_and(|s| s.contains(&leaf_index))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_types::{
        BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeader, BlockHeight, BoundedVec,
        CertificateRoot, CertifiedBlockHeader, Hash, InFlightCount, LeafIndex, LocalReceiptRoot,
        ProposerTimestamp, ProvisionsRoot, QuorumCertificate, Round, ShardGroupId, ShardWitness,
        ShardWitnessPayload, ShardWitnessProof, SignerBitfield, Stake, StakePoolId, StateRoot,
        TransactionRoot, ValidatorId, Verified, WeightedTimestamp, zero_bls_signature,
    };

    use super::*;

    fn shard(n: u64) -> ShardGroupId {
        ShardGroupId::new(n)
    }

    /// Build a verified `CertifiedBlockHeader` with the few fields the
    /// tracker reads — shard, height, `weighted_timestamp` (carried on
    /// the QC), witness root, leaf count.
    fn verified_header(
        s: ShardGroupId,
        height: u64,
        wt_millis: u64,
        leaf_count: u64,
    ) -> Arc<Verified<CertifiedBlockHeader>> {
        let parent_qc = QuorumCertificate::genesis(s);
        let parent_block_hash = BlockHash::ZERO;
        let header = BlockHeader::new(
            s,
            BlockHeight::new(height),
            parent_block_hash,
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
        );
        let block_hash = header.hash();
        let qc = QuorumCertificate::new(
            block_hash,
            s,
            BlockHeight::new(height),
            parent_block_hash,
            Round::INITIAL,
            SignerBitfield::new(4),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(wt_millis),
        );
        Arc::new(Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
            header, qc,
        )))
    }

    fn witness(s: ShardGroupId, leaf_index: u64) -> Arc<Verified<ShardWitness>> {
        Arc::new(Verified::new_unchecked_for_test(ShardWitness {
            payload: ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(0),
                amount: Stake::from_whole_tokens(1),
            },
            proof: ShardWitnessProof {
                shard_id: s,
                committed_block_hash: BlockHash::ZERO,
                leaf_index: LeafIndex::new(leaf_index),
                siblings: BoundedVec::new(),
            },
        }))
    }

    #[test]
    fn empty_after_new() {
        let t = ShardWitnessFetchTracker::new();
        assert!(t.header(shard(0), BlockHeight::new(0)).is_none());
        assert_eq!(t.pool_len(shard(0)), 0);
        assert_eq!(t.pending_fetches_len(shard(0)), 0);
    }

    #[test]
    fn on_verified_remote_header_inserts_header() {
        let mut t = ShardWitnessFetchTracker::new();
        t.on_verified_remote_header(verified_header(shard(0), 1, 1_000, 7));
        let h = t.header(shard(0), BlockHeight::new(1)).unwrap();
        assert_eq!(
            h.header().beacon_witness_leaf_count(),
            BeaconWitnessLeafCount::new(7),
        );
        assert_eq!(
            h.qc().weighted_timestamp(),
            WeightedTimestamp::from_millis(1_000),
        );
    }

    #[test]
    fn admit_witness_lands_in_pool_and_clears_pending_fetch() {
        let mut t = ShardWitnessFetchTracker::new();
        assert!(t.register_pending_fetch(
            shard(0),
            LeafIndex::new(3),
            BlockHeight::new(1),
            BlockHash::ZERO
        ));
        assert!(t.is_pending_fetch(shard(0), LeafIndex::new(3)));
        t.admit_witness(witness(shard(0), 3));
        assert_eq!(t.pool_len(shard(0)), 1);
        assert!(!t.is_pending_fetch(shard(0), LeafIndex::new(3)));
    }

    #[test]
    fn register_pending_fetch_is_idempotent() {
        let mut t = ShardWitnessFetchTracker::new();
        assert!(t.register_pending_fetch(
            shard(0),
            LeafIndex::new(3),
            BlockHeight::new(1),
            BlockHash::ZERO
        ));
        assert!(!t.register_pending_fetch(
            shard(0),
            LeafIndex::new(3),
            BlockHeight::new(1),
            BlockHash::ZERO
        ));
    }

    #[test]
    fn register_pending_fetch_rejects_when_already_pooled() {
        let mut t = ShardWitnessFetchTracker::new();
        t.admit_witness(witness(shard(0), 5));
        assert!(!t.register_pending_fetch(
            shard(0),
            LeafIndex::new(5),
            BlockHeight::new(1),
            BlockHash::ZERO,
        ));
    }

    #[test]
    fn drain_for_proposal_returns_witnesses_inside_wt_and_above_watermark() {
        let mut t = ShardWitnessFetchTracker::new();
        // One header at WT 1_000 with leaf_count 5 — leaves 1..=5 are
        // eligible for any epoch with t_end ≥ 1_000.
        t.on_verified_remote_header(verified_header(shard(0), 1, 1_000, 5));
        // Pool has leaves 2, 3, 4. consumed_through says we've already
        // consumed up to 2, so only 3 and 4 should drain.
        t.admit_witness(witness(shard(0), 2));
        t.admit_witness(witness(shard(0), 3));
        t.admit_witness(witness(shard(0), 4));
        let mut consumed = BTreeMap::new();
        consumed.insert(shard(0), LeafIndex::new(2));

        let drained = t.drain_for_proposal(WeightedTimestamp::from_millis(2_000), &consumed);
        let indices: Vec<u64> = drained.iter().map(|w| w.proof.leaf_index.inner()).collect();
        assert_eq!(indices, vec![3, 4]);
        // Mark-not-remove: all three leaves still resident; the two
        // drained ones are marked in pending_in_proposal.
        assert_eq!(t.pool_len(shard(0)), 3);
        assert_eq!(t.pending_in_proposal_len(shard(0)), 2);
        assert!(t.is_pending_in_proposal(shard(0), LeafIndex::new(3)));
        assert!(t.is_pending_in_proposal(shard(0), LeafIndex::new(4)));
    }

    /// A drained witness whose block doesn't commit is still in the
    /// pool, and a subsequent drain at the same watermark returns it
    /// again. This is the property that lets a proposer re-propose
    /// after an SPC stall or a skipped epoch without re-fetching from
    /// shards.
    #[test]
    fn drain_is_idempotent_when_watermark_unchanged() {
        let mut t = ShardWitnessFetchTracker::new();
        t.on_verified_remote_header(verified_header(shard(0), 1, 1_000, 5));
        t.admit_witness(witness(shard(0), 3));
        t.admit_witness(witness(shard(0), 4));
        let consumed = BTreeMap::new();

        let first = t.drain_for_proposal(WeightedTimestamp::from_millis(2_000), &consumed);
        let second = t.drain_for_proposal(WeightedTimestamp::from_millis(2_000), &consumed);
        let first_indices: Vec<u64> = first.iter().map(|w| w.proof.leaf_index.inner()).collect();
        let second_indices: Vec<u64> = second.iter().map(|w| w.proof.leaf_index.inner()).collect();
        assert_eq!(first_indices, vec![3, 4]);
        assert_eq!(second_indices, vec![3, 4]);
    }

    /// `notify_consumed_advanced(shard, w)` evicts pool entries with
    /// `leaf_index ≤ w` and retains those with `leaf_index > w`.
    #[test]
    fn notify_consumed_advanced_evicts_at_or_below_watermark() {
        let mut t = ShardWitnessFetchTracker::new();
        t.admit_witness(witness(shard(0), 1));
        t.admit_witness(witness(shard(0), 2));
        t.admit_witness(witness(shard(0), 3));
        t.admit_witness(witness(shard(0), 4));
        t.admit_witness(witness(shard(0), 5));

        t.notify_consumed_advanced(shard(0), LeafIndex::new(3));

        assert_eq!(t.pool_len(shard(0)), 2);
        assert!(
            t.pool
                .get(&shard(0))
                .unwrap()
                .contains_key(&LeafIndex::new(4))
        );
        assert!(
            t.pool
                .get(&shard(0))
                .unwrap()
                .contains_key(&LeafIndex::new(5))
        );
    }

    /// `notify_consumed_advanced` mirrors the eviction over
    /// `pending_in_proposal`: leaves at-or-below the watermark are
    /// dropped, leaves above are retained.
    #[test]
    fn notify_consumed_advanced_evicts_pending_in_proposal() {
        let mut t = ShardWitnessFetchTracker::new();
        t.on_verified_remote_header(verified_header(shard(0), 1, 1_000, 5));
        for leaf in 1..=5u64 {
            t.admit_witness(witness(shard(0), leaf));
        }
        let consumed = BTreeMap::new();
        let _ = t.drain_for_proposal(WeightedTimestamp::from_millis(2_000), &consumed);
        assert_eq!(t.pending_in_proposal_len(shard(0)), 5);

        t.notify_consumed_advanced(shard(0), LeafIndex::new(3));

        assert_eq!(t.pending_in_proposal_len(shard(0)), 2);
        assert!(t.is_pending_in_proposal(shard(0), LeafIndex::new(4)));
        assert!(t.is_pending_in_proposal(shard(0), LeafIndex::new(5)));
    }

    /// `notify_consumed_advanced` with a non-advancing watermark is a
    /// no-op — calling it repeatedly across blocks that don't advance
    /// `consumed_through` for this shard doesn't disturb the pool.
    #[test]
    fn notify_consumed_advanced_is_idempotent() {
        let mut t = ShardWitnessFetchTracker::new();
        t.admit_witness(witness(shard(0), 4));
        t.admit_witness(witness(shard(0), 5));

        t.notify_consumed_advanced(shard(0), LeafIndex::new(3));
        t.notify_consumed_advanced(shard(0), LeafIndex::new(3));
        assert_eq!(t.pool_len(shard(0)), 2);
    }

    #[test]
    fn drain_excludes_leaves_above_wt_eligible_count() {
        let mut t = ShardWitnessFetchTracker::new();
        t.on_verified_remote_header(verified_header(shard(0), 1, 1_000, 3));
        // Pool has leaf 5 which is above the WT-eligible count of 3.
        t.admit_witness(witness(shard(0), 5));
        let consumed = BTreeMap::new();
        let drained = t.drain_for_proposal(WeightedTimestamp::from_millis(2_000), &consumed);
        assert!(drained.is_empty());
        assert_eq!(t.pool_len(shard(0)), 1);
    }

    #[test]
    fn drain_with_no_headers_for_shard_returns_nothing() {
        let mut t = ShardWitnessFetchTracker::new();
        t.admit_witness(witness(shard(0), 1));
        let consumed = BTreeMap::new();
        let drained = t.drain_for_proposal(WeightedTimestamp::from_millis(2_000), &consumed);
        assert!(drained.is_empty());
    }

    #[test]
    fn is_ready_to_propose_true_when_all_shards_crossed() {
        let mut t = ShardWitnessFetchTracker::new();
        // Both shards have observed a header past t_end = 1_000.
        t.on_verified_remote_header(verified_header(shard(0), 1, 1_500, 0));
        t.on_verified_remote_header(verified_header(shard(1), 1, 2_000, 0));
        assert!(
            t.is_ready_to_propose(&[shard(0), shard(1)], WeightedTimestamp::from_millis(1_000),)
        );
    }

    #[test]
    fn is_ready_to_propose_false_when_a_shard_hasnt_crossed() {
        let mut t = ShardWitnessFetchTracker::new();
        t.on_verified_remote_header(verified_header(shard(0), 1, 1_500, 0));
        // shard(1) only has a header at WT 500 — not past t_end = 1_000.
        t.on_verified_remote_header(verified_header(shard(1), 1, 500, 0));
        assert!(
            !t.is_ready_to_propose(&[shard(0), shard(1)], WeightedTimestamp::from_millis(1_000),)
        );
    }

    #[test]
    fn is_ready_to_propose_false_when_shard_has_no_headers() {
        let t = ShardWitnessFetchTracker::new();
        assert!(!t.is_ready_to_propose(&[shard(0)], WeightedTimestamp::from_millis(1_000),));
    }

    #[test]
    fn evicted_from_committee_clears_pool_and_pending_keeps_headers() {
        let mut t = ShardWitnessFetchTracker::new();
        t.on_verified_remote_header(verified_header(shard(0), 1, 1_000, 5));
        t.admit_witness(witness(shard(0), 3));
        t.register_pending_fetch(
            shard(0),
            LeafIndex::new(4),
            BlockHeight::new(1),
            BlockHash::ZERO,
        );
        let consumed = BTreeMap::new();
        let _ = t.drain_for_proposal(WeightedTimestamp::from_millis(2_000), &consumed);
        assert_eq!(t.pending_in_proposal_len(shard(0)), 1);

        t.evicted_from_committee();

        assert_eq!(t.pool_len(shard(0)), 0);
        assert_eq!(t.pending_fetches_len(shard(0)), 0);
        assert_eq!(t.pending_in_proposal_len(shard(0)), 0);
        assert!(t.header(shard(0), BlockHeight::new(1)).is_some());
    }
}
