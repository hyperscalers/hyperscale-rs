//! Provision verification pipeline.
//!
//! Owns the lifecycle from raw provisions arrival through to verified
//! storage:
//!
//! - **Pending**: provisions buffered while their paired remote header
//!   is still in flight, keyed by `(source_shard, block_height)` — the
//!   join point with the header is `(shard, height)`, the only identity
//!   known before merkle-proof verification produces a content hash.
//! - **Verified**: provisions that have passed merkle proof
//!   verification, keyed by [`ProvisionHash`] so distinct batches at
//!   the same source `(shard, height)` (different proposal rounds,
//!   only one of which ultimately commits) each get their own slot.
//! - **Store**: shared content-addressed map serving both this pipeline's
//!   inbound writes and the io-loop's `local_provision.request` handler.
//!
//! The deadline sweep evicts any artefact whose source block has aged
//! past `RETENTION_HORIZON` — past that, every tx in the provisions has
//! expired its `validity_range` and no shard can still need the data.
//!
//! No topology, no time source. Inputs are `WeightedTimestamp` and the
//! coordinator decides when to call each method.

use std::collections::HashMap;
use std::sync::Arc;

use hyperscale_types::{
    BlockHeight, MAX_TXS_PER_BLOCK, ProvisionHash, Provisions, ShardId, Verified, WeightedTimestamp,
};

use crate::store::ProvisionStore;

type Key = (ShardId, BlockHeight);

/// Hard ceiling on provision entries buffered across every pending key —
/// the count cap a single-signer holding class takes (see
/// [`hyperscale_types::verifiable`]).
///
/// A pending bundle is committee-gated at ingress but its merkle proof is
/// not checked until the paired header arrives, and the source block height
/// it names is the sender's own — so one Byzantine member of any source
/// shard can mint distinct `(shard, height)` keys and fill each with a
/// block's worth of entries, held until the deadline sweep a whole
/// `RETENTION_HORIZON` out. The bound is on entries rather than keys or
/// bundles because entries are what carries the bytes.
///
/// Sized at a block's worth per legitimately in-flight source header, with
/// room for several proposal rounds each: honest buffering only spans the
/// headers a shard has not yet verified, which is normally none. Past the
/// ceiling new bundles are dropped, and a drop is recoverable — the
/// expectation tracker fetches what a commit-proven header says it is owed,
/// which is the path a bundle that never arrived takes anyway.
pub const MAX_PENDING_PROVISION_ENTRIES: usize = 64 * MAX_TXS_PER_BLOCK;

/// Outputs of one deadline sweep — partitioned so the coordinator can
/// prune header buffers from one half and emit fetch cancellations from
/// the other without the call site re-deriving them.
pub struct DeadlineSweep {
    /// `(source_shard, source_block_height)` keys whose verified entries
    /// evicted. Header buffers keyed by `(shard, height)` are pruned here.
    pub evicted_keys: Vec<Key>,
    /// Content hashes of pending entries dropped before verification.
    /// The coordinator emits an `AbandonFetch::LocalProvisions` for each
    /// so any pinned local-DA fetch releases its slot.
    pub evicted_pending: Vec<ProvisionHash>,
}

/// Verified provisions held in `verified`, paired with their source
/// block's `weighted_timestamp` for deadline-anchored eviction.
#[derive(Debug, Clone)]
struct VerifiedProvision {
    provisions: Arc<Verified<Provisions>>,
    source_block_ts: WeightedTimestamp,
}

/// Provisions buffered while waiting for their matching verified remote
/// header. `received_at` is the local committed `WeightedTimestamp` at
/// receipt — provably ≥ the source block's true ts, so the deadline sweep
/// only drops entries whose true deadline has passed.
#[derive(Debug, Clone)]
struct PendingProvision {
    provisions: Provisions,
    received_at: WeightedTimestamp,
}

/// Pending → verified → store lifecycle for inbound provisions.
///
/// `pending` is keyed by `(source_shard, source_block_height)` because
/// that's the join point with the verified remote header — the only
/// identifier known before merkle-proof verification produces a
/// content hash.
///
/// `verified` is keyed by [`ProvisionHash`] because a single source
/// `(shard, height)` can produce **multiple** distinct provisions
/// batches across proposal rounds — each round attempts its own tx
/// selection at the same height, only one eventually commits, but
/// validators see and verify every round's batch in flight. Keying
/// `verified` by `(shard, height)` would collapse them onto a single
/// slot and let the `has_verified` short-circuit drop the
/// actually-committed batch when a fetch later retrieves it.
pub struct ProvisionPipeline {
    pending: HashMap<Key, Vec<PendingProvision>>,
    /// Running total of provision entries across every `pending` entry,
    /// kept in step with it so the [`MAX_PENDING_PROVISION_ENTRIES`] cap is
    /// an O(1) check. Every path that drops a pending bundle subtracts what
    /// it dropped.
    pending_entries: usize,
    verified: HashMap<ProvisionHash, VerifiedProvision>,
    store: Arc<ProvisionStore>,
}

impl ProvisionPipeline {
    pub(crate) fn new(store: Arc<ProvisionStore>) -> Self {
        Self {
            pending: HashMap::new(),
            pending_entries: 0,
            verified: HashMap::new(),
            store,
        }
    }

    /// Have these specific verified provisions been recorded already?
    /// Keyed by content hash so a later proposal round at the same
    /// `(shard, height)` is not falsely treated as a duplicate.
    pub(crate) fn has_verified(&self, hash: &ProvisionHash) -> bool {
        self.verified.contains_key(hash)
    }

    /// Buffer provisions awaiting their paired remote header.
    ///
    /// Returns `false` if the bundle was dropped because the buffer is at
    /// [`MAX_PENDING_PROVISION_ENTRIES`] capacity.
    pub(crate) fn buffer_pending(
        &mut self,
        key: Key,
        provisions: Provisions,
        received_at: WeightedTimestamp,
    ) -> bool {
        let entries = provisions.transactions().len();
        if self.pending_entries.saturating_add(entries) > MAX_PENDING_PROVISION_ENTRIES {
            tracing::debug!(
                source_shard = key.0.inner(),
                block_height = key.1.inner(),
                buffered = self.pending_entries,
                entries,
                "Pending provision buffer at capacity — dropping bundle"
            );
            return false;
        }
        self.pending.entry(key).or_default().push(PendingProvision {
            provisions,
            received_at,
        });
        self.pending_entries += entries;
        true
    }

    /// Drain every provisions entry buffered for `key`. The coordinator
    /// calls this when the matching header arrives; each drained entry is
    /// then run through merkle proof verification.
    pub(crate) fn drain_pending_for_key(&mut self, key: Key) -> Vec<Provisions> {
        self.pending
            .remove(&key)
            .map(|entries| {
                for p in &entries {
                    self.pending_entries -= p.provisions.transactions().len();
                }
                entries.into_iter().map(|p| p.provisions).collect()
            })
            .unwrap_or_default()
    }

    /// Drop parked bundles keyed to `shard` strictly above a pending
    /// recovery's attested frontier — they can never verify — returning
    /// their hashes so in-flight local-DA fetches can be abandoned.
    pub(crate) fn purge_fenced(
        &mut self,
        shard: ShardId,
        frontier: BlockHeight,
    ) -> Vec<ProvisionHash> {
        let mut evicted = Vec::new();
        let pending_entries = &mut self.pending_entries;
        self.pending.retain(|&(s, h), entries| {
            if s != shard || h <= frontier {
                return true;
            }
            for p in entries.iter() {
                *pending_entries -= p.provisions.transactions().len();
            }
            evicted.extend(entries.iter().map(|p| p.provisions.hash()));
            false
        });
        evicted
    }

    /// Insert verified provisions into the pipeline + store. Returns the
    /// verified `Arc` the coordinator hands downstream (queue + `ProvisionsAdmitted`
    /// emit). Idempotent if the same content hash is inserted twice.
    ///
    /// The shared [`ProvisionStore`] holds raw `Arc<Provisions>` because the
    /// network worker thread reads it to serve wire bodies; the body clone
    /// at the seam keeps every wire read clone-free at the cost of one
    /// allocation per verified batch.
    pub(crate) fn insert_verified(
        &mut self,
        verified: Arc<Verified<Provisions>>,
        source_block_ts: WeightedTimestamp,
    ) -> Arc<Verified<Provisions>> {
        let hash = verified.hash();
        self.store.insert(Arc::new((**verified).clone()));
        self.verified.insert(
            hash,
            VerifiedProvision {
                provisions: Arc::clone(&verified),
                source_block_ts,
            },
        );
        verified
    }

    /// Drop verified and pending entries whose deadline has passed `now`.
    ///
    /// Returns:
    /// - `evicted_keys` — `(source_shard, source_block_height)` keys whose
    ///   verified entries evicted, so the coordinator can prune matching
    ///   header buffer entries. Multiple distinct hashes may share the same
    ///   `(shard, height)`; each evicted entry contributes its key
    ///   independently — duplicates in the returned vec are harmless
    ///   because `headers.remove` is idempotent.
    /// - `evicted_pending` — content hashes of pending entries dropped
    ///   before they could be verified. Any in-flight local-DA fetch for
    ///   these hashes is now waiting on a payload that will never be
    ///   admitted; the coordinator forwards them as `AbandonFetch` so the
    ///   FSM releases its slot.
    pub(crate) fn drop_past_deadline(&mut self, now: WeightedTimestamp) -> DeadlineSweep {
        let mut evicted_keys = Vec::new();
        let store = &self.store;
        self.verified.retain(|hash, entry| {
            let alive = entry.provisions.deadline(entry.source_block_ts) > now;
            if !alive {
                store.evict(std::iter::once(*hash));
                evicted_keys.push((
                    entry.provisions.source_shard(),
                    entry.provisions.block_height(),
                ));
            }
            alive
        });

        // `received_at` is a conservative upper bound on the source block's
        // ts (we received the provisions after the source committed them),
        // so `received_at + RETENTION_HORIZON` conservatively bounds the
        // true deadline — past that, it has provably passed.
        let mut evicted_pending = Vec::new();
        let pending_entries = &mut self.pending_entries;
        self.pending.retain(|_, entries| {
            entries.retain(|p| {
                let alive = p.provisions.deadline(p.received_at) > now;
                if !alive {
                    *pending_entries -= p.provisions.transactions().len();
                    evicted_pending.push(p.provisions.hash());
                }
                alive
            });
            !entries.is_empty()
        });

        DeadlineSweep {
            evicted_keys,
            evicted_pending,
        }
    }

    /// Verified handle by content hash, if held in the pipeline's
    /// `verified` map. The shared store still holds raw bodies for
    /// wire-serving; this is the typed-state-bearing read path used by
    /// pending-block assembly.
    pub(crate) fn get_provisions_by_hash(
        &self,
        hash: ProvisionHash,
    ) -> Option<Arc<Verified<Provisions>>> {
        self.verified.get(&hash).map(|v| Arc::clone(&v.provisions))
    }

    pub(crate) const fn store(&self) -> &Arc<ProvisionStore> {
        &self.store
    }

    /// Provision entries buffered, not keys: the figure the cap is on and
    /// the one that tracks what the buffer actually holds.
    pub(crate) const fn pending_len(&self) -> usize {
        self.pending_entries
    }

    pub(crate) fn verified_len(&self) -> usize {
        self.verified.len()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{Hash, MerkleInclusionProof, ProvisionEntry, TxHash};

    use super::*;

    fn ts(ms: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(ms)
    }

    fn make_provisions(seed: u8, source_shard: ShardId, height: BlockHeight) -> Provisions {
        Provisions::new(
            source_shard,
            ShardId::leaf(2, 0),
            height,
            WeightedTimestamp::ZERO,
            MerkleInclusionProof::dummy(),
            vec![ProvisionEntry::new(
                TxHash::from(Hash::from_bytes(&[seed])),
                vec![],
            )],
        )
    }

    #[test]
    fn fresh_pipeline_is_empty() {
        let pl = ProvisionPipeline::new(Arc::new(ProvisionStore::new()));
        assert_eq!(pl.pending_len(), 0);
        assert_eq!(pl.verified_len(), 0);
        let hash = make_provisions(99, ShardId::leaf(2, 1), BlockHeight::new(1)).hash();
        assert!(!pl.has_verified(&hash));
    }

    #[test]
    fn buffer_and_drain_round_trip() {
        let mut pl = ProvisionPipeline::new(Arc::new(ProvisionStore::new()));
        let key = (ShardId::leaf(2, 1), BlockHeight::new(10));
        pl.buffer_pending(
            key,
            make_provisions(1, ShardId::leaf(2, 1), BlockHeight::new(10)),
            ts(100),
        );
        pl.buffer_pending(
            key,
            make_provisions(2, ShardId::leaf(2, 1), BlockHeight::new(10)),
            ts(100),
        );
        // Two bundles of one entry each under one key: the count is
        // entries, which is what the cap is on and what holds the bytes.
        assert_eq!(pl.pending_len(), 2);
        let drained = pl.drain_pending_for_key(key);
        assert_eq!(drained.len(), 2);
        assert_eq!(pl.pending_len(), 0);
    }

    /// The running total must survive every path that drops a pending
    /// bundle, or the cap drifts into refusing an empty buffer.
    #[test]
    fn the_pending_total_tracks_every_removal_path() {
        let mut pl = ProvisionPipeline::new(Arc::new(ProvisionStore::new()));
        let shard = ShardId::leaf(2, 1);
        let recount = |pl: &ProvisionPipeline| -> usize {
            pl.pending
                .values()
                .flat_map(|entries| entries.iter())
                .map(|p| p.provisions.transactions().len())
                .sum()
        };

        for height in 1u64..=6 {
            let key = (shard, BlockHeight::new(height));
            assert!(pl.buffer_pending(
                key,
                make_provisions(
                    u8::try_from(height).unwrap(),
                    shard,
                    BlockHeight::new(height)
                ),
                ts(100),
            ));
        }
        assert_eq!(pl.pending_len(), 6);
        assert_eq!(pl.pending_len(), recount(&pl));

        // Drained by a header arriving.
        pl.drain_pending_for_key((shard, BlockHeight::new(1)));
        assert_eq!(pl.pending_len(), recount(&pl));

        // Purged by a recovery fence above height 3.
        pl.purge_fenced(shard, BlockHeight::new(3));
        assert_eq!(pl.pending_len(), recount(&pl));

        // Swept past the deadline.
        pl.drop_past_deadline(ts(u64::MAX / 2));
        assert_eq!(pl.pending_len(), 0);
        assert_eq!(pl.pending_len(), recount(&pl));
    }

    /// Past the ceiling a bundle is refused rather than buffered — the
    /// gate a source shard's byzantine member would otherwise walk past,
    /// one fabricated source height at a time.
    #[test]
    fn a_pending_buffer_at_capacity_refuses_a_bundle() {
        let mut pl = ProvisionPipeline::new(Arc::new(ProvisionStore::new()));
        let shard = ShardId::leaf(2, 1);
        for i in 0..MAX_PENDING_PROVISION_ENTRIES {
            let h = BlockHeight::new(u64::try_from(i).unwrap());
            assert!(pl.buffer_pending(
                (shard, h),
                make_provisions(u8::try_from(i % 251).unwrap(), shard, h),
                ts(100),
            ));
        }
        assert_eq!(pl.pending_len(), MAX_PENDING_PROVISION_ENTRIES);

        let over = BlockHeight::new(u64::try_from(MAX_PENDING_PROVISION_ENTRIES).unwrap());
        assert!(
            !pl.buffer_pending((shard, over), make_provisions(7, shard, over), ts(100)),
            "a bundle past the ceiling must be refused",
        );
        assert_eq!(pl.pending_len(), MAX_PENDING_PROVISION_ENTRIES);

        // A drain reopens room for exactly what it freed.
        pl.drain_pending_for_key((shard, BlockHeight::new(0)));
        assert!(pl.buffer_pending((shard, over), make_provisions(7, shard, over), ts(100)));
    }

    #[test]
    fn drain_for_unknown_key_returns_empty() {
        let mut pl = ProvisionPipeline::new(Arc::new(ProvisionStore::new()));
        assert!(
            pl.drain_pending_for_key((ShardId::leaf(2, 1), BlockHeight::new(10)))
                .is_empty()
        );
    }

    #[test]
    fn insert_verified_populates_store_and_index() {
        let store = Arc::new(ProvisionStore::new());
        let mut pl = ProvisionPipeline::new(Arc::clone(&store));
        let provisions = make_provisions(1, ShardId::leaf(2, 1), BlockHeight::new(10));
        let hash = provisions.hash();
        let arc = pl.insert_verified(
            Arc::new(Verified::new_unchecked_for_test(provisions)),
            ts(1_000),
        );
        assert!(pl.has_verified(&hash));
        assert!(store.get(hash).is_some());
        assert_eq!(arc.source_shard(), ShardId::leaf(2, 1));
    }

    #[test]
    fn multiple_hashes_per_shard_height_coexist() {
        // Regression: re-keying `verified` by content hash means two
        // batches with the same `(source_shard, source_block_height)` —
        // e.g. different proposal rounds at the same source height —
        // can both register without one displacing the other. Keying
        // by `(shard, height)` would lose the first batch on the
        // second insert.
        let store = Arc::new(ProvisionStore::new());
        let mut pl = ProvisionPipeline::new(Arc::clone(&store));
        let shard = ShardId::leaf(2, 1);
        let height = BlockHeight::new(10);

        let p_a = make_provisions(1, shard, height);
        let p_b = make_provisions(2, shard, height);
        let hash_a = p_a.hash();
        let hash_b = p_b.hash();
        assert_ne!(hash_a, hash_b);

        pl.insert_verified(Arc::new(Verified::new_unchecked_for_test(p_a)), ts(1_000));
        pl.insert_verified(Arc::new(Verified::new_unchecked_for_test(p_b)), ts(1_000));

        assert!(pl.has_verified(&hash_a));
        assert!(pl.has_verified(&hash_b));
        assert_eq!(pl.verified_len(), 2);
    }

    #[test]
    fn drop_past_deadline_returns_evicted_keys_and_drops_pending() {
        let store = Arc::new(ProvisionStore::new());
        let mut pl = ProvisionPipeline::new(Arc::clone(&store));

        let key_v = (ShardId::leaf(2, 1), BlockHeight::new(10));
        let provisions_v = make_provisions(1, ShardId::leaf(2, 1), BlockHeight::new(10));
        let hash_v = provisions_v.hash();
        let source_ts = ts(1_000);
        let live_after = provisions_v.deadline(source_ts);
        pl.insert_verified(
            Arc::new(Verified::new_unchecked_for_test(provisions_v)),
            source_ts,
        );

        let pending = make_provisions(2, ShardId::leaf(2, 2), BlockHeight::new(5));
        let pending_hash = pending.hash();
        pl.buffer_pending(
            (ShardId::leaf(2, 2), BlockHeight::new(5)),
            pending,
            ts(1_000),
        );

        // Just before deadline: nothing evicted.
        let sweep = pl.drop_past_deadline(ts(live_after.as_millis().saturating_sub(1)));
        assert!(sweep.evicted_keys.is_empty());
        assert!(sweep.evicted_pending.is_empty());
        assert!(pl.has_verified(&hash_v));
        assert_eq!(pl.pending_len(), 1);

        // Past deadline: verified evicted, pending evicted with its hash
        // surfaced so the coordinator can cancel any pinned local-DA fetch.
        let sweep = pl.drop_past_deadline(ts(live_after.as_millis() + 1));
        assert_eq!(sweep.evicted_keys, vec![key_v]);
        assert_eq!(sweep.evicted_pending, vec![pending_hash]);
        assert!(!pl.has_verified(&hash_v));
        assert_eq!(pl.pending_len(), 0);
    }
}
