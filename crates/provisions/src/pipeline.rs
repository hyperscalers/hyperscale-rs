//! Provision verification pipeline.
//!
//! Owns the lifecycle from raw provisions arrival through to verified
//! storage:
//!
//! - **Pending**: provisions buffered while their paired remote header is
//!   still in flight, keyed by `(source_shard, block_height)`.
//! - **Verified**: provisions that have passed merkle proof verification,
//!   stored whole and indexed by the same key.
//! - **Store**: shared content-addressed map serving both this pipeline's
//!   inbound writes and the io-loop's `local_provision.request` handler.
//!
//! The deadline sweep evicts any artefact whose source block has aged
//! past `RETENTION_HORIZON` — past that, every tx in the provisions has
//! expired its `validity_range` and no shard can still need the data.
//!
//! No topology, no time source. Inputs are `WeightedTimestamp` and the
//! coordinator decides when to call each method.

use crate::store::ProvisionStore;
use hyperscale_types::{BlockHeight, ProvisionHash, Provisions, ShardGroupId, WeightedTimestamp};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

type Key = (ShardGroupId, BlockHeight);

/// Verified provisions held in `verified`, paired with their source
/// block's `weighted_timestamp` for deadline-anchored eviction.
#[derive(Debug, Clone)]
struct VerifiedProvision {
    provisions: Arc<Provisions>,
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
pub(crate) struct ProvisionPipeline {
    pending: HashMap<Key, Vec<PendingProvision>>,
    verified: BTreeMap<Key, VerifiedProvision>,
    store: Arc<ProvisionStore>,
}

impl ProvisionPipeline {
    pub(crate) fn new(store: Arc<ProvisionStore>) -> Self {
        Self {
            pending: HashMap::new(),
            verified: BTreeMap::new(),
            store,
        }
    }

    /// Have verified provisions already been recorded for this key?
    pub(crate) fn has_verified(&self, key: Key) -> bool {
        self.verified.contains_key(&key)
    }

    /// Buffer provisions awaiting their paired remote header.
    pub(crate) fn buffer_pending(
        &mut self,
        key: Key,
        provisions: Provisions,
        received_at: WeightedTimestamp,
    ) {
        self.pending.entry(key).or_default().push(PendingProvision {
            provisions,
            received_at,
        });
    }

    /// Drain every provisions entry buffered for `key`. The coordinator
    /// calls this when the matching header arrives; each drained entry is
    /// then run through merkle proof verification.
    pub(crate) fn drain_pending_for_key(&mut self, key: Key) -> Vec<Provisions> {
        self.pending
            .remove(&key)
            .map(|entries| entries.into_iter().map(|p| p.provisions).collect())
            .unwrap_or_default()
    }

    /// Insert verified provisions into the pipeline + store. Returns the
    /// `Arc` the coordinator hands downstream (queue + ProvisionsVerified
    /// emit). Idempotent if the same content hash is inserted twice.
    pub(crate) fn insert_verified(
        &mut self,
        provisions: Provisions,
        source_block_ts: WeightedTimestamp,
    ) -> Arc<Provisions> {
        let key = (provisions.source_shard, provisions.block_height);
        let provisions = Arc::new(provisions);
        self.verified.insert(
            key,
            VerifiedProvision {
                provisions: Arc::clone(&provisions),
                source_block_ts,
            },
        );
        self.store.insert(Arc::clone(&provisions));
        provisions
    }

    /// Drop verified and pending entries whose deadline has passed `now`.
    /// Returns the keys evicted from `verified` so the coordinator can
    /// prune the matching header buffer entries.
    pub(crate) fn drop_past_deadline(&mut self, now: WeightedTimestamp) -> Vec<Key> {
        let mut evicted_keys = Vec::new();
        let store = &self.store;
        self.verified.retain(|key, entry| {
            let alive = entry.provisions.deadline(entry.source_block_ts) > now;
            if !alive {
                store.evict(std::iter::once(entry.provisions.hash()));
                evicted_keys.push(*key);
            }
            alive
        });

        // `received_at` is a conservative upper bound on the source block's
        // ts (we received the provisions after the source committed them),
        // so `received_at + RETENTION_HORIZON` conservatively bounds the
        // true deadline — past that, it has provably passed.
        self.pending.retain(|_, entries| {
            entries.retain(|p| p.provisions.deadline(p.received_at) > now);
            !entries.is_empty()
        });

        evicted_keys
    }

    pub(crate) fn get_provisions_by_hash(&self, hash: &ProvisionHash) -> Option<Arc<Provisions>> {
        self.store.get(hash)
    }

    pub(crate) fn store(&self) -> &Arc<ProvisionStore> {
        &self.store
    }

    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub(crate) fn verified_len(&self) -> usize {
        self.verified.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{MerkleInclusionProof, TxEntries, TxHash};

    fn ts(ms: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(ms)
    }

    fn make_provisions(seed: u8, source_shard: ShardGroupId, height: BlockHeight) -> Provisions {
        Provisions::new(
            source_shard,
            height,
            MerkleInclusionProof::dummy(),
            vec![TxEntries {
                tx_hash: TxHash::from_raw(hyperscale_types::Hash::from_bytes(&[seed])),
                entries: vec![],
                target_nodes: vec![],
            }],
        )
    }

    #[test]
    fn fresh_pipeline_is_empty() {
        let pl = ProvisionPipeline::new(Arc::new(ProvisionStore::new()));
        assert_eq!(pl.pending_len(), 0);
        assert_eq!(pl.verified_len(), 0);
        assert!(!pl.has_verified((ShardGroupId(1), BlockHeight(1))));
    }

    #[test]
    fn buffer_and_drain_round_trip() {
        let mut pl = ProvisionPipeline::new(Arc::new(ProvisionStore::new()));
        let key = (ShardGroupId(1), BlockHeight(10));
        pl.buffer_pending(
            key,
            make_provisions(1, ShardGroupId(1), BlockHeight(10)),
            ts(100),
        );
        pl.buffer_pending(
            key,
            make_provisions(2, ShardGroupId(1), BlockHeight(10)),
            ts(100),
        );
        assert_eq!(pl.pending_len(), 1);
        let drained = pl.drain_pending_for_key(key);
        assert_eq!(drained.len(), 2);
        assert_eq!(pl.pending_len(), 0);
    }

    #[test]
    fn drain_for_unknown_key_returns_empty() {
        let mut pl = ProvisionPipeline::new(Arc::new(ProvisionStore::new()));
        assert!(pl
            .drain_pending_for_key((ShardGroupId(1), BlockHeight(10)))
            .is_empty());
    }

    #[test]
    fn insert_verified_populates_store_and_index() {
        let store = Arc::new(ProvisionStore::new());
        let mut pl = ProvisionPipeline::new(Arc::clone(&store));
        let provisions = make_provisions(1, ShardGroupId(1), BlockHeight(10));
        let hash = provisions.hash();
        let arc = pl.insert_verified(provisions, ts(1_000));
        assert!(pl.has_verified((ShardGroupId(1), BlockHeight(10))));
        assert!(store.get(&hash).is_some());
        assert_eq!(arc.source_shard, ShardGroupId(1));
    }

    #[test]
    fn drop_past_deadline_returns_evicted_keys_and_drops_pending() {
        let store = Arc::new(ProvisionStore::new());
        let mut pl = ProvisionPipeline::new(Arc::clone(&store));

        let key_v = (ShardGroupId(1), BlockHeight(10));
        let provisions_v = make_provisions(1, ShardGroupId(1), BlockHeight(10));
        let source_ts = ts(1_000);
        let live_after = provisions_v.deadline(source_ts);
        pl.insert_verified(provisions_v, source_ts);

        pl.buffer_pending(
            (ShardGroupId(2), BlockHeight(5)),
            make_provisions(2, ShardGroupId(2), BlockHeight(5)),
            ts(1_000),
        );

        // Just before deadline: nothing evicted.
        let evicted = pl.drop_past_deadline(ts(live_after.as_millis().saturating_sub(1)));
        assert!(evicted.is_empty());
        assert!(pl.has_verified(key_v));
        assert_eq!(pl.pending_len(), 1);

        // Past deadline: verified evicted, pending evicted.
        let evicted = pl.drop_past_deadline(ts(live_after.as_millis() + 1));
        assert_eq!(evicted, vec![key_v]);
        assert!(!pl.has_verified(key_v));
        assert_eq!(pl.pending_len(), 0);
    }
}
