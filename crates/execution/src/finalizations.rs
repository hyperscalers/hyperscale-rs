//! Terminal-state lookup for finalizations.
//!
//! A finalization lands here after its local EC is aggregated and every remote shard
//! has attested coverage — at that point every participating shard's
//! certificate is in hand and the receipts are ready for block inclusion.
//! Entries are removed by the
//! coordinator once the containing block commits; until then the
//! store answers tx-membership and tick-id lookups for peers that need
//! to fetch the finalized data to vote.
//!
//! This is write-once, read-many — [`TickRegistry`](crate::ticks::TickRegistry)
//! owns the mutable in-flight lifecycle (ticks, vote trackers, retries) and
//! hands them off to this store at the moment of finalization.
//!
//! Entries are keyed by `(TickId, FinalizationHash)` so iteration is both
//! deterministic and in tick order — load-bearing for simulation
//! determinism and for proposal building, which iterates the store to
//! include finalizations in block order. A tick can settle in more than
//! one part, so the tick alone does not identify an entry; the hash is
//! what a manifest names and a fetch asks by. Beside the map, a
//! `TxHash → key` index answers the questions that are per transaction
//! rather than per tick: whether a transaction has reached terminal
//! state, which finalization carries it, and what a sync requester
//! already holds.
//!
//! Held behind an `RwLock` so an `Arc<FinalizationStore>` can be shared
//! across every same-shard vnode's `ExecutionCoordinator`. In practice
//! the pinned thread serializes every write, so the lock never contends
//! — it exists to satisfy the type system around shared mutability.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, PoisonError, RwLock};

use hyperscale_types::{
    BloomFilter, DEFAULT_FPR, Finalization, FinalizationHash, TickId, TxHash, Verifiable,
};

/// A tracked finalization's place in the store: its tick, which orders it
/// against every other, and its identity, which distinguishes the parts a
/// tick settles in.
type Slot = (TickId, FinalizationHash);

/// Ticks by id, plus the transaction index derived from them. Both live
/// under one lock so a reader can never observe a transaction indexed
/// against a finalization the map has already dropped.
struct Inner {
    finalizations: BTreeMap<Slot, Arc<Verifiable<Finalization>>>,
    by_tx: HashMap<TxHash, Slot>,
    by_hash: HashMap<FinalizationHash, Slot>,
}

/// Per-shard finalization store. See module docs for lifecycle.
///
/// Stored values are [`Verifiable<Finalization>`] in the
/// `Verifiable::Verified` variant. Holding the `Block::Live.certificates`
/// transport shape directly lets the proposal-build path source verifiable
/// arcs without a per-extraction conversion; the typed-gate `insert` is
/// the single place where the conversion (and body clone) happens.
pub struct FinalizationStore {
    inner: RwLock<Inner>,
}

impl Default for FinalizationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl FinalizationStore {
    /// Construct an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(Inner {
                finalizations: BTreeMap::new(),
                by_tx: HashMap::new(),
                by_hash: HashMap::new(),
            }),
        }
    }

    /// True if no finalizations are currently tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .finalizations
            .is_empty()
    }

    /// Record a newly-finalization under its `TickId`. Callers wrap
    /// their upstream [`Verified<Finalization>`](hyperscale_types::Verified) into
    /// `Verifiable::Verified` before insertion so the same `Arc` can be
    /// shared with downstream `FinalizationsAdmitted` consumers without
    /// re-cloning. The store enforces — by virtue of its `Verifiable`
    /// argument type and the typed gates the caller went through to
    /// produce it — that every value held here is in the
    /// `Verifiable::Verified` variant.
    pub fn insert(&self, tick_id: TickId, fw: Arc<Verifiable<Finalization>>) {
        debug_assert!(
            fw.verified().is_some(),
            "FinalizationStore invariant: only Verifiable::Verified entries are admitted"
        );
        let slot = (tick_id, fw.receipt_hash());
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        for tx_hash in fw.tx_hashes() {
            inner.by_tx.insert(tx_hash, slot);
        }
        inner.by_hash.insert(slot.1, slot);
        inner.finalizations.insert(slot, fw);
    }

    /// Remove the entry with this identity, if any. No-op when absent
    /// (sync paths may remove a finalization the local node never
    /// aggregated).
    pub fn remove(&self, hash: &FinalizationHash) {
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        let Some(slot) = inner.by_hash.remove(hash) else {
            return;
        };
        let Some(fw) = inner.finalizations.remove(&slot) else {
            return;
        };
        for tx_hash in fw.tx_hashes() {
            // A later finalization re-indexing the same transaction would
            // own the entry; only drop the one this one still holds.
            if inner.by_tx.get(&tx_hash) == Some(&slot) {
                inner.by_tx.remove(&tx_hash);
            }
        }
    }

    /// Remove every finalization of `tick_id`, if any.
    pub fn remove_tick(&self, tick_id: &TickId) {
        let hashes: Vec<FinalizationHash> = self
            .inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .finalizations
            .keys()
            .filter(|(tick, _)| tick == tick_id)
            .map(|(_, hash)| *hash)
            .collect();
        for hash in hashes {
            self.remove(&hash);
        }
    }

    /// Whether the store holds `tick_id`'s determined half.
    #[must_use]
    pub fn holds_determined(&self, tick_id: &TickId) -> bool {
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .finalizations
            .range((*tick_id, FinalizationHash::ZERO)..)
            .take_while(|((tick, _), _)| tick == tick_id)
            .any(|(_, fw)| fw.is_determined())
    }

    /// All finalizations in tick order. Used by the proposer to include
    /// finalizations in the next block.
    #[must_use]
    pub fn all(&self) -> Vec<Arc<Verifiable<Finalization>>> {
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .finalizations
            .values()
            .map(Arc::clone)
            .collect()
    }

    /// Lookup by identity. Peers reference finalizations by the hash a
    /// manifest names, so this is the primary ingress lookup for serving
    /// finalization data.
    #[must_use]
    pub fn get(&self, hash: &FinalizationHash) -> Option<Arc<Verifiable<Finalization>>> {
        let inner = self.inner.read().unwrap_or_else(PoisonError::into_inner);
        let slot = inner.by_hash.get(hash)?;
        inner.finalizations.get(slot).map(Arc::clone)
    }

    /// Tick containing `tx_hash`, if any. Used to answer terminal-state
    /// queries for a single transaction (e.g. RPC, mempool status).
    /// Returns `None` once the finalization has been removed — callers then fall
    /// back to persisted storage.
    #[must_use]
    pub fn get_for_tx(&self, tx_hash: TxHash) -> Option<Arc<Verifiable<Finalization>>> {
        let inner = self.inner.read().unwrap_or_else(PoisonError::into_inner);
        let slot = inner.by_tx.get(&tx_hash)?;
        inner.finalizations.get(slot).map(Arc::clone)
    }

    /// Whether `tx_hash` is part of any currently-tracked finalization.
    #[must_use]
    pub fn is_finalized(&self, tx_hash: TxHash) -> bool {
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .by_tx
            .contains_key(&tx_hash)
    }

    /// Every transaction in a tracked finalization.
    ///
    /// The node passes this to shard consensus for conflict filtering — a transaction
    /// already finalized should not be re-proposed.
    #[must_use]
    pub fn all_tx_hashes(&self) -> HashSet<TxHash> {
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .by_tx
            .keys()
            .copied()
            .collect()
    }

    /// Whether any part of `tick_id` is tracked. Used by debug/query
    /// paths to distinguish "tick is finalized" from "tick has no
    /// tracker".
    #[must_use]
    pub fn contains(&self, tick_id: &TickId) -> bool {
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .finalizations
            .range((*tick_id, FinalizationHash::ZERO)..)
            .next()
            .is_some_and(|((tick, _), _)| tick == tick_id)
    }

    /// Number of finalizations currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .finalizations
            .len()
    }

    /// Build a bloom filter over every transaction in a tracked finalization. Sync
    /// inventory attaches this to `GetBlockRequest` so the responder can
    /// elide the finalizations the requester already has — one whose
    /// every transaction is in the filter.
    #[must_use]
    pub fn cert_bloom_snapshot(&self) -> Option<BloomFilter<TxHash>> {
        // Snapshot ids under the lock, build the bloom after release so
        // we don't hold the read guard across the heavier filter inserts.
        let tx_hashes: Vec<TxHash> = self
            .inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .by_tx
            .keys()
            .copied()
            .collect();
        let mut bf = BloomFilter::with_capacity(tx_hashes.len(), DEFAULT_FPR)?;
        for tx_hash in &tx_hashes {
            bf.insert(tx_hash);
        }
        Some(bf)
    }
}

#[cfg(test)]
mod tests {

    use hyperscale_types::{
        AggregateSignature, BlockHeight, ExecutionCertificate, ExecutionOutcome, GlobalReceiptHash,
        GlobalReceiptRoot, Hash, ShardId, SignerBitfield, TickHalf, TxHash, TxOutcome, Verified,
        WeightedTimestamp,
    };

    use super::*;

    fn make_tick_id(block_height: u64) -> TickId {
        TickId::new(ShardId::ROOT, BlockHeight::new(block_height))
    }

    fn make_finalization(
        block_height: u64,
        tx_hashes: &[TxHash],
    ) -> (TickId, Arc<Verifiable<Finalization>>) {
        let tick_id = make_tick_id(block_height);
        let tx_outcomes: Vec<TxOutcome> = tx_hashes
            .iter()
            .map(|h| {
                TxOutcome::new(
                    *h,
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                )
            })
            .collect();
        let ec = ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            tx_outcomes,
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        );
        // Lookups in this module only inspect the certificates' outcomes; an
        // empty receipts vector is fine for the store's contract.
        let verified = Verified::new_unchecked_for_test(Finalization::new(
            tick_id,
            TickHalf::Determined,
            vec![Arc::new(ec)],
            vec![],
        ));
        let fw = Arc::new(verified.into());
        (tick_id, fw)
    }

    #[test]
    fn empty_store_reports_no_finalized_state() {
        let store = FinalizationStore::new();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
        assert!(!store.is_finalized(TxHash::from(Hash::from_bytes(b"anything"))));
        assert!(store.all_tx_hashes().is_empty());
        assert!(store.all().is_empty());
    }

    #[test]
    fn insert_then_lookup_by_tx_hash() {
        let store = FinalizationStore::new();
        let tx = TxHash::from(Hash::from_bytes(b"tx1"));
        let (wid, fw) = make_finalization(1, &[tx]);
        let _id = fw.receipt_hash();

        store.insert(wid, fw);

        assert!(store.is_finalized(tx));
        assert!(store.contains(&wid));
        assert_eq!(store.len(), 1);
        let found = store.get_for_tx(tx).expect("finalization present");
        assert_eq!(found.tick_id(), &wid);
    }

    #[test]
    fn lookup_by_tick_id_matches_inserted_finalization() {
        let store = FinalizationStore::new();
        let tx = TxHash::from(Hash::from_bytes(b"tx1"));
        let (wid, fw) = make_finalization(1, &[tx]);
        let id = fw.receipt_hash();

        store.insert(wid, fw);

        let looked_up = store.get(&id).expect("finalization present by identity");
        assert_eq!(looked_up.tick_id(), &wid);

        // Unknown id returns None.
        assert!(
            store
                .get(&FinalizationHash::from_raw(Hash::from_bytes(b"absent")))
                .is_none()
        );
    }

    #[test]
    fn all_tx_hashes_flattens_across_finalizations() {
        let store = FinalizationStore::new();
        let a = TxHash::from(Hash::from_bytes(b"a"));
        let b = TxHash::from(Hash::from_bytes(b"b"));
        let c = TxHash::from(Hash::from_bytes(b"c"));
        let (wid1, fw1) = make_finalization(1, &[a, b]);
        let _id1 = fw1.receipt_hash();
        let (wid2, fw2) = make_finalization(2, &[c]);
        let _id2 = fw2.receipt_hash();

        store.insert(wid1, fw1);
        store.insert(wid2, fw2);

        let all = store.all_tx_hashes();
        assert_eq!(all.len(), 3);
        assert!(all.contains(&a));
        assert!(all.contains(&b));
        assert!(all.contains(&c));
    }

    #[test]
    fn remove_drops_only_the_named_finalization() {
        let store = FinalizationStore::new();
        let tx1 = TxHash::from(Hash::from_bytes(b"tx1"));
        let tx2 = TxHash::from(Hash::from_bytes(b"tx2"));
        let (wid1, fw1) = make_finalization(1, &[tx1]);
        let id1 = fw1.receipt_hash();
        let (wid2, fw2) = make_finalization(2, &[tx2]);
        let _id2 = fw2.receipt_hash();

        store.insert(wid1, fw1);
        store.insert(wid2, fw2);

        store.remove(&id1);

        assert!(!store.contains(&wid1));
        assert!(store.contains(&wid2));
        assert!(!store.is_finalized(tx1));
        assert!(store.is_finalized(tx2));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn cert_bloom_snapshot_contains_every_tracked_transaction() {
        let store = FinalizationStore::new();
        let tx1 = TxHash::from(Hash::from_bytes(b"tx1"));
        let tx2 = TxHash::from(Hash::from_bytes(b"tx2"));
        let (wid1, fw1) = make_finalization(1, &[tx1]);
        let _id1 = fw1.receipt_hash();
        let (wid2, fw2) = make_finalization(2, &[tx2]);
        let _id2 = fw2.receipt_hash();
        store.insert(wid1, fw1);
        store.insert(wid2, fw2);

        let bf = store.cert_bloom_snapshot().expect("sizing ok");
        assert!(bf.contains(&tx1));
        assert!(bf.contains(&tx2));
        // Untracked transaction: exercises the filter's zero region.
        assert!(!bf.contains(&TxHash::from(Hash::from_bytes(b"absent"))));
    }

    /// Removing one finalization leaves another's transactions indexed —
    /// the index is per finalization, not a single shared set.
    #[test]
    fn remove_drops_only_the_removed_finalization_from_the_tx_index() {
        let store = FinalizationStore::new();
        let a = TxHash::from(Hash::from_bytes(b"a"));
        let b = TxHash::from(Hash::from_bytes(b"b"));
        let (wid1, fw1) = make_finalization(1, &[a]);
        let id1 = fw1.receipt_hash();
        let (wid2, fw2) = make_finalization(2, &[b]);
        let _id2 = fw2.receipt_hash();
        store.insert(wid1, fw1);
        store.insert(wid2, fw2);

        store.remove(&id1);

        assert!(!store.is_finalized(a));
        assert!(store.is_finalized(b));
        assert!(store.get_for_tx(a).is_none());
        assert!(store.get_for_tx(b).is_some());
        assert_eq!(store.all_tx_hashes(), HashSet::from([b]));
    }

    #[test]
    fn remove_absent_finalization_is_noop() {
        let store = FinalizationStore::new();
        let _missing = make_tick_id(42);
        // No panic, no state change.
        store.remove(&FinalizationHash::from_raw(Hash::from_bytes(b"absent")));
        assert!(store.is_empty());
    }

    #[test]
    fn all_iterates_in_tick_id_order() {
        let store = FinalizationStore::new();
        let (wid_high, fw_high) = make_finalization(5, &[TxHash::from(Hash::from_bytes(b"hi"))]);
        let (wid_low, fw_low) = make_finalization(1, &[TxHash::from(Hash::from_bytes(b"lo"))]);

        store.insert(wid_high, fw_high);
        store.insert(wid_low, fw_low);

        let all = store.all();
        assert_eq!(all.len(), 2);
        // BTreeMap iteration is ordered by key; lower block_height comes first.
        assert_eq!(all[0].tick_id().block_height().inner(), 1);
        assert_eq!(all[1].tick_id().block_height().inner(), 5);
    }
}
