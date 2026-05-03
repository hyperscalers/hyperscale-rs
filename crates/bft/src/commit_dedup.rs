//! Deduplication index for committed artifacts referenced by block contents.
//!
//! The BFT layer enforces a single contract: every committed artifact (tx,
//! cert, provision) appears in the chain exactly once. This index is the
//! mechanism — proposers consult it to filter candidates, validators consult
//! it to reject duplicate inclusions.
//!
//! Two complementary tiers share the index:
//!
//! 1. **Bridge buffer** (`recent_*`): hashes from blocks just committed by
//!    BFT, held synchronously until the post-commit registration path runs.
//!    Covers the gap where the just-committed block has been evicted from
//!    `pending_blocks` but the QC-chain walk doesn't yet see it via durable
//!    storage. Drained by `register_committed_*`.
//!
//! 2. **Retention lookup** (`*_retention`): per-artifact deadline maps
//!    surviving the bridge drain. Each entry is bounded by an artifact-
//!    specific horizon — for txs, the tx's own `end_timestamp_exclusive`
//!    (capped by `MAX_VALIDITY_RANGE` at admission); pruned when
//!    `committed_ts >= deadline`. Past expiry, validity-window checks
//!    independently reject re-submission, so the entry is no longer
//!    correctness-bearing.

use hyperscale_types::{RoutableTransaction, TxHash, WaveId, WeightedTimestamp};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub struct CommitDedupIndex {
    /// `tx_hash → end_timestamp_exclusive`. Pruned when
    /// `end_timestamp_exclusive <= current_committed_ts`.
    tx_retention: HashMap<TxHash, WeightedTimestamp>,
    recent_txs: HashSet<TxHash>,
    recent_certs: HashSet<WaveId>,
}

impl CommitDedupIndex {
    pub fn new() -> Self {
        Self {
            tx_retention: HashMap::new(),
            recent_txs: HashSet::new(),
            recent_certs: HashSet::new(),
        }
    }

    /// Buffer tx hashes and cert ids from a freshly committed block. Called
    /// synchronously at BFT commit time; entries are cleared by
    /// `register_committed_txs` (txs) or `remove_tx` (certs) once the
    /// mempool catches up.
    pub fn buffer_commit(
        &mut self,
        tx_hashes: impl IntoIterator<Item = TxHash>,
        cert_ids: impl IntoIterator<Item = WaveId>,
    ) {
        self.recent_txs.extend(tx_hashes);
        self.recent_certs.extend(cert_ids);
    }

    /// Promote a block's transactions from the bridge buffer into the
    /// retention lookup. Each entry's stored value is the tx's
    /// `validity_range.end_timestamp_exclusive`, which bounds the entry's
    /// lifetime. Called by the node state layer after the mempool
    /// processes a committed block.
    pub fn register_committed_txs(&mut self, transactions: &[Arc<RoutableTransaction>]) {
        for tx in transactions {
            let tx_hash = tx.hash();
            let end = tx.validity_range.end_timestamp_exclusive;
            self.tx_retention.entry(tx_hash).or_insert(end);
            self.recent_txs.remove(&tx_hash);
        }
    }

    /// Remove a finalized transaction from the retention lookup. Called when
    /// a TC is committed, so the tx is no longer relevant for timeout
    /// validation.
    pub fn remove_tx(&mut self, tx_hash: &TxHash) {
        self.tx_retention.remove(tx_hash);
    }

    /// Drop retention-lookup entries whose `end_timestamp_exclusive <= now`.
    /// `now` is the `weighted_timestamp` of the latest committed block.
    /// Past expiry, the validator-side validity check rejects any
    /// re-submission, so the entry is no longer correctness-bearing.
    pub fn prune(&mut self, now: WeightedTimestamp) {
        self.tx_retention.retain(|_, end| *end > now);
    }

    pub fn contains_tx(&self, tx_hash: &TxHash) -> bool {
        self.tx_retention.contains_key(tx_hash)
    }

    pub fn recent_tx_hashes(&self) -> impl Iterator<Item = TxHash> + '_ {
        self.recent_txs.iter().copied()
    }

    pub fn recent_cert_ids(&self) -> impl Iterator<Item = WaveId> + '_ {
        self.recent_certs.iter().cloned()
    }

    pub fn tx_retention_len(&self) -> usize {
        self.tx_retention.len()
    }

    pub fn recent_txs_len(&self) -> usize {
        self.recent_txs.len()
    }

    pub fn recent_certs_len(&self) -> usize {
        self.recent_certs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::test_utils::test_notarized_transaction_v1;
    use hyperscale_types::{
        BlockHeight, Hash, ShardGroupId, TimestampRange, routable_from_notarized_v1,
    };
    use std::collections::BTreeSet;

    fn wid(height: u64) -> WaveId {
        WaveId::new(ShardGroupId(0), BlockHeight(height), BTreeSet::new())
    }

    fn th(b: &[u8]) -> TxHash {
        TxHash::from_raw(Hash::from_bytes(b))
    }

    /// Build a test tx whose `validity_range.end_timestamp_exclusive == end_ms`.
    fn tx_with_end(seed: u8, end_ms: u64) -> Arc<RoutableTransaction> {
        let notarized = test_notarized_transaction_v1(&[seed]);
        let range = TimestampRange::new(WeightedTimestamp::ZERO, WeightedTimestamp(end_ms));
        Arc::new(routable_from_notarized_v1(notarized, range).expect("valid notarized fixture"))
    }

    #[test]
    fn buffered_hashes_surface_in_recent_iterators() {
        let mut cache = CommitDedupIndex::new();
        let c1 = wid(1);
        cache.buffer_commit([th(b"tx1"), th(b"tx2")], [c1.clone()]);

        let txs: HashSet<TxHash> = cache.recent_tx_hashes().collect();
        let certs: HashSet<WaveId> = cache.recent_cert_ids().collect();
        assert_eq!(txs, HashSet::from([th(b"tx1"), th(b"tx2")]));
        assert_eq!(certs, HashSet::from([c1]));
    }

    #[test]
    fn register_promotes_to_lookup_and_clears_bridge() {
        let mut cache = CommitDedupIndex::new();
        let tx1 = tx_with_end(1, 60_000);
        let tx1_hash = tx1.hash();
        // tx2 is in the bridge but not registered — it should stay buffered.
        let tx2_hash = th(b"tx2");
        cache.buffer_commit([tx1_hash, tx2_hash], []);
        cache.register_committed_txs(std::slice::from_ref(&tx1));

        assert!(cache.contains_tx(&tx1_hash));
        assert!(!cache.contains_tx(&tx2_hash));

        let remaining: HashSet<TxHash> = cache.recent_tx_hashes().collect();
        assert_eq!(remaining, HashSet::from([tx2_hash]));
    }

    #[test]
    fn prune_drops_entries_past_their_end_exclusive() {
        let mut cache = CommitDedupIndex::new();
        let early = tx_with_end(1, 100);
        let later = tx_with_end(2, 900);
        let early_hash = early.hash();
        let later_hash = later.hash();
        cache.register_committed_txs(&[early, later]);

        // At now=500: early (end=100) is past expiry, later (end=900) survives.
        cache.prune(WeightedTimestamp(500));

        assert!(!cache.contains_tx(&early_hash));
        assert!(cache.contains_tx(&later_hash));
    }

    #[test]
    fn remove_clears_lookup() {
        let mut cache = CommitDedupIndex::new();
        let tx = tx_with_end(1, 60_000);
        let tx_hash = tx.hash();
        cache.register_committed_txs(&[tx]);

        cache.remove_tx(&tx_hash);

        assert!(!cache.contains_tx(&tx_hash));
    }
}
