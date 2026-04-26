//! Deduplication cache for committed transaction and certificate hashes.
//!
//! Serves two purposes:
//!
//! 1. **Bridge buffer** (`recently_committed_*`): hashes from blocks just
//!    committed by BFT, held synchronously until the mempool processes the
//!    async `BlockCommitted` event and purges them. Lets proposal dedup and
//!    QC-chain walks see the latest commit even while the event is in flight.
//!
//! 2. **Retention lookup** (`tx_lookup`): tx hash → `end_timestamp_exclusive`
//!    from the tx's `validity_range`, for historical dedup over a bounded
//!    window. Survives mempool processing; pruned at the entry's own
//!    `end_timestamp_exclusive`. Past expiry, the validator-side validity
//!    check rejects re-submission anyway, so the entry is no longer
//!    correctness-bearing — it becomes a perf optimisation. Maximum age is
//!    bounded by `MAX_VALIDITY_RANGE` because admission requires
//!    `end_timestamp_exclusive <= anchor + MAX_VALIDITY_RANGE`.

use hyperscale_types::{RoutableTransaction, TxHash, WaveIdHash, WeightedTimestamp};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub(crate) struct CommittedTxCache {
    /// `tx_hash → end_timestamp_exclusive`. Pruned when
    /// `end_timestamp_exclusive <= current_committed_ts`.
    tx_lookup: HashMap<TxHash, WeightedTimestamp>,
    recently_committed_txs: HashSet<TxHash>,
    recently_committed_certs: HashSet<WaveIdHash>,
}

impl CommittedTxCache {
    pub fn new() -> Self {
        Self {
            tx_lookup: HashMap::new(),
            recently_committed_txs: HashSet::new(),
            recently_committed_certs: HashSet::new(),
        }
    }

    /// Buffer tx and cert hashes from a freshly committed block. Called
    /// synchronously at BFT commit time; entries are cleared by
    /// `register_committed` (txs) or `remove` (certs) once the mempool
    /// catches up.
    pub fn buffer_commit(
        &mut self,
        tx_hashes: impl IntoIterator<Item = TxHash>,
        cert_hashes: impl IntoIterator<Item = WaveIdHash>,
    ) {
        self.recently_committed_txs.extend(tx_hashes);
        self.recently_committed_certs.extend(cert_hashes);
    }

    /// Promote a block's transactions from the bridge buffer into the
    /// retention lookup. Each entry's stored value is the tx's
    /// `validity_range.end_timestamp_exclusive`, which bounds the entry's
    /// lifetime. Called by the node state layer after the mempool
    /// processes a committed block.
    pub fn register_committed(&mut self, transactions: &[Arc<RoutableTransaction>]) {
        for tx in transactions {
            let tx_hash = tx.hash();
            let end = tx.validity_range.end_timestamp_exclusive;
            self.tx_lookup.entry(tx_hash).or_insert(end);
            self.recently_committed_txs.remove(&tx_hash);
        }
    }

    /// Remove a finalized transaction from the retention lookup. Called when
    /// a TC is committed, so the tx is no longer relevant for timeout
    /// validation.
    pub fn remove(&mut self, tx_hash: &TxHash) {
        self.tx_lookup.remove(tx_hash);
    }

    /// Drop retention-lookup entries whose `end_timestamp_exclusive <= now`.
    /// `now` is the `weighted_timestamp` of the latest committed block.
    /// Past expiry, the validator-side validity check rejects any
    /// re-submission, so the entry is no longer correctness-bearing.
    pub fn prune(&mut self, now: WeightedTimestamp) {
        self.tx_lookup.retain(|_, end| *end > now);
    }

    pub fn contains_tx(&self, tx_hash: &TxHash) -> bool {
        self.tx_lookup.contains_key(tx_hash)
    }

    pub fn recent_tx_hashes(&self) -> impl Iterator<Item = TxHash> + '_ {
        self.recently_committed_txs.iter().copied()
    }

    pub fn recent_cert_hashes(&self) -> impl Iterator<Item = WaveIdHash> + '_ {
        self.recently_committed_certs.iter().copied()
    }

    pub fn tx_lookup_len(&self) -> usize {
        self.tx_lookup.len()
    }

    pub fn recent_txs_len(&self) -> usize {
        self.recently_committed_txs.len()
    }

    pub fn recent_certs_len(&self) -> usize {
        self.recently_committed_certs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::test_utils::test_notarized_transaction_v1;
    use hyperscale_types::{Hash, TimestampRange, routable_from_notarized_v1};

    fn h(b: &[u8]) -> WaveIdHash {
        WaveIdHash::from_raw(Hash::from_bytes(b))
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
        let mut cache = CommittedTxCache::new();
        cache.buffer_commit([th(b"tx1"), th(b"tx2")], [h(b"c1")]);

        let txs: HashSet<TxHash> = cache.recent_tx_hashes().collect();
        let certs: HashSet<WaveIdHash> = cache.recent_cert_hashes().collect();
        assert_eq!(txs, HashSet::from([th(b"tx1"), th(b"tx2")]));
        assert_eq!(certs, HashSet::from([h(b"c1")]));
    }

    #[test]
    fn register_promotes_to_lookup_and_clears_bridge() {
        let mut cache = CommittedTxCache::new();
        let tx1 = tx_with_end(1, 60_000);
        let tx1_hash = tx1.hash();
        // tx2 is in the bridge but not registered — it should stay buffered.
        let tx2_hash = th(b"tx2");
        cache.buffer_commit([tx1_hash, tx2_hash], []);
        cache.register_committed(std::slice::from_ref(&tx1));

        assert!(cache.contains_tx(&tx1_hash));
        assert!(!cache.contains_tx(&tx2_hash));

        let remaining: HashSet<TxHash> = cache.recent_tx_hashes().collect();
        assert_eq!(remaining, HashSet::from([tx2_hash]));
    }

    #[test]
    fn prune_drops_entries_past_their_end_exclusive() {
        let mut cache = CommittedTxCache::new();
        let early = tx_with_end(1, 100);
        let later = tx_with_end(2, 900);
        let early_hash = early.hash();
        let later_hash = later.hash();
        cache.register_committed(&[early, later]);

        // At now=500: early (end=100) is past expiry, later (end=900) survives.
        cache.prune(WeightedTimestamp(500));

        assert!(!cache.contains_tx(&early_hash));
        assert!(cache.contains_tx(&later_hash));
    }

    #[test]
    fn remove_clears_lookup() {
        let mut cache = CommittedTxCache::new();
        let tx = tx_with_end(1, 60_000);
        let tx_hash = tx.hash();
        cache.register_committed(&[tx]);

        cache.remove(&tx_hash);

        assert!(!cache.contains_tx(&tx_hash));
    }
}
