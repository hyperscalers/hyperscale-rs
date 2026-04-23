//! Deduplication cache for committed transaction and certificate hashes.
//!
//! Serves two purposes:
//!
//! 1. **Bridge buffer** (`recently_committed_*`): hashes from blocks just
//!    committed by BFT, held synchronously until the mempool processes the
//!    async `BlockCommitted` event and purges them. Lets proposal dedup and
//!    QC-chain walks see the latest commit even while the event is in flight.
//!
//! 2. **Retention lookup** (`tx_lookup`): tx hash → `weighted_timestamp_ms`
//!    at commit, for historical dedup over a bounded window. Survives
//!    mempool processing; pruned by `COMMITTED_TX_RETENTION`.

use hyperscale_types::{TxHash, WaveIdHash, WeightedTimestamp};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

/// How long to retain committed transaction hashes for proposal dedup.
/// Matches the mempool tombstone window so entries outlive any possible
/// re-proposal. Anchored on the weighted timestamp of the committing QC.
const COMMITTED_TX_RETENTION: Duration = Duration::from_secs(300);

pub(crate) struct CommittedTxCache {
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

    /// Promote a block's tx hashes from the bridge buffer into the
    /// retention lookup. Called by the node state layer after the mempool
    /// processes a committed block.
    pub fn register_committed(&mut self, tx_hashes: &[TxHash], commit_ts: WeightedTimestamp) {
        for tx_hash in tx_hashes {
            if let Some(&existing) = self.tx_lookup.get(tx_hash) {
                if existing != commit_ts {
                    tracing::warn!(
                        tx_hash = %tx_hash,
                        existing = %existing,
                        new = %commit_ts,
                        "Transaction committed at two different timestamps!"
                    );
                }
            }
            self.tx_lookup.entry(*tx_hash).or_insert(commit_ts);
        }
        for tx_hash in tx_hashes {
            self.recently_committed_txs.remove(tx_hash);
        }
    }

    /// Remove a finalized transaction from the retention lookup. Called when
    /// a TC is committed, so the tx is no longer relevant for timeout
    /// validation.
    pub fn remove(&mut self, tx_hash: &TxHash) {
        self.tx_lookup.remove(tx_hash);
    }

    /// Drop retention-lookup entries older than the retention window.
    /// `now` is the `weighted_timestamp` of the latest committed block.
    pub fn prune(&mut self, now: WeightedTimestamp) {
        let cutoff = now.minus(COMMITTED_TX_RETENTION);
        self.tx_lookup.retain(|_, ts| *ts > cutoff);
    }

    pub fn contains_tx(&self, tx_hash: &TxHash) -> bool {
        self.tx_lookup.contains_key(tx_hash)
    }

    pub fn tx_commit_ts(&self, tx_hash: &TxHash) -> Option<WeightedTimestamp> {
        self.tx_lookup.get(tx_hash).copied()
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
    use hyperscale_types::Hash;

    fn h(b: &[u8]) -> WaveIdHash {
        WaveIdHash::from_raw(Hash::from_bytes(b))
    }

    fn th(b: &[u8]) -> TxHash {
        TxHash::from_raw(Hash::from_bytes(b))
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
        cache.buffer_commit([th(b"tx1"), th(b"tx2")], []);
        cache.register_committed(&[th(b"tx1")], WeightedTimestamp(1000));

        assert!(cache.contains_tx(&th(b"tx1")));
        assert_eq!(
            cache.tx_commit_ts(&th(b"tx1")),
            Some(WeightedTimestamp(1000))
        );
        assert!(!cache.contains_tx(&th(b"tx2")));

        let remaining: HashSet<TxHash> = cache.recent_tx_hashes().collect();
        assert_eq!(remaining, HashSet::from([th(b"tx2")]));
    }

    #[test]
    fn prune_drops_entries_older_than_retention() {
        let mut cache = CommittedTxCache::new();
        let retention_ms = COMMITTED_TX_RETENTION.as_millis() as u64;
        cache.register_committed(&[th(b"old")], WeightedTimestamp(100));
        cache.register_committed(&[th(b"new")], WeightedTimestamp(retention_ms + 200));

        cache.prune(WeightedTimestamp(retention_ms + 200));

        assert!(!cache.contains_tx(&th(b"old")));
        assert!(cache.contains_tx(&th(b"new")));
    }

    #[test]
    fn remove_clears_lookup() {
        let mut cache = CommittedTxCache::new();
        cache.register_committed(&[th(b"tx")], WeightedTimestamp(100));

        cache.remove(&th(b"tx"));

        assert!(!cache.contains_tx(&th(b"tx")));
    }
}
