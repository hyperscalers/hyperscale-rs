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

use hyperscale_types::Hash;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

/// How long to retain committed transaction hashes for proposal dedup.
/// Matches the mempool tombstone window so entries outlive any possible
/// re-proposal. Anchored on the weighted timestamp of the committing QC.
const COMMITTED_TX_RETENTION: Duration = Duration::from_secs(300);

pub(crate) struct CommittedTxCache {
    tx_lookup: HashMap<Hash, u64>,
    recently_committed_txs: HashSet<Hash>,
    recently_committed_certs: HashSet<Hash>,
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
        tx_hashes: impl IntoIterator<Item = Hash>,
        cert_hashes: impl IntoIterator<Item = Hash>,
    ) {
        self.recently_committed_txs.extend(tx_hashes);
        self.recently_committed_certs.extend(cert_hashes);
    }

    /// Promote a block's tx hashes from the bridge buffer into the
    /// retention lookup. Called by the node state layer after the mempool
    /// processes a committed block.
    pub fn register_committed(&mut self, tx_hashes: &[Hash], commit_ts_ms: u64) {
        for tx_hash in tx_hashes {
            if let Some(&existing) = self.tx_lookup.get(tx_hash) {
                if existing != commit_ts_ms {
                    tracing::warn!(
                        tx_hash = %tx_hash,
                        existing_ts_ms = existing,
                        new_ts_ms = commit_ts_ms,
                        "Transaction committed at two different timestamps!"
                    );
                }
            }
            self.tx_lookup.entry(*tx_hash).or_insert(commit_ts_ms);
        }
        for tx_hash in tx_hashes {
            self.recently_committed_txs.remove(tx_hash);
        }
    }

    /// Remove a finalized transaction from the retention lookup. Called when
    /// a TC is committed, so the tx is no longer relevant for timeout
    /// validation.
    pub fn remove(&mut self, tx_hash: &Hash) {
        self.tx_lookup.remove(tx_hash);
        self.recently_committed_certs.remove(tx_hash);
    }

    /// Drop retention-lookup entries older than the retention window.
    /// `now_ms` is the `weighted_timestamp_ms` of the latest committed block.
    pub fn prune(&mut self, now_ms: u64) {
        let retention_ms = COMMITTED_TX_RETENTION.as_millis() as u64;
        let cutoff_ms = now_ms.saturating_sub(retention_ms);
        self.tx_lookup.retain(|_, ts_ms| *ts_ms > cutoff_ms);
    }

    pub fn contains_tx(&self, tx_hash: &Hash) -> bool {
        self.tx_lookup.contains_key(tx_hash)
    }

    pub fn tx_commit_ts_ms(&self, tx_hash: &Hash) -> Option<u64> {
        self.tx_lookup.get(tx_hash).copied()
    }

    pub fn recent_tx_hashes(&self) -> impl Iterator<Item = Hash> + '_ {
        self.recently_committed_txs.iter().copied()
    }

    pub fn recent_cert_hashes(&self) -> impl Iterator<Item = Hash> + '_ {
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

    fn h(b: &[u8]) -> Hash {
        Hash::from_bytes(b)
    }

    #[test]
    fn buffered_hashes_surface_in_recent_iterators() {
        let mut cache = CommittedTxCache::new();
        cache.buffer_commit([h(b"tx1"), h(b"tx2")], [h(b"c1")]);

        let txs: HashSet<Hash> = cache.recent_tx_hashes().collect();
        let certs: HashSet<Hash> = cache.recent_cert_hashes().collect();
        assert_eq!(txs, HashSet::from([h(b"tx1"), h(b"tx2")]));
        assert_eq!(certs, HashSet::from([h(b"c1")]));
    }

    #[test]
    fn register_promotes_to_lookup_and_clears_bridge() {
        let mut cache = CommittedTxCache::new();
        cache.buffer_commit([h(b"tx1"), h(b"tx2")], []);
        cache.register_committed(&[h(b"tx1")], 1000);

        assert!(cache.contains_tx(&h(b"tx1")));
        assert_eq!(cache.tx_commit_ts_ms(&h(b"tx1")), Some(1000));
        assert!(!cache.contains_tx(&h(b"tx2")));

        let remaining: HashSet<Hash> = cache.recent_tx_hashes().collect();
        assert_eq!(remaining, HashSet::from([h(b"tx2")]));
    }

    #[test]
    fn prune_drops_entries_older_than_retention() {
        let mut cache = CommittedTxCache::new();
        let retention_ms = COMMITTED_TX_RETENTION.as_millis() as u64;
        cache.register_committed(&[h(b"old")], 100);
        cache.register_committed(&[h(b"new")], retention_ms + 200);

        cache.prune(retention_ms + 200);

        assert!(!cache.contains_tx(&h(b"old")));
        assert!(cache.contains_tx(&h(b"new")));
    }

    #[test]
    fn remove_clears_both_lookup_and_cert_bridge() {
        let mut cache = CommittedTxCache::new();
        cache.buffer_commit([], [h(b"cert")]);
        cache.register_committed(&[h(b"tx")], 100);

        cache.remove(&h(b"tx"));
        cache.remove(&h(b"cert"));

        assert!(!cache.contains_tx(&h(b"tx")));
        assert_eq!(cache.recent_cert_hashes().count(), 0);
    }
}
