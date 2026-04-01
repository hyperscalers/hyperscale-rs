//! Vote storage (BFT Safety Critical).

use crate::core::RocksDbStorage;
use hyperscale_dispatch::Dispatch;
use hyperscale_metrics as metrics;
use hyperscale_types::Hash;
use tracing::{instrument, Level};

impl<D: Dispatch + 'static> RocksDbStorage<D> {
    /// Store our own vote for a height.
    ///
    /// **BFT Safety Critical**: This MUST be called before broadcasting the vote.
    /// After crash/restart, votes must be loaded to prevent equivocation
    /// (voting for a different block at the same height).
    ///
    /// # Panics
    ///
    /// Panics if the vote cannot be persisted. This is intentional: if we cannot
    /// persist the vote, we must NOT broadcast it, as that could lead to equivocation
    /// after a crash/restart. Crashing immediately is the safest response to storage
    /// failure for BFT-critical writes - it prevents the node from making safety
    /// violations and allows operators to investigate and fix the underlying issue.
    ///
    /// Key: height (u64 big-endian)
    /// Value: (block_hash, round) SBOR-encoded
    #[instrument(level = Level::DEBUG, skip(self), fields(
        latency_us = tracing::field::Empty,
        otel.kind = "INTERNAL",
    ))]
    pub fn put_own_vote(&self, height: u64, round: u64, block_hash: Hash) {
        let start = std::time::Instant::now();

        let key = height.to_be_bytes();
        let value = sbor::basic_encode(&(block_hash, round))
            .expect("vote encoding must succeed - this is a bug if it fails");

        // Use sync write for durability - this is safety critical
        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);

        self.db
            .put_cf_opt(self.cf().votes, key, value, &write_opts)
            .expect("BFT SAFETY CRITICAL: vote persistence failed - cannot continue safely");

        let elapsed = start.elapsed();
        metrics::record_storage_write(elapsed.as_secs_f64());
        metrics::record_storage_operation("put_vote", elapsed.as_secs_f64());
        metrics::record_vote_persisted();

        // Record span fields
        tracing::Span::current().record("latency_us", elapsed.as_micros() as u64);
    }

    /// Get our own vote for a height (if any).
    ///
    /// Returns `Some((block_hash, round))` if we previously voted at this height.
    pub fn get_own_vote(&self, height: u64) -> Option<(Hash, u64)> {
        let key = height.to_be_bytes();

        match self.db.get_cf(self.cf().votes, key) {
            Ok(Some(value)) => sbor::basic_decode(&value).ok(),
            _ => None,
        }
    }

    /// Get all our own votes (for recovery on startup).
    ///
    /// Returns a map of height -> (block_hash, round).
    pub fn get_all_own_votes(&self) -> std::collections::HashMap<u64, (Hash, u64)> {
        let cf = self.cf().votes;

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

        iter.filter_map(|item| {
            item.ok().and_then(|(key, value)| {
                let height_bytes: [u8; 8] = key.as_ref().try_into().ok()?;
                let height = u64::from_be_bytes(height_bytes);
                let (hash, round): (Hash, u64) = sbor::basic_decode(&value).ok()?;
                Some((height, (hash, round)))
            })
        })
        .collect()
    }

    /// Remove votes at or below a committed height (cleanup).
    ///
    /// Once a height is committed, we no longer need to track our vote for it.
    /// This prevents unbounded storage growth.
    pub fn prune_own_votes(&self, committed_height: u64) {
        let cf = self.cf().votes;

        // Delete all votes at or below committed_height
        let mut batch = rocksdb::WriteBatch::default();
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

        for (key, _) in iter.flatten() {
            if let Ok(height_bytes) = <[u8; 8]>::try_from(key.as_ref()) {
                let height = u64::from_be_bytes(height_bytes);
                if height <= committed_height {
                    batch.delete_cf(cf, key);
                }
            }
        }

        if let Err(e) = self.db.write(batch) {
            tracing::error!("Failed to prune votes: {}", e);
        }
    }
}
