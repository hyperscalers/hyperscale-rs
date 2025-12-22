//! Batched transaction validation for high-throughput scenarios.
//!
//! This module provides:
//! - **Deduplication**: Skip validation for already-seen transactions
//! - **Batching**: Collect transactions over a time window and validate in parallel
//!
//! # Architecture
//!
//! ```text
//! Network Gossip ──► ValidationBatcher ──► Crypto Pool ──► Transaction Channel
//!                         │
//!                    SeenCache (dedup)
//! ```
//!
//! Instead of spawning one crypto task per transaction, this batcher:
//! 1. Checks a bloom-filter-like cache to skip duplicates
//! 2. Collects transactions for a short time window (e.g., 20ms)
//! 3. Dispatches a single crypto task that validates all in parallel via rayon

use crate::thread_pools::ThreadPoolManager;
use dashmap::DashMap;
use hyperscale_core::Event;
use hyperscale_engine::TransactionValidation;
use hyperscale_types::{Hash, RoutableTransaction};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, trace};

/// Configuration for the transaction validation batcher.
#[derive(Debug, Clone)]
pub struct ValidationBatcherConfig {
    /// Maximum time to wait before dispatching a batch (default: 20ms).
    pub batch_timeout: Duration,

    /// Maximum batch size before forced dispatch (default: 128).
    pub max_batch_size: usize,

    /// Capacity of the seen transactions cache (default: 100,000).
    /// Uses a simple bounded HashSet with LRU-like eviction.
    pub seen_cache_capacity: usize,

    /// How often to clean expired entries from seen cache (default: 60s).
    pub seen_cache_cleanup_interval: Duration,
}

impl Default for ValidationBatcherConfig {
    fn default() -> Self {
        Self {
            batch_timeout: Duration::from_millis(20),
            max_batch_size: 128,
            seen_cache_capacity: 100_000,
            seen_cache_cleanup_interval: Duration::from_secs(60),
        }
    }
}

/// Statistics for the transaction validation batcher.
#[derive(Debug, Default)]
pub struct ValidationBatcherStats {
    /// Total transactions submitted.
    pub submitted: AtomicU64,
    /// Transactions skipped due to deduplication.
    pub deduplicated: AtomicU64,
    /// Transactions that passed validation.
    pub valid: AtomicU64,
    /// Transactions that failed validation.
    pub invalid: AtomicU64,
    /// Number of batches dispatched.
    pub batches_dispatched: AtomicU64,
}

impl ValidationBatcherStats {
    /// Get deduplication ratio (0.0 to 1.0).
    pub fn dedup_ratio(&self) -> f64 {
        let submitted = self.submitted.load(Ordering::Relaxed);
        let deduped = self.deduplicated.load(Ordering::Relaxed);
        if submitted == 0 {
            0.0
        } else {
            deduped as f64 / submitted as f64
        }
    }
}

/// A lock-free cache of recently seen transaction hashes for deduplication.
///
/// Uses DashMap for lock-free concurrent access. When capacity is exceeded,
/// we evict approximately 10% of entries (random eviction is acceptable for
/// this deduplication use case).
struct SeenCache {
    hashes: DashMap<Hash, ()>,
    capacity: usize,
}

impl SeenCache {
    fn new(capacity: usize) -> Self {
        Self {
            hashes: DashMap::with_capacity(capacity),
            capacity,
        }
    }

    /// Check if a hash has been seen. Returns true if already seen.
    /// This is lock-free - multiple threads can call concurrently.
    fn check_and_insert(&self, hash: Hash) -> bool {
        // Fast path: check if already exists (lock-free read)
        if self.hashes.contains_key(&hash) {
            return true;
        }

        // Evict ~10% if at capacity (approximate, non-blocking)
        if self.hashes.len() >= self.capacity {
            let to_remove: Vec<_> = self
                .hashes
                .iter()
                .take(self.capacity / 10)
                .map(|r| *r.key())
                .collect();
            for h in to_remove {
                self.hashes.remove(&h);
            }
        }

        // Insert and return false (not seen before)
        // Note: There's a small race window here, but it's acceptable for dedup
        self.hashes.insert(hash, ());
        false
    }

    /// Get current size.
    fn len(&self) -> usize {
        self.hashes.len()
    }
}

/// Handle for submitting transactions to the batcher.
#[derive(Clone)]
pub struct ValidationBatcherHandle {
    tx: mpsc::UnboundedSender<Arc<RoutableTransaction>>,
    stats: Arc<ValidationBatcherStats>,
    seen_cache: Arc<SeenCache>,
}

impl ValidationBatcherHandle {
    /// Submit a transaction for validation.
    ///
    /// Returns `true` if the transaction was submitted for validation,
    /// `false` if it was deduplicated (already seen).
    ///
    /// This method is lock-free and can be called concurrently from multiple threads.
    pub fn submit(&self, tx: Arc<RoutableTransaction>) -> bool {
        self.stats.submitted.fetch_add(1, Ordering::Relaxed);

        // Check dedup cache first (lock-free)
        let hash = tx.hash();
        if self.seen_cache.check_and_insert(hash) {
            self.stats.deduplicated.fetch_add(1, Ordering::Relaxed);
            trace!(tx_hash = ?hash, "Deduplicated transaction");
            return false;
        }

        // Submit for validation
        if self.tx.send(tx).is_err() {
            // Channel closed, batcher is shut down
            return false;
        }

        true
    }

    /// Get current statistics.
    pub fn stats(&self) -> &ValidationBatcherStats {
        &self.stats
    }

    /// Get seen cache size (for metrics).
    pub fn seen_cache_size(&self) -> usize {
        self.seen_cache.len()
    }
}

/// Batched transaction validator.
///
/// Runs as a background task, collecting transactions and dispatching
/// batched validation to the crypto thread pool.
pub struct ValidationBatcher {
    config: ValidationBatcherConfig,
    validator: Arc<TransactionValidation>,
    thread_pools: Arc<ThreadPoolManager>,
    output_tx: mpsc::UnboundedSender<Event>,
    stats: Arc<ValidationBatcherStats>,
}

impl ValidationBatcher {
    /// Run the batcher loop.
    ///
    /// This should be spawned as a background task.
    pub async fn run(self, mut rx: mpsc::UnboundedReceiver<Arc<RoutableTransaction>>) {
        let mut batch: Vec<Arc<RoutableTransaction>> =
            Vec::with_capacity(self.config.max_batch_size);
        let mut batch_start: Option<Instant> = None;

        loop {
            let timeout = if batch.is_empty() {
                // No pending batch, wait indefinitely for first transaction
                Duration::from_secs(3600)
            } else {
                // Have pending transactions, use remaining batch timeout
                let elapsed = batch_start.unwrap().elapsed();
                self.config.batch_timeout.saturating_sub(elapsed)
            };

            tokio::select! {
                // Receive new transaction
                maybe_tx = rx.recv() => {
                    match maybe_tx {
                        Some(tx) => {
                            if batch.is_empty() {
                                batch_start = Some(Instant::now());
                            }
                            batch.push(tx);

                            // Dispatch if batch is full
                            if batch.len() >= self.config.max_batch_size {
                                self.dispatch_batch(std::mem::take(&mut batch));
                                batch_start = None;
                            }
                        }
                        None => {
                            // Channel closed, dispatch remaining and exit
                            if !batch.is_empty() {
                                self.dispatch_batch(batch);
                            }
                            debug!("Transaction validation batcher shutting down");
                            return;
                        }
                    }
                }

                // Batch timeout expired
                _ = tokio::time::sleep(timeout), if !batch.is_empty() => {
                    self.dispatch_batch(std::mem::take(&mut batch));
                    batch_start = None;
                }
            }
        }
    }

    /// Dispatch a batch of transactions to the crypto thread pool.
    fn dispatch_batch(&self, batch: Vec<Arc<RoutableTransaction>>) {
        if batch.is_empty() {
            return;
        }

        let batch_size = batch.len();
        self.stats
            .batches_dispatched
            .fetch_add(1, Ordering::Relaxed);

        let validator = Arc::clone(&self.validator);
        let output_tx = self.output_tx.clone();
        let stats = Arc::clone(&self.stats);

        debug!(batch_size, "Dispatching transaction validation batch");

        self.thread_pools.spawn_tx_validation(move || {
            // Use rayon to validate in parallel across all tx validation threads
            use rayon::prelude::*;

            let results: Vec<_> = batch
                .into_par_iter()
                .map(|tx| {
                    let result = validator.validate_transaction(&tx);
                    (tx, result)
                })
                .collect();

            // Send results back
            for (tx, result) in results {
                match result {
                    Ok(()) => {
                        stats.valid.fetch_add(1, Ordering::Relaxed);
                        let _ = output_tx.send(Event::TransactionGossipReceived { tx });
                    }
                    Err(e) => {
                        stats.invalid.fetch_add(1, Ordering::Relaxed);
                        debug!(
                            tx_hash = %hex::encode(tx.hash().as_bytes()),
                            error = %e,
                            "Transaction validation failed"
                        );
                        crate::metrics::record_invalid_message();
                    }
                }
            }
        });
    }
}

/// Create a transaction validation batcher and spawn it as a background task.
///
/// Returns a handle that can be used to submit transactions.
pub fn spawn_tx_validation_batcher(
    config: ValidationBatcherConfig,
    validator: Arc<TransactionValidation>,
    thread_pools: Arc<ThreadPoolManager>,
    output_tx: mpsc::UnboundedSender<Event>,
) -> ValidationBatcherHandle {
    let stats = Arc::new(ValidationBatcherStats::default());
    let seen_cache = Arc::new(SeenCache::new(config.seen_cache_capacity));
    let (tx, rx) = mpsc::unbounded_channel::<Arc<RoutableTransaction>>();

    let handle = ValidationBatcherHandle {
        tx,
        stats: Arc::clone(&stats),
        seen_cache,
    };

    let batcher = ValidationBatcher {
        config,
        validator,
        thread_pools,
        output_tx,
        stats,
    };

    // Spawn the batcher as a background task
    tokio::spawn(async move {
        batcher.run(rx).await;
    });

    handle
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seen_cache_dedup() {
        let cache = SeenCache::new(10);
        let hash1 = Hash::from_hash_bytes(&[1; 32]);
        let hash2 = Hash::from_hash_bytes(&[2; 32]);

        // First insert should return false (not seen)
        assert!(!cache.check_and_insert(hash1));

        // Second insert of same hash should return true (seen)
        assert!(cache.check_and_insert(hash1));

        // Different hash should return false
        assert!(!cache.check_and_insert(hash2));
    }

    #[test]
    fn test_seen_cache_eviction() {
        let cache = SeenCache::new(10);

        // Fill the cache
        for i in 0..10 {
            let hash = Hash::from_hash_bytes(&[i as u8; 32]);
            assert!(!cache.check_and_insert(hash));
        }
        assert_eq!(cache.len(), 10);

        // Insert one more should trigger eviction (~10% = 1 entry)
        let hash = Hash::from_hash_bytes(&[100; 32]);
        assert!(!cache.check_and_insert(hash));

        // Should have evicted ~10% (1 entry) then added 1
        // Result: 10 - 1 + 1 = 10
        assert!(cache.len() <= 10);
    }

    #[test]
    fn test_config_default() {
        let config = ValidationBatcherConfig::default();
        assert_eq!(config.batch_timeout, Duration::from_millis(20));
        assert_eq!(config.max_batch_size, 128);
        assert_eq!(config.seen_cache_capacity, 100_000);
    }

    #[test]
    fn test_stats_dedup_ratio() {
        let stats = ValidationBatcherStats::default();

        // No submissions yet
        assert_eq!(stats.dedup_ratio(), 0.0);

        // 10 submitted, 3 deduplicated = 30% dedup ratio
        stats.submitted.store(10, Ordering::Relaxed);
        stats.deduplicated.store(3, Ordering::Relaxed);
        assert!((stats.dedup_ratio() - 0.3).abs() < 0.001);
    }
}
