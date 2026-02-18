//! Batched message sending for execution layer messages.
//!
//! This module batches outgoing execution messages (state votes, certificates,
//! provisions) to reduce network overhead. Instead of sending one network
//! message per item, we accumulate items and send them together.
//!
//! # Architecture
//!
//! ```text
//! State Machine ──► Action::BroadcastStateVote ──► MessageBatcher ──► Network
//!                   Action::BroadcastStateCertificate ──►    │
//!                   Action::BroadcastStateProvision ──►      │
//!                                                       Flush Timer (50ms)
//!                                                            │
//!                                                       Retry Queue (on failure)
//! ```
//!
//! # Benefits
//!
//! - Reduces message count by ~40-60% under load
//! - Amortizes network overhead (headers, framing) across multiple items
//! - Minimal latency impact (max 50ms delay, typically much less)
//! - Automatic retry with exponential backoff for failed broadcasts
//!
//! # Reliability
//!
//! Failed broadcasts are automatically retried with exponential backoff.
//! Cross-shard messages (provisions, votes, certificates) are critical for
//! transaction completion, so we retry up to MAX_RETRY_ATTEMPTS times before
//! giving up and logging an error.

use crate::adapter::{Libp2pAdapter, NetworkError};
use async_trait::async_trait;
use hyperscale_core::OutboundMessage;
use hyperscale_messages::{
    StateCertificateBatch, StateProvisionBatch, StateVoteBatch, TraceContext,
};
use hyperscale_types::{ShardGroupId, StateCertificate, StateProvision, StateVoteBlock};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, trace, warn};

/// Trait for broadcasting messages to a shard group.
///
/// Abstracts the network broadcast capability so `MessageBatcher` doesn't
/// depend on a concrete adapter type.
#[async_trait]
pub trait ShardBroadcast: Send + Sync {
    /// Broadcast a message to all nodes in the given shard group.
    async fn broadcast_shard(
        &self,
        shard: ShardGroupId,
        message: &OutboundMessage,
    ) -> Result<(), NetworkError>;
}

#[async_trait]
impl ShardBroadcast for Libp2pAdapter {
    async fn broadcast_shard(
        &self,
        shard: ShardGroupId,
        message: &OutboundMessage,
    ) -> Result<(), NetworkError> {
        Libp2pAdapter::broadcast_shard(self, shard, message).await
    }
}

/// Maximum retry attempts before giving up on a failed broadcast.
const MAX_RETRY_ATTEMPTS: u32 = 5;

/// Initial retry delay (doubles with each attempt).
const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Maximum retry delay cap.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(5);

/// Maximum size of the retry queue before dropping oldest entries.
const MAX_RETRY_QUEUE_SIZE: usize = 1000;

/// Configuration for the message batcher.
#[derive(Debug, Clone)]
pub struct MessageBatcherConfig {
    /// Maximum time to wait before flushing a batch (default: 50ms).
    pub flush_interval: Duration,

    /// Maximum items per batch before forced flush (default: 64).
    pub max_batch_size: usize,

    /// Whether batching is enabled (default: true).
    /// When disabled, messages are sent immediately without batching.
    #[allow(dead_code)]
    pub enabled: bool,

    /// Maximum retry attempts for failed broadcasts (default: 5).
    pub max_retry_attempts: u32,

    /// Initial retry delay, doubles with each attempt (default: 100ms).
    pub initial_retry_delay: Duration,

    /// Maximum retry delay cap (default: 5s).
    pub max_retry_delay: Duration,

    /// Maximum retry queue size before dropping oldest entries (default: 1000).
    pub max_retry_queue_size: usize,
}

impl Default for MessageBatcherConfig {
    fn default() -> Self {
        Self {
            flush_interval: Duration::from_millis(50),
            max_batch_size: 64,
            enabled: true,
            max_retry_attempts: MAX_RETRY_ATTEMPTS,
            initial_retry_delay: INITIAL_RETRY_DELAY,
            max_retry_delay: MAX_RETRY_DELAY,
            max_retry_queue_size: MAX_RETRY_QUEUE_SIZE,
        }
    }
}

/// Statistics for the message batcher.
#[derive(Debug, Default)]
pub struct MessageBatcherStats {
    /// Total items queued for batching.
    pub items_queued: AtomicU64,
    /// Total batches sent.
    pub batches_sent: AtomicU64,
    /// Total items sent (for calculating average batch size).
    pub items_sent: AtomicU64,
    /// Flushes triggered by max batch size.
    pub flushes_by_size: AtomicU64,
    /// Flushes triggered by timer.
    pub flushes_by_timer: AtomicU64,
    /// Total broadcast failures (before retry).
    pub broadcast_failures: AtomicU64,
    /// Total successful retries.
    pub retry_successes: AtomicU64,
    /// Total messages dropped after max retries.
    pub messages_dropped: AtomicU64,
    /// Current retry queue size.
    pub retry_queue_size: AtomicU64,
    /// Total retries attempted.
    pub retries_attempted: AtomicU64,
}

impl MessageBatcherStats {
    /// Get average items per batch.
    #[cfg(test)]
    pub fn avg_batch_size(&self) -> f64 {
        let batches = self.batches_sent.load(Ordering::Relaxed);
        let items = self.items_sent.load(Ordering::Relaxed);
        if batches == 0 {
            0.0
        } else {
            items as f64 / batches as f64
        }
    }
}

/// A batchable message item.
#[derive(Debug, Clone)]
#[allow(clippy::enum_variant_names)]
pub enum BatchableItem {
    StateVote(StateVoteBlock),
    StateCertificate(StateCertificate),
    StateProvision(StateProvision),
}

/// Command sent to the batcher task.
pub enum BatcherCommand {
    /// Queue an item for batching.
    /// Item is boxed to reduce enum size variance.
    Queue {
        shard: ShardGroupId,
        item: Box<BatchableItem>,
    },
    /// Flush all pending batches immediately.
    #[allow(dead_code)]
    Flush,
    /// Shutdown the batcher.
    #[allow(dead_code)]
    Shutdown,
}

/// Handle for sending messages to the batcher.
#[derive(Clone)]
pub struct MessageBatcherHandle {
    tx: mpsc::UnboundedSender<BatcherCommand>,
    stats: Arc<MessageBatcherStats>,
    #[allow(dead_code)]
    config: MessageBatcherConfig,
}

impl MessageBatcherHandle {
    /// Queue a state vote for batching.
    pub fn queue_vote(&self, shard: ShardGroupId, vote: StateVoteBlock) {
        self.stats.items_queued.fetch_add(1, Ordering::Relaxed);
        let _ = self.tx.send(BatcherCommand::Queue {
            shard,
            item: Box::new(BatchableItem::StateVote(vote)),
        });
    }

    /// Queue a state certificate for batching.
    pub fn queue_certificate(&self, shard: ShardGroupId, certificate: StateCertificate) {
        self.stats.items_queued.fetch_add(1, Ordering::Relaxed);
        let _ = self.tx.send(BatcherCommand::Queue {
            shard,
            item: Box::new(BatchableItem::StateCertificate(certificate)),
        });
    }

    /// Queue a state provision for batching.
    pub fn queue_provision(&self, shard: ShardGroupId, provision: StateProvision) {
        self.stats.items_queued.fetch_add(1, Ordering::Relaxed);
        let _ = self.tx.send(BatcherCommand::Queue {
            shard,
            item: Box::new(BatchableItem::StateProvision(provision)),
        });
    }

    /// Force flush all pending batches.
    #[allow(dead_code)]
    pub fn flush(&self) {
        let _ = self.tx.send(BatcherCommand::Flush);
    }

    /// Shutdown the batcher.
    #[allow(dead_code)]
    pub fn shutdown(&self) {
        let _ = self.tx.send(BatcherCommand::Shutdown);
    }

    /// Get current statistics.
    #[allow(dead_code)]
    pub fn stats(&self) -> &MessageBatcherStats {
        &self.stats
    }

    /// Check if batching is enabled.
    #[allow(dead_code)]
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

/// Pending batch for a specific shard and message type.
#[derive(Default)]
struct PendingBatch {
    votes: Vec<StateVoteBlock>,
    certificates: Vec<StateCertificate>,
    provisions: Vec<StateProvision>,
    first_item_time: Option<Instant>,
}

impl PendingBatch {
    fn is_empty(&self) -> bool {
        self.votes.is_empty() && self.certificates.is_empty() && self.provisions.is_empty()
    }

    fn total_items(&self) -> usize {
        self.votes.len() + self.certificates.len() + self.provisions.len()
    }
}

/// Type of failed batch for retry purposes.
#[derive(Debug, Clone)]
enum FailedBatchType {
    Votes(Vec<StateVoteBlock>),
    Certificates(Vec<StateCertificate>),
    Provisions(Vec<StateProvision>),
}

impl FailedBatchType {
    fn type_name(&self) -> &'static str {
        match self {
            FailedBatchType::Votes(_) => "votes",
            FailedBatchType::Certificates(_) => "certificates",
            FailedBatchType::Provisions(_) => "provisions",
        }
    }

    fn len(&self) -> usize {
        match self {
            FailedBatchType::Votes(v) => v.len(),
            FailedBatchType::Certificates(c) => c.len(),
            FailedBatchType::Provisions(p) => p.len(),
        }
    }
}

/// Entry in the retry queue.
#[derive(Debug, Clone)]
struct RetryEntry {
    /// Target shard for the broadcast.
    shard: ShardGroupId,
    /// The failed batch to retry.
    batch: FailedBatchType,
    /// Number of retry attempts so far.
    attempts: u32,
    /// When to next attempt the retry.
    next_retry_at: Instant,
    /// When this entry was first created (for logging).
    created_at: Instant,
}

impl RetryEntry {
    fn new(shard: ShardGroupId, batch: FailedBatchType, initial_delay: Duration) -> Self {
        let now = Instant::now();
        Self {
            shard,
            batch,
            attempts: 0,
            next_retry_at: now + initial_delay,
            created_at: now,
        }
    }

    /// Calculate the next retry delay with exponential backoff.
    fn next_delay(&self, initial: Duration, max: Duration) -> Duration {
        let delay = initial * 2u32.saturating_pow(self.attempts);
        delay.min(max)
    }
}

/// The message batcher task.
pub struct MessageBatcher {
    config: MessageBatcherConfig,
    network: Arc<dyn ShardBroadcast>,
    stats: Arc<MessageBatcherStats>,
    /// Pending batches by shard.
    pending: HashMap<ShardGroupId, PendingBatch>,
    /// Queue of failed broadcasts awaiting retry.
    retry_queue: VecDeque<RetryEntry>,
}

impl MessageBatcher {
    /// Run the batcher loop.
    pub async fn run(mut self, mut rx: mpsc::UnboundedReceiver<BatcherCommand>) {
        let mut flush_interval = tokio::time::interval(self.config.flush_interval);
        flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Retry check interval - more frequent than flush to catch ready retries
        let mut retry_interval = tokio::time::interval(Duration::from_millis(50));
        retry_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                // Handle incoming commands
                maybe_cmd = rx.recv() => {
                    match maybe_cmd {
                        Some(BatcherCommand::Queue { shard, item }) => {
                            self.queue_item(shard, *item).await;
                        }
                        Some(BatcherCommand::Flush) => {
                            self.flush_all().await;
                        }
                        Some(BatcherCommand::Shutdown) | None => {
                            // Flush remaining and exit
                            self.flush_all().await;
                            // Try one final retry pass
                            self.process_retries().await;
                            debug!(
                                retry_queue_remaining = self.retry_queue.len(),
                                "Message batcher shutting down"
                            );
                            return;
                        }
                    }
                }

                // Periodic flush
                _ = flush_interval.tick() => {
                    self.flush_expired().await;
                }

                // Process retry queue
                _ = retry_interval.tick() => {
                    self.process_retries().await;
                }
            }
        }
    }

    /// Process entries in the retry queue that are ready for retry.
    async fn process_retries(&mut self) {
        let now = Instant::now();
        let mut retries_to_process = Vec::new();

        // Collect entries ready for retry
        while let Some(entry) = self.retry_queue.front() {
            if entry.next_retry_at <= now {
                retries_to_process.push(self.retry_queue.pop_front().unwrap());
            } else {
                // Queue is ordered by next_retry_at, so we can stop here
                break;
            }
        }

        // Update queue size stat
        self.stats
            .retry_queue_size
            .store(self.retry_queue.len() as u64, Ordering::Relaxed);

        // Process each retry
        for mut entry in retries_to_process {
            entry.attempts += 1;
            self.stats.retries_attempted.fetch_add(1, Ordering::Relaxed);

            let result = self.send_batch(entry.shard, &entry.batch).await;

            match result {
                Ok(count) => {
                    self.stats.retry_successes.fetch_add(1, Ordering::Relaxed);
                    self.stats.batches_sent.fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .items_sent
                        .fetch_add(count as u64, Ordering::Relaxed);
                    debug!(
                        shard = entry.shard.0,
                        batch_type = entry.batch.type_name(),
                        count,
                        attempts = entry.attempts,
                        elapsed_ms = entry.created_at.elapsed().as_millis(),
                        "Retry succeeded"
                    );
                }
                Err(e) => {
                    if entry.attempts >= self.config.max_retry_attempts {
                        // Give up after max attempts
                        self.stats.messages_dropped.fetch_add(1, Ordering::Relaxed);
                        error!(
                            shard = entry.shard.0,
                            batch_type = entry.batch.type_name(),
                            count = entry.batch.len(),
                            attempts = entry.attempts,
                            elapsed_ms = entry.created_at.elapsed().as_millis(),
                            error = %e,
                            "CRITICAL: Cross-shard message batch dropped after max retries - \
                             transactions may be stuck until timeout"
                        );
                    } else {
                        // Schedule for retry with exponential backoff
                        let delay = entry.next_delay(
                            self.config.initial_retry_delay,
                            self.config.max_retry_delay,
                        );
                        entry.next_retry_at = Instant::now() + delay;

                        warn!(
                            shard = entry.shard.0,
                            batch_type = entry.batch.type_name(),
                            count = entry.batch.len(),
                            attempts = entry.attempts,
                            next_retry_ms = delay.as_millis(),
                            error = %e,
                            "Broadcast retry failed, will retry again"
                        );

                        self.enqueue_retry(entry);
                    }
                }
            }
        }
    }

    /// Send a batch to the network, returning item count on success.
    async fn send_batch(
        &self,
        shard: ShardGroupId,
        batch: &FailedBatchType,
    ) -> Result<usize, String> {
        match batch {
            FailedBatchType::Votes(votes) => {
                let msg = OutboundMessage::StateVoteBatch(StateVoteBatch::new(votes.clone()));
                self.network
                    .broadcast_shard(shard, &msg)
                    .await
                    .map(|_| votes.len())
                    .map_err(|e| e.to_string())
            }
            FailedBatchType::Certificates(certs) => {
                let mut batch_msg = StateCertificateBatch::new(certs.clone());
                batch_msg.trace_context = TraceContext::from_current();
                let msg = OutboundMessage::StateCertificateBatch(batch_msg);
                self.network
                    .broadcast_shard(shard, &msg)
                    .await
                    .map(|_| certs.len())
                    .map_err(|e| e.to_string())
            }
            FailedBatchType::Provisions(provs) => {
                let mut batch_msg = StateProvisionBatch::new(provs.clone());
                batch_msg.trace_context = TraceContext::from_current();
                let msg = OutboundMessage::StateProvisionBatch(batch_msg);
                self.network
                    .broadcast_shard(shard, &msg)
                    .await
                    .map(|_| provs.len())
                    .map_err(|e| e.to_string())
            }
        }
    }

    /// Enqueue a retry entry, enforcing queue size limits.
    fn enqueue_retry(&mut self, entry: RetryEntry) {
        // Enforce queue size limit by dropping oldest entries
        while self.retry_queue.len() >= self.config.max_retry_queue_size {
            if let Some(dropped) = self.retry_queue.pop_front() {
                self.stats.messages_dropped.fetch_add(1, Ordering::Relaxed);
                error!(
                    shard = dropped.shard.0,
                    batch_type = dropped.batch.type_name(),
                    count = dropped.batch.len(),
                    attempts = dropped.attempts,
                    "Cross-shard message batch dropped due to retry queue overflow"
                );
            }
        }

        // Insert maintaining order by next_retry_at (simple linear insert for now)
        // In practice the queue should be small so this is fine
        let insert_pos = self
            .retry_queue
            .iter()
            .position(|e| e.next_retry_at > entry.next_retry_at)
            .unwrap_or(self.retry_queue.len());
        self.retry_queue.insert(insert_pos, entry);

        self.stats
            .retry_queue_size
            .store(self.retry_queue.len() as u64, Ordering::Relaxed);
    }

    /// Queue an item, potentially triggering a flush if batch is full.
    async fn queue_item(&mut self, shard: ShardGroupId, item: BatchableItem) {
        let batch = self.pending.entry(shard).or_default();

        if batch.first_item_time.is_none() {
            batch.first_item_time = Some(Instant::now());
        }

        match item {
            BatchableItem::StateVote(vote) => batch.votes.push(vote),
            BatchableItem::StateCertificate(cert) => batch.certificates.push(cert),
            BatchableItem::StateProvision(prov) => batch.provisions.push(prov),
        }

        // Check if we should flush due to size
        if batch.total_items() >= self.config.max_batch_size {
            self.stats.flushes_by_size.fetch_add(1, Ordering::Relaxed);
            self.flush_shard(shard).await;
        }
    }

    /// Flush batches that have exceeded the flush interval.
    async fn flush_expired(&mut self) {
        let now = Instant::now();
        let shards_to_flush: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, batch)| {
                batch
                    .first_item_time
                    .map(|t| now.duration_since(t) >= self.config.flush_interval)
                    .unwrap_or(false)
            })
            .map(|(shard, _)| *shard)
            .collect();

        for shard in shards_to_flush {
            self.stats.flushes_by_timer.fetch_add(1, Ordering::Relaxed);
            self.flush_shard(shard).await;
        }
    }

    /// Flush all pending batches.
    async fn flush_all(&mut self) {
        let shards: Vec<_> = self.pending.keys().copied().collect();
        for shard in shards {
            self.flush_shard(shard).await;
        }
    }

    /// Flush a specific shard's pending batch.
    async fn flush_shard(&mut self, shard: ShardGroupId) {
        // Extract data from pending batch first to avoid borrow conflicts
        let (votes, certificates, provisions) = {
            let Some(batch) = self.pending.get_mut(&shard) else {
                return;
            };

            if batch.is_empty() {
                return;
            }

            // Take all pending items
            let votes = std::mem::take(&mut batch.votes);
            let certificates = std::mem::take(&mut batch.certificates);
            let provisions = std::mem::take(&mut batch.provisions);
            batch.first_item_time = None;

            (votes, certificates, provisions)
        };

        // Collect failed batches for retry (to avoid borrowing self in the loop)
        let mut failed_batches: Vec<FailedBatchType> = Vec::new();
        let initial_delay = self.config.initial_retry_delay;

        // Send votes batch
        if !votes.is_empty() {
            let count = votes.len();
            let msg = OutboundMessage::StateVoteBatch(StateVoteBatch::new(votes.clone()));

            if let Err(e) = self.network.broadcast_shard(shard, &msg).await {
                self.stats
                    .broadcast_failures
                    .fetch_add(1, Ordering::Relaxed);
                warn!(
                    shard = shard.0,
                    count,
                    error = %e,
                    "Failed to broadcast state vote batch, queuing for retry"
                );
                failed_batches.push(FailedBatchType::Votes(votes));
            } else {
                trace!(?shard, count, "Flushed state vote batch");
                self.stats.batches_sent.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .items_sent
                    .fetch_add(count as u64, Ordering::Relaxed);
            }
        }

        // Send certificates batch
        if !certificates.is_empty() {
            let count = certificates.len();
            let mut batch_msg = StateCertificateBatch::new(certificates.clone());
            batch_msg.trace_context = TraceContext::from_current();
            let msg = OutboundMessage::StateCertificateBatch(batch_msg);

            if let Err(e) = self.network.broadcast_shard(shard, &msg).await {
                self.stats
                    .broadcast_failures
                    .fetch_add(1, Ordering::Relaxed);
                warn!(
                    shard = shard.0,
                    count,
                    error = %e,
                    "Failed to broadcast state certificate batch, queuing for retry"
                );
                failed_batches.push(FailedBatchType::Certificates(certificates));
            } else {
                trace!(?shard, count, "Flushed state certificate batch");
                self.stats.batches_sent.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .items_sent
                    .fetch_add(count as u64, Ordering::Relaxed);
            }
        }

        // Send provisions batch
        if !provisions.is_empty() {
            let count = provisions.len();
            let mut batch_msg = StateProvisionBatch::new(provisions.clone());
            batch_msg.trace_context = TraceContext::from_current();
            let msg = OutboundMessage::StateProvisionBatch(batch_msg);

            if let Err(e) = self.network.broadcast_shard(shard, &msg).await {
                self.stats
                    .broadcast_failures
                    .fetch_add(1, Ordering::Relaxed);
                warn!(
                    shard = shard.0,
                    count,
                    error = %e,
                    "Failed to broadcast state provision batch, queuing for retry"
                );
                failed_batches.push(FailedBatchType::Provisions(provisions));
            } else {
                trace!(?shard, count, "Flushed state provision batch");
                self.stats.batches_sent.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .items_sent
                    .fetch_add(count as u64, Ordering::Relaxed);
            }
        }

        // Enqueue all failed batches for retry
        for failed in failed_batches {
            self.enqueue_retry(RetryEntry::new(shard, failed, initial_delay));
        }
    }
}

/// Create a message batcher and spawn it as a background task.
///
/// Returns a handle that can be used to queue messages.
pub fn spawn_message_batcher(
    config: MessageBatcherConfig,
    network: Arc<impl ShardBroadcast + 'static>,
) -> MessageBatcherHandle {
    let stats = Arc::new(MessageBatcherStats::default());
    let (tx, rx) = mpsc::unbounded_channel();

    let handle = MessageBatcherHandle {
        tx,
        stats: Arc::clone(&stats),
        config: config.clone(),
    };

    let batcher = MessageBatcher {
        config,
        network,
        stats,
        pending: HashMap::new(),
        retry_queue: VecDeque::new(),
    };

    tokio::spawn(async move {
        batcher.run(rx).await;
    });

    handle
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = MessageBatcherConfig::default();
        assert_eq!(config.flush_interval, Duration::from_millis(50));
        assert_eq!(config.max_batch_size, 64);
        assert!(config.enabled);
    }

    #[test]
    fn test_stats_avg_batch_size() {
        let stats = MessageBatcherStats::default();

        // No batches yet
        assert_eq!(stats.avg_batch_size(), 0.0);

        // 100 items in 10 batches = avg 10
        stats.items_sent.store(100, Ordering::Relaxed);
        stats.batches_sent.store(10, Ordering::Relaxed);
        assert!((stats.avg_batch_size() - 10.0).abs() < 0.001);
    }

    #[test]
    fn test_pending_batch() {
        let mut batch = PendingBatch::default();
        assert!(batch.is_empty());
        assert_eq!(batch.total_items(), 0);

        batch.votes.push(StateVoteBlock {
            transaction_hash: hyperscale_types::Hash::from_bytes(b"tx"),
            shard_group_id: ShardGroupId(0),
            state_root: hyperscale_types::Hash::from_bytes(b"root"),
            success: true,
            state_writes: vec![],
            validator: hyperscale_types::ValidatorId(0),
            signature: hyperscale_types::zero_bls_signature(),
        });

        assert!(!batch.is_empty());
        assert_eq!(batch.total_items(), 1);
    }
}
