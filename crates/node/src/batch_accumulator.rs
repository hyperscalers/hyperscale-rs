//! Batch accumulators for time-and-count-based flushing.
//!
//! Both [`BatchAccumulator`] and [`ShardedBatchAccumulator`] collect items until
//! either a maximum count or a time window is reached, at which point the caller
//! flushes the batch. Deadlines are tracked as logical time (`Duration`) so both
//! production (wall clock) and simulation (logical clock) use the same paths.

use hyperscale_types::ShardGroupId;
use std::collections::HashMap;
use std::time::Duration;

/// A batch accumulator that collects items until a count or time limit is reached.
///
/// Items are stored in a flat `Vec`. For batches where the logical count differs
/// from `items.len()` (e.g. counting individual votes rather than vote groups),
/// use [`push_weighted`](Self::push_weighted).
pub(crate) struct BatchAccumulator<T> {
    items: Vec<T>,
    count: usize,
    max_count: usize,
    window: Duration,
    deadline: Option<Duration>,
}

impl<T> BatchAccumulator<T> {
    /// Create a new accumulator that flushes after `max_count` items or `window` time.
    pub fn new(max_count: usize, window: Duration) -> Self {
        Self {
            items: Vec::new(),
            count: 0,
            max_count,
            window,
            deadline: None,
        }
    }

    /// Push an item with weight 1. Returns `true` if the batch is full.
    pub fn push(&mut self, item: T, now: Duration) -> bool {
        self.push_weighted(item, 1, now)
    }

    /// Push an item with custom weight. Returns `true` if the batch is full.
    ///
    /// Use this when the count threshold applies to a measure other than the
    /// number of items (e.g. total individual votes across grouped vote items).
    pub fn push_weighted(&mut self, item: T, weight: usize, now: Duration) -> bool {
        if self.count == 0 {
            self.deadline = Some(now + self.window);
        }
        self.items.push(item);
        self.count += weight;
        self.count >= self.max_count
    }

    /// Take all items, resetting the accumulator and clearing the deadline.
    pub fn take(&mut self) -> Vec<T> {
        self.count = 0;
        self.deadline = None;
        std::mem::take(&mut self.items)
    }

    /// Whether the batch deadline has expired.
    pub fn is_expired(&self, now: Duration) -> bool {
        self.deadline.is_some_and(|d| now >= d)
    }

    /// The deadline for this batch, if non-empty.
    pub fn deadline(&self) -> Option<Duration> {
        self.deadline
    }
}

/// A sharded batch accumulator that groups items by [`ShardGroupId`].
///
/// Items are collected into per-shard `Vec`s. The batch flushes when the total
/// count across all shards reaches `max_count` or the time window expires.
pub(crate) struct ShardedBatchAccumulator<T> {
    by_shard: HashMap<ShardGroupId, Vec<T>>,
    total: usize,
    max_count: usize,
    window: Duration,
    deadline: Option<Duration>,
}

impl<T> ShardedBatchAccumulator<T> {
    /// Create a new sharded accumulator.
    pub fn new(max_count: usize, window: Duration) -> Self {
        Self {
            by_shard: HashMap::new(),
            total: 0,
            max_count,
            window,
            deadline: None,
        }
    }

    /// Push an item for a specific shard. Returns `true` if the batch is full.
    pub fn push(&mut self, shard: ShardGroupId, item: T, now: Duration) -> bool {
        if self.total == 0 {
            self.deadline = Some(now + self.window);
        }
        self.by_shard.entry(shard).or_default().push(item);
        self.total += 1;
        self.total >= self.max_count
    }

    /// Take all items grouped by shard, resetting the accumulator.
    pub fn take(&mut self) -> HashMap<ShardGroupId, Vec<T>> {
        self.total = 0;
        self.deadline = None;
        std::mem::take(&mut self.by_shard)
    }

    /// Whether the batch deadline has expired.
    pub fn is_expired(&self, now: Duration) -> bool {
        self.deadline.is_some_and(|d| now >= d)
    }

    /// The deadline for this batch, if non-empty.
    pub fn deadline(&self) -> Option<Duration> {
        self.deadline
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_returns_true_when_full() {
        let mut batch = BatchAccumulator::new(3, Duration::from_millis(100));
        let now = Duration::from_secs(1);
        assert!(!batch.push("a", now));
        assert!(!batch.push("b", now));
        assert!(batch.push("c", now));
    }

    #[test]
    fn take_resets_accumulator() {
        let mut batch = BatchAccumulator::new(10, Duration::from_millis(100));
        let now = Duration::from_secs(1);
        batch.push("a", now);
        batch.push("b", now);

        let items = batch.take();
        assert_eq!(items, vec!["a", "b"]);
        assert!(batch.deadline().is_none());

        // After take, next push sets a fresh deadline.
        let now2 = Duration::from_secs(2);
        batch.push("c", now2);
        assert_eq!(batch.deadline(), Some(now2 + Duration::from_millis(100)));
    }

    #[test]
    fn deadline_set_on_first_push() {
        let mut batch = BatchAccumulator::<u32>::new(10, Duration::from_millis(50));
        assert!(batch.deadline().is_none());

        let now = Duration::from_secs(1);
        batch.push(1, now);
        assert_eq!(batch.deadline(), Some(now + Duration::from_millis(50)));

        // Second push doesn't change deadline.
        let later = Duration::from_secs(2);
        batch.push(2, later);
        assert_eq!(batch.deadline(), Some(now + Duration::from_millis(50)));
    }

    #[test]
    fn is_expired() {
        let mut batch = BatchAccumulator::new(10, Duration::from_millis(100));
        let now = Duration::from_secs(1);
        batch.push(42, now);

        assert!(!batch.is_expired(now));
        assert!(!batch.is_expired(now + Duration::from_millis(99)));
        assert!(batch.is_expired(now + Duration::from_millis(100)));
        assert!(batch.is_expired(now + Duration::from_millis(200)));
    }

    #[test]
    fn weighted_push() {
        let mut batch = BatchAccumulator::new(10, Duration::from_millis(100));
        let now = Duration::from_secs(1);
        assert!(!batch.push_weighted("group_a", 4, now));
        assert!(!batch.push_weighted("group_b", 5, now));
        assert!(batch.push_weighted("group_c", 1, now)); // total = 10

        let items = batch.take();
        assert_eq!(items.len(), 3); // 3 items, but weight was 10
    }

    #[test]
    fn sharded_push_and_take() {
        let mut batch = ShardedBatchAccumulator::new(5, Duration::from_millis(100));
        let now = Duration::from_secs(1);
        let shard_a = ShardGroupId(0);
        let shard_b = ShardGroupId(1);

        assert!(!batch.push(shard_a, "x", now));
        assert!(!batch.push(shard_b, "y", now));
        assert!(!batch.push(shard_a, "z", now));

        let by_shard = batch.take();
        assert_eq!(by_shard[&shard_a], vec!["x", "z"]);
        assert_eq!(by_shard[&shard_b], vec!["y"]);
        assert!(batch.deadline().is_none());
    }

    #[test]
    fn sharded_full() {
        let mut batch = ShardedBatchAccumulator::new(2, Duration::from_millis(100));
        let now = Duration::from_secs(1);
        let shard = ShardGroupId(0);

        assert!(!batch.push(shard, 1, now));
        assert!(batch.push(shard, 2, now));
    }
}
