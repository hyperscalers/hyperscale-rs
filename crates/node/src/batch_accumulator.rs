//! Batch accumulator for time-and-count-based flushing.
//!
//! [`BatchAccumulator`] collects items until either a maximum count or a time
//! window is reached, at which point the caller flushes the batch. Deadlines are
//! tracked as `LocalTimestamp` (the `io_loop`'s monotonic local clock) so both
//! production and simulation use the same paths.

use hyperscale_types::LocalTimestamp;
use std::time::Duration;

/// A batch accumulator that collects items until a count or time limit is reached.
///
/// Items are stored in a flat `Vec`. For batches where the logical count differs
/// from `items.len()` (e.g. counting individual votes rather than vote groups),
/// use [`push_weighted`](Self::push_weighted).
pub struct BatchAccumulator<T> {
    items: Vec<T>,
    count: usize,
    max_count: usize,
    window: Duration,
    deadline: Option<LocalTimestamp>,
}

impl<T> BatchAccumulator<T> {
    /// Create a new accumulator that flushes after `max_count` items or `window` time.
    pub const fn new(max_count: usize, window: Duration) -> Self {
        Self {
            items: Vec::new(),
            count: 0,
            max_count,
            window,
            deadline: None,
        }
    }

    /// Push an item with weight 1. Returns `true` if the batch is full.
    pub fn push(&mut self, item: T, now: LocalTimestamp) -> bool {
        self.push_weighted(item, 1, now)
    }

    /// Push an item with custom weight. Returns `true` if the batch is full.
    ///
    /// Use this when the count threshold applies to a measure other than the
    /// number of items (e.g. total individual votes across grouped vote items).
    pub fn push_weighted(&mut self, item: T, weight: usize, now: LocalTimestamp) -> bool {
        if self.count == 0 {
            self.deadline = Some(now.plus(self.window));
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
    pub fn is_expired(&self, now: LocalTimestamp) -> bool {
        self.deadline.is_some_and(|d| now >= d)
    }

    /// The deadline for this batch, if non-empty.
    pub const fn deadline(&self) -> Option<LocalTimestamp> {
        self.deadline
    }

    /// Number of items currently buffered.
    pub const fn len(&self) -> usize {
        self.items.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_returns_true_when_full() {
        let mut batch = BatchAccumulator::new(3, Duration::from_millis(100));
        let now = LocalTimestamp::from_millis(1_000);
        assert!(!batch.push("a", now));
        assert!(!batch.push("b", now));
        assert!(batch.push("c", now));
    }

    #[test]
    fn take_resets_accumulator() {
        let mut batch = BatchAccumulator::new(10, Duration::from_millis(100));
        let now = LocalTimestamp::from_millis(1_000);
        batch.push("a", now);
        batch.push("b", now);

        let items = batch.take();
        assert_eq!(items, vec!["a", "b"]);
        assert!(batch.deadline().is_none());

        // After take, next push sets a fresh deadline.
        let now2 = LocalTimestamp::from_millis(2_000);
        batch.push("c", now2);
        assert_eq!(
            batch.deadline(),
            Some(now2.plus(Duration::from_millis(100)))
        );
    }

    #[test]
    fn deadline_set_on_first_push() {
        let mut batch = BatchAccumulator::<u32>::new(10, Duration::from_millis(50));
        assert!(batch.deadline().is_none());

        let now = LocalTimestamp::from_millis(1_000);
        batch.push(1, now);
        assert_eq!(batch.deadline(), Some(now.plus(Duration::from_millis(50))));

        // Second push doesn't change deadline.
        let later = LocalTimestamp::from_millis(2_000);
        batch.push(2, later);
        assert_eq!(batch.deadline(), Some(now.plus(Duration::from_millis(50))));
    }

    #[test]
    fn is_expired() {
        let mut batch = BatchAccumulator::new(10, Duration::from_millis(100));
        let now = LocalTimestamp::from_millis(1_000);
        batch.push(42, now);

        assert!(!batch.is_expired(now));
        assert!(!batch.is_expired(now.plus(Duration::from_millis(99))));
        assert!(batch.is_expired(now.plus(Duration::from_millis(100))));
        assert!(batch.is_expired(now.plus(Duration::from_millis(200))));
    }

    #[test]
    fn weighted_push() {
        let mut batch = BatchAccumulator::new(10, Duration::from_millis(100));
        let now = LocalTimestamp::from_millis(1_000);
        assert!(!batch.push_weighted("group_a", 4, now));
        assert!(!batch.push_weighted("group_b", 5, now));
        assert!(batch.push_weighted("group_c", 1, now)); // total = 10

        let items = batch.take();
        assert_eq!(items.len(), 3); // 3 items, but weight was 10
    }
}
