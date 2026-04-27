//! In-flight slot accounting.
//!
//! Bounds the number of concurrent in-flight fetches and answers membership
//! queries — given a key (height, scope tuple, etc.), is there an in-flight
//! request for it right now?

use std::collections::HashSet;
use std::hash::Hash;

/// Cap-enforced set of in-flight keys.
#[derive(Debug)]
pub struct SlotTracker<K: Eq + Hash + Clone> {
    capacity: usize,
    in_flight: HashSet<K>,
}

impl<K: Eq + Hash + Clone> SlotTracker<K> {
    /// Build a tracker that allows up to `capacity` concurrent in-flight keys.
    /// `capacity = 0` disables the cap (any number of acquires succeed) — used
    /// by callers that want only the membership tracking.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            in_flight: HashSet::new(),
        }
    }

    /// Try to claim a slot for `key`. Returns `true` if the slot was acquired
    /// (key is now in-flight), `false` if the cap is reached or `key` was
    /// already in-flight.
    pub fn try_acquire(&mut self, key: K) -> bool {
        if self.capacity > 0 && self.in_flight.len() >= self.capacity {
            return false;
        }
        self.in_flight.insert(key)
    }

    /// Release the slot held by `key`. Returns `true` if a slot was actually
    /// freed, `false` if `key` wasn't in-flight.
    pub fn release(&mut self, key: &K) -> bool {
        self.in_flight.remove(key)
    }

    /// Whether `key` currently holds a slot.
    #[must_use]
    pub fn contains(&self, key: &K) -> bool {
        self.in_flight.contains(key)
    }

    /// Count of slots currently held.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// Whether at least one slot is free.
    #[must_use]
    pub fn has_capacity(&self) -> bool {
        self.capacity == 0 || self.in_flight.len() < self.capacity
    }

    /// Drop every key for which `f` returns false. Used by callers that need
    /// to evict stale or no-longer-relevant scopes from the tracker.
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&K) -> bool,
    {
        self.in_flight.retain(|k| f(k));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_and_release_round_trip() {
        let mut s = SlotTracker::<u32>::new(3);
        assert!(s.try_acquire(1));
        assert!(s.try_acquire(2));
        assert_eq!(s.in_flight(), 2);
        assert!(s.contains(&1));

        assert!(s.release(&1));
        assert!(!s.contains(&1));
        assert_eq!(s.in_flight(), 1);
    }

    #[test]
    fn cap_blocks_acquire_when_full() {
        let mut s = SlotTracker::<u32>::new(2);
        assert!(s.try_acquire(1));
        assert!(s.try_acquire(2));
        assert!(!s.try_acquire(3));
        assert_eq!(s.in_flight(), 2);
        assert!(!s.contains(&3));
    }

    #[test]
    fn duplicate_acquire_returns_false() {
        let mut s = SlotTracker::<u32>::new(5);
        assert!(s.try_acquire(1));
        assert!(!s.try_acquire(1));
        assert_eq!(s.in_flight(), 1);
    }

    #[test]
    fn capacity_zero_is_uncapped() {
        let mut s = SlotTracker::<u32>::new(0);
        for k in 0..1000 {
            assert!(s.try_acquire(k));
        }
        assert_eq!(s.in_flight(), 1000);
        assert!(s.has_capacity());
    }

    #[test]
    fn retain_drops_matching_keys() {
        let mut s = SlotTracker::<u32>::new(10);
        for k in 1..=5 {
            s.try_acquire(k);
        }
        s.retain(|k| *k > 3);
        assert_eq!(s.in_flight(), 2);
        assert!(s.contains(&4));
        assert!(s.contains(&5));
        assert!(!s.contains(&1));
    }

    #[test]
    fn release_unknown_returns_false() {
        let mut s = SlotTracker::<u32>::new(5);
        assert!(!s.release(&42));
    }
}
