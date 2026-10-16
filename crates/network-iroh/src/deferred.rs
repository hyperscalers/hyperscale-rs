//! Gossip items waiting on a verdict a check settles later.
//!
//! A handler that defers its verdict hands the item to a check that runs
//! elsewhere, which may settle it before the transport has recorded that it
//! waits: the check can be quick and the transport records the wait only
//! once the handler returns. A settlement that finds nothing waiting is
//! therefore remembered for a while, and a wait recorded after it takes it
//! at once.

use std::collections::{HashMap, VecDeque};

use hyperscale_network::{GossipVerdict, VerdictKey};

/// Settlements remembered for an item whose wait was not recorded yet.
/// Checks settle every copy they run on, local ones included, so this is
/// a window over the latest, not a set of every settlement.
const EARLY_SETTLED: usize = 1024;

/// Items waiting on a deferred verdict, and verdicts settled before their
/// item's wait was recorded.
pub struct Waiting<T> {
    items: HashMap<VerdictKey, T>,
    early: HashMap<VerdictKey, GossipVerdict>,
    early_order: VecDeque<VerdictKey>,
}

impl<T> Default for Waiting<T> {
    fn default() -> Self {
        Self {
            items: HashMap::new(),
            early: HashMap::new(),
            early_order: VecDeque::new(),
        }
    }
}

impl<T> Waiting<T> {
    /// Record that `item` waits on the verdict `key` names. Returns the item
    /// and its verdict when the verdict came already, or when a copy of the
    /// item waits already, in which case this one goes unjudged.
    pub fn defer(&mut self, key: VerdictKey, item: T) -> Option<(T, GossipVerdict)> {
        if let Some(verdict) = self.early.remove(&key) {
            return Some((item, verdict));
        }
        if self.items.contains_key(&key) {
            return Some((item, GossipVerdict::Ignore));
        }
        self.items.insert(key, item);
        None
    }

    /// Settle the verdict `key` names. Returns the item that waited on it,
    /// or remembers the verdict for an item whose wait is still to come.
    pub fn settle(&mut self, key: VerdictKey, verdict: GossipVerdict) -> Option<T> {
        if let Some(item) = self.items.remove(&key) {
            return Some(item);
        }
        if self.early.insert(key, verdict).is_none() {
            self.early_order.push_back(key);
            if self.early_order.len() > EARLY_SETTLED
                && let Some(oldest) = self.early_order.pop_front()
            {
                self.early.remove(&oldest);
            }
        }
        None
    }

    /// Give up on the item waiting on `key`, if it still does.
    pub fn expire(&mut self, key: VerdictKey) -> Option<T> {
        self.items.remove(&key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u64) -> VerdictKey {
        VerdictKey::of(&n)
    }

    #[test]
    fn a_verdict_reaches_the_item_that_waits_on_it_once() {
        let mut waiting = Waiting::default();
        assert_eq!(waiting.defer(key(1), "item"), None);
        assert_eq!(waiting.settle(key(1), GossipVerdict::Accept), Some("item"));
        assert_eq!(waiting.expire(key(1)), None, "settled items do not expire");
    }

    #[test]
    fn a_verdict_that_comes_before_its_wait_is_kept_for_it() {
        let mut waiting = Waiting::default();
        assert_eq!(waiting.settle(key(1), GossipVerdict::Reject), None);
        assert_eq!(
            waiting.defer(key(1), "item"),
            Some(("item", GossipVerdict::Reject))
        );
        assert_eq!(waiting.defer(key(1), "again"), None, "taken once");
    }

    #[test]
    fn a_second_copy_of_a_waiting_item_goes_unjudged() {
        let mut waiting = Waiting::default();
        assert_eq!(waiting.defer(key(1), "first"), None);
        assert_eq!(
            waiting.defer(key(1), "copy"),
            Some(("copy", GossipVerdict::Ignore))
        );
        assert_eq!(waiting.expire(key(1)), Some("first"));
    }

    #[test]
    fn early_verdicts_are_a_bounded_window() {
        let mut waiting: Waiting<&str> = Waiting::default();
        for n in 0..(EARLY_SETTLED as u64 * 3) {
            assert_eq!(waiting.settle(key(n), GossipVerdict::Accept), None);
        }
        assert_eq!(waiting.early.len(), EARLY_SETTLED);
        assert_eq!(
            waiting.defer(key(0), "oldest"),
            None,
            "the oldest was let go"
        );
        let newest = EARLY_SETTLED as u64 * 3 - 1;
        assert!(waiting.defer(key(newest), "newest").is_some());
    }
}
