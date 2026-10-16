//! Items waiting on verdicts that checks settle later.
//!
//! A handler that defers names every check its item rests on, and each
//! check settles its part. An item holds up once every part has settled
//! [`Verdict::Accept`], and is refused as soon as one settles anything else.
//!
//! A check can finish before the transport has recorded that anything waits
//! on it: it can be quick, the transport records the wait only once the
//! handler returns, and the same part (a vote, a quorum certificate) can be
//! carried by many items and checked once, when the first of them arrives.
//! A definite settlement is therefore remembered for a while, and a wait
//! recorded after it takes it at once. A part this host could not judge is
//! not remembered: the host may be able to judge it later.

use std::collections::{HashMap, VecDeque};

use hyperscale_network::{Verdict, VerdictKey};

/// Definite settlements remembered. Checks settle every copy they run on,
/// local ones included, so this is a window over the latest, not a set of
/// every settlement. It holds minutes of committed headers, two parts each,
/// from dozens of busy shards, and a large pool's ratify votes besides.
const SETTLED_REMEMBERED: usize = 65_536;

/// Names one wait.
pub type WaitId = u64;

/// An item and the parts it still waits on.
struct Waiter<T> {
    item: T,
    outstanding: Vec<VerdictKey>,
}

/// Items waiting on deferred verdicts, and definite verdicts settled lately.
pub struct Waiting<T> {
    waiters: HashMap<WaitId, Waiter<T>>,
    /// The waits each outstanding part holds up.
    by_part: HashMap<VerdictKey, Vec<WaitId>>,
    /// Whether each part settled lately held up.
    settled: HashMap<VerdictKey, bool>,
    settled_order: VecDeque<VerdictKey>,
    next: WaitId,
}

impl<T> Default for Waiting<T> {
    fn default() -> Self {
        Self {
            waiters: HashMap::new(),
            by_part: HashMap::new(),
            settled: HashMap::new(),
            settled_order: VecDeque::new(),
            next: 0,
        }
    }
}

/// What deferring an item came to.
#[derive(Debug, PartialEq, Eq)]
pub enum Deferred<T> {
    /// It waits, under this id.
    Waits(WaitId),
    /// Its parts were all settled already: here is its verdict.
    Settled(T, Verdict),
}

impl<T> Waiting<T> {
    /// Record that `item` waits on the checks of every item `parts` names.
    pub fn defer(&mut self, parts: &[VerdictKey], item: T) -> Deferred<T> {
        let mut outstanding = Vec::with_capacity(parts.len());
        for part in parts {
            match self.settled.get(part) {
                Some(true) => {}
                Some(false) => return Deferred::Settled(item, Verdict::Reject),
                None if outstanding.contains(part) => {}
                None => outstanding.push(*part),
            }
        }
        if outstanding.is_empty() {
            return Deferred::Settled(item, Verdict::Accept);
        }
        let id = self.next;
        self.next += 1;
        for part in &outstanding {
            self.by_part.entry(*part).or_default().push(id);
        }
        self.waiters.insert(id, Waiter { item, outstanding });
        Deferred::Waits(id)
    }

    /// Settle the part `key` names. Returns every item that has its
    /// verdict now, with that verdict.
    pub fn settle(&mut self, key: VerdictKey, verdict: Verdict) -> Vec<(T, Verdict)> {
        let verdict = match verdict {
            Verdict::Defer(_) => Verdict::Ignore,
            definite => definite,
        };
        match verdict {
            Verdict::Accept => self.remember(key, true),
            Verdict::Reject => self.remember(key, false),
            Verdict::Ignore | Verdict::Defer(_) => {}
        }
        let mut done = Vec::new();
        for id in self.by_part.remove(&key).unwrap_or_default() {
            let Some(waiter) = self.waiters.get_mut(&id) else {
                continue;
            };
            waiter.outstanding.retain(|part| *part != key);
            if verdict == Verdict::Accept && !waiter.outstanding.is_empty() {
                continue;
            }
            if let Some(item) = self.release(id) {
                done.push((item, verdict.clone()));
            }
        }
        done
    }

    /// Give up on the wait `id`, if it still waits.
    pub fn expire(&mut self, id: WaitId) -> Option<T> {
        self.release(id)
    }

    /// Take the wait `id` out of every part it still waits on.
    fn release(&mut self, id: WaitId) -> Option<T> {
        let waiter = self.waiters.remove(&id)?;
        for part in &waiter.outstanding {
            if let Some(waits) = self.by_part.get_mut(part) {
                waits.retain(|wait| *wait != id);
                if waits.is_empty() {
                    self.by_part.remove(part);
                }
            }
        }
        Some(waiter.item)
    }

    fn remember(&mut self, key: VerdictKey, held: bool) {
        if self.settled.insert(key, held).is_none() {
            self.settled_order.push_back(key);
            if self.settled_order.len() > SETTLED_REMEMBERED
                && let Some(oldest) = self.settled_order.pop_front()
            {
                self.settled.remove(&oldest);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u64) -> VerdictKey {
        VerdictKey::of(&n)
    }

    fn waits<T>(deferred: &Deferred<T>) -> WaitId {
        match deferred {
            Deferred::Waits(id) => *id,
            Deferred::Settled(..) => panic!("the item waits"),
        }
    }

    #[test]
    fn a_verdict_reaches_the_item_that_waits_on_it_once() {
        let mut waiting = Waiting::default();
        let id = waits(&waiting.defer(&[key(1)], "item"));
        assert_eq!(
            waiting.settle(key(1), Verdict::Accept),
            vec![("item", Verdict::Accept)]
        );
        assert_eq!(waiting.expire(id), None, "settled items do not expire");
        assert!(waiting.settle(key(1), Verdict::Accept).is_empty());
    }

    #[test]
    fn an_item_holds_up_only_once_every_part_does() {
        let mut waiting = Waiting::default();
        waits(&waiting.defer(&[key(1), key(2)], "item"));
        assert!(waiting.settle(key(1), Verdict::Accept).is_empty());
        assert_eq!(
            waiting.settle(key(2), Verdict::Accept),
            vec![("item", Verdict::Accept)]
        );
    }

    #[test]
    fn one_false_part_refuses_the_item_at_once() {
        let mut waiting = Waiting::default();
        waits(&waiting.defer(&[key(1), key(2)], "item"));
        assert_eq!(
            waiting.settle(key(2), Verdict::Reject),
            vec![("item", Verdict::Reject)]
        );
        assert!(
            waiting.settle(key(1), Verdict::Accept).is_empty(),
            "a refused item waits on nothing more"
        );
    }

    #[test]
    fn a_part_many_items_carry_settles_them_all() {
        let mut waiting = Waiting::default();
        waits(&waiting.defer(&[key(1), key(2)], "first"));
        waits(&waiting.defer(&[key(1), key(3)], "second"));
        assert!(waiting.settle(key(1), Verdict::Accept).is_empty());
        assert_eq!(
            waiting.settle(key(3), Verdict::Accept),
            vec![("second", Verdict::Accept)]
        );
        assert_eq!(
            waiting.settle(key(2), Verdict::Ignore),
            vec![("first", Verdict::Ignore)]
        );
    }

    #[test]
    fn a_definite_verdict_that_comes_before_its_wait_is_kept_for_every_item() {
        let mut waiting = Waiting::default();
        assert!(waiting.settle(key(1), Verdict::Accept).is_empty());
        assert!(waiting.settle(key(2), Verdict::Reject).is_empty());
        assert_eq!(
            waiting.defer(&[key(1)], "item"),
            Deferred::Settled("item", Verdict::Accept)
        );
        assert_eq!(
            waiting.defer(&[key(1)], "again"),
            Deferred::Settled("again", Verdict::Accept),
            "a settlement serves every later wait"
        );
        assert_eq!(
            waiting.defer(&[key(1), key(2)], "carrier"),
            Deferred::Settled("carrier", Verdict::Reject)
        );
        let id = waits(&waiting.defer(&[key(1), key(3)], "rest"));
        assert_eq!(waiting.expire(id), Some("rest"));
    }

    #[test]
    fn a_part_this_host_could_not_judge_is_not_remembered() {
        let mut waiting = Waiting::default();
        assert!(waiting.settle(key(1), Verdict::Ignore).is_empty());
        waits(&waiting.defer(&[key(1)], "item"));
    }

    #[test]
    fn an_expired_wait_leaves_nothing_behind() {
        let mut waiting = Waiting::default();
        let id = waits(&waiting.defer(&[key(1), key(2)], "item"));
        assert_eq!(waiting.expire(id), Some("item"));
        assert!(waiting.by_part.is_empty());
        assert!(waiting.settle(key(1), Verdict::Reject).is_empty());
    }

    #[test]
    fn remembered_verdicts_are_a_bounded_window() {
        let mut waiting: Waiting<&str> = Waiting::default();
        for n in 0..(SETTLED_REMEMBERED as u64 * 3) {
            assert!(waiting.settle(key(n), Verdict::Accept).is_empty());
        }
        assert_eq!(waiting.settled.len(), SETTLED_REMEMBERED);
        waits(&waiting.defer(&[key(0)], "oldest"));
        let newest = SETTLED_REMEMBERED as u64 * 3 - 1;
        assert_eq!(
            waiting.defer(&[key(newest)], "newest"),
            Deferred::Settled("newest", Verdict::Accept)
        );
    }
}
