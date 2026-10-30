//! One producer per key, a bounded cache of what producers made, and a
//! bounded wait for everyone else asking the same key meanwhile.

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

/// What one production publishes to the callers waiting on it. `None`
/// while it runs; `Some(None)` once it ends having made nothing, a panic
/// included.
type Waiter<V> = Arc<(Mutex<Option<Option<V>>>, Condvar)>;

struct Slot<V> {
    waiter: Waiter<V>,
    waiters: usize,
}

struct State<K, V> {
    cache: BTreeMap<K, V>,
    in_flight: BTreeMap<K, Slot<V>>,
}

/// Collapses concurrent requests for the same key into one production.
///
/// The first caller for a key not in the cache produces; callers arriving
/// while it runs wait on its answer, up to `max_waiters` of them and for at
/// most `wait_budget` each. A produced value is cached, and the cache keeps
/// the `cache_capacity` greatest keys.
pub struct SingleFlight<K, V> {
    state: Arc<Mutex<State<K, V>>>,
    cache_capacity: usize,
    max_waiters: usize,
    wait_budget: Duration,
}

/// How a [`SingleFlight::get_or_produce`] call was answered.
#[derive(Debug, PartialEq, Eq)]
pub enum Flight<V> {
    /// From the cache, without waiting.
    Cached(V),
    /// From another caller's production, waited on.
    Joined(V),
    /// By this caller's own production.
    Produced(V),
    /// Not at all: the production made nothing, the wait ran out, or the
    /// key already had `max_waiters` callers waiting.
    Unavailable,
}

impl<K: Ord + Copy, V: Clone> SingleFlight<K, V> {
    pub fn new(cache_capacity: usize, max_waiters: usize, wait_budget: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                cache: BTreeMap::new(),
                in_flight: BTreeMap::new(),
            })),
            cache_capacity,
            max_waiters,
            wait_budget,
        }
    }

    /// Answer `key` from the cache, from a production already running for
    /// it, or by running `produce` here.
    ///
    /// The cache check, the join and the producer's reservation share one
    /// critical section, so at most one production runs per key.
    pub fn get_or_produce(&self, key: K, produce: impl FnOnce() -> Option<V>) -> Flight<V> {
        let mut state = lock(&self.state);
        if let Some(cached) = state.cache.get(&key) {
            return Flight::Cached(cached.clone());
        }
        if let Some(slot) = state.in_flight.get_mut(&key) {
            if slot.waiters >= self.max_waiters {
                return Flight::Unavailable;
            }
            slot.waiters += 1;
            let waiter = Arc::clone(&slot.waiter);
            drop(state);
            return self.join(key, &waiter);
        }
        let waiter: Waiter<V> = Arc::new((Mutex::new(None), Condvar::new()));
        state.in_flight.insert(
            key,
            Slot {
                waiter: Arc::clone(&waiter),
                waiters: 0,
            },
        );
        drop(state);
        self.produce(key, waiter, produce)
    }

    fn produce(&self, key: K, waiter: Waiter<V>, produce: impl FnOnce() -> Option<V>) -> Flight<V> {
        let guard = InFlightGuard {
            state: Arc::clone(&self.state),
            waiter,
            key,
        };
        let Some(value) = produce() else {
            return Flight::Unavailable;
        };
        {
            let mut state = lock(&self.state);
            state.cache.insert(key, value.clone());
            if state.cache.len() > self.cache_capacity {
                state.cache.pop_first();
            }
        }
        *lock(&guard.waiter.0) = Some(Some(value.clone()));
        Flight::Produced(value)
    }

    fn join(&self, key: K, waiter: &Waiter<V>) -> Flight<V> {
        let (answer, cvar) = &**waiter;
        let answer = {
            let (answer, _) = cvar
                .wait_timeout_while(lock(answer), self.wait_budget, |answer| answer.is_none())
                .unwrap_or_else(PoisonError::into_inner);
            answer.clone().flatten()
        };
        // The producer's guard may already have cleared the slot, and a
        // later producer may hold the key by now: only the slot this call
        // joined is the one to leave.
        if let Some(slot) = lock(&self.state).in_flight.get_mut(&key)
            && Arc::ptr_eq(&slot.waiter, waiter)
        {
            slot.waiters = slot.waiters.saturating_sub(1);
        }
        answer.map_or(Flight::Unavailable, Flight::Joined)
    }
}

/// A production's hold on its key. Dropped on every exit from the
/// production, a panicking one included, it clears the key's slot if the
/// slot is still this production's, ends the production for its waiters
/// if it published nothing, and wakes them.
struct InFlightGuard<K: Ord, V> {
    state: Arc<Mutex<State<K, V>>>,
    waiter: Waiter<V>,
    key: K,
}

impl<K: Ord, V> Drop for InFlightGuard<K, V> {
    fn drop(&mut self) {
        {
            let mut state = lock(&self.state);
            if state
                .in_flight
                .get(&self.key)
                .is_some_and(|slot| Arc::ptr_eq(&slot.waiter, &self.waiter))
            {
                state.in_flight.remove(&self.key);
            }
        }
        lock(&self.waiter.0).get_or_insert(None);
        self.waiter.1.notify_all();
    }
}

/// Every critical section here leaves its data whole, so a lock a panic
/// poisoned is still sound to take.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Barrier, mpsc};
    use std::thread;

    use super::*;

    const BUDGET: Duration = Duration::from_secs(5);

    #[test]
    fn concurrent_callers_for_one_key_produce_once() {
        const CALLERS: usize = 16;
        let flight = Arc::new(SingleFlight::<u64, u64>::new(8, CALLERS, BUDGET));
        let productions = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(Barrier::new(CALLERS));
        let mut callers = Vec::with_capacity(CALLERS);
        for _ in 0..CALLERS {
            let flight = Arc::clone(&flight);
            let productions = Arc::clone(&productions);
            let start = Arc::clone(&start);
            callers.push(thread::spawn(move || {
                start.wait();
                flight.get_or_produce(7, || {
                    productions.fetch_add(1, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(50));
                    Some(42)
                })
            }));
        }
        let flights: Vec<_> = callers
            .into_iter()
            .map(|caller| caller.join().expect("caller"))
            .collect();

        assert_eq!(productions.load(Ordering::SeqCst), 1);
        assert_eq!(
            flights
                .iter()
                .filter(|flight| **flight == Flight::Produced(42))
                .count(),
            1
        );
        assert!(
            flights
                .iter()
                .all(|flight| matches!(flight, Flight::Produced(42) | Flight::Joined(42)))
        );
        assert_eq!(flight.get_or_produce(7, || None), Flight::Cached(42));
    }

    #[test]
    fn a_production_that_makes_nothing_releases_its_waiters_at_once() {
        let flight = Arc::new(SingleFlight::<u64, u64>::new(8, 4, BUDGET));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let producer = {
            let flight = Arc::clone(&flight);
            thread::spawn(move || {
                flight.get_or_produce(1, || {
                    started_tx.send(()).expect("started");
                    release_rx.recv().expect("release");
                    None
                })
            })
        };
        started_rx.recv().expect("producer started");
        let waiter = {
            let flight = Arc::clone(&flight);
            thread::spawn(move || flight.get_or_produce(1, || panic!("the key is in flight")))
        };
        while lock(&flight.state).in_flight[&1].waiters == 0 {
            thread::yield_now();
        }
        let released = std::time::Instant::now();
        release_tx.send(()).expect("release");

        assert_eq!(producer.join().expect("producer"), Flight::Unavailable);
        assert_eq!(waiter.join().expect("waiter"), Flight::Unavailable);
        assert!(released.elapsed() < BUDGET);
        assert!(lock(&flight.state).in_flight.is_empty());
        assert_eq!(flight.get_or_produce(1, || Some(3)), Flight::Produced(3));
    }

    #[test]
    fn a_guard_leaves_a_slot_it_does_not_hold() {
        let flight = SingleFlight::<u64, u64>::new(8, 4, BUDGET);
        let abandoned: Waiter<u64> = Arc::new((Mutex::new(None), Condvar::new()));
        let held: Waiter<u64> = Arc::new((Mutex::new(None), Condvar::new()));
        lock(&flight.state).in_flight.insert(
            5,
            Slot {
                waiter: Arc::clone(&held),
                waiters: 0,
            },
        );

        drop(InFlightGuard {
            state: Arc::clone(&flight.state),
            waiter: abandoned,
            key: 5,
        });

        assert!(Arc::ptr_eq(
            &lock(&flight.state).in_flight[&5].waiter,
            &held
        ));
    }

    #[test]
    fn waiters_past_the_cap_are_turned_away() {
        let flight = Arc::new(SingleFlight::<u64, u64>::new(8, 0, BUDGET));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let producer = {
            let flight = Arc::clone(&flight);
            thread::spawn(move || {
                flight.get_or_produce(1, || {
                    started_tx.send(()).expect("started");
                    release_rx.recv().expect("release");
                    Some(9)
                })
            })
        };
        started_rx.recv().expect("producer started");

        assert_eq!(
            flight.get_or_produce(1, || panic!("the key is in flight")),
            Flight::Unavailable
        );
        release_tx.send(()).expect("release");
        assert_eq!(producer.join().expect("producer"), Flight::Produced(9));
    }

    #[test]
    fn the_cache_keeps_the_greatest_keys() {
        let flight = SingleFlight::<u64, u64>::new(2, 4, BUDGET);
        for key in [3, 1, 2] {
            assert_eq!(
                flight.get_or_produce(key, || Some(key)),
                Flight::Produced(key)
            );
        }
        assert_eq!(flight.get_or_produce(2, || None), Flight::Cached(2));
        assert_eq!(flight.get_or_produce(3, || None), Flight::Cached(3));
        assert_eq!(flight.get_or_produce(1, || None), Flight::Unavailable);
    }
}
