//! One producer per key, a byte-budgeted cache of what producers made,
//! and a bounded wait for everyone else asking the same key meanwhile.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// What one production publishes to the callers waiting on it. `None`
/// while it runs; `Some(None)` once it ends without making the key, a
/// panic included, and the callers waiting ask for it again.
type Waiter<V> = Arc<(Mutex<Option<Option<V>>>, Condvar)>;

/// Keys beside the production each is answered by.
type Held<K, V> = Vec<(K, Waiter<V>)>;

/// What a joined production published by the joiner's deadline.
enum Published<V> {
    Made(V),
    /// It ended without making the key, and the joiner asks again.
    Unmade,
    /// It was still running.
    Late,
}

struct Slot<V> {
    waiter: Waiter<V>,
    waiters: usize,
}

struct State<K, V> {
    /// Each value beside the bytes it was charged.
    cache: BTreeMap<K, (V, usize)>,
    cached_bytes: usize,
    in_flight: BTreeMap<K, Slot<V>>,
}

/// Collapses concurrent requests for the same key into one production.
///
/// A caller names any number of keys. Those cached are answered at once;
/// those another caller is producing are waited on, up to `max_waiters`
/// callers per key and for at most `wait_budget` in all; the rest this
/// caller produces in one go. A produced value is cached at the weight
/// `weigh` gives it, and the cache keeps the greatest keys whose weights
/// fit `cache_bytes`: past the budget the least keys are evicted, and one
/// value heavier than the whole budget is answered but never kept.
pub struct SingleFlight<K, V> {
    state: Arc<Mutex<State<K, V>>>,
    cache_bytes: usize,
    weigh: fn(&V) -> usize,
    max_waiters: usize,
    wait_budget: Duration,
}

/// How one key of a [`SingleFlight::get_or_produce`] call was answered.
#[derive(Debug, PartialEq, Eq)]
pub enum Flight<V> {
    /// From the cache, without waiting.
    Cached(V),
    /// From another caller's production, waited on.
    Joined(V),
    /// By this caller's own production.
    Produced(V),
    /// Not at all: this caller's own production left it out, the wait
    /// ran out, or the key already had `max_waiters` callers waiting.
    Unavailable,
}

impl<V> Flight<V> {
    /// The value, however it was come by.
    pub fn value(self) -> Option<V> {
        match self {
            Self::Cached(value) | Self::Joined(value) | Self::Produced(value) => Some(value),
            Self::Unavailable => None,
        }
    }
}

impl<K: Ord + Copy, V: Clone> SingleFlight<K, V> {
    pub fn new(
        cache_bytes: usize,
        weigh: fn(&V) -> usize,
        max_waiters: usize,
        wait_budget: Duration,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                cache: BTreeMap::new(),
                cached_bytes: 0,
                in_flight: BTreeMap::new(),
            })),
            cache_bytes,
            weigh,
            max_waiters,
            wait_budget,
        }
    }

    /// Answer each of `keys` from the cache, from a production already
    /// running for it, or by running `produce` here over the keys nobody
    /// holds, handed to it in ascending order. `produce` returns a value
    /// for each key it made. A key it leaves out was not made: it is
    /// unavailable to this caller, and a caller that was waiting on it
    /// asks for it again, producing it itself if nobody has taken it up
    /// meanwhile, while its wait budget lasts. `produce` runs once per
    /// such round.
    ///
    /// The cache checks, the joins and the producer's reservations share
    /// one critical section, so at most one production runs per key. This
    /// caller produces before it waits on anyone else's.
    pub fn get_or_produce(
        &self,
        keys: &[K],
        mut produce: impl FnMut(&[K]) -> Vec<(K, V)>,
    ) -> Vec<(K, Flight<V>)> {
        let mut answers: BTreeMap<K, Flight<V>> = BTreeMap::new();
        // A key named twice would otherwise wait on its own production.
        let mut seen = BTreeSet::new();
        let mut asking: Vec<K> = keys
            .iter()
            .copied()
            .filter(|key| seen.insert(*key))
            .collect();
        let mut deadline = None;
        while !asking.is_empty() {
            let (own, joins) = self.reserve(&asking, &mut answers);
            if !own.is_empty() {
                answers.extend(self.produce(own, &mut produce));
            }
            let deadline = *deadline.get_or_insert_with(|| Instant::now() + self.wait_budget);
            asking.clear();
            for (key, waiter) in joins {
                match self.join(key, &waiter, deadline) {
                    Published::Made(value) => {
                        answers.insert(key, Flight::Joined(value));
                    }
                    Published::Unmade if Instant::now() < deadline => asking.push(key),
                    Published::Unmade | Published::Late => {
                        answers.insert(key, Flight::Unavailable);
                    }
                }
            }
        }
        keys.iter()
            .filter_map(|key| answers.remove(key).map(|flight| (*key, flight)))
            .collect()
    }

    /// Answer each of `keys` from the cache or turn it away, and split the
    /// rest into those this caller now produces and those it joins.
    fn reserve(
        &self,
        keys: &[K],
        answers: &mut BTreeMap<K, Flight<V>>,
    ) -> (Held<K, V>, Held<K, V>) {
        let mut joins = Vec::new();
        let mut own = Vec::new();
        let mut state = lock(&self.state);
        for &key in keys {
            if let Some((cached, _)) = state.cache.get(&key) {
                answers.insert(key, Flight::Cached(cached.clone()));
            } else if let Some(slot) = state.in_flight.get_mut(&key) {
                if slot.waiters >= self.max_waiters {
                    answers.insert(key, Flight::Unavailable);
                } else {
                    slot.waiters += 1;
                    joins.push((key, Arc::clone(&slot.waiter)));
                }
            } else {
                let waiter: Waiter<V> = Arc::new((Mutex::new(None), Condvar::new()));
                state.in_flight.insert(
                    key,
                    Slot {
                        waiter: Arc::clone(&waiter),
                        waiters: 0,
                    },
                );
                own.push((key, waiter));
            }
        }
        drop(state);
        (own, joins)
    }

    fn produce(
        &self,
        own: Held<K, V>,
        produce: &mut impl FnMut(&[K]) -> Vec<(K, V)>,
    ) -> Vec<(K, Flight<V>)> {
        let mut keys: Vec<K> = own.iter().map(|(key, _)| *key).collect();
        keys.sort_unstable();
        let guards: Vec<InFlightGuard<K, V>> = own
            .into_iter()
            .map(|(key, waiter)| InFlightGuard {
                state: Arc::clone(&self.state),
                waiter,
                key,
            })
            .collect();
        let mut made: BTreeMap<K, V> = produce(&keys)
            .into_iter()
            .filter(|(key, _)| keys.binary_search(key).is_ok())
            .collect();
        {
            let mut state = lock(&self.state);
            for (key, value) in &made {
                self.keep(&mut state, *key, value.clone());
            }
        }
        guards
            .into_iter()
            .map(|guard| {
                let key = guard.key;
                let flight = made.remove(&key).map_or(Flight::Unavailable, |value| {
                    *lock(&guard.waiter.0) = Some(Some(value.clone()));
                    Flight::Produced(value)
                });
                (key, flight)
            })
            .collect()
    }

    /// Cache `value` under `key`, then evict the least keys until the
    /// cache is back within its budget. A value heavier than the whole
    /// budget is not kept, and evicts nothing.
    fn keep(&self, state: &mut State<K, V>, key: K, value: V) {
        let weight = (self.weigh)(&value);
        if weight > self.cache_bytes {
            return;
        }
        if let Some((_, replaced)) = state.cache.insert(key, (value, weight)) {
            state.cached_bytes -= replaced;
        }
        state.cached_bytes += weight;
        while state.cached_bytes > self.cache_bytes {
            let Some((_, (_, evicted))) = state.cache.pop_first() else {
                break;
            };
            state.cached_bytes -= evicted;
        }
    }

    /// How many callers are waiting on the production running for `key`.
    #[cfg(test)]
    pub fn waiting(&self, key: &K) -> usize {
        lock(&self.state)
            .in_flight
            .get(key)
            .map_or(0, |slot| slot.waiters)
    }

    /// What the production `waiter` names published for `key` by
    /// `deadline`.
    fn join(&self, key: K, waiter: &Waiter<V>, deadline: Instant) -> Published<V> {
        let (answer, cvar) = &**waiter;
        let answer = {
            let left = deadline.saturating_duration_since(Instant::now());
            let (answer, _) = cvar
                .wait_timeout_while(lock(answer), left, |answer| answer.is_none())
                .unwrap_or_else(PoisonError::into_inner);
            match answer.clone() {
                Some(Some(value)) => Published::Made(value),
                Some(None) => Published::Unmade,
                None => Published::Late,
            }
        };
        // The producer's guard may already have cleared the slot, and a
        // later producer may hold the key by now: only the slot this call
        // joined is the one to leave.
        if let Some(slot) = lock(&self.state).in_flight.get_mut(&key)
            && Arc::ptr_eq(&slot.waiter, waiter)
        {
            slot.waiters = slot.waiters.saturating_sub(1);
        }
        answer
    }
}

/// A production's hold on one key. Dropped on every exit from the
/// production, a panicking one included, it clears the key's slot if the
/// slot is still this production's, ends the production for its waiters
/// if it published nothing, so they ask again, and wakes them.
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

    /// A flight whose every value weighs what it says.
    fn flight(cache_bytes: usize, max_waiters: usize) -> SingleFlight<u64, u64> {
        SingleFlight::new(
            cache_bytes,
            |value| usize::try_from(*value).expect("a test weight"),
            max_waiters,
            BUDGET,
        )
    }

    /// Ask for `key` alone, producing `value` if it falls to this caller.
    fn one(flight: &SingleFlight<u64, u64>, key: u64, value: Option<u64>) -> Flight<u64> {
        let mut answers =
            flight.get_or_produce(&[key], |_| value.map(|v| (key, v)).into_iter().collect());
        assert_eq!(answers.len(), 1);
        answers.pop().expect("one key asked").1
    }

    #[test]
    fn concurrent_callers_for_one_key_produce_once() {
        const CALLERS: usize = 16;
        let flight = Arc::new(flight(64, CALLERS));
        let productions = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(Barrier::new(CALLERS));
        let mut callers = Vec::with_capacity(CALLERS);
        for _ in 0..CALLERS {
            let flight = Arc::clone(&flight);
            let productions = Arc::clone(&productions);
            let start = Arc::clone(&start);
            callers.push(thread::spawn(move || {
                start.wait();
                flight
                    .get_or_produce(&[7], |_| {
                        productions.fetch_add(1, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(50));
                        vec![(7, 42)]
                    })
                    .pop()
                    .expect("one key asked")
                    .1
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
        assert_eq!(one(&flight, 7, None), Flight::Cached(42));
    }

    /// A caller naming several keys produces only those nobody holds,
    /// joins the one another caller is producing, and answers the cached
    /// one at once.
    #[test]
    fn a_caller_produces_only_the_keys_nobody_holds() {
        let flight = Arc::new(flight(64, 4));
        assert_eq!(one(&flight, 1, Some(1)), Flight::Produced(1));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let producer = {
            let flight = Arc::clone(&flight);
            thread::spawn(move || {
                flight.get_or_produce(&[2], |_| {
                    started_tx.send(()).expect("started");
                    release_rx.recv().expect("release");
                    vec![(2, 2)]
                })
            })
        };
        started_rx.recv().expect("producer started");
        let caller = {
            let flight = Arc::clone(&flight);
            thread::spawn(move || {
                flight.get_or_produce(&[1, 2, 3], |keys| {
                    assert_eq!(keys, [3], "only the key nobody holds");
                    vec![(3, 3)]
                })
            })
        };
        while lock(&flight.state).in_flight[&2].waiters == 0 {
            thread::yield_now();
        }
        release_tx.send(()).expect("release");
        producer.join().expect("producer");
        assert_eq!(
            caller.join().expect("caller"),
            vec![
                (1, Flight::Cached(1)),
                (2, Flight::Joined(2)),
                (3, Flight::Produced(3)),
            ]
        );
    }

    /// A key the production leaves out was not made, not found to have
    /// no value: the caller waiting on it produces it itself.
    #[test]
    fn a_waiter_produces_what_the_production_left_out() {
        let flight = Arc::new(flight(64, 4));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let producer = {
            let flight = Arc::clone(&flight);
            thread::spawn(move || {
                flight.get_or_produce(&[1, 2], |_| {
                    started_tx.send(()).expect("started");
                    release_rx.recv().expect("release");
                    vec![(1, 1)]
                })
            })
        };
        started_rx.recv().expect("producer started");
        let waiter = {
            let flight = Arc::clone(&flight);
            thread::spawn(move || {
                flight.get_or_produce(&[1, 2], |keys| {
                    assert_eq!(keys, [2], "only the key left out");
                    vec![(2, 2)]
                })
            })
        };
        while flight.waiting(&2) == 0 {
            thread::yield_now();
        }
        let released = Instant::now();
        release_tx.send(()).expect("release");

        assert_eq!(
            producer.join().expect("producer"),
            vec![(1, Flight::Produced(1)), (2, Flight::Unavailable)]
        );
        assert_eq!(
            waiter.join().expect("waiter"),
            vec![(1, Flight::Joined(1)), (2, Flight::Produced(2))]
        );
        assert!(released.elapsed() < BUDGET);
        assert!(lock(&flight.state).in_flight.is_empty());
        assert_eq!(one(&flight, 2, None), Flight::Cached(2));
    }

    /// A production that panics with callers waiting on several of its
    /// keys releases every one of them, and the waiter produces them all
    /// itself.
    #[test]
    fn a_panicking_production_releases_every_key_it_held() {
        let flight = Arc::new(flight(64, 4));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let producer = {
            let flight = Arc::clone(&flight);
            thread::spawn(move || {
                flight.get_or_produce(&[1, 2, 3], |_| {
                    started_tx.send(()).expect("started");
                    release_rx.recv().expect("release");
                    panic!("the production fails");
                })
            })
        };
        started_rx.recv().expect("producer started");
        let waiter = {
            let flight = Arc::clone(&flight);
            thread::spawn(move || {
                flight.get_or_produce(&[1, 2, 3], |keys| {
                    assert_eq!(keys, [1, 2, 3], "every key the panic left");
                    keys.iter().map(|key| (*key, *key)).collect()
                })
            })
        };
        while [1, 2, 3].iter().any(|key| flight.waiting(key) == 0) {
            thread::yield_now();
        }
        release_tx.send(()).expect("release");

        assert!(producer.join().is_err(), "the producer panicked");
        assert_eq!(
            waiter.join().expect("waiter"),
            vec![
                (1, Flight::Produced(1)),
                (2, Flight::Produced(2)),
                (3, Flight::Produced(3)),
            ]
        );
        assert!(lock(&flight.state).in_flight.is_empty());
    }

    /// A key named twice in one call is produced once and answered once,
    /// without the call waiting on its own production.
    #[test]
    fn a_key_named_twice_is_answered_once() {
        let flight = flight(64, 4);
        let started = Instant::now();
        assert_eq!(
            flight.get_or_produce(&[1, 2, 1], |keys| {
                assert_eq!(keys, [1, 2]);
                vec![(1, 1), (2, 2)]
            }),
            vec![(1, Flight::Produced(1)), (2, Flight::Produced(2))]
        );
        assert!(started.elapsed() < BUDGET, "it never waits on itself");
        assert!(lock(&flight.state).in_flight.is_empty());
    }

    #[test]
    fn a_guard_leaves_a_slot_it_does_not_hold() {
        let flight = flight(64, 4);
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
        let flight = Arc::new(flight(64, 0));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let producer = {
            let flight = Arc::clone(&flight);
            thread::spawn(move || {
                flight.get_or_produce(&[1], |_| {
                    started_tx.send(()).expect("started");
                    release_rx.recv().expect("release");
                    vec![(1, 9)]
                })
            })
        };
        started_rx.recv().expect("producer started");

        assert_eq!(
            flight.get_or_produce(&[1], |_| panic!("the key is in flight")),
            vec![(1, Flight::Unavailable)]
        );
        release_tx.send(()).expect("release");
        assert_eq!(
            producer.join().expect("producer"),
            vec![(1, Flight::Produced(9))]
        );
    }

    /// Filled to its byte budget, the cache makes room for a greater key
    /// by evicting the least, and an evicted key is produced again when
    /// next asked. A value heavier than the whole budget is answered and
    /// not kept.
    #[test]
    fn the_cache_keeps_the_greatest_keys_within_its_bytes() {
        let flight = flight(30, 4);
        for key in [3, 1, 2] {
            assert_eq!(one(&flight, key, Some(10)), Flight::Produced(10));
        }
        assert_eq!(lock(&flight.state).cached_bytes, 30, "filled to the budget");

        assert_eq!(one(&flight, 4, Some(10)), Flight::Produced(10));
        assert_eq!(
            one(&flight, 1, None),
            Flight::Unavailable,
            "the least key went"
        );
        for key in [2, 3, 4] {
            assert_eq!(one(&flight, key, None), Flight::Cached(10));
        }
        assert_eq!(lock(&flight.state).cached_bytes, 30);

        assert_eq!(
            one(&flight, 1, Some(10)),
            Flight::Produced(10),
            "asked again"
        );

        assert_eq!(one(&flight, 9, Some(31)), Flight::Produced(31));
        assert_eq!(
            one(&flight, 9, None),
            Flight::Unavailable,
            "too heavy to keep"
        );
        for key in [2, 3, 4] {
            assert_eq!(
                one(&flight, key, None),
                Flight::Cached(10),
                "and it evicts nothing"
            );
        }
    }

    thread_local! {
        static COMPARED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// A key that counts how often it is compared.
    #[derive(Clone, Copy, Debug)]
    struct Counted(u32);

    impl PartialEq for Counted {
        fn eq(&self, other: &Self) -> bool {
            self.cmp(other).is_eq()
        }
    }

    impl Eq for Counted {}

    impl PartialOrd for Counted {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for Counted {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            COMPARED.with(|compared| compared.set(compared.get() + 1));
            self.0.cmp(&other.0)
        }
    }

    /// Producing many keys at once costs comparisons in proportion to
    /// `n log n`, not to `n²`.
    #[test]
    fn producing_many_keys_compares_them_a_logarithmic_number_of_times() {
        const KEYS: u32 = 4096;
        let flight: SingleFlight<Counted, u32> = SingleFlight::new(1 << 20, |_| 1, 4, BUDGET);
        let keys: Vec<Counted> = (0..KEYS).map(Counted).collect();
        COMPARED.with(|compared| compared.set(0));

        let answers =
            flight.get_or_produce(&keys, |own| own.iter().map(|key| (*key, key.0)).collect());

        assert_eq!(answers.len(), KEYS as usize);
        let compared = COMPARED.with(std::cell::Cell::get);
        assert!(
            compared < 32 * (KEYS * KEYS.ilog2()) as usize,
            "{compared} comparisons for {KEYS} keys",
        );
    }
}
