//! Synchronous inline dispatch for deterministic simulation.
//!
//! [`SyncDispatch`] runs all closures inline on the calling thread,
//! ensuring deterministic execution order. Queue depths are always 0.
//!
//! A dispatcher built with [`SyncDispatch::with_completion_delay`] still
//! runs each closure inline, but records the events it emits so a driver
//! can deliver them a drawn processing time later: the work a production
//! pool takes time to do is done at once and only its answer waits.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyperscale_dispatch::{Dispatch, DispatchPool, Parallelism};

/// Synchronous dispatch that runs closures inline.
///
/// Used by simulation runners for deterministic execution.
/// All work runs on the calling thread in the order dispatched.
#[derive(Clone, Default)]
pub struct SyncDispatch {
    completion: Option<Arc<CompletionDelay>>,
}

impl std::fmt::Debug for SyncDispatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncDispatch")
            .field("delays_completion", &self.completion.is_some())
            .finish()
    }
}

impl SyncDispatch {
    /// Create an inline dispatcher whose work completes at once.
    #[must_use]
    pub const fn new() -> Self {
        Self { completion: None }
    }

    /// Create an inline dispatcher whose work completes after `delay`
    /// draws a processing time for it.
    #[must_use]
    pub const fn with_completion_delay(delay: Arc<CompletionDelay>) -> Self {
        Self {
            completion: Some(delay),
        }
    }
}

impl Dispatch for SyncDispatch {
    fn spawn(&self, pool: DispatchPool, f: impl FnOnce() + Send + 'static) {
        match &self.completion {
            Some(delay) => delay.run(pool, f),
            None => f(),
        }
    }

    fn queue_depth(&self, _pool: DispatchPool) -> usize {
        0
    }

    fn parallelism(&self) -> Parallelism {
        Parallelism::Sequential
    }
}

/// How long dispatched work takes, per pool: each run draws uniformly up
/// to its pool's bound, and a rare one stalls for the tail instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessingTimes {
    /// Bound on a [`DispatchPool::Consensus`] run.
    pub consensus: Duration,
    /// Bound on a [`DispatchPool::Throughput`] run.
    pub throughput: Duration,
    /// Bound on a [`DispatchPool::Io`] run.
    pub io: Duration,
    /// Runs in a million that stall for [`Self::tail`] instead.
    pub tail_per_million: u32,
    /// How long a stalled run takes.
    pub tail: Duration,
}

impl ProcessingTimes {
    /// Work completes at once.
    pub const INSTANT: Self = Self {
        consensus: Duration::ZERO,
        throughput: Duration::ZERO,
        io: Duration::ZERO,
        tail_per_million: 0,
        tail: Duration::ZERO,
    };

    /// Whether any run can take time.
    #[must_use]
    pub fn takes_time(&self) -> bool {
        *self != Self::INSTANT
    }

    const fn bound(&self, pool: DispatchPool) -> Duration {
        match pool {
            DispatchPool::Consensus => self.consensus,
            DispatchPool::Throughput => self.throughput,
            DispatchPool::Io => self.io,
        }
    }
}

/// The processing times of dispatched work, as spans of a host's event
/// stream.
///
/// A run is bracketed by the stream's send position before and after it,
/// so the events it emitted are exactly the ones between, and they are
/// due the run's drawn time after the driver drains them. A run nested in
/// another is processed within it, so an event inside both waits for the
/// sum.
pub struct CompletionDelay {
    times: ProcessingTimes,
    /// The index the next event sent on the host's stream will take.
    position: Box<dyn Fn() -> u64 + Send + Sync>,
    state: Mutex<DelayState>,
}

struct DelayState {
    rng: u64,
    spans: Vec<Span>,
}

struct Span {
    start: u64,
    end: u64,
    delay: Duration,
}

impl CompletionDelay {
    /// Delay the work of a host whose event stream reports its send
    /// position through `position`, drawing from `seed`.
    pub fn new(
        times: ProcessingTimes,
        seed: u64,
        position: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Self {
        Self {
            times,
            position: Box::new(position),
            state: Mutex::new(DelayState {
                rng: seed,
                spans: Vec::new(),
            }),
        }
    }

    fn run(&self, pool: DispatchPool, f: impl FnOnce()) {
        let delay = self.draw(pool);
        let start = (self.position)();
        f();
        let end = (self.position)();
        if end > start && delay > Duration::ZERO {
            self.state
                .lock()
                .expect("completion delay lock")
                .spans
                .push(Span { start, end, delay });
        }
    }

    fn draw(&self, pool: DispatchPool) -> Duration {
        let mut state = self.state.lock().expect("completion delay lock");
        let roll = splitmix(&mut state.rng);
        if self.times.tail_per_million > 0
            && roll % 1_000_000 < u64::from(self.times.tail_per_million)
        {
            return self.times.tail;
        }
        let bound = self.times.bound(pool);
        let nanos = u64::try_from(bound.as_nanos()).unwrap_or(u64::MAX);
        if nanos == 0 {
            return Duration::ZERO;
        }
        Duration::from_nanos(splitmix(&mut state.rng) % (nanos + 1))
    }

    /// How long after it is drained the event at `index` is due. Indices
    /// are asked in the order the stream was sent, so spans wholly behind
    /// `index` are dropped.
    ///
    /// # Panics
    ///
    /// Panics if a run panicked while holding the delay's lock.
    pub fn due_after(&self, index: u64) -> Duration {
        let mut state = self.state.lock().expect("completion delay lock");
        state.spans.retain(|span| span.end > index);
        state
            .spans
            .iter()
            .filter(|span| span.start <= index)
            .map(|span| span.delay)
            .sum()
    }
}

const fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn test_sync_dispatch_runs_inline() {
        let dispatch = SyncDispatch::new();
        let counter = Arc::new(AtomicUsize::new(0));

        for pool in [DispatchPool::Consensus, DispatchPool::Throughput] {
            let c = counter.clone();
            dispatch.spawn(pool, move || {
                c.fetch_add(1, Ordering::SeqCst);
            });
        }
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_queue_depths_always_zero() {
        let dispatch = SyncDispatch::new();
        for pool in [
            DispatchPool::Consensus,
            DispatchPool::Throughput,
            DispatchPool::Io,
        ] {
            assert_eq!(dispatch.queue_depth(pool), 0);
        }
    }

    /// A stream of events a test sends by bumping the position.
    fn stream() -> Arc<AtomicU64> {
        Arc::new(AtomicU64::new(0))
    }

    fn delaying(times: ProcessingTimes, sent: &Arc<AtomicU64>) -> Arc<CompletionDelay> {
        let sent = Arc::clone(sent);
        Arc::new(CompletionDelay::new(times, 7, move || {
            sent.load(Ordering::SeqCst)
        }))
    }

    const FIXED: ProcessingTimes = ProcessingTimes {
        consensus: Duration::from_millis(5),
        throughput: Duration::ZERO,
        io: Duration::ZERO,
        tail_per_million: 1_000_000,
        tail: Duration::from_millis(5),
    };

    /// Work still runs at once, but only what it sent waits: an event
    /// sent outside any run is due when drained.
    #[test]
    fn only_the_events_a_run_sends_wait_its_processing_time() {
        let sent = stream();
        let delay = delaying(FIXED, &sent);
        let dispatch = SyncDispatch::with_completion_delay(Arc::clone(&delay));

        sent.fetch_add(1, Ordering::SeqCst);
        let ran = Arc::new(AtomicUsize::new(0));
        let (in_run, stream_in_run) = (Arc::clone(&ran), Arc::clone(&sent));
        dispatch.spawn(DispatchPool::Consensus, move || {
            in_run.fetch_add(1, Ordering::SeqCst);
            stream_in_run.fetch_add(2, Ordering::SeqCst);
        });
        assert_eq!(ran.load(Ordering::SeqCst), 1, "the run happened inline");
        sent.fetch_add(1, Ordering::SeqCst);

        assert_eq!(delay.due_after(0), Duration::ZERO);
        assert_eq!(delay.due_after(1), Duration::from_millis(5));
        assert_eq!(delay.due_after(2), Duration::from_millis(5));
        assert_eq!(delay.due_after(3), Duration::ZERO);
    }

    /// A run nested in another is processed inside it, so what it sends
    /// waits for both.
    #[test]
    fn a_nested_run_waits_for_both() {
        let sent = stream();
        let delay = delaying(FIXED, &sent);
        let dispatch = SyncDispatch::with_completion_delay(Arc::clone(&delay));

        let (outer_stream, inner_dispatch) = (Arc::clone(&sent), dispatch.clone());
        dispatch.spawn(DispatchPool::Consensus, move || {
            outer_stream.fetch_add(1, Ordering::SeqCst);
            let inner_stream = Arc::clone(&outer_stream);
            inner_dispatch.spawn(DispatchPool::Consensus, move || {
                inner_stream.fetch_add(1, Ordering::SeqCst);
            });
        });

        assert_eq!(delay.due_after(0), Duration::from_millis(5));
        assert_eq!(delay.due_after(1), Duration::from_millis(10));
    }

    /// Instant times take no span at all.
    #[test]
    fn instant_work_completes_when_drained() {
        let sent = stream();
        let delay = delaying(ProcessingTimes::INSTANT, &sent);
        let dispatch = SyncDispatch::with_completion_delay(Arc::clone(&delay));
        let stream_in_run = Arc::clone(&sent);
        dispatch.spawn(DispatchPool::Throughput, move || {
            stream_in_run.fetch_add(1, Ordering::SeqCst);
        });
        assert!(!ProcessingTimes::INSTANT.takes_time());
        assert_eq!(delay.due_after(0), Duration::ZERO);
    }
}
