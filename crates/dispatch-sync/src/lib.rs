//! Synchronous inline dispatch for deterministic simulation.
//!
//! [`SyncDispatch`] runs all closures inline on the calling thread,
//! ensuring deterministic execution order. Queue depths are always 0.
//!
//! A dispatcher built with [`SyncDispatch::with_completion_delay`] still
//! runs each closure inline, but records the events it emits so a driver
//! can deliver them a drawn processing time later: the work a production
//! pool takes time to do is done at once and only its answer waits.
//!
//! A dispatcher built with [`SyncDispatch::deferred`] runs nothing at
//! spawn: it queues each closure with a drawn processing time on
//! [`DeferredJobs`], and the driver runs it when that time comes, so the
//! work reads the state it finds then.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyperscale_dispatch::{Dispatch, DispatchPool, Parallelism};

/// Synchronous dispatch that runs closures inline.
///
/// Used by simulation runners for deterministic execution.
/// All work runs on the calling thread in the order dispatched.
#[derive(Clone, Default)]
pub struct SyncDispatch {
    mode: Mode,
}

#[derive(Clone, Default)]
enum Mode {
    #[default]
    Inline,
    Delayed(Arc<CompletionDelay>),
    Deferred(Arc<DeferredJobs>),
}

impl std::fmt::Debug for SyncDispatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mode = match self.mode {
            Mode::Inline => "inline",
            Mode::Delayed(_) => "delayed",
            Mode::Deferred(_) => "deferred",
        };
        f.debug_struct("SyncDispatch").field("mode", &mode).finish()
    }
}

impl SyncDispatch {
    /// Create an inline dispatcher whose work completes at once.
    #[must_use]
    pub const fn new() -> Self {
        Self { mode: Mode::Inline }
    }

    /// Create an inline dispatcher whose work completes after `delay`
    /// draws a processing time for it.
    #[must_use]
    pub const fn with_completion_delay(delay: Arc<CompletionDelay>) -> Self {
        Self {
            mode: Mode::Delayed(delay),
        }
    }

    /// Create a dispatcher that queues every closure on `jobs` for the
    /// driver to run once its processing time has passed.
    #[must_use]
    pub const fn deferred(jobs: Arc<DeferredJobs>) -> Self {
        Self {
            mode: Mode::Deferred(jobs),
        }
    }
}

impl Dispatch for SyncDispatch {
    fn spawn(&self, pool: DispatchPool, f: impl FnOnce() + Send + 'static) {
        match &self.mode {
            Mode::Inline => f(),
            Mode::Delayed(delay) => delay.run(pool, f),
            Mode::Deferred(jobs) => jobs.push(pool, Box::new(f)),
        }
    }

    fn queue_depth(&self, _pool: DispatchPool) -> usize {
        0
    }

    fn parallelism(&self) -> Parallelism {
        Parallelism::Sequential
    }
}

/// How long dispatched work takes, per pool.
///
/// Each run draws uniformly between half its pool's bound and the bound,
/// and a rare one stalls for the tail instead. Work of one kind costs much
/// the same each time — a signature check is a signature check — so no
/// run is free.
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

    /// One run's processing time on `pool`, drawn from `rng`.
    fn draw(&self, pool: DispatchPool, rng: &mut u64) -> Duration {
        let roll = splitmix(rng);
        if self.tail_per_million > 0 && roll % 1_000_000 < u64::from(self.tail_per_million) {
            return self.tail;
        }
        let nanos = u64::try_from(self.bound(pool).as_nanos()).unwrap_or(u64::MAX);
        if nanos == 0 {
            return Duration::ZERO;
        }
        let floor = nanos / 2;
        Duration::from_nanos(floor + splitmix(rng) % (nanos - floor + 1))
    }
}

/// A closure a [`SyncDispatch::deferred`] dispatcher queued.
pub type Job = Box<dyn FnOnce() + Send>;

/// The work a host's deferred dispatcher has queued and the driver has
/// not yet taken, each with the processing time drawn for it.
///
/// A job spawned while another runs is queued like any other, so its
/// time starts when the driver takes it: nested work waits for both.
pub struct DeferredJobs {
    times: ProcessingTimes,
    state: Mutex<DeferredState>,
}

struct DeferredState {
    rng: u64,
    queued: Vec<(Duration, Job)>,
}

impl DeferredJobs {
    /// An empty queue drawing processing times from `times` and `seed`.
    #[must_use]
    pub const fn new(times: ProcessingTimes, seed: u64) -> Self {
        Self {
            times,
            state: Mutex::new(DeferredState {
                rng: seed,
                queued: Vec::new(),
            }),
        }
    }

    fn push(&self, pool: DispatchPool, job: Job) {
        let mut state = self.state.lock().expect("deferred jobs lock");
        let delay = self.times.draw(pool, &mut state.rng);
        state.queued.push((delay, job));
    }

    /// Every job queued since the last take, in spawn order, each with
    /// how long after now it is due.
    ///
    /// # Panics
    ///
    /// Panics if a job panicked while holding the queue's lock.
    pub fn take(&self) -> Vec<(Duration, Job)> {
        std::mem::take(&mut self.state.lock().expect("deferred jobs lock").queued)
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
        self.times.draw(pool, &mut state.rng)
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

    /// A deferred run happens only once the driver takes it, and reads the
    /// state it finds then rather than the state at spawn.
    #[test]
    fn a_deferred_run_reads_the_state_it_finds_when_run() {
        let jobs = Arc::new(DeferredJobs::new(FIXED, 7));
        let dispatch = SyncDispatch::deferred(Arc::clone(&jobs));
        let state = Arc::new(AtomicU64::new(1));
        let seen = Arc::new(AtomicU64::new(0));

        let (read, into) = (Arc::clone(&state), Arc::clone(&seen));
        dispatch.spawn(DispatchPool::Consensus, move || {
            into.store(read.load(Ordering::SeqCst), Ordering::SeqCst);
        });
        assert_eq!(seen.load(Ordering::SeqCst), 0, "nothing ran at spawn");
        state.store(2, Ordering::SeqCst);

        let taken = jobs.take();
        assert_eq!(taken.len(), 1);
        assert!(jobs.take().is_empty(), "a take empties the queue");
        let (due, job) = taken.into_iter().next().expect("one job");
        assert_eq!(due, Duration::from_millis(5));
        job();
        assert_eq!(seen.load(Ordering::SeqCst), 2);
    }

    /// Work spawned by a running job is queued again rather than run in
    /// it, so its processing time starts when the driver takes it.
    #[test]
    fn a_job_spawned_by_a_job_waits_its_own_turn() {
        let jobs = Arc::new(DeferredJobs::new(FIXED, 7));
        let dispatch = SyncDispatch::deferred(Arc::clone(&jobs));
        let ran = Arc::new(AtomicUsize::new(0));

        let (inner_dispatch, counted) = (dispatch.clone(), Arc::clone(&ran));
        dispatch.spawn(DispatchPool::Consensus, move || {
            inner_dispatch.spawn(DispatchPool::Consensus, move || {
                counted.fetch_add(1, Ordering::SeqCst);
            });
        });

        for (_, job) in jobs.take() {
            job();
        }
        assert_eq!(ran.load(Ordering::SeqCst), 0, "the inner job waits");
        let inner = jobs.take();
        assert_eq!(inner.len(), 1);
        for (_, job) in inner {
            job();
        }
        assert_eq!(ran.load(Ordering::SeqCst), 1);
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
