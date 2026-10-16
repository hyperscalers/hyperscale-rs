//! Per-principal budget for the time this host's request handlers spend on
//! a peer.
//!
//! How many of a peer's requests are served at once is bounded where they
//! are admitted; this bounds what they cost over time. Each request served
//! is charged the processor time its handler took, plus a little for the
//! stream it came on. A peer may run up [`ALLOWANCE`] of such work at once,
//! and time pays it down as it passes, so a peer can keep this host's
//! handlers busy for one core's worth of time at most: what a peer gets
//! from a backend that serves one of its requests at a time. A peer past
//! its allowance is answered busy, before any handler runs, until time has
//! paid its debt back under the allowance; it asks another member
//! meanwhile. Time a handler spends waiting, on a disk say, is not charged:
//! it costs this host a thread, which the bound on requests at once
//! already holds.
//!
//! Cheap requests barely touch the budget. What exhausts it is a peer
//! asking for expensive answers, such as state ranges with their proofs,
//! faster than one core can produce them.

use std::time::Duration;

use dashmap::DashMap;
use hyperscale_types::ValidatorId;
use tokio::time::Instant;

/// Handler time a peer may run up at once before it is answered busy.
const ALLOWANCE: Duration = Duration::from_secs(1);

/// Work charged for each request served, on top of its handler's time:
/// the stream, the decode, and the response's encoding and write.
const REQUEST_WORK: Duration = Duration::from_micros(50);

/// Handler time a peer has run up and not yet paid down.
struct Debt {
    owed: Duration,
    updated: Instant,
}

impl Debt {
    /// Bring `owed` up to date at `now`: time pays it down as it passes.
    fn pay_down(&mut self, now: Instant) {
        self.owed = self
            .owed
            .saturating_sub(now.saturating_duration_since(self.updated));
        self.updated = now;
    }
}

/// Run `work` on the calling thread, returning what it gave and the
/// processor time it took; where the platform keeps no processor clock per
/// thread, the time it took.
pub fn processor_time<T>(work: impl FnOnce() -> T) -> (T, Duration) {
    let started = thread_clock();
    let done = work();
    (done, thread_clock().saturating_sub(started))
}

/// Processor time the calling thread has taken so far.
#[cfg(unix)]
pub fn thread_clock() -> Duration {
    use libc::{CLOCK_THREAD_CPUTIME_ID, clock_gettime, timespec};

    let mut now = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime` writes only the timespec it is handed, which
    // lives for the call, and the calling thread's clock always exists.
    if unsafe { clock_gettime(CLOCK_THREAD_CPUTIME_ID, &raw mut now) } != 0 {
        return Duration::ZERO;
    }
    Duration::new(
        u64::try_from(now.tv_sec).unwrap_or(0),
        u32::try_from(now.tv_nsec).unwrap_or(0),
    )
}

/// Time since the process first asked, standing in for a thread's
/// processor clock where the platform keeps none.
#[cfg(not(unix))]
pub fn thread_clock() -> Duration {
    use std::sync::OnceLock;
    use std::time::Instant as WallClock;

    static ORIGIN: OnceLock<WallClock> = OnceLock::new();
    ORIGIN.get_or_init(WallClock::now).elapsed()
}

/// What each principal's served requests have cost this host's handlers.
#[derive(Default)]
pub struct ServeBudget {
    peers: DashMap<ValidatorId, Debt>,
}

impl ServeBudget {
    /// Whether a request from `peer` may run its handler now.
    pub fn admits(&self, peer: ValidatorId) -> bool {
        let now = Instant::now();
        self.peers.get_mut(&peer).is_none_or(|mut debt| {
            debt.pay_down(now);
            debt.owed <= ALLOWANCE
        })
    }

    /// Charge `peer` for a request whose handler took `handler` of
    /// processor time.
    pub fn charge(&self, peer: ValidatorId, handler: Duration) {
        let now = Instant::now();
        let mut debt = self.peers.entry(peer).or_insert_with(|| Debt {
            owed: Duration::ZERO,
            updated: now,
        });
        debt.pay_down(now);
        debt.owed += handler + REQUEST_WORK;
    }
}

#[cfg(test)]
mod tests {
    use std::hint::spin_loop;
    use std::thread::sleep;
    use std::time::Instant as WallClock;

    use tokio::time::advance;

    use super::*;

    const PEER: ValidatorId = ValidatorId::new(1);

    #[tokio::test(start_paused = true)]
    async fn a_peer_within_its_allowance_is_served() {
        let budget = ServeBudget::default();
        assert!(budget.admits(PEER), "a peer starts with nothing owed");
        budget.charge(PEER, ALLOWANCE / 2);
        assert!(budget.admits(PEER));
    }

    #[tokio::test(start_paused = true)]
    async fn a_peer_past_its_allowance_is_busy_until_time_pays_it_down() {
        let budget = ServeBudget::default();
        budget.charge(PEER, ALLOWANCE * 3);
        assert!(!budget.admits(PEER));
        advance(ALLOWANCE).await;
        assert!(!budget.admits(PEER), "still twice its allowance in debt");
        advance(ALLOWANCE * 2).await;
        assert!(budget.admits(PEER), "time paid its debt down");
    }

    #[tokio::test(start_paused = true)]
    async fn a_peer_keeps_this_host_busy_for_one_core_at_most() {
        let budget = ServeBudget::default();
        let handler = Duration::from_millis(5);
        let watch = Duration::from_secs(60);
        let started = Instant::now();
        let mut served = Duration::ZERO;
        // The peer asks again the moment it may, a millisecond apart.
        while started.elapsed() < watch {
            if budget.admits(PEER) {
                budget.charge(PEER, handler);
                served += handler;
            }
            advance(Duration::from_millis(1)).await;
        }
        assert!(
            served <= watch + ALLOWANCE,
            "{served:?} of handler time in {watch:?}"
        );
        assert!(
            served >= watch * 9 / 10,
            "a busy peer still gets nearly a core: {served:?} in {watch:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn processor_time_counts_work_and_not_waits() {
        let ((), slept) = processor_time(|| sleep(Duration::from_millis(50)));
        let ((), worked) = processor_time(|| {
            let started = WallClock::now();
            while started.elapsed() < Duration::from_millis(50) {
                spin_loop();
            }
        });
        assert!(slept < Duration::from_millis(10), "slept {slept:?}");
        assert!(worked >= Duration::from_millis(25), "worked {worked:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn one_peer_in_debt_leaves_another_served() {
        let budget = ServeBudget::default();
        budget.charge(PEER, ALLOWANCE * 3);
        assert!(!budget.admits(PEER));
        assert!(budget.admits(ValidatorId::new(2)));
    }
}
