//! A process crash at a chosen storage write.
//!
//! A driver arms a countdown around one stretch of a host's work with
//! [`armed`]. Each durable write the host's stores make — one write
//! batch, as a persistent backend commits it — counts one down, and the
//! write the countdown reaches does not happen: the work unwinds from
//! there, before the store takes any lock, as a process killed mid-write
//! stops. Nothing after it runs, so nothing the work would have sent
//! after that write leaves the process either.
//!
//! The countdown is the calling thread's, so only the work run inside
//! [`armed`] counts; a store written anywhere else never crashes.

use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

thread_local! {
    static COUNTDOWN: Cell<Option<u64>> = const { Cell::new(None) };
}

/// The work [`armed`] ran crashed at a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crashed;

/// Run `work` with `countdown` writes left before a crash, or none.
///
/// Returns what `work` returned, or [`Crashed`] if it reached the write
/// the countdown named, along with the writes still left when it
/// finished; a crash leaves none.
///
/// # Panics
///
/// Re-raises any panic of `work`'s own.
pub fn armed<R>(
    countdown: Option<u64>,
    work: impl FnOnce() -> R,
) -> (Result<R, Crashed>, Option<u64>) {
    let outer = COUNTDOWN.replace(countdown);
    let ran = catch_unwind(AssertUnwindSafe(work));
    let left = COUNTDOWN.replace(outer);
    match ran {
        Ok(value) => (Ok(value), left),
        Err(payload) if payload.is::<Crashed>() => (Err(Crashed), None),
        Err(payload) => resume_unwind(payload),
    }
}

/// Count one durable write down, crashing the work at the write the
/// countdown reaches. Called first in every write path, before any lock.
pub(crate) fn write() {
    match COUNTDOWN.get() {
        None => {}
        Some(0) => {
            COUNTDOWN.set(None);
            resume_unwind(Box::new(Crashed));
        }
        Some(left) => COUNTDOWN.set(Some(left - 1)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_crashes_at_the_write_the_countdown_names() {
        let mut done = 0;
        let (ran, left) = armed(Some(2), || {
            for _ in 0..5 {
                write();
                done += 1;
            }
        });
        assert_eq!(ran, Err(Crashed));
        assert_eq!(done, 2, "the two writes before it land, the third does not");
        assert_eq!(left, None);
    }

    #[test]
    fn work_that_writes_less_carries_what_is_left() {
        let (ran, left) = armed(Some(5), || {
            write();
            write();
        });
        assert_eq!(ran, Ok(()));
        assert_eq!(left, Some(3));
    }

    #[test]
    fn writes_outside_armed_work_never_crash() {
        write();
        let (ran, left) = armed(None, write);
        assert_eq!(ran, Ok(()));
        assert_eq!(left, None);
    }

    #[test]
    #[should_panic(expected = "its own")]
    fn a_panic_of_the_works_own_passes_through() {
        let _ = armed(Some(1), || panic!("its own"));
    }
}
