//! How often this host checks one validator's address records.
//!
//! A record's signature is checked on every host it reaches, and a validator
//! may sign records with a rising sequence as fast as it likes. So each
//! validator gets one check per [`RECORD_INTERVAL`]: a record that arrives
//! while its validator's turn is still to come is held, unchecked, in place
//! of any older one held, and the newest held record is checked when the
//! turn comes. However fast a validator signs, it makes each host check at
//! most one of its records an interval, and a host forwards at most that
//! one.
//!
//! An honest validator signs a record again only when its addresses
//! change, so its peers learn of a second change within one interval
//! of it, and of a first change at once.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use hyperscale_types::ValidatorId;
use tokio::time::Instant;

/// Least time between two checks of one validator's records.
pub const RECORD_INTERVAL: Duration = Duration::from_secs(5);

/// What to do with a record offered for its validator's turn.
#[derive(Debug, PartialEq, Eq)]
pub enum Offer<T> {
    /// Check it now: the validator's turn has come and nothing is held.
    Check(T),
    /// It is held for the validator's turn in place of `displaced`. When
    /// `wake_at` is set, nothing is waiting for the turn yet, and the caller
    /// releases the validator's held record then.
    Hold {
        displaced: Option<T>,
        wake_at: Option<Instant>,
    },
    /// A record at least as new is held already; this one is dropped.
    Drop(T),
}

/// One validator's turn and the record held for it.
struct Turn<T> {
    /// When the validator's next record may be checked.
    next_check: Instant,
    /// The newest record waiting for that turn, with its sequence.
    held: Option<(u64, T)>,
}

/// Each validator's turn at having its address records checked.
pub struct RecordPace<T> {
    turns: Mutex<HashMap<ValidatorId, Turn<T>>>,
}

impl<T> Default for RecordPace<T> {
    fn default() -> Self {
        Self {
            turns: Mutex::new(HashMap::new()),
        }
    }
}

impl<T> RecordPace<T> {
    /// Offer `record`, `validator`'s record at `sequence`, at `now`.
    pub fn offer(
        &self,
        validator: ValidatorId,
        sequence: u64,
        record: T,
        now: Instant,
    ) -> Offer<T> {
        offer(
            &mut self.turns.lock().expect("record pace lock"),
            validator,
            sequence,
            record,
            now,
        )
    }

    /// Take the record held for `validator`'s turn, which comes at `now`.
    pub fn release(&self, validator: ValidatorId, now: Instant) -> Option<T> {
        let mut turns = self.turns.lock().expect("record pace lock");
        let turn = turns.get_mut(&validator)?;
        let held = turn.held.take().map(|(_, held)| held);
        if held.is_some() {
            turn.next_check = now + RECORD_INTERVAL;
        }
        drop(turns);
        held
    }
}

/// [`RecordPace::offer`] over the turns it holds.
fn offer<T>(
    turns: &mut HashMap<ValidatorId, Turn<T>>,
    validator: ValidatorId,
    sequence: u64,
    record: T,
    now: Instant,
) -> Offer<T> {
    let Some(turn) = turns.get_mut(&validator) else {
        turns.insert(
            validator,
            Turn {
                next_check: now + RECORD_INTERVAL,
                held: None,
            },
        );
        return Offer::Check(record);
    };
    match &turn.held {
        None if now >= turn.next_check => {
            turn.next_check = now + RECORD_INTERVAL;
            Offer::Check(record)
        }
        Some((held, _)) if *held >= sequence => Offer::Drop(record),
        held => {
            let wake_at = held.is_none().then_some(turn.next_check);
            let displaced = turn.held.replace((sequence, record)).map(|(_, held)| held);
            Offer::Hold { displaced, wake_at }
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::time::advance;

    use super::*;

    const V: ValidatorId = ValidatorId::new(1);

    fn held(offer: &Offer<&'static str>) -> Option<Instant> {
        match offer {
            Offer::Hold { wake_at, .. } => *wake_at,
            other => panic!("expected the record held, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_validators_first_record_is_checked_and_the_next_waits_its_turn() {
        let pace = RecordPace::default();
        let start = Instant::now();
        assert_eq!(pace.offer(V, 1, "first", start), Offer::Check("first"));

        advance(Duration::from_secs(1)).await;
        let wake = held(&pace.offer(V, 2, "second", Instant::now()));
        assert_eq!(wake, Some(start + RECORD_INTERVAL));

        // A newer record takes the older one's place; nobody new is woken.
        assert_eq!(
            pace.offer(V, 3, "third", Instant::now()),
            Offer::Hold {
                displaced: Some("second"),
                wake_at: None
            }
        );
        // An older one than what is held is dropped.
        assert_eq!(
            pace.offer(V, 2, "late", Instant::now()),
            Offer::Drop("late")
        );

        advance(RECORD_INTERVAL).await;
        assert_eq!(pace.release(V, Instant::now()), Some("third"));
        assert_eq!(pace.release(V, Instant::now()), None, "released once");
    }

    #[tokio::test(start_paused = true)]
    async fn a_validator_signing_without_pause_is_checked_once_an_interval() {
        let pace = RecordPace::default();
        let start = Instant::now();
        let mut checked = 0;
        let mut wake: Option<Instant> = None;
        let mut sequence = 0;
        // A record every millisecond for six intervals, released as the
        // fan-out releases them: when the turn it was told of comes.
        while Instant::now() < start + RECORD_INTERVAL * 6 {
            sequence += 1;
            match pace.offer(V, sequence, sequence, Instant::now()) {
                Offer::Check(_) => checked += 1,
                Offer::Hold {
                    wake_at: Some(at), ..
                } => wake = Some(at),
                Offer::Hold { .. } | Offer::Drop(_) => {}
            }
            advance(Duration::from_millis(1)).await;
            if wake.is_some_and(|at| Instant::now() >= at) {
                wake = None;
                checked += u32::from(pace.release(V, Instant::now()).is_some());
            }
        }
        assert_eq!(
            checked, 7,
            "the first at once, then one at each of six turns"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn validators_take_turns_apart() {
        let pace = RecordPace::default();
        let now = Instant::now();
        assert_eq!(pace.offer(V, 1, "a", now), Offer::Check("a"));
        assert_eq!(
            pace.offer(ValidatorId::new(2), 1, "b", now),
            Offer::Check("b")
        );
        assert!(held(&pace.offer(V, 2, "c", now)).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn a_validator_quiet_for_an_interval_is_checked_at_once() {
        let pace = RecordPace::default();
        assert_eq!(pace.offer(V, 1, "a", Instant::now()), Offer::Check("a"));
        advance(RECORD_INTERVAL).await;
        assert_eq!(pace.offer(V, 2, "b", Instant::now()), Offer::Check("b"));
    }
}
