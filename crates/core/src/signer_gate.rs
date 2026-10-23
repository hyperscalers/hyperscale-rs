//! The release gate a signing identity's delegated handlers pass through.
//!
//! A node loop builds one gate per attachment of a signer and hands it to
//! every action it dispatches for that signer. A handler enters the gate
//! around its persist, sign and notify, and the loop closes the gate when
//! the attachment ends. Once [`SignerGate::close_and_wait`] returns, no
//! handler of that attachment is mid-signature and none will start one.

use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

/// A single-use release gate. Closing it is final: a fresh attachment
/// builds a fresh gate, so a task queued under an earlier attachment
/// never signs under a later one.
#[derive(Debug)]
pub struct SignerGate {
    state: Mutex<GateState>,
    idle: Condvar,
}

#[derive(Debug)]
struct GateState {
    open: bool,
    in_flight: usize,
}

/// A handler's pass through an open gate, held across its persist, sign
/// and notify. Dropping it exits the gate.
#[must_use = "the signature must be made while the entry is held"]
#[derive(Debug)]
pub struct GateEntry<'a> {
    gate: &'a SignerGate,
}

impl SignerGate {
    /// An open gate with nothing in flight.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(GateState {
                open: true,
                in_flight: 0,
            }),
            idle: Condvar::new(),
        }
    }

    /// Enter the gate, or `None` once it has closed, in which case the
    /// handler drops its action unsigned.
    pub fn enter(&self) -> Option<GateEntry<'_>> {
        let mut state = self.lock();
        if !state.open {
            return None;
        }
        state.in_flight += 1;
        drop(state);
        Some(GateEntry { gate: self })
    }

    /// Close the gate and wait until every handler that entered it has
    /// exited.
    pub fn close_and_wait(&self) {
        let closed = self.close();
        drop(
            self.idle
                .wait_while(closed, |state| state.in_flight > 0)
                .unwrap_or_else(PoisonError::into_inner),
        );
    }

    /// Close the gate, keeping the lock for the wait.
    fn close(&self) -> MutexGuard<'_, GateState> {
        let mut state = self.lock();
        state.open = false;
        state
    }

    fn exit(&self) {
        let mut state = self.lock();
        state.in_flight -= 1;
        let idle = state.in_flight == 0;
        drop(state);
        if idle {
            self.idle.notify_all();
        }
    }

    /// Entries exit on unwind, so a lock a panicking handler poisoned
    /// still holds exact counts.
    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Default for SignerGate {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for GateEntry<'_> {
    fn drop(&mut self) {
        self.gate.exit();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{TryRecvError, channel};
    use std::thread;

    use super::*;

    /// A close waits out a signature already started, and from the moment
    /// it begins no handler enters.
    #[test]
    fn close_and_wait_waits_for_a_started_signature_and_refuses_later_ones() {
        let gate = Arc::new(SignerGate::new());
        let signed = Arc::new(AtomicBool::new(false));
        let started = gate.enter().expect("an open gate admits");

        let (done_tx, done_rx) = channel();
        let closer = {
            let gate = Arc::clone(&gate);
            let signed = Arc::clone(&signed);
            thread::spawn(move || {
                gate.close_and_wait();
                done_tx
                    .send(signed.load(Ordering::SeqCst))
                    .expect("the test holds the receiver");
            })
        };

        // The closer has closed the gate once an entry is refused; each
        // admitted probe exits at once and leaves the count where it was.
        while gate.enter().is_some() {
            thread::yield_now();
        }
        assert_eq!(
            done_rx.try_recv(),
            Err(TryRecvError::Empty),
            "the close returned while a started signature was still in flight",
        );

        signed.store(true, Ordering::SeqCst);
        drop(started);
        assert!(
            done_rx
                .recv()
                .expect("the close returns once the signature exits"),
            "the close returned before the started signature finished",
        );
        closer.join().expect("the closer thread does not panic");
        assert!(gate.enter().is_none(), "a closed gate admits nothing");
    }

    /// Closing is final: a closed gate never reopens, and a second close
    /// returns at once.
    #[test]
    fn a_closed_gate_stays_closed() {
        let gate = SignerGate::new();
        gate.close_and_wait();
        gate.close_and_wait();
        assert!(gate.enter().is_none());
    }
}
