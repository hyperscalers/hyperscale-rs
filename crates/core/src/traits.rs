//! Core traits for state machines.

use hyperscale_types::LocalTimestamp;

use crate::{Action, ProtocolEvent};

/// A state machine that processes events.
///
/// This is the core abstraction for the consensus architecture.
/// All consensus logic is implemented as state machines that:
///
/// - **Synchronous**: No async, no `.await`
/// - **Deterministic**: Same state + event = same actions
/// - **Pure-ish**: Mutates self, but performs no I/O
///
/// # Example
///
/// ```ignore
/// impl StateMachine for MyStateMachine {
///     fn handle(&mut self, now: LocalTimestamp, event: ProtocolEvent) -> Vec<Action> {
///         self.now = now;
///         match event {
///             ProtocolEvent::UnverifiedBlockVoteReceived { vote } => self.on_block_vote(vote),
///             // ... etc
///         }
///     }
/// }
/// ```
pub trait StateMachine {
    /// Process a protocol event at wall-clock `now`, returning actions
    /// to perform.
    ///
    /// `now` is the validator's monotonic local wall-clock, minted by
    /// the IO boundary (production `io_loop` or simulator driver) in
    /// milliseconds since a fixed origin captured at process start.
    /// Anchors view-change timers, IO retry backoff, and the proposer-
    /// skew check — never used as a deterministic consensus anchor (use
    /// `WeightedTimestamp` for that).
    ///
    /// # Guarantees
    ///
    /// - **Synchronous**: This method never blocks or awaits
    /// - **Deterministic**: Given the same state, `now`, and event, always returns the same actions
    /// - **No I/O**: All I/O is performed by the runner via the returned actions
    fn handle(&mut self, now: LocalTimestamp, event: ProtocolEvent) -> Vec<Action>;
}
