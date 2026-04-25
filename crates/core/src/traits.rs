//! Core traits for state machines.

use crate::{Action, ProtocolEvent};
use hyperscale_types::LocalTimestamp;

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
/// impl StateMachine for NodeStateMachine {
///     fn handle(&mut self, event: ProtocolEvent) -> Vec<Action> {
///         match event {
///             ProtocolEvent::ContentAvailable => self.try_propose(),
///             ProtocolEvent::BlockVoteReceived { vote } => {
///                 self.bft.on_block_vote(vote)
///             }
///             // ... etc
///         }
///     }
///
///     fn set_time(&mut self, now: LocalTimestamp) {
///         self.now = now;
///     }
/// }
/// ```
pub trait StateMachine {
    /// Process a protocol event, returning actions to perform.
    ///
    /// # Guarantees
    ///
    /// - **Synchronous**: This method never blocks or awaits
    /// - **Deterministic**: Given the same state and event, always returns the same actions
    /// - **No I/O**: All I/O is performed by the runner via the returned actions
    ///
    /// # Arguments
    ///
    /// * `event` - The protocol event to process
    ///
    /// # Returns
    ///
    /// A list of actions for the runner to execute. Actions may include:
    /// - Sending network messages
    /// - Setting timers
    /// - Continuation events for further processing
    /// - Emitting notifications to clients
    fn handle(&mut self, event: ProtocolEvent) -> Vec<Action>;

    /// Set the current local wall-clock time.
    ///
    /// Called by the runner before each `handle()` call. The clock is
    /// minted by the IO boundary (production io_loop or simulator driver)
    /// in milliseconds since a fixed origin captured at process start.
    /// Anchors view-change timers, IO retry backoff, and the proposer-skew
    /// check — never used as a deterministic consensus anchor (use
    /// `WeightedTimestamp` for that).
    ///
    /// # Arguments
    ///
    /// * `now` - This validator's monotonic local wall-clock.
    fn set_time(&mut self, now: LocalTimestamp);

    /// Get the current local wall-clock time, as last set via `set_time`.
    fn now(&self) -> LocalTimestamp;
}
