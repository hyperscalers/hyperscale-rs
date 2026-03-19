//! Core traits for state machines.

use crate::{Action, ProtocolEvent};
use hyperscale_types::{ConcreteConfig, TypeConfig};
use std::time::Duration;

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
///             ProtocolEvent::ProposalTimer => self.bft.on_proposal_timer(),
///             ProtocolEvent::BlockVoteReceived { vote } => {
///                 self.bft.on_block_vote(vote)
///             }
///             // ... etc
///         }
///     }
///
///     fn set_time(&mut self, now: Duration) {
///         self.now = now;
///     }
/// }
/// ```
pub trait StateMachine<C: TypeConfig = ConcreteConfig> {
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
    fn handle(&mut self, event: ProtocolEvent<C>) -> Vec<Action<C>>;

    /// Set the current time.
    ///
    /// Called by the runner before each `handle()` call to provide the
    /// current simulation or wall-clock time.
    ///
    /// # Arguments
    ///
    /// * `now` - The current time as a duration since some epoch
    fn set_time(&mut self, now: Duration);

    /// Get the current time.
    ///
    /// Returns the time that was last set via `set_time()`.
    fn now(&self) -> Duration;
}
