//! Core traits for state machines.

use crate::{Action, ProtocolEvent};
use hyperscale_types::{Hash, SubstateWrite};
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

/// Trait for computing JMT state roots.
///
/// Implemented by the runner (which has storage access) and passed to `BftState`.
/// Used to compute speculative state roots when proposing blocks.
///
/// Only computes the root hash - state_version is derived from chain history.
pub trait StateRootComputer: Send + Sync {
    /// Compute the speculative state root after applying writes from multiple certificates.
    ///
    /// # Arguments
    /// * `base_root` - The state root to compute from. This MUST match the parent block's
    ///   `header.state_root` to ensure proposer and verifier compute the same result.
    ///   The implementation waits/verifies that local JMT matches this root.
    /// * `writes_per_cert` - State writes grouped by certificate. Each inner Vec represents
    ///   one certificate's writes.
    ///
    /// # Important
    /// - The `base_root` must be the parent block's state_root from its header
    /// - Writes are applied incrementally (one JMT version per certificate)
    /// - If local JMT doesn't match `base_root`, computation may produce wrong results
    ///
    /// # Returns
    /// The state root hash after applying all certificate writes.
    fn compute_speculative_root(
        &self,
        base_root: Hash,
        writes_per_cert: &[Vec<SubstateWrite>],
    ) -> Hash;
}

/// No-op implementation for unit tests.
///
/// Returns `Hash::ZERO` for all computations. Suitable for tests that don't
/// verify state roots.
pub struct NoOpStateRootComputer;

impl StateRootComputer for NoOpStateRootComputer {
    fn compute_speculative_root(
        &self,
        _base_root: Hash,
        _writes_per_cert: &[Vec<SubstateWrite>],
    ) -> Hash {
        Hash::ZERO
    }
}
