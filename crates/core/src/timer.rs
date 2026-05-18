//! Timer identifiers emitted by the state machine.
//!
//! State machines emit `Action::SetTimer { id: TimerId, .. }` and
//! `Action::CancelTimer { id }`. The runner translates these into its
//! native scheduling primitive (tokio sleep in production, deterministic
//! event queue in simulation) and converts the firing back into a
//! `ShardEvent`. That conversion lives in the node crate next to the
//! transport-layer `TimerOp` buffer it feeds.

/// Timer identification for scheduled events.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TimerId {
    /// View change timeout — one-shot, reset on leader activity.
    /// Shard-scoped.
    ViewChange,
    /// Periodic cleanup timer. Shard-scoped.
    Cleanup,
    /// Periodic tick for the fetch protocol (retry pending fetches).
    /// Process-scoped — fans out across all hosted shards on fire.
    FetchTick,
}
