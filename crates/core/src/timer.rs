//! Timer identifiers emitted by the state machine. Runners map these to
//! their scheduling primitive (tokio sleep in production, deterministic
//! event queue in simulation).

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
