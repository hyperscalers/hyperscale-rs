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
    /// Beacon committee-start timer. Fires at the upcoming epoch's
    /// wall-clock boundary if the local vnode is on the next
    /// committee and that block isn't committed yet. Process-scoped.
    BeaconCommitteeStart,
    /// Beacon ratify timer. First fires `SKIP_TIMEOUT` past the
    /// expected block time when the local vnode hasn't observed the
    /// expected commit (the coordinator's `skip_trigger_due` check
    /// reads against this), then re-arms as the ratify round timeout
    /// while the epoch is undecided. Process-scoped.
    BeaconRatifyTrigger,
    /// Beacon SPC view-timeout timer. Set by the SPC FSM when
    /// entering a view; on fire, the coordinator drives the inner
    /// PC instance with the current view's input even if the view's
    /// leader hasn't surfaced one. Process-scoped.
    BeaconSpcView,
    /// Beacon SPC proposal-collection dwell. Armed at SPC bootstrap;
    /// on fire, the coordinator feeds the view-1 PC input from
    /// whatever proposals the pool holds, unless the quorum fast
    /// path already fed it. Process-scoped.
    BeaconSpcInputDwell,
}
