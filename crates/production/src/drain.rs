//! Graceful-drain timing for a shard the beacon moved a vnode off.
//!
//! A vnode that loses its placement exits the shard's *consensus*
//! automatically — committee resolution and the ready filter exclude it
//! once the new window's schedule entry activates — but the host keeps
//! the shard's loop serving (fetch, sync, state ranges, witness
//! history) through a grace period so cross-shard fallback fetches and
//! a still-bootstrapping replacement aren't stranded. The departing
//! node is its replacement's ideal snap-sync source, so the teardown
//! deliberately overlaps the incoming bootstrap.
//!
//! Timing is observed, not predicted: the drain waits until the live
//! topology's *active* committee no longer names the validator (the
//! window actually closed — a stalled beacon postpones the drain rather
//! than tearing down a still-active participant), then keeps serving
//! for the grace period, then re-checks membership so a validator
//! shuffled back during grace cancels the teardown.

use std::time::Duration;

use hyperscale_node::SharedTopologySnapshot;
use hyperscale_types::{RETENTION_HORIZON, ShardId, ValidatorId};
use tokio::time::sleep;

/// How long a departing vnode keeps its shard serving after its window
/// closes: the DA retention horizon, so every artifact a remote shard
/// or joiner could still legitimately request from it stays servable
/// through the handover.
pub const DRAIN_GRACE: Duration = RETENTION_HORIZON;

/// How often the drain re-reads the topology while waiting for the
/// validator's window to close.
pub const DRAIN_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Wait out a departing vnode's serving obligations on `shard`.
///
/// Resolves `true` when the shard should now be left (the validator's
/// window closed and the grace period elapsed), `false` when the drain
/// was cancelled because the validator re-entered the shard's active
/// committee during grace.
pub async fn drain_after_window_close(
    topology: &SharedTopologySnapshot,
    validator: ValidatorId,
    shard: ShardId,
    grace: Duration,
    poll: Duration,
) -> bool {
    while topology
        .load()
        .committee_for_shard(shard)
        .contains(&validator)
    {
        sleep(poll).await;
    }
    sleep(grace).await;
    !topology
        .load()
        .committee_for_shard(shard)
        .contains(&validator)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use arc_swap::ArcSwap;
    use hyperscale_types::{
        NetworkDefinition, TopologySnapshot, ValidatorInfo, ValidatorSet, generate_bls_keypair,
    };
    use tokio::time::timeout;

    use super::*;

    const SHARD: ShardId = ShardId::ROOT;
    const LEAVER: ValidatorId = ValidatorId::new(7);

    fn snapshot_with_members(members: Vec<ValidatorId>) -> TopologySnapshot {
        let validators: Vec<ValidatorInfo> = members
            .iter()
            .map(|&validator_id| ValidatorInfo {
                validator_id,
                public_key: generate_bls_keypair().public_key(),
            })
            .collect();
        TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &ValidatorSet::new(validators),
            HashMap::from([(SHARD, members)]),
            HashMap::new(),
            HashMap::new(),
        )
    }

    fn topology(members: Vec<ValidatorId>) -> SharedTopologySnapshot {
        Arc::new(ArcSwap::from_pointee(snapshot_with_members(members)))
    }

    const TICK: Duration = Duration::from_millis(20);

    /// The drain holds while the validator is still in the active
    /// committee, runs the grace after the window closes, and then
    /// releases.
    #[tokio::test]
    async fn drains_after_window_close_plus_grace() {
        let topology = topology(vec![LEAVER, ValidatorId::new(8)]);
        let drain = drain_after_window_close(&topology, LEAVER, SHARD, TICK, TICK);
        tokio::pin!(drain);

        // Window still open: the drain must not resolve.
        let held = timeout(Duration::from_millis(100), &mut drain).await;
        assert!(held.is_err(), "drain resolved while the window was open");

        // The shuffle's activation drops the leaver from the committee.
        topology.store(Arc::new(snapshot_with_members(vec![ValidatorId::new(8)])));
        let proceed = timeout(Duration::from_secs(5), drain)
            .await
            .expect("drain resolves after window close + grace");
        assert!(proceed, "completed drain proceeds to the leave");
    }

    /// A validator shuffled back onto the shard during grace cancels
    /// the teardown — the shard stays up.
    #[tokio::test]
    async fn rejoin_during_grace_cancels_the_drain() {
        let topology = topology(vec![ValidatorId::new(8)]);
        let drain =
            drain_after_window_close(&topology, LEAVER, SHARD, Duration::from_millis(200), TICK);
        tokio::pin!(drain);

        // Window already closed; re-seat the leaver mid-grace.
        let _ = timeout(Duration::from_millis(50), &mut drain).await;
        topology.store(Arc::new(snapshot_with_members(vec![
            LEAVER,
            ValidatorId::new(8),
        ])));
        let proceed = timeout(Duration::from_secs(5), drain)
            .await
            .expect("drain resolves after grace");
        assert!(!proceed, "rejoin during grace must cancel the teardown");
    }
}
