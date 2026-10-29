//! The host's beacon thread: its [`BeaconLoop`], its timers, and the
//! observer that publishes what the loop has seen.
//!
//! [`BeaconLoop`]: hyperscale_node::beacon_loop::BeaconLoop

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam::channel::{Receiver, after, never};
use hyperscale_core::{ParticipationChange, TimerId};
use hyperscale_dispatch_pooled::PooledDispatch;
use hyperscale_network_iroh::IrohNetwork;
use hyperscale_node::beacon_loop::BeaconLoop;
use hyperscale_node::shard::{
    BeaconScopedInput, HostEvent, StepOutput, TimerOp, TimerOwner, timer_event,
};
use hyperscale_storage_rocksdb::RocksDbShardStorage;
use hyperscale_types::{GenesisConfigHash, LocalTimestamp};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::observe::{HeaderRing, Observations, Observer};
use crate::runner::wall_clock_local;

/// Concrete `BeaconLoop` type for the production runner.
pub type ProdBeaconLoop = BeaconLoop<RocksDbShardStorage, IrohNetwork, PooledDispatch>;

/// Configuration for a host's pinned beacon thread — the sibling of
/// [`ShardLoopConfig`]. The beacon loop runs no shard consensus, so there
/// are no batches: it drains beacon traffic, what the replicas report and
/// the chains' registrations, and surfaces the seat triggers its
/// participants raise.
pub struct BeaconLoopConfig {
    /// Beacon gossip, what the replicas report, the chains' registrations,
    /// and the loop's own continuations and fetch answers.
    pub(crate) beacon_rx: Receiver<HostEvent>,
    /// Stops the beacon thread on teardown.
    pub(crate) shutdown_rx: Receiver<()>,
    /// Placement deltas the participants surface (their own seat
    /// triggers), forwarded to the runner's reconfiguration loop.
    pub(crate) participation_tx: mpsc::UnboundedSender<ParticipationChange>,
    /// Where each step's reported headers are summarised and kept.
    pub(crate) headers: Arc<HeaderRing>,
    /// Where each step's observation is published.
    pub(crate) observations: Observations,
    /// The genesis this host's network started from, stamped on every
    /// observation.
    pub(crate) genesis: GenesisConfigHash,
}

/// Apply one beacon step's output: fold its timer ops into the loop's
/// deadline table (keyed by the timer's owner and its [`TimerId`]) and
/// forward its placement deltas to the runner's reconfiguration loop.
fn apply_beacon_step_output(
    deadlines: &mut BTreeMap<(TimerOwner, TimerId), LocalTimestamp>,
    participation_tx: &mpsc::UnboundedSender<ParticipationChange>,
    now: LocalTimestamp,
    output: StepOutput,
) {
    for op in output.timer_ops {
        match op {
            TimerOp::Set {
                owner: owner @ (TimerOwner::Participant(_) | TimerOwner::Beacon),
                id,
                duration,
            } => {
                let fire = now
                    .as_millis()
                    .saturating_add(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX));
                deadlines.insert((owner, id), LocalTimestamp::from_millis(fire));
            }
            TimerOp::Cancel {
                owner: owner @ (TimerOwner::Participant(_) | TimerOwner::Beacon),
                id,
            } => {
                deadlines.remove(&(owner, id));
            }
            TimerOp::Set { .. } | TimerOp::Cancel { .. } => {
                warn!("Beacon loop emitted a shard-owned timer op; dropping");
            }
        }
    }
    for change in output.participation_changes {
        // Send failure means the runner is shutting down.
        let _ = participation_tx.send(change);
    }
}

/// Drive a host's [`BeaconLoop`] on its pinned thread, blocking until the
/// shutdown signal fires. Dropping the loop on the way out, by a return or
/// by a panic unwinding the thread, closes every participant's release
/// gate. The loop only consumes beacon events ([`HostEvent::Beacon`]); shard /
/// process envelopes never reach this channel and there is no batch
/// flushing. Its timers live in a thread-local deadline table: every
/// participant's beacon timer chain fires here, and the loop's own fetch
/// tick retries its held fetches.
fn run_beacon_loop(mut beacon: ProdBeaconLoop, config: BeaconLoopConfig) {
    info!("Beacon event loop starting");
    drive_beacon_loop(&mut beacon, config);
    info!("Beacon event loop exiting");
}

fn drive_beacon_loop(beacon: &mut ProdBeaconLoop, config: BeaconLoopConfig) {
    let BeaconLoopConfig {
        beacon_rx,
        shutdown_rx,
        participation_tx,
        headers,
        observations,
        genesis,
    } = config;
    let mut observer = Observer::new(genesis, headers, observations);

    let mut deadlines: BTreeMap<(TimerOwner, TimerId), LocalTimestamp> = BTreeMap::new();

    // The participants armed their beacon startup timers at construction,
    // but a genesis ceremony on this host may already have drained that
    // scratch into ops this thread never sees. Re-arming is idempotent
    // (replace at the table, identical durations), so arm-and-drain
    // unconditionally.
    let now = wall_clock_local();
    beacon.set_time(now);
    let startup = beacon.startup_output();
    apply_beacon_step_output(&mut deadlines, &participation_tx, now, startup);
    observe_step(&mut observer, beacon);

    loop {
        if shutdown_rx.try_recv().is_ok() {
            info!("Beacon event loop received shutdown signal");
            return;
        }
        let now = wall_clock_local();
        beacon.set_time(now);

        // Fire due timers: each fire re-enters the loop as its owner's
        // input, and its re-arms fold back into the table.
        for input in take_due_beacon_timers(&mut deadlines, now) {
            let output = beacon.run_step(input);
            apply_beacon_step_output(&mut deadlines, &participation_tx, now, output);
            observe_step(&mut observer, beacon);
        }

        let wake = beacon_wake(&deadlines, now);
        let event = crossbeam::channel::select! {
            recv(shutdown_rx) -> _ => {
                info!("Beacon event loop received shutdown signal (select)");
                return;
            }
            recv(beacon_rx) -> e => e.ok(),
            recv(wake) -> _ => None,
        };
        // The select blocks until the wake; re-read the clock so the step
        // and the deadlines its re-arms produce measure from the wake, not
        // the pre-sleep instant.
        let now = wall_clock_local();
        beacon.set_time(now);
        // A timer wake fires at the loop top; a stray non-beacon envelope
        // is dropped.
        let Some(HostEvent::Beacon(input)) = event else {
            continue;
        };
        let output = beacon.run_step(input);
        apply_beacon_step_output(&mut deadlines, &participation_tx, now, output);
        observe_step(&mut observer, beacon);
    }
}

/// Hand the step's adopted epochs and reported headers to the observer.
fn observe_step(observer: &mut Observer, beacon: &mut ProdBeaconLoop) {
    let adopted = beacon.take_adopted();
    let admitted = beacon.take_admitted();
    observer.step(adopted, admitted, beacon.beacon_state(), beacon.schedule());
}

/// Remove every beacon timer due at `now` from the table, returning the
/// input each fire feeds the loop.
fn take_due_beacon_timers(
    deadlines: &mut BTreeMap<(TimerOwner, TimerId), LocalTimestamp>,
    now: LocalTimestamp,
) -> Vec<BeaconScopedInput> {
    let (due, pending): (BTreeMap<_, _>, BTreeMap<_, _>) = std::mem::take(deadlines)
        .into_iter()
        .partition(|(_, fire)| fire.as_millis() <= now.as_millis());
    *deadlines = pending;
    due.into_keys()
        .filter_map(|(owner, id)| match timer_event(&id, owner) {
            HostEvent::Beacon(input) => Some(input),
            _ => None,
        })
        .collect()
}

/// What the beacon thread's select wakes on besides an event: the nearest
/// deadline in the table, or nothing at all while the table is empty.
fn beacon_wake(
    deadlines: &BTreeMap<(TimerOwner, TimerId), LocalTimestamp>,
    now: LocalTimestamp,
) -> Receiver<Instant> {
    deadlines.values().min().map_or_else(never, |fire| {
        after(Duration::from_millis(
            fire.as_millis().saturating_sub(now.as_millis()),
        ))
    })
}

/// Spawn the host's beacon thread, mirroring [`spawn_shard_loop`]. The
/// thread holds `exited` until it ends, by a return or by a panic
/// unwinding it, so its receiver hears of the end either way.
pub fn spawn_beacon_loop(
    beacon: ProdBeaconLoop,
    config: BeaconLoopConfig,
    exited: oneshot::Sender<()>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("beacon-loop".to_string())
        .spawn(move || {
            let _exited = exited;
            run_beacon_loop(beacon, config);
        })
        .expect("failed to spawn beacon-loop thread")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With nothing armed the beacon thread waits on events alone; the
    /// loop's fetch tick, once armed, wakes it when due and fires as the
    /// loop's own tick.
    #[test]
    fn the_beacon_fetch_tick_arms_the_threads_wake_and_fires_on_the_loop() {
        let mut deadlines = BTreeMap::new();
        let (participation_tx, _participation_rx) = mpsc::unbounded_channel();
        let now = LocalTimestamp::from_millis(1_000);
        assert!(
            beacon_wake(&deadlines, now).try_recv().is_err(),
            "nothing armed: no wake",
        );

        let interval = Duration::from_secs(3_600);
        let mut armed = StepOutput::default();
        armed.timer_ops.push(TimerOp::Set {
            owner: TimerOwner::Beacon,
            id: TimerId::FetchTick,
            duration: interval,
        });
        apply_beacon_step_output(&mut deadlines, &participation_tx, now, armed);
        assert!(
            beacon_wake(&deadlines, now).try_recv().is_err(),
            "an armed tick not yet due does not wake the thread",
        );
        assert!(take_due_beacon_timers(&mut deadlines, now).is_empty());

        let due = LocalTimestamp::from_millis(1_000 + 3_600_000);
        assert!(
            beacon_wake(&deadlines, due).try_recv().is_ok(),
            "a due tick wakes the thread at once",
        );
        assert!(matches!(
            take_due_beacon_timers(&mut deadlines, due).as_slice(),
            [BeaconScopedInput::FetchTick],
        ));
        assert!(deadlines.is_empty(), "a fired tick leaves the table");
    }
}
