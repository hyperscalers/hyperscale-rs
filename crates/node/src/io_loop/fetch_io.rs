//! Generic fetch dispatch + tick-timer plumbing.

use std::time::Duration;

use hyperscale_core::{ProtocolEvent, TimerId};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_network::Network;
use hyperscale_storage::Storage;
use hyperscale_types::ShardGroupId;

use super::{IoLoop, TimerOp};
use crate::shard::fetch::binding::{
    ExecCertBinding, FetchBinding, FinalizedWaveBinding, LocalProvisionBinding, ProvisionBinding,
    TransactionBinding,
};
use crate::shard::fetch::{FetchInput, FetchOutput};

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Interval for the periodic fetch tick timer.
    const FETCH_TICK_INTERVAL: Duration = Duration::from_millis(200);

    /// Dispatch outputs from a [`FetchBinding`]'s state machine on
    /// `local_shard`: emit one network request per chunk (or per id,
    /// for `PER_ID` bindings) and route the response through the
    /// binding's callback.
    ///
    /// `local_shard` is the shard whose [`FetchHost`] produced these
    /// outputs — it's threaded through to per-binding callbacks so the
    /// response can be routed back to the right hosted shard.
    ///
    /// [`FetchHost`]: crate::shard::fetch::FetchHost
    pub(in crate::io_loop) fn process_fetch_outputs<B: FetchBinding>(
        &self,
        local_shard: ShardGroupId,
        outputs: Vec<FetchOutput<B::Id>>,
    ) {
        for FetchOutput::Send {
            ids,
            shard,
            preferred,
            class,
        } in outputs
        {
            if B::PER_ID {
                for id in ids {
                    B::dispatch_chunk(
                        vec![id],
                        local_shard,
                        shard,
                        preferred,
                        class,
                        &*self.network,
                        &self.event_sender,
                    );
                }
            } else {
                B::dispatch_chunk(
                    ids,
                    local_shard,
                    shard,
                    preferred,
                    class,
                    &*self.network,
                    &self.event_sender,
                );
            }
        }
    }

    /// Drive a single fetch binding on `local_shard`: feed an input and
    /// dispatch the outputs the handler returns. Each handler ends with
    /// `spawn_pending_fetches` so freed slots are filled in the same
    /// event-loop turn — this wrapper just routes the FSM-emitted Sends
    /// to the network.
    pub(in crate::io_loop) fn drive_fetch<B: FetchBinding>(
        &mut self,
        local_shard: ShardGroupId,
        input: FetchInput<B::Id>,
    ) {
        if let FetchInput::Request {
            ids,
            shard,
            preferred,
            class,
        } = &input
        {
            tracing::trace!(
                binding = B::NAME,
                local_shard = ?local_shard,
                ids = ids.len(),
                shard = ?shard,
                preferred = ?preferred,
                class = ?class,
                "Dispatching fetch request"
            );
        }
        let outputs = B::fetch_mut(&mut self.shard_io_mut(local_shard).fetches).handle(input);
        self.process_fetch_outputs::<B>(local_shard, outputs);
    }

    /// Route an admission `ProtocolEvent` to whichever fetch bindings
    /// drain in-flight tracking on it, scoped to `local_shard`. Goes
    /// through `drive_fetch` so the freed slots' `spawn_pending_fetches`
    /// outputs reach the network in the same event-loop turn instead
    /// of being silently dropped.
    pub(in crate::io_loop) fn drive_fetch_admission(
        &mut self,
        local_shard: ShardGroupId,
        event: &ProtocolEvent,
    ) {
        match event {
            // Drain on TransactionsReceived to catch every delivered hash —
            // duplicates / tombstoned / validity-expired txs don't surface
            // via TransactionsAdmitted, so without this they'd pin the
            // in-flight set forever. TransactionsAdmitted covers the
            // broadcast path that has no Received event precursor.
            ProtocolEvent::TransactionsReceived { transactions } => {
                let ids: Vec<_> = transactions.iter().map(|tx| tx.hash()).collect();
                if !ids.is_empty() {
                    self.drive_fetch::<TransactionBinding>(
                        local_shard,
                        FetchInput::Admitted { ids },
                    );
                }
            }
            ProtocolEvent::TransactionsAdmitted { txs } => {
                let ids: Vec<_> = txs.iter().map(|tx| tx.hash()).collect();
                if !ids.is_empty() {
                    self.drive_fetch::<TransactionBinding>(
                        local_shard,
                        FetchInput::Admitted { ids },
                    );
                }
            }
            ProtocolEvent::ProvisionsAdmitted { provisions, .. } => {
                self.drive_fetch::<LocalProvisionBinding>(
                    local_shard,
                    FetchInput::Admitted {
                        ids: vec![provisions.hash()],
                    },
                );
                self.drive_fetch::<ProvisionBinding>(
                    local_shard,
                    FetchInput::Admitted {
                        ids: vec![(
                            provisions.source_shard(),
                            provisions.target_shard(),
                            provisions.block_height(),
                        )],
                    },
                );
            }
            ProtocolEvent::FinalizedWavesAdmitted { waves } => {
                let ids: Vec<_> = waves.iter().map(|w| w.wave_id().clone()).collect();
                self.drive_fetch::<FinalizedWaveBinding>(local_shard, FetchInput::Admitted { ids });
            }
            ProtocolEvent::ExecutionCertificateAdmitted { certificate } => {
                self.drive_fetch::<ExecCertBinding>(
                    local_shard,
                    FetchInput::Admitted {
                        ids: vec![certificate.wave_id().clone()],
                    },
                );
            }
            _ => {}
        }
    }

    /// Refresh the global `FetchTick` timer based on whether any hosted
    /// shard has pending fetches or in-progress sync. The timer is
    /// process-scoped — it fires once and the tick handler fans out
    /// across every hosted shard — so the Set/Cancel decision must look
    /// at the union, not a single shard.
    pub(in crate::io_loop) fn update_fetch_tick_timer(&mut self) {
        let any_pending = self
            .shards
            .values_mut()
            .any(|g| g.io.fetches.has_any_pending() || g.io.syncs.has_any_pending());
        // FetchTick is process-global. The `shard` on `TimerOp` exists
        // to key the runner's timer manager by `(TimerId, ShardGroupId)`;
        // pick a stable sentinel from the hosted set so set/cancel pairs
        // match. The firing path passes `shard` to `timer_event` which
        // ignores it for `FetchTick`.
        let sentinel_shard = *self
            .shards
            .keys()
            .next()
            .expect("IoLoop hosts at least one shard");
        let op = if any_pending {
            TimerOp::Set {
                shard: sentinel_shard,
                id: TimerId::FetchTick,
                duration: Self::FETCH_TICK_INTERVAL,
            }
        } else {
            TimerOp::Cancel {
                shard: sentinel_shard,
                id: TimerId::FetchTick,
            }
        };
        self.pending_timer_ops.push(op);
    }
}
