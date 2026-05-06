//! Generic fetch dispatch + tick-timer plumbing.

use std::time::Duration;

use hyperscale_core::{ProtocolEvent, TimerId};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_network::Network;
use hyperscale_storage::Storage;

use super::{IoLoop, TimerOp};
use crate::io_loop::fetch::binding::{
    ExecCertBinding, FetchBinding, FinalizedWaveBinding, LocalProvisionBinding, ProvisionBinding,
    TransactionBinding,
};
use crate::io_loop::fetch::{FetchInput, FetchOutput};

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    /// Interval for the periodic fetch tick timer.
    const FETCH_TICK_INTERVAL: Duration = Duration::from_millis(200);

    /// Dispatch outputs from any [`FetchBinding`]'s state machine: emit one
    /// network request per chunk (or per id, for `PER_ID` bindings) and
    /// route the response through the binding's callback.
    pub(in crate::io_loop) fn process_fetch_outputs<B: FetchBinding>(
        &self,
        outputs: Vec<FetchOutput<B::Id>>,
    ) {
        let local_shard = self.topology_snapshot.load().local_shard();
        for FetchOutput::Send { ids, peers, origin } in outputs {
            if B::PER_ID {
                for id in ids {
                    B::dispatch_chunk(
                        vec![id],
                        &peers,
                        origin,
                        local_shard,
                        &*self.network,
                        &self.event_sender,
                    );
                }
            } else {
                B::dispatch_chunk(
                    ids,
                    &peers,
                    origin,
                    local_shard,
                    &*self.network,
                    &self.event_sender,
                );
            }
        }
    }

    /// Drive a single fetch binding: feed an input and dispatch the
    /// outputs the handler returns. Each handler ends with
    /// `spawn_pending_fetches` so freed slots are filled in the same
    /// event-loop turn — this wrapper just routes the FSM-emitted Sends
    /// to the network.
    pub(in crate::io_loop) fn drive_fetch<B: FetchBinding>(&mut self, input: FetchInput<B::Id>) {
        if let FetchInput::Request { ids, peers, origin } = &input {
            tracing::trace!(
                binding = B::NAME,
                ids = ids.len(),
                peer_count = peers.peers.len() + usize::from(peers.preferred.is_some()),
                origin = ?origin,
                "Dispatching fetch request"
            );
        }
        let outputs = B::fetch_mut(&mut self.fetches).handle(input);
        self.process_fetch_outputs::<B>(outputs);
    }

    /// Route an admission `ProtocolEvent` to whichever fetch bindings
    /// drain in-flight tracking on it. Goes through `drive_fetch` so the
    /// freed slots' `spawn_pending_fetches` outputs reach the network in
    /// the same event-loop turn instead of being silently dropped.
    pub(in crate::io_loop) fn drive_fetch_admission(&mut self, event: &ProtocolEvent) {
        match event {
            // Drain on TransactionsReceived to catch every delivered hash —
            // duplicates / tombstoned / validity-expired txs don't surface
            // via TransactionsAdmitted, so without this they'd pin the
            // in-flight set forever. TransactionsAdmitted covers the
            // broadcast path that has no Received event precursor.
            ProtocolEvent::TransactionsReceived { transactions } => {
                let ids: Vec<_> = transactions.iter().map(|tx| tx.hash()).collect();
                if !ids.is_empty() {
                    self.drive_fetch::<TransactionBinding>(FetchInput::Admitted { ids });
                }
            }
            ProtocolEvent::TransactionsAdmitted { txs } => {
                let ids: Vec<_> = txs.iter().map(|tx| tx.hash()).collect();
                if !ids.is_empty() {
                    self.drive_fetch::<TransactionBinding>(FetchInput::Admitted { ids });
                }
            }
            ProtocolEvent::ProvisionsAdmitted { provisions, .. } => {
                self.drive_fetch::<LocalProvisionBinding>(FetchInput::Admitted {
                    ids: vec![provisions.hash()],
                });
                self.drive_fetch::<ProvisionBinding>(FetchInput::Admitted {
                    ids: vec![(provisions.source_shard, provisions.block_height)],
                });
            }
            ProtocolEvent::FinalizedWavesAdmitted { waves } => {
                let ids: Vec<_> = waves.iter().map(|w| w.wave_id().clone()).collect();
                self.drive_fetch::<FinalizedWaveBinding>(FetchInput::Admitted { ids });
            }
            ProtocolEvent::ExecutionCertificateAdmitted { certificate } => {
                self.drive_fetch::<ExecCertBinding>(FetchInput::Admitted {
                    ids: vec![certificate.wave_id.clone()],
                });
            }
            _ => {}
        }
    }

    pub(in crate::io_loop) fn update_fetch_tick_timer(&mut self) {
        let op = if self.fetches.has_any_pending() || self.syncs.has_any_pending() {
            TimerOp::Set {
                id: TimerId::FetchTick,
                duration: Self::FETCH_TICK_INTERVAL,
            }
        } else {
            TimerOp::Cancel {
                id: TimerId::FetchTick,
            }
        };
        self.pending_timer_ops.push(op);
    }
}
