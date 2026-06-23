//! Generic fetch dispatch + tick-timer plumbing.

use std::time::Duration;

use hyperscale_core::{ProtocolEvent, TimerId};
use hyperscale_dispatch::Dispatch;
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;

use super::{ShardLoop, TimerOp};
use crate::beacon;
use crate::fetch::binding::FetchBinding;
use crate::fetch::{FetchInput, FetchOutput};
use crate::shard::cross_shard::{
    ExecCertBinding, FinalizedWaveBinding, LocalProvisionBinding, ProvisionBinding,
};
use crate::shard::mempool::TransactionBinding;

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Dispatch outputs from a [`FetchBinding`]'s state machine on this
    /// shard: emit one network request per chunk (or per id, for `PER_ID`
    /// bindings) and route the response through the binding's callback.
    ///
    /// The shard's id is threaded through to per-binding callbacks so the
    /// response can be routed back to this shard.
    ///
    /// [`FetchHost`]: crate::fetch::FetchHost
    pub(in crate::shard_loop) fn process_fetch_outputs<B: FetchBinding>(
        &self,
        outputs: Vec<FetchOutput<B::Id>>,
    ) {
        let local_shard = self.shard;
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
                        &*self.process.network,
                        self.event_sender(),
                    );
                }
            } else {
                B::dispatch_chunk(
                    ids,
                    local_shard,
                    shard,
                    preferred,
                    class,
                    &*self.process.network,
                    self.event_sender(),
                );
            }
        }
    }

    /// Drive a single fetch binding on this shard: feed an input and
    /// dispatch the outputs the handler returns. Each handler ends with
    /// `spawn_pending_fetches` so freed slots are filled in the same
    /// event-loop turn — this wrapper just routes the FSM-emitted Sends
    /// to the network.
    pub(crate) fn drive_fetch<B: FetchBinding>(&mut self, input: FetchInput<B::Id>) {
        if let FetchInput::Request {
            ids,
            shard,
            preferred,
            class,
        } = &input
        {
            tracing::trace!(
                binding = B::NAME,
                local_shard = ?self.shard,
                ids = ids.len(),
                shard = ?shard,
                preferred = ?preferred,
                class = ?class,
                "Dispatching fetch request"
            );
        }
        let outputs = B::fetch_mut(&mut self.io).handle(input);
        self.process_fetch_outputs::<B>(outputs);
    }

    /// Route an admission `ProtocolEvent` to whichever fetch bindings
    /// drain in-flight tracking on it, scoped to this shard. Goes
    /// through `drive_fetch` so the freed slots' `spawn_pending_fetches`
    /// outputs reach the network in the same event-loop turn instead
    /// of being silently dropped.
    pub(in crate::shard_loop) fn drive_fetch_admission(&mut self, event: &ProtocolEvent) {
        match event {
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
                    ids: vec![(
                        provisions.source_shard(),
                        provisions.target_shard(),
                        provisions.block_height(),
                    )],
                });
            }
            ProtocolEvent::FinalizedWavesAdmitted { waves } => {
                let ids: Vec<_> = waves.iter().map(|w| w.wave_id().clone()).collect();
                self.drive_fetch::<FinalizedWaveBinding>(FetchInput::Admitted { ids });
            }
            ProtocolEvent::ExecutionCertificateAdmitted { certificate } => {
                self.drive_fetch::<ExecCertBinding>(FetchInput::Admitted {
                    ids: vec![certificate.wave_id().clone()],
                });
            }
            _ => {}
        }
    }
}

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Interval for the periodic fetch tick timer.
    pub(in crate::shard_loop) const FETCH_TICK_INTERVAL: Duration = Duration::from_millis(200);

    /// Refresh this shard's `FetchTick` timer based on whether its own
    /// fetch host or sync host has any pending work. Each shard manages
    /// its own ticker — a shard with idle fetches stops paying for the
    /// 200ms wake-up while busier shards keep ticking.
    pub(crate) fn update_fetch_tick_timer(&mut self) {
        let any_pending = self.io.fetches.has_any_pending()
            || self.io.mempool.has_pending()
            || self.io.syncs.has_any_pending()
            || beacon::has_pending(&self.beacon_block)
            || self.io.cross_shard.has_pending();
        let op = if any_pending {
            TimerOp::Set {
                shard: self.shard,
                id: TimerId::FetchTick,
                duration: Self::FETCH_TICK_INTERVAL,
            }
        } else {
            TimerOp::Cancel {
                shard: self.shard,
                id: TimerId::FetchTick,
            }
        };
        self.pending_timer_ops.push(op);
    }
}
