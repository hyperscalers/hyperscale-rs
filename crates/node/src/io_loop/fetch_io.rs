//! Generic fetch dispatch + tick-timer plumbing.

use super::{IoLoop, TimerOp};
use crate::io_loop::protocol::binding::FetchBinding;
use hyperscale_core::TimerId;
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_network::Network;
use hyperscale_storage::Storage;
use std::time::Duration;

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
        outputs: Vec<crate::io_loop::protocol::fetch::FetchOutput<B::Id>>,
    ) {
        use crate::io_loop::protocol::fetch::FetchOutput;

        for FetchOutput::Send { ids, peers } in outputs {
            if B::PER_ID {
                for id in ids {
                    B::dispatch_chunk(
                        vec![id],
                        &peers,
                        self.local_shard,
                        &*self.network,
                        &self.event_sender,
                    );
                }
            } else {
                B::dispatch_chunk(
                    ids,
                    &peers,
                    self.local_shard,
                    &*self.network,
                    &self.event_sender,
                );
            }
        }
    }

    /// Drive a single fetch binding: feed a `Request`, drain the resulting
    /// `Tick` outputs through `process_fetch_outputs`. Used by both the
    /// `Action::Fetch` arms and the `*FetchFailed` step arms.
    pub(in crate::io_loop) fn drive_fetch<B: FetchBinding>(
        &mut self,
        input: crate::io_loop::protocol::fetch::FetchInput<B::Id>,
    ) {
        use crate::io_loop::protocol::fetch::FetchInput;
        if let FetchInput::Request { ids, peers } = &input {
            tracing::trace!(
                binding = B::NAME,
                ids = ids.len(),
                peer_count = peers.peers.len() + usize::from(peers.preferred.is_some()),
                "Dispatching fetch request"
            );
        }
        let outputs = {
            let fetch = B::fetch_mut(&mut self.protocols);
            fetch.handle(input);
            fetch.handle(FetchInput::Tick)
        };
        self.process_fetch_outputs::<B>(outputs);
    }

    pub(in crate::io_loop) fn update_fetch_tick_timer(&mut self) {
        let op = if self.protocols.has_any_pending() {
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
