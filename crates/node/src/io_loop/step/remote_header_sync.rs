//! Remote-header sync I/O glue.
//!
//! Bridges `Sync<RemoteHeaderSyncBinding>`'s scheduling to the network
//! and to the existing `RemoteHeaderReceived` ingestion path. The FSM
//! tracks heights only; the step layer owns wire shape (range fetches),
//! response decoding, and feeding delivered headers into per-header QC
//! verification.

use hyperscale_core::{NodeInput, ProtocolEvent};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_messages::request::GetRemoteHeadersRequest;
use hyperscale_messages::response::GetRemoteHeadersResponse;
use hyperscale_metrics::{
    record_sync_round_completed, record_sync_round_retried, record_sync_round_started,
};
use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_storage::Storage;
use hyperscale_types::{BlockHeight, CommittedBlockHeader, ShardGroupId, ValidatorId};

use crate::io_loop::IoLoop;
use crate::io_loop::sync::SyncOutput;
use crate::io_loop::sync::remote_header::{RemoteHeaderSyncInput, RemoteHeaderSyncOutput};

impl<S, N, D, E> IoLoop<S, N, D, E>
where
    S: Storage,
    N: Network,
    D: Dispatch,
    E: Engine,
{
    // ─── Action dispatch ────────────────────────────────────────────────

    /// Handle `Action::StartRemoteHeaderSync`: feed the FSM and dispatch
    /// any range fetches it emits.
    pub(in crate::io_loop) fn process_start_remote_header_sync(
        &mut self,
        source_shard: ShardGroupId,
        target: BlockHeight,
    ) {
        let outputs = self
            .syncs
            .remote_header
            .handle(RemoteHeaderSyncInput::StartSync {
                scope: source_shard,
                target,
            });
        self.process_remote_header_sync_outputs(outputs);
        self.update_fetch_tick_timer();
    }

    // ─── step() handlers ────────────────────────────────────────────────

    /// Network callback: a range response arrived (possibly empty). Each
    /// returned header is funneled through the same `RemoteHeaderReceived`
    /// path gossip-arrived headers take, so QC verification + admission
    /// stay unchanged. The FSM is told which heights actually arrived so
    /// it can defer the short-capped tail.
    pub(in crate::io_loop) fn handle_remote_headers_response_received(
        &mut self,
        source_shard: ShardGroupId,
        from_height: BlockHeight,
        count: u64,
        headers: Vec<CommittedBlockHeader>,
    ) {
        // Filter to in-range, in-shard deliveries; deliver each to the
        // existing verification path and collect the heights for the FSM.
        // `saturating_add` prevents the `from_height + count` overflow path
        // when an attacker (or a future caller) supplies values near
        // `u64::MAX`. The shard filter rejects responses where the
        // responder served headers from the wrong shard — the responder
        // gates this too, but defending in depth on the receiver lets us
        // surface peer misbehavior even if a future serve change drops it.
        let upper_bound = from_height.0.saturating_add(count);
        let mut delivered_heights = Vec::with_capacity(headers.len());
        for header in headers {
            let h = header.header.height;
            if h < from_height || h.0 >= upper_bound {
                tracing::warn!(
                    source_shard = source_shard.0,
                    requested_from = from_height.0,
                    requested_count = count,
                    height = h.0,
                    "remote-header sync: response contained out-of-range height — discarding"
                );
                continue;
            }
            if header.shard_group_id() != source_shard {
                tracing::warn!(
                    source_shard = source_shard.0,
                    response_shard = header.shard_group_id().0,
                    height = h.0,
                    "remote-header sync: response contained wrong-shard header — discarding"
                );
                continue;
            }
            delivered_heights.push(h);
            // The `sender` field carries no meaning for fetched headers —
            // a sentinel value avoids confusion with real validator ids.
            self.feed_event(ProtocolEvent::RemoteHeaderReceived {
                committed_header: header,
                sender: ValidatorId(u64::MAX),
            });
        }

        let outputs = self
            .syncs
            .remote_header
            .handle(RemoteHeaderSyncInput::FetchSucceeded {
                scope: source_shard,
                from: from_height,
                count,
                delivered_heights,
                now: std::time::Instant::now(),
            });
        self.process_remote_header_sync_outputs(outputs);
        self.update_fetch_tick_timer();
    }

    /// Network callback: a range fetch failed.
    pub(in crate::io_loop) fn handle_remote_headers_fetch_failed(
        &mut self,
        source_shard: ShardGroupId,
        from_height: BlockHeight,
        count: u64,
    ) {
        let outputs = self
            .syncs
            .remote_header
            .handle(RemoteHeaderSyncInput::FetchFailed {
                scope: source_shard,
                from: from_height,
                count,
                now: std::time::Instant::now(),
            });
        self.process_remote_header_sync_outputs(outputs);
        self.update_fetch_tick_timer();
    }

    // ─── Output processing ──────────────────────────────────────────────

    /// Route FSM outputs: `Fetch` → network request, `Complete` →
    /// `RemoteHeaderSyncComplete` event.
    pub(in crate::io_loop) fn process_remote_header_sync_outputs(
        &mut self,
        outputs: Vec<RemoteHeaderSyncOutput>,
    ) {
        for output in outputs {
            match output {
                SyncOutput::Fetch {
                    scope: source_shard,
                    from: from_height,
                    count,
                } => {
                    let es = self.event_sender.clone();
                    let peers = self
                        .topology_snapshot
                        .load()
                        .committee_for_shard(source_shard)
                        .to_vec();
                    let request = GetRemoteHeadersRequest {
                        source_shard,
                        from_height,
                        count,
                    };
                    record_sync_round_started("remote_header");
                    self.network.request(
                        &peers,
                        None,
                        request,
                        None,
                        Box::new(move |result: Result<GetRemoteHeadersResponse, _>| {
                            if let Ok(resp) = result {
                                record_sync_round_completed("remote_header");
                                let _ = es.send(NodeInput::RemoteHeadersResponseReceived {
                                    source_shard,
                                    from_height,
                                    count,
                                    headers: resp.headers,
                                });
                            } else {
                                record_sync_round_retried("remote_header");
                                let _ = es.send(NodeInput::RemoteHeadersFetchFailed {
                                    source_shard,
                                    from_height,
                                    count,
                                });
                            }
                            ResponseVerdict::Accept
                        }),
                    );
                }
                SyncOutput::Complete {
                    scope: source_shard,
                    height,
                } => {
                    tracing::info!(
                        source_shard = source_shard.0,
                        height = height.0,
                        "remote-header sync caught up"
                    );
                    self.feed_event(ProtocolEvent::RemoteHeaderSyncComplete {
                        source_shard,
                        height,
                    });
                }
            }
        }
    }
}
