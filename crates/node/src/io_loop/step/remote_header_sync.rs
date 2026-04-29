//! Remote-header sync I/O glue.
//!
//! Bridges `Sync<RemoteHeaderSyncBinding>`'s scheduling to the network
//! and to the existing `RemoteHeaderReceived` ingestion path. The FSM
//! tracks heights only; the step layer owns wire shape (range fetches),
//! response decoding, and feeding delivered headers into per-header QC
//! verification.

use crate::io_loop::IoLoop;
use crate::io_loop::protocol::remote_header_sync::{RemoteHeaderSyncInput, RemoteHeaderSyncOutput};
use crate::io_loop::protocol::sync::SyncOutput;
use hyperscale_core::{NodeInput, ProtocolEvent};
use hyperscale_dispatch::Dispatch;
use hyperscale_engine::Engine;
use hyperscale_messages::request::GetRemoteHeadersRequest;
use hyperscale_metrics as metrics;
use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_storage::Storage;
use hyperscale_types::{BlockHeight, CommittedBlockHeader, ShardGroupId, ValidatorId};

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
            .protocols
            .remote_header_sync
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
        // Filter to in-range deliveries, deliver each to the existing
        // verification path, and collect the heights for the FSM.
        let mut delivered_heights = Vec::with_capacity(headers.len());
        for header in headers {
            let h = header.header.height;
            if h < from_height || h.0 >= from_height.0 + count {
                tracing::warn!(
                    source_shard = source_shard.0,
                    requested_from = from_height.0,
                    requested_count = count,
                    height = h.0,
                    "remote-header sync: response contained out-of-range height — discarding"
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

        let outputs =
            self.protocols
                .remote_header_sync
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
        let outputs =
            self.protocols
                .remote_header_sync
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
    /// `RemoteHeaderSyncProtocolComplete` event.
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
                        .topology
                        .load()
                        .committee_for_shard(source_shard)
                        .to_vec();
                    let request = GetRemoteHeadersRequest {
                        source_shard,
                        from_height,
                        count,
                    };
                    metrics::record_fetch_started("remote_header");
                    self.network.request(
                        &peers,
                        None,
                        request,
                        Box::new(move |result| {
                            if let Ok(resp) = result {
                                metrics::record_fetch_completed("remote_header");
                                metrics::record_fetch_items_received(
                                    "remote_header",
                                    resp.headers.len(),
                                );
                                let _ = es.send(NodeInput::RemoteHeadersResponseReceived {
                                    source_shard,
                                    from_height,
                                    count,
                                    headers: resp.headers,
                                });
                            } else {
                                metrics::record_fetch_failed("remote_header");
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
                    self.feed_event(ProtocolEvent::RemoteHeaderSyncProtocolComplete {
                        source_shard,
                        height,
                    });
                }
            }
        }
    }
}
