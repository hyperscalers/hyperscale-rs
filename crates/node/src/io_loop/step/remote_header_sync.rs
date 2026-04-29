//! Remote-header sync step handlers.
//!
//! I/O glue between `RemoteHeaderSyncProtocol` and the runner. Drives:
//! - `Action::StartRemoteHeaderSync` → kicks off / raises target on the FSM
//! - Network callbacks (`NodeInput::RemoteHeaders*`) → fed back into the FSM
//! - FSM outputs (`FetchHeaders`, `DeliverHeader`, `SyncComplete`) → routed
//!   to the network layer, the protocol-event stream, or
//!   `NodeStateMachine` respectively.
//!
//! Per-header validation goes through the existing
//! `ProtocolEvent::RemoteHeaderReceived` path so QC verification is
//! unchanged from the gossip-driven path. The FSM observes admission via
//! the `RemoteHeaderAdmitted` continuation interception in
//! `handle_continuation`.

use crate::io_loop::IoLoop;
use crate::io_loop::protocol::remote_header_sync::{RemoteHeaderSyncInput, RemoteHeaderSyncOutput};
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
                source_shard,
                target,
            });
        self.process_remote_header_sync_outputs(outputs);
        self.update_fetch_tick_timer();
    }

    // ─── step() handlers ────────────────────────────────────────────────

    /// Network callback: a range response arrived (possibly empty).
    pub(in crate::io_loop) fn handle_remote_headers_response_received(
        &mut self,
        source_shard: ShardGroupId,
        from_height: BlockHeight,
        count: u64,
        headers: Vec<CommittedBlockHeader>,
    ) {
        let outputs = self.protocols.remote_header_sync.handle(
            RemoteHeaderSyncInput::HeadersResponseReceived {
                source_shard,
                from_height,
                count,
                headers,
                now: std::time::Instant::now(),
            },
        );
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
                .handle(RemoteHeaderSyncInput::HeadersFetchFailed {
                    source_shard,
                    from_height,
                    count,
                    now: std::time::Instant::now(),
                });
        self.process_remote_header_sync_outputs(outputs);
        self.update_fetch_tick_timer();
    }

    // ─── Output processing ──────────────────────────────────────────────

    /// Route FSM outputs: `FetchHeaders` → network request,
    /// `DeliverHeader` → `RemoteHeaderReceived` event,
    /// `SyncComplete` → `RemoteHeaderSyncProtocolComplete` event.
    pub(in crate::io_loop) fn process_remote_header_sync_outputs(
        &mut self,
        outputs: Vec<RemoteHeaderSyncOutput>,
    ) {
        for output in outputs {
            match output {
                RemoteHeaderSyncOutput::FetchHeaders {
                    source_shard,
                    from_height,
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
                RemoteHeaderSyncOutput::DeliverHeader {
                    source_shard: _,
                    header,
                } => {
                    // Funnel through the same path gossip-arrived headers
                    // take; QC verification + admission run unchanged. The
                    // `sender` field carries no meaning for fetched headers
                    // — set to a sentinel that won't be confused with a
                    // real validator.
                    self.feed_event(ProtocolEvent::RemoteHeaderReceived {
                        committed_header: *header,
                        sender: ValidatorId(u64::MAX),
                    });
                }
                RemoteHeaderSyncOutput::SyncComplete {
                    source_shard,
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
