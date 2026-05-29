//! Remote-header sync I/O glue.
//!
//! Bridges `Sync<RemoteHeaderSyncBinding>`'s scheduling to the network
//! and to the existing `RemoteHeaderReceived` ingestion path. The FSM
//! tracks heights only; the step layer owns wire shape (range fetches),
//! response decoding, and feeding delivered headers into per-header QC
//! verification.

use std::sync::Arc;

use hyperscale_core::ProtocolEvent;
use hyperscale_dispatch::Dispatch;
use hyperscale_metrics::{
    record_sync_round_completed, record_sync_round_retried, record_sync_round_started,
};
use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::request::GetRemoteHeadersRequest;
use hyperscale_types::network::response::GetRemoteHeadersResponse;
use hyperscale_types::{
    BlockHeight, CertifiedBlockHeader, HeaderFetchCount, ShardGroupId, ValidatorId,
};

use crate::shard_io::sync::SyncOutput;
use crate::shard_io::sync::remote_header::{RemoteHeaderSyncInput, RemoteHeaderSyncOutput};
use crate::shard_loop::step::block_sync::classify_fetch_error;
use crate::shard_loop::{FetchFailureKind, ShardLoop, ShardScopedInput, push_shard_input};

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    // ─── Action dispatch ────────────────────────────────────────────────

    /// Handle `Action::StartRemoteHeaderSync`: feed this shard's FSM and
    /// dispatch any range fetches it emits. `source_shard` is the remote
    /// shard whose committed headers we're catching up on.
    pub(in crate::shard_loop) fn process_start_remote_header_sync(
        &mut self,
        source_shard: ShardGroupId,
        target: BlockHeight,
    ) {
        let outputs = self
            .io
            .syncs
            .remote_header
            .handle(RemoteHeaderSyncInput::StartSync {
                scope: source_shard,
                target,
            });
        self.process_remote_header_sync_outputs(outputs);
    }

    // ─── step() handlers ────────────────────────────────────────────────

    /// Network callback: a range response arrived (possibly empty). Each
    /// returned header is funneled through the same `RemoteHeaderReceived`
    /// path gossip-arrived headers take, so QC verification + admission
    /// stay unchanged. The FSM is told which heights actually arrived so
    /// it can defer the short-capped tail.
    pub(in crate::shard_loop) fn handle_remote_headers_response_received(
        &mut self,
        source_shard: ShardGroupId,
        from_height: BlockHeight,
        count: HeaderFetchCount,
        headers: Vec<CertifiedBlockHeader>,
    ) {
        // Filter to in-range, in-shard deliveries; deliver each to the
        // existing verification path and collect the heights for the FSM.
        // `saturating_add` prevents the `from_height + count` overflow path
        // when an attacker (or a future caller) supplies values near
        // `u64::MAX`. The shard filter rejects responses where the
        // responder served headers from the wrong shard — the responder
        // gates this too, but defending in depth on the receiver lets us
        // surface peer misbehavior even if a future serve change drops it.
        let upper_bound = from_height.inner().saturating_add(count.inner());
        let mut delivered_heights = Vec::with_capacity(headers.len());
        for header in headers {
            let h = header.header().height();
            if h < from_height || h.inner() >= upper_bound {
                tracing::warn!(
                    source_shard = source_shard.inner(),
                    requested_from = from_height.inner(),
                    requested_count = count.inner(),
                    height = h.inner(),
                    "remote-header sync: response contained out-of-range height — discarding"
                );
                continue;
            }
            if header.shard_group_id() != source_shard {
                tracing::warn!(
                    source_shard = source_shard.inner(),
                    response_shard = header.shard_group_id().inner(),
                    height = h.inner(),
                    "remote-header sync: response contained wrong-shard header — discarding"
                );
                continue;
            }
            delivered_heights.push(h);
            // The `sender` field carries no meaning for fetched headers —
            // a sentinel value avoids confusion with real validator ids.
            self.dispatch_event(ProtocolEvent::UnverifiedRemoteHeaderReceived {
                certified_header: Arc::new(header),
                sender: ValidatorId::new(u64::MAX),
            });
        }

        let outputs = self
            .io
            .syncs
            .remote_header
            .handle(RemoteHeaderSyncInput::FetchSucceeded {
                scope: source_shard,
                from: from_height,
                count: count.inner(),
                delivered_heights,
                now: std::time::Instant::now(),
            });
        self.process_remote_header_sync_outputs(outputs);
    }

    /// Network callback: a range fetch failed.
    pub(in crate::shard_loop) fn handle_remote_headers_fetch_failed(
        &mut self,
        source_shard: ShardGroupId,
        from_height: BlockHeight,
        count: HeaderFetchCount,
        kind: FetchFailureKind,
    ) {
        let outputs = self
            .io
            .syncs
            .remote_header
            .handle(RemoteHeaderSyncInput::FetchFailed {
                scope: source_shard,
                from: from_height,
                count: count.inner(),
                kind,
                now: std::time::Instant::now(),
            });
        self.process_remote_header_sync_outputs(outputs);
    }

    // ─── Output processing ──────────────────────────────────────────────

    /// Route FSM outputs: `Fetch` → network request, `Complete` →
    /// `RemoteHeaderSyncComplete` event.
    pub(in crate::shard_loop) fn process_remote_header_sync_outputs(
        &mut self,
        outputs: Vec<RemoteHeaderSyncOutput>,
    ) {
        let local_shard = self.shard;
        for output in outputs {
            match output {
                SyncOutput::Fetch {
                    scope: source_shard,
                    from: from_height,
                    count,
                } => {
                    let es = self.event_sender().clone();
                    let typed_count = HeaderFetchCount::new(count);
                    let request = GetRemoteHeadersRequest {
                        source_shard,
                        from_height,
                        count: typed_count,
                    };
                    record_sync_round_started("remote_header");
                    self.process.network.request(
                        source_shard,
                        None,
                        request,
                        None,
                        Box::new(move |result: Result<GetRemoteHeadersResponse, _>| {
                            match result {
                                Ok(resp) => {
                                    record_sync_round_completed("remote_header");
                                    push_shard_input(
                                        &es,
                                        local_shard,
                                        ShardScopedInput::RemoteHeadersResponseReceived {
                                            source_shard,
                                            from_height,
                                            count: typed_count,
                                            headers: resp.headers,
                                        },
                                    );
                                }
                                Err(err) => {
                                    record_sync_round_retried("remote_header");
                                    let kind = classify_fetch_error(&err);
                                    push_shard_input(
                                        &es,
                                        local_shard,
                                        ShardScopedInput::RemoteHeadersFetchFailed {
                                            source_shard,
                                            from_height,
                                            count: typed_count,
                                            kind,
                                        },
                                    );
                                }
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
                        source_shard = source_shard.inner(),
                        height = height.inner(),
                        "remote-header sync caught up"
                    );
                    self.dispatch_event(ProtocolEvent::RemoteHeaderSyncComplete {
                        source_shard,
                        height,
                    });
                }
            }
        }
    }
}
