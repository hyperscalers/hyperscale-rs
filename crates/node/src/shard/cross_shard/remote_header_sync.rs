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
use hyperscale_types::{BlockHeight, CertifiedBlockHeader, HeaderFetchCount, ShardId, ValidatorId};

use super::remote_header::{RemoteHeaderSyncInput, RemoteHeaderSyncOutput};
use crate::event::classify_fetch_error;
use crate::shard::{FetchFailureKind, ShardLoop, ShardScopedInput, push_shard_input};
use crate::sync::SyncOutput;

impl<S, N, D> ShardLoop<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    // ─── Action dispatch ────────────────────────────────────────────────

    /// Handle `Action::StartRemoteHeaderSync`: feed this shard's FSM and
    /// dispatch any range fetches it emits. `source_shard` is the remote
    /// shard whose certified headers we're catching up on.
    ///
    /// The scope is pointed at the slowest seat before the target moves.
    /// A source shard that reshaped into existence begins its chain above
    /// genesis, and a seat tracking it anchors at its attested boundary; a
    /// scope left below that anchor fetches from genesis, the
    /// contiguous-prefix responder returns empty (or, on a production split
    /// child whose store is a checkpoint of the parent, the parent's
    /// wrong-shard headers) for the heights below the chain start, and the
    /// FSM infers a tip below the real chain and stalls.
    pub(crate) fn process_start_remote_header_sync(
        &mut self,
        source_shard: ShardId,
        target: BlockHeight,
    ) {
        self.follow_slowest_remote_header_seat(source_shard);
        let outputs =
            self.io
                .cross_shard
                .remote_header_sync
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
    ///
    /// An empty answer that names a floor above the range is the source
    /// saying the range is gone for good: each seat re-anchors the source
    /// at its attested boundary, and the scope follows the slowest seat
    /// there, rather than asking for the range again.
    pub(crate) fn handle_remote_headers_response_received(
        &mut self,
        source_shard: ShardId,
        from_height: BlockHeight,
        count: HeaderFetchCount,
        headers: Vec<CertifiedBlockHeader>,
        floor: Option<BlockHeight>,
    ) {
        if let Some(floor) = floor.filter(|floor| headers.is_empty() && *floor > from_height) {
            self.dispatch_event(ProtocolEvent::RemoteHeadersBelowFloor {
                source_shard,
                floor,
            });
            self.follow_slowest_remote_header_seat(source_shard);
        }
        let delivered_heights =
            self.deliver_fetched_headers(source_shard, from_height, count, headers);
        let outputs =
            self.io
                .cross_shard
                .remote_header_sync
                .handle(RemoteHeaderSyncInput::FetchSucceeded {
                    scope: source_shard,
                    from: from_height,
                    count: count.inner(),
                    delivered_heights,
                    now: self.now,
                });
        self.process_remote_header_sync_outputs(outputs);
    }

    /// Filter a header-range response to in-range, in-shard deliveries and
    /// feed each to the existing verification path, returning the heights
    /// that arrived. `saturating_add` prevents the `from_height + count`
    /// overflow path when an attacker (or a future caller) supplies values
    /// near `u64::MAX`. The shard filter rejects responses where the
    /// responder served headers from the wrong shard — the responder gates
    /// this too, but defending in depth on the receiver lets us surface
    /// peer misbehavior even if a future serve change drops it.
    fn deliver_fetched_headers(
        &mut self,
        source_shard: ShardId,
        from_height: BlockHeight,
        count: HeaderFetchCount,
        headers: Vec<CertifiedBlockHeader>,
    ) -> Vec<BlockHeight> {
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
            if header.shard_id() != source_shard {
                tracing::warn!(
                    source_shard = source_shard.inner(),
                    response_shard = header.shard_id().inner(),
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
        delivered_heights
    }

    /// Handle `Action::FetchCommitProof`: one targeted range fetch for a
    /// height the forward sync never reaches (at or below the source
    /// shard's attested boundary). Stateless on the runner side — a
    /// transport failure pushes nothing, and the coordinator's commit
    /// sweep re-issues the fetch until the height proves or ages out.
    pub(crate) fn process_fetch_commit_proof(
        &self,
        source_shard: ShardId,
        from_height: BlockHeight,
        count: HeaderFetchCount,
    ) {
        let es = self.event_sender().clone();
        let local_shard = self.shard;
        let request = GetRemoteHeadersRequest {
            source_shard,
            from_height,
            count,
        };
        record_sync_round_started("commit_proof");
        self.process.network.request(
            source_shard,
            None,
            request,
            None,
            Box::new(move |result: Result<GetRemoteHeadersResponse, _>| {
                match result {
                    Ok(resp) => {
                        record_sync_round_completed("commit_proof");
                        push_shard_input(
                            &es,
                            local_shard,
                            ShardScopedInput::CommitProofResponseReceived {
                                source_shard,
                                from_height,
                                count,
                                headers: resp.headers.into_inner(),
                            },
                        );
                    }
                    Err(err) => {
                        record_sync_round_retried("commit_proof");
                        tracing::debug!(
                            source_shard = source_shard.inner(),
                            from_height = from_height.inner(),
                            error = %err,
                            "commit-proof fetch failed; the commit sweep re-issues it"
                        );
                    }
                }
                ResponseVerdict::Accept
            }),
        );
    }

    /// A commit-proof range response arrived: feed the headers through the
    /// shared delivery path. No FSM to notify — proof establishment is
    /// observed by the remote-header coordinator itself (`try_prove`), and
    /// its commit sweep stops re-issuing once the height proves.
    pub(crate) fn handle_commit_proof_response_received(
        &mut self,
        source_shard: ShardId,
        from_height: BlockHeight,
        count: HeaderFetchCount,
        headers: Vec<CertifiedBlockHeader>,
    ) {
        let _ = self.deliver_fetched_headers(source_shard, from_height, count, headers);
    }

    /// Network callback: a range fetch failed.
    pub(crate) fn handle_remote_headers_fetch_failed(
        &mut self,
        source_shard: ShardId,
        from_height: BlockHeight,
        count: HeaderFetchCount,
        kind: FetchFailureKind,
    ) {
        let outputs =
            self.io
                .cross_shard
                .remote_header_sync
                .handle(RemoteHeaderSyncInput::FetchFailed {
                    scope: source_shard,
                    from: from_height,
                    count: count.inner(),
                    kind,
                    now: self.now,
                });
        self.process_remote_header_sync_outputs(outputs);
    }

    // ─── Output processing ──────────────────────────────────────────────

    /// Route FSM outputs: `Fetch` → network request, `Complete` →
    /// `RemoteHeaderSyncComplete` event.
    pub(crate) fn process_remote_header_sync_outputs(
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
                                            headers: resp.headers.into_inner(),
                                            floor: resp.floor,
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
