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
    record_sync_block_filtered, record_sync_round_completed, record_sync_round_retried,
    record_sync_round_started,
};
use hyperscale_network::{Network, RequestError, ResponseVerdict};
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
    /// The scope is pointed at the replica's verified frontier before the
    /// target moves. A source shard that reshaped into existence begins
    /// its chain above genesis, and the replica anchors it at its attested
    /// boundary; a
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
        self.follow_remote_header_frontier(source_shard);
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

    /// Admit `source_shard`'s scope up to the replica's contiguous verified
    /// frontier for it, where the replica tracks the shard.
    ///
    /// The frontier only rises while the replica tracks the shard: a shard
    /// it stops tracking loses its scope (see
    /// [`Self::forget_untracked_remote_header_scopes`]), so one tracked
    /// again from a lower anchor starts a fresh scope there.
    ///
    /// A scope this starts has no target of its own. When the replica
    /// already holds a header verified above the frontier, as a shard
    /// tracked again from its anchor does the moment it hears the live
    /// tip, the scope syncs toward it at once rather than waiting out the
    /// liveness probe.
    pub(crate) fn follow_remote_header_frontier(&mut self, source_shard: ShardId) {
        let coordinator = self.replica.remote_headers_coordinator();
        let Some(height) = coordinator.verified_frontier(source_shard) else {
            return;
        };
        let gap_target = coordinator.gap_sync_target(source_shard);
        let sync = &mut self.io.cross_shard.remote_header_sync;
        let held = sync.frontier(&source_shard);
        if held.is_some_and(|held| held >= height) {
            return;
        }
        let mut outputs = sync.handle(RemoteHeaderSyncInput::Admitted {
            scope: source_shard,
            height,
        });
        if held.is_none()
            && let Some(target) = gap_target
        {
            outputs.extend(sync.handle(RemoteHeaderSyncInput::StartSync {
                scope: source_shard,
                target,
            }));
        }
        self.process_remote_header_sync_outputs(outputs);
    }

    /// Forget the scope of every shard the replica no longer tracks.
    pub(crate) fn forget_untracked_remote_header_scopes(&mut self) {
        let coordinator = self.replica.remote_headers_coordinator();
        self.io
            .cross_shard
            .remote_header_sync
            .retain_scopes(|shard| coordinator.verified_frontier(*shard).is_some());
    }

    // ─── step() handlers ────────────────────────────────────────────────

    /// Network callback: a range response arrived (possibly empty). Each
    /// returned header is funneled through the same `RemoteHeaderReceived`
    /// path gossip-arrived headers take, so QC verification + admission
    /// stay unchanged. The FSM is told which heights actually arrived so
    /// it can defer the short-capped tail.
    ///
    /// An empty answer that names a floor above the range is the source
    /// saying the range is gone for good: the replica re-anchors the
    /// source at its attested boundary, and the scope follows it there,
    /// rather than asking for the range again.
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
            self.follow_remote_header_frontier(source_shard);
        }
        let delivered_heights = self.deliver_fetched_headers(headers);
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

    /// Feed each header of a screened range response to the existing
    /// verification path, returning the heights that arrived.
    fn deliver_fetched_headers(&mut self, headers: Vec<CertifiedBlockHeader>) -> Vec<BlockHeight> {
        let mut delivered_heights = Vec::with_capacity(headers.len());
        for header in headers {
            delivered_heights.push(header.header().height());
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
                let resp = match result {
                    Ok(resp) => resp,
                    Err(err) => {
                        record_sync_round_retried("commit_proof");
                        tracing::debug!(
                            source_shard = source_shard.inner(),
                            from_height = from_height.inner(),
                            error = %err,
                            "commit-proof fetch failed; the commit sweep re-issues it"
                        );
                        return ResponseVerdict::Accept;
                    }
                };
                let headers = resp.headers.into_inner();
                if screen_range("commit_proof", source_shard, from_height, count, &headers).is_err()
                {
                    return ResponseVerdict::Reject;
                }
                record_sync_round_completed("commit_proof");
                push_shard_input(
                    &es,
                    local_shard,
                    ShardScopedInput::CommitProofResponseReceived { headers },
                );
                ResponseVerdict::Accept
            }),
        );
    }

    /// A commit-proof range response arrived, screened at its callback:
    /// feed the headers through the shared delivery path. No FSM to notify — proof establishment is
    /// observed by the remote-header coordinator itself (`try_prove`), and
    /// its commit sweep stops re-issuing once the height proves.
    pub(crate) fn handle_commit_proof_response_received(
        &mut self,
        headers: Vec<CertifiedBlockHeader>,
    ) {
        let _ = self.deliver_fetched_headers(headers);
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
                            let (input, verdict) = remote_headers_answer(
                                source_shard,
                                from_height,
                                typed_count,
                                result,
                            );
                            push_shard_input(&es, local_shard, input);
                            verdict
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

/// What a header-range fetch feeds the shard, and what it says of the
/// peer that served it.
///
/// An honest responder serves a contiguous prefix of the range it was
/// asked, from the shard it was asked about, and stops at the first
/// height it lacks. A header outside the range or from another shard is
/// therefore no answer: the whole response is dropped, the range retried
/// as a failed fetch, and the peer rejected here, at the only point its
/// answer can still be scored. An empty answer is a responder at or
/// behind the range's start and is not rejected; it reads as the
/// responder's tip, which the liveness probe raises past again.
fn remote_headers_answer(
    source_shard: ShardId,
    from_height: BlockHeight,
    count: HeaderFetchCount,
    result: Result<GetRemoteHeadersResponse, RequestError>,
) -> (ShardScopedInput, ResponseVerdict) {
    let failed = |kind| ShardScopedInput::RemoteHeadersFetchFailed {
        source_shard,
        from_height,
        count,
        kind,
    };
    let resp = match result {
        Ok(resp) => resp,
        Err(err) => {
            record_sync_round_retried("remote_header");
            return (failed(classify_fetch_error(&err)), ResponseVerdict::Accept);
        }
    };
    let headers = resp.headers.into_inner();
    if screen_range("remote_header", source_shard, from_height, count, &headers).is_err() {
        record_sync_round_retried("remote_header");
        return (failed(FetchFailureKind::Transport), ResponseVerdict::Reject);
    }
    record_sync_round_completed("remote_header");
    (
        ShardScopedInput::RemoteHeadersResponseReceived {
            source_shard,
            from_height,
            count,
            headers,
            floor: resp.floor,
        },
        ResponseVerdict::Accept,
    )
}

/// Whether every header of a range response lies in the range asked and
/// on the shard asked about. `saturating_add` keeps a range near
/// `u64::MAX` from wrapping.
fn screen_range(
    kind: &'static str,
    source_shard: ShardId,
    from_height: BlockHeight,
    count: HeaderFetchCount,
    headers: &[CertifiedBlockHeader],
) -> Result<(), &'static str> {
    let upper_bound = from_height.inner().saturating_add(count.inner());
    for header in headers {
        let height = header.header().height();
        let reason = if height < from_height || height.inner() >= upper_bound {
            "out_of_range"
        } else if header.shard_id() != source_shard {
            "wrong_shard"
        } else {
            continue;
        };
        tracing::warn!(
            source_shard = source_shard.inner(),
            response_shard = header.shard_id().inner(),
            requested_from = from_height.inner(),
            requested_count = count.inner(),
            height = height.inner(),
            reason,
            "Dropping remote-header range response"
        );
        record_sync_block_filtered(kind, reason);
        return Err(reason);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::Capped;
    use hyperscale_types::{
        BlockHeader, BlockHeaderParts, ChainOrigin, QuorumCertificate, WeightedTimestamp,
    };

    use super::*;

    const SOURCE: ShardId = ShardId::leaf(1, 1);

    fn header(shard: ShardId, height: u64) -> CertifiedBlockHeader {
        CertifiedBlockHeader::new(
            BlockHeader::new(BlockHeaderParts {
                shard_id: shard,
                height: BlockHeight::new(height),
                ..Default::default()
            }),
            QuorumCertificate::genesis(shard, ChainOrigin::root(WeightedTimestamp::ZERO)),
        )
    }

    fn answer(headers: Vec<CertifiedBlockHeader>) -> (ShardScopedInput, ResponseVerdict) {
        remote_headers_answer(
            SOURCE,
            BlockHeight::new(5),
            HeaderFetchCount::new(3),
            Ok(GetRemoteHeadersResponse::of(Capped::new(headers).unwrap())),
        )
    }

    /// A header outside the range asked, or from another shard, is no
    /// answer from an honest responder: the range is retried and the peer
    /// rejected at the callback, the only place its answer is scored.
    #[test]
    fn a_header_off_the_range_asked_rejects_the_peer() {
        for (headers, what) in [
            (vec![header(SOURCE, 5), header(SOURCE, 8)], "past the range"),
            (vec![header(SOURCE, 4)], "below the range"),
            (vec![header(ShardId::leaf(1, 0), 5)], "another shard"),
        ] {
            let (input, verdict) = answer(headers);
            assert_eq!(verdict, ResponseVerdict::Reject, "{what}");
            assert!(
                matches!(
                    input,
                    ShardScopedInput::RemoteHeadersFetchFailed {
                        kind: FetchFailureKind::Transport,
                        ..
                    }
                ),
                "{what}: the range is asked again",
            );
        }
    }

    /// A contiguous prefix, empty included, is an honest answer.
    #[test]
    fn a_prefix_of_the_range_is_accepted() {
        for headers in [vec![header(SOURCE, 5), header(SOURCE, 6)], Vec::new()] {
            let count = headers.len();
            let (input, verdict) = answer(headers);
            assert_eq!(verdict, ResponseVerdict::Accept);
            assert!(matches!(
                input,
                ShardScopedInput::RemoteHeadersResponseReceived { headers, .. }
                    if headers.len() == count
            ));
        }
    }
}
