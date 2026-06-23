//! Cross-shard fetch bindings.
//!
//! The [`FetchBinding`] impls for the cross-shard data-availability payloads —
//! provisions, execution certificates, finalized waves, and local provisions.
//! Each `fetch_mut` resolves the binding's `Fetch` instance out of this shard's
//! [`CrossShardState`](super::CrossShardState). The generic engine, the
//! `FetchBinding` trait, and the shared `partition_solicited` helper live in
//! [`crate::fetch`].

use std::sync::Arc;

use crossbeam::channel::Sender;
use hyperscale_core::ProtocolEvent;
use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::request::{
    GetExecutionCertsRequest, GetFinalizedWavesRequest, GetLocalProvisionsRequest,
    GetProvisionsRequest,
};
use hyperscale_types::{
    BlockHeight, ExecutionCertificate, FinalizedWave, MessageClass, ProvisionHash, ShardId,
    ValidatorId, Verifiable, WaveId,
};

use crate::fetch::Fetch;
use crate::fetch::binding::{FetchBinding, partition_solicited};
use crate::shard::ShardIo;
use crate::shard_loop::{HostEvent, ShardScopedInput, push_protocol_event, push_shard_input};

// ─── Type aliases ──────────────────────────────────────────────────────
/// Local-provision fetch keyed by [`ProvisionHash`].
pub type LocalProvisionFetch = Fetch<ProvisionHash>;
/// Finalized-wave fetch keyed by [`WaveId`].
pub type FinalizedWaveFetch = Fetch<WaveId>;
/// Cross-shard execution-cert fetch keyed by [`WaveId`].
pub type ExecCertFetch = Fetch<WaveId>;
/// Cross-shard provision fetch keyed by
/// `(source_shard, target_shard, block_height)`. `source_shard` selects
/// the responding committee; `target_shard` rides in the body for
/// response filtering on the responder.
pub type ProvisionFetch = Fetch<(ShardId, ShardId, BlockHeight)>;

// ─── Bindings ──────────────────────────────────────────────────────────

/// Marker type for the per-block local-provision fetch.
pub struct LocalProvisionBinding;

impl FetchBinding for LocalProvisionBinding {
    type Id = ProvisionHash;

    const NAME: &'static str = "local_provision";

    fn fetch_mut<S: ShardStorage>(shard: &mut ShardIo<S>) -> &mut Fetch<ProvisionHash> {
        &mut shard.cross_shard.local_provision
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<ProvisionHash>,
        local_shard: ShardId,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
        network: &N,
        sender: &Sender<HostEvent>,
    ) {
        let es = sender.clone();
        let hs = ids.clone();
        network.request(
            shard,
            preferred,
            GetLocalProvisionsRequest::new(ids),
            class,
            Box::new(move |result| {
                if let Ok(resp) = result {
                    let split = partition_solicited(resp.entries.into_inner(), &hs, |entry| {
                        entry.provisions.hash()
                    });
                    // Push the bundled source header BEFORE the provisions
                    // so the verification pipeline has a chance to admit it
                    // first. The header is QC-self-authenticating; sender is
                    // the fetched-header sentinel (no peer attestation).
                    for entry in split.kept {
                        if let Some(certified_header) = entry.source_header {
                            push_protocol_event(
                                &es,
                                local_shard,
                                ProtocolEvent::UnverifiedRemoteHeaderReceived {
                                    certified_header,
                                    sender: ValidatorId::new(u64::MAX),
                                },
                            );
                        }
                        push_protocol_event(
                            &es,
                            local_shard,
                            ProtocolEvent::UnverifiedProvisionsReceived {
                                provisions: entry.provisions,
                            },
                        );
                    }
                    let had_misses = !split.missing.is_empty();
                    if had_misses {
                        push_shard_input(
                            &es,
                            local_shard,
                            ShardScopedInput::LocalProvisionsFetchFailed {
                                hashes: split.missing,
                            },
                        );
                    }
                    // Reject the response if the peer shipped unsolicited
                    // provisions OR if any requested hash was missing.
                    if split.unsolicited > 0 || had_misses {
                        ResponseVerdict::Reject
                    } else {
                        ResponseVerdict::Accept
                    }
                } else {
                    push_shard_input(
                        &es,
                        local_shard,
                        ShardScopedInput::LocalProvisionsFetchFailed { hashes: hs },
                    );
                    ResponseVerdict::Accept
                }
            }),
        );
    }
}

/// Marker type for the per-block finalized-wave fetch.
pub struct FinalizedWaveBinding;

impl FetchBinding for FinalizedWaveBinding {
    type Id = WaveId;

    const NAME: &'static str = "finalized_wave";

    fn fetch_mut<S: ShardStorage>(shard: &mut ShardIo<S>) -> &mut Fetch<WaveId> {
        &mut shard.cross_shard.finalized_wave
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<WaveId>,
        local_shard: ShardId,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
        network: &N,
        sender: &Sender<HostEvent>,
    ) {
        let es = sender.clone();
        let requested_ids = ids.clone();
        network.request(
            shard,
            preferred,
            GetFinalizedWavesRequest::new(ids),
            class,
            Box::new(move |result| {
                if let Ok(resp) = result {
                    let split = partition_solicited(resp.waves.into_inner(), &requested_ids, |w| {
                        w.wave_id().clone()
                    });
                    if !split.kept.is_empty() {
                        // Refcount is 1 right after decode, so each unwrap moves.
                        let waves: Vec<Arc<Verifiable<FinalizedWave>>> = split
                            .kept
                            .into_iter()
                            .map(|arc| Arc::new(Arc::unwrap_or_clone(arc).into()))
                            .collect();
                        push_protocol_event(
                            &es,
                            local_shard,
                            ProtocolEvent::FinalizedWavesReceived { waves },
                        );
                    }
                    let had_misses = !split.missing.is_empty();
                    if had_misses {
                        push_shard_input(
                            &es,
                            local_shard,
                            ShardScopedInput::FinalizedWavesFetchFailed { ids: split.missing },
                        );
                    }
                    // Reject responses with unsolicited waves (peer scoring;
                    // also avoids wasted BLS verification on items we never
                    // asked for) or with any missing requested id.
                    if split.unsolicited > 0 || had_misses {
                        ResponseVerdict::Reject
                    } else {
                        ResponseVerdict::Accept
                    }
                } else {
                    push_shard_input(
                        &es,
                        local_shard,
                        ShardScopedInput::FinalizedWavesFetchFailed { ids: requested_ids },
                    );
                    ResponseVerdict::Accept
                }
            }),
        );
    }
}

/// Marker type for the cross-shard execution-cert fetch.
pub struct ExecCertBinding;

impl FetchBinding for ExecCertBinding {
    type Id = WaveId;

    const NAME: &'static str = "exec_cert";

    fn fetch_mut<S: ShardStorage>(shard: &mut ShardIo<S>) -> &mut Fetch<WaveId> {
        &mut shard.cross_shard.exec_cert
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<WaveId>,
        local_shard: ShardId,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
        network: &N,
        sender: &Sender<HostEvent>,
    ) {
        let es = sender.clone();
        let failed_ids = ids.clone();
        network.request(
            shard,
            preferred,
            GetExecutionCertsRequest { wave_ids: ids },
            class,
            Box::new(move |result| {
                if let Ok(response) = result {
                    let certs = response.certificates.unwrap_or_default();
                    let split = partition_solicited(certs, &failed_ids, |c| c.wave_id().clone());
                    let had_misses = !split.missing.is_empty();
                    if !split.kept.is_empty() {
                        // Refcount is 1 right after decode, so each unwrap moves.
                        let certificates: Vec<Verifiable<ExecutionCertificate>> = split
                            .kept
                            .into_iter()
                            .map(|arc| Arc::unwrap_or_clone(arc).into())
                            .collect();
                        push_protocol_event(
                            &es,
                            local_shard,
                            ProtocolEvent::ExecutionCertificatesReceived { certificates },
                        );
                    }
                    if had_misses {
                        push_shard_input(
                            &es,
                            local_shard,
                            ShardScopedInput::ExecCertFetchFailed {
                                hashes: split.missing,
                            },
                        );
                    }
                    // Reject the response if the peer shipped unsolicited
                    // ECs (peer scoring; also avoids wasted BLS verification
                    // on items we never asked for) or any missing id.
                    if split.unsolicited > 0 || had_misses {
                        ResponseVerdict::Reject
                    } else {
                        ResponseVerdict::Accept
                    }
                } else {
                    push_shard_input(
                        &es,
                        local_shard,
                        ShardScopedInput::ExecCertFetchFailed { hashes: failed_ids },
                    );
                    ResponseVerdict::Accept
                }
            }),
        );
    }
}

/// Marker type for the cross-shard provision fetch.
pub struct ProvisionBinding;

impl FetchBinding for ProvisionBinding {
    type Id = (ShardId, ShardId, BlockHeight);

    const NAME: &'static str = "provision";

    /// Cross-shard provisions are addressed by a single `(shard, height)` —
    /// each request targets exactly one scope.
    const PER_ID: bool = true;

    fn fetch_mut<S: ShardStorage>(shard: &mut ShardIo<S>) -> &mut Fetch<Self::Id> {
        &mut shard.cross_shard.provision
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<(ShardId, ShardId, BlockHeight)>,
        local_shard: ShardId,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
        network: &N,
        sender: &Sender<HostEvent>,
    ) {
        // PER_ID means the dispatcher hands us exactly one id at a time.
        debug_assert_eq!(ids.len(), 1);
        let (source_shard, target_shard, block_height) = ids[0];
        debug_assert_eq!(
            shard, source_shard,
            "ProvisionBinding routes to the source shard; the runner sets it from the variant"
        );
        // `target_shard` (the requester's shard) is the body field: the
        // source filters provisions by which shard is asking. Routing
        // shard `shard = source_shard` picks the responding committee.
        let request = GetProvisionsRequest {
            block_height,
            target_shard,
        };
        let es = sender.clone();
        network.request(
            shard,
            preferred,
            request,
            class,
            Box::new(move |result| {
                let push_fetch_failed = || {
                    push_shard_input(
                        &es,
                        local_shard,
                        ShardScopedInput::ProvisionsFetchFailed {
                            source_shard,
                            block_height,
                        },
                    );
                };
                let Ok(response) = result else {
                    push_fetch_failed();
                    return ResponseVerdict::Accept;
                };
                let Some(provisions) = response.provisions else {
                    push_fetch_failed();
                    return ResponseVerdict::Reject;
                };
                if provisions.source_shard() != source_shard
                    || provisions.target_shard() != target_shard
                    || provisions.block_height() != block_height
                {
                    tracing::warn!(
                        expected_source = source_shard.inner(),
                        got_source = provisions.source_shard().inner(),
                        expected_target = target_shard.inner(),
                        got_target = provisions.target_shard().inner(),
                        expected_height = block_height.inner(),
                        got_height = provisions.block_height().inner(),
                        "Dropping provision fetch response: scope mismatch"
                    );
                    push_fetch_failed();
                    return ResponseVerdict::Reject;
                }
                if provisions.transactions().is_empty() {
                    // Empty-but-scope-matched response is still a miss for
                    // the requester: the FSM has nothing to admit, so
                    // without an explicit `Failed` the id stays in_flight
                    // forever.
                    push_fetch_failed();
                    return ResponseVerdict::Reject;
                }
                push_protocol_event(
                    &es,
                    local_shard,
                    ProtocolEvent::UnverifiedProvisionsReceived { provisions },
                );
                ResponseVerdict::Accept
            }),
        );
    }
}
