//! Per-payload bindings of the generic [`Fetch`] state machine.
//!
//! Each fetch payload (transactions, provisions, headers, …) gets one
//! [`FetchBinding`] impl that owns:
//!
//! - the `Id` type the fetch is keyed by;
//! - which `Fetch<Id>` instance on [`ProtocolHost`] backs it;
//! - the request/response shape and the per-binding rules for translating
//!   responses back into [`NodeInput`] events;
//! - which `ProtocolEvent` admits ids out of the in-flight set.
//!
//! `IoLoop` invokes the trait methods through generic helpers
//! (`process_fetch_outputs`, `dispatch_fetch_request`), so adding a new
//! payload means writing one impl block here — not editing three parallel
//! files.

use super::fetch::{Fetch, FetchInput};
use super::host::ProtocolHost;
use crossbeam::channel::Sender;
use hyperscale_core::{FetchPeers, NodeInput, ProtocolEvent};
use hyperscale_messages::request::{
    GetCommittedBlockHeaderRequest, GetExecutionCertsRequest, GetFinalizedWavesRequest,
    GetLocalProvisionsRequest, GetProvisionsRequest, GetTransactionsRequest,
};
use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_types::{
    BlockHeight, ProvisionHash, ShardGroupId, TxHash, ValidatorId, WaveId, WaveIdHash,
};
use std::hash::Hash;
use std::sync::Arc;

// ─── Type aliases used across the module tree ──────────────────────────

/// Per-tx fetch keyed by [`TxHash`].
pub type TransactionFetch = Fetch<TxHash>;
/// Local-provision fetch keyed by [`ProvisionHash`].
pub type LocalProvisionFetch = Fetch<ProvisionHash>;
/// Finalized-wave fetch keyed by [`WaveIdHash`].
pub type FinalizedWaveFetch = Fetch<WaveIdHash>;
/// Cross-shard execution-cert fetch keyed by [`WaveId`].
pub type ExecCertFetch = Fetch<WaveId>;
/// Cross-shard provision fetch keyed by `(source_shard, block_height)`.
pub type ProvisionFetch = Fetch<(ShardGroupId, BlockHeight)>;
/// Cross-shard committed-block-header fetch keyed by `(source_shard, height)`.
pub type HeaderFetch = Fetch<(ShardGroupId, BlockHeight)>;

// ─── Trait ─────────────────────────────────────────────────────────────

/// A per-payload binding of the generic [`Fetch`] state machine.
pub trait FetchBinding: 'static {
    /// Id used to address payloads of this kind.
    type Id: Clone + Ord + Hash + std::fmt::Debug + Send + Sync + 'static;

    /// Stable identifier for this binding — used in dispatch tracing.
    const NAME: &'static str;

    /// One network request per id (vs. one batched request per chunk).
    /// Cross-shard fetches that target a single `(shard, height)` set this
    /// to `true`; bag-of-hashes fetches leave it `false`.
    const PER_ID: bool = false;

    /// Locate the `Fetch<Id>` instance for this binding inside the host.
    fn fetch_mut(host: &mut ProtocolHost) -> &mut Fetch<Self::Id>;

    /// Send one request covering `ids` and route the response back through
    /// the event sender. For [`PER_ID`](Self::PER_ID) bindings the dispatcher
    /// pre-splits into single-element chunks before calling this.
    fn dispatch_chunk<N: Network>(
        ids: Vec<Self::Id>,
        peers: &FetchPeers,
        local_shard: ShardGroupId,
        network: &N,
        sender: &Sender<NodeInput>,
    );

    /// Drain admitted ids on the matching `ProtocolEvent`. No-op for events
    /// the binding doesn't subscribe to.
    fn apply_admission(fetch: &mut Fetch<Self::Id>, event: &ProtocolEvent);
}

// ─── Bindings ──────────────────────────────────────────────────────────

/// Marker type for the per-block transaction fetch.
pub struct TransactionBinding;

impl FetchBinding for TransactionBinding {
    type Id = TxHash;

    const NAME: &'static str = "transaction";

    fn fetch_mut(host: &mut ProtocolHost) -> &mut Fetch<TxHash> {
        &mut host.transaction
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<TxHash>,
        peers: &FetchPeers,
        _local_shard: ShardGroupId,
        network: &N,
        sender: &Sender<NodeInput>,
    ) {
        let es = sender.clone();
        let hs = ids.clone();
        network.request(
            &peers.peers,
            peers.preferred,
            GetTransactionsRequest::new(ids),
            Box::new(move |result| {
                if let Ok(resp) = result {
                    let txs = resp.into_transactions();
                    let returned = txs.len();
                    let requested = hs.len();
                    let _ = es.send(NodeInput::TransactionReceived { transactions: txs });
                    if returned < requested {
                        ResponseVerdict::Reject
                    } else {
                        ResponseVerdict::Accept
                    }
                } else {
                    let _ = es.send(NodeInput::FetchTransactionsFailed { hashes: hs });
                    ResponseVerdict::Accept
                }
            }),
        );
    }

    fn apply_admission(fetch: &mut Fetch<TxHash>, event: &ProtocolEvent) {
        if let ProtocolEvent::TransactionsAdmitted { txs } = event {
            let ids: Vec<TxHash> = txs.iter().map(|tx| tx.hash()).collect();
            fetch.handle(FetchInput::Admitted { ids });
        }
    }
}

/// Marker type for the per-block local-provision fetch.
pub struct LocalProvisionBinding;

impl FetchBinding for LocalProvisionBinding {
    type Id = ProvisionHash;

    const NAME: &'static str = "local_provision";

    fn fetch_mut(host: &mut ProtocolHost) -> &mut Fetch<ProvisionHash> {
        &mut host.local_provision
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<ProvisionHash>,
        peers: &FetchPeers,
        _local_shard: ShardGroupId,
        network: &N,
        sender: &Sender<NodeInput>,
    ) {
        let es = sender.clone();
        let hs = ids.clone();
        network.request(
            &peers.peers,
            peers.preferred,
            GetLocalProvisionsRequest::new(ids),
            Box::new(move |result| {
                if let Ok(resp) = result {
                    let had_misses = !resp.missing_hashes.is_empty();
                    let batches = resp.batches.into_iter().map(Arc::new).collect();
                    let _ = es.send(NodeInput::LocalProvisionReceived {
                        batches,
                        missing_hashes: resp.missing_hashes,
                    });
                    if had_misses {
                        ResponseVerdict::Reject
                    } else {
                        ResponseVerdict::Accept
                    }
                } else {
                    let _ = es.send(NodeInput::LocalProvisionsFetchFailed { hashes: hs });
                    ResponseVerdict::Accept
                }
            }),
        );
    }

    fn apply_admission(fetch: &mut Fetch<ProvisionHash>, event: &ProtocolEvent) {
        if let ProtocolEvent::ProvisionsAdmitted { provisions, .. } = event {
            fetch.handle(FetchInput::Admitted {
                ids: vec![provisions.hash()],
            });
        }
    }
}

/// Marker type for the per-block finalized-wave fetch.
pub struct FinalizedWaveBinding;

impl FetchBinding for FinalizedWaveBinding {
    type Id = WaveIdHash;

    const NAME: &'static str = "finalized_wave";

    fn fetch_mut(host: &mut ProtocolHost) -> &mut Fetch<WaveIdHash> {
        &mut host.finalized_wave
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<WaveIdHash>,
        peers: &FetchPeers,
        _local_shard: ShardGroupId,
        network: &N,
        sender: &Sender<NodeInput>,
    ) {
        let es = sender.clone();
        let hs = ids.clone();
        network.request(
            &peers.peers,
            peers.preferred,
            GetFinalizedWavesRequest::new(ids),
            Box::new(move |result| {
                if let Ok(resp) = result {
                    let returned = resp.waves.len();
                    let requested = hs.len();
                    let waves = resp.waves.into_iter().map(Arc::new).collect();
                    let _ = es.send(NodeInput::FinalizedWaveReceived { waves });
                    if returned < requested {
                        ResponseVerdict::Reject
                    } else {
                        ResponseVerdict::Accept
                    }
                } else {
                    let _ = es.send(NodeInput::FinalizedWaveFetchFailed { hashes: hs });
                    ResponseVerdict::Accept
                }
            }),
        );
    }

    fn apply_admission(fetch: &mut Fetch<WaveIdHash>, event: &ProtocolEvent) {
        if let ProtocolEvent::FinalizedWavesAdmitted { waves } = event {
            let ids: Vec<WaveIdHash> = waves.iter().map(|w| w.wave_id_hash()).collect();
            fetch.handle(FetchInput::Admitted { ids });
        }
    }
}

/// Marker type for the cross-shard execution-cert fetch.
pub struct ExecCertBinding;

impl FetchBinding for ExecCertBinding {
    type Id = WaveId;

    const NAME: &'static str = "exec_cert";

    fn fetch_mut(host: &mut ProtocolHost) -> &mut Fetch<WaveId> {
        &mut host.exec_cert
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<WaveId>,
        peers: &FetchPeers,
        _local_shard: ShardGroupId,
        network: &N,
        sender: &Sender<NodeInput>,
    ) {
        let es = sender.clone();
        let failed_ids = ids.clone();
        network.request(
            &peers.peers,
            peers.preferred,
            GetExecutionCertsRequest { wave_ids: ids },
            Box::new(move |result| {
                if let Ok(response) = result {
                    match response.certificates {
                        Some(certs) if !certs.is_empty() => {
                            let _ = es.send(NodeInput::ExecutionCertsReceived {
                                certificates: certs,
                            });
                            ResponseVerdict::Accept
                        }
                        _ => {
                            let _ = es.send(NodeInput::ExecCertFetchFailed { hashes: failed_ids });
                            ResponseVerdict::Reject
                        }
                    }
                } else {
                    let _ = es.send(NodeInput::ExecCertFetchFailed { hashes: failed_ids });
                    ResponseVerdict::Accept
                }
            }),
        );
    }

    fn apply_admission(fetch: &mut Fetch<WaveId>, event: &ProtocolEvent) {
        if let ProtocolEvent::ExecutionCertificateAdmitted { wave_id } = event {
            fetch.handle(FetchInput::Admitted {
                ids: vec![wave_id.clone()],
            });
        }
    }
}

/// Marker type for the cross-shard provision fetch.
pub struct ProvisionBinding;

impl FetchBinding for ProvisionBinding {
    type Id = (ShardGroupId, BlockHeight);

    const NAME: &'static str = "provision";

    /// Cross-shard provisions are addressed by a single `(shard, height)` —
    /// each request targets exactly one scope.
    const PER_ID: bool = true;

    fn fetch_mut(host: &mut ProtocolHost) -> &mut Fetch<Self::Id> {
        &mut host.provision
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<(ShardGroupId, BlockHeight)>,
        peers: &FetchPeers,
        local_shard: ShardGroupId,
        network: &N,
        sender: &Sender<NodeInput>,
    ) {
        // PER_ID means the dispatcher hands us exactly one id at a time.
        debug_assert_eq!(ids.len(), 1);
        let (source_shard, block_height) = ids[0];
        let target_shard = local_shard;
        let request = GetProvisionsRequest {
            block_height,
            target_shard,
        };
        let es = sender.clone();
        network.request(
            &peers.peers,
            peers.preferred,
            request,
            Box::new(move |result| {
                let Ok(response) = result else {
                    let _ = es.send(NodeInput::ProvisionsFetchFailed {
                        source_shard,
                        block_height,
                    });
                    return ResponseVerdict::Accept;
                };
                let Some(provisions) = response.provisions else {
                    let _ = es.send(NodeInput::ProvisionsFetchFailed {
                        source_shard,
                        block_height,
                    });
                    return ResponseVerdict::Reject;
                };
                if provisions.source_shard != source_shard
                    || provisions.target_shard != target_shard
                    || provisions.block_height != block_height
                {
                    tracing::warn!(
                        expected_source = source_shard.0,
                        got_source = provisions.source_shard.0,
                        expected_target = target_shard.0,
                        got_target = provisions.target_shard.0,
                        expected_height = block_height.0,
                        got_height = provisions.block_height.0,
                        "Dropping provision fetch response: scope mismatch"
                    );
                    let _ = es.send(NodeInput::ProvisionsFetchFailed {
                        source_shard,
                        block_height,
                    });
                    return ResponseVerdict::Reject;
                }
                if provisions.transactions.is_empty() {
                    return ResponseVerdict::Reject;
                }
                let _ = es.send(NodeInput::Protocol(ProtocolEvent::ProvisionsReceived {
                    provisions,
                }));
                ResponseVerdict::Accept
            }),
        );
    }

    fn apply_admission(fetch: &mut Fetch<Self::Id>, event: &ProtocolEvent) {
        if let ProtocolEvent::ProvisionsAdmitted { provisions, .. } = event {
            fetch.handle(FetchInput::Admitted {
                ids: vec![(provisions.source_shard, provisions.block_height)],
            });
        }
    }
}

/// True once `ProvisionCoordinator` no longer expects provisions for `id`.
///
/// The verified remote header that registered the expectation has either
/// been satisfied or pruned. Lifetime is bound by `ProvisionCoordinator`'s
/// expected-set, not by admission events alone.
#[must_use]
pub fn provisions_is_abandoned(
    state: &crate::state::NodeStateMachine,
    id: &(ShardGroupId, BlockHeight),
) -> bool {
    let (shard, height) = *id;
    !state.provisions().is_expected(shard, height)
}

/// Marker type for the cross-shard committed-block-header fetch.
pub struct HeaderBinding;

impl FetchBinding for HeaderBinding {
    type Id = (ShardGroupId, BlockHeight);

    const NAME: &'static str = "header";

    /// Each request targets exactly one `(shard, height)`.
    const PER_ID: bool = true;

    fn fetch_mut(host: &mut ProtocolHost) -> &mut Fetch<Self::Id> {
        &mut host.header
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<(ShardGroupId, BlockHeight)>,
        peers: &FetchPeers,
        _local_shard: ShardGroupId,
        network: &N,
        sender: &Sender<NodeInput>,
    ) {
        debug_assert_eq!(ids.len(), 1);
        let (source_shard, from_height) = ids[0];
        let request = GetCommittedBlockHeaderRequest {
            shard: source_shard,
            height: from_height,
        };
        let es = sender.clone();
        network.request(
            &peers.peers,
            peers.preferred,
            request,
            Box::new(move |result| {
                let Ok(response) = result else {
                    let _ = es.send(NodeInput::HeaderFetchFailed {
                        source_shard,
                        from_height,
                    });
                    return ResponseVerdict::Accept;
                };
                let Some(header) = response.header else {
                    let _ = es.send(NodeInput::HeaderFetchFailed {
                        source_shard,
                        from_height,
                    });
                    return ResponseVerdict::Reject;
                };
                let _ = es.send(NodeInput::Protocol(ProtocolEvent::RemoteHeaderReceived {
                    committed_header: header,
                    sender: ValidatorId(0),
                }));
                ResponseVerdict::Accept
            }),
        );
    }

    fn apply_admission(fetch: &mut Fetch<Self::Id>, event: &ProtocolEvent) {
        if let ProtocolEvent::RemoteHeaderAdmitted { committed_header } = event {
            fetch.handle(FetchInput::Admitted {
                ids: vec![(committed_header.shard_group_id(), committed_header.height())],
            });
        }
    }
}
