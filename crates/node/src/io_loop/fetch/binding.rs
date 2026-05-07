//! Per-payload bindings of the generic [`Fetch`] state machine.
//!
//! Each fetch payload (transactions, provisions, headers, …) gets one
//! [`FetchBinding`] impl that owns:
//!
//! - the `Id` type the fetch is keyed by;
//! - which `Fetch<Id>` instance on [`FetchHost`] backs it;
//! - the request/response shape and the per-binding rules for translating
//!   responses back into [`NodeInput`] events.
//!
//! The `ProtocolEvent` → in-flight-drain mapping is *not* a per-binding
//! concern: it lives in `io_loop::drive_fetch_admission`, which calls
//! `Fetch::handle(FetchInput::Admitted { .. })` on the right binding
//! when each canonical admission event fires.
//!
//! `IoLoop` invokes the trait methods through generic helpers
//! (`process_fetch_outputs`, `dispatch_fetch_request`), so adding a new
//! payload means writing one impl block here — not editing three parallel
//! files.

use std::collections::HashSet;
use std::hash::Hash;
use std::sync::Arc;

use crossbeam::channel::Sender;
use hyperscale_core::{FetchOrigin, FetchPeers, NodeInput, ProtocolEvent};
use hyperscale_messages::request::{
    GetExecutionCertsRequest, GetFinalizedWavesRequest, GetLocalProvisionsRequest,
    GetProvisionsRequest, GetTransactionsRequest,
};
use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_types::{BlockHeight, ProvisionHash, ShardGroupId, TxHash, WaveId};

use super::Fetch;
use super::host::FetchHost;

// ─── Type aliases used across the module tree ──────────────────────────

/// Per-tx fetch keyed by [`TxHash`].
pub type TransactionFetch = Fetch<TxHash>;
/// Local-provision fetch keyed by [`ProvisionHash`].
pub type LocalProvisionFetch = Fetch<ProvisionHash>;
/// Finalized-wave fetch keyed by [`WaveId`].
pub type FinalizedWaveFetch = Fetch<WaveId>;
/// Cross-shard execution-cert fetch keyed by [`WaveId`].
pub type ExecCertFetch = Fetch<WaveId>;
/// Cross-shard provision fetch keyed by `(source_shard, block_height)`.
pub type ProvisionFetch = Fetch<(ShardGroupId, BlockHeight)>;

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
    fn fetch_mut(host: &mut FetchHost) -> &mut Fetch<Self::Id>;

    /// Send one request covering `ids` and route the response back through
    /// the event sender. `origin` flows down to `Network::request` as the
    /// per-call class override. For [`PER_ID`](Self::PER_ID) bindings the
    /// dispatcher pre-splits into single-element chunks before calling this.
    fn dispatch_chunk<N: Network>(
        ids: Vec<Self::Id>,
        peers: &FetchPeers,
        origin: FetchOrigin,
        local_shard: ShardGroupId,
        network: &N,
        sender: &Sender<NodeInput>,
    );
}

// ─── Bindings ──────────────────────────────────────────────────────────

/// Result of partitioning a fetch response against the requested set.
struct Partition<T, Id> {
    /// Items whose extracted id matched a requested id.
    kept: Vec<T>,
    /// Requested ids that didn't appear in the response.
    missing: Vec<Id>,
    /// Count of returned items whose id was NOT requested. A non-zero
    /// value indicates a buggy or malicious peer trying to inject items
    /// we never asked for.
    unsolicited: usize,
}

/// Split a fetch response into solicited / missing / unsolicited buckets.
///
/// Per-binding admit handlers downstream check binding-specific invariants
/// (mempool dedup + validity range for txs, BLS quorum for ECs, merkle
/// proof for provisions) but none of them ask "did we request this?".
/// Filtering at the response boundary keeps unsolicited items from
/// reaching pre-verification state mutations and from racing the legitimate
/// fetch path.
fn partition_solicited<T, Id, F>(returned: Vec<T>, requested: &[Id], extract: F) -> Partition<T, Id>
where
    Id: Clone + Eq + Hash,
    F: Fn(&T) -> Id,
{
    let requested_set: HashSet<Id> = requested.iter().cloned().collect();
    let mut kept = Vec::with_capacity(returned.len().min(requested.len()));
    let mut delivered: HashSet<Id> = HashSet::with_capacity(requested.len());
    let mut unsolicited = 0usize;
    for item in returned {
        let id = extract(&item);
        if requested_set.contains(&id) {
            delivered.insert(id);
            kept.push(item);
        } else {
            unsolicited += 1;
        }
    }
    let missing = requested
        .iter()
        .filter(|id| !delivered.contains(id))
        .cloned()
        .collect();
    Partition {
        kept,
        missing,
        unsolicited,
    }
}

/// Marker type for the per-block transaction fetch.
pub struct TransactionBinding;

impl FetchBinding for TransactionBinding {
    type Id = TxHash;

    const NAME: &'static str = "transaction";

    fn fetch_mut(host: &mut FetchHost) -> &mut Fetch<TxHash> {
        &mut host.transaction
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<TxHash>,
        peers: &FetchPeers,
        origin: FetchOrigin,
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
            origin.class_override(),
            Box::new(move |result| {
                if let Ok(resp) = result {
                    let split = partition_solicited(resp.into_transactions(), &hs, |tx| tx.hash());
                    if !split.kept.is_empty() {
                        let _ = es.send(NodeInput::Protocol(Box::new(
                            ProtocolEvent::TransactionsReceived {
                                transactions: split.kept,
                            },
                        )));
                    }
                    if !split.missing.is_empty() {
                        let _ = es.send(NodeInput::TransactionsFetchFailed {
                            hashes: split.missing.clone(),
                        });
                    }
                    // Reject the response if the peer shipped unsolicited
                    // txs (injection attempt or buggy peer) OR if any
                    // requested hash was missing from the delivery.
                    if split.unsolicited > 0 || !split.missing.is_empty() {
                        ResponseVerdict::Reject
                    } else {
                        ResponseVerdict::Accept
                    }
                } else {
                    let _ = es.send(NodeInput::TransactionsFetchFailed { hashes: hs });
                    ResponseVerdict::Accept
                }
            }),
        );
    }
}

/// Marker type for the per-block local-provision fetch.
pub struct LocalProvisionBinding;

impl FetchBinding for LocalProvisionBinding {
    type Id = ProvisionHash;

    const NAME: &'static str = "local_provision";

    fn fetch_mut(host: &mut FetchHost) -> &mut Fetch<ProvisionHash> {
        &mut host.local_provision
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<ProvisionHash>,
        peers: &FetchPeers,
        origin: FetchOrigin,
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
            origin.class_override(),
            Box::new(move |result| {
                if let Ok(resp) = result {
                    let split = partition_solicited(resp.provisions, &hs, |p| p.hash());
                    for provisions in split.kept {
                        // Refcount is 1 right after decode, so this moves rather than clones.
                        let provisions = Arc::unwrap_or_clone(provisions);
                        let _ = es.send(NodeInput::Protocol(Box::new(
                            ProtocolEvent::ProvisionsReceived { provisions },
                        )));
                    }
                    let had_misses = !split.missing.is_empty();
                    if had_misses {
                        let _ = es.send(NodeInput::LocalProvisionsFetchFailed {
                            hashes: split.missing,
                        });
                    }
                    // Reject the response if the peer shipped unsolicited
                    // provisions OR if any requested hash was missing.
                    if split.unsolicited > 0 || had_misses {
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
}

/// Marker type for the per-block finalized-wave fetch.
pub struct FinalizedWaveBinding;

impl FetchBinding for FinalizedWaveBinding {
    type Id = WaveId;

    const NAME: &'static str = "finalized_wave";

    fn fetch_mut(host: &mut FetchHost) -> &mut Fetch<WaveId> {
        &mut host.finalized_wave
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<WaveId>,
        peers: &FetchPeers,
        origin: FetchOrigin,
        _local_shard: ShardGroupId,
        network: &N,
        sender: &Sender<NodeInput>,
    ) {
        let es = sender.clone();
        let requested_ids = ids.clone();
        network.request(
            &peers.peers,
            peers.preferred,
            GetFinalizedWavesRequest::new(ids),
            origin.class_override(),
            Box::new(move |result| {
                if let Ok(resp) = result {
                    let split =
                        partition_solicited(resp.waves, &requested_ids, |w| w.wave_id().clone());
                    if !split.kept.is_empty() {
                        let _ = es.send(NodeInput::Protocol(Box::new(
                            ProtocolEvent::FinalizedWavesReceived { waves: split.kept },
                        )));
                    }
                    let had_misses = !split.missing.is_empty();
                    if had_misses {
                        let _ =
                            es.send(NodeInput::FinalizedWavesFetchFailed { ids: split.missing });
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
                    let _ = es.send(NodeInput::FinalizedWavesFetchFailed { ids: requested_ids });
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

    fn fetch_mut(host: &mut FetchHost) -> &mut Fetch<WaveId> {
        &mut host.exec_cert
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<WaveId>,
        peers: &FetchPeers,
        origin: FetchOrigin,
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
            origin.class_override(),
            Box::new(move |result| {
                if let Ok(response) = result {
                    let certs = response.certificates.unwrap_or_default();
                    let split = partition_solicited(certs, &failed_ids, |c| c.wave_id.clone());
                    let had_misses = !split.missing.is_empty();
                    if !split.kept.is_empty() {
                        // Refcount is 1 right after decode, so each unwrap moves.
                        let certificates =
                            split.kept.into_iter().map(Arc::unwrap_or_clone).collect();
                        let _ = es.send(NodeInput::Protocol(Box::new(
                            ProtocolEvent::ExecutionCertificatesReceived { certificates },
                        )));
                    }
                    if had_misses {
                        let _ = es.send(NodeInput::ExecCertFetchFailed {
                            hashes: split.missing,
                        });
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
                    let _ = es.send(NodeInput::ExecCertFetchFailed { hashes: failed_ids });
                    ResponseVerdict::Accept
                }
            }),
        );
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

    fn fetch_mut(host: &mut FetchHost) -> &mut Fetch<Self::Id> {
        &mut host.provision
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<(ShardGroupId, BlockHeight)>,
        peers: &FetchPeers,
        origin: FetchOrigin,
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
            origin.class_override(),
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
                        expected_source = source_shard.inner(),
                        got_source = provisions.source_shard.inner(),
                        expected_target = target_shard.inner(),
                        got_target = provisions.target_shard.inner(),
                        expected_height = block_height.inner(),
                        got_height = provisions.block_height.inner(),
                        "Dropping provision fetch response: scope mismatch"
                    );
                    let _ = es.send(NodeInput::ProvisionsFetchFailed {
                        source_shard,
                        block_height,
                    });
                    return ResponseVerdict::Reject;
                }
                if provisions.transactions.is_empty() {
                    // Empty-but-scope-matched response is still a miss for
                    // the requester: the FSM has nothing to admit, so
                    // without an explicit `Failed` the id stays in_flight
                    // forever.
                    let _ = es.send(NodeInput::ProvisionsFetchFailed {
                        source_shard,
                        block_height,
                    });
                    return ResponseVerdict::Reject;
                }
                // Refcount is 1 right after decode, so this moves rather than clones.
                let provisions = Arc::unwrap_or_clone(provisions);
                let _ = es.send(NodeInput::Protocol(Box::new(
                    ProtocolEvent::ProvisionsReceived { provisions },
                )));
                ResponseVerdict::Accept
            }),
        );
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::RoutableTransaction;
    use hyperscale_types::test_utils::test_transaction;

    use super::*;

    fn tx_arc(seed: u8) -> Arc<RoutableTransaction> {
        Arc::new(test_transaction(seed))
    }

    fn tx_hash(tx: &Arc<RoutableTransaction>) -> TxHash {
        tx.hash()
    }

    #[test]
    fn partition_keeps_only_solicited_and_flags_extras() {
        // Requested two known hashes; peer ships one we asked for plus one
        // we never asked for. The unsolicited tx must be dropped from the
        // delivery and counted in `unsolicited`.
        let asked = tx_arc(1);
        let asked_hash = asked.hash();
        let extra = tx_arc(99);
        let other_requested = tx_arc(2).hash();

        let split = partition_solicited(
            vec![Arc::clone(&asked), Arc::clone(&extra)],
            &[asked_hash, other_requested],
            tx_hash,
        );
        assert_eq!(split.kept.len(), 1);
        assert_eq!(split.kept[0].hash(), asked_hash);
        assert_eq!(split.unsolicited, 1);
        assert_eq!(split.missing, vec![other_requested]);
    }

    #[test]
    fn partition_full_delivery_yields_no_missing_no_unsolicited() {
        let a = tx_arc(1);
        let b = tx_arc(2);
        let split = partition_solicited(
            vec![Arc::clone(&a), Arc::clone(&b)],
            &[a.hash(), b.hash()],
            tx_hash,
        );
        assert_eq!(split.kept.len(), 2);
        assert!(split.missing.is_empty());
        assert_eq!(split.unsolicited, 0);
    }

    #[test]
    fn partition_only_unsolicited_yields_kept_empty_all_missing() {
        let bogus_a = tx_arc(50);
        let bogus_b = tx_arc(51);
        let wanted_1 = tx_arc(1).hash();
        let wanted_2 = tx_arc(2).hash();

        let split = partition_solicited(vec![bogus_a, bogus_b], &[wanted_1, wanted_2], tx_hash);
        assert!(split.kept.is_empty());
        assert_eq!(split.unsolicited, 2);
        assert_eq!(split.missing.len(), 2);
    }

    #[test]
    fn partition_works_for_non_copy_id_via_clone() {
        // Sanity-check that the generic helper accepts a Clone (non-Copy)
        // id type; WaveId is the production motivator here.
        #[derive(Clone, Eq, Hash, PartialEq, Debug)]
        struct CompoundId(String);
        struct Item(CompoundId);

        let a = Item(CompoundId("a".into()));
        let b = Item(CompoundId("b".into()));
        let split = partition_solicited(
            vec![a, b],
            &[CompoundId("a".into()), CompoundId("c".into())],
            |it| it.0.clone(),
        );
        assert_eq!(split.kept.len(), 1);
        assert_eq!(split.unsolicited, 1);
        assert_eq!(split.missing, vec![CompoundId("c".into())]);
    }

    #[test]
    fn partition_filters_unsolicited_local_provisions() {
        // The LocalProvisionBinding admits each kept item as a separate
        // ProvisionsReceived event, which buffers in the provision pipeline
        // before signature/merkle verification — so unsolicited deliveries
        // must be dropped at the response boundary.
        use hyperscale_types::{
            BlockHeight, Hash, MerkleInclusionProof, Provisions, ShardGroupId, TxEntries, TxHash,
        };
        let asked = Arc::new(Provisions::new(
            ShardGroupId::new(1),
            ShardGroupId::new(2),
            BlockHeight::new(10),
            MerkleInclusionProof::dummy(),
            vec![TxEntries {
                tx_hash: TxHash::from_raw(Hash::from_bytes(b"asked")),
                entries: vec![],
                target_nodes: vec![],
            }],
        ));
        let extra = Arc::new(Provisions::new(
            ShardGroupId::new(3),
            ShardGroupId::new(2),
            BlockHeight::new(11),
            MerkleInclusionProof::dummy(),
            vec![TxEntries {
                tx_hash: TxHash::from_raw(Hash::from_bytes(b"extra")),
                entries: vec![],
                target_nodes: vec![],
            }],
        ));
        let asked_hash = asked.hash();
        let split = partition_solicited(
            vec![Arc::clone(&asked), Arc::clone(&extra)],
            &[asked_hash],
            |p| p.hash(),
        );
        assert_eq!(split.kept.len(), 1);
        assert_eq!(split.kept[0].hash(), asked_hash);
        assert_eq!(split.unsolicited, 1);
        assert!(split.missing.is_empty());
    }
}
