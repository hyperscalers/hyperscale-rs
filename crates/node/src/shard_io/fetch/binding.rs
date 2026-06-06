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
//! `NodeHost` invokes the trait methods through generic helpers
//! (`process_fetch_outputs`, `dispatch_fetch_request`), so adding a new
//! payload means writing one impl block here — not editing three parallel
//! files.

use std::collections::HashSet;
use std::hash::Hash;
use std::sync::Arc;

use crossbeam::channel::Sender;
use hyperscale_core::ProtocolEvent;
use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_types::network::request::beacon::{
    GetBeaconProposalRequest, GetShardWitnessesRequest,
};
use hyperscale_types::network::request::{
    GetExecutionCertsRequest, GetFinalizedWavesRequest, GetLocalProvisionsRequest,
    GetProvisionsRequest, GetTransactionsRequest,
};
use hyperscale_types::{
    BlockHash, BlockHeight, Epoch, ExecutionCertificate, FinalizedWave, LeafIndex, MessageClass,
    ProvisionHash, ShardId, ShardWitness, TxHash, ValidatorId, Verifiable, WaveId,
};

use super::Fetch;
use super::host::FetchHost;
use crate::shard_loop::{ShardEvent, ShardScopedInput, push_protocol_event, push_shard_input};

// ─── Type aliases used across the module tree ──────────────────────────

/// Per-tx fetch keyed by [`TxHash`].
pub type TransactionFetch = Fetch<TxHash>;
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
/// Cross-shard beacon-witness fetch keyed by
/// `(source_shard, block_height, committed_block_hash, leaf_index)`.
/// Each id is a single leaf in the source shard's accumulator at the
/// named committed block.
pub type ShardWitnessFetch = Fetch<(ShardId, BlockHeight, BlockHash, LeafIndex)>;
/// Missing-proposal fetch keyed by `(epoch, validator)` — one entry
/// per beacon-committee member whose proposal SPC's `OutputHigh`
/// committed but the local pool never observed.
pub type BeaconProposalFetch = Fetch<(Epoch, ValidatorId)>;

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

    /// Send one request covering `ids` against `shard`'s committee and
    /// route the response back through the event sender. `class` flows
    /// down to `Network::request` as the per-call class override. For
    /// [`PER_ID`](Self::PER_ID) bindings the dispatcher pre-splits into
    /// single-element chunks before calling this.
    ///
    /// `local_shard` is the hosted shard whose `FetchHost` produced this
    /// request — it's threaded into the response callback so the resulting
    /// `ShardScopedInput::Protocol` and `*FetchFailed` events route to the right
    /// hosted shard under cross-shard hosting (distinct from `shard`,
    /// which selects the *target* committee).
    fn dispatch_chunk<N: Network>(
        ids: Vec<Self::Id>,
        local_shard: ShardId,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
        network: &N,
        sender: &Sender<ShardEvent>,
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
        local_shard: ShardId,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
        network: &N,
        sender: &Sender<ShardEvent>,
    ) {
        let es = sender.clone();
        let hs = ids.clone();
        network.request(
            shard,
            preferred,
            GetTransactionsRequest::new(ids),
            class,
            Box::new(move |result| {
                if let Ok(resp) = result {
                    let split = partition_solicited(resp.into_transactions(), &hs, |tx| tx.hash());
                    if !split.kept.is_empty() {
                        push_shard_input(
                            &es,
                            local_shard,
                            ShardScopedInput::TransactionsFetched { batch: split.kept },
                        );
                    }
                    if !split.missing.is_empty() {
                        push_shard_input(
                            &es,
                            local_shard,
                            ShardScopedInput::TransactionsFetchFailed {
                                hashes: split.missing.clone(),
                            },
                        );
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
                    push_shard_input(
                        &es,
                        local_shard,
                        ShardScopedInput::TransactionsFetchFailed { hashes: hs },
                    );
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
        local_shard: ShardId,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
        network: &N,
        sender: &Sender<ShardEvent>,
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

    fn fetch_mut(host: &mut FetchHost) -> &mut Fetch<WaveId> {
        &mut host.finalized_wave
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<WaveId>,
        local_shard: ShardId,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
        network: &N,
        sender: &Sender<ShardEvent>,
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

    fn fetch_mut(host: &mut FetchHost) -> &mut Fetch<WaveId> {
        &mut host.exec_cert
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<WaveId>,
        local_shard: ShardId,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
        network: &N,
        sender: &Sender<ShardEvent>,
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

    fn fetch_mut(host: &mut FetchHost) -> &mut Fetch<Self::Id> {
        &mut host.provision
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<(ShardId, ShardId, BlockHeight)>,
        local_shard: ShardId,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
        network: &N,
        sender: &Sender<ShardEvent>,
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

/// Marker type for the cross-shard beacon-witness fetch.
pub struct ShardWitnessBinding;

impl FetchBinding for ShardWitnessBinding {
    type Id = (ShardId, BlockHeight, BlockHash, LeafIndex);

    const NAME: &'static str = "shard_witness";

    /// One request per leaf — keeps the dispatcher simple. The
    /// underlying wire type can carry many leaves per request; a
    /// future grouping optimisation can chunk-batch leaves that
    /// share `(shard, block_height, committed_block_hash)`.
    const PER_ID: bool = true;

    fn fetch_mut(host: &mut FetchHost) -> &mut Fetch<Self::Id> {
        &mut host.shard_witness
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<Self::Id>,
        local_shard: ShardId,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
        network: &N,
        sender: &Sender<ShardEvent>,
    ) {
        debug_assert_eq!(ids.len(), 1, "PER_ID binding hands one id per chunk");
        let (source_shard, block_height, committed_block_hash, leaf_index) = ids[0];
        debug_assert_eq!(
            shard, source_shard,
            "ShardWitnessBinding routes to the source shard; the runner sets it from the variant",
        );
        let request = GetShardWitnessesRequest::new(
            source_shard,
            block_height,
            committed_block_hash,
            vec![leaf_index],
        );
        let es = sender.clone();
        network.request(
            shard,
            preferred,
            request,
            class,
            Box::new(move |result| {
                let push_failed = || {
                    push_shard_input(
                        &es,
                        local_shard,
                        ShardScopedInput::ShardWitnessesFetchFailed {
                            ids: vec![(
                                source_shard,
                                block_height,
                                committed_block_hash,
                                leaf_index,
                            )],
                        },
                    );
                };
                let Ok(response) = result else {
                    push_failed();
                    return ResponseVerdict::Accept;
                };
                if response.witnesses.is_empty() {
                    push_failed();
                    return ResponseVerdict::Reject;
                }
                let witnesses: Vec<Arc<ShardWitness>> = response.witnesses.into_inner();
                push_protocol_event(
                    &es,
                    local_shard,
                    ProtocolEvent::ShardWitnessesReceived {
                        shard_id: source_shard,
                        witnesses,
                    },
                );
                ResponseVerdict::Accept
            }),
        );
    }
}

/// Marker type for the missing-proposal fetch.
pub struct BeaconProposalBinding;

impl FetchBinding for BeaconProposalBinding {
    type Id = (Epoch, ValidatorId);

    const NAME: &'static str = "beacon_proposal";

    /// One request per `(epoch, validator)` — the wire type addresses
    /// a single proposal.
    const PER_ID: bool = true;

    fn fetch_mut(host: &mut FetchHost) -> &mut Fetch<Self::Id> {
        &mut host.beacon_proposal
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<Self::Id>,
        local_shard: ShardId,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
        network: &N,
        sender: &Sender<ShardEvent>,
    ) {
        debug_assert_eq!(ids.len(), 1, "PER_ID binding hands one id per chunk");
        let (epoch, validator) = ids[0];
        let request = GetBeaconProposalRequest::new(epoch, validator);
        let es = sender.clone();
        network.request(
            shard,
            preferred,
            request,
            class,
            Box::new(move |result| {
                let push_failed = || {
                    push_shard_input(
                        &es,
                        local_shard,
                        ShardScopedInput::BeaconProposalFetchFailed {
                            ids: vec![(epoch, validator)],
                        },
                    );
                };
                let Ok(response) = result else {
                    push_failed();
                    return ResponseVerdict::Accept;
                };
                let was_empty = response.proposal.is_none();
                push_protocol_event(
                    &es,
                    local_shard,
                    ProtocolEvent::BeaconProposalFetched {
                        epoch,
                        validator,
                        proposal: response.proposal,
                    },
                );
                if was_empty {
                    ResponseVerdict::Reject
                } else {
                    ResponseVerdict::Accept
                }
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
        // UnverifiedProvisionsReceived event, which buffers in the provision pipeline
        // before signature/merkle verification — so unsolicited deliveries
        // must be dropped at the response boundary.
        use hyperscale_types::{
            BlockHeight, Hash, MerkleInclusionProof, ProvisionEntry, Provisions, ShardId, TxHash,
        };
        let asked = Arc::new(Provisions::new(
            ShardId::leaf(2, 1),
            ShardId::leaf(2, 2),
            BlockHeight::new(10),
            MerkleInclusionProof::dummy(),
            vec![ProvisionEntry::new(
                TxHash::from_raw(Hash::from_bytes(b"asked")),
                vec![],
                vec![],
                vec![],
            )],
        ));
        let extra = Arc::new(Provisions::new(
            ShardId::leaf(2, 3),
            ShardId::leaf(2, 2),
            BlockHeight::new(11),
            MerkleInclusionProof::dummy(),
            vec![ProvisionEntry::new(
                TxHash::from_raw(Hash::from_bytes(b"extra")),
                vec![],
                vec![],
                vec![],
            )],
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
