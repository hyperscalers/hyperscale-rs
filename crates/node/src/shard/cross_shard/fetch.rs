//! Cross-shard fetch bindings.
//!
//! The [`FetchBinding`] impls for the cross-shard data-availability payloads —
//! provisions, execution certificates, finalizations, local provisions, and
//! the answers checked against a remote chain's committed state.
//! Each `fetch_mut` resolves the binding's `Fetch` instance out of this shard's
//! [`CrossShardState`](super::CrossShardState). The generic engine, the
//! `FetchBinding` trait, and the shared `partition_solicited` helper live in
//! [`crate::fetch`].

use std::sync::Arc;

use crossbeam::channel::Sender;
use hyperscale_core::{FetchIds, ProtocolEvent};
use hyperscale_metrics::record_fetch_response_refused;
use hyperscale_network::{Network, RequestError, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::request::{
    GetCommittedTxsRequest, GetExecutionCertsRequest, GetFinalizationsRequest,
    GetLocalProvisionsRequest, GetProvisionsRequest, GetRelayedStateProofRequest,
    GetSettledTxsRequest, GetStateProofRequest,
};
use hyperscale_types::network::response::{
    CommittedTxVerdict, GetCommittedTxsResponse, GetSettledTxsResponse, GetStateProofResponse,
};
use hyperscale_types::{
    Anchor, BlockHeight, ExecutionCertificate, Finalization, FinalizationHash, MessageClass,
    PredecessorTerminal, ProvisionHash, ShardId, SubstateKey, TerminalEvidence, TxHash,
    ValidatorId, Verifiable, settled_txs_root_from_hashes,
};

use crate::fetch::{
    Fetch, FetchBinding, Refusal, ScopedAnswer, dispatch_scoped, partition_solicited,
};
use crate::shard::{HostEvent, ShardIo, ShardScopedInput, push_protocol_event, push_shard_input};

// ─── Type aliases ──────────────────────────────────────────────────────
/// Local-provision fetch keyed by [`ProvisionHash`].
pub type LocalProvisionFetch = Fetch<ProvisionHash>;
/// Finalization fetch keyed by [`TickId`].
pub type FinalizationFetch = Fetch<FinalizationHash>;
/// Cross-shard execution-cert fetch keyed by [`TickId`].
pub type ExecCertFetch = Fetch<(ShardId, TxHash)>;
/// Cross-shard provision fetch keyed by
/// `(source_shard, target_shard, block_height)`. `source_shard` selects
/// the responding committee; `target_shard` rides in the body for
/// response filtering on the responder.
pub type ProvisionFetch = Fetch<(ShardId, ShardId, BlockHeight)>;
/// Committed-transaction membership fetch keyed by
/// `(predecessor, tx_hash)`. The predecessor's shard selects the
/// responding committee, its terminal rides in the body as the window to
/// reconstruct, and its `committed_txs_root` is the key each absence
/// proof is checked against.
pub type CommittedTxFetch = Fetch<(PredecessorTerminal, TxHash)>;
pub type StateProofFetch = Fetch<(Anchor, SubstateKey)>;
/// Settled-set fetch keyed by the departed shard's terminal evidence:
/// the terminal the window is reconstructed from and the root the list
/// must recompute to.
pub type SettledTxsFetch = Fetch<TerminalEvidence>;

// ─── Bindings ──────────────────────────────────────────────────────────

/// Marker type for the per-block local-provision fetch.
pub struct LocalProvisionBinding;

impl FetchBinding for LocalProvisionBinding {
    type Id = ProvisionHash;

    const NAME: &'static str = "local_provision";

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::LocalProvisions(ids)
    }

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
                    let split =
                        partition_solicited(resp.entries, &hs, |entry| [entry.provisions.hash()]);
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
                            ShardScopedInput::FetchFailed(Self::ids(split.missing)),
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
                        ShardScopedInput::FetchFailed(Self::ids(hs)),
                    );
                    ResponseVerdict::Accept
                }
            }),
        );
    }
}

/// Marker type for the per-block finalization fetch.
pub struct FinalizationBinding;

impl FetchBinding for FinalizationBinding {
    type Id = FinalizationHash;

    const NAME: &'static str = "finalization";

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::Finalizations(ids)
    }

    fn fetch_mut<S: ShardStorage>(shard: &mut ShardIo<S>) -> &mut Fetch<FinalizationHash> {
        &mut shard.cross_shard.finalization
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<FinalizationHash>,
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
            GetFinalizationsRequest::new(ids),
            class,
            Box::new(move |result| {
                if let Ok(resp) = result {
                    let split = partition_solicited(resp.finalizations, &requested_ids, |w| {
                        [w.receipt_hash()]
                    });
                    if !split.kept.is_empty() {
                        // Refcount is 1 right after decode, so each unwrap moves.
                        let finalizations: Vec<Arc<Verifiable<Finalization>>> = split
                            .kept
                            .into_iter()
                            .map(|arc| Arc::new(Arc::unwrap_or_clone(arc).into()))
                            .collect();
                        push_protocol_event(
                            &es,
                            local_shard,
                            ProtocolEvent::FinalizationsReceived { finalizations },
                        );
                    }
                    let had_misses = !split.missing.is_empty();
                    if had_misses {
                        push_shard_input(
                            &es,
                            local_shard,
                            ShardScopedInput::FetchFailed(Self::ids(split.missing)),
                        );
                    }
                    // Reject responses with unsolicited ticks (peer scoring;
                    // also avoids wasted signature verification on items we never
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
                        ShardScopedInput::FetchFailed(Self::ids(requested_ids)),
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
    /// `(source_shard, tx_hash)` — the shard whose outcome is missing and
    /// the transaction it is missing for. The certificate's own identity
    /// is not a key here: the requester knows which shards its tick waits
    /// on, not which certificate each will put the transaction in.
    type Id = (ShardId, TxHash);

    const NAME: &'static str = "exec_cert";

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::ExecutionCerts(ids)
    }

    fn fetch_mut<S: ShardStorage>(shard: &mut ShardIo<S>) -> &mut Fetch<(ShardId, TxHash)> {
        &mut shard.cross_shard.exec_cert
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<(ShardId, TxHash)>,
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
            GetExecutionCertsRequest {
                tx_hashes: ids.into_iter().map(|(_, tx_hash)| tx_hash).collect(),
            },
            class,
            Box::new(move |result| {
                if let Ok(response) = result {
                    let certs = response.certificates.unwrap_or_default();
                    // One certificate answers for every transaction of its
                    // batch, so it clears every requested key it covers.
                    let split = partition_solicited(certs, &failed_ids, |c| {
                        let cert_shard = c.shard_id();
                        c.tx_outcomes()
                            .iter()
                            .map(|outcome| (cert_shard, outcome.tx_hash()))
                            .collect::<Vec<_>>()
                    });
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
                            ShardScopedInput::FetchFailed(Self::ids(split.missing)),
                        );
                    }
                    // Reject the response if the peer shipped unsolicited
                    // ECs (peer scoring; also avoids wasted signature verification
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
                        ShardScopedInput::FetchFailed(Self::ids(failed_ids)),
                    );
                    ResponseVerdict::Accept
                }
            }),
        );
    }
}

/// Pair a committed-transaction response with the transactions it
/// answers for, or `None` when the response is unusable.
///
/// Verdicts are positional, so a length that doesn't match the request
/// is malformed rather than partial — nothing in it can be paired up.
/// Absence is the answer that relaxes the successor's standing refusal,
/// so it is the one that has to lift to `terminal.committed_txs_root`;
/// `Committed` is what the successor already assumes and carries no
/// proof.
///
/// One bad entry condemns the whole response rather than being skipped.
/// A peer that got any of it wrong has said nothing this node can lift
/// to the attested root, and picking through it would let a peer choose
/// which questions get answered.
fn verified_answers(
    verdicts: &[CommittedTxVerdict],
    terminal: PredecessorTerminal,
    tx_hashes: &[TxHash],
) -> Option<Vec<(TxHash, bool)>> {
    if verdicts.len() != tx_hashes.len() {
        return None;
    }
    verdicts
        .iter()
        .zip(tx_hashes)
        .map(|(verdict, hash)| match verdict {
            CommittedTxVerdict::Committed => Some((*hash, false)),
            CommittedTxVerdict::Absent(proof) => proof
                .proves_absent(hash, terminal.committed_txs_root)
                .then_some((*hash, true)),
        })
        .collect()
}

/// Marker type for the committed-transaction membership fetch.
pub struct CommittedTxBinding;

impl FetchBinding for CommittedTxBinding {
    /// `(predecessor, tx_hash)` — the chain that ran before this one and
    /// a transaction whose membership in its committed set decides
    /// whether this chain may admit it. The predecessor rides whole
    /// because the request names its terminal and the answer is checked
    /// against that terminal's root.
    type Id = (PredecessorTerminal, TxHash);

    const NAME: &'static str = "committed_tx";

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::CommittedTxs(ids)
    }

    fn fetch_mut<S: ShardStorage>(shard: &mut ShardIo<S>) -> &mut Fetch<Self::Id> {
        &mut shard.cross_shard.committed_tx
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<Self::Id>,
        local_shard: ShardId,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
        network: &N,
        sender: &Sender<HostEvent>,
    ) {
        dispatch_scoped::<Self, N>(ids, local_shard, shard, preferred, class, network, sender);
    }
}

impl ScopedAnswer for CommittedTxBinding {
    type Scope = PredecessorTerminal;
    type Key = TxHash;
    type Request = GetCommittedTxsRequest;

    fn split(id: Self::Id) -> (Self::Scope, Self::Key) {
        id
    }

    fn join(scope: Self::Scope, key: Self::Key) -> Self::Id {
        (scope, key)
    }

    fn request(scope: Self::Scope, keys: &[Self::Key]) -> Self::Request {
        GetCommittedTxsRequest::new(scope.height, scope.block_hash, keys.to_vec())
    }

    /// Absence is the answer that relaxes the successor's standing
    /// refusal, so it is the one that has to lift to the terminal's
    /// `committed_txs_root`; `Committed` is what the successor already
    /// assumes and carries no proof.
    fn answer(
        scope: Self::Scope,
        keys: Vec<Self::Key>,
        response: GetCommittedTxsResponse,
    ) -> Result<ProtocolEvent, Refusal> {
        let verdicts = response.verdicts.ok_or(Refusal::NotHeld)?;
        let answers = verified_answers(&verdicts, scope, &keys)
            .ok_or(Refusal::Unusable("unusable_verdicts"))?;
        Ok(ProtocolEvent::PrecutResolutionsReceived {
            predecessor: scope.shard,
            answers,
        })
    }
}

/// Marker type for the state-proof fetch against a commit-proven remote
/// header.
pub struct StateProofBinding;

impl FetchBinding for StateProofBinding {
    /// `(anchor, key)` — the commit-proven state the proof reconstructs
    /// and one key whose presence under it is asked. The anchor rides
    /// whole because its root is what the answer is checked against
    /// before it reaches the coordinator.
    type Id = (Anchor, SubstateKey);

    const NAME: &'static str = "state_proof";

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::StateProofs(ids)
    }

    fn fetch_mut<S: ShardStorage>(shard: &mut ShardIo<S>) -> &mut Fetch<Self::Id> {
        &mut shard.cross_shard.state_proof
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<Self::Id>,
        local_shard: ShardId,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
        network: &N,
        sender: &Sender<HostEvent>,
    ) {
        dispatch_scoped::<Self, N>(ids, local_shard, shard, preferred, class, network, sender);
    }
}

impl ScopedAnswer for StateProofBinding {
    type Scope = Anchor;
    type Key = SubstateKey;
    type Request = GetStateProofRequest;

    fn split(id: Self::Id) -> (Self::Scope, Self::Key) {
        id
    }

    fn join(scope: Self::Scope, key: Self::Key) -> Self::Id {
        (scope, key)
    }

    fn request(scope: Self::Scope, keys: &[Self::Key]) -> Self::Request {
        GetStateProofRequest::new(scope.height, keys.to_vec())
    }

    /// Checked here so an unusable proof rotates the peer rather than
    /// reaching a block. What it says is read off the block that carries
    /// it, by every replica.
    fn answer(
        scope: Self::Scope,
        keys: Vec<Self::Key>,
        response: GetStateProofResponse,
    ) -> Result<ProtocolEvent, Refusal> {
        let proof = response.proof.ok_or(Refusal::NotHeld)?;
        proof
            .inclusions(scope.state_root, scope.shard, &keys)
            .map_err(|_| Refusal::Unusable("unusable_proof"))?;
        Ok(ProtocolEvent::FetchedStateProofVerified {
            anchor: scope,
            keys,
            proof,
        })
    }
}

/// Marker type for the state-proof relay: the same question as
/// [`StateProofBinding`], put to this shard's own committee.
///
/// A separate binding rather than a routing argument on that one,
/// because a fetch is keyed by its ids: the two ask different committees
/// about the same `(anchor, key)`, and one slot would hold whichever
/// asked first. The answer is the same event, since a proof is checked
/// against the anchor's root whoever served it.
pub struct StateProofRelayBinding;

impl FetchBinding for StateProofRelayBinding {
    /// `(anchor, key)`, as [`StateProofBinding`].
    type Id = (Anchor, SubstateKey);

    const NAME: &'static str = "relayed_state_proof";

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::RelayedStateProofs(ids)
    }

    fn fetch_mut<S: ShardStorage>(shard: &mut ShardIo<S>) -> &mut Fetch<Self::Id> {
        &mut shard.cross_shard.relayed_state_proof
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<Self::Id>,
        local_shard: ShardId,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
        network: &N,
        sender: &Sender<HostEvent>,
    ) {
        dispatch_scoped::<Self, N>(ids, local_shard, shard, preferred, class, network, sender);
    }
}

impl ScopedAnswer for StateProofRelayBinding {
    type Scope = Anchor;
    type Key = SubstateKey;
    type Request = GetRelayedStateProofRequest;

    fn split(id: Self::Id) -> (Self::Scope, Self::Key) {
        id
    }

    fn join(scope: Self::Scope, key: Self::Key) -> Self::Id {
        (scope, key)
    }

    /// The anchor's shard rides in the body: the request goes to this
    /// shard's committee, and what it asks about is another shard's
    /// state.
    fn request(scope: Self::Scope, keys: &[Self::Key]) -> Self::Request {
        GetRelayedStateProofRequest::new(scope.shard, scope.height, keys.to_vec())
    }

    /// Checked here, against the anchor the requester commit-proved, so
    /// a peer passing on a proof of any other tree rotates rather than
    /// being believed.
    fn answer(
        scope: Self::Scope,
        keys: Vec<Self::Key>,
        response: GetStateProofResponse,
    ) -> Result<ProtocolEvent, Refusal> {
        let proof = response.proof.ok_or(Refusal::NotHeld)?;
        proof
            .inclusions(scope.state_root, scope.shard, &keys)
            .map_err(|_| Refusal::Unusable("unusable_proof"))?;
        Ok(ProtocolEvent::FetchedStateProofVerified {
            anchor: scope,
            keys,
            proof,
        })
    }
}

/// Marker type for the settled-set fetch against a departed shard's
/// terminal.
pub struct SettledTxsBinding;

impl FetchBinding for SettledTxsBinding {
    /// The terminal to ask for and the root the answer must recompute
    /// to, read off this node's own beacon fold. A revised terminal is a
    /// different id.
    type Id = TerminalEvidence;

    const NAME: &'static str = "settled_txs";

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::SettledTxs(ids)
    }

    fn fetch_mut<S: ShardStorage>(shard: &mut ShardIo<S>) -> &mut Fetch<Self::Id> {
        &mut shard.cross_shard.settled_txs
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<Self::Id>,
        local_shard: ShardId,
        shard: ShardId,
        preferred: Option<ValidatorId>,
        class: Option<MessageClass>,
        network: &N,
        sender: &Sender<HostEvent>,
    ) {
        dispatch_scoped::<Self, N>(ids, local_shard, shard, preferred, class, network, sender);
    }
}

/// One request reconstructs one terminal's whole window, so the evidence
/// is the scope and the question under it is the window itself.
impl ScopedAnswer for SettledTxsBinding {
    type Scope = TerminalEvidence;
    type Key = ();
    type Request = GetSettledTxsRequest;

    fn split(id: Self::Id) -> (Self::Scope, Self::Key) {
        (id, ())
    }

    fn join(scope: Self::Scope, (): Self::Key) -> Self::Id {
        scope
    }

    fn request(scope: Self::Scope, _keys: &[Self::Key]) -> Self::Request {
        GetSettledTxsRequest::new(scope.height, scope.block_hash)
    }

    /// The list is complete or it is nothing: a root over the whole
    /// window means a peer can neither hide a settled transaction nor
    /// add one, which is what makes every absence from the set sound.
    fn answer(
        scope: Self::Scope,
        _keys: Vec<Self::Key>,
        response: GetSettledTxsResponse,
    ) -> Result<ProtocolEvent, Refusal> {
        let txs = response.txs.ok_or(Refusal::NotHeld)?;
        if settled_txs_root_from_hashes(txs.iter()) != scope.attested_root {
            return Err(Refusal::Unusable("root_mismatch"));
        }
        Ok(ProtocolEvent::SettledTxsReconstructed {
            shard: scope.shard,
            txs: txs.into_iter().collect(),
            terminal_wt: scope.terminal_wt,
        })
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

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::RemoteProvisions(ids)
    }

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
                        ShardScopedInput::FetchFailed(Self::ids(vec![(
                            source_shard,
                            target_shard,
                            block_height,
                        )])),
                    );
                };
                let response = match result {
                    Ok(response) => response,
                    Err(error) => {
                        if matches!(error, RequestError::PeerError(_)) {
                            record_fetch_response_refused("provision", "unusable_answer");
                        }
                        push_fetch_failed();
                        return ResponseVerdict::Accept;
                    }
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
                    record_fetch_response_refused("provision", "scope_mismatch");
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

#[cfg(test)]
mod committed_tx_tests {
    use hyperscale_types::{
        BlockHash, BlockHeight, CommittedTxsRoot, Hash, committed_txs_root_from_hashes,
        prove_committed_tx_absent,
    };

    use super::*;

    fn tx(seed: u8) -> TxHash {
        TxHash::from(Hash::from_bytes(&[seed]))
    }

    /// A committed set of seeds 0..8 and the terminal that roots it.
    fn terminal_over(seeds: std::ops::Range<u8>) -> (PredecessorTerminal, Vec<TxHash>) {
        let mut members: Vec<TxHash> = seeds.map(tx).collect();
        members.sort_unstable();
        let terminal = PredecessorTerminal {
            shard: ShardId::leaf(1, 0),
            height: BlockHeight::new(9),
            block_hash: BlockHash::ZERO,
            committed_txs_root: committed_txs_root_from_hashes(members.iter()),
        };
        (terminal, members)
    }

    fn absence(members: &[TxHash], probe: TxHash) -> CommittedTxVerdict {
        CommittedTxVerdict::Absent(
            prove_committed_tx_absent(members, &probe).expect("probe is not a member"),
        )
    }

    /// The two verdicts map to the two answers, in the order asked.
    #[test]
    fn verifies_each_answer_against_the_terminal_root() {
        let (terminal, members) = terminal_over(0..8);
        let probe = tx(200);
        let answers = verified_answers(
            &[CommittedTxVerdict::Committed, absence(&members, probe)],
            terminal,
            &[members[0], probe],
        )
        .expect("both verdicts are usable");
        assert_eq!(answers, vec![(members[0], false), (probe, true)]);
    }

    /// An absence proof lifted from a different set doesn't verify
    /// against this terminal's root, and the whole response goes with it
    /// — including the `Committed` answer beside it, which on its own
    /// would have been fine.
    #[test]
    fn a_proof_against_another_root_condemns_the_response() {
        let (terminal, _) = terminal_over(0..8);
        let (_, other_members) = terminal_over(100..108);
        let probe = tx(200);
        assert!(
            verified_answers(
                &[
                    CommittedTxVerdict::Committed,
                    absence(&other_members, probe)
                ],
                terminal,
                &[tx(0), probe],
            )
            .is_none()
        );
    }

    /// A transaction the predecessor really committed cannot be shown
    /// absent: no proof over the rooted set brackets a member.
    #[test]
    fn a_member_has_no_absence_proof() {
        let (_, members) = terminal_over(0..8);
        assert!(prove_committed_tx_absent(&members, &members[3]).is_none());
    }

    /// Short and long answers are both malformed rather than partial —
    /// positional pairing has nothing to anchor on.
    #[test]
    fn a_length_mismatch_is_unusable() {
        let (terminal, _) = terminal_over(0..8);
        assert!(
            verified_answers(&[CommittedTxVerdict::Committed], terminal, &[tx(0), tx(1)]).is_none()
        );
        assert!(
            verified_answers(
                &[CommittedTxVerdict::Committed, CommittedTxVerdict::Committed],
                terminal,
                &[tx(0)],
            )
            .is_none()
        );
    }

    /// An empty set roots to `ZERO` and every absence over it is free,
    /// so a predecessor that committed nothing in its window answers
    /// every query without a tree to walk.
    #[test]
    fn an_empty_committed_set_proves_every_absence() {
        let terminal = PredecessorTerminal {
            shard: ShardId::leaf(1, 0),
            height: BlockHeight::new(9),
            block_hash: BlockHash::ZERO,
            committed_txs_root: CommittedTxsRoot::ZERO,
        };
        let probe = tx(7);
        let answers = verified_answers(&[absence(&[], probe)], terminal, &[probe])
            .expect("absence over an empty set verifies");
        assert_eq!(answers, vec![(probe, true)]);
    }
}

#[cfg(test)]
mod settled_txs_tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    use hyperscale_storage::PendingChain;
    use hyperscale_storage::test_helpers::{commit_settled_at, make_test_certified};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::{
        AggregateSignature, BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHash,
        BlockHeader, BlockHeaderParts, BlockHeight, CertificateRoot, ChainOrigin,
        ExecutionCertificate, ExecutionOutcome, Finalization, GlobalReceiptHash, GlobalReceiptRoot,
        Hash, ProposerTimestamp, QuorumCertificate, Round, SettledTxsRoot, SignerBitfield,
        TickHalf, TickId, TxOutcome, Verified, WeightedTimestamp, WitnessSources,
    };

    use super::*;
    use crate::shard::cross_shard::serve_settled_txs_request;

    const SHARD: ShardId = ShardId::ROOT;

    /// The transaction the tick at `height` settles — distinct per tick,
    /// so a window over several ticks has one entry each.
    fn settled_tx(height: u64) -> TxHash {
        TxHash::from(Hash::from_bytes(&height.to_le_bytes()))
    }

    fn certificate(tick: TickId, height: u64) -> Arc<ExecutionCertificate> {
        Arc::new(ExecutionCertificate::new(
            tick,
            WeightedTimestamp::from_millis(1),
            GlobalReceiptRoot::ZERO,
            vec![TxOutcome::new(
                settled_tx(height),
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            )],
            AggregateSignature::new([0u8; 96]),
            SignerBitfield::new(4),
        ))
    }

    /// A finalization settling one transaction beside a counterpart's
    /// certificate for it: what makes it reach beyond this shard, and so
    /// what puts it in the settled set.
    fn finalization(height: u64) -> Arc<Verifiable<Finalization>> {
        let tick = TickId::new(SHARD, BlockHeight::new(height));
        let remote = TickId::new(ShardId::from_heap_index(2), BlockHeight::new(height));
        Arc::new(Verifiable::from(Finalization::new(
            tick,
            TickHalf::Determined,
            vec![certificate(tick, height), certificate(remote, height)],
            vec![],
        )))
    }

    /// Commit `count` blocks (1..=count), each carrying its own settled
    /// tick, and return the storage, the terminal hash, and the attested
    /// settled root over the whole window.
    fn served_chain(count: u64) -> (Arc<SimShardStorage>, BlockHash, SettledTxsRoot) {
        let storage = Arc::new(SimShardStorage::default());
        let mut parent = BlockHash::ZERO;
        for h in 1..=count {
            let certs = [finalization(h)];
            let parent_qc = QuorumCertificate::new(
                parent,
                SHARD,
                BlockHeight::new(h.saturating_sub(1)),
                BlockHash::ZERO,
                Round::INITIAL,
                SignerBitfield::new(4),
                AggregateSignature::new([0u8; 96]),
                WeightedTimestamp::from_millis(1_000 * h),
            );
            let header = BlockHeader::new(BlockHeaderParts {
                shard_id: SHARD,
                height: BlockHeight::new(h),
                parent_block_hash: parent,
                parent_qc: parent_qc.into(),
                timestamp: ProposerTimestamp::from_millis(1_000 * h),
                certificate_root: *Verified::<CertificateRoot>::compute(&certs).as_ref(),
                provision_tx_roots: BTreeMap::new(),
                ..Default::default()
            });
            let block = Block::Live {
                header,
                transactions: Arc::new(Vec::new()),
                certificates: Arc::new(certs.to_vec()),
                provisions: Arc::new(Vec::new()),
                abandonment_records: Arc::new(Vec::new()),
                state_claims: Arc::new(Vec::new()),
                witness_sources: Arc::new(WitnessSources::empty()),
            };
            parent = block.hash();
            commit_settled_at(
                storage.as_ref(),
                &make_test_certified(block),
                &[],
                &[],
                &BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
            );
        }
        let root =
            settled_txs_root_from_hashes((1..=count).map(settled_tx).collect::<Vec<_>>().iter());
        (storage, parent, root)
    }

    fn evidence(terminal: BlockHash, attested_root: SettledTxsRoot) -> TerminalEvidence {
        TerminalEvidence {
            shard: SHARD,
            height: BlockHeight::new(3),
            block_hash: terminal,
            terminal_wt: WeightedTimestamp::from_millis(9_000),
            attested_root,
        }
    }

    /// The served window recomputes to the attested root and reaches the
    /// coordinator whole, stamped with the terminal's clock.
    #[test]
    fn a_served_window_lifts_to_the_attested_root() {
        let (storage, terminal, root) = served_chain(3);
        let pending_chain = PendingChain::new(storage, ChainOrigin::ROOT);
        let scope = evidence(terminal, root);
        let response = serve_settled_txs_request(
            &pending_chain,
            None,
            &SettledTxsBinding::request(scope, &[]),
        );
        match SettledTxsBinding::answer(scope, vec![()], response) {
            Ok(ProtocolEvent::SettledTxsReconstructed {
                shard,
                txs,
                terminal_wt,
            }) => {
                assert_eq!(shard, SHARD);
                assert_eq!(terminal_wt, WeightedTimestamp::from_millis(9_000));
                assert_eq!(
                    txs,
                    BTreeSet::from([settled_tx(1), settled_tx(2), settled_tx(3)])
                );
            }
            other => panic!("expected the reconstructed set, got {other:?}"),
        }
    }

    /// A list that does not recompute to the attested root is refused
    /// as unusable rather than recorded: the peer rotates.
    #[test]
    fn a_window_off_the_attested_root_is_unusable() {
        let (storage, terminal, _) = served_chain(3);
        let pending_chain = PendingChain::new(storage, ChainOrigin::ROOT);
        let scope = evidence(terminal, settled_txs_root_from_hashes([&settled_tx(99)]));
        let response = serve_settled_txs_request(
            &pending_chain,
            None,
            &SettledTxsBinding::request(scope, &[]),
        );
        assert_eq!(
            SettledTxsBinding::answer(scope, vec![()], response).err(),
            Some(Refusal::Unusable("root_mismatch"))
        );
    }

    /// A peer that does not hold the terminal is not held against; the
    /// ids release for the next peer.
    #[test]
    fn a_peer_without_the_terminal_is_not_held() {
        let scope = evidence(BlockHash::ZERO, SettledTxsRoot::ZERO);
        assert_eq!(
            SettledTxsBinding::answer(scope, vec![()], GetSettledTxsResponse::not_found()).err(),
            Some(Refusal::NotHeld)
        );
    }
}
