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
use hyperscale_hbor::Capped;
use hyperscale_metrics::record_fetch_response_refused;
use hyperscale_network::{Network, RequestError, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::request::{
    GetExecutionCertsRequest, GetFinalizationsRequest, GetLocalProvisionsRequest,
    GetProvisionsRequest, GetSettledTxsRequest, GetStateProofRequest, GetTerminalLinesRequest,
};
use hyperscale_types::network::response::{
    GetSettledTxsResponse, GetStateProofResponse, GetTerminalLinesResponse,
};
use hyperscale_types::state_key::jmt_value_hash;
use hyperscale_types::{
    Anchor, BlockHeight, ExecutionCertificate, Finalization, FinalizationHash, MessageClass,
    ProvisionHash, ShardId, SubstateKey, TerminalEvidence, TxHash, ValidatorId, VerdictCells,
    Verifiable, settled_txs_root_from_hashes,
};

use crate::fetch::{
    Fetch, FetchBinding, Refusal, ScopedAnswer, dispatch_scoped, failed_chunk, partition_solicited,
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
pub type StateProofFetch = Fetch<(Anchor, SubstateKey)>;
/// Verdict-question fetch keyed by the anchor asked at and the three
/// cells the question reads there.
pub type VerdictProofFetch = Fetch<(Anchor, VerdictCells)>;
/// Settled-set fetch keyed by the departed shard's terminal evidence:
/// the terminal the window is reconstructed from and the root the list
/// must recompute to.
pub type SettledTxsFetch = Fetch<TerminalEvidence>;
/// Terminal-lines fetch keyed by the departed shard's terminal evidence:
/// the terminal block asked for and the hash its header must come to.
pub type TerminalLinesFetch = Fetch<TerminalEvidence>;

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
            GetLocalProvisionsRequest::new(
                Capped::new(ids).expect("the fetch config clamps a chunk below the wire cap"),
            ),
            class,
            Box::new(move |result| {
                let resp = match result {
                    Ok(resp) => resp,
                    Err(error) => {
                        push_shard_input(&es, local_shard, failed_chunk(&error, Self::ids(hs)));
                        return ResponseVerdict::Accept;
                    }
                };
                let split = partition_solicited(resp.entries.into_inner(), &hs, |entry| {
                    [entry.provisions.hash()]
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
            GetFinalizationsRequest::new(
                Capped::new(ids).expect("the fetch config clamps a chunk below the wire cap"),
            ),
            class,
            Box::new(move |result| {
                let resp = match result {
                    Ok(resp) => resp,
                    Err(error) => {
                        push_shard_input(
                            &es,
                            local_shard,
                            failed_chunk(&error, Self::ids(requested_ids)),
                        );
                        return ResponseVerdict::Accept;
                    }
                };
                let split =
                    partition_solicited(resp.finalizations.into_inner(), &requested_ids, |w| {
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
                tx_hashes: Capped::new(ids.into_iter().map(|(_, tx_hash)| tx_hash).collect())
                    .expect("no more hashes than one block carries"),
            },
            class,
            Box::new(move |result| {
                let response = match result {
                    Ok(response) => response,
                    Err(error) => {
                        push_shard_input(
                            &es,
                            local_shard,
                            failed_chunk(&error, Self::ids(failed_ids)),
                        );
                        return ResponseVerdict::Accept;
                    }
                };
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
            }),
        );
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

    fn request(scope: Self::Scope, keys: &[Self::Key], _asker: ShardId) -> Self::Request {
        GetStateProofRequest::new(
            scope.height,
            Capped::new(keys.to_vec()).expect("the fetch config clamps a chunk below the wire cap"),
        )
    }

    /// Checked here so an unusable proof rotates the peer rather than
    /// reaching a block, and so does a served value that does not hash
    /// to the presence the proof reconstructs for its key. What the
    /// proof says is read off the block that carries it, by every
    /// replica.
    fn answer(
        scope: Self::Scope,
        keys: Vec<Self::Key>,
        response: GetStateProofResponse,
    ) -> Result<ProtocolEvent, Refusal> {
        let proof = response.proof.ok_or(Refusal::NotHeld)?;
        let inclusions = proof
            .inclusions(scope.state_root, scope.shard, &keys)
            .map_err(|_| Refusal::Unusable("unusable_proof"))?;
        let values = response.values.into_inner();
        for (key, bytes) in &values {
            let proven = inclusions
                .iter()
                .find(|(asked, _)| asked == key)
                .map(|(_, inclusion)| inclusion.value_hash());
            if proven != Some(Some(jmt_value_hash(bytes))) {
                return Err(Refusal::Unusable("value_off_its_proof"));
            }
        }
        Ok(ProtocolEvent::FetchedStateProofVerified {
            anchor: scope,
            keys,
            proof,
            values,
        })
    }
}

/// Marker type for the fetch of siblings' verdict cells.
///
/// An id is one question: an anchor and the three cells the question
/// reads there. A request names every cell of the questions it carries,
/// so an answer holds each question whole. A fetch of its own: a sibling
/// that stops serving leaves these asks out, and they take up only this
/// fetch's places.
pub struct VerdictProofBinding;

impl FetchBinding for VerdictProofBinding {
    type Id = (Anchor, VerdictCells);

    const NAME: &'static str = "verdict_proof";

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::VerdictProofs(ids)
    }

    fn fetch_mut<S: ShardStorage>(shard: &mut ShardIo<S>) -> &mut Fetch<Self::Id> {
        &mut shard.cross_shard.verdict_proof
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

impl ScopedAnswer for VerdictProofBinding {
    type Scope = Anchor;
    type Key = VerdictCells;
    type Request = GetStateProofRequest;

    fn split(id: Self::Id) -> (Self::Scope, Self::Key) {
        id
    }

    fn join(scope: Self::Scope, key: Self::Key) -> Self::Id {
        (scope, key)
    }

    fn request(scope: Self::Scope, keys: &[Self::Key], asker: ShardId) -> Self::Request {
        StateProofBinding::request(scope, &cells_of(keys), asker)
    }

    /// Checked as a state proof is, over every cell of the questions
    /// asked, so an unusable proof rotates the peer.
    fn answer(
        scope: Self::Scope,
        keys: Vec<Self::Key>,
        response: GetStateProofResponse,
    ) -> Result<ProtocolEvent, Refusal> {
        let proof = response.proof.ok_or(Refusal::NotHeld)?;
        proof
            .inclusions(scope.state_root, scope.shard, &cells_of(&keys))
            .map_err(|_| Refusal::Unusable("unusable_proof"))?;
        Ok(ProtocolEvent::FetchedVerdictProofVerified {
            anchor: scope,
            questions: keys,
            proof,
        })
    }
}

/// Every cell `questions` read, three a question.
fn cells_of(questions: &[VerdictCells]) -> Vec<SubstateKey> {
    questions.iter().flat_map(VerdictCells::keys).collect()
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

    fn request(scope: Self::Scope, _keys: &[Self::Key], _asker: ShardId) -> Self::Request {
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

/// Marker type for the fetch of a departed shard's terminal manifest.
pub struct TerminalLinesBinding;

impl FetchBinding for TerminalLinesBinding {
    /// The terminal to ask for and the block hash the answer is held to,
    /// read off this node's own beacon fold. A revised terminal is a
    /// different id.
    type Id = TerminalEvidence;

    const NAME: &'static str = "terminal_lines";

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::TerminalLines(ids)
    }

    fn fetch_mut<S: ShardStorage>(shard: &mut ShardIo<S>) -> &mut Fetch<Self::Id> {
        &mut shard.cross_shard.terminal_lines
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

/// One request answers for one terminal block, so the evidence is the
/// scope and the question under it is the block's manifest itself.
impl ScopedAnswer for TerminalLinesBinding {
    type Scope = TerminalEvidence;
    type Key = ();
    type Request = GetTerminalLinesRequest;

    fn split(id: Self::Id) -> (Self::Scope, Self::Key) {
        (id, ())
    }

    fn join(scope: Self::Scope, (): Self::Key) -> Self::Id {
        scope
    }

    fn request(scope: Self::Scope, _keys: &[Self::Key], _asker: ShardId) -> Self::Request {
        GetTerminalLinesRequest::new(scope.height, scope.block_hash)
    }

    /// The lines are the terminal's own or they are nothing: the block
    /// hash binds the header, the header the section roots and those
    /// the manifest, so a peer can neither hide an ended transaction
    /// nor add one, which is what makes a name's absence sound.
    fn answer(
        scope: Self::Scope,
        _keys: Vec<Self::Key>,
        response: GetTerminalLinesResponse,
    ) -> Result<ProtocolEvent, Refusal> {
        let lines = response.lines.ok_or(Refusal::NotHeld)?;
        let ended = lines
            .ended_under(&scope)
            .map_err(|unbound| Refusal::Unusable(unbound.label()))?;
        Ok(ProtocolEvent::TerminalLinesVerified {
            shard: scope.shard,
            terminal: scope.block_hash,
            ended,
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
        let request = GetProvisionsRequest::new(block_height, target_shard);
        let es = sender.clone();
        network.request(
            shard,
            preferred,
            request,
            class,
            Box::new(move |result| {
                let ids = || Self::ids(vec![(source_shard, target_shard, block_height)]);
                let push_fetch_failed = || {
                    push_shard_input(&es, local_shard, ShardScopedInput::FetchFailed(ids()));
                };
                let response = match result {
                    Ok(response) => response,
                    Err(error) => {
                        if matches!(error, RequestError::PeerError(_)) {
                            record_fetch_response_refused("provision", "unusable_answer");
                        }
                        push_shard_input(&es, local_shard, failed_chunk(&error, ids()));
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
mod state_proof_tests {
    use hyperscale_hbor::Bytes;
    use hyperscale_types::test_utils::{state_and_proof, test_key};
    use hyperscale_types::{BlockHeight, MAX_HELD_VALUE_BYTES, WeightedTimestamp};

    use super::*;

    /// A served value is held to the presence the proof reconstructs
    /// for its key: one that hashes to it rides on, and one that does
    /// not, or one for a key the proof shows absent, rotates the peer
    /// as an unusable answer.
    #[test]
    fn a_served_value_off_its_proof_rotates_the_peer() {
        let shard = ShardId::leaf(1, 0);
        let (held, missing) = (test_key(0x21), test_key(0x22));
        let (state_root, proof) = state_and_proof(shard, &[held], &[held, missing]);
        let anchor = Anchor {
            shard,
            height: BlockHeight::new(4),
            state_root,
            ts: WeightedTimestamp::from_millis(4_000),
        };
        let keys = vec![held, missing];
        let value = |bytes: Vec<u8>| Bytes::new(bytes).unwrap();
        let answer = |values: Vec<(SubstateKey, Bytes<MAX_HELD_VALUE_BYTES>)>| {
            StateProofBinding::answer(
                anchor,
                keys.clone(),
                GetStateProofResponse::found(proof.clone(), Capped::new(values).unwrap()),
            )
        };

        let Ok(ProtocolEvent::FetchedStateProofVerified { values, .. }) =
            answer(vec![(held, value(held.to_bytes().to_vec()))])
        else {
            panic!("the fixture's leaf value is the key's own bytes");
        };
        assert_eq!(values.len(), 1);

        assert_eq!(
            answer(vec![(held, value(b"another value".to_vec()))]).map(|_| ()),
            Err(Refusal::Unusable("value_off_its_proof")),
        );
        assert_eq!(
            answer(vec![(missing, value(missing.to_bytes().to_vec()))]).map(|_| ()),
            Err(Refusal::Unusable("value_off_its_proof")),
            "a value for a key the proof shows absent",
        );
    }
}

#[cfg(test)]
mod settled_txs_tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use hyperscale_storage::PendingChain;
    use hyperscale_storage::test_helpers::{commit_settled_at, make_test_certified};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::{
        AggregateSignature, BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHash,
        BlockHeader, BlockHeaderParts, BlockHeight, CertificateRoot, ChainOrigin, ConsensusReceipt,
        ExecutionCertificate, ExecutionOutcome, Finalization, GlobalReceiptHash, Hash,
        ProposerTimestamp, QuorumCertificate, Round, SectionRoots, SettledTxsRoot, SignerBitfield,
        StateWrites, StoredReceipt, TickHalf, TickId, TxOutcome, Verified, WeightedTimestamp,
        WitnessSources, compute_global_receipt_root,
    };

    use super::*;
    use crate::shard::cross_shard::{SettledTxsCache, serve_settled_txs_request};

    const SHARD: ShardId = ShardId::ROOT;

    /// The transaction the tick at `height` settles — distinct per tick,
    /// so a window over several ticks has one entry each.
    fn settled_tx(height: u64) -> TxHash {
        TxHash::from(Hash::from_bytes(&height.to_le_bytes()))
    }

    fn certificate(tick: TickId, height: u64) -> Arc<ExecutionCertificate> {
        let outcomes = [TxOutcome::new(
            settled_tx(height),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        )];
        Arc::new(ExecutionCertificate::new(
            tick,
            WeightedTimestamp::from_millis(1),
            compute_global_receipt_root(&outcomes),
            Capped::from_array(outcomes),
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
            &Capped::from_array([certificate(tick, height), certificate(remote, height)]),
            Capped::from_array([StoredReceipt::new(
                settled_tx(height),
                Arc::new(ConsensusReceipt::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                    writes: StateWrites::default(),
                    beacon_witness_events: Capped::empty(),
                    events: Capped::empty(),
                }),
            )]),
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
                body_root: SectionRoots {
                    certificates: *Verified::<CertificateRoot>::compute(&certs).as_ref(),
                    ..SectionRoots::EMPTY
                }
                .root(),
                provision_tx_roots: Capped::default(),
                terminal_settled_txs: Some(SettledTxsRoot::ZERO),
                ..Default::default()
            });
            let block = Block::Live {
                header,
                transactions: Arc::new(Capped::empty()),
                certificates: Arc::new(Capped::from_array(certs)),
                provisions: Arc::new(Capped::empty()),
                abandonment_records: Arc::new(Capped::empty()),
                state_claims: Arc::new(Capped::empty()),
                tick_manifest: Arc::new(Capped::empty()),
                terms: Arc::new(Capped::empty()),
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
            &SettledTxsCache::default(),
            None,
            &SettledTxsBinding::request(scope, &[], ShardId::ROOT),
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
            &SettledTxsCache::default(),
            None,
            &SettledTxsBinding::request(scope, &[], ShardId::ROOT),
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

#[cfg(test)]
mod terminal_lines_tests {
    use std::collections::BTreeSet;
    use std::sync::Mutex;

    use crossbeam::channel::unbounded;
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};
    use hyperscale_network::{GossipHandler, NotificationHandler, RequestHandler};
    use hyperscale_storage::PendingChain;
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::{
        Block, BlockHash, ChainOrigin, GossipMessage, LeafRoot, NetworkMessage, Request,
        SettledTxsRoot, TerminalLines, TickLine, TickManifestRoot, WeightedTimestamp,
    };

    use super::*;
    use crate::fetch::{FetchConfig, FetchInput, Release};
    use crate::shard::cross_shard::terminal_fixture::{SHARD, commit_block, end_line, ended_tx};
    use crate::shard::cross_shard::{TerminalLinesCache, serve_terminal_lines_request};

    type Names = BTreeSet<TxHash>;

    /// A departed shard's chain, held whole: three blocks, the terminal
    /// carrying `lines`.
    struct Departed {
        chain: PendingChain<SimShardStorage>,
        /// The block below the terminal, whose header is a real one and
        /// not the terminal's.
        below: Block,
        /// What a survivor's own beacon fold says of the terminal.
        scope: TerminalEvidence,
    }

    fn departed(lines: &[TickLine]) -> Departed {
        let storage = SimShardStorage::default();
        let first = commit_block(&storage, 1, BlockHash::ZERO, &[]);
        let below = commit_block(&storage, 2, first.hash(), &[]);
        let terminal = commit_block(&storage, 3, below.hash(), lines);
        let scope = TerminalEvidence {
            shard: SHARD,
            height: terminal.height(),
            block_hash: terminal.hash(),
            terminal_wt: WeightedTimestamp::from_millis(9_000),
            attested_root: SettledTxsRoot::ZERO,
        };
        Departed {
            chain: PendingChain::new(Arc::new(storage), ChainOrigin::ROOT),
            below,
            scope,
        }
    }

    impl Departed {
        /// What an honest holder of the chain answers.
        fn served(&self) -> GetTerminalLinesResponse {
            serve_terminal_lines_request(
                &self.chain,
                &TerminalLinesCache::default(),
                &TerminalLinesBinding::request(self.scope, &[], ShardId::ROOT),
            )
        }

        /// The honest answer with its lines put through `forge`.
        fn forged(&self, forge: impl FnOnce(&mut TerminalLines)) -> GetTerminalLinesResponse {
            let mut response = self.served();
            forge(response.lines.as_mut().expect("the terminal is held"));
            response
        }
    }

    /// The names `answer` took from `response` under `scope`.
    fn taken(
        scope: TerminalEvidence,
        response: GetTerminalLinesResponse,
    ) -> Result<Names, Refusal> {
        match TerminalLinesBinding::answer(scope, vec![()], response)? {
            ProtocolEvent::TerminalLinesVerified {
                shard,
                terminal,
                ended,
            } => {
                assert_eq!((shard, terminal), (scope.shard, scope.block_hash));
                Ok(ended)
            }
            other => panic!("expected the terminal's lines, got {other:?}"),
        }
    }

    fn names(seeds: &[u8]) -> Names {
        seeds.iter().copied().map(ended_tx).collect()
    }

    /// The lines are taken where the header hashes to the evidence's
    /// block, the section roots combine to the header's body root and
    /// the manifest recomputes the manifest root, and at no answer that
    /// breaks any one of the three.
    #[test]
    fn terminal_lines_are_taken_only_at_the_headers_body_root() {
        let departed = departed(&[end_line(1), end_line(2)]);
        let scope = departed.scope;

        assert_eq!(taken(scope, departed.served()), Ok(names(&[1, 2])));

        // A real header of the same chain that is not the terminal's.
        let other_header =
            departed.forged(|served| served.header = departed.below.header().clone());
        assert_eq!(
            taken(scope, other_header),
            Err(Refusal::Unusable("terminal_header_mismatch")),
        );

        // The terminal's header over roots it does not commit.
        let other_roots = departed.forged(|served| {
            served.roots.tick_manifest = TickManifestRoot::over(&[end_line(9)]);
        });
        assert_eq!(
            taken(scope, other_roots),
            Err(Refusal::Unusable("terminal_body_root_mismatch")),
        );

        // The terminal's header and roots over lines they do not commit.
        let other_manifest =
            departed.forged(|served| served.manifest = Capped::from_array([end_line(9)]));
        assert_eq!(
            taken(scope, other_manifest),
            Err(Refusal::Unusable("terminal_manifest_root_mismatch")),
        );
    }

    /// A server holding the right header can neither invent an accepted
    /// member nor hide one: an added, dropped, swapped or reordered end
    /// line moves the manifest root, and roots rewritten to match no
    /// longer combine to the header's body root.
    #[test]
    fn a_server_cannot_hide_or_invent_an_ended_transaction() {
        let departed = departed(&[end_line(1), end_line(2)]);
        let scope = departed.scope;
        let manifests: [Vec<TickLine>; 5] = [
            vec![end_line(1), end_line(2), end_line(3)],
            vec![end_line(1)],
            Vec::new(),
            vec![end_line(1), end_line(3)],
            vec![end_line(2), end_line(1)],
        ];

        for forged in manifests {
            let lied = departed.forged(|served| {
                served.manifest = Capped::new(forged.clone()).expect("within the line cap");
            });
            assert_eq!(
                taken(scope, lied),
                Err(Refusal::Unusable("terminal_manifest_root_mismatch")),
            );

            let covered = departed.forged(|served| {
                served.manifest = Capped::new(forged.clone()).expect("within the line cap");
                served.roots.tick_manifest = TickManifestRoot::over(&forged);
            });
            assert_eq!(
                taken(scope, covered),
                Err(Refusal::Unusable("terminal_body_root_mismatch")),
            );
        }
    }

    /// A terminal that ended nothing answers with an empty list, which
    /// says every transaction asked about was left.
    #[test]
    fn a_terminal_with_no_end_line_answers_with_no_names() {
        let departed = departed(&[]);
        assert_eq!(taken(departed.scope, departed.served()), Ok(Names::new()));
    }

    /// A peer that does not hold the terminal is not held against.
    #[test]
    fn a_peer_without_the_terminal_is_not_held() {
        let departed = departed(&[end_line(1)]);
        assert_eq!(
            taken(departed.scope, GetTerminalLinesResponse::not_found()),
            Err(Refusal::NotHeld),
        );
    }

    /// A network of one peer that answers every request with the same
    /// response and keeps what the requester scored it.
    struct Peer {
        response: GetTerminalLinesResponse,
        verdict: Mutex<Option<ResponseVerdict>>,
    }

    impl Network for Peer {
        fn broadcast_to_shard<M: GossipMessage + 'static>(&self, _: ShardId, _: &M) {}
        fn broadcast_global<M: GossipMessage + 'static>(&self, _: &M) {}
        fn register_gossip_handler<M: GossipMessage + 'static>(&self, _: impl GossipHandler<M>) {}
        fn register_host_gossip_handler<M: GossipMessage + 'static>(
            &self,
            _: impl Fn(M) + Send + Sync + 'static,
        ) {
        }
        fn register_request_handler<R: Request + Send + 'static>(
            &self,
            _: ShardId,
            _: impl RequestHandler<R>,
        ) where
            R::Response: Send + 'static,
        {
        }
        fn notify<M: NetworkMessage + 'static>(&self, _: &[ValidatorId], _: &M) {}
        fn register_notification_handler<M: NetworkMessage + Clone + 'static>(
            &self,
            _: impl NotificationHandler<M>,
        ) {
        }
        fn subscribe_shard(&self, _: ShardId) {}
        fn unsubscribe_shard(&self, _: ShardId) {}
        fn request<R: Request + Clone + 'static>(
            &self,
            _: ShardId,
            _: Option<ValidatorId>,
            _: R,
            _: Option<MessageClass>,
            on_response: Box<
                dyn FnOnce(Result<R::Response, RequestError>) -> ResponseVerdict + Send,
            >,
        ) {
            let bytes = hbor_to_vec(&self.response).expect("the fixture answer encodes");
            let answer = hbor_from_slice::<R::Response>(&bytes)
                .expect("the fixture is only asked for a terminal's lines");
            *self.verdict.lock().expect("no other thread holds it") = Some(on_response(Ok(answer)));
        }
    }

    /// What one answer does to the fetch of a terminal's lines.
    #[derive(Debug, PartialEq, Eq)]
    struct Round {
        /// How the requester scored the peer.
        verdict: ResponseVerdict,
        /// The names delivered to the coordinator.
        delivered: Option<Names>,
        /// Whether the release sent the terminal out again at once.
        asked_again: bool,
        /// Whether the fetch still tracks the terminal.
        tracked: bool,
    }

    /// Ask for `scope` through the fetch engine, answer with `response`
    /// at the response boundary, and feed what the boundary pushes back
    /// into the engine.
    fn round(scope: TerminalEvidence, response: GetTerminalLinesResponse) -> Round {
        let mut engine = TerminalLinesFetch::new("terminal_lines", FetchConfig::default());
        let sent = engine.handle(FetchInput::Request {
            ids: vec![scope],
            shard: scope.shard,
            preferred: None,
            class: None,
        });
        assert_eq!(sent.len(), 1, "the terminal is asked for once");

        let peer = Peer {
            response,
            verdict: Mutex::new(None),
        };
        let (sender, receiver) = unbounded();
        let local = ShardId::leaf(1, 1);
        TerminalLinesBinding::dispatch_chunk(
            vec![scope],
            local,
            scope.shard,
            None,
            None,
            &peer,
            &sender,
        );
        drop(sender);

        let (mut delivered, mut asked_again) = (None, false);
        for pushed in receiver {
            let HostEvent::Shard(to, input) = pushed else {
                panic!("the boundary pushes to the asking shard alone");
            };
            assert_eq!(to, local);
            match input {
                ShardScopedInput::FetchFailed(FetchIds::TerminalLines(ids)) => {
                    asked_again = !engine.handle(Release::Failed.input(ids)).is_empty();
                }
                ShardScopedInput::FetchFulfilled(FetchIds::TerminalLines(ids)) => {
                    let _ = engine.handle(Release::Admitted.input(ids));
                }
                ShardScopedInput::Protocol(event) => match *event {
                    ProtocolEvent::TerminalLinesVerified { ended, .. } => delivered = Some(ended),
                    other => panic!("expected the terminal's lines, got {other:?}"),
                },
                _ => panic!("a lines answer releases its id and delivers its event"),
            }
        }
        let verdict = peer
            .verdict
            .lock()
            .expect("no other thread holds it")
            .take();
        Round {
            verdict: verdict.expect("the peer was asked"),
            delivered,
            asked_again,
            tracked: engine.has_pending(),
        }
    }

    /// The terminal's own lines deliver its names and end the fetch.
    #[test]
    fn a_good_answer_delivers_the_names_and_fulfils_the_fetch() {
        let departed = departed(&[end_line(1), end_line(2)]);
        assert_eq!(
            round(departed.scope, departed.served()),
            Round {
                verdict: ResponseVerdict::Accept,
                delivered: Some(names(&[1, 2])),
                asked_again: false,
                tracked: false,
            },
        );
    }

    /// Forged lines deliver nothing, score the peer, and the terminal is
    /// asked for again at once.
    #[test]
    fn forged_lines_score_a_rejection_and_are_retried() {
        let departed = departed(&[end_line(1)]);
        let lied = departed.forged(|served| served.manifest = Capped::empty());
        assert_eq!(
            round(departed.scope, lied),
            Round {
                verdict: ResponseVerdict::Reject,
                delivered: None,
                asked_again: true,
                tracked: true,
            },
        );
    }

    /// An empty answer delivers nothing and scores nobody: the peer said
    /// what it holds, and the terminal is asked for again at once.
    #[test]
    fn an_empty_answer_is_retried_without_a_score() {
        let departed = departed(&[end_line(1)]);
        assert_eq!(
            round(departed.scope, GetTerminalLinesResponse::not_found()),
            Round {
                verdict: ResponseVerdict::Accept,
                delivered: None,
                asked_again: true,
                tracked: true,
            },
        );
    }
}
