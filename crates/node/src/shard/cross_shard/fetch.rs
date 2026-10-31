//! Cross-shard fetch bindings.
//!
//! The [`FetchBinding`] impls for the cross-shard data-availability payloads —
//! provisions, finalizations, local provisions, and
//! the answers checked against a remote chain's committed state.
//! Each `fetch_mut` resolves the binding's `Fetch` instance out of this shard's
//! [`CrossShardState`](super::CrossShardState). The generic engine, the
//! `FetchBinding` trait, and the [`ScopedAnswer`] and [`SolicitedAnswer`]
//! response boundaries live in [`crate::fetch`].

use hyperscale_core::{FetchIds, ProtocolEvent};
use hyperscale_hbor::Capped;
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::request::{
    GetFinalizationsRequest, GetLocalProvisionsRequest, GetProvisionsRequest, GetSettledTxsRequest,
    GetStateProofRequest,
};
use hyperscale_types::network::response::{
    GetFinalizationsResponse, GetLocalProvisionsResponse, GetProvisionResponse,
    GetSettledTxsResponse, GetStateProofResponse, LocalProvisionEntry,
};
use hyperscale_types::state_key::jmt_value_hash;
use hyperscale_types::{
    Anchor, BlockHeight, Finalization, FinalizationHash, HeaderSource, ProvisionHash, Provisions,
    ShardId, SubstateKey, TerminalEvidence, VerdictCells, Verifiable, settled_txs_root_from_hashes,
};

use crate::event::ShardScopedInput;
use crate::fetch::{
    Fetch, FetchBinding, FetchedBy, Refusal, Route, ScopedAnswer, Settles, ShardReply,
    SolicitedAnswer, dispatch_scoped, dispatch_solicited,
};
use crate::shard::ShardIo;

// ─── Type aliases ──────────────────────────────────────────────────────
/// Local-provision fetch keyed by [`ProvisionHash`].
pub type LocalProvisionFetch = Fetch<ProvisionHash>;
/// Finalization fetch keyed by [`FinalizationHash`].
pub type FinalizationFetch = Fetch<FinalizationHash>;
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

// ─── Bindings ──────────────────────────────────────────────────────────

/// Marker type for the per-block local-provision fetch.
pub struct LocalProvisionBinding;

impl FetchBinding for LocalProvisionBinding {
    type Id = ProvisionHash;

    const NAME: &'static str = "local_provision";

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::LocalProvisions(ids)
    }
}

impl<S: ShardStorage> FetchedBy<ShardIo<S>> for LocalProvisionBinding {
    fn fetch_mut(shard: &mut ShardIo<S>) -> &mut Fetch<ProvisionHash> {
        &mut shard.cross_shard.local_provision
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<ProvisionHash>,
        route: Route,
        network: &N,
        reply: &ShardReply,
    ) {
        dispatch_solicited::<Self, N, _>(ids, route, network, reply);
    }
}

/// A bundle's proof is checked against its source header on the
/// coordinator, which may still be waiting for that header, so the ids
/// stay in flight until it admits the bundle or fails it.
impl SolicitedAnswer for LocalProvisionBinding {
    type Request = GetLocalProvisionsRequest;
    type Item = LocalProvisionEntry;
    type Input = ShardScopedInput;

    const SETTLES: Settles = Settles::OnVerdict;

    fn request(ids: &[ProvisionHash]) -> GetLocalProvisionsRequest {
        GetLocalProvisionsRequest::new(
            Capped::new(ids.to_vec()).expect("the fetch config clamps a chunk below the wire cap"),
        )
    }

    fn items(response: GetLocalProvisionsResponse) -> Vec<LocalProvisionEntry> {
        response.entries.into_inner()
    }

    fn answers_for(entry: &LocalProvisionEntry) -> impl IntoIterator<Item = ProvisionHash> + use<> {
        [entry.provisions.hash()]
    }

    /// The bundled source header goes ahead of its provisions, so the
    /// verification pipeline has a chance to admit it first. The header
    /// is QC-self-authenticating.
    fn deliver(kept: Vec<LocalProvisionEntry>) -> Vec<ShardScopedInput> {
        let mut inputs = Vec::with_capacity(kept.len() * 2);
        for entry in kept {
            if let Some(certified_header) = entry.source_header {
                inputs.push(ShardScopedInput::Protocol(Box::new(
                    ProtocolEvent::UnverifiedRemoteHeaderReceived {
                        certified_header,
                        source: HeaderSource::Fetched,
                    },
                )));
            }
            inputs.push(ShardScopedInput::Protocol(Box::new(
                ProtocolEvent::UnverifiedProvisionsReceived {
                    provisions: entry.provisions,
                },
            )));
        }
        inputs
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
}

impl<S: ShardStorage> FetchedBy<ShardIo<S>> for FinalizationBinding {
    fn fetch_mut(shard: &mut ShardIo<S>) -> &mut Fetch<FinalizationHash> {
        &mut shard.cross_shard.finalization
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<FinalizationHash>,
        route: Route,
        network: &N,
        reply: &ShardReply,
    ) {
        dispatch_solicited::<Self, N, _>(ids, route, network, reply);
    }
}

/// A finalization's certificates are checked on the execution
/// coordinator, which parks one whose committee the beacon has not
/// folded yet; the ids stay in flight until it admits or abandons it, so
/// a pending block's re-ask does not fetch the parked copy again.
impl SolicitedAnswer for FinalizationBinding {
    type Request = GetFinalizationsRequest;
    type Item = Finalization;
    type Input = ShardScopedInput;

    const SETTLES: Settles = Settles::OnVerdict;

    fn request(ids: &[FinalizationHash]) -> GetFinalizationsRequest {
        GetFinalizationsRequest::new(
            Capped::new(ids.to_vec()).expect("the fetch config clamps a chunk below the wire cap"),
        )
    }

    fn items(response: GetFinalizationsResponse) -> Vec<Finalization> {
        response.finalizations.into_inner()
    }

    fn answers_for(
        finalization: &Finalization,
    ) -> impl IntoIterator<Item = FinalizationHash> + use<> {
        [finalization.receipt_hash()]
    }

    fn deliver(kept: Vec<Finalization>) -> Vec<ShardScopedInput> {
        let finalizations: Vec<Verifiable<Finalization>> =
            kept.into_iter().map(Verifiable::from).collect();
        vec![ShardScopedInput::Protocol(Box::new(
            ProtocolEvent::FinalizationsReceived { finalizations },
        ))]
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
}

impl<S: ShardStorage> FetchedBy<ShardIo<S>> for StateProofBinding {
    fn fetch_mut(shard: &mut ShardIo<S>) -> &mut Fetch<Self::Id> {
        &mut shard.cross_shard.state_proof
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<Self::Id>,
        route: Route,
        network: &N,
        reply: &ShardReply,
    ) {
        dispatch_scoped::<Self, N, _>(ids, route, network, reply);
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
}

impl<S: ShardStorage> FetchedBy<ShardIo<S>> for VerdictProofBinding {
    fn fetch_mut(shard: &mut ShardIo<S>) -> &mut Fetch<Self::Id> {
        &mut shard.cross_shard.verdict_proof
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<Self::Id>,
        route: Route,
        network: &N,
        reply: &ShardReply,
    ) {
        dispatch_scoped::<Self, N, _>(ids, route, network, reply);
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

    fn request(scope: Self::Scope, keys: &[Self::Key]) -> Self::Request {
        StateProofBinding::request(scope, &cells_of(keys))
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
}

impl<S: ShardStorage> FetchedBy<ShardIo<S>> for SettledTxsBinding {
    fn fetch_mut(shard: &mut ShardIo<S>) -> &mut Fetch<Self::Id> {
        &mut shard.cross_shard.settled_txs
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<Self::Id>,
        route: Route,
        network: &N,
        reply: &ShardReply,
    ) {
        dispatch_scoped::<Self, N, _>(ids, route, network, reply);
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
            txs: txs.iter().copied().collect(),
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
}

impl<S: ShardStorage> FetchedBy<ShardIo<S>> for ProvisionBinding {
    fn fetch_mut(shard: &mut ShardIo<S>) -> &mut Fetch<Self::Id> {
        &mut shard.cross_shard.provision
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<(ShardId, ShardId, BlockHeight)>,
        route: Route,
        network: &N,
        reply: &ShardReply,
    ) {
        debug_assert!(
            ids.iter()
                .all(|(source_shard, ..)| route.shard == *source_shard),
            "ProvisionBinding routes to the source shard; the runner sets it from the variant"
        );
        dispatch_solicited::<Self, N, _>(ids, route, network, reply);
    }
}

/// A bundle answers for the `(source, target, height)` it names, so one
/// for another scope is unsolicited. Its proof is checked on the
/// coordinator against the commit-proven source header, and the
/// expectation that asked does not ask again, so the id stays in flight
/// until the coordinator admits the bundle or fails it: the fetch's own
/// retry is the only one there is.
impl SolicitedAnswer for ProvisionBinding {
    type Request = GetProvisionsRequest;
    type Item = Provisions;
    type Input = ShardScopedInput;

    const SETTLES: Settles = Settles::OnVerdict;

    /// `target_shard` (the requester's shard) is the body field: the
    /// source filters provisions by which shard is asking. The route's
    /// shard, the source, picks the responding committee.
    fn request(ids: &[Self::Id]) -> GetProvisionsRequest {
        debug_assert_eq!(ids.len(), 1, "PER_ID hands over one id at a time");
        let (_, target_shard, block_height) = ids[0];
        GetProvisionsRequest::new(block_height, target_shard)
    }

    /// A bundle with no transactions is a source with nothing owed to
    /// the asker at that height, which reads as not holding it.
    fn items(response: GetProvisionResponse) -> Vec<Provisions> {
        response
            .provisions
            .into_iter()
            .filter(|provisions| !provisions.transactions().is_empty())
            .collect()
    }

    fn answers_for(provisions: &Provisions) -> impl IntoIterator<Item = Self::Id> + use<> {
        [(
            provisions.source_shard(),
            provisions.target_shard(),
            provisions.block_height(),
        )]
    }

    fn deliver(kept: Vec<Provisions>) -> Vec<ShardScopedInput> {
        kept.into_iter()
            .map(|provisions| {
                ShardScopedInput::Protocol(Box::new(ProtocolEvent::UnverifiedProvisionsReceived {
                    provisions,
                }))
            })
            .collect()
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
        BlockHeader, BlockHeaderParts, BlockHeight, CertificateRoot, ConsensusReceipt,
        ExecutionCertificate, ExecutionOutcome, Finalization, GlobalReceiptHash, Hash,
        ProposerTimestamp, QuorumCertificate, Role, Round, SectionRoots, SettledTxsRoot,
        SignerBitfield, StateWrites, StoredReceipt, TickHalf, TickId, TxHash, TxOutcome, Verified,
        WeightedTimestamp, WitnessSources, compute_global_receipt_root,
    };

    use super::*;
    use crate::shard::cross_shard::{SettledTxsCache, serve_settled_txs_request};

    const SHARD: ShardId = ShardId::ROOT;

    /// The transaction the tick at `height` settles — distinct per tick,
    /// so a window over several ticks has one entry each.
    fn settled_tx(height: u64) -> TxHash {
        TxHash::from(Hash::from_bytes(&height.to_le_bytes()))
    }

    fn certificate(tick: TickId, height: u64) -> ExecutionCertificate {
        let outcomes = [TxOutcome::new(
            settled_tx(height),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        )
        .as_role(Role::Leg)];
        ExecutionCertificate::new(
            tick,
            WeightedTimestamp::from_millis(1),
            compute_global_receipt_root(&outcomes),
            Capped::from_array(outcomes),
            AggregateSignature::new([0u8; 96]),
            SignerBitfield::new(4),
        )
    }

    /// A finalization settling one leg that ran: what reaches beyond this
    /// shard, and so what puts it in the settled set.
    fn finalization(height: u64) -> Verifiable<Finalization> {
        let tick = TickId::new(SHARD, BlockHeight::new(height));
        Verifiable::from(Finalization::new(
            tick,
            TickHalf::Determined,
            Some(certificate(tick, height)),
            Capped::from_array([StoredReceipt::new(
                settled_tx(height),
                Arc::new(ConsensusReceipt::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                    writes: StateWrites::default(),
                    beacon_witness_events: Capped::empty(),
                    events: Capped::empty(),
                }),
            )]),
        ))
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
        let pending_chain = PendingChain::new(storage, BlockHeight::GENESIS);
        let scope = evidence(terminal, root);
        let response = serve_settled_txs_request(
            &pending_chain,
            &SettledTxsCache::default(),
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
        let pending_chain = PendingChain::new(storage, BlockHeight::GENESIS);
        let scope = evidence(terminal, settled_txs_root_from_hashes([&settled_tx(99)]));
        let response = serve_settled_txs_request(
            &pending_chain,
            &SettledTxsCache::default(),
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

#[cfg(test)]
mod solicited_tests {
    use crossbeam::channel::unbounded;
    use hyperscale_network::ResponseVerdict;
    use hyperscale_types::network::Request;
    use hyperscale_types::{Hash, MerkleInclusionProof, ProvisionEntry, TxHash, WeightedTimestamp};

    use super::*;
    use crate::event::HostEvent;
    use crate::fetch::settle_solicited;

    const LOCAL: ShardId = ShardId::leaf(2, 0);
    const SOURCE: ShardId = ShardId::leaf(2, 1);

    fn bundle(target: ShardId, height: u64, txs: &[&[u8]]) -> Provisions {
        Provisions::new(
            SOURCE,
            target,
            BlockHeight::new(height),
            WeightedTimestamp::ZERO,
            MerkleInclusionProof::dummy(),
            Capped::new(
                txs.iter()
                    .map(|tx| {
                        ProvisionEntry::new(TxHash::from(Hash::from_bytes(tx)), Capped::empty())
                    })
                    .collect(),
            )
            .unwrap(),
        )
    }

    /// Settle `response` to a request for `requested` and return the
    /// verdict beside what reached the loop.
    fn settle<B>(
        requested: Vec<B::Id>,
        response: <B::Request as Request>::Response,
    ) -> (ResponseVerdict, Vec<ShardScopedInput>)
    where
        B: SolicitedAnswer<Input = ShardScopedInput>,
    {
        let (sender, events) = unbounded();
        let verdict = settle_solicited::<B, _>(
            requested,
            Ok(response),
            &ShardReply {
                shard: LOCAL,
                sender,
            },
        );
        let inputs = events
            .try_iter()
            .map(|event| match event {
                HostEvent::Shard(_, input) => input,
                _ => panic!("a shard reply pushes shard inputs"),
            })
            .collect();
        (verdict, inputs)
    }

    fn is_fulfilled(input: &ShardScopedInput) -> bool {
        matches!(input, ShardScopedInput::FetchFulfilled(_))
    }

    /// A peer that trims its answer to its budget is not at fault: what it
    /// left out is asked again and the answer is accepted. What it did
    /// send reaches the coordinator and stays in flight for its verdict.
    #[test]
    fn a_trimmed_answer_releases_its_misses_without_blame() {
        let sent = bundle(LOCAL, 10, &[b"a"]);
        let left_out = bundle(LOCAL, 11, &[b"b"]).hash();
        let (verdict, inputs) = settle::<LocalProvisionBinding>(
            vec![sent.hash(), left_out],
            GetLocalProvisionsResponse::new(Capped::from_array([LocalProvisionEntry {
                provisions: sent.clone(),
                source_header: None,
            }])),
        );
        assert_eq!(verdict, ResponseVerdict::Accept);
        assert!(!inputs.iter().any(is_fulfilled), "held until its verdict");
        assert!(inputs.iter().any(|input| matches!(
            input,
            ShardScopedInput::Protocol(event)
                if matches!(&**event, ProtocolEvent::UnverifiedProvisionsReceived { provisions }
                    if provisions.hash() == sent.hash())
        )));
        assert!(inputs.iter().any(|input| matches!(
            input,
            ShardScopedInput::FetchFailed(FetchIds::LocalProvisions(ids)) if ids == &[left_out]
        )));
    }

    /// An item nobody asked for is dropped and rejects the answer.
    #[test]
    fn an_unsolicited_item_rejects_the_answer() {
        let asked = bundle(LOCAL, 10, &[b"a"]);
        let extra = bundle(LOCAL, 12, &[b"c"]);
        let (verdict, inputs) = settle::<LocalProvisionBinding>(
            vec![asked.hash()],
            GetLocalProvisionsResponse::new(Capped::from_array([&asked, &extra].map(
                |provisions| LocalProvisionEntry {
                    provisions: provisions.clone(),
                    source_header: None,
                },
            ))),
        );
        assert_eq!(verdict, ResponseVerdict::Reject);
        let delivered: Vec<_> = inputs
            .iter()
            .filter_map(|input| match input {
                ShardScopedInput::Protocol(event) => match &**event {
                    ProtocolEvent::UnverifiedProvisionsReceived { provisions } => {
                        Some(provisions.hash())
                    }
                    _ => None,
                },
                _ => None,
            })
            .collect();
        assert_eq!(delivered, vec![asked.hash()]);
    }

    /// A source that does not hold the block, or owes the asker nothing
    /// at it, answers honestly and is asked again elsewhere; a bundle for
    /// another scope is no answer and rejects the peer.
    #[test]
    fn a_remote_bundle_is_held_to_its_scope_and_a_miss_costs_nothing() {
        let id = (SOURCE, LOCAL, BlockHeight::new(10));
        let failed = |inputs: &[ShardScopedInput]| {
            inputs.iter().any(|input| {
                matches!(input,
                    ShardScopedInput::FetchFailed(FetchIds::RemoteProvisions(ids)) if ids == &[id])
            })
        };

        for (response, what) in [
            (GetProvisionResponse { provisions: None }, "not held"),
            (
                GetProvisionResponse {
                    provisions: Some(bundle(LOCAL, 10, &[])),
                },
                "nothing owed",
            ),
        ] {
            let (verdict, inputs) = settle::<ProvisionBinding>(vec![id], response);
            assert_eq!(verdict, ResponseVerdict::Accept, "{what}");
            assert!(failed(&inputs), "{what}: asked again");
        }

        let (verdict, inputs) = settle::<ProvisionBinding>(
            vec![id],
            GetProvisionResponse {
                provisions: Some(bundle(ShardId::leaf(2, 3), 10, &[b"a"])),
            },
        );
        assert_eq!(verdict, ResponseVerdict::Reject, "another scope");
        assert!(failed(&inputs), "another scope: asked again");

        let (verdict, inputs) = settle::<ProvisionBinding>(
            vec![id],
            GetProvisionResponse {
                provisions: Some(bundle(LOCAL, 10, &[b"a"])),
            },
        );
        assert_eq!(verdict, ResponseVerdict::Accept);
        assert!(!failed(&inputs) && !inputs.iter().any(is_fulfilled));
    }
}
