//! Cross-shard fetch bindings.
//!
//! The [`FetchBinding`] impls for the cross-shard data-availability payloads —
//! provisions, finalizations, local provisions, and
//! the answers checked against a remote chain's committed state.
//! Each `fetch_mut` resolves the binding's `Fetch` instance out of this shard's
//! [`CrossShardState`](super::CrossShardState). The generic engine, the
//! `FetchBinding` trait, and the [`ScopedAnswer`] and [`SolicitedAnswer`]
//! response boundaries live in [`crate::fetch`].

use std::collections::BTreeMap;

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
    Anchor, BlockHeight, CheckedStateProof, Finalization, FinalizationHash, HeaderSource,
    Provision, ProvisionHash, ShardId, SubstateKey, TerminalEvidence, VerdictCells, Verifiable,
    settled_txs_root_from_hashes,
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
/// `(source_shard, target_shard, block_height, leaf_index)`.
/// `source_shard` selects the responding committee; `target_shard` and
/// the indices ride in the body for response filtering on the responder.
pub type ProvisionFetch = Fetch<(ShardId, ShardId, BlockHeight, u32)>;
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

    type Ids = FetchIds;

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
        [entry.provision.hash()]
    }

    /// The bundled source headers go ahead of the parts, so the
    /// verification pipeline has a chance to admit them first. A header
    /// is QC-self-authenticating.
    fn deliver(kept: Vec<LocalProvisionEntry>) -> Vec<ShardScopedInput> {
        let mut inputs = Vec::with_capacity(kept.len() + 1);
        let mut parts = Vec::with_capacity(kept.len());
        for entry in kept {
            if let Some(certified_header) = entry.source_header {
                inputs.push(ShardScopedInput::Protocol(Box::new(
                    ProtocolEvent::UnverifiedRemoteHeaderReceived {
                        certified_header,
                        source: HeaderSource::Fetched,
                    },
                )));
            }
            parts.push(entry.provision);
        }
        inputs.push(ShardScopedInput::Protocol(Box::new(
            ProtocolEvent::UnverifiedProvisionsReceived { parts },
        )));
        inputs
    }
}

/// Marker type for the per-block finalization fetch.
pub struct FinalizationBinding;

impl FetchBinding for FinalizationBinding {
    type Id = FinalizationHash;

    const NAME: &'static str = "finalization";

    type Ids = FetchIds;

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

    type Ids = FetchIds;

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
        let proof = CheckedStateProof::check(scope, keys, proof)
            .map_err(|_| Refusal::Unusable("unusable_proof"))?;
        let values = response.values.into_inner();
        for (key, bytes) in &values {
            let proven = proof
                .inclusions()
                .iter()
                .find(|(asked, _)| asked == key)
                .map(|(_, inclusion)| inclusion.value_hash());
            if proven != Some(Some(jmt_value_hash(bytes))) {
                return Err(Refusal::Unusable("value_off_its_proof"));
            }
        }
        Ok(ProtocolEvent::FetchedStateProofVerified { proof, values })
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

    type Ids = FetchIds;

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
        let proof = CheckedStateProof::check(scope, cells_of(&keys), proof)
            .map_err(|_| Refusal::Unusable("unusable_proof"))?;
        Ok(ProtocolEvent::FetchedVerdictProofVerified {
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

    type Ids = FetchIds;

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
    /// `(source_shard, target_shard, block_height, leaf_index)`: one
    /// part, so every limit a part meets is the id's alone.
    type Id = (ShardId, ShardId, BlockHeight, u32);

    const NAME: &'static str = "provision";

    type Ids = FetchIds;

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::RemoteProvisions(ids)
    }
}

impl<S: ShardStorage> FetchedBy<ShardIo<S>> for ProvisionBinding {
    fn fetch_mut(shard: &mut ShardIo<S>) -> &mut Fetch<Self::Id> {
        &mut shard.cross_shard.provision
    }

    /// A chunk is grouped by route, which does not separate two source
    /// blocks of one shard, so it is split by `(source, target, height)`
    /// and each scope asked in a request of its own. Each still settles
    /// through the solicited boundary.
    fn dispatch_chunk<N: Network>(
        ids: Vec<Self::Id>,
        route: Route,
        network: &N,
        reply: &ShardReply,
    ) {
        debug_assert!(
            ids.iter()
                .all(|(source_shard, ..)| route.shard == *source_shard),
            "ProvisionBinding routes to the source shard; the runner sets it from the variant"
        );
        let mut by_scope: BTreeMap<(ShardId, ShardId, BlockHeight), Vec<Self::Id>> =
            BTreeMap::new();
        for id in ids {
            by_scope.entry((id.0, id.1, id.2)).or_default().push(id);
        }
        for scope_ids in by_scope.into_values() {
            dispatch_solicited::<Self, N, _>(scope_ids, route, network, reply);
        }
    }
}

/// A part answers for the `(source, target, height, index)` it names, so
/// one for another scope or index is unsolicited. Its leaf and proof are
/// checked on the coordinator against the commit-proven source header,
/// and the expectation that asked does not ask again, so the id stays in
/// flight until the coordinator admits a part or fails it: the fetch's
/// own retry is the only one there is.
impl SolicitedAnswer for ProvisionBinding {
    type Request = GetProvisionsRequest;
    type Item = Provision;
    type Input = ShardScopedInput;

    const SETTLES: Settles = Settles::OnVerdict;

    /// `target_shard` (the requester's shard) is the body field: the
    /// source filters provisions by which shard is asking. The route's
    /// shard, the source, picks the responding committee. Every id of a
    /// chunk shares one scope.
    fn request(ids: &[Self::Id]) -> GetProvisionsRequest {
        let (_, target_shard, block_height, _) = ids[0];
        let indices: Vec<u32> = ids.iter().map(|(.., index)| *index).collect();
        GetProvisionsRequest::new(
            block_height,
            target_shard,
            Capped::new(indices).expect("the fetch config clamps a chunk below the wire cap"),
        )
    }

    /// The count witness reaches the coordinator whatever the parts
    /// settle, an answer that builds none of them included: it answers
    /// for no id, and teaches how many there are.
    fn beside(requested: &[Self::Id], response: &GetProvisionResponse) -> Vec<ShardScopedInput> {
        let (Some(count), Some(&(source_shard, target_shard, block_height, _))) =
            (response.count, requested.first())
        else {
            return Vec::new();
        };
        vec![ShardScopedInput::Protocol(Box::new(
            ProtocolEvent::ProvisionCountReceived {
                source_shard,
                target_shard,
                block_height,
                count,
            },
        ))]
    }

    /// A server lays its parts out by leaf index, so an answer carrying
    /// one twice, or out of order, is no honest answer.
    fn well_formed(response: &GetProvisionResponse) -> bool {
        response.is_in_leaf_order()
    }

    /// Every part names exactly one transaction, so none is filtered: an
    /// engagement echo with no entries is a part like any other.
    fn items(response: GetProvisionResponse) -> Vec<Provision> {
        response.parts.into_inner()
    }

    fn answers_for(part: &Provision) -> impl IntoIterator<Item = Self::Id> + use<> {
        [(
            part.source_shard(),
            part.target_shard(),
            part.block_height(),
            part.leaf().index,
        )]
    }

    fn deliver(kept: Vec<Provision>) -> Vec<ShardScopedInput> {
        vec![ShardScopedInput::Protocol(Box::new(
            ProtocolEvent::UnverifiedProvisionsReceived { parts: kept },
        ))]
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
        BlockHeader, BlockHeaderParts, BlockHeight, CertificateRoot, ConsensusReceipt, Epoch,
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
                Epoch::GENESIS,
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
    use hyperscale_types::{Hash, ProvisionCount, TxHash};

    use super::*;
    use crate::event::HostEvent;
    use crate::fetch::settle_solicited;

    const LOCAL: ShardId = ShardId::leaf(2, 0);
    const SOURCE: ShardId = ShardId::leaf(2, 1);

    fn bundle(target: ShardId, height: u64, tx: &[u8]) -> Provision {
        Provision::dummy(
            SOURCE,
            target,
            BlockHeight::new(height),
            TxHash::from(Hash::from_bytes(tx)),
        )
    }

    /// Settle `response` to a request for `requested` and return the
    /// verdict beside what reached the loop.
    fn settle<B>(
        requested: Vec<B::Id>,
        response: <B::Request as Request>::Response,
    ) -> (ResponseVerdict, Vec<ShardScopedInput>)
    where
        B: SolicitedAnswer<Input = ShardScopedInput, Ids = FetchIds>,
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
                HostEvent::Beacon(_) => panic!("a shard reply pushes shard inputs"),
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
        let sent = bundle(LOCAL, 10, b"a");
        let left_out = bundle(LOCAL, 11, b"b").hash();
        let (verdict, inputs) = settle::<LocalProvisionBinding>(
            vec![sent.hash(), left_out],
            GetLocalProvisionsResponse::new(Capped::from_array([LocalProvisionEntry {
                provision: sent.clone(),
                source_header: None,
            }])),
        );
        assert_eq!(verdict, ResponseVerdict::Accept);
        assert!(!inputs.iter().any(is_fulfilled), "held until its verdict");
        assert!(inputs.iter().any(|input| matches!(
            input,
            ShardScopedInput::Protocol(event)
                if matches!(&**event, ProtocolEvent::UnverifiedProvisionsReceived { parts }
                    if parts.iter().map(Provision::hash).eq([sent.hash()]))
        )));
        assert!(inputs.iter().any(|input| matches!(
            input,
            ShardScopedInput::FetchFailed(FetchIds::LocalProvisions(ids)) if ids == &[left_out]
        )));
    }

    /// An item nobody asked for is dropped and rejects the answer.
    #[test]
    fn an_unsolicited_item_rejects_the_answer() {
        let asked = bundle(LOCAL, 10, b"a");
        let extra = bundle(LOCAL, 12, b"c");
        let (verdict, inputs) = settle::<LocalProvisionBinding>(
            vec![asked.hash()],
            GetLocalProvisionsResponse::new(Capped::from_array([&asked, &extra].map(
                |provision| LocalProvisionEntry {
                    provision: provision.clone(),
                    source_header: None,
                },
            ))),
        );
        assert_eq!(verdict, ResponseVerdict::Reject);
        let delivered: Vec<_> = inputs
            .iter()
            .filter_map(|input| match input {
                ShardScopedInput::Protocol(event) => match &**event {
                    ProtocolEvent::UnverifiedProvisionsReceived { parts } => {
                        Some(parts.iter().map(Provision::hash).collect::<Vec<_>>())
                    }
                    _ => None,
                },
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(delivered, vec![asked.hash()]);
    }

    /// Parts answering for `parts`, and no count.
    fn parts(parts: impl IntoIterator<Item = Provision>) -> GetProvisionResponse {
        GetProvisionResponse {
            parts: Capped::new(parts.into_iter().collect()).unwrap(),
            count: None,
        }
    }

    fn failed_ids(inputs: &[ShardScopedInput]) -> Vec<(ShardId, ShardId, BlockHeight, u32)> {
        inputs
            .iter()
            .filter_map(|input| match input {
                ShardScopedInput::FetchFailed(FetchIds::RemoteProvisions(ids)) => Some(ids.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    /// A source that does not hold the block answers honestly and is
    /// asked again elsewhere; a part for another scope is no answer and
    /// rejects the peer.
    #[test]
    fn a_remote_part_is_held_to_its_scope_and_a_miss_costs_nothing() {
        let id = (SOURCE, LOCAL, BlockHeight::new(10), 0);

        let (verdict, inputs) = settle::<ProvisionBinding>(vec![id], GetProvisionResponse::empty());
        assert_eq!(verdict, ResponseVerdict::Accept, "not held");
        assert_eq!(failed_ids(&inputs), vec![id], "not held: asked again");

        let (verdict, inputs) =
            settle::<ProvisionBinding>(vec![id], parts([bundle(ShardId::leaf(2, 3), 10, b"a")]));
        assert_eq!(verdict, ResponseVerdict::Reject, "another scope");
        assert_eq!(failed_ids(&inputs), vec![id], "another scope: asked again");

        let (verdict, inputs) =
            settle::<ProvisionBinding>(vec![id], parts([bundle(LOCAL, 10, b"a")]));
        assert_eq!(verdict, ResponseVerdict::Accept);
        assert!(failed_ids(&inputs).is_empty() && !inputs.iter().any(is_fulfilled));
    }

    /// A part answers for its own index alone. An index the answer leaves
    /// out — a responder lying by omission, or trimming to its budget —
    /// is released for retry elsewhere at no cost to the peer, and the
    /// part it did send stays in flight for its verdict.
    #[test]
    fn an_index_left_out_is_asked_again_and_the_rest_kept() {
        let at = |index| (SOURCE, LOCAL, BlockHeight::new(10), index);
        let (verdict, inputs) =
            settle::<ProvisionBinding>(vec![at(0), at(1)], parts([bundle(LOCAL, 10, b"a")]));
        assert_eq!(verdict, ResponseVerdict::Accept);
        assert_eq!(failed_ids(&inputs), vec![at(1)]);
        assert!(!inputs.iter().any(is_fulfilled));
    }

    /// An answer carrying a part twice is refused whole: nothing reaches
    /// the coordinator, every asked index is asked again, and the peer
    /// is blamed. The same parts once each, in leaf order, are kept.
    #[test]
    fn an_answer_repeating_a_part_is_refused_whole() {
        let at = |index| (SOURCE, LOCAL, BlockHeight::new(10), index);
        let first = bundle(LOCAL, 10, b"a");
        let second = bundle(LOCAL, 10, b"b").at_leaf(1, 2);

        let (verdict, inputs) = settle::<ProvisionBinding>(
            vec![at(0), at(1)],
            parts([first.clone(), first.clone(), second.clone()]),
        );
        assert_eq!(verdict, ResponseVerdict::Reject);
        assert_eq!(failed_ids(&inputs), vec![at(0), at(1)]);
        assert!(
            !inputs
                .iter()
                .any(|input| matches!(input, ShardScopedInput::Protocol(_))),
            "nothing of it is handed over",
        );

        let (verdict, inputs) =
            settle::<ProvisionBinding>(vec![at(0), at(1)], parts([first, second]));
        assert_eq!(verdict, ResponseVerdict::Accept);
        assert!(failed_ids(&inputs).is_empty());
    }

    /// The count witness reaches the coordinator from an answer that
    /// builds none of the asked parts, every one of which is released for
    /// retry: it answers for no id, and teaches how many there are.
    #[test]
    fn a_count_witness_rides_an_answer_with_no_part() {
        let at = |index| (SOURCE, LOCAL, BlockHeight::new(10), index);
        let count = ProvisionCount {
            count: 3,
            merkle_root: Hash::from_bytes(b"root"),
        };
        let (verdict, inputs) = settle::<ProvisionBinding>(
            vec![at(0), at(2)],
            GetProvisionResponse {
                parts: Capped::empty(),
                count: Some(count),
            },
        );
        assert_eq!(verdict, ResponseVerdict::Accept);
        assert_eq!(failed_ids(&inputs), vec![at(0), at(2)]);
        assert!(inputs.iter().any(|input| matches!(
            input,
            ShardScopedInput::Protocol(event)
                if matches!(&**event, ProtocolEvent::ProvisionCountReceived {
                    source_shard, target_shard, block_height, count: stated,
                } if *source_shard == SOURCE && *target_shard == LOCAL
                    && *block_height == BlockHeight::new(10) && *stated == count)
        )));
    }

    /// An engagement echo — a part carrying no entries — is an answer
    /// like any other: kept, held to its scope, and handed over.
    #[test]
    fn an_empty_entry_part_passes_the_response_boundary() {
        let id = (SOURCE, LOCAL, BlockHeight::new(10), 0);
        let echo = bundle(LOCAL, 10, b"echo");
        assert!(echo.entries().is_empty());
        let (verdict, inputs) = settle::<ProvisionBinding>(vec![id], parts([echo.clone()]));
        assert_eq!(verdict, ResponseVerdict::Accept);
        assert!(inputs.iter().any(|input| matches!(
            input,
            ShardScopedInput::Protocol(event)
                if matches!(&**event, ProtocolEvent::UnverifiedProvisionsReceived { parts }
                    if parts.iter().map(Provision::hash).eq([echo.hash()]))
        )));
        assert!(
            !inputs
                .iter()
                .any(|input| matches!(input, ShardScopedInput::FetchFailed(_)))
        );
    }
}
