//! Beacon fetch instances and their bindings.
//!
//! The host's beacon loop drives five id-keyed fetches from the one
//! [`BeaconFetchState`]. Three serve the beacon itself: missing beacon
//! proposals (`beacon_proposal`), ratify candidates the pool prevoted and
//! the local member never received (`beacon_candidate`), and
//! shard-accumulator witness leaves (`shard_witness`, pulled to build the
//! windowed beacon-witness commitment). Its participants' proposal and
//! candidate asks go past the host, and the fold's witness asks try the
//! host's own stores first. The other two are the host's record and code
//! fetches (`instance_record`, `package_artifact`), which every chain loop
//! on the host asks through it.
//!
//! The generic engine, the [`FetchBinding`] trait, and the shared
//! `partition_solicited` helper live in [`crate::fetch`].

use std::sync::Arc;

use crossbeam::channel::Sender;
use hyperscale_core::{BeaconFetchIds, FetchIds, ProtocolEvent};
use hyperscale_metrics::record_fetch_response_refused;
use hyperscale_network::{Network, RequestError, ResponseVerdict};
use hyperscale_types::network::request::beacon::{
    GetBeaconCandidateRequest, GetBeaconProposalRequest, GetShardWitnessesRequest,
};
use hyperscale_types::network::request::{
    MAX_INSTANCE_RECORDS_PER_REQUEST, MAX_PACKAGE_ARTIFACTS_PER_REQUEST,
};
use hyperscale_types::network::response::beacon::{
    GetBeaconCandidateResponse, GetBeaconProposalResponse, GetShardWitnessesResponse,
};
use hyperscale_types::{
    Address, BeaconBlockHash, BeaconProposalVerifyContext, BlockHash, BlockHeight, Epoch, Hash,
    LeafIndex, NetworkDefinition, ShardId, ValidatorId, Verifiable, Verifier,
};
use tracing::warn;

use crate::config::NodeConfig;
use crate::event::BeaconScopedInput;
use crate::fetch::{
    Fetch, FetchBinding, FetchConfig, FetchOwner, FetchReply, FetchedBy, HandsOver, Refusal, Route,
    ScopedAnswer, defers_to_the_tick, dispatch_scoped, transport_failed,
};
use crate::shard::{HostEvent, SharedTopologySnapshot};

/// Cross-shard beacon-witness fetch keyed by
/// `(source_shard, block_height, committed_block_hash, lo, hi)`.
/// Each id is one contiguous leaf run in the source shard's accumulator
/// at the named committed block — the unit a range proof covers.
pub type ShardWitnessFetch = Fetch<(ShardId, BlockHeight, BlockHash, LeafIndex, LeafIndex)>;
/// Missing-proposal fetch keyed by `(epoch, validator)` — one entry
/// per beacon-committee member whose proposal SPC's `OutputHigh`
/// committed but the local pool never observed.
pub type BeaconProposalFetch = Fetch<(Epoch, ValidatorId)>;
/// Ratify-candidate fetch keyed by `(epoch, block_hash)` — one entry per
/// candidate hash the pool prevoted that the local member never held.
pub type BeaconCandidateFetch = Fetch<(Epoch, BeaconBlockHash)>;

/// Per-component record fetch, keyed by the address the record derives.
pub type InstanceRecordFetch = Fetch<Address>;
/// Per-package artifact fetch, keyed by content address.
pub type PackageArtifactFetch = Fetch<Hash>;

/// Beacon fetch state: the id-keyed fetches the host's beacon loop
/// drives for its fold, its participants and its chains.
pub struct BeaconFetchState {
    /// Cross-shard beacon-witness fetch (rotates through source committee).
    pub(crate) shard_witness: ShardWitnessFetch,
    /// Missing-proposal fetch (rotates through beacon committee).
    pub(crate) beacon_proposal: BeaconProposalFetch,
    /// Ratify-candidate fetch (asks the members that prevoted it).
    pub(crate) beacon_candidate: BeaconCandidateFetch,
    /// Component records, from the committee of the shard owning each
    /// one's prefix.
    pub(crate) instance_record: InstanceRecordFetch,
    /// Package artifacts, from the committee of each one's custodian.
    pub(crate) package_artifact: PackageArtifactFetch,
}

impl BeaconFetchState {
    /// Build the beacon loop's fetch state. Its proposal and candidate
    /// fetches ask past the host: the host's own beacon store and serve
    /// caches are filled by the same paths that left its participants
    /// short, so a local answer is one its peers also hold. Witness
    /// asks try the host first, which answers a shard it serves from its
    /// own store.
    #[must_use]
    pub(crate) fn new(config: &NodeConfig) -> Self {
        Self {
            shard_witness: ShardWitnessFetch::new(
                "shard_witness",
                config.shard_witness_fetch.clone(),
            ),
            beacon_proposal: BeaconProposalFetch::peers_only(
                "beacon_proposal",
                config.beacon_proposal_fetch.clone(),
            ),
            beacon_candidate: BeaconCandidateFetch::peers_only(
                "beacon_candidate",
                config.beacon_proposal_fetch.clone(),
            ),
            instance_record: InstanceRecordFetch::new(
                "instance_record",
                clamped(
                    &config.instance_record_fetch,
                    MAX_INSTANCE_RECORDS_PER_REQUEST,
                ),
            ),
            // The wire caps the batch far below the generic default: an
            // artifact runs to a transaction's whole byte budget.
            package_artifact: PackageArtifactFetch::new(
                "package_artifact",
                clamped(
                    &config.package_artifact_fetch,
                    MAX_PACKAGE_ARTIFACTS_PER_REQUEST,
                ),
            ),
        }
    }
}

/// `config` with its batch clamped to what one request may carry.
fn clamped(config: &FetchConfig, cap: usize) -> FetchConfig {
    let mut config = config.clone();
    config.max_ids_per_request = config.max_ids_per_request.min(cap);
    config
}

impl FetchOwner for BeaconFetchState {
    type Reply = BeaconReply;
}

/// The beacon loop's reply handle: the host's beacon channel, and the
/// keys a fetched proposal's VRF reveal is checked under at its response
/// boundary.
#[derive(Clone)]
pub struct BeaconReply {
    sender: Sender<HostEvent>,
    proposal_keys: ProposalKeys,
}

/// What a fetched proposal's reveal is checked under: its author's key
/// in the topology the beacon loop publishes at each adoption, the same
/// key the wire handler checks a gossiped proposal under.
#[derive(Clone)]
pub struct ProposalKeys {
    pub(crate) topology: SharedTopologySnapshot,
    pub(crate) verifier: Arc<dyn Verifier>,
    pub(crate) network: NetworkDefinition,
}

impl BeaconReply {
    pub(crate) const fn new(sender: Sender<HostEvent>, proposal_keys: ProposalKeys) -> Self {
        Self {
            sender,
            proposal_keys,
        }
    }

    pub(crate) fn push(&self, input: BeaconScopedInput) {
        let _ = self.sender.send(HostEvent::Beacon(input));
    }

    /// The response boundary of a proposal fetch for `id`: a proposal
    /// whose reveal holds under its author's key retires `id` and is
    /// handed over checked; one that fails is the peer's fault and is
    /// asked of another. A peer that does not hold it, or an author this
    /// host holds no key for, releases `id` at no cost to the peer.
    fn settle_proposal(
        &self,
        id: (Epoch, ValidatorId),
        result: Result<GetBeaconProposalResponse, RequestError>,
    ) -> ResponseVerdict {
        let response = match result {
            Ok(response) => response,
            Err(error) => {
                return transport_failed::<BeaconProposalBinding, _>(vec![id], &error, self);
            }
        };
        let ids = BeaconProposalBinding::ids(vec![id]);
        let (epoch, validator) = id;
        let (Some(proposal), Some(sender_pk)) = (
            response.proposal,
            self.proposal_keys.topology.load().public_key(validator),
        ) else {
            self.refused(ids);
            return ResponseVerdict::Accept;
        };
        let ctx = BeaconProposalVerifyContext {
            verifier: self.proposal_keys.verifier.as_ref(),
            network: &self.proposal_keys.network,
            epoch,
            sender_pk,
        };
        match Arc::unwrap_or_clone(proposal).upgrade(&ctx) {
            Ok(checked) => {
                self.answered(
                    ids,
                    ProtocolEvent::BeaconProposalFetched {
                        epoch,
                        validator,
                        proposal: Arc::new(Verifiable::from(checked)),
                    },
                );
                ResponseVerdict::Accept
            }
            Err((_, err)) => {
                warn!(
                    ?validator,
                    epoch = epoch.inner(),
                    ?err,
                    "Fetched BeaconProposal failed VRF verification — asking another peer"
                );
                record_fetch_response_refused(BeaconProposalBinding::NAME, "bad_reveal");
                self.refused(ids);
                ResponseVerdict::Reject
            }
        }
    }
}

impl FetchReply for BeaconReply {
    fn failed(&self, ids: FetchIds, error: &RequestError) {
        self.push(if defers_to_the_tick(error) {
            BeaconScopedInput::FetchUnroutable(ids)
        } else {
            BeaconScopedInput::FetchFailed(ids)
        });
    }

    fn refused(&self, ids: FetchIds) {
        self.push(BeaconScopedInput::FetchFailed(ids));
    }

    fn answered(&self, ids: FetchIds, event: ProtocolEvent) {
        self.push(BeaconScopedInput::Answered {
            ids,
            event: Box::new(event),
        });
    }
}

impl HandsOver<BeaconScopedInput> for BeaconReply {
    fn hand_over(&self, fulfilled: Option<FetchIds>, inputs: Vec<BeaconScopedInput>) {
        if let Some(ids) = fulfilled {
            self.push(BeaconScopedInput::FetchFulfilled(ids));
        }
        for input in inputs {
            self.push(input);
        }
    }
}

/// Marker type for the cross-shard beacon-witness fetch.
pub struct ShardWitnessBinding;

impl FetchBinding for ShardWitnessBinding {
    type Id = (ShardId, BlockHeight, BlockHash, LeafIndex, LeafIndex);

    const NAME: &'static str = "shard_witness";

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::Beacon(BeaconFetchIds::Witnesses(ids))
    }
}

impl FetchedBy<BeaconFetchState> for ShardWitnessBinding {
    fn fetch_mut(state: &mut BeaconFetchState) -> &mut Fetch<Self::Id> {
        &mut state.shard_witness
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<Self::Id>,
        route: Route,
        network: &N,
        reply: &BeaconReply,
    ) {
        dispatch_scoped::<Self, N, _>(ids, route, network, reply);
    }
}

/// The id names a whole leaf run and a range proof only verifies for the
/// run it covers, so the run is the scope and one request carries one.
impl ScopedAnswer for ShardWitnessBinding {
    type Scope = Self::Id;
    type Key = ();
    type Request = GetShardWitnessesRequest;

    fn split(id: Self::Id) -> (Self::Scope, Self::Key) {
        (id, ())
    }

    fn join(scope: Self::Scope, (): Self::Key) -> Self::Id {
        scope
    }

    fn request(scope: Self::Scope, _keys: &[Self::Key]) -> Self::Request {
        let (source_shard, block_height, committed_block_hash, lo, hi) = scope;
        GetShardWitnessesRequest::new(source_shard, block_height, committed_block_hash, lo, hi)
    }

    fn answer(
        scope: Self::Scope,
        _keys: Vec<Self::Key>,
        response: GetShardWitnessesResponse,
    ) -> Result<ProtocolEvent, Refusal> {
        if response.payloads.is_empty() {
            return Err(Refusal::NotHeld);
        }
        let (source_shard, _, committed_block_hash, lo, _) = scope;
        Ok(ProtocolEvent::ShardWitnessesReceived {
            shard_id: source_shard,
            committed_block_hash,
            lo,
            payloads: response.payloads.into_inner(),
            range_proof: response.range_proof.into_inner(),
        })
    }
}

/// Marker type for the missing-proposal fetch.
pub struct BeaconProposalBinding;

impl FetchBinding for BeaconProposalBinding {
    type Id = (Epoch, ValidatorId);

    const NAME: &'static str = "beacon_proposal";

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::Beacon(BeaconFetchIds::Proposals(ids))
    }
}

/// The wire type addresses a single proposal, so one request carries
/// one id. A peer that does not hold the proposal releases the slot for
/// retry against another committee member rather than resolving the
/// await: the participant keeps awaiting it, `prune_stale` bounds the
/// rotation once the epoch commits, and the beacon-block gossip path is
/// only the last-resort backstop.
impl FetchedBy<BeaconFetchState> for BeaconProposalBinding {
    fn fetch_mut(state: &mut BeaconFetchState) -> &mut Fetch<Self::Id> {
        &mut state.beacon_proposal
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<Self::Id>,
        route: Route,
        network: &N,
        reply: &BeaconReply,
    ) {
        for id @ (epoch, validator) in ids {
            let reply = reply.clone();
            route.request(
                network,
                GetBeaconProposalRequest::new(epoch, validator),
                Box::new(move |result| reply.settle_proposal(id, result)),
            );
        }
    }
}

/// Marker type for the ratify-candidate fetch.
pub struct BeaconCandidateBinding;

impl FetchBinding for BeaconCandidateBinding {
    type Id = (Epoch, BeaconBlockHash);

    const NAME: &'static str = "beacon_candidate";

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::Beacon(BeaconFetchIds::Candidates(ids))
    }
}

impl FetchedBy<BeaconFetchState> for BeaconCandidateBinding {
    fn fetch_mut(state: &mut BeaconFetchState) -> &mut Fetch<Self::Id> {
        &mut state.beacon_candidate
    }

    fn dispatch_chunk<N: Network>(
        ids: Vec<Self::Id>,
        route: Route,
        network: &N,
        reply: &BeaconReply,
    ) {
        dispatch_scoped::<Self, N, _>(ids, route, network, reply);
    }
}

/// The wire type addresses a single candidate, so `(epoch, block_hash)`
/// is the scope and one request carries one.
impl ScopedAnswer for BeaconCandidateBinding {
    type Scope = Self::Id;
    type Key = ();
    type Request = GetBeaconCandidateRequest;

    fn split(id: Self::Id) -> (Self::Scope, Self::Key) {
        (id, ())
    }

    fn join(scope: Self::Scope, (): Self::Key) -> Self::Id {
        scope
    }

    fn request((epoch, block_hash): Self::Scope, _keys: &[Self::Key]) -> Self::Request {
        GetBeaconCandidateRequest::new(epoch, block_hash)
    }

    /// A peer answering with a candidate other than the one asked for is
    /// refused here; the beacon loop checks the rest as a gossiped
    /// candidate is checked before the slot retires.
    fn answer(
        (epoch, block_hash): Self::Scope,
        _keys: Vec<Self::Key>,
        response: GetBeaconCandidateResponse,
    ) -> Result<ProtocolEvent, Refusal> {
        let candidate = response.candidate.ok_or(Refusal::NotHeld)?;
        if candidate.epoch() != epoch || candidate.block_hash() != block_hash {
            return Err(Refusal::Unusable("candidate_mismatch"));
        }
        Ok(ProtocolEvent::BeaconCandidateReceived { candidate })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crossbeam::channel::unbounded;
    use hyperscale_types::{BeaconProposal, BeaconProposalDraft, BlockHeight, VrfProof};

    use super::*;
    use crate::shard::test_host::Fixture;

    /// A fetched proposal whose VRF reveal fails under its author's key
    /// rejects the peer that gave it and is asked of another; one that
    /// holds is handed over already checked.
    #[test]
    fn a_fetched_proposal_failing_its_reveal_rejects_its_peer() {
        let fix = Fixture::new();
        let host = fix.host(BlockHeight::GENESIS);
        let network = NetworkDefinition::simulator();
        let (tx, events) = unbounded();
        let reply = BeaconReply::new(
            tx,
            ProposalKeys {
                topology: host.process.topology_snapshot.clone(),
                verifier: Arc::clone(&host.process.verifier),
                network: network.clone(),
            },
        );
        let author = fix.committee.validator_id(1);
        let id = (Epoch::new(1), author);
        let answer = |proposal: BeaconProposal| {
            Ok(GetBeaconProposalResponse::new(Some(Arc::new(
                Verifiable::from(proposal),
            ))))
        };

        let forged = BeaconProposal::new(
            BTreeMap::new(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            VrfProof::ZERO,
        );
        assert!(matches!(
            reply.settle_proposal(id, answer(forged)),
            ResponseVerdict::Reject
        ));
        assert!(matches!(
            events.try_recv(),
            Ok(HostEvent::Beacon(BeaconScopedInput::FetchFailed(_)))
        ));

        let signer = fix.committee.signer(1);
        let honest = BeaconProposalDraft::new(
            signer.as_ref(),
            &network,
            Epoch::new(1),
            BTreeMap::new(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
        )
        .and_then(BeaconProposalDraft::sign)
        .expect("the author's key signs its proposal")
        .into_inner();
        assert!(matches!(
            reply.settle_proposal(id, answer(honest)),
            ResponseVerdict::Accept
        ));
        let Ok(HostEvent::Beacon(BeaconScopedInput::Answered { event, .. })) = events.try_recv()
        else {
            panic!("an honest proposal is handed over");
        };
        assert!(matches!(
            *event,
            ProtocolEvent::BeaconProposalFetched { proposal, .. } if proposal.verified().is_some()
        ));
    }
}
