//! Beacon fetch instances and their bindings.
//!
//! The beacon coordinator drives three id-keyed fetches: missing beacon
//! proposals (`beacon_proposal`), ratify candidates the pool prevoted and
//! the local member never received (`beacon_candidate`), and
//! shard-accumulator witness leaves (`shard_witness`, pulled to build the
//! windowed beacon-witness commitment). The host's beacon loop carries
//! the one [`BeaconFetchState`]: its participants' proposal and candidate
//! asks go past the host, and the fold's witness asks try the host's own
//! stores first. Beside them it carries the host's record and code
//! fetches (`instance_record`, `package_artifact`), which every loop on
//! the host asks through it.
//!
//! The generic engine, the [`FetchBinding`] trait, and the shared
//! `partition_solicited` helper live in [`crate::fetch`].

use crossbeam::channel::Sender;
use hyperscale_core::{BeaconFetchIds, FetchIds, ProtocolEvent};
use hyperscale_network::{Network, RequestError};
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
    Address, BeaconBlockHash, BlockHash, BlockHeight, Epoch, Hash, LeafIndex, ShardId, ValidatorId,
};

use crate::config::NodeConfig;
use crate::event::BeaconScopedInput;
use crate::fetch::{
    Fetch, FetchBinding, FetchConfig, FetchOwner, FetchReply, FetchedBy, Refusal, Route,
    ScopedAnswer, defers_to_the_tick, dispatch_scoped,
};
use crate::shard::HostEvent;

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

    /// True if any beacon fetch has work outstanding (in-flight or
    /// queued). Keeps the owning loop's fetch tick alive so deferred ids
    /// eventually retry.
    #[must_use]
    pub(crate) fn has_pending(&self) -> bool {
        self.shard_witness.has_pending()
            || self.beacon_proposal.has_pending()
            || self.beacon_candidate.has_pending()
            || self.instance_record.has_pending()
            || self.package_artifact.has_pending()
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

/// The beacon loop's reply handle: the host's beacon channel.
#[derive(Clone)]
pub struct BeaconReply(pub(crate) Sender<HostEvent>);

impl BeaconReply {
    pub(crate) fn push(&self, input: BeaconScopedInput) {
        let _ = self.0.send(HostEvent::Beacon(input));
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
        dispatch_scoped::<Self, N, _>(ids, route, network, reply);
    }
}

/// The wire type addresses a single proposal, so `(epoch, validator)` is
/// the scope and one request carries one.
impl ScopedAnswer for BeaconProposalBinding {
    type Scope = Self::Id;
    type Key = ();
    type Request = GetBeaconProposalRequest;

    fn split(id: Self::Id) -> (Self::Scope, Self::Key) {
        (id, ())
    }

    fn join(scope: Self::Scope, (): Self::Key) -> Self::Id {
        scope
    }

    fn request((epoch, validator): Self::Scope, _keys: &[Self::Key]) -> Self::Request {
        GetBeaconProposalRequest::new(epoch, validator)
    }

    /// A peer that does not hold the proposal releases the slot for
    /// retry against another committee member rather than resolving the
    /// await: the coordinator keeps awaiting it, `prune_stale` bounds the
    /// rotation once the epoch commits, and the beacon-block gossip path
    /// is only the last-resort backstop.
    fn answer(
        (epoch, validator): Self::Scope,
        _keys: Vec<Self::Key>,
        response: GetBeaconProposalResponse,
    ) -> Result<ProtocolEvent, Refusal> {
        let proposal = response.proposal.ok_or(Refusal::NotHeld)?;
        Ok(ProtocolEvent::BeaconProposalFetched {
            epoch,
            validator,
            proposal,
        })
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

    /// The answer enters the coordinator as a gossiped candidate does,
    /// so it passes the same checks; a peer answering with a candidate
    /// other than the one asked for is refused here.
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
