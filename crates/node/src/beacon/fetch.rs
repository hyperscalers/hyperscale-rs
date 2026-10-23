//! Beacon fetch instances and their bindings.
//!
//! The beacon coordinator drives three id-keyed fetches: missing beacon
//! proposals (`beacon_proposal`), ratify candidates the pool prevoted and
//! the local member never received (`beacon_candidate`), and
//! shard-accumulator witness leaves (`shard_witness`, pulled to build the
//! windowed beacon-witness commitment). A shard loop carries one
//! [`BeaconFetchState`] for its seated vnodes on [`ShardIo`], and the
//! beacon loop carries its own for its participants, whose proposal and
//! candidate asks go past the host.
//!
//! The generic engine, the [`FetchBinding`] trait, and the shared
//! `partition_solicited` helper live in [`crate::fetch`].

use crossbeam::channel::Sender;
use hyperscale_core::{FetchIds, ProtocolEvent};
use hyperscale_network::{Network, RequestError};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::request::beacon::{
    GetBeaconCandidateRequest, GetBeaconProposalRequest, GetShardWitnessesRequest,
};
use hyperscale_types::network::response::beacon::{
    GetBeaconCandidateResponse, GetBeaconProposalResponse, GetShardWitnessesResponse,
};
use hyperscale_types::{
    BeaconBlockHash, BlockHash, BlockHeight, Epoch, LeafIndex, ShardId, ValidatorId,
};

use crate::config::NodeConfig;
use crate::event::BeaconScopedInput;
use crate::fetch::{
    Fetch, FetchBinding, FetchOwner, FetchReply, FetchedBy, Refusal, Route, ScopedAnswer,
    ShardReply, defers_to_the_tick, dispatch_scoped,
};
use crate::shard::{HostEvent, ShardIo};

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

/// Beacon fetch state: the id-keyed fetches the beacon coordinator
/// drives.
pub struct BeaconFetchState {
    /// Cross-shard beacon-witness fetch (rotates through source committee).
    pub(crate) shard_witness: ShardWitnessFetch,
    /// Missing-proposal fetch (rotates through beacon committee).
    pub(crate) beacon_proposal: BeaconProposalFetch,
    /// Ratify-candidate fetch (asks the members that prevoted it).
    pub(crate) beacon_candidate: BeaconCandidateFetch,
}

impl BeaconFetchState {
    /// Build beacon fetch state for a freshly hosted shard.
    #[must_use]
    pub(crate) fn new(config: &NodeConfig) -> Self {
        Self {
            shard_witness: ShardWitnessFetch::new(
                "shard_witness",
                config.shard_witness_fetch.clone(),
            ),
            beacon_proposal: BeaconProposalFetch::new(
                "beacon_proposal",
                config.beacon_proposal_fetch.clone(),
            ),
            beacon_candidate: BeaconCandidateFetch::new(
                "beacon_candidate",
                config.beacon_proposal_fetch.clone(),
            ),
        }
    }

    /// Build the beacon loop's fetch state. Its proposal and candidate
    /// fetches ask past the host: the host's own beacon store and serve
    /// caches are filled by the same paths that left its participants
    /// short, so a local answer is one its peers also hold.
    #[must_use]
    pub(crate) fn past_the_host(config: &NodeConfig) -> Self {
        Self {
            beacon_proposal: BeaconProposalFetch::peers_only(
                "beacon_proposal",
                config.beacon_proposal_fetch.clone(),
            ),
            beacon_candidate: BeaconCandidateFetch::peers_only(
                "beacon_candidate",
                config.beacon_proposal_fetch.clone(),
            ),
            ..Self::new(config)
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
    }
}

impl FetchOwner for BeaconFetchState {
    type Reply = BeaconReply;
}

/// The beacon loop's reply handle: the host's beacon channel.
#[derive(Clone)]
pub struct BeaconReply(pub(crate) Sender<HostEvent>);

impl BeaconReply {
    fn push(&self, input: BeaconScopedInput) {
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
        self.push(BeaconScopedInput::FetchFulfilled(ids));
        self.push(BeaconScopedInput::Protocol(Box::new(event)));
    }
}

/// Marker type for the cross-shard beacon-witness fetch.
pub struct ShardWitnessBinding;

impl FetchBinding for ShardWitnessBinding {
    type Id = (ShardId, BlockHeight, BlockHash, LeafIndex, LeafIndex);

    const NAME: &'static str = "shard_witness";

    fn ids(ids: Vec<Self::Id>) -> FetchIds {
        FetchIds::ShardWitnesses(ids)
    }
}

impl<S: ShardStorage> FetchedBy<ShardIo<S>> for ShardWitnessBinding {
    fn fetch_mut(shard: &mut ShardIo<S>) -> &mut Fetch<Self::Id> {
        &mut shard.beacon_fetch.shard_witness
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
        FetchIds::BeaconProposals(ids)
    }
}

impl<S: ShardStorage> FetchedBy<ShardIo<S>> for BeaconProposalBinding {
    fn fetch_mut(shard: &mut ShardIo<S>) -> &mut Fetch<Self::Id> {
        &mut shard.beacon_fetch.beacon_proposal
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
        FetchIds::BeaconCandidates(ids)
    }
}

impl<S: ShardStorage> FetchedBy<ShardIo<S>> for BeaconCandidateBinding {
    fn fetch_mut(shard: &mut ShardIo<S>) -> &mut Fetch<Self::Id> {
        &mut shard.beacon_fetch.beacon_candidate
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
