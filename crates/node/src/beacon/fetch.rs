//! Per-shard beacon fetch instances and their bindings.
//!
//! The beacon coordinator drives three id-keyed fetches per shard: missing
//! beacon proposals (`beacon_proposal`), ratify candidates the pool
//! prevoted and the local member never received (`beacon_candidate`), and
//! shard-accumulator witness leaves (`shard_witness`, pulled to build the
//! windowed beacon-witness commitment). All are per-shard `Fetch` instances — each driver runs its own, the
//! lock-free per-thread trade-off the beacon chain keeps — so they live on
//! [`ShardIo`] inside [`BeaconFetchState`], while their driving body and serve
//! paths stay in this beacon package.
//!
//! The generic engine, the [`FetchBinding`] trait, and the shared
//! `partition_solicited` helper live in [`crate::fetch`].

use crossbeam::channel::Sender;
use hyperscale_core::{FetchIds, ProtocolEvent};
use hyperscale_network::Network;
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::request::beacon::{
    GetBeaconCandidateRequest, GetBeaconProposalRequest, GetShardWitnessesRequest,
};
use hyperscale_types::network::response::beacon::{
    GetBeaconCandidateResponse, GetBeaconProposalResponse, GetShardWitnessesResponse,
};
use hyperscale_types::{
    BeaconBlockHash, BlockHash, BlockHeight, Epoch, LeafIndex, MessageClass, ShardId, ValidatorId,
};

use crate::config::NodeConfig;
use crate::fetch::{Fetch, FetchBinding, Refusal, ScopedAnswer, dispatch_scoped};
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

/// Per-shard beacon fetch state.
///
/// Composed into [`ShardIo`]. Holds the id-keyed fetches the beacon
/// coordinator drives for this shard.
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

    /// True if any beacon fetch has work outstanding (in-flight or
    /// queued). Keeps this shard's `FetchTick` timer alive so deferred ids
    /// eventually retry.
    #[must_use]
    pub(crate) fn has_pending(&self) -> bool {
        self.shard_witness.has_pending()
            || self.beacon_proposal.has_pending()
            || self.beacon_candidate.has_pending()
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

    fn fetch_mut<S: ShardStorage>(shard: &mut ShardIo<S>) -> &mut Fetch<Self::Id> {
        &mut shard.beacon_fetch.shard_witness
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

    fn request(scope: Self::Scope, _keys: &[Self::Key], _asker: ShardId) -> Self::Request {
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

    fn fetch_mut<S: ShardStorage>(shard: &mut ShardIo<S>) -> &mut Fetch<Self::Id> {
        &mut shard.beacon_fetch.beacon_proposal
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

    fn request(
        (epoch, validator): Self::Scope,
        _keys: &[Self::Key],
        _asker: ShardId,
    ) -> Self::Request {
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

    fn fetch_mut<S: ShardStorage>(shard: &mut ShardIo<S>) -> &mut Fetch<Self::Id> {
        &mut shard.beacon_fetch.beacon_candidate
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

    fn request(
        (epoch, block_hash): Self::Scope,
        _keys: &[Self::Key],
        _asker: ShardId,
    ) -> Self::Request {
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
