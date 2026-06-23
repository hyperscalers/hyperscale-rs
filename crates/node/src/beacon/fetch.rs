//! Per-shard beacon fetch instances and their bindings.
//!
//! The beacon coordinator drives two id-keyed fetches per shard: missing
//! beacon proposals (`beacon_proposal`) and shard-accumulator witness leaves
//! (`shard_witness`, pulled to build the windowed beacon-witness commitment).
//! Both are per-shard `Fetch` instances — each driver runs its own, the
//! lock-free per-thread trade-off the beacon chain keeps — so they live on
//! [`ShardIo`] inside [`BeaconFetchState`], while their driving body and serve
//! paths stay in this beacon package.
//!
//! The generic engine, the [`FetchBinding`] trait, and the shared
//! `partition_solicited` helper live in [`crate::fetch`].

use std::sync::Arc;

use crossbeam::channel::Sender;
use hyperscale_core::ProtocolEvent;
use hyperscale_network::{Network, ResponseVerdict};
use hyperscale_storage::ShardStorage;
use hyperscale_types::network::request::beacon::{
    GetBeaconProposalRequest, GetShardWitnessesRequest,
};
use hyperscale_types::{
    BlockHash, BlockHeight, Epoch, LeafIndex, MessageClass, ShardId, ShardWitness, ValidatorId,
};

use crate::config::NodeConfig;
use crate::fetch::{Fetch, FetchBinding};
use crate::shard::ShardIo;
use crate::shard_loop::{HostEvent, ShardScopedInput, push_protocol_event, push_shard_input};

/// Cross-shard beacon-witness fetch keyed by
/// `(source_shard, block_height, committed_block_hash, leaf_index)`.
/// Each id is a single leaf in the source shard's accumulator at the
/// named committed block.
pub type ShardWitnessFetch = Fetch<(ShardId, BlockHeight, BlockHash, LeafIndex)>;
/// Missing-proposal fetch keyed by `(epoch, validator)` — one entry
/// per beacon-committee member whose proposal SPC's `OutputHigh`
/// committed but the local pool never observed.
pub type BeaconProposalFetch = Fetch<(Epoch, ValidatorId)>;

/// Per-shard beacon fetch state.
///
/// Composed into [`ShardIo`]. Holds the two id-keyed fetches the beacon
/// coordinator drives for this shard.
pub struct BeaconFetchState {
    /// Cross-shard beacon-witness fetch (rotates through source committee).
    pub shard_witness: ShardWitnessFetch,
    /// Missing-proposal fetch (rotates through beacon committee).
    pub beacon_proposal: BeaconProposalFetch,
}

impl BeaconFetchState {
    /// Build beacon fetch state for a freshly hosted shard.
    #[must_use]
    pub fn new(config: &NodeConfig) -> Self {
        Self {
            shard_witness: ShardWitnessFetch::new(
                "shard_witness",
                config.shard_witness_fetch.clone(),
            ),
            beacon_proposal: BeaconProposalFetch::new(
                "beacon_proposal",
                config.beacon_proposal_fetch.clone(),
            ),
        }
    }

    /// True if either beacon fetch has work outstanding (in-flight or
    /// queued). Keeps this shard's `FetchTick` timer alive so deferred ids
    /// eventually retry.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.shard_witness.has_pending() || self.beacon_proposal.has_pending()
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
