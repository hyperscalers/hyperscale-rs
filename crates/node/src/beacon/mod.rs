//! Host-global beacon subsystem.
//!
//! One beacon chain per host. [`sync`] holds the beacon-block catch-up
//! binding the beacon loop drives. [`proposal_cache`] backs the
//! beacon-proposal serve path and [`candidate_cache`] the ratify-candidate
//! one.
//! [`serve`] answers inbound `GetBeaconBlockRequest`s; [`gossip`] registers
//! the beacon gossip handlers. [`fetch`] holds the beacon fetches
//! (missing proposals, ratify candidates, shard-witness leaves) and their
//! bindings;
//! [`witness_serve`] answers inbound `GetShardWitnessesRequest`s.

mod candidate_cache;
mod fetch;
pub mod gossip;
mod proposal_cache;
pub mod serve;
mod sync;
pub mod witness_serve;

pub use candidate_cache::BeaconCandidateCache;
pub use fetch::{
    BeaconCandidateBinding, BeaconFetchState, BeaconProposalBinding, BeaconReply, ProposalKeys,
    ShardWitnessBinding,
};
pub use proposal_cache::BeaconProposalCache;
pub use sync::{
    BeaconBlockSync, BeaconBlockSyncInput, BeaconBlockSyncOutput, has_pending, resumed_at,
};
