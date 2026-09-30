//! Host-global beacon subsystem.
//!
//! One beacon chain per host. [`sync`] holds the beacon-block catch-up
//! engine binding, the [`BeaconSyncSink`] each driver implements, and the
//! single driving body both the shard loop and the follower pool route
//! through. [`commit`] is the per-host beacon-commit dedup; [`proposal_cache`]
//! backs the beacon-proposal serve path and [`candidate_cache`] the
//! ratify-candidate one.
//! [`serve`] answers inbound `GetBeaconBlockRequest`s; [`gossip`] registers
//! the beacon gossip handlers. [`fetch`] holds the two per-shard beacon
//! fetches (missing proposals, shard-witness leaves) and their bindings;
//! [`witness_serve`] answers inbound `GetShardWitnessesRequest`s.

mod candidate_cache;
mod commit;
mod fetch;
pub mod gossip;
mod proposal_cache;
pub mod serve;
mod sync;
pub mod witness_serve;

pub use candidate_cache::BeaconCandidateCache;
pub use commit::BeaconCommitCoordinator;
pub use fetch::{
    BeaconCandidateBinding, BeaconFetchState, BeaconProposalBinding, ShardWitnessBinding,
};
pub use proposal_cache::BeaconProposalCache;
pub use sync::{
    BeaconBlockSync, BeaconSyncSink, beacon_block_sync_config, has_pending, on_admitted,
    on_fetch_failed, on_response, on_tick, start,
};
