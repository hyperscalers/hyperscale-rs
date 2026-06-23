//! Host-global beacon subsystem.
//!
//! One beacon chain per host. [`sync`] holds the beacon-block catch-up
//! engine binding, the [`BeaconSyncSink`] each driver implements, and the
//! single driving body both the shard loop and the follower pool route
//! through. [`commit`] is the per-host beacon-commit dedup; [`proposal_cache`]
//! and [`proposal_serve`] back the beacon-proposal pool's serve path.
//! [`serve`] answers inbound `GetBeaconBlockRequest`s; [`gossip`] registers
//! the beacon gossip handlers. [`fetch`] holds the two per-shard beacon
//! fetches (missing proposals, shard-witness leaves) and their bindings;
//! [`witness_serve`] answers inbound `GetShardWitnessesRequest`s.

pub mod commit;
pub mod fetch;
pub mod gossip;
pub mod proposal_cache;
pub mod proposal_serve;
pub mod serve;
pub mod sync;
pub mod witness_serve;

pub use commit::BeaconCommitCoordinator;
pub use fetch::{BeaconFetchState, BeaconProposalBinding, ShardWitnessBinding};
pub use proposal_cache::BeaconProposalCache;
pub use sync::{
    BeaconBlockSync, BeaconSyncSink, beacon_block_sync_config, has_pending, on_admitted,
    on_fetch_failed, on_response, on_tick, start,
};
