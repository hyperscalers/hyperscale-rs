//! Host-global beacon subsystem.
//!
//! One beacon chain per host. [`sync`] holds the beacon-block catch-up
//! engine binding, the [`BeaconSyncSink`] each driver implements, and the
//! single driving body both the shard loop and the follower pool route
//! through. [`commit`] is the per-host beacon-commit dedup; [`proposal_cache`]
//! and [`proposal_serve`] back the beacon-proposal pool's serve path.
//! [`serve`] answers inbound `GetBeaconBlockRequest`s; [`gossip`] registers
//! the beacon gossip handlers.

pub mod commit;
pub mod gossip;
pub mod proposal_cache;
pub mod proposal_serve;
pub mod serve;
pub mod sync;

pub use commit::BeaconCommitCoordinator;
pub use proposal_cache::BeaconProposalCache;
pub use sync::{
    BeaconBlockSync, BeaconSyncSink, beacon_block_sync_config, has_pending, on_admitted,
    on_fetch_failed, on_response, on_tick, start,
};
