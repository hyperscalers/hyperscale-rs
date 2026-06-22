//! Host-global beacon subsystem.
//!
//! One beacon chain per host. [`sync`] holds the beacon-block catch-up
//! engine binding, the [`BeaconSyncSink`] each driver implements, and the
//! single driving body both the shard loop and the follower pool route
//! through. [`serve`] answers inbound `GetBeaconBlockRequest`s.

pub mod serve;
pub mod sync;

pub use sync::{
    BeaconBlockSync, BeaconSyncSink, beacon_block_sync_config, has_pending, on_admitted,
    on_fetch_failed, on_response, on_tick, start,
};
