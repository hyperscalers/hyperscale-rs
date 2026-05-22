//! Beacon-chain consensus types.
//!
//! - [`header`]: [`BeaconBlockHeader`] (committee-signed chain link).

pub mod header;

pub use header::BeaconBlockHeader;
