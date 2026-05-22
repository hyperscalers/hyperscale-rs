//! Beacon-chain consensus types.
//!
//! - [`header`]: [`BeaconBlockHeader`] (committee-signed chain link).
//! - [`recovery`]: [`RecoveryRequest`] and [`RecoveryCertificate`] (committee
//!   replacement after stall).

pub mod header;
pub mod recovery;

pub use header::BeaconBlockHeader;
pub use recovery::{RecoveryCertificate, RecoveryRequest, recovery_cert_hash};
