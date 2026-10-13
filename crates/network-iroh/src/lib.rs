//! iroh network transport.
//!
//! Validators reach each other by endpoint identity over QUIC. A relay opens
//! a connection between two hosts behind NAT and coordinates the hole punch;
//! traffic then moves to a direct path, with the relayed path kept as a
//! degraded fallback.

pub mod path;
#[cfg(feature = "test-utils")]
pub mod testing;
