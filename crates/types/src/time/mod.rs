//! Time-domain types for consensus.
//!
//! - [`timestamp`]: typed wall-clocks ([`WeightedTimestamp`], [`ProposerTimestamp`],
//!   [`LocalTimestamp`]) with distinct trust guarantees.
//! - [`range`]: half-open [`TimestampRange`] used as a transaction validity window.
//! - [`timeouts`]: shared `Duration` constants for retention horizons.

pub mod range;
pub mod timeouts;
pub mod timestamp;
