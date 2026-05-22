//! Time-domain types for consensus.
//!
//! - [`timestamp`]: typed wall-clocks ([`WeightedTimestamp`], [`ProposerTimestamp`],
//!   [`LocalTimestamp`]) with distinct trust guarantees.
//! - [`range`]: half-open [`TimestampRange`] used as a transaction validity window.
//! - [`timeouts`]: protocol `Duration` constants — retention windows and
//!   liveness timers that every validator must enforce identically.
//! - [`limits`]: hard caps applied at admission time on peer-supplied
//!   timestamps.

pub mod limits;
pub mod range;
pub mod timeouts;
pub mod timestamp;
