//! Tracker types for cross-shard execution coordination.
//!
//! These trackers manage the state of in-flight cross-shard transactions
//! as they progress through the cross-shard atomic execution protocol.

mod certificate;
mod vote;

pub use certificate::CertificateTracker;
pub use vote::VoteTracker;
