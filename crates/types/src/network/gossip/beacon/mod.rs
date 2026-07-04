//! Beacon-chain gossip wire-types.
//!
//! Broadcast traffic where reach matters more than ms-level latency:
//! finalized [`BeaconBlock`](crate::BeaconBlock) dissemination and
//! per-validator skip attestations.
//!
//! Inner-consensus traffic uses notifications instead — see
//! [`network::notification::beacon`](crate::network::notification::beacon).
//! Shard witnesses don't gossip individually; their accumulator root
//! rides in each shard's
//! [`CertifiedBlockHeader`](crate::CertifiedBlockHeader), and beacon
//! validators fetch witness contents on demand via request/response.

mod beacon_block;
mod candidate;
mod ratify_vote;
mod skip_request;

pub use beacon_block::BeaconBlockGossip;
pub use candidate::BeaconCandidateGossip;
pub use ratify_vote::RatifyVoteGossip;
pub use skip_request::SkipRequestGossip;
