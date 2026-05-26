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
//! [`CommittedBlockHeader`](crate::CommittedBlockHeader), and beacon
//! validators fetch witness contents on demand via request/response.

mod beacon_block;
mod skip_cert;
mod skip_request;

pub use beacon_block::BeaconBlockGossip;
pub use skip_cert::SkipCertGossip;
pub use skip_request::SkipRequestGossip;
