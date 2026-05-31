//! Beacon-chain fetch requests.
//!
//! Catch-up traffic where reach matters but latency doesn't —
//! beacon validators pull witnesses lifted by shards they're not a
//! member of, or pull a committee member's missed `BeaconProposal`,
//! via these per-payload requests.

mod proposal;
mod shard_witnesses;

pub use proposal::GetBeaconProposalRequest;
pub use shard_witnesses::GetShardWitnessesRequest;
