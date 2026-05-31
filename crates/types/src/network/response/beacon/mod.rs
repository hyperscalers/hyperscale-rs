//! Beacon-chain fetch responses.

mod proposal;
mod shard_witnesses;

pub use proposal::GetBeaconProposalResponse;
pub use shard_witnesses::GetShardWitnessesResponse;
