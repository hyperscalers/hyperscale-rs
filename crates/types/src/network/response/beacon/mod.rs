//! Beacon-chain fetch responses.

mod block;
mod candidate;
mod proposal;
mod shard_witnesses;

pub use block::GetBeaconBlockResponse;
pub use candidate::GetBeaconCandidateResponse;
pub use proposal::GetBeaconProposalResponse;
pub use shard_witnesses::GetShardWitnessesResponse;
