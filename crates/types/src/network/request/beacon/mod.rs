//! Beacon-chain fetch requests.
//!
//! Catch-up traffic where reach matters but latency doesn't —
//! beacon validators pull witnesses lifted by shards they're not a
//! member of via these per-payload requests.

mod shard_witnesses;

pub use shard_witnesses::GetShardWitnessesRequest;
