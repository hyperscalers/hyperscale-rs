//! Gossip messages broadcast via pubsub.
//!
//! These messages use gossipsub for one-to-many broadcast and are
//! forwarded by the mesh to all subscribed peers.

pub mod beacon;

mod certified_block_header;
mod shard_fork_proof;
mod shard_vote_equivocation;
mod transaction;
mod validator_address;

pub use certified_block_header::CertifiedBlockHeaderGossip;
pub use shard_fork_proof::ShardForkProofGossip;
pub use shard_vote_equivocation::ShardVoteEquivocationGossip;
pub use transaction::TransactionGossip;
pub use validator_address::{
    MAX_ANNOUNCED_ADDRESS_BYTES, MAX_ANNOUNCED_ADDRESSES, MAX_ANNOUNCED_PEER_ID_BYTES,
    ValidatorAddressGossip,
};
