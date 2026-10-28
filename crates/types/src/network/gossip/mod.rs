//! Gossip messages, fanned out one to many.
//!
//! The transport sends each to the audience its scope names: a shard's
//! committee, or every host for a global message.

pub mod beacon;

mod certified_block_header;
mod shard_fork_proof;
mod shard_vote_equivocation;
mod transaction;
mod validator_address;

pub use certified_block_header::CertifiedBlockHeaderGossip;
pub use shard_fork_proof::ShardForkProofGossip;
pub use shard_vote_equivocation::ShardVoteEquivocationGossip;
pub use transaction::{MAX_GOSSIP_TX_BATCH, TransactionGossip};
pub use validator_address::{
    AnnouncedAddresses, ENDPOINT_ID_LEN, MAX_ANNOUNCED_ADDRESS_BYTES, MAX_ANNOUNCED_ADDRESSES,
    ValidatorAddressGossip,
};
