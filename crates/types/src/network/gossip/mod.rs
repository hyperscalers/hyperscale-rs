//! Gossip messages broadcast via pubsub.
//!
//! These messages use gossipsub for one-to-many broadcast and are
//! forwarded by the mesh to all subscribed peers.

pub mod beacon;

mod certified_block_header;
mod transaction;

pub use certified_block_header::CertifiedBlockHeaderGossip;
pub use transaction::TransactionGossip;
