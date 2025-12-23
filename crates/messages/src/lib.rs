//! Network messages for the consensus protocol.

pub mod gossip;
pub mod request;
pub mod response;
pub mod trace_context;

// Re-export commonly used types
pub use gossip::{
    BlockHeaderGossip, BlockVoteGossip, StateCertificateBatch, StateProvisionBatch, StateVoteBatch,
    TransactionCertificateGossip, TransactionGossip,
};
pub use trace_context::TraceContext;
