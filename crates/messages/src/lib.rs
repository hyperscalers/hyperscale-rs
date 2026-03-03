//! Network messages for the consensus protocol.

pub mod gossip;
pub mod request;
pub mod response;
mod trace_context;

// Re-export commonly used types
pub use gossip::{
    BlockHeaderGossip, BlockVoteGossip, CommittedBlockHeaderGossip, ExecutionCertificateBatch,
    ExecutionVoteBatch, StateProvisionBatch, TransactionCertificateGossip, TransactionGossip,
};
pub use trace_context::TraceContext;
