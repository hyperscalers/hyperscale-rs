//! Network messages for the consensus protocol.

pub mod gossip;
pub mod notification;
pub mod request;
pub mod response;
mod trace_context;

// Re-export commonly used types
pub use gossip::{CommittedBlockHeaderGossip, TransactionGossip};
pub use notification::{
    BlockHeaderNotification, BlockVoteNotification, ExecutionCertificatesNotification,
    ExecutionVotesNotification, ExecutionWaveCertificatesNotification,
    ExecutionWaveVotesNotification, StateProvisionsNotification,
};
pub use trace_context::TraceContext;
