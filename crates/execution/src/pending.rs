//! Pending verification types for async signature verification.
//!
//! These structs track in-flight signature verifications that have been
//! delegated to the runner. When verification completes, the runner sends
//! an event back and we look up the pending state to continue processing.

use hyperscale_types::{BlockHeight, Hash, ShardGroupId, StateCertificate, TransactionCertificate};
use std::collections::HashSet;

/// Tracks a pending provision broadcast waiting for state fetch.
///
/// When starting cross-shard execution, we need to fetch state entries from
/// storage before we can broadcast provisions to target shards.
#[derive(Debug)]
pub struct PendingProvisionBroadcast {
    /// Block height when the transaction was committed.
    pub block_height: BlockHeight,
    /// Unix timestamp (milliseconds) of the block that triggered this provision.
    pub block_timestamp: u64,
    /// Target shards to broadcast to.
    pub target_shards: Vec<ShardGroupId>,
}

/// Tracks a pending state certificate signature verification.
///
/// When we receive a state certificate from another shard, we delegate
/// aggregated signature verification to the runner before accepting it.
///
/// The certificate field is kept for debugging/diagnostics even though
/// the verification result provides the certificate.
#[derive(Debug, Clone)]
pub struct PendingCertificateVerification {
    /// The certificate awaiting verification (stored for diagnostics).
    #[allow(dead_code)]
    pub certificate: StateCertificate,
}

/// Tracks a fetched TransactionCertificate awaiting verification.
///
/// A TransactionCertificate contains multiple StateCertificates (one per shard).
/// We must verify each embedded StateCertificate's signature before using
/// the TransactionCertificate to complete a pending block.
#[derive(Debug, Clone)]
pub struct PendingFetchedCertificateVerification {
    /// The full TransactionCertificate being verified.
    pub certificate: TransactionCertificate,
    /// Block hash this certificate is needed for.
    pub block_hash: Hash,
    /// Shards whose StateCertificates still need verification.
    pub pending_shards: HashSet<ShardGroupId>,
    /// Whether any shard verification has failed.
    pub has_failed: bool,
}

/// Tracks a pending state certificate BLS aggregation.
///
/// When vote quorum is reached, we delegate BLS signature aggregation to
/// the crypto pool. This struct stores the state needed to continue
/// processing when aggregation completes.
#[derive(Debug, Clone)]
pub struct PendingCertificateAggregation {
    /// Shards to broadcast the certificate to.
    pub participating_shards: Vec<ShardGroupId>,
}
