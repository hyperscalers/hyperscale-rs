//! Certificate tracker for cross-shard finalization.
//!
//! Tracks the collection of execution certificates from all participating shards
//! during Phase 5 of the cross-shard atomic execution protocol.

use hyperscale_types::{
    Hash, ShardExecutionProof, ShardGroupId, TransactionCertificate, TransactionDecision,
};
use std::collections::{BTreeMap, BTreeSet};
use tracing::instrument;

/// Tracks certificates for cross-shard finalization.
///
/// After each shard creates an execution certificate (aggregated vote), validators
/// collect certificates from all participating shards. Once all certificates
/// are received, a final `TransactionCertificate` can be created.
#[derive(Debug)]
pub struct CertificateTracker {
    /// Transaction hash.
    tx_hash: Hash,
    /// Shards we expect certificates from.
    expected_shards: BTreeSet<ShardGroupId>,
    /// Proofs received per shard.
    certificates: BTreeMap<ShardGroupId, ShardExecutionProof>,
}

impl CertificateTracker {
    /// Create a new certificate tracker.
    ///
    /// # Arguments
    ///
    /// * `tx_hash` - The transaction being tracked
    /// * `expected_shards` - Set of shards we need certificates from
    pub fn new(tx_hash: Hash, expected_shards: BTreeSet<ShardGroupId>) -> Self {
        Self {
            tx_hash,
            expected_shards,
            certificates: BTreeMap::new(),
        }
    }

    /// Get the number of certificates collected.
    pub fn certificate_count(&self) -> usize {
        self.certificates.len()
    }

    /// Get the number of expected certificates.
    pub fn expected_count(&self) -> usize {
        self.expected_shards.len()
    }

    /// Add a proof for a shard. Returns true if all proofs are collected.
    #[instrument(level = "debug", skip(self, proof), fields(
        tx_hash = %self.tx_hash,
        shard = shard.0,
        collected = self.certificates.len(),
        expected = self.expected_shards.len(),
    ))]
    pub fn add_proof(&mut self, shard: ShardGroupId, proof: ShardExecutionProof) -> bool {
        if !self.expected_shards.contains(&shard) {
            tracing::debug!(
                tx_hash = ?self.tx_hash,
                shard = shard.0,
                expected = ?self.expected_shards,
                "Proof from unexpected shard, ignoring"
            );
            return false;
        }

        // Don't overwrite existing proof
        if self.certificates.contains_key(&shard) {
            tracing::debug!(
                tx_hash = ?self.tx_hash,
                shard = shard.0,
                "Duplicate proof from shard, ignoring"
            );
            return self.is_complete();
        }

        self.certificates.insert(shard, proof);
        let complete = self.is_complete();
        tracing::debug!(
            tx_hash = ?self.tx_hash,
            shard = shard.0,
            collected = self.certificates.len(),
            expected = self.expected_shards.len(),
            complete = complete,
            "Added proof from shard"
        );
        complete
    }

    /// Check if we have all expected certificates.
    pub fn is_complete(&self) -> bool {
        self.certificates.len() == self.expected_shards.len()
    }

    /// Create a `TransactionCertificate` from collected certificates.
    ///
    /// Takes ownership of collected certificates to avoid cloning.
    ///
    /// Returns `None` if:
    /// - Not all certificates have been collected
    /// - Certificates have mismatched receipt hashes (Byzantine behavior)
    #[instrument(level = "debug", skip(self), fields(
        tx_hash = %self.tx_hash,
        shard_count = self.certificates.len(),
    ))]
    pub fn create_tx_certificate(&mut self) -> Option<TransactionCertificate> {
        if !self.is_complete() {
            tracing::debug!(
                tx_hash = ?self.tx_hash,
                collected = self.certificates.len(),
                expected = self.expected_shards.len(),
                "Cannot create TX certificate - not all certificates collected"
            );
            return None;
        }

        // Verify all shards agree on receipt hash
        let per_shard: Vec<_> = self
            .certificates
            .iter()
            .map(|(s, c)| (*s, c.receipt_hash))
            .collect();
        let first_hash = per_shard[0].1;
        if !per_shard.iter().all(|(_, h)| *h == first_hash) {
            tracing::warn!(
                tx_hash = ?self.tx_hash,
                per_shard = ?per_shard,
                "Receipt hash mismatch across shards - cannot create TX certificate"
            );
            return None;
        }

        tracing::debug!(
            tx_hash = ?self.tx_hash,
            shards = ?self.certificates.keys().collect::<Vec<_>>(),
            "Creating TX certificate - all certificates collected and receipt hashes match"
        );

        // Determine decision first (before moving certificates)
        let all_succeeded = self.certificates.values().all(|c| c.success);
        let decision = if all_succeeded {
            TransactionDecision::Accept
        } else {
            TransactionDecision::Reject
        };

        // Take ownership of certificates directly (no wrapping, no cloning!)
        let shard_proofs = std::mem::take(&mut self.certificates);

        Some(TransactionCertificate {
            transaction_hash: self.tx_hash,
            decision,
            shard_proofs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proof(receipt_hash: Hash) -> ShardExecutionProof {
        ShardExecutionProof {
            receipt_hash,
            success: true,
            write_nodes: vec![],
        }
    }

    #[test]
    fn test_certificate_tracker_basic() {
        let tx_hash = Hash::from_bytes(b"test_tx");
        let shard0 = ShardGroupId(0);
        let shard1 = ShardGroupId(1);
        let commitment = Hash::from_bytes(b"commitment");

        let expected = [shard0, shard1].into_iter().collect();
        let mut tracker = CertificateTracker::new(tx_hash, expected);

        assert!(!tracker.is_complete());

        assert!(!tracker.add_proof(shard0, make_proof(commitment)));
        assert!(tracker.add_proof(shard1, make_proof(commitment)));

        assert!(tracker.is_complete());

        let tx_cert = tracker.create_tx_certificate();
        assert!(tx_cert.is_some());
        let tx_cert = tx_cert.unwrap();
        assert_eq!(tx_cert.transaction_hash, tx_hash);
        assert!(tx_cert.is_accepted());
        assert_eq!(tx_cert.shard_count(), 2);
    }

    #[test]
    fn test_certificate_tracker_merkle_mismatch() {
        let tx_hash = Hash::from_bytes(b"test_tx");
        let shard0 = ShardGroupId(0);
        let shard1 = ShardGroupId(1);
        let root_a = Hash::from_bytes(b"root_a");
        let root_b = Hash::from_bytes(b"root_b");

        let expected = [shard0, shard1].into_iter().collect();
        let mut tracker = CertificateTracker::new(tx_hash, expected);

        tracker.add_proof(shard0, make_proof(root_a));
        tracker.add_proof(shard1, make_proof(root_b));

        assert!(tracker.is_complete());
        // But can't create certificate due to mismatch
        assert!(tracker.create_tx_certificate().is_none());
    }

    #[test]
    fn test_certificate_tracker_ignores_unknown_shard() {
        let tx_hash = Hash::from_bytes(b"test_tx");
        let shard0 = ShardGroupId(0);
        let commitment = Hash::from_bytes(b"commitment");

        let expected = [shard0].into_iter().collect();
        let mut tracker = CertificateTracker::new(tx_hash, expected);

        // Proof from unknown shard
        assert!(!tracker.add_proof(ShardGroupId(99), make_proof(commitment)));
        assert!(!tracker.is_complete());
    }

    #[test]
    fn test_certificate_tracker_no_duplicate() {
        let tx_hash = Hash::from_bytes(b"test_tx");
        let shard0 = ShardGroupId(0);
        let commitment = Hash::from_bytes(b"commitment");

        let expected = [shard0].into_iter().collect();
        let mut tracker = CertificateTracker::new(tx_hash, expected);

        assert!(tracker.add_proof(shard0, make_proof(commitment)));

        // Duplicate should not change state
        assert_eq!(tracker.certificate_count(), 1);
        tracker.add_proof(shard0, make_proof(commitment));
        assert_eq!(tracker.certificate_count(), 1);
    }
}
