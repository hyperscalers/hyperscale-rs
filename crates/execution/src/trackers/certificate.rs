//! Certificate tracker for cross-shard finalization.
//!
//! Tracks the collection of state certificates from all participating shards
//! during Phase 5 of the cross-shard 2PC protocol.

use hyperscale_types::{
    Hash, ShardGroupId, StateCertificate, TransactionCertificate, TransactionDecision,
};
use std::collections::{BTreeMap, BTreeSet};

/// Tracks certificates for cross-shard finalization.
///
/// After each shard creates a state certificate (aggregated vote), validators
/// collect certificates from all participating shards. Once all certificates
/// are received, a final `TransactionCertificate` can be created.
#[derive(Debug)]
pub struct CertificateTracker {
    /// Transaction hash.
    tx_hash: Hash,
    /// Shards we expect certificates from.
    expected_shards: BTreeSet<ShardGroupId>,
    /// Certificates received per shard.
    certificates: BTreeMap<ShardGroupId, StateCertificate>,
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

    /// Get the transaction hash this tracker is for.
    pub fn tx_hash(&self) -> Hash {
        self.tx_hash
    }

    /// Get the number of certificates collected.
    pub fn certificate_count(&self) -> usize {
        self.certificates.len()
    }

    /// Get the number of expected certificates.
    pub fn expected_count(&self) -> usize {
        self.expected_shards.len()
    }

    /// Add a certificate. Returns true if all certificates are collected.
    pub fn add_certificate(&mut self, cert: StateCertificate) -> bool {
        let shard = cert.shard_group_id;

        if !self.expected_shards.contains(&shard) {
            tracing::debug!(
                tx_hash = ?self.tx_hash,
                shard = shard.0,
                expected = ?self.expected_shards,
                "Certificate from unexpected shard, ignoring"
            );
            return false;
        }

        // Don't overwrite existing certificate
        if self.certificates.contains_key(&shard) {
            tracing::debug!(
                tx_hash = ?self.tx_hash,
                shard = shard.0,
                "Duplicate certificate from shard, ignoring"
            );
            return self.is_complete();
        }

        self.certificates.insert(shard, cert);
        let complete = self.is_complete();
        tracing::debug!(
            tx_hash = ?self.tx_hash,
            shard = shard.0,
            collected = self.certificates.len(),
            expected = self.expected_shards.len(),
            complete = complete,
            "Added certificate from shard"
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
    /// - Certificates have mismatched merkle roots (Byzantine behavior)
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

        // Verify all shards agree on merkle root (zero-allocation iterator approach)
        let mut roots_iter = self.certificates.values().map(|c| c.outputs_merkle_root);
        let first_root = roots_iter.next()?; // Safe: is_complete() guarantees at least one
        if !roots_iter.all(|r| r == first_root) {
            tracing::warn!(
                tx_hash = ?self.tx_hash,
                "Merkle root mismatch across shards - cannot create TX certificate"
            );
            return None;
        }

        tracing::debug!(
            tx_hash = ?self.tx_hash,
            shards = ?self.certificates.keys().collect::<Vec<_>>(),
            "Creating TX certificate - all certificates collected and merkle roots match"
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
    use hyperscale_types::{Signature, SignerBitfield};

    fn make_certificate(tx_hash: Hash, shard: ShardGroupId, merkle_root: Hash) -> StateCertificate {
        StateCertificate {
            transaction_hash: tx_hash,
            shard_group_id: shard,
            read_nodes: vec![],
            state_writes: vec![],
            outputs_merkle_root: merkle_root,
            success: true,
            aggregated_signature: Signature::zero(),
            signers: SignerBitfield::new(4),
            voting_power: 3,
        }
    }

    #[test]
    fn test_certificate_tracker_basic() {
        let tx_hash = Hash::from_bytes(b"test_tx");
        let shard0 = ShardGroupId(0);
        let shard1 = ShardGroupId(1);
        let merkle_root = Hash::from_bytes(b"merkle_root");

        let expected = [shard0, shard1].into_iter().collect();
        let mut tracker = CertificateTracker::new(tx_hash, expected);

        assert!(!tracker.is_complete());

        let cert0 = make_certificate(tx_hash, shard0, merkle_root);
        assert!(!tracker.add_certificate(cert0));

        let cert1 = make_certificate(tx_hash, shard1, merkle_root);
        assert!(tracker.add_certificate(cert1));

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

        tracker.add_certificate(make_certificate(tx_hash, shard0, root_a));
        tracker.add_certificate(make_certificate(tx_hash, shard1, root_b));

        assert!(tracker.is_complete());
        // But can't create certificate due to mismatch
        assert!(tracker.create_tx_certificate().is_none());
    }

    #[test]
    fn test_certificate_tracker_ignores_unknown_shard() {
        let tx_hash = Hash::from_bytes(b"test_tx");
        let shard0 = ShardGroupId(0);
        let merkle_root = Hash::from_bytes(b"merkle_root");

        let expected = [shard0].into_iter().collect();
        let mut tracker = CertificateTracker::new(tx_hash, expected);

        // Certificate from unknown shard
        let unknown_cert = make_certificate(tx_hash, ShardGroupId(99), merkle_root);
        assert!(!tracker.add_certificate(unknown_cert));
        assert!(!tracker.is_complete());
    }

    #[test]
    fn test_certificate_tracker_no_duplicate() {
        let tx_hash = Hash::from_bytes(b"test_tx");
        let shard0 = ShardGroupId(0);
        let merkle_root = Hash::from_bytes(b"merkle_root");

        let expected = [shard0].into_iter().collect();
        let mut tracker = CertificateTracker::new(tx_hash, expected);

        let cert = make_certificate(tx_hash, shard0, merkle_root);
        assert!(tracker.add_certificate(cert.clone()));

        // Duplicate should not change state
        assert_eq!(tracker.certificate_count(), 1);
        tracker.add_certificate(cert);
        assert_eq!(tracker.certificate_count(), 1);
    }
}
