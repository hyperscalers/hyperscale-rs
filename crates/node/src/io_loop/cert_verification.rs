//! Certificate signature verification tracking.
//!
//! When a `TransactionCertificate` is received from a peer, each embedded
//! `ExecutionCertificate` BLS signature is verified before persisting to
//! prevent malicious peers from filling storage with invalid certificates.

use super::IoLoop;
use hyperscale_core::{NodeInput, ProtocolEvent, StateMachine};
use hyperscale_dispatch::Dispatch;
use hyperscale_metrics as metrics;
use hyperscale_network::Network;
use hyperscale_storage::{CommitStore, ConsensusStore, SubstateStore};
use hyperscale_types::{Hash, ShardGroupId, TransactionCertificate};
use std::collections::HashSet;
use std::sync::Arc;
use tracing::warn;

impl<S, N, D> IoLoop<S, N, D>
where
    S: CommitStore + SubstateStore + ConsensusStore + Send + Sync + 'static,
    N: Network,
    D: Dispatch + 'static,
{
    /// Handle a received TransactionCertificate.
    ///
    /// Verifies each embedded ExecutionCertificate's BLS signature before persisting
    /// to prevent malicious peers from filling storage with invalid certificates.
    pub(super) fn handle_received_certificate(&mut self, certificate: TransactionCertificate) {
        let tx_hash = certificate.transaction_hash;

        // Fast path: skip if we built this certificate locally (O(1) cache check).
        if self.cert_cache.get(&tx_hash).is_some() {
            return;
        }

        // Skip if already in verification pipeline.
        if self.pending_cert_verifications.contains_key(&tx_hash) {
            return;
        }

        // Skip if already persisted in storage.
        if self.storage.get_certificate(&tx_hash).is_some() {
            return;
        }

        // Collect shards that need verification.
        let pending_shards: HashSet<ShardGroupId> =
            certificate.shard_proofs.keys().copied().collect();

        let certificate = Arc::new(certificate);

        if pending_shards.is_empty() {
            // Empty certificate (no shard proofs) - persist directly.
            self.persist_and_notify_verified_certificate(certificate);
            return;
        }

        let now = self.state.now();

        // Track pending verification.
        self.pending_cert_verifications.insert(
            tx_hash,
            super::PendingCertificateVerification {
                certificate: Arc::clone(&certificate),
                pending_shards,
                failed: false,
                created_at: now,
            },
        );

        // Dispatch BLS signature verification for each shard proof.
        for (shard_id, execution_cert) in &certificate.shard_proofs {
            let committee = self.topology.committee_for_shard(*shard_id);
            let public_keys: Vec<hyperscale_types::Bls12381G1PublicKey> = committee
                .iter()
                .filter_map(|&vid| self.topology.public_key(vid))
                .collect();

            if public_keys.len() != committee.len() {
                warn!(
                    tx_hash = ?tx_hash,
                    shard = shard_id.0,
                    "Could not resolve all public keys for received certificate"
                );
                if let Some(pending) = self.pending_cert_verifications.get_mut(&tx_hash) {
                    pending.failed = true;
                    pending.pending_shards.remove(shard_id);
                    if pending.pending_shards.is_empty() {
                        self.pending_cert_verifications.remove(&tx_hash);
                    }
                }
                continue;
            }

            let es = self.event_sender.clone();
            let shard = *shard_id;
            let cert = execution_cert.clone();

            self.dispatch.spawn_crypto(move || {
                let start = std::time::Instant::now();
                let valid = hyperscale_execution::handlers::verify_execution_certificate_signature(
                    &cert,
                    &public_keys,
                );
                metrics::record_signature_verification_latency(
                    "bls_execution_cert",
                    start.elapsed().as_secs_f64(),
                );
                if !valid {
                    metrics::record_signature_verification_failure();
                }
                let _ = es.send(NodeInput::CertificateSignatureVerified {
                    tx_hash,
                    shard,
                    valid,
                });
            });
        }
    }

    /// Handle a certificate verification result from the crypto pool.
    pub(super) fn handle_cert_verification_result(
        &mut self,
        tx_hash: Hash,
        shard: ShardGroupId,
        valid: bool,
    ) {
        if let Some(pending) = self.pending_cert_verifications.get_mut(&tx_hash) {
            if !valid {
                pending.failed = true;
                warn!(
                    tx_hash = ?tx_hash,
                    shard = shard.0,
                    "Certificate signature verification failed"
                );
            }
            pending.pending_shards.remove(&shard);

            if pending.pending_shards.is_empty() {
                let pending = self.pending_cert_verifications.remove(&tx_hash).unwrap();

                if !pending.failed {
                    self.persist_and_notify_verified_certificate(pending.certificate);
                }
            }
        }
    }

    /// Persist a verified certificate and notify the state machine.
    pub(super) fn persist_and_notify_verified_certificate(
        &mut self,
        certificate: Arc<TransactionCertificate>,
    ) {
        let tx_hash = certificate.transaction_hash;

        // Populate cert cache.
        self.cert_cache.insert(tx_hash, Arc::clone(&certificate));

        // Persist to storage.
        self.storage.store_certificate(&certificate);

        // Feed TransactionCertificateVerified directly to state machine.
        self.feed_event(ProtocolEvent::TransactionCertificateVerified { certificate });
    }
}
