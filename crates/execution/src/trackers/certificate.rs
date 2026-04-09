//! Wave certificate tracker for wave-level finalization.
//!
//! Replaces the per-tx CertificateTracker. Tracks the collection of execution
//! certificates from all participating shards for an entire wave (all txs sharing
//! the same provision dependency set within a block).

use hyperscale_types::{
    ExecutionCertificate, Hash, ShardAttestation, ShardGroupId, TransactionDecision, TxDecision,
    TxExecutionOutcome, WaveCertificate, WaveId,
};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

/// Tracks execution certificates for wave-level finalization.
///
/// Collects ShardAttestations from ECs. A single remote shard may contribute
/// multiple ECs (when it committed the wave's txs across multiple blocks),
/// so we track per-tx coverage rather than per-shard.
///
/// Completion = every tx in the wave has all participating shards covered.
#[derive(Debug)]
pub struct WaveCertificateTracker {
    /// The wave being tracked.
    wave_id: WaveId,
    /// Transaction hashes in this wave (from accumulator).
    tx_hashes: Vec<Hash>,
    /// Participating shards for each tx (local + remote).
    participating_shards: BTreeMap<Hash, BTreeSet<ShardGroupId>>,
    /// Per-tx, which shards have reported.
    covered: BTreeMap<Hash, BTreeSet<ShardGroupId>>,
    /// Per-tx, whether any shard reported an abort.
    aborted: BTreeSet<Hash>,
    /// All contributing ECs (held as Arc for cheap sharing).
    execution_certificates: Vec<Arc<ExecutionCertificate>>,
    /// ShardAttestations built from ECs (for WaveCertificate construction).
    attestations: Vec<ShardAttestation>,
    /// Canonical hashes of ECs already processed (dedup guard).
    /// Prevents duplicate attestations from network re-delivery.
    seen_ec_hashes: HashSet<Hash>,
    /// Height when this tracker was created.
    created_at: u64,
}

impl WaveCertificateTracker {
    /// Create a new tracker for a wave.
    ///
    /// `tx_participating_shards` maps each tx_hash to the set of shards that
    /// participate in its execution (local shard + remote provision sources).
    pub fn new(
        wave_id: WaveId,
        tx_participating_shards: BTreeMap<Hash, BTreeSet<ShardGroupId>>,
        created_at: u64,
    ) -> Self {
        let tx_hashes: Vec<Hash> = tx_participating_shards.keys().copied().collect();
        let covered: BTreeMap<Hash, BTreeSet<ShardGroupId>> =
            tx_hashes.iter().map(|h| (*h, BTreeSet::new())).collect();
        Self {
            wave_id,
            tx_hashes,
            participating_shards: tx_participating_shards,
            covered,
            aborted: BTreeSet::new(),
            execution_certificates: Vec::new(),
            attestations: Vec::new(),
            seen_ec_hashes: HashSet::new(),
            created_at,
        }
    }

    pub fn wave_id(&self) -> &WaveId {
        &self.wave_id
    }

    pub fn tx_hashes(&self) -> &[Hash] {
        &self.tx_hashes
    }

    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Feed an EC into the tracker. Returns true if the wave is now complete.
    ///
    /// Builds a ShardAttestation from the EC and updates per-tx coverage.
    /// Duplicate ECs (same canonical_hash) are silently ignored to prevent
    /// non-deterministic attestation lists from network re-delivery.
    pub fn add_execution_certificate(&mut self, ec: Arc<ExecutionCertificate>) -> bool {
        let ec_hash = ec.canonical_hash();
        if !self.seen_ec_hashes.insert(ec_hash) {
            // Already processed this EC — skip to avoid duplicate attestations.
            return self.is_complete();
        }

        let shard = ec.shard_group_id();

        // Build attestation from EC
        let attestation = ShardAttestation {
            shard_group_id: shard,
            ec_hash: ec.canonical_hash(),
            vote_height: ec.vote_height,
            global_receipt_root: ec.global_receipt_root,
            aggregated_signature: ec.aggregated_signature,
            signers: ec.signers.clone(),
        };

        // Update per-tx coverage
        for outcome in &ec.tx_outcomes {
            if let Some(covered_shards) = self.covered.get_mut(&outcome.tx_hash) {
                covered_shards.insert(shard);
                if outcome.is_aborted() {
                    self.aborted.insert(outcome.tx_hash);
                }
            }
            // Outcomes for unknown tx_hashes are silently ignored — they may
            // belong to a different wave on the remote shard.
        }

        self.attestations.push(attestation);
        self.execution_certificates.push(ec);

        self.is_complete()
    }

    /// Whether every tx in the wave has all participating shards covered.
    ///
    /// Aborted txs are treated as fully covered: the local shard's abort
    /// decision is terminal and doesn't require remote shard confirmation.
    /// This avoids a deadlock where the remote shard never committed the tx
    /// (e.g. livelock — the tx was only committed on the local shard).
    pub fn is_complete(&self) -> bool {
        for (tx_hash, expected) in &self.participating_shards {
            // Aborted txs don't need remote EC coverage — abort is terminal.
            if self.aborted.contains(tx_hash) {
                continue;
            }
            if let Some(covered) = self.covered.get(tx_hash) {
                if !expected.is_subset(covered) {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }

    /// Create a WaveCertificate from collected attestations.
    ///
    /// Call only when `is_complete()` returns true.
    ///
    /// Only includes attestations from ECs that cover at least one non-aborted tx
    /// in this wave. ECs that only cover aborted txs are excluded — since aborted
    /// txs don't require remote confirmation, including those ECs would make the
    /// attestation list non-deterministic (depends on EC arrival order/timing).
    ///
    /// Attestations are sorted by (shard_group_id, ec_hash) for deterministic receipt_hash.
    pub fn create_wave_certificate(&mut self) -> WaveCertificate {
        // Build set of ec_hashes that cover at least one non-aborted tx in this wave.
        let required_ec_hashes: HashSet<Hash> = self
            .execution_certificates
            .iter()
            .filter(|ec| {
                ec.tx_outcomes.iter().any(|outcome| {
                    // Must be a tx in this wave AND not aborted
                    self.participating_shards.contains_key(&outcome.tx_hash)
                        && !self.aborted.contains(&outcome.tx_hash)
                })
            })
            .map(|ec| ec.canonical_hash())
            .collect();

        // Filter attestations to only required ECs
        let mut attestations: Vec<ShardAttestation> = self
            .attestations
            .iter()
            .filter(|att| required_ec_hashes.contains(&att.ec_hash))
            .cloned()
            .collect();

        // Sort for deterministic receipt_hash
        attestations
            .sort_by(|a, b| (&a.shard_group_id, &a.ec_hash).cmp(&(&b.shard_group_id, &b.ec_hash)));

        WaveCertificate {
            wave_id: self.wave_id.clone(),
            attestations,
        }
    }

    /// Derive per-tx decisions from the collected ECs.
    ///
    /// Decision priority: Aborted > Reject > Accept (same as old CertificateTracker).
    /// Only ECs that actually contain an outcome for a given tx are considered —
    /// a remote shard may produce multiple ECs (D8), and each only covers a subset.
    /// Check if a specific transaction was aborted.
    pub fn is_tx_aborted(&self, tx_hash: &Hash) -> bool {
        self.aborted.contains(tx_hash)
    }

    pub fn tx_decisions(&self) -> Vec<TxDecision> {
        self.tx_hashes
            .iter()
            .map(|tx_hash| {
                let decision = if self.aborted.contains(tx_hash) {
                    TransactionDecision::Aborted
                } else {
                    // Only check ECs that contain an outcome for this tx.
                    // A remote shard may split the wave's txs across multiple
                    // blocks → multiple ECs, each covering a subset of txs.
                    let all_succeeded = self
                        .execution_certificates
                        .iter()
                        .filter_map(|ec| ec.tx_outcomes.iter().find(|o| o.tx_hash == *tx_hash))
                        .all(|o| {
                            matches!(
                                o.outcome,
                                TxExecutionOutcome::Executed { success: true, .. }
                            )
                        });
                    if all_succeeded {
                        TransactionDecision::Accept
                    } else {
                        TransactionDecision::Reject
                    }
                };
                TxDecision {
                    tx_hash: *tx_hash,
                    decision,
                }
            })
            .collect()
    }

    /// Take the collected execution certificates (for FinalizedWave).
    pub fn take_execution_certificates(&mut self) -> Vec<Arc<ExecutionCertificate>> {
        std::mem::take(&mut self.execution_certificates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{Bls12381G2Signature, SignerBitfield, TxOutcome, WaveId};
    use std::collections::BTreeSet;

    fn make_wave_id() -> WaveId {
        WaveId::new(ShardGroupId(0), 10, BTreeSet::from([ShardGroupId(1)]))
    }

    fn make_ec(
        shard: ShardGroupId,
        _wave_id: &WaveId,
        tx_hashes: &[Hash],
        success: bool,
    ) -> Arc<ExecutionCertificate> {
        let outcomes: Vec<TxOutcome> = tx_hashes
            .iter()
            .map(|h| TxOutcome {
                tx_hash: *h,
                outcome: if success {
                    TxExecutionOutcome::Executed {
                        receipt_hash: Hash::from_bytes(b"receipt"),
                        success: true,
                        write_nodes: vec![],
                    }
                } else {
                    TxExecutionOutcome::Aborted
                },
            })
            .collect();
        // Build the EC's wave_id with the source shard's shard_group_id,
        // since ec.shard_group_id() is derived from wave_id.shard_group_id.
        // Each shard creates its own wave_id reflecting itself as origin.
        let ec_wave_id = WaveId::new(shard, _wave_id.block_height, _wave_id.remote_shards.clone());
        Arc::new(ExecutionCertificate {
            wave_id: ec_wave_id,
            vote_height: 11,
            global_receipt_root: Hash::from_bytes(b"receipt_root"),
            tx_outcomes: outcomes,
            aggregated_signature: Bls12381G2Signature([0u8; 96]),
            signers: SignerBitfield::new(4),
        })
    }

    #[test]
    fn test_single_shard_wave() {
        let wave_id = WaveId::new(ShardGroupId(0), 10, BTreeSet::new());
        let tx1 = Hash::from_bytes(b"tx1");

        let mut participating = BTreeMap::new();
        participating.insert(tx1, BTreeSet::from([ShardGroupId(0)]));

        let mut tracker = WaveCertificateTracker::new(wave_id.clone(), participating, 10);
        assert!(!tracker.is_complete());

        let ec = make_ec(ShardGroupId(0), &wave_id, &[tx1], true);
        assert!(tracker.add_execution_certificate(ec));
        assert!(tracker.is_complete());

        let wc = tracker.create_wave_certificate();
        assert_eq!(wc.attestations().len(), 1);
    }

    #[test]
    fn test_cross_shard_wave() {
        let wave_id = make_wave_id();
        let tx1 = Hash::from_bytes(b"tx1");
        let tx2 = Hash::from_bytes(b"tx2");

        let both_shards = BTreeSet::from([ShardGroupId(0), ShardGroupId(1)]);
        let mut participating = BTreeMap::new();
        participating.insert(tx1, both_shards.clone());
        participating.insert(tx2, both_shards);

        let mut tracker = WaveCertificateTracker::new(wave_id.clone(), participating, 10);

        // Local shard EC
        let ec_local = make_ec(ShardGroupId(0), &wave_id, &[tx1, tx2], true);
        assert!(!tracker.add_execution_certificate(ec_local));

        // Remote shard EC
        let ec_remote = make_ec(ShardGroupId(1), &wave_id, &[tx1, tx2], true);
        assert!(tracker.add_execution_certificate(ec_remote));

        let decisions = tracker.tx_decisions();
        assert_eq!(decisions.len(), 2);
        assert!(decisions
            .iter()
            .all(|d| d.decision == TransactionDecision::Accept));
    }

    #[test]
    fn test_abort_decision() {
        let wave_id = make_wave_id();
        let tx1 = Hash::from_bytes(b"tx1");

        let both_shards = BTreeSet::from([ShardGroupId(0), ShardGroupId(1)]);
        let mut participating = BTreeMap::new();
        participating.insert(tx1, both_shards);

        let mut tracker = WaveCertificateTracker::new(wave_id.clone(), participating, 10);

        // Local shard says success
        let ec_local = make_ec(ShardGroupId(0), &wave_id, &[tx1], true);
        tracker.add_execution_certificate(ec_local);

        // Remote shard says abort
        let ec_remote = make_ec(ShardGroupId(1), &wave_id, &[tx1], false);
        tracker.add_execution_certificate(ec_remote);

        let decisions = tracker.tx_decisions();
        assert_eq!(decisions[0].decision, TransactionDecision::Aborted);
    }
}
