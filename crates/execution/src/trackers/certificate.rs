//! Wave certificate tracker for wave-level finalization.
//!
//! Replaces the per-tx CertificateTracker. Tracks the collection of execution
//! certificates from all participating shards for an entire wave (all txs sharing
//! the same provision dependency set within a block).

use hyperscale_types::{
    ExecutionCertificate, ExecutionOutcome, Hash, ShardGroupId, TransactionDecision,
    WaveCertificate, WaveId,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

/// Tracks execution certificates for wave-level finalization.
///
/// Collects ECs from all participating shards. A single remote shard may
/// contribute multiple ECs (when it committed the wave's txs across multiple
/// blocks), so we track per-tx coverage rather than per-shard.
///
/// Completion = every tx in the wave has all participating shards covered.
///
/// # Ordering
///
/// `tx_hashes` is stored in **block order** (the order in which the transactions
/// appear in the source block). This matches the accumulator / ExecutionVote /
/// ExecutionCertificate ordering convention, so `FinalizedWave.receipts` built
/// from this tracker is aligned 1:1 with the local EC's `tx_outcomes`.
#[derive(Debug)]
pub struct WaveCertificateTracker {
    /// The wave being tracked.
    wave_id: WaveId,
    /// Transaction hashes in this wave, in block order (canonical).
    tx_hashes: Vec<Hash>,
    /// Participating shards for each tx (local + remote).
    participating_shards: HashMap<Hash, BTreeSet<ShardGroupId>>,
    /// Per-tx, which shards have reported.
    covered: HashMap<Hash, BTreeSet<ShardGroupId>>,
    /// Per-tx, whether any shard reported an abort.
    aborted: HashSet<Hash>,
    /// All contributing ECs (held as Arc for cheap sharing).
    execution_certificates: Vec<Arc<ExecutionCertificate>>,
    /// Canonical hashes of ECs already processed (dedup guard).
    /// Prevents duplicate ECs from network re-delivery.
    seen_ec_hashes: HashSet<Hash>,
    /// Per-tx: whether any EC reported a non-success outcome. Built incrementally
    /// during add_execution_certificate to avoid O(txs × ecs × outcomes) in tx_decisions.
    tx_has_failure: HashSet<Hash>,
    /// Height when this tracker was created.
    created_at: u64,
}

impl WaveCertificateTracker {
    /// Create a new tracker for a wave.
    ///
    /// `tx_participating_shards` is a list of `(tx_hash, shards)` pairs in
    /// **block order** — the order is preserved as the canonical tx ordering
    /// for the resulting `FinalizedWave.receipts`. Each entry maps a tx to the
    /// set of shards that participate in its execution (local + remote provision
    /// sources).
    pub fn new(
        wave_id: WaveId,
        tx_participating_shards: Vec<(Hash, BTreeSet<ShardGroupId>)>,
        created_at: u64,
    ) -> Self {
        let tx_hashes: Vec<Hash> = tx_participating_shards.iter().map(|(h, _)| *h).collect();
        let covered: HashMap<Hash, BTreeSet<ShardGroupId>> =
            tx_hashes.iter().map(|h| (*h, BTreeSet::new())).collect();
        let participating_shards: HashMap<Hash, BTreeSet<ShardGroupId>> =
            tx_participating_shards.into_iter().collect();
        Self {
            wave_id,
            tx_hashes,
            participating_shards,
            covered,
            aborted: HashSet::new(),
            execution_certificates: Vec::new(),
            seen_ec_hashes: HashSet::new(),
            tx_has_failure: HashSet::new(),
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
    /// Updates per-tx coverage from the EC's outcomes. Duplicate ECs (same
    /// canonical_hash) are silently ignored to prevent non-deterministic
    /// certificate lists from network re-delivery.
    pub fn add_execution_certificate(&mut self, ec: Arc<ExecutionCertificate>) -> bool {
        let ec_hash = ec.canonical_hash();
        if !self.seen_ec_hashes.insert(ec_hash) {
            return self.is_complete();
        }

        let shard = ec.shard_group_id();

        // Update per-tx coverage and failure tracking
        for outcome in &ec.tx_outcomes {
            if let Some(covered_shards) = self.covered.get_mut(&outcome.tx_hash) {
                covered_shards.insert(shard);
                if outcome.is_aborted() {
                    self.aborted.insert(outcome.tx_hash);
                }
                if !matches!(
                    outcome.outcome,
                    ExecutionOutcome::Executed { success: true, .. }
                ) {
                    self.tx_has_failure.insert(outcome.tx_hash);
                }
            }
        }

        self.execution_certificates.push(ec);

        self.is_complete()
    }

    /// Whether every tx in the wave has all participating shards covered.
    ///
    /// The **local EC** (matching `self.wave_id`) must be present — this is
    /// the downstream invariant for `FinalizedWave::local_ec()`. Without it we
    /// could race-finalize on a remote EC alone when both shards detect a
    /// livelock conflict and our local EC arrives after the remote one.
    ///
    /// Aborted txs are treated as fully covered by remote shards: the abort
    /// decision is terminal and doesn't require remote shard confirmation.
    /// This avoids a deadlock where the remote shard never committed the tx
    /// (e.g. livelock — the tx was only committed on the local shard).
    pub fn is_complete(&self) -> bool {
        // The local EC must be present. It carries the canonical tx list /
        // ordering for downstream consumers and is deterministic (one vote per
        // wave from the local accumulator).
        let has_local_ec = self
            .execution_certificates
            .iter()
            .any(|ec| ec.wave_id == self.wave_id);
        if !has_local_ec {
            return false;
        }

        for tx_hash in &self.tx_hashes {
            // Aborted txs don't need remote EC coverage — abort is terminal.
            if self.aborted.contains(tx_hash) {
                continue;
            }
            let Some(expected) = self.participating_shards.get(tx_hash) else {
                return false;
            };
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

    /// Create a WaveCertificate from collected execution certificates.
    ///
    /// Call only when `is_complete()` returns true.
    ///
    /// The local EC (where `ec.wave_id == self.wave_id`) is always included —
    /// it is the authoritative source for the wave's tx set and canonical ordering,
    /// and is deterministic (the local accumulator emits exactly one vote per wave).
    ///
    /// Remote ECs are included only if they cover at least one non-aborted tx.
    /// ECs covering only aborted txs are excluded because aborted txs don't require
    /// remote confirmation — including them would make the certificate list
    /// non-deterministic (depends on remote EC arrival order/timing).
    ///
    /// ECs are sorted by (shard_group_id, canonical_hash) for deterministic receipt_hash.
    pub fn create_wave_certificate(&mut self) -> WaveCertificate {
        // Remote ECs: include only if they cover at least one non-aborted tx.
        let required_remote_ec_hashes: HashSet<Hash> = self
            .execution_certificates
            .iter()
            .filter(|ec| ec.wave_id != self.wave_id)
            .filter(|ec| {
                ec.tx_outcomes.iter().any(|outcome| {
                    self.participating_shards.contains_key(&outcome.tx_hash)
                        && !self.aborted.contains(&outcome.tx_hash)
                })
            })
            .map(|ec| ec.canonical_hash())
            .collect();

        // Collect: all local ECs + filtered remote ECs.
        let mut ecs: Vec<Arc<ExecutionCertificate>> = self
            .execution_certificates
            .iter()
            .filter(|ec| {
                ec.wave_id == self.wave_id
                    || required_remote_ec_hashes.contains(&ec.canonical_hash())
            })
            .cloned()
            .collect();

        // Sort for deterministic receipt_hash
        ecs.sort_by(|a, b| {
            (&a.shard_group_id(), &a.canonical_hash())
                .cmp(&(&b.shard_group_id(), &b.canonical_hash()))
        });

        WaveCertificate {
            wave_id: self.wave_id.clone(),
            execution_certificates: ecs,
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

    pub fn tx_decisions(&self) -> Vec<(Hash, TransactionDecision)> {
        self.tx_hashes
            .iter()
            .map(|tx_hash| {
                let decision = if self.aborted.contains(tx_hash) {
                    TransactionDecision::Aborted
                } else if self.tx_has_failure.contains(tx_hash) {
                    TransactionDecision::Reject
                } else {
                    TransactionDecision::Accept
                };
                (*tx_hash, decision)
            })
            .collect()
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
                    ExecutionOutcome::Executed {
                        receipt_hash: Hash::from_bytes(b"receipt"),
                        success: true,
                    }
                } else {
                    ExecutionOutcome::Aborted
                },
            })
            .collect();
        // Build the EC's wave_id with the source shard's shard_group_id,
        // since ec.shard_group_id() is derived from wave_id.shard_group_id.
        // Each shard creates its own wave_id reflecting itself as origin.
        let ec_wave_id = WaveId::new(shard, _wave_id.block_height, _wave_id.remote_shards.clone());
        Arc::new(ExecutionCertificate::new(
            ec_wave_id,
            11,
            Hash::from_bytes(b"receipt_root"),
            outcomes,
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        ))
    }

    #[test]
    fn test_single_shard_wave() {
        let wave_id = WaveId::new(ShardGroupId(0), 10, BTreeSet::new());
        let tx1 = Hash::from_bytes(b"tx1");

        let participating = vec![(tx1, BTreeSet::from([ShardGroupId(0)]))];

        let mut tracker = WaveCertificateTracker::new(wave_id.clone(), participating, 10);
        assert!(!tracker.is_complete());

        let ec = make_ec(ShardGroupId(0), &wave_id, &[tx1], true);
        assert!(tracker.add_execution_certificate(ec));
        assert!(tracker.is_complete());

        let wc = tracker.create_wave_certificate();
        assert_eq!(wc.execution_certificates().len(), 1);
    }

    #[test]
    fn test_cross_shard_wave() {
        let wave_id = make_wave_id();
        let tx1 = Hash::from_bytes(b"tx1");
        let tx2 = Hash::from_bytes(b"tx2");

        let both_shards = BTreeSet::from([ShardGroupId(0), ShardGroupId(1)]);
        let participating = vec![(tx1, both_shards.clone()), (tx2, both_shards)];

        let mut tracker = WaveCertificateTracker::new(wave_id.clone(), participating, 10);

        // Local shard EC
        let ec_local = make_ec(ShardGroupId(0), &wave_id, &[tx1, tx2], true);
        assert!(!tracker.add_execution_certificate(ec_local));

        // Remote shard EC
        let ec_remote = make_ec(ShardGroupId(1), &wave_id, &[tx1, tx2], true);
        assert!(tracker.add_execution_certificate(ec_remote));

        let decisions = tracker.tx_decisions();
        assert_eq!(decisions.len(), 2);
        assert!(decisions.iter().all(|d| d.1 == TransactionDecision::Accept));
    }

    #[test]
    fn test_abort_decision() {
        let wave_id = make_wave_id();
        let tx1 = Hash::from_bytes(b"tx1");

        let both_shards = BTreeSet::from([ShardGroupId(0), ShardGroupId(1)]);
        let participating = vec![(tx1, both_shards)];

        let mut tracker = WaveCertificateTracker::new(wave_id.clone(), participating, 10);

        // Local shard says success
        let ec_local = make_ec(ShardGroupId(0), &wave_id, &[tx1], true);
        tracker.add_execution_certificate(ec_local);

        // Remote shard says abort
        let ec_remote = make_ec(ShardGroupId(1), &wave_id, &[tx1], false);
        tracker.add_execution_certificate(ec_remote);

        let decisions = tracker.tx_decisions();
        assert_eq!(decisions[0].1, TransactionDecision::Aborted);
    }

    #[test]
    fn all_aborted_wave_retains_local_ec() {
        // Invariant: a well-formed WaveCertificate always contains the local EC
        // (the one matching wc.wave_id), even when every tx in the wave is aborted.
        // This is required so downstream reconstruction can recover the canonical
        // tx list + ordering from the local EC's tx_outcomes without any source-block
        // lookup.
        let wave_id = make_wave_id();
        let tx1 = Hash::from_bytes(b"tx1");
        let tx2 = Hash::from_bytes(b"tx2");

        let both_shards = BTreeSet::from([ShardGroupId(0), ShardGroupId(1)]);
        let participating = vec![(tx1, both_shards.clone()), (tx2, both_shards)];

        let mut tracker = WaveCertificateTracker::new(wave_id.clone(), participating, 10);

        // Both shards report all txs aborted.
        let ec_local = make_ec(ShardGroupId(0), &wave_id, &[tx1, tx2], false);
        let ec_remote = make_ec(ShardGroupId(1), &wave_id, &[tx1, tx2], false);
        tracker.add_execution_certificate(ec_local);
        tracker.add_execution_certificate(ec_remote);

        let wc = tracker.create_wave_certificate();

        // Local EC must be present — identified by ec.wave_id == wc.wave_id.
        let local_ec = wc
            .execution_certificates()
            .iter()
            .find(|ec| ec.wave_id == wc.wave_id);
        assert!(
            local_ec.is_some(),
            "all-aborted WC must still contain local EC"
        );
        assert_eq!(local_ec.unwrap().tx_outcomes.len(), 2);

        // Remote EC (which only covers aborted txs) is correctly excluded.
        let remote_count = wc
            .execution_certificates()
            .iter()
            .filter(|ec| ec.wave_id != wc.wave_id)
            .count();
        assert_eq!(
            remote_count, 0,
            "remote ECs covering only aborted txs should be excluded"
        );
    }

    #[test]
    fn tx_hashes_preserve_insertion_order() {
        // Tracker must store tx_hashes in the order given by the caller
        // (block order), not sort by hash. This is the canonical ordering
        // invariant for downstream FinalizedWave.receipts.
        let wave_id = make_wave_id();
        // Pick hashes where block order != hash order.
        let tx_a = Hash::from_bytes(b"zzz_first_in_block");
        let tx_b = Hash::from_bytes(b"aaa_second_in_block");
        let tx_c = Hash::from_bytes(b"mmm_third_in_block");

        let shards = BTreeSet::from([ShardGroupId(0)]);
        let participating = vec![
            (tx_a, shards.clone()),
            (tx_b, shards.clone()),
            (tx_c, shards),
        ];

        let tracker = WaveCertificateTracker::new(wave_id, participating, 10);
        assert_eq!(tracker.tx_hashes(), &[tx_a, tx_b, tx_c]);
    }
}
