//! [`FinalizedWave`] — wave certificate plus locally-executed receipts.
//!
//! [`FinalizedWave`] is the raw wire form. Its verified form is
//! `Verified<FinalizedWave>`; predicate at
//! [`impl Verify<&FinalizedWaveContext<'_>>`](Verify::verify) below.

use std::collections::HashSet;
use std::sync::Arc;

use sbor::prelude::*;
use thiserror::Error;

use crate::{
    Bls12381G1PublicKey, BoundedVec, ConsensusReceipt, ExecutionCertificate,
    ExecutionCertificateContext, ExecutionCertificateVerifyError, ExecutionOutcome,
    GlobalReceiptHash, MAX_TXS_PER_BLOCK, NetworkDefinition, StoredReceipt, TransactionDecision,
    TxHash, TxOutcome, Verified, Verify, WaveCertificate, WaveId,
};

/// A finalized wave — all participating shards have reported, `WaveCertificate` created.
///
/// Holds the wave certificate (which contains the execution certificates) plus the
/// stored receipts produced by local execution. Receipts are written atomically
/// with the block at commit time (not fire-and-forget).
///
/// # Derived views
///
/// The wave's canonical tx list, ordering, and per-tx decisions are all **derived**
/// from the `WaveCertificate`, not stored alongside it. See:
/// - [`FinalizedWave::local_ec`] — the authoritative EC (where `ec.wave_id() == wc.wave_id`)
/// - [`FinalizedWave::tx_hashes`] — iterator over the wave's tx hashes in block order
/// - [`FinalizedWave::tx_decisions`] — aggregated (Aborted > Reject > Accept) per tx
///
/// `receipts` contains only txs that actually executed (sparse subset of
/// `tx_hashes()`, same block order). Aborted txs produce no receipt.
///
/// Shared via `Arc` across the system — flows from execution state through
/// pending blocks, actions, and into the commit path.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct FinalizedWave {
    certificate: Arc<WaveCertificate>,
    receipts: BoundedVec<StoredReceipt, MAX_TXS_PER_BLOCK>,
}

/// Reason a `FinalizedWave`'s receipts don't agree with its own EC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptValidationError {
    /// The `WaveCertificate` has no EC whose `wave_id == wc.wave_id`.
    /// Every committed WC carries exactly one such "local" EC per the
    /// `create_wave_certificate` invariant; this indicates a malformed
    /// or tampered certificate.
    MissingLocalEc,
    /// A non-aborted `tx_outcome` has no corresponding receipt.
    MissingReceipt {
        /// Hash of the tx whose receipt is missing.
        tx_hash: TxHash,
    },
    /// A receipt's `tx_hash` doesn't match the expected position in
    /// canonical order.
    TxHashMismatch {
        /// `tx_hash` the canonical order required at this position.
        expected: TxHash,
        /// `tx_hash` the receipt actually carried.
        actual: TxHash,
    },
    /// EC attested the tx as `Succeeded` but the stored receipt is `Failed`.
    UnexpectedFailure {
        /// Hash of the tx.
        tx_hash: TxHash,
    },
    /// EC attested the tx as `Failed` but the stored receipt is `Succeeded`.
    UnexpectedSuccess {
        /// Hash of the tx.
        tx_hash: TxHash,
    },
    /// EC's `receipt_hash` for a `Succeeded` tx disagrees with the stored
    /// receipt's `receipt_hash`. Catches divergent state for the same tx
    /// across validators that both succeeded but produced different writes.
    ReceiptHashMismatch {
        /// Hash of the tx.
        tx_hash: TxHash,
        /// `receipt_hash` attested by the EC.
        expected: GlobalReceiptHash,
        /// `receipt_hash` carried by the stored receipt.
        actual: GlobalReceiptHash,
    },
    /// More receipts than non-aborted outcomes.
    ExtraReceipt {
        /// Hash of the surplus receipt's tx.
        tx_hash: TxHash,
    },
}

impl FinalizedWave {
    /// The wave certificate carrying per-shard ECs and tx outcomes.
    #[must_use]
    pub const fn certificate(&self) -> &Arc<WaveCertificate> {
        &self.certificate
    }

    /// Stored receipts for txs that executed. Aborted txs are absent —
    /// `receipts.len() <= tx_count()`. Preserves canonical block order.
    /// Held in-memory until block commit, then written atomically with block metadata.
    #[must_use]
    pub const fn receipts(&self) -> &BoundedVec<StoredReceipt, MAX_TXS_PER_BLOCK> {
        &self.receipts
    }

    /// Get the wave ID from the certificate.
    #[must_use]
    pub fn wave_id(&self) -> &WaveId {
        self.certificate.wave_id()
    }

    /// Get the execution certificates (from the wave certificate).
    #[must_use]
    pub fn execution_certificates(&self) -> &[Arc<ExecutionCertificate>] {
        self.certificate.execution_certificates()
    }

    /// The local shard's EC — authoritative for wave membership and ordering.
    ///
    /// A well-formed `WaveCertificate` has exactly one EC with `ec.wave_id() == wc.wave_id`
    /// (invariant established by `WaveCertificateTracker::create_wave_certificate`
    /// and the endorsement + convergence gate).
    ///
    /// # Panics
    ///
    /// Panics if the local EC is missing — that indicates a malformed
    /// or tampered `WaveCertificate`.
    #[must_use]
    pub fn local_ec(&self) -> &ExecutionCertificate {
        self.certificate
            .execution_certificates()
            .iter()
            .find(|ec| ec.wave_id() == self.certificate.wave_id())
            .expect("WaveCertificate invariant: local EC must be present")
    }

    /// Number of transactions in this wave.
    #[must_use]
    pub fn tx_count(&self) -> usize {
        self.local_ec().tx_outcomes().len()
    }

    /// Iterator over each receipt's consensus payload, in canonical
    /// block order. Used by pending-chain insertion and local-receipt
    /// root verification.
    pub fn consensus_receipts(&self) -> impl Iterator<Item = Arc<ConsensusReceipt>> + '_ {
        self.receipts.iter().map(|r| Arc::clone(&r.consensus))
    }

    /// Iterator over the wave's tx hashes in canonical block order.
    pub fn tx_hashes(&self) -> impl Iterator<Item = TxHash> + '_ {
        self.local_ec().tx_outcomes().iter().map(TxOutcome::tx_hash)
    }

    /// Whether the wave contains a given tx.
    #[must_use]
    pub fn contains_tx(&self, tx_hash: &TxHash) -> bool {
        self.local_ec()
            .tx_outcomes()
            .iter()
            .any(|o| &o.tx_hash() == tx_hash)
    }

    /// Reconstruct a `FinalizedWave` from a `WaveCertificate` and a receipt lookup.
    ///
    /// Used on the storage/sync serving side to rebuild the in-memory shape
    /// from committed state. Walks the local EC's `tx_outcomes` (canonical block
    /// order) and fetches each receipt via `lookup`. Aborted txs are skipped —
    /// they produce no receipt (matches the shape in `execution::finalize_wave`).
    ///
    /// Returns `None` if:
    /// - The `WaveCertificate` lacks a local EC (malformed — should not happen
    ///   for a committed WC per the `create_wave_certificate` invariant).
    /// - Any non-aborted tx's receipt is missing from the lookup (peer/storage
    ///   has incomplete state — syncing peer should try a different source).
    pub fn reconstruct<F>(certificate: Arc<WaveCertificate>, mut lookup: F) -> Option<Self>
    where
        F: FnMut(&TxHash) -> Option<Arc<ConsensusReceipt>>,
    {
        let local_ec = certificate
            .execution_certificates()
            .iter()
            .find(|ec| ec.wave_id() == certificate.wave_id())?;

        let mut receipts: Vec<StoredReceipt> = Vec::with_capacity(local_ec.tx_outcomes().len());
        for outcome in local_ec.tx_outcomes() {
            match lookup(&outcome.tx_hash()) {
                Some(receipt) => {
                    receipts.push(StoredReceipt::synced(outcome.tx_hash(), receipt));
                }
                None if outcome.is_aborted() => {}
                None => return None,
            }
        }

        Some(Self::new(certificate, receipts))
    }

    /// Build a `FinalizedWave` from raw inputs, wrapping `receipts` into
    /// its bounded type.
    ///
    /// # Panics
    ///
    /// Panics if `receipts.len() > MAX_TXS_PER_BLOCK`.
    #[must_use]
    pub fn new(certificate: Arc<WaveCertificate>, receipts: Vec<StoredReceipt>) -> Self {
        Self {
            certificate,
            receipts: receipts.into(),
        }
    }

    /// Validate that `receipts` are consistent with the local EC's
    /// `tx_outcomes`: exactly one receipt per non-aborted outcome, in
    /// `tx_outcomes` canonical order, with matching `tx_hash` and matching
    /// success/failure outcome.
    ///
    /// This does **not** verify `database_updates` or `writes_root` —
    /// `ConsensusReceipt::Succeeded` carries only shard-filtered writes, so the global
    /// `writes_root` the EC commits to can't be reconstructed from a
    /// stored receipt alone. Use to catch gross drift (wrong tx, wrong
    /// success/fail, missing or surplus receipts) at peer-wave ingress.
    ///
    /// # Errors
    ///
    /// Returns the corresponding [`ReceiptValidationError`] variant on
    /// the first inconsistency found.
    pub fn validate_receipts_against_ec(&self) -> Result<(), ReceiptValidationError> {
        let local_ec = self
            .certificate
            .execution_certificates()
            .iter()
            .find(|ec| ec.wave_id() == self.certificate.wave_id())
            .ok_or(ReceiptValidationError::MissingLocalEc)?;

        let mut receipt_iter = self.receipts.iter();
        for outcome in local_ec.tx_outcomes() {
            // Aborted outcomes carry no stored receipt; skip.
            let ec_kind = match outcome.outcome() {
                ExecutionOutcome::Aborted => continue,
                ExecutionOutcome::Succeeded { receipt_hash } => Some(*receipt_hash),
                ExecutionOutcome::Failed => None,
            };

            let receipt =
                receipt_iter
                    .next()
                    .ok_or_else(|| ReceiptValidationError::MissingReceipt {
                        tx_hash: outcome.tx_hash(),
                    })?;
            if receipt.tx_hash != outcome.tx_hash() {
                return Err(ReceiptValidationError::TxHashMismatch {
                    expected: outcome.tx_hash(),
                    actual: receipt.tx_hash,
                });
            }

            match (ec_kind, receipt.consensus.as_ref()) {
                (
                    Some(expected_hash),
                    ConsensusReceipt::Succeeded {
                        receipt_hash: actual_hash,
                        ..
                    },
                ) => {
                    if *actual_hash != expected_hash {
                        return Err(ReceiptValidationError::ReceiptHashMismatch {
                            tx_hash: outcome.tx_hash(),
                            expected: expected_hash,
                            actual: *actual_hash,
                        });
                    }
                }
                (Some(_), ConsensusReceipt::Failed) => {
                    return Err(ReceiptValidationError::UnexpectedFailure {
                        tx_hash: outcome.tx_hash(),
                    });
                }
                (None, ConsensusReceipt::Succeeded { .. }) => {
                    return Err(ReceiptValidationError::UnexpectedSuccess {
                        tx_hash: outcome.tx_hash(),
                    });
                }
                (None, ConsensusReceipt::Failed) => { /* match — both Failed */ }
            }
        }
        if let Some(extra) = receipt_iter.next() {
            return Err(ReceiptValidationError::ExtraReceipt {
                tx_hash: extra.tx_hash,
            });
        }
        Ok(())
    }

    /// Aggregate per-tx decisions across all ECs (Aborted > Reject > Accept).
    ///
    /// Iteration order follows the local EC's canonical (block) order.
    #[must_use]
    pub fn tx_decisions(&self) -> Vec<(TxHash, TransactionDecision)> {
        let mut aborted: HashSet<TxHash> = HashSet::new();
        let mut failure: HashSet<TxHash> = HashSet::new();
        for ec in self.certificate.execution_certificates() {
            for outcome in ec.tx_outcomes() {
                if outcome.is_aborted() {
                    aborted.insert(outcome.tx_hash());
                }
                if !matches!(outcome.outcome(), ExecutionOutcome::Succeeded { .. }) {
                    failure.insert(outcome.tx_hash());
                }
            }
        }
        self.tx_hashes()
            .map(|h| {
                let d = if aborted.contains(&h) {
                    TransactionDecision::Aborted
                } else if failure.contains(&h) {
                    TransactionDecision::Reject
                } else {
                    TransactionDecision::Accept
                };
                (h, d)
            })
            .collect()
    }
}

/// Inputs the [`FinalizedWave`] verifier reads against. Borrows
/// everything; nothing is consumed.
#[derive(Debug, Clone, Copy)]
pub struct FinalizedWaveContext<'a> {
    /// Network identifier — feeds the domain-separated signing message
    /// for each constituent EC.
    pub network: &'a NetworkDefinition,
    /// Committee public keys for each EC, parallel to
    /// `wave.execution_certificates()`. Each inner slice is the
    /// committee for that EC's shard, in committee order.
    pub ec_public_keys: &'a [Vec<Bls12381G1PublicKey>],
}

/// Failure modes of [`FinalizedWave`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum FinalizedWaveVerifyError {
    /// `ec_public_keys.len() != wave.execution_certificates().len()`.
    /// Caller-side packaging error.
    #[error(
        "ec_public_keys length {actual} doesn't match execution_certificates length {expected}"
    )]
    PublicKeyVectorLengthMismatch {
        /// Number of ECs in the wave.
        expected: usize,
        /// Number of public-key vectors supplied.
        actual: usize,
    },
    /// One of the embedded ECs failed its own predicate.
    #[error("execution certificate at index {index}: {source}")]
    ExecutionCertificate {
        /// Position in `wave.execution_certificates()` whose verify failed.
        index: usize,
        /// The underlying EC verifier error.
        source: ExecutionCertificateVerifyError,
    },
}

/// Construction asserts: every [`ExecutionCertificate`] in
/// `wave.execution_certificates()` verifies under its corresponding
/// `ec_public_keys[i]` committee.
///
/// Construction goes through one of four gates:
///
/// - [`<FinalizedWave as Verify>::verify`](Verify::verify) — runs the
///   embedded-EC predicate over every constituent EC.
/// - [`Verified::<FinalizedWave>::seal`] — wraps a locally-finalized
///   wave whose ECs were produced through the
///   [`Verified::<ExecutionCertificate>::aggregate`] gate.
/// - [`Verified::<FinalizedWave>::from_remote_attestation`] — named
///   alias for the `verify` path, used at wire-admission sites.
/// - [`Verified::<FinalizedWave>::from_committed_block`] — wraps a
///   wave reaching downstream consumers via a
///   [`Verified<CertifiedBlock>`], where the source committee's QC
///   BFT-transitively attests the per-EC signature claim.
///
/// [`Verified<CertifiedBlock>`]: crate::CertifiedBlock
impl Verify<&FinalizedWaveContext<'_>> for FinalizedWave {
    type Error = FinalizedWaveVerifyError;

    fn verify(&self, ctx: &FinalizedWaveContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let ecs = self.execution_certificates();
        if ctx.ec_public_keys.len() != ecs.len() {
            return Err(FinalizedWaveVerifyError::PublicKeyVectorLengthMismatch {
                expected: ecs.len(),
                actual: ctx.ec_public_keys.len(),
            });
        }
        for (index, (ec, pks)) in ecs.iter().zip(ctx.ec_public_keys.iter()).enumerate() {
            let ec_ctx = ExecutionCertificateContext {
                network: ctx.network,
                public_keys: pks,
            };
            ec.verify(&ec_ctx).map_err(|source| {
                FinalizedWaveVerifyError::ExecutionCertificate { index, source }
            })?;
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verified<FinalizedWave> {
    /// Wrap a locally-finalized wave whose ECs were built through the
    /// [`Verified::<ExecutionCertificate>::aggregate`] gate.
    ///
    /// Trust source: every EC in the wrapped `WaveCertificate` was
    /// produced from a quorum of verified votes on this validator, so
    /// the predicate (per-EC BLS verify against the matching committee)
    /// holds by construction. Used at the [`WaveState::into_finalized`]
    /// boundary.
    ///
    /// [`WaveState::into_finalized`]: crate::WaveState::into_finalized
    #[must_use]
    pub const fn seal(wave: FinalizedWave) -> Self {
        // SAFETY: every EC in `wave.execution_certificates()` was
        // built by the local aggregator from verified votes (see
        // `Verified::<ExecutionCertificate>::aggregate`); the per-EC
        // BLS verify against the matching committee pubkey vector
        // holds by construction.
        Self::new_unchecked(wave)
    }

    /// Run the wire-admission predicate. Named alias of
    /// [`<FinalizedWave as Verify>::verify`](Verify::verify) for use
    /// at delegated-action handlers that admit waves arrived from a
    /// peer.
    ///
    /// # Errors
    ///
    /// Returns [`FinalizedWaveVerifyError`] from the first EC whose
    /// predicate fails.
    pub fn from_remote_attestation(
        wave: &FinalizedWave,
        ctx: &FinalizedWaveContext<'_>,
    ) -> Result<Self, FinalizedWaveVerifyError> {
        wave.verify(ctx)
    }

    /// Wrap a finalized wave reaching the system via a committed block.
    ///
    /// Trust source: the wave was carried inside a
    /// [`Verified<CertifiedBlock>`]; 2f+1 of the block's committee
    /// signed over `block.hash()`, which commits to every contained
    /// wave via the header's `certificate_root` and to each wave's
    /// receipt set via `local_receipt_root`. Honest signers ran the
    /// per-EC BLS predicate before voting, so the predicate
    /// [`<FinalizedWave as Verify>::verify`] would run is
    /// BFT-transitively attested by that committee.
    ///
    /// Used at sync admission, where the QC chain replaces local
    /// per-EC signature checks on each contained wave.
    ///
    /// [`Verified<CertifiedBlock>`]: crate::CertifiedBlock
    #[must_use]
    pub const fn from_committed_block(wave: FinalizedWave) -> Self {
        // SAFETY: the wave was carried in a `Verified<CertifiedBlock>`;
        // the source committee's QC attests its inclusion and per-EC
        // signature checks via the block's `certificate_root` and
        // `local_receipt_root`. Mirrors `Verified::<Provisions>::from_committed_block`
        // and the QC-transitive trust shape on
        // `Verified::<CertifiedBlock>::from_qc_attestation`.
        Self::new_unchecked(wave)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BlockHash, BlockHeight, Bls12381G1PrivateKey, Bls12381G2Signature, ExecutionVote, Hash,
        ShardGroupId, ValidatorId, WeightedTimestamp, compute_global_receipt_root,
        generate_bls_keypair,
    };

    fn make_outcome(seed: u8) -> TxOutcome {
        TxOutcome::new(
            TxHash::from_raw(Hash::from_bytes(&[seed; 4])),
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(&[seed + 100; 4])),
            },
        )
    }

    fn wave_id(shard: u64, height: u64, remote: &[u64]) -> WaveId {
        WaveId::new(
            ShardGroupId::new(shard),
            BlockHeight::new(height),
            remote.iter().copied().map(ShardGroupId::new).collect(),
        )
    }

    /// Build a verified EC for `wave_id` by aggregating real signed votes
    /// from `signers`. Output verifies against `signers.public_key()`s.
    fn make_verified_ec(
        net: &NetworkDefinition,
        wave_id: &WaveId,
        outcomes: &[TxOutcome],
        signers: &[Bls12381G1PrivateKey],
    ) -> Verified<ExecutionCertificate> {
        let root = compute_global_receipt_root(outcomes);
        let committee: Vec<ValidatorId> = (0..signers.len())
            .map(|i| ValidatorId::new(u64::try_from(i).unwrap()))
            .collect();
        let votes: Vec<Verified<ExecutionVote>> = signers
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                Verified::<ExecutionVote>::sign_local(
                    net,
                    BlockHash::from_raw(Hash::from_bytes(b"block")),
                    wave_id.block_height(),
                    WeightedTimestamp::from_millis(wave_id.block_height().inner() + 1),
                    wave_id.clone(),
                    wave_id.shard_group_id(),
                    outcomes.to_vec(),
                    ValidatorId::new(u64::try_from(i).unwrap()),
                    sk,
                )
            })
            .collect();
        Verified::<ExecutionCertificate>::aggregate(wave_id, root, &votes, &committee)
    }

    /// Honest path: every EC verifies under its committee PKs.
    #[test]
    fn verify_accepts_finalized_wave_with_valid_ecs() {
        let net = NetworkDefinition::simulator();

        let local_wid = wave_id(0, 7, &[1]);
        let remote_wid = wave_id(1, 7, &[0]);

        let shard0_signers: Vec<Bls12381G1PrivateKey> =
            (0..2).map(|_| generate_bls_keypair()).collect();
        let shard1_signers: Vec<Bls12381G1PrivateKey> =
            (0..2).map(|_| generate_bls_keypair()).collect();
        let shard0_pks: Vec<Bls12381G1PublicKey> = shard0_signers
            .iter()
            .map(Bls12381G1PrivateKey::public_key)
            .collect();
        let shard1_pks: Vec<Bls12381G1PublicKey> = shard1_signers
            .iter()
            .map(Bls12381G1PrivateKey::public_key)
            .collect();

        let local_outcomes = vec![make_outcome(1), make_outcome(2)];
        let remote_outcomes = vec![make_outcome(1), make_outcome(2)];
        let local_ec =
            make_verified_ec(&net, &local_wid, &local_outcomes, &shard0_signers).into_inner();
        let remote_ec =
            make_verified_ec(&net, &remote_wid, &remote_outcomes, &shard1_signers).into_inner();

        let wc = Arc::new(WaveCertificate::new(
            local_wid,
            vec![Arc::new(local_ec), Arc::new(remote_ec)],
        ));
        let wave = FinalizedWave::new(wc, vec![]);

        let ec_pks = vec![shard0_pks, shard1_pks];
        let ctx = FinalizedWaveContext {
            network: &net,
            ec_public_keys: &ec_pks,
        };
        wave.verify(&ctx)
            .expect("honest finalized wave must verify");
    }

    /// One tampered EC fails its own predicate; the error names the
    /// failing index.
    #[test]
    fn verify_rejects_finalized_wave_with_one_bad_ec() {
        let net = NetworkDefinition::simulator();
        let local_wid = wave_id(0, 7, &[1]);
        let remote_wid = wave_id(1, 7, &[0]);

        let shard0_signers: Vec<Bls12381G1PrivateKey> =
            (0..2).map(|_| generate_bls_keypair()).collect();
        let shard1_signers: Vec<Bls12381G1PrivateKey> =
            (0..2).map(|_| generate_bls_keypair()).collect();
        let shard0_pks: Vec<Bls12381G1PublicKey> = shard0_signers
            .iter()
            .map(Bls12381G1PrivateKey::public_key)
            .collect();
        let shard1_pks: Vec<Bls12381G1PublicKey> = shard1_signers
            .iter()
            .map(Bls12381G1PrivateKey::public_key)
            .collect();

        let local_outcomes = vec![make_outcome(1)];
        let remote_outcomes = vec![make_outcome(1)];
        let local_ec =
            make_verified_ec(&net, &local_wid, &local_outcomes, &shard0_signers).into_inner();
        let remote_ec =
            make_verified_ec(&net, &remote_wid, &remote_outcomes, &shard1_signers).into_inner();

        // Tamper the second EC's aggregated signature.
        let tampered_remote = ExecutionCertificate::new(
            remote_ec.wave_id().clone(),
            remote_ec.vote_anchor_ts(),
            remote_ec.global_receipt_root(),
            remote_ec.tx_outcomes().clone(),
            Bls12381G2Signature([0xFF; 96]),
            remote_ec.signers().clone(),
        );

        let wc = Arc::new(WaveCertificate::new(
            local_wid,
            vec![Arc::new(local_ec), Arc::new(tampered_remote)],
        ));
        let wave = FinalizedWave::new(wc, vec![]);

        let ec_pks = vec![shard0_pks, shard1_pks];
        let ctx = FinalizedWaveContext {
            network: &net,
            ec_public_keys: &ec_pks,
        };
        let err = wave.verify(&ctx).expect_err("tampered EC must fail verify");
        assert!(matches!(
            err,
            FinalizedWaveVerifyError::ExecutionCertificate { index: 1, .. }
        ));
    }

    /// `from_committed_block` produces a verified wave whose inner is
    /// byte-equal to the input — the gate names the trust source, it
    /// does not modify the wave. Honest signers behind a real
    /// `Verified<CertifiedBlock>` would have already cleared every
    /// contained EC's BLS predicate; this test pins the gate's
    /// no-op-on-content shape.
    #[test]
    fn from_committed_block_wraps_input_without_modification() {
        let net = NetworkDefinition::simulator();
        let local_wid = wave_id(0, 7, &[]);
        let sks: Vec<Bls12381G1PrivateKey> = (0..2).map(|_| generate_bls_keypair()).collect();
        let outcomes = vec![make_outcome(1)];
        let ec = make_verified_ec(&net, &local_wid, &outcomes, &sks).into_inner();

        let wc = Arc::new(WaveCertificate::new(local_wid, vec![Arc::new(ec)]));
        let wave = FinalizedWave::new(wc, vec![]);

        let verified = Verified::<FinalizedWave>::from_committed_block(wave.clone());
        assert_eq!(verified.into_inner(), wave);
    }

    /// `ec_public_keys` length must match the number of ECs.
    #[test]
    fn verify_rejects_mismatched_public_key_vector_length() {
        let net = NetworkDefinition::simulator();
        let local_wid = wave_id(0, 7, &[]);
        let sks: Vec<Bls12381G1PrivateKey> = (0..2).map(|_| generate_bls_keypair()).collect();

        let outcomes = vec![make_outcome(1)];
        let ec = make_verified_ec(&net, &local_wid, &outcomes, &sks).into_inner();

        let wc = Arc::new(WaveCertificate::new(local_wid, vec![Arc::new(ec)]));
        let wave = FinalizedWave::new(wc, vec![]);

        // Supply two public-key vectors for a single-EC wave.
        let ec_pks: Vec<Vec<Bls12381G1PublicKey>> = vec![vec![], vec![]];
        let ctx = FinalizedWaveContext {
            network: &net,
            ec_public_keys: &ec_pks,
        };
        assert_eq!(
            wave.verify(&ctx),
            Err(FinalizedWaveVerifyError::PublicKeyVectorLengthMismatch {
                expected: 1,
                actual: 2,
            })
        );
    }
}
