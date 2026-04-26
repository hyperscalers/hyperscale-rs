//! [`FinalizedWave`] — wave certificate plus locally-executed receipts, with
//! reconstruction, validation, and `Vec<Arc<FinalizedWave>>` SBOR helpers.

use crate::{
    ExecutionCertificate, ExecutionOutcome, LocalReceipt, ReceiptBundle, TransactionDecision,
    TransactionOutcome, TxHash, WaveCertificate, WaveId, WaveIdHash,
};
use sbor::prelude::*;
use std::sync::Arc;

/// A finalized wave — all participating shards have reported, `WaveCertificate` created.
///
/// Holds the wave certificate (which contains the execution certificates) plus the
/// receipt bundles produced by local execution. Receipts are written atomically
/// with the block at commit time (not fire-and-forget).
///
/// # Derived views
///
/// The wave's canonical tx list, ordering, and per-tx decisions are all **derived**
/// from the `WaveCertificate`, not stored alongside it. See:
/// - [`FinalizedWave::local_ec`] — the authoritative EC (where `ec.wave_id == wc.wave_id`)
/// - [`FinalizedWave::tx_hashes`] — iterator over the wave's tx hashes in block order
/// - [`FinalizedWave::tx_decisions`] — aggregated (Aborted > Reject > Accept) per tx
///
/// `receipts` contains only txs that actually executed (sparse subset of
/// `tx_hashes()`, same block order). Aborted txs produce no receipt.
///
/// Shared via `Arc` across the system — flows from execution state through
/// pending blocks, actions, and into the commit path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedWave {
    /// The wave certificate carrying per-shard ECs and tx outcomes.
    pub certificate: Arc<WaveCertificate>,
    /// Receipt bundles for txs that executed. Aborted txs are absent —
    /// `receipts.len() <= tx_count()`. Preserves canonical block order.
    /// Held in-memory until block commit, then written atomically with block metadata.
    pub receipts: Vec<ReceiptBundle>,
}

/// Reason a `FinalizedWave`'s receipts don't agree with its own EC.
/// Returned by [`FinalizedWave::validate_receipts_against_ec`].
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
    /// A receipt's outcome (Success/Failure) disagrees with the EC's
    /// attested outcome for that tx.
    OutcomeMismatch {
        /// Hash of the tx whose outcomes disagree.
        tx_hash: TxHash,
        /// Outcome attested by the EC.
        expected: TransactionOutcome,
        /// Outcome carried by the receipt.
        actual: TransactionOutcome,
    },
    /// More receipts than non-aborted outcomes.
    ExtraReceipt {
        /// Hash of the surplus receipt's tx.
        tx_hash: TxHash,
    },
}

impl FinalizedWave {
    /// Get the wave ID from the certificate.
    #[must_use]
    pub fn wave_id(&self) -> &WaveId {
        &self.certificate.wave_id
    }

    /// Get the wave ID hash (used as key in pending block tracking).
    #[must_use]
    pub fn wave_id_hash(&self) -> WaveIdHash {
        self.certificate.wave_id.hash()
    }

    /// Get the execution certificates (from the wave certificate).
    #[must_use]
    pub fn execution_certificates(&self) -> &[Arc<ExecutionCertificate>] {
        &self.certificate.execution_certificates
    }

    /// The local shard's EC — authoritative for wave membership and ordering.
    ///
    /// A well-formed `WaveCertificate` has exactly one EC with `ec.wave_id == wc.wave_id`
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
            .execution_certificates
            .iter()
            .find(|ec| ec.wave_id == self.certificate.wave_id)
            .expect("WaveCertificate invariant: local EC must be present")
    }

    /// Number of transactions in this wave.
    #[must_use]
    pub fn tx_count(&self) -> usize {
        self.local_ec().tx_outcomes.len()
    }

    /// Iterator over the wave's tx hashes in canonical block order.
    pub fn tx_hashes(&self) -> impl Iterator<Item = TxHash> + '_ {
        self.local_ec().tx_outcomes.iter().map(|o| o.tx_hash)
    }

    /// Whether the wave contains a given tx.
    #[must_use]
    pub fn contains_tx(&self, tx_hash: &TxHash) -> bool {
        self.local_ec()
            .tx_outcomes
            .iter()
            .any(|o| &o.tx_hash == tx_hash)
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
        F: FnMut(&TxHash) -> Option<Arc<LocalReceipt>>,
    {
        let local_ec = certificate
            .execution_certificates
            .iter()
            .find(|ec| ec.wave_id == certificate.wave_id)?;

        let mut receipts: Vec<ReceiptBundle> = Vec::with_capacity(local_ec.tx_outcomes.len());
        for outcome in &local_ec.tx_outcomes {
            match lookup(&outcome.tx_hash) {
                Some(receipt) => receipts.push(ReceiptBundle {
                    tx_hash: outcome.tx_hash,
                    local_receipt: receipt,
                    execution_output: None,
                }),
                None if outcome.is_aborted() => {}
                None => return None,
            }
        }

        Some(Self {
            certificate,
            receipts,
        })
    }

    /// Validate that `receipts` are consistent with the local EC's
    /// `tx_outcomes`: exactly one receipt per non-aborted outcome, in
    /// `tx_outcomes` canonical order, with matching `tx_hash` and matching
    /// success/failure outcome.
    ///
    /// This does **not** verify `database_updates` or `writes_root` —
    /// `LocalReceipt` carries only shard-filtered writes, so the global
    /// `writes_root` the EC commits to can't be reconstructed from a
    /// local receipt alone. Use to catch gross drift (wrong tx, wrong
    /// success/fail, missing or surplus receipts) at peer-wave ingress.
    ///
    /// # Errors
    ///
    /// Returns the corresponding [`ReceiptValidationError`] variant on
    /// the first inconsistency found.
    pub fn validate_receipts_against_ec(&self) -> Result<(), ReceiptValidationError> {
        let local_ec = self
            .certificate
            .execution_certificates
            .iter()
            .find(|ec| ec.wave_id == self.certificate.wave_id)
            .ok_or(ReceiptValidationError::MissingLocalEc)?;

        let mut receipt_iter = self.receipts.iter();
        for outcome in &local_ec.tx_outcomes {
            match outcome.outcome {
                ExecutionOutcome::Aborted => {
                    // Aborted outcomes carry no local receipt; skip.
                }
                ExecutionOutcome::Executed { success, .. } => {
                    let receipt =
                        receipt_iter
                            .next()
                            .ok_or(ReceiptValidationError::MissingReceipt {
                                tx_hash: outcome.tx_hash,
                            })?;
                    if receipt.tx_hash != outcome.tx_hash {
                        return Err(ReceiptValidationError::TxHashMismatch {
                            expected: outcome.tx_hash,
                            actual: receipt.tx_hash,
                        });
                    }
                    let expected = if success {
                        TransactionOutcome::Success
                    } else {
                        TransactionOutcome::Failure
                    };
                    if receipt.local_receipt.outcome != expected {
                        return Err(ReceiptValidationError::OutcomeMismatch {
                            tx_hash: outcome.tx_hash,
                            expected,
                            actual: receipt.local_receipt.outcome,
                        });
                    }
                }
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
        let mut aborted: std::collections::HashSet<TxHash> = std::collections::HashSet::new();
        let mut failure: std::collections::HashSet<TxHash> = std::collections::HashSet::new();
        for ec in &self.certificate.execution_certificates {
            for outcome in &ec.tx_outcomes {
                if outcome.is_aborted() {
                    aborted.insert(outcome.tx_hash);
                }
                if !matches!(
                    outcome.outcome,
                    ExecutionOutcome::Executed { success: true, .. }
                ) {
                    failure.insert(outcome.tx_hash);
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

// Manual SBOR implementation for FinalizedWave (Arc fields prevent BasicSbor derive).
// Encodes Arc<T> as T, decodes T and wraps in Arc.

impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for FinalizedWave
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(2)?;
        encoder.encode(self.certificate.as_ref())?;
        encoder.encode(&self.receipts)?;
        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for FinalizedWave
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 2 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 2,
                actual: length,
            });
        }
        let certificate: WaveCertificate = decoder.decode()?;
        let receipts: Vec<ReceiptBundle> = decoder.decode()?;
        Ok(Self {
            certificate: Arc::new(certificate),
            receipts,
        })
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for FinalizedWave {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for FinalizedWave {
    const TYPE_ID: sbor::RustTypeId = sbor::RustTypeId::novel_with_code("FinalizedWave", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

/// Encode a `Vec<Arc<FinalizedWave>>` as an SBOR array.
///
/// # Errors
///
/// Forwards [`sbor::EncodeError`] from the underlying encoder.
pub fn encode_finalized_wave_vec<E: sbor::Encoder<sbor::NoCustomValueKind>>(
    encoder: &mut E,
    waves: &[Arc<FinalizedWave>],
) -> Result<(), sbor::EncodeError> {
    encoder.write_value_kind(sbor::ValueKind::Array)?;
    encoder.write_value_kind(sbor::ValueKind::Tuple)?;
    encoder.write_size(waves.len())?;
    for wave in waves {
        encoder.encode_deeper_body(wave.as_ref())?;
    }
    Ok(())
}

/// Decode a `Vec<Arc<FinalizedWave>>` from an SBOR array.
///
/// # Errors
///
/// Returns [`sbor::DecodeError::UnexpectedSize`] if the encoded count
/// exceeds `max_size`, or any decoder error from reading individual
/// finalized waves.
pub fn decode_finalized_wave_vec<D: sbor::Decoder<sbor::NoCustomValueKind>>(
    decoder: &mut D,
    max_size: usize,
) -> Result<Vec<Arc<FinalizedWave>>, sbor::DecodeError> {
    decoder.read_and_check_value_kind(sbor::ValueKind::Array)?;
    decoder.read_and_check_value_kind(sbor::ValueKind::Tuple)?;
    let count = decoder.read_size()?;
    if count > max_size {
        return Err(sbor::DecodeError::UnexpectedSize {
            expected: max_size,
            actual: count,
        });
    }
    let mut waves = Vec::with_capacity(count);
    for _ in 0..count {
        let wave: FinalizedWave =
            decoder.decode_deeper_body_with_value_kind(sbor::ValueKind::Tuple)?;
        waves.push(Arc::new(wave));
    }
    Ok(waves)
}
