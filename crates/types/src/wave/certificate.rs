//! [`WaveCertificate`] — proof of execution finalization carrying every
//! participating shard's [`ExecutionCertificate`], plus encode/decode helpers
//! for `Vec<Arc<WaveCertificate>>`.

use crate::{ExecutionCertificate, Hash, WaveId, WaveReceiptHash};
use sbor::prelude::*;
use std::sync::Arc;

/// Wave certificate — proof of execution finalization for a wave.
///
/// Contains the execution certificates from all participating shards.
/// Per-tx decisions (Accept/Reject/Aborted) are derived from the ECs.
/// Every wave resolves through the EC path — there is no all-abort fallback.
///
/// # Invariant (well-formed WC)
///
/// A well-formed `WaveCertificate` always contains the **local EC** — the EC
/// where `ec.wave_id == wc.wave_id`. The local EC is the authoritative source
/// for the wave's tx set and canonical (block) ordering. Remote ECs attest
/// against their own wave decompositions and may cover only subsets.
///
/// Enforced by `WaveCertificateTracker::create_wave_certificate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaveCertificate {
    /// Self-contained wave identifier (shard + height + remote dependencies).
    /// Globally unique. `hash(wave_id)` = identity key for manifest/storage.
    pub wave_id: WaveId,
    /// Execution certificates from all participating shards.
    /// Always includes the local EC (see invariant above).
    /// May contain multiple ECs from the same remote shard — this happens when
    /// a remote shard committed this wave's transactions across multiple blocks,
    /// producing separate ECs.
    /// Sorted by (`shard_group_id`, `canonical_hash`) for deterministic `receipt_hash`.
    pub execution_certificates: Vec<Arc<ExecutionCertificate>>,
}

impl WaveCertificate {
    /// Compute the receipt hash for this wave certificate.
    ///
    /// Hashes sorted (`shard_group_id`, `canonical_hash`) pairs. The vec is
    /// pre-sorted at construction time for deterministic ordering.
    /// `canonical_hash` already encodes the `WaveId`, `vote_anchor_ts`,
    /// `global_receipt_root`, and all `tx_outcomes` — so this commits to
    /// the full content of every contributing EC.
    ///
    /// # Panics
    ///
    /// Panics if SBOR encoding of a `ShardGroupId` fails — closed SBOR
    /// type, infallible in practice.
    #[must_use]
    pub fn receipt_hash(&self) -> WaveReceiptHash {
        let mut hasher = blake3::Hasher::new();
        for ec in &self.execution_certificates {
            hasher.update(&basic_encode(&ec.shard_group_id()).unwrap());
            hasher.update(ec.canonical_hash().as_raw().as_bytes());
        }
        WaveReceiptHash::from_raw(Hash::from_hash_bytes(hasher.finalize().as_bytes()))
    }

    /// Get the execution certificates.
    #[must_use]
    pub fn execution_certificates(&self) -> &[Arc<ExecutionCertificate>] {
        &self.execution_certificates
    }
}

// Manual SBOR implementation (since we need stable encoding)

impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for WaveCertificate
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(2)?;
        encoder.encode(&self.wave_id)?;
        // Encode Vec<Arc<ExecutionCertificate>> as Vec<ExecutionCertificate>
        encoder.write_value_kind(sbor::ValueKind::Array)?;
        encoder.write_value_kind(sbor::ValueKind::Tuple)?;
        encoder.write_size(self.execution_certificates.len())?;
        for ec in &self.execution_certificates {
            encoder.encode_deeper_body(ec.as_ref())?;
        }
        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for WaveCertificate
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
        let wave_id: WaveId = decoder.decode()?;
        // Decode Vec<ExecutionCertificate> into Vec<Arc<ExecutionCertificate>>
        decoder.read_and_check_value_kind(sbor::ValueKind::Array)?;
        decoder.read_and_check_value_kind(sbor::ValueKind::Tuple)?;
        let count = decoder.read_size()?;
        let mut execution_certificates = Vec::with_capacity(count);
        for _ in 0..count {
            let ec: ExecutionCertificate =
                decoder.decode_deeper_body_with_value_kind(sbor::ValueKind::Tuple)?;
            execution_certificates.push(Arc::new(ec));
        }
        Ok(Self {
            wave_id,
            execution_certificates,
        })
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for WaveCertificate {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for WaveCertificate {
    const TYPE_ID: sbor::RustTypeId =
        sbor::RustTypeId::novel_with_code("WaveCertificate", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

/// Encode a `Vec<Arc<WaveCertificate>>` as an SBOR array.
///
/// # Errors
///
/// Forwards [`sbor::EncodeError`] from the underlying encoder.
pub fn encode_wave_cert_vec<E: sbor::Encoder<sbor::NoCustomValueKind>>(
    encoder: &mut E,
    certs: &[Arc<WaveCertificate>],
) -> Result<(), sbor::EncodeError> {
    encoder.write_value_kind(sbor::ValueKind::Array)?;
    encoder.write_value_kind(sbor::ValueKind::Tuple)?;
    encoder.write_size(certs.len())?;
    for cert in certs {
        encoder.encode_deeper_body(cert.as_ref())?;
    }
    Ok(())
}

/// Decode a `Vec<Arc<WaveCertificate>>` from an SBOR array.
///
/// # Errors
///
/// Returns [`sbor::DecodeError::UnexpectedSize`] if the encoded count
/// exceeds `max_size`, or any decoder error from reading individual
/// certificates.
pub fn decode_wave_cert_vec<D: sbor::Decoder<sbor::NoCustomValueKind>>(
    decoder: &mut D,
    max_size: usize,
) -> Result<Vec<Arc<WaveCertificate>>, sbor::DecodeError> {
    decoder.read_and_check_value_kind(sbor::ValueKind::Array)?;
    decoder.read_and_check_value_kind(sbor::ValueKind::Tuple)?;
    let count = decoder.read_size()?;
    if count > max_size {
        return Err(sbor::DecodeError::UnexpectedSize {
            expected: max_size,
            actual: count,
        });
    }
    let mut certs = Vec::with_capacity(count);
    for _ in 0..count {
        let cert: WaveCertificate =
            decoder.decode_deeper_body_with_value_kind(sbor::ValueKind::Tuple)?;
        certs.push(Arc::new(cert));
    }
    Ok(certs)
}
