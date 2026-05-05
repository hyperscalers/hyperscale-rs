//! [`WaveCertificate`] — proof of execution finalization carrying every
//! participating shard's [`ExecutionCertificate`], plus encode/decode helpers
//! for `Vec<Arc<WaveCertificate>>`.

use std::sync::Arc;

use blake3::Hasher;
use sbor::prelude::*;
use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, TypeKind, ValueKind,
};

use crate::{ExecutionCertificate, Hash, WaveId, WaveReceiptHash};

/// Cap on execution certificates accepted in a single `WaveCertificate` at
/// decode time.
///
/// A wave's EC set is one local EC plus at most one EC per participating
/// remote shard (and may include a few extras if a remote shard committed
/// the wave's transactions across multiple blocks). 1024 is well above any
/// realistic shard count and bounds the per-element pre-allocation that
/// would otherwise let a peer claim billions of inner ECs and OOM the
/// validator at decode time.
const MAX_EXECUTION_CERTIFICATES_PER_WAVE: usize = 1024;

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
        let mut hasher = Hasher::new();
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

impl<E: Encoder<NoCustomValueKind>> Encode<NoCustomValueKind, E> for WaveCertificate {
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_value_kind(ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        encoder.write_size(2)?;
        encoder.encode(&self.wave_id)?;
        // Encode Vec<Arc<ExecutionCertificate>> as Vec<ExecutionCertificate>
        encoder.write_value_kind(ValueKind::Array)?;
        encoder.write_value_kind(ValueKind::Tuple)?;
        encoder.write_size(self.execution_certificates.len())?;
        for ec in &self.execution_certificates {
            encoder.encode_deeper_body(ec.as_ref())?;
        }
        Ok(())
    }
}

impl<D: Decoder<NoCustomValueKind>> Decode<NoCustomValueKind, D> for WaveCertificate {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Tuple)?;
        let length = decoder.read_size()?;
        if length != 2 {
            return Err(DecodeError::UnexpectedSize {
                expected: 2,
                actual: length,
            });
        }
        let wave_id: WaveId = decoder.decode()?;
        // Decode Vec<ExecutionCertificate> into Vec<Arc<ExecutionCertificate>>
        decoder.read_and_check_value_kind(ValueKind::Array)?;
        decoder.read_and_check_value_kind(ValueKind::Tuple)?;
        let count = decoder.read_size()?;
        if count > MAX_EXECUTION_CERTIFICATES_PER_WAVE {
            return Err(DecodeError::UnexpectedSize {
                expected: MAX_EXECUTION_CERTIFICATES_PER_WAVE,
                actual: count,
            });
        }
        let mut execution_certificates = Vec::with_capacity(count);
        for _ in 0..count {
            let ec: ExecutionCertificate =
                decoder.decode_deeper_body_with_value_kind(ValueKind::Tuple)?;
            execution_certificates.push(Arc::new(ec));
        }
        // Reject any WC that violates the local-EC invariant. Without this
        // check a peer-supplied WC reaches `FinalizedWave::local_ec()`,
        // which panics on the missing match.
        if !execution_certificates
            .iter()
            .any(|ec| ec.wave_id == wave_id)
        {
            return Err(DecodeError::InvalidCustomValue);
        }
        Ok(Self {
            wave_id,
            execution_certificates,
        })
    }
}

impl Categorize<NoCustomValueKind> for WaveCertificate {
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        ValueKind::Tuple
    }
}

impl Describe<NoCustomTypeKind> for WaveCertificate {
    const TYPE_ID: RustTypeId = RustTypeId::novel_with_code("WaveCertificate", &[], &[]);

    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        TypeData::unnamed(TypeKind::Any)
    }
}

/// Encode a `Vec<Arc<WaveCertificate>>` as an SBOR array.
///
/// # Errors
///
/// Forwards [`EncodeError`] from the underlying encoder.
pub fn encode_wave_cert_vec<E: Encoder<NoCustomValueKind>>(
    encoder: &mut E,
    certs: &[Arc<WaveCertificate>],
) -> Result<(), EncodeError> {
    encoder.write_value_kind(ValueKind::Array)?;
    encoder.write_value_kind(ValueKind::Tuple)?;
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
/// Returns [`DecodeError::UnexpectedSize`] if the encoded count
/// exceeds `max_size`, or any decoder error from reading individual
/// certificates.
pub fn decode_wave_cert_vec<D: Decoder<NoCustomValueKind>>(
    decoder: &mut D,
    max_size: usize,
) -> Result<Vec<Arc<WaveCertificate>>, DecodeError> {
    decoder.read_and_check_value_kind(ValueKind::Array)?;
    decoder.read_and_check_value_kind(ValueKind::Tuple)?;
    let count = decoder.read_size()?;
    if count > max_size {
        return Err(DecodeError::UnexpectedSize {
            expected: max_size,
            actual: count,
        });
    }
    let mut certs = Vec::with_capacity(count);
    for _ in 0..count {
        let cert: WaveCertificate = decoder.decode_deeper_body_with_value_kind(ValueKind::Tuple)?;
        certs.push(Arc::new(cert));
    }
    Ok(certs)
}
