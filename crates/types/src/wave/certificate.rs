//! [`WaveCertificate`] — proof of execution finalization carrying every
//! participating shard's [`ExecutionCertificate`].

use std::sync::Arc;

use blake3::Hasher;
use sbor::prelude::*;
use sbor::{Decode, DecodeError, Decoder, NoCustomValueKind, ValueKind};

use crate::{BoundedVec, ExecutionCertificate, Hash, WaveId, WaveReceiptHash};

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
/// A well-formed `WaveCertificate` contains **exactly one local EC** — the
/// EC where `ec.wave_id() == wc.wave_id`. The local EC is the authoritative
/// source for the wave's tx set and canonical (block) ordering. Remote ECs
/// attest against their own wave decompositions and may cover only subsets;
/// the local shard, by construction, produces a single EC per wave.
///
/// Enforced at construction by `WaveCertificateTracker::create_wave_certificate`
/// and at the wire boundary by `WaveCertificate`'s SBOR `Decode` impl.
/// Downstream helpers like [`FinalizedWave::local_ec`](crate::FinalizedWave::local_ec)
/// `expect` this invariant.
#[derive(Debug, Clone, PartialEq, Eq, BasicEncode, BasicCategorize, BasicDescribe)]
pub struct WaveCertificate {
    wave_id: WaveId,
    execution_certificates:
        BoundedVec<Arc<ExecutionCertificate>, MAX_EXECUTION_CERTIFICATES_PER_WAVE>,
}

impl WaveCertificate {
    /// Build a `WaveCertificate` from its parts.
    ///
    /// Does not validate the exactly-one-local-EC invariant; that is
    /// enforced at the wire boundary by the `Decode` impl and at the
    /// build boundary by `WaveCertificateTracker::create_wave_certificate`.
    ///
    /// # Panics
    ///
    /// Panics if `execution_certificates.len() > MAX_EXECUTION_CERTIFICATES_PER_WAVE`.
    #[must_use]
    pub fn new(wave_id: WaveId, execution_certificates: Vec<Arc<ExecutionCertificate>>) -> Self {
        Self {
            wave_id,
            execution_certificates: execution_certificates.into(),
        }
    }

    /// Self-contained wave identifier (shard + height + remote dependencies).
    /// Globally unique. `hash(wave_id)` = identity key for manifest/storage.
    #[must_use]
    pub const fn wave_id(&self) -> &WaveId {
        &self.wave_id
    }

    /// Execution certificates from all participating shards.
    /// Always includes the local EC (see invariant above).
    /// May contain multiple ECs from the same remote shard — this happens when
    /// a remote shard committed this wave's transactions across multiple blocks,
    /// producing separate ECs.
    /// Sorted by (`shard_group_id`, `wave_id`) for deterministic `receipt_hash`.
    #[must_use]
    pub fn execution_certificates(&self) -> &[Arc<ExecutionCertificate>] {
        &self.execution_certificates
    }

    /// Compute the receipt hash for this wave certificate.
    ///
    /// Hashes sorted (`shard_group_id`, `wave_id`) pairs. The vec is
    /// pre-sorted at construction time for deterministic ordering. At most
    /// one valid EC exists per `wave_id` (signature verification upstream
    /// enforces this), so committing to `wave_id` is content-equivalent.
    ///
    /// # Panics
    ///
    /// Panics if SBOR encoding of a `ShardGroupId` or `WaveId` fails —
    /// closed SBOR types, infallible in practice.
    #[must_use]
    pub fn receipt_hash(&self) -> WaveReceiptHash {
        let mut hasher = Hasher::new();
        for ec in self.execution_certificates.iter() {
            hasher.update(&basic_encode(&ec.shard_group_id()).unwrap());
            hasher.update(&basic_encode(&ec.wave_id()).unwrap());
        }
        WaveReceiptHash::from_raw(Hash::from_hash_bytes(hasher.finalize().as_bytes()))
    }
}

// Manual `Decode` overrides the derive purely to enforce the
// exactly-one-local-EC invariant at the wire boundary; encode / categorize
// / describe are derived against the inner field.
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
        let execution_certificates: BoundedVec<
            Arc<ExecutionCertificate>,
            MAX_EXECUTION_CERTIFICATES_PER_WAVE,
        > = decoder.decode()?;
        // Reject any WC that violates the exactly-one-local-EC invariant.
        // Zero local ECs would crash `FinalizedWave::local_ec()`; multiple
        // would let downstream code silently disagree on which EC is
        // authoritative for tx ordering.
        let local_ec_count = execution_certificates
            .iter()
            .filter(|ec| ec.wave_id() == &wave_id)
            .count();
        if local_ec_count != 1 {
            return Err(DecodeError::InvalidCustomValue);
        }
        Ok(Self {
            wave_id,
            execution_certificates,
        })
    }
}
