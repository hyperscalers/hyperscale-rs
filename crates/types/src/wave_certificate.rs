//! Wave certificate types for wave-level finalization.
//!
//! A `WaveCertificate` is a lean proof containing shard attestations (BLS
//! signatures + ec_hashes). Per-tx decisions are NOT embedded — they are
//! derived from the ECs referenced by the attestations.

use crate::{Bls12381G2Signature, Hash, ShardGroupId, SignerBitfield, WaveId};
use sbor::prelude::*;
use std::sync::Arc;

/// Wave certificate — proof of execution finalization for a wave.
///
/// Contains only shard attestations (proof half). Per-tx decisions
/// (Accept/Reject/Aborted) are derived from the ECs referenced by
/// the attestations. Every wave resolves through the EC path — there
/// is no all-abort fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaveCertificate {
    /// Self-contained wave identifier (shard + height + remote dependencies).
    /// Globally unique. `hash(wave_id)` = identity key for manifest/storage.
    pub wave_id: WaveId,
    /// Shard attestations proving execution finalization.
    /// May contain multiple attestations from the same shard — this happens when
    /// a remote shard committed this wave's transactions across multiple blocks,
    /// producing separate ECs.
    /// Sorted by (shard_group_id, ec_hash) for deterministic receipt_hash.
    pub attestations: Vec<ShardAttestation>,
}

/// Proof half of an execution certificate from a single shard.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ShardAttestation {
    /// Which shard produced this EC.
    pub shard_group_id: ShardGroupId,
    /// Canonical hash of the EC this attestation came from.
    pub ec_hash: Hash,
    /// Vote height at which the EC was aggregated.
    pub vote_height: u64,
    /// Merkle root over per-tx outcome leaves in the EC.
    pub global_receipt_root: Hash,
    /// BLS aggregated signature from 2f+1 validators on this shard.
    pub aggregated_signature: Bls12381G2Signature,
    /// Which validators signed (bitfield indexed by committee position).
    pub signers: SignerBitfield,
}

impl WaveCertificate {
    /// Compute the receipt hash for this wave certificate.
    ///
    /// Hashes sorted (shard_group_id, ec_hash) pairs. The vec is pre-sorted
    /// at construction time for deterministic ordering. ec_hash already encodes
    /// the WaveId, vote_height, global_receipt_root, and all tx_outcomes — so
    /// this commits to the full content of every contributing EC.
    pub fn receipt_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        for att in &self.attestations {
            hasher.update(&basic_encode(&att.shard_group_id).unwrap());
            hasher.update(att.ec_hash.as_bytes());
        }
        Hash::from_hash_bytes(hasher.finalize().as_bytes())
    }

    /// Get attestations.
    pub fn attestations(&self) -> &[ShardAttestation] {
        &self.attestations
    }
}

// ============================================================================
// Manual SBOR implementation (since we need stable encoding)
// ============================================================================

impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for WaveCertificate
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(2)?;
        encoder.encode(&self.wave_id)?;
        encoder.encode(&self.attestations)?;
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
        let attestations: Vec<ShardAttestation> = decoder.decode()?;
        Ok(Self {
            wave_id,
            attestations,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn make_test_wave_id() -> WaveId {
        WaveId {
            shard_group_id: ShardGroupId(0),
            block_height: 42,
            remote_shards: BTreeSet::from([ShardGroupId(1)]),
        }
    }

    fn make_test_attestation(shard: u64, ec_hash_seed: u8) -> ShardAttestation {
        ShardAttestation {
            shard_group_id: ShardGroupId(shard),
            ec_hash: Hash::from_bytes(&[ec_hash_seed; 4]),
            vote_height: 43,
            global_receipt_root: Hash::from_bytes(&[ec_hash_seed + 100; 4]),
            aggregated_signature: Bls12381G2Signature([0u8; 96]),
            signers: SignerBitfield::new(4),
        }
    }

    #[test]
    fn test_receipt_hash_deterministic() {
        let wc = WaveCertificate {
            wave_id: make_test_wave_id(),
            attestations: vec![make_test_attestation(0, 1), make_test_attestation(1, 2)],
        };
        assert_eq!(wc.receipt_hash(), wc.receipt_hash());
        assert_ne!(wc.receipt_hash(), Hash::ZERO);
    }

    #[test]
    fn test_receipt_hash_changes_with_ec_hash() {
        let wave_id = make_test_wave_id();
        let wc1 = WaveCertificate {
            wave_id: wave_id.clone(),
            attestations: vec![make_test_attestation(0, 1)],
        };
        let wc2 = WaveCertificate {
            wave_id,
            attestations: vec![make_test_attestation(0, 2)],
        };
        assert_ne!(wc1.receipt_hash(), wc2.receipt_hash());
    }

    #[test]
    fn test_sbor_roundtrip() {
        let wc = WaveCertificate {
            wave_id: make_test_wave_id(),
            attestations: vec![make_test_attestation(0, 1), make_test_attestation(1, 2)],
        };
        let encoded = basic_encode(&wc).unwrap();
        let decoded: WaveCertificate = basic_decode(&encoded).unwrap();
        assert_eq!(wc, decoded);
    }

    #[test]
    fn test_arc_vec_sbor_roundtrip() {
        let certs = vec![
            Arc::new(WaveCertificate {
                wave_id: make_test_wave_id(),
                attestations: vec![make_test_attestation(0, 1)],
            }),
            Arc::new(WaveCertificate {
                wave_id: WaveId {
                    shard_group_id: ShardGroupId(0),
                    block_height: 42,
                    remote_shards: BTreeSet::new(),
                },
                attestations: vec![make_test_attestation(1, 3)],
            }),
        ];

        // Encode
        let mut buf = Vec::new();
        let mut encoder = sbor::BasicEncoder::new(&mut buf, sbor::BASIC_SBOR_V1_MAX_DEPTH);
        encode_wave_cert_vec(&mut encoder, &certs).unwrap();

        // Decode
        let mut decoder = sbor::BasicDecoder::new(&buf, sbor::BASIC_SBOR_V1_MAX_DEPTH);
        let decoded = decode_wave_cert_vec(&mut decoder, 100).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].as_ref(), certs[0].as_ref());
        assert_eq!(decoded[1].as_ref(), certs[1].as_ref());
    }
}
