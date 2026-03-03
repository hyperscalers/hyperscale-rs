//! Proof types for Byzantine-safe backpressure and livelock handling.
//!
//! This module contains cryptographic proof types that enable validators to verify
//! block contents without depending on having seen the same network messages.
//!
//! # Proof Types
//!
//! - [`CommitmentProof`]: Proves a transaction was committed on another shard (quorum of provisions)
//!
//! # Usage
//!
//! These proofs are attached to blocks to justify:
//! 1. Including cross-shard transactions that would otherwise be rejected by backpressure
//! 2. Deferring transactions due to livelock cycle detection
//!
//! Without proofs, validators might reject valid blocks simply because they haven't
//! received provisions yet, causing expensive view changes.

use crate::{
    state_provision_message, BlockHeight, Bls12381G2Signature, Hash, NodeId, ShardGroupId,
    SignerBitfield, StateEntry,
};
use sbor::prelude::*;
use std::collections::HashSet;
use std::sync::Arc;

/// Proof that a transaction was committed on another shard.
///
/// Uses BLS signature aggregation for compact representation. This proof enables:
/// 1. **Priority ordering**: TXs with proof are included BEFORE other TXs in blocks
/// 2. **Limit bypass**: TXs with proof can exceed the backpressure limit (1024 cross-shard TXs)
///
/// # Size Optimization
///
/// Before (individual signatures): 67 provisions × 64 bytes = ~4KB signatures + duplicated state
/// After (aggregated): 48 byte bitfield + 48 byte signature + single copy of state entries
///
/// This follows the same pattern used by `QuorumCertificate` and `ExecutionCertificate`.
#[derive(Debug, Clone)]
pub struct CommitmentProof {
    /// The transaction that was committed elsewhere.
    pub tx_hash: Hash,

    /// Source shard that committed the transaction.
    pub source_shard: ShardGroupId,

    /// Target shard that received the provisions (prevents cross-shard replay).
    pub target_shard: ShardGroupId,

    /// Which validators signed (bitfield).
    pub signers: SignerBitfield,

    /// Aggregated BLS signature from all signers.
    pub aggregated_signature: Bls12381G2Signature,

    /// Block height at which the tx was committed on the source shard.
    pub block_height: BlockHeight,

    /// Unix timestamp (milliseconds) of the block that triggered the provisions.
    pub block_timestamp: u64,

    /// The state entries with pre-computed storage keys.
    /// Needed for cycle detection (node overlap checking via StateEntry::node_id()).
    /// Wrapped in Arc for efficient sharing.
    pub entries: Arc<Vec<StateEntry>>,
}

// Manual PartialEq (compare Arc contents, not pointer identity)
impl PartialEq for CommitmentProof {
    fn eq(&self, other: &Self) -> bool {
        self.tx_hash == other.tx_hash
            && self.source_shard == other.source_shard
            && self.target_shard == other.target_shard
            && self.signers == other.signers
            && self.aggregated_signature == other.aggregated_signature
            && self.block_height == other.block_height
            && self.block_timestamp == other.block_timestamp
            && *self.entries == *other.entries
    }
}

impl Eq for CommitmentProof {}

// ============================================================================
// Manual SBOR implementation (since Arc doesn't derive BasicSbor)
// ============================================================================

impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for CommitmentProof
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(8)?;
        encoder.encode(&self.tx_hash)?;
        encoder.encode(&self.source_shard)?;
        encoder.encode(&self.target_shard)?;
        encoder.encode(&self.signers)?;
        encoder.encode(&self.aggregated_signature)?;
        encoder.encode(&self.block_height)?;
        encoder.encode(&self.block_timestamp)?;
        // Entries: encode the inner Vec directly (unwrap Arc)
        encoder.encode(self.entries.as_ref())?;
        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for CommitmentProof
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: sbor::ValueKind<sbor::NoCustomValueKind>,
    ) -> Result<Self, sbor::DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, sbor::ValueKind::Tuple)?;
        let length = decoder.read_size()?;

        if length != 8 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 8,
                actual: length,
            });
        }

        let tx_hash: Hash = decoder.decode()?;
        let source_shard: ShardGroupId = decoder.decode()?;
        let target_shard: ShardGroupId = decoder.decode()?;
        let signers: SignerBitfield = decoder.decode()?;
        let aggregated_signature: Bls12381G2Signature = decoder.decode()?;
        let block_height: BlockHeight = decoder.decode()?;
        let block_timestamp: u64 = decoder.decode()?;
        // Entries: decode Vec and wrap in Arc
        let entries: Vec<StateEntry> = decoder.decode()?;

        Ok(Self {
            tx_hash,
            source_shard,
            target_shard,
            signers,
            aggregated_signature,
            block_height,
            block_timestamp,
            entries: Arc::new(entries),
        })
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for CommitmentProof {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for CommitmentProof {
    const TYPE_ID: sbor::RustTypeId =
        sbor::RustTypeId::novel_with_code("CommitmentProof", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

impl CommitmentProof {
    /// Create a new commitment proof.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx_hash: Hash,
        source_shard: ShardGroupId,
        target_shard: ShardGroupId,
        signers: SignerBitfield,
        aggregated_signature: Bls12381G2Signature,
        block_height: BlockHeight,
        block_timestamp: u64,
        entries: Vec<StateEntry>,
    ) -> Self {
        Self {
            tx_hash,
            source_shard,
            target_shard,
            signers,
            aggregated_signature,
            block_height,
            block_timestamp,
            entries: Arc::new(entries),
        }
    }

    /// Get the nodes referenced in this proof.
    ///
    /// Used by livelock for cycle detection (node overlap checking).
    pub fn nodes(&self) -> HashSet<NodeId> {
        self.entries.iter().filter_map(|e| e.node_id()).collect()
    }

    /// Get the number of signers in this proof.
    pub fn signer_count(&self) -> usize {
        self.signers.count()
    }

    /// Get indices of validators who signed.
    pub fn signer_indices(&self) -> Vec<usize> {
        self.signers.set_indices().collect()
    }

    /// Build the canonical signing message for this proof.
    ///
    /// Uses `DOMAIN_STATE_PROVISION` tag for domain separation.
    /// This is the same message that validators sign when creating provisions.
    pub fn signing_message(&self) -> Vec<u8> {
        let entry_hashes: Vec<Hash> = self.entries.iter().map(|e| e.hash()).collect();
        state_provision_message(
            &self.tx_hash,
            self.target_shard,
            self.source_shard,
            self.block_height,
            self.block_timestamp,
            &entry_hashes,
        )
    }

    /// Compute a hash of all entries for comparison purposes.
    pub fn entries_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        for entry in self.entries.iter() {
            hasher.update(entry.hash().as_bytes());
        }
        Hash::from_bytes(hasher.finalize().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{zero_bls_signature, DOMAIN_STATE_PROVISION};

    /// Create a test StateEntry with a valid storage key format.
    ///
    /// Storage key format: RADIX_PREFIX (6) + hash_prefix (20) + node_id (30) + partition (1) + sort_key
    fn test_entry(seed: u8) -> StateEntry {
        // Build a valid storage key
        let mut storage_key = Vec::with_capacity(6 + 20 + 30 + 1 + 1);
        storage_key.extend_from_slice(b"radix:"); // RADIX_PREFIX (6 bytes)
        storage_key.extend_from_slice(&[0u8; 20]); // hash prefix (20 bytes)
        storage_key.extend_from_slice(&[seed; 30]); // node_id (30 bytes)
        storage_key.push(0); // partition
        storage_key.push(seed); // sort_key

        StateEntry::new(storage_key, Some(vec![seed, seed + 1]))
    }

    #[test]
    fn test_commitment_proof_nodes() {
        let entries = vec![test_entry(1), test_entry(2), test_entry(3)];

        let proof = CommitmentProof::new(
            Hash::from_bytes(b"tx_hash"),
            ShardGroupId(0),
            ShardGroupId(1),
            SignerBitfield::new(10),
            zero_bls_signature(),
            BlockHeight(100),
            1000,
            entries,
        );

        let nodes = proof.nodes();
        assert_eq!(nodes.len(), 3);
        assert!(nodes.contains(&NodeId([1; 30])));
        assert!(nodes.contains(&NodeId([2; 30])));
        assert!(nodes.contains(&NodeId([3; 30])));
    }

    #[test]
    fn test_commitment_proof_signing_message_deterministic() {
        let entries = vec![test_entry(1)];
        let proof = CommitmentProof::new(
            Hash::from_bytes(b"tx_hash"),
            ShardGroupId(0),
            ShardGroupId(1),
            SignerBitfield::new(10),
            zero_bls_signature(),
            BlockHeight(100),
            1000,
            entries,
        );

        let msg1 = proof.signing_message();
        let msg2 = proof.signing_message();
        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_STATE_PROVISION));
    }

    #[test]
    fn test_commitment_proof_serialization_roundtrip() {
        let entries = vec![test_entry(1), test_entry(2)];
        let original = CommitmentProof::new(
            Hash::from_bytes(b"tx_hash"),
            ShardGroupId(1),
            ShardGroupId(2),
            SignerBitfield::new(5),
            zero_bls_signature(),
            BlockHeight(50),
            1000,
            entries,
        );

        // Serialize
        let bytes = sbor::basic_encode(&original).expect("encoding should succeed");

        // Deserialize
        let decoded: CommitmentProof = sbor::basic_decode(&bytes).expect("decoding should succeed");

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_signer_count() {
        let mut signers = SignerBitfield::new(10);
        signers.set(0);
        signers.set(3);
        signers.set(7);

        let proof = CommitmentProof::new(
            Hash::from_bytes(b"tx"),
            ShardGroupId(0),
            ShardGroupId(1),
            signers,
            zero_bls_signature(),
            BlockHeight(1),
            1000,
            vec![],
        );

        assert_eq!(proof.signer_count(), 3);
        assert_eq!(proof.signer_indices(), vec![0, 3, 7]);
    }

    #[test]
    fn test_entries_hash_deterministic() {
        let entries = vec![test_entry(1), test_entry(2)];
        let proof = CommitmentProof::new(
            Hash::from_bytes(b"tx"),
            ShardGroupId(0),
            ShardGroupId(1),
            SignerBitfield::new(10),
            zero_bls_signature(),
            BlockHeight(1),
            1000,
            entries,
        );

        let hash1 = proof.entries_hash();
        let hash2 = proof.entries_hash();
        assert_eq!(hash1, hash2);
    }
}
