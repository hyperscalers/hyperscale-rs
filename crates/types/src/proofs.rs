//! Proof types for Byzantine-safe backpressure and livelock handling.
//!
//! This module contains cryptographic proof types that enable validators to verify
//! block contents without depending on having seen the same network messages.
//!
//! # Proof Types
//!
//! - [`CommitmentProof`]: Proves a transaction was committed on another shard (quorum of provisions)
//! - [`CycleProof`]: Proves a livelock cycle exists (wraps CommitmentProof + shows node overlap)
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
    BlockHeight, Bls12381G2Signature, Hash, NodeId, ShardGroupId, SignerBitfield, StateEntry,
};
use sbor::prelude::*;
use std::collections::HashSet;
use std::sync::Arc;

/// Domain tag for commitment proof signatures.
///
/// Format: `COMMITMENT_PROOF` || tx_hash || source_shard || height || entries_hash
pub const DOMAIN_COMMITMENT_PROOF: &[u8] = b"COMMITMENT_PROOF";

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
/// This follows the same pattern used by `QuorumCertificate` and `StateCertificate`.
#[derive(Debug, Clone)]
pub struct CommitmentProof {
    /// The transaction that was committed elsewhere.
    pub tx_hash: Hash,

    /// Source shard that committed the transaction.
    pub source_shard: ShardGroupId,

    /// Which validators signed (bitfield).
    pub signers: SignerBitfield,

    /// Aggregated BLS signature from all signers.
    pub aggregated_signature: Bls12381G2Signature,

    /// Block height at which the tx was committed on the source shard.
    pub block_height: BlockHeight,

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
            && self.signers == other.signers
            && self.aggregated_signature == other.aggregated_signature
            && self.block_height == other.block_height
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
        encoder.write_size(6)?;
        encoder.encode(&self.tx_hash)?;
        encoder.encode(&self.source_shard)?;
        encoder.encode(&self.signers)?;
        encoder.encode(&self.aggregated_signature)?;
        encoder.encode(&self.block_height)?;
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

        if length != 6 {
            return Err(sbor::DecodeError::UnexpectedSize {
                expected: 6,
                actual: length,
            });
        }

        let tx_hash: Hash = decoder.decode()?;
        let source_shard: ShardGroupId = decoder.decode()?;
        let signers: SignerBitfield = decoder.decode()?;
        let aggregated_signature: Bls12381G2Signature = decoder.decode()?;
        let block_height: BlockHeight = decoder.decode()?;
        // Entries: decode Vec and wrap in Arc
        let entries: Vec<StateEntry> = decoder.decode()?;

        Ok(Self {
            tx_hash,
            source_shard,
            signers,
            aggregated_signature,
            block_height,
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
    pub fn new(
        tx_hash: Hash,
        source_shard: ShardGroupId,
        signers: SignerBitfield,
        aggregated_signature: Bls12381G2Signature,
        block_height: BlockHeight,
        entries: Vec<StateEntry>,
    ) -> Self {
        Self {
            tx_hash,
            source_shard,
            signers,
            aggregated_signature,
            block_height,
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

    /// Create the signing message for this proof.
    ///
    /// This is the message that was signed by validators to create provisions.
    /// The aggregated signature verifies against this message.
    pub fn signing_message(&self) -> Vec<u8> {
        let entry_hashes: Vec<Hash> = self.entries.iter().map(|e| e.hash()).collect();
        commitment_proof_message(
            &self.tx_hash,
            self.source_shard,
            self.block_height,
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

/// Build the signing message for a commitment proof.
///
/// This uses the same format as state provisions since commitment proofs
/// aggregate provision signatures.
pub fn commitment_proof_message(
    tx_hash: &Hash,
    source_shard: ShardGroupId,
    block_height: BlockHeight,
    entry_hashes: &[Hash],
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(DOMAIN_COMMITMENT_PROOF);
    msg.extend_from_slice(tx_hash.as_bytes());
    msg.extend_from_slice(&source_shard.0.to_le_bytes());
    msg.extend_from_slice(&block_height.0.to_le_bytes());

    for hash in entry_hashes {
        msg.extend_from_slice(hash.as_bytes());
    }

    msg
}

/// Proof that a livelock cycle exists, justifying a transaction deferral.
///
/// This proof demonstrates that:
/// 1. The winner transaction was committed on another shard (has valid CommitmentProof)
/// 2. The winner has a lower hash than the loser (deterministic winner selection)
/// 3. The winner and loser have overlapping nodes (actual conflict exists)
///
/// # Minimal Design
///
/// The proof is intentionally minimal - just enough to prove the cycle exists:
/// - The winner TX hash
/// - Provisions from the winner proving it's waiting on overlapping nodes
/// - Signatures already embedded in the CommitmentProof
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CycleProof {
    /// The winning transaction (has lower hash).
    pub winner_tx_hash: Hash,

    /// Proof that the winner was committed on another shard.
    /// Contains the aggregated signature and state entries.
    pub winner_commitment: CommitmentProof,
}

impl CycleProof {
    /// Create a new cycle proof.
    pub fn new(winner_tx_hash: Hash, winner_commitment: CommitmentProof) -> Self {
        Self {
            winner_tx_hash,
            winner_commitment,
        }
    }

    /// Get the nodes involved in the winner transaction.
    ///
    /// Used to verify overlap with the loser transaction.
    pub fn winner_nodes(&self) -> HashSet<NodeId> {
        self.winner_commitment.nodes()
    }

    /// Get the source shard of the winner commitment.
    pub fn winner_source_shard(&self) -> ShardGroupId {
        self.winner_commitment.source_shard
    }
}

// ============================================================================
// Manual SBOR for CycleProof (since it contains CommitmentProof with Arc)
// ============================================================================

impl<E: sbor::Encoder<sbor::NoCustomValueKind>> sbor::Encode<sbor::NoCustomValueKind, E>
    for CycleProof
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_value_kind(sbor::ValueKind::Tuple)
    }

    fn encode_body(&self, encoder: &mut E) -> Result<(), sbor::EncodeError> {
        encoder.write_size(2)?;
        encoder.encode(&self.winner_tx_hash)?;
        encoder.encode(&self.winner_commitment)?;
        Ok(())
    }
}

impl<D: sbor::Decoder<sbor::NoCustomValueKind>> sbor::Decode<sbor::NoCustomValueKind, D>
    for CycleProof
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

        let winner_tx_hash: Hash = decoder.decode()?;
        let winner_commitment: CommitmentProof = decoder.decode()?;

        Ok(Self {
            winner_tx_hash,
            winner_commitment,
        })
    }
}

impl sbor::Categorize<sbor::NoCustomValueKind> for CycleProof {
    fn value_kind() -> sbor::ValueKind<sbor::NoCustomValueKind> {
        sbor::ValueKind::Tuple
    }
}

impl sbor::Describe<sbor::NoCustomTypeKind> for CycleProof {
    const TYPE_ID: sbor::RustTypeId = sbor::RustTypeId::novel_with_code("CycleProof", &[], &[]);

    fn type_data() -> sbor::TypeData<sbor::NoCustomTypeKind, sbor::RustTypeId> {
        sbor::TypeData::unnamed(sbor::TypeKind::Any)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zero_bls_signature;

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
            SignerBitfield::new(10),
            zero_bls_signature(),
            BlockHeight(100),
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
            SignerBitfield::new(10),
            zero_bls_signature(),
            BlockHeight(100),
            entries,
        );

        let msg1 = proof.signing_message();
        let msg2 = proof.signing_message();
        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_COMMITMENT_PROOF));
    }

    #[test]
    fn test_commitment_proof_serialization_roundtrip() {
        let entries = vec![test_entry(1), test_entry(2)];
        let original = CommitmentProof::new(
            Hash::from_bytes(b"tx_hash"),
            ShardGroupId(1),
            SignerBitfield::new(5),
            zero_bls_signature(),
            BlockHeight(50),
            entries,
        );

        // Serialize
        let bytes = sbor::basic_encode(&original).expect("encoding should succeed");

        // Deserialize
        let decoded: CommitmentProof = sbor::basic_decode(&bytes).expect("decoding should succeed");

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_cycle_proof_winner_nodes() {
        let entries = vec![test_entry(5), test_entry(6)];
        let commitment = CommitmentProof::new(
            Hash::from_bytes(b"winner"),
            ShardGroupId(1),
            SignerBitfield::new(10),
            zero_bls_signature(),
            BlockHeight(100),
            entries,
        );

        let proof = CycleProof::new(Hash::from_bytes(b"winner"), commitment);

        let nodes = proof.winner_nodes();
        assert_eq!(nodes.len(), 2);
        assert!(nodes.contains(&NodeId([5; 30])));
        assert!(nodes.contains(&NodeId([6; 30])));
    }

    #[test]
    fn test_cycle_proof_serialization_roundtrip() {
        let entries = vec![test_entry(1)];
        let commitment = CommitmentProof::new(
            Hash::from_bytes(b"winner"),
            ShardGroupId(0),
            SignerBitfield::new(5),
            zero_bls_signature(),
            BlockHeight(100),
            entries,
        );

        let original = CycleProof::new(Hash::from_bytes(b"winner"), commitment);

        // Serialize
        let bytes = sbor::basic_encode(&original).expect("encoding should succeed");

        // Deserialize
        let decoded: CycleProof = sbor::basic_decode(&bytes).expect("decoding should succeed");

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
            signers,
            zero_bls_signature(),
            BlockHeight(1),
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
            SignerBitfield::new(10),
            zero_bls_signature(),
            BlockHeight(1),
            entries,
        );

        let hash1 = proof.entries_hash();
        let hash2 = proof.entries_hash();
        assert_eq!(hash1, hash2);
    }
}
