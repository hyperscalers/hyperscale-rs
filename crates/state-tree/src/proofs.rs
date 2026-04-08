//! Verkle proof generation, verification, and serialization.
//!
//! With the flat single-tree design, proof operations are simple:
//! - Generation: `jvt::verkle_proof::prove(store, root_key, &all_keys)` → single proof
//! - Verification: `jvt::verkle_proof::verify(proof, root_commitment, &keys, &values)` → bool
//!
//! A single ~576-byte multipoint proof covers ALL entries in a block.

use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use hyperscale_types::{Hash, SubstateInclusionProof, VerkleInclusionProof};
use jellyfish_verkle_tree as jvt;

use crate::tree_store::ReadableTreeStore;

// ============================================================================
// JVT VerkleProof serialization
// ============================================================================

/// Serialize a JVT `VerkleProof` to bytes (compact format v2).
///
/// Layout: commitment_table + multipoint_proof + key_data.
/// The verifier reconstructs opening triples from the commitment table
/// and per-key metadata, eliminating redundant results and eval points.
pub fn serialize_verkle_proof(proof: &jvt::verkle_proof::VerkleProof) -> Vec<u8> {
    let mut buf = Vec::with_capacity(proof.total_byte_size() + 64);

    // Commitment table (deduplicated)
    write_u32(&mut buf, proof.commitments.len() as u32);
    for comm in &proof.commitments {
        write_point(&mut buf, comm);
    }

    // Multipoint proof
    write_point(&mut buf, &proof.multipoint_proof.d_comm);
    let ipa = &proof.multipoint_proof.ipa_proof;
    write_u32(&mut buf, ipa.l_vec.len() as u32);
    for (l, r) in ipa.l_vec.iter().zip(ipa.r_vec.iter()) {
        write_point(&mut buf, l);
        write_point(&mut buf, r);
    }
    write_scalar(&mut buf, &ipa.a_scalar);

    // Key data
    write_u32(&mut buf, proof.key_data.len() as u32);
    for kd in &proof.key_data {
        buf.extend_from_slice(&kd.key); // fixed 32 bytes
        match &kd.value {
            Some(v) => {
                buf.push(1);
                write_scalar(&mut buf, &v.0);
            }
            None => buf.push(0),
        }
        buf.push(kd.depth);
        // commitment_path: Vec<u16>
        write_u32(&mut buf, kd.commitment_path.len() as u32);
        for &idx in &kd.commitment_path {
            buf.extend_from_slice(&idx.to_le_bytes());
        }
        match &kd.termination {
            jvt::verkle_proof::TerminationKind::FoundEaS => buf.push(0),
            jvt::verkle_proof::TerminationKind::EmptySlot => buf.push(1),
            jvt::verkle_proof::TerminationKind::StemMismatch {
                diverge_byte,
                actual_stem_byte,
            } => {
                buf.push(2);
                buf.push(*diverge_byte as u8);
                match actual_stem_byte {
                    Some(b) => {
                        buf.push(1);
                        buf.push(*b);
                    }
                    None => buf.push(0),
                }
            }
        }
    }

    buf
}

/// Deserialize a JVT `VerkleProof` from bytes (compact format v2).
pub fn deserialize_verkle_proof(
    data: &[u8],
) -> Result<jvt::verkle_proof::VerkleProof, ProofDeserializeError> {
    let mut cursor = Cursor::new(data);

    // Commitment table
    let num_commitments = cursor.read_u32()? as usize;
    let mut commitments = Vec::with_capacity(num_commitments);
    for _ in 0..num_commitments {
        commitments.push(cursor.read_point()?);
    }

    // Multipoint proof
    let d_comm = cursor.read_point()?;
    let num_rounds = cursor.read_u32()? as usize;
    let mut l_vec = Vec::with_capacity(num_rounds);
    let mut r_vec = Vec::with_capacity(num_rounds);
    for _ in 0..num_rounds {
        l_vec.push(cursor.read_point()?);
        r_vec.push(cursor.read_point()?);
    }
    let a_scalar = cursor.read_scalar()?;

    let ipa_proof = jvt::multiproof::ipa::IPAProof {
        l_vec,
        r_vec,
        a_scalar,
    };
    let multipoint_proof = jvt::multiproof::prover::MultiPointProof { ipa_proof, d_comm };

    // Key data
    let num_keys = cursor.read_u32()? as usize;
    let mut key_data = Vec::with_capacity(num_keys);
    for _ in 0..num_keys {
        let key_bytes = cursor.read_bytes(32)?;
        let key: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| ProofDeserializeError::InvalidData)?;
        let has_value = cursor.read_u8()?;
        let value = if has_value == 1 {
            let scalar = cursor.read_scalar()?;
            Some(jvt::commitment::FieldElement(scalar))
        } else {
            None
        };
        let depth = cursor.read_u8()?;
        let num_path = cursor.read_u32()? as usize;
        let mut commitment_path = Vec::with_capacity(num_path);
        for _ in 0..num_path {
            let idx_bytes = cursor.read_bytes(2)?;
            commitment_path.push(u16::from_le_bytes([idx_bytes[0], idx_bytes[1]]));
        }
        let termination_tag = cursor.read_u8()?;
        let termination = match termination_tag {
            0 => jvt::verkle_proof::TerminationKind::FoundEaS,
            1 => jvt::verkle_proof::TerminationKind::EmptySlot,
            2 => {
                let diverge_byte = cursor.read_u8()? as usize;
                let has_actual = cursor.read_u8()?;
                let actual_stem_byte = if has_actual == 1 {
                    Some(cursor.read_u8()?)
                } else {
                    None
                };
                jvt::verkle_proof::TerminationKind::StemMismatch {
                    diverge_byte,
                    actual_stem_byte,
                }
            }
            _ => return Err(ProofDeserializeError::InvalidData),
        };

        key_data.push(jvt::verkle_proof::KeyProofData {
            key,
            value,
            depth,
            commitment_path,
            termination,
        });
    }

    Ok(jvt::verkle_proof::VerkleProof {
        multipoint_proof,
        commitments,
        key_data,
    })
}

#[derive(Debug)]
pub enum ProofDeserializeError {
    UnexpectedEof,
    InvalidData,
    ArkError,
}

// ============================================================================
// Proof generation
// ============================================================================

/// Generate an aggregated verkle proof for a set of storage keys.
///
/// Produces a single `SubstateInclusionProof` (~576 bytes) covering ALL entries,
/// regardless of how many keys are provided.
pub fn generate_proof<S: ReadableTreeStore>(
    tree_store: &S,
    storage_keys: &[Vec<u8>],
    block_height: u64,
    node_cache: &crate::NodeCache,
) -> Option<SubstateInclusionProof> {
    let root_key = jvt::NodeKey::root(block_height);

    let jvt_keys: Vec<jvt::Key> = storage_keys
        .iter()
        .map(|sk| crate::hash_storage_key(sk))
        .collect();

    let adapter = crate::StoreAdapter {
        store: tree_store,
        node_cache,
    };

    let proof = jvt::verkle_proof::prove(&adapter, &root_key, &jvt_keys)?;

    Some(VerkleInclusionProof::new(serialize_verkle_proof(&proof)))
}

// ============================================================================
// Proof verification
// ============================================================================

/// Verify an aggregated verkle proof against a state root.
///
/// The proof covers ALL entries in a single multipoint verification.
pub fn verify_proof(
    proof: &SubstateInclusionProof,
    entries: &[hyperscale_types::StateEntry],
    state_root: Hash,
    storage_key_for_entry: impl Fn(&hyperscale_types::StateEntry) -> &[u8],
) -> bool {
    if proof.as_bytes().is_empty() {
        return entries.is_empty();
    }

    let jvt_proof = match deserialize_verkle_proof(proof.as_bytes()) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let state_root_commitment = match bytes_to_commitment_safe(state_root.as_bytes()) {
        Some(c) => c,
        None => return false,
    };

    // Hash keys and convert values to field elements for verification.
    let keys: Vec<jvt::Key> = entries
        .iter()
        .map(|e| crate::hash_storage_key(storage_key_for_entry(e)))
        .collect();

    let values: Vec<Option<jvt::Value>> = entries
        .iter()
        .map(|e| e.value.as_ref().map(|v| jvt::commitment::value_to_field(v)))
        .collect();

    jvt::verkle_proof::verify(&jvt_proof, state_root_commitment, &keys, &values)
}

// ─── Helpers ────────────────────────────────────────────────────────────

fn bytes_to_commitment_safe(bytes: &[u8]) -> Option<jvt::Commitment> {
    let point = EdwardsAffine::deserialize_compressed(bytes).ok()?;
    Some(jvt::Commitment(point))
}

fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_point(buf: &mut Vec<u8>, point: &EdwardsAffine) {
    let mut bytes = [0u8; 32];
    point
        .serialize_compressed(&mut bytes[..])
        .expect("point serialization must succeed");
    buf.extend_from_slice(&bytes);
}

fn write_scalar(buf: &mut Vec<u8>, scalar: &Fr) {
    let mut bytes = [0u8; 32];
    scalar
        .serialize_compressed(&mut bytes[..])
        .expect("scalar serialization must succeed");
    buf.extend_from_slice(&bytes);
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>, ProofDeserializeError> {
        if self.pos + n > self.data.len() {
            return Err(ProofDeserializeError::UnexpectedEof);
        }
        let bytes = self.data[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(bytes)
    }

    fn read_u8(&mut self) -> Result<u8, ProofDeserializeError> {
        if self.pos >= self.data.len() {
            return Err(ProofDeserializeError::UnexpectedEof);
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32, ProofDeserializeError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_point(&mut self) -> Result<EdwardsAffine, ProofDeserializeError> {
        let bytes = self.read_bytes(32)?;
        EdwardsAffine::deserialize_compressed(&bytes[..])
            .map_err(|_| ProofDeserializeError::ArkError)
    }

    fn read_scalar(&mut self) -> Result<Fr, ProofDeserializeError> {
        let bytes = self.read_bytes(32)?;
        Fr::deserialize_compressed(&bytes[..]).map_err(|_| ProofDeserializeError::ArkError)
    }
}
