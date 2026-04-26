//! Batched multiproofs.
//!
//! A multiproof authenticates a batch of keys against a single root hash.
//! It exploits path sharing: sibling hashes are emitted only when they
//! cannot be reconstructed from hashes already in the batch.
//!
//! # Wire shape
//!
//! The proof contains:
//! - One [`ProofClaim`] per claimed key describing how the lookup
//!   terminated (found leaf, empty slot, or divergent leaf) plus the
//!   value hash if present.
//! - A flat list of sibling hashes, ordered for linear consumption by
//!   the verifier (depth-first, bucket-0-first traversal).
//!
//! # Construction
//!
//! 1. Sort claims by key (so paths are visited in deterministic order).
//! 2. Recursively walk down. At each internal node, iterate buckets
//!    `0..ARITY`:
//!    - Bucket contains claimed keys → recurse; collect claims/siblings.
//!    - Bucket has no claimed keys → emit the bucket's child hash as
//!      a sibling.
//! 3. At leaves, emit one [`ProofClaim`] per claimed key.
//!
//! # Verification
//!
//! Walk the same structure bottom-up, rehashing computed subtree roots
//! together with the supplied siblings until a single root hash is
//! derived. Compare against the signed root.

use crate::hasher::{Hash, Hasher, EMPTY_HASH};
use crate::node::{Key, NibblePath, Node, NodeKey, ValueHash};
use crate::storage::TreeReader;
use crate::tree::Tree;

/// A batched proof covering multiple keys against a single root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiProof {
    /// Per-claim termination metadata, in sorted-key order.
    pub claims: Vec<ProofClaim>,

    /// Sibling hashes, in depth-first left-to-right consumption order.
    pub siblings: Vec<Hash>,
}

/// One key's outcome inside a [`MultiProof`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofClaim {
    /// The 32-byte key the claim is about.
    pub key: Key,
    /// `Some` iff the lookup hit a leaf whose key matches.
    pub value_hash: Option<ValueHash>,
    /// Depth (in bits) at which the lookup terminated.
    pub depth_bits: u16,
    /// How the lookup ended (leaf, empty slot, or divergent leaf).
    pub termination: ClaimTermination,
}

/// How a single-key lookup ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimTermination {
    /// Reached a leaf whose key matched.
    Leaf,
    /// Reached an empty child slot — the key is absent.
    EmptySubtree,
    /// Reached a leaf whose key differs — still a valid non-inclusion
    /// proof. Carries the stored leaf's data so the verifier can
    /// reconstruct its hash.
    LeafMismatch {
        /// Key actually stored at the divergent leaf.
        stored_key: Key,
        /// Value hash actually stored at the divergent leaf.
        stored_value_hash: ValueHash,
    },
}

/// Errors produced during proof construction or verification.
#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    /// The supplied root key is not present in storage.
    #[error("root key not found in store")]
    RootMissing,

    /// A node referenced by the walk could not be loaded from storage.
    #[error("node at {key:?} referenced but missing")]
    MissingNode {
        /// Key of the node that could not be loaded.
        key: NodeKey,
    },

    /// The proof reconstructs to a hash that disagrees with the expected root.
    #[error("computed root does not match expected root")]
    RootMismatch,

    /// The proof is internally inconsistent (structurally invalid).
    #[error("malformed proof: {0}")]
    Malformed(&'static str),

    /// The verifier expected a claim the proof does not contain.
    #[error("claim for key not present in proof")]
    MissingClaim,

    /// A claim's stored value disagrees with the verifier's expected value.
    #[error("claim asserts a value the proof does not support")]
    ValueMismatch,
}

impl<H: Hasher, const ARITY_BITS: u8> Tree<H, ARITY_BITS> {
    /// Build a multiproof covering `keys` against the given root.
    ///
    /// Keys are internally sorted and deduplicated. The resulting proof
    /// authenticates each distinct key's value hash (or non-existence).
    /// An empty `keys` slice yields an empty proof.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::RootMissing`] if `root_key` does not resolve
    /// in `store`, or [`ProofError::MissingNode`] if a referenced child
    /// node has been pruned underneath the walk.
    pub fn prove<S>(store: &S, root_key: &NodeKey, keys: &[Key]) -> Result<MultiProof, ProofError>
    where
        S: TreeReader,
    {
        let mut sorted: Vec<Key> = keys.to_vec();
        sorted.sort_unstable();
        sorted.dedup();

        let mut claims = Vec::with_capacity(sorted.len());
        let mut siblings = Vec::new();

        if sorted.is_empty() {
            return Ok(MultiProof { claims, siblings });
        }

        // The caller provided a root key — it must resolve to a node in
        // the store. If not, either the version was never committed or
        // was pruned; in both cases we cannot meaningfully prove against
        // it, and emitting all-EmptySubtree claims would silently pass
        // off a "not available" as "tree is empty".
        if store.get_node(root_key).is_none() {
            return Err(ProofError::RootMissing);
        }

        let claim_refs: Vec<&Key> = sorted.iter().collect();
        prove_rec::<S, H, ARITY_BITS>(store, root_key, &claim_refs, &mut claims, &mut siblings)?;

        Ok(MultiProof { claims, siblings })
    }

    /// Verify a multiproof against an expected root.
    ///
    /// `expected_claims` is the application-level assertion: for each
    /// key the caller asserts what value (or absence) it expects. The
    /// verifier checks both that the proof is self-consistent against
    /// `expected_root` and that the proved results match the caller's
    /// assertions.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::MissingClaim`] when `expected_claims`
    /// names a key the proof does not authenticate;
    /// [`ProofError::ValueMismatch`] when a claim disagrees with the
    /// expected value; [`ProofError::Malformed`] when the proof is
    /// structurally invalid; and [`ProofError::RootMismatch`] when the
    /// reconstructed root differs from `expected_root`.
    pub fn verify(
        proof: &MultiProof,
        expected_root: Hash,
        expected_claims: &[(Key, Option<ValueHash>)],
    ) -> Result<(), ProofError> {
        // Cross-check each expected claim against the proof. Both are
        // keyed by 32-byte keys; sort expected and walk together with
        // proof.claims (which is sorted by prove()).
        let mut expected: Vec<(Key, Option<ValueHash>)> = expected_claims.to_vec();
        expected.sort_by_key(|(k, _)| *k);
        expected.dedup_by_key(|(k, _)| *k);

        // Walk sorted expected claims against sorted proof claims.
        // Proof claims are allowed to be a superset (e.g. the caller
        // might check only some of the batch), but expected must be a
        // subset.
        let mut p = 0usize;
        for (exp_key, exp_val) in &expected {
            while p < proof.claims.len() && proof.claims[p].key < *exp_key {
                p += 1;
            }
            if p >= proof.claims.len() || proof.claims[p].key != *exp_key {
                return Err(ProofError::MissingClaim);
            }
            let c = &proof.claims[p];
            match (exp_val, &c.termination) {
                (Some(v), ClaimTermination::Leaf) => {
                    if c.value_hash.as_ref() != Some(v) {
                        return Err(ProofError::ValueMismatch);
                    }
                }
                (None, ClaimTermination::EmptySubtree | ClaimTermination::LeafMismatch { .. }) => {}
                _ => return Err(ProofError::ValueMismatch),
            }
            p += 1;
        }

        if proof.claims.is_empty() {
            // Nothing to authenticate; conventionally accept only if
            // the caller also expected nothing AND the expected root is
            // EMPTY_HASH. Otherwise the proof is insufficient.
            return if expected.is_empty() && expected_root == EMPTY_HASH {
                Ok(())
            } else {
                Err(ProofError::Malformed("empty proof with non-empty claims"))
            };
        }

        // Reconstruct root by walking the claim topology.
        let mut sib_iter = proof.siblings.iter();
        let computed = verify_rec::<H, ARITY_BITS>(&proof.claims, 0, &mut sib_iter)?;

        if sib_iter.next().is_some() {
            return Err(ProofError::Malformed("trailing siblings"));
        }

        if computed != expected_root {
            return Err(ProofError::RootMismatch);
        }

        Ok(())
    }
}

// ============================================================
// Internal helpers
// ============================================================

/// Extract `count` bits from `key` starting at bit offset `depth_bits`
/// from the MSB.
fn bits_at(key: &Key, depth_bits: u16, count: u8) -> u8 {
    debug_assert!(count <= 8);
    debug_assert!(depth_bits as usize + count as usize <= 256);

    let byte = (depth_bits / 8) as usize;
    let off = (depth_bits % 8) as usize;
    let hi = u16::from(key[byte]);
    let lo = u16::from(*key.get(byte + 1).unwrap_or(&0));
    let combined = (hi << 8) | lo;
    let shift = 16 - off - count as usize;
    let mask = (1u16 << count) - 1;
    u8::try_from((combined >> shift) & mask).unwrap_or(u8::MAX)
}

fn child_path(parent: &NibblePath, bucket: u8, count: u8) -> NibblePath {
    let mut p = parent.clone();
    p.push_bits(bucket, count);
    p
}

fn termination_hash<H: Hasher>(claim: &ProofClaim) -> Hash {
    match &claim.termination {
        ClaimTermination::Leaf => {
            // value_hash must be Some for Leaf; validated at construction.
            let vh = claim
                .value_hash
                .unwrap_or_else(|| panic!("Leaf claim missing value_hash"));
            H::hash_leaf(&claim.key, &vh)
        }
        ClaimTermination::EmptySubtree => EMPTY_HASH,
        ClaimTermination::LeafMismatch {
            stored_key,
            stored_value_hash,
        } => H::hash_leaf(stored_key, stored_value_hash),
    }
}

fn prove_rec<S, H, const ARITY_BITS: u8>(
    store: &S,
    node_key: &NodeKey,
    claim_keys: &[&Key],
    claims_out: &mut Vec<ProofClaim>,
    siblings_out: &mut Vec<Hash>,
) -> Result<(), ProofError>
where
    S: TreeReader,
    H: Hasher,
{
    let node = store
        .get_node(node_key)
        .ok_or_else(|| ProofError::MissingNode {
            key: node_key.clone(),
        })?;
    let depth = node_key.path.len();

    match &*node {
        Node::Leaf(leaf) => {
            // All claimed keys routed to this leaf terminate here.
            for key in claim_keys {
                let (termination, value_hash) = if **key == leaf.key {
                    (ClaimTermination::Leaf, Some(leaf.value_hash))
                } else {
                    (
                        ClaimTermination::LeafMismatch {
                            stored_key: leaf.key,
                            stored_value_hash: leaf.value_hash,
                        },
                        None,
                    )
                };
                claims_out.push(ProofClaim {
                    key: **key,
                    value_hash,
                    depth_bits: depth,
                    termination,
                });
            }
            Ok(())
        }
        Node::Internal(internal) => {
            let arity = 1usize << ARITY_BITS as usize;
            let mut pos = 0usize;
            for bucket in 0..arity {
                let start = pos;
                while pos < claim_keys.len()
                    && bits_at(claim_keys[pos], depth, ARITY_BITS) as usize == bucket
                {
                    pos += 1;
                }
                let claimed_here = pos > start;
                let child = internal.children.get(bucket).and_then(|c| c.as_ref());

                if claimed_here {
                    let bucket_byte = u8::try_from(bucket).unwrap_or(u8::MAX);
                    if let Some(child) = child {
                        let sub_path = child_path(&node_key.path, bucket_byte, ARITY_BITS);
                        let sub_key = NodeKey::new(child.version, sub_path);
                        prove_rec::<S, H, ARITY_BITS>(
                            store,
                            &sub_key,
                            &claim_keys[start..pos],
                            claims_out,
                            siblings_out,
                        )?;
                    } else {
                        // Claimed path hits empty slot — emit non-inclusion.
                        for key in &claim_keys[start..pos] {
                            claims_out.push(ProofClaim {
                                key: **key,
                                value_hash: None,
                                depth_bits: depth + u16::from(ARITY_BITS),
                                termination: ClaimTermination::EmptySubtree,
                            });
                        }
                    }
                } else {
                    // Unclaimed bucket → emit sibling for verifier.
                    let sibling_hash = child.map_or(EMPTY_HASH, |c| c.hash);
                    siblings_out.push(sibling_hash);
                }
            }
            Ok(())
        }
    }
}

fn verify_rec<H, const ARITY_BITS: u8>(
    claims: &[ProofClaim],
    depth: u16,
    siblings: &mut std::slice::Iter<'_, Hash>,
) -> Result<Hash, ProofError>
where
    H: Hasher,
{
    debug_assert!(!claims.is_empty());

    // Terminal: all claims pinpoint the current depth.
    let all_terminal = claims.iter().all(|c| c.depth_bits == depth);
    let any_terminal = claims.iter().any(|c| c.depth_bits == depth);
    if any_terminal && !all_terminal {
        return Err(ProofError::Malformed(
            "mixed termination depths at same subtree",
        ));
    }
    if all_terminal {
        // All claims must agree on the termination content. We derive
        // the hash from the first claim; consistency checking across
        // claims is left to the application layer (expected_claims
        // matching in verify()).
        return Ok(termination_hash::<H>(&claims[0]));
    }

    // Non-terminal: split claims by bucket at this depth.
    let arity = 1usize << ARITY_BITS as usize;
    let mut children: Vec<Hash> = vec![EMPTY_HASH; arity];
    let mut pos = 0usize;
    for (bucket, child) in children.iter_mut().enumerate() {
        let start = pos;
        while pos < claims.len() && bits_at(&claims[pos].key, depth, ARITY_BITS) as usize == bucket
        {
            pos += 1;
        }
        if pos > start {
            *child = verify_rec::<H, ARITY_BITS>(
                &claims[start..pos],
                depth + u16::from(ARITY_BITS),
                siblings,
            )?;
        } else {
            *child = *siblings.next().ok_or(ProofError::Malformed(
                "not enough siblings to reconstruct internal node",
            ))?;
        }
    }
    if pos != claims.len() {
        return Err(ProofError::Malformed("claims not covered by bucket split"));
    }
    Ok(H::hash_internal(&children))
}

// ============================================================
// Wire format
// ============================================================
//
// A multiproof serializes to a canonical byte sequence with a one-byte
// version prefix so decoders can cleanly reject future formats.
//
// ```text
// byte 0       : version (u8) = 0x01
// bytes 1..5   : claim_count (u32 big-endian)
// bytes 5..    : claim_count × claim
// next 4 bytes : sibling_count (u32 big-endian)
// then         : sibling_count × hash (32 bytes each)
// ```
//
// A claim has the layout:
//
// ```text
// 32 bytes : key
// 2 bytes  : depth_bits (u16 big-endian)
// 1 byte   : termination discriminator
// ...      : termination-specific body:
//              0x01 Leaf          → 32 bytes value_hash
//              0x02 EmptySubtree  → (no additional data)
//              0x03 LeafMismatch  → 32 bytes stored_key ||
//                                   32 bytes stored_value_hash
// ```
//
// Invariants enforced by the decoder:
// - `version` must equal `0x01` (other values yield `UnsupportedVersion`).
// - The buffer must be fully consumed (`TrailingBytes` otherwise).
// - Every length claimed in a count prefix must fit in the buffer
//   (`Truncated` otherwise).
// - The termination discriminator must be one of the three defined
//   values (`InvalidTermination` otherwise).
//
// Note: the decoder does NOT cross-check the structural validity of the
// decoded proof against a root or key set. Use [`Tree::verify`] for that.

const WIRE_VERSION: u8 = 0x01;
const TERM_LEAF: u8 = 0x01;
const TERM_EMPTY: u8 = 0x02;
const TERM_LEAF_MISMATCH: u8 = 0x03;

/// Errors produced by [`MultiProof::decode`].
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    /// Wire-format version byte is not [`WIRE_VERSION`].
    #[error("unsupported proof format version {0:#04x}")]
    UnsupportedVersion(u8),

    /// Buffer ended before the decode could finish.
    #[error("buffer truncated — not enough bytes to decode")]
    Truncated,

    /// Decode succeeded but bytes remain past the structured payload.
    #[error("trailing bytes after successful decode")]
    TrailingBytes,

    /// A claim's termination discriminator is not one of the defined values.
    #[error("unknown termination discriminator {0:#04x}")]
    InvalidTermination(u8),
}

impl MultiProof {
    /// Encode this proof to the canonical wire format.
    ///
    /// See the module-level wire format documentation for the exact
    /// layout. The output is deterministic: the same `MultiProof`
    /// always produces the same bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_size_hint());
        buf.push(WIRE_VERSION);
        buf.extend_from_slice(
            &u32::try_from(self.claims.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for claim in &self.claims {
            encode_claim(claim, &mut buf);
        }
        buf.extend_from_slice(
            &u32::try_from(self.siblings.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for sib in &self.siblings {
            buf.extend_from_slice(sib);
        }
        buf
    }

    /// Decode a proof from the canonical wire format.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if the version byte is unrecognized, the
    /// buffer is truncated mid-claim, a claim carries an unknown
    /// termination discriminator, or unexpected trailing bytes follow
    /// the structured payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = ByteReader::new(bytes);
        let version = r.u8()?;
        if version != WIRE_VERSION {
            return Err(DecodeError::UnsupportedVersion(version));
        }
        let claim_count = r.u32_be()? as usize;
        let mut claims = Vec::with_capacity(claim_count);
        for _ in 0..claim_count {
            claims.push(decode_claim(&mut r)?);
        }
        let sibling_count = r.u32_be()? as usize;
        let mut siblings = Vec::with_capacity(sibling_count);
        for _ in 0..sibling_count {
            siblings.push(r.bytes32()?);
        }
        if !r.is_empty() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(Self { claims, siblings })
    }

    fn encoded_size_hint(&self) -> usize {
        let claims_bytes: usize = self
            .claims
            .iter()
            .map(|c| {
                32 + 2
                    + 1
                    + match c.termination {
                        ClaimTermination::Leaf => 32,
                        ClaimTermination::EmptySubtree => 0,
                        ClaimTermination::LeafMismatch { .. } => 64,
                    }
            })
            .sum();
        1 + 4 + claims_bytes + 4 + self.siblings.len() * 32
    }
}

fn encode_claim(claim: &ProofClaim, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&claim.key);
    buf.extend_from_slice(&claim.depth_bits.to_be_bytes());
    match &claim.termination {
        ClaimTermination::Leaf => {
            buf.push(TERM_LEAF);
            // Leaf claims carry their value_hash out-of-band in
            // `claim.value_hash` — a debug-time invariant we check
            // rather than fall back on silently.
            let vh = claim
                .value_hash
                .expect("invariant: Leaf claim must carry value_hash");
            buf.extend_from_slice(&vh);
        }
        ClaimTermination::EmptySubtree => {
            buf.push(TERM_EMPTY);
        }
        ClaimTermination::LeafMismatch {
            stored_key,
            stored_value_hash,
        } => {
            buf.push(TERM_LEAF_MISMATCH);
            buf.extend_from_slice(stored_key);
            buf.extend_from_slice(stored_value_hash);
        }
    }
}

fn decode_claim(r: &mut ByteReader) -> Result<ProofClaim, DecodeError> {
    let key = r.bytes32()?;
    let depth_bits = r.u16_be()?;
    let disc = r.u8()?;
    let (termination, value_hash) = match disc {
        TERM_LEAF => {
            let vh = r.bytes32()?;
            (ClaimTermination::Leaf, Some(vh))
        }
        TERM_EMPTY => (ClaimTermination::EmptySubtree, None),
        TERM_LEAF_MISMATCH => {
            let sk = r.bytes32()?;
            let svh = r.bytes32()?;
            (
                ClaimTermination::LeafMismatch {
                    stored_key: sk,
                    stored_value_hash: svh,
                },
                None,
            )
        }
        other => return Err(DecodeError::InvalidTermination(other)),
    };
    Ok(ProofClaim {
        key,
        value_hash,
        depth_bits,
        termination,
    })
}

/// Minimal byte reader with explicit truncation signaling.
struct ByteReader<'a> {
    bytes: &'a [u8],
}

impl<'a> ByteReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        if self.bytes.is_empty() {
            return Err(DecodeError::Truncated);
        }
        let b = self.bytes[0];
        self.bytes = &self.bytes[1..];
        Ok(b)
    }

    fn u16_be(&mut self) -> Result<u16, DecodeError> {
        if self.bytes.len() < 2 {
            return Err(DecodeError::Truncated);
        }
        let n = u16::from_be_bytes([self.bytes[0], self.bytes[1]]);
        self.bytes = &self.bytes[2..];
        Ok(n)
    }

    fn u32_be(&mut self) -> Result<u32, DecodeError> {
        if self.bytes.len() < 4 {
            return Err(DecodeError::Truncated);
        }
        let n = u32::from_be_bytes([self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]]);
        self.bytes = &self.bytes[4..];
        Ok(n)
    }

    fn bytes32(&mut self) -> Result<[u8; 32], DecodeError> {
        if self.bytes.len() < 32 {
            return Err(DecodeError::Truncated);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.bytes[..32]);
        self.bytes = &self.bytes[32..];
        Ok(arr)
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::Blake3Hasher;
    use crate::storage::MemoryStore;
    use crate::tree::Tree;
    use std::collections::BTreeMap;

    type Jmt = Tree<Blake3Hasher, 1>;

    fn k(b: u8) -> Key {
        let mut key = [0u8; 32];
        key[0] = b;
        key
    }

    fn v(b: u8) -> ValueHash {
        [b; 32]
    }

    fn build_store(entries: &[(Key, ValueHash)]) -> (MemoryStore, NodeKey, Hash) {
        let mut store = MemoryStore::new();
        let updates: BTreeMap<Key, Option<ValueHash>> =
            entries.iter().map(|(k, v)| (*k, Some(*v))).collect();
        let res = Jmt::apply_updates(&store, None, 1, &updates).unwrap();
        store.apply(&res);
        let root = store.get_root_key(1).unwrap();
        (store, root, res.root_hash)
    }

    #[test]
    fn prove_and_verify_single_inclusion() {
        let (store, root, root_hash) = build_store(&[(k(1), v(10)), (k(2), v(20))]);
        let proof = Jmt::prove(&store, &root, &[k(1)]).unwrap();
        Jmt::verify(&proof, root_hash, &[(k(1), Some(v(10)))]).unwrap();
    }

    #[test]
    fn prove_and_verify_batch_inclusion() {
        let entries: Vec<(Key, ValueHash)> = (0u8..8).map(|i| (k(i), v(i * 10))).collect();
        let (store, root, root_hash) = build_store(&entries);

        let keys: Vec<Key> = entries.iter().map(|(k, _)| *k).collect();
        let proof = Jmt::prove(&store, &root, &keys).unwrap();
        let expected: Vec<(Key, Option<ValueHash>)> =
            entries.iter().map(|(k, v)| (*k, Some(*v))).collect();
        Jmt::verify(&proof, root_hash, &expected).unwrap();
    }

    #[test]
    fn prove_and_verify_non_inclusion() {
        let (store, root, root_hash) = build_store(&[(k(1), v(10)), (k(2), v(20))]);
        // k(99) isn't in the tree.
        let proof = Jmt::prove(&store, &root, &[k(99)]).unwrap();
        Jmt::verify(&proof, root_hash, &[(k(99), None)]).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_value() {
        let (store, root, root_hash) = build_store(&[(k(1), v(10))]);
        let proof = Jmt::prove(&store, &root, &[k(1)]).unwrap();
        let err = Jmt::verify(&proof, root_hash, &[(k(1), Some(v(99)))]).unwrap_err();
        assert!(matches!(err, ProofError::ValueMismatch));
    }

    #[test]
    fn verify_rejects_wrong_root() {
        let (store, root, _root_hash) = build_store(&[(k(1), v(10))]);
        let proof = Jmt::prove(&store, &root, &[k(1)]).unwrap();
        let err = Jmt::verify(&proof, [0xAA; 32], &[(k(1), Some(v(10)))]).unwrap_err();
        assert!(matches!(err, ProofError::RootMismatch));
    }

    #[test]
    fn verify_rejects_tampered_sibling() {
        let (store, root, root_hash) =
            build_store(&[(k(1), v(10)), (k(2), v(20)), (k(3), v(30)), (k(4), v(40))]);
        let mut proof = Jmt::prove(&store, &root, &[k(1)]).unwrap();
        if let Some(sib) = proof.siblings.first_mut() {
            sib[0] ^= 0xFF;
        }
        let err = Jmt::verify(&proof, root_hash, &[(k(1), Some(v(10)))]).unwrap_err();
        assert!(matches!(err, ProofError::RootMismatch));
    }

    #[test]
    fn mixed_inclusion_and_non_inclusion() {
        let (store, root, root_hash) = build_store(&[(k(1), v(10)), (k(2), v(20)), (k(3), v(30))]);
        let proof = Jmt::prove(&store, &root, &[k(1), k(99), k(3)]).unwrap();
        Jmt::verify(
            &proof,
            root_hash,
            &[(k(1), Some(v(10))), (k(3), Some(v(30))), (k(99), None)],
        )
        .unwrap();
    }

    #[test]
    fn prove_against_empty_tree_errors() {
        // Proving against a non-existent root now returns RootMissing,
        // so callers can distinguish "unavailable" from "genuinely empty".
        let store = MemoryStore::new();
        let root = NodeKey::root(1);
        let err = Jmt::prove(&store, &root, &[k(1)]).unwrap_err();
        assert!(matches!(err, ProofError::RootMissing));
    }

    #[test]
    fn deep_prefix_divergence_proof() {
        // Two keys sharing a long prefix — exercises binary chain.
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        for i in 0..20 {
            k1[i] = 0xAB;
            k2[i] = 0xAB;
        }
        k1[20] = 0x00;
        k2[20] = 0xFF;

        let (store, root, root_hash) = build_store(&[(k1, v(1)), (k2, v(2))]);
        let proof = Jmt::prove(&store, &root, &[k1]).unwrap();
        Jmt::verify(&proof, root_hash, &[(k1, Some(v(1)))]).unwrap();
    }

    #[test]
    fn larger_batch_roundtrip() {
        let mut entries: Vec<(Key, ValueHash)> = Vec::new();
        for i in 0u8..128 {
            let mut key = [0u8; 32];
            key[0] = i.wrapping_mul(17);
            key[15] = i.wrapping_mul(31);
            entries.push((key, [i; 32]));
        }
        let (store, root, root_hash) = build_store(&entries);
        let keys: Vec<Key> = entries.iter().map(|(k, _)| *k).collect();
        let proof = Jmt::prove(&store, &root, &keys).unwrap();
        let expected: Vec<(Key, Option<ValueHash>)> =
            entries.iter().map(|(k, v)| (*k, Some(*v))).collect();
        Jmt::verify(&proof, root_hash, &expected).unwrap();

        // Also try a subset of keys.
        let subset: Vec<Key> = keys.iter().take(10).copied().collect();
        let sub_proof = Jmt::prove(&store, &root, &subset).unwrap();
        let sub_expected: Vec<(Key, Option<ValueHash>)> = entries
            .iter()
            .take(10)
            .map(|(k, v)| (*k, Some(*v)))
            .collect();
        Jmt::verify(&sub_proof, root_hash, &sub_expected).unwrap();
    }

    #[test]
    fn radix4_proofs_roundtrip() {
        type Jmt4 = Tree<Blake3Hasher, 2>;
        let mut store = MemoryStore::new();
        let entries: Vec<(Key, ValueHash)> = (0u8..16).map(|i| (k(i), v(i * 3))).collect();
        let updates: BTreeMap<Key, Option<ValueHash>> =
            entries.iter().map(|(k, v)| (*k, Some(*v))).collect();
        let res = Jmt4::apply_updates(&store, None, 1, &updates).unwrap();
        store.apply(&res);
        let root = store.get_root_key(1).unwrap();

        let keys: Vec<Key> = entries.iter().map(|(k, _)| *k).collect();
        let proof = Jmt4::prove(&store, &root, &keys).unwrap();
        let expected: Vec<(Key, Option<ValueHash>)> =
            entries.iter().map(|(k, v)| (*k, Some(*v))).collect();
        Jmt4::verify(&proof, res.root_hash, &expected).unwrap();
    }

    // ========================================================
    // Wire format tests
    // ========================================================

    #[test]
    fn encode_decode_empty_proof() {
        let proof = MultiProof {
            claims: vec![],
            siblings: vec![],
        };
        let bytes = proof.encode();
        // version (1) + claim_count (4) + sibling_count (4) = 9 bytes
        assert_eq!(bytes.len(), 9);
        assert_eq!(bytes[0], WIRE_VERSION);
        let decoded = MultiProof::decode(&bytes).unwrap();
        assert_eq!(proof, decoded);
    }

    #[test]
    fn encode_decode_inclusion_roundtrip() {
        let (store, root, root_hash) =
            build_store(&[(k(1), v(10)), (k(2), v(20)), (k(3), v(30)), (k(4), v(40))]);
        let proof = Jmt::prove(&store, &root, &[k(1), k(3)]).unwrap();

        let bytes = proof.encode();
        let decoded = MultiProof::decode(&bytes).unwrap();
        assert_eq!(proof, decoded);

        // Re-verify after roundtrip to confirm no semantic change.
        Jmt::verify(
            &decoded,
            root_hash,
            &[(k(1), Some(v(10))), (k(3), Some(v(30)))],
        )
        .unwrap();
    }

    #[test]
    fn encode_decode_non_inclusion_roundtrip() {
        let (store, root, root_hash) = build_store(&[(k(1), v(10)), (k(2), v(20))]);
        let proof = Jmt::prove(&store, &root, &[k(99)]).unwrap();

        let bytes = proof.encode();
        let decoded = MultiProof::decode(&bytes).unwrap();
        assert_eq!(proof, decoded);

        Jmt::verify(&decoded, root_hash, &[(k(99), None)]).unwrap();
    }

    #[test]
    fn encode_decode_leaf_mismatch_roundtrip() {
        // Construct a scenario where a claim terminates as LeafMismatch.
        // A key that shares a prefix with an existing key but diverges
        // will terminate at the existing leaf (mismatch).
        let (store, root, root_hash) = build_store(&[(k(1), v(10))]);
        // k(1) is at the root (single-entry tree → root IS the leaf).
        // A non-matching key hits a LeafMismatch termination.
        let other = k(2);
        let proof = Jmt::prove(&store, &root, &[other]).unwrap();
        assert!(matches!(
            proof.claims[0].termination,
            ClaimTermination::LeafMismatch { .. }
        ));

        let bytes = proof.encode();
        let decoded = MultiProof::decode(&bytes).unwrap();
        assert_eq!(proof, decoded);

        Jmt::verify(&decoded, root_hash, &[(other, None)]).unwrap();
    }

    #[test]
    fn decode_rejects_unsupported_version() {
        let bytes = vec![0xFF, 0, 0, 0, 0, 0, 0, 0, 0];
        let err = MultiProof::decode(&bytes).unwrap_err();
        assert!(matches!(err, DecodeError::UnsupportedVersion(0xFF)));
    }

    #[test]
    fn decode_rejects_truncated_header() {
        // Version byte only — no claim_count.
        let bytes = vec![WIRE_VERSION];
        let err = MultiProof::decode(&bytes).unwrap_err();
        assert!(matches!(err, DecodeError::Truncated));
    }

    #[test]
    fn decode_rejects_truncated_claims() {
        // Version + claim_count=1, then a partial claim.
        let mut bytes = vec![WIRE_VERSION];
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 10]); // only 10 bytes of a claim
        let err = MultiProof::decode(&bytes).unwrap_err();
        assert!(matches!(err, DecodeError::Truncated));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let (store, root, _) = build_store(&[(k(1), v(10)), (k(2), v(20))]);
        let proof = Jmt::prove(&store, &root, &[k(1)]).unwrap();
        let mut bytes = proof.encode();
        bytes.push(0x00);
        let err = MultiProof::decode(&bytes).unwrap_err();
        assert!(matches!(err, DecodeError::TrailingBytes));
    }

    #[test]
    fn decode_rejects_invalid_termination_discriminator() {
        // Construct a minimal proof: version + claim_count=1 + key + depth
        // + invalid discriminator.
        let mut bytes = vec![WIRE_VERSION];
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 32]); // key
        bytes.extend_from_slice(&0u16.to_be_bytes()); // depth
        bytes.push(0xAA); // invalid discriminator
        let err = MultiProof::decode(&bytes).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidTermination(0xAA)));
    }

    #[test]
    fn encoded_proof_is_deterministic() {
        // Same proof encodes byte-for-byte identically on repeat calls.
        let (store, root, _) = build_store(&[(k(1), v(10)), (k(2), v(20)), (k(3), v(30))]);
        let proof = Jmt::prove(&store, &root, &[k(1), k(2)]).unwrap();
        let a = proof.encode();
        let b = proof.encode();
        assert_eq!(a, b);
    }
}
