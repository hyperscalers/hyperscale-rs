//! Merkle proofs over the JMT state tree, on the wire.

use hyperscale_hbor::{Bytes, Hbor};
use hyperscale_jmt::{Blake3Hasher, ClaimTermination, MultiProof, Tree, ValueHash};
use thiserror::Error;

use crate::{MAX_MERKLE_PROOF_LEN, ShardId, StateRoot, SubstateKey, shard_prefix_path};

/// Merkle multiproof authenticating substates' presence in, or absence
/// from, the JMT state tree.
///
/// Opaque bytes containing an encoded `hyperscale_jmt::MultiProof`.
/// Generation lives in the storage crate, which walks the tree; reading
/// one back against a root is [`Self::inclusions`] here, beside the
/// provisions verifier that consumes the same bytes.
///
/// The proof contains:
/// - Per-claimed-key termination metadata (leaf / empty-subtree / leaf-mismatch)
/// - Sibling hashes for bottom-up verification
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hbor)]
#[hbor(transparent)]
pub struct MerkleInclusionProof(pub Bytes<MAX_MERKLE_PROOF_LEN>);

/// What a proof says about one key under the root it reconstructs.
///
/// A presence carries the leaf's value hash — what the reconstruction
/// weighed, and so the only statement about the value the proof is in a
/// position to make. A consumer holding the bytes confirms them against
/// it; one that only asked whether the cell is there ignores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub enum Inclusion {
    /// A leaf at the key, hashing to this.
    Present(ValueHash),
    /// No leaf at the key: an empty slot, or a leaf for some other key
    /// on the path.
    Absent,
}

impl Inclusion {
    /// Whether the key has a leaf.
    #[must_use]
    pub const fn is_present(self) -> bool {
        matches!(self, Self::Present(_))
    }

    /// The leaf's value hash, or `None` where the key is absent — the
    /// form a carried value is compared in.
    #[must_use]
    pub const fn value_hash(self) -> Option<ValueHash> {
        match self {
            Self::Present(hash) => Some(hash),
            Self::Absent => None,
        }
    }
}

/// Why a proof does not answer for the keys it was asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StateProofError {
    /// The bytes do not decode as a multiproof.
    #[error("malformed state proof")]
    Malformed,
    /// A key asked about has no claim in the proof.
    #[error("state proof carries no claim for a requested key")]
    MissingClaim,
    /// The proof does not reconstruct the root it was checked against.
    #[error("state proof does not reconstruct the state root")]
    RootMismatch,
}

impl MerkleInclusionProof {
    /// Create a new proof from raw bytes.
    ///
    /// # Panics
    ///
    /// If `bytes` runs past what a proof may occupy, which a proof
    /// generated over a tree this codebase builds cannot.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Bytes::new(bytes).expect("a proof over one shard's tree fits its cap"))
    }

    /// Each of `keys` as this proof attests it under `shard`'s `root`, in
    /// the order asked.
    ///
    /// The proof's own claims are what is checked: each asked key's
    /// claim is read off the proof and the tree is reconstructed from
    /// exactly those, so a proof that reaches `root` has attested every
    /// termination it carries. A key the proof does not claim, a proof
    /// that does not decode, and one reconstructing another root are
    /// each refused whole — a proof is usable or it is not.
    ///
    /// `shard` is whose root this is, and every claim must sit under its
    /// prefix. A shard's tree is rooted there, so the reconstruction
    /// never reads the bits above it: without the prefix a proof from one
    /// shard answers for another shard's keys, and since an absence
    /// contributes the same empty hash whatever key it names, it answers
    /// them absent.
    ///
    /// # Errors
    ///
    /// As [`StateProofError`] lists them.
    pub fn inclusions(
        &self,
        root: StateRoot,
        shard: ShardId,
        keys: &[SubstateKey],
    ) -> Result<Vec<(SubstateKey, Inclusion)>, StateProofError> {
        let proof = MultiProof::decode(self.as_bytes()).map_err(|_| StateProofError::Malformed)?;
        let mut expected = Vec::with_capacity(keys.len());
        let mut inclusions = Vec::with_capacity(keys.len());
        for key in keys {
            let jmt_key = key.to_bytes();
            let claim = proof
                .claims
                .binary_search_by_key(&jmt_key, |claim| claim.key)
                .ok()
                .map(|at| &proof.claims[at])
                .ok_or(StateProofError::MissingClaim)?;
            let inclusion = match claim.termination {
                // `value_hash` is `Some` exactly for a matched leaf, and
                // a `Leaf` claim without one would reconstruct as an
                // absence — which the root check then refuses.
                ClaimTermination::Leaf => claim
                    .value_hash
                    .map_or(Inclusion::Absent, Inclusion::Present),
                ClaimTermination::EmptySubtree | ClaimTermination::LeafMismatch { .. } => {
                    Inclusion::Absent
                }
            };
            expected.push((jmt_key, inclusion.value_hash()));
            inclusions.push((*key, inclusion));
        }
        let root_bytes: [u8; 32] = *root.as_raw().as_bytes();
        <Tree<Blake3Hasher, 1>>::verify(&proof, root_bytes, &shard_prefix_path(shard), &expected)
            .map_err(|_| StateProofError::RootMismatch)?;
        Ok(inclusions)
    }

    /// Get the raw proof bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create a dummy (empty) proof for testing.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub const fn dummy() -> Self {
        Self(Bytes::empty())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_hbor::{
        DecodeError, from_slice as hbor_from_slice, to_vec as hbor_to_vec, varint,
    };
    use hyperscale_jmt::{Key as JmtKey, LeafValue, MemoryStore, NodeKey};

    use super::*;
    use crate::state_key::jmt_value_hash;
    use crate::test_utils::test_key;
    use crate::{Address, AddressClass, Hash, LocalKey};

    type Jmt = Tree<Blake3Hasher, 1>;

    /// A one-version tree holding `present`, and a proof over `asked`
    /// against it.
    fn tree_and_proof(
        present: &[SubstateKey],
        asked: &[SubstateKey],
    ) -> (StateRoot, MerkleInclusionProof) {
        let mut store = MemoryStore::new();
        let updates: BTreeMap<JmtKey, Option<LeafValue>> = present
            .iter()
            .map(|key| {
                let value = key.to_bytes().to_vec();
                (
                    key.to_bytes(),
                    Some(LeafValue::new(jmt_value_hash(&value), value.len() as u64)),
                )
            })
            .collect();
        let result = Jmt::apply_updates(&store, None, 1, &updates).unwrap();
        let root = StateRoot::from_raw(Hash::from_hash_bytes(&result.root_hash));
        store.apply(&result);
        let jmt_keys: Vec<JmtKey> = asked.iter().map(SubstateKey::to_bytes).collect();
        let proof = Jmt::prove(&store, &NodeKey::root(1), &jmt_keys).unwrap();
        (root, MerkleInclusionProof::new(proof.encode()))
    }

    /// A key the tree holds reads back present, naming what its leaf
    /// hashes to, and one it does not reads back absent — in the order
    /// asked, under the root the proof reconstructs.
    #[test]
    fn inclusions_read_presence_and_absence_off_one_proof() {
        let (held, other, missing) = (test_key(1), test_key(2), test_key(3));
        let (root, proof) = tree_and_proof(&[held, other], &[missing, held]);
        let held_hash = jmt_value_hash(held.to_bytes().as_ref());
        assert_eq!(
            proof
                .inclusions(root, ShardId::ROOT, &[missing, held])
                .unwrap(),
            vec![
                (missing, Inclusion::Absent),
                (held, Inclusion::Present(held_hash)),
            ]
        );
    }

    /// A shard's root answers only for cells that shard owns.
    ///
    /// The reconstruction buckets a key from the root depth down, so the
    /// bits naming the shard reach no hash: an absence taken from an
    /// empty slot of one shard's tree carries over to the same position
    /// under its sibling's prefix untouched. A presence cannot travel
    /// that way — the leaf hash covers its key — which is why this is
    /// stated on an absence, and why it is the reachable forgery.
    #[test]
    fn inclusions_refuse_a_claim_the_root_does_not_own() {
        let source = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let owned = |seed: u8, local: u8| SubstateKey {
            owner: Address::new(
                {
                    let mut body = [seed; 31];
                    body[0] = seed;
                    body
                },
                AddressClass::Component,
            ),
            local: LocalKey([local; 16]),
        };

        // A tree rooted at the source's prefix, and an honest absence for
        // a cell the source owns and lacks.
        let held = owned(0x11, 0x11);
        let absent = owned(0x40, 0x40);
        let mut store = MemoryStore::new();
        let value = held.to_bytes().to_vec();
        let updates: BTreeMap<JmtKey, Option<LeafValue>> = BTreeMap::from([(
            held.to_bytes(),
            Some(LeafValue::new(jmt_value_hash(&value), value.len() as u64)),
        )]);
        let root_path = shard_prefix_path(source);
        let result = Jmt::apply_updates_at(&store, None, 1, &root_path, &updates).unwrap();
        let root = StateRoot::from_raw(Hash::from_hash_bytes(&result.root_hash));
        store.apply(&result);
        let honest = Jmt::prove(
            &store,
            &NodeKey::new(1, root_path.clone()),
            &[absent.to_bytes()],
        )
        .unwrap();

        // Relabel it onto the sibling's prefix: the same position, one
        // bit up, which is what a forging quorum controls.
        let foreign = owned(0xC0, 0x40);
        assert_ne!(
            root_path,
            shard_prefix_path(sibling),
            "the two prefixes differ, so the relabel crosses shards"
        );
        let mut forged = honest;
        for claim in &mut forged.claims {
            claim.key = foreign.to_bytes();
            if let ClaimTermination::LeafMismatch { stored_key, .. } = &mut claim.termination {
                stored_key[0] |= 0x80;
            }
        }
        let relabelled = MerkleInclusionProof::new(forged.encode());

        assert_eq!(
            relabelled.inclusions(root, sibling, &[foreign]),
            Err(StateProofError::RootMismatch),
            "an absence forged onto another shard's prefix answers nothing",
        );
    }

    /// A proof is refused whole when it reconstructs another root, when
    /// it carries no claim for a key asked, and when it does not decode.
    #[test]
    fn inclusions_refuse_a_proof_that_does_not_answer() {
        let (held, missing) = (test_key(1), test_key(3));
        let (root, proof) = tree_and_proof(&[held], &[missing]);
        let other_root = StateRoot::from_raw(Hash::from_bytes(b"another state"));
        assert_eq!(
            proof.inclusions(other_root, ShardId::ROOT, &[missing]),
            Err(StateProofError::RootMismatch)
        );
        assert_eq!(
            proof.inclusions(root, ShardId::ROOT, &[missing, held]),
            Err(StateProofError::MissingClaim),
            "the proof was taken over the missing key alone"
        );
        assert_eq!(
            MerkleInclusionProof::new(vec![0xff; 8]).inclusions(root, ShardId::ROOT, &[missing]),
            Err(StateProofError::Malformed)
        );
    }

    #[test]
    fn roundtrip_preserves_bytes() {
        let proof = MerkleInclusionProof::new(vec![0xab; 1024]);
        let bytes = hbor_to_vec(&proof).unwrap();
        let decoded: MerkleInclusionProof = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded, proof);
    }

    #[test]
    fn decode_rejects_oversized_proof() {
        let mut buf = Vec::new();
        varint::write(&mut buf, MAX_MERKLE_PROOF_LEN + 1).unwrap();
        buf.extend(std::iter::repeat_n(0u8, MAX_MERKLE_PROOF_LEN + 1));
        let err = hbor_from_slice::<MerkleInclusionProof>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_MERKLE_PROOF_LEN && actual == MAX_MERKLE_PROOF_LEN + 1
        ));
    }
}
