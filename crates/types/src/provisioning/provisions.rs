//! Per-block bundle of transaction provisions with a shared merkle proof.
//!
//! [`Provisions`] is the raw wire form. Its verified form is
//! `Verified<Provisions>`; predicate at
//! [`impl Verify<&ProvisionsContext<'_>>`](Verify::verify) below.

use std::collections::HashSet;
use std::fmt::{self, Debug, Formatter};
use std::sync::OnceLock;

use blake3::hash as blake3_hash;
use hyperscale_jmt::{Blake3Hasher, MultiProof, Tree};
use sbor::prelude::*;
use thiserror::Error;

use crate::{
    BlockHeight, BoundedVec, CommittedBlockHeader, Hash, MAX_TXS_PER_BLOCK, MerkleInclusionProof,
    NodeId, ProvisionEntry, ProvisionHash, RETENTION_HORIZON, ShardGroupId, SubstateEntry, TxHash,
    Verified, Verify, WeightedTimestamp,
};

/// All provisions from a single source block, scoped to a single target shard.
///
/// Identifies the (source block, target shard) pair: source identifies what
/// state was committed and where to verify it; target identifies which shard
/// the bundle is destined for. One `Provisions` per (`source_block`, `target_shard`)
/// — a source block contributing state to multiple target shards produces
/// multiple `Provisions`, each with its own merkle proof scoped to that
/// shard's slice of entries.
///
/// The QC and `state_root` are obtained from `CommittedBlockHeader` received
/// via gossip — they don't travel with the provisions.
///
/// The content hash is computed lazily on first call to [`Self::hash`] and
/// cached for the lifetime of the value.
#[derive(BasicSbor)]
pub struct Provisions {
    source_shard: ShardGroupId,
    target_shard: ShardGroupId,
    block_height: BlockHeight,
    proof: MerkleInclusionProof,
    transactions: BoundedVec<ProvisionEntry, MAX_TXS_PER_BLOCK>,

    /// Lazily-computed content hash (blake3 over SBOR-encoded content fields).
    /// Populated on first [`Self::hash`] call; not on the wire.
    #[sbor(skip)]
    hash: OnceLock<ProvisionHash>,
}

impl Debug for Provisions {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Provision")
            .field("hash", &self.hash())
            .field("source_shard", &self.source_shard)
            .field("target_shard", &self.target_shard)
            .field("block_height", &self.block_height)
            .field("transactions", &self.transactions.len())
            .finish_non_exhaustive()
    }
}

impl Clone for Provisions {
    fn clone(&self) -> Self {
        let cloned_hash = OnceLock::new();
        if let Some(h) = self.hash.get() {
            let _ = cloned_hash.set(*h);
        }
        Self {
            source_shard: self.source_shard,
            target_shard: self.target_shard,
            block_height: self.block_height,
            proof: self.proof.clone(),
            transactions: self.transactions.clone(),
            hash: cloned_hash,
        }
    }
}

impl PartialEq for Provisions {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}

impl Eq for Provisions {}

impl Provisions {
    /// Create a new provisions. The content hash is computed lazily on
    /// first call to [`Self::hash`].
    ///
    /// # Panics
    ///
    /// Panics if `transactions.len() > MAX_TXS_PER_BLOCK`.
    #[must_use]
    pub fn new(
        source_shard: ShardGroupId,
        target_shard: ShardGroupId,
        block_height: BlockHeight,
        proof: MerkleInclusionProof,
        transactions: Vec<ProvisionEntry>,
    ) -> Self {
        Self {
            source_shard,
            target_shard,
            block_height,
            proof,
            transactions: transactions.into(),
            hash: OnceLock::new(),
        }
    }

    /// Source shard that committed this block.
    #[must_use]
    pub const fn source_shard(&self) -> ShardGroupId {
        self.source_shard
    }

    /// Target shard the bundle is destined for.
    #[must_use]
    pub const fn target_shard(&self) -> ShardGroupId {
        self.target_shard
    }

    /// Block height at which the state was committed.
    #[must_use]
    pub const fn block_height(&self) -> BlockHeight {
        self.block_height
    }

    /// Aggregated merkle multiproof covering all entries for this block.
    #[must_use]
    pub const fn proof(&self) -> &MerkleInclusionProof {
        &self.proof
    }

    /// Per-transaction entries.
    #[must_use]
    pub const fn transactions(&self) -> &BoundedVec<ProvisionEntry, MAX_TXS_PER_BLOCK> {
        &self.transactions
    }

    /// Content hash, computed on first call and cached.
    #[must_use]
    pub fn hash(&self) -> ProvisionHash {
        *self.hash.get_or_init(|| {
            Self::compute_hash(
                self.source_shard,
                self.target_shard,
                self.block_height,
                &self.proof,
                &self.transactions,
            )
        })
    }

    /// Deadline past which these provisions are provably useless on every
    /// shard.
    ///
    /// `source_weighted_ts` is the source block's QC `weighted_timestamp`,
    /// available from the paired remote header. Past
    /// `source_weighted_ts + RETENTION_HORIZON` every tx that could have
    /// referenced this data has expired its `validity_range` and
    /// completed (or aborted via the all-abort fallback) — no shard can
    /// still reference these provisions.
    #[must_use]
    pub fn deadline(&self, source_weighted_ts: WeightedTimestamp) -> WeightedTimestamp {
        source_weighted_ts.plus(RETENTION_HORIZON)
    }

    fn compute_hash(
        source_shard: ShardGroupId,
        target_shard: ShardGroupId,
        block_height: BlockHeight,
        proof: &MerkleInclusionProof,
        transactions: &[ProvisionEntry],
    ) -> ProvisionHash {
        // Encode the content fields (excluding the hash itself) for hashing.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &basic_encode(&source_shard).expect("ShardGroupId serialization should never fail"),
        );
        bytes.extend_from_slice(
            &basic_encode(&target_shard).expect("ShardGroupId serialization should never fail"),
        );
        bytes.extend_from_slice(
            &basic_encode(&block_height).expect("BlockHeight serialization should never fail"),
        );
        bytes.extend_from_slice(
            &basic_encode(proof).expect("MerkleInclusionProof serialization should never fail"),
        );
        bytes.extend_from_slice(
            &basic_encode(transactions)
                .expect("Vec<ProvisionEntry> serialization should never fail"),
        );
        ProvisionHash::from_raw(Hash::from_bytes(&bytes))
    }

    /// Get all node IDs across all transactions.
    #[must_use]
    pub fn all_node_ids(&self) -> HashSet<NodeId> {
        self.transactions
            .iter()
            .flat_map(|tx| tx.entries.iter().filter_map(SubstateEntry::node_id))
            .collect()
    }

    /// Get all entries across all transactions, sorted and deduped by `storage_key`.
    #[must_use]
    pub fn all_entries_deduped(&self) -> Vec<SubstateEntry> {
        let mut entries: Vec<SubstateEntry> = self
            .transactions
            .iter()
            .flat_map(|tx| tx.entries.iter().cloned())
            .collect();
        entries.sort_by(|a, b| a.storage_key.cmp(&b.storage_key));
        entries.dedup_by(|a, b| a.storage_key == b.storage_key);
        entries
    }

    /// Get the transaction hashes in these provisions.
    #[must_use]
    pub fn tx_hashes(&self) -> Vec<TxHash> {
        self.transactions.iter().map(|tx| tx.tx_hash).collect()
    }

    /// Create a dummy `Provisions` for testing.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn dummy(
        source_shard: ShardGroupId,
        target_shard: ShardGroupId,
        block_height: BlockHeight,
    ) -> Self {
        Self::new(
            source_shard,
            target_shard,
            block_height,
            MerkleInclusionProof::dummy(),
            vec![],
        )
    }
}

/// Inputs the [`Provisions`] verifier reads against.
#[derive(Debug, Clone, Copy)]
pub struct ProvisionsContext<'a> {
    /// The committed source-block header whose `state_root` the merkle
    /// proof must validate against. Carrying the verified marker means
    /// the QC over the source header has already cleared.
    pub committed_header: &'a Verified<CommittedBlockHeader>,
}

/// Failure modes of [`Provisions`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ProvisionsVerifyError {
    /// `proof` bytes are non-empty but did not decode as a JMT
    /// [`MultiProof`].
    #[error("merkle proof bytes failed to decode")]
    MalformedProof,
    /// `proof` bytes are empty but the bundle carries entries.
    #[error("empty merkle proof with non-empty entry set")]
    EmptyProofWithEntries,
    /// The decoded multiproof did not validate against
    /// `ctx.committed_header.state_root()` for the bundle's claimed
    /// entries.
    #[error("merkle inclusion verification failed against committed state root")]
    BadInclusion,
}

/// Construction asserts: the aggregated merkle multiproof in
/// `provisions.proof()` validates every entry under
/// `ctx.committed_header.state_root()`.
///
/// Construction goes through one of three gates:
///
/// - [`<Provisions as Verify>::verify`](Verify::verify) — runs the JMT
///   multiproof check against the committed state root. The
///   wire-admission path.
/// - [`Verified::<Provisions>::from_local`] — wraps a locally-built
///   bundle whose proof was generated from this validator's own JMT
///   view.
/// - [`Verified::<Provisions>::from_committed_block`] — wraps a bundle
///   reaching execution via a [`Verified<CertifiedBlock>`], where the
///   source committee's QC BFT-transitively attests the inclusion claim.
///
/// [`Verified<CertifiedBlock>`]: crate::CertifiedBlock
impl Verify<&ProvisionsContext<'_>> for Provisions {
    type Error = ProvisionsVerifyError;

    fn verify(&self, ctx: &ProvisionsContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let entries = self.all_entries_deduped();
        let proof_bytes = self.proof.as_bytes();

        if proof_bytes.is_empty() {
            if entries.is_empty() {
                return Ok(Verified::new_unchecked(self.clone()));
            }
            return Err(ProvisionsVerifyError::EmptyProofWithEntries);
        }

        let multi_proof =
            MultiProof::decode(proof_bytes).map_err(|_| ProvisionsVerifyError::MalformedProof)?;

        let expected: Vec<([u8; 32], Option<[u8; 32]>)> = entries
            .iter()
            .map(|e| {
                let key: [u8; 32] = *blake3_hash(&e.storage_key).as_bytes();
                let value_hash = e.value.as_ref().map(|v| *blake3_hash(v).as_bytes());
                (key, value_hash)
            })
            .collect();

        let root_bytes: [u8; 32] = *ctx.committed_header.state_root().as_raw().as_bytes();
        <Tree<Blake3Hasher, 1>>::verify(&multi_proof, root_bytes, &expected)
            .map_err(|_| ProvisionsVerifyError::BadInclusion)?;

        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verified<Provisions> {
    /// Wrap a locally-built provisions whose proof was generated
    /// against this validator's own JMT view of a committed state.
    ///
    /// Trust source: assembled by the `FetchAndBroadcastProvisions`
    /// action handler from the local substate view at a committed
    /// source-block height; the inclusion claim holds by construction
    /// of the proof bytes.
    #[must_use]
    pub const fn from_local(provisions: Provisions) -> Self {
        Self::new_unchecked(provisions)
    }

    /// Wrap a provisions reaching execution via a committed block.
    ///
    /// Trust source: the bundle arrived inside a
    /// [`Verified<CertifiedBlock>`]; 2f+1 source-shard validators ran
    /// the merkle predicate at receipt before signing the block, so
    /// the inclusion claim is BFT-transitively attested by the
    /// source committee's QC.
    ///
    /// [`Verified<CertifiedBlock>`]: crate::CertifiedBlock
    #[must_use]
    pub const fn from_committed_block(provisions: Provisions) -> Self {
        Self::new_unchecked(provisions)
    }
}

#[cfg(test)]
mod tests {
    use sbor::{Categorize as _, DecodeError, Encoder as _, NoCustomValueKind, ValueKind};

    use super::*;

    fn test_entry(seed: u8) -> SubstateEntry {
        let mut storage_key = Vec::with_capacity(20 + 30 + 1 + 1);
        storage_key.extend_from_slice(&[0u8; 20]);
        storage_key.extend_from_slice(&[seed; 30]);
        storage_key.push(0);
        storage_key.push(seed);
        SubstateEntry::new(storage_key, Some(vec![seed, seed + 1]))
    }

    #[test]
    fn test_provision_deadline_is_source_ts_plus_retention_horizon() {
        let provisions = Provisions::new(
            ShardGroupId::new(1),
            ShardGroupId::new(2),
            BlockHeight::new(100),
            MerkleInclusionProof::new(vec![]),
            vec![],
        );
        let source_ts = WeightedTimestamp::from_millis(1_000_000);
        assert_eq!(
            provisions.deadline(source_ts),
            source_ts.plus(RETENTION_HORIZON)
        );
    }

    #[test]
    fn test_provisions_fields_roundtrip() {
        let original = Provisions::new(
            ShardGroupId::new(1),
            ShardGroupId::new(2),
            BlockHeight::new(42),
            MerkleInclusionProof::new(vec![1, 2, 3]),
            vec![],
        );

        let bytes = basic_encode(&original).unwrap();
        let decoded: Provisions = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
        assert_eq!(decoded.target_shard(), ShardGroupId::new(2));
    }

    #[test]
    fn test_provision_entry_node_ids() {
        let tx = ProvisionEntry::new(
            TxHash::from_raw(Hash::from_bytes(b"tx")),
            vec![test_entry(1), test_entry(2)],
            vec![],
            vec![],
        );
        let nodes = tx.node_ids();
        assert_eq!(nodes.len(), 2);
        assert!(nodes.contains(&NodeId([1; 30])));
        assert!(nodes.contains(&NodeId([2; 30])));
    }

    #[test]
    fn test_provisions_roundtrip() {
        let provisions = Provisions::new(
            ShardGroupId::new(0),
            ShardGroupId::new(1),
            BlockHeight::new(10),
            MerkleInclusionProof::dummy(),
            vec![ProvisionEntry::new(
                TxHash::from_raw(Hash::from_bytes(b"tx1")),
                vec![test_entry(1)],
                vec![],
                vec![],
            )],
        );

        let bytes = basic_encode(&provisions).unwrap();
        let decoded: Provisions = basic_decode(&bytes).unwrap();
        assert_eq!(provisions, decoded);
    }

    #[test]
    fn test_provisions_all_entries_deduped() {
        let entry = test_entry(1);
        let provisions = Provisions::new(
            ShardGroupId::new(0),
            ShardGroupId::new(1),
            BlockHeight::new(10),
            MerkleInclusionProof::dummy(),
            vec![
                ProvisionEntry::new(
                    TxHash::from_raw(Hash::from_bytes(b"tx1")),
                    vec![entry.clone()],
                    vec![],
                    vec![],
                ),
                ProvisionEntry::new(
                    TxHash::from_raw(Hash::from_bytes(b"tx2")),
                    vec![entry, test_entry(2)],
                    vec![],
                    vec![],
                ),
            ],
        );

        let deduped = provisions.all_entries_deduped();
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_merkle_inclusion_proof_roundtrip() {
        let proof = MerkleInclusionProof::new(vec![1, 2, 3, 4, 5]);
        let bytes = basic_encode(&proof).unwrap();
        let decoded: MerkleInclusionProof = basic_decode(&bytes).unwrap();
        assert_eq!(proof, decoded);
    }

    mod verify {
        use std::collections::BTreeMap;

        use blake3::hash as blake3_hash;
        use hyperscale_jmt::{Blake3Hasher, MemoryStore, NodeKey, Tree};

        use super::*;
        use crate::{
            BlockHeader, BlockHeight, Hash, QuorumCertificate, ShardGroupId, StateRoot, ValidatorId,
        };

        type Jmt = Tree<Blake3Hasher, 1>;

        fn entry(seed: u8) -> (Vec<u8>, Vec<u8>) {
            let mut storage_key = Vec::with_capacity(20 + 30 + 1 + 1);
            storage_key.extend_from_slice(&[0u8; 20]);
            storage_key.extend_from_slice(&[seed; 30]);
            storage_key.push(0);
            storage_key.push(seed);
            (storage_key, vec![seed, seed.wrapping_add(1)])
        }

        fn build_jmt(entries: &[(Vec<u8>, Vec<u8>)]) -> (StateRoot, MerkleInclusionProof) {
            let mut store = MemoryStore::new();
            let updates: BTreeMap<[u8; 32], Option<[u8; 32]>> = entries
                .iter()
                .map(|(k, v)| {
                    let key: [u8; 32] = *blake3_hash(k).as_bytes();
                    let val: [u8; 32] = *blake3_hash(v).as_bytes();
                    (key, Some(val))
                })
                .collect();
            let result = Jmt::apply_updates(&store, None, 1, &updates).unwrap();
            let root_hash = result.root_hash;
            store.apply(&result);
            let root_key = NodeKey::root(1);
            let jmt_keys: Vec<[u8; 32]> = entries
                .iter()
                .map(|(k, _)| *blake3_hash(k).as_bytes())
                .collect();
            let proof = Jmt::prove(&store, &root_key, &jmt_keys).unwrap();
            let state_root = StateRoot::from_raw(Hash::from_hash_bytes(&root_hash));
            (state_root, MerkleInclusionProof::new(proof.encode()))
        }

        fn header_with_state_root(state_root: StateRoot) -> Verified<CommittedBlockHeader> {
            let shard = ShardGroupId::new(0);
            let header = BlockHeader::genesis(shard, ValidatorId::new(0), state_root);
            Verified::<CommittedBlockHeader>::new_unchecked_for_test(CommittedBlockHeader::new(
                header,
                Verified::<QuorumCertificate>::genesis(shard),
            ))
        }

        fn provisions_with(
            proof: MerkleInclusionProof,
            items: Vec<(Vec<u8>, Vec<u8>)>,
        ) -> Provisions {
            let tx_entries = items
                .into_iter()
                .enumerate()
                .map(|(i, (storage_key, value))| {
                    let tx_hash =
                        TxHash::from_raw(Hash::from_bytes(&[u8::try_from(i).unwrap(); 4]));
                    ProvisionEntry::new(
                        tx_hash,
                        vec![SubstateEntry::new(storage_key, Some(value))],
                        vec![],
                        vec![],
                    )
                })
                .collect();
            Provisions::new(
                ShardGroupId::new(1),
                ShardGroupId::new(0),
                BlockHeight::new(1),
                proof,
                tx_entries,
            )
        }

        #[test]
        fn verify_accepts_provisions_with_valid_inclusion_proof() {
            let items = vec![entry(1), entry(2), entry(3)];
            let (state_root, proof) = build_jmt(&items);
            let verified_header = header_with_state_root(state_root);
            let provisions = provisions_with(proof, items);
            let ctx = ProvisionsContext {
                committed_header: &verified_header,
            };
            provisions
                .verify(&ctx)
                .expect("honest provisions must verify");
        }

        #[test]
        fn verify_rejects_tampered_proof_bytes() {
            let items = vec![entry(1), entry(2)];
            let (state_root, proof) = build_jmt(&items);
            let verified_header = header_with_state_root(state_root);

            let mut bytes = proof.as_bytes().to_vec();
            assert!(bytes.len() > 4);
            let last = bytes.len() - 1;
            bytes[last] ^= 0xFF;
            let tampered = MerkleInclusionProof::new(bytes);
            let provisions = provisions_with(tampered, items);

            let ctx = ProvisionsContext {
                committed_header: &verified_header,
            };
            let err = provisions
                .verify(&ctx)
                .expect_err("tampered proof must fail verify");
            assert!(
                matches!(
                    err,
                    ProvisionsVerifyError::BadInclusion | ProvisionsVerifyError::MalformedProof,
                ),
                "got {err:?}",
            );
        }

        #[test]
        fn verify_accepts_empty_proof_with_empty_entries() {
            let state_root = StateRoot::ZERO;
            let verified_header = header_with_state_root(state_root);
            let provisions = Provisions::new(
                ShardGroupId::new(1),
                ShardGroupId::new(0),
                BlockHeight::new(1),
                MerkleInclusionProof::new(vec![]),
                vec![],
            );
            let ctx = ProvisionsContext {
                committed_header: &verified_header,
            };
            provisions
                .verify(&ctx)
                .expect("empty proof + empty entries is vacuously valid");
        }

        #[test]
        fn verify_rejects_empty_proof_with_non_empty_entries() {
            let state_root = StateRoot::ZERO;
            let verified_header = header_with_state_root(state_root);
            let provisions = provisions_with(MerkleInclusionProof::new(vec![]), vec![entry(1)]);
            let ctx = ProvisionsContext {
                committed_header: &verified_header,
            };
            assert_eq!(
                provisions.verify(&ctx),
                Err(ProvisionsVerifyError::EmptyProofWithEntries)
            );
        }
    }

    #[test]
    fn decode_rejects_oversized_transactions_count() {
        use sbor::{BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, VecEncoder};
        let mut buf = Vec::with_capacity(64);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(5).unwrap();
            enc.encode(&ShardGroupId::new(1)).unwrap();
            enc.encode(&ShardGroupId::new(2)).unwrap();
            enc.encode(&BlockHeight::new(10)).unwrap();
            enc.encode(&MerkleInclusionProof::dummy()).unwrap();
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(ProvisionEntry::value_kind()).unwrap();
            enc.write_size(MAX_TXS_PER_BLOCK + 1).unwrap();
        }
        let err = basic_decode::<Provisions>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_TXS_PER_BLOCK
                    && actual == MAX_TXS_PER_BLOCK + 1
        ));
    }
}
