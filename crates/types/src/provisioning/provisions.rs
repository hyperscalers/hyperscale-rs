//! Per-block bundle of transaction provisions with a shared merkle proof.
//!
//! [`Provisions`] is the raw wire form. Its verified form is
//! `Verified<Provisions>`; predicate at
//! [`impl Verify<&ProvisionsContext<'_>>`](Verify::verify) below.

use std::fmt::{self, Debug, Formatter};
use std::sync::OnceLock;

use hyperscale_hbor::{Hbor, to_vec as hbor_to_vec};
use thiserror::Error;

use crate::state_key::jmt_value_hash;
use crate::{
    BlockHeight, CertifiedBlockHeader, Hash, MAX_TXS_PER_BLOCK, MerkleInclusionProof,
    ProvisionEntry, ProvisionHash, RETENTION_HORIZON, ShardId, StateProofError, SubstateEntry,
    SubstateKey, TxHash, Verified, Verify, WeightedTimestamp,
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
/// The QC and `state_root` are obtained from `CertifiedBlockHeader` received
/// via gossip — they don't travel with the provisions.
///
/// The content hash is computed lazily on first call to [`Self::hash`] and
/// cached for the lifetime of the value.
#[derive(Hbor)]
pub struct Provisions {
    source_shard: ShardId,
    target_shard: ShardId,
    block_height: BlockHeight,
    /// The source block's parent-QC weighted timestamp. Verification
    /// checks it against the commit-proven source header, so a bundle
    /// reaching execution through a committed block carries the value
    /// BFT-attested — the transaction clock for every transaction the
    /// source block committed, available to receivers that no longer
    /// hold the header itself.
    source_block_ts: WeightedTimestamp,
    proof: MerkleInclusionProof,
    #[hbor(max = MAX_TXS_PER_BLOCK)]
    transactions: Vec<ProvisionEntry>,

    /// Lazily-computed content hash (blake3 over HBOR-encoded content fields).
    /// Populated on first [`Self::hash`] call; not on the wire.
    #[hbor(skip)]
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
            source_block_ts: self.source_block_ts,
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
    /// first call to [`Self::hash`]. The entry cap is enforced at encode
    /// and decode, not here.
    #[must_use]
    pub const fn new(
        source_shard: ShardId,
        target_shard: ShardId,
        block_height: BlockHeight,
        source_block_ts: WeightedTimestamp,
        proof: MerkleInclusionProof,
        transactions: Vec<ProvisionEntry>,
    ) -> Self {
        Self {
            source_shard,
            target_shard,
            block_height,
            source_block_ts,
            proof,
            transactions,
            hash: OnceLock::new(),
        }
    }

    /// Source shard that committed this block.
    #[must_use]
    pub const fn source_shard(&self) -> ShardId {
        self.source_shard
    }

    /// Target shard the bundle is destined for.
    #[must_use]
    pub const fn target_shard(&self) -> ShardId {
        self.target_shard
    }

    /// Block height at which the state was committed.
    #[must_use]
    pub const fn block_height(&self) -> BlockHeight {
        self.block_height
    }

    /// The source block's parent-QC weighted timestamp, as carried on the
    /// wire and checked against the commit-proven header at verification.
    #[must_use]
    pub const fn source_block_ts(&self) -> WeightedTimestamp {
        self.source_block_ts
    }

    /// Aggregated merkle multiproof covering all entries for this block.
    #[must_use]
    pub const fn proof(&self) -> &MerkleInclusionProof {
        &self.proof
    }

    /// Per-transaction entries.
    #[must_use]
    pub const fn transactions(&self) -> &Vec<ProvisionEntry> {
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
                self.source_block_ts,
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
        source_shard: ShardId,
        target_shard: ShardId,
        block_height: BlockHeight,
        source_block_ts: WeightedTimestamp,
        proof: &MerkleInclusionProof,
        transactions: &[ProvisionEntry],
    ) -> ProvisionHash {
        // Encode the content fields (excluding the hash itself) for hashing.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &hbor_to_vec(&source_shard).expect("ShardId serialization should never fail"),
        );
        bytes.extend_from_slice(
            &hbor_to_vec(&target_shard).expect("ShardId serialization should never fail"),
        );
        bytes.extend_from_slice(
            &hbor_to_vec(&block_height).expect("BlockHeight serialization should never fail"),
        );
        bytes.extend_from_slice(
            &hbor_to_vec(&source_block_ts)
                .expect("WeightedTimestamp serialization should never fail"),
        );
        bytes.extend_from_slice(
            &hbor_to_vec(proof).expect("MerkleInclusionProof serialization should never fail"),
        );
        bytes.extend_from_slice(
            &hbor_to_vec(&transactions.to_vec())
                .expect("Vec<ProvisionEntry> serialization should never fail"),
        );
        ProvisionHash::from_raw(Hash::from_bytes(&bytes))
    }

    /// Get all entries across all transactions, sorted and deduped by key.
    #[must_use]
    pub fn all_entries_deduped(&self) -> Vec<SubstateEntry> {
        let mut entries: Vec<SubstateEntry> = self
            .transactions
            .iter()
            .flat_map(|tx| tx.entries.iter().cloned())
            .collect();
        entries.sort_by_key(|entry| entry.key);
        entries.dedup_by(|a, b| a.key == b.key);
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
    pub const fn dummy(
        source_shard: ShardId,
        target_shard: ShardId,
        block_height: BlockHeight,
    ) -> Self {
        Self::new(
            source_shard,
            target_shard,
            block_height,
            WeightedTimestamp::ZERO,
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
    pub certified_header: &'a Verified<CertifiedBlockHeader>,
}

/// Failure modes of [`Provisions`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ProvisionsVerifyError {
    /// `proof` bytes are non-empty but did not decode as a JMT
    /// [`MultiProof`](hyperscale_jmt::MultiProof).
    #[error("merkle proof bytes failed to decode")]
    MalformedProof,
    /// `proof` bytes are empty but the bundle carries entries.
    #[error("empty merkle proof with non-empty entry set")]
    EmptyProofWithEntries,
    /// The decoded multiproof did not validate against
    /// `ctx.certified_header.state_root()` for the bundle's claimed
    /// entries.
    #[error("merkle inclusion verification failed against committed state root")]
    BadInclusion,
    /// The bundle names a source shard other than the one whose header
    /// it is checked against.
    #[error("provisions source shard does not match the committed header")]
    SourceShardMismatch,
    /// The bundle's claimed `source_block_ts` does not equal the
    /// commit-proven source header's parent-QC weighted timestamp.
    #[error("provisions source block timestamp does not match the committed header")]
    SourceBlockTsMismatch,
    /// The proof reconstructs the root, but an entry carries a value the
    /// source's chain does not hold at that key — or claims a cell the
    /// chain holds is absent.
    #[error("provisions entry for {key:?} is not what the source's chain attested")]
    EntryMisstated {
        /// The cell whose carried value the proof contradicts.
        key: SubstateKey,
    },
}

/// Construction asserts: the aggregated merkle multiproof in
/// `provisions.proof()` validates every entry under
/// `ctx.certified_header.state_root()`.
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
        // The bundle's own account of who is answering must be the shard
        // whose root it is checked against. Only the header is trusted,
        // and consumers key what they absorb — the source of every entry,
        // and which requirement it satisfies — off the bundle's field.
        let source_shard = ctx.certified_header.shard_id();
        if self.source_shard != source_shard {
            return Err(ProvisionsVerifyError::SourceShardMismatch);
        }

        // The carried source-block timestamp must be the header's own
        // parent-QC anchor: receivers consume it as the transaction
        // clock, so it clears verification or the bundle does not.
        if self.source_block_ts
            != ctx
                .certified_header
                .header()
                .parent_qc()
                .weighted_timestamp()
        {
            return Err(ProvisionsVerifyError::SourceBlockTsMismatch);
        }

        let entries = self.all_entries_deduped();

        if self.proof.as_bytes().is_empty() {
            if entries.is_empty() {
                return Ok(Verified::new_unchecked(self.clone()));
            }
            return Err(ProvisionsVerifyError::EmptyProofWithEntries);
        }

        // One routine reads a proof, and it is the one the evidence path
        // reads through: it decodes once, roots the reconstruction at the
        // source shard's prefix — which is what binds every claim to a
        // cell that shard owns — and answers per key. What is left here
        // is this bundle's own claim, that the values it carries are the
        // ones the source's chain attested.
        let keys: Vec<SubstateKey> = entries.iter().map(|entry| entry.key).collect();
        let attested = self
            .proof
            .inclusions(ctx.certified_header.state_root(), source_shard, &keys)
            .map_err(|error| match error {
                StateProofError::Malformed => ProvisionsVerifyError::MalformedProof,
                StateProofError::MissingClaim | StateProofError::RootMismatch => {
                    ProvisionsVerifyError::BadInclusion
                }
            })?;

        for (entry, (_, inclusion)) in entries.iter().zip(&attested) {
            let carried = entry.value.as_ref().map(|value| jmt_value_hash(value));
            if carried != inclusion.value_hash() {
                return Err(ProvisionsVerifyError::EntryMisstated { key: entry.key });
            }
        }

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
    use hyperscale_hbor::{
        DecodeError, from_slice as hbor_from_slice, to_vec as hbor_to_vec, varint,
    };
    use hyperscale_vm_types::{LocalKey, SubstateKey};

    use super::*;
    use crate::test_utils::test_prefix;

    fn cell(owner: u8, local: u8) -> SubstateKey {
        SubstateKey {
            owner: test_prefix(owner),
            local: LocalKey([local; 16]),
        }
    }

    fn test_entry(seed: u8) -> SubstateEntry {
        SubstateEntry::new(cell(seed, seed), Some(vec![seed, seed + 1]))
    }

    #[test]
    fn test_provision_deadline_is_source_ts_plus_retention_horizon() {
        let provisions = Provisions::new(
            ShardId::leaf(1, 1),
            ShardId::leaf(2, 2),
            BlockHeight::new(100),
            WeightedTimestamp::ZERO,
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
            ShardId::leaf(1, 1),
            ShardId::leaf(2, 2),
            BlockHeight::new(42),
            WeightedTimestamp::ZERO,
            MerkleInclusionProof::new(vec![1, 2, 3]),
            vec![],
        );

        let bytes = hbor_to_vec(&original).unwrap();
        let decoded: Provisions = hbor_from_slice(&bytes).unwrap();
        assert_eq!(original, decoded);
        assert_eq!(decoded.target_shard(), ShardId::leaf(2, 2));
    }

    #[test]
    fn test_provisions_roundtrip() {
        let provisions = Provisions::new(
            ShardId::leaf(1, 0),
            ShardId::leaf(1, 1),
            BlockHeight::new(10),
            WeightedTimestamp::ZERO,
            MerkleInclusionProof::dummy(),
            vec![ProvisionEntry::new(
                TxHash::from(Hash::from_bytes(b"tx1")),
                vec![test_entry(1)],
            )],
        );

        let bytes = hbor_to_vec(&provisions).unwrap();
        let decoded: Provisions = hbor_from_slice(&bytes).unwrap();
        assert_eq!(provisions, decoded);
    }

    #[test]
    fn test_provisions_all_entries_deduped() {
        let entry = test_entry(1);
        let provisions = Provisions::new(
            ShardId::leaf(1, 0),
            ShardId::leaf(1, 1),
            BlockHeight::new(10),
            WeightedTimestamp::ZERO,
            MerkleInclusionProof::dummy(),
            vec![
                ProvisionEntry::new(TxHash::from(Hash::from_bytes(b"tx1")), vec![entry.clone()]),
                ProvisionEntry::new(
                    TxHash::from(Hash::from_bytes(b"tx2")),
                    vec![entry, test_entry(2)],
                ),
            ],
        );

        let deduped = provisions.all_entries_deduped();
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_merkle_inclusion_proof_roundtrip() {
        let proof = MerkleInclusionProof::new(vec![1, 2, 3, 4, 5]);
        let bytes = hbor_to_vec(&proof).unwrap();
        let decoded: MerkleInclusionProof = hbor_from_slice(&bytes).unwrap();
        assert_eq!(proof, decoded);
    }

    mod verify {
        use std::collections::BTreeMap;

        use hyperscale_jmt::{
            Blake3Hasher, ClaimTermination, Key as JmtKey, LeafValue, MemoryStore, NodeKey, Tree,
        };

        use super::*;
        use crate::state_key::jmt_value_hash;
        use crate::{
            BlockHeader, BlockHeight, ChainOrigin, Hash, QuorumCertificate, ShardId, StateRoot,
            ValidatorId, shard_prefix_path,
        };

        type Jmt = Tree<Blake3Hasher, 1>;

        /// The shard the fixtures' tree is rooted at and whose header
        /// every bundle here is checked against. A one-bit prefix of `0`,
        /// so a `test_prefix` seed below `0x80` is a cell it owns and one
        /// at or above is a cell its sibling owns.
        const SOURCE: ShardId = ShardId::leaf(1, 0);

        fn entry(seed: u8) -> (SubstateKey, Vec<u8>) {
            (cell(seed, seed), vec![seed, seed.wrapping_add(1)])
        }

        fn build_jmt(entries: &[(SubstateKey, Vec<u8>)]) -> (StateRoot, MerkleInclusionProof) {
            let mut store = MemoryStore::new();
            let updates: BTreeMap<JmtKey, Option<LeafValue>> = entries
                .iter()
                .map(|(k, v)| {
                    let val = LeafValue::new(jmt_value_hash(v), v.len() as u64);
                    (k.to_bytes(), Some(val))
                })
                .collect();
            let root_path = shard_prefix_path(SOURCE);
            let result = Jmt::apply_updates_at(&store, None, 1, &root_path, &updates).unwrap();
            let root_hash = result.root_hash;
            store.apply(&result);
            let root_key = NodeKey::new(1, root_path);
            let jmt_keys: Vec<JmtKey> = entries.iter().map(|(k, _)| k.to_bytes()).collect();
            let proof = Jmt::prove(&store, &root_key, &jmt_keys).unwrap();
            let state_root = StateRoot::from_raw(Hash::from_hash_bytes(&root_hash));
            (state_root, MerkleInclusionProof::new(proof.encode()))
        }

        fn header_with_state_root(state_root: StateRoot) -> Verified<CertifiedBlockHeader> {
            let shard = SOURCE;
            let header =
                BlockHeader::genesis(shard, ValidatorId::new(0), state_root, ChainOrigin::ROOT);
            Verified::<CertifiedBlockHeader>::new_unchecked_for_test(CertifiedBlockHeader::new(
                header,
                Verified::<QuorumCertificate>::genesis(shard, ChainOrigin::ROOT),
            ))
        }

        fn provisions_with(
            proof: MerkleInclusionProof,
            items: Vec<(SubstateKey, Vec<u8>)>,
        ) -> Provisions {
            let tx_entries = items
                .into_iter()
                .enumerate()
                .map(|(i, (key, value))| {
                    let tx_hash = TxHash::from(Hash::from_bytes(&[u8::try_from(i).unwrap(); 4]));
                    ProvisionEntry::new(tx_hash, vec![SubstateEntry::new(key, Some(value))])
                })
                .collect();
            Provisions::new(
                SOURCE,
                ShardId::leaf(1, 1),
                BlockHeight::new(1),
                WeightedTimestamp::ZERO,
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
                certified_header: &verified_header,
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
                certified_header: &verified_header,
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
                SOURCE,
                ShardId::leaf(1, 1),
                BlockHeight::new(1),
                WeightedTimestamp::ZERO,
                MerkleInclusionProof::new(vec![]),
                vec![],
            );
            let ctx = ProvisionsContext {
                certified_header: &verified_header,
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
                certified_header: &verified_header,
            };
            assert_eq!(
                provisions.verify(&ctx),
                Err(ProvisionsVerifyError::EmptyProofWithEntries)
            );
        }

        /// Only the header says who is answering. Consumers key what they
        /// absorb off the bundle's own field, so the two must agree.
        #[test]
        fn verify_rejects_a_bundle_naming_another_source_shard() {
            let items = vec![entry(1)];
            let (state_root, proof) = build_jmt(&items);
            let verified_header = header_with_state_root(state_root);
            let mut provisions = provisions_with(proof, items);
            provisions.source_shard = ShardId::leaf(1, 1);
            let ctx = ProvisionsContext {
                certified_header: &verified_header,
            };
            assert_eq!(
                provisions.verify(&ctx),
                Err(ProvisionsVerifyError::SourceShardMismatch)
            );
        }

        /// A shard cannot answer for a cell it does not own, and absence
        /// is the direction that needs saying so.
        ///
        /// The proof reconstructs from the source shard's prefix
        /// downward, so the bits naming the shard reach no hash: an
        /// absence taken from an empty slot of this shard's own tree
        /// carries over to the same position under its sibling's prefix
        /// untouched. A present entry cannot travel that way — the leaf
        /// hash covers its key — which is why this is stated on an
        /// absence.
        #[test]
        fn verify_rejects_an_absence_for_a_cell_the_source_shard_does_not_own() {
            let items = vec![entry(1), entry(2)];
            let (state_root, _) = build_jmt(&items);

            // An honest absence for a cell this shard owns and lacks.
            let absent = cell(0x40, 0x40);
            let (_, honest) = {
                let mut store = MemoryStore::new();
                let updates: BTreeMap<JmtKey, Option<LeafValue>> = items
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.to_bytes(),
                            Some(LeafValue::new(jmt_value_hash(v), v.len() as u64)),
                        )
                    })
                    .collect();
                let root_path = shard_prefix_path(SOURCE);
                let result = Jmt::apply_updates_at(&store, None, 1, &root_path, &updates).unwrap();
                store.apply(&result);
                let proof =
                    Jmt::prove(&store, &NodeKey::new(1, root_path), &[absent.to_bytes()]).unwrap();
                (result.root_hash, proof)
            };

            // Relabel it onto the sibling shard's prefix — the same
            // position, one bit up. Both the claim and the entry move,
            // which is what a forging quorum controls.
            let foreign = cell(0xC0, 0x40);
            assert_ne!(
                shard_prefix_path(SOURCE),
                shard_prefix_path(ShardId::leaf(1, 1)),
                "the two prefixes differ, so the relabel crosses shards"
            );
            let mut forged = honest;
            for claim in &mut forged.claims {
                claim.key = foreign.to_bytes();
                if let ClaimTermination::LeafMismatch { stored_key, .. } = &mut claim.termination {
                    stored_key[0] |= 0x80;
                }
            }

            let verified_header = header_with_state_root(state_root);
            let provisions = Provisions::new(
                SOURCE,
                ShardId::leaf(1, 1),
                BlockHeight::new(1),
                WeightedTimestamp::ZERO,
                MerkleInclusionProof::new(forged.encode()),
                vec![ProvisionEntry::new(
                    TxHash::from(Hash::from_bytes(b"tx")),
                    vec![SubstateEntry::new(foreign, None)],
                )],
            );
            let ctx = ProvisionsContext {
                certified_header: &verified_header,
            };
            assert_eq!(
                provisions.verify(&ctx),
                Err(ProvisionsVerifyError::BadInclusion)
            );
        }

        /// The proof reconstructs the root and the bundle still lies:
        /// the value it carries is not the one the source's chain holds
        /// at that key.
        ///
        /// Named apart from a bad proof because they are different
        /// faults — one says the evidence is unusable, the other that
        /// the evidence is fine and the bundle misreports it — and the
        /// consuming shard executes against the carried bytes.
        #[test]
        fn verify_rejects_an_entry_the_proof_does_not_attest() {
            let items = vec![entry(1), entry(2)];
            let (state_root, proof) = build_jmt(&items);
            let verified_header = header_with_state_root(state_root);
            let ctx = ProvisionsContext {
                certified_header: &verified_header,
            };

            // The honest bundle clears.
            assert!(
                provisions_with(proof.clone(), items.clone())
                    .verify(&ctx)
                    .is_ok()
            );

            // One entry's value swapped for another's: same keys, same
            // proof, a value the chain does not hold there.
            let (key, _) = items[0].clone();
            let lied = vec![(key, vec![0xAA, 0xBB]), items[1].clone()];
            assert_eq!(
                provisions_with(proof.clone(), lied).verify(&ctx),
                Err(ProvisionsVerifyError::EntryMisstated { key }),
            );

            // And a cell the chain holds, carried as absent.
            let absent = vec![
                ProvisionEntry::new(
                    TxHash::from(Hash::from_bytes(b"tx")),
                    vec![SubstateEntry::new(key, None)],
                ),
                ProvisionEntry::new(
                    TxHash::from(Hash::from_bytes(b"ty")),
                    vec![SubstateEntry::new(items[1].0, Some(items[1].1.clone()))],
                ),
            ];
            let bundle = Provisions::new(
                SOURCE,
                ShardId::leaf(1, 1),
                BlockHeight::new(1),
                WeightedTimestamp::ZERO,
                proof,
                absent,
            );
            assert_eq!(
                bundle.verify(&ctx),
                Err(ProvisionsVerifyError::EntryMisstated { key }),
            );
        }

        #[test]
        fn verify_rejects_a_mismatched_source_block_ts() {
            // The bundle claims a source anchor the commit-proven header
            // does not carry: receivers would consume it as the
            // transaction clock, so verification refuses it outright.
            let items = vec![entry(1)];
            let (state_root, proof) = build_jmt(&items);
            let verified_header = header_with_state_root(state_root);
            let provisions = Provisions::new(
                SOURCE,
                ShardId::leaf(1, 1),
                BlockHeight::new(1),
                WeightedTimestamp::from_millis(1),
                proof,
                vec![ProvisionEntry::new(
                    TxHash::from(Hash::from_bytes(b"tx")),
                    vec![SubstateEntry::new(items[0].0, Some(items[0].1.clone()))],
                )],
            );
            let ctx = ProvisionsContext {
                certified_header: &verified_header,
            };
            assert_eq!(
                provisions.verify(&ctx),
                Err(ProvisionsVerifyError::SourceBlockTsMismatch)
            );
        }
    }

    #[test]
    fn decode_rejects_oversized_transactions_count() {
        let mut buf = Vec::new();
        for part in [
            hbor_to_vec(&ShardId::leaf(1, 1)).unwrap(),
            hbor_to_vec(&ShardId::leaf(2, 2)).unwrap(),
            hbor_to_vec(&BlockHeight::new(10)).unwrap(),
            hbor_to_vec(&WeightedTimestamp::ZERO).unwrap(),
            hbor_to_vec(&MerkleInclusionProof::dummy()).unwrap(),
        ] {
            buf.extend_from_slice(&part);
        }
        varint::write(&mut buf, MAX_TXS_PER_BLOCK + 1).unwrap();
        buf.extend(std::iter::repeat_n(0u8, (MAX_TXS_PER_BLOCK + 1) * 64));
        let err = hbor_from_slice::<Provisions>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_TXS_PER_BLOCK && actual == MAX_TXS_PER_BLOCK + 1
        ));
    }
}
