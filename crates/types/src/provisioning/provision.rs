//! One transaction's provision from one source block to one target
//! shard, with a proof of its own.
//!
//! [`Provision`] is the raw wire form. Its verified form is
//! `Verified<Provision>`; predicate at
//! [`impl Verify<&ProvisionContext>`](Verify::verify) below.

use std::fmt::{self, Debug, Formatter};
use std::sync::{Arc, OnceLock};

use hyperscale_hbor::{Capped, Hbor, to_vec as hbor_to_vec};
use thiserror::Error;

use crate::state_key::jmt_value_hash;
use crate::{
    Anchor, BlockHeight, Hash, LeafPath, MAX_PROVISION_WEIGHT, MerkleInclusionProof, ProvisionHash,
    RETENTION_HORIZON, ShardId, StateProofError, SubstateEntry, SubstateKey, TxHash, Verified,
    Verify, WeightedTimestamp, provision_leaf, served_digest,
};

/// One transaction's reads from one source block, for one target shard.
///
/// A part is the unit of admission, inclusion and fetch: its entries
/// carry their own proof, and its leaf path places the transaction in
/// the source header's `provision_tx_roots[target]`, so what one part
/// weighs, proves or fails costs no other transaction of the block.
///
/// The QC and `state_root` are obtained from `CertifiedBlockHeader` received
/// via gossip — they don't travel with the part.
///
/// Every clone shares one allocation, the cached hash included, so moving
/// a part between its raw, verifiable and verified forms copies a
/// pointer, not its entries.
#[derive(Clone, Hbor)]
#[hbor(transparent)]
pub struct Provision(Arc<Carried>);

/// What every clone of one [`Provision`] shares.
#[derive(Hbor)]
struct Carried {
    source_shard: ShardId,
    target_shard: ShardId,
    block_height: BlockHeight,
    /// The source block's parent-QC weighted timestamp. Verification
    /// checks it against the commit-proven source header, so a part
    /// reaching execution through a committed block carries the value
    /// BFT-attested — the transaction clock, available to receivers that
    /// no longer hold the header itself.
    source_block_ts: WeightedTimestamp,
    tx_hash: TxHash,
    /// Strictly ascending by key. Empty for an engagement echo — a
    /// counterpart with nothing to serve still owes the payer its
    /// commitment of the transaction.
    entries: Capped<Vec<SubstateEntry>, MAX_PROVISION_WEIGHT>,
    proof: MerkleInclusionProof,
    leaf: LeafPath,

    /// Content hash over every field above. Populated on first
    /// [`Provision::hash`] call; not on the wire.
    #[hbor(skip)]
    hash: OnceLock<ProvisionHash>,
}

/// The fields a [`Provision`] is made of.
pub struct ProvisionParts {
    /// The shard that committed the source block.
    pub source_shard: ShardId,
    /// The shard the part is owed to.
    pub target_shard: ShardId,
    /// The source block's height.
    pub block_height: BlockHeight,
    /// The source block's parent-QC weighted timestamp.
    pub source_block_ts: WeightedTimestamp,
    /// The transaction the part provisions.
    pub tx_hash: TxHash,
    /// Its entries, strictly ascending by key.
    pub entries: Capped<Vec<SubstateEntry>, MAX_PROVISION_WEIGHT>,
    /// The proof holding every entry to the source's state root.
    pub proof: MerkleInclusionProof,
    /// The transaction's leaf in the source header's root for the target.
    pub leaf: LeafPath,
}

impl Debug for Provision {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Provision")
            .field("hash", &self.hash())
            .field("source_shard", &self.0.source_shard)
            .field("target_shard", &self.0.target_shard)
            .field("block_height", &self.0.block_height)
            .field("tx_hash", &self.0.tx_hash)
            .field("index", &self.0.leaf.index)
            .field("entries", &self.0.entries.len())
            .finish_non_exhaustive()
    }
}

impl PartialEq for Provision {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}

impl Eq for Provision {}

impl Provision {
    /// A part of `parts`. The content hash is computed lazily on first
    /// call to [`Self::hash`]; the entry cap is enforced at encode and
    /// decode, and their order at verification, not here.
    #[must_use]
    pub fn new(parts: ProvisionParts) -> Self {
        let ProvisionParts {
            source_shard,
            target_shard,
            block_height,
            source_block_ts,
            tx_hash,
            entries,
            proof,
            leaf,
        } = parts;
        Self(Arc::new(Carried {
            source_shard,
            target_shard,
            block_height,
            source_block_ts,
            tx_hash,
            entries,
            proof,
            leaf,
            hash: OnceLock::new(),
        }))
    }

    /// Source shard that committed this block.
    #[must_use]
    pub fn source_shard(&self) -> ShardId {
        self.0.source_shard
    }

    /// Target shard the part is owed to.
    #[must_use]
    pub fn target_shard(&self) -> ShardId {
        self.0.target_shard
    }

    /// Block height at which the state was committed.
    #[must_use]
    pub fn block_height(&self) -> BlockHeight {
        self.0.block_height
    }

    /// The source block's parent-QC weighted timestamp, as carried on the
    /// wire and checked against the commit-proven header at verification.
    #[must_use]
    pub fn source_block_ts(&self) -> WeightedTimestamp {
        self.0.source_block_ts
    }

    /// The transaction this part provisions.
    #[must_use]
    pub fn tx_hash(&self) -> TxHash {
        self.0.tx_hash
    }

    /// The transaction's entries, strictly ascending by key once
    /// verified.
    #[must_use]
    pub fn entries(&self) -> &[SubstateEntry] {
        &self.0.entries
    }

    /// The merkle multiproof covering this part's entries.
    #[must_use]
    pub fn proof(&self) -> &MerkleInclusionProof {
        &self.0.proof
    }

    /// Where the transaction's leaf sits in the source header's root for
    /// the target.
    #[must_use]
    pub fn leaf(&self) -> &LeafPath {
        &self.0.leaf
    }

    /// The leaf this part is under its target's root: its transaction
    /// and the keys it carries, so a part serving other keys than its
    /// source committed walks to another root.
    #[must_use]
    pub fn leaf_hash(&self) -> Hash {
        provision_leaf(
            self.0.tx_hash,
            served_digest(self.0.entries.iter().map(|entry| entry.key)),
        )
    }

    /// Content hash, computed on first call and cached.
    ///
    /// # Panics
    ///
    /// Never: a part that was built or decoded encodes.
    #[must_use]
    pub fn hash(&self) -> ProvisionHash {
        *self.0.hash.get_or_init(|| {
            ProvisionHash::from_raw(Hash::from_bytes(
                &hbor_to_vec(&*self.0).expect("a part encodes"),
            ))
        })
    }

    /// Deadline past which this part is provably useless on every shard.
    ///
    /// `source_weighted_ts` is the source block's QC `weighted_timestamp`,
    /// available from the paired remote header. Past
    /// `source_weighted_ts + RETENTION_HORIZON` every tx that could have
    /// referenced a read set has expired its `validity_range` and
    /// completed (or aborted via the all-abort fallback) — no shard can
    /// still reference the part.
    #[must_use]
    pub fn deadline(&self, source_weighted_ts: WeightedTimestamp) -> WeightedTimestamp {
        source_weighted_ts.plus(RETENTION_HORIZON)
    }

    /// An engagement echo for `tx_hash` at index 0 of one leaf, with an
    /// empty proof, for tests that never walk its path.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn dummy(
        source_shard: ShardId,
        target_shard: ShardId,
        block_height: BlockHeight,
        tx_hash: TxHash,
    ) -> Self {
        Self::dummy_at(
            source_shard,
            target_shard,
            block_height,
            WeightedTimestamp::ZERO,
            tx_hash,
        )
    }

    /// [`Self::dummy`], read off a source block anchored at
    /// `source_block_ts`.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn dummy_at(
        source_shard: ShardId,
        target_shard: ShardId,
        block_height: BlockHeight,
        source_block_ts: WeightedTimestamp,
        tx_hash: TxHash,
    ) -> Self {
        Self::new(ProvisionParts {
            source_shard,
            target_shard,
            block_height,
            source_block_ts,
            tx_hash,
            entries: Capped::empty(),
            proof: MerkleInclusionProof::new(Vec::new()),
            leaf: LeafPath {
                count: 1,
                index: 0,
                siblings: Capped::empty(),
            },
        })
    }

    /// This part with its leaf moved to `index` of `count`, the path left
    /// empty, for tests that order parts without walking them.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn at_leaf(&self, index: u32, count: u32) -> Self {
        let carried = &*self.0;
        Self::new(ProvisionParts {
            source_shard: carried.source_shard,
            target_shard: carried.target_shard,
            block_height: carried.block_height,
            source_block_ts: carried.source_block_ts,
            tx_hash: carried.tx_hash,
            entries: carried.entries.clone(),
            proof: carried.proof.clone(),
            leaf: LeafPath {
                count,
                index,
                siblings: Capped::empty(),
            },
        })
    }
}

/// Whether `parts` run strictly ascending by leaf index: the order every
/// honest packer and server lays a block's parts out in, which leaves no
/// room for one part twice.
pub fn in_leaf_order<'a>(parts: impl IntoIterator<Item = &'a Provision>) -> bool {
    let mut previous: Option<u32> = None;
    parts.into_iter().all(|part| {
        let index = part.leaf().index;
        let ascending = previous.is_none_or(|previous| previous < index);
        previous = Some(index);
        ascending
    })
}

/// Inputs the [`Provision`] verifier reads against.
#[derive(Debug, Clone, Copy)]
pub struct ProvisionContext {
    /// The source anchor whose `state_root` the merkle proof must
    /// validate against — a height this node has commit-proven.
    ///
    /// The anchor and not the header it was taken from, because the root
    /// is the whole of what a proof is checked against and a header is
    /// only one way to name one. A pushed part's anchor comes off the
    /// producing header; a pulled one's off this node's own mirror of
    /// what it has proven, which no promise gates.
    pub anchor: Anchor,
}

/// Failure modes of [`Provision`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ProvisionVerifyError {
    /// `proof` bytes are non-empty but did not decode as a JMT
    /// [`MultiProof`](hyperscale_jmt::MultiProof).
    #[error("merkle proof bytes failed to decode")]
    MalformedProof,
    /// `proof` bytes are empty but the part carries entries.
    #[error("empty merkle proof with non-empty entry set")]
    EmptyProofWithEntries,
    /// The decoded multiproof did not validate against
    /// `ctx.anchor.state_root` for the part's claimed entries.
    #[error("merkle inclusion verification failed against committed state root")]
    BadInclusion,
    /// The part names a source shard other than the one whose header
    /// it is checked against.
    #[error("provision source shard does not match the committed header")]
    SourceShardMismatch,
    /// The part's claimed `source_block_ts` does not equal the
    /// commit-proven source header's parent-QC weighted timestamp.
    #[error("provision source block timestamp does not match the committed header")]
    SourceBlockTsMismatch,
    /// An entry's key is not strictly above the one before it: a part
    /// carries each key once, in order.
    #[error("provision entry for {key:?} is out of order or repeated")]
    EntriesNotAscending {
        /// The first key not above its predecessor.
        key: SubstateKey,
    },
    /// The proof reconstructs the root, but an entry carries a value the
    /// source's chain does not hold at that key — or claims a cell the
    /// chain holds is absent.
    #[error("provision entry for {key:?} is not what the source's chain attested")]
    EntryMisstated {
        /// The cell whose carried value the proof contradicts.
        key: SubstateKey,
    },
}

/// Construction asserts: the merkle multiproof in `provision.proof()`
/// validates every entry under `ctx.anchor.state_root`, and the entries
/// are strictly ascending by key.
///
/// Construction goes through one of three gates:
///
/// - [`<Provision as Verify>::verify`](Verify::verify) — runs the JMT
///   multiproof check against the committed state root. The
///   wire-admission path.
/// - [`Verified::<Provision>::from_local`] — wraps a locally-built
///   part whose proof was generated from this validator's own JMT
///   view.
/// - [`Verified::<Provision>::from_committed_block`] — wraps a part
///   reaching execution via a [`Verified<CertifiedBlock>`], where the
///   source committee's QC BFT-transitively attests the inclusion claim.
///
/// The leaf path is not this predicate's: it is held to the header's
/// root before the proof is checked.
///
/// [`Verified<CertifiedBlock>`]: crate::CertifiedBlock
impl Verify<&ProvisionContext> for Provision {
    type Error = ProvisionVerifyError;

    fn verify(&self, ctx: &ProvisionContext) -> Result<Verified<Self>, Self::Error> {
        // The part's own account of who is answering must be the shard
        // whose root it is checked against. Only the anchor is trusted,
        // and consumers key what they absorb off the part's field.
        let source_shard = ctx.anchor.shard;
        if self.0.source_shard != source_shard {
            return Err(ProvisionVerifyError::SourceShardMismatch);
        }

        // The carried source-block timestamp must be the anchor's own
        // parent-QC reading: receivers consume it as the transaction
        // clock, so it clears verification or the part does not.
        if self.0.source_block_ts != ctx.anchor.ts {
            return Err(ProvisionVerifyError::SourceBlockTsMismatch);
        }

        // One copy per key, in order: the proof answers once per key and
        // the transaction executes against the one copy it carries.
        for pair in self.0.entries.windows(2) {
            if pair[1].key <= pair[0].key {
                return Err(ProvisionVerifyError::EntriesNotAscending { key: pair[1].key });
            }
        }

        if self.0.proof.as_bytes().is_empty() {
            if self.0.entries.is_empty() {
                return Ok(Verified::new_unchecked(self.clone()));
            }
            return Err(ProvisionVerifyError::EmptyProofWithEntries);
        }

        // One routine reads a proof, and it is the one the evidence path
        // reads through: it decodes once, roots the reconstruction at the
        // source shard's prefix — which is what binds every claim to a
        // cell that shard owns — and answers per key. What is left here
        // is this part's own claim, that the values it carries are the
        // ones the source's chain attested.
        let keys: Vec<SubstateKey> = self.0.entries.iter().map(|entry| entry.key).collect();
        let attested = self
            .0
            .proof
            .inclusions(ctx.anchor.state_root, source_shard, &keys)
            .map_err(|error| match error {
                StateProofError::Malformed => ProvisionVerifyError::MalformedProof,
                StateProofError::MissingClaim
                | StateProofError::RootMismatch
                | StateProofError::ExtraClaim
                | StateProofError::ReadingMismatch => ProvisionVerifyError::BadInclusion,
            })?;

        for (entry, (_, inclusion)) in self.0.entries.iter().zip(attested) {
            let carried = entry.value.as_ref().map(|value| jmt_value_hash(value));
            if carried != inclusion.value_hash() {
                return Err(ProvisionVerifyError::EntryMisstated { key: entry.key });
            }
        }

        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verified<Provision> {
    /// Wrap a locally-built part whose proof was generated against this
    /// validator's own JMT view of a committed state.
    ///
    /// Trust source: assembled by the `FetchAndBroadcastProvisions`
    /// action handler from the local substate view at a committed
    /// source-block height; the inclusion claim holds by construction
    /// of the proof bytes.
    #[must_use]
    pub const fn from_local(provision: Provision) -> Self {
        Self::new_unchecked(provision)
    }

    /// Wrap a part reaching execution via a committed block.
    ///
    /// Trust source: the part arrived inside a
    /// [`Verified<CertifiedBlock>`]; 2f+1 source-shard validators ran
    /// the merkle predicate at receipt before signing the block, so
    /// the inclusion claim is BFT-transitively attested by the
    /// source committee's QC.
    ///
    /// [`Verified<CertifiedBlock>`]: crate::CertifiedBlock
    #[must_use]
    pub const fn from_committed_block(provision: Provision) -> Self {
        Self::new_unchecked(provision)
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{Bytes, from_slice as hbor_from_slice, to_vec as hbor_to_vec};
    use hyperscale_vm_types::{LocalKey, SubstateKey};

    use super::*;
    use crate::test_utils::test_prefix;
    use crate::{CertifiedBlockHeader, Verifiable};

    fn cell(owner: u8, local: u8) -> SubstateKey {
        SubstateKey {
            owner: test_prefix(owner),
            local: LocalKey([local; 16]),
        }
    }

    fn tx(seed: &[u8]) -> TxHash {
        TxHash::from(Hash::from_bytes(seed))
    }

    /// The coordinator queues the verified form and a proposal carries
    /// the verifiable one; lifting between them hands over the one part
    /// rather than copying its entries.
    #[test]
    fn every_form_of_a_part_shares_one_body() {
        let raw = Provision::dummy(
            ShardId::leaf(1, 1),
            ShardId::leaf(2, 2),
            BlockHeight::new(7),
            tx(b"tx"),
        );
        let verified = Verified::<Provision>::from_local(raw.clone());
        let wire: Verifiable<Provision> = verified.clone().into();
        assert!(Arc::ptr_eq(&raw.0, &verified.0));
        assert!(Arc::ptr_eq(&raw.0, &wire.as_unverified().0));
    }

    #[test]
    fn a_parts_deadline_is_its_source_ts_plus_the_retention_horizon() {
        let part = Provision::dummy(
            ShardId::leaf(1, 1),
            ShardId::leaf(2, 2),
            BlockHeight::new(100),
            tx(b"tx"),
        );
        let source_ts = WeightedTimestamp::from_millis(1_000_000);
        assert_eq!(part.deadline(source_ts), source_ts.plus(RETENTION_HORIZON));
    }

    /// Every field reaches the wire and the hash: two parts differing in
    /// any one of them differ.
    #[test]
    fn a_part_round_trips_and_its_hash_covers_its_path() {
        let entry = SubstateEntry::new(cell(1, 1), Some(Bytes::from_array([1, 2])));
        let part = |index: u32| {
            Provision::new(ProvisionParts {
                source_shard: ShardId::leaf(1, 0),
                target_shard: ShardId::leaf(1, 1),
                block_height: BlockHeight::new(10),
                source_block_ts: WeightedTimestamp::ZERO,
                tx_hash: tx(b"tx1"),
                entries: Capped::from_array([entry.clone()]),
                proof: MerkleInclusionProof::dummy(),
                leaf: LeafPath {
                    count: 2,
                    index,
                    siblings: Capped::from_array([Hash::from_bytes(b"sibling")]),
                },
            })
        };
        let original = part(0);
        let bytes = hbor_to_vec(&original).unwrap();
        let decoded: Provision = hbor_from_slice(&bytes).unwrap();
        assert_eq!(original, decoded);
        assert_eq!(decoded.leaf(), original.leaf());
        assert_ne!(part(0).hash(), part(1).hash());
    }

    mod verify {
        use std::collections::BTreeMap;

        use hyperscale_hbor::Bytes;
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
        /// every part here is checked against. A one-bit prefix of `0`,
        /// so a `test_prefix` seed below `0x80` is a cell it owns and one
        /// at or above is a cell its sibling owns.
        const SOURCE: ShardId = ShardId::leaf(1, 0);

        fn entry(seed: u8) -> (SubstateKey, Vec<u8>) {
            (cell(seed, seed), vec![seed, seed.wrapping_add(1)])
        }

        fn held<const N: usize>(bytes: Vec<u8>) -> Bytes<N> {
            Bytes::new(bytes).expect("a list written out in a test")
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

        fn context(state_root: StateRoot) -> ProvisionContext {
            let header = BlockHeader::genesis(
                SOURCE,
                ValidatorId::new(0),
                state_root,
                ChainOrigin::root(WeightedTimestamp::ZERO),
            );
            let certified = Verified::<CertifiedBlockHeader>::new_unchecked_for_test(
                CertifiedBlockHeader::new(
                    header,
                    Verified::<QuorumCertificate>::genesis(
                        SOURCE,
                        ChainOrigin::root(WeightedTimestamp::ZERO),
                    ),
                ),
            );
            ProvisionContext {
                anchor: Anchor::of(&certified),
            }
        }

        fn part_with(
            proof: MerkleInclusionProof,
            entries: Vec<SubstateEntry>,
            source_block_ts: WeightedTimestamp,
        ) -> Provision {
            Provision::new(ProvisionParts {
                source_shard: SOURCE,
                target_shard: ShardId::leaf(1, 1),
                block_height: BlockHeight::new(1),
                source_block_ts,
                tx_hash: tx(b"tx"),
                entries: Capped::new(entries).expect("a list written out in a test"),
                proof,
                leaf: LeafPath {
                    count: 1,
                    index: 0,
                    siblings: Capped::empty(),
                },
            })
        }

        fn carried(items: &[(SubstateKey, Vec<u8>)]) -> Vec<SubstateEntry> {
            let mut entries: Vec<SubstateEntry> = items
                .iter()
                .map(|(key, value)| SubstateEntry::new(*key, Some(held(value.clone()))))
                .collect();
            entries.sort_by_key(|entry| entry.key);
            entries
        }

        #[test]
        fn an_honest_part_verifies() {
            let items = vec![entry(1), entry(2), entry(3)];
            let (state_root, proof) = build_jmt(&items);
            part_with(proof, carried(&items), WeightedTimestamp::ZERO)
                .verify(&context(state_root))
                .expect("an honest part verifies");
        }

        #[test]
        fn tampered_proof_bytes_are_refused() {
            let items = vec![entry(1), entry(2)];
            let (state_root, proof) = build_jmt(&items);
            let mut bytes = proof.as_bytes().to_vec();
            assert!(bytes.len() > 4);
            let last = bytes.len() - 1;
            bytes[last] ^= 0xFF;
            let err = part_with(
                MerkleInclusionProof::new(bytes),
                carried(&items),
                WeightedTimestamp::ZERO,
            )
            .verify(&context(state_root))
            .expect_err("a tampered proof is refused");
            assert!(
                matches!(
                    err,
                    ProvisionVerifyError::BadInclusion | ProvisionVerifyError::MalformedProof,
                ),
                "got {err:?}",
            );
        }

        /// An engagement echo carries nothing and needs no proof.
        #[test]
        fn an_echo_with_no_entries_needs_no_proof() {
            part_with(
                MerkleInclusionProof::new(vec![]),
                Vec::new(),
                WeightedTimestamp::ZERO,
            )
            .verify(&context(StateRoot::ZERO))
            .expect("an empty part with an empty proof is vacuously valid");
        }

        #[test]
        fn entries_without_a_proof_are_refused() {
            assert_eq!(
                part_with(
                    MerkleInclusionProof::new(vec![]),
                    carried(&[entry(1)]),
                    WeightedTimestamp::ZERO
                )
                .verify(&context(StateRoot::ZERO)),
                Err(ProvisionVerifyError::EmptyProofWithEntries)
            );
        }

        /// A key carried twice is refused even when both copies agree
        /// with the proof, and so is a pair out of order: a part carries
        /// each key once, ascending.
        #[test]
        fn a_repeated_or_unordered_key_is_refused() {
            let items = vec![entry(1), entry(2)];
            let (state_root, proof) = build_jmt(&items);
            let ctx = context(state_root);
            let mut doubled = carried(&items);
            doubled.insert(1, doubled[0].clone());
            assert_eq!(
                part_with(proof.clone(), doubled, WeightedTimestamp::ZERO).verify(&ctx),
                Err(ProvisionVerifyError::EntriesNotAscending { key: items[0].0 }),
            );
            let mut reversed = carried(&items);
            reversed.reverse();
            assert_eq!(
                part_with(proof, reversed.clone(), WeightedTimestamp::ZERO).verify(&ctx),
                Err(ProvisionVerifyError::EntriesNotAscending {
                    key: reversed[1].key
                }),
            );
        }

        /// Only the header says who is answering. Consumers key what they
        /// absorb off the part's own field, so the two must agree.
        #[test]
        fn a_part_naming_another_source_shard_is_refused() {
            let items = vec![entry(1)];
            let (state_root, proof) = build_jmt(&items);
            let part = Provision::new(ProvisionParts {
                source_shard: ShardId::leaf(1, 1),
                target_shard: ShardId::leaf(1, 1),
                block_height: BlockHeight::new(1),
                source_block_ts: WeightedTimestamp::ZERO,
                tx_hash: tx(b"tx"),
                entries: Capped::new(carried(&items)).unwrap(),
                proof,
                leaf: LeafPath {
                    count: 1,
                    index: 0,
                    siblings: Capped::empty(),
                },
            });
            assert_eq!(
                part.verify(&context(state_root)),
                Err(ProvisionVerifyError::SourceShardMismatch)
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
        fn an_absence_for_a_cell_the_source_shard_does_not_own_is_refused() {
            let items = vec![entry(1), entry(2)];
            let (state_root, _) = build_jmt(&items);

            // An honest absence for a cell this shard owns and lacks.
            let absent = cell(0x40, 0x40);
            let honest = {
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
                Jmt::prove(&store, &NodeKey::new(1, root_path), &[absent.to_bytes()]).unwrap()
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

            assert_eq!(
                part_with(
                    MerkleInclusionProof::new(forged.encode()),
                    vec![SubstateEntry::new(foreign, None)],
                    WeightedTimestamp::ZERO,
                )
                .verify(&context(state_root)),
                Err(ProvisionVerifyError::BadInclusion)
            );
        }

        /// The proof reconstructs the root and the part still lies: the
        /// value it carries is not the one the source's chain holds at
        /// that key, or it claims a held cell absent.
        ///
        /// Named apart from a bad proof because they are different
        /// faults — one says the evidence is unusable, the other that
        /// the evidence is fine and the part misreports it — and the
        /// consuming shard executes against the carried bytes.
        #[test]
        fn an_entry_the_proof_does_not_attest_is_refused() {
            let items = vec![entry(1), entry(2)];
            let (state_root, proof) = build_jmt(&items);
            let ctx = context(state_root);
            assert!(
                part_with(proof.clone(), carried(&items), WeightedTimestamp::ZERO)
                    .verify(&ctx)
                    .is_ok()
            );

            let key = items[0].0;
            let lied = carried(&[(key, vec![0xAA, 0xBB]), items[1].clone()]);
            assert_eq!(
                part_with(proof.clone(), lied, WeightedTimestamp::ZERO).verify(&ctx),
                Err(ProvisionVerifyError::EntryMisstated { key }),
            );

            let mut absent = carried(&items);
            for entry in &mut absent {
                if entry.key == key {
                    *entry = SubstateEntry::new(key, None);
                }
            }
            assert_eq!(
                part_with(proof, absent, WeightedTimestamp::ZERO).verify(&ctx),
                Err(ProvisionVerifyError::EntryMisstated { key }),
            );
        }

        #[test]
        fn a_mismatched_source_block_ts_is_refused() {
            // The part claims a source anchor the commit-proven header
            // does not carry: receivers would consume it as the
            // transaction clock, so verification refuses it outright.
            let items = vec![entry(1)];
            let (state_root, proof) = build_jmt(&items);
            assert_eq!(
                part_with(proof, carried(&items), WeightedTimestamp::from_millis(1))
                    .verify(&context(state_root)),
                Err(ProvisionVerifyError::SourceBlockTsMismatch)
            );
        }
    }
}
