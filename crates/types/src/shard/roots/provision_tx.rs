//! Per-target-shard [`ProvisionTxRoot`]: what it commits and how it is
//! verified.
//!
//! A source block's root for a target wraps the binary merkle root over
//! one tagged leaf per transaction it owes that target with the number
//! of those leaves. A part carries its leaf's path and that count, and a
//! receiver walks the path to the header's root: the count fixes the
//! tree's depth, so a part verifies only at a real leaf position, never
//! at an internal node, a padding slot or an index aliased past the end.

use std::collections::BTreeMap;

use hyperscale_hbor::{Capped, Hbor};
use thiserror::Error;

use crate::{
    Hash, MAX_PROVISION_TARGET_SHARDS, ProvisionTxRoot, ShardId, TopologySnapshot, Transaction,
    TxHash, Verifiable, Verified, Verify, compute_merkle_root, merkle_paths,
};

/// Domain tag of a provision leaf's preimage.
///
/// Its length is not 32, so a leaf's preimage — the tag and a 32-byte
/// transaction hash — is never 64 bytes long, which every internal
/// node's preimage is.
pub const PROVISION_LEAF_DOMAIN_TAG: &[u8] = b"hyperscale-provision-leaf-v1";

/// Domain tag of the wrap committing a provision root's leaf count.
pub const PROVISION_ROOT_DOMAIN_TAG: &[u8] = b"hyperscale-provision-root-v1";

const _: () = assert!(PROVISION_LEAF_DOMAIN_TAG.len() != 32);

/// The deepest tree a provision path walks: a block owes one target far
/// fewer than `2^32` transactions.
pub const MAX_PROVISION_PATH_DEPTH: usize = 32;

/// The leaf a provision root holds for `tx_hash`.
#[must_use]
pub fn provision_leaf(tx_hash: TxHash) -> Hash {
    Hash::from_parts(&[PROVISION_LEAF_DOMAIN_TAG, Hash::from(tx_hash).as_bytes()])
}

/// Where one part's leaf sits in its target's root: the leaf count the
/// root commits, the leaf's index, and its siblings from the leaf level
/// upward.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct LeafPath {
    /// The number of leaves under the root.
    pub count: u32,
    /// This leaf's position among them.
    pub index: u32,
    /// The leaf's siblings, leaf level first.
    pub siblings: Capped<Vec<Hash>, MAX_PROVISION_PATH_DEPTH>,
}

impl LeafPath {
    /// Every leaf's path under [`ProvisionTxRoot::over`] of `leaves`, in
    /// order.
    ///
    /// # Panics
    ///
    /// If `leaves` holds more than `u32::MAX` entries, which no block
    /// owes a target.
    #[must_use]
    pub fn all(leaves: &[Hash]) -> Vec<Self> {
        let count = u32::try_from(leaves.len()).expect("a block owes a target few leaves");
        merkle_paths(leaves)
            .into_iter()
            .zip(0..)
            .map(|(siblings, index)| Self {
                count,
                index,
                siblings: Capped::new(siblings).expect("a tree of u32 leaves is 32 deep"),
            })
            .collect()
    }
}

impl ProvisionTxRoot {
    /// The root over `leaves`, in order.
    ///
    /// # Panics
    ///
    /// If `leaves` holds more than `u32::MAX` entries, which no block
    /// owes a target.
    #[must_use]
    pub fn over(leaves: &[Hash]) -> Self {
        let count = u32::try_from(leaves.len()).expect("a block owes a target few leaves");
        Self::wrap(count, compute_merkle_root(leaves))
    }

    /// The root committing `count` leaves under `merkle_root`.
    #[must_use]
    pub fn wrap(count: u32, merkle_root: Hash) -> Self {
        Self::from_raw(Hash::from_parts(&[
            PROVISION_ROOT_DOMAIN_TAG,
            &count.to_le_bytes(),
            merkle_root.as_bytes(),
        ]))
    }

    /// The root `leaf` walks to along `path`, or `None` where the path
    /// cannot name a real leaf: a count of zero, an index at or past the
    /// count, or a sibling list other than the exact depth of a tree of
    /// `count` leaves.
    #[must_use]
    pub fn through(leaf: Hash, path: &LeafPath) -> Option<Self> {
        if path.count == 0 || path.index >= path.count {
            return None;
        }
        let depth = path.count.checked_next_power_of_two()?.trailing_zeros() as usize;
        if path.siblings.len() != depth {
            return None;
        }
        let merkle_root = path
            .siblings
            .iter()
            .enumerate()
            .fold(leaf, |node, (level, sibling)| {
                if (path.index >> level) & 1 == 0 {
                    Hash::from_parts(&[node.as_bytes(), sibling.as_bytes()])
                } else {
                    Hash::from_parts(&[sibling.as_bytes(), node.as_bytes()])
                }
            });
        Some(Self::wrap(path.count, merkle_root))
    }
}

/// Which shards commit a transaction: its participants, less any that
/// only take delivery of its owed crossings, which never include it.
/// The classification that answers it lives above this crate.
pub type CommittingShards<'a> = &'a dyn Fn(&Transaction) -> Vec<ShardId>;

/// Inputs the provision-tx-roots verifier reads against.
#[derive(Clone, Copy)]
pub struct ProvisionTxRootsContext<'a> {
    /// Source shard the block belongs to — excluded from the per-target
    /// fan-out so each shard's own provision-tx root isn't included in
    /// its own map.
    pub local_shard: ShardId,
    /// Topology snapshot anchoring shard routing — drives which target
    /// shards each cross-shard tx contributes to.
    pub topology_snapshot: &'a TopologySnapshot,
    /// The block's transactions in block order.
    pub transactions: &'a [Verifiable<Transaction>],
    /// The shards that commit each transaction, which are the only ones
    /// a bundle goes to.
    pub committing: CommittingShards<'a>,
}

/// Provision-tx roots map type as carried by [`BlockHeader`](crate::BlockHeader),
/// at the entry cap a block's provision targets are held to.
///
/// [`MAX_PROVISION_TARGET_SHARDS`]: crate::MAX_PROVISION_TARGET_SHARDS
pub type ProvisionTxRootsMap =
    Capped<BTreeMap<ShardId, ProvisionTxRoot>, MAX_PROVISION_TARGET_SHARDS>;

/// Failure modes of provision-tx-roots verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ProvisionTxRootsVerifyError {
    /// The per-target-shard map computed from the supplied transactions
    /// does not match the claimed map.
    #[error("computed provision_tx_roots {computed:?} ≠ claimed {expected:?}")]
    Mismatch {
        /// Header's claimed per-target-shard provision-tx roots.
        expected: ProvisionTxRootsMap,
        /// Map computed from the supplied transactions.
        computed: ProvisionTxRootsMap,
    },
}

impl Verified<ProvisionTxRootsMap> {
    /// Pipeline-attestation gate for slot prefill. The trust source is
    /// the verification pipeline's per-root tracking: either the
    /// header's claimed map is empty (no cross-shard targets) or an
    /// earlier verifier run already accepted `map`.
    #[must_use]
    pub const fn from_pipeline_attestation(map: ProvisionTxRootsMap) -> Self {
        Self::new_unchecked(map)
    }

    /// Compute the per-target-shard provision-tx roots from
    /// `transactions` under `topology`. Verified by construction.
    ///
    /// For each cross-shard tx, its leaf lands in the bucket of every
    /// remote shard it touches. Each bucket is committed in that order,
    /// with its leaf count, so the target shard can hold every part it
    /// receives to a real position in the full set it was meant to
    /// receive, and the part builder stages requests in the same order.
    /// Only emits an entry
    /// for targets with ≥1 tx. A block promises read sets only: a
    /// crossing record reaches its consumer as a state claim, never as
    /// a bundle. A shard that only takes delivery of the transaction
    /// never includes it, so no bundle goes there.
    ///
    /// # Panics
    ///
    /// Never: a block exports to at most one entry per other shard,
    /// which is what [`MAX_PROVISION_TARGET_SHARDS`] counts.
    ///
    /// [`MAX_PROVISION_TARGET_SHARDS`]: crate::MAX_PROVISION_TARGET_SHARDS
    #[must_use]
    pub fn compute(
        local_shard: ShardId,
        topology_snapshot: &TopologySnapshot,
        transactions: &[Verifiable<Transaction>],
        committing: CommittingShards<'_>,
    ) -> Self {
        let mut per_target: BTreeMap<ShardId, Vec<Hash>> = BTreeMap::new();

        for tx in transactions {
            if topology_snapshot.is_single_shard_transaction(tx) {
                continue;
            }
            // A transaction's fan-out is role-shaped. The payer shard and
            // the shards owning part of its read set attest toward every
            // participant: the payer's bundle is the engagement evidence
            // and flows even with no state, an owner's carries its
            // read-set values. Every other participant owes exactly one
            // edge — the engagement echo toward the payer: its commitment
            // of the transaction is what the payer's vote waits for, and
            // nobody else consumes anything from it.
            let trie = topology_snapshot.shard_trie();
            let payer_shard = trie.shard_for_prefix(tx.fee_payer());
            let owns_read_set = tx
                .routing()
                .provision_prefixes
                .iter()
                .any(|prefix| trie.shard_for_prefix(*prefix) == local_shard);
            if payer_shard != local_shard && !owns_read_set {
                per_target
                    .entry(payer_shard)
                    .or_default()
                    .push(provision_leaf(tx.hash()));
                continue;
            }
            for shard in committing(tx) {
                if shard == local_shard {
                    continue;
                }
                per_target
                    .entry(shard)
                    .or_default()
                    .push(provision_leaf(tx.hash()));
            }
        }

        let map: ProvisionTxRootsMap = Capped::new(
            per_target
                .into_iter()
                .map(|(shard, leaves)| (shard, ProvisionTxRoot::over(&leaves)))
                .collect(),
        )
        .expect("a block exports one entry per other shard");
        Self::new_unchecked(map)
    }
}

/// Construction asserts: the wrapped map equals
/// [`Verified::<ProvisionTxRootsMap>::compute`] of the block's
/// transactions under the supplied topology.
impl Verify<&ProvisionTxRootsContext<'_>> for ProvisionTxRootsMap {
    type Error = ProvisionTxRootsVerifyError;

    fn verify(&self, ctx: &ProvisionTxRootsContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let computed = Verified::<Self>::compute(
            ctx.local_shard,
            ctx.topology_snapshot,
            ctx.transactions,
            ctx.committing,
        );
        if computed.as_ref() != self {
            return Err(ProvisionTxRootsVerifyError::Mismatch {
                expected: self.clone(),
                computed: computed.into_inner(),
            });
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        TestCommittee, install_stub_protocol_statics, stub_transaction, test_prefix, test_principal,
    };
    use crate::{PrincipalAddr, TimestampRange, WeightedTimestamp};

    fn cross_shard_tx(payer: PrincipalAddr) -> Verifiable<Transaction> {
        install_stub_protocol_statics();
        let validity = TimestampRange::new(
            WeightedTimestamp::ZERO,
            WeightedTimestamp::from_millis(100_000),
        );
        Verifiable::from(Verified::new_unchecked_for_test(stub_transaction(
            payer,
            &[test_prefix(0x01), test_prefix(0x81)],
            1_000,
            validity,
        )))
    }

    fn leaves(n: u8) -> Vec<Hash> {
        (0..n)
            .map(|i| provision_leaf(TxHash::from(Hash::from_bytes(&[i]))))
            .collect()
    }

    fn path(count: u32, index: u32, siblings: Vec<Hash>) -> LeafPath {
        LeafPath {
            count,
            index,
            siblings: Capped::new(siblings).expect("a path written out in a test"),
        }
    }

    /// Every leaf of every small tree walks to the root over the whole
    /// list, at its own index and the count of the whole list.
    #[test]
    fn every_real_leaf_walks_to_the_root() {
        for n in 1..=9u8 {
            let leaves = leaves(n);
            let root = ProvisionTxRoot::over(&leaves);
            for (index, siblings) in merkle_paths(&leaves).into_iter().enumerate() {
                let index = u32::try_from(index).unwrap();
                let walked = ProvisionTxRoot::through(
                    leaves[index as usize],
                    &path(u32::from(n), index, siblings),
                );
                assert_eq!(walked, Some(root), "leaf {index} of {n}");
            }
        }
    }

    /// A count the root does not commit walks to another root, so a lie
    /// about the count fails the comparison with the header's.
    #[test]
    fn the_root_commits_its_leaf_count() {
        let leaves = leaves(3);
        let root = ProvisionTxRoot::over(&leaves);
        let siblings = merkle_paths(&leaves).swap_remove(0);
        assert_ne!(
            ProvisionTxRoot::through(leaves[0], &path(4, 0, siblings)),
            Some(root),
            "three leaves padded to four is not four leaves"
        );
        assert_ne!(
            ProvisionTxRoot::over(&leaves),
            ProvisionTxRoot::from_raw(compute_merkle_root(&leaves)),
            "the bare merkle root is not the provision root"
        );
    }

    /// A path that cannot name a real leaf is refused before it is
    /// walked: no leaves, an index at or past the count, or a sibling
    /// list off the tree's exact depth either way.
    #[test]
    fn a_path_naming_no_real_leaf_is_refused() {
        let leaves = leaves(5);
        let siblings = merkle_paths(&leaves).swap_remove(4);
        assert_eq!(siblings.len(), 3);
        assert!(ProvisionTxRoot::through(leaves[4], &path(5, 4, siblings.clone())).is_some());

        assert_eq!(
            ProvisionTxRoot::through(leaves[4], &path(0, 0, Vec::new())),
            None,
            "zero leaves"
        );
        for index in [5, 6, 7, u32::MAX] {
            assert_eq!(
                ProvisionTxRoot::through(leaves[4], &path(5, index, siblings.clone())),
                None,
                "index {index} of five"
            );
        }
        assert_eq!(
            ProvisionTxRoot::through(leaves[4], &path(5, 4, siblings[..2].to_vec())),
            None,
            "a short path"
        );
        let mut long = siblings;
        long.push(Hash::ZERO);
        assert_eq!(
            ProvisionTxRoot::through(leaves[4], &path(5, 4, long)),
            None,
            "a long path"
        );
    }

    /// An internal node presented as a leaf with the path above it walks
    /// to the right merkle root, but only on a sibling list one level
    /// short, which the committed count refuses.
    #[test]
    fn an_internal_node_is_not_a_leaf() {
        let leaves = leaves(4);
        let root = ProvisionTxRoot::over(&leaves);
        let node = Hash::from_parts(&[leaves[0].as_bytes(), leaves[1].as_bytes()]);
        let above = vec![Hash::from_parts(&[
            leaves[2].as_bytes(),
            leaves[3].as_bytes(),
        ])];
        assert_eq!(
            compute_merkle_root(&[node, above[0]]),
            compute_merkle_root(&leaves),
            "the node does sit under the merkle root"
        );
        assert_eq!(
            ProvisionTxRoot::through(node, &path(4, 0, above.clone())),
            None
        );
        assert_ne!(
            ProvisionTxRoot::through(node, &path(2, 0, above)),
            Some(root),
            "claimed as one of two leaves, it walks to another count's root"
        );
    }

    /// No leaf equals an internal node over the same leaves: a leaf's
    /// preimage is the tag and a transaction hash, never the 64 bytes of
    /// a node's.
    #[test]
    fn no_leaf_equals_an_internal_node() {
        let txs: Vec<TxHash> = (0..8u8)
            .map(|i| TxHash::from(Hash::from_bytes(&[i])))
            .collect();
        let leaves: Vec<Hash> = txs.iter().map(|tx| provision_leaf(*tx)).collect();
        let mut level = leaves.clone();
        let mut nodes = Vec::new();
        while level.len() > 1 {
            level = level
                .as_chunks::<2>()
                .0
                .iter()
                .map(|[left, right]| Hash::from_parts(&[left.as_bytes(), right.as_bytes()]))
                .collect();
            nodes.extend_from_slice(&level);
        }
        for leaf in &leaves {
            assert!(!nodes.contains(leaf));
        }
        assert_ne!(PROVISION_LEAF_DOMAIN_TAG.len() + 32, 64);
    }

    #[test]
    fn a_pure_counterpart_fans_out_to_the_payer_alone() {
        // The stub derivation carries no provision prefixes, so the
        // non-payer shard owns nothing to attest: its only edge is the
        // engagement echo toward the payer.
        let topo = TestCommittee::new(4, 42).topology_snapshot(2);
        let payer_shard = ShardId::leaf(1, 1);
        let counterpart = ShardId::leaf(1, 0);
        let txs = vec![cross_shard_tx(test_principal(0x81))];

        let everyone = |tx: &Transaction| topo.all_shards_for_transaction(tx);
        let at_counterpart =
            Verified::<ProvisionTxRootsMap>::compute(counterpart, &topo, &txs, &everyone);
        let targets: Vec<ShardId> = at_counterpart.as_ref().keys().copied().collect();
        assert_eq!(targets, vec![payer_shard]);

        // The payer still fans out to every participant: its bundle is
        // the engagement evidence.
        let at_payer =
            Verified::<ProvisionTxRootsMap>::compute(payer_shard, &topo, &txs, &everyone);
        let targets: Vec<ShardId> = at_payer.as_ref().keys().copied().collect();
        assert_eq!(targets, vec![counterpart]);

        // A participant that only takes delivery commits nothing, so no
        // bundle goes to it.
        let only_payer = |_: &Transaction| vec![payer_shard];
        let delivered =
            Verified::<ProvisionTxRootsMap>::compute(payer_shard, &topo, &txs, &only_payer);
        assert!(delivered.as_ref().is_empty());
    }
}
