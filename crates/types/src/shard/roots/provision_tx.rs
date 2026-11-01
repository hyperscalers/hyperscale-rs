//! Per-target-shard [`ProvisionTxRoot`]: what it commits and how it is
//! verified.
//!
//! A source block's root for a target wraps the binary merkle root over
//! one tagged leaf per transaction it owes that target with the number
//! of those leaves. Each leaf binds the transaction and the keys its
//! part serves, so a part missing a key, or carrying one more, walks to
//! another root. A part carries its leaf's path and that count, and a
//! receiver recomputes the leaf from the part and walks the path to the
//! header's root: the count fixes the tree's depth, so a part verifies
//! only at a real leaf position, never at an internal node, a padding
//! slot or an index aliased past the end.

use std::collections::BTreeMap;

use hyperscale_hbor::{Capped, Hbor};

use crate::{
    Hash, MAX_PROVISION_TARGET_SHARDS, ProvisionTxRoot, ShardId, SubstateKey, TxHash,
    compute_merkle_root, merkle_paths,
};

/// Domain tag of a provision leaf's preimage.
///
/// Its length is not 32, so a leaf's preimage — the tag, a 32-byte
/// transaction hash and a 32-byte served digest — is never 64 bytes
/// long, which every internal node's preimage is.
pub const PROVISION_LEAF_DOMAIN_TAG: &[u8] = b"hyperscale-provision-leaf-v1";

/// Domain tag of the digest over a part's served keys.
pub const PROVISION_SERVED_DOMAIN_TAG: &[u8] = b"hyperscale-provision-served-v1";

/// Domain tag of the wrap committing a provision root's leaf count.
pub const PROVISION_ROOT_DOMAIN_TAG: &[u8] = b"hyperscale-provision-root-v1";

const _: () = assert!(PROVISION_LEAF_DOMAIN_TAG.len() != 32);

/// The deepest tree a provision path walks: a block owes one target far
/// fewer than `2^32` transactions.
pub const MAX_PROVISION_PATH_DEPTH: usize = 32;

/// The digest over `keys`, the keys one part serves in the order it
/// carries them: ascending and once each for every part a source builds.
///
/// It commits the count and every key, so dropping, adding or replacing
/// one changes it. Values and presence are the part's proof's to bind.
///
/// # Panics
///
/// If `keys` holds more than `u32::MAX` entries, which no part carries.
#[must_use]
pub fn served_digest(keys: impl ExactSizeIterator<Item = SubstateKey>) -> Hash {
    let count = u32::try_from(keys.len()).expect("a part serves few keys");
    let keys: Vec<_> = keys.map(|key| key.to_bytes()).collect();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(keys.len() + 2);
    parts.push(PROVISION_SERVED_DOMAIN_TAG);
    let count = count.to_le_bytes();
    parts.push(&count);
    parts.extend(keys.iter().map(<[u8; _]>::as_slice));
    Hash::from_parts(&parts)
}

/// The leaf a provision root holds for `tx_hash`, whose part serves the
/// keys `served` digests.
#[must_use]
pub fn provision_leaf(tx_hash: TxHash, served: Hash) -> Hash {
    Hash::from_parts(&[
        PROVISION_LEAF_DOMAIN_TAG,
        Hash::from(tx_hash).as_bytes(),
        served.as_bytes(),
    ])
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

/// A target's leaf count and the bare merkle root over its leaves: what
/// any holder of the source block can state, and what wraps to the
/// header's root when it is true.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub struct ProvisionCount {
    /// The number of leaves the source block owes the target.
    pub count: u32,
    /// The merkle root over those leaves, before the count is wrapped in.
    pub merkle_root: Hash,
}

impl ProvisionCount {
    /// The count `leaves` makes.
    ///
    /// # Panics
    ///
    /// If `leaves` holds more than `u32::MAX` entries, which no block
    /// owes a target.
    #[must_use]
    pub fn over(leaves: &[Hash]) -> Self {
        Self {
            count: u32::try_from(leaves.len()).expect("a block owes a target few leaves"),
            merkle_root: compute_merkle_root(leaves),
        }
    }

    /// The root this count wraps to: equal to the header's when the
    /// count is true.
    #[must_use]
    pub fn root(&self) -> ProvisionTxRoot {
        ProvisionTxRoot::wrap(self.count, self.merkle_root)
    }
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
        ProvisionCount::over(leaves).root()
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
        Some(Self::wrap(path.count, path.merkle_root(leaf)?))
    }
}

impl LeafPath {
    /// The bare merkle root `leaf` walks to along this path, under the
    /// same refusals as [`ProvisionTxRoot::through`]: what a holder of
    /// one checked part states as the count witness beside its count.
    #[must_use]
    pub fn merkle_root(&self, leaf: Hash) -> Option<Hash> {
        if self.count == 0 || self.index >= self.count {
            return None;
        }
        let depth = self.count.checked_next_power_of_two()?.trailing_zeros() as usize;
        if self.siblings.len() != depth {
            return None;
        }
        Some(
            self.siblings
                .iter()
                .enumerate()
                .fold(leaf, |node, (level, sibling)| {
                    if (self.index >> level) & 1 == 0 {
                        Hash::from_parts(&[node.as_bytes(), sibling.as_bytes()])
                    } else {
                        Hash::from_parts(&[sibling.as_bytes(), node.as_bytes()])
                    }
                }),
        )
    }
}

/// Provision-tx roots map type as carried by [`BlockHeader`](crate::BlockHeader),
/// at the entry cap a block's provision targets are held to.
///
/// [`MAX_PROVISION_TARGET_SHARDS`]: crate::MAX_PROVISION_TARGET_SHARDS
pub type ProvisionTxRootsMap =
    Capped<BTreeMap<ShardId, ProvisionTxRoot>, MAX_PROVISION_TARGET_SHARDS>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_key;

    fn leaves(n: u8) -> Vec<Hash> {
        (0..n)
            .map(|i| {
                provision_leaf(
                    TxHash::from(Hash::from_bytes(&[i])),
                    served_digest(std::iter::empty()),
                )
            })
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
    /// preimage is the tag, a transaction hash and a digest, never the
    /// 64 bytes of a node's.
    #[test]
    fn no_leaf_equals_an_internal_node() {
        let txs: Vec<TxHash> = (0..8u8)
            .map(|i| TxHash::from(Hash::from_bytes(&[i])))
            .collect();
        let leaves: Vec<Hash> = txs
            .iter()
            .map(|tx| provision_leaf(*tx, served_digest(std::iter::empty())))
            .collect();
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
        assert_ne!(PROVISION_LEAF_DOMAIN_TAG.len() + 64, 64);
    }

    /// A transaction's leaf moves with every key its part serves: one
    /// dropped, one added or one replaced each walk to another leaf, and
    /// so do the same keys under another transaction.
    #[test]
    fn a_leaf_binds_every_served_key() {
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        let leaf = |keys: &[u8]| {
            provision_leaf(tx, served_digest(keys.iter().map(|seed| test_key(*seed))))
        };
        let honest = leaf(&[1, 2, 3]);
        for other in [
            leaf(&[1, 3]),
            leaf(&[1, 2, 3, 4]),
            leaf(&[1, 2, 4]),
            leaf(&[]),
        ] {
            assert_ne!(other, honest);
        }
        assert_eq!(leaf(&[1, 2, 3]), honest);
        assert_ne!(
            provision_leaf(
                TxHash::from(Hash::from_bytes(b"other")),
                served_digest([1, 2, 3].map(test_key).into_iter()),
            ),
            honest,
        );
    }
}
