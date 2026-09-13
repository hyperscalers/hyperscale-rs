//! Shard assignment and write filtering for [`StateWrites`](hyperscale_types::StateWrites).
//!
//! A substate key carries its owner prefix — the identity leaf's routing
//! half — so shard assignment is a prefix walk over the shard trie and
//! nothing else. Genesis replicates the stdlib package to every shard's
//! substate store for read availability, but each shard's prefix-rooted
//! JMT must contain only its own subtree, so what a shard commits is
//! filtered here first.

use hyperscale_types::{Hash, SettledWrites, ShardId, ShardTrie, StateWrites, WritesRoot};
use hyperscale_vm_effects::{ShardId as VmShardId, ShardResolver};
use hyperscale_vm_types::Address;

use crate::executor::protocol_hash;

/// The routing layer's view of the trie, for the classifier.
///
/// Routing partitions a declaration by the same prefix walk that decides
/// which shard commits a cell, so a leg's home and its writes' home
/// cannot disagree. The two shard types are one number — a heap index —
/// which is what lets the mapping be a cast rather than a table.
#[derive(Clone, Copy, Debug)]
pub struct TrieShardResolver<'a> {
    /// The active partition.
    pub trie: &'a ShardTrie,
}

impl ShardResolver for TrieShardResolver<'_> {
    fn shard_of(&self, owner: Address) -> VmShardId {
        VmShardId(self.trie.shard_for_prefix(owner).inner())
    }
}

/// Whether `local_shard` owns the cells under an address, under `trie`.
///
/// The predicate the filters below take and every other reading of
/// "this shard's own keys" builds from, so a caller that filters writes
/// and events in one pass states the rule once. A borrowing closure
/// rather than an [`OwnerSet`](hyperscale_vm_kernel::OwnerSet): the
/// kernel's set owns what it captures, which would clone the trie per
/// transaction on a path that projects one receipt at a time.
///
/// The answer does not depend on *which* trie, only that `local_shard`
/// is a leaf of it. A walk descends from the root and stops at the first
/// leaf on the address's path, so a reshape elsewhere subdivides some
/// other leaf's range and leaves this one's alone — every trie holding
/// `local_shard` as a leaf sorts every address the same way. That is why
/// a caller may hand this the trie it happens to hold rather than the
/// one the content committed under: the only trie that would disagree is
/// one where this shard has been cut, and past its terminal window a
/// shard commits nothing for a projection to filter. Quantities without
/// that invariance — a price level, which every fold moves for every
/// shard — must be read at the anchor instead.
pub fn owned_by(local_shard: ShardId, trie: &ShardTrie) -> impl Fn(Address) -> bool + Copy {
    move |owner| trie.shard_for_prefix(owner) == local_shard
}

/// Filter genesis writes to the cells `owned` holds, for building a
/// shard's prefix-rooted JMT.
///
/// The stdlib package is replicated to every shard's substate store for
/// read availability, but the prefix-rooted JMT must contain only this
/// shard's subtree — so the committed `state_root` is exactly the global
/// tree's node at the shard prefix. Single-shard deployments root at the
/// empty prefix, where every cell routes to the one shard and this is
/// the identity filter.
#[must_use]
pub fn filter_genesis_writes_for_shard(
    merged: &SettledWrites,
    owned: impl Fn(Address) -> bool,
) -> SettledWrites {
    SettledWrites::from_parts(
        merged
            .cells()
            .iter()
            .filter(|(key, _)| owned(key.owner))
            .map(|(key, change)| (*key, change.clone()))
            .collect(),
        merged
            .entries()
            .iter()
            .filter(|(key, _)| owned(key.owner))
            .map(|(key, change)| (*key, change.clone()))
            .collect(),
    )
}

/// Filter [`StateWrites`] to the cells `owned` holds.
///
/// A substate key carries its owner prefix — the identity leaf's routing
/// half — so shard assignment is a prefix walk and nothing else.
#[must_use]
pub fn filter_writes_for_shard(
    writes: &StateWrites,
    owned: impl Fn(Address) -> bool,
) -> StateWrites {
    let mut filtered = StateWrites::default();
    for (key, change) in &writes.cells {
        if owned(key.owner) {
            filtered.cells.insert(*key, change.clone());
        }
    }
    for (key, movement) in &writes.movements {
        if owned(key.owner) {
            filtered.movements.insert(*key, *movement);
        }
    }
    for (key, change) in &writes.entries {
        if owned(key.owner) {
            filtered.entries.insert(*key, change.clone());
        }
    }
    filtered
}

/// The `writes_root` for a [`GlobalReceipt`](hyperscale_types::GlobalReceipt)
/// over the writes the executing shard attests — the shard-projected
/// delta for a batch with cross-shard members, the full fold for a
/// whole-locality batch.
///
/// [`StateWrites`] encodes in canonical key order by construction, so the
/// root is the hash of the encoding — a pure function of content with no
/// sort step. Empty writes commit to [`WritesRoot::ZERO`].
#[must_use]
pub fn writes_root(writes: &StateWrites) -> WritesRoot {
    if writes.is_empty() {
        return WritesRoot::ZERO;
    }
    WritesRoot::from_raw(Hash::from(writes.root(protocol_hash)))
}

#[cfg(test)]
mod resolver_tests {
    use hyperscale_types::AddressClass;

    use super::*;

    /// A shard named by the routing layer is the shard that commits the
    /// cell, on both sides of a two-shard trie.
    #[test]
    fn the_resolver_names_the_shard_that_commits_the_cell() {
        let trie = ShardTrie::uniform(1);
        let resolver = TrieShardResolver { trie: &trie };
        for (byte, path) in [(0x00u8, 0u64), (0x80, 1)] {
            let owner = Address::new([byte; 31], AddressClass::Component);
            let committed = trie.shard_for_prefix(owner);
            assert_eq!(committed, ShardId::leaf(1, path));
            assert_eq!(resolver.shard_of(owner), VmShardId(committed.inner()));
            assert_eq!(
                ShardId::from_heap_index(resolver.shard_of(owner).0),
                committed
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::test_principal;
    use hyperscale_types::{ShardId, ShardTrie, StateWrites, SubstateKey, WritesRoot};
    use hyperscale_vm_types::{LocalKey, PrincipalAddr};

    use super::*;

    fn writes(cells: &[(PrincipalAddr, [u8; 16], Vec<u8>)]) -> StateWrites {
        let mut writes = StateWrites::default();
        for (owner, local, value) in cells {
            writes.cells.insert(
                SubstateKey {
                    owner: owner.address(),
                    local: LocalKey(*local),
                },
                Some(value.clone()),
            );
        }
        writes
    }

    // ── writes_root ──────────────────────────────────────────────────────────

    #[test]
    fn writes_root_empty_is_zero() {
        assert_eq!(writes_root(&StateWrites::default()), WritesRoot::ZERO);
    }

    #[test]
    fn writes_root_distinguishes_inputs() {
        let a = writes(&[(test_principal(1), [0; 16], vec![1])]);
        let b = writes(&[(test_principal(2), [0; 16], vec![1])]);
        assert_ne!(writes_root(&a), writes_root(&b));
        assert_eq!(writes_root(&a), writes_root(&a.clone()));
    }

    // ── filter_writes_for_shard ──────────────────────────────────────────────

    #[test]
    fn filter_for_shard_keeps_only_this_shard_prefixes() {
        let trie = ShardTrie::uniform_from_count(2);
        let left = test_principal(0x00);
        let right = test_principal(0xFF);
        assert_ne!(trie.shard_for_prefix(left), trie.shard_for_prefix(right));
        let all = writes(&[(left, [1; 16], vec![1]), (right, [1; 16], vec![2])]);

        let filtered = filter_writes_for_shard(&all, owned_by(trie.shard_for_prefix(left), &trie));
        assert_eq!(filtered.cells.len(), 1);
        assert_eq!(filtered.cells.keys().next().unwrap().owner, left);
    }

    #[test]
    fn filter_for_single_shard_is_the_identity() {
        let all = writes(&[
            (test_principal(1), [1; 16], vec![1]),
            (test_principal(9), [2; 16], vec![2]),
        ]);
        let single = ShardTrie::uniform_from_count(1);
        let filtered = filter_writes_for_shard(&all, owned_by(ShardId::ROOT, &single));
        assert_eq!(filtered, all);
    }
}
