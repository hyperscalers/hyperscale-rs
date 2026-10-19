//! Where a shard's tick membership family sits in its state.
//!
//! The family's collections share the shard's own owner and one slot,
//! told apart by their material, which also names the shard. A member's
//! entries are keyed by the first 128 bits of its transaction hash, so a
//! reader holding only the transaction and the shard derives the cell a
//! state claim proves.

use hyperscale_vm_effects::{ProtocolHasher, TICK_MEMBER_SLOT, collection_id};

use crate::{
    Address, CollectionId, EntryKey, ShardId, ShardTrie, SubstateKey, TxHash, entry_leaf_key,
};

/// One collection of a shard's tick membership family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberCollection {
    /// The member rows, by member.
    Members,
    /// The tick rows, by height.
    Ticks,
    /// The seats, by member.
    Seats,
    /// The reserved totals, by vault.
    Reserved,
    /// The verdict leaves, by member.
    Verdicts,
    /// The yes receipts of the stated rows, by member.
    Staged,
}

impl MemberCollection {
    /// Every collection of the family, in the order of their materials.
    const ALL: [Self; 6] = [
        Self::Members,
        Self::Ticks,
        Self::Seats,
        Self::Reserved,
        Self::Verdicts,
        Self::Staged,
    ];

    const fn material(self) -> u8 {
        match self {
            Self::Members => 0,
            Self::Ticks => 1,
            Self::Seats => 2,
            Self::Reserved => 3,
            Self::Verdicts => 4,
            Self::Staged => 5,
        }
    }

    /// This collection of `shard`'s family: its owner and its id.
    #[must_use]
    pub fn of(self, shard: ShardId) -> (Address, CollectionId) {
        let owner = ShardTrie::shard_owner(shard);
        (owner, self.id(owner, shard))
    }

    fn id(self, owner: Address, shard: ShardId) -> CollectionId {
        let material = [vec![self.material()], shard.inner().to_be_bytes().to_vec()];
        collection_id(&ProtocolHasher, owner, TICK_MEMBER_SLOT, &material)
    }

    /// The entry `tx` is keyed at in this collection of `shard`'s
    /// family.
    #[must_use]
    pub fn entry(self, shard: ShardId, tx: TxHash) -> EntryKey {
        let (owner, collection) = self.of(shard);
        EntryKey {
            owner,
            collection,
            order: member_order(tx),
        }
    }
}

/// Every collection of one shard's family, each id derived once: what a
/// holder that reads or writes the family many times keys it by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberFamily {
    owner: Address,
    ids: [CollectionId; 6],
}

impl MemberFamily {
    /// `shard`'s family, as [`MemberCollection::of`] places each of its
    /// collections.
    #[must_use]
    pub fn of(shard: ShardId) -> Self {
        let owner = ShardTrie::shard_owner(shard);
        Self {
            owner,
            ids: MemberCollection::ALL.map(|kind| kind.id(owner, shard)),
        }
    }

    /// The owner every collection of the family shares.
    #[must_use]
    pub const fn owner(&self) -> Address {
        self.owner
    }

    /// The id of the family's `kind` collection.
    #[must_use]
    pub const fn id(&self, kind: MemberCollection) -> CollectionId {
        self.ids[kind.material() as usize]
    }

    /// The entry at `order` in the family's `kind` collection.
    #[must_use]
    pub const fn entry(&self, kind: MemberCollection, order: u128) -> EntryKey {
        EntryKey {
            owner: self.owner,
            collection: self.id(kind),
            order,
        }
    }
}

/// A member's order key: the first 128 bits of its hash.
#[must_use]
pub fn member_order(tx: TxHash) -> u128 {
    let mut high = [0u8; 16];
    high.copy_from_slice(&tx.as_bytes()[..16]);
    u128::from_be_bytes(high)
}

/// The tree leaf of `tx`'s verdict in `shard`'s family: present exactly
/// while `tx`'s row there gives a verdict, holding that verdict.
#[must_use]
pub fn verdict_leaf(shard: ShardId, tx: TxHash) -> SubstateKey {
    entry_leaf_key(&ProtocolHasher, MemberCollection::Verdicts.entry(shard, tx))
}

/// The tree leaf of the yes `tx`'s row in `shard`'s family stages:
/// present exactly while the row stands stated.
#[must_use]
pub fn staged_leaf(shard: ShardId, tx: TxHash) -> SubstateKey {
    entry_leaf_key(&ProtocolHasher, MemberCollection::Staged.entry(shard, tx))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_family_places_each_collection_where_the_collection_does() {
        for shard in [ShardId::ROOT, ShardId::leaf(1, 1), ShardId::leaf(3, 5)] {
            let family = MemberFamily::of(shard);
            for kind in MemberCollection::ALL {
                assert_eq!((family.owner(), family.id(kind)), kind.of(shard));
            }
        }
    }
}
