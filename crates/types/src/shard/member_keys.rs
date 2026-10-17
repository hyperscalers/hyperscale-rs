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
        let material = [vec![self.material()], shard.inner().to_be_bytes().to_vec()];
        (
            owner,
            collection_id(&ProtocolHasher, owner, TICK_MEMBER_SLOT, &material),
        )
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
