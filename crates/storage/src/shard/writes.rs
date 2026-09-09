//! Merging and filtering [`StateWrites`].

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_hbor::{from_slice, to_vec};
use hyperscale_jmt::{Key as JmtKey, NibblePath};
use hyperscale_types::{
    Address, AddressClass, BlockHeight, CollectionId, Compose, EntryKey, EntryLeaf, Finalization,
    LocalKey, Movement, ProtocolHasher, SettledEntries, SettledWrites, StateWrites, StoredReceipt,
    SubstateKey, Verifiable, entry_leaf_key,
};
use hyperscale_vm_kernel::Substates;

use crate::shard::store::Anchored;
use crate::shard::sweep::{removals_of, with_sweep};
use crate::tree::JmtSnapshot;

/// Extract and merge the writes from stored receipts, resolving what
/// they moved against the state they land on.
///
/// Canonical projection from receipts to JMT/substate-write input.
/// Failed receipts contribute nothing (`ConsensusReceipt::writes`
/// returns `None`).
///
/// Two rules, because a receipt says two kinds of thing. An exclusive
/// write is an absolute and the last one wins, matching commit order — a
/// rule that is only sound while settlement order agrees with execution
/// order, which is what the pre-vote settlement-order gate enforces. A
/// movement is relative and composes with every other movement on the
/// cell, so the pair needs no ordering at all and cannot overwrite each
/// other whichever way round they arrive.
///
/// `prior` reads the state being settled into. It is consulted only for
/// cells something moved and nothing in this batch wrote, which is the
/// one case where the starting value is not already here.
///
/// It is [`Anchored`] because a movement's baseline decides the state
/// root. A live reader resolves against whatever the node it runs on has
/// persisted, so two validators at different persistence depths would
/// settle one block's movements onto two different values and attest two
/// different roots. Knowing the version was fixed is what this asks; a
/// caller that needs a *particular* height still checks `anchor()`,
/// because a snapshot of the wrong block is as wrong as a live read and
/// looks the same from here.
///
/// # Panics
///
/// If a certified debit runs past what its cell holds. The kernel judged
/// every movement against committed balance less outstanding holds
/// before recording it, so this is a receipt disagreeing with the state
/// it lands on, and the chain halts on it rather than settle a balance
/// nothing produced.
#[must_use]
pub fn merge_writes_from_receipts(
    receipts: &[StoredReceipt],
    prior: &dyn Anchored,
) -> SettledWrites {
    settle_writes(&merge_receipts(receipts), prior)
}

/// Everything a prepared commit lands: the receipts `finalizations`
/// settle, resolved against the parent's baseline, plus the block's own
/// creations, the sweep's removals and the refusals' retractions.
///
/// One resolution, feeding both the tree and the substate store — they
/// commit the same values or they disagree about state. It happens once
/// per block rather than per receipt because a receipt says what it
/// moved, and two receipts moving one cell compose only once something
/// has said what they moved from.
///
/// The one place either backend computes it, so a rule about how a
/// block's writes settle cannot hold on one store and not the other.
///
/// # Panics
///
/// If `baseline` is not anchored at `parent_height`. The type says the
/// baseline was fixed when it was made; which block it was fixed at is
/// the caller's to have got right, and a movement resolved against any
/// other is as wrong as one resolved live.
#[must_use]
pub fn settled_writes_at(
    finalizations: &[Arc<Verifiable<Finalization>>],
    baseline: &dyn Anchored,
    parent_height: BlockHeight,
    creations: &[(SubstateKey, Vec<u8>)],
    swept: &[SubstateKey],
) -> SettledWrites {
    assert_eq!(
        baseline.anchor(),
        parent_height,
        "a movement's baseline is anchored at the wrong height",
    );
    let settling: Vec<StoredReceipt> = finalizations
        .iter()
        .flat_map(|fw| fw.settling_receipts())
        .collect();
    with_sweep(
        merge_writes_from_receipts(&settling, baseline),
        creations,
        &removals_of(swept, finalizations),
    )
}

/// The receipts' writes folded in commit order, unresolved.
///
/// What a caller settling only part of them — a follower holding one
/// prefix of the chain's tree — restricts before resolving, since a
/// movement on a cell it does not hold reads an empty prior and is
/// nobody's debit to judge.
#[must_use]
pub fn merge_receipts(receipts: &[StoredReceipt]) -> StateWrites {
    let mut merged = StateWrites::default();
    for receipt in receipts {
        if let Some(writes) = receipt.consensus.writes() {
            fold_state_writes(&mut merged, writes);
        }
    }
    merged
}

/// Resolve `writes` against the state they settle into.
///
/// # Panics
///
/// If a certified debit runs past what its cell holds — see
/// [`merge_writes_from_receipts`].
#[must_use]
pub fn settle_writes(writes: &StateWrites, prior: &dyn Anchored) -> SettledWrites {
    writes
        .resolve(&mut |key| prior.cell(key))
        .unwrap_or_else(|over| {
            panic!(
                "BFT CRITICAL: a certified debit runs past what {:?} holds: held {}, debit {}",
                over.key, over.held, over.debit
            )
        })
}

/// Fold `writes` onto `merged`, in that order.
///
/// The one place the workspace composes two write sets. An exclusive
/// write supersedes whatever stood before it, movements included — the
/// cell's value is now stated outright. A movement composes onto what is
/// already there, because that is what commutative means.
///
/// Everything that lays one write set over another goes through here:
/// settlement, the tick chain's readable fold, and the batch fold's own
/// merge. A second copy of this rule is a second chance to drop a
/// movement silently.
pub fn fold_state_writes(merged: &mut StateWrites, writes: &StateWrites) {
    for (key, change) in &writes.cells {
        merged.cells.insert(*key, change.clone());
        merged.movements.remove(key);
    }
    for (key, movement) in &writes.movements {
        merged
            .movements
            .entry(*key)
            .and_modify(|standing| *standing = compose_movements(*key, *standing, *movement))
            .or_insert(*movement);
    }
    for (key, change) in &writes.entries {
        merged.entries.insert(*key, change.clone());
    }
}

/// One cell's movement followed by another, at the merge layer's own
/// altitude: exact gross totals while they fit, and the net the pair
/// stands for where they do not.
///
/// A receipt's own movement is consensus content and stays gross — the
/// kernel refuses a composition past `u128` there, because no execution
/// produced one. A merged movement is not: everything it feeds —
/// settlement's `resolve`, the tick view's readable fold — applies the
/// net against a prior value, and gross totals past `u128` across many
/// valid receipts are legal, since a large-supply resource moving
/// through one cell repeatedly grows them without bound while the net
/// stays a difference of two balances. The net is therefore what such a
/// composition means, and it fits `u128` on whichever side it falls.
///
/// The saturation on the same-signed arm is [`StateWrites::resolve`]'s
/// own posture: a net past `u128` is no difference of balances this
/// chain held, and settlement saturates rather than raising an error no
/// caller could act on.
///
/// # Panics
///
/// If the two name different resources. One cell holds one resource,
/// so a second denomination reaching it is a certified receipt
/// disagreeing with the state it lands on — netting across the two
/// would spend one resource out of the other's balance, and dropping
/// either would settle a movement nobody recorded.
pub(crate) fn compose_movements(key: SubstateKey, standing: Movement, next: Movement) -> Movement {
    match standing.then(next) {
        Ok(composed) => composed,
        Err(Compose::Denomination) => panic!(
            "BFT CRITICAL: movements of two resources on one cell {key:?}: {:?} then {:?}",
            standing.resource, next.resource
        ),
        Err(Compose::Overflow) => {
            let (standing_gains, standing_net) = net(standing);
            let (next_gains, next_net) = net(next);
            let (gains, magnitude) = if standing_gains == next_gains {
                (standing_gains, standing_net.saturating_add(next_net))
            } else if standing_net >= next_net {
                (standing_gains, standing_net - next_net)
            } else {
                (next_gains, next_net - standing_net)
            };
            Movement {
                resource: standing.resource,
                credit: if gains { magnitude } else { 0 },
                debit: if gains { 0 } else { magnitude },
            }
        }
    }
}

/// A movement as the direction and magnitude it nets to.
const fn net(movement: Movement) -> (bool, u128) {
    if movement.credit >= movement.debit {
        (true, movement.credit - movement.debit)
    } else {
        (false, movement.debit - movement.credit)
    }
}

/// Merge writes in order; later entries win per cell.
#[must_use]
pub fn merge_state_writes(list: &[&StateWrites]) -> StateWrites {
    let mut merged = StateWrites::default();
    for writes in list {
        fold_state_writes(&mut merged, writes);
    }
    merged
}

/// Restrict `writes` to the cells and entries whose JMT leaves fall
/// under `prefix` — the subset of a followed chain's block writes that
/// belongs to a store rooted there.
///
/// A substate key's leading bits are its owner prefix — the identity
/// leaf's routing half — so every cell of one owner shares the prefix
/// decision, and an entry's leaf is prefixed by its collection's owner
/// the same way.
#[must_use]
pub fn filter_writes_to_prefix(writes: &SettledWrites, prefix: &NibblePath) -> SettledWrites {
    SettledWrites::from_parts(
        writes
            .cells()
            .iter()
            .filter(|(key, _)| key_under_prefix(&key.to_bytes(), prefix))
            .map(|(key, change)| (*key, change.clone()))
            .collect(),
        writes
            .entries()
            .iter()
            .filter(|(key, _)| {
                key_under_prefix(&entry_leaf_key(&ProtocolHasher, **key).to_bytes(), prefix)
            })
            .map(|(key, change)| (*key, change.clone()))
            .collect(),
    )
}

/// Restrict unresolved `writes` to the cells, movements and entries
/// whose JMT leaves fall under `prefix`.
///
/// The rule [`filter_writes_to_prefix`] applies to settled writes, for a
/// follower to apply before it resolves, so a movement on a cell outside
/// its prefix is never judged against a prior it does not hold.
#[must_use]
pub fn filter_state_writes_to_prefix(writes: &StateWrites, prefix: &NibblePath) -> StateWrites {
    let under = |key: &SubstateKey| key_under_prefix(&key.to_bytes(), prefix);
    StateWrites {
        cells: writes
            .cells
            .iter()
            .filter(|(key, _)| under(key))
            .map(|(key, change)| (*key, change.clone()))
            .collect(),
        movements: writes
            .movements
            .iter()
            .filter(|(key, _)| under(key))
            .map(|(key, movement)| (*key, *movement))
            .collect(),
        entries: writes
            .entries
            .iter()
            .filter(|(key, _)| {
                key_under_prefix(&entry_leaf_key(&ProtocolHasher, **key).to_bytes(), prefix)
            })
            .map(|(key, change)| (*key, change.clone()))
            .collect(),
    }
}

/// Decode a leaf back to the entry it commits, if it is one.
///
/// An entry leaf's value parses as an [`EntryLeaf`] and the leaf key
/// re-derives from it under the leaf's owner. A cell value cannot
/// satisfy both — the leaf-key derivation is domain-separated — so this
/// is the import path's discriminator, and the index it rebuilds equals
/// the tree's entry leaves by construction.
#[must_use]
pub fn entry_from_leaf(key: SubstateKey, value: &[u8]) -> Option<(EntryKey, Vec<u8>)> {
    let leaf: EntryLeaf = from_slice(value).ok()?;
    let entry_key = EntryKey {
        owner: key.owner,
        collection: leaf.collection,
        order: leaf.order,
    };
    (entry_leaf_key(&ProtocolHasher, entry_key) == key).then_some((entry_key, leaf.value))
}

/// The leaf-row form of a settled set's entries: each entry keyed by its
/// derived leaf key, valued by its self-describing [`EntryLeaf`]
/// encoding, `None` a removal.
///
/// This is what commits — into the state CF, the history log, and the
/// tree — beside the cells; the order-keyed index is maintained
/// separately by each backend, and at every height it must equal these
/// leaves.
///
/// # Panics
///
/// Panics if an entry value exceeds the encoder's bounds, which none
/// within the cell cap can.
#[must_use]
pub fn entry_leaf_rows(entries: &SettledEntries) -> BTreeMap<SubstateKey, Option<Vec<u8>>> {
    entries
        .iter()
        .map(|(key, change)| {
            let leaf_key = entry_leaf_key(&ProtocolHasher, *key);
            let leaf_value = change.as_ref().map(|value| entry_leaf_value(key, value));
            (leaf_key, leaf_value)
        })
        .collect()
}

/// The latest pending write of `key` across the unpersisted ancestor
/// chain, or `None` when no pending block touched it and the persisted
/// store owns the answer.
///
/// The outer `Some` distinguishes a pending tombstone (`Some(None)`)
/// from no pending write at all.
///
/// This is the writer-side spelling of the overlay-first read the
/// pending chain's views make: a batch prepared over unpersisted
/// ancestors applies only after they have, so its priors must be judged
/// against their settled writes, not the persisted store.
///
/// Latest by snapshot height rather than slice position, so the answer
/// does not depend on how a caller happened to order the chain.
#[allow(clippy::option_option)] // outer = "a pending block wrote it", inner = that write
pub fn pending_write<K: Ord>(
    pending: &[Arc<JmtSnapshot>],
    writes_of: impl Fn(&SettledWrites) -> &BTreeMap<K, Option<Vec<u8>>>,
    key: &K,
) -> Option<Option<Vec<u8>>> {
    pending
        .iter()
        .filter_map(|snapshot| {
            writes_of(&snapshot.settled)
                .get(key)
                .map(|prior| (snapshot.new_height, prior))
        })
        .max_by_key(|(height, _)| *height)
        .map(|(_, prior)| prior.clone())
}

/// One entry's self-describing leaf encoding: the bytes its leaf row
/// holds wherever it commits.
///
/// # Panics
///
/// Panics if the entry value exceeds the encoder's bounds, which none
/// within the cell cap can.
#[must_use]
pub fn entry_leaf_value(key: &EntryKey, value: &[u8]) -> Vec<u8> {
    to_vec(&EntryLeaf {
        collection: key.collection,
        order: key.order,
        value: value.to_vec(),
    })
    .expect("an entry leaf within the cell cap stays within the encoder's bounds")
}

/// The slice of an entry-keyed overlay covering one collection's
/// `[lo, hi]` interval, ascending; `None` values are removals.
#[must_use]
pub fn entry_overlay_range(
    overlay: &BTreeMap<EntryKey, Option<Vec<u8>>>,
    owner: Address,
    collection: CollectionId,
    lo: u128,
    hi: u128,
) -> Vec<(u128, Option<Vec<u8>>)> {
    if lo > hi {
        return Vec::new();
    }
    let lo_key = EntryKey {
        owner,
        collection,
        order: lo,
    };
    let hi_key = EntryKey {
        owner,
        collection,
        order: hi,
    };
    overlay
        .range(lo_key..=hi_key)
        .map(|(key, change)| (key.order, change.clone()))
        .collect()
}

/// The layered range read every overlay reader shares: fetch the base
/// interval at a limit widened by the overlay's removal count, then let
/// overlay values and removals win per order key.
///
/// The widening is what lets a mostly-deleted interval still fill
/// `limit` from the survivors behind it.
///
/// `base` receives the widened limit and may refuse (`None`), which
/// refuses the whole read — the height-pinned fetch's shape. The
/// widening arithmetic lives only here: a second copy would be a second
/// chance to fill a mostly-deleted interval short.
#[must_use]
pub fn merge_entry_overlay_with(
    base: impl FnOnce(usize) -> Option<Vec<(u128, Vec<u8>)>>,
    overlay: Vec<(u128, Option<Vec<u8>>)>,
    limit: usize,
) -> Option<Vec<(u128, Vec<u8>)>> {
    if limit == 0 {
        return Some(Vec::new());
    }
    let tombstones = overlay
        .iter()
        .filter(|(_, change)| change.is_none())
        .count();
    let mut merged: BTreeMap<u128, Vec<u8>> = base(limit.saturating_add(tombstones))?
        .into_iter()
        .collect();
    for (order, change) in overlay {
        match change {
            Some(value) => {
                merged.insert(order, value);
            }
            None => {
                merged.remove(&order);
            }
        }
    }
    Some(merged.into_iter().take(limit).collect())
}

/// [`merge_entry_overlay_with`] over a [`Substates`] base — the
/// infallible form every overlaid `entries_in_range` takes.
#[must_use]
pub fn merge_entry_overlay(
    base: &(impl Substates + ?Sized),
    overlay: Vec<(u128, Option<Vec<u8>>)>,
    owner: Address,
    collection: CollectionId,
    lo: u128,
    hi: u128,
    limit: usize,
) -> Vec<(u128, Vec<u8>)> {
    if lo > hi {
        return Vec::new();
    }
    merge_entry_overlay_with(
        |widened| Some(base.entries_in_range(owner, collection, lo, hi, widened)),
        overlay,
        limit,
    )
    .unwrap_or_default()
}

/// The lowest leaf key under `prefix`: its bits, then zeros.
///
/// The keyspace is owner-major and an owner is wholly one prefix's, so a
/// prefix names a contiguous run of keys and this is where it starts —
/// the seek point a scan of one shard's slice begins at, with
/// [`key_under_prefix`] ending it.
#[must_use]
pub fn prefix_low_key(prefix: &NibblePath) -> SubstateKey {
    let mut body = [0u8; 31];
    let bits = prefix.as_bytes();
    let taken = bits.len().min(body.len());
    body[..taken].copy_from_slice(&bits[..taken]);
    SubstateKey {
        // The lowest assigned class tag, so the key sorts at or below
        // every address sharing these leading bits.
        owner: Address::new(body, AddressClass::Principal),
        local: LocalKey([0; 16]),
    }
}

/// Whether `key`'s leading bits equal `prefix` — the subtree-membership
/// test shard prefixes partition the keyspace by.
#[must_use]
pub fn key_under_prefix(key: &JmtKey, prefix: &NibblePath) -> bool {
    (0..prefix.len()).all(|i| {
        let key_bit = (key[usize::from(i / 8)] >> (7 - (i % 8))) & 1;
        prefix.bits_at(i, 1) == key_bit
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_jmt::NibblePath;
    use hyperscale_types::test_utils::test_prefix;
    use hyperscale_types::{Address, LocalKey, ResourceAddr, SubstateKey};

    use super::*;

    fn writes_for(owner: Address, value: u8) -> SettledWrites {
        SettledWrites::from_absolutes(BTreeMap::from([(
            SubstateKey {
                owner,
                local: LocalKey([1; 16]),
            },
            Some(vec![value]),
        )]))
    }

    fn key(local: u8) -> SubstateKey {
        SubstateKey {
            owner: test_prefix(1),
            local: LocalKey([local; 16]),
        }
    }

    /// Two movements naming different resources on one cell are a
    /// receipt disagreeing with the state it lands on, and the merge
    /// halts on them rather than net one resource out of the other.
    #[test]
    #[should_panic(expected = "BFT CRITICAL")]
    fn movements_of_two_resources_on_one_cell_halt_the_merge() {
        let (xrd, other) = (ResourceAddr::new([7; 31]), ResourceAddr::new([8; 31]));
        let _ = compose_movements(key(1), Movement::debit(xrd, 1), Movement::debit(other, 1));
    }

    fn relative(owner: Address, value: u8) -> StateWrites {
        let mut writes = StateWrites::default();
        writes.cells.insert(
            SubstateKey {
                owner,
                local: LocalKey([1; 16]),
            },
            Some(vec![value]),
        );
        writes
    }

    #[test]
    fn later_writes_win_per_cell() {
        let merged =
            merge_state_writes(&[&relative(test_prefix(1), 1), &relative(test_prefix(1), 2)]);
        assert_eq!(merged.cells.len(), 1);
        assert_eq!(merged.cells.values().next().unwrap(), &Some(vec![2]));
    }

    /// Gross totals past `u128` are legal at the merge layer — many
    /// valid receipts moving one large-supply resource through one cell
    /// grow them without bound — and what such a composition means is
    /// the net, which is what everything downstream applies.
    #[test]
    fn a_composition_past_u128_keeps_its_net() {
        let resource = ResourceAddr::new([7; 31]);
        let paid_in = Movement {
            resource,
            credit: u128::MAX,
            debit: 0,
        };
        let cycled = Movement {
            resource,
            credit: 5,
            debit: u128::MAX,
        };
        // Exact while it fits: nothing about a small pair is reduced.
        let small = Movement {
            resource,
            credit: 3,
            debit: 1,
        };
        assert_eq!(compose_movements(key(1), small, small).credit, 6);
        assert_eq!(compose_movements(key(1), small, small).debit, 2);
        // Past the width, the net survives: everything paid in came
        // back out but five, and the composed movement says exactly
        // that on the crediting side.
        let folded = compose_movements(key(1), paid_in, cycled);
        assert_eq!((folded.credit, folded.debit), (5, 0));
        // The other way round nets to a debit.
        let folded = compose_movements(key(1), cycled, paid_in);
        assert_eq!((folded.credit, folded.debit), (5, 0));
        let drained = compose_movements(
            key(1),
            Movement {
                resource,
                credit: 0,
                debit: u128::MAX,
            },
            Movement {
                resource,
                credit: u128::MAX,
                debit: 3,
            },
        );
        assert_eq!((drained.credit, drained.debit), (0, 3));
    }

    #[test]
    fn prefix_filter_splits_on_the_leading_bit() {
        let low = writes_for(test_prefix(0x00), 1);
        let high = writes_for(test_prefix(0xFF), 2);
        let merged = SettledWrites::from_absolutes(
            low.cells()
                .iter()
                .chain(high.cells())
                .map(|(key, change)| (*key, change.clone()))
                .collect(),
        );

        let mut left = NibblePath::empty();
        left.push_bits(0, 1);
        let mut right = NibblePath::empty();
        right.push_bits(1, 1);
        assert_eq!(filter_writes_to_prefix(&merged, &left), low);
        assert_eq!(filter_writes_to_prefix(&merged, &right), high);
        assert_eq!(
            filter_writes_to_prefix(&merged, &NibblePath::empty()),
            merged
        );
    }
    #[test]
    fn entries_fold_last_writer_wins_and_filter_by_owner_prefix() {
        let key = |order: u128| EntryKey {
            owner: test_prefix(0x00),
            collection: CollectionId([4; 16]),
            order,
        };
        let mut first = StateWrites::default();
        first.entries.insert(key(5), Some(vec![1]));
        first.entries.insert(key(9), Some(vec![9]));
        let mut second = StateWrites::default();
        second.entries.insert(key(5), None);
        let merged = merge_state_writes(&[&first, &second]);
        assert_eq!(merged.entries[&key(5)], None);
        assert_eq!(merged.entries[&key(9)], Some(vec![9]));

        // The prefix filter follows the collection owner's leaf prefix.
        let settled = merged.resolve(&mut |_| None).expect("the debit fits");
        let mut left = NibblePath::empty();
        left.push_bits(0, 1);
        let mut right = NibblePath::empty();
        right.push_bits(1, 1);
        assert_eq!(filter_writes_to_prefix(&settled, &left), settled);
        assert!(filter_writes_to_prefix(&settled, &right).is_empty());
    }

    #[test]
    fn a_leaf_round_trips_to_its_entry_and_a_cell_does_not() {
        let key = EntryKey {
            owner: test_prefix(7),
            collection: CollectionId([4; 16]),
            order: 12,
        };
        let rows = entry_leaf_rows(&BTreeMap::from([(key, Some(vec![3, 3]))]));
        let (leaf_key, leaf_value) = rows.into_iter().next().unwrap();
        assert_eq!(
            entry_from_leaf(leaf_key, &leaf_value.unwrap()),
            Some((key, vec![3, 3]))
        );
        // An ordinary cell value never re-derives the leaf key.
        assert_eq!(entry_from_leaf(leaf_key, &[1, 2, 3]), None);
    }

    #[test]
    fn overlay_merge_wins_per_order_and_tombstones_widen_the_fetch() {
        struct Base;
        impl Substates for Base {
            fn cell(&self, _key: SubstateKey) -> Option<Vec<u8>> {
                None
            }
            fn entries_in_range(
                &self,
                _owner: Address,
                _collection: CollectionId,
                lo: u128,
                hi: u128,
                limit: usize,
            ) -> Vec<(u128, Vec<u8>)> {
                (lo..=hi)
                    .take(limit)
                    .map(|order| (order, vec![u8::try_from(order % 251).unwrap()]))
                    .collect()
            }
        }
        let owner: Address = test_prefix(1);
        let collection = CollectionId([4; 16]);
        // Overlay: delete order 0, overwrite order 1, insert nothing new.
        let overlay = vec![(0u128, None), (1, Some(vec![99]))];
        let merged = merge_entry_overlay(&Base, overlay, owner, collection, 0, 100, 2);
        // The tombstone widened the base fetch, so the limit still fills:
        // order 0 is gone, 1 is overwritten, 2 survives from the base.
        assert_eq!(merged, vec![(1, vec![99]), (2, vec![2])]);
    }
}
