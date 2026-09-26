//! Fee holds as committed state: what a committed transaction reserves
//! against its payer's vault until the payer's shard burns its price.
//!
//! One [`FeeHold`] cell per `(vault, tx)` under the vault's owner, beside
//! a per-vault total, both in the kernel band. The commit fold writes a
//! hold for every transaction a block carries whose vault sits under the
//! store's prefix, and lowers the total by the hold's own fee wherever
//! the block's writes delete one. The deletion rides the write set that
//! burns the price, so a hold ends exactly where its charge lands.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_jmt::NibblePath;
use hyperscale_types::{SettledWrites, SubstateKey, Transaction, TxHash};
use hyperscale_vm_effects::vocabulary::vault_cell;
use hyperscale_vm_effects::{
    FeeHold, ProtocolHasher, fee_hold_key, fee_hold_total_key, protocol_resource,
};

use crate::Substates;
use crate::shard::writes::key_under_prefix;

/// What one transaction reserves: the vault its fee burns from and the
/// signed ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeTerms {
    /// The payer's vault of the protocol resource.
    pub vault: SubstateKey,
    /// The transaction.
    pub tx: TxHash,
    /// Its signed ceiling.
    pub max_fee: u128,
}

impl FeeTerms {
    /// Off the transaction's signed terms alone: the vault is the payer's
    /// protocol resource vault, the key the derivation names as its fee
    /// vault, read without deriving, so a replica that cannot route the
    /// transaction folds the same hold.
    #[must_use]
    pub fn of(tx: &Transaction) -> Self {
        let terms = tx.terms();
        Self {
            vault: vault_cell(
                &ProtocolHasher,
                terms.fee_payer,
                protocol_resource(&ProtocolHasher),
            ),
            tx: tx.hash(),
            max_fee: terms.max_fee,
        }
    }

    /// The cell holding this reservation.
    #[must_use]
    pub fn hold_key(&self) -> SubstateKey {
        fee_hold_key(&ProtocolHasher, self.vault, self.tx)
    }
}

/// A vault's held total as `state` holds it: zero where absent, since a
/// total is deleted at zero.
///
/// # Panics
///
/// On a total that is not an amount, which no fold writes.
fn held_total(state: &(impl Substates + ?Sized), vault: SubstateKey) -> u128 {
    state
        .cell(fee_hold_total_key(&ProtocolHasher, vault))
        .map_or(0, |bytes| decode_total(&bytes))
}

/// A total's bytes read as an amount.
///
/// # Panics
///
/// On bytes that are not an amount, which no fold writes.
#[must_use]
pub fn decode_total(bytes: &[u8]) -> u128 {
    u128::from_le_bytes(
        bytes
            .try_into()
            .expect("a held total is an amount's sixteen bytes"),
    )
}

/// The hold and total writes a block adds to `settled`, its own writes
/// resolved against `prior`, restricted to `prefix`.
///
/// Releases are the hold cells `settled` deletes that stand in `prior`,
/// each lowering its vault's total by its own fee; a deletion of a hold
/// that does not stand moves nothing. Inclusions are every transaction
/// of `fees` whose hold neither stands in `prior` nor is written by
/// `settled`: a standing hold adds nothing, and a hold released in the
/// block that includes it is never written. A total is written only
/// where it changes, and deleted at zero.
fn fee_hold_writes(
    fees: &[FeeTerms],
    settled: &SettledWrites,
    prior: &(impl Substates + ?Sized),
    prefix: &NibblePath,
) -> Vec<(SubstateKey, Option<Vec<u8>>)> {
    let under = |key: &SubstateKey| key_under_prefix(&key.to_bytes(), prefix);
    let mut delta: BTreeMap<SubstateKey, (u128, u128)> = BTreeMap::new();
    for (key, change) in settled.cells() {
        if change.is_some() || !under(key) {
            continue;
        }
        let Some(hold) = prior.cell(*key).as_deref().and_then(FeeHold::from_bytes) else {
            continue;
        };
        if hold.key(&ProtocolHasher, key.owner) != *key {
            continue;
        }
        let released = &mut delta.entry(hold.vault(key.owner)).or_default().1;
        *released = released.saturating_add(hold.fee);
    }
    let mut writes = Vec::new();
    let mut included = BTreeSet::new();
    for fee in fees.iter().filter(|fee| under(&fee.vault)) {
        let key = fee.hold_key();
        if settled.cells().contains_key(&key) || !included.insert(key) || prior.cell(key).is_some()
        {
            continue;
        }
        let hold = FeeHold {
            vault: fee.vault.local,
            tx: fee.tx,
            fee: fee.max_fee,
        };
        writes.push((key, Some(hold.to_bytes())));
        let added = &mut delta.entry(fee.vault).or_default().0;
        *added = added.saturating_add(fee.max_fee);
    }
    for (vault, (added, released)) in delta {
        let standing = held_total(prior, vault);
        let total = standing
            .checked_add(added)
            .and_then(|raised| raised.checked_sub(released))
            .expect("a vault's held total covers every standing hold's fee");
        if total != standing {
            let key = fee_hold_total_key(&ProtocolHasher, vault);
            writes.push((key, (total != 0).then(|| total.to_le_bytes().to_vec())));
        }
    }
    writes
}

/// `settled` with the block's hold and total writes folded in.
///
/// # Panics
///
/// Where a hold or total write lands on a cell the block's other writes
/// also write, which no receipt does: a receipt only deletes a hold, and
/// a deleted hold is never written here. Where a vault's total falls
/// short of the holds a block releases against it, which no fold that
/// writes both together leaves.
#[must_use]
pub fn with_fee_holds(
    settled: SettledWrites,
    fees: &[FeeTerms],
    prior: &(impl Substates + ?Sized),
    prefix: &NibblePath,
) -> SettledWrites {
    let writes = fee_hold_writes(fees, &settled, prior, prefix);
    if writes.is_empty() {
        return settled;
    }
    let (mut cells, entries) = settled.into_parts();
    for (key, change) in writes {
        assert!(
            cells.insert(key, change).is_none(),
            "the chain wrote the fee hold family at {key:?}, which this block's receipts also write",
        );
    }
    SettledWrites::from_parts(cells, entries)
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{Address, CollectionId, Hash, PrincipalAddr, SettledCells};

    use super::*;

    /// Point cells alone, for the fold to read and write.
    #[derive(Default)]
    struct Cells(BTreeMap<SubstateKey, Vec<u8>>);

    impl Cells {
        /// Fold one block carrying `fees`, whose other writes are
        /// `released` hold deletions, under the root prefix.
        fn fold(&mut self, fees: &[FeeTerms], released: &[FeeTerms]) -> SettledWrites {
            self.fold_under(fees, released, &NibblePath::empty())
        }

        fn fold_under(
            &mut self,
            fees: &[FeeTerms],
            released: &[FeeTerms],
            prefix: &NibblePath,
        ) -> SettledWrites {
            let deletions: SettledCells =
                released.iter().map(|fee| (fee.hold_key(), None)).collect();
            let settled = with_fee_holds(
                SettledWrites::from_absolutes(deletions),
                fees,
                &*self,
                prefix,
            );
            for (key, change) in settled.cells() {
                match change {
                    Some(bytes) => self.0.insert(*key, bytes.clone()),
                    None => self.0.remove(key),
                };
            }
            settled
        }

        fn total(&self, vault: SubstateKey) -> u128 {
            held_total(self, vault)
        }

        fn holds(&self, fee: &FeeTerms) -> bool {
            self.0.contains_key(&fee.hold_key())
        }
    }

    impl Substates for Cells {
        fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
            self.0.get(&key).cloned()
        }

        fn entries_in_range(
            &self,
            _owner: Address,
            _collection: CollectionId,
            _lo: u128,
            _hi: u128,
            _limit: usize,
        ) -> Vec<(u128, Vec<u8>)> {
            Vec::new()
        }
    }

    fn vault(seed: u8) -> SubstateKey {
        vault_cell(
            &ProtocolHasher,
            PrincipalAddr::new([seed; 31]),
            protocol_resource(&ProtocolHasher),
        )
    }

    fn fee(payer: u8, tx: u8, max_fee: u128) -> FeeTerms {
        FeeTerms {
            vault: vault(payer),
            tx: TxHash::from(Hash::from_bytes(&[tx; 32])),
            max_fee,
        }
    }

    #[test]
    fn an_inclusion_writes_a_hold_and_raises_the_total() {
        let mut state = Cells::default();
        let one = fee(1, 1, 100);
        let two = fee(1, 2, 30);
        state.fold(&[one, two], &[]);
        assert!(state.holds(&one) && state.holds(&two));
        assert_eq!(state.total(vault(1)), 130);
        let hold = FeeHold::from_bytes(&state.0[&one.hold_key()]).expect("a hold");
        assert_eq!(hold.key(&ProtocolHasher, vault(1).owner), one.hold_key());
        assert_eq!(hold.fee, 100);
    }

    #[test]
    fn a_release_deletes_the_hold_and_lowers_the_total_by_its_own_fee() {
        let mut state = Cells::default();
        let one = fee(1, 1, 100);
        let two = fee(1, 2, 30);
        state.fold(&[one, two], &[]);
        state.fold(&[], &[one]);
        assert!(!state.holds(&one) && state.holds(&two));
        assert_eq!(state.total(vault(1)), 30);
    }

    #[test]
    fn the_total_is_deleted_at_zero() {
        let mut state = Cells::default();
        let one = fee(1, 1, 100);
        state.fold(&[one], &[]);
        let settled = state.fold(&[], &[one]);
        let total = fee_hold_total_key(&ProtocolHasher, vault(1));
        assert_eq!(settled.cells().get(&total), Some(&None));
        assert!(state.0.is_empty(), "{:?}", state.0.keys());
    }

    /// A deletion of a hold that does not stand, a finalization naming a
    /// transaction this shard never held a fee for, moves no total.
    #[test]
    fn a_release_of_no_standing_hold_moves_nothing() {
        let mut state = Cells::default();
        let one = fee(1, 1, 100);
        state.fold(&[one], &[]);
        let settled = state.fold(&[], &[fee(1, 9, 100)]);
        let total = fee_hold_total_key(&ProtocolHasher, vault(1));
        assert!(!settled.cells().contains_key(&total));
        assert_eq!(state.total(vault(1)), 100);
    }

    #[test]
    fn a_second_inclusion_of_a_standing_hold_adds_nothing() {
        let mut state = Cells::default();
        let one = fee(1, 1, 100);
        state.fold(&[one], &[]);
        let settled = state.fold(&[one], &[]);
        assert!(settled.is_empty(), "{settled:?}");
        state.fold(&[one, one], &[]);
        assert_eq!(state.total(vault(1)), 100);
    }

    #[test]
    fn a_payer_outside_the_prefix_writes_nothing_here() {
        let mut state = Cells::default();
        let here = fee(1, 1, 100);
        let there = fee(2, 2, 100);
        assert_ne!(
            here.vault.to_bytes().as_ref()[0],
            there.vault.to_bytes().as_ref()[0],
            "the two vaults sit under different first bytes",
        );
        let prefix = NibblePath::from_key_prefix(&here.vault.to_bytes(), 8);
        state.fold_under(&[here, there], &[], &prefix);
        assert!(state.holds(&here) && !state.holds(&there));
        assert_eq!(state.total(vault(2)), 0);
        assert!(
            state
                .0
                .keys()
                .all(|key| key_under_prefix(&key.to_bytes(), &prefix))
        );
    }

    /// Inclusions fold before releases: a block that includes one
    /// transaction and releases another from the same vault writes the
    /// total once, over both; a hold released in the block that includes
    /// it is never written.
    #[test]
    fn inclusions_fold_before_releases() {
        let mut state = Cells::default();
        let old = fee(1, 1, 100);
        let new = fee(1, 2, 40);
        state.fold(&[old], &[]);
        state.fold(&[new], &[old]);
        assert!(!state.holds(&old) && state.holds(&new));
        assert_eq!(state.total(vault(1)), 40);

        let fated = fee(1, 3, 7);
        state.fold(&[fated], &[fated]);
        assert!(!state.holds(&fated));
        assert_eq!(state.total(vault(1)), 40);
    }
}
