//! Fee holds as committed state: what a committed transaction reserves
//! against its payer's vault until the payer's shard burns its price.
//!
//! One [`FeeHold`] cell per `(vault, tx)` under the vault's owner, beside
//! a per-vault total, both in the kernel band. The commit fold writes a
//! hold for every transaction a block carries whose vault sits under the
//! store's prefix, and lowers the total by the hold's own fee wherever
//! the block's writes delete one. The deletion rides the write set that
//! burns the price, so a hold ends exactly where its charge lands.
//!
//! Execution judges every debit of a vault under the holds standing on
//! it. A tick's baseline is the base as of the block below it, so what
//! stands for the tick is that base's total, less the holds whose
//! release an unsettled tick already carries, plus the holds the tick's
//! own block includes: [`StandingFeeHolds`].

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

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
#[must_use]
pub fn held_total(state: &(impl Substates + ?Sized), vault: SubstateKey) -> u128 {
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

/// The transactions of `fees` a block over `prior` includes a hold for,
/// under `prefix`: the first of each hold key whose hold does not
/// already stand.
///
/// The one predicate for an inclusion, read by the commit fold that
/// writes the hold and by the tick that counts it before the fold has
/// run.
pub(crate) fn included<'a, P: Substates + ?Sized>(
    fees: &'a [FeeTerms],
    prior: &'a P,
    prefix: &'a NibblePath,
) -> impl Iterator<Item = &'a FeeTerms> {
    let mut seen = BTreeSet::new();
    fees.iter().filter(move |fee| {
        let key = fee.hold_key();
        key_under_prefix(&fee.vault.to_bytes(), prefix)
            && seen.insert(key)
            && prior.cell(key).is_none()
    })
}

/// The hold a deletion of `key` releases, as `base` holds it: its vault,
/// its transaction and the ceiling it reserved.
///
/// Nothing where the cell is absent or is not a hold sitting at its own
/// key, so a deletion of anything else, or of a hold that does not
/// stand, releases nothing. The one identification of a release, read by
/// the commit fold that lowers the total and by the tick chain's fold
/// that leaves the same ceiling out before the total has moved.
pub(crate) fn release_of(
    base: &(impl Substates + ?Sized),
    key: SubstateKey,
) -> Option<(SubstateKey, TxHash, u128)> {
    let hold = base.cell(key).as_deref().and_then(FeeHold::from_bytes)?;
    (hold.key(&ProtocolHasher, key.owner) == key)
        .then(|| (hold.vault(key.owner), hold.tx, hold.fee))
}

/// The hold and total writes a block adds to `settled`, its own writes
/// resolved against `prior`, restricted to `prefix`.
///
/// Releases are the hold cells `settled` deletes that stand in `prior`,
/// each lowering its vault's total by its own fee; a deletion of a hold
/// that does not stand moves nothing. Inclusions are every transaction
/// [`included`] names whose hold `settled` does not write: a standing
/// hold adds nothing, and a hold released in the block that includes it
/// is never written. A total is written only where it changes, and
/// deleted at zero.
fn fee_hold_writes(
    fees: &[FeeTerms],
    settled: &SettledWrites,
    prior: &(impl Substates + ?Sized),
    prefix: &NibblePath,
) -> Vec<(SubstateKey, Option<Vec<u8>>)> {
    let mut delta: BTreeMap<SubstateKey, (u128, u128)> = BTreeMap::new();
    for (key, change) in settled.cells() {
        if change.is_some() || !key_under_prefix(&key.to_bytes(), prefix) {
            continue;
        }
        let Some((vault, _, fee)) = release_of(prior, *key) else {
            continue;
        };
        let released = &mut delta.entry(vault).or_default().1;
        *released = released.saturating_add(fee);
    }
    let mut writes = Vec::new();
    for fee in included(fees, prior, prefix) {
        let key = fee.hold_key();
        if settled.cells().contains_key(&key) {
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

/// The ceilings held against each vault, by transaction.
pub(crate) type HeldByTx = BTreeMap<SubstateKey, BTreeMap<TxHash, u128>>;

/// What a tick's batch reads of the fee holds standing on a vault.
///
/// The executing shard judges every debit of a vault under
/// [`Self::standing`], with each of the batch's own members named apart
/// at [`Self::own`] so its burn can come out of its own hold.
pub trait FeeHoldReading {
    /// Every ceiling held against `vault` for the tick.
    fn standing(&self, vault: SubstateKey) -> u128;

    /// The ceiling `tx` holds against `vault` for the tick, zero where
    /// it holds none.
    fn own(&self, vault: SubstateKey, tx: TxHash) -> u128;
}

/// A reading with no hold on any vault, for a batch with nothing
/// committed over it: a preview, or a harness that folds no hold.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoFeeHolds;

impl FeeHoldReading for NoFeeHolds {
    fn standing(&self, _vault: SubstateKey) -> u128 {
        0
    }

    fn own(&self, _vault: SubstateKey, _tx: TxHash) -> u128 {
        0
    }
}

/// The fee holds standing for one tick, read off the base its baseline
/// is anchored at.
///
/// Three readings of that base. Its per-vault total counts every hold a
/// block at or below the anchor included and no block at or below it
/// released. A hold whose release an unsettled tick's writes carry is
/// still in that total while its burn is already in the baseline, so its
/// ceiling comes out. A hold the tick's own block includes is in no
/// base the tick can read, so its ceiling goes in.
pub struct StandingFeeHolds<Snap> {
    base: Snap,
    released: Arc<HeldByTx>,
    included: HeldByTx,
}

impl<Snap: Substates> StandingFeeHolds<Snap> {
    /// The holds standing over `base` for a tick whose block carries
    /// `fees`, with `released` the holds the baseline's unsettled writes
    /// delete, under `prefix`.
    pub(crate) fn new(
        base: Snap,
        released: Arc<HeldByTx>,
        fees: &[FeeTerms],
        prefix: &NibblePath,
    ) -> Self {
        let mut standing: HeldByTx = BTreeMap::new();
        for fee in included(fees, &base, prefix) {
            standing
                .entry(fee.vault)
                .or_default()
                .insert(fee.tx, fee.max_fee);
        }
        Self {
            base,
            released,
            included: standing,
        }
    }
}

/// Every ceiling `held` names against `vault`, saturating.
fn sum_on(held: &HeldByTx, vault: SubstateKey) -> u128 {
    held.get(&vault).map_or(0, |by_tx| {
        by_tx
            .values()
            .fold(0u128, |total, fee| total.saturating_add(*fee))
    })
}

impl<Snap: Substates> FeeHoldReading for StandingFeeHolds<Snap> {
    /// # Panics
    ///
    /// Where the releases exceed the base's total, which no base leaves:
    /// every released ceiling was read off a hold cell the same base
    /// holds beside the total that counts it.
    fn standing(&self, vault: SubstateKey) -> u128 {
        let total = held_total(&self.base, vault);
        let released = sum_on(&self.released, vault);
        total
            .checked_sub(released)
            .unwrap_or_else(|| {
                panic!(
                    "BFT CRITICAL: the holds released against {vault:?} come to {released}, past \
                     the {total} held"
                )
            })
            .saturating_add(sum_on(&self.included, vault))
    }

    fn own(&self, vault: SubstateKey, tx: TxHash) -> u128 {
        let named = |held: &HeldByTx| held.get(&vault).and_then(|by_tx| by_tx.get(&tx)).copied();
        if let Some(ceiling) = named(&self.included) {
            return ceiling;
        }
        if named(&self.released).is_some() {
            return 0;
        }
        release_of(&self.base, fee_hold_key(&ProtocolHasher, vault, tx))
            .map_or(0, |(_, _, ceiling)| ceiling)
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{Address, CollectionId, Hash, PrincipalAddr, SettledCells};
    use proptest::prelude::*;

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

    /// The holds standing for a tick over `base` whose block carries
    /// `fees`, with the baseline's layers releasing `released`.
    fn standing<'a>(
        base: &'a Cells,
        fees: &[FeeTerms],
        released: &[FeeTerms],
    ) -> StandingFeeHolds<&'a Cells> {
        let mut by_tx = HeldByTx::new();
        for fee in released {
            let (vault, tx, ceiling) =
                release_of(base, fee.hold_key()).expect("the base holds what a layer releases");
            by_tx.entry(vault).or_default().insert(tx, ceiling);
        }
        StandingFeeHolds::new(base, Arc::new(by_tx), fees, &NibblePath::empty())
    }

    /// A hold the tick's block includes is in no base the tick reads, so
    /// it is added; one the base already shows is in the total, so the
    /// same transaction carried again adds nothing, and neither does a
    /// second copy in one block.
    #[test]
    fn standing_counts_a_blocks_inclusion_once() {
        let mut state = Cells::default();
        let old = fee(1, 1, 100);
        let new = fee(1, 2, 40);
        let elsewhere = fee(2, 3, 9);
        state.fold(&[old], &[]);

        let reading = standing(&state, &[new, new, old, elsewhere], &[]);
        assert_eq!(reading.standing(vault(1)), 140);
        assert_eq!(reading.standing(vault(2)), 9);
        assert_eq!(standing(&state, &[], &[]).standing(vault(1)), 100);
        assert_eq!(NoFeeHolds.standing(vault(1)), 0);

        // The block's own commit fold then writes exactly what the tick
        // counted.
        state.fold(&[new, new, old, elsewhere], &[]);
        assert_eq!(state.total(vault(1)), 140);
        assert_eq!(state.total(vault(2)), 9);
    }

    /// A hold a layer deletes carries its burn in the same layer while
    /// the base's total still counts it, so its ceiling comes out, and
    /// the block settling that layer lowers the total to the same figure.
    #[test]
    fn standing_leaves_out_what_the_overlay_releases() {
        let mut state = Cells::default();
        let burned = fee(1, 1, 100);
        let pending = fee(1, 2, 30);
        state.fold(&[burned, pending], &[]);
        assert_eq!(state.total(vault(1)), 130);

        let reading = standing(&state, &[], &[burned]);
        assert_eq!(reading.standing(vault(1)), 30);
        assert_eq!(
            reading.own(vault(1), burned.tx),
            0,
            "a released hold is not held"
        );
        assert_eq!(reading.own(vault(1), pending.tx), 30);

        state.fold(&[], &[burned]);
        assert_eq!(state.total(vault(1)), 30);
        assert_eq!(standing(&state, &[], &[]).standing(vault(1)), 30);
    }

    #[test]
    #[should_panic(expected = "BFT CRITICAL: the holds released against")]
    fn standing_refuses_releases_past_the_total() {
        let mut state = Cells::default();
        let one = fee(1, 1, 100);
        state.fold(&[one], &[]);
        let total = fee_hold_total_key(&ProtocolHasher, vault(1));
        state.0.insert(total, 99u128.to_le_bytes().to_vec());
        let _ = standing(&state, &[], &[one]).standing(vault(1));
    }

    /// A member's own ceiling is the inclusion's where its block carries
    /// it, the base cell's where an earlier block did, and nothing where
    /// neither holds it or the vault is another's.
    #[test]
    fn own_reads_the_inclusion_then_the_cell() {
        let mut state = Cells::default();
        let committed = fee(1, 1, 100);
        let included = fee(1, 2, 40);
        state.fold(&[committed], &[]);

        let reading = standing(&state, &[included], &[]);
        assert_eq!(reading.own(vault(1), included.tx), 40);
        assert_eq!(reading.own(vault(1), committed.tx), 100);
        assert_eq!(reading.own(vault(1), fee(1, 9, 5).tx), 0);
        assert_eq!(reading.own(vault(2), committed.tx), 0);
        assert_eq!(NoFeeHolds.own(vault(1), committed.tx), 0);
    }

    fn fees_strategy() -> impl Strategy<Value = Vec<FeeTerms>> {
        prop::collection::vec((1u8..4, 1u8..12, 1u128..1_000), 0..12).prop_map(|drawn| {
            let mut ceilings: BTreeMap<(u8, u8), u128> = BTreeMap::new();
            drawn
                .into_iter()
                .map(|(payer, tx, max_fee)| {
                    // One ceiling per transaction, as one signed envelope
                    // states it however often a block carries it.
                    let max_fee = *ceilings.entry((payer, tx)).or_insert(max_fee);
                    fee(payer, tx, max_fee)
                })
                .collect()
        })
    }

    proptest! {
        /// What a tick counts as its block's inclusions is exactly what
        /// that block's commit fold writes a hold for, where the block
        /// settles nothing: the transactions `included` names over a
        /// prior are the holds `with_fee_holds` adds to it.
        #[test]
        fn included_is_the_folds_predicate(
            standing_fees in fees_strategy(),
            block in fees_strategy(),
            narrow in any::<bool>(),
        ) {
            let prefix = if narrow {
                NibblePath::from_key_prefix(&vault(1).to_bytes(), 8)
            } else {
                NibblePath::empty()
            };
            let mut prior = Cells::default();
            prior.fold_under(&standing_fees, &[], &prefix);

            let named: BTreeMap<SubstateKey, u128> = included(&block, &prior, &prefix)
                .map(|fee| (fee.hold_key(), fee.max_fee))
                .collect();
            let settled = with_fee_holds(SettledWrites::default(), &block, &prior, &prefix);
            let written: BTreeMap<SubstateKey, u128> = settled
                .cells()
                .iter()
                .filter_map(|(key, change)| {
                    let hold = FeeHold::from_bytes(change.as_deref()?)?;
                    (hold.key(&ProtocolHasher, key.owner) == *key).then_some((*key, hold.fee))
                })
                .collect();
            prop_assert_eq!(&named, &written);

            // And the tick's reading of the block is the total the fold
            // leaves.
            let reading = StandingFeeHolds::new(&prior, Arc::default(), &block, &prefix);
            let counted: Vec<u128> = (1u8..4).map(|payer| reading.standing(vault(payer))).collect();
            prior.fold_under(&block, &[], &prefix);
            let folded: Vec<u128> = (1u8..4).map(|payer| prior.total(vault(payer))).collect();
            prop_assert_eq!(counted, folded);
        }

        /// A deletion releases a hold for the tick chain's fold exactly
        /// where it releases one for the commit fold: over any prior and
        /// any set of deleted cells, the ceilings `release_of` names per
        /// vault are what `with_fee_holds` lowers that vault's total by.
        #[test]
        fn a_release_is_what_the_commit_fold_releases(
            standing_fees in fees_strategy(),
            deleted in fees_strategy(),
            stray in prop::collection::vec(1u8..4, 0..3),
        ) {
            let mut prior = Cells::default();
            prior.fold(&standing_fees, &[]);
            // Deletions of holds that stand, of holds that do not, of
            // totals, and of a cell that is no hold.
            let mut keys: BTreeSet<SubstateKey> =
                deleted.iter().map(FeeTerms::hold_key).collect();
            for payer in stray {
                keys.insert(vault(payer));
            }

            let mut named: BTreeMap<SubstateKey, u128> = BTreeMap::new();
            for key in &keys {
                if let Some((on, _, ceiling)) = release_of(&prior, *key) {
                    *named.entry(on).or_default() += ceiling;
                }
            }

            let before: Vec<u128> = (1u8..4).map(|payer| prior.total(vault(payer))).collect();
            let deletions: SettledCells = keys.iter().map(|key| (*key, None)).collect();
            let settled = with_fee_holds(
                SettledWrites::from_absolutes(deletions),
                &[],
                &prior,
                &NibblePath::empty(),
            );
            for (key, change) in settled.cells() {
                match change {
                    Some(bytes) => prior.0.insert(*key, bytes.clone()),
                    None => prior.0.remove(key),
                };
            }
            for (payer, before) in (1u8..4).zip(before) {
                let lowered = before - prior.total(vault(payer));
                prop_assert_eq!(
                    lowered,
                    named.get(&vault(payer)).copied().unwrap_or(0),
                    "vault {}",
                    payer,
                );
            }
        }
    }
}
