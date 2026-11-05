//! Transactions and states the request and root tests share.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_storage::Substates;
use hyperscale_types::test_utils::{
    StubVmStatics, install_stub_protocol_statics, stub_transaction,
};
use hyperscale_types::{
    Address, CollectionId, DeclaredKey, EntryKey, Mode, PrincipalAddr, Routing, SettledWrites,
    SubstateKey, TimestampRange, Transaction, Verifiable, WeightedTimestamp,
};
use hyperscale_vm_types::{LegShape, Moves};

/// A write of a cell, which reads its prior and so is served.
pub const WRITE: Mode = Mode::Write { moves: Moves::Both };

/// A credit to a cell, which reads nothing and so is not served.
pub const CREDIT: Mode = Mode::Delta { moves: Moves::In };

/// A state holding the ordered entries a settled set writes, and no
/// cell.
pub struct Entries(BTreeMap<EntryKey, Vec<u8>>);

impl Entries {
    /// Nothing at all.
    pub const fn empty() -> Self {
        Self(BTreeMap::new())
    }

    /// What `writes` leave over nothing.
    pub fn of(writes: &SettledWrites) -> Self {
        Self(
            writes
                .entries()
                .iter()
                .filter_map(|(key, value)| value.clone().map(|value| (*key, value)))
                .collect(),
        )
    }
}

impl Substates for Entries {
    fn cell(&self, _: SubstateKey) -> Option<Vec<u8>> {
        None
    }

    fn entries_in_range(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        self.0
            .iter()
            .filter(|(key, _)| {
                key.owner == owner && key.collection == collection && (lo..=hi).contains(&key.order)
            })
            .take(limit)
            .map(|(key, value)| (key.order, value.clone()))
            .collect()
    }
}

/// The routing a derivation files for `declared`: fresh reads share,
/// every mutation excludes, and reads and writes provision.
fn routing_of(declared: &[(DeclaredKey, Mode)]) -> Routing {
    let keys = |pick: fn(&Mode) -> bool| -> Vec<DeclaredKey> {
        let keys: BTreeSet<DeclaredKey> = declared
            .iter()
            .filter(|(_, mode)| pick(mode))
            .map(|(key, _)| *key)
            .collect();
        keys.into_iter().collect()
    };
    let prefixes = |keys: &[DeclaredKey]| -> Vec<Address> {
        let owners: BTreeSet<Address> = keys.iter().map(DeclaredKey::owner).collect();
        owners.into_iter().collect()
    };
    let read_keys = keys(|mode| matches!(mode, Mode::Read));
    let write_keys = keys(|mode| !matches!(mode, Mode::Read));
    let provision_keys = keys(|mode| matches!(mode, Mode::Read | Mode::Write { .. }));
    let mut declared_modes = declared.to_vec();
    declared_modes.sort_unstable();
    Routing {
        read_prefixes: prefixes(&read_keys),
        write_prefixes: prefixes(&write_keys),
        provision_prefixes: prefixes(&provision_keys),
        read_keys,
        write_keys,
        provision_keys,
        declared_modes,
    }
}

/// A transaction paid by `payer` declaring `declared` beside its fee
/// debit, in the shape `legs` give it: whole where they are empty.
pub fn shaped(
    payer: PrincipalAddr,
    declared: &[(DeclaredKey, Mode)],
    legs: Vec<LegShape>,
) -> Verifiable<Transaction> {
    install_stub_protocol_statics();
    let mut declared = declared.to_vec();
    declared.push((
        DeclaredKey::substate(payer.address(), [0xFE; 16]),
        Mode::Delta { moves: Moves::Out },
    ));
    let validity = TimestampRange::new(
        WeightedTimestamp::ZERO,
        WeightedTimestamp::from_millis(60_000),
    );
    let tx = stub_transaction(payer, &[], 1_000, validity)
        .with_routing(&StubVmStatics, routing_of(&declared));
    Verifiable::from(tx.with_legs(&StubVmStatics, legs))
}

/// The cell of `owner` seeded by `seed`.
pub const fn cell(owner: Address, seed: u8) -> DeclaredKey {
    DeclaredKey::substate(owner, [seed; 16])
}
