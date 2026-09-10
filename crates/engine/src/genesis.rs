//! Genesis seeding: this network's allocations, as substate writes.
//!
//! [`GenesisConfig`] is the canonical input — the accounts a deployment
//! funds and the stake pools its beacon folds facts for — so two nodes
//! with the same config install byte-identical state. The world those
//! pools are seated in is [`hyperscale_effects_bridge::genesis`]'s; what
//! is here is the state genesis writes, which is the half that needs the
//! kernel's own amount encoding.

use std::sync::Arc;

pub use hyperscale_effects_bridge::genesis::{
    GenesisPackages, OWNER_BADGE_ID, OWNER_BADGE_RECORD, STAKE_UNIT_RECORD, World, XRD_RECORD,
    account_artifact, genesis_publisher, genesis_world, genesis_world_with_pools, pool_address,
    pool_meta, pool_owner_badge, stake_unit, staking_artifact,
};
use hyperscale_effects_bridge::vm_statics::config_key;
use hyperscale_effects_bridge::{ProtocolHasher, validator_key};
pub use hyperscale_effects_bridge::{XRD, draw_key, vault_key};
use hyperscale_hbor::{Hash32, to_vec};
use hyperscale_types::{EntryKey, Hash, PrincipalAddr, SettledWrites, StakePoolSeat};
use hyperscale_vm_effects::{
    Declaration, DeclaredAccess, IssuanceGrant, Issued, ResourceKind, holdings_collection,
    instance_data_key, package_hash, resource_record_key,
};
use hyperscale_vm_kernel::{EnvInputs, KernelSession, MemoryStore, OverlayStore, OwnerSet};
use hyperscale_vm_stdlib::{package_writes, staking};
use hyperscale_vm_types::{Address, Effect, EffectSet, EffectTarget, Mode, Moves, Outcome, TxHash};

use crate::executor::{artifact_package, protocol_hash};

/// Configuration for genesis bootstrapping.
#[derive(Debug, Clone, Default)]
pub struct GenesisConfig {
    /// Funded accounts: owner prefix and initial balance. Seeded as
    /// identity-keyed vault cells. Funding is all this does — an account
    /// is callable whether or not it appears here.
    pub accounts: Vec<(PrincipalAddr, u128)>,

    /// Stake pools the beacon folds facts for: the pool instance's owner
    /// prefix and the identifier it is folded under. Seated as stake pool
    /// package instances in the engine's world, which is what makes their
    /// emitted events beacon facts — running the package never does,
    /// because anyone may run the package.
    pub pools: Vec<StakePoolSeat>,

    /// The packages this network is born running. The protocol's own by
    /// default; a test or simulation network seeds fixtures beside them.
    ///
    /// Part of the config rather than of the call site because a restart
    /// replicates genesis from this, and a set that differed between the
    /// two would rebuild a store the chain no longer matches.
    pub packages: GenesisPackages,
}

/// The genesis substate writes.
///
/// The protocol's stdlib flash composed with this network's allocations:
/// a seated pool's validator records, its owner-badge custody, and one
/// [`XRD`] vault cell per funded account, identity-keyed under the
/// owner's prefix.
///
/// # Panics
///
/// Panics if the badge record exceeds its wire depth, which the one
/// fixed record cannot.
#[must_use]
pub fn genesis_writes(
    accounts: &[(PrincipalAddr, u128)],
    pools: &[StakePoolSeat],
    packages: &GenesisPackages,
) -> SettledWrites {
    // Each genesis package as a committed cell, under the same content
    // address a publish would place it at. Genesis is then the cache's
    // cold start in the literal sense — the same projection of committed
    // state every later block extends, rather than a second source the
    // cache would have to be told about separately.
    let mut writes = package_writes(&ProtocolHasher, packages.artifacts());
    let staking_package = package_hash(&ProtocolHasher, staking_artifact());
    // A seated pool's record of the validators it already operates.
    // Beacon genesis creates those memberships directly in beacon state,
    // so without this the contract would hold no record of validators it
    // demonstrably operates — and its own methods would refuse to speak
    // about them.
    for seat in pools {
        let pool = pool_address(staking_package, seat);
        for (validator, pubkey) in &seat.founding {
            // Written as the record the package declares, through that
            // package's own type: genesis seeds what a registration
            // would have written, so the methods that read it back are
            // reading their own encoding rather than a layout stated
            // twice.
            let held = to_vec(&staking::Validator {
                pubkey: *pubkey.as_bytes(),
            })
            .expect("a validator record encodes");
            writes
                .cells
                .insert(validator_key(pool, validator.inner()), Some(held));
        }
        // The seal: the pool's creation-fixed record in its configuration
        // leaf, whose presence is what every method's fence reads. A
        // seated pool has to be actual or the network's own validators
        // could not reach it.
        writes.cells.insert(
            config_key(pool),
            Some(
                pool_meta(staking_package, seat)
                    .leaf_bytes()
                    .expect("a pool's record encodes"),
            ),
        );
        // Custody of the pool: the badge's record under the pool, the
        // instance's data cell, and the holdings entry in the seat's
        // operator account. The badge and its id both derive from the
        // pool, so these writes and the seal are the whole seating —
        // nothing stores a mapping, and selling the pool is an ordinary
        // holdings transfer from here on.
        let badge = pool_owner_badge(pool);
        writes.cells.insert(
            resource_record_key(&ProtocolHasher, pool, badge),
            Some(
                OWNER_BADGE_RECORD
                    .to_cell()
                    .expect("a record encodes within its wire depth"),
            ),
        );
        writes.cells.insert(
            instance_data_key(&ProtocolHasher, pool, badge, OWNER_BADGE_ID),
            Some(vec![1]),
        );
        // The stake unit's record beside the badge's: instantiation
        // writes one cell per declared mark, whether or not anything has
        // been issued yet, so a seated pool carries the same set.
        writes.cells.insert(
            resource_record_key(&ProtocolHasher, pool, stake_unit(pool)),
            Some(
                STAKE_UNIT_RECORD
                    .to_cell()
                    .expect("a record encodes within its wire depth"),
            ),
        );
        // Empty content, as `deposit-nf` files an entry: presence is the
        // whole of what a holdings entry says, and the two writers of
        // this entry must agree byte for byte.
        writes.entries.insert(
            EntryKey {
                owner: seat.operator.address(),
                collection: holdings_collection(&ProtocolHasher, seat.operator, badge),
                order: u128::from(OWNER_BADGE_ID),
            },
            Some(Vec::new()),
        );
    }
    // The fee resource's record, under its issuer: the one cell that says
    // what XRD is, written where every resource's record lives.
    writes.cells.insert(
        resource_record_key(&ProtocolHasher, genesis_publisher(&ProtocolHasher), *XRD),
        Some(
            XRD_RECORD
                .to_cell()
                .expect("a record encodes within its wire depth"),
        ),
    );
    // Both halves of what the mint produced, though a fungible seed
    // yields only cells: what genesis seeds is read off a receipt, and a
    // reader that takes half of one decides by omission what a later
    // seed is allowed to be.
    let (cells, entries) = minted_allocations(accounts).into_parts();
    writes.cells.extend(cells);
    writes.entries.extend(entries);
    SettledWrites::from_parts(writes.cells, writes.entries)
}

/// The XRD each funded account is born holding, as the mint that made it.
///
/// Value enters the world through a mint and nowhere else, genesis
/// included. Written straight into the cells it would be a stock no
/// supply answers for, and the rule every later transaction meets would
/// have one exception, at the one block nobody can inspect the history
/// of. Run through the kernel it is a transaction like any other, and it
/// meets the same fold — so a genesis that seeded more than it minted
/// would not produce a receipt to seed from.
///
/// Only the value. Packages, validator records, pool configuration and
/// badge custody are records rather than holdings, and stay the direct
/// writes they are.
fn minted_allocations(accounts: &[(PrincipalAddr, u128)]) -> SettledWrites {
    /// What the opening mint is recorded under. Genesis has no signed
    /// transaction behind it, so the hash names the occasion instead.
    const GENESIS_TX: TxHash = TxHash(Hash32([0; 32]));

    // One clause per allocation, in the order they are given, so a
    // handle's index is the account it credits and nothing has to look
    // one up.
    let ordered: Vec<DeclaredAccess> = accounts
        .iter()
        .map(|(address, _)| DeclaredAccess {
            effect: Effect {
                target: EffectTarget::Point(vault_key(*address, *XRD)),
                mode: Mode::Delta { moves: Moves::Both },
            },
            holds: Some(*XRD),
            // Genesis credits the accounts it is naming, so every one of
            // these is under the prefix it belongs to and none reaches a
            // stranger's.
            reach: None,
            clause: None,
        })
        .collect();
    let mut set = EffectSet::new();
    for declared in &ordered {
        set.insert(declared.effect)
            .expect("a commutative credit conflicts with nothing");
    }
    let declaration = Declaration {
        set,
        ordered,
        ..Declaration::default()
    };
    let mut session = KernelSession::materialize(
        OverlayStore::new(Arc::new(MemoryStore::new())),
        &declaration,
        GENESIS_TX,
        EnvInputs::unsealed(0),
        protocol_hash,
    )
    .expect("every allocation names one unheld vault");

    // The one issuance genesis holds, so every mint below names index
    // zero. Founding rather than minting under a rule: the fee resource
    // grants no `Mint` entry, and what a body may do here is the
    // occasion's rather than any caller's.
    session.grant_issuance(vec![IssuanceGrant {
        resource: *XRD,
        kind: ResourceKind::Fungible,
        direction: Issued::Minted,
    }]);
    // A session seeds one site per capability, in table order, so the
    // clause a vault was declared under is reached at the same position
    // with no walk having bound anything first.
    for (site, (_, balance)) in accounts.iter().enumerate() {
        let site = u32::try_from(site).expect("one clause per funded account");
        let minted = session.mint(0, *balance).expect("the grant mints");
        session
            .cell_put(site, 0, minted)
            .expect("into the vault it was minted for");
    }
    let (receipt, _) = session
        .finish(Vec::new(), 0)
        .expect("genesis declares every cell it credits");
    assert!(
        matches!(receipt.outcome, Outcome::Completed { .. }),
        "genesis seeds only what it mints: {:?}",
        receipt.outcome
    );
    // Resolved against nothing, which is what an opening balance lands
    // on: every credit here is the first thing its cell ever held.
    receipt
        .delta
        .project(&OwnerSet::whole())
        .expect("kernel-produced movements compose")
        .resolve(&mut |_| None)
        .expect("an opening balance lands on nothing")
}

/// The packages the chain is born running, as the beacon registry holds
/// them: `(content address, the prefix their bytes sit under)`.
///
/// Genesis seeds these so the block-validity rule can ask one question of
/// every package a transaction names. They are usable from the genesis
/// epoch and no node ever fetches them, because every node compiles them
/// at boot — the publisher is what the registry keys fetching on, and it
/// is never consulted for these.
#[must_use]
pub fn genesis_package_facts(packages: &GenesisPackages) -> Vec<(Hash, Address)> {
    let publisher = Address::from(genesis_publisher(&ProtocolHasher));
    packages
        .artifacts()
        .iter()
        .map(|artifact| (artifact_package(artifact), publisher))
        .collect()
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::test_principal;
    use hyperscale_vm_types::encode_amount;

    use super::*;

    /// The opening balances come from a mint, never from a write.
    ///
    /// A genesis seeding more than it minted would not get this far: the
    /// session it runs through meets the same fold every later
    /// transaction does, and the seeding is read off the receipt.
    #[test]
    fn funded_vaults_are_what_genesis_minted() {
        let alice = test_principal(0x11);
        let bob = test_principal(0x22);
        let (cells, entries) = minted_allocations(&[(alice, 500), (bob, 700)]).into_parts();

        assert!(entries.is_empty(), "a balance is a cell, not an entry");
        assert_eq!(
            cells,
            std::collections::BTreeMap::from([
                (vault_key(alice, *XRD), Some(encode_amount(500).to_vec())),
                (vault_key(bob, *XRD), Some(encode_amount(700).to_vec())),
            ]),
            "the mint credits each funded vault and nothing besides"
        );
    }

    #[test]
    fn genesis_writes_are_identity_keyed_vault_cells() {
        let alice = test_principal(0x11);
        let bob = test_principal(0x22);
        let writes = genesis_writes(
            &[(alice, 500), (bob, 700)],
            &[],
            &GenesisPackages::protocol(),
        );
        // Two funded accounts' vault cells, the stdlib packages under
        // the publisher no key derives, and the fee resource's record
        // under the same publisher.
        assert_eq!(writes.cells().len(), 5);
        assert_eq!(
            writes.cells().get(&resource_record_key(
                &ProtocolHasher,
                genesis_publisher(&ProtocolHasher),
                *XRD
            )),
            Some(&Some(XRD_RECORD.to_cell().expect("a record encodes")))
        );
        assert!(
            writes
                .cells()
                .keys()
                .any(|key| key.owner == genesis_publisher(&ProtocolHasher))
        );

        for (owner, balance) in [(alice, 500u128), (bob, 700)] {
            let key = vault_key(owner, *XRD);
            assert_eq!(key.owner, owner);
            assert_eq!(
                writes.cells().get(&key),
                Some(&Some(encode_amount(balance).to_vec()))
            );
        }
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn both_runtimes_accept_the_section_carrying_artifact() {
        // The blessed engine's acceptance is proved by every guest test
        // in this crate, which now runs the artifact. The reference
        // interpreter ships only on wasm32, so its acceptance has no
        // native witness unless one is written.
        use hyperscale_vm_ref::RefModule;

        RefModule::decode(account_artifact())
            .expect("the reference interpreter decodes the stdlib artifact");
    }
}
