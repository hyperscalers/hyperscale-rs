//! The genesis-static world: what a cold start already knows.
//!
//! Published stdlib metadata, the blueprint serving every principal, and
//! the pool instances a deployment seats. It is a projection of genesis
//! configuration and immutable artifacts and nothing else, which is why it
//! sits beside the rest of this crate's bindings rather than inside the
//! engine: a load generator, a wallet and a scenario all need to resolve a
//! target, and none of them executes anything.

use hyperscale_types::{ComponentAddr, ResourceAddr, StakePoolSeat};
use hyperscale_vm_effects::{
    Hasher, InstanceMeta, InstanceRegistry, MetadataCache, PackageHash, ResourceKind,
    ResourceRecord, Value, package_hash, resource_address,
};
use hyperscale_vm_fixtures::artifacts as fixture_artifacts;
pub use hyperscale_vm_stdlib::{account_artifact, genesis_publisher, staking_artifact};
use hyperscale_vm_stdlib::{protocol_artifacts, staking};
use hyperscale_vm_types::Address;

use crate::records::{InstanceCache, NodeRecords, PackageCache};
use crate::{PoolRegistry, ProtocolHasher, XRD, admit_protocol_package};

/// The packages a network is born running.
///
/// The protocol's own are every network's; a network may seed others
/// beside them, and a test or simulation network is where that happens.
/// Production names [`GenesisPackages::protocol`] and nothing else, so a
/// fixture reaching a real chain takes a deliberate edit at the call site
/// rather than a flag someone left on.
///
/// Every genesis surface reads its set from one of these — the package
/// cells, the beacon's usability registry, and the process's metadata
/// cache — because a package present in one and absent from another is a
/// chain that cannot route to its own code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisPackages(Vec<&'static [u8]>);

impl Default for GenesisPackages {
    fn default() -> Self {
        Self::protocol()
    }
}

impl GenesisPackages {
    /// The protocol's own: the account every principal answers and the
    /// stake pool the beacon folds facts for.
    #[must_use]
    pub fn protocol() -> Self {
        Self(protocol_artifacts())
    }

    /// The protocol's, plus the test packages a network outside
    /// production seeds beside them.
    #[must_use]
    pub fn with_fixtures() -> Self {
        let mut packages = Self::protocol();
        packages.0.extend(fixture_artifacts());
        packages
    }

    /// The artifacts, in the order they are seeded.
    #[must_use]
    pub fn artifacts(&self) -> &[&'static [u8]] {
        &self.0
    }
}

/// The genesis-static world: published stdlib metadata, the blueprint
/// serving every principal, and any seated pool instances.
#[derive(Debug, Clone)]
pub struct World {
    /// Published package metadata, growing as blocks commit.
    pub cache: PackageCache,
    /// The instances the chain answers for, growing as blocks commit.
    pub instances: InstanceCache,
    /// The stdlib account package's content address.
    pub account_package: PackageHash,
    /// The stdlib stake pool package's content address — the code a
    /// recognised pool must be running for its events to be read as
    /// beacon facts.
    pub staking_package: PackageHash,
    /// The stake pools the beacon folds for. Empty on a network with no
    /// staking surface, which is every network until genesis seats one.
    pub pools: PoolRegistry,
}

impl World {
    /// This world's records, pinned for one derivation.
    ///
    /// Both caches are loaded once here, so a reader holds the world it
    /// started in however many lookups it makes.
    ///
    /// No committed state behind it: a world on its own is what a
    /// composer or a test holds, and it answers from its caches alone. A
    /// node reads its own state too, through
    /// [`BridgeStatics::records`](crate::BridgeStatics::records).
    #[must_use]
    pub fn records(&self) -> NodeRecords {
        NodeRecords::pinned(&self.cache, &self.instances, None)
    }

    /// A second node's copy of this world: the same packages and the
    /// same instances, in caches that share nothing either side goes on
    /// to absorb.
    ///
    /// Copied rather than rebuilt from genesis because the copy is what
    /// a node booting alongside this one would hold, and rebuilding
    /// would re-admit every artifact for an answer already computed.
    /// What a node accumulates after this is its own: a package it never
    /// committed and a component whose seal landed on a shard it does
    /// not serve are both absent from it, which is the whole point of
    /// holding one each.
    #[must_use]
    pub fn fork(&self) -> Self {
        Self {
            cache: PackageCache::new((*self.cache.load()).clone()),
            instances: self.instances.forked(),
            account_package: self.account_package,
            staking_package: self.staking_package,
            pools: self.pools.clone(),
        }
    }
}

/// Build the world: the stdlib packages published under their artifact
/// hashes, and the account package bound as the one serving every
/// principal.
///
/// Funded accounts are not an input. A principal address commits its own
/// auth material, so an account is callable without anything registered
/// for it — genesis seeds balances, not instances.
///
/// The published signatures are the ones the artifact declares, admitted
/// through the same check a publish transaction runs — genesis is the
/// cold start of the cache, not a second source of truth for it.
///
/// # Panics
///
/// Panics if the stdlib artifact would not be admissible as a published
/// package — a build defect, not a runtime condition.
#[must_use]
pub fn genesis_world() -> World {
    genesis_world_with_pools(&[], &GenesisPackages::protocol())
}

/// [`genesis_world`] over `packages`, seating `pools` as the stake pools
/// the beacon folds for: `(instance address, the identifier it is folded
/// under)`.
///
/// A pool is an instance of the stdlib stake pool package configured with
/// the resource it stakes and the resource it issues. Seating it here is
/// what makes its events beacon facts — the package alone never does,
/// because anyone may run the package.
///
/// # Panics
///
/// Panics if a genesis artifact would not be admissible as a published
/// package — a build defect, not a runtime condition.
#[must_use]
pub fn genesis_world_with_pools(pools: &[StakePoolSeat], packages: &GenesisPackages) -> World {
    let mut seed = MetadataCache::new();
    for artifact in packages.artifacts() {
        seed.publish(
            package_hash(&ProtocolHasher, artifact),
            admit_protocol_package(artifact).expect("a genesis artifact publishes as a package"),
        )
        .expect("a gate-admitted record clears the cache door");
    }
    let account_package = package_hash(&ProtocolHasher, account_artifact());
    let staking_package = package_hash(&ProtocolHasher, staking_artifact());

    let cache = PackageCache::new(seed);
    let mut instances = InstanceRegistry::new();
    // Funded accounts need nothing registered: a principal address
    // commits its own auth material, and the blueprint serving every
    // principal is protocol-defined.
    instances.serve_principals(account_package);
    let mut registry = PoolRegistry::new();
    for seat in pools {
        let address = instances.create(&ProtocolHasher, pool_meta(staking_package, seat));
        registry.register(address, seat.id);
    }
    World {
        cache,
        instances: InstanceCache::new(instances),
        account_package,
        staking_package,
        pools: registry,
    }
}

/// A genesis-seated pool's creation-fixed record.
///
/// Its configuration is the resource a delegation is denominated in and
/// who may found it. The resource the pool *issues* and the owner badge
/// its operator surface admits are both derived from the pool rather
/// than configured, and the pool's own identity is its address — so
/// neither is named here. The founder is the seat's operator: genesis
/// seats the badge directly, so the founding call its configuration
/// admits is already spent, and the field's whole work is keeping a
/// genesis pool and a founded one one shape.
///
/// The salt stands in for a creating transaction's fresh id, which
/// genesis has none of: the pool's own beacon identifier separates two
/// pools that would otherwise be seated identically.
#[must_use]
pub fn pool_meta(staking_package: PackageHash, seat: &StakePoolSeat) -> InstanceMeta {
    InstanceMeta {
        package: staking_package,
        config: vec![
            Value::Address(XRD.address()),
            Value::Address(seat.operator.address()),
        ],
        salt: ProtocolHasher.hash(DOMAIN_GENESIS_SALT, &[&seat.id.inner().to_le_bytes()]),
    }
}

/// The address genesis seats `seat` at.
#[must_use]
pub fn pool_address(staking_package: PackageHash, seat: &StakePoolSeat) -> ComponentAddr {
    pool_meta(staking_package, seat).address(&ProtocolHasher)
}

/// The domain separating a genesis instance's salt.
///
/// A hashing input, so its bytes are part of every seated pool's address
/// and fixed by that rather than by where the constant is declared.
const DOMAIN_GENESIS_SALT: &[u8] = b"hyperscale/engine/genesis-instance";

/// The resource a pool issues against delegations.
///
/// A resource address under the pool's own provenance, which is what the
/// staking signature's own derivation evaluates to — so two pools can
/// never be seated on one stake-unit resource, a holder's units always
/// name the pool that owes them, and the address says both facts on
/// sight.
///
/// # Panics
///
/// If `pool` is not a component address. A pool is one by construction,
/// so a caller passing anything else has already lost the thing it
/// meant to name.
#[must_use]
pub fn stake_unit(pool: impl Into<Address>) -> ResourceAddr {
    // Through the package's own helper rather than a restatement of it:
    // a resource's address folds the rules its declaration grants, and
    // the stake unit grants its issuer the right to mint and retire it.
    // Deriving it any other way names a vacant sibling — an address
    // nothing is ever minted at, where a read finds an empty vault and
    // nothing fails.
    staking::Staking::at(ComponentAddr::try_from(pool.into()).expect("a pool is a component"))
        .issued_stake_unit(&ProtocolHasher)
}

/// The pool's owner badge: the identity its operator surface admits.
///
/// Derived like the stake unit and separated from it by the stdlib's
/// badge material — the same derivation the operator gate evaluates, so
/// holding this resource is operating the pool and selling the pool is
/// transferring it.
#[must_use]
pub fn pool_owner_badge(pool: impl Into<Address>) -> ResourceAddr {
    resource_address(
        &ProtocolHasher,
        pool,
        ResourceKind::NonFungible,
        &[Value::Bytes(staking::OWNER_BADGE.to_vec()).canonical_bytes()],
    )
}

/// The badge instance a pool's seating mints: id 0, in genesis and in a
/// founding call alike.
///
/// A constant rather than a derivation, because the badge resource is
/// already the pool's own — per-pool uniqueness lives in the address —
/// and a founding call's `mint_nf` names the same literal. One value in
/// two writers is what the cell-for-cell parity between a seated pool
/// and a founded one rests on.
pub const OWNER_BADGE_ID: u64 = 0;

/// The stake unit's resource record, at the display width the staking
/// package's own mark declares — instantiation writes this cell for a
/// pool it brings up, and genesis writes it for a pool it seats.
pub const STAKE_UNIT_RECORD: ResourceRecord = ResourceRecord::Fungible { display_digits: 18 };

/// The owner badge's resource record: one non-fungible kind.
pub const OWNER_BADGE_RECORD: ResourceRecord = ResourceRecord::NonFungible;

/// The fee resource's record: fungible, displayed at eighteen subunit
/// digits. Display quantization only — nothing on-chain consults it.
pub const XRD_RECORD: ResourceRecord = ResourceRecord::Fungible { display_digits: 18 };

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::test_principal;
    use hyperscale_vm_stdlib::{ACCOUNT_MODULE, account};

    use super::*;
    use crate::account_address;

    #[test]
    fn the_stdlib_artifact_describes_itself() {
        let artifact = account_artifact();

        // The code is the committed blob and the section is what was
        // added, so the address covers both.
        assert!(artifact.starts_with(ACCOUNT_MODULE));
        assert!(artifact.len() > ACCOUNT_MODULE.len());
        assert_ne!(
            package_hash(&ProtocolHasher, artifact),
            package_hash(&ProtocolHasher, ACCOUNT_MODULE)
        );

        // What genesis publishes is admitted out of the artifact by the
        // publish check, and it is the signature set the stdlib authors:
        // the real guest's exports back every method it declares.
        let declared = admit_protocol_package(artifact).expect("publishes as a package");
        assert_eq!(declared, account::metadata());
        let world = genesis_world();
        assert_eq!(
            world.cache.load().get(world.account_package),
            Some(&declared)
        );
        assert_eq!(
            world.account_package,
            package_hash(&ProtocolHasher, artifact)
        );
    }

    #[test]
    fn the_world_binds_every_principal_to_the_stdlib_package() {
        // Funding is not what makes an account callable: the world is
        // built without naming any address, and an address nothing has
        // ever funded resolves the same as one genesis seeds.
        let world = genesis_world();
        assert!(world.cache.load().get(world.account_package).is_some());
        for address in [test_principal(0x11), test_principal(0x22)] {
            assert_eq!(
                world.instances.record(address.into()).map(|m| m.package),
                Some(world.account_package)
            );
        }
    }

    #[test]
    fn account_addresses_derive_deterministically_from_keys() {
        let a = account_address(&[7u8; 32]);
        assert_eq!(a, account_address(&[7u8; 32]));
        assert_ne!(a, account_address(&[8u8; 32]));
    }
}
