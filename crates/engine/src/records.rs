//! What a batch resolves its call targets through.
//!
//! Admission and execution ask the same question — which record serves
//! this target — but they are owed different answers. Admission is a
//! node deciding whether it can judge an envelope at all, and a node
//! that cannot resolve a target says so and fetches; the envelope waits
//! and nothing has been decided. Execution is past that: the block is
//! certified, every member is producing a receipt root, and a member
//! that resolved one target fewer than its peers produces a different
//! one.
//!
//! So execution answers from the block and the chain alone. Three
//! sources, none of them node-local: the records genesis seated, the
//! configuration leaves this shard holds committed, and the leaves its
//! counterparts provisioned for the transactions in this batch. The
//! fence admission puts on every component call declares a read of the
//! target's own leaf, and a declared read is provisioned to every shard
//! the transaction routes to — so a counterpart's record arrives as
//! ordinary block content, carried by the transaction that needs it.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_effects_bridge::records::{committed_instance, resource_issued_by};
use hyperscale_effects_bridge::vm_statics::config_key;
use hyperscale_types::{SubstateEntry, TxHash};
use hyperscale_vm_effects::{
    ChainRecords, Hasher, InstanceMeta, InstanceRegistry, MetadataCache, PackageHash,
    PackageMetadata, ResourceMeta,
};
use hyperscale_vm_kernel::Substates;
use hyperscale_vm_types::{CallTarget, ResourceAddr, SubstateKey};

/// The records one batch answers a call target with.
///
/// Every source is a function of committed state or of the block, so two
/// members of a shard resolve a target alike or neither does — which is
/// what lets a refusal here be a deterministic failure rather than one
/// member's opinion.
///
/// Packages still come from the node's own cache, and can: a member
/// cannot run code it never acquired whatever else it resolves, so
/// holding every published package is a condition of executing at all
/// rather than something a lookup here might find missing.
pub struct BatchRecords<'a> {
    packages: Arc<MetadataCache>,
    /// The blueprint serving every principal, and the instances genesis
    /// seated — the records with no cell to read, and the same set on
    /// every node.
    seeded: Arc<InstanceRegistry>,
    /// Leaves a counterpart shard provisioned, by the key they sit at.
    provisioned: BTreeMap<SubstateKey, &'a [u8]>,
    /// This shard's own committed state, at the height the batch runs
    /// against.
    committed: &'a (dyn Substates + Sync),
}

impl<'a> BatchRecords<'a> {
    /// The records for a batch executing against `committed`, with
    /// whatever its transactions were provisioned layered beside them.
    #[must_use]
    pub(crate) fn new(
        packages: Arc<MetadataCache>,
        seeded: Arc<InstanceRegistry>,
        provisions: &'a BTreeMap<TxHash, Vec<Arc<Vec<SubstateEntry>>>>,
        committed: &'a (dyn Substates + Sync),
    ) -> Self {
        // Indexed across the whole batch rather than per transaction:
        // the provisions are block content, so the same set is here on
        // every member, and a record is the record its address derives
        // whichever transaction carried it.
        let provisioned = provisions
            .values()
            .flatten()
            .flat_map(|entries| entries.iter())
            .filter_map(|entry| Some((entry.key, entry.value.as_deref()?)))
            .collect();
        Self {
            packages,
            seeded,
            provisioned,
            committed,
        }
    }
}

impl ChainRecords for BatchRecords<'_> {
    fn instance(&self, target: CallTarget) -> Option<Arc<InstanceMeta>> {
        if let Some(seeded) = self.seeded.record(target) {
            return Some(seeded);
        }
        // A principal has no leaf to read: its address derives from a
        // key, and the blueprint serving it is seeded above.
        let CallTarget::Component(address) = target else {
            return None;
        };
        let address = address.address();
        let key = config_key(address);
        // The provisioned copy first, because it costs a lookup where the
        // committed one costs a read, and a prefix routes to exactly one
        // of them anyway. Neither is trusted past the leaf's own
        // contents — a source answering with anything but the record its
        // owner derives is passed over rather than believed, which is
        // why the second is still asked when the first says nothing.
        self.provisioned
            .get(&key)
            .and_then(|provisioned| committed_instance(address, key.local.0, provisioned))
            .or_else(|| committed_instance(address, key.local.0, &self.committed.cell(key)?))
            .map(Arc::new)
    }

    fn package(&self, hash: PackageHash) -> Option<Arc<PackageMetadata>> {
        self.packages.record(hash)
    }

    /// Derived over the seeded records alone, which is the only
    /// instance set this batch can scan without leaving the block and
    /// the chain: `provisioned` and `committed` answer an address that
    /// is asked for, and nothing enumerates the issuers among them.
    ///
    /// Deterministic for that reason rather than in spite of it — the
    /// seeded set is genesis's and identical on every node, so two
    /// members of a shard resolve a resource alike or neither does.
    fn resource(&self, resource: ResourceAddr, hasher: &dyn Hasher) -> Option<ResourceMeta> {
        resource_issued_by(
            self.seeded.components(),
            self.packages.as_ref(),
            resource,
            hasher,
        )
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_effects_bridge::ProtocolHasher;
    use hyperscale_vm_effects::{Hash32, Hasher, Value};
    use hyperscale_vm_types::{Address, CollectionId};

    use super::*;

    /// A store holding nothing: what a shard that owns none of a
    /// component's prefix answers with.
    struct Barren;

    impl Substates for Barren {
        fn cell(&self, _key: SubstateKey) -> Option<Vec<u8>> {
            None
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

    /// A store holding one cell.
    struct OneCell(SubstateKey, Vec<u8>);

    impl Substates for OneCell {
        fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
            (key == self.0).then(|| self.1.clone())
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

    fn record(salt: u8) -> InstanceMeta {
        InstanceMeta {
            package: PackageHash(ProtocolHasher.hash(b"package", &[b"staking"])),
            config: vec![Value::U64(u64::from(salt))],
            salt: Hash32([salt; 32]),
        }
    }

    fn provisioned(entries: Vec<SubstateEntry>) -> BTreeMap<TxHash, Vec<Arc<Vec<SubstateEntry>>>> {
        BTreeMap::from([(TxHash(Hash32([7; 32])), vec![Arc::new(entries)])])
    }

    fn records<'a>(
        provisions: &'a BTreeMap<TxHash, Vec<Arc<Vec<SubstateEntry>>>>,
        committed: &'a (dyn Substates + Sync),
    ) -> BatchRecords<'a> {
        BatchRecords::new(
            Arc::new(MetadataCache::new()),
            Arc::new(InstanceRegistry::new()),
            provisions,
            committed,
        )
    }

    /// A counterpart's record arrives as block content.
    ///
    /// The whole of what lets execution stop asking a cache: the fence
    /// declares a read of the target's own leaf, so the shard owning it
    /// provisions it to every shard the transaction routes to. A node
    /// that never derived this transaction — it took the block on a
    /// quorum certificate — resolves the target all the same.
    #[test]
    fn a_provisioned_leaf_answers_for_a_component_this_shard_owns_none_of() {
        let meta = record(1);
        let address = meta.address(&ProtocolHasher);
        let entries = vec![SubstateEntry::new(
            config_key(address),
            Some(meta.leaf_bytes().expect("a record encodes")),
        )];
        let provisions = provisioned(entries);
        let chain = records(&provisions, &Barren);
        assert_eq!(
            chain.instance(address.into()).as_deref(),
            Some(&meta),
            "a provisioned configuration leaf resolves its own component"
        );
    }

    /// And a shard that owns the prefix reads its own committed leaf,
    /// with nothing provisioned and nothing cached.
    #[test]
    fn a_committed_leaf_answers_for_a_component_this_shard_owns() {
        let meta = record(2);
        let address = meta.address(&ProtocolHasher);
        let store = OneCell(
            config_key(address),
            meta.leaf_bytes().expect("a record encodes"),
        );
        let provisions = BTreeMap::new();
        let chain = records(&provisions, &store);
        assert_eq!(chain.instance(address.into()).as_deref(), Some(&meta));
    }

    /// Neither source is trusted for more than the leaf's own contents:
    /// bytes that derive some other address are not this component's
    /// record, wherever they came from.
    #[test]
    fn a_leaf_holding_another_components_record_answers_for_neither() {
        let meta = record(3);
        let elsewhere = record(4);
        let address = meta.address(&ProtocolHasher);
        let entries = vec![SubstateEntry::new(
            config_key(address),
            Some(elsewhere.leaf_bytes().expect("a record encodes")),
        )];
        let provisions = provisioned(entries);
        let chain = records(&provisions, &Barren);
        assert!(chain.instance(address.into()).is_none());
        assert!(
            chain
                .instance(elsewhere.address(&ProtocolHasher).into())
                .is_none(),
            "nor for the component whose record it does hold, which sits elsewhere"
        );
    }

    /// A provisioned leaf that answers for nothing does not stop this
    /// shard reading its own.
    ///
    /// The two sources are asked in an order, not chosen between: a
    /// prefix routes to one of them, so an entry at this key that is not
    /// this component's record is a source with nothing to say rather
    /// than an answer of "no".
    #[test]
    fn a_provisioned_leaf_that_answers_for_nothing_is_passed_over() {
        let meta = record(6);
        let address = meta.address(&ProtocolHasher);
        let leaf = meta.leaf_bytes().expect("a record encodes");
        let entries = vec![SubstateEntry::new(config_key(address), Some(vec![0xFF; 8]))];
        let provisions = provisioned(entries);
        let store = OneCell(config_key(address), leaf);
        let chain = records(&provisions, &store);
        assert_eq!(chain.instance(address.into()).as_deref(), Some(&meta));
    }

    /// A target neither the block nor this shard's state answers for
    /// resolves to nothing — the refusal every member reaches alike.
    #[test]
    fn a_component_neither_source_holds_resolves_to_nothing() {
        let provisions = BTreeMap::new();
        let chain = records(&provisions, &Barren);
        assert!(
            chain
                .instance(record(5).address(&ProtocolHasher).into())
                .is_none()
        );
    }
}
