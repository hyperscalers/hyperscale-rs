//! What one node holds, and what it answers a call target with.
//!
//! A derivation resolves a call through two records: the instance the
//! target names, and the package that instance runs. Both are committed
//! state, so what this module is about is where a node *keeps* them —
//! caches it grows as blocks commit, its own committed cells behind
//! those, and a fetch behind that for prefixes it does not serve.
//!
//! Every source here is held to one check and no other: a record derives
//! the address it is claimed for, or it is not that component's record.
//! That is what lets a cache be bounded, a peer be untrusted, and an
//! evicted record be read back without anything having to agree.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use arc_swap::ArcSwap;
use hyperscale_hbor::from_slice as hbor_from_slice;
use hyperscale_vm_effects::{
    ChainRecords, CrossingCell, Hasher, InstanceMeta, InstanceRegistry, Issuance, Marker,
    MetadataCache, PackageHash, PackageMetadata, ResourceMeta, Value, escrow_record_key,
    package_hash,
};
use hyperscale_vm_types::{
    Address, CallTarget, ComponentAddr, LocalKey, ResourceAddr, SubstateKey, SweepBucket,
};
use im::{OrdMap, Vector};

use crate::ProtocolHasher;
use crate::artifact::admit_package;
use crate::vm_statics::{config_key, package_key};

/// The package a committed cell publishes, or `None` for every other
/// cell.
///
/// A package cell is self-identifying: its key is the content address of
/// the very bytes it stores, so recomputing the address from the value
/// and rebuilding the key answers the question without any side channel,
/// any tag, and any trust in what wrote it. A cell of any other kind
/// cannot match except by finding a hash collision.
///
/// The preamble is tested first because this runs over every cell of
/// every commit, and hashing a whole value to learn that it was never
/// code is the one cost that scales with what the chain writes rather
/// than with what it publishes. Admission demands the deterministic wasm
/// profile of anything it lets through, so no artifact that could
/// publish is turned away here.
#[must_use]
pub(crate) fn committed_package(
    owner: Address,
    local: [u8; 16],
    value: &[u8],
) -> Option<PackageHash> {
    if !value.starts_with(WASM_PREAMBLE) {
        return None;
    }
    let package = package_hash(&ProtocolHasher, value);
    let key = package_key(package);
    (key.owner == owner && key.local.0 == local).then_some(package)
}

/// The four bytes every wasm artifact opens with.
const WASM_PREAMBLE: &[u8] = b"\0asm";

/// When a committed cell stops being needed, or `None` for every cell a
/// sweep does not reach.
///
/// A sweepable cell is self-identifying the way a package cell is: the
/// value carries the expiry it is owed until, and the key re-derives
/// from that expiry under the family's own domain. So a cell of any
/// other kind cannot pass except by finding a collision, and a writer
/// cannot claim a life its declaration does not name — the key a false
/// expiry produces is not the key the declaration covers.
///
/// Three families: the nullifier, the committed-transaction cell, and
/// the escrow claim. Each arm is its own derivation, so arms cannot
/// overlap and the order they are tried in does not decide the answer —
/// a value that decodes under two layouts re-derives at most one
/// family's key.
///
/// The escrow record is not among them, and that is what makes it a
/// balance rather than a witness: it is retired by whoever consumes it,
/// so its key names the edge alone and carries no bucket for a sweep to
/// walk. The claim beside it is a witness of a delivery admitted inside
/// a window on its own chain's clock, and keeps its bucket.
///
/// Three tests, cheapest first, because this runs over every cell of
/// every commit. The decode rejects on shape alone; the bucket check
/// costs nothing and is the statement that the two halves of the key
/// agree; only then is a hash worth taking.
#[must_use]
pub(crate) fn sweepable_cell(owner: Address, local: [u8; 16], value: &[u8]) -> Option<u64> {
    let marker = Marker::from_bytes(value)?;
    if SweepBucket::claimed_by(LocalKey(local)) != SweepBucket::of(marker.expiry_ms) {
        return None;
    }
    (marker.key(&ProtocolHasher, owner).local.0 == local).then_some(marker.expiry_ms)
}

/// Whether a committed cell is an escrow record.
///
/// Judged the way the three sweepable families are — the value
/// re-derives the key under the record's own role — and answering a
/// different question. A record's key carries no expiry bucket, which is
/// what keeps every sweep off it, so this is the only thing that tells a
/// reader holding the leaf that it is value the shard still owes an
/// answer for.
#[must_use]
pub(crate) fn record_cell(owner: Address, local: [u8; 16], value: &[u8]) -> bool {
    let Ok(cell) = hbor_from_slice::<CrossingCell>(value) else {
        return false;
    };
    let key = escrow_record_key(&ProtocolHasher, owner, cell.intent, cell.local, cell.output);
    key.local.0 == local
}

/// The instance a committed cell seals, or `None` for every other cell.
///
/// A configuration leaf is self-identifying twice over: it sits at the
/// one key its owner's `CONFIG` slot derives, and the record it holds
/// derives that owner in turn. So a cell is this instance's seal exactly
/// when both hold, and neither asks anything of whatever wrote it.
///
/// The key is tested first, because this runs over every cell of every
/// commit and decoding a value to learn it was never a record is the one
/// cost that scales with what the chain writes rather than with what it
/// instantiates.
#[must_use]
pub fn committed_instance(owner: Address, local: [u8; 16], value: &[u8]) -> Option<InstanceMeta> {
    if config_key(owner).local.0 != local {
        return None;
    }
    let meta: InstanceMeta = hbor_from_slice(value).ok()?;
    meta.derives(&ProtocolHasher, owner).then_some(meta)
}

/// The committed cells this node can read for itself.
///
/// A component's record is a cell — the `CONFIG` leaf its instantiation
/// sealed — so the shard owning its prefix already holds it, and a node
/// serving that shard needs neither a cached copy to answer for it nor a
/// fetch to recover one it dropped. What a node cannot read this way is
/// exactly what belongs to some other shard, which is what the fetch is
/// for.
///
/// Implemented by the host over the stores it has open, so this crate
/// stays below the node and learns nothing about how a shard is served.
pub trait LocalCells: Send + Sync {
    /// The value committed at `key` at this node's own tip, or `None`
    /// where the cell is absent or no shard it serves owns the prefix.
    ///
    /// Read at the committed tip and never at a pending one: what the
    /// caches hold is what commits put there, and a pending block two
    /// nodes disagree about would make them derive an envelope two ways.
    fn committed_cell(&self, key: SubstateKey) -> Option<Vec<u8>>;
}

/// One node's answers for the length of one derivation.
///
/// Both caches are loaded once and held by refcount, so a block
/// committing partway through a derivation swaps them under a later
/// reader and this one keeps the world it started in.
///
/// A record the cache does not hold is looked for in this node's own
/// committed state before it is given up on, so what the cache costs is
/// bounded by what a node calls rather than by what the chain has ever
/// created. The two sources answer alike — a record is the record its
/// cell holds — which is what makes dropping one from the cache a
/// question of cost and not of meaning.
///
/// That read is at the node's tip rather than at a pinned height, and
/// what each one finds is held here for the rest of the derivation. Both
/// halves matter for the [`ChainRecords`] stability the caller is owed:
/// a leaf is written once and never rewritten, so the only way the tip's
/// answer can move under a derivation is from absent to present — and
/// holding what was found means a second lookup reads the first one's
/// answer rather than the state again.
pub struct NodeRecords {
    packages: Arc<MetadataCache>,
    instances: Arc<Resident>,
    /// Where a cache miss is looked for, and where what it finds is put
    /// back so the next derivation reads it from memory.
    cells: Option<Arc<dyn LocalCells>>,
    cache: InstanceCache,
    /// What the state answered during this derivation. Successes only,
    /// on the same terms the envelope derivation itself caches them: an
    /// absence is a record this node has yet to see rather than a fact
    /// about the chain, and nothing should have to be undone when it
    /// arrives.
    seen: Mutex<BTreeMap<Address, Arc<InstanceMeta>>>,
}

impl NodeRecords {
    /// Load both caches once, fixing the world this view answers from.
    #[must_use]
    pub(crate) fn pinned(
        packages: &PackageCache,
        instances: &InstanceCache,
        cells: Option<Arc<dyn LocalCells>>,
    ) -> Self {
        Self {
            packages: packages.load(),
            instances: instances.load(),
            cells,
            cache: instances.clone(),
            seen: Mutex::new(BTreeMap::new()),
        }
    }

    /// What the state already answered for `address` in this derivation.
    fn seen(&self, address: Address) -> Option<Arc<InstanceMeta>> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&address)
            .cloned()
    }

    /// Hold `record` for the rest of this derivation.
    fn hold(&self, address: Address, record: &Arc<InstanceMeta>) {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(address, Arc::clone(record));
    }

    /// The record `address` sealed, read out of this node's own state.
    ///
    /// Verified on the way in exactly as a fetched one is: the leaf sits
    /// at the key its owner derives and holds a record deriving that
    /// owner, so bytes that say anything else are not this component's
    /// record and are dropped.
    fn read_from_state(&self, address: Address) -> Option<Arc<InstanceMeta>> {
        let key = config_key(address);
        let value = self.cells.as_ref()?.committed_cell(key)?;
        let meta = committed_instance(address, key.local.0, &value)?;
        // Seated for the next derivation rather than this one: the view
        // this one answers from is already fixed, and re-reading a cell
        // is cheaper than letting a pinned snapshot go stale.
        self.cache.seat_record(&meta);
        Some(Arc::new(meta))
    }
}

impl ChainRecords for NodeRecords {
    fn instance(&self, target: CallTarget) -> Option<Arc<InstanceMeta>> {
        if let Some(record) = self.instances.record(target) {
            return Some(record);
        }
        match target {
            // A principal has no record to read: its address derives
            // from a key, and the blueprint serving it is the
            // protocol's, held from genesis and never absent.
            CallTarget::Principal(_) => None,
            CallTarget::Component(address) => {
                let address = address.address();
                if let Some(seen) = self.seen(address) {
                    return Some(seen);
                }
                let record = self.read_from_state(address)?;
                self.hold(address, &record);
                Some(record)
            }
        }
    }

    fn package(&self, hash: PackageHash) -> Option<Arc<PackageMetadata>> {
        self.packages.record(hash)
    }

    /// Derived from the records this node is holding: every resident
    /// instance's package declares which resources it issues, and each
    /// of those addresses re-derives against the instance issuing it.
    ///
    /// Bounded by residency rather than by the chain, which is the same
    /// bound every other answer here carries — a record evicted from
    /// the cache is read back by [`Self::instance`] before it is given
    /// up on, and one this node never held is one no call of its own
    /// named.
    fn resource(&self, resource: ResourceAddr, hasher: &dyn Hasher) -> Option<ResourceMeta> {
        resource_issued_by(
            self.instances.components(),
            self.packages.as_ref(),
            resource,
            hasher,
        )
    }
}

/// Find the record `resource` derives among everything `instances`
/// issue, or `None` where none of them could have issued it.
///
/// A scan rather than an index, because what it scans is bounded by the
/// caller's own world — and an index would be one more thing to keep
/// agreeing with the collections beside it.
pub fn resource_issued_by<'a>(
    instances: impl Iterator<Item = (Address, &'a InstanceMeta)>,
    packages: &MetadataCache,
    resource: ResourceAddr,
    hasher: &dyn Hasher,
) -> Option<ResourceMeta> {
    instances
        .filter_map(|(issuer, meta)| Some((issuer, meta, packages.record(meta.package)?)))
        .flat_map(|(issuer, meta, package)| {
            package
                .methods
                .values()
                .flat_map(|signature| &signature.issues)
                .filter_map(|issuance| issued_record(hasher, issuer, meta, issuance))
                .collect::<Vec<_>>()
        })
        .find(|record| record.address(hasher) == resource)
}

/// The record one declared issuance commits, resolved against the
/// instance issuing it.
///
/// `None` where the grant tree names something the instance's own
/// configuration does not resolve — a resource that instance could
/// never issue, and so one no address of this world's names.
///
/// Shared rather than repeated: an address folds the rules it grants,
/// so two sites deriving it differently would answer for two different
/// resources under one name.
pub(crate) fn issued_record(
    hasher: &dyn Hasher,
    issuer: Address,
    meta: &InstanceMeta,
    issuance: &Issuance,
) -> Option<ResourceMeta> {
    Some(ResourceMeta {
        namespace: issuer,
        kind: issuance.kind,
        material: vec![Value::Bytes(issuance.mark.clone()).canonical_bytes()],
        rules: issuance.grants.resolve(hasher, issuer, &meta.config).ok()?,
    })
}

/// The component address a record's own contents derive, or `None` for
/// bytes that decode as no record at all.
///
/// What a fetched record is verified by: an address is the hash of the
/// record sealed at it, so bytes either derive the address they were
/// asked for or derive some other one and are dropped.
#[must_use]
pub fn record_address(record: &[u8]) -> Option<Address> {
    let meta: InstanceMeta = hbor_from_slice(record).ok()?;
    Some(meta.address(&ProtocolHasher).address())
}

/// How many grown records a node holds before it starts letting the
/// oldest go.
///
/// A bound rather than a horizon, because instances outnumber packages
/// by orders of magnitude and a node that kept every record the chain
/// ever created would hold a copy of a growing share of state in memory
/// forever. What makes a bound safe is that nothing is lost by it: a
/// record for a prefix this node serves is read back from the cell that
/// sealed it, and one for a prefix it does not serve is fetched from the
/// shard that does.
pub(crate) const MAX_RESIDENT_INSTANCES: usize = 1 << 16;

/// The records a node is holding, and the order it lets them go in.
///
/// Immutable, so seating one leaves every pinned reader's view intact —
/// and shared structurally, so leaving it intact costs a handful of
/// nodes rather than a copy of the map.
#[derive(Clone, Debug)]
pub(crate) struct Resident {
    /// The blueprint serving every principal, and the instances genesis
    /// seated. Never let go: a genesis pool on a shard this node does
    /// not serve is answered by neither its state nor, usefully, a
    /// fetch — and the set is small and identical on every node.
    seeded: Arc<InstanceRegistry>,
    /// What commits and fetches have added since.
    grown: OrdMap<Address, Arc<InstanceMeta>>,
    /// The order `grown` was filled in, oldest first.
    ///
    /// Insertion order rather than use: recording a use would mean
    /// writing on the read path, which is every admission on the node.
    /// A record that is still wanted after its turn comes up is read
    /// back and seated afresh, so being busy keeps a record resident
    /// without anything having to measure it.
    order: Vector<Address>,
    capacity: usize,
}

impl Resident {
    /// The record serving a call target, if this node is holding one.
    #[must_use]
    pub(crate) fn record(&self, target: CallTarget) -> Option<Arc<InstanceMeta>> {
        if let Some(seeded) = self.seeded.record(target) {
            return Some(seeded);
        }
        match target {
            CallTarget::Principal(_) => None,
            CallTarget::Component(address) => self.grown.get(&address.address()).cloned(),
        }
    }

    /// Every component record this node is currently holding, seeded
    /// and grown alike.
    ///
    /// Seeded first, so a genesis record answers ahead of a grown one
    /// claiming its address — the same order [`Self::record`] reads in.
    pub(crate) fn components(&self) -> impl Iterator<Item = (Address, &InstanceMeta)> {
        self.seeded.components().chain(
            self.grown
                .iter()
                .map(|(address, meta)| (*address, meta.as_ref())),
        )
    }

    /// This world with `meta` seated at `address`, and whatever the
    /// bound leaves no room for let go.
    ///
    /// A record already resident seats again as itself. The question is
    /// asked here rather than only at the door because two threads
    /// seating one address both find it absent before either commits,
    /// and the loser retries against a world that already holds it — a
    /// second place in the order would then let the record go while the
    /// first place still answers for it.
    fn seated(&self, address: ComponentAddr, meta: &InstanceMeta) -> Self {
        let mut next = self.clone();
        if next.record(address.into()).is_some() {
            return next;
        }
        let address = address.address();
        next.grown.insert(address, Arc::new(meta.clone()));
        next.order.push_back(address);
        while next.order.len() > next.capacity {
            let Some(oldest) = next.order.pop_front() else {
                break;
            };
            next.grown.remove(&oldest);
        }
        next
    }
}

/// The instance registry: what the chain answers a call target with,
/// grown from committed state and bounded.
///
/// The same shape as [`PackageCache`] — a record is immutable once
/// sealed, so two readers hold the same thing and a reader never waits
/// on the commit path — with a bound beneath it, because there are
/// vastly more components than packages and no node needs every one of
/// them in memory to serve the ones it is asked about.
#[derive(Clone, Debug)]
pub struct InstanceCache(Arc<ArcSwap<Resident>>);

impl InstanceCache {
    /// A registry seeded with the instances a cold start already knows,
    /// at the default bound.
    #[must_use]
    pub(crate) fn new(seed: InstanceRegistry) -> Self {
        Self::bounded(seed, MAX_RESIDENT_INSTANCES)
    }

    /// [`Self::new`] holding at most `capacity` grown records.
    #[must_use]
    pub(crate) fn bounded(seed: InstanceRegistry, capacity: usize) -> Self {
        Self(Arc::new(ArcSwap::from_pointee(Resident {
            seeded: Arc::new(seed),
            grown: OrdMap::new(),
            order: Vector::new(),
            capacity,
        })))
    }

    /// The instances this node currently answers for.
    #[must_use]
    pub(crate) fn load(&self) -> Arc<Resident> {
        self.0.load_full()
    }

    /// The records a cold start is born with: the blueprint serving
    /// every principal, and whatever genesis seated.
    ///
    /// Held apart from what a node grew because these are the ones no
    /// node acquires and none may let go — identical on every node, and
    /// so the only records a reader may consult when its answer has to
    /// be the same everywhere.
    #[must_use]
    pub fn seeded(&self) -> Arc<InstanceRegistry> {
        Arc::clone(&self.load().seeded)
    }

    /// A second node's copy: the same records, in a cache that shares
    /// nothing either side goes on to hold or let go.
    #[must_use]
    pub(crate) fn forked(&self) -> Self {
        Self(Arc::new(ArcSwap::from_pointee(Resident::clone(
            &self.load(),
        ))))
    }

    /// The record serving `target`, if this node is holding one.
    #[must_use]
    pub fn record(&self, target: CallTarget) -> Option<Arc<InstanceMeta>> {
        self.load().record(target)
    }

    /// Register `meta` at the address it derives, unless it is already
    /// there.
    ///
    /// First-write-wins, which costs nothing to be sure of: a record is
    /// registered at the address its own contents derive, so a second
    /// one at that address is the same record.
    ///
    /// The check here spares the common repeat a swap; the one the fold
    /// makes is what settles it, since only that one sees the world the
    /// swap actually lands on.
    fn seat(&self, hasher: &dyn Hasher, meta: &InstanceMeta) {
        let address = meta.address(hasher);
        if self.load().record(address.into()).is_some() {
            return;
        }
        self.0.rcu(|current| current.seated(address, meta));
    }

    /// Seat a record verified elsewhere — read out of a committed cell
    /// or delivered by the fetch, both of which check it derives the
    /// address it is claimed for.
    pub(crate) fn seat_record(&self, meta: &InstanceMeta) {
        self.seat(&ProtocolHasher, meta);
    }

    /// Seat the instance a committed cell seals, and answer whether it
    /// was one.
    pub fn absorb_cell(&self, owner: impl Into<Address>, local: [u8; 16], value: &[u8]) -> bool {
        let Some(meta) = committed_instance(owner.into(), local, value) else {
            return false;
        };
        self.seat(&ProtocolHasher, &meta);
        true
    }
}

/// The published-package cache: content-addressed, held by a node, and
/// grown from committed state.
///
/// One cache per node rather than one per shard, because a package is
/// immutable and named by the hash of its own bytes — two shards holding
/// it hold the same thing, and a node running several vnodes has no
/// reason to hold it twice. Two *nodes* are a different matter: what a
/// node has seen commit is its own, and a shard it does not serve
/// publishes code it never absorbs.
///
/// Reads are lock-free because every admission derivation takes one:
/// swapping a whole new map in on the rare publish costs a clone that
/// nothing waits on, where a lock would put every derivation behind the
/// commit path.
#[derive(Clone, Debug)]
pub struct PackageCache {
    published: Arc<ArcSwap<Published>>,
}

/// A package's metadata and its artifact's length, which are one fact.
///
/// Held under a single atom rather than side by side, because a
/// derivation reads both and prices the node on what it finds: metadata
/// without a length would price an instantiation at no bytes at all,
/// and that figure reaches the header's `used`. One swap publishes
/// both, so no reader can see half of a package.
#[derive(Clone, Debug)]
struct Published {
    metadata: Arc<MetadataCache>,
    /// Each published artifact's length: what derivation prices a
    /// node's instantiation at, since running a node reads the
    /// package's artifact whole.
    artifact_bytes: BTreeMap<PackageHash, u64>,
}

impl PackageCache {
    /// A cache seeded with the packages a cold start already knows,
    /// their artifact lengths unknown until [`Self::publish`] states
    /// them.
    #[must_use]
    pub(crate) fn new(seed: MetadataCache) -> Self {
        Self {
            published: Arc::new(ArcSwap::from_pointee(Published {
                metadata: Arc::new(seed),
                artifact_bytes: BTreeMap::new(),
            })),
        }
    }

    /// A cache holding what this one holds now, growing apart from it
    /// afterwards.
    #[must_use]
    pub(crate) fn forked(&self) -> Self {
        Self {
            published: Arc::new(ArcSwap::from_pointee((**self.published.load()).clone())),
        }
    }

    /// The current published set.
    #[must_use]
    pub fn load(&self) -> Arc<MetadataCache> {
        Arc::clone(&self.published.load().metadata)
    }

    /// The length of `package`'s artifact, where this node has seen it.
    #[must_use]
    pub(crate) fn artifact_bytes(&self, package: PackageHash) -> Option<u64> {
        self.published.load().artifact_bytes.get(&package).copied()
    }

    /// Publish `metadata` under `package` unless it is already there,
    /// and record the artifact's length.
    ///
    /// First-write-wins by content address, which is what makes
    /// republishing idempotent: equal hash means equal artifact, so the
    /// entry can never need replacing.
    ///
    /// # Panics
    ///
    /// Panics if the metadata fails the cache's publish check. Every
    /// caller feeds this from a committed artifact that already cleared
    /// admission, so a refusal here is a node defect, never an input.
    pub fn publish(&self, package: PackageHash, metadata: &PackageMetadata, bytes: u64) {
        let current = self.published.load();
        if current.artifact_bytes.contains_key(&package) && current.metadata.get(package).is_some()
        {
            return;
        }
        drop(current);
        // Read-modify-write under a compare-and-swap, because two shard
        // drivers on one node publish concurrently into this one cache:
        // a plain store would drop whichever of two packages lost the
        // race, and `artifact_bytes` fails open at zero where the
        // metadata fails closed.
        self.published.rcu(|current| {
            let mut next = (**current).clone();
            next.artifact_bytes.insert(package, bytes);
            if next.metadata.get(package).is_none() {
                let mut grown = (*next.metadata).clone();
                grown
                    .publish(package, metadata.clone())
                    .expect("everything published here cleared the artifact gate");
                next.metadata = Arc::new(grown);
            }
            Arc::new(next)
        });
    }

    /// Publish the package a committed cell holds, if it holds one, and
    /// say whether it did.
    ///
    /// A package cell is self-identifying — see [`committed_package`] —
    /// and its bytes still have to clear admission before anything is
    /// published under them. The two together are the whole of what
    /// makes a cell a package, which is why the answer is returned
    /// rather than inferred again by the caller: the code that runs an
    /// artifact and the metadata that routes calls into it must never
    /// disagree about whether it was admitted.
    pub fn absorb_cell(&self, owner: impl Into<Address>, local: [u8; 16], value: &[u8]) -> bool {
        let Some(package) = committed_package(owner.into(), local, value) else {
            return false;
        };
        let Ok(metadata) = admit_package(value) else {
            return false;
        };
        self.publish(package, &metadata, value.len() as u64);
        true
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hyperscale_hbor::to_vec as hbor_to_vec;
    use hyperscale_vm_effects::{Hash32, Value};
    use hyperscale_vm_stdlib::account;

    use super::*;

    /// One cell, for a node whose state holds exactly one record.
    struct OneCell {
        key: SubstateKey,
        value: Vec<u8>,
    }

    impl LocalCells for OneCell {
        fn committed_cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
            (key == self.key).then(|| self.value.clone())
        }
    }

    /// A cell answering once, counting how often it was asked.
    struct CountedCell {
        inner: OneCell,
        reads: AtomicUsize,
    }

    impl LocalCells for CountedCell {
        fn committed_cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.inner.committed_cell(key)
        }
    }

    /// Every package published concurrently keeps both halves.
    ///
    /// One cache serves a whole node, and a node runs a shard driver per
    /// hosted shard — so two commits publishing different packages meet
    /// here on different threads. A read-modify-write that is not
    /// compare-and-swapped drops whichever lost, and a package whose
    /// length went missing is priced at no read bytes at all: the
    /// derivation still routes the call, so the node folds a different
    /// `used` into its header than its committee does.
    #[test]
    fn concurrent_publishes_all_survive() {
        const PACKAGES: u8 = 32;

        let cache = PackageCache::new(MetadataCache::new());
        let hashes: Vec<PackageHash> = (0..PACKAGES)
            .map(|seed| PackageHash(ProtocolHasher.hash(b"package", &[&[seed]])))
            .collect();

        std::thread::scope(|scope| {
            for (seed, package) in hashes.iter().enumerate() {
                let cache = &cache;
                scope.spawn(move || {
                    cache.publish(*package, &account::metadata(), seed as u64 + 1);
                });
            }
        });

        for (seed, package) in hashes.iter().enumerate() {
            assert!(
                cache.load().get(*package).is_some(),
                "every package's metadata is published"
            );
            assert_eq!(
                cache.artifact_bytes(*package),
                Some(seed as u64 + 1),
                "and the length it was published with is beside it"
            );
        }
    }

    /// One derivation reads a leaf once, however often it asks for the
    /// record.
    ///
    /// The state read is at the node's own tip, which no view pins, so
    /// what makes the answers one derivation gets a single world's is
    /// that the first one is held: a manifest naming a component in ten
    /// nodes reads its leaf once and reads that answer nine times.
    #[test]
    fn one_derivation_reads_a_leaf_once_however_often_it_asks() {
        let meta = InstanceMeta {
            package: PackageHash(ProtocolHasher.hash(b"package", &[b"staking"])),
            config: vec![Value::U64(4)],
            salt: Hash32([0xA7; 32]),
        };
        let address = meta.address(&ProtocolHasher);
        let cells = Arc::new(CountedCell {
            inner: OneCell {
                key: config_key(address),
                value: hbor_to_vec(&meta).expect("a record encodes"),
            },
            reads: AtomicUsize::new(0),
        });

        let instances = InstanceCache::new(InstanceRegistry::new());
        let packages = PackageCache::new(MetadataCache::new());
        let chain = NodeRecords::pinned(&packages, &instances, Some(Arc::clone(&cells) as Arc<_>));
        for _ in 0..3 {
            assert_eq!(
                chain.instance(address.into()).as_deref(),
                Some(&meta),
                "every lookup in one derivation answers alike"
            );
        }
        assert_eq!(
            cells.reads.load(Ordering::Relaxed),
            1,
            "the leaf is read once and held for the rest of the derivation"
        );
    }

    /// A record the cache never absorbed is read out of the cell that
    /// sealed it — and seated, so the next derivation reads it from
    /// memory.
    ///
    /// What makes a bound on the cache a question of cost rather than of
    /// meaning: on the shard owning a component's prefix the record is
    /// already on disk, so dropping it costs a state read and never an
    /// answer.
    #[test]
    fn a_record_absent_from_the_cache_is_read_from_committed_state() {
        let meta = InstanceMeta {
            package: PackageHash(ProtocolHasher.hash(b"package", &[b"staking"])),
            config: vec![Value::U64(7)],
            salt: Hash32([3; 32]),
        };
        let address = meta.address(&ProtocolHasher);
        let key = config_key(address);
        let cells = Arc::new(OneCell {
            key,
            value: hbor_to_vec(&meta).expect("a record encodes"),
        });

        let instances = InstanceCache::new(InstanceRegistry::new());
        let packages = PackageCache::new(MetadataCache::new());
        assert!(
            instances.record(address.into()).is_none(),
            "the cache starts holding nothing"
        );

        let chain = NodeRecords::pinned(&packages, &instances, Some(cells));
        let answered = chain
            .instance(address.into())
            .expect("the sealing cell answers for it");
        assert_eq!(*answered, meta);

        // Seated on the way past, so the read is paid once.
        assert_eq!(instances.record(address.into()).as_deref(), Some(&meta));
    }

    /// A node past its bound lets the oldest record go, and answers for
    /// it again from the cell that sealed it.
    ///
    /// The whole of what makes the bound safe: nothing a node drops is
    /// lost, so the cache is sized for what it is asked about rather
    /// than for everything the chain has ever created.
    #[test]
    fn a_record_past_the_bound_is_let_go_and_read_back() {
        let record_at = |salt: u8| InstanceMeta {
            package: PackageHash(ProtocolHasher.hash(b"package", &[b"staking"])),
            config: Vec::new(),
            salt: Hash32([salt; 32]),
        };
        let oldest = record_at(1);
        let address = oldest.address(&ProtocolHasher);

        let instances = InstanceCache::bounded(InstanceRegistry::new(), 2);
        for salt in 1..=3 {
            instances.seat_record(&record_at(salt));
        }
        assert!(
            instances.record(address.into()).is_none(),
            "the third record past a bound of two lets the first go"
        );
        assert!(
            instances
                .record(record_at(3).address(&ProtocolHasher).into())
                .is_some(),
            "and the newest stays"
        );

        // The cell that sealed it still answers, so the node resolves
        // the target it just stopped holding.
        let key = config_key(address);
        let cells = Arc::new(OneCell {
            key,
            value: hbor_to_vec(&oldest).expect("a record encodes"),
        });
        let packages = PackageCache::new(MetadataCache::new());
        let chain = NodeRecords::pinned(&packages, &instances, Some(cells));
        assert_eq!(
            chain.instance(address.into()).as_deref(),
            Some(&oldest),
            "a record let go is read back from its own cell"
        );
    }

    /// A record seated twice takes one place in the order.
    ///
    /// The fold a swap retries against already holds what the losing
    /// thread was seating, and a second place would let the record go
    /// while the first still answers for it — so the bound would evict a
    /// record the node is holding and count a place that names nothing.
    #[test]
    fn a_record_seated_twice_takes_one_place_in_the_order() {
        let record_at = |salt: u8| InstanceMeta {
            package: PackageHash(ProtocolHasher.hash(b"package", &[b"staking"])),
            config: Vec::new(),
            salt: Hash32([salt; 32]),
        };
        let first = record_at(1);
        let second = record_at(2);

        // What the losing thread's retry runs: seating a record the
        // world it retried against already holds.
        let resident = Resident {
            seeded: Arc::new(InstanceRegistry::new()),
            grown: OrdMap::new(),
            order: Vector::new(),
            capacity: 2,
        };
        let once = resident.seated(first.address(&ProtocolHasher), &first);
        let twice = once.seated(first.address(&ProtocolHasher), &first);
        let then = twice.seated(second.address(&ProtocolHasher), &second);

        assert_eq!(then.order.len(), 2, "one place each, not one per seating");
        assert_eq!(
            then.record(first.address(&ProtocolHasher).into())
                .as_deref(),
            Some(&first),
            "a bound of two holds both, so the twice-seated record stays"
        );
        assert_eq!(
            then.record(second.address(&ProtocolHasher).into())
                .as_deref(),
            Some(&second),
        );
    }

    /// What genesis seated is never let go: a pool on a shard this node
    /// does not serve is answered by neither its state nor a fetch it
    /// has any reason to make.
    #[test]
    fn the_genesis_seed_outlives_the_bound() {
        let seeded = InstanceMeta {
            package: PackageHash(ProtocolHasher.hash(b"package", &[b"staking"])),
            config: vec![Value::U64(1)],
            salt: Hash32([0xEE; 32]),
        };
        let address = seeded.address(&ProtocolHasher);
        let mut seed = InstanceRegistry::new();
        seed.create(&ProtocolHasher, seeded.clone());

        let instances = InstanceCache::bounded(seed, 1);
        for salt in 1..=4 {
            instances.seat_record(&InstanceMeta {
                package: PackageHash(ProtocolHasher.hash(b"package", &[b"staking"])),
                config: Vec::new(),
                salt: Hash32([salt; 32]),
            });
        }
        assert_eq!(
            instances.record(address.into()).as_deref(),
            Some(&seeded),
            "the bound is over what a node grew, not over what it was born with"
        );
    }

    /// Bytes at the leaf that derive some other address are not this
    /// component's record, and are refused where a fetched one would be.
    #[test]
    fn a_cell_holding_another_components_record_answers_for_neither() {
        let meta = InstanceMeta {
            package: PackageHash(ProtocolHasher.hash(b"package", &[b"staking"])),
            config: vec![Value::U64(7)],
            salt: Hash32([3; 32]),
        };
        let elsewhere = InstanceMeta {
            salt: Hash32([9; 32]),
            ..meta.clone()
        };
        let address = meta.address(&ProtocolHasher);
        // The honest record of a different component, sitting at this
        // one's leaf.
        let cells = Arc::new(OneCell {
            key: config_key(address),
            value: hbor_to_vec(&elsewhere).expect("a record encodes"),
        });

        let instances = InstanceCache::new(InstanceRegistry::new());
        let packages = PackageCache::new(MetadataCache::new());
        let chain = NodeRecords::pinned(&packages, &instances, Some(cells));
        assert!(
            chain.instance(address.into()).is_none(),
            "a record derives the address it is admitted at, or none"
        );
        assert!(
            instances.record(address.into()).is_none(),
            "and nothing it refused is seated"
        );
    }

    /// A committed-transaction cell is judged sweepable off its own
    /// leaf: the value re-derives the key, the bucket the key leads with
    /// is the expiry's, and a leaf at any other local is nothing.
    #[test]
    fn a_committed_transaction_cell_is_judged_off_its_leaf() {
        use hyperscale_vm_effects::{Marked, committed_tx_key};
        use hyperscale_vm_types::{AddressClass, TxHash};

        let owner = Address::new([0x5A; 31], AddressClass::Native);
        let cell = Marker {
            tx: TxHash(Hash32([0xC0; 32])),
            expiry_ms: 200_000,
            marks: Marked::Committed,
        };
        let key = committed_tx_key(&ProtocolHasher, owner, cell.tx, cell.expiry_ms);
        assert_eq!(
            sweepable_cell(owner, key.local.0, &cell.to_bytes()),
            Some(200_000)
        );
        let mut elsewhere = key.local.0;
        elsewhere[15] ^= 1;
        assert_eq!(sweepable_cell(owner, elsewhere, &cell.to_bytes()), None);
        let other_owner = Address::new([0x5B; 31], AddressClass::Native);
        assert_eq!(
            sweepable_cell(other_owner, key.local.0, &cell.to_bytes()),
            None
        );
    }

    /// An escrow claim is judged sweepable off its own leaf, at the
    /// producing intent's validity end plus the escrow grace, and at no
    /// other local and under no other owner. The record beside it is
    /// swept by nothing: it is a balance, retired by whoever consumes
    /// it, so a sweep that could reach it would burn value on a clock.
    #[test]
    fn a_claim_is_judged_off_its_leaf_and_a_record_is_swept_by_nothing() {
        use hyperscale_vm_effects::{CrossingSite, IntentHeader, crossing_expiry_ms};
        use hyperscale_vm_types::{AddressClass, CROSSING_GRACE_MS, IntentHash, NetworkId, TxHash};

        let header = IntentHeader {
            network: NetworkId(0),
            validity_start_ms: 0,
            validity_end_ms: 300_000,
            discriminator: 0,
        };
        let expiry_ms = crossing_expiry_ms(&header);
        assert_eq!(expiry_ms, 300_000 + CROSSING_GRACE_MS);

        let producer = Address::new([0x5A; 31], AddressClass::Component);
        let taker = Address::new([0x5C; 31], AddressClass::Component);
        let intent = IntentHash(Hash32([0xB0; 32]));
        let record_site = CrossingSite::record(&ProtocolHasher, producer, intent, 1, 0, expiry_ms);
        let claim_site = CrossingSite::claim(&ProtocolHasher, taker, intent, 1, 0, expiry_ms);
        let record = record_site.crossing(
            TxHash(Hash32([0xC0; 32])),
            ResourceAddr::new([0xE0; 31]),
            500,
            claim_site.key(),
            None,
        );
        let claim = claim_site.claimed_by(TxHash(Hash32([0xC0; 32])));

        let claim_value = claim.to_bytes();
        let local = claim_site.key().local.0;
        assert_eq!(sweepable_cell(taker, local, &claim_value), Some(expiry_ms));
        let mut elsewhere = local;
        elsewhere[15] ^= 1;
        assert_eq!(sweepable_cell(taker, elsewhere, &claim_value), None);
        let other_owner = Address::new([0x5B; 31], AddressClass::Component);
        assert_eq!(sweepable_cell(other_owner, local, &claim_value), None);

        // The record answers for nothing, at its own leaf or anywhere
        // else: no arm claims it, so no sweep can name it.
        let record_value = record.to_bytes();
        assert_eq!(
            sweepable_cell(producer, record_site.key().local.0, &record_value),
            None
        );
        assert_eq!(
            sweepable_cell(producer, claim_site.key().local.0, &record_value),
            None
        );
        assert_eq!(
            sweepable_cell(taker, record_site.key().local.0, &claim_value),
            None
        );
    }
}
