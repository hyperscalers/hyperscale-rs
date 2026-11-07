//! The VM engine's tick-batch executor.
//!
//! `execute_tick_batch` runs one tick's VM sub-batch end to end: derive
//! each transaction's manifest and effect set through the bridge
//! (exactly the derivation admission ran), pre-read the declared cells
//! from the tick snapshot into an owned committed base, hand the batch
//! to `vm_kernel::execute_batch`, then fold the schedule-invariant
//! receipts into per-transaction absolute `database_updates` in
//! canonical order against the batch baseline — the same fold the
//! kernel's apply phase performs, checked against its end state before
//! anything is returned.
//!
//! Batch receipts are batch-dependent (reservation feasibility is judged
//! with the whole batch's holds in place), so VM outputs are never
//! memoized per transaction — the same transaction in a different block
//! may abort differently.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use blake3::hash as blake3_hash;
use hyperscale_effects_bridge::records::{PackageCache, record_address};
use hyperscale_effects_bridge::vm_statics::{config_key, package_key};
use hyperscale_effects_bridge::{
    BridgeStatics, CallEnvelope, DeclaredVector, NodeRecords, PROTOCOL_RESOURCE, ProtocolHasher,
    RecordStore, admit_package, declared_vector, envelope_bytes, is_protocol_vault,
    witness_from_event,
};
use hyperscale_metrics::{record_provision_range_entries_consumed, record_transaction_executed};
use hyperscale_storage::{Anchored, TickViewSnapshot, entry_from_leaf};
use hyperscale_types::{
    BeaconWitnessEvent, BeaconWitnessRoot, ConsensusReceipt, Derivation, EffectsDigest, Epoch,
    EscrowedValue, Event, EventExt, EventRoot, ExecutionMetadata, FeeSummary, GlobalReceipt, Hash,
    MAX_STAGED_RECEIPT_BYTES, MAX_TICK_STAGED_BYTES, Movement, PriceTable, PrincipalAddr,
    ProvisionalHolds, Role, ShardId, ShardTrie, StakePoolSeat, StateWrites, SubstateEntry,
    Transaction, TxHash, Verified, WeightedTimestamp, compute_merkle_root, effects_digest,
    install_protocol_statics, staged_yes_bytes, whole_work, witness_root, writes_root,
};
use hyperscale_vm_effects::{
    Admitted, Answered, ChainRecords, Composed, CrossingId, Declaration, DeclaredAccess,
    InstanceMeta, IntentRecord, PackageHash, fee_hold_key, legs_of, package_hash,
};
use hyperscale_vm_kernel::{
    AmountLedger, Baseline, BatchError, BatchTx, EnvInputs, ExecutionMode, FeeBurn, FeeHolds, Job,
    LegPlan, ManifestWalk, MemoryStore, OverlayStore, OwnerSet, Receipt, ServedReads, StoreError,
    Substates, WithheldCredits, execute_batch,
};
use hyperscale_vm_types::{
    AbortReason, Address, CallTarget, CollectionId, DeclaredWork, Effect, EffectSet, EffectTarget,
    EntryKey, Mode, Moves, Outcome, ResourceAddr, SeedWindow, SubstateKey, UnmetCondition,
    range_lift,
};

use crate::backend::{Availability, EngineBackend};
use crate::genesis::{GenesisPackages, World, genesis_world_with_pools};
use crate::legs::{Member, never_answer};
use crate::records::MemberRecords;
use crate::sharding::owned_by;
use crate::{CachedOutput, ExecutedTx, TickBatchContext, TickTxInput, project_to_shard};

/// One derived transaction, as the batch consumes it.
///
/// The walk itself is the kernel's: routing lowers each manifest node to
/// the invocation its package's ABI binding describes, and
/// [`ManifestWalk`] performs them over the engine backend. Nothing on
/// this side names a method.
pub struct PreparedTx {
    /// What the kernel does for this member: walk the lowered
    /// invocations, in manifest node order, under the plan saying which
    /// of them this shard runs — envelope trees lower into one flat
    /// list, so nothing downstream sees intent structure.
    pub(crate) job: Job,
    /// The routed declaration, both views: the folded set scheduling
    /// reads, and the clause order the capability table is built in —
    /// which is what a lowered call's handle positions index.
    pub(crate) declaration: Declaration,
    /// One record per intent: the nullifier the batch entry enforces,
    /// and what the cell recording its spend says.
    pub(crate) nullifiers: Vec<IntentRecord>,
    /// The envelope's signed compute ceilings, in fuel: one per manifest
    /// node, in node order, each metering its own node and nothing else.
    pub(crate) gas_limits: Vec<u64>,
    /// What each call's method declares it may emit, in node order,
    /// which the kernel meters that node's events against and the
    /// declaration priced as retention.
    pub(crate) event_bytes: Vec<u32>,
    /// What the transaction declares it may consume, whole.
    pub(crate) work: DeclaredWork,
    /// The owners this shard judges — with the job's plan, the one part
    /// of an entry that differs per participant.
    pub(crate) judges: OwnerSet,
    /// The instance records the envelope carries: what a component this
    /// transaction seals is known by before any commit holds it, so the
    /// witness lift can tell a pool sealed here from any other emitter.
    pub(crate) presented: Arc<[InstanceMeta]>,
}

/// The component address a record's own contents derive, or `None` for
/// bytes that are not a record.
///
/// What verifies a fetched record: the address is the hash of the
/// record, so bytes claiming to be one either derive the address asked
/// for or derive some other and are dropped.
#[must_use]
pub fn instance_of_record(record: &[u8]) -> Option<Address> {
    record_address(record)
}

/// The content address of a package artifact, as the workspace hash the
/// beacon registry and fetch protocol carry.
#[must_use]
pub fn artifact_package(artifact: &[u8]) -> Hash {
    Hash::from(package_hash(&ProtocolHasher, artifact).0)
}

/// The protocol crypto hash behind the kernel's hashing host function
/// and fresh-ID derivation.
#[must_use]
pub fn protocol_hash(data: &[u8]) -> [u8; 32] {
    *blake3_hash(data).as_bytes()
}

/// The environment a member executes under: its transaction clock, the
/// epoch that clock falls in, and the seeds a draw clocked there reads.
///
/// All three are facts about the transaction: every shard running the
/// same body passes one clock, the epoch is the grid's answer for it,
/// and the seed window is a function of that epoch alone, so two shards
/// running one core in ticks under different windows pass one window.
///
/// Each epoch's window is built once into `drawn` and shared by every
/// member clocked in it.
///
/// # Panics
///
/// Where the tick's ring lacks a seed of the member's window. A tick
/// dispatches only once it holds every member's, so this is a dispatch
/// that skipped the wait; answering it anyway would be a draw this node
/// alone answers.
fn env_at(
    ctx: &TickBatchContext<'_>,
    drawn: &mut BTreeMap<Epoch, SeedWindow>,
    clock: WeightedTimestamp,
) -> EnvInputs {
    let epoch = ctx.env.windows.epoch_for(clock);
    let seeds = drawn
        .entry(epoch)
        .or_insert_with(|| {
            ctx.env
                .seeds
                .window_for(epoch)
                .expect("a tick dispatches once its ring holds every member's seed window")
        })
        .clone();
    EnvInputs {
        clock_ms: clock.as_millis(),
        epoch: epoch.inner(),
        seeds,
    }
}

/// The batch's committed baseline: the declared content pre-read from
/// the tick's JMT-backed snapshot at materialize time — point cells and
/// the entries of declared collection intervals.
///
/// Every kernel read flows through a capability for a declared effect,
/// so pre-reading exactly the declared targets is complete. An
/// instance's configuration leaf is one of them: committed state the
/// fence on every method reads, immutable by its one-way write door
/// rather than by a lock, so nothing here is locked.
#[derive(Debug, Default)]
pub struct TickBaseline {
    pub(crate) cells: BTreeMap<SubstateKey, Vec<u8>>,
    /// The committed entries of every declared collection interval,
    /// keyed by entry identity — [`materialize_declared`] fills it, and
    /// the kernel's range capabilities read through it.
    pub(crate) entries: BTreeMap<EntryKey, Vec<u8>>,
    /// What legs of unresolved ticks hold against these cells. Empty for
    /// a baseline with nothing in flight over it — a preview, or a shard
    /// with no cross-shard leg outstanding.
    pub(crate) holds: ProvisionalHolds,
    /// The fee holds standing on each protocol vault the batch can
    /// reach, its own members named apart. Empty for a baseline with
    /// nothing committed over it — a preview.
    pub(crate) fee_holds: BTreeMap<SubstateKey, FeeHolds>,
    /// The owners whose entry points fall through, and the reader that
    /// answers one no pre-read named, at the version the pre-read read.
    /// The owners are the ones the trie routes to the executing shard,
    /// the same rule [`materialize_declared`]'s locality and the fee
    /// paths apply. `None` answers every point from the map alone.
    pub(crate) points: Option<(OwnerSet, Arc<dyn PointReads>)>,
}

/// Point reads of ordered-collection entries at a baseline's version.
///
/// What a take or a filing probes at an order no declaration's pre-read
/// could know, since a filing can follow a mint whose ids the issuer
/// chose. Ranges never reach this: they are the pre-read's.
pub trait PointReads: Send + Sync + std::fmt::Debug {
    /// The entry at `order`, if any.
    fn entry(&self, owner: Address, collection: CollectionId, order: u128) -> Option<Vec<u8>>;
}

/// The owners `trie` routes to `shard`: a batch's share of the world
/// when it reaches beyond its shard, and the owners whose points fall
/// through to its reader.
pub fn routed_to(trie: &ShardTrie, shard: ShardId) -> OwnerSet {
    let trie = trie.clone();
    OwnerSet::of(move |owner: Address| trie.shard_for_prefix(owner) == shard)
}

impl<Snap: Anchored + 'static> PointReads for TickViewSnapshot<Snap> {
    fn entry(&self, owner: Address, collection: CollectionId, order: u128) -> Option<Vec<u8>> {
        Substates::entry(self, owner, collection, order)
    }
}

impl Substates for TickBaseline {
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        self.cells.get(&key).cloned()
    }

    fn entries_in_range(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
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
        self.entries
            .range(lo_key..=hi_key)
            .take(limit)
            .map(|(key, value)| (key.order, value.clone()))
            .collect()
    }

    /// The map, then the point reader for an owner the trie routes here.
    /// Any other owner's entry answers from the map alone: read out of
    /// this store it would differ between replicas, which hold nothing of
    /// another shard's subtree in common, and the pre-read named none of
    /// it either.
    fn entry(&self, owner: Address, collection: CollectionId, order: u128) -> Option<Vec<u8>> {
        let key = EntryKey {
            owner,
            collection,
            order,
        };
        if let Some(value) = self.entries.get(&key) {
            return Some(value.clone());
        }
        let (routed, points) = self.points.as_ref()?;
        if !routed.covers(owner) {
            return None;
        }
        points.entry(owner, collection, order)
    }
}

impl Baseline for TickBaseline {
    fn holds(&self, key: SubstateKey) -> BTreeMap<TxHash, u128> {
        self.holds.get(&key).cloned().unwrap_or_default()
    }

    fn fee_holds(&self, key: SubstateKey) -> FeeHolds {
        self.fee_holds.get(&key).cloned().unwrap_or_default()
    }

    fn withheld_credits(&self, _key: SubstateKey) -> WithheldCredits {
        WithheldCredits::default()
    }
}

/// Materialize one declaration's baseline from the tick snapshot: for
/// every declared effect this shard owns, the committed content it
/// reads — the point cell, or the interval's [`range_lift`] lowest
/// entries, which is what the kernel's page lifts and what a provision
/// part serves of the same interval.
///
/// The one pre-read: `run_batch` and `preview` both fill their baselines
/// here, so ordered-collection support exists in exactly one place and
/// the preview cannot drift from execution. The match is exhaustive over
/// the target vocabulary — a new target form fails here at compile time
/// rather than executing against a silently empty baseline.
pub fn materialize_declared(
    snapshot: &(dyn Substates + Sync),
    declared: &EffectSet,
    locality: &OwnerSet,
    base: &mut TickBaseline,
) {
    for effect in declared.iter() {
        // An entry is its width-one interval — the same normalization
        // `admission_key` applies, so the two vocabulary walks stay
        // parallel.
        let (owner, collection, lo, hi, cap) = match effect.target {
            EffectTarget::Point(key) => {
                if locality.covers(key.owner)
                    && let Some(value) = snapshot.cell(key)
                {
                    base.cells.insert(key, value);
                }
                continue;
            }
            EffectTarget::Entry {
                owner,
                collection,
                order,
            } => (owner, collection, order, order, 1),
            EffectTarget::Range {
                owner,
                collection,
                lo,
                hi,
                cap,
            } => (owner, collection, lo, hi, cap),
        };
        if locality.covers(owner) {
            for (order, value) in
                snapshot.entries_in_range(owner, collection, lo, hi, range_lift(lo, hi, cap))
            {
                base.entries.insert(
                    EntryKey {
                        owner,
                        collection,
                        order,
                    },
                    value,
                );
            }
        }
    }
}

/// What one member's counterparts provisioned it, as the content its
/// session reads beneath the batch's baseline.
///
/// A provisioned leaf is a cell or an ordered-collection entry, and the
/// leaf says which: an entry re-derives its own key and lands where the
/// kernel's range capabilities read. An absent leaf adds nothing.
/// Returns the reads and how many of them are entries.
fn provisioned_reads(lists: &[Arc<Vec<SubstateEntry>>]) -> (MemoryStore, usize) {
    let mut reads = MemoryStore::new();
    let entries = lists.iter().map(|list| absorb_part(&mut reads, list)).sum();
    (reads, entries)
}

/// Write `part` into `reads`, and how many of its leaves were collection
/// entries. An absent cell writes nothing: it reads absent.
fn absorb_part(reads: &mut MemoryStore, part: &[SubstateEntry]) -> usize {
    let mut entries = 0;
    for entry in part {
        let Some(value) = entry.value.as_ref() else {
            continue;
        };
        if let Some((key, value)) = entry_from_leaf(entry.key, value) {
            reads.entry_write(key.owner, key.collection, key.order, value);
            entries += 1;
        } else {
            reads.write(entry.key, value.clone().into_inner());
        }
    }
    entries
}

/// The VM engine: the genesis-static world, the compiled stdlib guests,
/// and the batch scheduling mode.
pub struct Executor {
    pub(crate) world: World,
    pub(crate) backend: EngineBackend,
    pub(crate) mode: ExecutionMode,
    derivation: Arc<BridgeStatics>,
}

/// This node could not run a package a tick's member named.
///
/// Machine-local, so nothing about the transaction is decided by it: the
/// batch produced no receipts and attested nothing. What the embedder
/// owes it is the code and another attempt at the same tick — which is
/// still the tick its committee composed, whenever it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeUnavailable {
    /// The transaction whose invocation found the environment wanting.
    pub tx: TxHash,
    /// The package whose code this node could not run.
    pub package: Hash,
    /// The class the backend reported.
    pub(crate) reason: AbortReason,
}

/// Whether this node holds the code a tick's members name.
///
/// A local readiness question, never an input to a committed value: what
/// it gates is *when* a tick dispatches, not what the tick is or what it
/// decides. The answer is monotone, so a tick released on it cannot find
/// the code gone by the time it runs.
///
/// True of a build still in flight as well as one that landed. The
/// invocation waits a build out — that wait is what keeps two replicas
/// from answering differently about one package — so holding a tick for
/// it would trade a bounded wait on the execution thread for one whose
/// length is a background compile's, and make when a tick runs a
/// question about this machine's load.
///
/// Asked where the dispatch decision is made, rather than pushed there
/// as a set: a set has to be seeded, and a shard seated mid-epoch has
/// nobody to seed it.
pub trait CodeAvailability: Send + Sync {
    /// Whether `package`'s code is in this node's hands, built or
    /// building.
    fn can_run(&self, package: Hash) -> bool;
}

impl CodeAvailability for Executor {
    fn can_run(&self, package: Hash) -> bool {
        matches!(
            self.package_standing(PackageHash(package.as_hash32())),
            Availability::Runnable | Availability::Building
        )
    }
}

/// A [`CodeAvailability`] that answers for every package.
///
/// For a harness standing a coordinator up with no engine behind it. A
/// node that acquires code answers from its engine, which is the only
/// answer that can hold a tick.
#[cfg(feature = "test-utils")]
pub struct AllCodeRuns;

#[cfg(feature = "test-utils")]
impl CodeAvailability for AllCodeRuns {
    fn can_run(&self, _package: Hash) -> bool {
        true
    }
}

impl Executor {
    /// Build the engine, its derivation, and the process-wide protocol
    /// answers (first installation wins, so co-hosted nodes sharing one
    /// genesis coexist).
    ///
    /// # Panics
    ///
    /// Panics if the committed stdlib artifact fails validation or
    /// compilation — a build defect surfaced at boot, not in a tick.
    #[must_use]
    pub fn new(mode: ExecutionMode) -> Self {
        Self::with_genesis(&[], &GenesisPackages::protocol(), mode)
    }

    /// [`Self::new`] over this network's genesis: `pools` seated as the
    /// stake pools the beacon folds for, and `packages` as the code the
    /// chain is born running.
    ///
    /// # Panics
    ///
    /// As [`Self::new`].
    #[must_use]
    pub fn with_genesis(
        pools: &[StakePoolSeat],
        packages: &GenesisPackages,
        mode: ExecutionMode,
    ) -> Self {
        let world = genesis_world_with_pools(pools, packages);
        let backend = EngineBackend::new(packages);
        // The two halves split on whether a node can answer differently.
        // The derivation reads this engine's caches and is held here, so
        // a process standing several nodes up gives each its own; the
        // protocol answers read nothing a node accumulates, so they are
        // installed once for the process.
        let derivation = Arc::new(BridgeStatics {
            cache: world.cache.clone(),
            instances: world.instances.clone(),
            artifact_sink: Some(Arc::new(backend.absorber())),
            store: OnceLock::new(),
        });
        install_protocol_statics(Box::new(BridgeStatics {
            cache: world.cache.clone(),
            instances: world.instances.clone(),
            artifact_sink: None,
            store: OnceLock::new(),
        }));
        Self {
            world,
            backend,
            mode,
            derivation,
        }
    }

    /// This engine's derivation: what its node can resolve an envelope
    /// against.
    #[must_use]
    pub fn derivation(&self) -> Arc<dyn Derivation> {
        Arc::clone(&self.derivation) as Arc<dyn Derivation>
    }

    /// A second engine beside this one: its own copy of the world, its
    /// own derivation over that copy, and its own compiled code.
    ///
    /// A harness standing several nodes up in one process uses this so
    /// each of them holds only what it has itself seen — the code a
    /// publish put on the chain and the record an instantiation sealed
    /// alike — the way separate processes would. A node on a shard where
    /// neither committed genuinely cannot answer for them until its own
    /// fetch lands, which is what puts the acquisition paths under test
    /// instead of around them.
    ///
    /// The backend starts at the protocol's own code rather than at this
    /// engine's, so a genesis fixture package is acquired too.
    #[must_use]
    pub fn peer(&self, mode: ExecutionMode) -> Self {
        let world = self.world.fork();
        let backend = EngineBackend::new(&GenesisPackages::protocol());
        let derivation = Arc::new(BridgeStatics {
            cache: world.cache.clone(),
            instances: world.instances.clone(),
            artifact_sink: Some(Arc::new(backend.absorber())),
            store: OnceLock::new(),
        });
        Self {
            world,
            backend,
            mode,
            derivation,
        }
    }

    /// The published-package cache this engine routes against.
    ///
    /// Shared with this engine's derivation rather than copied, so a
    /// package a committed block publishes is visible to admission and to
    /// execution at the same instant.
    #[must_use]
    pub const fn packages(&self) -> &PackageCache {
        &self.world.cache
    }

    /// What this engine's world answers for, pinned — the same view
    /// admission derives through.
    #[must_use]
    pub fn records(&self) -> NodeRecords {
        self.derivation.records()
    }

    /// Tell this engine where its node keeps records on disk, so a
    /// record the cache does not hold is looked for there before it is
    /// given up on. Installed by the host, which knows what it serves
    /// and where it keeps what it fetched.
    pub fn install_store(&self, store: Arc<dyn RecordStore>) {
        self.derivation.install_store(store);
    }

    /// Seed one committed artifact from a store's package index: metadata
    /// into the cache, code into the backend.
    ///
    /// The boot half of what commit-time absorption does live — a
    /// restarted node re-learns its packages from the index its own
    /// commits wrote. The index holds only committed, self-identified
    /// artifacts, so a refusal here means a corrupt store and is skipped
    /// loudly rather than trusted.
    pub fn install_artifact(&self, artifact: &[u8]) {
        match admit_package(artifact) {
            Ok(metadata) => {
                self.world.cache.publish(
                    package_hash(&ProtocolHasher, artifact),
                    &metadata,
                    artifact.len() as u64,
                );
                self.backend.absorb_artifact(artifact);
            }
            Err(error) => {
                tracing::warn!(
                    reason = %error,
                    "indexed package artifact refused admission"
                );
            }
        }
    }

    /// Where `package` stands on this node.
    #[must_use]
    pub fn package_standing(&self, package: PackageHash) -> Availability {
        self.backend.code_standing(package)
    }

    /// Whether the artifact behind `package` is worth asking a peer for:
    /// this node holds none of its bytes.
    #[must_use]
    pub fn needs_artifact(&self, package: Hash) -> bool {
        self.package_standing(PackageHash(package.as_hash32())) == Availability::Absent
    }

    /// The cell a package's artifact is kept in — where a node serving
    /// an artifact fetch reads, and what the content address alone
    /// names.
    ///
    /// Like a component's record and for the same reason: the key
    /// derives from the name, so a request naming a package is a request
    /// naming a key and the shard owning that prefix is the one obliged
    /// to answer.
    #[must_use]
    pub fn package_artifact_key(package: Hash) -> SubstateKey {
        package_key(PackageHash(package.as_hash32()))
    }

    /// The cell a component's record is sealed into — where a node
    /// serving a record fetch reads, and what the address alone names.
    ///
    /// Unlike a package, whose cell sits under whoever published it, a
    /// component's leaf sits under the component itself. So a request
    /// naming an address is a request naming a key, and serving one
    /// needs no index over what a store has committed.
    #[must_use]
    pub fn instance_record_key(instance: Address) -> SubstateKey {
        config_key(instance)
    }

    /// Seat one fetched record under the component it derives.
    ///
    /// The re-derivation is the whole verification, and it happens here
    /// as well as at the response boundary: a component's address is the
    /// hash of its record, so bytes deriving any other address seat
    /// nothing. Idempotent — a record is immutable once sealed, so a
    /// second copy is the same copy.
    pub fn install_instance(&self, instance: Address, record: &[u8]) {
        let _ = self.world.instances.absorb_cell(
            instance,
            Self::instance_record_key(instance).local.0,
            record,
        );
    }

    /// Whether this node answers for the component at `instance`: the
    /// question derivation asks of the same view, the stores the node
    /// keeps on disk included.
    #[must_use]
    pub fn instance_known(&self, instance: Address) -> bool {
        CallTarget::try_from(instance).is_ok_and(|target| self.records().instance(target).is_some())
    }

    /// Whether derivation reads `package`'s metadata on this node.
    #[must_use]
    pub fn package_known(&self, package: Hash) -> bool {
        self.records()
            .package(PackageHash(package.as_hash32()))
            .is_some()
    }

    /// Derive one transaction's invocations, effect set, and nullifiers
    /// — the same `decode → admit → route` admission ran; refusal here
    /// means the transaction bypassed admission and fails
    /// deterministically.
    ///
    /// Deterministically only as far as `chain` is: a refusal is this
    /// member's contribution to a receipt root, so what answers a target
    /// on the commit path has to answer the same on every member. That
    /// is [`MemberRecords`], which reads the block and committed state
    /// and nothing a node accumulated on its own.
    ///
    /// Nothing of the engine enters it, which is the same statement from
    /// the other side: what an envelope declares is a function of the
    /// envelope and the records, and of no node running it.
    ///
    /// [`MemberRecords`]: crate::records::MemberRecords
    pub(crate) fn prepare(
        tx: &Transaction,
        chain: &dyn ChainRecords,
        packages: &PackageCache,
    ) -> Result<PreparedTx, String> {
        Self::prepare_admitting(tx, chain, packages).map(|(prepared, _)| prepared)
    }

    /// [`Self::prepare`] for a member running the transaction's shape:
    /// the legs `decomposed` gives this shard under `ctx`, with its
    /// crossing cells declared.
    fn prepare_shape(
        tx: &Transaction,
        records: &MemberRecords,
        packages: &PackageCache,
        member: &Member,
        arrivals: &[EscrowedValue],
    ) -> Result<PreparedTx, String> {
        let mut entry = Self::prepare(tx, records, packages)?;
        let plan = member
            .classified()
            .plan(
                arrivals,
                member.local(),
                tx.validity_range().end_timestamp_exclusive,
            )
            .map_err(|defect| format!("no plan for this shard: {defect}"))?;
        declare_crossing_cells(&mut entry.declaration, &plan.legs)?;
        entry.job.legs = plan.legs;
        entry.judges = plan.judges;
        Ok(entry)
    }

    /// [`Self::prepare`], keeping the admitted form it lowered from.
    ///
    /// The commit path drops it — what a block runs is the entry — and a
    /// preview keeps it, because a refusal is explained against the
    /// declaration that named the condition and nothing else can say
    /// which node asked for what.
    pub(crate) fn prepare_admitting(
        tx: &Transaction,
        chain: &dyn ChainRecords,
        packages: &PackageCache,
    ) -> Result<(PreparedTx, Admitted), String> {
        let vm = tx.body();
        // The same decode, attesting sets and admission a derivation
        // runs, the same terms held to the manifest and the same
        // declared debits held to what a fee hold stands under — a
        // preview reaches the kernel without deriving, and what it
        // reports has to be the verdict the chain would reach. Whose
        // keys attested
        // each intent is read off the envelope's own material, verified
        // or not: a gate names an account, and only an intent that
        // account signed presents it, so there is nothing an unsigned
        // envelope could be assumed into that signing it would not also
        // do. The records the caller answers with come through `chain`;
        // admission composes the envelope's own over them itself.
        let call = CallEnvelope::decode(vm).map_err(|error| error.to_string())?;
        let admitted = call.admit(chain).map_err(|error| error.to_string())?;
        let terms = call.terms();
        // The same vector derivation puts on the envelope, so a preview
        // reports what a block would charge without running the
        // derivation — which admits under the rule as the chain applies
        // it, and caches what it derived onto the transaction.
        let legs = legs_of(&admitted);
        let DeclaredVector {
            shares,
            node_terms,
            artifacts,
            everywhere,
            event_bytes,
        } = declared_vector(
            packages,
            terms,
            call.signature_work(),
            &admitted,
            &legs,
            envelope_bytes(vm).map_err(|error| error.to_string())?,
        )
        .map_err(|refusal| refusal.to_string())?;
        let work = whole_work(&shares, &node_terms, &artifacts, everywhere);
        // Both views of the declaration, straight from the fold: the
        // folded set that scheduling and judging read, and the clause
        // order capability materialization walks.
        let declaration = admitted.declaration().clone();
        let calls = admitted.calls().to_vec();
        let presented: Arc<[InstanceMeta]> = call.tree.instances.iter().cloned().collect();
        Ok((
            PreparedTx {
                // Whole until the batch pipeline plans the member for its
                // shard; a preview never divides.
                job: Job {
                    calls,
                    legs: LegPlan::whole(0),
                },
                declaration,
                nullifiers: admitted.intents().to_vec(),
                gas_limits: terms.gas_limits.to_vec(),
                event_bytes,
                work,
                judges: OwnerSet::whole(),
                presented,
            },
            admitted,
        ))
    }
}

/// The batch entry `prepared` runs as: every bound the kernel meters
/// against and every set it judges against, carried from the
/// preparation.
///
/// One mapping for every caller, because a term left behind here is a
/// bound the kernel does not apply — and a preview that left one behind
/// would report a verdict the chain would not reach. `applies` is the
/// caller's, being the one thing the preparation does not fix: a tick
/// scopes it to the shard's own keys and a preview covers everything.
/// So is `credits_withheld`, which is a fact about the member's
/// batch-mates: whether any of them can settle without it.
pub fn batch_entry(
    tx: TxHash,
    prepared: &PreparedTx,
    env: EnvInputs,
    applies: OwnerSet,
    fee: Option<FeeBurn>,
    credits_withheld: bool,
) -> BatchTx {
    BatchTx::new(tx, prepared.declaration.clone(), env)
        .with_job(prepared.job.clone())
        .with_nullifiers(prepared.nullifiers.clone())
        .with_gas_limits(prepared.gas_limits.clone())
        .with_event_bytes(prepared.event_bytes.clone())
        .with_applies(applies)
        .with_judges(prepared.judges.clone())
        .with_fee(fee)
        .with_credits_withheld(credits_withheld)
}

/// Fuel and the abort reason (if any) as node-local metadata.
/// How an abort reads in a diagnostic: its class, rendered.
///
/// The only place an abort becomes prose, and it is the right one — the
/// metadata is node-local, so nothing downstream of here is hashed or
/// compared between committees.
///
/// One derivation, because a preview quotes the same verdict a tick
/// records and two copies would drift apart silently. Never
/// consensus-critical — it lands in the node-local metadata, which a
/// syncing replica does not carry.
///
/// # Panics
///
/// Panics on a completed outcome, which is not an abort.
pub fn abort_reason(outcome: &Outcome) -> String {
    match outcome {
        Outcome::UserError { reason } | Outcome::ProtocolError { reason } => format!("{reason:?}"),
        Outcome::Infeasible { key, amount } => format!("infeasible: {amount} uncovered on {key:?}"),
        Outcome::ConstraintUnmet {
            node,
            param,
            amount,
        } => format!("constraint unmet: node {node} parameter {param} carried {amount}"),
        Outcome::NullifierSpent { key } => format!("subintent already spent at {key:?}"),
        Outcome::EscrowAlreadyClaimed { key } => format!("crossing already claimed at {key:?}"),
        Outcome::EscrowAlreadyIssued { key } => format!("crossing already issued at {key:?}"),
        Outcome::BaselineDiscarded { flipped } => {
            format!("baseline discarded: group-mate {flipped:?} flipped at apply")
        }
        Outcome::Declined { node, code } => format!("node {node} declined with code {code}"),
        Outcome::ConditionUnmet { condition } => match condition {
            UnmetCondition::Holds {
                target,
                required,
                node,
            } => node.map_or_else(
                || format!("leaf of {target:?} is not {required:?} as the condition required"),
                |node| {
                    format!(
                        "node {node} required leaf of {target:?} to be {required:?}, and it is not"
                    )
                },
            ),
            UnmetCondition::Satisfies { node } => {
                format!("node {node} presents nothing that satisfies a required rule")
            }
            UnmetCondition::SignedIn { account } => format!(
                "the rule stored at {account:?} does not admit the keys that attested the intent \
                 acting as it"
            ),
            UnmetCondition::Unanswerable { node } => node.map_or_else(
                || "a condition the judge it reached could not answer".to_owned(),
                |node| format!("node {node} declared a condition its judge could not answer"),
            ),
        },
        Outcome::Completed { .. } => unreachable!("aborts only"),
    }
}

/// The node-local metadata of one execution: what it was charged, and
/// why it aborted if it did.
/// The receipt's own summary of what was charged, in quanta — the unit
/// the price and the ceiling are already in.
fn vm_metadata(charged: u128, error: Option<String>) -> ExecutionMetadata {
    ExecutionMetadata::new(
        FeeSummary {
            total_execution_cost: Some(charged),
            total_royalty_cost: None,
            total_storage_cost: None,
            total_tipping_cost: None,
        },
        Vec::new(),
        error,
    )
}
/// End the fee hold `tx` placed on `vault`, in the write set that burns
/// its price: a hold stands from the block committing the transaction
/// to the one settling this write, whatever the burn comes to.
fn release_fee_hold(writes: &mut StateWrites, vault: SubstateKey, tx: TxHash) {
    writes
        .cells
        .insert(fee_hold_key(&ProtocolHasher, vault, tx), None);
}

/// Lay a run's burn over the writes its delta projected to: the delta is
/// the one every shard of the member derives, and the burn this shard's
/// alone.
fn compose_burn(writes: &mut StateWrites, burn: Option<(SubstateKey, Movement)>) {
    let Some((vault, burned)) = burn else {
        return;
    };
    let composed = writes.movements.get(&vault).map_or(burned, |standing| {
        standing
            .then(burned)
            .expect("a vault's debits fit under its balance and its credits")
    });
    writes.movements.insert(vault, composed);
}

/// The digest of a run a counterpart can refuse: its whole delta and all
/// its events, owned and remote, the burn apart. The one thing every
/// shard it spans derives alike, and what a sibling's yes is held to.
/// Taken here and not in the kernel, because a member nobody shares has
/// no reader for it.
fn whole_effects(receipt: &Receipt) -> EffectsDigest {
    let whole = receipt
        .delta
        .project(&OwnerSet::whole())
        .expect("the kernel weighed every movement of the run");
    let events: Vec<Hash> = receipt.events.iter().map(EventExt::hash).collect();
    effects_digest(&whole, EventRoot::from_raw(compute_merkle_root(&events)))
}

/// What the charge pass took for a member the kernel burned nothing
/// for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Charge {
    /// An admitted publish's whole price, which the vault covers under
    /// every other hold standing on it: a judged debit inside the
    /// publish's own writes, and apart beside them where a counterpart
    /// can still refuse it.
    Burned(u128),
    /// What the floor left of the price of a member that applied no
    /// effects, taken apart in its refusal receipt. The whole price
    /// wherever the member's hold was covered when its block committed.
    Apart(u128),
}

impl Charge {
    const fn amount(self) -> u128 {
        match self {
            Self::Burned(amount) | Self::Apart(amount) => amount,
        }
    }
}

/// Charge every member whose price no kernel session burned: one that
/// did not complete, one refused before the kernel ran, and a publish,
/// which never enters it.
///
/// One judgement for all of them, the one a completed member's burn
/// gets: the member's fee hold ends, and its price comes out of what the
/// vault holds under every reservation, every other fee hold still
/// standing and every credit withheld from it. `settled` is the kernel's
/// applied store, so each charge is judged over everything the batch's
/// completed members moved; the pass runs in canonical transaction order
/// over its own copy, so each charge is judged over the ones before it
/// too.
///
/// An admitted publish burns its whole price or is refused: it writes
/// its artifact only as a transaction that paid. Everything else takes
/// the price down to what the floor leaves, and that is the whole price
/// wherever the vault covered the member's hold when its block
/// committed, since the hold just ended was standing under every debit
/// judged since.
fn charge_unburned(
    settled: &OverlayStore,
    fees: &BTreeMap<TxHash, PayerFee>,
    receipts: &BTreeMap<TxHash, Receipt>,
    admitted_publishes: &BTreeSet<TxHash>,
) -> BTreeMap<TxHash, Charge> {
    let mut store = settled.clone();
    let mut charges = BTreeMap::new();
    for (tx, payer) in fees {
        let burned_in_session = receipts
            .get(tx)
            .is_some_and(|receipt| matches!(receipt.outcome, Outcome::Completed { .. }));
        if burned_in_session {
            continue;
        }
        store.set_fee_hold(payer.vault, *tx, None);
        let spendable = match store.spendable(payer.vault, *tx, 0) {
            Ok(spendable) => spendable,
            // Reservations past the cell leave no balance to judge a
            // charge against.
            Err(StoreError::HeldExceedsCommitted(_)) => 0,
            // A vault whose cell is no amount is one no replica can
            // charge, where an absent one holds nothing.
            Err(error) => panic!(
                "BFT CRITICAL: the charge of {tx:?} reads no floor on {:?}: {error}",
                payer.vault
            ),
        };
        let price = payer.burned();
        let charge = if admitted_publishes.contains(tx) && price <= spendable {
            Charge::Burned(price)
        } else {
            Charge::Apart(price.min(spendable))
        };
        if charge.amount() > 0 {
            store
                .apply_movement(payer.vault, *tx, 0, charge.amount())
                .expect("a charge within what the floor leaves is one the floor admits");
        }
        charges.insert(*tx, charge);
    }
    charges
}

/// What this shard, as a transaction's fee payer, charges it.
#[derive(Clone, Copy)]
pub struct PayerFee {
    pub(crate) vault: SubstateKey,
    /// The signed ceiling: the hold the price has to fit, and the most
    /// any burn reaches.
    pub(crate) max_fee: u128,
    /// The declared price — what every attempt owes, whatever refused
    /// it, derived from signed content and the committing block's table
    /// before anything runs.
    pub(crate) price: u128,
    /// Whether a tick can abort this transaction after it executed —
    /// true for a cross-shard leg, which is the one shape whose effects
    /// are discarded after the engine completed them.
    pub(crate) abortable: bool,
}

impl PayerFee {
    /// What the payer's vault actually loses, which is the one figure
    /// any receipt may name.
    ///
    /// The price and the ceiling meet on the commit path, where
    /// admission already refused a transaction priced past what it
    /// signed for — but they meet at the table admission read, and a
    /// block anchored the other side of a fold prices under its own. So
    /// the ceiling binds here, and it binds in one place: a charge
    /// reported above what was burned would claim emission weight for
    /// quanta nobody paid.
    #[must_use]
    pub(crate) const fn burned(&self) -> u128 {
        if self.price < self.max_fee {
            self.price
        } else {
            self.max_fee
        }
    }
}

/// Whether an attempt's charge settles through a receipt of its own
/// rather than inside its writes.
///
/// One price whatever the outcome. A completed run burns it inside the
/// writes the receipt carries; only where a tick can still discard those
/// writes is the same figure also built apart, so the abort that
/// discards them settles it. Every attempt that applied no effects has
/// no writes to carry the burn, and settles it apart — a lost race, a
/// declared refusal, the sender's own defect and the kernel's alike:
/// the network routed, provisioned and ran a batch for it either way,
/// and a schedule that discounted any of them is one an adversary picks
/// the cheap entry from.
const fn settled_apart(outcome: &Outcome, payer: PayerFee) -> bool {
    match outcome {
        Outcome::Completed { .. } => payer.abortable,
        Outcome::UserError { .. }
        | Outcome::Infeasible { .. }
        | Outcome::ConstraintUnmet { .. }
        | Outcome::NullifierSpent { .. }
        | Outcome::EscrowAlreadyClaimed { .. }
        | Outcome::EscrowAlreadyIssued { .. }
        | Outcome::ConditionUnmet { .. }
        | Outcome::BaselineDiscarded { .. }
        | Outcome::Declined { .. }
        | Outcome::ProtocolError { .. } => true,
    }
}

/// The fold's mutable state across a batch: the kernel-mirror map a
/// later transaction reads what an earlier one left through, and the
/// differential's source.
///
/// Fees do not appear here. A burn is a debit, a debit is a movement,
/// and a movement needs no baseline — so nothing has to track what
/// siblings have already burned in order to keep a later absolute from
/// reverting it.
struct FoldState {
    running: BTreeMap<SubstateKey, Option<Vec<u8>>>,
    /// The entry mirror beside the cells: exclusive writes with no
    /// movement form, folded only so the differential can hold over
    /// them too.
    running_entries: BTreeMap<EntryKey, Option<Vec<u8>>>,
}

/// Build the receipt an abort of this transaction settles: the payer's
/// vault debited by the declared price, and nothing else.
///
/// A debit rather than a value, so it neither reads nor depends on what
/// the vault held when the transaction ran. An abort discards this
/// transaction's own effects, and the price lands on whatever its
/// siblings left — which is what a movement means and what an absolute
/// computed here could not have expressed without re-deriving their
/// burns.
///
/// Shared with the abandonment path, which settles the same price for a
/// transaction that never reached the engine: both are the same charge
/// on the same vault, and two builders would be two receipt hashes for
/// one verdict.
///
/// The one place an unjudged charge is built, and the only reason it is
/// safe to build one. A judged debit past what the vault holds halts the
/// shard rather than settle a balance nothing produced; an unjudged one
/// has no such backstop and takes what is there, so the vault named here
/// and the amount carried with it are the whole of what separates a fee
/// floor from a drain nobody priced.
///
/// What bounds the take is that the charge never exceeds the fee hold it
/// ends: the price under the signed ceiling, for an abandonment and for
/// everything [`PayerFee::burned`] caps. Every debit of the vault is
/// judged under the holds standing on it, this member's among them from
/// the block that committed it, so the charge reaches only value its own
/// hold kept and leaves every sibling's judged debit feasible when it
/// settles.
///
/// Beside the charge ride the member's `Never` answers, one absolute
/// cell write per refusable crossing it consumed and was refused for,
/// under one writes root. `None` where both are empty: a member with
/// nothing to settle apart names no receipt.
#[must_use]
pub fn build_refusal_receipt(
    local_shard: ShardId,
    shard_trie: &ShardTrie,
    tx_hash: TxHash,
    charge: Option<(SubstateKey, Movement)>,
    nevers: &[(SubstateKey, Vec<u8>)],
) -> Option<ConsensusReceipt> {
    if charge.is_none() && nevers.is_empty() {
        return None;
    }
    let amount = charge.as_ref().map_or(0, |(_, movement)| {
        movement.debit.saturating_add(movement.unjudged_debit)
    });
    let mut writes = StateWrites {
        cells: nevers
            .iter()
            .map(|(key, value)| (*key, Some(value.clone())))
            .collect(),
        movements: BTreeMap::new(),
        entries: BTreeMap::new(),
    };
    if let Some((vault, movement)) = charge {
        writes.movements.insert(vault, movement);
        release_fee_hold(&mut writes, vault, tx_hash);
    }
    let receipt_hash = GlobalReceipt::new(
        true,
        EventRoot::ZERO,
        BeaconWitnessRoot::ZERO,
        writes_root(&writes),
        EffectsDigest::ZERO,
    )
    .receipt_hash();
    let cached = CachedOutput::succeeded(
        writes,
        receipt_hash,
        None,
        vm_metadata(amount, None),
        Vec::new(),
        Vec::new(),
    );
    Some(project_to_shard(&cached, tx_hash, local_shard, shard_trie).consensus)
}

/// The `Never` answers a refused member writes: one per refusable
/// crossing it consumed whose decline cell this shard holds, where
/// neither the claim nor the decline holds this transaction's answer
/// already, read off `cell` — the batch's running fold over the tick's
/// baseline.
///
/// A `Never` is skipped where this transaction's answer stands, never
/// trapped: the member is the one writer of its own answers and no tick
/// runs it twice, so its answer found there is the answer already
/// given. The keys name the edge and no transaction, so either may hold
/// what another transaction answered a record that stood at this edge
/// before: that answers nothing here, and the `Never` is written, over
/// it where it stands at the decline key.
fn never_answers(
    input: Option<&TickTxInput<'_>>,
    tx_hash: TxHash,
    local_shard: ShardId,
    locality: &OwnerSet,
    cell: impl Fn(SubstateKey) -> Option<Vec<u8>>,
) -> Vec<(SubstateKey, Vec<u8>)> {
    let Some(TickTxInput {
        member,
        transaction,
        ..
    }) = input
    else {
        return Vec::new();
    };
    let validity_end_ms = transaction
        .validity_range()
        .end_timestamp_exclusive
        .as_millis();
    let answered = |id: CrossingId, answered: Answered| {
        cell(id.answer_key(&ProtocolHasher, answered))
            .is_some_and(|value| id.answered_by(tx_hash, validity_end_ms, answered, &value))
    };
    member
        .classified()
        .refusable_consumed(local_shard)
        .filter(|edge| {
            let id = edge.crossing.id;
            !answered(id, Answered::Taken) && !answered(id, Answered::Never)
        })
        .map(|edge| never_answer(tx_hash, validity_end_ms, edge))
        .filter(|(never, _)| locality.covers(never.owner))
        .collect()
}

/// One publish of the batch.
#[derive(Clone, Copy)]
struct Publish<'a> {
    tx: TxHash,
    publisher: PrincipalAddr,
    artifact: &'a [u8],
    /// Whether a counterpart's verdict can still discard it.
    abortable: bool,
}

/// Settle one publish: the artifact lands in the cell its content
/// address names, and the fee burns from the publisher's vault.
///
/// The two sit under different owners, so a publish reaches two shards
/// and each writes the half its locality covers.
///
/// A publish never enters the kernel — there is no manifest to run — so
/// it settles outside the batch fold rather than inside it. Its package
/// cell is content-addressed and exclusive, so nothing else in the batch
/// writes it. Its burn is `charge`, which the charge pass judged over
/// the kernel's applied store as it judges every price no session
/// burned: where the vault covers the price under every other hold, a
/// judged debit in these writes; where it does not, `refusal` says so
/// and the publish settles as every refused member does.
///
/// `refusal` is why the publish applies nothing, where it does not:
/// admission reached its verdict on the artifact from these same bytes,
/// so a refused artifact means the transaction bypassed admission — the
/// same condition `prepare` treats as a deterministic failure — and a
/// price the vault cannot cover is a publish that did not pay.
fn assemble_published_tx(
    ctx: &TickBatchContext<'_>,
    publish: Publish<'_>,
    refusal: Option<&str>,
    charge: Option<(PayerFee, Charge)>,
    locality: &OwnerSet,
) -> ExecutedTx {
    let Publish {
        tx: tx_hash,
        publisher,
        artifact,
        abortable,
    } = publish;
    // The declaration's price at the block's table, like any other
    // transaction: a publish's artifact is bytes written and retained,
    // and its two point writes are writes.
    let charged = charge.map_or(0, |(_, charge)| charge.amount());

    let cached = refusal.map_or_else(
        || {
            let mut writes = StateWrites::default();
            let package = package_hash(&ProtocolHasher, artifact);
            let cell = package_key(package);
            // The artifact alone, whichever shard holds its cell, and
            // never the burn: that much every shard of the member runs.
            let effects = abortable.then(|| {
                let whole = StateWrites {
                    cells: BTreeMap::from([(cell, Some(artifact.to_vec()))]),
                    ..StateWrites::default()
                };
                effects_digest(&whole, EventRoot::ZERO)
            });
            if locality.covers(cell.owner) {
                // Content-addressed, so republishing the same artifact
                // writes the same bytes to the same cell: idempotent by
                // construction rather than by a first-write-wins branch.
                writes.cells.insert(cell, Some(artifact.to_vec()));
            }
            if let Some((PayerFee { vault, .. }, Charge::Burned(burned))) = charge
                && locality.covers(publisher.address())
            {
                release_fee_hold(&mut writes, vault, tx_hash);
                // A movement, like every other debit, so the burn
                // composes with whatever else reaches the vault when
                // the block settles.
                if burned > 0 {
                    writes
                        .movements
                        .insert(vault, Movement::debit(*PROTOCOL_RESOURCE, burned));
                }
            }
            let receipt_hash = GlobalReceipt::new(
                true,
                EventRoot::ZERO,
                BeaconWitnessRoot::ZERO,
                writes_root(&writes),
                effects.unwrap_or(EffectsDigest::ZERO),
            )
            .receipt_hash();
            // The publish raises no beacon fact. Nothing global answers
            // for a package: its key follows from its content address,
            // which is the whole of what a node needs to ask for it.
            CachedOutput::succeeded(
                writes,
                receipt_hash,
                effects,
                vm_metadata(charged, None),
                Vec::new(),
                Vec::new(),
            )
        },
        |reason| CachedOutput::failed(vm_metadata(charged, Some(reason.to_owned()))),
    );
    // A refused publish settles the price an accepted one burns — the
    // artifact's length under the signed ceiling — as every refusal
    // does, down to what the floor left of it: the shard judged these
    // bytes before it knew the answer, and what it charges is what it
    // declared, never the ceiling.
    //
    // An accepted publish a counterpart can still refuse names the burn
    // its writes carry a second time, apart and judged as it was there:
    // the refusal discards those writes, and this is what settles the
    // price and ends the hold in their place.
    let apart = match (refusal, charge) {
        (Some(_), Some((payer, charge))) => Some((
            payer.vault,
            Movement::unjudged(*PROTOCOL_RESOURCE, charge.amount()),
        )),
        (None, Some((payer, Charge::Burned(burned)))) if payer.abortable => {
            Some((payer.vault, Movement::debit(*PROTOCOL_RESOURCE, burned)))
        }
        _ => None,
    };
    let refusal_receipt =
        build_refusal_receipt(ctx.local_shard, ctx.shard_trie, tx_hash, apart, &[]);

    let mut executed = project_to_shard(&cached, tx_hash, ctx.local_shard, ctx.shard_trie);
    executed.refusal_receipt = refusal_receipt;
    executed
}

/// Declare the record and claim cells a divided member's plan writes,
/// as exclusive writes appended to its declaration.
///
/// Routing declares nothing here: the cells are written only by a
/// divided execution, and which member writes which is a placement
/// fact routing cannot know. The kernel refuses a plan whose cells are
/// undeclared — the declaration is what puts every writer of one cell
/// in one conflict group — so the engine declares them where it plans.
/// Appended, never interleaved, so every capability rep admission fixed
/// keeps its position.
///
/// # Errors
///
/// A cell the declaration already carries under another mode: the
/// member is refused rather than run against a contradiction.
fn declare_crossing_cells(declaration: &mut Declaration, legs: &LegPlan) -> Result<(), String> {
    // The decline cells beside the claims: the member's refusal receipt
    // writes them, so the declaration is honest, the baseline pre-read
    // holds them, and every writer of one sits in one conflict group.
    for key in legs.records().chain(legs.claims()).chain(legs.nevers()) {
        let effect = Effect {
            target: EffectTarget::Point(key),
            mode: Mode::Write { moves: Moves::Both },
        };
        declare(declaration, effect, None).map_err(|conflict| {
            format!("crossing cell {key:?} contradicts the declaration: {conflict}")
        })?;
    }
    Ok(())
}

/// Append one access to both views of a declaration: the folded set and
/// the clause order, at the end, so every position already fixed keeps
/// its rep. `holds` is what the cell denominates, which a movement on it
/// cannot do without.
fn declare(
    declaration: &mut Declaration,
    effect: Effect,
    holds: Option<ResourceAddr>,
) -> Result<(), String> {
    // A cell the host reaches by key — a payer's vault, a signer's
    // stored rule — names no slot a declaration could bound, so it is
    // bounded at the cap.
    declaration
        .set
        .insert_at_cap(effect)
        .map_err(|conflict| conflict.to_string())?;
    declaration.ordered.push(DeclaredAccess {
        effect,
        holds,
        reach: None,
        clause: None,
    });
    Ok(())
}

/// What every transaction in a batch assembles against: the pre-read
/// baseline its receipts fold over, the share of the world this shard
/// applies, and the code a pool must be running, which the witness lift
/// asks to decide whether an emitted event is a beacon fact.
#[derive(Clone, Copy)]
struct BatchInputs<'a> {
    base: &'a TickBaseline,
    locality: &'a OwnerSet,
    staking_package: PackageHash,
}

/// What one member assembles from: the receipt the kernel ran it to, its
/// payer and the charge set apart for it, the input its block froze, what
/// its own counterparts provisioned it, and the instance records it
/// resolves through — its batch's and the ones its envelope carries.
#[derive(Clone, Copy)]
struct MemberInputs<'a> {
    vm_tx: TxHash,
    receipt: &'a Receipt,
    fee: Option<(PayerFee, u128)>,
    input: Option<&'a TickTxInput<'a>>,
    own_reads: Option<&'a MemberReads>,
    instances: &'a dyn ChainRecords,
    presented: &'a [InstanceMeta],
}

/// What one member reads that no batch-mate does: what it was provisioned
/// and the part its own shard serves it, and the keys of that part, which
/// it reads from there and nowhere else.
#[derive(Debug)]
struct MemberReads {
    store: Arc<MemoryStore>,
    served: Arc<ServedReads>,
}

/// The committed value `key` holds as one member reads it: the part alone
/// on a key its own shard serves it, an absence included, and otherwise
/// the batch's baseline, and beneath it what that member alone was
/// provisioned.
fn member_cell(
    base: &TickBaseline,
    own_reads: Option<&MemberReads>,
    key: SubstateKey,
) -> Option<Vec<u8>> {
    if let Some(own) = own_reads
        && own.served.cells.contains(&key)
    {
        return own.store.cell(key);
    }
    base.cells
        .get(&key)
        .cloned()
        .or_else(|| own_reads.and_then(|own| own.store.cell(key)))
}

/// What a member that ran is charged, and the charge its refusal receipt
/// settles apart where it settles one.
///
/// A completed run burned its price in the kernel, judged against the
/// vault with its own hold ended, so the figure is the price and a charge
/// built beside it for an abort is judged too. Every other outcome
/// settles the figure carried beside the payer: what the charge pass
/// found the floor to leave of the price once the member's hold ended.
fn member_charge(
    fee: Option<(PayerFee, u128)>,
    outcome: &Outcome,
) -> (u128, Option<(SubstateKey, Movement)>) {
    let completed = matches!(outcome, Outcome::Completed { .. });
    let charged = fee.map_or(
        0,
        |(payer, apart)| {
            if completed { payer.burned() } else { apart }
        },
    );
    let charge = fee
        .map(|(payer, _)| payer)
        .filter(|payer| settled_apart(outcome, *payer))
        .map(|payer| {
            let charge = if completed {
                Movement::debit(*PROTOCOL_RESOURCE, charged)
            } else {
                Movement::unjudged(*PROTOCOL_RESOURCE, charged)
            };
            (payer.vault, charge)
        });
    (charged, charge)
}

fn assemble_executed_tx(
    ctx: &TickBatchContext<'_>,
    inputs: BatchInputs<'_>,
    fold: &mut FoldState,
    member_inputs: MemberInputs<'_>,
) -> ExecutedTx {
    let MemberInputs {
        vm_tx: tx_hash,
        receipt,
        fee,
        input,
        own_reads,
        instances,
        presented,
    } = member_inputs;
    let member = input.map(|input| &input.member);
    let BatchInputs { base, locality, .. } = inputs;
    let completed = matches!(receipt.outcome, Outcome::Completed { .. });
    let (charged, charge) = member_charge(fee, &receipt.outcome);
    // The member's answers where it can still be refused: here, by
    // its own outcome, or later, by a counterpart's verdict. A
    // multi-core consumer that completed here, holds no vault and is
    // refused by a sibling still names a receipt carrying its `Never`.
    let nevers = if completed && !member.is_some_and(Member::abortable) {
        Vec::new()
    } else {
        never_answers(input, tx_hash, ctx.local_shard, locality, |key| {
            fold.running
                .get(&key)
                .map_or_else(|| member_cell(base, own_reads, key), Clone::clone)
        })
    };
    let refusal_receipt =
        build_refusal_receipt(ctx.local_shard, ctx.shard_trie, tx_hash, charge, &nevers);
    let cached = if completed {
        // What the receipt carries: exclusive writes as absolutes,
        // everything commutative as the movement it was. Unresolved,
        // because the state this lands on is not the state it ran
        // against — that is settlement's question.
        let mut writes = receipt
            .delta
            .project(locality)
            .expect("kernel-produced movements compose");
        compose_burn(&mut writes, receipt.burn);
        // The charging member's run burns the price inside these writes,
        // or apart in its refusal receipt; the hold ends in whichever of
        // the two its finalization settles.
        if let Some((payer, _)) = fee {
            release_fee_hold(&mut writes, payer.vault, tx_hash);
        }
        // The batch's own fold is the one reader whose baseline really is
        // this one: a later transaction in this tick must see what an
        // earlier one left. It mirrors the kernel's store, so it takes
        // the resolved form.
        let resolved = writes
            .resolve(&mut |key| {
                fold.running
                    .get(&key)
                    .map_or_else(|| base.cells.get(&key).cloned(), Clone::clone)
            })
            .expect("the kernel judged every movement it recorded against this baseline");
        for (key, change) in resolved.cells() {
            fold.running.insert(*key, change.clone());
        }
        for (key, change) in resolved.entries() {
            fold.running_entries.insert(*key, change.clone());
        }
        // The kernel's record is the wire record — one shared type, so
        // there is nothing to convert.
        let events: Vec<Event> = receipt.events.clone();
        // The beacon facts among them. Read here rather than at
        // projection because this is where the world that decides is in
        // reach, and read from the whole union rather than one shard's
        // share so every participant derives the same set — which shard
        // keeps a fact is settled once, at projection, by the same rule
        // that settles which shard keeps the event. An emitter resolves
        // through the chain first and then through the records the
        // envelope carries, each keyed at the address its contents
        // derive: every participant holds the same envelope, so a pool
        // this transaction seals speaks here and is read alike
        // everywhere.
        let records = Composed::new(instances, presented, &ProtocolHasher);
        let witnesses: Vec<(Address, BeaconWitnessEvent)> = events
            .iter()
            .filter_map(|event| {
                witness_from_event(event, &records, inputs.staking_package)
                    .map(|witness| (event.emitter, witness))
            })
            .collect();
        // The root covers the events this shard's own emitters produced
        // — what its receipt stores — and not a union: a participant
        // running only its own legs cannot assemble one, and two
        // participants attesting different unions under one signed root
        // would contradict each other. What the shards of a shared member
        // hold each other to is the digest below, over the whole run.
        let event_hashes: Vec<Hash> = events
            .iter()
            .filter(|event| locality.covers(event.emitter))
            .map(EventExt::hash)
            .collect();
        let effects = member
            .is_some_and(Member::abortable)
            .then(|| whole_effects(receipt));
        // The facts the receipt carries are the ones whose emitters this
        // shard owns, whatever the batch's locality: the projection keeps
        // a fact by its emitter's owner alone, and the root binds what it
        // keeps so no fact joins or leaves the receipt under one hash.
        let owned = owned_by(ctx.local_shard, ctx.shard_trie);
        let receipt_hash = GlobalReceipt::new(
            true,
            EventRoot::from_raw(compute_merkle_root(&event_hashes)),
            witness_root(
                witnesses
                    .iter()
                    .filter(|(emitter, _)| owned(*emitter))
                    .map(|(_, witness)| witness),
            ),
            writes_root(&writes),
            effects.unwrap_or(EffectsDigest::ZERO),
        )
        .receipt_hash();
        CachedOutput::succeeded(
            writes,
            receipt_hash,
            effects,
            vm_metadata(charged, None),
            events,
            witnesses,
        )
    } else {
        CachedOutput::failed(vm_metadata(charged, Some(abort_reason(&receipt.outcome))))
    };
    let mut executed = project_to_shard(&cached, tx_hash, ctx.local_shard, ctx.shard_trie);
    executed.refusal_receipt = refusal_receipt;
    executed
}

/// Refuse each yes of the batch past the staged caps.
///
/// Walks the batch's receipts in its fold order. A member `abortable`
/// holds, one a sibling's verdict can discard, whose receipt succeeded
/// is a yes its row will
/// stage: one past [`MAX_STAGED_RECEIPT_BYTES`], or one that would take
/// the batch's yes bytes past [`MAX_TICK_STAGED_BYTES`], fails instead,
/// keeping the refusal receipt built beside it, so it settles exactly as
/// a refused member does. Its batch-mates read its debits and never its
/// credits, which is the view a sibling's refusal of it leaves too.
///
/// Under a sound [`staged_yes_bound`](hyperscale_types::staged_yes_bound) and a manifest within its staged
/// budget, nothing is refused here.
fn cap_staged_yes(folded: &mut BTreeMap<TxHash, ExecutedTx>, abortable: impl Fn(&TxHash) -> bool) {
    let mut staged = 0u64;
    for (vm_tx, executed) in folded.iter_mut() {
        if !abortable(vm_tx) || !executed.is_success() {
            continue;
        }
        let bytes = staged_yes_bytes(&executed.consensus);
        let total = staged.saturating_add(bytes);
        if bytes > MAX_STAGED_RECEIPT_BYTES || total > MAX_TICK_STAGED_BYTES {
            tracing::error!(
                tx = ?vm_tx,
                bytes,
                staged,
                "a yes receipt passes the staged caps; refusing it"
            );
            executed.consensus = ConsensusReceipt::Failed;
            executed.metadata = ExecutionMetadata::new(
                executed.metadata.fee_summary.clone(),
                Vec::new(),
                Some(format!(
                    "its yes receipt stages {bytes} bytes, past the staged caps"
                )),
            );
            continue;
        }
        staged = total;
    }
}

/// One member of a tick's batch: what its receipt is keyed by, and the
/// body it runs over.
struct BatchMember {
    tx_hash: TxHash,
    body: Verified<Transaction>,
    /// The table this member's committing block anchored to: what its
    /// fee is weighed at, carried per member because that is the grain
    /// the anchor has.
    prices: PriceTable,
}

impl Executor {
    /// The batch pipeline every dispatch arm shares: derive, pre-read the
    /// local baseline, layer provisioned remote cells, execute under the
    /// shard's locality, fold local keys, and project. Each input says
    /// what kind of member its transaction is; a batch in which no member
    /// declares a cell beyond this shard executes under total locality.
    #[allow(clippy::too_many_lines)] // one pipeline, stages in order
    fn run_batch(
        &self,
        ctx: &TickBatchContext<'_>,
        snapshot: &(dyn Substates + Sync),
        inputs: &[TickTxInput<'_>],
    ) -> Result<Vec<ExecutedTx>, CodeUnavailable> {
        if inputs.is_empty() {
            return Ok(Vec::new());
        }
        let members: Vec<BatchMember> = inputs
            .iter()
            .map(|i| BatchMember {
                tx_hash: i.tx_hash,
                body: i.transaction.clone(),
                prices: i.prices,
            })
            .collect();
        // What each member reads beneath the batch's baseline: its own
        // provisions and no batch-mate's. Two members can hold one remote
        // cell at different heights of its source, and the shards running
        // a transaction batch it with different neighbours, so a value
        // read off a neighbour's list would split its receipt. The part
        // its own shard serves it sits there too, and reads over the
        // baseline, so a key absent from that part reads absent here as
        // it does on every counterpart, provisions or none.
        let own_reads: BTreeMap<TxHash, MemberReads> = inputs
            .iter()
            .filter(|i| !i.provisions.is_empty() || i.served_part.is_some())
            .map(|i| {
                let (mut reads, entries) = provisioned_reads(i.provisions);
                if entries > 0 && i.member.role() == Role::Core {
                    record_provision_range_entries_consumed(ctx.local_shard.inner(), entries);
                }
                if let Some(part) = i.served_part {
                    absorb_part(&mut reads, &part.entries);
                }
                let reads = MemberReads {
                    store: Arc::new(reads),
                    served: i
                        .served_part
                        .map_or_else(Arc::default, |part| Arc::clone(&part.served)),
                };
                (i.tx_hash, reads)
            })
            .collect();
        let mut drawn = BTreeMap::new();
        let env_by_tx: BTreeMap<TxHash, EnvInputs> = inputs
            .iter()
            .map(|i| (i.tx_hash, env_at(ctx, &mut drawn, i.clock)))
            .collect();
        let shapes: BTreeMap<TxHash, &TickTxInput<'_>> =
            inputs.iter().map(|i| (i.tx_hash, i)).collect();
        // A member declaring remote cells has its writes filtered to the
        // local subtree; a batch of genuinely single-shard members owns
        // every key it declares and total locality is the same filter
        // without the trie walk.
        let locality = if inputs.iter().all(|i| !i.member.reaches_beyond()) {
            OwnerSet::whole()
        } else {
            routed_to(ctx.shard_trie, ctx.local_shard)
        };
        // Publishes carry no manifest, so they never reach the kernel;
        // they settle in their own pass below.
        let publishes: BTreeMap<TxHash, (PrincipalAddr, Vec<u8>)> = members
            .iter()
            .filter_map(|member| {
                let tx = &member.body;
                let artifact = tx.body().artifact.as_ref()?;
                Some((member.tx_hash, (tx.terms().fee_payer, artifact.to_vec())))
            })
            .collect();

        // What each member resolves its targets through: genesis, this
        // shard's committed leaves, and the ones its own counterparts
        // provisioned it. Every replica of the shard builds the same
        // three for a member from the same block, and every shard running
        // the transaction reads the same provisioned leaves whatever its
        // batch-mates, which is what makes a refusal below a property of
        // the transaction rather than of the node or of its neighbours.
        let packages = self.world.cache.load();
        let seeded = self.world.instances.seeded();
        let records: BTreeMap<TxHash, MemberRecords<'_>> = inputs
            .iter()
            .map(|input| {
                let records = MemberRecords::new(
                    Arc::clone(&packages),
                    Arc::clone(&seeded),
                    input.provisions,
                    snapshot,
                );
                (input.tx_hash, records)
            })
            .collect();

        // Derive every transaction; refusals become deterministic
        // failures without touching the batch.
        let mut prepared: BTreeMap<TxHash, PreparedTx> = BTreeMap::new();
        let mut refused: BTreeMap<TxHash, String> = BTreeMap::new();
        for input in inputs {
            let vm_tx = input.tx_hash;
            if publishes.contains_key(&vm_tx) {
                continue;
            }
            let records = records
                .get(&vm_tx)
                .expect("every input resolves through its own records");
            // What this shard runs of the member: the whole shape unless
            // the coordinator froze a division, and then the legs its
            // placement gives it. A plan that cannot be built is a
            // deterministic refusal like a derivation that cannot be —
            // every replica reads the same legs and the same arrivals.
            let planned = Self::prepare_shape(
                input.transaction,
                records,
                &self.world.cache,
                &input.member,
                input.arrivals,
            );
            match planned {
                Ok(entry) => {
                    record_transaction_executed();
                    prepared.insert(vm_tx, entry);
                }
                Err(reason) => {
                    tracing::warn!(tx_hash = ?vm_tx, reason, "VM transaction refused at execution");
                    refused.insert(vm_tx, reason);
                }
            }
        }

        // The committed baseline every member shares: the locally owned
        // declared content from the tick snapshot. Provisioned content is
        // each member's own, beneath it.
        let mut base = TickBaseline {
            points: ctx.points.as_ref().map(|points| {
                (
                    routed_to(ctx.shard_trie, ctx.local_shard),
                    Arc::clone(points),
                )
            }),
            ..TickBaseline::default()
        };
        for entry in prepared.values() {
            materialize_declared(snapshot, &entry.declaration.set, &locality, &mut base);
        }
        // A manifest needn't touch its payer's own vault — a publish
        // declares no effects at all, and a call can spend entirely from
        // other parties' cells. The burn re-derives its debit from this
        // baseline, so every collectible payer's vault joins it: an
        // absent baseline value is indistinguishable from an absent
        // cell, and the burn would silently apply to nothing.
        //
        // Collectible means the vault routes to the executing shard by
        // the trie, not by tick locality: a local-only tick's
        // `OwnerSet::whole()` claims every owner, and reading another
        // shard's cell out of this shard's store is nondeterministic —
        // members disagree on what they hold outside their own subtree,
        // and a split baseline splits the tick's receipt roots.
        for tx in members.iter().map(|member| &member.body) {
            let key = tx.fee_vault();
            if ctx.shard_trie.shard_for_prefix(key.owner) == ctx.local_shard
                && let Some(value) = snapshot.cell(key)
            {
                base.cells.insert(key, value);
            }
        }
        // The fee payers this shard settles: a completed transaction
        // burns its attested actual from its payer's vault, on the
        // payer's shard only.
        // Trie-routed, like the pre-read: a tick's own locality cannot
        // decide fee ownership, because the single-shard arm's
        // `OwnerSet::whole()` would claim payers whose vaults live on
        // shards this tick never engaged.
        let fee_by_tx: BTreeMap<TxHash, PayerFee> = members
            .iter()
            .filter_map(|member| {
                let tx = &member.body;
                let vault = tx.fee_vault();
                if ctx.shard_trie.shard_for_prefix(vault.owner) != ctx.local_shard {
                    return None;
                }
                let shape = &shapes.get(&tx.hash())?.member;
                Some((
                    tx.hash(),
                    PayerFee {
                        vault,
                        max_fee: tx.terms().max_fee,
                        price: tx.price(&member.prices),
                        abortable: shape.abortable(),
                    },
                ))
            })
            .collect();

        // Trie-routed like the pre-read above, and for the same reason:
        // a declaration spans every participating shard, so the holds it
        // implies do too, and a shard that reported one against a cell it
        // holds none of would judge a reservation as exceeding a balance
        // it cannot see. A tick's own locality cannot decide this — the
        // single-shard arm's `OwnerSet::whole()` claims every owner.
        let here =
            |key: &SubstateKey| ctx.shard_trie.shard_for_prefix(key.owner) == ctx.local_shard;
        base.holds = ctx
            .holds
            .iter()
            .filter(|(key, _)| here(key))
            .map(|(key, held)| (*key, held.clone()))
            .collect();
        // The fee holds standing on every protocol vault the batch can
        // debit: each payer's, and each one a member declares. Named by
        // key and not by what the baseline holds, because a vault at
        // zero has no cell and still has its holds, and a credit landing
        // on it in this batch is spoken for by them.
        let floored: BTreeSet<SubstateKey> = members
            .iter()
            .map(|member| member.body.fee_vault())
            .chain(
                prepared
                    .values()
                    .flat_map(|entry| entry.declaration.set.iter())
                    .filter_map(|effect| match effect.target {
                        EffectTarget::Point(key) if is_protocol_vault(&key) => Some(key),
                        _ => None,
                    }),
            )
            .filter(here)
            .collect();
        for vault in floored {
            let standing = ctx.fee_holds.standing(vault);
            // A member's own hold stands under its body apart from the
            // rest, so its burn can end it. Where nothing can abort the
            // member the hold is its price: the burn is fixed before
            // the body runs, so the body may spend the slack between
            // price and ceiling. Where a counterpart can, the body's
            // debits stay hidden until the verdict and the whole
            // ceiling stands under them.
            let mut named = 0u128;
            let mut holds = FeeHolds::default();
            for (tx, payer) in fee_by_tx.iter().filter(|(_, payer)| payer.vault == vault) {
                let ceiling = ctx.fee_holds.own(vault, *tx);
                if ceiling == 0 {
                    continue;
                }
                named = named.saturating_add(ceiling);
                let own = if payer.abortable {
                    ceiling
                } else {
                    payer.burned().min(ceiling)
                };
                holds.members.insert(*tx, own);
            }
            holds.rest = standing.checked_sub(named).unwrap_or_else(|| {
                panic!(
                    "BFT CRITICAL: the members of this batch hold {named} against {vault:?}, \
                     past the {standing} standing on it"
                )
            });
            if holds.total() > 0 {
                base.fee_holds.insert(vault, holds);
            }
        }
        let base = Arc::new(base);

        let batch: Vec<BatchTx> = prepared
            .iter()
            .map(|(vm_tx, entry)| {
                // Total: both dispatch arms build the map from the same
                // transactions the derivation ran over, and `prepared` is
                // a subset of those.
                let env = env_by_tx
                    .get(vm_tx)
                    .cloned()
                    .expect("every prepared transaction has an environment");
                let batched = batch_entry(
                    *vm_tx,
                    entry,
                    env,
                    locality.clone(),
                    fee_by_tx.get(vm_tx).map(|payer| FeeBurn {
                        vault: payer.vault,
                        resource: *PROTOCOL_RESOURCE,
                        amount: payer.burned(),
                    }),
                    // Every prepared transaction is an input, and one
                    // that were not would be withheld: nothing says a
                    // batch-mate cannot settle without it.
                    shapes
                        .get(vm_tx)
                        .is_none_or(|input| input.member.abortable()),
                );
                match own_reads.get(vm_tx) {
                    Some(own) => {
                        batched.with_served_reads(Arc::clone(&own.store), Arc::clone(&own.served))
                    }
                    None => batched,
                }
            })
            .collect();
        let walk = ManifestWalk {
            backend: &self.backend,
        };
        let outcome = match execute_batch(
            Arc::clone(&base) as Arc<dyn Baseline>,
            &batch,
            &walk,
            protocol_hash,
            self.mode,
        ) {
            Ok(outcome) => outcome,
            // The one machine-local refusal the kernel raises. Every
            // other batch error is a defect in what the committee
            // composed, which every replica reaches alike.
            Err(BatchError::Unavailable {
                tx,
                package,
                reason,
            }) => {
                return Err(CodeUnavailable {
                    tx,
                    package: Hash::from(package.0),
                    reason,
                });
            }
            Err(error) => panic!("BFT CRITICAL: VM batch execution failed: {error}"),
        };

        // A publish runs no session, so whether its artifact is admitted
        // is settled here, ahead of the pass that charges it.
        let publish_refusals: BTreeMap<TxHash, Option<String>> = publishes
            .iter()
            .map(|(vm_tx, (_, artifact))| {
                let refusal = admit_package(artifact).err().map(|error| error.to_string());
                (*vm_tx, refusal)
            })
            .collect();
        let admitted_publishes: BTreeSet<TxHash> = publish_refusals
            .iter()
            .filter(|(_, refusal)| refusal.is_none())
            .map(|(vm_tx, _)| *vm_tx)
            .collect();
        let unburned = charge_unburned(
            &outcome.store,
            &fee_by_tx,
            &outcome.receipts,
            &admitted_publishes,
        );
        let apart = |vm_tx: &TxHash| unburned.get(vm_tx).map_or(0, |charge| charge.amount());

        // Fold receipts into per-transaction absolute updates in
        // canonical order, then check the folded end state against the
        // kernel's own applied store — the fold must be the same fold.
        let mut fold = FoldState {
            running: BTreeMap::new(),
            running_entries: BTreeMap::new(),
        };
        let mut folded: BTreeMap<TxHash, ExecutedTx> = BTreeMap::new();
        for (vm_tx, receipt) in &outcome.receipts {
            // The kernel priced this shard's share under the same locality
            // the receipts were applied through, so nothing here re-derives
            // it — a workspace-side filter would be a second opinion on a
            // quantity that must agree.
            let executed = assemble_executed_tx(
                ctx,
                BatchInputs {
                    base: &base,
                    locality: &locality,
                    staking_package: self.world.staking_package,
                },
                &mut fold,
                MemberInputs {
                    vm_tx: *vm_tx,
                    receipt,
                    fee: fee_by_tx.get(vm_tx).map(|payer| (*payer, apart(vm_tx))),
                    input: shapes.get(vm_tx).copied(),
                    own_reads: own_reads.get(vm_tx),
                    instances: records
                        .get(vm_tx)
                        .expect("every receipt is an input's, which resolves through its own"),
                    presented: prepared
                        .get(vm_tx)
                        .map_or(&[][..], |entry| &entry.presented),
                },
            );
            folded.insert(*vm_tx, executed);
        }

        for (vm_tx, (publisher, artifact)) in &publishes {
            let charge = fee_by_tx
                .get(vm_tx)
                .zip(unburned.get(vm_tx))
                .map(|(payer, charge)| (*payer, *charge));
            // An admitted publish the pass could not burn whole is one
            // whose vault does not cover its price under the holds
            // standing on it.
            let unpaid = match charge {
                Some((payer, Charge::Apart(_))) => Some(abort_reason(&Outcome::Infeasible {
                    key: payer.vault,
                    amount: payer.burned(),
                })),
                _ => None,
            };
            let refusal = publish_refusals.get(vm_tx).cloned().flatten().or(unpaid);
            folded.insert(
                *vm_tx,
                assemble_published_tx(
                    ctx,
                    Publish {
                        tx: *vm_tx,
                        publisher: *publisher,
                        artifact,
                        abortable: shapes
                            .get(vm_tx)
                            .is_some_and(|input| input.member.abortable()),
                    },
                    refusal.as_deref(),
                    charge,
                    &locality,
                ),
            );
        }

        // The differential: every folded key's end value must equal the
        // kernel's applied store. A mismatch is a fold defect — receipts
        // silently diverging from kernel semantics — and must never ship.
        for (key, change) in &fold.running {
            let applied = Substates::cell(&outcome.store, *key);
            assert_eq!(
                change.as_ref(),
                applied.as_ref(),
                "BFT CRITICAL: VM fold diverged from the kernel apply at {key:?}"
            );
        }
        for (key, change) in &fold.running_entries {
            let applied = Substates::entries_in_range(
                &outcome.store,
                key.owner,
                key.collection,
                key.order,
                key.order,
                1,
            )
            .into_iter()
            .next()
            .map(|(_, value)| value);
            assert_eq!(
                change.as_ref(),
                applied.as_ref(),
                "BFT CRITICAL: VM fold diverged from the kernel apply at entry {key:?}"
            );
        }

        cap_staged_yes(&mut folded, |vm_tx| {
            shapes
                .get(vm_tx)
                .is_some_and(|input| input.member.abortable())
        });

        // Reassemble in input order.
        Ok(members
            .iter()
            .map(|member| {
                let vm_tx = member.tx_hash;
                folded.get(&vm_tx).cloned().unwrap_or_else(|| {
                    let reason = refused
                        .get(&vm_tx)
                        .cloned()
                        .unwrap_or_else(|| "missing batch receipt".to_string());
                    // Refused before the kernel ran — a plan that cannot
                    // be built, a derivation this node refuses — is an
                    // attempt like any other: the network committed it,
                    // reserved for it and dispatched it, and it settles
                    // the same price apart, as every attempt that applied
                    // no effects does: what the charge pass found the
                    // floor to leave of it.
                    let fee = fee_by_tx.get(&vm_tx).copied();
                    let charged = apart(&vm_tx);
                    let cached = CachedOutput::failed(vm_metadata(charged, Some(reason)));
                    let mut executed =
                        project_to_shard(&cached, vm_tx, ctx.local_shard, ctx.shard_trie);
                    // Refused before any of it ran, so nothing of this
                    // batch wrote its answers: the tick's baseline is
                    // what says whether one already stands.
                    let own = own_reads.get(&vm_tx);
                    let nevers = never_answers(
                        shapes.get(&vm_tx).copied(),
                        vm_tx,
                        ctx.local_shard,
                        &locality,
                        |key| member_cell(&base, own, key),
                    );
                    executed.refusal_receipt = build_refusal_receipt(
                        ctx.local_shard,
                        ctx.shard_trie,
                        vm_tx,
                        fee.map(|payer| {
                            (payer.vault, Movement::unjudged(*PROTOCOL_RESOURCE, charged))
                        }),
                        &nevers,
                    );
                    executed
                })
            })
            .collect())
    }
}

impl Executor {
    /// Execute `transactions` against `snapshot` and project each result
    /// to the context's local shard, all under the context's own
    /// environment.
    ///
    /// The unit is the batch: the whole of it goes to the
    /// deterministic-parallel executor at once, which returns one
    /// [`ExecutedTx`] per input transaction, in input order.
    ///
    /// `prices` is stated rather than read off the context, because a
    /// table is a fact about the block that committed a member and a
    /// context spans a tick: one reachable from here would be one a
    /// caller could take off its own head, which prices a transaction
    /// differently on two shards.
    ///
    /// # Errors
    ///
    /// [`CodeUnavailable`] where this node cannot run a package a member
    /// names. Nothing is attested, so the batch is the caller's to run
    /// again once it holds the code.
    pub fn execute_batch(
        &self,
        ctx: &TickBatchContext<'_>,
        prices: PriceTable,
        snapshot: &(dyn Substates + Sync),
        transactions: &[Verified<Transaction>],
    ) -> Result<Vec<ExecutedTx>, CodeUnavailable> {
        // Every member runs whole on its own shard and reads the
        // context's own clock: one block committed them all, so one
        // epoch seals them all — and one table prices them all.
        let inputs: Vec<TickTxInput<'_>> = transactions
            .iter()
            .map(|tx| TickTxInput {
                tx_hash: tx.hash(),
                transaction: tx,
                provisions: &[],
                clock: ctx.tick_ts,
                prices,
                member: Member::whole(ctx.local_shard),
                arrivals: &[],
                served_part: None,
            })
            .collect();
        self.run_batch(ctx, snapshot, &inputs)
    }

    /// Execute one tick's whole batch — single-shard members beside
    /// cross-shard legs — against `snapshot`. One [`ExecutedTx`] per
    /// input, in input order, projected to the context's local shard.
    ///
    /// Batch composition is consensus input: conflict grouping and the
    /// fold run over the whole tick, so every replica must compose the
    /// same members in the same tick.
    ///
    /// # Errors
    ///
    /// As [`Self::execute_batch`].
    pub fn execute_tick_batch(
        &self,
        ctx: &TickBatchContext<'_>,
        snapshot: &(dyn Substates + Sync),
        inputs: &[TickTxInput<'_>],
    ) -> Result<Vec<ExecutedTx>, CodeUnavailable> {
        self.run_batch(ctx, snapshot, inputs)
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::Capped;
    use hyperscale_types::{AddressClass, ExecutionOutcome, GlobalReceiptHash, LocalKey, Presence};
    use hyperscale_vm_kernel::{KernelHost, KernelSession};
    use hyperscale_vm_types::{AbortReason, encode_amount};

    use super::*;
    use crate::genesis::vault_key;

    /// A served key answers from the part alone, an absence included,
    /// over a baseline that holds it. Any other key reads the baseline,
    /// and the member's own reads only beneath it.
    #[test]
    fn member_cell_reads_a_served_key_from_the_part() {
        let cell = |seed: u8| SubstateKey {
            owner: Address::new([seed; 31], AddressClass::Component),
            local: LocalKey([seed; 16]),
        };
        let (served, absent, plain, own_only) = (cell(1), cell(2), cell(3), cell(4));
        let mut base = TickBaseline::default();
        for key in [served, absent, plain] {
            base.cells.insert(key, b"view".to_vec());
        }
        let mut store = MemoryStore::new();
        store.write(served, b"part".to_vec());
        store.write(plain, b"part".to_vec());
        store.write(own_only, b"part".to_vec());
        let own = MemberReads {
            store: Arc::new(store),
            served: Arc::new(ServedReads {
                cells: [served, absent].into_iter().collect(),
                ranges: Vec::new(),
            }),
        };
        let read = |key| member_cell(&base, Some(&own), key);
        assert_eq!(read(served), Some(b"part".to_vec()));
        assert_eq!(read(absent), None, "the part proved it absent");
        assert_eq!(read(plain), Some(b"view".to_vec()));
        assert_eq!(read(own_only), Some(b"part".to_vec()));
        assert_eq!(member_cell(&base, None, served), Some(b"view".to_vec()));
    }

    /// A success writing one cell `width` bytes wide, beside the refusal
    /// receipt its member settles if refused: its charge out of the
    /// payer's vault and its `Never` for a crossing it consumed.
    fn yes_of(seed: u8, width: usize) -> ExecutedTx {
        let mut writes = StateWrites::default();
        writes.cells.insert(
            SubstateKey {
                owner: Address::new([seed; 31], AddressClass::Component),
                local: LocalKey([seed; 16]),
            },
            Some(vec![seed; width]),
        );
        let mut refusal = StateWrites::default();
        refusal.movements.insert(
            vault_key(
                Address::new([0xAA; 31], AddressClass::Principal),
                *PROTOCOL_RESOURCE,
            ),
            Movement::unjudged(*PROTOCOL_RESOURCE, 7),
        );
        refusal.cells.insert(
            SubstateKey {
                owner: Address::new([0xBB; 31], AddressClass::Component),
                local: LocalKey([seed; 16]),
            },
            Some(b"never".to_vec()),
        );
        let mut executed = ExecutedTx::new(
            TxHash::from(Hash::from_bytes(&[seed; 32])),
            ConsensusReceipt::Succeeded {
                receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(&[seed, 1])),
                writes,
                beacon_witness_events: Capped::empty(),
                effects: None,
                events: Capped::empty(),
            },
            vm_metadata(7, None),
        );
        executed.refusal_receipt = Some(ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::from_raw(Hash::from_bytes(&[seed, 2])),
            writes: refusal,
            beacon_witness_events: Capped::empty(),
            effects: None,
            events: Capped::empty(),
        });
        executed
    }

    fn batch(members: impl IntoIterator<Item = ExecutedTx>) -> BTreeMap<TxHash, ExecutedTx> {
        members
            .into_iter()
            .map(|executed| (executed.tx_hash, executed))
            .collect()
    }

    /// A core member whose yes receipt passes the receipt cap fails
    /// instead of stating: it carries no effects, and the refusal
    /// receipt built beside it stands. A member no sibling's verdict can
    /// discard stages nothing, so the same receipt stands for it.
    #[test]
    fn an_oversized_core_receipt_is_refused_not_stated() {
        let width = usize::try_from(MAX_STAGED_RECEIPT_BYTES).expect("a width");
        let (core, alone) = (yes_of(1, width), yes_of(2, width));
        let core_hash = core.tx_hash;
        let mut folded = batch([core, alone.clone()]);
        cap_staged_yes(&mut folded, |tx| *tx == core_hash);

        let refused = &folded[&core_hash];
        assert!(!refused.is_success(), "the oversized yes is refused");
        assert!(matches!(
            refused.outcome().outcome(),
            ExecutionOutcome::Failed
        ));
        assert!(refused.refusal_receipt.is_some());
        assert_eq!(
            folded[&alone.tx_hash].consensus, alone.consensus,
            "a determined member is left as it ran"
        );
    }

    /// Yes receipts within the receipt cap state until the batch's yes
    /// bytes would pass the tick cap: the yes that would take it past is
    /// refused, and a later one that still fits states.
    #[test]
    fn a_tick_past_its_staged_bytes_refuses_its_later_yes() {
        let width = usize::try_from(MAX_STAGED_RECEIPT_BYTES / 2).expect("a width");
        let count =
            u8::try_from(MAX_TICK_STAGED_BYTES / (MAX_STAGED_RECEIPT_BYTES / 2)).expect("few");
        let mut members: Vec<ExecutedTx> = (1..=count).map(|seed| yes_of(seed, width)).collect();
        members.push(yes_of(count + 1, 0));
        let mut folded = batch(members);
        cap_staged_yes(&mut folded, |_| true);

        let staged: u64 = folded
            .values()
            .filter(|executed| executed.is_success())
            .map(|executed| staged_yes_bytes(&executed.consensus))
            .sum();
        assert!(staged <= MAX_TICK_STAGED_BYTES);
        let refused: Vec<&ExecutedTx> = folded
            .values()
            .filter(|executed| !executed.is_success())
            .collect();
        assert!(!refused.is_empty(), "the batch passes the tick cap");
        assert!(
            folded[&yes_of(count + 1, 0).tx_hash].is_success(),
            "a small yes the cap still leaves room for states",
        );
        let first_refused = refused[0].tx_hash;
        assert!(
            folded
                .range(..first_refused)
                .all(|(_, executed)| executed.is_success()),
            "every yes before the first refused one states",
        );
    }

    /// A core member refused at the cap settles as a refused member
    /// does: the refusal receipt it carries is the one built beside its
    /// run, burning its charge out of its payer's vault and writing its
    /// `Never`.
    #[test]
    fn an_over_cap_core_member_pays_its_charge_and_answers_never() {
        let width = usize::try_from(MAX_STAGED_RECEIPT_BYTES).expect("a width");
        let ran = yes_of(3, width);
        let built = ran.refusal_receipt.clone();
        let mut folded = batch([ran.clone()]);
        cap_staged_yes(&mut folded, |_| true);

        let refused = &folded[&ran.tx_hash];
        assert_eq!(refused.consensus, ConsensusReceipt::Failed);
        assert_eq!(
            refused.refusal_receipt, built,
            "the refusal receipt built beside it"
        );
        let refusal = refused
            .refusal_receipt
            .as_ref()
            .and_then(ConsensusReceipt::writes)
            .expect("a refusal receipt with writes");
        assert!(
            refusal
                .movements
                .values()
                .any(|movement| movement == &Movement::unjudged(*PROTOCOL_RESOURCE, 7)),
            "it burns the charge",
        );
        assert!(
            refusal
                .cells
                .values()
                .any(|value| value.as_deref() == Some(&b"never"[..])),
            "and answers never",
        );
    }

    /// Every bound the preparation fixed reaches the entry the kernel
    /// runs. A bound left behind here is one the kernel never applies,
    /// and a preview that left one behind would report a verdict the
    /// chain would not reach — which is why both callers map through
    /// one function and why this names the terms it must carry.
    #[test]
    fn the_batch_entry_carries_every_bound_the_preparation_fixed() {
        let prepared = PreparedTx {
            job: Job {
                calls: Vec::new(),
                legs: LegPlan::whole(0),
            },
            declaration: Declaration::default(),
            nullifiers: Vec::new(),
            gas_limits: vec![7, 9],
            event_bytes: vec![4_321],
            work: DeclaredWork::ZERO,
            judges: OwnerSet::whole(),
            presented: Arc::from(Vec::new()),
        };
        let entry = batch_entry(
            TxHash::from(Hash::from_bytes(b"entry")),
            &prepared,
            EnvInputs::unsealed(1_000),
            OwnerSet::whole(),
            Some(FeeBurn {
                vault: SubstateKey {
                    owner: Address::new([3; 31], AddressClass::Component),
                    local: LocalKey([4; 16]),
                },
                resource: *PROTOCOL_RESOURCE,
                amount: 11,
            }),
            true,
        );
        assert_eq!(entry.gas_limits, prepared.gas_limits);
        assert_eq!(entry.event_bytes, prepared.event_bytes);
        assert_eq!(entry.fee.as_ref().map(|burn| burn.amount), Some(11));
        assert!(entry.credits_withheld);
    }

    /// One price, whatever refused it. A completed run carries the burn
    /// in its own writes and settles it apart only where a tick can
    /// still discard them; every attempt that applied no effects — a
    /// lost race, a declared refusal, the sender's own defect, the
    /// kernel's — settles the same price apart, so no failure is the
    /// cheaper way to buy execution and no class is anyone's to place.
    #[test]
    fn every_attempt_settles_the_one_declared_price() {
        let payer = |abortable: bool| PayerFee {
            vault: SubstateKey {
                owner: Address::new([1; 31], AddressClass::Component),
                local: LocalKey([0; 16]),
            },
            max_fee: 1_000,
            price: 7,
            abortable,
        };
        let completed = Outcome::Completed {
            answers: Capped::empty(),
        };
        assert!(
            !settled_apart(&completed, payer(false)),
            "a completed run burns inside its writes"
        );
        assert!(
            settled_apart(&completed, payer(true)),
            "unless a tick can still discard them"
        );
        let leaf = EffectTarget::Point(SubstateKey {
            owner: Address::new([2; 31], AddressClass::Component),
            local: LocalKey([9; 16]),
        });
        for outcome in [
            Outcome::Declined { node: 0, code: 3 },
            Outcome::UserError {
                reason: AbortReason::Unreachable,
            },
            Outcome::ConditionUnmet {
                condition: UnmetCondition::Holds {
                    target: leaf,
                    required: Presence::Present,
                    node: None,
                },
            },
            Outcome::ConditionUnmet {
                condition: UnmetCondition::Satisfies { node: 0 },
            },
            Outcome::ProtocolError {
                reason: AbortReason::ValueNotConserved,
            },
        ] {
            assert!(
                settled_apart(&outcome, payer(false)),
                "{outcome:?} settles the price apart"
            );
        }
    }

    /// What the charge pass takes of a price of 40 for one member the
    /// kernel burned nothing for, over a baseline whose one cell is its
    /// payer's vault with a leg holding `reserved` of it.
    fn charge_over(vault_cell: Vec<u8>, reserved: u128) -> Charge {
        let tx = TxHash::from(Hash::from_bytes(b"refused"));
        let leg = TxHash::from(Hash::from_bytes(b"leg"));
        let vault = vault_key(PrincipalAddr::new([0x61; 31]), *PROTOCOL_RESOURCE);
        let base = TickBaseline {
            cells: BTreeMap::from([(vault, vault_cell)]),
            holds: BTreeMap::from([(vault, BTreeMap::from([(leg, reserved)]))]),
            ..Default::default()
        };
        let fees = BTreeMap::from([(
            tx,
            PayerFee {
                vault,
                max_fee: 100,
                price: 40,
                abortable: false,
            },
        )]);
        let charges = charge_unburned(
            &OverlayStore::new(Arc::new(base)),
            &fees,
            &BTreeMap::new(),
            &BTreeSet::new(),
        );
        charges[&tx]
    }

    #[test]
    fn a_charge_takes_the_price_the_floor_leaves() {
        let funded = encode_amount(1_000).to_vec();
        assert_eq!(charge_over(funded.clone(), 0), Charge::Apart(40));
        assert_eq!(charge_over(funded, 975), Charge::Apart(25));
    }

    /// Reservations past the cell leave no balance to judge a charge
    /// against: the one reading of the floor that charges nothing.
    #[test]
    fn a_charge_under_reservations_past_the_cell_takes_nothing() {
        assert_eq!(
            charge_over(encode_amount(10).to_vec(), 11),
            Charge::Apart(0)
        );
    }

    /// A vault that is not an amount is not a vault holding nothing: no
    /// replica can say what the floor leaves of it, so none settles a
    /// charge against it.
    #[test]
    #[should_panic(expected = "BFT CRITICAL")]
    fn a_charge_on_a_vault_that_is_no_amount_stops_the_batch() {
        let _ = charge_over(b"not an amount".to_vec(), 0);
    }

    const LADDER_OWNER: Address = Address::new([0x11; 31], AddressClass::Component);
    const LADDER: CollectionId = CollectionId([4; 16]);

    /// A store holding an entry at each order in `0..count` of the
    /// ladder.
    fn ladder_of(count: u8) -> MemoryStore {
        let mut store = MemoryStore::new();
        for order in 0..count {
            store.entry_write(LADDER_OWNER, LADDER, u128::from(order), vec![order]);
        }
        store
    }

    /// The whole ladder at `cap`, in `mode`.
    fn ladder_at(cap: u32, mode: Mode) -> Effect {
        Effect {
            target: EffectTarget::Range {
                owner: LADDER_OWNER,
                collection: LADDER,
                lo: 0,
                hi: u128::MAX,
                cap,
            },
            mode,
        }
    }

    fn declared_of(effects: &[Effect]) -> EffectSet {
        let mut set = EffectSet::new();
        for effect in effects {
            set.insert_at_cap(*effect)
                .expect("the fixture's accesses fold");
        }
        set
    }

    /// The orders of the ladder a baseline holds.
    fn orders_in(base: &TickBaseline) -> Vec<u128> {
        base.entries.keys().map(|key| key.order).collect()
    }

    /// A declared range lifts one past its cap: the successor a page's
    /// coverage turns on.
    #[test]
    fn a_declared_range_materializes_its_successor() {
        let mut base = TickBaseline::default();
        materialize_declared(
            &ladder_of(6),
            &declared_of(&[ladder_at(3, Mode::Read)]),
            &OwnerSet::whole(),
            &mut base,
        );
        assert_eq!(orders_in(&base), vec![0, 1, 2, 3]);
    }

    /// The source's baseline holds whatever a batch-mate's wider read
    /// materializes beside a member's own interval, and a counterpart's
    /// holds the member's part alone. A page that removes what it shows
    /// counts and covers alike over both, because both answer its lift.
    #[test]
    fn a_full_page_answers_coverage_alike_on_both_shards() {
        let store = ladder_of(10);
        let member = ladder_at(4, Mode::Write { moves: Moves::Both });
        let mut source = TickBaseline::default();
        materialize_declared(
            &store,
            &declared_of(&[member, ladder_at(8, Mode::Read)]),
            &OwnerSet::whole(),
            &mut source,
        );
        let mut counterpart = TickBaseline::default();
        materialize_declared(
            &store,
            &declared_of(&[member]),
            &OwnerSet::whole(),
            &mut counterpart,
        );
        assert_eq!(orders_in(&source).len(), 9, "the batch-mate's read");
        assert_eq!(orders_in(&counterpart), vec![0, 1, 2, 3, 4], "the part");

        let walk = |base: TickBaseline| {
            let mut session = KernelSession::materialize(
                OverlayStore::new(Arc::new(base)),
                &Declaration::from_set(declared_of(&[member])),
                TxHash::from(Hash::from_bytes(b"walker")),
                EnvInputs::unsealed(0),
                protocol_hash,
            )
            .expect("one write interval materializes");
            let mut answers = Vec::new();
            for _ in 0..4 {
                answers.push((
                    session.range_count(0, 0).unwrap(),
                    KernelHost::site_covered(&mut session, 0, 0).unwrap(),
                ));
                session.range_remove(0, 0, 0).unwrap();
            }
            answers.push((
                session.range_count(0, 0).unwrap(),
                KernelHost::site_covered(&mut session, 0, 0).unwrap(),
            ));
            answers
        };
        let on_source = walk(source);
        assert_eq!(on_source, walk(counterpart));
        assert_eq!(
            on_source,
            vec![(4, false), (3, false), (2, false), (1, false), (0, false)]
        );
    }

    /// A reader answering every point it is asked.
    #[derive(Debug)]
    struct Everywhere;

    impl PointReads for Everywhere {
        fn entry(&self, _: Address, _: CollectionId, _: u128) -> Option<Vec<u8>> {
            Some(vec![7])
        }
    }

    /// A baseline executing on `shard` under `trie`, its points read by
    /// [`Everywhere`].
    fn probing(trie: &ShardTrie, shard: ShardId) -> TickBaseline {
        TickBaseline {
            points: Some((routed_to(trie, shard), Arc::new(Everywhere))),
            ..TickBaseline::default()
        }
    }

    /// A point the map lacks falls through to the reader for an owner
    /// the trie routes to this shard, and never for one it routes away:
    /// another shard's cell read out of this store would differ between
    /// replicas.
    #[test]
    fn a_point_of_another_shards_owner_never_falls_through() {
        let trie = ShardTrie::uniform_from_count(2);
        let ours = Address::new([0x00; 31], AddressClass::Component);
        let theirs = Address::new([0xFF; 31], AddressClass::Component);
        let shard = trie.shard_for_prefix(ours);
        assert_ne!(trie.shard_for_prefix(theirs), shard);
        let base = probing(&trie, shard);
        assert_eq!(base.entry(ours, LADDER, 5), Some(vec![7]));
        assert_eq!(base.entry(theirs, LADDER, 5), None);
        // And a baseline with no reader answers from its map alone.
        assert_eq!(TickBaseline::default().entry(ours, LADDER, 5), None);
    }

    /// A shard the trie has split, as a straddling parent executing after
    /// its split is, routes no owner to itself, so no point falls through:
    /// the gate is the pre-read's locality, which names none of its old
    /// subtree either, not the prefix the parent once owned.
    #[test]
    fn a_point_on_a_shard_no_longer_a_leaf_never_falls_through() {
        let trie = ShardTrie::uniform_from_count(2);
        let base = probing(&trie, ShardId::ROOT);
        for owner in [[0x00; 31], [0xFF; 31]] {
            let owner = Address::new(owner, AddressClass::Component);
            assert!(ShardTrie::shard_owns_prefix(ShardId::ROOT, owner));
            assert_eq!(base.entry(owner, LADDER, 5), None);
        }
    }
}
