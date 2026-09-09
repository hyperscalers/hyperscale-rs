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
//! memoized in the per-transaction `ProcessExecutionCache` — the same
//! transaction in a different block may abort differently.

use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, OnceLock};

use blake3::hash as blake3_hash;
use hyperscale_effects_bridge::records::{PackageCache, record_address};
use hyperscale_effects_bridge::vm_statics::{config_key, package_key, principal_for};
use hyperscale_effects_bridge::{
    BridgeStatics, LocalCells, NodeRecords, PoolRegistry, ProtocolHasher, XRD, admit_package,
    decode_tree, envelope_identity, witness_from_event,
};
use hyperscale_metrics::record_transaction_executed;
use hyperscale_storage::entry_from_leaf;
use hyperscale_types::{
    BeaconWitnessEvent, BeaconWitnessRoot, ConsensusReceipt, Derivation, EscrowedValue, Event,
    EventExt, EventRoot, ExecutionMetadata, FeeSummary, GlobalReceipt, Hash, Movement,
    PrincipalAddr, ProvisionalHolds, ShardId, ShardTrie, StakePoolSeat, StateWrites, SubstateEntry,
    Transaction, TxHash, Verified, WeightedTimestamp, compute_merkle_root,
    install_protocol_statics,
};
use hyperscale_vm_effects::{
    ChainRecords, CrossingCell, CrossingSite, Declaration, DeclaredAccess, NodeCall, PackageHash,
    PrefixShardResolver, SubintentRecord, admit_tree, package_hash, route_tree,
};
use hyperscale_vm_kernel::{
    Baseline, BatchTx, Disposal, Disposition, EnvInputs, ExecutionMode, FeeBurn, Job, LegPlan,
    ManifestWalk, OwnerSet, Receipt, Substates, execute_batch,
};
use hyperscale_vm_types::{
    Address, CallTarget, CollectionId, Effect, EffectSet, EffectTarget, EntryKey, Mode, Moves,
    Outcome, ResourceAddr, SubstateKey, UnmetCondition,
};

use crate::backend::EngineBackend;
use crate::genesis::{GenesisPackages, World, genesis_world_with_pools};
use crate::legs::{Licence, Member, Runs};
use crate::records::BatchRecords;
use crate::sharding::writes_root;
use crate::{CachedOutput, ExecutedTx, TickBatchContext, TickTxInput, project_to_shard};

/// Whether a derivation holds a gated node to its target's authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetAuthority {
    /// The rule as the chain applies it.
    Required,
    /// Every gated node is treated as authorised. A preview grant only,
    /// for answering what an envelope would do before the accounts it
    /// touches have signed for it.
    Assumed,
}

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
    /// list, so nothing downstream sees intent structure — or settle
    /// the records a settlement names.
    pub job: Job,
    /// The routed declaration, both views: the folded set scheduling
    /// reads, and the clause order the capability table is built in —
    /// which is what a lowered call's handle positions index.
    pub declaration: Declaration,
    /// One record per bound subintent: the nullifier the batch entry
    /// enforces, and what the cell recording its spend says.
    pub nullifiers: Vec<SubintentRecord>,
    /// The envelope's signed execution ceiling, in fuel — one budget for
    /// the whole transaction, however many nodes its manifest walks.
    pub gas_limit: u64,
    /// The owners this shard judges — with the job's plan, the one part
    /// of an entry that differs per participant.
    pub judges: OwnerSet,
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

/// The environment a member executes under: its own clock, the epoch
/// that clock falls in, and the seeds a seal written in that epoch can
/// later be opened against.
///
/// Every input is a fact about the transaction or about the beacon, and
/// none is a fact about the block executing it — which is what lets the
/// shards of a cross-shard transaction derive one receipt, and what
/// leaves nothing for an attempt to grind.
fn env_at(ctx: &TickBatchContext<'_>, clock: WeightedTimestamp) -> EnvInputs {
    EnvInputs {
        clock_ms: clock.as_millis(),
        epoch: ctx.env.windows.epoch_for(clock).inner(),
        seeds: ctx.env.seeds.clone(),
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
    pub cells: BTreeMap<SubstateKey, Vec<u8>>,
    /// The committed entries of every declared collection interval,
    /// keyed by entry identity — [`materialize_declared`] fills it, and
    /// the kernel's range capabilities read through it.
    pub entries: BTreeMap<EntryKey, Vec<u8>>,
    /// What legs of unresolved ticks hold against these cells. Empty for
    /// a baseline with nothing in flight over it — a preview, or a shard
    /// with no cross-shard leg outstanding.
    pub holds: ProvisionalHolds,
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
}

impl Baseline for TickBaseline {
    fn holds(&self, key: SubstateKey) -> BTreeMap<TxHash, u128> {
        self.holds.get(&key).cloned().unwrap_or_default()
    }
}

/// Materialize one declaration's baseline from the tick snapshot: for
/// every declared effect this shard owns, the committed content it
/// reads — the point cell, or the entries of the collection interval.
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
            for (order, value) in snapshot.entries_in_range(owner, collection, lo, hi, cap as usize)
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

/// The VM engine: the genesis-static world, the compiled stdlib guests,
/// and the batch scheduling mode.
pub struct Executor {
    pub(crate) world: World,
    pub(crate) backend: EngineBackend,
    pub(crate) mode: ExecutionMode,
    derivation: Arc<BridgeStatics>,
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
            cells: OnceLock::new(),
        });
        install_protocol_statics(Box::new(BridgeStatics {
            cache: world.cache.clone(),
            instances: world.instances.clone(),
            artifact_sink: None,
            cells: OnceLock::new(),
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
            cells: OnceLock::new(),
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

    /// Tell this engine where its node's committed state is, so a record
    /// the cache does not hold is looked for there before it is given up
    /// on. Installed by the host, which knows what it serves.
    pub fn install_cells(&self, cells: Arc<dyn LocalCells>) {
        self.derivation.install_cells(cells);
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
                self.world
                    .cache
                    .publish(package_hash(&ProtocolHasher, artifact), metadata);
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

    /// Whether `package`'s code resolves without waiting — built, or
    /// refused by a build every replica refuses alike.
    #[must_use]
    pub fn package_code_settled(&self, package: PackageHash) -> bool {
        self.backend.code_settled(package)
    }

    /// Whether the artifact behind `package` — named by the workspace
    /// hash the beacon registry carries — is judged or being built.
    #[must_use]
    pub fn package_known(&self, package: Hash) -> bool {
        self.backend.code_known(PackageHash(package.as_hash32()))
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

    /// Whether this node answers for the component at `instance`.
    #[must_use]
    pub fn instance_known(&self, instance: Address) -> bool {
        CallTarget::try_from(instance)
            .is_ok_and(|target| self.world.instances.record(target).is_some())
    }

    /// Derive one transaction's invocations, effect set, and nullifiers
    /// — the same `decode → admit → route` admission ran; refusal here
    /// means the transaction bypassed admission and fails
    /// deterministically.
    ///
    /// Deterministically only as far as `chain` is: a refusal is this
    /// member's contribution to a receipt root, so what answers a target
    /// on the commit path has to answer the same on every member. That
    /// is [`BatchRecords`], which reads the block and committed state
    /// and nothing a node accumulated on its own.
    ///
    /// Nothing of the engine enters it, which is the same statement from
    /// the other side: what an envelope declares is a function of the
    /// envelope and the records, and of no node running it.
    ///
    /// [`BatchRecords`]: crate::records::BatchRecords
    pub(crate) fn prepare(
        tx: &Transaction,
        chain: &dyn ChainRecords,
    ) -> Result<PreparedTx, String> {
        Self::prepare_with_authority(tx, chain, TargetAuthority::Required)
    }

    /// [`Self::prepare`] for a member running the transaction's shape:
    /// the legs `decomposed` gives this shard under `ctx`, with its
    /// crossing cells declared.
    fn prepare_shape(
        tx: &Transaction,
        records: &BatchRecords,
        member: &Member,
        arrivals: &[EscrowedValue],
    ) -> Result<PreparedTx, String> {
        let mut entry = Self::prepare(tx, records)?;
        let plan = member
            .classified()
            .plan(arrivals, member.local(), member.side())
            .map_err(|defect| format!("no plan for this shard: {defect}"))?;
        // The second member a shard runs of one transaction commits no
        // nullifier: the issuing one did, and a second spend of the same
        // cell would refuse this one before it ran.
        if member.is_second() {
            entry.nullifiers.clear();
        }
        declare_crossing_cells(&mut entry.declaration, &plan.legs)?;
        let Job::Manifest { calls, .. } = entry.job else {
            return Err("a prepared transaction walks its manifest".to_string());
        };
        entry.job = Job::Manifest {
            calls,
            legs: plan.legs,
        };
        entry.judges = plan.judges;
        Ok(entry)
    }

    /// The entry a settlement runs: no call, no nullifier, and a
    /// declaration of its own over exactly the cells it touches — each
    /// record read and deleted, and where a crossing is taken back, its
    /// claim written and its origin credited in the resource the record
    /// names.
    ///
    /// A settlement derives from the cell, not the manifest, so it
    /// carries none of the transaction's declaration: no node is
    /// invoked, so no table position matters, and the transaction's own
    /// mode on the origin — a reservation, where the value left — is not
    /// the credit a reclaim makes. Every term is the record's: the edge
    /// it names, the claim key its expiry derives, the resource, the
    /// amount and the cell to credit.
    ///
    /// What each record takes is the licence's to say. On a
    /// counterpart's committed evidence every record takes the same arm,
    /// and a record this shard cannot read is a refusal, since one that
    /// is not there was retired or taken back already. On this shard's
    /// own leaf each record takes the arm its claim cell decides —
    /// present means the crossing was taken and the record is a balance
    /// for a claim that happened, which is deleted; absent means no
    /// consumer took it, and none can now, since the member is admitted
    /// only past the lapse, which is credited back — and a record
    /// already gone is skipped rather than refused, since a
    /// member admitted for several records is one member, and one of
    /// them having been settled by the shard's own evidence path in
    /// between is not a reason to strand the rest.
    ///
    /// The scope is this shard's own subtree, whatever the transaction's
    /// placement was. Every cell a settlement touches sits under the
    /// record's owner, which is a prefix this shard holds or the record
    /// would not be here; and a batch of settlements alone reaches
    /// beyond nothing, so its writes are unfiltered — a credit to an
    /// origin owned elsewhere has to trap here rather than land in a
    /// store that does not own it.
    fn prepare_settle(
        records: &[SubstateKey],
        on: Licence,
        ctx: &TickBatchContext<'_>,
        snapshot: &(dyn Substates + Sync),
    ) -> Result<PreparedTx, String> {
        if records.is_empty() {
            return Err("this shard has no record to settle".to_string());
        }
        let mut disposals = Vec::with_capacity(records.len());
        let mut declaration = Declaration::default();
        for key in records {
            let record = match (read_record(snapshot, *key), on) {
                (Some(record), _) => record,
                (None, Licence::OwnLeaf) => continue,
                (None, Licence::Claimed | Licence::Unclaimed) => {
                    return Err(format!("settlement of record {key:?} reads no record"));
                }
            };
            let mut declare_here = |effect, holds| {
                declare(&mut declaration, effect, holds).map_err(|conflict| {
                    format!("settled cell contradicts the declaration: {conflict}")
                })
            };
            declare_here(
                Effect {
                    target: EffectTarget::Point(*key),
                    mode: Mode::Write { moves: Moves::Both },
                },
                None,
            )?;
            // The claim site under the producer's own target: what a
            // reclaim writes, and what holds either settlement to the
            // record's edge.
            let claim = CrossingSite::claim_on(&ProtocolHasher, key.owner, &record);
            let disposition = if takes_back(on, &record, snapshot) {
                let origin = record
                    .origin
                    .ok_or_else(|| format!("reclaim of record {key:?} names no origin"))?;
                declare_here(
                    Effect {
                        target: EffectTarget::Point(claim.key()),
                        mode: Mode::Write { moves: Moves::Both },
                    },
                    None,
                )?;
                declare_here(
                    Effect {
                        target: EffectTarget::Point(origin),
                        mode: Mode::Delta { moves: Moves::Both },
                    },
                    Some(record.resource),
                )?;
                Disposition::Reclaim
            } else {
                Disposition::Retire
            };
            disposals.push(Disposal {
                record: *key,
                claim,
                disposition,
            });
        }
        if disposals.is_empty() {
            return Err("every inherited record was settled already".to_string());
        }
        let trie = ctx.shard_trie.clone();
        let local = ctx.local_shard;
        Ok(PreparedTx {
            job: Job::Records(disposals),
            declaration,
            nullifiers: Vec::new(),
            gas_limit: 0,
            judges: OwnerSet::of(move |owner| trie.shard_for_prefix(owner) == local),
        })
    }

    /// [`Self::prepare`] with the target-authority rule made optional.
    ///
    /// Only a preview waives it, and only when its caller asked to be
    /// shown what an envelope would do before its counterparties have
    /// signed. Nothing on the commit path reaches this with
    /// [`TargetAuthority::Assumed`].
    pub(crate) fn prepare_with_authority(
        tx: &Transaction,
        chain: &dyn ChainRecords,
        authority: TargetAuthority,
    ) -> Result<PreparedTx, String> {
        let vm = tx.body();
        let tree = decode_tree(
            vm.call_tree()
                .ok_or_else(|| "publish body in a call sub-batch".to_string())?,
        )
        .map_err(|error| error.to_string())?;
        // The composer identity is what the signature's own key opens,
        // never the payer field: the payer names who is debited, and
        // whether the payer's rule admits this signer was the payer
        // shard's verdict before the transaction committed.
        let signer = principal_for(vm.signer_scheme, &vm.signer)
            .ok_or_else(|| "the envelope's signer key derives no principal".to_string())?;
        // The records the caller answers with. Admission composes the
        // envelope's own over these itself, and holds each to standing
        // for the seal of the component it derives.
        let admitted = admit_tree(&tree, signer, envelope_identity(vm), chain, &ProtocolHasher)
            .map_err(|error| format!("admission: {error}"))?;
        let routing = route_tree(&admitted, &PrefixShardResolver { bits: 0 });
        // Both views of the declaration, straight from the fold: the
        // folded set that scheduling and judging read, and the clause
        // order capability materialization walks. Unioning `per_shard`
        // here would reach the same set but discard the order, which is
        // what a guest's positional handle parameters are indexed by.
        let declaration = routing.declaration().clone();
        let calls = match authority {
            TargetAuthority::Required => routing.calls,
            // A preview shown before its counterparties have signed:
            // every guarded call is answered as if whoever it names
            // had presented themselves. The lie is told here and
            // nowhere else, so nothing on the commit path can reach
            // it.
            TargetAuthority::Assumed => routing
                .calls
                .into_iter()
                .map(|call| NodeCall {
                    requires: Vec::new(),
                    ..call
                })
                .collect(),
        };
        Ok(PreparedTx {
            // Whole until the batch pipeline plans the member for its
            // shard; a preview never divides.
            job: Job::Manifest {
                calls,
                legs: LegPlan::whole(0),
            },
            declaration,
            nullifiers: admitted.subintents,
            gas_limit: vm.gas_limit,
            judges: OwnerSet::whole(),
        })
    }
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
/// The receipt's own summary of what was charged, in attos — the unit
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
/// Debit the payer's vault by `amount`, held to the signed ceiling: a
/// publish's burn, priced by its artifact, on the one path that runs no
/// kernel session to record it inside the receipt.
///
/// A movement, like every other debit, which is what makes the burn
/// compose with whatever else reaches the vault instead of having to be
/// re-derived into each sibling's absolute. There is nothing cumulative
/// to track and nothing to re-stamp: two transactions burning against
/// one vault each record their own debit and settlement adds them.
fn apply_fee_burn(writes: &mut StateWrites, fee: Option<PayerFee>, amount: u128) {
    let Some(payer) = fee else {
        return;
    };
    let burn = amount.min(payer.max_fee);
    if burn == 0 {
        return;
    }
    // A fee is paid in the protocol's own resource, which is what the
    // payer's vault is keyed by and what makes this movement nameable
    // without reading the vault.
    //
    // This composition lands in the receipt `writes_root` commits over,
    // so it stays exact gross — and it can: the standing debit is
    // bounded by the XRD that exists, the burn by the ceiling the payer
    // signed, and the two together sit far inside `u128`.
    let burned = Movement::debit(*XRD, burn);
    writes
        .movements
        .entry(payer.vault)
        .and_modify(|standing| {
            *standing = standing
                .then(burned)
                .expect("a vault's debits and a u64 fee compose inside u128");
        })
        .or_insert(burned);
}

/// What this shard, as a transaction's fee payer, charges it.
#[derive(Clone, Copy)]
pub struct PayerFee {
    pub vault: SubstateKey,
    /// The signed ceiling: the hold the price has to fit, and the most
    /// any burn reaches.
    pub max_fee: u128,
    /// The declared price — what every attempt owes, whatever refused
    /// it, derived from signed content before anything runs.
    pub price: u128,
    /// Whether a tick can abort this transaction after it executed —
    /// true for a cross-shard leg, which is the one shape whose effects
    /// are discarded after the engine completed them.
    pub abortable: bool,
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
#[must_use]
pub fn build_fee_receipt(
    local_shard: ShardId,
    shard_trie: &ShardTrie,
    tx_hash: TxHash,
    vault: SubstateKey,
    amount: u128,
) -> ConsensusReceipt {
    let writes = StateWrites {
        cells: BTreeMap::new(),
        movements: BTreeMap::from([(vault, Movement::debit(*XRD, amount))]),
        entries: BTreeMap::new(),
    };
    let receipt_hash = GlobalReceipt::new(
        true,
        EventRoot::ZERO,
        BeaconWitnessRoot::ZERO,
        writes_root(&writes),
    )
    .receipt_hash();
    // No gas: this receipt settles a price, it does not report execution.
    // The transaction whose abort it settles consumed real work, but that
    // work is unattested — a failed outcome carries no gas either — so an
    // abort contributes nothing to its shard's emission weight. Pricing
    // aborted work is the floor's job, not the weight's.
    let cached = CachedOutput::succeeded(
        writes,
        receipt_hash,
        vm_metadata(amount, None),
        0,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    project_to_shard(&cached, tx_hash, local_shard, shard_trie).consensus
}

/// What judging and storing one artifact costs, whatever the verdict:
/// the shard reached it from these bytes before it knew the answer.
///
/// One unit per byte is a placeholder until measured baselines set the
/// real rate, like every other number in the fee model.
#[must_use]
pub const fn publish_work(artifact: &[u8]) -> u64 {
    artifact.len() as u64
}

/// Settle one publish: the artifact lands in its content-addressed cell
/// under the publisher, and the fee burns from the publisher's vault.
///
/// A publish never enters the kernel — there is no manifest to run — so
/// it settles outside the batch fold rather than inside it. That is
/// sound because a publish declares exactly two keys, its own package
/// cell and its own fee vault, and both are exclusive: no sibling in the
/// block can be touching either, so there are no earlier burns to layer
/// on and nothing for the kernel differential to check.
fn assemble_published_tx(
    ctx: &TickBatchContext<'_>,
    vm_tx: TxHash,
    publisher: PrincipalAddr,
    artifact: &[u8],
    fee: Option<PayerFee>,
    locality: &OwnerSet,
) -> ExecutedTx {
    let tx_hash = vm_tx;
    let work = publish_work(artifact);
    let charged = fee.map_or(0, |payer| u128::from(work).min(payer.max_fee));

    // Admission reached the whole verdict from these same bytes, so a
    // refusal here means the transaction bypassed admission — the same
    // condition `prepare` treats as a deterministic failure.
    let refusal = admit_package(artifact).err().map(|error| error.to_string());

    let cached = refusal.as_ref().map_or_else(
        || {
            let mut writes = StateWrites::default();
            if locality.covers(publisher) {
                let package = package_hash(&ProtocolHasher, artifact);
                // Content-addressed, so republishing the same artifact
                // writes the same bytes to the same cell: idempotent by
                // construction rather than by a first-write-wins branch.
                writes
                    .cells
                    .insert(package_key(publisher, package), Some(artifact.to_vec()));
            }
            apply_fee_burn(&mut writes, fee, u128::from(work));
            let receipt_hash = GlobalReceipt::new(
                true,
                EventRoot::ZERO,
                BeaconWitnessRoot::ZERO,
                writes_root(&writes),
            )
            .receipt_hash();
            // The publish becomes a beacon fact: paired with the
            // publisher as emitter, so the shard owning the publisher's
            // prefix — the one that keeps the cell — is the one whose
            // witness stream carries it, exactly once.
            let package = package_hash(&ProtocolHasher, artifact);
            let witnesses = vec![(
                publisher.address(),
                BeaconWitnessEvent::PackagePublished {
                    package: Hash::from(package.0),
                    publisher: publisher.address(),
                },
            )];
            CachedOutput::succeeded(
                writes,
                receipt_hash,
                vm_metadata(charged, None),
                work,
                Vec::new(),
                witnesses,
                Vec::new(),
            )
        },
        |reason| CachedOutput::failed(vm_metadata(charged, Some(reason.clone()))),
    );
    // A refused artifact settles the same price an accepted one burns —
    // the artifact's length under the signed ceiling — as every refusal
    // does: the shard judged these bytes before it knew the answer, and
    // what it charges is what it declared, never the ceiling.
    let fee_receipt = match (&refusal, fee) {
        (Some(_), Some(payer)) => Some(build_fee_receipt(
            ctx.local_shard,
            ctx.shard_trie,
            tx_hash,
            payer.vault,
            charged,
        )),
        _ => None,
    };

    let mut executed = project_to_shard(&cached, tx_hash, ctx.local_shard, ctx.shard_trie);
    executed.fee_receipt = fee_receipt;
    executed.attested_work = work;
    executed
}

/// The plan a member that ran the whole shape ran under, for a receipt
/// with no prepared entry to read one off.
static WHOLE_JOB: LazyLock<Job> = LazyLock::new(|| Job::Manifest {
    calls: Vec::new(),
    legs: LegPlan::whole(0),
});

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
    for key in legs.records().chain(legs.claims()) {
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
    declaration
        .set
        .insert(effect)
        .map_err(|conflict| conflict.to_string())?;
    declaration.ordered.push(DeclaredAccess {
        effect,
        holds,
        reach: None,
        clause: None,
    });
    Ok(())
}

/// What the kernel reported for one transaction: the effect record every
/// participant derives identically, and this shard's own attested share.
#[derive(Clone, Copy)]
struct KernelOutput<'a> {
    receipt: &'a Receipt,
    work: u64,
    /// What the member did: whose plan names the record cell of each
    /// edge the receipt says it issued.
    job: &'a Job,
}

/// What every transaction in a batch assembles against: the pre-read
/// baseline its receipts fold over, the share of the world this shard
/// applies, and what the witness lift needs to decide whether an emitted
/// event is a beacon fact — the pools the network recognises, what code
/// each instance runs, and the code a pool must be running.
#[derive(Clone, Copy)]
struct BatchInputs<'a> {
    base: &'a TickBaseline,
    locality: &'a OwnerSet,
    pools: &'a PoolRegistry,
    instances: &'a dyn ChainRecords,
    staking_package: PackageHash,
}

fn assemble_executed_tx(
    ctx: &TickBatchContext<'_>,
    inputs: BatchInputs<'_>,
    fold: &mut FoldState,
    vm_tx: TxHash,
    kernel: KernelOutput<'_>,
    fee: Option<PayerFee>,
) -> ExecutedTx {
    let BatchInputs { base, locality, .. } = inputs;
    let KernelOutput {
        receipt,
        work: attested_work,
        job,
    } = kernel;
    let tx_hash = vm_tx;
    let charged = fee.map_or(0, |payer| payer.price.min(payer.max_fee));
    let fee_receipt = fee
        .filter(|payer| settled_apart(&receipt.outcome, *payer))
        .map(|payer| {
            build_fee_receipt(
                ctx.local_shard,
                ctx.shard_trie,
                tx_hash,
                payer.vault,
                payer.price.min(payer.max_fee),
            )
        });
    let cached = if matches!(receipt.outcome, Outcome::Completed { .. }) {
        // What the receipt carries: exclusive writes as absolutes,
        // everything commutative as the movement it was. Unresolved,
        // because the state this lands on is not the state it ran
        // against — that is settlement's question.
        let writes = receipt
            .delta
            .project(locality)
            .expect("kernel-produced movements compose");
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
        // that settles which shard keeps the event.
        let witnesses: Vec<(Address, BeaconWitnessEvent)> = events
            .iter()
            .filter_map(|event| {
                witness_from_event(
                    event,
                    inputs.pools,
                    inputs.instances,
                    inputs.staking_package,
                )
                .map(|witness| (event.emitter, witness))
            })
            .collect();
        // The root covers the events this shard's own emitters produced
        // — what its receipt stores — and not a union: a participant
        // running only its own legs cannot assemble one, and two
        // participants attesting different unions under one signed root
        // would contradict each other. Agreement across shards is
        // outcome-level in the certificates, never hash equality.
        let event_hashes: Vec<Hash> = events
            .iter()
            .filter(|event| locality.covers(event.emitter))
            .map(EventExt::hash)
            .collect();
        let receipt_hash = GlobalReceipt::new(
            true,
            EventRoot::from_raw(compute_merkle_root(&event_hashes)),
            BeaconWitnessRoot::ZERO,
            writes_root(&writes),
        )
        .receipt_hash();
        // What left on each departing edge, with the record cell the plan
        // filed for it. The kernel issues only what the plan departs, so
        // an edge the plan has no site for is a kernel defect, not a
        // silently shorter list.
        let escrowed: Vec<EscrowedValue> = receipt
            .escrow
            .issues()
            .map(|((node, output), crossed)| EscrowedValue {
                node,
                output,
                resource: crossed.resource,
                amount: crossed.amount,
                record: job
                    .departure(node, output)
                    .expect("the kernel issues only what the plan departs")
                    .site
                    .key(),
            })
            .collect();
        CachedOutput::succeeded(
            writes,
            receipt_hash,
            vm_metadata(charged, None),
            receipt.fuel,
            events,
            witnesses,
            escrowed,
        )
    } else {
        CachedOutput::failed(vm_metadata(charged, Some(abort_reason(&receipt.outcome))))
    };
    let mut executed = project_to_shard(&cached, tx_hash, ctx.local_shard, ctx.shard_trie);
    executed.fee_receipt = fee_receipt;
    executed.attested_work = attested_work;
    executed
}

/// One member of a tick's batch: what its receipt is keyed by, and the
/// body it runs over if it runs one.
///
/// A housekeeping member has none. Its cells are named by the record
/// leaves its `Runs` arm carries, which is what lets a reshape successor
/// compose one at all — the transaction is a name, not an input.
struct BatchMember {
    tx_hash: TxHash,
    body: Option<Arc<Verified<Transaction>>>,
}

/// Whether the settlement of `record` under `on` takes the crossing
/// back rather than deleting a record whose claim happened: what the
/// licence says, or for a record on this shard's own leaf what its
/// claim cell says — present is a claim that happened, absent is one
/// that never will. That the absence is read inside the window it
/// means something in is the licence's business: a member is admitted
/// on this shard's own leaf only inside the lapse, as it is admitted on
/// a counterpart's evidence only once that evidence stands.
fn takes_back(on: Licence, record: &CrossingCell, snapshot: &(dyn Substates + Sync)) -> bool {
    match on {
        Licence::Claimed => false,
        Licence::Unclaimed => true,
        Licence::OwnLeaf => snapshot.cell(record.consumer_claim).is_none(),
    }
}

/// The record a leaf holds, or nothing where the cell is absent or is
/// not one.
fn read_record(snapshot: &(dyn Substates + Sync), key: SubstateKey) -> Option<CrossingCell> {
    snapshot
        .cell(key)
        .and_then(|bytes| CrossingCell::from_bytes(&bytes))
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
    ) -> Vec<ExecutedTx> {
        if inputs.is_empty() {
            return Vec::new();
        }
        let members: Vec<BatchMember> = inputs
            .iter()
            .map(|i| BatchMember {
                tx_hash: i.tx_hash,
                body: i.transaction.map(Arc::clone),
            })
            .collect();
        let provisions_by_tx: BTreeMap<TxHash, Vec<Arc<Vec<SubstateEntry>>>> = inputs
            .iter()
            .filter(|i| !i.provisions.is_empty())
            .map(|i| (i.tx_hash, i.provisions.to_vec()))
            .collect();
        let env_by_tx: BTreeMap<TxHash, EnvInputs> = inputs
            .iter()
            .map(|i| (i.tx_hash, env_at(ctx, i.clock)))
            .collect();
        let shapes: BTreeMap<TxHash, &TickTxInput<'_>> =
            inputs.iter().map(|i| (i.tx_hash, i)).collect();
        // A member declaring remote cells has its writes filtered to the
        // local subtree; a batch of genuinely single-shard members owns
        // every key it declares and total locality is the same filter
        // without the trie walk.
        let locality = if inputs.iter().all(|i| !i.runs.reaches_beyond()) {
            OwnerSet::whole()
        } else {
            let trie = ctx.shard_trie.clone();
            let local_shard = ctx.local_shard;
            OwnerSet::of(move |owner: Address| trie.shard_for_prefix(owner) == local_shard)
        };
        // Publishes carry no manifest, so they never reach the kernel;
        // they settle in their own pass below.
        let publishes: BTreeMap<TxHash, (PrincipalAddr, Vec<u8>)> = members
            .iter()
            .filter_map(|member| {
                let vm = member.body.as_ref()?.body();
                let artifact = vm.artifact()?;
                Some((member.tx_hash, (vm.fee_payer, artifact.to_vec())))
            })
            .collect();

        // What this batch resolves its targets through: genesis, this
        // shard's committed leaves, and the ones its counterparts
        // provisioned. Every member of the shard builds the same three
        // from the same block, which is what makes a refusal below a
        // property of the transaction rather than of the node.
        let records = BatchRecords::new(
            self.world.cache.load(),
            self.world.instances.seeded(),
            &provisions_by_tx,
            snapshot,
        );

        // Derive every transaction; refusals become deterministic
        // failures without touching the batch.
        let mut prepared: BTreeMap<TxHash, PreparedTx> = BTreeMap::new();
        let mut refused: BTreeMap<TxHash, String> = BTreeMap::new();
        for input in inputs {
            let vm_tx = input.tx_hash;
            if publishes.contains_key(&vm_tx) {
                continue;
            }
            // What this shard runs of the member: the whole shape unless
            // the coordinator froze a division, and then the legs its
            // placement gives it — or, for a settlement, no node at all.
            // A plan that cannot be built is a deterministic refusal like
            // a derivation that cannot be — every replica reads the same
            // legs and the same arrivals.
            let planned = match &input.runs {
                Runs::Settle { records, on, .. } => {
                    Self::prepare_settle(records, *on, ctx, snapshot)
                }
                Runs::Shape(shape) => input
                    .transaction
                    .ok_or_else(|| "a member running a shape holds no body".to_string())
                    .and_then(|tx| Self::prepare_shape(tx, &records, shape, input.arrivals)),
            };
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

        // The committed baseline: provisioned remote cells first — a
        // key's owner prefix routes it to exactly one source, so nothing
        // arbitrates — then the locally owned declared content from the
        // tick snapshot.
        let mut base = TickBaseline::default();
        for lists in provisions_by_tx.values() {
            for entries in lists {
                for entry in entries.iter() {
                    if let Some(value) = entry.value.as_ref() {
                        // A provisioned leaf is a cell or an
                        // ordered-collection entry, and the leaf says
                        // which: an entry re-derives its own key, and
                        // lands in the interval map the kernel's range
                        // capabilities read.
                        if let Some((entry_key, entry_value)) = entry_from_leaf(entry.key, value) {
                            base.entries.insert(entry_key, entry_value);
                        } else {
                            base.cells.insert(entry.key, value.clone());
                        }
                    }
                }
            }
        }
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
        for tx in members.iter().filter_map(|member| member.body.as_ref()) {
            let key = tx.fee_vault();
            if ctx.shard_trie.shard_for_prefix(key.owner) == ctx.local_shard
                && let Some(value) = snapshot.cell(key)
            {
                base.cells.insert(key, value);
            }
        }
        // Trie-routed like the pre-read above, and for the same reason:
        // a declaration spans every participating shard, so the holds it
        // implies do too, and a shard that reported one against a cell it
        // holds none of would judge a reservation as exceeding a balance
        // it cannot see. A tick's own locality cannot decide this — the
        // single-shard arm's `OwnerSet::whole()` claims every owner.
        base.holds = ctx
            .holds
            .iter()
            .filter(|(key, _)| ctx.shard_trie.shard_for_prefix(key.owner) == ctx.local_shard)
            .map(|(key, held)| (*key, held.clone()))
            .collect();
        let base = Arc::new(base);

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
                let tx = member.body.as_ref()?;
                let vm = tx.body();
                let vault = tx.fee_vault();
                if ctx.shard_trie.shard_for_prefix(vault.owner) != ctx.local_shard {
                    return None;
                }
                // A second execution of a transaction this shard already
                // charged burns nothing, so the price is levied exactly
                // once: the reclaim of a leg that ran, whose own
                // certificate burned it inside its writes, and the
                // delivering member of a mixed shard, whose issuing member
                // did. The reclaim of a leg that never ran is the one
                // receipt of this shard's that can still carry it.
                if shapes
                    .get(&tx.hash())
                    .is_some_and(|input| input.runs.charged_already())
                {
                    return None;
                }
                Some((
                    tx.hash(),
                    PayerFee {
                        vault,
                        max_fee: vm.max_fee,
                        price: tx.price(),
                        abortable: shapes
                            .get(&tx.hash())
                            .is_some_and(|input| input.runs.abortable()),
                    },
                ))
            })
            .collect();

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
                BatchTx::new(*vm_tx, entry.declaration.clone(), env)
                    .with_job(entry.job.clone())
                    .with_nullifiers(entry.nullifiers.clone())
                    .with_gas_limit(entry.gas_limit)
                    .with_applies(locality.clone())
                    .with_judges(entry.judges.clone())
                    .with_fee(fee_by_tx.get(vm_tx).map(|payer| FeeBurn {
                        vault: payer.vault,
                        resource: *XRD,
                        amount: payer.price.min(payer.max_fee),
                    }))
            })
            .collect();
        let walk = ManifestWalk {
            backend: &self.backend,
        };
        let outcome = execute_batch(
            Arc::clone(&base) as Arc<dyn Baseline>,
            &batch,
            &walk,
            protocol_hash,
            self.mode,
        )
        .unwrap_or_else(|error| panic!("BFT CRITICAL: VM batch execution failed: {error}"));

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
            let kernel = KernelOutput {
                receipt,
                work: outcome.work.get(vm_tx).map_or(0, |w| w.units),
                job: prepared.get(vm_tx).map_or(&WHOLE_JOB, |entry| &entry.job),
            };
            let executed = assemble_executed_tx(
                ctx,
                BatchInputs {
                    base: &base,
                    locality: &locality,
                    pools: &self.world.pools,
                    instances: &records,
                    staking_package: self.world.staking_package,
                },
                &mut fold,
                *vm_tx,
                kernel,
                fee_by_tx.get(vm_tx).copied(),
            );
            folded.insert(*vm_tx, executed);
        }

        for (vm_tx, (publisher, artifact)) in &publishes {
            folded.insert(
                *vm_tx,
                assemble_published_tx(
                    ctx,
                    *vm_tx,
                    *publisher,
                    artifact,
                    fee_by_tx.get(vm_tx).copied(),
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

        // Reassemble in input order.
        members
            .iter()
            .map(|member| {
                let vm_tx = member.tx_hash;
                folded.get(&vm_tx).cloned().unwrap_or_else(|| {
                    let reason = refused
                        .get(&vm_tx)
                        .cloned()
                        .unwrap_or_else(|| "missing batch receipt".to_string());
                    // Refused before the kernel ran — a plan that cannot
                    // be built, a derivation this node refuses, a reclaim
                    // with nothing to reclaim — is an attempt like any
                    // other: the network committed it, reserved for it
                    // and dispatched it, and it settles the same price
                    // apart, as every attempt that applied no effects does.
                    let fee = fee_by_tx.get(&vm_tx).copied();
                    let charged = fee.map_or(0, |payer| payer.price.min(payer.max_fee));
                    let cached = CachedOutput::failed(vm_metadata(charged, Some(reason)));
                    let mut executed =
                        project_to_shard(&cached, vm_tx, ctx.local_shard, ctx.shard_trie);
                    executed.fee_receipt = fee.map(|payer| {
                        build_fee_receipt(
                            ctx.local_shard,
                            ctx.shard_trie,
                            vm_tx,
                            payer.vault,
                            charged,
                        )
                    });
                    executed
                })
            })
            .collect()
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
    #[must_use]
    pub fn execute_batch(
        &self,
        ctx: &TickBatchContext<'_>,
        snapshot: &(dyn Substates + Sync),
        transactions: &[Arc<Verified<Transaction>>],
    ) -> Vec<ExecutedTx> {
        // Every member runs whole on its own shard and reads the
        // context's own clock: one block committed them all, so one
        // epoch seals them all.
        let inputs: Vec<TickTxInput<'_>> = transactions
            .iter()
            .map(|tx| TickTxInput {
                tx_hash: tx.hash(),
                transaction: Some(tx),
                provisions: &[],
                clock: ctx.tick_ts,
                runs: Runs::Shape(Member::whole(ctx.local_shard)),
                arrivals: &[],
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
    #[must_use]
    pub fn execute_tick_batch(
        &self,
        ctx: &TickBatchContext<'_>,
        snapshot: &(dyn Substates + Sync),
        inputs: &[TickTxInput<'_>],
    ) -> Vec<ExecutedTx> {
        self.run_batch(ctx, snapshot, inputs)
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{AddressClass, LocalKey, Presence};
    use hyperscale_vm_types::AbortReason;

    use super::*;

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
            answers: Vec::new(),
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
}
