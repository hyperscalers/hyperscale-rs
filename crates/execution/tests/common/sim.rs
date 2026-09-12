//! A sans-io driver for [`ExecutionCoordinator`].
//!
//! Mirrors the beacon and shard `CoordinatorSim` pattern, minus the
//! consensus: blocks arrive already committed, so there is no QC chaining,
//! view change, or round timeout to model. What is left is the part this
//! crate owns — tick composition, the tick chain, and tick resolution.
//!
//! # What it is for
//!
//! Control over *ordering*. The full simulator produces whatever interleaving
//! its network happens to produce; here a test states one. A tick's completion
//! can be held while later blocks commit, a tick's certificate can be placed
//! in a block of the test's choosing, and both can be varied while the
//! committed chain stays byte-identical. That is what makes the
//! schedule-invariance lane a real assertion rather than a restatement of
//! determinism: the committed chain is the input, local timing is the thing
//! being quantified over, and the tick outputs must not move.
//!
//! Execution is a stub, not the engine. It reads each transaction's declared
//! cells through [`TickChain::view_at`] exactly as the real handler does and
//! writes a value derived from what it read, so a tick's output depends on
//! its baseline — which is the only property the lane needs. The engine's own
//! fold is checked against the kernel's applied store on every batch it runs
//! (`BFT CRITICAL: VM fold diverged from the kernel apply`), so nothing here
//! is standing in for that.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use hyperscale_core::{Action, CrossShardExecutionRequest, TickBatchOutcome};
use hyperscale_engine::ExecutedTx;
use hyperscale_engine::sharding::writes_root;
use hyperscale_execution::action_handlers::{
    ExecutionOutputs, accumulate_tick_output, split_execution_outputs,
};
use hyperscale_execution::{ExecCertStore, ExecutionCoordinator, FinalizationStore};
use hyperscale_storage::{
    Anchored, RecoveredState, ReplayWindow, SubstateStore, Substates, TickChain, TickOutput,
    VersionedStore, merge_writes_from_receipts,
};
use hyperscale_types::test_utils::{StubVmStatics, TestCommittee, certify, make_live_block};
use hyperscale_types::{
    Address, AggregateSignature, BeaconWitnessRoot, Block, BlockHeight, CertifiedBlock,
    ConsensusReceipt, CounterpartMirror, DeclaredRange, EventRoot, ExecutionCertificate,
    ExecutionMetadata, ExecutionOutcome, Finalization, GlobalReceipt, LocalKey,
    MerkleInclusionProof, Movement, ProvenAnchors, ProvenCells, ProvisionEntry, Provisions,
    ResourceAddr, SettledWrites, ShardId, ShardTrie, SignerBitfield, StateRoot, StateWrites,
    StoredReceipt, SubstateKey, TickHalf, TickId, TopologySchedule, TopologySnapshot, Transaction,
    TxHash, TxOutcome, ValidatorId, Verifiable, Verified, WeightedTimestamp,
    compute_global_receipt_root, read_amount,
};
use hyperscale_vm_types::CollectionId;

/// What every cell these fixtures move holds.
const RESOURCE: ResourceAddr = ResourceAddr::new([0xE1; 31]);

/// The shard a single-shard fixture runs on.
pub const SHARD: ShardId = ShardId::ROOT;

/// The local shard of a two-shard fixture. A declared prefix routes by its
/// leading bit, so `test_prefix(seed)` with `seed < 128` lands here and
/// `seed >= 128` lands on its sibling.
pub const LEFT: ShardId = ShardId::leaf(1, 0);

/// Milliseconds between synthesised block timestamps. Large enough that
/// nothing in the tick machinery reaches a deadline over a short run.
const BLOCK_INTERVAL_MS: u64 = 500;

/// When the driver releases a dispatched tick's completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Schedule {
    /// Complete each tick before the commit that dispatched it returns.
    Eager,
    /// Hold every completion until `n` further blocks have committed, so
    /// composition runs well ahead of execution. Ticks still complete in
    /// order — they are serial by construction — but the resolutions they
    /// gate are emitted later, which is the timing the lane quantifies over.
    Lagged(usize),
}

/// The settled base every tick reads through, versioned by height.
///
/// A tick reads it as of its own anchor, not as of whatever this replica
/// has persisted, so the harness has to keep the history: a settlement at
/// height 9 must be invisible to a read anchored at 8, exactly as it is
/// in the real store.
#[derive(Default)]
struct StubBase {
    /// Settled writes in commit order, each with the height that applied
    /// them.
    history: Mutex<Vec<(BlockHeight, SettledWrites)>>,
}

impl StubBase {
    /// Land a settled write set at `height`.
    fn apply(&self, height: BlockHeight, writes: &SettledWrites) {
        self.history
            .lock()
            .expect("base lock")
            .push((height, writes.clone()));
    }

    /// The cells as of `height`: every settled write at or below it, in
    /// commit order, last writer per cell.
    fn cells_at(&self, height: BlockHeight) -> HashMap<SubstateKey, Vec<u8>> {
        let mut cells = HashMap::new();
        for (applied, writes) in self.history.lock().expect("base lock").iter() {
            if *applied > height {
                break;
            }
            for (key, change) in writes.cells() {
                match change {
                    Some(value) => {
                        cells.insert(*key, value.clone());
                    }
                    None => {
                        cells.remove(key);
                    }
                }
            }
        }
        cells
    }
}

/// A snapshot of [`StubBase`] — cloned, so a fold cannot mutate through it.
struct StubSnapshot(HashMap<SubstateKey, Vec<u8>>);

impl Anchored for StubSnapshot {
    fn anchor(&self) -> BlockHeight {
        BlockHeight::GENESIS
    }
}

impl Substates for StubSnapshot {
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

impl Substates for StubBase {
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        self.cells_at(BlockHeight::new(u64::MAX)).get(&key).cloned()
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

impl SubstateStore for StubBase {
    type Snapshot<'a> = StubSnapshot;

    fn snapshot(&self) -> Self::Snapshot<'_> {
        StubSnapshot(self.cells_at(BlockHeight::new(u64::MAX)))
    }
    fn jmt_height(&self) -> BlockHeight {
        BlockHeight::GENESIS
    }
    fn state_root(&self) -> StateRoot {
        StateRoot::ZERO
    }
    fn get_entries_at_height(
        &self,
        _range: DeclaredRange,
        _block_height: BlockHeight,
    ) -> Option<Vec<(u128, Vec<u8>)>> {
        // The map holds no entries at any height.
        Some(Vec::new())
    }

    fn get_substate_at_height(
        &self,
        _key: SubstateKey,
        _block_height: BlockHeight,
    ) -> Option<Option<Vec<u8>>> {
        None
    }
}

impl VersionedStore for StubBase {
    fn retention_floor(&self) -> u64 {
        0
    }

    fn snapshot_held_at(&self, height: BlockHeight) -> Option<Self::Snapshot<'_>> {
        (height <= self.jmt_height()).then(|| self.snapshot_at(height))
    }

    fn snapshot_at(&self, height: BlockHeight) -> Self::Snapshot<'_> {
        StubSnapshot(self.cells_at(height))
    }
    fn substate_bytes_at(&self, _height: BlockHeight) -> Option<u64> {
        None
    }
}

/// A tick dispatched but not yet completed.
struct PendingBatch {
    tick: BlockHeight,
    requests: Vec<CrossShardExecutionRequest>,
    /// Height at which the schedule releases it.
    release_at: BlockHeight,
}

/// The driver.
pub struct ExecutionSim {
    coord: ExecutionCoordinator,
    topology: TopologySchedule,
    snapshot: Arc<TopologySnapshot>,
    chain: Arc<TickChain<StubBase>>,
    schedule: Schedule,
    pending: VecDeque<PendingBatch>,
    height: BlockHeight,
    /// Every tick output produced, in production order — what the
    /// invariance lane compares.
    outputs: Vec<(BlockHeight, TickOutput)>,
    /// The receipts each tick's tick produced, so a test can settle a tick
    /// with what it actually executed rather than with a stand-in.
    receipts: BTreeMap<TickId, Vec<StoredReceipt>>,
    /// The charges each tick's tick held in reserve beside those
    /// receipts — what settles instead of them when the tick refuses.
    charges: BTreeMap<TickId, Vec<StoredReceipt>>,
    /// Every block committed, as storage would hand it back — the input
    /// a restart replays.
    committed: Vec<Verified<CertifiedBlock>>,
    /// The settled state every tick reads through, so the harness models
    /// the whole path: a committed certificate's receipts land here in
    /// commit order, exactly as `merge_writes_from_receipts` lands them in
    /// the JMT.
    base: Arc<StubBase>,
    local_shard: ShardId,
}

impl ExecutionSim {
    /// A single-shard driver over a four-validator committee, this node
    /// seated first. Every tick it composes is single-shard, so every
    /// write is determined at commit.
    #[must_use]
    pub fn new(schedule: Schedule) -> Self {
        Self::with_shards(schedule, 1, SHARD)
    }

    /// A driver over a `num_shards`-wide topology with `local_shard` as
    /// this node's seat. A transaction declaring prefixes on both sides of
    /// the partition composes a cross-shard tick, whose writes are
    /// provisional until its certificate commits.
    #[must_use]
    pub fn with_shards(schedule: Schedule, num_shards: u64, local_shard: ShardId) -> Self {
        let committee = TestCommittee::new(4, 42);
        let base = Arc::new(StubBase::default());
        let snapshot = Arc::new(committee.topology_snapshot(num_shards));
        Self {
            coord: ExecutionCoordinator::new(ValidatorId::new(0), local_shard),
            topology: TopologySchedule::single(Arc::clone(&snapshot)),
            snapshot,
            chain: Arc::new(TickChain::new(Arc::clone(&base))),
            schedule,
            pending: VecDeque::new(),
            height: BlockHeight::GENESIS,
            outputs: Vec::new(),
            receipts: BTreeMap::new(),
            charges: BTreeMap::new(),
            committed: Vec::new(),
            base,
            local_shard,
        }
    }

    /// Commit a block carrying `txs` and `certificates`, then run whatever
    /// the schedule releases.
    pub fn commit(&mut self, txs: Vec<Transaction>, certificates: Vec<Finalization>) {
        self.height = self.height.next();
        // Settlement: a committed certificate's receipts reach state here,
        // in commit order and last-writer-wins per cell — the same
        // projection `merge_writes_from_receipts` performs into the JMT.
        for fw in &certificates {
            // Movements resolve against the state they land on, which is
            // whatever the certificates before this one already settled.
            let resolved =
                merge_writes_from_receipts(&fw.settling_receipts(), &self.base.snapshot());
            self.base.apply(self.height, &resolved);
        }
        let block = make_live_block(
            self.local_shard,
            self.height,
            self.height.inner() * BLOCK_INTERVAL_MS,
            ValidatorId::new(0),
            txs.into_iter().map(Arc::new).collect(),
            certificates
                .into_iter()
                .map(|fw| Arc::new(Verifiable::from(fw)))
                .collect(),
        );
        let certified = certify(block, self.height.inner() * BLOCK_INTERVAL_MS);
        self.committed
            .push(Verified::<CertifiedBlock>::from_persisted(
                certified.clone(),
            ));
        let actions = self.coord.on_block_committed(&self.topology, &certified);
        self.absorb(actions);
        // Persistence follows the commit, which is when the chain evicts
        // the folds it believes the base now covers.
        self.chain.prune_persisted(self.height);
        self.release_due();
    }

    /// Commit a counterpart's engagement for `tx_hashes`: the bundle a
    /// shard sends the payer because its own block committed the
    /// transaction. A payer's leg waits for this before executing, since
    /// the tick that runs it is the tick that attests it.
    pub fn engage(&mut self, from: ShardId, tx_hashes: &[TxHash]) {
        let bundle = Provisions::new(
            from,
            self.local_shard,
            self.height,
            WeightedTimestamp::from_millis(self.height.inner() * BLOCK_INTERVAL_MS),
            MerkleInclusionProof::dummy(),
            tx_hashes
                .iter()
                .map(|h| ProvisionEntry::new(*h, vec![]))
                .collect(),
        );
        self.height = self.height.next();
        let block = match make_live_block(
            self.local_shard,
            self.height,
            self.height.inner() * BLOCK_INTERVAL_MS,
            ValidatorId::new(0),
            Vec::new(),
            Vec::new(),
        ) {
            Block::Live {
                header,
                transactions,
                certificates,
                abandonment_records,
                state_claims,
                witness_sources,
                ..
            } => Block::Live {
                header,
                transactions,
                certificates,
                provisions: Arc::new(vec![Arc::new(Verifiable::from(bundle))]),
                abandonment_records,
                state_claims,
                witness_sources,
            },
            sealed @ Block::Sealed { .. } => sealed,
        };
        let certified = certify(block, self.height.inner() * BLOCK_INTERVAL_MS);
        self.committed
            .push(Verified::<CertifiedBlock>::from_persisted(
                certified.clone(),
            ));
        let actions = self.coord.on_block_committed(&self.topology, &certified);
        self.absorb(actions);
        self.chain.prune_persisted(self.height);
        self.release_due();
    }

    /// Complete every tick the schedule has released at the current height.
    fn release_due(&mut self) {
        while self
            .pending
            .front()
            .is_some_and(|batch| batch.release_at <= self.height)
        {
            let batch = self.pending.pop_front().expect("checked");
            let actions = self.run_batch(batch);
            self.absorb(actions);
        }
    }

    /// Drain every held completion regardless of schedule — what a test
    /// calls once it has finished committing and wants the pipeline empty.
    pub fn drain(&mut self) {
        while !self.pending.is_empty() {
            let batch = self.pending.pop_front().expect("checked");
            let actions = self.run_batch(batch);
            self.absorb(actions);
        }
    }

    /// Route the coordinator's actions: queue dispatches, apply tick-chain
    /// maintenance inline exactly as the shard thread does, ignore the rest
    /// (votes and broadcasts have no bearing on what is being measured).
    fn absorb(&mut self, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::ExecuteTransactions { tick, requests, .. } => {
                    let release_at = match self.schedule {
                        Schedule::Eager => self.height,
                        Schedule::Lagged(n) => BlockHeight::new(
                            self.height.inner() + u64::try_from(n).expect("lag fits"),
                        ),
                    };
                    self.pending.push_back(PendingBatch {
                        tick,
                        requests,
                        release_at,
                    });
                }
                Action::ResolveTicks { resolutions } => {
                    for (tick_id, resolution) in &resolutions {
                        self.chain.resolve(tick_id, resolution);
                    }
                }
                Action::ClearTickChain => self.chain.clear(),
                _ => {}
            }
        }
    }

    /// Execute one tick against its baseline and feed the result back.
    ///
    /// The same order the real handler uses: read through the previous
    /// tick's view, fold the output, append it, and only then notify — the
    /// coordinator dispatches the next tick on that notification and its
    /// baseline has to include this one.
    fn run_batch(&mut self, batch: PendingBatch) -> Vec<Action> {
        let PendingBatch { tick, requests, .. } = batch;
        let view = self
            .chain
            .view_at(BlockHeight::new(tick.inner().saturating_sub(1)));
        let snapshot = view.snapshot();
        let trie = self.snapshot.shard_trie();

        let tick_id = TickId::new(self.local_shard, tick);
        let executed: Vec<ExecutedTx> = requests
            .iter()
            .filter_map(|request| {
                let tx = request.transaction.as_ref()?;
                Some(stub_execute(
                    &snapshot,
                    trie,
                    self.local_shard,
                    request.tx_hash,
                    tx,
                    request.runs.abortable(),
                ))
            })
            .collect();
        let mut output = TickOutput::default();
        accumulate_tick_output(&mut output, &requests, &executed);
        let ExecutionOutputs {
            outcomes,
            results,
            fee_receipts,
        } = split_execution_outputs(executed);
        self.receipts
            .entry(tick_id)
            .or_default()
            .extend(results.iter().cloned());
        self.charges
            .entry(tick_id)
            .or_default()
            .extend(fee_receipts.iter().cloned());
        let outcome = TickBatchOutcome {
            tick_id,
            results,
            tx_outcomes: outcomes,
            fee_receipts,
        };

        self.outputs.push((tick, output.clone()));
        self.chain.append(tick, output);
        self.coord
            .on_execution_batch_completed(&self.topology, tick, outcome)
    }

    /// Every tick output this run produced, in order.
    #[must_use]
    pub fn outputs(&self) -> &[(BlockHeight, TickOutput)] {
        &self.outputs
    }

    /// The readable value of `key` as of the tick chain's tip: settled
    /// state with every retained fold over it — what the next tick would
    /// execute against.
    #[must_use]
    pub fn read(&self, key: SubstateKey) -> Option<Vec<u8>> {
        self.chain.view_at(self.height).snapshot().cell(key)
    }

    /// The settled value of `key` — what committed certificates have put
    /// into state, with no unresolved fold over it.
    #[must_use]
    pub fn settled(&self, key: SubstateKey) -> Option<Vec<u8>> {
        self.base.cell(key)
    }

    /// Restart this replica: the settled base survives, and everything
    /// execution was holding does not — the coordinator and the tick
    /// chain both come back empty, exactly as they do at startup.
    ///
    /// The whole committed chain is handed over as the replay window.
    /// Where that window's floor actually sits is storage's question,
    /// and this harness holds no retention window to answer it with.
    pub fn restart(&mut self) {
        let recovered = RecoveredState {
            committed_height: self.height,
            replay: ReplayWindow {
                blocks: self.committed.clone(),
                compose_from: BlockHeight::GENESIS,
                anchor_wt: None,
            },
            ..RecoveredState::default()
        };
        self.coord = ExecutionCoordinator::with_shared_stores(
            ValidatorId::new(0),
            self.local_shard,
            &recovered,
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::new(ProvenAnchors::new()),
            Arc::new(ProvenCells::new()),
            Arc::new(CounterpartMirror::new()),
        );
        self.chain = Arc::new(TickChain::new(Arc::clone(&self.base)));
        self.pending.clear();
        let actions = self
            .coord
            .on_committed_state_restored(&self.topology, &StubVmStatics);
        self.absorb(actions);
        self.drain();
    }

    /// Hand a finalization to the coordinator as ready for inclusion,
    /// without committing a block for it — what local aggregation does.
    pub fn admit(&self, finalization: Finalization) {
        let tick_id = *finalization.tick_id();
        // The store admits verified entries only; local aggregation
        // produces one, and the fixture stands in for that gate.
        let verified = Verified::new_unchecked_for_test(finalization);
        self.coord
            .finalization_store()
            .insert(tick_id, Arc::new(Verifiable::from(verified)));
    }

    /// The ticks a proposal would carry certificates for, in the order it
    /// would carry them.
    #[must_use]
    pub fn offered_finalizations(&self) -> Vec<TickId> {
        self.coord
            .get_finalizations()
            .iter()
            .map(|fw| *fw.tick_id())
            .collect()
    }

    /// The receipts `tick_id`'s tick produced.
    #[must_use]
    pub fn receipts_for(&self, tick_id: &TickId) -> Vec<StoredReceipt> {
        self.receipts.get(tick_id).cloned().unwrap_or_default()
    }

    /// The charges `tick_id`'s tick held in reserve.
    #[must_use]
    pub fn charges_for(&self, tick_id: &TickId) -> Vec<StoredReceipt> {
        self.charges.get(tick_id).cloned().unwrap_or_default()
    }

    /// The tick a transaction was assigned to, if the coordinator still
    /// tracks it.
    #[must_use]
    pub fn tick_of(&self, tx_hash: TxHash) -> Option<TickId> {
        self.coord.tick_assignment_for(tx_hash)
    }
}

/// The cell a declared owner prefix maps to.
#[must_use]
pub const fn cell_of(owner: Address) -> SubstateKey {
    SubstateKey {
        owner,
        local: LocalKey([0; 16]),
    }
}

/// The amount cell a declared owner prefix credits, beside the counter
/// cell it writes.
///
/// A receipt says two kinds of thing and the pair has to be exercised
/// together: an exclusive write states the value it left, and a
/// commutative access states only what it moved. The second is what every
/// fee burn and every payment actually carries, and it is the one that
/// does not survive being dropped from a fold or applied twice.
#[must_use]
pub const fn vault_of(owner: Address) -> SubstateKey {
    SubstateKey {
        owner,
        local: LocalKey([1; 16]),
    }
}

/// What each transaction credits to the vault of every cell it writes —
/// one per write, so the vault must always read exactly the counter.
pub const CREDIT: u128 = 1;

/// The cell a leg's abort charge reaches, and the amount it carries.
///
/// A cross-shard leg that completes here still owes a floor if the tick
/// refuses it, and that charge rides its own receipt — held in reserve
/// beside the effects, settled only if the effects are not. Separate
/// from [`vault_of`] so a test can read what was charged without
/// unpicking it from what was moved.
#[must_use]
pub const fn charge_of(owner: Address) -> SubstateKey {
    SubstateKey {
        owner,
        local: LocalKey([2; 16]),
    }
}

/// What an abort charge carries.
pub const FLOOR: u128 = 7;

/// Decode a counter cell; an absent cell reads as zero.
#[must_use]
pub fn counter(bytes: Option<Vec<u8>>) -> u64 {
    bytes.map_or(0, |raw| {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&raw[..8]);
        u64::from_le_bytes(buf)
    })
}

/// Decode an amount cell; an absent cell reads as zero.
#[must_use]
pub fn amount(bytes: Option<Vec<u8>>) -> u128 {
    bytes.map_or(0, |raw| read_amount(&raw).expect("an amount cell"))
}

/// Execute one transaction: increment every cell it declares exclusively,
/// and credit the same owner's vault.
///
/// Reads run through the tick view, so the counter is a function of the
/// baseline — which is what makes a wrong baseline observable as a wrong
/// count rather than as nothing at all. The credit reads nothing, so it
/// is the opposite probe: it states what it moved, and any fold that
/// drops it or applies it twice shows up as a vault that disagrees with
/// the counter beside it.
fn stub_execute(
    snapshot: &impl Substates,
    trie: &ShardTrie,
    local_shard: ShardId,
    tx_hash: TxHash,
    tx: &Arc<Verified<Transaction>>,
    abortable: bool,
) -> ExecutedTx {
    let mut cells = BTreeMap::new();
    let mut movements: BTreeMap<SubstateKey, Movement> = BTreeMap::new();
    // The payer this shard would charge: the first owner it holds.
    let mut charged: Option<Address> = None;
    for key in tx.admission_write_keys() {
        // Only the owning shard applies a cell, exactly as `OwnerSet`
        // scopes the engine's fold.
        if trie.shard_for_prefix(key.owner()) != local_shard {
            continue;
        }
        let cell = cell_of(key.owner());
        let next = counter(snapshot.cell(cell)) + 1;
        cells.insert(cell, Some(next.to_le_bytes().to_vec()));
        charged.get_or_insert_with(|| key.owner());
        let credited = Movement {
            resource: RESOURCE,
            credit: CREDIT,
            debit: 0,
        };
        movements
            .entry(vault_of(key.owner()))
            .and_modify(|standing| {
                *standing = standing
                    .then(credited)
                    .expect("a fixture's constant credits compose inside u128");
            })
            .or_insert(credited);
    }
    let writes = StateWrites {
        cells,
        movements,
        entries: BTreeMap::new(),
    };
    let receipt_hash = GlobalReceipt::new(
        true,
        EventRoot::ZERO,
        BeaconWitnessRoot::ZERO,
        writes_root(&writes),
    )
    .receipt_hash();
    let mut executed = ExecutedTx::new(
        tx_hash,
        ConsensusReceipt::Succeeded {
            receipt_hash,
            writes,
            beacon_witness_events: Vec::new(),
            events: Vec::new(),
        },
        ExecutionMetadata::empty(),
    );
    // A leg a tick can still discard carries its charge beside its
    // effects, exactly as the engine builds one for a cross-shard
    // member. Which of the two settles is the tick's decision, not this
    // shard's.
    if abortable {
        executed.fee_receipt = charged.map(stub_charge);
    }
    executed
}

/// The receipt a refused leg settles: the abort floor and nothing else.
fn stub_charge(owner: Address) -> ConsensusReceipt {
    let mut writes = StateWrites::default();
    writes.movements.insert(
        charge_of(owner),
        Movement {
            resource: RESOURCE,
            credit: FLOOR,
            debit: 0,
        },
    );
    let receipt_hash = GlobalReceipt::new(
        true,
        EventRoot::ZERO,
        BeaconWitnessRoot::ZERO,
        writes_root(&writes),
    )
    .receipt_hash();
    ConsensusReceipt::Succeeded {
        receipt_hash,
        writes,
        beacon_witness_events: Vec::new(),
        events: Vec::new(),
    }
}

/// A committed `Finalization` settling `tick_id`, accepting every member.
///
/// The harness places these in blocks of its own choosing, which is how a
/// test states a settlement order rather than observing one.
#[must_use]
pub fn settle(tick_id: &TickId, receipts: &[StoredReceipt]) -> Finalization {
    let outcomes: Vec<TxOutcome> = receipts
        .iter()
        .map(|receipt| {
            TxOutcome::new(
                receipt.tx_hash,
                ExecutionOutcome::Succeeded {
                    receipt_hash: receipt.consensus.receipt_hash(),
                },
            )
        })
        .collect();
    let ec = ExecutionCertificate::new(
        *tick_id,
        WeightedTimestamp::from_millis(tick_id.block_height().inner() * BLOCK_INTERVAL_MS),
        compute_global_receipt_root(&outcomes),
        outcomes,
        AggregateSignature::new([0u8; 96]),
        SignerBitfield::new(4),
    );
    Finalization::new(
        *tick_id,
        TickHalf::Determined,
        vec![Arc::new(ec)],
        receipts.to_vec(),
    )
}

/// A committed `Finalization` whose counterpart refused every member.
///
/// The local shard completed its half and carries the receipts to prove
/// it; the counterpart's certificate reports failure for the same
/// transactions, so the tick as a whole decided against them. Two
/// certificates for one tick is the ordinary cross-shard shape — what the
/// combine exists to reconcile.
#[must_use]
pub fn settle_refused_by_counterpart(
    tick_id: &TickId,
    counterpart: ShardId,
    receipts: &[StoredReceipt],
    charges: &[StoredReceipt],
) -> Finalization {
    // The local certificate reports what this shard did and names the
    // charge it holds against a refusal, which is what its own outcomes
    // carry. The stored receipts are the charges, because that is the
    // side of each outcome the tick's verdict selects.
    let outcomes: Vec<TxOutcome> = receipts
        .iter()
        .zip(charges)
        .map(|(receipt, charge)| {
            TxOutcome::with_fee(
                receipt.tx_hash,
                ExecutionOutcome::Succeeded {
                    receipt_hash: receipt.consensus.receipt_hash(),
                },
                charge.consensus.receipt_hash(),
            )
        })
        .collect();
    let local = ExecutionCertificate::new(
        *tick_id,
        WeightedTimestamp::from_millis(tick_id.block_height().inner() * BLOCK_INTERVAL_MS),
        compute_global_receipt_root(&outcomes),
        outcomes,
        AggregateSignature::new([0u8; 96]),
        SignerBitfield::new(4),
    );
    let refused: Vec<TxOutcome> = receipts
        .iter()
        .map(|receipt| TxOutcome::new(receipt.tx_hash, ExecutionOutcome::Failed))
        .collect();
    let remote_id = TickId::new(counterpart, tick_id.block_height());
    let remote = ExecutionCertificate::new(
        remote_id,
        WeightedTimestamp::from_millis(tick_id.block_height().inner() * BLOCK_INTERVAL_MS),
        compute_global_receipt_root(&refused),
        refused,
        AggregateSignature::new([0u8; 96]),
        SignerBitfield::new(4),
    );
    Finalization::new(
        *tick_id,
        TickHalf::Legs,
        vec![Arc::new(local), Arc::new(remote)],
        charges.to_vec(),
    )
}
