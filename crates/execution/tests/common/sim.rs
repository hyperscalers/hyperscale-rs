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
use hyperscale_engine::tick_select::terms_of;
use hyperscale_engine::{AllCodeRuns, ExecutedTx, PROTOCOL_RESOURCE};
use hyperscale_execution::action_handlers::{
    ExecutionOutputs, accumulate_tick_output, split_execution_outputs,
};
use hyperscale_execution::{
    CrossingIndexSlot, ExecCertStore, ExecutionCoordinator, FinalizationStore,
};
use hyperscale_hbor::Capped;
use hyperscale_storage::{
    Anchored, FeeHoldReading, FeeTerms, MemberIndex, MemberInputs, MemberSections, RecoveredState,
    ReplayWindow, SubstateStore, Substates, TickChain, TickOutput, TickResolution, VersionedStore,
    fate_writes, filter_state_writes_to_prefix, merge_writes_from_receipts, settle_writes,
    with_fee_holds,
};
use hyperscale_types::test_utils::{
    StubVmStatics, TestCommittee, certify, make_live_block, naming,
};
use hyperscale_types::{
    Address, AggregateSignature, BeaconWitnessRoot, Block, BlockHeight, CertifiedBlock,
    ConsensusReceipt, CounterpartMirror, DeclaredRange, Epoch, EpochWindows, EventRoot,
    ExecutionCertificate, ExecutionMetadata, ExecutionOutcome, Finalization, GlobalReceipt,
    LocalKey, MerkleInclusionProof, Movement, ProvenAnchors, ProvisionEntry, Provisions,
    RecoveryCause, ResourceAddr, SettledWrites, ShardId, ShardRecovery, ShardTrie, SignerBitfield,
    StateRoot, StateWrites, StatedTerms, StoredReceipt, SubstateKey, TickHalf, TickId, TickLine,
    TopologySchedule, TopologySnapshot, Transaction, TxHash, TxOutcome, ValidatorId, Verifiable,
    Verified, WeightedTimestamp, compute_global_receipt_root, encode_amount, read_amount,
    shard_prefix_path, writes_root,
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

    fn hold_retention_at(&self, _height: BlockHeight) {}
}

/// A tick dispatched but not yet completed.
struct PendingBatch {
    tick: BlockHeight,
    /// The fates its coordinator held for it at dispatch.
    fates: Vec<TickResolution>,
    requests: Vec<CrossShardExecutionRequest>,
    /// The fee terms of the transactions its block carries.
    included: Vec<FeeTerms>,
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
    /// Whether each commit's write is acknowledged as it lands, to the
    /// tick chain and then to the coordinator, as the shard loop does on
    /// `BlockPersisted`.
    persisting: bool,
    /// The settled state every tick reads through, so the harness models
    /// the whole path: a committed certificate's receipts land here in
    /// commit order, exactly as `merge_writes_from_receipts` lands them in
    /// the JMT.
    base: Arc<StubBase>,
    local_shard: ShardId,
    /// The vault each of these transactions empties when it runs.
    spending: BTreeMap<TxHash, SubstateKey>,
    /// Whether the schedule has a window per block, which a recovery
    /// gives it.
    windowed: bool,
    /// Below this epoch the windows hold the snapshot as it stood before
    /// the beacon stamped the recovery, as the windows a beacon froze
    /// before its fold do.
    unstamped: Option<(Epoch, Arc<TopologySnapshot>)>,
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
        let topology = TopologySchedule::single(Arc::clone(&snapshot));
        let mut coord = ExecutionCoordinator::new(local_shard, Arc::new(AllCodeRuns));
        let _ = coord.attach_signer(&topology, ValidatorId::new(0));
        Self {
            coord,
            topology,
            snapshot,
            chain: Arc::new(TickChain::new(Arc::clone(&base))),
            schedule,
            pending: VecDeque::new(),
            height: BlockHeight::GENESIS,
            outputs: Vec::new(),
            receipts: BTreeMap::new(),
            charges: BTreeMap::new(),
            committed: Vec::new(),
            persisting: true,
            base,
            local_shard,
            spending: BTreeMap::new(),
            windowed: false,
            unstamped: None,
        }
    }

    /// A replica seated fresh at `height`: its coordinator holds the
    /// committed state there and no tick chain below it, as a halt
    /// recovery's snap-synced committee does at the attested frontier.
    #[must_use]
    pub fn seated_at(schedule: Schedule, height: BlockHeight) -> Self {
        let mut sim = Self::new(schedule);
        sim.height = height;
        let recovered = RecoveredState {
            committed_height: height,
            ..RecoveredState::default()
        };
        sim.coord = ExecutionCoordinator::with_shared_stores(
            sim.local_shard,
            Arc::new(AllCodeRuns),
            Arc::new(CrossingIndexSlot::default()),
            &recovered,
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::new(ProvenAnchors::new()),
            Arc::new(CounterpartMirror::new()),
            height,
        );
        let _ = sim.coord.attach_signer(&sim.topology, ValidatorId::new(0));
        sim.seat_on_store_at(height);
        sim
    }

    /// Seat the tick chain over a store already written through
    /// `height`, as a host does when it opens a shard: the chain learns
    /// what its base carries, as the coordinator built over it did.
    fn seat_on_store_at(&self, height: BlockHeight) {
        self.chain
            .prune_persisted(height, self.coord.baseline_floor());
    }

    /// Acknowledge the write of every block committed so far, in the
    /// shard loop's order: the chain evicts the folds the base now
    /// covers, then the coordinator releases the tick that was waiting
    /// to read it.
    fn acknowledge_writes(&mut self) {
        self.chain
            .prune_persisted(self.height, self.coord.baseline_floor());
        let actions = self.coord.on_block_persisted(&self.topology, self.height);
        self.absorb(actions);
    }

    /// Write every block committed so far, then run whatever the
    /// schedule releases: what ends a [`Self::withhold_persistence`].
    pub fn persist(&mut self) {
        self.acknowledge_writes();
        self.release_due();
    }

    /// The beacon records a halt recovery of this shard at `frontier`
    /// whose bridge is `bridge`: the schedule's head carries it from the
    /// next commit on.
    ///
    /// From here on the schedule has a window per block: the block at
    /// height `n` is anchored in epoch `n`, so the block at the bridge's
    /// height is the shard's crossing block and every block below it is
    /// anchored below the bridge. The windows from the bridge on carry
    /// the recovery and every window below it the snapshot as it stood,
    /// as the beacon stamps it.
    pub fn recover(&mut self, frontier: BlockHeight, bridge: Epoch) {
        let before = Arc::clone(&self.snapshot);
        let recorded = (*self.snapshot)
            .clone()
            .with_pending_recoveries(BTreeMap::from([(
                self.local_shard,
                ShardRecovery {
                    cause: RecoveryCause::Halt,
                    rotated_at: bridge.saturating_sub(1),
                    retained: Vec::new(),
                    attested_frontier: frontier,
                },
            )]));
        self.snapshot = Arc::new(recorded);
        self.topology = TopologySchedule::new(
            EpochWindows::new(0, BLOCK_INTERVAL_MS),
            Epoch::GENESIS,
            Arc::clone(&self.snapshot),
        );
        self.windowed = true;
        self.unstamped = Some((bridge, before));
        for epoch in 0..self.height.inner() {
            self.open_window(Epoch::new(epoch));
        }
        self.open_windows();
    }

    /// Hold the window of `epoch`, stamped or not as [`Self::recover`]
    /// says.
    fn open_window(&mut self, epoch: Epoch) {
        let snapshot = match &self.unstamped {
            Some((from, before)) if epoch < *from => Arc::clone(before),
            _ => Arc::clone(&self.snapshot),
        };
        self.topology.insert(epoch, snapshot);
    }

    /// The epoch the next block is anchored in, once a recovery has given
    /// the schedule a window per block: a bridge there makes the next
    /// block the shard's crossing block.
    #[must_use]
    pub const fn next_epoch(&self) -> Epoch {
        Epoch::new(self.height.inner() + 1)
    }

    /// Hold a window for the tip's epoch through the one after the next
    /// block's, where the schedule has a window per block.
    fn open_windows(&mut self) {
        if !self.windowed {
            return;
        }
        for epoch in self.height.inner()..=self.height.inner() + 2 {
            self.open_window(Epoch::new(epoch));
        }
    }

    /// The committee anchor of the block at the tip, as the shard hands
    /// it to execution: its parent's anchor, the clock the block is built
    /// and voted under.
    const fn committee_anchor(&self) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(self.height.inner().saturating_sub(1) * BLOCK_INTERVAL_MS)
    }

    /// Commit a block carrying `txs` and `certificates`, then run whatever
    /// the schedule releases.
    pub fn commit(&mut self, txs: Vec<Transaction>, certificates: Vec<Finalization>) {
        self.commit_block(txs, certificates, None);
    }

    /// Commit a block whose manifest names `lines`, seated as a
    /// proposer's block is: off the manifest, with nothing composed from
    /// this node's own inputs.
    pub fn commit_naming(&mut self, lines: Vec<TickLine>) {
        self.commit_block(Vec::new(), Vec::new(), Some(lines));
    }

    /// Commit a block carrying `txs` and `certificates`, seating the
    /// members `manifest` names where it is given and the ones this
    /// node's own inputs name where it is not.
    fn commit_block(
        &mut self,
        txs: Vec<Transaction>,
        certificates: Vec<Finalization>,
        manifest: Option<Vec<TickLine>>,
    ) {
        self.height = self.height.next();
        self.open_windows();
        // Settlement: the block's certificates' receipts reach state
        // here, folded in commit order and resolved once against what
        // the block below left — the same projection
        // `merge_writes_from_receipts` performs into the JMT. The commit
        // fold's fee holds land with them: a hold for each transaction
        // the block carries, and the end of each one a receipt releases,
        // so the base holds what a tick's floor reads.
        let settling: Vec<StoredReceipt> = certificates
            .iter()
            .flat_map(Finalization::settling_receipts)
            .collect();
        let fees: Vec<FeeTerms> = txs.iter().map(FeeTerms::of).collect();
        let prior = self.base.snapshot();
        let settled = with_fee_holds(
            merge_writes_from_receipts(&settling, &prior),
            &fees,
            &prior,
            &shard_prefix_path(self.local_shard),
        );
        if !settled.is_empty() {
            self.base.apply(self.height, &settled);
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
        let committee_anchor = self.committee_anchor();
        let effects = match manifest {
            Some(lines) => self.coord.commit_block(
                &self.topology,
                &naming(&certified, lines),
                committee_anchor,
            ),
            None => self
                .coord
                .commit_block_composing(&self.topology, &certified, committee_anchor),
        };
        // The fates the block names burn in its own fold, after its
        // receipts: each takes its charge and ends its hold in the base
        // this block leaves.
        let prefix = shard_prefix_path(self.local_shard);
        let manifest = Capped::new(effects.named.clone()).expect("a tick's lines fit a manifest");
        let fated = filter_state_writes_to_prefix(&fate_writes(&manifest), &prefix);
        if !fated.is_empty() {
            let prior = self.base.snapshot();
            let burned = with_fee_holds(settle_writes(&fated, &prior), &[], &prior, &prefix);
            self.base.apply(self.height, &burned);
        }
        // Kept naming what its commit seated, as a proposer's block
        // would, so a replay seats the same members.
        self.committed
            .push(Verified::<CertifiedBlock>::from_persisted(naming(
                &certified,
                effects.named,
            )));
        self.absorb(effects.actions);
        // Persistence follows the commit.
        if self.persisting {
            self.acknowledge_writes();
        }
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
            Capped::new(
                tx_hashes
                    .iter()
                    .map(|h| ProvisionEntry::new(*h, Capped::from_array([])))
                    .collect(),
            )
            .expect("a list written out in a test"),
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
                provisions: Arc::new(Capped::from_array([Arc::new(Verifiable::from(bundle))])),
                abandonment_records,
                state_claims,
                tick_manifest: Arc::new(Capped::empty()),
                terms: Arc::new(Capped::empty()),
                witness_sources,
            },
            sealed @ Block::Sealed { .. } => sealed,
        };
        let certified = certify(block, self.height.inner() * BLOCK_INTERVAL_MS);
        let committee_anchor = self.committee_anchor();
        let effects =
            self.coord
                .commit_block_composing(&self.topology, &certified, committee_anchor);
        // Kept naming what its commit seated, as a proposer's block
        // would, so a replay seats the same members.
        self.committed
            .push(Verified::<CertifiedBlock>::from_persisted(naming(
                &certified,
                effects.named,
            )));
        self.absorb(effects.actions);
        if self.persisting {
            self.acknowledge_writes();
        }
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
                Action::ExecuteTransactions {
                    tick,
                    fates,
                    requests,
                    included,
                    ..
                } => {
                    let release_at = match self.schedule {
                        Schedule::Eager => self.height,
                        Schedule::Lagged(n) => BlockHeight::new(
                            self.height.inner() + u64::try_from(n).expect("lag fits"),
                        ),
                    };
                    self.pending.push_back(PendingBatch {
                        tick,
                        fates,
                        requests,
                        included,
                        release_at,
                    });
                }
                Action::ResolveTicks { resolutions } => {
                    for (tick_id, resolution) in &resolutions {
                        self.chain.resolve(tick_id, resolution);
                    }
                }
                Action::ClearTickChain => self.chain.clear(),
                Action::RaiseTickFloor { floor } => {
                    self.chain.raise_floor(floor, self.local_shard);
                    self.chain.seed_stated(&self.member_rows());
                }
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
        let (tick, outcome) = self.execute(batch);
        self.coord
            .on_execution_batch_completed(&self.topology, tick, outcome)
    }

    /// The handler's half of a tick, which ends at the append: the
    /// result is in hand and the coordinator has not heard of it.
    fn execute(&mut self, batch: PendingBatch) -> (BlockHeight, TickBatchOutcome) {
        let PendingBatch {
            tick,
            fates,
            requests,
            included,
            ..
        } = batch;
        let view = self
            .chain
            .view_at(BlockHeight::new(tick.inner().saturating_sub(1)));
        let snapshot = view.snapshot();
        let trie = self.snapshot.shard_trie();
        let holds = view.holds();
        let fee_holds = view.fee_holds(&included, &shard_prefix_path(self.local_shard));

        let tick_id = TickId::new(self.local_shard, tick);
        // What the batch's spenders have already taken from each vault,
        // as the engine's running fold carries it between members.
        let mut taken: BTreeMap<SubstateKey, u128> = BTreeMap::new();
        let executed: Vec<ExecutedTx> = requests
            .iter()
            .map(|request| {
                let tx = &request.transaction;
                let spend = self.spending.get(&request.tx_hash).map(|vault| {
                    let held: u128 = holds
                        .get(vault)
                        .map_or(0, |legs| legs.values().copied().sum());
                    let taken = taken.entry(*vault).or_default();
                    // Every fee hold standing on the vault but the
                    // spender's own, which ends with it: the stub burns
                    // no price, so the whole of its own hold is its to
                    // spend.
                    let promised = fee_holds
                        .standing(*vault)
                        .saturating_sub(fee_holds.own(*vault, request.tx_hash));
                    let spendable = amount(snapshot.cell(*vault))
                        .saturating_sub(held)
                        .saturating_sub(promised)
                        .saturating_sub(*taken);
                    *taken += spendable;
                    (*vault, spendable)
                });
                stub_execute(
                    &snapshot,
                    trie,
                    self.local_shard,
                    request.tx_hash,
                    tx,
                    request.member.abortable(),
                    spend,
                )
            })
            .collect();
        let mut output = TickOutput::default();
        accumulate_tick_output(&mut output, &requests, &executed);
        let ExecutionOutputs {
            outcomes,
            results,
            refusal_receipts,
        } = split_execution_outputs(executed);
        self.receipts
            .entry(tick_id)
            .or_default()
            .extend(results.iter().cloned());
        self.charges
            .entry(tick_id)
            .or_default()
            .extend(refusal_receipts.iter().cloned());
        let outcome = TickBatchOutcome {
            tick_id,
            results,
            tx_outcomes: outcomes,
            refusal_receipts,
        };

        self.outputs.push((tick, output.clone()));
        self.chain.append(tick, output, &fates);
        (tick, outcome)
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
        self.restart_replaying(BlockHeight::new(1), BlockHeight::GENESIS);
    }

    /// Restart this replica as [`Self::restart`] does, over a store that
    /// hands back the committed blocks from `replay_from` up and answers
    /// for no baseline below the one `dispatch_from` reads: every tick
    /// the replay seats below `dispatch_from` is held, and a transaction
    /// committed below `replay_from` is one this replica's ledger never
    /// hears of.
    pub fn restart_replaying(&mut self, replay_from: BlockHeight, dispatch_from: BlockHeight) {
        self.coord = self.restored(replay_from, dispatch_from, self.height);
        self.chain = Arc::new(TickChain::new(Arc::clone(&self.base)));
        self.seat_on_store_at(self.height);
        self.pending.clear();
        let effects = self
            .coord
            .on_committed_state_restored(&self.topology, &StubVmStatics);
        self.absorb(effects.actions);
        self.drain();
    }

    /// A coordinator restored over a store that hands back the committed
    /// blocks from `replay_from` up and answers for no baseline below
    /// the one `dispatch_from` reads, written through `persisted_base`.
    fn restored(
        &self,
        replay_from: BlockHeight,
        dispatch_from: BlockHeight,
        persisted_base: BlockHeight,
    ) -> ExecutionCoordinator {
        let blocks: Vec<Verified<CertifiedBlock>> = self
            .committed
            .iter()
            .filter(|certified| certified.block().height() >= replay_from)
            .cloned()
            .collect();
        // The clock of the block below the window, which the first block
        // replayed carries forward.
        let anchor_wt = replay_from
            .prev()
            .filter(|below| *below > BlockHeight::GENESIS)
            .map(|below| WeightedTimestamp::from_millis(below.inner() * BLOCK_INTERVAL_MS));
        let recovered = RecoveredState {
            committed_height: self.height,
            replay: ReplayWindow {
                blocks,
                dispatch_from,
                anchor_wt,
            },
            ..RecoveredState::default()
        };
        let mut coord = ExecutionCoordinator::with_shared_stores(
            self.local_shard,
            Arc::new(AllCodeRuns),
            Arc::new(CrossingIndexSlot::default()),
            &recovered,
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::new(ProvenAnchors::new()),
            Arc::new(CounterpartMirror::new()),
            persisted_base,
        );
        let _ = coord.attach_signer(&self.topology, ValidatorId::new(0));
        coord
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

    /// The finalizations a proposal would carry, in the order it would
    /// carry them.
    #[must_use]
    pub fn offered(&self) -> Vec<Finalization> {
        self.coord
            .get_finalizations()
            .iter()
            .map(|fw| fw.as_unverified().clone())
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

    /// Cast every vote the coordinator has ready and hand each back as
    /// the certificate its committee would aggregate, returning the
    /// finalizations the coordinator then offers for those ticks.
    ///
    /// The outcomes and the receipts are the coordinator's own; only the
    /// tally is stood in for, as [`Self::admit`] stands in for the gate.
    pub fn certify_votable(&mut self) -> Vec<Finalization> {
        let mut certified = Vec::new();
        for action in self.coord.emit_vote_actions(&self.topology) {
            let Action::SignAndSendExecutionVote {
                vote_anchor_ts,
                tick_id,
                global_receipt_root,
                tx_outcomes,
                ..
            } = action
            else {
                continue;
            };
            let certificate = ExecutionCertificate::new(
                tick_id,
                vote_anchor_ts,
                global_receipt_root,
                Capped::new(tx_outcomes).expect("a tick's outcomes fit a certificate"),
                AggregateSignature::new([0u8; 96]),
                SignerBitfield::new(4),
            );
            let actions = self.coord.on_certificate_aggregated(
                &self.topology,
                &tick_id,
                &Arc::new(Verified::new_unchecked_for_test(certificate)),
            );
            self.absorb(actions);
            certified.push(tick_id);
        }
        self.coord
            .get_finalizations()
            .iter()
            .filter(|fw| certified.contains(fw.tick_id()))
            .map(|fw| fw.as_unverified().clone())
            .collect()
    }

    /// Seed `vault` with `amount` in the settled base at genesis, as a
    /// genesis-funded account holds it. Called before the first commit.
    pub fn fund(&self, vault: SubstateKey, amount: u128) {
        self.base.apply(
            BlockHeight::GENESIS,
            &SettledWrites::from_absolutes(BTreeMap::from([(
                vault,
                Some(encode_amount(amount).to_vec()),
            )])),
        );
    }

    /// Have `tx` empty `vault` when it runs: a judged debit of the whole
    /// balance its tick's baseline shows, less what unresolved legs hold
    /// of it and less every fee hold standing on it but `tx`'s own.
    ///
    /// The harness's stand-in for a transfer of a payer's full balance.
    /// No kernel judges it: the amount is read off the baseline the way
    /// the kernel's floor for one movement is, and nothing here checks
    /// the debit against the state it later settles on.
    pub fn spend_all(&mut self, tx: TxHash, vault: SubstateKey) {
        self.spending.insert(tx, vault);
    }

    /// Stop acknowledging writes: every later block commits and stays
    /// unwritten until [`Self::persist`].
    pub const fn withhold_persistence(&mut self) {
        self.persisting = false;
    }

    /// The committed clock at the tip: what a transaction's validity has
    /// to cover for the next block to seat it.
    #[must_use]
    pub const fn now(&self) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(self.height.inner() * BLOCK_INTERVAL_MS)
    }

    /// Every block committed, each naming the lines its commit seated.
    #[must_use]
    pub fn committed(&self) -> &[Verified<CertifiedBlock>] {
        &self.committed
    }

    /// The member rows every block committed leaves: each block's
    /// transactions on the terms the committee derives for them, its
    /// finalizations, and the lines its commit seated.
    #[must_use]
    pub fn member_rows(&self) -> MemberIndex {
        let mut rows = MemberIndex::empty(self.local_shard);
        for certified in &self.committed {
            let block = certified.block();
            let header = block.header();
            let terms = block
                .transactions()
                .iter()
                .map(|tx| StatedTerms {
                    tx: tx.hash(),
                    terms: terms_of(tx.as_unverified(), &self.snapshot, self.local_shard),
                })
                .collect();
            rows.advance(&MemberInputs {
                manifest: Arc::new(block.tick_manifest().clone()),
                ..MemberInputs::deriving(
                    self.local_shard,
                    header.height(),
                    header.parent_qc().weighted_timestamp(),
                    block.transactions().iter().map(|tx| tx.as_unverified()),
                    MemberSections {
                        certificates: block.certificates(),
                        records: block.abandonment_records(),
                        claims: block.state_claims(),
                    },
                    EpochWindows::new(0, 0),
                    terms,
                )
            });
        }
        rows
    }

    /// The committee every block of the fixture is classified under.
    #[must_use]
    pub fn snapshot(&self) -> &TopologySnapshot {
        &self.snapshot
    }

    /// The height of the last block committed.
    #[must_use]
    pub const fn height(&self) -> BlockHeight {
        self.height
    }

    /// The anchor the next block commits under: the clock its tick is
    /// composed against.
    #[must_use]
    pub const fn next_anchor(&self) -> WeightedTimestamp {
        WeightedTimestamp::from_millis((self.height.inner() + 1) * BLOCK_INTERVAL_MS)
    }

    /// How many ticks the chain retains an entry for.
    #[must_use]
    pub fn retained_ticks(&self) -> usize {
        self.chain.len()
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
/// and credit the same owner's vault. One named in `spend` also debits
/// that vault by that amount, judged. Where this shard holds the payer's
/// vault the writes end the transaction's fee hold, as the engine's do in
/// the write set that burns the price.
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
    spend: Option<(SubstateKey, u128)>,
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
            unjudged_debit: 0,
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
    if let Some((vault, spent)) = spend {
        movements.insert(vault, Movement::debit(*PROTOCOL_RESOURCE, spent));
    }
    let fee = FeeTerms::of(tx);
    let hold = (trie.shard_for_prefix(fee.vault.owner) == local_shard).then(|| fee.hold_key());
    if let Some(hold) = hold {
        cells.insert(hold, None);
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
            beacon_witness_events: Capped::empty(),
            events: Capped::empty(),
        },
        ExecutionMetadata::empty(),
    );
    // A leg a tick can still discard carries its charge beside its
    // effects, exactly as the engine builds one for a cross-shard
    // member. Which of the two settles is the tick's decision, not this
    // shard's.
    if abortable {
        executed.refusal_receipt = charged.map(|owner| stub_charge(owner, hold));
    }
    executed
}

/// The receipt a refused leg settles: the abort floor and the end of the
/// fee hold at `hold`, and nothing else.
fn stub_charge(owner: Address, hold: Option<SubstateKey>) -> ConsensusReceipt {
    let mut writes = StateWrites::default();
    if let Some(hold) = hold {
        writes.cells.insert(hold, None);
    }
    writes.movements.insert(
        charge_of(owner),
        Movement {
            resource: RESOURCE,
            credit: FLOOR,
            debit: 0,
            unjudged_debit: 0,
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
        beacon_witness_events: Capped::empty(),
        events: Capped::empty(),
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
        Capped::new(outcomes).expect("a list written out in a test"),
        AggregateSignature::new([0u8; 96]),
        SignerBitfield::new(4),
    );
    Finalization::new(
        *tick_id,
        TickHalf::Determined,
        Some(ec),
        Capped::new(receipts.to_vec()).expect("a list written out in a test"),
    )
}
