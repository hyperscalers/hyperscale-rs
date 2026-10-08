//! Shared state types for simulated storage.
//!
//! Contains the internal state structures protected by `RwLocks` in `SimShardStorage`.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_hbor::{
    HborDecode, HborEncode, from_slice as hbor_from_slice, to_vec as hbor_to_vec,
};
use hyperscale_jmt::NodeKey;
use hyperscale_storage::tree::{jmt_parent_height, put_at_version};
use hyperscale_storage::{
    BlockRows, Indexed, JmtSnapshot, RowChange, SweepRows, entry_leaf_rows, index_leaf,
    retire_dated,
};
use hyperscale_types::{
    BeaconWitnessLeafCount, Block, BlockHash, BlockHeight, BlockMetadata, CertifiedBlock,
    CertifiedBlockHeader, ChainOrigin, ConsensusReceipt, EntryKey, Finalization, FinalizationHash,
    GlobalReceiptHash, Hash, ProvisionHash, Provisions, QuorumCertificate, SafeVoteRegisters,
    SettledWrites, ShardWitnessPayload, StateRoot, StoredReceipt, SubstateKey, Transaction, TxHash,
    ValidatorId, Verified, WeightedTimestamp,
};
use im::{OrdMap, OrdSet};

use super::tree_store::SimTreeStore;

// ═══════════════════════════════════════════════════════════════════════
// Shared substate + JMT state (single RwLock)
// ═══════════════════════════════════════════════════════════════════════

/// Current value per substate key.
pub type Cells = OrdMap<SubstateKey, Arc<[u8]>>;

/// Prior value per `(key, write_version)`; `None` when the key was absent
/// before that write.
pub type CellHistory = OrdMap<(SubstateKey, u64), Option<Arc<[u8]>>>;

/// Current value per ordered-collection entry.
pub type Entries = OrdMap<EntryKey, Arc<[u8]>>;

/// Prior value per `(entry key, write_version)`, mirroring [`CellHistory`].
pub type EntryHistory = OrdMap<(EntryKey, u64), Option<Arc<[u8]>>>;

/// Substate data and JMT state protected by a single `RwLock`.
///
/// Using `RwLock` (instead of Mutex) allows concurrent read access: speculative
/// JMT computations from `prepare_block_commit` take a read lock and can run
/// concurrently with other readers, while commits take a write lock.
///
/// The substate maps are persistent: a snapshot clones them by sharing
/// their structure, so taking one costs the same whatever the state holds,
/// and a write after it copies only the path it touches. Values are shared
/// slices for the same reason — a copied path carries pointers, not bytes.
#[derive(Clone)]
pub struct SharedState {
    pub(crate) tree_store: SimTreeStore,
    pub(crate) current_block_height: BlockHeight,
    pub(crate) current_root_hash: StateRoot,
    /// Current value per substate key. Absent key = no value. This is
    /// the authoritative source of truth for reads at the current tip.
    pub(crate) current_state: Cells,
    /// Per-write prior-value entries keyed by `(key, write_version)`.
    /// `None` means the key was absent immediately before the write at
    /// that version. Consumed by historical reads and the retention GC.
    pub(crate) state_history: CellHistory,
    /// Current value per ordered-collection entry — the order-native
    /// mirror of the entry leaves in `current_state`. Derived state: at
    /// every height it equals the tree's entry leaves.
    pub(crate) current_entries: Entries,
    /// Per-write prior-value entries for the entry index, mirroring
    /// `state_history` row for row.
    pub(crate) entries_history: EntryHistory,
    /// Each version's weighted timestamp, from the floor on; what
    /// [`retire_dated`] reads.
    pub(crate) version_time: OrdMap<u64, u64>,
    /// The oldest version historical reads are answered at.
    pub(crate) retention_floor: u64,
    /// The tree nodes each version superseded, keyed by that version:
    /// unreachable from its root and every later one, so reclaimed once
    /// the floor passes the version.
    pub(crate) stale_jmt_nodes: OrdMap<u64, Arc<[NodeKey]>>,
    /// Superseded tree nodes a pinned boundary still reaches, keyed by
    /// the newest pin reaching them and the version that superseded them.
    pub(crate) pinned_jmt_nodes: OrdMap<(BlockHeight, u64), Arc<[NodeKey]>>,
    /// The pins [`Self::pinned_jmt_nodes`] holds nodes under.
    pub(crate) holding_pins: OrdSet<BlockHeight>,
    /// The oldest version this node's own readers still name;
    /// `u64::MAX` until one holds. The floor never passes it.
    pub(crate) retention_hold: u64,
    /// Committed substate byte total per version, written in
    /// lockstep with each applied snapshot. Consensus-critical:
    /// shard-witness derivation reads it, so it must be identical on
    /// every replica.
    pub(crate) substate_bytes: OrdMap<u64, u64>,
    /// Committed package artifacts by content address — the mirror of
    /// the `RocksDB` backend's package index. Derived state: a committed
    /// cell that self-identifies as a package lands its bytes here in
    /// the same application that lands the cell.
    pub(crate) package_artifacts: OrdMap<Hash, Vec<u8>>,
    /// The sweep index — the mirror of the `RocksDB` backend's, fed
    /// from the same judgement so both backends enumerate the same
    /// candidates.
    pub(crate) sweep_index: SweepRows,
    /// The crossing index — the mirror of the `RocksDB` backend's: one
    /// key per committed crossing record or answer.
    pub(crate) crossing_index: OrdSet<SubstateKey>,
}

impl SharedState {
    /// Date `version` and move the floor past what that retires
    /// ([`retire_dated`]). Returns the floor this commit establishes.
    pub(crate) fn advance_retention_floor(
        &mut self,
        version: u64,
        tip_ts: WeightedTimestamp,
    ) -> u64 {
        self.version_time.insert(version, tip_ts.as_millis());
        let retired = retire_dated(
            self.retention_floor,
            version,
            self.retention_hold,
            tip_ts,
            self.version_time
                .range(self.retention_floor..)
                .map(|(dated, ts)| (*dated, *ts)),
        );
        for dated in &retired.versions {
            self.version_time.remove(dated);
        }
        self.retention_floor = retired.floor;
        retired.floor
    }

    /// Note the tree nodes the commit at `version` superseded.
    fn record_stale_jmt_nodes(&mut self, version: u64, keys: &[NodeKey]) {
        if !keys.is_empty() {
            self.stale_jmt_nodes.insert(version, Arc::from(keys));
        }
    }

    /// Drop the tree nodes nothing can reach any more: superseded below
    /// the retention floor, so no root a reader may name reaches them, and
    /// reached by none of `pins`. A pin reads the live tree at its height,
    /// so it holds what that root reaches as a production checkpoint holds
    /// its files; a node only a pin reaches waits under the newest such
    /// pin and is weighed again once that pin is trimmed.
    pub(crate) fn reclaim_stale_jmt_nodes(&mut self, pins: &OrdSet<BlockHeight>) {
        let released: Vec<BlockHeight> = self
            .holding_pins
            .iter()
            .filter(|pin| !pins.contains(pin))
            .copied()
            .collect();
        for pin in released {
            self.holding_pins.remove(&pin);
            let held: Vec<(u64, Arc<[NodeKey]>)> = self
                .pinned_jmt_nodes
                .range((pin, 0)..=(pin, u64::MAX))
                .map(|((_, stale_at), keys)| (*stale_at, Arc::clone(keys)))
                .collect();
            for (stale_at, keys) in held {
                self.pinned_jmt_nodes.remove(&(pin, stale_at));
                self.release_stale_jmt_nodes(stale_at, &keys, pins);
            }
        }
        while let Some((stale_at, keys)) = self.stale_jmt_nodes.get_min().cloned() {
            if stale_at >= self.retention_floor {
                break;
            }
            self.stale_jmt_nodes.remove(&stale_at);
            self.release_stale_jmt_nodes(stale_at, &keys, pins);
        }
    }

    /// Drop each of `keys`, superseded at `stale_at`, that no pin reaches,
    /// and hold the rest under the newest pin that does. A node written at
    /// version `v` and superseded at `stale_at` is in the tree at exactly
    /// the versions from `v` up to `stale_at`.
    fn release_stale_jmt_nodes(
        &mut self,
        stale_at: u64,
        keys: &[NodeKey],
        pins: &OrdSet<BlockHeight>,
    ) {
        let mut held: BTreeMap<BlockHeight, Vec<NodeKey>> = BTreeMap::new();
        for key in keys {
            let reaching = (key.version < stale_at)
                .then(|| {
                    pins.range(BlockHeight::new(key.version)..BlockHeight::new(stale_at))
                        .next_back()
                })
                .flatten();
            match reaching {
                Some(pin) => held.entry(*pin).or_default().push(key.clone()),
                None => self.tree_store.remove(key),
            }
        }
        for (pin, keys) in held {
            self.holding_pins.insert(pin);
            self.pinned_jmt_nodes
                .insert((pin, stale_at), Arc::from(keys));
        }
    }

    pub(crate) fn new() -> Self {
        Self {
            tree_store: SimTreeStore::new(),
            current_block_height: BlockHeight::GENESIS,
            current_root_hash: StateRoot::ZERO,
            current_state: OrdMap::new(),
            state_history: OrdMap::new(),
            current_entries: OrdMap::new(),
            entries_history: OrdMap::new(),
            version_time: OrdMap::new(),
            stale_jmt_nodes: OrdMap::new(),
            pinned_jmt_nodes: OrdMap::new(),
            holding_pins: OrdSet::new(),
            retention_floor: 0,
            retention_hold: u64::MAX,
            substate_bytes: OrdMap::new(),
            package_artifacts: OrdMap::new(),
            sweep_index: SweepRows::default(),
            crossing_index: OrdSet::new(),
        }
    }

    /// Apply a JMT snapshot directly, inserting precomputed nodes.
    ///
    /// The snapshot's tree nodes are consensus-verified (2f+1 validators
    /// agreed on the resulting state root). We apply unconditionally —
    /// the overlay may have computed from a base state ahead of the
    /// tree store, so `base_root` mismatches are expected and safe.
    pub(crate) fn apply_jmt_snapshot(&mut self, snapshot: &JmtSnapshot) {
        for (jmt_key, jmt_node) in &snapshot.nodes {
            self.tree_store
                .insert(jmt_key.clone(), Arc::clone(jmt_node));
        }
        self.record_stale_jmt_nodes(snapshot.new_height.inner(), &snapshot.stale_node_keys);

        // Substate bytes: the byte total behind the currently applied version
        // (equal across any interleaved empty commits) plus this
        // snapshot's leaf delta.
        let prior = self
            .substate_bytes
            .get(&self.current_block_height.inner())
            .copied()
            .unwrap_or(0);
        let count = prior
            .checked_add_signed(snapshot.bytes_delta)
            .expect("substate byte total must not go negative");
        self.substate_bytes
            .insert(snapshot.new_height.inner(), count);

        self.current_block_height = snapshot.new_height;
        self.current_root_hash = snapshot.result_root;
    }
}

/// Apply `updates` at `height` over the shared state — substate values
/// (with history), the JMT, the substate byte total, and the tip
/// version/root — and return the resulting root. The state-level half
/// of a block commit, shared by the chain writer's sync path and a
/// split observer's follow path.
pub fn apply_state_writes(
    s: &mut SharedState,
    writes: &SettledWrites,
    height: BlockHeight,
) -> StateRoot {
    apply_writes(s, writes, height.inner(), /* write_history */ true);

    let parent_version =
        jmt_parent_height(s.current_block_height, s.current_root_hash).map(BlockHeight::inner);
    let (new_root, collected) =
        put_at_version(&s.tree_store, parent_version, height.inner(), writes);

    for (key, node) in &collected.nodes {
        s.tree_store.insert(key.clone(), Arc::clone(node));
    }
    s.record_stale_jmt_nodes(height.inner(), &collected.stale_node_keys);

    // Substate bytes: prior byte total behind the current version plus
    // this application's leaf delta — same rule as `apply_jmt_snapshot`.
    let prior = s
        .substate_bytes
        .get(&s.current_block_height.inner())
        .copied()
        .unwrap_or(0);
    let count = prior
        .checked_add_signed(collected.bytes_delta)
        .expect("substate byte total must not go negative");
    s.substate_bytes.insert(height.inner(), count);

    s.current_block_height = height;
    s.current_root_hash = new_root;
    new_root
}

// ═══════════════════════════════════════════════════════════════════════
// Consolidated consensus state (single RwLock)
// ═══════════════════════════════════════════════════════════════════════

/// A stored row: a value HBOR-encoded exactly as the `RocksDB` backend's
/// column family holds it, decoded on every read.
pub type Row = Arc<[u8]>;

fn encode_row<T: HborEncode>(value: &T) -> Row {
    Arc::from(hbor_to_vec(value).expect("a stored row encodes"))
}

fn decode_row<T: HborDecode>(row: &[u8]) -> T {
    hbor_from_slice(row).expect("a stored row decodes")
}

/// All consensus-related metadata bundled into a single `RwLock`.
///
/// A committed block is kept as the rows the `RocksDB` backend writes,
/// never whole, and read back through the reconstruction both backends
/// share ([`reconstruct_block`](hyperscale_storage::reconstruct_block)).
#[derive(Clone)]
pub struct ConsensusState {
    /// Committed blocks' [`BlockMetadata`] rows by height.
    pub(crate) blocks: OrdMap<BlockHeight, Row>,
    /// Certified headers held without their blocks: the anchor a
    /// snap-sync imported, kept so this store serves the next joiner's
    /// witness history as one that committed the block would.
    pub(crate) boundary_headers: OrdMap<BlockHeight, Arc<CertifiedBlockHeader>>,
    /// Committed height.
    pub(crate) committed_height: BlockHeight,
    /// Committed block hash.
    pub(crate) committed_hash: Option<BlockHash>,
    /// Latest QC.
    pub(crate) committed_qc: Option<QuorumCertificate>,
    /// Committed transactions' wire bytes by hash.
    pub(crate) transactions: OrdMap<TxHash, Row>,
    /// Finalization attestations by their hash.
    pub(crate) certificates: OrdMap<FinalizationHash, Row>,
    /// Consensus receipts by transaction hash, then the receipt's own
    /// hash. Mirrors the production `consensus_receipts` CF.
    pub(crate) consensus_receipts: OrdMap<(TxHash, GlobalReceiptHash), Row>,
    /// Index: every finalization of this shard's carrying an outcome for
    /// a transaction, keyed by the transaction then the finalization's
    /// hash, its key in `certificates`. Mirrors the production
    /// `tx_finalizations` CF so simulation integration tests serve the
    /// by-transaction certificate fetch the same way a real node does.
    ///
    /// A set rather than a slot: a shard certifies one transaction its
    /// verdict and then again whatever settles what the verdict left —
    /// a retirement, a reclaim, an abandonment — and a counterpart that
    /// asks by naming the transaction cannot say which of them it
    /// wants.
    pub(crate) tx_finalizations: OrdSet<(TxHash, FinalizationHash)>,
    /// Beacon-witness leaves keyed by leaf index. Mirrors the production
    /// `RocksDB` `beacon_witnesses` CF so simulation integration tests
    /// can serve fetches and replay the accumulator on restart. Shard
    /// is implicit — storage is scoped per-shard.
    pub(crate) beacon_witnesses: OrdMap<u64, ShardWitnessPayload>,
    /// Provision bodies keyed by their committing height and hash.
    /// Mirrors the production `provisions` CF: a stored block keeps only
    /// the hashes, so this is what a replay reads the bodies back from.
    pub(crate) provisions: OrdMap<(BlockHeight, ProvisionHash), Arc<Provisions>>,
    /// The chain's origin — `ChainOrigin::ROOT` except for a split
    /// child's adopted store, where recovery must reconstruct the
    /// continued height line and clock.
    pub(crate) chain_origin: ChainOrigin,
    /// The height of the genesis this store installed: the network
    /// genesis ceremony's, or a reshape successor's adopted at its flip.
    pub(crate) installed_genesis: Option<BlockHeight>,
    /// The lowest height this store serves a block at.
    pub(crate) chain_floor: BlockHeight,
    /// Durable safe-vote register records keyed by validator, each
    /// tagged with the chain origin that wrote it. Mirrors the
    /// production `safe_vote_registers` CF; reads ignore records whose
    /// tag differs from the current `chain_origin`.
    pub(crate) safe_vote_registers: OrdMap<ValidatorId, (ChainOrigin, Arc<SafeVoteRegisters>)>,
    /// Blocks written beside a validator's safe-vote registers, keyed by
    /// height then hash and tagged with the chain origin that wrote them.
    /// Mirrors the production `voted_blocks` CF: the uncommitted chain
    /// behind the certificate the record carries, so a restarted
    /// validator can extend it. Dropped at or below the committed height
    /// on every commit — the hash in the key keeps a fork sibling from
    /// displacing its rival before then — and, like the registers,
    /// ignored by reads once the tag no longer matches.
    pub(crate) voted_blocks: OrdMap<(BlockHeight, BlockHash), (ChainOrigin, Arc<Block>)>,
}

impl ConsensusState {
    pub(crate) fn new() -> Self {
        Self {
            blocks: OrdMap::new(),
            boundary_headers: OrdMap::new(),
            committed_height: BlockHeight::new(0),
            committed_hash: None,
            committed_qc: None,
            transactions: OrdMap::new(),
            certificates: OrdMap::new(),
            consensus_receipts: OrdMap::new(),
            tx_finalizations: OrdSet::new(),
            beacon_witnesses: OrdMap::new(),
            provisions: OrdMap::new(),
            chain_origin: ChainOrigin::ROOT,
            installed_genesis: None,
            chain_floor: BlockHeight::GENESIS,
            safe_vote_registers: OrdMap::new(),
            voted_blocks: OrdMap::new(),
        }
    }

    /// Record the provision bodies a committing block carried, and drop
    /// every body below the retention floor — the depth a replay can
    /// still read state at, and so the depth one can start from. Mirrors
    /// `RocksDbShardStorage::append_provisions_to_batch`.
    pub(crate) fn record_provisions(&mut self, block: &Block, retention_floor: u64) {
        let height = block.height();
        let floor = BlockHeight::new(retention_floor);
        if floor > BlockHeight::GENESIS {
            let below: Vec<_> = self
                .provisions
                .keys()
                .take_while(|(at, _)| *at < floor)
                .copied()
                .collect();
            for key in below {
                self.provisions.remove(&key);
            }
        }
        for bundle in block.provisions() {
            self.provisions.insert(
                (height, bundle.hash()),
                Arc::new(bundle.as_unverified().clone()),
            );
        }
    }

    /// Drop the vote-justification blocks the chain has now committed.
    /// Everything at or below `committed` is durable as chain content,
    /// and a fork sibling at that height can no longer be extended.
    pub(crate) fn drop_voted_blocks_through(&mut self, committed: BlockHeight) {
        let through: Vec<_> = self
            .voted_blocks
            .keys()
            .take_while(|(at, _)| *at <= committed)
            .copied()
            .collect();
        for key in through {
            self.voted_blocks.remove(&key);
        }
    }

    /// Record a committed block's rows: its metadata stamped with
    /// `beacon_witness_leaf_count_at_block_end`, its transactions, its
    /// finalizations' attestations and the by-transaction index over
    /// this shard's own, and its provision bodies under
    /// `retention_floor`. Mirrors
    /// `RocksDbShardStorage::append_block_to_batch`, vote justifications
    /// at or below the height included.
    pub(crate) fn record_block(
        &mut self,
        block: &Block,
        qc: &Verified<QuorumCertificate>,
        beacon_witness_leaf_count_at_block_end: BeaconWitnessLeafCount,
        retention_floor: u64,
    ) {
        let metadata = BlockMetadata::from_block_with_witness_count(
            block,
            qc.clone(),
            beacon_witness_leaf_count_at_block_end,
        );
        self.blocks.insert(block.height(), encode_row(&metadata));
        self.drop_voted_blocks_through(block.height());
        self.record_transactions(block);
        let local_shard = block.header().shard_id();
        for fw in block.certificates().iter() {
            let hash = fw.receipt_hash();
            self.certificates
                .insert(hash, encode_row(&fw.attestation()));
            // Only a finalization of this shard's own tick is indexed,
            // and only for its local certificate: a counterpart's
            // certificate riding inside it answers a question nobody
            // asks this shard, and an asker served its own certificate
            // back refuses it as unsolicited and asks again.
            if fw.tick_id().shard_id() != local_shard {
                continue;
            }
            self.tx_finalizations.extend(
                fw.local_ec()
                    .tx_outcomes()
                    .iter()
                    .map(|outcome| (outcome.tx_hash(), hash)),
            );
        }
        self.record_provisions(block, retention_floor);
    }

    /// Record a block below the committed frontier: its metadata, its
    /// transactions, its attestations and the receipts its
    /// finalizations carry, and nothing a commit does around them.
    /// Mirrors `RocksDbShardStorage::append_historical_block_to_batch`.
    pub(crate) fn record_historical_block(&mut self, certified: &CertifiedBlock) {
        let block = certified.block();
        let metadata = BlockMetadata::from_block(block, certified.qc_verifiable().clone());
        self.blocks.insert(block.height(), encode_row(&metadata));
        self.record_transactions(block);
        for fw in block.certificates().iter() {
            self.certificates
                .insert(fw.receipt_hash(), encode_row(&fw.attestation()));
        }
        self.insert_receipts(block.certificates().iter().flat_map(|fw| fw.receipts()));
    }

    fn record_transactions(&mut self, block: &Block) {
        for tx in block.transactions().iter() {
            self.transactions
                .insert(tx.hash(), Arc::from(tx.cached_wire_bytes()));
        }
    }

    /// Store each receipt under its transaction and its own hash.
    pub(crate) fn insert_receipts<'a>(
        &mut self,
        receipts: impl IntoIterator<Item = &'a StoredReceipt>,
    ) {
        for receipt in receipts {
            self.consensus_receipts.insert(
                (receipt.tx_hash, receipt.consensus.receipt_hash()),
                encode_row(&*receipt.consensus),
            );
        }
    }

    /// Every consensus receipt `tx_hash` settled, decoded, in
    /// receipt-hash order.
    pub(crate) fn consensus_receipts_of(&self, tx_hash: &TxHash) -> Vec<Arc<ConsensusReceipt>> {
        self.consensus_receipts
            .range((*tx_hash, GlobalReceiptHash::from_raw(Hash::ZERO))..)
            .take_while(|((at, _), _)| at == tx_hash)
            .map(|(_, row)| Arc::new(decode_row(row)))
            .collect()
    }

    /// The finalization attestation stored under `id`, decoded.
    pub(crate) fn attestation(&self, id: &FinalizationHash) -> Option<Finalization> {
        self.certificates.get(id).map(|row| decode_row(row))
    }
}

impl BlockRows for ConsensusState {
    fn block_metadata(&self, height: BlockHeight) -> Option<BlockMetadata> {
        self.blocks.get(&height).map(|row| decode_row(row))
    }

    fn transactions(&self, hashes: &[TxHash]) -> Vec<Transaction> {
        hashes
            .iter()
            .filter_map(|hash| self.transactions.get(hash))
            .map(|row| decode_row(row))
            .collect()
    }

    fn attestations(&self, ids: &[FinalizationHash]) -> Vec<Finalization> {
        ids.iter().filter_map(|id| self.attestation(id)).collect()
    }

    fn consensus_receipt(
        &self,
        tx_hash: &TxHash,
        receipt_hash: &GlobalReceiptHash,
    ) -> Option<Arc<ConsensusReceipt>> {
        self.consensus_receipts
            .get(&(*tx_hash, *receipt_hash))
            .map(|row| Arc::new(decode_row(row)))
    }
}

/// Apply database updates to the substate store at `version`.
///
/// Each write mutates `current_state` directly. If `write_history` is
/// true, the pre-write value (or `None` if absent) is captured into
/// `state_history` at `(key_bytes, version)` before the write is
/// applied — this is the mechanism that lets historical reads at any
/// earlier version recover the value-at-that-version. Genesis and
/// other bootstrap paths pass `write_history: false` because there is
/// no pre-state to preserve.
pub fn apply_writes(
    state: &mut SharedState,
    writes: &SettledWrites,
    version: u64,
    write_history: bool,
) {
    // Each entry's leaf row rides the same state/history pipeline a
    // cell does; the index rows beside them keep range scans native.
    let leaf_rows = entry_leaf_rows(writes.entries());
    let mut sweep_rows = SweepRows::default();
    for (key, change) in writes.cells().iter().chain(&leaf_rows) {
        let prior = state.current_state.get(key).cloned();
        let Indexed { package, crossing } =
            index_leaf(*key, prior.as_deref(), change.as_deref(), &mut sweep_rows);
        if let (Some(package), Some(value)) = (package, change) {
            state.package_artifacts.insert(package, value.clone());
        }
        match crossing {
            RowChange::Put => {
                state.crossing_index.insert(*key);
            }
            RowChange::Delete => {
                state.crossing_index.remove(key);
            }
            RowChange::Keep => {}
        }
        if write_history {
            state.state_history.insert((*key, version), prior);
        }
        match change {
            Some(value) => {
                state
                    .current_state
                    .insert(*key, Arc::from(value.as_slice()));
            }
            None => {
                state.current_state.remove(key);
            }
        }
    }
    state.sweep_index.fold(&sweep_rows);
    for (key, change) in writes.entries() {
        let prior = state.current_entries.get(key).cloned();
        if write_history {
            state.entries_history.insert((*key, version), prior);
        }
        match change {
            Some(value) => {
                state
                    .current_entries
                    .insert(*key, Arc::from(value.as_slice()));
            }
            None => {
                state.current_entries.remove(key);
            }
        }
    }
}
