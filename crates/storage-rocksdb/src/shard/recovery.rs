//! Crash recovery for `RocksDB` storage.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_metrics::record_storage_operation;
use hyperscale_storage::{
    BoundaryStore, DedupWindow, RecoveredState, SafeVoteRegisterStore, SubstateStore, replay_window,
};
use hyperscale_types::{
    BeaconWitnessLeafCount, BlockHash, BlockHeight, BlockMetadata, ChainOrigin, CommittedTip, Hash,
    Provisions, SafeVoteRegisters, ShardId, ShardWitnessPayload, ValidatorId, WeightedTimestamp,
};

use super::column_families::{BeaconWitnessesCf, BlocksCf, ProvisionsCf, SafeVoteRegistersCf};
use super::core::RocksDbShardStorage;
use super::metadata::read_chain_origin;
use crate::typed_cf::{TypedCf, get, iter_all, iter_from};

impl RocksDbShardStorage {
    /// Load recovered state from storage for crash recovery.
    ///
    /// This should be called on startup before creating the state machine.
    /// Returns `RecoveredState::default()` for a fresh database.
    ///
    /// `shard` is the shard this store is resumed as, which narrows the
    /// escrow records to the ones it owns: a split child's cell column
    /// is a superset of its own leaves until the sibling's are
    /// compacted out of it.
    pub fn load_recovered_state(&self, shard: ShardId) -> RecoveredState {
        let start = std::time::Instant::now();
        let (committed_height, committed_hash, latest_qc) = self.get_chain_metadata();

        // Get current JMT state from storage - critical for correct state root computation.
        // Without this, the state machine would start with Hash::ZERO which causes
        // state root verification failures if the JMT has already advanced.
        //
        // Note: We always include JMT state, even at height 0, because genesis bootstrap
        // populates the JMT with the genesis flash at height 0 but with a non-zero root.
        // The height 0 case is handled correctly by the state machine.
        let jmt_block_height = self.jmt_height();
        let jmt_root = self.state_root();
        let jmt_root_opt = Some(jmt_root);

        // Recovery invariant: JMT version (= block height) must match committed_height.
        // Consensus metadata and the JMT commit share a single WriteBatch, so a
        // mismatch indicates storage corruption.
        if committed_height > BlockHeight::GENESIS && jmt_block_height != committed_height {
            tracing::error!(
                committed_height = committed_height.inner(),
                jmt_block_height = jmt_block_height.inner(),
                "RECOVERY: JMT version does not match committed height — \
                 this should not happen with atomic commits. Possible storage corruption."
            );
        }

        let beacon_witness_start = self.committed_witness_base(committed_height);
        let beacon_witness_leaf_hashes = self.load_beacon_witness_leaf_hashes(beacon_witness_start);

        let elapsed = start.elapsed().as_secs_f64();
        record_storage_operation("load_recovered_state", elapsed);

        tracing::info!(
            committed_height = committed_height.inner(),
            has_committed_hash = committed_hash.is_some(),
            has_latest_qc = latest_qc.is_some(),
            jmt_block_height = jmt_block_height.inner(),
            jmt_root = ?jmt_root,
            beacon_witness_start = beacon_witness_start.inner(),
            beacon_witness_leaf_count = beacon_witness_leaf_hashes.len(),
            load_time_ms = elapsed * 1000.0,
            "Loaded recovered state from storage"
        );

        let chain_origin = read_chain_origin(&*self.db);

        let committed_block_anchor_wt = self.anchor_ts_at(committed_height);
        RecoveredState {
            committed_height,
            // A restart reaches no reshape flip: the flip-time delivery
            // is gone with the process, and the roots come back off the
            // topology projection at the first beacon block committed
            // after boot. Empty means the strict pre-cut rule stands
            // until that lands.
            predecessors: Vec::new(),
            replay: replay_window(
                self,
                committed_height,
                committed_block_anchor_wt.unwrap_or(WeightedTimestamp::ZERO),
                BlockHeight::new(self.retention_floor()),
                chain_origin,
            ),
            dedup: DedupWindow::from_reader(
                self,
                committed_height,
                committed_block_anchor_wt.unwrap_or(WeightedTimestamp::ZERO),
                chain_origin,
            ),
            retained_provisions: self.load_retained_provisions(),
            committed_hash: committed_hash.map(BlockHash::from_raw),
            latest_qc,
            anchor_qc: None,
            committed_tip: self.committed_tip(committed_height),
            committed_block_anchor_wt,
            committed_committee_anchor_wt: committed_height
                .prev()
                .and_then(|parent_height| self.anchor_ts_at(parent_height)),
            jmt_root: jmt_root_opt,
            beacon_witness_start,
            beacon_witness_leaf_hashes,
            substate_bytes: self
                .substate_bytes_at_version(committed_height.inner())
                .unwrap_or(0),
            chain_origin,
            safe_vote_registers: self.load_safe_vote_registers(chain_origin),
            escrow_records: self.escrow_records(shard),
            voted_blocks: self.voted_blocks_above(committed_height),
        }
    }

    /// Durable safe-vote register records whose chain-origin tag matches
    /// the store's current origin. Records inherited through a
    /// checkpoint-seeded child store carry the parent's origin and are
    /// excluded — the child chain's round numbering is unrelated.
    fn load_safe_vote_registers(
        &self,
        origin: ChainOrigin,
    ) -> BTreeMap<ValidatorId, SafeVoteRegisters> {
        let cf = self.cf();
        iter_all::<SafeVoteRegistersCf>(&self.db, SafeVoteRegistersCf::handle(&cf))
            .filter_map(|(validator, (record_origin, registers))| {
                (record_origin == origin).then_some((validator, registers))
            })
            .collect()
    }

    /// Weighted timestamp of the parent QC on the stored header at `height` —
    /// that block's own position on the weighted-time grid. Read at the
    /// committed height it anchors the tip, and one below it the committee
    /// that signed the tip. `None` when no block is stored there (fresh start
    /// / genesis tip, or a parent pruned past retention), where the
    /// coordinator falls back a hop.
    fn anchor_ts_at(&self, height: BlockHeight) -> Option<WeightedTimestamp> {
        let cf = self.cf();
        let blocks_cf = BlocksCf::handle(&cf);
        let metadata: BlockMetadata = get::<BlocksCf>(&*self.db, blocks_cf, &height.inner())?;
        Some(metadata.header().parent_qc().weighted_timestamp())
    }

    /// The committed tip's running values, read from its stored header.
    /// `None` when no block is stored at `committed_height` (fresh start /
    /// genesis tip), where the coordinator seeds the genesis tip.
    fn committed_tip(&self, committed_height: BlockHeight) -> Option<CommittedTip> {
        let cf = self.cf();
        let blocks_cf = BlocksCf::handle(&cf);
        let metadata: BlockMetadata =
            get::<BlocksCf>(&*self.db, blocks_cf, &committed_height.inner())?;
        Some(metadata.header().committed_tip())
    }

    /// The committed tip's witness window base, read from its stored
    /// header. `ZERO` when no block is stored at `committed_height`
    /// (fresh start / genesis tip).
    fn committed_witness_base(&self, committed_height: BlockHeight) -> BeaconWitnessLeafCount {
        let cf = self.cf();
        let blocks_cf = BlocksCf::handle(&cf);
        get::<BlocksCf>(&*self.db, blocks_cf, &committed_height.inner())
            .map_or(BeaconWitnessLeafCount::ZERO, |metadata: BlockMetadata| {
                metadata.header().beacon_witness_base()
            })
    }

    /// Read the retained beacon-witness leaves at or above `start` from
    /// the [`BeaconWitnessesCf`](crate::column_families::BeaconWitnessesCf)
    /// in key order and hash each payload through
    /// [`ShardWitnessPayload::leaf_hash`]. The result feeds
    /// [`BeaconWitnessAccumulator::from_leaves`](../../crates/shard/src/beacon_witnesses.rs)
    /// at coordinator startup. Entries below `start` are the
    /// persistence layer's hysteresis stock — serving data, not
    /// accumulator state.
    fn load_beacon_witness_leaf_hashes(&self, start: BeaconWitnessLeafCount) -> Vec<Hash> {
        let cf = self.cf();
        let beacon_witnesses_cf = BeaconWitnessesCf::handle(&cf);
        iter_from::<BeaconWitnessesCf>(&self.db, beacon_witnesses_cf, &start.inner())
            .map(|(_leaf_index, payload): (_, ShardWitnessPayload)| payload.leaf_hash())
            .collect()
    }

    /// Every provision body still retained, for the shared store a
    /// restarted node reads them back from.
    ///
    /// A full scan rather than a seek: the commit-path sweep is what
    /// bounds the CF, so everything present is everything wanted.
    fn load_retained_provisions(&self) -> Vec<Arc<Provisions>> {
        let cf = self.cf();
        let provisions_cf = ProvisionsCf::handle(&cf);
        iter_all::<ProvisionsCf>(&self.db, provisions_cf)
            .map(|(_key, provisions)| Arc::new(provisions))
            .collect()
    }
}
