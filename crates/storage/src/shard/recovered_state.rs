//! State recovered from storage on startup, used to restore the consensus
//! state machine after a crash or restart.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_types::{
    BeaconWitnessLeafCount, Block, BlockHash, BlockHeader, BlockHeight, ChainOrigin, CommittedTip,
    Hash, PredecessorTerminal, Provisions, QuorumCertificate, SafeVoteRegisters, ShardAnchor,
    StateRoot, SubstateKey, ValidatorId, Verified, WeightedTimestamp,
};

use super::dedup_window::DedupWindow;
use super::unresolved::ReplayWindow;

/// State recovered from storage on startup.
///
/// Constructed by storage backends (e.g. `RocksDbShardStorage::load_recovered_state`)
/// and passed to `ShardCoordinator::new()` to restore consensus state after a
/// crash/restart. For a fresh start, use `RecoveredState::default()`.
#[derive(Debug, Clone, Default)]
pub struct RecoveredState {
    /// Last committed height; the resume point for proposal/voting after restart.
    pub committed_height: BlockHeight,

    /// Where execution resumes: the blocks it replays to rebuild
    /// everything it was tracking, and the clock the first of them
    /// carries forward.
    ///
    /// Composition and execution both read only committed content, so
    /// replaying it reproduces the tick membership and the tick outputs a
    /// replica had before it went down — neither of which survives the
    /// restart this state exists to recover from.
    pub replay: ReplayWindow,

    /// The committed artifacts a coordinator has to refuse a second
    /// inclusion of, rebuilt from the chain the restart kept.
    ///
    /// A different and wider question from [`replay`](Self::replay), which
    /// is bounded by what is still owed an outcome and is empty when
    /// nothing is: a chain that resolved everything it committed has no
    /// replay window and a full dedup window. So this walks its own range
    /// — every block within [`RETENTION_HORIZON`] of the tip — rather than
    /// reusing that floor.
    ///
    /// [`RETENTION_HORIZON`]: hyperscale_types::RETENTION_HORIZON
    pub dedup: DedupWindow,

    /// The chains this one succeeds, and the commitments they left — one
    /// for a split child, two for a merged parent, empty for a chain born
    /// at network genesis or recovered by any path but a reshape flip.
    ///
    /// Set only on the flip, which is the delivery fast enough to matter:
    /// the rule these relax retires `MAX_VALIDITY_RANGE` past the origin,
    /// well before the beacon folds the same roots. Empty here is not a
    /// gap — a seat that missed the flip reads them off its topology
    /// projection instead, via
    /// `TopologySchedule::predecessor_terminals`, and until either lands
    /// the strict rule stands.
    pub predecessors: Vec<PredecessorTerminal>,

    /// The provision bodies still held for the blocks that carried them.
    /// A stored block keeps only their hashes, so this is what puts them
    /// back in the shared store a restarted node reads them from.
    pub retained_provisions: Vec<Arc<Provisions>>,

    /// Last committed block hash (None for fresh start).
    pub committed_hash: Option<BlockHash>,

    /// Latest QC (certifies the highest certified block). Wrapped as
    /// `Verified<QuorumCertificate>` via `new_unchecked` inside the
    /// storage adapter; the trust source is the persistence invariant
    /// that QCs only land in storage after verification at admission.
    pub latest_qc: Option<Verified<QuorumCertificate>>,

    /// The QC certifying a snap-synced boundary anchor, served alongside
    /// the witness history and structurally bound by the fetch path (it
    /// certifies exactly the beacon-attested anchor `block_hash`, which
    /// pins every certified field through the vote message). Its
    /// aggregate signature is *not* yet verified — the coordinator
    /// resolves the anchor's committee from its topology schedule and
    /// verifies before adopting it as `latest_qc`, giving the fresh
    /// committee the parent QC its first block past the anchor extends.
    /// `None` on an ordinary restart, where `latest_qc` recovers from
    /// storage directly.
    pub anchor_qc: Option<QuorumCertificate>,

    /// The committed tip's running values, read back from its stored
    /// header on an ordinary restart and seeded from the boundary header
    /// by a snap-synced bootstrap, so in both cases the first block
    /// extending the tip is checkable — the vote path checks a block's
    /// claims against the parent's, and skips the vote when it cannot
    /// resolve them. `None` only when no block is stored at the committed
    /// height, where the coordinator seeds the genesis tip.
    pub committed_tip: Option<CommittedTip>,

    /// Weighted timestamp of the committed tip's *parent* QC — the tip's own
    /// position on the weighted-time grid, and the anchor of the committee
    /// governing the block that extends it. Distinct from `latest_qc`'s
    /// timestamp (the tip's own WT) when the tip is an epoch's first block.
    /// `None` for a fresh start or genesis tip; the coordinator then falls
    /// back to the tip's own WT, exact except across that one boundary case.
    pub committed_block_anchor_wt: Option<WeightedTimestamp>,

    /// Weighted timestamp of the parent QC on the header *below* the committed
    /// tip — the anchor of the committee that signed the tip itself, since a
    /// block's committee keys on its parent. Read back one height below
    /// `committed_block_anchor_wt` from the same stored headers. `None` when that
    /// header isn't stored (fresh start, genesis tip, a snap-synced boundary
    /// whose parent was never imported, or a parent pruned past retention);
    /// the coordinator then falls back to the tip's own anchor, which resolves
    /// the same committee except when the tip is an epoch's first block.
    pub committed_committee_anchor_wt: Option<WeightedTimestamp>,

    /// Last committed JMT root hash.
    ///
    /// Restored from storage at startup so proposals use the correct parent
    /// state root instead of the default `StateRoot::ZERO`.
    ///
    /// If not provided (None), defaults to `StateRoot::ZERO` for fresh start.
    pub jmt_root: Option<StateRoot>,

    /// Absolute leaf index of `beacon_witness_leaf_hashes[0]` — the
    /// committed tip's witness window base. Stored payloads below it
    /// (the persistence layer's one-window hysteresis stock) are
    /// serving data, not accumulator state, and are excluded from the
    /// recovered window. `ZERO` on a fresh start.
    pub beacon_witness_start: BeaconWitnessLeafCount,

    /// Beacon-witness accumulator leaf hashes for the recovery shard
    /// from `beacon_witness_start`, in monotonic leaf-index order.
    /// Storage backends derive these from the `beacon_witnesses` CF by
    /// hashing each retained payload at or above the tip's window base,
    /// so the shard coordinator can rebuild
    /// [`BeaconWitnessAccumulator`](../../crates/shard/src/beacon_witnesses.rs)
    /// to the on-disk count without re-deriving from receipts +
    /// historical topology. Empty on a fresh start.
    pub beacon_witness_leaf_hashes: Vec<Hash>,

    /// Committed substate byte total behind the committed tip — seeds the
    /// coordinator's byte frontier for reshape-trigger derivation.
    /// Zero on a fresh start.
    pub substate_bytes: u64,

    /// The chain's origin — genesis height plus start-time anchor (see
    /// `ChainOrigin`). `ChainOrigin::ROOT` for chains born at network
    /// genesis; a child chain created by a shard split continues the
    /// parent's height line and clock. The coordinator reconstructs
    /// genesis-fallback QCs from this value, so it must byte-match the
    /// chain's real genesis QC.
    pub chain_origin: ChainOrigin,

    /// Durable safe-vote registers for each validator that has signed a
    /// vote or timeout on this store's chain, excluding records from a
    /// different chain incarnation. The coordinator floors its registers
    /// at these values on restart, so it can never re-sign a round it
    /// already consumed. Empty on a fresh start — including after
    /// snap-sync, where the imported store carries no signing history.
    pub safe_vote_registers: BTreeMap<ValidatorId, SafeVoteRegisters>,

    /// The escrow records this store holds under the shard's prefix,
    /// with their committed bytes.
    ///
    /// Value this shard owes an answer for, read from the leaves that
    /// hold it and from nothing else — every start's first term, which
    /// the commits after it add to and take from. Nothing else can name
    /// them: the
    /// entry that would is a fold over a chain a successor never
    /// replays and a restart replays only a window of, and the cell is
    /// outside every sweep's reach. The state is the authority, and it
    /// is what every node holding the prefix has — which is what makes
    /// the set a function of committed content rather than of how a
    /// node got here.
    ///
    /// Read the same way however the store was reached: adopted whole
    /// at a reshape seat, resumed after a restart, or imported by
    /// snap-sync. A set seeded by an event one node witnessed and
    /// another did not is a set two replicas compose different ticks
    /// from.
    pub escrow_records: Vec<(SubstateKey, Vec<u8>)>,

    /// The uncommitted blocks the store kept beside the safe-vote
    /// registers, above the committed tip and in height order.
    ///
    /// The certificate a restored record carries names one of these, and
    /// a proposer extends the block its high QC certifies — so without
    /// them a committee that restarted together holds a lock no proposal
    /// it can build satisfies. Seeded into the coordinator's pending
    /// blocks, where verification re-derives the state each one left.
    /// Empty on a fresh start and after snap-sync, where the store
    /// carries no signing history.
    pub voted_blocks: Vec<Arc<Block>>,
}

impl RecoveredState {
    /// The recovered state of a snap-synced bootstrap: the store was
    /// imported at the beacon-attested boundary `anchor`, so the
    /// committed tip is the boundary block itself.
    ///
    /// `boundary_header` is the anchor block's header, hash-verified
    /// against `anchor.block_hash` by the fetch path; its `parent_qc`
    /// weighted timestamp is the tip's committee anchor, and
    /// `witness_leaf_hashes` is its verified accumulator window —
    /// starting at the header's `beacon_witness_base`. `latest_qc`
    /// stays `None` — the boundary block's own QC arrives structurally
    /// bound in [`anchor_qc`](Self::anchor_qc), and the coordinator
    /// adopts it only after verifying it against the anchor's resolved
    /// committee; a higher tail-synced QC still adopts through the
    /// normal round-monotonic path.
    #[must_use]
    pub fn from_snap_synced_boundary(
        anchor: &ShardAnchor,
        boundary_header: &BlockHeader,
        anchor_qc: QuorumCertificate,
        witness_leaf_hashes: Vec<Hash>,
        substate_bytes: u64,
    ) -> Self {
        Self {
            committed_height: anchor.height,
            // Nothing below the anchor is imported, so a snap-synced
            // replica knows of nothing in flight beneath it: no block to
            // replay, and none that carried a bundle.
            replay: ReplayWindow::default(),
            // Nothing below the anchor is imported, so there is no chain
            // to fold a dedup window out of yet. The tail sync above the
            // anchor supplies it as it commits.
            dedup: DedupWindow::covering_nothing(),
            // A snap-synced joiner reaches no reshape flip, so it reads its
            // predecessors off the topology projection at its first beacon
            // block instead.
            predecessors: Vec::new(),
            retained_provisions: Vec::new(),
            committed_hash: Some(anchor.block_hash),
            latest_qc: None,
            anchor_qc: Some(anchor_qc),
            committed_tip: Some(boundary_header.committed_tip()),
            committed_block_anchor_wt: Some(boundary_header.parent_qc().weighted_timestamp()),
            // The boundary's parent is not imported, so the committee that
            // signed the boundary block resolves only through the fallback.
            committed_committee_anchor_wt: None,
            jmt_root: Some(anchor.state_root),
            beacon_witness_start: boundary_header.beacon_witness_base(),
            beacon_witness_leaf_hashes: witness_leaf_hashes,
            substate_bytes,
            // A genesis boundary header carries the chain's origin
            // outright — a straggler joining a split child at its first
            // anchor recovers the continued height line and clock from
            // it. A later boundary on a child chain still reads `ROOT`
            // here; the origin only feeds genesis-QC reconstruction,
            // which a joiner that far past genesis never performs.
            chain_origin: if boundary_header.is_genesis() {
                ChainOrigin {
                    genesis_height: boundary_header.height(),
                    anchor_wt: boundary_header.parent_qc().weighted_timestamp(),
                }
            } else {
                ChainOrigin::ROOT
            },
            safe_vote_registers: BTreeMap::new(),
            escrow_records: Vec::new(),
            voted_blocks: Vec::new(),
        }
    }

    /// The recovered tip's own position on the weighted-time grid —
    /// [`committed_block_anchor_wt`](Self::committed_block_anchor_wt) when storage
    /// recovered it, else the tip QC's own weighted timestamp (identical
    /// except when the tip is an epoch's first block), else `ZERO` on a fresh
    /// start.
    #[must_use]
    pub fn block_anchor_wt(&self) -> WeightedTimestamp {
        self.committed_block_anchor_wt.unwrap_or_else(|| {
            self.latest_qc.as_deref().map_or(
                WeightedTimestamp::ZERO,
                QuorumCertificate::weighted_timestamp,
            )
        })
    }

    /// Anchor of the committee that signed the recovered tip —
    /// [`committed_committee_anchor_wt`](Self::committed_committee_anchor_wt)
    /// when storage recovered it, else the tip's own anchor, which names the
    /// same committee except when the tip is an epoch's first block. The
    /// oldest weighted timestamp the recovered chain can still key a topology
    /// lookup on, so it is what schedule retention floors on.
    #[must_use]
    pub fn committee_anchor_wt(&self) -> WeightedTimestamp {
        self.committed_committee_anchor_wt
            .unwrap_or_else(|| self.block_anchor_wt())
    }
}
