//! State recovered from storage on startup, used to restore the consensus
//! state machine after a crash or restart.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_types::{
    Anchor, BeaconWitnessLeafCount, Block, BlockHash, BlockHeader, BlockHeight, ChainOrigin,
    CommittedTip, Hash, Provisions, QuorumCertificate, ReadFrontier, SafeVoteRegisters,
    ShardAnchor, StateRoot, ValidatorId, Verified, VotePosition, WeightedTimestamp,
};

use super::boundary::BoundaryStore;
use super::chain_reader::ShardChainReader;
use super::dedup_window::DedupWindow;
use super::unresolved::{ReplayWindow, replay_window};
use super::vote_registers::SafeVoteRegisterStore;
use crate::MemberIndex;

/// How many committed headers a restart replays into the delay estimate.
///
/// Covers one rotation of any committee up to this size; a larger
/// committee fills the remainder from live commits.
pub const RECENT_HEADER_REPLAY: usize = 256;

/// The committed headers from up to [`RECENT_HEADER_REPLAY`] below
/// `committed_height` through it, ascending and contiguous: the walk stops
/// at the first height the store no longer holds.
pub fn recent_headers<R: ShardChainReader + ?Sized>(
    reader: &R,
    committed_height: BlockHeight,
) -> Vec<BlockHeader> {
    let floor = committed_height
        .inner()
        .saturating_sub(RECENT_HEADER_REPLAY as u64);
    let mut headers: Vec<BlockHeader> = (floor..=committed_height.inner())
        .rev()
        .map_while(|height| reader.get_certified_header(BlockHeight::new(height)))
        .map(|certified| certified.header().clone())
        .collect();
    headers.reverse();
    headers
}

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

    /// The chains this one succeeds, each as its terminal state — one for
    /// a split child, two for a merged parent, empty for a chain born at
    /// network genesis or recovered by any path but a reshape flip.
    ///
    /// Set only on the flip, which is the delivery fast enough to matter:
    /// the rule these relax retires `MAX_VALIDITY_RANGE` past the origin,
    /// well before the beacon folds the same roots. Empty here is not a
    /// gap — a seat that missed the flip reads them off its topology
    /// projection instead, via
    /// `TopologySchedule::predecessor_terminals`, and until either lands
    /// the strict rule stands.
    pub predecessors: Vec<Anchor>,

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

    /// The QC certifying a snap-synced boundary anchor: the canonical QC
    /// the beacon fold recorded for the crossing, or, for a seeded anchor
    /// no crossing refreshed, the one served alongside the witness history
    /// and structurally bound by the fetch path (it certifies exactly the
    /// anchor `block_hash`, which pins every certified field through the
    /// vote message). Its aggregate signature is not yet verified here —
    /// the coordinator
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
    /// already consumed. Empty on a fresh start and after a snap-sync
    /// onto a store that replaces none; a rebuilt store carries the rounds
    /// signed on the one it replaces
    /// ([`carry_signed_rounds`](Self::carry_signed_rounds)).
    pub safe_vote_registers: BTreeMap<ValidatorId, SafeVoteRegisters>,

    /// The read frontier the committed state holds: how far along each
    /// producer this shard has read, which bounds the record presences
    /// a block may carry and licenses the deletion of an answer. Read
    /// off the state on every path that builds one, since it is state
    /// and every seat holds it; the execution coordinator advances its
    /// copy from here with the same rule the fold writes it by.
    pub read_frontier: ReadFrontier,

    /// The tick membership the committed state holds, read off it on
    /// every path that builds one, as the read frontier is. `None` on a
    /// fresh start, which holds no rows.
    pub members: Option<MemberIndex>,

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

    /// The committed headers just below the tip, ascending, that seed the
    /// round timer's delay estimate so a restart does not spend a rotation
    /// on the default timeout. Empty when the store holds no history below
    /// the tip, as after a snap-sync.
    pub recent_headers: Vec<BlockHeader>,
}

impl RecoveredState {
    /// The recovered state of a snap-synced bootstrap: `store` was
    /// imported at the beacon-attested boundary `anchor`, so the
    /// committed tip is the boundary block itself.
    ///
    /// `boundary_header` is the anchor block's header, hash-verified
    /// against `anchor.block_hash` by the fetch path; its `parent_qc`
    /// weighted timestamp is the tip's committee anchor, and
    /// `witness_leaf_hashes` is its verified accumulator window —
    /// starting at the header's `beacon_witness_base`. The read frontier
    /// and the tick membership are the ones the imported state holds.
    /// `latest_qc` stays `None` — the boundary block's own QC arrives in
    /// [`anchor_qc`](Self::anchor_qc), and the coordinator
    /// adopts it only after verifying it against the anchor's resolved
    /// committee; a higher tail-synced QC still adopts through the
    /// normal round-monotonic path.
    ///
    /// The replay is the one a restart at the anchor takes, over the
    /// committed chain the history walk recorded beneath it. The anchor's
    /// state carries only what had settled there, so a tick at or below
    /// the anchor still owed its determined half left writes that state
    /// lacks and every tick above it reads. Replaying seats that tick,
    /// holds dispatch behind it, and the commit of its finalization
    /// restores those writes from the receipts. The imported state
    /// answers at the anchor and nowhere below it, so nothing the replay
    /// seats runs.
    #[must_use]
    pub fn from_snap_synced_boundary<S: BoundaryStore + ShardChainReader + ?Sized>(
        store: &S,
        anchor: &ShardAnchor,
        boundary_header: &BlockHeader,
        anchor_qc: QuorumCertificate,
        witness_leaf_hashes: Vec<Hash>,
        substate_bytes: u64,
    ) -> Self {
        let shard = boundary_header.shard_id();
        let committed_ts = boundary_header.parent_qc().weighted_timestamp();
        // A genesis boundary header carries the chain's origin outright —
        // a straggler joining a split child at its first anchor recovers
        // the continued height line and clock from it. A later boundary
        // on a child chain still reads `ROOT` here: the origin feeds
        // genesis-QC reconstruction, which a joiner that far past genesis
        // never performs, and the replay's lower bound, which the history
        // walk already draws at the chain's first block.
        let chain_origin = if boundary_header.is_genesis() {
            ChainOrigin {
                genesis_height: boundary_header.height(),
                anchor_wt: committed_ts,
            }
        } else {
            ChainOrigin::ROOT
        };
        Self {
            committed_height: anchor.height,
            replay: replay_window(
                store,
                anchor.height,
                committed_ts,
                anchor.height,
                chain_origin,
            ),
            // The dedup window starts empty, and the tail sync above the
            // anchor fills it as it commits.
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
            committed_block_anchor_wt: Some(committed_ts),
            // The boundary's parent is not imported, so the committee that
            // signed the boundary block resolves only through the fallback.
            committed_committee_anchor_wt: None,
            jmt_root: Some(anchor.state_root),
            beacon_witness_start: boundary_header.beacon_witness_base(),
            beacon_witness_leaf_hashes: witness_leaf_hashes,
            substate_bytes,
            chain_origin,
            safe_vote_registers: BTreeMap::new(),
            read_frontier: store.read_frontier(shard),
            members: Some(store.member_index(shard)),
            voted_blocks: Vec::new(),
            recent_headers: Vec::new(),
        }
    }

    /// Carry the rounds every validator signed in on `replaced` onto
    /// `store`, rebuilt beneath the same chain to take its place, and
    /// into this state, which that store's coordinators boot from.
    ///
    /// A rebuilt store holds the chain as its attested anchor left it and
    /// none of what its host signed, while the rounds its validators
    /// consumed on the replaced store are still theirs to refuse. Without
    /// them a coordinator booted here signs a second time in a round the
    /// chain may not have left, and votes beneath a lock it took.
    ///
    /// Only the two rounds travel. The certificate and the blocks beside a
    /// record describe the replaced store's view of the chain, which the
    /// anchor supersedes: the lock is satisfied by the certificates the
    /// chain's live peers hold, as a snap-synced joiner's is.
    ///
    /// Durable on return, so call it before any coordinator booted from
    /// this state can sign, and only once nothing signs against `replaced`.
    pub fn carry_signed_rounds<R, S>(&mut self, replaced: &R, store: &S)
    where
        R: SafeVoteRegisterStore + ?Sized,
        S: SafeVoteRegisterStore + ?Sized,
    {
        for (validator, signed) in replaced.all_safe_vote_registers() {
            let position = VotePosition {
                registers: SafeVoteRegisters {
                    locked_round: signed.locked_round,
                    last_voted_round: signed.last_voted_round,
                    high_qc: None,
                    high_tc: None,
                },
                justification: Vec::new(),
            };
            store.persist_vote_position(validator, &position);
        }
        self.safe_vote_registers = store.all_safe_vote_registers();
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
