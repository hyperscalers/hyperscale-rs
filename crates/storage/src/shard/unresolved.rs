//! Where a restarted replica's execution has to resume from.
//!
//! What a shard has committed and not yet resolved is a fold over its own
//! blocks, so a replica that lost its execution state can recover it by
//! replaying them. That is the whole point of keeping the account on the
//! chain rather than in tick state: a shard whose replicas all restarted
//! can still name what it committed and never finished, and therefore
//! still finish it or abort it.
//!
//! The walk belongs here, because this is what holds the blocks and knows
//! how far back the retention window reaches. What the walk *means* does
//! not: composition needs a topology and a provisioning tracker, so the
//! replay itself is the coordinator's, and this hands back where it
//! starts.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_hbor::Capped;
use hyperscale_types::{
    BlockHeight, CertifiedBlock, ChainOrigin, EPOCH_DURATION, Provisions, TERMINAL_EVIDENCE_EPOCHS,
    TRANSACTION_EVIDENCE_HORIZON, TxHash, Verifiable, Verified, WeightedTimestamp,
};

use super::chain_reader::ShardChainReader;

/// How far back a rebuild reads for a transaction a committed boundary
/// record decides.
///
/// Such a record carries every term abandoning the transaction takes, so
/// reaching the record is reaching the entry however far below the
/// transaction's own block sits. And the record is bounded where the
/// transaction is not: it is composed after its shard's cut and the entry
/// it writes dies at that cut's terminal-evidence expiry, so one still
/// owed a verdict now was committed within that span of now.
///
/// Stated in [`EPOCH_DURATION`] rather than the beacon's configured window
/// because a rebuild reads this before the schedule is up. A chain running
/// shorter windows only over-reaches, which costs a longer scan and
/// nothing else.
const RECORD_WINDOW: Duration = Duration::from_secs(
    EPOCH_DURATION
        .as_secs()
        .saturating_mul(TERMINAL_EVIDENCE_EPOCHS),
);

/// How far back from the tip a restart replay reads: the wider of the
/// transaction evidence horizon and [`RECORD_WINDOW`].
pub(crate) const REPLAY_REACH: Duration =
    if TRANSACTION_EVIDENCE_HORIZON.as_secs() > RECORD_WINDOW.as_secs() {
        TRANSACTION_EVIDENCE_HORIZON
    } else {
        RECORD_WINDOW
    };

/// The lowest height committing something the chain still owes an outcome
/// for — where a replay has to start to rebuild everything execution was
/// tracking.
///
/// Two things put a height in the running, because two things put an entry
/// in the ledger. A committed transaction no certificate has resolved is
/// the first, and every tick with an unresolved member sits at or above
/// the lowest of them: a tick below would need a member committed below
/// it, which would have been this floor instead.
///
/// A committed boundary record no certificate has discharged is the
/// second. It carries every term abandoning the transactions it names
/// takes, so replaying it rebuilds their entries whether or not the walk
/// reaches the blocks that committed them — which is the whole point,
/// since a counterpart may depart arbitrarily long after a transaction
/// commits and no span measured back from the tip would reach both.
///
/// `None` when nothing is owed, where there is nothing to replay.
///
/// Reads forward from the oldest block in the window, so a transaction
/// and the finalization resolving it are seen in the order they
/// committed — the reverse would drop a release whose registration had
/// not happened yet.
///
/// Bounded below by `origin`, the height this chain begins at. A split
/// child's `RocksDB` store is a hard-linked clone of its parent's and
/// holds the parent's whole chain, so a walk measured in time alone
/// reads the parent's blocks as this chain's and replays parts no peer
/// seeded from the same clone ever held. Nothing under the origin is
/// owed here in any case: a transaction whose validity window opened
/// before the chain did cannot be admitted at all, which is the rule
/// [`DedupWindow::from_reader`] stops at the same height for.
///
/// Bounded above that by what the reader holds: a snap-synced replica
/// has no blocks below its anchor and recovers only what committed above
/// it, which is the same limit that applies to everything else it cannot
/// see.
///
/// [`DedupWindow::from_reader`]: crate::DedupWindow::from_reader
#[must_use]
pub fn unresolved_replay_floor<R: ShardChainReader + ?Sized>(
    reader: &R,
    committed_height: BlockHeight,
    committed_ts: WeightedTimestamp,
    origin: ChainOrigin,
) -> Option<BlockHeight> {
    let cutoff = replay_cutoff(committed_ts);

    // Walk back to the window's edge, then fold forward from there.
    let mut oldest = committed_height;
    while let Some(previous) = oldest.prev() {
        if previous < origin.genesis_height {
            break;
        }
        match reader.get_block(previous) {
            Some(block) if block.block().header().parent_qc().weighted_timestamp() >= cutoff => {
                oldest = previous;
            }
            _ => break,
        }
    }

    // A transaction is in the running only from the shorter window; a
    // record is in it from the whole of the longer one. Tracked apart so
    // the extra reach a record needs does not resurrect a transaction the
    // deadline path retired.
    //
    // The shorter window is the transaction's own evidence horizon,
    // which spans every entry whose fate is its own clock's to settle,
    // leg entries included. It does not span every entry the ledger
    // holds: one a certificate of this shard's covers lives while some
    // counterpart can still answer, which is the counterpart's clock —
    // it may run for hours past the commit and only then depart, and
    // the entry survives to that departure's terminal-evidence expiry.
    // `RECORD_WINDOW` is what reaches those. Which of the two is wider
    // is not fixed — the claim window puts the transaction horizon a
    // validity range past it — so the scan takes the greater of them
    // and each cutoff is applied where it belongs.
    let fold_cutoff = committed_ts.minus(TRANSACTION_EVIDENCE_HORIZON);
    let mut unresolved: BTreeMap<TxHash, BlockHeight> = BTreeMap::new();
    let mut undischarged: BTreeMap<TxHash, BlockHeight> = BTreeMap::new();
    let mut height = oldest;
    loop {
        if let Some(certified) = reader.get_block(height) {
            let block = certified.block();
            if block.header().parent_qc().weighted_timestamp() >= fold_cutoff {
                for tx in block.transactions().iter() {
                    unresolved.insert(tx.hash(), height);
                }
            }
            for verdict in block.abandonment_records() {
                for tx_hash in verdict.tx_hashes() {
                    undischarged.insert(tx_hash, height);
                }
            }
            // Only a deciding outcome retires an entry: a leg's own
            // finalization names the leg and resolves nothing, since its
            // entry lives on for the reclaim its core's refusal or its
            // deliveries' lapse may license.
            for finalization in block.certificates().iter() {
                for tx_hash in finalization.deciding_tx_hashes() {
                    unresolved.remove(&tx_hash);
                    undischarged.remove(&tx_hash);
                }
            }
        }
        if height >= committed_height {
            break;
        }
        height = height.next();
    }

    unresolved
        .into_values()
        .chain(undischarged.into_values())
        .min()
}

/// The oldest parent-QC clock a replay from a tip at `committed_ts`
/// reads a block at: [`REPLAY_REACH`] below it.
#[must_use]
pub fn replay_cutoff(committed_ts: WeightedTimestamp) -> WeightedTimestamp {
    committed_ts.minus(REPLAY_REACH)
}

/// Where a restart resumes execution: the blocks to replay, and the
/// clock the first of them carries forward.
#[derive(Debug, Clone, Default)]
pub struct ReplayWindow {
    /// Every block from the replay's start through the committed tip,
    /// each with the provision bundles it carried reattached. Empty when
    /// nothing is owed an outcome.
    ///
    /// The start is [`unresolved_replay_floor`], or lower where a tick a
    /// finalization committed from [`Self::dispatch_from`] on settles, or
    /// a member it names, sits beneath that.
    pub blocks: Vec<Verified<CertifiedBlock>>,
    /// The lowest height the replay may *dispatch* a tick at: the higher
    /// of [`unresolved_replay_floor`] and the first height whose baseline
    /// — the settled state as of the height below it — the store still
    /// answers for.
    ///
    /// The replay has two reaches because it has two jobs. Composition
    /// runs over every block the window holds, which runs back as far as
    /// an undischarged record, because which tick holds a member is what
    /// every replica of the shard has to agree on whatever its own store
    /// still reaches; execution runs over a baseline, and a baseline is a
    /// historical read the store retires at
    /// [`RETENTION_HORIZON`](hyperscale_types::RETENTION_HORIZON). Below
    /// this a tick is seated and never runs, which costs nothing: it was
    /// taken by a fate the replay reads off the chain, and what it left
    /// is seated from the finalizations that settled it as their commits
    /// replay.
    pub dispatch_from: BlockHeight,
    /// The parent-QC weighted timestamp of the block *below* the first
    /// one replayed — the clock execution resumes at, so the block above
    /// it stays on the exact carry path and classifies its ticks under
    /// the window they committed in.
    ///
    /// `None` when that block is not held: the floor is the chain's
    /// first block, or its predecessor has aged out. The first block
    /// replayed then classifies under its own anchor, the same fallback
    /// a chain with no history behind it takes.
    pub anchor_wt: Option<WeightedTimestamp>,
}

/// Build the window a restart replays.
///
/// The bodies sealing dropped come back through
/// [`ShardChainReader::provisions_at`], lifted under the same trust as
/// the commit path's: they reached storage inside a block this shard
/// committed, and our own disk is not a weaker source than the peer's
/// block that put them there.
///
/// A hole anywhere in the range yields an empty window rather than a
/// partial one: the folds above a missing block would sit on a baseline
/// that block was supposed to have contributed to.
///
/// `retention_floor` is the oldest version the store answers a historical
/// read at. A tick reads its baseline at the height below it, so a tick
/// dispatches only from the first height above that floor and the ones
/// below it compose without running.
#[must_use]
pub fn replay_window<R: ShardChainReader + ?Sized>(
    reader: &R,
    committed_height: BlockHeight,
    committed_ts: WeightedTimestamp,
    retention_floor: BlockHeight,
    origin: ChainOrigin,
) -> ReplayWindow {
    let Some(owed) = unresolved_replay_floor(reader, committed_height, committed_ts, origin) else {
        return ReplayWindow::default();
    };
    let dispatch_from = owed.max(retention_floor.next());
    let floor = settled_reach(
        reader,
        committed_height,
        committed_ts,
        origin,
        owed,
        dispatch_from,
    );
    let anchor_wt = floor
        .prev()
        .and_then(|below| reader.get_block(below))
        .map(|certified| certified.block().header().parent_qc().weighted_timestamp());

    let mut blocks = Vec::new();
    let mut height = floor;
    loop {
        match reader.get_block(height) {
            Some(certified) => blocks.push(rehydrate(certified, reader.provisions_at(height))),
            None => return ReplayWindow::default(),
        }
        if height >= committed_height {
            break;
        }
        height = height.next();
    }
    ReplayWindow {
        blocks,
        dispatch_from,
        anchor_wt,
    }
}

/// Where a replay from `owed` has to start instead, for every tick a
/// finalization committed from `dispatch_from` on settles to be seated,
/// holding the members that finalization names.
///
/// Such a tick may sit below `owed`: a leg's verdict decides its
/// transaction, so a tick whose legs settle inside the window can owe
/// nothing at the tip while a later transaction holds the floor above
/// it. And a tick the replay dispatches nothing at is still read. Every
/// tick dispatched below the commit settling a completed leg holds what
/// the leg reserved, and every tick from it reads what the leg left;
/// the commit seats both from the finalization, but only for a tick the
/// replay seated, and the holds only for the legs it seated in it. A
/// member is seated only when the replay registers the block that
/// committed it, which can sit below its tick.
///
/// A finalization committed below `dispatch_from` asks for none of this:
/// the baseline the first dispatched tick reads already carries what it
/// settled, and no dispatched tick sits below its commit to read a hold.
///
/// Walks down from the tip, on past the replay's reach for as long as a
/// tick asks for blocks beneath it, and past the tick only while a
/// member is still unfound and the blocks are dated inside that reach. A
/// record naming a member is reached too, since it carries every term
/// abandoning the member takes. A member committed further down, or on
/// no block of this chain's, is seated as far as the store reaches.
/// Never below `origin`, nor beneath a block the store no longer holds.
fn settled_reach<R: ShardChainReader + ?Sized>(
    reader: &R,
    committed_height: BlockHeight,
    committed_ts: WeightedTimestamp,
    origin: ChainOrigin,
    owed: BlockHeight,
    dispatch_from: BlockHeight,
) -> BlockHeight {
    let cutoff = replay_cutoff(committed_ts);
    let mut floor = owed;
    let mut members: BTreeSet<TxHash> = BTreeSet::new();
    let mut height = committed_height;
    loop {
        let Some(certified) = reader.get_block(height) else {
            return floor.max(height.next()).min(owed);
        };
        let block = certified.block();
        if height >= dispatch_from {
            let shard = block.header().shard_id();
            for finalization in block.certificates().iter() {
                let tick = finalization.tick_id();
                if tick.shard_id() == shard {
                    floor = floor.min(tick.block_height());
                    members.extend(finalization.tx_hashes());
                }
            }
        }
        for tx in block.transactions().iter() {
            if members.remove(&tx.hash()) {
                floor = floor.min(height);
            }
        }
        for verdict in block.abandonment_records() {
            if verdict
                .tx_hashes()
                .any(|tx_hash| members.contains(&tx_hash))
            {
                floor = floor.min(height);
            }
        }
        let dated_out = block.header().parent_qc().weighted_timestamp() < cutoff;
        if height <= floor && (members.is_empty() || dated_out) {
            return floor;
        }
        match height.prev() {
            Some(below) if below >= origin.genesis_height => height = below,
            _ => return floor.max(height),
        }
    }
}

/// Put a stored block back in the shape a commit runs on, with whatever
/// provision bundles it carried reattached.
///
/// Live whether or not any came back, because the variant is what decides
/// whether the commit path registers the block's transactions at all: a
/// sealed block is one past its execution window, owing nothing and
/// carrying nothing to compose. A block in this window is there precisely
/// because it committed a transaction the chain still owes an outcome
/// for, so handing it back sealed would skip the registration the replay
/// exists to redo. Blocks that carried no bundles, and blocks whose
/// bundles have aged out from under them, both arrive here empty and both
/// still owe their transactions an outcome.
fn rehydrate(
    certified: Verified<CertifiedBlock>,
    provisions: Vec<Arc<Verifiable<Provisions>>>,
) -> Verified<CertifiedBlock> {
    let (block, qc) = certified.into_inner().into_parts();
    // Sealing keeps the header, and the header is what the hash and the
    // QC pairing are over, so reattaching the bodies cannot break it.
    let live = block.into_live(Arc::new(
        Capped::new(provisions).expect("a rebuilt block keeps the caps its source met"),
    ));
    Verified::<CertifiedBlock>::from_persisted(CertifiedBlock::new_unchecked(live, qc))
}
