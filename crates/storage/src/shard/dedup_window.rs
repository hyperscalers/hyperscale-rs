//! The window of committed artifacts a coordinator has to refuse a second
//! inclusion of.
//!
//! Every committed artifact appears in a shard's chain exactly once, and
//! the index enforcing that is a fold over committed blocks. A coordinator
//! that starts without having personally committed the window — a restart,
//! a reshape successor, a fresh join — holds none of it, and an empty
//! index is maximally permissive: it refuses nothing. So the fold has to
//! be re-runnable from the blocks themselves, which is what this is.
//!
//! Plain data rather than the index itself. The index lives in the shard
//! crate, which depends on this one, so the window travels as the pairs it
//! is built from and the index takes them at construction.
//!
//! Unlike [`replay_window`](super::unresolved::replay_window), a hole makes
//! this window **incomplete rather than empty**. The two run opposite
//! because their failure modes do: a partial replay would sit on a
//! baseline a missing block should have contributed to, where a partial
//! dedup window merely refuses less than it could — and an empty one
//! refuses nothing at all. Empty is the safe answer there and the unsafe
//! one here, so the gap is reported instead of erasing the window.

use std::collections::HashSet;

use hyperscale_types::{
    Block, BlockHeight, ChainOrigin, DEDUP_WINDOW, Deadline, FEE_HOLD_WINDOW, FinalizationHash,
    PrincipalAddr, ProvisionHash, RETENTION_HORIZON, TxHash, WeightedTimestamp, Window,
};

use super::chain_reader::ShardChainReader;

/// One rebuild of the committed-artifact window, and whether it covers the
/// whole of it.
///
/// The three maps carry their own deadlines because the tiers differ: a
/// transaction's is the close of the delivery window its signed
/// `end_timestamp_exclusive` opens, a resolution's comes off the
/// resolving certificate, and a provision batch's is keyed to the block
/// that committed it.
#[derive(Debug, Clone, Default)]
pub struct DedupWindow {
    /// `(tx_hash, close of the delivery window)` for every transaction
    /// the window's blocks committed.
    pub committed: Vec<(TxHash, WeightedTimestamp)>,
    /// `(tx_hash, deadline)` for every transaction a committed
    /// finalization in the window reached a verdict for.
    pub resolved: Vec<(TxHash, WeightedTimestamp)>,
    /// `(provision_hash, deadline)` for every batch the window's blocks
    /// committed.
    pub provisions: Vec<(ProvisionHash, WeightedTimestamp)>,
    /// `(receipt_hash, deadline)` for every finalization the window's
    /// blocks committed.
    ///
    /// Separate from [`Self::resolved`] because the two answer different
    /// questions. That tier says a transaction has a verdict, which is
    /// what refuses a second one; this says the chain already carries
    /// *this certificate*, which is the only thing that refuses one whose
    /// members reach no verdict at all.
    pub finalizations: Vec<(FinalizationHash, WeightedTimestamp)>,
    /// The oldest block anchor the walk folded, or `None` when it folded
    /// nothing.
    ///
    /// Coverage is a span rather than a flag because it is not fixed at
    /// construction: a coordinator that starts short of the horizon
    /// reaches it by committing across it, and the blocks it commits are
    /// the same evidence a walk would have read. So the depth travels and
    /// is measured against the reader's own clock, which is what makes a
    /// short window legible as short rather than as an empty one.
    pub covered_from: Option<WeightedTimestamp>,
    /// Whether the walk bottomed out at the chain's own origin.
    ///
    /// Nothing exists below it to have missed, so such a window is whole
    /// however short its span — which is what a young chain has, and what
    /// keeps it from being treated as a chain with a hole in it.
    pub reached_origin: bool,
    /// Every fee reservation the window's blocks engaged and no committed
    /// finalization in them released.
    ///
    /// Folded over a deeper span than the tiers above
    /// ([`FEE_HOLD_WINDOW`]), because a hold outlives a transaction's
    /// delivery window. Held as what a payer shard's ledger takes rather
    /// than as a dedup tier: nothing here refuses a second inclusion.
    pub fee_holds: Vec<FeeHold>,
    /// Whether the fee-hold fold reached its own floor or the chain's
    /// origin. False means the ledger it seeds is short, and a short
    /// ledger under-counts what a payer has engaged.
    pub fee_holds_whole: bool,
}

/// One reservation a committed block engaged, as the recovery walk reads
/// it back: the payer's own terms, since a hold is a statement about the
/// transaction and not about the block that carried it.
#[derive(Debug, Clone, Copy)]
pub struct FeeHold {
    /// The transaction whose commit engaged it.
    pub tx_hash: TxHash,
    /// The fee payer, whose shard decides whether this hold is its own.
    pub payer: PrincipalAddr,
    /// The ceiling held against the payer's vault.
    pub max_fee: u128,
    /// Validity end plus [`RETENTION_HORIZON`] — where the hold prunes if
    /// nothing ever resolves it.
    pub deadline: WeightedTimestamp,
}

impl DedupWindow {
    /// Rebuild the window from a reader's own committed chain, walking back
    /// from `committed_height` until a block's anchor falls below
    /// `committed_ts − DEDUP_WINDOW`.
    ///
    /// The walk reads each block's own `parent_qc` weighted timestamp — the
    /// hash-pinned value every replica sees identically — so two nodes
    /// folding the same chain agree on the range.
    ///
    /// The transaction and resolution tiers reproduce the live path
    /// exactly: neither deadline is a function of when the block was
    /// committed, only of the transaction's own signed window and the
    /// resolving certificate's anchor. The provision tier is keyed to the
    /// committing clock, which the live path clamps monotonically against
    /// everything it had committed before; a walk that starts inside the
    /// window cannot see below it to reproduce that clamp, so a batch takes
    /// its own block's anchor and lands at or before where the live path put
    /// it. Early is the conservative direction — a batch whose entry expired
    /// early is re-requested, not wrongly admitted.
    ///
    /// `origin` is where this chain begins, which is not generally height
    /// zero: a reshape successor continues its predecessor's height line.
    /// Reaching it makes the window whole, because what lies below is the
    /// predecessor's and is refused on validity rather than on dedup.
    #[must_use]
    pub fn from_reader<R: ShardChainReader + ?Sized>(
        reader: &R,
        committed_height: BlockHeight,
        committed_ts: WeightedTimestamp,
        origin: ChainOrigin,
    ) -> Self {
        let dedup_floor = committed_ts.minus(DEDUP_WINDOW);
        let fee_floor = committed_ts.minus(FEE_HOLD_WINDOW);
        let mut window = Self::default();
        let mut height = committed_height;
        // One descent, each tier stopping at its own floor. The fee tier
        // reaches deeper, so the dedup tiers pin their coverage on the way
        // past rather than ending the walk.
        let mut dedup_done = false;
        // What a finalization already released, gathered descending — a
        // block's certificates are read before its transactions, and a
        // finalization always sits at or above the block that committed
        // what it names.
        let mut released: HashSet<TxHash> = HashSet::new();

        loop {
            if height < origin.genesis_height {
                // The bottom of this chain. Nothing beneath it was ever
                // committed *here*, and for a reshape successor what its
                // predecessor committed beneath it is refused by a
                // different rule — a transaction whose validity window
                // opened before the chain did cannot be admitted at all,
                // so there is nothing down there for this window to hold.
                window.reached_origin = true;
                window.fee_holds_whole = true;
                return window;
            }
            let Some(certified) = reader.get_block(height) else {
                // A gap inside the range, or the bottom of what this node
                // holds. Either way the window is short of the horizon.
                return window;
            };
            let block = certified.block();
            let anchor = block.header().parent_qc().weighted_timestamp();
            if anchor < fee_floor {
                // Below every floor: nothing this walk seeds reaches here.
                window.fee_holds_whole = true;
                return window;
            }
            if !dedup_done && anchor < dedup_floor {
                // Below the dedup floor: everything those tiers have to
                // cover is already folded, and this block is the proof of
                // it. The descent continues for the fee tier alone.
                window.covered_from = Some(anchor);
                dedup_done = true;
            }
            if !dedup_done {
                window.fold_block(block, anchor);
            }
            window.fold_fee_holds(block, committed_ts, &mut released);

            let Some(previous) = height.prev() else {
                // Height zero: there is no block beneath it anywhere.
                window.reached_origin = true;
                window.fee_holds_whole = true;
                return window;
            };
            height = previous;
        }
    }

    /// Fold one committed block's artifacts in, and record that coverage
    /// now reaches its anchor.
    ///
    /// `anchor` is the block's own `parent_qc` weighted timestamp, which
    /// the provision tier keys its deadline on.
    fn fold_block(&mut self, block: &Block, anchor: WeightedTimestamp) {
        self.covered_from = Some(self.covered_from.map_or(anchor, |from| from.min(anchor)));
        for tx in block.transactions().iter() {
            let deadline = Window::Delivery.of(Deadline::of_transaction(tx)).end;
            self.committed.push((tx.hash(), deadline));
        }
        for finalization in block.certificates().iter() {
            let deadline = finalization.local_ec().deadline();
            self.finalizations
                .push((finalization.receipt_hash(), deadline));
            // The names it *decided*, which is what the live index
            // records. A leg's finalization names its transaction
            // without resolving it, and the reclaim's finalization
            // naming the hash later is the one neither may refuse.
            for tx_hash in finalization.deciding_tx_hashes() {
                self.resolved.push((tx_hash, deadline));
            }
        }
        let provision_deadline = anchor.plus(RETENTION_HORIZON);
        for hash in block.provision_hashes() {
            self.provisions.push((hash, provision_deadline));
        }
    }

    /// Fold one committed block's fee reservations in: what its
    /// finalizations released, then what its transactions engaged and
    /// nothing above it released.
    ///
    /// Reads the same two events the live ledger does — a commit engages,
    /// a committed finalization releases — so a seeded ledger and one
    /// that ran the chain hold the same set. `released` accumulates
    /// across the descent because a finalization sits at or above the
    /// block that committed what it names, so the walk meets it first.
    ///
    /// A hold already past its deadline at `committed_ts` is dropped
    /// here rather than carried: the live ledger's prune would have taken
    /// it at the same instant.
    fn fold_fee_holds(
        &mut self,
        block: &Block,
        committed_ts: WeightedTimestamp,
        released: &mut HashSet<TxHash>,
    ) {
        for finalization in block.certificates().iter() {
            released.extend(finalization.tx_hashes());
        }
        for tx in block.transactions().iter() {
            let tx_hash = tx.hash();
            if released.contains(&tx_hash) {
                continue;
            }
            let terms = tx.terms();
            let deadline = tx
                .validity_range()
                .end_timestamp_exclusive
                .plus(RETENTION_HORIZON);
            if deadline <= committed_ts {
                continue;
            }
            self.fee_holds.push(FeeHold {
                tx_hash,
                payer: terms.fee_payer,
                max_fee: terms.max_fee,
                deadline,
            });
        }
    }

    /// A window covering nothing, and saying so.
    ///
    /// What a store with no chain beneath its tip yields — a snap-synced
    /// import sitting at its anchor. The gap closes on its own: the
    /// import is followed by a tail sync from the anchor to the live tip,
    /// and every block that commits deepens the coverage until it reaches
    /// the horizon. Since the anchor trails the tip by up to a full epoch
    /// and the horizon is under one, the tail alone often covers it.
    #[must_use]
    pub(crate) fn covering_nothing() -> Self {
        Self::default()
    }
}
