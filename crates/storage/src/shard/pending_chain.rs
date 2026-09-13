//! Chain-anchored pending state index.
//!
//! Single shared structure keyed by block hash. Reads happen through
//! [`SubstateView`], which is built by walking the parent chain from a
//! given anchor — orphaned blocks are not ancestors of the canonical
//! chain, so they are structurally invisible to anchored views.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, RwLock};

use hyperscale_jmt::{NibblePath, Node as JmtNode, NodeKey as JmtNodeKey, TreeReader};
use hyperscale_types::{
    BeaconWitnessLeafCount, BlockHash, BlockHeight, CertifiedBlock, CertifiedBlockHeader,
    ConsensusReceipt, DeclaredRange, EntryKey, ExecutionCertificate, Finalization,
    FinalizationHash, QuorumCertificate, RETENTION_HORIZON, ShardId, ShardWitnessPayload,
    StateRoot, SubstateKey, SweepBucket, SweepFrontier, TerminalRoots, TickId, Transaction, TxHash,
    Verifiable, Verified, WeightedTimestamp, committed_txs_root_from_hashes,
    local_settled_tx_hashes, settled_txs_root_from_hashes,
};
use hyperscale_vm_types::{Address, CollectionId};

use crate::lock_recover::{lock_or_recover, read_or_recover, write_or_recover};
use crate::{
    Anchored, BlockForSync, JmtSnapshot, ShardChainReader, SubstateStore, Substates, SweepIndex,
    VersionedStore, entry_overlay_range, merge_entry_overlay, merge_entry_overlay_with,
    merge_sweep_overlay,
};

/// Cached base-storage reads observed through a [`SubstateView`].
///
/// Populated lazily on every overlay-miss read; captured at commit time
/// and handed to `append_substate_writes_to_batch` so `capture_history`
/// can source priors without a fresh `multi_get_cf` on `StateCf`. Entries
/// are `SubstateKey → value-at-anchor`.
pub type BaseReadCache = HashMap<SubstateKey, Option<Vec<u8>>>;
/// Where a terminal-roots walk starts and stops.
///
/// Every field must resolve identically on the proposer and on each
/// verifier, or the attested roots diverge and the block reaches no
/// quorum: the parent pins the ancestry both walk, `anchor_wt` is the
/// block's parent-QC weighted timestamp, and `settled_window_floor` is the
/// schedule's settled-window floor. They travel as one value because they
/// are one agreement, not five arguments that happen to be passed together.
#[derive(Debug, Clone, Copy)]
pub struct TerminalWindow {
    /// The shard whose settlements the settled walk keys on.
    pub local_shard: ShardId,
    /// Hash of the block being built or verified over.
    pub parent_block_hash: BlockHash,
    /// Height of that parent.
    pub parent_block_height: BlockHeight,
    /// The block's parent-QC weighted timestamp.
    pub anchor_wt: WeightedTimestamp,
    /// The schedule's settled-window floor, which reaches the settled walk
    /// back to the reshape's admission. The committed walk has no
    /// equivalent — it floors at `anchor_wt − RETENTION_HORIZON` alone.
    pub settled_window_floor: Option<WeightedTimestamp>,
}

/// One block's worth of pending state, indexed by block hash in
/// [`PendingChain::entries`].
#[derive(Clone)]
pub struct ChainEntry {
    /// Parent block hash. Used to walk the chain back to the committed tip.
    pub parent_block_hash: BlockHash,
    /// Block height. Used for pruning and version-aware reads.
    pub height: BlockHeight,
    /// Tick-ids this shard settled in this block — the local execution
    /// certificate of each committed tick. Carried from insert (the
    /// certificates exist before the QC attaches `certified_block`), so a
    /// settled-transaction window walk reaches a pending ancestor's contribution
    /// during the proposer's build, not just after commit.
    pub settled_txs: Vec<TxHash>,
    /// Hashes of the transactions this block carries. Carried from insert
    /// for the same reason as `settled_txs`: a pending ancestor has no
    /// attached block until the commit pipeline reaches it, so a
    /// committed-transaction window walk would miss its contribution
    /// during the proposer's build.
    pub committed_txs: Vec<TxHash>,
    /// JMT snapshot from this block's speculative state-root computation.
    pub jmt_snapshot: Arc<JmtSnapshot>,
    /// shard-committed block paired with its QC. `None` until the entry's
    /// block reaches the commit pipeline — JMT preparation happens before
    /// the QC arrives. Attached by
    /// [`PendingChain::attach_certified_block`] from
    /// `BlockCommitCoordinator::accumulate`, making the block visible to
    /// fetch handlers throughout the shard-committed / JMT-persisted window.
    pub certified_block: Option<Arc<Verified<CertifiedBlock>>>,
    /// Certified block whose commit is still pending — attached by
    /// [`PendingChain::attach_certified_uncommitted`] as soon as a QC
    /// verifies against the held block, before the round-contiguous
    /// child that commits it exists. Read only by block-sync serving
    /// ([`PendingChain::block_for_sync`]): a peer wedged below the
    /// certified tip may be exactly the vote the committing child
    /// needs, and fetchers adopt a served QC without committing on it,
    /// so serving a certified block that later loses its round is
    /// safe. Every other serving surface reads `certified_block` and
    /// keeps its committed-only meaning.
    pub certified_uncommitted: Option<Arc<Verified<CertifiedBlock>>>,
}

/// Append-only index of pending block state, shared between the `io_loop`
/// and dispatch closures via `Arc`.
///
/// **Anchored reads.** Reads happen through [`Self::view_at`], which
/// walks `parent_block_hash` back to the committed tip and flattens that
/// chain's pending state into a [`SubstateView`]. Orphaned blocks (whose
/// `parent_block_hash` doesn't lead back to the committed chain) are not
/// visited and contribute nothing — the orphan-corruption bug becomes
/// impossible by construction.
pub struct PendingChain<S> {
    base: Arc<S>,
    entries: RwLock<HashMap<BlockHash, ChainEntry>>,
    settled_window_memo: RwLock<Option<SettledWindowMemo>>,
}

/// Memoized committed-tail contribution to a terminating shard's
/// settled-transaction window (see [`PendingChain::settled_txs_in_window`]).
///
/// Valid only under a schedule-stable floor: the committed chain is linear
/// and immutable, so for a fixed `(shard, floor)` the accumulated set only
/// extends at the tip. Bounded by the window's cross-shard settlements —
/// the same set the wire cap bounds.
struct SettledWindowMemo {
    local_shard: ShardId,
    floor: WeightedTimestamp,
    /// Highest committed height folded into `set` (inclusive).
    upto: BlockHeight,
    set: std::collections::BTreeSet<TxHash>,
}

impl<S> PendingChain<S>
where
    S: SubstateStore + TreeReader + ShardChainReader + Sync + 'static,
{
    /// Create a new empty `PendingChain` over the given base storage.
    pub fn new(base: Arc<S>) -> Self {
        Self {
            base,
            entries: RwLock::new(HashMap::new()),
            settled_window_memo: RwLock::new(None),
        }
    }

    /// Append an entry.
    pub fn insert(&self, block_hash: BlockHash, entry: ChainEntry) {
        write_or_recover(&self.entries).insert(block_hash, entry);
    }

    /// Drop all entries with `height ≤ committed_height`. Called on
    /// `BlockPersisted`. Also drops cache entries whose anchor is at or
    /// below the committed height — higher-anchor views remain valid.
    pub fn prune(&self, committed_height: BlockHeight) {
        write_or_recover(&self.entries).retain(|_, e| e.height > committed_height);
    }

    /// Number of pending entries (for diagnostics / metrics).
    #[must_use]
    pub fn len(&self) -> usize {
        read_or_recover(&self.entries).len()
    }

    /// Whether the chain has any pending entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        read_or_recover(&self.entries).is_empty()
    }

    /// Build a view anchored at `(parent_block_hash, parent_height)`.
    ///
    /// The view sees state through `parent_block_hash` and all of its committed
    /// ancestors back to the persisted tip. Orphaned blocks not on this
    /// chain are invisible.
    ///
    /// `parent_height` is the explicit anchor height of `parent_block_hash`.
    /// Callers always supply both — the height is required to anchor base-storage
    /// reads at the block's own historical version even after the block has been
    /// pruned from the pending index (e.g. because it was persisted). Without
    /// an explicit height the fallback would read at `base.jmt_height()`, which
    /// drifts per-validator with persistence progress and silently leaks
    /// post-anchor writes into cross-shard execution.
    pub fn view_at(
        self: &Arc<Self>,
        parent_block_hash: BlockHash,
        parent_height: BlockHeight,
    ) -> Arc<SubstateView<S>> {
        Arc::new(self.build_view(parent_block_hash, parent_height))
    }

    /// Build a view anchored at the latest committed block.
    /// For actions without a natural parent (RPC reads, fetch handlers).
    ///
    /// If no blocks have been committed yet, returns a view with no
    /// pending entries (reads fall through to base storage).
    pub fn view_at_committed_tip(self: &Arc<Self>) -> Arc<SubstateView<S>> {
        self.base.committed_hash().map_or_else(
            || {
                Arc::new(SubstateView::base_only(
                    Arc::clone(&self.base),
                    self.base.jmt_height(),
                ))
            },
            |h| self.view_at(h, self.base.committed_height()),
        )
    }

    /// Attach the [`CertifiedBlock`] to the entry inserted earlier at
    /// JMT-prep time, making the block readable through
    /// [`Self::certified_block`] / [`Self::certified_header`] /
    /// [`Self::transactions_for_block`] while persistence is still
    /// catching up.
    ///
    /// Idempotent: a no-op if no entry exists for `block_hash` (the entry
    /// was pruned, or sync raced ahead of prepare). Callers don't need to
    /// special-case skipped commits.
    pub fn attach_certified_block(
        &self,
        block_hash: BlockHash,
        certified: Arc<Verified<CertifiedBlock>>,
    ) {
        if let Some(entry) = write_or_recover(&self.entries).get_mut(&block_hash) {
            entry.certified_block = Some(certified);
            // The committed handle supersedes the pre-commit one; the
            // committed-only accessors serve this entry from here on.
            entry.certified_uncommitted = None;
        }
    }

    /// Attach a certified block whose commit is still pending, making it
    /// servable through [`Self::block_for_sync`] only — see
    /// [`ChainEntry::certified_uncommitted`] for why the other serving
    /// surfaces don't read it. Returns `false` without attaching when no
    /// entry exists for `block_hash` (the block stays unservable to sync
    /// until commit); callers with a logging context should surface the
    /// miss.
    pub fn attach_certified_uncommitted(
        &self,
        block_hash: BlockHash,
        certified: Arc<Verified<CertifiedBlock>>,
    ) -> bool {
        if let Some(entry) = write_or_recover(&self.entries).get_mut(&block_hash) {
            entry.certified_uncommitted = Some(certified);
            true
        } else {
            false
        }
    }

    /// shard-committed block at `height`. Returns `Some` for any height
    /// `<= committed_height`, regardless of whether JMT persistence has
    /// caught up: the pending entry serves the unpersisted window, then
    /// the base store takes over.
    ///
    /// Forks may produce multiple pending entries at the same height;
    /// only the entry whose block won certification ever gets a
    /// `certified_block`, so iteration here is unambiguous.
    pub fn certified_block(&self, height: BlockHeight) -> Option<Arc<Verified<CertifiedBlock>>> {
        let pending = self.pending_certified_at(height);
        if pending.is_some() {
            return pending;
        }
        self.base.get_block(height).map(Arc::new)
    }

    /// Certified header at `height`. Header-only view of
    /// [`Self::certified_block`] — pending entry first, base store fallback.
    pub fn certified_header(
        &self,
        height: BlockHeight,
    ) -> Option<Arc<Verified<CertifiedBlockHeader>>> {
        if let Some(certified) = self.pending_certified_at(height) {
            return Some(Arc::new(certified.certified_header()));
        }
        self.base.get_certified_header(height).map(Arc::new)
    }

    /// Certified-but-uncommitted header at `height`, if any — the certified
    /// tip before its committing child exists, best-guessed by highest QC
    /// round when siblings certified. Serves remote-header fetches one
    /// height above the committed tip so a cross-shard consumer can
    /// complete a commit proof of the tip itself: the tip's committing QC
    /// travels only inside this header, and if the chain stalls here no
    /// later commit will ever gossip it. A losing sibling served by the
    /// guess is harmless — it fails the consumer's parent-hash link and
    /// proves nothing.
    pub fn certified_uncommitted_header(
        &self,
        height: BlockHeight,
    ) -> Option<Arc<Verified<CertifiedBlockHeader>>> {
        self.pending_certified_uncommitted_at(height)
            .map(|certified| Arc::new(certified.certified_header()))
    }

    /// Transactions in the block at `height`. Pending entry first, base
    /// store fallback. Each tx is `Arc`-cloned from the pending block —
    /// callers receive shared refcounts, not deep copies.
    pub fn transactions_for_block(
        &self,
        height: BlockHeight,
    ) -> Option<Vec<Arc<Verifiable<Transaction>>>> {
        if let Some(certified) = self.pending_certified_at(height) {
            return Some(certified.block().transactions().iter().cloned().collect());
        }
        let certified = self.base.get_block(height)?;
        Some(certified.block().transactions().iter().cloned().collect())
    }

    /// Sync-ready bundle for block at `height`: block + QC +
    /// provision-hash list, spanning pending and persisted.
    ///
    /// Pending entries preserve the [`Block::Live`] shape — provisions
    /// stay inline, ready to ship without a cache round-trip. The
    /// `provision_hashes` list is still populated so the caller's
    /// dedup-horizon gate can short-circuit when the block carries no
    /// provisions. Persisted heights delegate to the base store's
    /// [`ShardChainReader::get_block_for_sync`], which returns
    /// [`Block::Sealed`](hyperscale_types::Block::Sealed) paired with the manifest's hashes.
    ///
    /// [`Block::Live`]: hyperscale_types::Block::Live
    pub fn block_for_sync(&self, height: BlockHeight) -> Option<BlockForSync> {
        // Committed entry first; then a certified-but-uncommitted one —
        // the fetcher adopts the QC without committing on it, so the
        // certified tip is servable before its committing child exists.
        let pending = self
            .pending_certified_at(height)
            .or_else(|| self.pending_certified_uncommitted_at(height));
        if let Some(certified) = pending {
            let block = certified.block().clone();
            let qc = certified.qc().clone();
            let provision_hashes = block.provision_hashes();
            return Some(BlockForSync {
                block,
                qc,
                provision_hashes,
            });
        }
        self.base.get_block_for_sync(height)
    }

    /// The commitments a terminating boundary header carries, both walked
    /// over the block being built or verified and the committed window
    /// behind it.
    ///
    /// One call because one predicate governs both: a header carries the
    /// pair or neither, so computing one without the other has no caller.
    /// The two walks differ in reach and in what they fold. The settled
    /// side runs over `[min(anchor_wt, settled_window_floor) −
    /// RETENTION_HORIZON, parent]`, because a counterpart's fence can hold
    /// a straddler admitted as far back as the reshape; the committed side
    /// floors at `anchor_wt − RETENTION_HORIZON`, because a successor only
    /// asks about transactions whose validity window is still open.
    ///
    /// `window` is where both walks start and stop; `own_certificates` and
    /// `own_txs` are what the block under construction contributes.
    #[must_use]
    pub fn terminal_roots_in_window(
        &self,
        window: &TerminalWindow,
        own_certificates: &[Arc<Verifiable<Finalization>>],
        own_txs: Vec<TxHash>,
    ) -> TerminalRoots {
        let settled = self.settled_txs_in_window(
            window.local_shard,
            window.parent_block_hash,
            window.parent_block_height,
            window.anchor_wt,
            window.settled_window_floor,
            local_settled_tx_hashes(own_certificates, window.local_shard),
        );
        let committed = self.committed_txs_in_window(
            window.parent_block_hash,
            window.parent_block_height,
            window.anchor_wt,
            own_txs,
        );
        TerminalRoots {
            settled_txs: settled_txs_root_from_hashes(settled.iter()),
            committed_txs: committed_txs_root_from_hashes(committed.iter()),
        }
    }

    /// Every transaction committed across the window, unioned with `own`
    /// (the block being built or verified).
    ///
    /// Structurally the settled walk's twin — pending prefix by hash, then
    /// the committed tail by height until a block falls below the floor —
    /// but it folds each block's whole transaction list rather than
    /// filtering certificates, and it takes no schedule-supplied floor.
    /// The settled root reaches back to the reshape's admission because a
    /// counterpart's fence can hold a straddler that old; a successor only
    /// asks about transactions whose validity window is still open, and
    /// nothing committed below `anchor_wt − RETENTION_HORIZON` can be.
    ///
    /// Pure over the parent chain, so the proposer (parent still pending)
    /// and every verifier (parent committed) walk the same ancestors and
    /// derive the same root.
    pub fn committed_txs_in_window(
        &self,
        parent_block_hash: BlockHash,
        parent_block_height: BlockHeight,
        anchor_wt: WeightedTimestamp,
        own: Vec<TxHash>,
    ) -> std::collections::BTreeSet<TxHash> {
        let mut set: std::collections::BTreeSet<TxHash> = own.into_iter().collect();
        // Pending prefix: walk by hash so a certified-but-unattached
        // ancestor still resolves. These sit within the window by
        // construction and carry no QC to test a floor against.
        let mut hash = parent_block_hash;
        let mut height = parent_block_height;
        {
            let entries = read_or_recover(&self.entries);
            while let Some(entry) = entries.get(&hash) {
                set.extend(entry.committed_txs.iter().copied());
                hash = entry.parent_block_hash;
                let Some(prev) = height.prev() else { break };
                height = prev;
            }
        }
        // Committed tail, floored on each block's own `parent_qc` weighted
        // timestamp — the canonical, hash-pinned value, identical on every
        // node. The served certifying QC must not gate it: a coast past
        // the crossing can re-issue that QC at a higher round with a
        // divergent timestamp, and a per-node-variable cutoff would
        // diverge the attested root.
        let floor = anchor_wt
            .as_millis()
            .saturating_sub(RETENTION_HORIZON.as_secs() * 1000);
        let mut h = height;
        loop {
            let Some(entry) = self.block_for_sync(h) else {
                break;
            };
            if entry
                .block
                .header()
                .parent_qc()
                .weighted_timestamp()
                .as_millis()
                < floor
            {
                break;
            }
            set.extend(entry.block.transactions().iter().map(|tx| tx.hash()));
            let Some(prev) = h.prev() else { break };
            h = prev;
        }
        set
    }

    /// The tick-ids `local_shard` settled across the window, unioned with
    /// `own` (the block being built or verified). Walks the parent's
    /// pending prefix by hash (each entry carries its settled transaction-ids
    /// from insert, so a not-yet-attached ancestor still contributes),
    /// then the committed tail by height until a block falls below the
    /// floor: `RETENTION_HORIZON` behind `anchor_wt`, extended down to
    /// `window_floor` when the schedule supplies one — the reach back to
    /// the reshape's admission that covers every settlement a counterpart
    /// fence can still be holding a straddler against.
    ///
    /// Pure over the parent chain: the proposer (parent still pending) and
    /// every verifier (parent committed) walk the same ancestors and
    /// produce the same set, so the settled-transaction root they derive agrees.
    /// A terminal committee serving a counterpart its window list reads the
    /// same set off the committed tail (`own` is the terminal block's own
    /// settled transaction-ids, its prefix the committed ancestors), so the served
    /// list recomputes to the attested root.
    pub fn settled_txs_in_window(
        &self,
        local_shard: ShardId,
        parent_block_hash: BlockHash,
        parent_block_height: BlockHeight,
        anchor_wt: WeightedTimestamp,
        window_floor: Option<WeightedTimestamp>,
        own: Vec<TxHash>,
    ) -> std::collections::BTreeSet<TxHash> {
        let mut set: std::collections::BTreeSet<TxHash> = own.into_iter().collect();
        // Pending prefix: walk by hash so a certified-but-unattached
        // ancestor still resolves. These ancestors sit within the window by
        // construction (they are the recent uncommitted tip), so they need
        // no floor test — and a pending entry carries no QC to test against.
        let mut hash = parent_block_hash;
        let mut height = parent_block_height;
        {
            let entries = read_or_recover(&self.entries);
            while let Some(entry) = entries.get(&hash) {
                set.extend(entry.settled_txs.iter().copied());
                hash = entry.parent_block_hash;
                let Some(prev) = height.prev() else { break };
                height = prev;
            }
        }
        // Committed tail: read by height (the committed chain is linear, so
        // height is unambiguous) until a block's weighted timestamp falls
        // below the retention floor. A schedule-supplied floor is fixed for
        // the whole scheduled window, so its walk is memoized; the anchor
        // floor moves with every block and spans only the horizon, so it
        // walks plainly.
        let anchor_floor = anchor_wt
            .as_millis()
            .saturating_sub(RETENTION_HORIZON.as_secs() * 1000);
        if let Some(floor) = window_floor.filter(|f| f.as_millis() <= anchor_floor) {
            set.extend(self.committed_settled_window(local_shard, floor, height));
        } else {
            let floor = WeightedTimestamp::from_millis(anchor_floor);
            self.walk_committed_settled(local_shard, floor, height, None, &mut set);
        }
        set
    }

    /// The committed-tail contribution to a settled-transaction window under a
    /// schedule-stable floor: every tick `local_shard` settled in a
    /// committed block with weighted timestamp at or above `floor`, at
    /// heights up to `upto` (inclusive).
    ///
    /// Memoized: the committed chain is linear and immutable, so for a
    /// fixed floor the set only extends at the tip. A terminating shard's
    /// window reaches back to its reshape's admission — several epochs of
    /// blocks — and is recomputed on every coast proposal and every
    /// verification of one; without the memo each call re-walks the whole
    /// span. A call the memo doesn't cover (a lower height than already
    /// folded, or a different floor) walks in full and leaves it alone.
    fn committed_settled_window(
        &self,
        local_shard: ShardId,
        floor: WeightedTimestamp,
        upto: BlockHeight,
    ) -> std::collections::BTreeSet<TxHash> {
        let covered: Option<(BlockHeight, std::collections::BTreeSet<TxHash>)> =
            read_or_recover(&self.settled_window_memo)
                .as_ref()
                .filter(|m| m.local_shard == local_shard && m.floor == floor && m.upto <= upto)
                .map(|m| (m.upto, m.set.clone()));
        let (covered_upto, mut set) = match covered {
            Some((u, s)) => (Some(u), s),
            None => (None, std::collections::BTreeSet::new()),
        };
        self.walk_committed_settled(local_shard, floor, upto, covered_upto, &mut set);

        let mut memo = write_or_recover(&self.settled_window_memo);
        if memo
            .as_ref()
            .is_none_or(|m| m.local_shard != local_shard || m.floor != floor || m.upto < upto)
        {
            *memo = Some(SettledWindowMemo {
                local_shard,
                floor,
                upto,
                set: set.clone(),
            });
        }
        set
    }

    /// Walk the committed chain downward from `upto`, folding
    /// `local_shard`'s settled transaction-ids into `set`, stopping below `floor`
    /// or at `covered_upto` (heights at or below it are already folded).
    ///
    /// The floor reads each block's own `parent_qc` weighted timestamp —
    /// the same canonical, hash-pinned value the window anchor is,
    /// identical on every node. The served certifying QC must not gate the
    /// floor: a coast past the crossing can re-issue it at a higher round
    /// with a divergent timestamp, and a per-node-variable cutoff would
    /// diverge the attested root.
    fn walk_committed_settled(
        &self,
        local_shard: ShardId,
        floor: WeightedTimestamp,
        upto: BlockHeight,
        covered_upto: Option<BlockHeight>,
        set: &mut std::collections::BTreeSet<TxHash>,
    ) {
        let mut h = upto;
        while covered_upto != Some(h) {
            let Some(entry) = self.block_for_sync(h) else {
                break;
            };
            let block_wt = entry.block.header().parent_qc().weighted_timestamp();
            if block_wt.as_millis() < floor.as_millis() {
                break;
            }
            set.extend(local_settled_tx_hashes(
                entry.block.certificates().iter(),
                local_shard,
            ));
            let Some(prev) = h.prev() else { break };
            h = prev;
        }
    }

    /// Most recent QC observed by this chain. Pending entries shadow the
    /// persisted tip — the QC certifying the highest shard-committed block
    /// is the highest-height pending entry's, then the base store's
    /// `latest_qc`. Used by sync-serving handlers to compute the dedup
    /// horizon without needing raw `&S`.
    pub fn latest_qc(&self) -> Option<Verified<QuorumCertificate>> {
        let entries = read_or_recover(&self.entries);
        let pending_qc = entries
            .values()
            .filter_map(|e| {
                e.certified_block
                    .as_ref()
                    .map(|c| (e.height, c.qc_verified()))
            })
            .max_by_key(|(h, _)| *h)
            .map(|(_, qc)| qc.clone());
        drop(entries);
        pending_qc.or_else(|| self.base.latest_qc())
    }

    /// Batched transaction read by hash. The pending window is covered by
    /// the mempool's `TxStore` (tombstone retention outlives JMT
    /// persistence lag by orders of magnitude), so this method is a
    /// thin pass-through to base storage; keeping it on `PendingChain`
    /// preserves the "no raw `&S` in serve handlers" invariant.
    pub fn transactions_batch(&self, hashes: &[TxHash]) -> Vec<Verified<Transaction>> {
        self.base.get_transactions_batch(hashes)
    }

    /// Batched attestation read by identity. Pass-through to base storage —
    /// pending entries don't carry attestations, only the receipts that
    /// contribute to them.
    pub fn certificates_batch(&self, ids: &[FinalizationHash]) -> Vec<Finalization> {
        self.base.get_certificates_batch(ids)
    }

    /// Consensus receipt by tx hash. Pass-through to base storage.
    pub fn consensus_receipt(&self, tx_hash: &TxHash) -> Option<Arc<ConsensusReceipt>> {
        self.base.get_consensus_receipt(tx_hash)
    }

    /// Batched execution-certificate read by `TickId`. Pass-through to
    /// base storage.
    pub fn execution_certificates_batch(
        &self,
        ids: &[TickId],
    ) -> Vec<Verified<ExecutionCertificate>> {
        self.base.get_execution_certificates_batch(ids)
    }

    /// The execution certificates carrying outcomes for `tx_hashes`,
    /// deduplicated. Pass-through to base storage.
    pub fn execution_certificates_for_txs(
        &self,
        tx_hashes: &[TxHash],
    ) -> Vec<Verified<ExecutionCertificate>> {
        self.base.get_execution_certificates_for_txs(tx_hashes)
    }

    /// Beacon-witness payloads in leaf-index order up to (but not
    /// including) `end`. Pass-through to base storage.
    pub fn get_beacon_witness_payloads(
        &self,
        end: BeaconWitnessLeafCount,
    ) -> Vec<ShardWitnessPayload> {
        self.base.get_beacon_witness_payloads(end)
    }

    /// Beacon-witness payloads with leaf indices in `[start, end)`.
    /// Pass-through to base storage.
    pub fn get_beacon_witness_payload_range(
        &self,
        start: u64,
        end: u64,
    ) -> Vec<ShardWitnessPayload> {
        self.base.get_beacon_witness_payload_range(start, end)
    }

    /// Look up the pending entry at `height` that has a `certified_block`
    /// attached. Scoped so the read lock drops before the result is used —
    /// holding it across the caller's match arms would chain the lock
    /// lifetime to base-storage reads on the fall-through path.
    fn pending_certified_at(&self, height: BlockHeight) -> Option<Arc<Verified<CertifiedBlock>>> {
        read_or_recover(&self.entries)
            .values()
            .find(|e| e.height == height && e.certified_block.is_some())
            .and_then(|e| e.certified_block.clone())
    }

    /// Certified-but-uncommitted entry at `height`, if any. Forks can
    /// certify two siblings at one height; only the one a
    /// round-contiguous child extends ever commits. Serving the highest
    /// QC round is a best guess at that winner — the committing child
    /// extends the newest QC its proposer holds, which is usually the
    /// newest QC anyone holds. A wrong guess is safe: fetchers track
    /// applied blocks by height and hash, so one that applied a losing
    /// sibling applies the winner on a later fetch instead of treating
    /// the height as done.
    fn pending_certified_uncommitted_at(
        &self,
        height: BlockHeight,
    ) -> Option<Arc<Verified<CertifiedBlock>>> {
        read_or_recover(&self.entries)
            .values()
            .filter(|e| e.height == height)
            .filter_map(|e| e.certified_uncommitted.clone())
            .max_by_key(|certified| certified.qc().round())
    }

    /// Walk `parent_block_hash` back through ancestors and flatten the chain
    /// into a `SubstateView`. Stops when an entry's parent is not in the
    /// index (it's been persisted, or it's the committed tip).
    ///
    /// Holds the read lock for the duration of the walk; no per-entry
    /// clones.
    fn build_view(
        &self,
        parent_block_hash: BlockHash,
        parent_height: BlockHeight,
    ) -> SubstateView<S> {
        let entries = read_or_recover(&self.entries);
        let mut chain: Vec<&ChainEntry> = Vec::new();
        let mut cursor = parent_block_hash;
        while let Some(entry) = entries.get(&cursor) {
            cursor = entry.parent_block_hash;
            chain.push(entry);
        }
        // Walk produces deepest-first; flip to commit order.
        chain.reverse();
        // Anchor at the caller-supplied height — the block's own historical
        // version. If the walk found pending entries, the chain tip's height
        // must match (we panic on mismatch — caller bug, would silently
        // diverge state otherwise). If the chain is empty the block has
        // already been persisted out of pending, and the caller's height is
        // the only correct anchor.
        if let Some(tip) = chain.last() {
            assert_eq!(
                tip.height, parent_height,
                "view_at(parent_block_hash={parent_block_hash:?}, parent_height={parent_height}) \
                 but pending entry at that hash has height {} — caller bug",
                tip.height,
            );
        }
        SubstateView::from_chain(Arc::clone(&self.base), &chain, parent_height)
    }
}

// ─── SubstateView ───────────────────────────────────────────────────────

/// Flattened overlay entries: `SubstateKey → Some(value)` or `None`
/// (tombstone).
type OverlayEntries = HashMap<SubstateKey, Option<Vec<u8>>>;

/// JMT node index for O(1) tree-node lookup during proof generation.
type JmtNodeIndex = HashMap<JmtNodeKey, Arc<JmtNode>>;

/// Anchored read view over base storage + a slice of pending blocks.
///
/// Built once per anchor by [`PendingChain::view_at`] and cached via an
/// `Arc`. Implements [`Substates`], [`SubstateStore`],
/// [`ShardChainWriter`](crate::ShardChainWriter), and `jmt::TreeReader` so it can substitute
/// for the base storage in delegated action handlers.
///
/// Once built the view is immutable — interior data is never mutated.
/// This makes `Arc<SubstateView>` cheap to share across threads and
/// simplifies cache invalidation (the cache drops `Arc` references; live
/// views remain valid).
pub struct SubstateView<S> {
    base: Arc<S>,
    /// Block height of the anchor — the chain's tip, or the base's
    /// `jmt_height()` when the view has no pending entries. Used as the
    /// historical version for base-storage reads in [`Self::snapshot`],
    /// so the snapshot reflects state as-of this specific block rather
    /// than "whatever the validator has currently persisted." Critical
    /// for cross-validator determinism under persistence lag.
    anchor_height: BlockHeight,
    /// Flattened pending substates from the anchored chain, in commit order.
    /// Later entries override earlier ones for the same key.
    overlay: OverlayEntries,
    /// Flattened pending ordered-collection entries from the same chain,
    /// on the same last-writer-wins terms.
    overlay_entries: BTreeMap<EntryKey, Option<Vec<u8>>>,
    /// JMT snapshots from the same chain, in commit order. Exposed via
    /// [`Self::pending_snapshots`] so handlers can pass them to
    /// `prepare_block_commit` for chained verification.
    jmt_snapshots: Vec<Arc<JmtSnapshot>>,
    /// JMT node index built from `jmt_snapshots` for O(1) lookup
    /// (see [`jmt::TreeReader`] impl).
    jmt_nodes: JmtNodeIndex,
    /// Per-block settled writes for versioned queries
    /// ([`SubstateStore::get_substate_at_height`]).
    /// Sorted by height ascending.
    versioned_settled: Vec<(BlockHeight, Arc<JmtSnapshot>)>,
    /// Lazy cache of base-storage reads observed through this view.
    /// Populated on every overlay-miss `get_raw_substate_by_db_key` call.
    /// Consumed at commit time by `take_base_reads` so `capture_history`
    /// can skip a `multi_get_cf` on `StateCf` for keys execution already
    /// read. Arc-shared with derived `ViewSnapshot`s so reads through
    /// either path populate the same cache.
    base_reads: Arc<Mutex<BaseReadCache>>,
}

impl<S> SubstateView<S> {
    /// Pending JMT snapshots from the anchored chain, in commit order.
    /// Carry into a `ParentAnchor` so chained verification can find tree
    /// nodes from prior unpersisted blocks and the prepared batch can
    /// judge its priors against them.
    #[must_use]
    pub fn pending_snapshots(&self) -> &[Arc<JmtSnapshot>] {
        &self.jmt_snapshots
    }

    /// The persisted store this view reads through — the writer a
    /// commit pipeline anchors this view's state on.
    #[must_use]
    pub const fn base(&self) -> &Arc<S> {
        &self.base
    }
}

impl<S> SubstateView<S> {
    /// Build a view with no pending entries (reads always go to base).
    fn base_only(base: Arc<S>, anchor_height: BlockHeight) -> Self {
        Self {
            base,
            anchor_height,
            overlay: HashMap::new(),
            overlay_entries: BTreeMap::new(),
            jmt_snapshots: Vec::new(),
            jmt_nodes: HashMap::new(),
            versioned_settled: Vec::new(),
            base_reads: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Drain the cache of base-storage reads observed through this view.
    ///
    /// The returned map holds one entry per distinct key that was read
    /// from base (not overlay) during the view's
    /// lifetime — i.e. exactly the priors `capture_history` would
    /// otherwise re-read from `StateCf` at commit time. Called by the
    /// commit pipeline to skip the `multi_get_cf` on `StateCf` for keys
    /// already in the cache.
    #[must_use]
    pub fn take_base_reads(&self) -> BaseReadCache {
        std::mem::take(&mut *lock_or_recover(&self.base_reads))
    }
}

/// Apply overlay entries on top of a base `Substates` read.
///
/// If `base_reads_cache` is provided, every base-storage read (overlay
/// miss) is recorded there exactly once per key — the first observed
/// value wins. The cache is handed to `capture_history` at commit time
/// so priors for keys execution already read don't require a fresh
/// `multi_get_cf` on `StateCf`.
fn overlay_get(
    overlay: &OverlayEntries,
    base: &dyn Substates,
    key: SubstateKey,
    base_reads_cache: Option<&Mutex<BaseReadCache>>,
) -> Option<Vec<u8>> {
    if let Some(v) = overlay.get(&key) {
        return v.clone();
    }
    let value = base.cell(key);
    if let Some(cache) = base_reads_cache {
        lock_or_recover(cache)
            .entry(key)
            .or_insert_with(|| value.clone());
    }
    value
}

impl<S: Substates> SubstateView<S> {
    /// Build a view from a chain of entries in commit order (earliest first).
    /// Takes borrowed entries so the caller can hold a read lock over the
    /// chain index for the duration of the walk without cloning.
    ///
    /// `anchor_height` is the height of the view's anchor — the chain's
    /// tip (last entry) when non-empty, or the base's committed tip when
    /// the walk produced nothing.
    fn from_chain(base: Arc<S>, chain: &[&ChainEntry], anchor_height: BlockHeight) -> Self {
        let mut overlay: OverlayEntries = HashMap::new();
        let mut jmt_snapshots: Vec<Arc<JmtSnapshot>> = Vec::with_capacity(chain.len());
        let mut jmt_nodes: JmtNodeIndex = HashMap::new();
        let mut versioned_settled: Vec<(BlockHeight, Arc<JmtSnapshot>)> =
            Vec::with_capacity(chain.len());

        // The walk is in commit order and every entry states its cells
        // outright, so a later block's value replaces an earlier one's.
        // Nothing resolves here, and nothing may: a movement resolves
        // against the state its own block's parent left, which the
        // committing block already did. A second resolution would have
        // to pick a baseline, and the only one on hand is however far
        // this validator has persisted — which is not a quantity
        // consensus agrees on.
        let mut overlay_entries: BTreeMap<EntryKey, Option<Vec<u8>>> = BTreeMap::new();
        for entry in chain {
            for (key, change) in entry.jmt_snapshot.settled.cells() {
                overlay.insert(*key, change.clone());
            }
            for (key, change) in entry.jmt_snapshot.settled.entries() {
                overlay_entries.insert(*key, change.clone());
            }
            for (key, node) in &entry.jmt_snapshot.nodes {
                jmt_nodes.insert(key.clone(), Arc::clone(node));
            }
            versioned_settled.push((entry.height, Arc::clone(&entry.jmt_snapshot)));
            jmt_snapshots.push(Arc::clone(&entry.jmt_snapshot));
        }

        Self {
            base,
            anchor_height,
            overlay,
            overlay_entries,
            jmt_snapshots,
            jmt_nodes,
            versioned_settled,
            base_reads: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<S: Substates> Substates for SubstateView<S> {
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        overlay_get(&self.overlay, &*self.base, key, Some(&self.base_reads))
    }

    fn entries_in_range(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        merge_entry_overlay(
            &*self.base,
            entry_overlay_range(&self.overlay_entries, owner, collection, lo, hi),
            owner,
            collection,
            lo,
            hi,
            limit,
        )
    }
}

/// Snapshot from a `SubstateView` — overlays the same entries on the
/// base storage's snapshot.
pub struct ViewSnapshot<Snap> {
    base_snapshot: Snap,
    /// The view's anchor, which is the height `base_snapshot` reads at.
    anchor: BlockHeight,
    overlay: Arc<OverlayEntries>,
    overlay_entries: Arc<BTreeMap<EntryKey, Option<Vec<u8>>>>,
    /// Shared with the parent `SubstateView` so reads through this
    /// snapshot populate the same cache as direct-impl reads.
    base_reads: Arc<Mutex<BaseReadCache>>,
}

impl<Snap: Substates> Substates for ViewSnapshot<Snap> {
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        overlay_get(
            &self.overlay,
            &self.base_snapshot,
            key,
            Some(&self.base_reads),
        )
    }

    fn entries_in_range(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        merge_entry_overlay(
            &self.base_snapshot,
            entry_overlay_range(&self.overlay_entries, owner, collection, lo, hi),
            owner,
            collection,
            lo,
            hi,
            limit,
        )
    }
}

impl<Snap: Substates> Anchored for ViewSnapshot<Snap> {
    fn anchor(&self) -> BlockHeight {
        self.anchor
    }
}

impl<S: SubstateStore + VersionedStore + SweepIndex> SweepIndex for SubstateView<S> {
    fn sweep_candidates(
        &self,
        after: SweepFrontier,
        below: SweepBucket,
        limit: usize,
    ) -> Vec<(SubstateKey, u64)> {
        // Resolved through the overlay, never against the persisted
        // store. Those differ, and both directions move the state root:
        // a cell an unpersisted ancestor created reads as absent, so a
        // removal the chain owes goes unmade; a cell one retired reads
        // as live, so a removal is made twice and the second lands on a
        // key the tree no longer holds.
        //
        // The merge only closes the gap in one direction. The base's
        // index answers at whatever the store has persisted, and the
        // overlay carries the blocks from there up to the anchor — so a
        // store *ahead* of the anchor by blocks the overlay does not hold
        // has already retired rows this walk would still be told about,
        // and the removal set comes out wrong. Refused here rather than
        // computed: the alternative is a state root that differs from
        // every peer's, which the commit path answers with the same
        // fatality one block later and without naming the cause.
        assert!(
            self.base.jmt_height() <= self.anchor_height,
            "BFT CRITICAL: a sweep walk anchored at {} reads an index persisted to {}",
            self.anchor_height.inner(),
            self.base.jmt_height().inner(),
        );
        merge_sweep_overlay(
            |widened| self.base.sweep_candidates(after, below, widened),
            self.pending_snapshots(),
            after,
            below,
            limit,
        )
    }
}

impl<S: SubstateStore + VersionedStore> SubstateView<S> {
    /// Whether this view answers historical reads at `height`.
    ///
    /// The base's retention floor, asked rather than inferred: a server
    /// that decides by whether the tree still happens to hold a version's
    /// nodes answers for heights the store no longer promises, and the
    /// two servers that read history through this view would then answer
    /// differently for the same height.
    #[must_use]
    pub fn serves_at(&self, height: BlockHeight) -> bool {
        height.inner() >= self.base.retention_floor()
    }
}

impl<S: SubstateStore + VersionedStore> SubstateStore for SubstateView<S> {
    type Snapshot<'a>
        = ViewSnapshot<S::Snapshot<'a>>
    where
        Self: 'a;

    fn snapshot(&self) -> Self::Snapshot<'_> {
        // Base reads are anchored to the view's anchor height so that
        // keys not touched by any pending ancestor in the overlay resolve
        // to the value at the anchor — not "current StateCf", which would
        // leak post-anchor writes when this validator has persisted past
        // descendants that others haven't. This is the determinism fix
        // for cross-validator state_root computation.
        ViewSnapshot {
            base_snapshot: (*self.base).snapshot_at(self.anchor_height),
            anchor: self.anchor_height,
            // Clone the overlay into an Arc so the snapshot is `'static`
            // with respect to the view's overlay map.
            overlay: Arc::new(self.overlay.clone()),
            overlay_entries: Arc::new(self.overlay_entries.clone()),
            // Share the base-read cache so reads via either the view's
            // direct impl or this snapshot populate the same map.
            base_reads: Arc::clone(&self.base_reads),
        }
    }

    fn jmt_height(&self) -> BlockHeight {
        (*self.base).jmt_height()
    }

    fn state_root(&self) -> StateRoot {
        (*self.base).state_root()
    }

    fn get_substate_at_height(
        &self,
        key: SubstateKey,
        block_height: BlockHeight,
    ) -> Option<Option<Vec<u8>>> {
        let persisted_version = (*self.base).jmt_height();
        if block_height <= persisted_version {
            return (*self.base).get_substate_at_height(key, block_height);
        }

        // Base value at the persisted tip, then each pending block's
        // settled cells in commit order up to `block_height` — the
        // view's overlay walk, narrowed to one key.
        let mut value = (*self.base).get_substate_at_height(key, persisted_version)?;
        for (h, snapshot) in &self.versioned_settled {
            if *h > block_height {
                break;
            }
            if let Some(change) = snapshot.settled.cells().get(&key) {
                value.clone_from(change);
            }
        }
        Some(value)
    }

    fn get_entries_at_height(
        &self,
        range: DeclaredRange,
        block_height: BlockHeight,
    ) -> Option<Vec<(u128, Vec<u8>)>> {
        let persisted_version = (*self.base).jmt_height();
        if block_height <= persisted_version {
            return (*self.base).get_entries_at_height(range, block_height);
        }

        // Base interval at the persisted tip, then each pending block's
        // settled entries in commit order up to `block_height` — the
        // view's overlay walk, narrowed to one collection interval and
        // merged by the one widening rule every layered range read uses.
        let mut overlay: BTreeMap<EntryKey, Option<Vec<u8>>> = BTreeMap::new();
        for (h, snapshot) in &self.versioned_settled {
            if *h > block_height {
                break;
            }
            for (key, change) in snapshot.settled.entries() {
                overlay.insert(*key, change.clone());
            }
        }
        merge_entry_overlay_with(
            |widened| {
                let widened_range = DeclaredRange {
                    cap: u32::try_from(widened).unwrap_or(u32::MAX),
                    ..range
                };
                (*self.base).get_entries_at_height(widened_range, persisted_version)
            },
            entry_overlay_range(&overlay, range.owner, range.collection, range.lo, range.hi),
            range.cap as usize,
        )
    }
}

/// The JMT reader proof generation walks: pending snapshots' nodes over
/// the base store, so [`crate::tree::proofs::generate_proof`] over a
/// view serves persisted and unpersisted heights alike from one root
/// lookup.
impl<S: TreeReader + Send + Sync> TreeReader for SubstateView<S> {
    fn get_node(&self, key: &JmtNodeKey) -> Option<Arc<JmtNode>> {
        self.jmt_nodes
            .get(key)
            .cloned()
            .or_else(|| (*self.base).get_node(key))
    }

    fn get_root_key(&self, version: u64) -> Option<JmtNodeKey> {
        let root_key = JmtNodeKey::new(version, (*self.base).root_path());
        if self.jmt_nodes.contains_key(&root_key) {
            Some(root_key)
        } else {
            (*self.base).get_root_key(version)
        }
    }

    fn root_path(&self) -> NibblePath {
        (*self.base).root_path()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::PoisonError;

    use hyperscale_types::test_utils::{test_prefix, test_transaction};
    use hyperscale_types::{
        Address, AggregateSignature, Block, CertifiedBlock, CertifiedBlockHeader,
        ExecutionCertificate, ExecutionOutcome, Finalization, GlobalReceiptHash, GlobalReceiptRoot,
        Hash, LocalKey, Provisions, Round, SettledWrites, SignerBitfield, StateWrites, TickHalf,
        TickId, Transaction, TxHash, TxOutcome, WitnessSources,
    };

    use super::*;
    use crate::BlockForSync;

    /// Minimal stub implementing every trait `PendingChain<S>` requires.
    /// Returns no data by default; tests that need persisted fall-through
    /// for the chain-reader methods inject blocks via `with_block`.
    #[derive(Default)]
    struct StubStore {
        blocks: HashMap<BlockHeight, CertifiedBlock>,
        /// Persisted blocks served through [`ShardChainReader::get_block_for_sync`]
        /// — opt-in so the committed-tail walk can be exercised without the
        /// default-`None` boundary that `block_for_sync_falls_through_to_storage`
        /// pins.
        sync_blocks: HashMap<BlockHeight, BlockForSync>,
        /// Heights observed via [`VersionedStore::snapshot_at`]. Tests use
        /// this to assert that `view_at(hash, height)` anchors base reads
        /// at the supplied height rather than the live JMT tip.
        recorded_snapshot_at: Mutex<Vec<BlockHeight>>,
        /// What the store has persisted, for the sweep walk's guard —
        /// the one question that compares the base against the anchor.
        persisted: BlockHeight,
    }

    impl StubStore {
        fn with_block(mut self, certified: CertifiedBlock) -> Self {
            self.blocks.insert(certified.height(), certified);
            self
        }

        fn with_sync_block(mut self, height: BlockHeight, block: BlockForSync) -> Self {
            self.sync_blocks.insert(height, block);
            self
        }
    }

    impl Substates for StubStore {
        fn cell(&self, _key: SubstateKey) -> Option<Vec<u8>> {
            None
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

    /// Empty snapshot for `StubStore` — returns no data.
    struct StubSnapshot;
    impl Anchored for StubSnapshot {
        fn anchor(&self) -> BlockHeight {
            BlockHeight::GENESIS
        }
    }

    impl Substates for StubSnapshot {
        fn cell(&self, _key: SubstateKey) -> Option<Vec<u8>> {
            None
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

    impl SubstateStore for StubStore {
        type Snapshot<'a> = StubSnapshot;
        fn snapshot(&self) -> Self::Snapshot<'_> {
            StubSnapshot
        }
        fn jmt_height(&self) -> BlockHeight {
            self.persisted
        }
        fn state_root(&self) -> StateRoot {
            StateRoot::ZERO
        }
        fn get_entries_at_height(
            &self,
            _range: DeclaredRange,
            _block_height: BlockHeight,
        ) -> Option<Vec<(u128, Vec<u8>)>> {
            // Stub state holds no entries at any height.
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

    /// The empty index: what a store with nothing sweepable answers, and
    /// enough for the walk's own guard, which reads the heights and not
    /// the rows.
    impl SweepIndex for StubStore {}

    impl VersionedStore for StubStore {
        fn retention_floor(&self) -> u64 {
            0
        }

        fn snapshot_held_at(&self, height: BlockHeight) -> Option<Self::Snapshot<'_>> {
            (height <= self.persisted).then(|| self.snapshot_at(height))
        }

        fn snapshot_at(&self, height: BlockHeight) -> Self::Snapshot<'_> {
            self.recorded_snapshot_at
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(height);
            StubSnapshot
        }

        fn substate_bytes_at(&self, _height: BlockHeight) -> Option<u64> {
            None
        }
    }

    impl TreeReader for StubStore {
        fn get_node(&self, _key: &JmtNodeKey) -> Option<Arc<JmtNode>> {
            None
        }
        fn get_root_key(&self, _version: u64) -> Option<JmtNodeKey> {
            None
        }
        fn root_path(&self) -> NibblePath {
            NibblePath::empty()
        }
    }

    impl ShardChainReader for StubStore {
        fn provisions_at(&self, _height: BlockHeight) -> Vec<Arc<Verifiable<Provisions>>> {
            Vec::new()
        }

        fn get_block(&self, height: BlockHeight) -> Option<Verified<CertifiedBlock>> {
            self.blocks
                .get(&height)
                .cloned()
                .map(Verified::<CertifiedBlock>::from_persisted)
        }
        fn get_certified_header(
            &self,
            height: BlockHeight,
        ) -> Option<Verified<CertifiedBlockHeader>> {
            self.blocks.get(&height).map(|c| {
                Verified::<CertifiedBlockHeader>::from_persisted(CertifiedBlockHeader::new(
                    c.block().header().clone(),
                    c.qc().clone(),
                ))
            })
        }
        fn committed_height(&self) -> BlockHeight {
            BlockHeight::new(0)
        }
        fn committed_hash(&self) -> Option<BlockHash> {
            None
        }
        fn latest_qc(&self) -> Option<Verified<QuorumCertificate>> {
            None
        }
        fn get_block_for_sync(&self, height: BlockHeight) -> Option<BlockForSync> {
            self.sync_blocks.get(&height).cloned()
        }
        fn get_transactions_batch(&self, _hashes: &[TxHash]) -> Vec<Verified<Transaction>> {
            Vec::new()
        }
        fn get_certificates_batch(&self, _ids: &[FinalizationHash]) -> Vec<Finalization> {
            Vec::new()
        }
        fn get_consensus_receipt(&self, _tx_hash: &TxHash) -> Option<Arc<ConsensusReceipt>> {
            None
        }
        fn get_execution_certificate(
            &self,
            _tick_id: &TickId,
        ) -> Option<Verified<ExecutionCertificate>> {
            None
        }
        fn get_execution_certificates_batch(
            &self,
            _tick_ids: &[TickId],
        ) -> Vec<Verified<ExecutionCertificate>> {
            Vec::new()
        }
        fn get_execution_certificates_for_txs(
            &self,
            _tx_hashes: &[TxHash],
        ) -> Vec<Verified<ExecutionCertificate>> {
            Vec::new()
        }
        fn get_beacon_witness_payloads(
            &self,
            _end: BeaconWitnessLeafCount,
        ) -> Vec<ShardWitnessPayload> {
            Vec::new()
        }
        fn get_beacon_witness_payload_range(
            &self,
            _start: u64,
            _end: u64,
        ) -> Vec<ShardWitnessPayload> {
            Vec::new()
        }
    }

    fn cell(owner: Address, local: [u8; 16]) -> SubstateKey {
        SubstateKey {
            owner,
            local: LocalKey(local),
        }
    }

    fn make_writes(owner: Address, local: [u8; 16], value: Vec<u8>) -> StateWrites {
        let mut writes = StateWrites::default();
        writes.cells.insert(
            SubstateKey {
                owner,
                local: LocalKey(local),
            },
            Some(value),
        );
        writes
    }

    fn snapshot_of(settled: SettledWrites) -> Arc<JmtSnapshot> {
        Arc::new(JmtSnapshot {
            base_root: StateRoot::ZERO,
            base_height: BlockHeight::GENESIS,
            result_root: StateRoot::ZERO,
            new_height: BlockHeight::GENESIS,
            nodes: vec![],
            stale_node_keys: vec![],
            bytes_delta: 0,
            settled,
        })
    }

    fn empty_snapshot() -> Arc<JmtSnapshot> {
        snapshot_of(SettledWrites::default())
    }

    /// A block that settled `writes`. Resolved against an empty prior,
    /// as a block whose parent left the cells untouched would be.
    fn entry_at(parent: BlockHash, height: BlockHeight, writes: &StateWrites) -> ChainEntry {
        ChainEntry {
            parent_block_hash: parent,
            height,
            settled_txs: Vec::new(),
            committed_txs: Vec::new(),
            jmt_snapshot: snapshot_of(writes.resolve(&mut |_| None).expect("nothing moved")),
            certified_block: None,
            certified_uncommitted: None,
        }
    }

    fn bh(tag: &[u8]) -> BlockHash {
        BlockHash::from_raw(Hash::from_bytes(tag))
    }

    fn empty_chain() -> Arc<PendingChain<StubStore>> {
        Arc::new(PendingChain::new(Arc::new(StubStore::default())))
    }

    fn chain_with_persisted(blocks: Vec<CertifiedBlock>) -> Arc<PendingChain<StubStore>> {
        let mut stub = StubStore::default();
        for b in blocks {
            stub = stub.with_block(b);
        }
        Arc::new(PendingChain::new(Arc::new(stub)))
    }

    #[test]
    fn prune_drops_old_entries() {
        let chain = empty_chain();
        let h1 = bh(b"h1");
        let h2 = bh(b"h2");
        let h3 = bh(b"h3");
        chain.insert(
            h1,
            entry_at(
                BlockHash::ZERO,
                BlockHeight::new(1),
                &StateWrites::default(),
            ),
        );
        chain.insert(
            h2,
            entry_at(h1, BlockHeight::new(2), &StateWrites::default()),
        );
        chain.insert(
            h3,
            entry_at(h2, BlockHeight::new(3), &StateWrites::default()),
        );

        chain.prune(BlockHeight::new(2));
        assert_eq!(read_or_recover(&chain.entries).len(), 1);
        assert!(read_or_recover(&chain.entries).contains_key(&h3));
    }

    #[test]
    fn view_at_walks_parent_chain() {
        let chain = empty_chain();
        let h1 = bh(b"h1");
        let h2 = bh(b"h2");

        let owner = test_prefix(7);

        chain.insert(
            h1,
            entry_at(
                BlockHash::ZERO,
                BlockHeight::new(1),
                &make_writes(owner, [1; 16], vec![10]),
            ),
        );
        chain.insert(
            h2,
            entry_at(
                h1,
                BlockHeight::new(2),
                &make_writes(owner, [2; 16], vec![20]),
            ),
        );

        let view = chain.view_at(h2, BlockHeight::new(2));
        // h2's parent chain: h2 → h1 → ZERO. Should see both writes.
        assert_eq!(view.cell(cell(owner, [1; 16])), Some(vec![10]));
        assert_eq!(view.cell(cell(owner, [2; 16])), Some(vec![20]));
    }

    #[test]
    fn orphans_are_invisible_to_committed_chain_view() {
        let chain = empty_chain();
        let h1 = bh(b"h1");
        let orphan = bh(b"orphan");

        let owner = test_prefix(7);

        chain.insert(
            h1,
            entry_at(
                BlockHash::ZERO,
                BlockHeight::new(1),
                &make_writes(owner, [1; 16], vec![10]),
            ),
        );
        // Orphan: same height as h1, different parent (forks off ZERO).
        chain.insert(
            orphan,
            entry_at(
                BlockHash::ZERO,
                BlockHeight::new(1),
                &make_writes(owner, [1; 16], vec![99]),
            ),
        );

        // View anchored at h1: should see h1's value, not the orphan's.
        let view = chain.view_at(h1, BlockHeight::new(1));
        assert_eq!(view.cell(cell(owner, [1; 16])), Some(vec![10]));
    }

    #[test]
    fn view_at_anchors_at_supplied_height_after_block_pruned() {
        // Persistence-race regression: a block that's been pruned from
        // pending entries (because it was persisted) must still anchor
        // its snapshot reads at its own historical version, not at the
        // base's current `jmt_height()`. Pre-fix, the fallback in
        // `build_view` used `base.jmt_height()` whenever the walk produced
        // no pending entries — silently drifting to whatever each
        // validator had persisted, with cross-validator divergence the
        // result.
        let chain = empty_chain();
        let h1 = bh(b"h1");
        let target_height = BlockHeight::new(5);

        chain.insert(
            h1,
            entry_at(BlockHash::ZERO, target_height, &StateWrites::default()),
        );
        // Simulate persistence: prune the pending entry while leaving the
        // base store at its default `jmt_height = GENESIS`. The two
        // values differ — a pre-fix `view_at(h1)` would anchor at
        // GENESIS, not 5.
        chain.prune(target_height);
        assert!(read_or_recover(&chain.entries).is_empty());

        let view = chain.view_at(h1, target_height);
        assert!(view.pending_snapshots().is_empty());

        // Derive a snapshot — `SubstateStore::snapshot` calls
        // `base.snapshot_at(view.anchor_height)`. The stub records each
        // height observed there.
        let _snapshot = <SubstateView<_> as SubstateStore>::snapshot(&*view);
        let recorded: Vec<BlockHeight> = chain
            .base
            .recorded_snapshot_at
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        assert_eq!(
            recorded,
            vec![target_height],
            "snapshot must be anchored at the supplied parent_height, not base.jmt_height()",
        );
    }

    #[test]
    #[should_panic(expected = "caller bug")]
    fn view_at_panics_on_height_mismatch_with_pending_entry() {
        // The chain-present branch asserts that the supplied `parent_height`
        // matches the pending entry's recorded height. Drift between hash
        // and height would silently produce a divergent snapshot, so we
        // turn it into a hard panic rather than a latent corruption.
        let chain = empty_chain();
        let h1 = bh(b"h1");
        chain.insert(
            h1,
            entry_at(
                BlockHash::ZERO,
                BlockHeight::new(5),
                &StateWrites::default(),
            ),
        );
        let _view = chain.view_at(h1, BlockHeight::new(7));
    }

    #[test]
    fn view_at_committed_tip_with_no_commits_returns_base_only() {
        let chain = empty_chain();
        let view = chain.view_at_committed_tip();
        assert_eq!(view.cell(cell(test_prefix(9), [1; 16])), None);
    }

    // ── chain reader accessors ────────────────────────────────────────

    use crate::test_helpers::{make_test_block, make_test_block_with_anchor_wt, make_test_qc};

    fn make_certified(height: BlockHeight) -> Arc<Verified<CertifiedBlock>> {
        let block = make_test_block(height);
        let qc = make_test_qc(&block);
        // SAFETY: synthetic test fixture, no real signature.
        Arc::new(Verified::<CertifiedBlock>::new_unchecked_for_test(
            CertifiedBlock::new_unchecked(block, qc),
        ))
    }

    fn insert_pending(
        chain: &PendingChain<StubStore>,
        height: BlockHeight,
        attach: bool,
    ) -> Arc<Verified<CertifiedBlock>> {
        let certified = make_certified(height);
        let block_hash = certified.block().hash();
        chain.insert(
            block_hash,
            ChainEntry {
                parent_block_hash: BlockHash::ZERO,
                height,
                settled_txs: Vec::new(),
                committed_txs: Vec::new(),
                jmt_snapshot: empty_snapshot(),
                certified_block: None,
                certified_uncommitted: None,
            },
        );
        if attach {
            chain.attach_certified_block(block_hash, Arc::clone(&certified));
        }
        certified
    }

    #[test]
    fn certified_block_returns_pending_after_attach() {
        let chain = empty_chain();
        let certified = insert_pending(&chain, BlockHeight::new(5), true);
        let got = chain
            .certified_block(BlockHeight::new(5))
            .expect("should find pending block at h=5");
        assert_eq!(got.block().hash(), certified.block().hash());
    }

    #[test]
    fn certified_block_returns_none_before_attach() {
        // Entry inserted at JMT-prep time but accumulate has not run —
        // block is not shard-committed yet, so it must not be visible.
        let chain = empty_chain();
        let _ = insert_pending(&chain, BlockHeight::new(5), false);
        assert!(chain.certified_block(BlockHeight::new(5)).is_none());
    }

    #[test]
    fn certified_block_falls_through_to_storage_for_persisted_heights() {
        let persisted = make_certified(BlockHeight::new(3));
        let chain = chain_with_persisted(vec![persisted.as_ref().as_ref().clone()]);
        let got = chain
            .certified_block(BlockHeight::new(3))
            .expect("should fall through to persisted storage");
        assert_eq!(got.block().hash(), persisted.block().hash());
    }

    #[test]
    fn certified_block_returns_none_for_unknown_height() {
        let chain = empty_chain();
        assert!(chain.certified_block(BlockHeight::new(99)).is_none());
    }

    #[test]
    fn certified_uncommitted_serves_block_sync_only() {
        // A certified-but-uncommitted tip is servable to block-sync
        // fetchers (they adopt the QC without committing on it), but
        // must stay invisible to the committed-only serving surfaces —
        // a certified sibling can still lose its round, and remote
        // consumers of headers and provisions treat served entries as
        // final.
        let chain = empty_chain();
        let certified = insert_pending(&chain, BlockHeight::new(5), false);
        chain.attach_certified_uncommitted(certified.block().hash(), Arc::clone(&certified));

        let served = chain
            .block_for_sync(BlockHeight::new(5))
            .expect("block sync serves the certified tip");
        assert_eq!(served.block.hash(), certified.block().hash());

        assert!(chain.certified_block(BlockHeight::new(5)).is_none());
        assert!(chain.certified_header(BlockHeight::new(5)).is_none());
        assert!(chain.transactions_for_block(BlockHeight::new(5)).is_none());
        // The dedup-horizon reference stays anchored to committed QCs.
        assert!(chain.latest_qc().is_none());
    }

    #[test]
    fn committed_sibling_wins_over_certified_uncommitted() {
        // Two QCs can certify sibling blocks at one height; only one
        // commits. Once a sibling has committed, block sync must serve
        // it — a fetcher that applies the losing sibling never
        // re-fetches the height and wedges on the real chain.
        let chain = empty_chain();
        let winner = insert_pending(&chain, BlockHeight::new(5), true);

        let loser_block = make_test_block_with_anchor_wt(BlockHeight::new(5), 7_777);
        let loser_qc = make_test_qc(&loser_block);
        let loser = Arc::new(Verified::<CertifiedBlock>::new_unchecked_for_test(
            CertifiedBlock::new_unchecked(loser_block, loser_qc),
        ));
        assert_ne!(loser.block().hash(), winner.block().hash());
        chain.insert(
            loser.block().hash(),
            ChainEntry {
                parent_block_hash: BlockHash::ZERO,
                height: BlockHeight::new(5),
                settled_txs: Vec::new(),
                committed_txs: Vec::new(),
                jmt_snapshot: empty_snapshot(),
                certified_block: None,
                certified_uncommitted: None,
            },
        );
        chain.attach_certified_uncommitted(loser.block().hash(), Arc::clone(&loser));

        let served = chain
            .block_for_sync(BlockHeight::new(5))
            .expect("block sync serves the committed sibling");
        assert_eq!(served.block.hash(), winner.block().hash());
    }

    #[test]
    fn certified_header_pending_persisted_and_missing() {
        let persisted = make_certified(BlockHeight::new(2));
        let chain = chain_with_persisted(vec![persisted.as_ref().as_ref().clone()]);
        let pending = insert_pending(&chain, BlockHeight::new(7), true);

        let p = chain
            .certified_header(BlockHeight::new(7))
            .expect("pending header");
        assert_eq!(p.block_hash(), pending.block().hash());

        let s = chain
            .certified_header(BlockHeight::new(2))
            .expect("persisted header");
        assert_eq!(s.block_hash(), persisted.block().hash());

        assert!(chain.certified_header(BlockHeight::new(42)).is_none());
    }

    #[test]
    fn transactions_for_block_pending_persisted_and_missing() {
        let persisted = make_certified(BlockHeight::new(4));
        let chain = chain_with_persisted(vec![persisted.as_ref().as_ref().clone()]);
        let _ = insert_pending(&chain, BlockHeight::new(9), true);

        // `make_test_block` produces an empty tx list — assert presence, not contents.
        assert!(chain.transactions_for_block(BlockHeight::new(9)).is_some());
        assert!(chain.transactions_for_block(BlockHeight::new(4)).is_some());
        assert!(chain.transactions_for_block(BlockHeight::new(99)).is_none());
    }

    #[test]
    fn block_for_sync_pending_returns_live() {
        let chain = empty_chain();
        let pending = insert_pending(&chain, BlockHeight::new(7), true);
        let got = chain
            .block_for_sync(BlockHeight::new(7))
            .expect("pending block_for_sync");
        assert_eq!(got.qc.block_hash(), pending.block().hash());
        // `make_test_block` produces a Live block with no provisions; the
        // pending-path branch returns it as-is.
        assert!(got.block.is_live());
    }

    #[test]
    fn block_for_sync_falls_through_to_storage() {
        let persisted = make_certified(BlockHeight::new(3));
        let stub = StubStore::default().with_block(persisted.as_ref().as_ref().clone());
        // StubStore's get_block_for_sync isn't implemented above; rather
        // than expand the stub, exercise just the pending arm here. The
        // persisted fall-through is covered by integration tests in the
        // node crate where a real ShardChainReader is wired in.
        let chain = Arc::new(PendingChain::new(Arc::new(stub)));
        // No pending entry — pending arm misses, base arm returns None
        // because StubStore::get_block_for_sync is the trait default
        // (None). Documenting the boundary here.
        assert!(chain.block_for_sync(BlockHeight::new(3)).is_none());
    }

    #[test]
    fn latest_qc_returns_highest_pending_otherwise_base() {
        let chain = empty_chain();
        // No entries: falls through to base (None for StubStore).
        assert!(chain.latest_qc().is_none());

        let _low = insert_pending(&chain, BlockHeight::new(2), true);
        let high = insert_pending(&chain, BlockHeight::new(5), true);
        // Highest-height attached entry wins.
        let qc = chain.latest_qc().expect("pending qc");
        assert_eq!(qc.block_hash(), high.block().hash());
    }

    #[test]
    fn latest_qc_skips_pending_without_attached_block() {
        let chain = empty_chain();
        // Pending entry exists but no certified_block — should not be
        // considered "latest committed."
        let _unattached = insert_pending(&chain, BlockHeight::new(9), false);
        assert!(chain.latest_qc().is_none());
    }

    /// A tick keyed on `ShardId::ROOT`, the shard whose settled set these
    /// tests read; `local_settled_tx_hashes` names only that shard's own
    /// verdicts.
    fn tick(n: u64) -> TickId {
        TickId::new(ShardId::ROOT, BlockHeight::new(n))
    }

    /// The transaction a given tick settles. Distinct per tick, so a set
    /// built from several ticks has one entry each.
    fn settled_tx(tick: &TickId) -> TxHash {
        TxHash::from(Hash::from_bytes(&tick.block_height().inner().to_le_bytes()))
    }

    /// A counterpart shard's certificate for the same transaction — the
    /// evidence that makes it reach beyond the settling shard.
    fn remote_ec_for(tick: &TickId) -> Arc<ExecutionCertificate> {
        Arc::new(ExecutionCertificate::new(
            TickId::new(ShardId::from_heap_index(2), tick.block_height()),
            WeightedTimestamp::from_millis(1),
            GlobalReceiptRoot::ZERO,
            vec![TxOutcome::new(
                settled_tx(tick),
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            )],
            AggregateSignature::new([0u8; 96]),
            SignerBitfield::new(4),
        ))
    }

    fn ec_for(tick: &TickId) -> Arc<ExecutionCertificate> {
        Arc::new(ExecutionCertificate::new(
            *tick,
            WeightedTimestamp::from_millis(1),
            GlobalReceiptRoot::ZERO,
            vec![TxOutcome::new(
                settled_tx(tick),
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            )],
            AggregateSignature::new([0u8; 96]),
            SignerBitfield::new(4),
        ))
    }

    /// A `BlockForSync` at `height` whose QC carries `wt_ms` and whose
    /// single finalization settles `settles` (a local-shard tick).
    fn settled_sync_block(height: BlockHeight, wt_ms: u64, settles: &TickId) -> BlockForSync {
        // The block's own `parent_qc` carries `wt_ms` — the canonical clock the
        // floor reads.
        let Block::Live {
            header,
            transactions,
            provisions,
            ..
        } = make_test_block_with_anchor_wt(height, wt_ms)
        else {
            unreachable!("make_test_block returns a Live block")
        };
        let certs = vec![Arc::new(
            Finalization::new(
                *settles,
                TickHalf::Determined,
                // A counterpart's certificate for the same transaction:
                // what makes it cross-shard, and so what puts it in the
                // settled set.
                vec![ec_for(settles), remote_ec_for(settles)],
                vec![],
            )
            .into(),
        )];
        let block = Block::Live {
            header,
            transactions,
            certificates: Arc::new(certs),
            provisions,
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        // The certifying QC carries a deliberately divergent timestamp (a
        // higher-round re-certification past the crossing). The floor must
        // ignore it in favour of the block's `parent_qc`.
        let qc = QuorumCertificate::new(
            block.hash(),
            ShardId::ROOT,
            height,
            block.header().parent_block_hash(),
            Round::INITIAL,
            SignerBitfield::new(4),
            AggregateSignature::new([0u8; 96]),
            WeightedTimestamp::from_millis(wt_ms.saturating_add(1_000_000)),
        );
        BlockForSync {
            block,
            qc,
            provision_hashes: Vec::new(),
        }
    }

    /// The pending prefix contributes a parent and an ancestor whose
    /// `certified_block` has not attached yet — the exact state that left
    /// `block_for_sync` blind and made a proposer's settled-transaction root
    /// diverge from the verifiers'. The walk reads `settled_txs` straight
    /// off the entry, so both sides agree.
    #[test]
    fn settled_txs_window_collects_unattached_pending_ancestors() {
        let chain = empty_chain();
        let ancestor = BlockHash::from_raw(Hash::from_bytes(b"ancestor"));
        let parent = BlockHash::from_raw(Hash::from_bytes(b"parent"));
        let (wa, wb, own) = (tick(100), tick(101), tick(102));
        chain.insert(
            ancestor,
            ChainEntry {
                parent_block_hash: BlockHash::ZERO,
                height: BlockHeight::new(4),
                settled_txs: vec![settled_tx(&wa)],
                committed_txs: Vec::new(),
                jmt_snapshot: empty_snapshot(),
                certified_block: None,
                certified_uncommitted: None,
            },
        );
        chain.insert(
            parent,
            ChainEntry {
                parent_block_hash: ancestor,
                height: BlockHeight::new(5),
                settled_txs: vec![settled_tx(&wb)],
                committed_txs: Vec::new(),
                jmt_snapshot: empty_snapshot(),
                certified_block: None,
                certified_uncommitted: None,
            },
        );
        let set = chain.settled_txs_in_window(
            ShardId::ROOT,
            parent,
            BlockHeight::new(5),
            WeightedTimestamp::from_millis(10_000),
            None,
            vec![settled_tx(&own)],
        );
        assert_eq!(
            set,
            BTreeSet::from([settled_tx(&wa), settled_tx(&wb), settled_tx(&own)])
        );
    }

    /// The committed tail walks by height and stops at the retention floor:
    /// a block within `[anchor − RETENTION_HORIZON, anchor]` contributes,
    /// one below it does not. The floor reads each block's own `parent_qc`
    /// timestamp, not its served certifying QC — `settled_sync_block` gives
    /// the below-floor block a certifying QC far above the floor, so a floor
    /// that read the served QC would wrongly include it.
    #[test]
    fn settled_txs_window_floors_the_committed_tail() {
        let rh_ms = RETENTION_HORIZON.as_secs() * 1000;
        let anchor = WeightedTimestamp::from_millis(rh_ms + 10_000); // floor = 10_000
        let (in_window, below_floor, parent_tick) = (tick(200), tick(201), tick(202));
        let stub = StubStore::default()
            .with_sync_block(
                BlockHeight::new(3),
                settled_sync_block(BlockHeight::new(3), anchor.as_millis(), &in_window),
            )
            .with_sync_block(
                BlockHeight::new(2),
                settled_sync_block(BlockHeight::new(2), 9_999, &below_floor),
            );
        let chain = Arc::new(PendingChain::new(Arc::new(stub)));
        let parent = BlockHash::from_raw(Hash::from_bytes(b"parent"));
        chain.insert(
            parent,
            ChainEntry {
                parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"committed-tip")),
                height: BlockHeight::new(4),
                settled_txs: vec![settled_tx(&parent_tick)],
                committed_txs: Vec::new(),
                jmt_snapshot: empty_snapshot(),
                certified_block: None,
                certified_uncommitted: None,
            },
        );
        let set = chain.settled_txs_in_window(
            ShardId::ROOT,
            parent,
            BlockHeight::new(4),
            anchor,
            None,
            Vec::new(),
        );
        assert_eq!(
            set,
            BTreeSet::from([settled_tx(&parent_tick), settled_tx(&in_window)])
        );
    }

    /// A `BlockForSync` at `height` whose `parent_qc` carries `wt_ms` and
    /// whose transactions are `test_transaction(seed)` for each seed.
    fn committed_sync_block(height: BlockHeight, wt_ms: u64, seeds: &[u8]) -> BlockForSync {
        let Block::Live {
            header,
            certificates,
            provisions,
            ..
        } = make_test_block_with_anchor_wt(height, wt_ms)
        else {
            unreachable!("make_test_block returns a Live block")
        };
        let txs: Vec<Arc<Verifiable<Transaction>>> = seeds
            .iter()
            .map(|&seed| Arc::new(Verifiable::from(test_transaction(seed))))
            .collect();
        let block = Block::Live {
            header,
            transactions: Arc::new(txs),
            certificates,
            provisions,
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };
        // A deliberately divergent certifying timestamp, as in
        // `settled_sync_block`: the floor must read the block's own
        // `parent_qc` instead.
        let qc = QuorumCertificate::new(
            block.hash(),
            ShardId::ROOT,
            height,
            block.header().parent_block_hash(),
            Round::INITIAL,
            SignerBitfield::new(4),
            AggregateSignature::new([0u8; 96]),
            WeightedTimestamp::from_millis(wt_ms.saturating_add(1_000_000)),
        );
        BlockForSync {
            block,
            qc,
            provision_hashes: Vec::new(),
        }
    }

    fn tx_hash(seed: u8) -> TxHash {
        test_transaction(seed).hash()
    }

    /// The pending prefix contributes ancestors whose `certified_block`
    /// has not attached yet — invisible to `block_for_sync`, and the
    /// reason the entry carries its own transaction hashes. Without this
    /// a proposer's committed root would diverge from its verifiers'.
    #[test]
    fn committed_txs_window_collects_unattached_pending_ancestors() {
        let chain = empty_chain();
        let ancestor = BlockHash::from_raw(Hash::from_bytes(b"ancestor"));
        let parent = BlockHash::from_raw(Hash::from_bytes(b"parent"));
        chain.insert(
            ancestor,
            ChainEntry {
                parent_block_hash: BlockHash::ZERO,
                height: BlockHeight::new(4),
                settled_txs: Vec::new(),
                committed_txs: vec![tx_hash(1)],
                jmt_snapshot: empty_snapshot(),
                certified_block: None,
                certified_uncommitted: None,
            },
        );
        chain.insert(
            parent,
            ChainEntry {
                parent_block_hash: ancestor,
                height: BlockHeight::new(5),
                settled_txs: Vec::new(),
                committed_txs: vec![tx_hash(2)],
                jmt_snapshot: empty_snapshot(),
                certified_block: None,
                certified_uncommitted: None,
            },
        );
        let set = chain.committed_txs_in_window(
            parent,
            BlockHeight::new(5),
            WeightedTimestamp::from_millis(10_000),
            vec![tx_hash(3)],
        );
        assert_eq!(set, BTreeSet::from([tx_hash(1), tx_hash(2), tx_hash(3)]));
    }

    /// The committed tail walks by height and stops at `anchor −
    /// RETENTION_HORIZON`, reading each block's own `parent_qc` timestamp
    /// rather than its served certifying QC — which `committed_sync_block`
    /// sets far above the floor, so a walk reading the wrong one would
    /// include the below-floor block.
    #[test]
    fn committed_txs_window_floors_the_committed_tail() {
        let rh_ms = RETENTION_HORIZON.as_secs() * 1000;
        let anchor = WeightedTimestamp::from_millis(rh_ms + 10_000); // floor = 10_000
        let stub = StubStore::default()
            .with_sync_block(
                BlockHeight::new(3),
                committed_sync_block(BlockHeight::new(3), anchor.as_millis(), &[10, 11]),
            )
            .with_sync_block(
                BlockHeight::new(2),
                committed_sync_block(BlockHeight::new(2), 9_999, &[12]),
            );
        let chain = Arc::new(PendingChain::new(Arc::new(stub)));
        let parent = BlockHash::from_raw(Hash::from_bytes(b"parent"));
        chain.insert(
            parent,
            ChainEntry {
                parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"committed-tip")),
                height: BlockHeight::new(4),
                settled_txs: Vec::new(),
                committed_txs: vec![tx_hash(13)],
                jmt_snapshot: empty_snapshot(),
                certified_block: None,
                certified_uncommitted: None,
            },
        );
        let set = chain.committed_txs_in_window(parent, BlockHeight::new(4), anchor, Vec::new());
        assert_eq!(
            set,
            BTreeSet::from([tx_hash(13), tx_hash(10), tx_hash(11)]),
            "the below-floor block's transaction must not enter the window"
        );
    }

    /// The root is a pure function of the walked set, so a proposer
    /// building over a pending parent and a verifier reading the same
    /// chain derive the same value — and a transaction the walk misses
    /// changes it.
    #[test]
    fn committed_txs_root_tracks_the_window_set() {
        let chain = empty_chain();
        let parent = BlockHash::from_raw(Hash::from_bytes(b"parent"));
        chain.insert(
            parent,
            ChainEntry {
                parent_block_hash: BlockHash::ZERO,
                height: BlockHeight::new(2),
                settled_txs: Vec::new(),
                committed_txs: vec![tx_hash(20)],
                jmt_snapshot: empty_snapshot(),
                certified_block: None,
                certified_uncommitted: None,
            },
        );
        let anchor = WeightedTimestamp::from_millis(10_000);
        let root = chain
            .terminal_roots_in_window(
                &TerminalWindow {
                    local_shard: ShardId::ROOT,
                    parent_block_hash: parent,
                    parent_block_height: BlockHeight::new(2),
                    anchor_wt: anchor,
                    settled_window_floor: None,
                },
                &[],
                vec![tx_hash(21)],
            )
            .committed_txs;
        assert_eq!(
            root,
            committed_txs_root_from_hashes([tx_hash(20), tx_hash(21)].iter())
        );
        assert_ne!(
            root,
            committed_txs_root_from_hashes([tx_hash(20)].iter()),
            "dropping a transaction must change the root"
        );
    }

    /// A schedule-supplied window floor extends the committed walk below
    /// `anchor − RETENTION_HORIZON`: a tick settled early in a terminating
    /// shard's scheduled window — outside the anchor-relative span — still
    /// enters the set, so the attested root covers every settlement a
    /// counterpart fence can be holding a straddler against.
    #[test]
    fn window_floor_extends_the_committed_tail_below_the_horizon() {
        let rh_ms = RETENTION_HORIZON.as_secs() * 1000;
        let anchor = WeightedTimestamp::from_millis(rh_ms + 10_000); // anchor floor = 10_000
        let (in_window, early_settled) = (tick(300), tick(301));
        let stub = StubStore::default()
            .with_sync_block(
                BlockHeight::new(3),
                settled_sync_block(BlockHeight::new(3), anchor.as_millis(), &in_window),
            )
            .with_sync_block(
                BlockHeight::new(2),
                settled_sync_block(BlockHeight::new(2), 9_999, &early_settled),
            );
        let chain = Arc::new(PendingChain::new(Arc::new(stub)));
        let set = chain.settled_txs_in_window(
            ShardId::ROOT,
            BlockHash::from_raw(Hash::from_bytes(b"missing-parent")),
            BlockHeight::new(3),
            anchor,
            Some(WeightedTimestamp::from_millis(9_000)),
            Vec::new(),
        );
        assert_eq!(
            set,
            BTreeSet::from([settled_tx(&in_window), settled_tx(&early_settled)])
        );
    }

    /// The memoized window walk extends at the tip and never leaks later
    /// settlements into an earlier block's window: a second call at a
    /// higher height folds only the new blocks onto the memo, and a call
    /// back below the memo's coverage recomputes in full.
    #[test]
    fn settled_window_memo_extends_at_the_tip_only() {
        let rh_ms = RETENTION_HORIZON.as_secs() * 1000;
        let floor = Some(WeightedTimestamp::from_millis(500));
        let (w2, w3, w4) = (tick(400), tick(401), tick(402));
        let stub = StubStore::default()
            .with_sync_block(
                BlockHeight::new(2),
                settled_sync_block(BlockHeight::new(2), 1_000, &w2),
            )
            .with_sync_block(
                BlockHeight::new(3),
                settled_sync_block(BlockHeight::new(3), 2_000, &w3),
            )
            .with_sync_block(
                BlockHeight::new(4),
                settled_sync_block(BlockHeight::new(4), 3_000, &w4),
            );
        let chain = Arc::new(PendingChain::new(Arc::new(stub)));
        let at = |h: u64| {
            chain.settled_txs_in_window(
                ShardId::ROOT,
                BlockHash::from_raw(Hash::from_bytes(b"missing-parent")),
                BlockHeight::new(h),
                WeightedTimestamp::from_millis(rh_ms + 10_000),
                floor,
                Vec::new(),
            )
        };
        assert_eq!(at(3), BTreeSet::from([settled_tx(&w2), settled_tx(&w3)]));
        // The higher call folds only block 4 onto the memo.
        assert_eq!(
            at(4),
            BTreeSet::from([settled_tx(&w2), settled_tx(&w3), settled_tx(&w4)])
        );
        // Back below the memo's coverage: full recompute, no leak of block 4.
        assert_eq!(at(3), BTreeSet::from([settled_tx(&w2), settled_tx(&w3)]));
    }

    /// The sweep walk merges a base index answering at what the store has
    /// persisted with an overlay covering the blocks above it. A store
    /// already ahead of the anchor has retired rows the base would still
    /// report and the overlay does not carry, so the removal set comes
    /// out wrong — refused here rather than computed into a state root
    /// nobody else reaches.
    #[test]
    #[should_panic(expected = "a sweep walk anchored at")]
    fn a_sweep_walk_refuses_an_index_ahead_of_its_anchor() {
        let store = Arc::new(StubStore {
            persisted: BlockHeight::new(9),
            ..StubStore::default()
        });
        let view = SubstateView::base_only(store, BlockHeight::new(4));
        let ceiling = SweepFrontier::ceiling_at(WeightedTimestamp::from_millis(u64::MAX));
        let _ = view.sweep_candidates(SweepFrontier::ZERO, ceiling.bucket(), 10);
    }

    /// A store behind the anchor is what the overlay is for, and the walk
    /// runs.
    #[test]
    fn a_sweep_walk_runs_where_the_overlay_covers_the_gap() {
        let store = Arc::new(StubStore {
            persisted: BlockHeight::new(4),
            ..StubStore::default()
        });
        let view = SubstateView::base_only(store, BlockHeight::new(9));
        let ceiling = SweepFrontier::ceiling_at(WeightedTimestamp::from_millis(u64::MAX));
        assert!(
            view.sweep_candidates(SweepFrontier::ZERO, ceiling.bucket(), 10)
                .is_empty()
        );
    }
}
