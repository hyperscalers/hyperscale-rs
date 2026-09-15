//! Pending block assembly.
//!
//! Tracks blocks being assembled from headers + gossiped transactions + finalizations.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_core::{Action, FetchIds, FetchRequest};
use hyperscale_types::{
    Block, BlockHash, BlockHeader, BlockHeight, BlockManifest, Finalization, FinalizationHash,
    LocalTimestamp, ProvisionHash, Provisions, Round, ShardId, Transaction, TxHash, ValidatorId,
    Verifiable,
};
use tracing::{debug, warn};

/// Outstanding fetch ids orphaned by dropping pending blocks — already
/// filtered to ids no surviving block still needs, so cancelling them can't
/// starve another block's fetch. Produced by [`PendingBlocks::remove_orphaning`]
/// and [`PendingBlocks::prune_committed`].
#[derive(Debug, Default)]
pub struct OrphanedFetches {
    txs: Vec<TxHash>,
    finalizations: Vec<FinalizationHash>,
    provisions: Vec<ProvisionHash>,
}

impl OrphanedFetches {
    /// One [`Action::AbandonFetch`] per non-empty payload type, so the fetch
    /// FSM releases the in-flight slots these ids were pinning. Symmetric
    /// across transactions, finalizations, and local provisions — a dropped
    /// block can leave any of the three in flight.
    #[must_use]
    pub fn into_abandon_actions(self) -> Vec<Action> {
        let mut actions = Vec::new();
        if !self.txs.is_empty() {
            actions.push(Action::AbandonFetch(FetchIds::Transactions(self.txs)));
        }
        if !self.finalizations.is_empty() {
            actions.push(Action::AbandonFetch(FetchIds::Finalizations(
                self.finalizations,
            )));
        }
        if !self.provisions.is_empty() {
            actions.push(Action::AbandonFetch(FetchIds::LocalProvisions(
                self.provisions,
            )));
        }
        actions
    }
}

/// Map of block hash → [`PendingBlock`] for blocks currently being assembled.
///
/// Keys are derived from `block.header().hash()` on insert.
#[derive(Default)]
pub struct PendingBlocks(HashMap<BlockHash, PendingBlock>);

impl PendingBlocks {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn get(&self, block_hash: BlockHash) -> Option<&PendingBlock> {
        self.0.get(&block_hash)
    }

    pub fn get_mut(&mut self, block_hash: BlockHash) -> Option<&mut PendingBlock> {
        self.0.get_mut(&block_hash)
    }

    /// Insert `block` keyed on its own header hash. Silently overwrites any
    /// prior entry under the same hash; callers that need to gate on
    /// duplicates check [`contains_key`](Self::contains_key) first.
    pub fn insert(&mut self, block: PendingBlock) {
        self.0.insert(block.header().hash(), block);
    }

    /// Remove the block at `block_hash`, returning the outstanding fetch ids it
    /// was waiting on that **no surviving pending block still needs** — so the
    /// caller can cancel exactly those in-flight fetches without starving a
    /// fetch a sibling block shares. Returns `None` if the hash isn't present.
    pub fn remove_orphaning(&mut self, block_hash: BlockHash) -> Option<OrphanedFetches> {
        let pending = self.0.remove(&block_hash)?;
        Some(self.orphaned_among(
            pending.missing_transaction_hashes,
            pending.missing_finalization_hashes,
            pending.missing_provision_hashes,
        ))
    }

    pub fn contains_key(&self, block_hash: BlockHash) -> bool {
        self.0.contains_key(&block_hash)
    }

    /// Every pending block, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = &PendingBlock> {
        self.0.values()
    }

    /// Number of distinct pending headers at `(height, round)`. An honest
    /// proposer produces one; a larger count is a Byzantine proposer
    /// equivocating, used to cap how many it can make the node store and
    /// verify.
    pub fn count_at(&self, height: BlockHeight, round: Round) -> usize {
        self.0
            .values()
            .filter(|p| {
                let h = p.header();
                h.height() == height && h.round() == round
            })
            .count()
    }

    /// Number of distinct pending headers at `height`, across all rounds. The
    /// per-height cap is enforced against this.
    pub fn count_at_height(&self, height: BlockHeight) -> usize {
        self.0
            .values()
            .filter(|p| p.header().height() == height)
            .count()
    }

    /// The pending header at `height` whose round is farthest from `anchor`,
    /// with its round-distance, or `None` if no header is stored at `height`.
    /// Used to pick the eviction victim when the per-height cap is reached —
    /// `anchor` is the verified `high_qc` round, so flood rounds far from
    /// verified progress are shed before rounds near the committable block.
    pub fn farthest_round_at_height(
        &self,
        height: BlockHeight,
        anchor: Round,
    ) -> Option<(BlockHash, u64)> {
        self.0
            .values()
            .filter(|p| p.header().height() == height)
            .map(|p| {
                let h = p.header();
                (h.hash(), h.round().inner().abs_diff(anchor.inner()))
            })
            .max_by_key(|(_, distance)| *distance)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn values(&self) -> impl Iterator<Item = &PendingBlock> {
        self.0.values()
    }

    /// Drop pending blocks whose header height is at or below
    /// `committed_height`. Returns the outstanding fetch ids the dropped blocks
    /// were waiting on that no surviving block still needs, so the caller can
    /// cancel the orphaned in-flight fetches and free the FSM's slots.
    pub fn prune_committed(&mut self, committed_height: BlockHeight) -> OrphanedFetches {
        let mut txs: HashSet<TxHash> = HashSet::new();
        let mut finalizations: HashSet<FinalizationHash> = HashSet::new();
        let mut provisions: HashSet<ProvisionHash> = HashSet::new();
        self.0.retain(|_, pending| {
            if pending.header().height() > committed_height {
                return true;
            }
            txs.extend(pending.missing_transaction_hashes.iter().copied());
            finalizations.extend(pending.missing_finalization_hashes.iter().copied());
            provisions.extend(pending.missing_provision_hashes.iter().copied());
            false
        });
        self.orphaned_among(txs, finalizations, provisions)
    }

    /// Narrow a set of missing ids to those no remaining pending block needs.
    /// Shared by single-block drop and commit-time pruning so neither cancels a
    /// fetch another block is still waiting on.
    fn orphaned_among(
        &self,
        txs: HashSet<TxHash>,
        finalizations: HashSet<FinalizationHash>,
        provisions: HashSet<ProvisionHash>,
    ) -> OrphanedFetches {
        OrphanedFetches {
            txs: txs
                .into_iter()
                .filter(|h| !self.0.values().any(|p| p.needs_transaction(h)))
                .collect(),
            finalizations: finalizations
                .into_iter()
                .filter(|h| !self.0.values().any(|p| p.needs_finalization(h)))
                .collect(),
            provisions: provisions
                .into_iter()
                .filter(|h| !self.0.values().any(|p| p.needs_provision(h)))
                .collect(),
        }
    }

    /// Header for the pending block at `block_hash`, if present.
    pub fn get_header(&self, block_hash: BlockHash) -> Option<&BlockHeader> {
        self.0.get(&block_hash).map(PendingBlock::header)
    }

    /// Constructed [`Block`] for `block_hash`, if the pending block has fully
    /// assembled. Returns `None` when the hash is unknown OR when the block
    /// is still awaiting transactions/ticks/provisions.
    pub fn get_block(&self, block_hash: BlockHash) -> Option<&Arc<Block>> {
        self.0.get(&block_hash)?.block()
    }

    /// True when the pending block at `block_hash` has all data and the
    /// inner [`Block`] is ready to be built. False when the hash is unknown.
    pub fn is_complete(&self, block_hash: BlockHash) -> bool {
        self.0
            .get(&block_hash)
            .is_some_and(PendingBlock::is_complete)
    }

    /// True when some pending block at `height` is complete AND already has
    /// its inner [`Block`] constructed.
    pub fn has_complete_at(&self, height: BlockHeight) -> bool {
        self.0.values().any(|pending| {
            pending.header().height() == height
                && pending.is_complete()
                && pending.block().is_some()
        })
    }

    /// True when any pending block sits at `height`, regardless of completion
    /// state.
    pub fn has_any_at(&self, height: BlockHeight) -> bool {
        self.0
            .values()
            .any(|pending| pending.header().height() == height)
    }

    /// True when a pending block sits at `height` and was proposed in `round`.
    ///
    /// Rounds separate a live proposal from the leavings of one the pacemaker
    /// has already abandoned: both sit at the same height, and only the
    /// former can still certify.
    pub fn has_any_at_round(&self, height: BlockHeight, round: Round) -> bool {
        self.0
            .values()
            .any(|pending| pending.header().height() == height && pending.header().round() == round)
    }

    /// True when a block at `(height, round)` is one this replica still
    /// owes work to itself — content to gather, roots to check — rather
    /// than one waiting on another chain to answer for a claim.
    ///
    /// The round timer suppresses on the first and not the second. A
    /// replica gathering a block's own content finishes on its own and
    /// is worth waiting the long window for; one held at the fence is
    /// waiting on a counterpart it cannot make answer, which is the
    /// case the ordinary round timeout is there to bound.
    pub fn has_own_work_at_round(&self, height: BlockHeight, round: Round) -> bool {
        self.0.values().any(|pending| {
            pending.header().height() == height
                && pending.header().round() == round
                && !pending.awaiting_counterpart()
        })
    }

    /// Total transaction count across all pending blocks (manifest counts,
    /// independent of how much data has actually arrived).
    pub fn total_transaction_count(&self) -> usize {
        self.0.values().map(PendingBlock::transaction_count).sum()
    }

    /// Total certificate count across all pending blocks.
    pub fn total_certificate_count(&self) -> usize {
        self.0.values().map(PendingBlock::certificate_count).sum()
    }

    /// Build a [`PendingBlock`] from `header` + `manifest`, populate it from
    /// the supplied lookups, and insert it.
    pub fn assemble(
        &mut self,
        header: BlockHeader,
        manifest: BlockManifest,
        now: LocalTimestamp,
        lookup_tx: impl Fn(&TxHash) -> Option<Arc<Verifiable<Transaction>>>,
        lookup_finalization: impl Fn(&FinalizationHash) -> Option<Arc<Verifiable<Finalization>>>,
        lookup_provision: impl Fn(&ProvisionHash) -> Option<Arc<Verifiable<Provisions>>>,
    ) {
        let mut pending = PendingBlock::from_manifest(header, manifest, now);

        // Borrow the manifest only long enough to collect locally-available
        // Arcs, releasing it before the mutable `add_*` calls below.
        let txs: Vec<Arc<Verifiable<Transaction>>> = pending
            .manifest()
            .tx_hashes()
            .iter()
            .filter_map(&lookup_tx)
            .collect();
        for tx in txs {
            pending.add_transaction(tx);
        }

        let finalizations: Vec<Arc<Verifiable<Finalization>>> = pending
            .manifest()
            .cert_ids()
            .iter()
            .filter_map(&lookup_finalization)
            .collect();
        for fw in finalizations {
            pending.add_finalization(fw);
        }

        let provisions: Vec<Arc<Verifiable<Provisions>>> = pending
            .manifest()
            .provision_hashes()
            .iter()
            .filter_map(&lookup_provision)
            .collect();
        for p in provisions {
            pending.add_provision(p);
        }

        self.insert(pending);
    }

    /// Fold an arrival into every pending block that needs it. Returns the
    /// hashes of blocks that became complete and successfully constructed
    /// their inner [`Block`].
    fn fold_arrival<F, M>(&mut self, needs: F, apply: M) -> Vec<BlockHash>
    where
        F: Fn(&PendingBlock) -> bool,
        M: Fn(&mut PendingBlock),
    {
        let mut block_hashes: Vec<BlockHash> = self
            .0
            .iter()
            .filter(|(_, pending)| needs(pending))
            .map(|(hash, _)| *hash)
            .collect();
        block_hashes.sort();

        let mut newly_complete = Vec::new();
        for block_hash in block_hashes {
            if let Some(pending) = self.0.get_mut(&block_hash) {
                apply(pending);
                if Self::try_construct(pending) {
                    newly_complete.push(block_hash);
                }
            }
        }
        newly_complete
    }

    fn try_construct(pending: &mut PendingBlock) -> bool {
        if !pending.is_complete() {
            return false;
        }
        if pending.block().is_some() {
            return true;
        }
        match pending.construct_block() {
            Ok(_) => true,
            Err(e) => {
                warn!(error = %e, "Failed to construct block after arrival");
                false
            }
        }
    }

    /// Record an arrived transaction against any pending block that needs it.
    /// Returns the hashes of blocks that became complete as a result.
    pub fn receive_transaction(&mut self, tx: &Arc<Verifiable<Transaction>>) -> Vec<BlockHash> {
        let tx_hash = tx.hash();
        self.fold_arrival(
            |pending| pending.needs_transaction(&tx_hash),
            |pending| {
                pending.add_transaction(Arc::clone(tx));
            },
        )
    }

    /// Record an arrived finalization against any pending block that needs
    /// it. Returns the hashes of blocks that became complete as a result.
    pub fn receive_finalization(&mut self, fw: &Arc<Verifiable<Finalization>>) -> Vec<BlockHash> {
        let hash = fw.receipt_hash();
        self.fold_arrival(
            |pending| pending.needs_finalization(&hash),
            |pending| {
                pending.add_finalization(Arc::clone(fw));
            },
        )
    }

    /// Record an arrived provisions batch against any pending block that
    /// needs it. Returns the hashes of blocks that became complete as a
    /// result.
    pub fn receive_provision(&mut self, batch: &Arc<Verifiable<Provisions>>) -> Vec<BlockHash> {
        let provisions_hash = batch.hash();
        self.fold_arrival(
            |pending| pending.needs_provision(&provisions_hash),
            |pending| {
                pending.add_provision(Arc::clone(batch));
            },
        )
    }

    /// Emit fetch actions for pending blocks whose missing data has been
    /// outstanding longer than `timeout`. Skips complete blocks.
    /// `force_immediate` bypasses the age check.
    pub fn check_fetches(
        &self,
        me: ValidatorId,
        local_shard: ShardId,
        now: LocalTimestamp,
        timeout: Duration,
        force_immediate: bool,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        for (block_hash, pending) in &self.0 {
            if pending.is_complete() {
                continue;
            }

            let age = now.elapsed_since(pending.created_at());
            let ready = force_immediate || age >= timeout;
            if !ready {
                continue;
            }

            let proposer = pending.header().proposer();

            let missing_txs = pending.missing_transactions();
            if !missing_txs.is_empty() {
                debug!(
                    validator = ?me,
                    block_hash = ?block_hash,
                    missing_tx_count = missing_txs.len(),
                    age_ms = age.as_millis(),
                    timeout_ms = timeout.as_millis(),
                    "Fetch timeout reached, requesting missing transactions"
                );
                actions.push(Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::Transactions(missing_txs),
                    shard: local_shard,
                    preferred: Some(proposer),
                    class: None,
                }));
            }

            let missing_provisions = pending.missing_provisions();
            if !missing_provisions.is_empty() {
                debug!(
                    validator = ?me,
                    block_hash = ?block_hash,
                    missing_provision_count = missing_provisions.len(),
                    age_ms = age.as_millis(),
                    "Fetch timeout reached, requesting missing provisions"
                );
                actions.push(Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::LocalProvisions(missing_provisions),
                    shard: local_shard,
                    preferred: Some(proposer),
                    class: None,
                }));
            }

            let missing_finalizations = pending.missing_finalizations();
            if !missing_finalizations.is_empty() {
                debug!(
                    validator = ?me,
                    block_hash = ?block_hash,
                    missing_finalization_count = missing_finalizations.len(),
                    age_ms = age.as_millis(),
                    "Fetch timeout reached, requesting missing finalizations"
                );
                actions.push(Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::Finalizations(missing_finalizations),
                    shard: local_shard,
                    preferred: Some(proposer),
                    class: None,
                }));
            }
        }

        actions
    }

    #[cfg(test)]
    pub fn clear(&mut self) {
        self.0.clear();
    }
}

/// Tracks a block being assembled from header + gossiped transactions + finalizations.
///
/// # Lifecycle
///
/// 1. Created from `BlockHeader` (all transactions/ticks marked as absent by hash)
/// 2. Full `Transaction` objects arrive via gossip (stored in `received_transactions` map)
/// 3. `Finalization`s arrive when verifier independently finalizes each tick
///    (carries certificate + receipts + ECs)
/// 4. When all transactions and finalizations received, block can be constructed
/// 5. Block stored to storage
/// 6. Block ready for voting
#[derive(Debug, Clone)]
pub struct PendingBlock {
    /// Block header (received first).
    header: BlockHeader,

    /// Block contents manifest (transaction hashes, certificates, etc.)
    manifest: BlockManifest,

    /// Map of transaction hash -> Arc<Verifiable<Transaction>> (for received transactions).
    received_transactions: HashMap<TxHash, Arc<Verifiable<Transaction>>>,

    /// Set of transaction hashes we're still waiting for (`HashSet` for O(1) lookup).
    missing_transaction_hashes: HashSet<TxHash>,

    /// Finalizations by identity (each carries certificates + receipts).
    ///
    /// A block is complete once every finalization its manifest names has
    /// been independently finalized by this validator or fetched.
    received_finalizations: BTreeMap<FinalizationHash, Arc<Verifiable<Finalization>>>,

    /// Identities we're still waiting for.
    missing_finalization_hashes: HashSet<FinalizationHash>,

    /// Received provisions keyed by provisions hash. `BTreeMap` so
    /// `provisions()` iteration is deterministic across validators.
    received_provisions: BTreeMap<ProvisionHash, Arc<Verifiable<Provisions>>>,

    /// Set of provisions hashes we're still waiting for.
    missing_provision_hashes: HashSet<ProvisionHash>,

    /// The fully constructed block (None until all transactions/ticks received).
    constructed_block: Option<Arc<Block>>,

    /// Whether the vote fence withheld this block for want of evidence
    /// from another chain.
    ///
    /// Held apart from the missing-content sets above because it is a
    /// different kind of waiting. Those name content this replica is
    /// still gathering for a block the chain has committed to; this
    /// names a claim the proposer made about a counterpart that only
    /// that counterpart can settle. The round timer prices the two
    /// differently, which is the whole reason the flag exists — see
    /// [`PendingBlocks::has_own_work_at_round`].
    awaiting_counterpart: bool,

    /// Time at which this pending block was first observed. Used to schedule
    /// fetch requests for missing data after a gossip grace period.
    created_at: LocalTimestamp,
}

impl PendingBlock {
    /// Create a pending block from a header and manifest.
    pub fn from_manifest(
        header: BlockHeader,
        manifest: BlockManifest,
        created_at: LocalTimestamp,
    ) -> Self {
        let total_tx_count = manifest.transaction_count();
        let missing_transaction_hashes: HashSet<TxHash> =
            manifest.tx_hashes().iter().copied().collect();
        let missing_finalization_hashes: HashSet<FinalizationHash> =
            manifest.cert_ids().iter().copied().collect();
        let missing_provision_hashes: HashSet<ProvisionHash> =
            manifest.provision_hashes().iter().copied().collect();

        Self {
            header,
            received_transactions: HashMap::with_capacity(total_tx_count),
            missing_transaction_hashes,
            received_finalizations: BTreeMap::new(),
            missing_finalization_hashes,
            received_provisions: BTreeMap::new(),
            missing_provision_hashes,
            manifest,
            constructed_block: None,
            awaiting_counterpart: false,
            created_at,
        }
    }

    /// Create a pending block from a complete block (proposer's own block).
    ///
    /// The proposer already has all transactions, finalizations, and provision
    /// batches. Provision hashes are derived (and sorted) from the batches so the
    /// resulting `PendingBlock` is self-contained: both the manifest hashes and
    /// `received_provisions` are populated from the same source.
    ///
    /// The manifest mirrors the block's carried witness sources verbatim
    /// alongside the derived tx/cert/provision hashes — the block's
    /// witness root commits to them, so the rebuilt manifest must match
    /// exactly or every replica rejects the broadcast.
    pub fn from_complete_block(
        block: &Block,
        finalizations: Vec<Arc<Verifiable<Finalization>>>,
        provisions: Vec<Arc<Verifiable<Provisions>>>,
        created_at: LocalTimestamp,
    ) -> Self {
        let mut provision_hashes: Vec<ProvisionHash> =
            provisions.iter().map(|p| p.hash()).collect();
        provision_hashes.sort();
        let tx_hashes: Vec<TxHash> = block.transactions().iter().map(|tx| tx.hash()).collect();
        let cert_ids: Vec<FinalizationHash> = block
            .certificates()
            .iter()
            .map(|c| c.receipt_hash())
            .collect();
        let manifest = BlockManifest::new(
            tx_hashes,
            cert_ids,
            provision_hashes,
            block.abandonment_records().to_vec(),
            block.state_claims().to_vec(),
            block.witness_sources().as_ref().clone(),
        );
        let mut received_provisions: BTreeMap<ProvisionHash, Arc<Verifiable<Provisions>>> =
            BTreeMap::new();
        for p in provisions {
            received_provisions.insert(p.hash(), p);
        }
        let mut pending = Self {
            header: block.header().clone(),
            received_transactions: HashMap::new(),
            missing_transaction_hashes: HashSet::new(),
            received_finalizations: BTreeMap::new(),
            missing_finalization_hashes: HashSet::new(),
            received_provisions,
            missing_provision_hashes: HashSet::new(),
            manifest,
            constructed_block: None,
            awaiting_counterpart: false,
            created_at,
        };
        // Fill in all transactions
        for tx in block.transactions().iter() {
            pending
                .received_transactions
                .insert(tx.hash(), Arc::clone(tx));
        }
        // Fill in all finalizations
        for fw in finalizations {
            pending.received_finalizations.insert(fw.receipt_hash(), fw);
        }
        pending
    }

    /// Add a received transaction.
    ///
    /// Returns true if this transaction was needed, false if duplicate or not in this block.
    pub fn add_transaction(&mut self, tx: Arc<Verifiable<Transaction>>) -> bool {
        let hash = tx.hash();
        if self.missing_transaction_hashes.remove(&hash) {
            self.received_transactions.insert(hash, tx);
            true
        } else {
            false
        }
    }

    /// Add a finalization (carries certificates + receipts).
    ///
    /// Returns true if it was needed, false if duplicate or not in this
    /// block.
    pub fn add_finalization(&mut self, fw: Arc<Verifiable<Finalization>>) -> bool {
        let hash = fw.receipt_hash();
        if self.missing_finalization_hashes.remove(&hash) {
            self.received_finalizations.insert(hash, fw);
            true
        } else {
            false
        }
    }

    /// Whether the vote fence withheld this block for want of another
    /// chain's evidence, rather than for content still landing here.
    pub const fn awaiting_counterpart(&self) -> bool {
        self.awaiting_counterpart
    }

    /// Record what the vote fence said of this block: `true` where it
    /// withheld the vote for want of a counterpart's evidence, `false`
    /// once the evidence stands and the block is judged on its own.
    pub const fn set_awaiting_counterpart(&mut self, awaiting: bool) {
        self.awaiting_counterpart = awaiting;
    }

    /// Check if all transactions, finalizations, and provisions have been received.
    pub fn is_complete(&self) -> bool {
        self.missing_transaction_hashes.is_empty()
            && self.missing_finalization_hashes.is_empty()
            && self.missing_provision_hashes.is_empty()
    }

    /// Get the number of missing transaction hashes.
    pub fn missing_transaction_count(&self) -> usize {
        self.missing_transaction_hashes.len()
    }

    /// Get the missing transaction hashes as a Vec (for iteration/display).
    pub fn missing_transactions(&self) -> Vec<TxHash> {
        self.missing_transaction_hashes.iter().copied().collect()
    }

    /// Check if this pending block needs a specific transaction.
    pub fn needs_transaction(&self, tx_hash: &TxHash) -> bool {
        self.missing_transaction_hashes.contains(tx_hash)
    }

    /// Get the number of missing finalizations.
    pub fn missing_finalization_count(&self) -> usize {
        self.missing_finalization_hashes.len()
    }

    /// Get the number of missing provision batches.
    pub fn missing_provision_count(&self) -> usize {
        self.missing_provision_hashes.len()
    }

    /// Check if this pending block needs a specific finalization.
    pub fn needs_finalization(&self, hash: &FinalizationHash) -> bool {
        self.missing_finalization_hashes.contains(hash)
    }

    /// Add a received provisions.
    ///
    /// Returns true if this provision was needed, false if duplicate or not in this block.
    pub fn add_provision(&mut self, provisions: Arc<Verifiable<Provisions>>) -> bool {
        let hash = provisions.hash();
        if self.missing_provision_hashes.remove(&hash) {
            self.received_provisions.insert(hash, provisions);
            true
        } else {
            false
        }
    }

    /// Get the missing provisions hashes as a Vec.
    pub fn missing_provisions(&self) -> Vec<ProvisionHash> {
        self.missing_provision_hashes.iter().copied().collect()
    }

    /// Check if this pending block needs a specific provisions.
    pub fn needs_provision(&self, batch_hash: &ProvisionHash) -> bool {
        self.missing_provision_hashes.contains(batch_hash)
    }

    /// Get the missing finalization identities as a Vec.
    pub fn missing_finalizations(&self) -> Vec<FinalizationHash> {
        self.missing_finalization_hashes.iter().copied().collect()
    }

    /// Get all received finalizations.
    pub fn finalizations(&self) -> Vec<Arc<Verifiable<Finalization>>> {
        self.received_finalizations.values().cloned().collect()
    }

    /// Construct the block from header + received transactions + received ticks.
    ///
    /// Should only be called when `is_complete()` returns true.
    pub fn construct_block(&mut self) -> Result<Arc<Block>, String> {
        if !self.is_complete() {
            return Err(format!(
                "Cannot construct block: {} transactions, {} ticks still missing",
                self.missing_transaction_hashes.len(),
                self.missing_finalization_hashes.len()
            ));
        }

        if let Some(ref block) = self.constructed_block {
            return Ok(Arc::clone(block));
        }

        // Build transactions in the ORIGINAL order from the gossip message.
        let transactions: Vec<Arc<Verifiable<Transaction>>> = self
            .manifest
            .tx_hashes()
            .iter()
            .filter_map(|hash| self.received_transactions.remove(hash))
            .collect();

        // Pass finalizations into the block in manifest order. The
        // upstream-verified marker on each `Arc<Verifiable<Finalization>>`
        // rides through unchanged so downstream consumers (apply phase,
        // verification pipeline) can peek `.verified()` and short-circuit.
        let certificates: Vec<Arc<Verifiable<Finalization>>> = self
            .manifest
            .cert_ids()
            .iter()
            .filter_map(|id| self.received_finalizations.get(id))
            .cloned()
            .collect();

        // Attach provisions in manifest order. `received_provisions` is
        // populated as provisions arrive via gossip / local fetch,
        // and `is_complete()` gates assembly on all of them being present.
        let provisions: Vec<Arc<Verifiable<Provisions>>> = self
            .manifest
            .provision_hashes()
            .iter()
            .filter_map(|hash| self.received_provisions.get(hash))
            .cloned()
            .collect();

        let block = Arc::new(Block::Live {
            header: self.header.clone(),
            transactions: Arc::new(transactions),
            certificates: Arc::new(certificates),
            provisions: Arc::new(provisions),
            abandonment_records: Arc::new(self.manifest.abandonment_records().clone()),
            state_claims: Arc::new(self.manifest.state_claims().clone()),
            witness_sources: Arc::new(self.manifest.witness_sources().clone()),
        });

        self.constructed_block = Some(Arc::clone(&block));
        Ok(block)
    }

    /// Get the constructed block, if available.
    pub const fn block(&self) -> Option<&Arc<Block>> {
        self.constructed_block.as_ref()
    }

    /// Get the block header.
    pub const fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// Time at which this pending block was first observed.
    pub const fn created_at(&self) -> LocalTimestamp {
        self.created_at
    }

    /// Get the block manifest.
    pub const fn manifest(&self) -> &BlockManifest {
        &self.manifest
    }

    /// Get total transaction count across all sections.
    pub const fn transaction_count(&self) -> usize {
        self.manifest.transaction_count()
    }

    /// Get certificate count.
    pub const fn certificate_count(&self) -> usize {
        self.manifest.cert_ids().len()
    }
}

#[cfg(test)]
impl PendingBlock {
    /// Check if all transactions have been received (ticks may still be pending).
    pub fn has_all_transactions(&self) -> bool {
        self.missing_transaction_hashes.is_empty()
    }
}

#[cfg(test)]
mod tests {

    use hyperscale_types::test_utils::test_transaction;
    use hyperscale_types::{
        Block, BlockHeaderParts, BlockHeight, ChainOrigin, Hash, ProposerTimestamp,
        QuorumCertificate, Round, ShardId, TickHalf, TickId, Verified, WitnessSources,
    };

    use super::*;

    fn make_header(height: BlockHeight) -> BlockHeader {
        BlockHeader::new(BlockHeaderParts {
            height,
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
            timestamp: ProposerTimestamp::from_millis(1_234_567_890),
            ..Default::default()
        })
    }

    fn make_header_round(height: BlockHeight, round: Round) -> BlockHeader {
        BlockHeader::new(BlockHeaderParts {
            height,
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
            timestamp: ProposerTimestamp::from_millis(1_234_567_890),
            round,
            ..Default::default()
        })
    }

    fn insert_at(pending: &mut PendingBlocks, height: BlockHeight, round: Round) -> BlockHash {
        let header = make_header_round(height, round);
        let hash = header.hash();
        pending.insert(PendingBlock::from_manifest(
            header,
            BlockManifest::default(),
            LocalTimestamp::ZERO,
        ));
        hash
    }

    /// A block held at the fence is not work this replica owes: the
    /// round timer prices it at the ordinary timeout, so the query the
    /// timer reads must not see it, while the one the pacemaker reads
    /// for a live proposal at the round still does.
    #[test]
    fn a_block_held_at_the_fence_is_not_this_replicas_own_work() {
        let mut pending = PendingBlocks::new();
        let height = BlockHeight::new(5);
        let round = Round::new(1);
        let hash = insert_at(&mut pending, height, round);

        assert!(pending.has_own_work_at_round(height, round));

        pending
            .get_mut(hash)
            .expect("the block was just inserted")
            .set_awaiting_counterpart(true);
        assert!(
            !pending.has_own_work_at_round(height, round),
            "a block waiting on a counterpart is not work that finishes here",
        );
        assert!(
            pending.has_any_at_round(height, round),
            "and it is still a proposal standing at the round",
        );

        pending
            .get_mut(hash)
            .expect("the block is still pending")
            .set_awaiting_counterpart(false);
        assert!(
            pending.has_own_work_at_round(height, round),
            "evidence that lands puts the block back in this replica's hands",
        );
    }

    #[test]
    fn count_at_height_counts_every_round() {
        let mut pending = PendingBlocks::new();
        insert_at(&mut pending, BlockHeight::new(5), Round::new(1));
        insert_at(&mut pending, BlockHeight::new(5), Round::new(2));
        insert_at(&mut pending, BlockHeight::new(6), Round::new(1));

        assert_eq!(pending.count_at_height(BlockHeight::new(5)), 2);
        assert_eq!(pending.count_at_height(BlockHeight::new(6)), 1);
        assert_eq!(pending.count_at_height(BlockHeight::new(7)), 0);
    }

    #[test]
    fn farthest_round_at_height_picks_max_distance_from_anchor() {
        let mut pending = PendingBlocks::new();
        insert_at(&mut pending, BlockHeight::new(5), Round::new(11));
        let far = insert_at(&mut pending, BlockHeight::new(5), Round::new(40));
        // A far-round block at a different height must not be considered.
        insert_at(&mut pending, BlockHeight::new(6), Round::new(1000));

        // Anchor at round 10: |11 − 10| = 1, |40 − 10| = 30 → round 40 wins.
        let (hash, distance) = pending
            .farthest_round_at_height(BlockHeight::new(5), Round::new(10))
            .expect("entries exist at height 5");
        assert_eq!(hash, far);
        assert_eq!(distance, 30);

        assert!(
            pending
                .farthest_round_at_height(BlockHeight::new(9), Round::new(10))
                .is_none()
        );
    }

    #[test]
    fn test_pending_block_creation() {
        let tx1 = TxHash::from(Hash::from_bytes(b"tx1"));
        let tx2 = TxHash::from(Hash::from_bytes(b"tx2"));
        let header = make_header(BlockHeight::new(1));

        let pb = PendingBlock::from_manifest(
            header,
            BlockManifest::new(
                vec![tx1, tx2],
                vec![],
                vec![],
                vec![],
                vec![],
                WitnessSources::empty(),
            ),
            LocalTimestamp::ZERO,
        );

        assert_eq!(pb.missing_transactions().len(), 2);
        assert!(pb.missing_transactions().contains(&tx1));
        assert!(pb.missing_transactions().contains(&tx2));
        assert!(!pb.is_complete());
        assert!(pb.block().is_none());
    }

    #[test]
    fn test_empty_block_is_complete() {
        let header = make_header(BlockHeight::new(1));
        let pb =
            PendingBlock::from_manifest(header, BlockManifest::default(), LocalTimestamp::ZERO);

        assert!(pb.is_complete());
    }

    #[test]
    fn test_pending_block_with_finalizations() {
        let tx1 = TxHash::from(Hash::from_bytes(b"tx1"));
        let one = FinalizationHash::from_raw(Hash::from_bytes(b"one"));
        let two = FinalizationHash::from_raw(Hash::from_bytes(b"two"));
        let header = make_header(BlockHeight::new(1));

        let pb = PendingBlock::from_manifest(
            header,
            BlockManifest::new(
                vec![tx1],
                vec![one, two],
                vec![],
                vec![],
                vec![],
                WitnessSources::empty(),
            ),
            LocalTimestamp::ZERO,
        );

        assert_eq!(pb.missing_transaction_count(), 1);
        assert_eq!(pb.missing_finalization_count(), 2);
        assert!(pb.needs_finalization(&one));
        assert!(pb.needs_finalization(&two));
        assert!(!pb.is_complete());
    }

    #[test]
    fn test_add_finalization() {
        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let header = make_header(BlockHeight::new(1));
        let fw: Arc<Verifiable<Finalization>> = Arc::new(
            Verified::new_unchecked_for_test(Finalization::new(
                tick_id,
                TickHalf::Determined,
                vec![],
                vec![],
            ))
            .into(),
        );

        let mut pb = PendingBlock::from_manifest(
            header,
            BlockManifest::new(
                vec![],
                vec![fw.receipt_hash()],
                vec![],
                vec![],
                vec![],
                WitnessSources::empty(),
            ),
            LocalTimestamp::ZERO,
        );

        assert_eq!(pb.missing_finalization_count(), 1);
        assert!(!pb.is_complete());

        let added = pb.add_finalization(fw);
        assert!(added);
        assert_eq!(pb.missing_finalization_count(), 0);
        assert!(pb.is_complete());
    }

    #[test]
    fn test_block_needs_transactions_and_finalizations() {
        let tx = Arc::new(Verifiable::from(test_transaction(1)));
        let tx_hash = tx.hash();
        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let header = make_header(BlockHeight::new(1));
        let fw: Arc<Verifiable<Finalization>> = Arc::new(
            Verified::new_unchecked_for_test(Finalization::new(
                tick_id,
                TickHalf::Determined,
                vec![],
                vec![],
            ))
            .into(),
        );

        let mut pb = PendingBlock::from_manifest(
            header,
            BlockManifest::new(
                vec![tx_hash],
                vec![fw.receipt_hash()],
                vec![],
                vec![],
                vec![],
                WitnessSources::empty(),
            ),
            LocalTimestamp::ZERO,
        );

        assert!(!pb.is_complete());

        // Add transaction
        pb.add_transaction(tx);
        assert!(pb.has_all_transactions());
        assert!(!pb.is_complete()); // Still missing the finalization

        pb.add_finalization(fw);
        assert!(pb.is_complete());
    }

    #[test]
    fn test_from_complete_block_is_complete() {
        let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(1));
        let fw = Arc::new(Finalization::new(
            tick_id,
            TickHalf::Determined,
            vec![],
            vec![],
        ));
        let verified_fw = Arc::new(Verified::new_unchecked_for_test((*fw).clone()).into());
        let wire_fw = Arc::new((*fw).clone().into());

        let block = Block::Live {
            header: make_header(BlockHeight::new(1)),
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(vec![wire_fw]),
            provisions: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
        };

        let pending = PendingBlock::from_complete_block(
            &block,
            vec![verified_fw],
            vec![],
            LocalTimestamp::ZERO,
        );
        assert!(pending.is_complete());
    }

    #[test]
    fn prune_committed_surfaces_orphaned_provision_hashes() {
        // Two pending blocks: one at the committed height with outstanding
        // provisions (will be pruned), one above (will be kept). The pruned
        // block's missing-provision ids must come back out so the caller
        // can cancel any pinned local-DA fetches.
        let mut pending_blocks = PendingBlocks::new();
        let prov_a = ProvisionHash::from_raw(Hash::from_bytes(b"prov_a"));
        let prov_b = ProvisionHash::from_raw(Hash::from_bytes(b"prov_b"));

        let stale = PendingBlock::from_manifest(
            make_header(BlockHeight::new(5)),
            BlockManifest::new(
                vec![],
                vec![],
                vec![prov_a, prov_b],
                vec![],
                vec![],
                WitnessSources::empty(),
            ),
            LocalTimestamp::ZERO,
        );
        let live = PendingBlock::from_manifest(
            make_header(BlockHeight::new(10)),
            BlockManifest::default(),
            LocalTimestamp::ZERO,
        );
        pending_blocks.insert(stale);
        pending_blocks.insert(live);

        let orphaned = pending_blocks.prune_committed(BlockHeight::new(5));
        let orphaned_provisions: HashSet<_> = orphaned.provisions.into_iter().collect();
        assert_eq!(orphaned_provisions, HashSet::from([prov_a, prov_b]));
        assert!(orphaned.txs.is_empty() && orphaned.finalizations.is_empty());
        assert_eq!(pending_blocks.len(), 1, "live block must remain");
    }

    #[test]
    fn prune_committed_yields_no_hashes_when_dropped_block_was_complete() {
        let mut pending_blocks = PendingBlocks::new();
        let complete = PendingBlock::from_manifest(
            make_header(BlockHeight::new(5)),
            BlockManifest::default(),
            LocalTimestamp::ZERO,
        );
        pending_blocks.insert(complete);

        let orphaned = pending_blocks.prune_committed(BlockHeight::new(5));
        assert!(orphaned.into_abandon_actions().is_empty());
        assert_eq!(pending_blocks.len(), 0);
    }

    #[test]
    fn prune_committed_keeps_fetches_a_surviving_block_still_needs() {
        // A provision shared between a pruned block and a surviving one must
        // NOT be cancelled — the surviving block is still waiting on it.
        let mut pending_blocks = PendingBlocks::new();
        let shared = ProvisionHash::from_raw(Hash::from_bytes(b"shared"));
        let only_stale = ProvisionHash::from_raw(Hash::from_bytes(b"only_stale"));

        let stale = PendingBlock::from_manifest(
            make_header(BlockHeight::new(5)),
            BlockManifest::new(
                vec![],
                vec![],
                vec![shared, only_stale],
                vec![],
                vec![],
                WitnessSources::empty(),
            ),
            LocalTimestamp::ZERO,
        );
        let live = PendingBlock::from_manifest(
            make_header(BlockHeight::new(10)),
            BlockManifest::new(
                vec![],
                vec![],
                vec![shared],
                vec![],
                vec![],
                WitnessSources::empty(),
            ),
            LocalTimestamp::ZERO,
        );
        pending_blocks.insert(stale);
        pending_blocks.insert(live);

        let orphaned = pending_blocks.prune_committed(BlockHeight::new(5));
        assert_eq!(
            orphaned.provisions,
            vec![only_stale],
            "only the id no surviving block needs may be orphaned",
        );
    }

    #[test]
    fn remove_orphaning_keeps_fetches_another_block_still_needs() {
        let mut pending_blocks = PendingBlocks::new();
        let shared = TxHash::from(Hash::from_bytes(b"shared_tx"));
        let only_dropped = TxHash::from(Hash::from_bytes(b"dropped_tx"));

        let dropped = PendingBlock::from_manifest(
            make_header(BlockHeight::new(7)),
            BlockManifest::new(
                vec![shared, only_dropped],
                vec![],
                vec![],
                vec![],
                vec![],
                WitnessSources::empty(),
            ),
            LocalTimestamp::ZERO,
        );
        let dropped_hash = dropped.header().hash();
        let other = PendingBlock::from_manifest(
            make_header(BlockHeight::new(8)),
            BlockManifest::new(
                vec![shared],
                vec![],
                vec![],
                vec![],
                vec![],
                WitnessSources::empty(),
            ),
            LocalTimestamp::ZERO,
        );
        pending_blocks.insert(dropped);
        pending_blocks.insert(other);

        let orphaned = pending_blocks
            .remove_orphaning(dropped_hash)
            .expect("block present");
        assert_eq!(
            orphaned.txs,
            vec![only_dropped],
            "a tx another pending block still needs must not be orphaned",
        );
    }
}
