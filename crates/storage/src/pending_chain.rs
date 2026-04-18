//! Chain-anchored pending state index.
//!
//! Single shared structure keyed by block hash. Reads happen through
//! [`SubstateView`], which is built by walking the parent chain from a
//! given anchor — orphaned blocks are not ancestors of the canonical
//! chain, so they are structurally invisible to anchored views.

use crate::{
    DatabaseUpdates, DbPartitionKey, DbSortKey, JmtSnapshot, PartitionDatabaseUpdates,
    SubstateStore,
};
use ::hyperscale_jmt as jmt;
use hyperscale_types::{Hash, LocalReceipt, MerkleInclusionProof, NodeId};
use radix_common::prelude::DatabaseUpdate;
use radix_substate_store_interface::interface::SubstateDatabase;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

/// Cached base-storage reads observed through a [`SubstateView`].
///
/// Populated lazily on every overlay-miss read; captured at commit time
/// and handed to `append_substate_writes_to_batch` so `capture_history`
/// can source priors without a fresh `multi_get_cf` on StateCf. Entries
/// are `(partition_key, sort_key) → value-at-anchor`.
pub type BaseReadCache = HashMap<(DbPartitionKey, DbSortKey), Option<Vec<u8>>>;

/// One block's worth of pending state, indexed by block hash in
/// [`PendingChain::entries`].
#[derive(Clone)]
pub struct ChainEntry {
    /// Parent block hash. Used to walk the chain back to the committed tip.
    pub parent_hash: Hash,
    /// Block height. Used for pruning and version-aware reads.
    pub height: u64,
    /// Per-tx receipts produced by this block.
    pub receipts: Vec<Arc<LocalReceipt>>,
    /// JMT snapshot from this block's speculative state-root computation.
    pub jmt_snapshot: Arc<JmtSnapshot>,
}

/// Append-only index of pending block state, shared between the io_loop
/// and dispatch closures via `Arc`.
///
/// **Anchored reads.** Reads happen through [`Self::view_at`], which
/// walks `parent_hash` back to the committed tip and flattens that
/// chain's pending state into a [`SubstateView`]. Orphaned blocks (whose
/// `parent_hash` doesn't lead back to the committed chain) are not
/// visited and contribute nothing — the orphan-corruption bug becomes
/// impossible by construction.
pub struct PendingChain<S> {
    base: Arc<S>,
    entries: RwLock<HashMap<Hash, ChainEntry>>,
}

impl<S> PendingChain<S>
where
    S: SubstateStore + jmt::TreeReader + crate::ChainReader + Sync + 'static,
{
    /// Create a new empty `PendingChain` over the given base storage.
    pub fn new(base: Arc<S>) -> Self {
        Self {
            base,
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Append an entry.
    pub fn insert(&self, block_hash: Hash, entry: ChainEntry) {
        self.entries.write().unwrap().insert(block_hash, entry);
    }

    /// Drop all entries with `height ≤ committed_height`. Called on
    /// `BlockPersisted`. Also drops cache entries whose anchor is at or
    /// below the committed height — higher-anchor views remain valid.
    pub fn prune(&self, committed_height: u64) {
        self.entries
            .write()
            .unwrap()
            .retain(|_, e| e.height > committed_height);
    }

    /// Number of pending entries (for diagnostics / metrics).
    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    /// Whether the chain has any pending entries.
    pub fn is_empty(&self) -> bool {
        self.entries.read().unwrap().is_empty()
    }

    /// Build a view anchored at `parent_hash`.
    ///
    /// The view sees state through `parent_hash` and all of its committed
    /// ancestors back to the persisted tip. Orphaned blocks not on this
    /// chain are invisible.
    pub fn view_at(self: &Arc<Self>, parent_hash: Hash) -> Arc<SubstateView<S>> {
        Arc::new(self.build_view(parent_hash))
    }

    /// Build a view anchored at the latest committed block.
    /// For actions without a natural parent (RPC reads, fetch handlers).
    ///
    /// If no blocks have been committed yet, returns a view with no
    /// pending entries (reads fall through to base storage).
    pub fn view_at_committed_tip(self: &Arc<Self>) -> Arc<SubstateView<S>> {
        match self.base.committed_hash() {
            Some(h) => self.view_at(h),
            None => Arc::new(SubstateView::base_only(
                Arc::clone(&self.base),
                self.base.jmt_version(),
            )),
        }
    }

    /// Walk `parent_hash` back through ancestors and flatten the chain
    /// into a `SubstateView`. Stops when an entry's parent is not in the
    /// index (it's been persisted, or it's the committed tip).
    ///
    /// Holds the read lock for the duration of the walk; no per-entry
    /// clones.
    fn build_view(&self, parent_hash: Hash) -> SubstateView<S> {
        let entries = self.entries.read().unwrap();
        let mut chain: Vec<&ChainEntry> = Vec::new();
        let mut cursor = parent_hash;
        while let Some(entry) = entries.get(&cursor) {
            cursor = entry.parent_hash;
            chain.push(entry);
        }
        // Walk produces deepest-first; flip to commit order.
        chain.reverse();
        // Anchor height = chain tip if any pending entries were found,
        // otherwise the base's committed tip (parent already persisted).
        let anchor_height = chain
            .last()
            .map(|e| e.height)
            .unwrap_or_else(|| self.base.jmt_version());
        SubstateView::from_chain(Arc::clone(&self.base), &chain, anchor_height)
    }
}

// ─── SubstateView ───────────────────────────────────────────────────────

/// Flattened overlay entries: `(partition_key, sort_key) → Some(value)`
/// or `None` (tombstone).
type OverlayEntries = HashMap<(DbPartitionKey, DbSortKey), Option<Vec<u8>>>;

/// JMT node index for O(1) tree-node lookup during proof generation.
type JmtNodeIndex = HashMap<jmt::NodeKey, Arc<jmt::Node>>;

/// Anchored read view over base storage + a slice of pending blocks.
///
/// Built once per anchor by [`PendingChain::view_at`] and cached via an
/// `Arc`. Implements [`SubstateDatabase`], [`SubstateStore`],
/// [`crate::ChainWriter`], and [`jmt::TreeReader`] so it can substitute
/// for the base storage in delegated action handlers.
///
/// Once built the view is immutable — interior data is never mutated.
/// This makes `Arc<SubstateView>` cheap to share across threads and
/// simplifies cache invalidation (the cache drops `Arc` references; live
/// views remain valid).
pub struct SubstateView<S> {
    base: Arc<S>,
    /// Block height of the anchor — the chain's tip, or the base's
    /// `jmt_version()` when the view has no pending entries. Used as the
    /// historical version for base-storage reads in [`Self::snapshot`],
    /// so the snapshot reflects state as-of this specific block rather
    /// than "whatever the validator has currently persisted." Critical
    /// for cross-validator determinism under persistence lag.
    anchor_height: u64,
    /// Flattened pending substates from the anchored chain, in commit order.
    /// Later entries override earlier ones for the same key.
    overlay: OverlayEntries,
    /// JMT snapshots from the same chain, in commit order. Exposed via
    /// [`Self::pending_snapshots`] so handlers can pass them to
    /// `prepare_block_commit` for chained verification.
    jmt_snapshots: Vec<Arc<JmtSnapshot>>,
    /// JMT node index built from `jmt_snapshots` for O(1) lookup
    /// (see [`jmt::TreeReader`] impl).
    jmt_nodes: JmtNodeIndex,
    /// Per-receipt references for versioned queries
    /// ([`SubstateStore::list_substates_for_node_at_height`]).
    /// Sorted by height ascending.
    versioned_receipts: Vec<(u64, Arc<LocalReceipt>)>,
    /// Lazy cache of base-storage reads observed through this view.
    /// Populated on every overlay-miss `get_raw_substate_by_db_key` call.
    /// Consumed at commit time by `take_base_reads` so `capture_history`
    /// can skip a `multi_get_cf` on StateCf for keys execution already
    /// read. Arc-shared with derived `ViewSnapshot`s so reads through
    /// either path populate the same cache.
    base_reads: Arc<Mutex<BaseReadCache>>,
}

impl<S> SubstateView<S> {
    /// Pending JMT snapshots from the anchored chain, in commit order.
    /// Pass to `prepare_block_commit` so chained verification can find
    /// tree nodes from prior unpersisted blocks.
    pub fn pending_snapshots(&self) -> &[Arc<JmtSnapshot>] {
        &self.jmt_snapshots
    }
}

impl<S> SubstateView<S> {
    /// Build a view from a chain of entries in commit order (earliest first).
    /// Takes borrowed entries so the caller can hold a read lock over the
    /// chain index for the duration of the walk without cloning.
    ///
    /// `anchor_height` is the height of the view's anchor — the chain's
    /// tip (last entry) when non-empty, or the base's committed tip when
    /// the walk produced nothing.
    fn from_chain(base: Arc<S>, chain: &[&ChainEntry], anchor_height: u64) -> Self {
        let mut overlay: OverlayEntries = HashMap::new();
        let mut jmt_snapshots: Vec<Arc<JmtSnapshot>> = Vec::with_capacity(chain.len());
        let mut jmt_nodes: JmtNodeIndex = HashMap::new();
        let mut versioned_receipts: Vec<(u64, Arc<LocalReceipt>)> = Vec::new();

        for entry in chain {
            for receipt in &entry.receipts {
                apply_database_updates(&mut overlay, &receipt.database_updates);
                versioned_receipts.push((entry.height, Arc::clone(receipt)));
            }
            for (key, node) in &entry.jmt_snapshot.nodes {
                jmt_nodes.insert(key.clone(), Arc::clone(node));
            }
            jmt_snapshots.push(Arc::clone(&entry.jmt_snapshot));
        }

        Self {
            base,
            anchor_height,
            overlay,
            jmt_snapshots,
            jmt_nodes,
            versioned_receipts,
            base_reads: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Build a view with no pending entries (reads always go to base).
    fn base_only(base: Arc<S>, anchor_height: u64) -> Self {
        Self {
            base,
            anchor_height,
            overlay: HashMap::new(),
            jmt_snapshots: Vec::new(),
            jmt_nodes: HashMap::new(),
            versioned_receipts: Vec::new(),
            base_reads: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Drain the cache of base-storage reads observed through this view.
    ///
    /// The returned map holds one entry per distinct `(partition_key,
    /// sort_key)` that was read from base (not overlay) during the view's
    /// lifetime — i.e. exactly the priors `capture_history` would
    /// otherwise re-read from StateCf at commit time. Called by the
    /// commit pipeline to skip the `multi_get_cf` on StateCf for keys
    /// already in the cache.
    pub fn take_base_reads(&self) -> BaseReadCache {
        std::mem::take(&mut *self.base_reads.lock().unwrap())
    }
}

/// Flatten one receipt's `DatabaseUpdates` into the overlay map.
/// Later calls override earlier ones for the same key (commit order).
fn apply_database_updates(overlay: &mut OverlayEntries, updates: &DatabaseUpdates) {
    for (node_key, node_updates) in &updates.node_updates {
        for (&partition_num, partition_updates) in &node_updates.partition_updates {
            let pk = DbPartitionKey {
                node_key: node_key.clone(),
                partition_num,
            };
            match partition_updates {
                PartitionDatabaseUpdates::Delta { substate_updates } => {
                    for (sort_key, update) in substate_updates {
                        let value = match update {
                            DatabaseUpdate::Set(v) => Some(v.clone()),
                            DatabaseUpdate::Delete => None,
                        };
                        overlay.insert((pk.clone(), sort_key.clone()), value);
                    }
                }
                PartitionDatabaseUpdates::Reset {
                    new_substate_values,
                } => {
                    overlay.retain(|(epk, _), _| epk != &pk);
                    for (sort_key, value) in new_substate_values {
                        overlay.insert((pk.clone(), sort_key.clone()), Some(value.clone()));
                    }
                }
            }
        }
    }
}

/// Apply overlay entries on top of a base `SubstateDatabase` read.
///
/// If `base_reads_cache` is provided, every base-storage read (overlay
/// miss) is recorded there exactly once per key — the first observed
/// value wins. The cache is handed to `capture_history` at commit time
/// so priors for keys execution already read don't require a fresh
/// `multi_get_cf` on StateCf.
fn overlay_get(
    overlay: &OverlayEntries,
    base: &dyn SubstateDatabase,
    partition_key: &DbPartitionKey,
    sort_key: &DbSortKey,
    base_reads_cache: Option<&Mutex<BaseReadCache>>,
) -> Option<Vec<u8>> {
    if let Some(v) = overlay.get(&(partition_key.clone(), sort_key.clone())) {
        return v.clone();
    }
    let value = base.get_raw_substate_by_db_key(partition_key, sort_key);
    if let Some(cache) = base_reads_cache {
        cache
            .lock()
            .unwrap()
            .entry((partition_key.clone(), sort_key.clone()))
            .or_insert_with(|| value.clone());
    }
    value
}

/// Apply overlay entries on top of a base `SubstateDatabase` list.
fn overlay_list(
    overlay: &OverlayEntries,
    base: &dyn SubstateDatabase,
    partition_key: &DbPartitionKey,
    from_sort_key: Option<&DbSortKey>,
) -> Vec<(DbSortKey, Vec<u8>)> {
    let mut overlay_for_partition: Vec<(DbSortKey, Option<Vec<u8>>)> = overlay
        .iter()
        .filter(|((pk, _), _)| pk == partition_key)
        .filter(|((_, sk), _)| from_sort_key.is_none_or(|from| sk >= from))
        .map(|((_, sk), v)| (sk.clone(), v.clone()))
        .collect();
    overlay_for_partition.sort_by(|(a, _), (b, _)| a.cmp(b));

    let overlay_keys: std::collections::HashSet<DbSortKey> = overlay_for_partition
        .iter()
        .map(|(sk, _)| sk.clone())
        .collect();

    let base_entries: Vec<(DbSortKey, Vec<u8>)> = base
        .list_raw_values_from_db_key(partition_key, from_sort_key)
        .filter(|(sk, _)| !overlay_keys.contains(sk))
        .collect();

    let overlay_live: Vec<(DbSortKey, Vec<u8>)> = overlay_for_partition
        .into_iter()
        .filter_map(|(sk, v)| v.map(|val| (sk, val)))
        .collect();

    let mut merged = Vec::with_capacity(overlay_live.len() + base_entries.len());
    merged.extend(overlay_live);
    merged.extend(base_entries);
    merged.sort_by(|(a, _), (b, _)| a.cmp(b));
    merged
}

impl<S: SubstateDatabase> SubstateDatabase for SubstateView<S> {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<Vec<u8>> {
        overlay_get(
            &self.overlay,
            &*self.base,
            partition_key,
            sort_key,
            Some(&self.base_reads),
        )
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = (DbSortKey, Vec<u8>)> + '_> {
        // List reads intentionally bypass the base-read cache: caching a
        // whole partition's rows per call would bloat the cache without
        // meaningfully reducing commit-path work (capture_history is
        // per-key, not per-partition).
        Box::new(overlay_list(&self.overlay, &*self.base, partition_key, from_sort_key).into_iter())
    }
}

/// Snapshot from a `SubstateView` — overlays the same entries on the
/// base storage's snapshot.
pub struct ViewSnapshot<Snap> {
    base_snapshot: Snap,
    overlay: Arc<OverlayEntries>,
    /// Shared with the parent `SubstateView` so reads through this
    /// snapshot populate the same cache as direct-impl reads.
    base_reads: Arc<Mutex<BaseReadCache>>,
}

impl<Snap: SubstateDatabase> SubstateDatabase for ViewSnapshot<Snap> {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<Vec<u8>> {
        overlay_get(
            &self.overlay,
            &self.base_snapshot,
            partition_key,
            sort_key,
            Some(&self.base_reads),
        )
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = (DbSortKey, Vec<u8>)> + '_> {
        Box::new(
            overlay_list(
                &self.overlay,
                &self.base_snapshot,
                partition_key,
                from_sort_key,
            )
            .into_iter(),
        )
    }
}

impl<S: SubstateStore + crate::VersionedStore> SubstateStore for SubstateView<S> {
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
            // Clone the overlay into an Arc so the snapshot is `'static`
            // with respect to the view's overlay map.
            overlay: Arc::new(self.overlay.clone()),
            // Share the base-read cache so reads via either the view's
            // direct impl or this snapshot populate the same map.
            base_reads: Arc::clone(&self.base_reads),
        }
    }

    fn jmt_version(&self) -> u64 {
        (*self.base).jmt_version()
    }

    fn state_root_hash(&self) -> Hash {
        (*self.base).state_root_hash()
    }

    fn list_substates_for_node_at_height(
        &self,
        node_id: &NodeId,
        block_height: u64,
    ) -> Option<Vec<(u8, DbSortKey, Vec<u8>)>> {
        let persisted_version = (*self.base).jmt_version();

        // If the requested height is within persisted range, delegate.
        if block_height <= persisted_version {
            return (*self.base).list_substates_for_node_at_height(node_id, block_height);
        }

        // Get base result at the persisted version (latest available on disk).
        let base_result =
            (*self.base).list_substates_for_node_at_height(node_id, persisted_version);

        // Build a map from base result, then apply pending receipts in
        // commit order up to block_height.
        let entity_key = crate::keys::node_entity_key(node_id);
        let mut substates: HashMap<(u8, DbSortKey), Vec<u8>> = base_result
            .unwrap_or_default()
            .into_iter()
            .map(|(part, sk, v)| ((part, sk), v))
            .collect();

        for (h, receipt) in &self.versioned_receipts {
            if *h > block_height {
                break;
            }
            let updates = &receipt.database_updates;
            if let Some(node_updates) = updates.node_updates.get(&entity_key) {
                for (&partition_num, partition_updates) in &node_updates.partition_updates {
                    match partition_updates {
                        PartitionDatabaseUpdates::Delta { substate_updates } => {
                            for (sort_key, update) in substate_updates {
                                match update {
                                    DatabaseUpdate::Set(v) => {
                                        substates
                                            .insert((partition_num, sort_key.clone()), v.clone());
                                    }
                                    DatabaseUpdate::Delete => {
                                        substates.remove(&(partition_num, sort_key.clone()));
                                    }
                                }
                            }
                        }
                        PartitionDatabaseUpdates::Reset {
                            new_substate_values,
                        } => {
                            substates.retain(|(p, _), _| *p != partition_num);
                            for (sort_key, value) in new_substate_values {
                                substates.insert((partition_num, sort_key.clone()), value.clone());
                            }
                        }
                    }
                }
            }
        }

        Some(
            substates
                .into_iter()
                .map(|((p, sk), v)| (p, sk, v))
                .collect(),
        )
    }

    fn generate_merkle_proofs(
        &self,
        storage_keys: &[Vec<u8>],
        block_height: u64,
    ) -> Option<MerkleInclusionProof> {
        // Try base first — works for heights already persisted.
        if let Some(proof) = (*self.base).generate_merkle_proofs(storage_keys, block_height) {
            return Some(proof);
        }
        // Beyond persisted — caller should use `generate_merkle_proofs_overlay`
        // which uses the JMT overlay via this view's `TreeReader` impl.
        None
    }
}

/// Override `generate_merkle_proofs` for callers that have a
/// `jmt::TreeReader`-capable base, using the JMT overlay for unpersisted
/// heights.
impl<S: SubstateStore + jmt::TreeReader + Sync> SubstateView<S> {
    /// Generate merkle proofs, falling back to the JMT overlay for
    /// unpersisted block heights.
    pub fn generate_merkle_proofs_overlay(
        &self,
        storage_keys: &[Vec<u8>],
        block_height: u64,
    ) -> Option<MerkleInclusionProof> {
        if let Some(proof) = (*self.base).generate_merkle_proofs(storage_keys, block_height) {
            return Some(proof);
        }
        crate::tree::proofs::generate_proof(self, storage_keys, block_height)
    }
}

impl<S: jmt::TreeReader + Sync> jmt::TreeReader for SubstateView<S> {
    fn get_node(&self, key: &jmt::NodeKey) -> Option<Arc<jmt::Node>> {
        self.jmt_nodes
            .get(key)
            .cloned()
            .or_else(|| (*self.base).get_node(key))
    }

    fn get_root_key(&self, version: u64) -> Option<jmt::NodeKey> {
        let root_key = jmt::NodeKey::root(version);
        if self.jmt_nodes.contains_key(&root_key) {
            Some(root_key)
        } else {
            (*self.base).get_root_key(version)
        }
    }
}

impl<S: crate::ChainWriter> crate::ChainWriter for SubstateView<S> {
    type PreparedCommit = S::PreparedCommit;

    fn prepare_block_commit(
        &self,
        parent_state_root: Hash,
        parent_block_height: u64,
        finalized_waves: &[Arc<hyperscale_types::FinalizedWave>],
        block_height: u64,
        pending_snapshots: &[Arc<JmtSnapshot>],
        base_reads: Option<&BaseReadCache>,
    ) -> (Hash, Self::PreparedCommit) {
        // Drain the view's own cache when the caller didn't supply one.
        // This is the common path: execution reads through the view,
        // prepare_block_commit consumes the accumulated priors so the
        // base's capture_history can skip the StateCf multi_get.
        let drained = if base_reads.is_none() {
            Some(self.take_base_reads())
        } else {
            None
        };
        let effective = base_reads.or(drained.as_ref());
        (*self.base).prepare_block_commit(
            parent_state_root,
            parent_block_height,
            finalized_waves,
            block_height,
            pending_snapshots,
            effective,
        )
    }

    fn commit_prepared_blocks(
        &self,
        blocks: Vec<(
            Self::PreparedCommit,
            Arc<hyperscale_types::Block>,
            Arc<hyperscale_types::QuorumCertificate>,
        )>,
    ) -> Vec<Hash> {
        (*self.base).commit_prepared_blocks(blocks)
    }

    fn commit_block(
        &self,
        block: &Arc<hyperscale_types::Block>,
        qc: &Arc<hyperscale_types::QuorumCertificate>,
    ) -> Hash {
        (*self.base).commit_block(block, qc)
    }

    fn jmt_snapshot(prepared: &Self::PreparedCommit) -> &JmtSnapshot {
        S::jmt_snapshot(prepared)
    }

    fn memory_usage_bytes(&self) -> (u64, u64) {
        (*self.base).memory_usage_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indexmap::IndexMap;
    use radix_substate_store_interface::interface::{DatabaseUpdates, PartitionDatabaseUpdates};

    /// Minimal stub implementing every trait `PendingChain<S>` requires.
    /// Returns no data — tests only exercise the overlay and chain-walk
    /// behavior, not the base storage.
    struct StubStore;

    impl SubstateDatabase for StubStore {
        fn get_raw_substate_by_db_key(
            &self,
            _partition_key: &DbPartitionKey,
            _sort_key: &DbSortKey,
        ) -> Option<Vec<u8>> {
            None
        }
        fn list_raw_values_from_db_key(
            &self,
            _partition_key: &DbPartitionKey,
            _from_sort_key: Option<&DbSortKey>,
        ) -> Box<dyn Iterator<Item = (DbSortKey, Vec<u8>)> + '_> {
            Box::new(std::iter::empty())
        }
    }

    /// Empty snapshot for `StubStore` — returns no data.
    struct StubSnapshot;
    impl SubstateDatabase for StubSnapshot {
        fn get_raw_substate_by_db_key(
            &self,
            _partition_key: &DbPartitionKey,
            _sort_key: &DbSortKey,
        ) -> Option<Vec<u8>> {
            None
        }
        fn list_raw_values_from_db_key(
            &self,
            _partition_key: &DbPartitionKey,
            _from_sort_key: Option<&DbSortKey>,
        ) -> Box<dyn Iterator<Item = (DbSortKey, Vec<u8>)> + '_> {
            Box::new(std::iter::empty())
        }
    }

    impl SubstateStore for StubStore {
        type Snapshot<'a> = StubSnapshot;
        fn snapshot(&self) -> Self::Snapshot<'_> {
            StubSnapshot
        }
        fn jmt_version(&self) -> u64 {
            0
        }
        fn state_root_hash(&self) -> Hash {
            Hash::ZERO
        }
        fn list_substates_for_node_at_height(
            &self,
            _node_id: &NodeId,
            _block_height: u64,
        ) -> Option<Vec<(u8, DbSortKey, Vec<u8>)>> {
            None
        }
        fn generate_merkle_proofs(
            &self,
            _storage_keys: &[Vec<u8>],
            _block_height: u64,
        ) -> Option<MerkleInclusionProof> {
            None
        }
    }

    impl crate::VersionedStore for StubStore {
        fn snapshot_at(&self, _version: u64) -> Self::Snapshot<'_> {
            StubSnapshot
        }
    }

    impl jmt::TreeReader for StubStore {
        fn get_node(&self, _key: &jmt::NodeKey) -> Option<Arc<jmt::Node>> {
            None
        }
        fn get_root_key(&self, _version: u64) -> Option<jmt::NodeKey> {
            None
        }
    }

    impl crate::ChainReader for StubStore {
        fn get_block(
            &self,
            _height: hyperscale_types::BlockHeight,
        ) -> Option<(hyperscale_types::Block, hyperscale_types::QuorumCertificate)> {
            None
        }
        fn committed_height(&self) -> hyperscale_types::BlockHeight {
            hyperscale_types::BlockHeight(0)
        }
        fn committed_hash(&self) -> Option<Hash> {
            None
        }
        fn latest_qc(&self) -> Option<hyperscale_types::QuorumCertificate> {
            None
        }
        fn get_block_for_sync(
            &self,
            _height: hyperscale_types::BlockHeight,
        ) -> Option<(hyperscale_types::Block, hyperscale_types::QuorumCertificate)> {
            None
        }
        fn get_transactions_batch(
            &self,
            _hashes: &[Hash],
        ) -> Vec<hyperscale_types::RoutableTransaction> {
            Vec::new()
        }
        fn get_certificates_batch(
            &self,
            _hashes: &[Hash],
        ) -> Vec<hyperscale_types::WaveCertificate> {
            Vec::new()
        }
        fn get_local_receipt(&self, _tx_hash: &Hash) -> Option<Arc<LocalReceipt>> {
            None
        }
        fn get_execution_certificates_by_height(
            &self,
            _block_height: u64,
        ) -> Vec<hyperscale_types::ExecutionCertificate> {
            Vec::new()
        }
        fn get_wave_certificate_for_tx(
            &self,
            _tx_hash: &Hash,
        ) -> Option<hyperscale_types::WaveCertificate> {
            None
        }
        fn get_ec_hashes_for_tx(
            &self,
            _tx_hash: &Hash,
        ) -> Option<Vec<(hyperscale_types::ShardGroupId, Hash)>> {
            None
        }
    }

    fn make_delta(
        node_key: &[u8],
        partition: u8,
        sort_key: Vec<u8>,
        value: Vec<u8>,
    ) -> DatabaseUpdates {
        let mut updates = DatabaseUpdates::default();
        let node = updates.node_updates.entry(node_key.to_vec()).or_default();
        let part = node.partition_updates.entry(partition).or_insert_with(|| {
            PartitionDatabaseUpdates::Delta {
                substate_updates: IndexMap::new(),
            }
        });
        if let PartitionDatabaseUpdates::Delta { substate_updates } = part {
            substate_updates.insert(DbSortKey(sort_key), DatabaseUpdate::Set(value));
        }
        updates
    }

    fn make_receipt(updates: DatabaseUpdates) -> Arc<LocalReceipt> {
        use hyperscale_types::{LocalReceipt, TransactionOutcome};
        Arc::new(LocalReceipt {
            outcome: TransactionOutcome::Success,
            database_updates: updates,
            application_events: vec![],
        })
    }

    fn empty_snapshot() -> Arc<JmtSnapshot> {
        Arc::new(JmtSnapshot {
            base_root: Hash::ZERO,
            base_version: 0,
            result_root: Hash::ZERO,
            new_version: 0,
            nodes: vec![],
            stale_node_keys: vec![],
            leaf_substate_associations: vec![],
        })
    }

    fn entry_at(parent: Hash, height: u64, updates: DatabaseUpdates) -> ChainEntry {
        ChainEntry {
            parent_hash: parent,
            height,
            receipts: vec![make_receipt(updates)],
            jmt_snapshot: empty_snapshot(),
        }
    }

    fn empty_chain() -> Arc<PendingChain<StubStore>> {
        Arc::new(PendingChain::new(Arc::new(StubStore)))
    }

    #[test]
    fn prune_drops_old_entries() {
        let chain = empty_chain();
        let h1 = Hash::from_bytes(b"h1");
        let h2 = Hash::from_bytes(b"h2");
        let h3 = Hash::from_bytes(b"h3");
        chain.insert(h1, entry_at(Hash::ZERO, 1, DatabaseUpdates::default()));
        chain.insert(h2, entry_at(h1, 2, DatabaseUpdates::default()));
        chain.insert(h3, entry_at(h2, 3, DatabaseUpdates::default()));

        chain.prune(2);
        assert_eq!(chain.entries.read().unwrap().len(), 1);
        assert!(chain.entries.read().unwrap().contains_key(&h3));
    }

    #[test]
    fn view_at_walks_parent_chain() {
        let chain = empty_chain();
        let h1 = Hash::from_bytes(b"h1");
        let h2 = Hash::from_bytes(b"h2");

        let pk = DbPartitionKey {
            node_key: b"node".to_vec(),
            partition_num: 0,
        };

        chain.insert(
            h1,
            entry_at(Hash::ZERO, 1, make_delta(b"node", 0, vec![1], vec![10])),
        );
        chain.insert(
            h2,
            entry_at(h1, 2, make_delta(b"node", 0, vec![2], vec![20])),
        );

        let view = chain.view_at(h2);
        // h2's parent chain: h2 → h1 → ZERO. Should see both writes.
        assert_eq!(
            view.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![1])),
            Some(vec![10]),
        );
        assert_eq!(
            view.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![2])),
            Some(vec![20]),
        );
    }

    #[test]
    fn orphans_are_invisible_to_committed_chain_view() {
        let chain = empty_chain();
        let h1 = Hash::from_bytes(b"h1");
        let orphan = Hash::from_bytes(b"orphan");

        let pk = DbPartitionKey {
            node_key: b"node".to_vec(),
            partition_num: 0,
        };

        chain.insert(
            h1,
            entry_at(Hash::ZERO, 1, make_delta(b"node", 0, vec![1], vec![10])),
        );
        // Orphan: same height as h1, different parent (forks off ZERO).
        chain.insert(
            orphan,
            entry_at(Hash::ZERO, 1, make_delta(b"node", 0, vec![1], vec![99])),
        );

        // View anchored at h1: should see h1's value, not the orphan's.
        let view = chain.view_at(h1);
        assert_eq!(
            view.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![1])),
            Some(vec![10]),
        );
    }

    #[test]
    fn view_at_committed_tip_with_no_commits_returns_base_only() {
        let chain = empty_chain();
        let view = chain.view_at_committed_tip();
        let pk = DbPartitionKey {
            node_key: b"missing".to_vec(),
            partition_num: 0,
        };
        assert_eq!(
            view.get_raw_substate_by_db_key(&pk, &DbSortKey(vec![1])),
            None,
        );
    }
}
