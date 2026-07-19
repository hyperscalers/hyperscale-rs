//! Serving-side access to shard state pinned at epoch boundaries.
//!
//! A serving shard member pins its committed state at recent epoch
//! boundary blocks so a joining vnode can snap-sync against the
//! beacon-attested boundary `state_root` while the live store keeps
//! committing and garbage-collecting. The pinning mechanics are the
//! backend's business — `RocksDB` uses hard-link checkpoints, the
//! in-memory store serves its versioned tree directly — so the node
//! layer's boundary trigger and range-serving code stay generic and run
//! identically in simulation and production.

use hyperscale_jmt::{Key, TreeReader};
use hyperscale_types::{
    BeaconWitnessLeafCount, Block, BlockHeight, ChainOrigin, ShardWitnessPayload, StateRoot,
    StoredReceipt,
};

/// How many boundary pins a backend retains before evicting the oldest.
pub const BOUNDARY_RETAIN: usize = 3;

/// Resolve a JMT leaf back to the raw substate pair it represents.
///
/// `jmt_leaf_key` is one-way, so range serving needs this to turn leaves
/// enumerated out of the tree into the raw `(storage key, value)` pairs
/// a snap-syncing joiner imports. Backends answer from their
/// leaf-association mapping at the boundary's pinned state.
pub trait ResolveLeaf {
    /// The raw `(storage key, value)` behind `leaf_key`, or `None` when
    /// the leaf is unknown at this boundary.
    fn resolve_leaf(&self, leaf_key: &Key) -> Option<(Vec<u8>, Vec<u8>)>;
}

/// The beacon-witness window a snap-synced import seeds alongside the
/// state.
///
/// Payloads for `[base, base + payloads.len())`, already verified
/// against the anchor header's witness commitment by the assembler.
/// Restores what a store that committed through the boundary would hold
/// in its witness column: the accumulator rebuilds from it on restart,
/// and the beacon fold's witness fetches answer from it. Empty for an
/// import with no witness history — a reshape successor's fresh domain.
#[derive(Debug, Clone, Default)]
pub struct WitnessSeed {
    /// Absolute leaf index of `payloads[0]` — the anchor window's base.
    pub base: BeaconWitnessLeafCount,
    /// The window's payloads in leaf-index order.
    pub payloads: Vec<ShardWitnessPayload>,
}

/// One verified snap-sync leaf ready for import: the hashed JMT key and
/// the raw substate pair it binds.
///
/// The leaf key is shipped, not recomputed — it carries the originating
/// shard's owner-prefixed routing half, which the importer cannot derive
/// from the raw key alone. The assembler has already proven it into the
/// attested `state_root` and bound both halves of the pair to it.
#[derive(Debug, Clone)]
pub struct ImportLeaf {
    /// The 32-byte hashed JMT leaf key.
    pub leaf_key: Key,
    /// The raw substate storage key.
    pub storage_key: Vec<u8>,
    /// The raw substate value.
    pub value: Vec<u8>,
}

/// Pin and serve committed state at epoch boundary heights.
pub trait BoundaryStore {
    /// A pinned boundary opened for serving: the JMT at the pinned
    /// version plus leaf resolution at that same state.
    type Boundary: TreeReader + ResolveLeaf + Send;

    /// Pin the committed state at `height` — the shard's epoch boundary
    /// block — keeping the newest [`BOUNDARY_RETAIN`] pins. Idempotent
    /// per height.
    ///
    /// # Errors
    ///
    /// Returns a description of the failure (e.g. checkpoint I/O). A
    /// failed pin degrades serving, never correctness — callers log and
    /// continue.
    fn pin_boundary(&self, height: BlockHeight) -> Result<(), String>;

    /// Open the pin at exactly `height`, or `None` if it was never
    /// pinned or has been evicted from the ring.
    fn open_boundary(&self, height: BlockHeight) -> Option<Self::Boundary>;

    /// Install a snap-synced boundary state at `height` into this
    /// (empty) store: raw substates, the JMT rebuilt from the shipped
    /// leaf keys, the leaf associations, and the anchor window's witness
    /// payloads — the state-level image of a store that committed through
    /// the boundary. Chain metadata is not touched; tail block-sync from
    /// `height + 1` layers on top.
    ///
    /// Returns the resulting state root, which the caller must compare
    /// against the beacon-attested anchor before trusting the store.
    ///
    /// # Errors
    ///
    /// Returns a description of the failure. Importing into a non-empty
    /// store is an error — the import is a bootstrap, not a merge.
    fn import_boundary_state(
        &self,
        height: BlockHeight,
        leaves: Vec<ImportLeaf>,
        witnesses: WitnessSeed,
    ) -> Result<StateRoot, String>;

    /// Apply the subset of a followed chain's block writes that falls
    /// under this store's prefix, at the block's height — substate
    /// values, the JMT, and the count, advancing the store's version.
    ///
    /// This is how a reshape observer's child-rooted store stays current
    /// with the splitting parent between its snap-synced anchor and the
    /// parent's terminal crossing: the followed blocks are the parent
    /// chain's (QC-trusted by the driver — the observer cannot verify
    /// the parent's full roots from a half store), and partition
    /// independence keeps the resulting root exactly the parent tree's
    /// subtree node at the prefix. A block whose writes carry nothing
    /// under the prefix is a no-op: the version does not advance, so the
    /// store's version line stays sparse on the parent's heights.
    ///
    /// Returns the store's state root after the application.
    ///
    /// # Errors
    ///
    /// Returns a description of the failure — a height at or below the
    /// store's current version, or a backend write failure.
    fn follow_block_writes(
        &self,
        height: BlockHeight,
        receipts: &[StoredReceipt],
    ) -> Result<StateRoot, String>;

    /// Adopt a split child's derived `genesis` into this parent-cloned
    /// store: re-root the state at the child subtree and install the block
    /// as the chain origin. Returns the adopted state root for the caller
    /// to verify against the beacon-attested anchor before trusting the
    /// store.
    ///
    /// # Errors
    ///
    /// Returns a description of the failure — a genesis block off the
    /// origin's height, an unresolvable child subtree, or a backend error.
    fn adopt_split_child(&self, origin: ChainOrigin, genesis: &Block) -> Result<StateRoot, String>;

    /// Adopt a split observer's followed-store `genesis`: the store already
    /// sits at the child state (snap-synced span plus followed parent
    /// writes), so this installs the block as the chain origin. Returns the
    /// adopted state root for the caller's anchor check.
    ///
    /// # Errors
    ///
    /// Returns a description of the failure — a genesis block off the
    /// origin's height or carrying a root other than the followed one, or a
    /// backend error.
    fn adopt_followed_child(
        &self,
        origin: ChainOrigin,
        genesis: &Block,
    ) -> Result<StateRoot, String>;

    /// Adopt a merge keeper's composed-parent `genesis` into this
    /// union-imported store, installing the block as the chain origin.
    /// Returns the adopted state root for the caller's anchor check.
    ///
    /// # Errors
    ///
    /// Returns a description of the failure — a genesis block off the
    /// origin's height, a store tip elsewhere, or a root mismatch.
    fn adopt_merge_parent(&self, origin: ChainOrigin, genesis: &Block)
    -> Result<StateRoot, String>;

    /// The committed substate byte total at `version`, or `None` when the
    /// store's version line doesn't carry it.
    fn substate_bytes_at_version(&self, version: u64) -> Option<u64>;
}
