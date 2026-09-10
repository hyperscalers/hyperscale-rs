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

use hyperscale_jmt::{Key, NibblePath, TreeReader};
use hyperscale_types::{
    BeaconWitnessLeafCount, Block, BlockHeight, CertifiedBlockHeader, ChainOrigin, ShardId,
    ShardWitnessPayload, StateRoot, SubstateKey, SubstateLeaf,
};

use crate::Substates;

/// The default number of boundary pins a backend retains before
/// evicting the oldest.
///
/// The memory backend's fixed retention and the `RocksDB` config
/// default. Production serving retention must cover the join budget
/// plus the attestation lag of the anchor a joiner selects, so the
/// validator overrides it with the chain-derived
/// `boundary_retention_epochs`.
pub const BOUNDARY_RETAIN: usize = 3;

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
    /// The anchor's certified header — the boundary block's header and
    /// the QC that certifies it, verified against the attested anchor.
    /// A store that committed through the boundary holds it with the
    /// block; an import holds it alone, and serves the next joiner's
    /// witness history from it. `None` for an import with no history.
    pub boundary: Option<CertifiedBlockHeader>,
}

/// One sub-range's fetch cursor within a staged import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportCursor {
    /// Next un-fetched key (inclusive). Meaningless when `done`.
    pub next: Key,
    /// Last key of the sub-range (inclusive).
    pub end: Key,
    /// Whether the sub-range is exhausted through `end`.
    pub done: bool,
}

/// The durable progress record of a streamed boundary import, written
/// atomically with every staged chunk.
///
/// Binds the staged data to the exact anchor its chunks were proven
/// against: staged leaves are meaningless against any other
/// `state_root`, so a resume whose attested anchor (or fetch geometry)
/// differs must wipe the staging area and start fresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportProgress {
    /// The anchor height the chunks verify at — the height finalize
    /// installs.
    pub anchor_height: BlockHeight,
    /// The attested state root every staged chunk was proven into.
    pub anchor_state_root: StateRoot,
    /// The sub-range fan-out the cursors were partitioned under.
    pub split_bits: u8,
    /// The per-request leaf limit the cursors advanced by.
    pub chunk_limit: u32,
    /// Accumulated leaf value bytes across every staged chunk — the
    /// imported substate byte total once the assembly completes. Restored
    /// on resume so the recovered state's byte frontier covers chunks
    /// staged before the restart.
    pub staged_bytes: u64,
    /// Per-sub-range fetch cursors.
    pub cursors: Vec<ImportCursor>,
}

/// How a reshape successor's store reaches the version its genesis sits at
/// — the only thing that differs between the three adoptions, decided by
/// [`adopt_plan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdoptSource {
    /// A split child seeded by checkpoint-cloning its parent: the child
    /// subtree is extracted from the parent's root node and re-pointed at
    /// the genesis version.
    ParentSubtree,
    /// A split child assembled by an observer: the store's own tip *is* the
    /// adopted subtree — snap-synced at the parent's anchor, then carried
    /// forward by following the parent's child-half writes. The version
    /// line is sparse on the parent's heights, so the tip's root node is
    /// re-pointed at the genesis version.
    FollowedTip,
    /// A merged parent's union, already assembled at the genesis version by
    /// the boundary import. Nothing to re-point; unlike a split child the
    /// prefix may be the trie root.
    InPlace,
}

/// What a store reads under its lock before deciding an adoption: the
/// tree's tip, the prefix it is rooted at, and the origin its chain
/// recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vintage {
    /// The tree's version.
    pub version: u64,
    /// The root the tree carries at that version.
    pub root: StateRoot,
    /// The prefix the tree is rooted at — a split child's, or the trie
    /// root for a merged parent.
    pub prefix: NibblePath,
    /// The origin the chain recorded.
    pub origin: ChainOrigin,
}

/// A subtree the tree holds at this store's prefix: the version its
/// root node sits at, and the root it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subtree {
    /// The version the root node is keyed at.
    pub version: u64,
    /// The subtree's root.
    pub root: StateRoot,
}

/// What an adoption does to the store, decided by [`adopt_plan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Adoption {
    /// A re-run over an already-adopted store: the recorded root, and
    /// nothing to write.
    Recorded(StateRoot),
    /// The tip already sits at the genesis version — a merged union the
    /// boundary import built there. Record the origin and the genesis
    /// tip over it.
    InPlace(StateRoot),
    /// Re-root the tree at the genesis version: copy the subtree's root
    /// node there, or install the empty root when the side is empty;
    /// then drop the sweep rows the prefix no longer owns, and record
    /// the origin and the genesis tip.
    Repoint(Option<Subtree>),
}

impl Adoption {
    /// The root the adoption installs, or answers with.
    #[must_use]
    pub fn root(self) -> StateRoot {
        match self {
            Self::Recorded(root) | Self::InPlace(root) => root,
            Self::Repoint(subtree) => subtree.map_or(StateRoot::ZERO, |subtree| subtree.root),
        }
    }
}

/// Decide a reshape successor's adoption of `genesis` from what the
/// store holds.
///
/// One decision for every backend and all three sources, so the two
/// stores cannot diverge on what an adoption admits. The store reads its
/// `vintage` under its commit lock and applies what comes back;
/// `parent_slot(version)` is the one read the decision needs mid-way —
/// the child-side slot of the parent root node at `version`, for a
/// clone of a parent checkpoint.
///
/// The rules, in order. The genesis must sit at the origin's height. A
/// store whose tip already sits at that height under this origin is
/// adopted: the answer is the recorded root, and the parent slot the
/// first run consumed is not read again. Then the source's vintage: an
/// in-place union must already sit at the genesis version; a followed
/// store must sit below it — it only ever advanced on the child half's
/// writes, which the parent's coast cannot produce; a parent checkpoint
/// may sit at the crossing or anywhere the coast carried it, since the
/// frozen root makes the extracted subtree identical at every one. A
/// split child needs a prefix off the trie root; a merged parent may sit
/// at it. Last, the root gate, which is the guarantee: a successor's
/// genesis derives from frozen chain content its duty commit-proved, so
/// it cannot name a subtree no terminal committed, and a store that does
/// not hold what the genesis names must not seat.
///
/// # Errors
///
/// A description of what refused the adoption: the genesis block off
/// the origin's height, a vintage `source` does not admit, an
/// unresolvable subtree, or an adopted root the genesis does not name.
pub fn adopt_plan(
    vintage: &Vintage,
    origin: ChainOrigin,
    genesis: &Block,
    source: AdoptSource,
    parent_slot: impl FnOnce(u64) -> Result<Option<Subtree>, String>,
) -> Result<Adoption, String> {
    if genesis.height() != origin.genesis_height {
        return Err(format!(
            "genesis block at height {} does not sit at the origin's {}",
            genesis.height(),
            origin.genesis_height,
        ));
    }
    let genesis_version = origin.genesis_height.inner();
    if vintage.version == genesis_version && vintage.origin == origin {
        return Ok(Adoption::Recorded(vintage.root));
    }
    let adoption = match source {
        AdoptSource::InPlace => {
            if vintage.version != genesis_version {
                return Err(format!(
                    "in-place adoption vintage mismatch: store at version {}, genesis height \
                     {genesis_version}",
                    vintage.version,
                ));
            }
            Adoption::InPlace(vintage.root)
        }
        AdoptSource::ParentSubtree | AdoptSource::FollowedTip => {
            if vintage.prefix.is_empty() {
                return Err("split adoption requires a non-root child prefix".to_string());
            }
            if source == AdoptSource::FollowedTip {
                if vintage.version >= genesis_version {
                    return Err(format!(
                        "followed adoption vintage mismatch: store at version {}, genesis \
                         height {genesis_version}",
                        vintage.version,
                    ));
                }
                Adoption::Repoint((vintage.root != StateRoot::ZERO).then_some(Subtree {
                    version: vintage.version,
                    root: vintage.root,
                }))
            } else {
                Adoption::Repoint(parent_slot(vintage.version)?)
            }
        }
    };
    let adopted = adoption.root();
    if adopted != genesis.header().state_root() {
        return Err(format!(
            "adopted root {adopted:?} does not match the genesis state root {:?}",
            genesis.header().state_root(),
        ));
    }
    Ok(adoption)
}

/// Whether a JMT at `height` carrying `root` already holds authenticated
/// state — anything a snap-sync import would overwrite.
///
/// The gate every import call owes the [`BoundaryStore`] contract, stated
/// once rather than spelled at each of them. Neither term implies the
/// other: a store past `BlockHeight::GENESIS` always holds state, and one
/// at `GENESIS` holds it as soon as a genesis build or a reshape clone has
/// filled its trie. Callers pass the pair they read under whatever lock
/// makes the two atomic for their backend.
///
/// Not "has a chain to resume from". A reshape seat boots with its
/// coordinator at `GENESIS` over a trie its adoption already filled, so a
/// caller choosing between resuming a chain and snap-syncing one asks the
/// chain, not this.
#[must_use]
pub fn holds_state(height: BlockHeight, root: StateRoot) -> bool {
    height != BlockHeight::GENESIS || root != StateRoot::ZERO
}

/// Pin and serve committed state at epoch boundary heights.
pub trait BoundaryStore {
    /// A pinned boundary opened for serving: the JMT at the pinned
    /// version plus substate reads at that same state — a leaf
    /// enumerated out of the tree is read back by its own key.
    type Boundary: TreeReader + Substates + Send;

    /// Pin the committed state at `height` — the shard's epoch boundary
    /// block — keeping a backend-configured number of recent pins
    /// (default [`BOUNDARY_RETAIN`]). A pinned boundary must outlive
    /// the join budget of a peer syncing against it. Idempotent per
    /// height.
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

    /// Durably stage one verified snap-sync chunk together with the
    /// import's progress record, in one atomic write. The store proper is
    /// untouched — staged bytes are not an import until
    /// [`Self::finalize_boundary_import`] builds the state from them —
    /// so the empty-store gate keeps its meaning throughout the
    /// assembly. Chunks may stage under different progress snapshots
    /// (a merge keeper stages both terminating children's disjoint
    /// spans into one store); the record reflects the latest write.
    ///
    /// # Errors
    ///
    /// Returns a description of the failure. Staging into a non-empty
    /// store is an error — the import is a bootstrap, not a merge.
    fn stage_import_chunk(
        &self,
        progress: &ImportProgress,
        leaves: &[SubstateLeaf],
    ) -> Result<(), String>;

    /// The staged import's progress record, or `None` when nothing is
    /// staged.
    fn read_import_progress(&self) -> Option<ImportProgress>;

    /// Discard every staged chunk, the progress record, and any partial
    /// state a [`finalize_boundary_import`](Self::finalize_boundary_import)
    /// interrupted before its completion marker left behind — the caller
    /// may build a fresh assembly directly on top of the wiped store. A
    /// no-op when nothing is staged.
    ///
    /// # Errors
    ///
    /// Returns a description of the failure (backend write error).
    fn wipe_import_staging(&self) -> Result<(), String>;

    /// Install the staged boundary state at `height` into this (empty)
    /// store: raw substates, the JMT rebuilt from the staged leaf keys,
    /// and the anchor window's witness payloads — the state-level image
    /// of a store that committed through the boundary, pinned at
    /// `height` as that store's would be and holding the boundary's
    /// certified header, so the next joiner can sync from this one. The
    /// staging area is cleared on success. No other chain metadata is
    /// touched; tail block-sync from `height + 1` layers on top.
    ///
    /// Returns the resulting state root, which the caller must compare
    /// against the beacon-attested anchor before trusting the store.
    /// Idempotent under re-runs after a crash mid-finalize: the JMT
    /// metadata write is the completion marker, and re-applying the same
    /// staged leaves overwrites deterministically.
    ///
    /// # Errors
    ///
    /// Returns a description of the failure. Finalizing a non-empty
    /// store is an error — the import is a bootstrap, not a merge.
    fn finalize_boundary_import(
        &self,
        height: BlockHeight,
        witnesses: WitnessSeed,
    ) -> Result<StateRoot, String>;

    /// Apply the subset of a followed chain's block that falls under
    /// this store's prefix, at the block's height — substate values, the
    /// JMT, and the count, advancing the store's version.
    ///
    /// This is how a reshape observer's child-rooted store stays current
    /// with the splitting parent between its snap-synced anchor and the
    /// parent's terminal crossing: the followed blocks are the parent
    /// chain's (QC-trusted by the driver — the observer cannot verify
    /// the parent's full roots from a half store), and partition
    /// independence keeps the resulting root exactly the parent tree's
    /// subtree node at the prefix. The block is applied as the chain
    /// applied it — the receipts its ticks settled, the committed cells
    /// its committer derived under the block's own window, `creations`,
    /// and the sweep its header names — so the follower's half reads
    /// exactly as the parent's. A block that
    /// touches nothing under the prefix is a no-op: the version does not
    /// advance, so the store's version line stays sparse on the parent's
    /// heights.
    ///
    /// Returns the store's state root after the application.
    ///
    /// # Errors
    ///
    /// Returns a description of the failure — a height at or below the
    /// store's current version, or a backend write failure.
    fn follow_block_writes(
        &self,
        block: &Block,
        creations: &[(SubstateKey, Vec<u8>)],
    ) -> Result<StateRoot, String>;

    /// Install a reshape successor's derived `genesis` as this store's
    /// chain origin and committed tip, returning the adopted state root:
    /// [`adopt_plan`] decided over this store's vintage, then applied.
    ///
    /// Idempotent: a re-run over an already-adopted store returns the
    /// recorded adoption.
    ///
    /// # Errors
    ///
    /// What [`adopt_plan`] refused.
    fn adopt_genesis(
        &self,
        origin: ChainOrigin,
        genesis: &Block,
        source: AdoptSource,
    ) -> Result<StateRoot, String>;

    /// The committed substate byte total at `version`, or `None` when the
    /// store's version line doesn't carry it.
    fn substate_bytes_at_version(&self, version: u64) -> Option<u64>;

    /// Every escrow record `shard`'s slice of the committed state holds,
    /// with its bytes.
    ///
    /// Derived on demand rather than indexed, because the state is the
    /// authority and the one caller asks once: a reshape successor whose
    /// adoption just filled its trie, and whose ledger begins empty
    /// while the value its predecessors escrowed rides the prefix in.
    /// Nothing else names those records — the entry that would is the
    /// predecessor's ledger's, a fold over a chain the successor never
    /// replays, and the cell is outside every sweep's reach.
    ///
    /// Bounded by the shard's own prefix rather than run over the store:
    /// a split child's store is a clone of its parent's and holds the
    /// sibling's leaves too, and an obligation the sibling owns is not
    /// this seat's to take. The keyspace is owner-major, so the prefix is
    /// a contiguous run and the scan is that run and nothing else.
    fn escrow_records(&self, shard: ShardId) -> Vec<(SubstateKey, Vec<u8>)>;
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{Hash, ValidatorId, WeightedTimestamp};

    use super::*;

    fn origin_at(height: u64) -> ChainOrigin {
        ChainOrigin {
            genesis_height: BlockHeight::new(height),
            anchor_wt: WeightedTimestamp::from_millis(42_000),
        }
    }

    fn genesis_naming(root: StateRoot, origin: ChainOrigin) -> Block {
        Block::genesis(ShardId::ROOT, ValidatorId::new(0), root, origin)
    }

    fn root(tag: &[u8]) -> StateRoot {
        StateRoot::from_raw(Hash::from_bytes(tag))
    }

    fn child_prefix() -> NibblePath {
        let mut path = NibblePath::empty();
        path.push_bits(1, 1);
        path
    }

    fn vintage(version: u64, root: StateRoot, prefix: NibblePath, origin: ChainOrigin) -> Vintage {
        Vintage {
            version,
            root,
            prefix,
            origin,
        }
    }

    fn no_slot(_: u64) -> Result<Option<Subtree>, String> {
        panic!("the parent slot is not read")
    }

    /// A store already sitting at the genesis under this origin answers
    /// its recorded root without reading the parent slot again.
    #[test]
    fn an_adopted_store_answers_its_recorded_root() {
        let origin = origin_at(10);
        let held = root(b"held");
        let genesis = genesis_naming(root(b"anything"), origin);
        let vintage = vintage(10, held, child_prefix(), origin);
        for source in [
            AdoptSource::ParentSubtree,
            AdoptSource::FollowedTip,
            AdoptSource::InPlace,
        ] {
            assert_eq!(
                adopt_plan(&vintage, origin, &genesis, source, no_slot),
                Ok(Adoption::Recorded(held)),
            );
        }
    }

    /// A followed store sits below the genesis height or it is not a
    /// followed store: its tip is the adopted subtree, and an empty tip is
    /// the empty side.
    #[test]
    fn a_followed_tip_must_sit_below_the_genesis_and_adopts_its_own_root() {
        let origin = origin_at(10);
        let followed = root(b"followed");
        let genesis = genesis_naming(followed, origin);
        let below = vintage(8, followed, child_prefix(), ChainOrigin::ROOT);
        assert_eq!(
            adopt_plan(&below, origin, &genesis, AdoptSource::FollowedTip, no_slot),
            Ok(Adoption::Repoint(Some(Subtree {
                version: 8,
                root: followed
            }))),
        );
        let at = vintage(10, followed, child_prefix(), ChainOrigin::ROOT);
        assert!(
            adopt_plan(&at, origin, &genesis, AdoptSource::FollowedTip, no_slot)
                .unwrap_err()
                .contains("followed adoption vintage mismatch")
        );
        let empty = vintage(3, StateRoot::ZERO, child_prefix(), ChainOrigin::ROOT);
        let empty_genesis = genesis_naming(StateRoot::ZERO, origin);
        assert_eq!(
            adopt_plan(
                &empty,
                origin,
                &empty_genesis,
                AdoptSource::FollowedTip,
                no_slot
            ),
            Ok(Adoption::Repoint(None)),
        );
    }

    /// A parent checkpoint adopts whatever the child slot holds at its
    /// version — at the crossing or past a coast — and the root gate is
    /// what refuses a slot the genesis does not name.
    #[test]
    fn a_parent_checkpoint_adopts_its_child_slot_behind_the_root_gate() {
        let origin = origin_at(10);
        let slot = root(b"child slot");
        let genesis = genesis_naming(slot, origin);
        let coasted = vintage(13, root(b"parent"), child_prefix(), ChainOrigin::ROOT);
        let read = |version: u64| {
            assert_eq!(version, 13, "the slot is read at the checkpoint's version");
            Ok(Some(Subtree {
                version: 9,
                root: slot,
            }))
        };
        assert_eq!(
            adopt_plan(&coasted, origin, &genesis, AdoptSource::ParentSubtree, read),
            Ok(Adoption::Repoint(Some(Subtree {
                version: 9,
                root: slot
            }))),
        );
        let forged = genesis_naming(root(b"forged"), origin);
        assert!(
            adopt_plan(&coasted, origin, &forged, AdoptSource::ParentSubtree, read)
                .unwrap_err()
                .contains("does not match the genesis state root")
        );
        let at_root = vintage(13, root(b"parent"), NibblePath::empty(), ChainOrigin::ROOT);
        assert!(
            adopt_plan(
                &at_root,
                origin,
                &genesis,
                AdoptSource::ParentSubtree,
                no_slot
            )
            .unwrap_err()
            .contains("non-root child prefix")
        );
    }

    /// A merged union is adopted where it stands, and only there.
    #[test]
    fn an_in_place_union_must_already_sit_at_the_genesis() {
        let origin = origin_at(10);
        let union = root(b"union");
        let genesis = genesis_naming(union, origin);
        let built = vintage(10, union, NibblePath::empty(), ChainOrigin::ROOT);
        assert_eq!(
            adopt_plan(&built, origin, &genesis, AdoptSource::InPlace, no_slot),
            Ok(Adoption::InPlace(union)),
        );
        let short = vintage(9, union, NibblePath::empty(), ChainOrigin::ROOT);
        assert!(
            adopt_plan(&short, origin, &genesis, AdoptSource::InPlace, no_slot)
                .unwrap_err()
                .contains("in-place adoption vintage mismatch")
        );
        let elsewhere = genesis_naming(union, origin_at(11));
        assert!(
            adopt_plan(&built, origin, &elsewhere, AdoptSource::InPlace, no_slot)
                .unwrap_err()
                .contains("does not sit at the origin's")
        );
    }
}
