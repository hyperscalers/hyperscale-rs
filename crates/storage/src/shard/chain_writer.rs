//! Chain writer trait.
//!
//! Abstracts the prepare-then-commit pattern used by both runners.
//! `prepare_block_commit` returns a [`PreparedCommit`] closure that
//! carries precomputed work; invoking the closure with a
//! [`hyperscale_types::SyncHint`] applies it efficiently.

use std::sync::Arc;

use hyperscale_types::{
    BlockHeight, Finalization, FrontierInputs, PreparedCommit, StateClaim, StateRoot, SubstateKey,
    Verifiable,
};

use crate::{Anchored, BaseReadCache, JmtSnapshot};

/// The block a new one builds on: what it committed, and the state it
/// left behind.
///
/// One value rather than five parameters because they answer one
/// question — what state did the parent leave? — and have to agree. A
/// settling receipt says what it *moved*, and a movement is nothing
/// without the value it moves from — so a `state` that did not come
/// from the block at `height` would resolve movements against the wrong
/// baseline and fork the state root against every replica that anchored
/// correctly. The pending chain and the read cache are that same answer
/// in two more forms, and carrying them here is what keeps the tree
/// overlay, the prior capture, and the movement baseline structurally
/// one chain: a mismatched pairing is not expressible.
pub struct ParentAnchor<'a> {
    /// The parent's committed state root.
    pub state_root: StateRoot,
    /// The parent's height.
    pub height: BlockHeight,
    /// The state as the parent left it — what this block's writes land
    /// on. Anchored at the parent, which is not always the committed
    /// tip: a proposer builds on blocks that have not persisted yet, so
    /// only a snapshot can answer for that height.
    pub state: &'a dyn Anchored,
    /// The certified-but-unpersisted ancestors between the committed tip
    /// and the parent, as their verification snapshots. Their tree nodes
    /// overlay the base store for the JMT computation, and their settled
    /// writes are the priors a prepared batch judges its no-op skip and
    /// history capture against — a batch built here applies only after
    /// they have. Empty when the parent is the committed tip.
    pub pending: &'a [Arc<JmtSnapshot>],
    /// Reads observed through the originating `SubstateView` during
    /// execution, keyed at the persisted base. Lets the prior capture
    /// skip a `StateCf` multi-get for keys already read — a large
    /// fraction at high TPS. `None` for callers without a view (sync,
    /// genesis, tests); implementations fall back to reading the store.
    pub base_reads: Option<&'a BaseReadCache>,
}

/// Abstracts state commitment for both simulation and production storage.
///
/// One commit path. `prepare_block_commit` computes the speculative
/// state root and returns `(state_root, jmt_snapshot, prepared)`: the
/// closure captures everything needed to perform the commit, and the
/// snapshot rides into `PendingChain` so child verifications can chain on
/// top of speculative state. The runner stores the closure and, at commit
/// time, invokes each with a `SyncHint`, batching fsyncs across the
/// flush. A block that reaches the store any other way — a synced block,
/// a reshape successor's first blocks — is prepared the same way against
/// the tip it lands on; nothing recomputes a root from scratch, so no
/// path can commit a root no verifier compared with the header's.
///
/// Execution certificates are extracted from `block.certificates` (finalizations
/// contain the ECs directly) — no separate parameter needed.
///
/// What the chain itself writes for a block beyond its receipts: the
/// committed cells it creates, the cells its sweep retires, what its
/// claims do to the read frontier, and the claims themselves, whose
/// readings license the crossing settlements the fold removes.
///
/// Derived from the block and the schedule by whoever prepares the
/// commit, so every reader of the root derives one set.
#[derive(Clone, Copy)]
pub struct ChainWrites<'a> {
    /// The committed-transaction cells, one per transaction the block
    /// carries.
    pub creations: &'a [(SubstateKey, Vec<u8>)],
    /// What the block's sweep retires.
    pub removals: &'a [SubstateKey],
    /// What the block's claims do to the read frontier.
    pub frontier: &'a FrontierInputs,
    /// The block's claims.
    pub state_claims: &'a [StateClaim],
}

/// All methods take `&self` — implementations use interior mutability.
pub trait ShardChainWriter: Send + Sync + 'static {
    /// Compute speculative state root and return precomputed commit work
    /// as a closure.
    ///
    /// Extracts and merges the writes from each finalization's receipts
    /// internally, then computes the speculative JMT root.
    ///
    /// `parent` carries everything "the state the parent left" means —
    /// the anchor root and height, the readable state, the unpersisted
    /// ancestor chain, and the execution read cache; see [`ParentAnchor`].
    /// The parent's height must be a committed height or have its tree
    /// nodes provided via `parent.pending`.
    ///
    /// `chain` is what the chain itself writes for the block beyond the
    /// receipts, and folds with their writes under the root this
    /// returns.
    ///
    /// `block_height` is the height of the block being prepared (used as
    /// the JMT new version).
    ///
    /// Returns `(computed_state_root, jmt_snapshot, prepared)`.
    fn prepare_block_commit(
        self: &Arc<Self>,
        parent: ParentAnchor<'_>,
        finalizations: &[Arc<Verifiable<Finalization>>],
        chain: ChainWrites<'_>,
        block_height: BlockHeight,
    ) -> (StateRoot, Arc<JmtSnapshot>, PreparedCommit);
}
