//! Host bring-up: genesis bootstrap.
//!
//! These methods run at well-defined points in the host's life, not
//! on every event. The run-loop methods live in [`super`].
//!
//! - [`NodeHost::initialize_shard_genesis`] feeds the supplied genesis
//!   block into its shard's replica and drains the resulting actions.
//! - [`network_genesis_block`] commits the network genesis substates into a
//!   fresh store and builds the genesis block over their state root. Every
//!   store that installs it builds the same block.

use std::sync::Arc;

use hyperscale_dispatch::Dispatch;
use hyperscale_engine::sharding::{filter_genesis_writes_for_shard, owned_by};
use hyperscale_engine::{GenesisConfig, genesis_writes};
use hyperscale_network::Network;
use hyperscale_storage::{GenesisCommit, RecoveredState, ShardStorage};
use hyperscale_types::{
    Block, CertifiedBlock, ChainOrigin, ShardId, StateRoot, TopologySnapshot, ValidatorId,
    Verified, WeightedTimestamp,
};

use crate::host::{NodeHost, ShardGenesis};
use crate::shard::{HostEvent, StepOutput, committed_state_restored};

impl<S, N, D> NodeHost<S, N, D>
where
    S: ShardStorage,
    N: Network,
    D: Dispatch,
{
    /// Initialize `genesis_block`'s shard's replica with the supplied
    /// genesis block, dispatching the resulting actions. Other hosted
    /// shards are untouched — cross-shard hosts call this once per shard
    /// with that shard's genesis block.
    pub fn initialize_shard_genesis(&mut self, genesis_block: &Block) {
        let shard_loop = self.shard_loop_mut(genesis_block.header().shard_id());
        let genesis_bytes = shard_loop.genesis_bytes(genesis_block);
        let actions =
            shard_loop
                .replica
                .initialize_genesis(shard_loop.now, genesis_block, genesis_bytes);
        shard_loop.drain_actions(actions);
        shard_loop.seed_genesis_standing_answers(genesis_block);
    }

    /// Resume a hosted shard's consensus from its recovered committed
    /// state — [`ShardLoop::resume_committed`]'s counterpart for
    /// the simulation runner, which routes the restore through the host
    /// step so the resulting sends and timer arms flow through its
    /// scheduler (production resumes the pinned loop pre-spawn and
    /// captures the timer ops directly). A committee seated onto a quiet
    /// chain — a halt recovery's fresh committee — hears nothing from
    /// gossip, so without the restore its replica never proposes or times
    /// out.
    ///
    /// [`ShardLoop::resume_committed`]: crate::shard::ShardLoop::resume_committed
    pub fn resume_shard_committed(
        &mut self,
        shard: ShardId,
        recovered: &RecoveredState,
    ) -> StepOutput {
        self.step(HostEvent::protocol(
            shard,
            committed_state_restored(recovered),
        ))
    }

    /// Run the deterministic part of one shard's genesis ceremony: install
    /// the network genesis into the shard's fresh store (see
    /// [`network_genesis_block`]), persist the block into the shard's
    /// replica, and drain the resulting setup output.
    ///
    /// Returns the block, its certified form, and the drained
    /// [`StepOutput`]. The caller commits the certified block, which lets
    /// the simulation schedule the commit after the network is wired.
    pub fn build_shard_genesis(&mut self, shard: ShardId, config: &GenesisConfig) -> ShardGenesis
    where
        S: GenesisCommit,
    {
        let topology_snapshot = self.process.topology_snapshot.load_full();
        let genesis = self.process.topology_schedule().windows().origin();
        let block = network_genesis_block(
            self.shard_io(shard).storage.as_ref(),
            shard,
            &topology_snapshot,
            config,
            genesis,
        );
        self.initialize_shard_genesis(&block);
        self.flush_all_batches();
        let setup_output = self.drain_pending_output();
        let certified = Arc::new(Verified::<CertifiedBlock>::genesis_certified(block.clone()));
        ShardGenesis {
            block,
            certified,
            setup_output,
        }
    }
}

/// The proposer every network genesis block names. A genesis block is
/// built, never proposed, and every store that installs it has to build
/// the same one.
const GENESIS_PROPOSER: ValidatorId = ValidatorId::new(0);

/// Install the network genesis for `shard` into its fresh `storage` and
/// build the genesis block over the resulting state root.
///
/// This is the ceremony every member of a network-genesis shard ran at
/// birth. `config` is the
/// network's genesis config and `genesis` its genesis instant, so every
/// store that runs this builds the same block, and block sync extends it
/// with the chain the members committed since.
///
/// `topology_snapshot` places the genesis accounts: a store holds only
/// the ones whose address falls in `shard`'s range, which is the same
/// under any topology `shard` is a leaf of.
///
/// # Panics
///
/// Panics if the store's JMT is already initialized (genesis must run on
/// a fresh store).
pub fn network_genesis_block<S: GenesisCommit>(
    storage: &S,
    shard: ShardId,
    topology_snapshot: &TopologySnapshot,
    config: &GenesisConfig,
    genesis: WeightedTimestamp,
) -> Block {
    // A per-shard store holds only its own shard's accounts:
    // prefix-rooting (each store roots its JMT at the shard's prefix)
    // requires it, since a foreign-prefix key would be mis-bucketed
    // beneath this shard's root.
    let mut config = config.clone();
    config
        .accounts
        .retain(|(address, _)| topology_snapshot.shard_for_prefix(*address) == shard);
    let merged = genesis_writes(&config.accounts, &config.pools, &config.packages);
    // The stdlib package is replicated to every shard's substate store
    // for read availability, but the prefix-rooted JMT must hold only
    // this shard's subtree, so the committed state root is the global
    // tree's node at the shard prefix.
    let jmt_writes =
        filter_genesis_writes_for_shard(&merged, owned_by(shard, topology_snapshot.shard_trie()));
    let state_root = storage.install_genesis(&merged, &jmt_writes);
    installed_network_genesis_block(shard, state_root, genesis)
}

/// The network genesis block of a store that already installed it.
///
/// `state_root` is the genesis root the store holds and `genesis` the
/// network's genesis instant, so this is the block
/// [`network_genesis_block`] built at the install. A store that crashed
/// before committing past its genesis resumes from it rather than
/// installing again.
#[must_use]
pub fn installed_network_genesis_block(
    shard: ShardId,
    state_root: StateRoot,
    genesis: WeightedTimestamp,
) -> Block {
    Block::genesis(
        shard,
        GENESIS_PROPOSER,
        state_root,
        ChainOrigin::root(genesis),
    )
}
