//! Shared context for executing delegated actions.
//!
//! Coordinator crates (`hyperscale_shard`, `hyperscale_execution`, etc.) accept
//! [`ActionContext`] when handling [`crate::Action`] variants, so they can read
//! storage/topology/engine state without depending on the node crate. Outcomes
//! flow back via the `notify` and `commit_prepared` callbacks.

use std::sync::Arc;

use hyperscale_dispatch::Parallelism;
use hyperscale_engine::Executor;
use hyperscale_network::Network;
use hyperscale_storage::{
    BeaconChainReader, BeaconVoteRegisterStore, JmtSnapshot, PendingChain, RatifyRegisterStore,
    SafeVoteRegisterStore, ShardStorage, TickChain,
};
use hyperscale_types::{
    BeaconProposal, BlockHash, BlockHeight, CandidateBeaconBlock, Epoch, PreparedCommit, ShardId,
    Signer, TopologySnapshot, TxHash, ValidatorId, Verified, Verifier,
};

use crate::{GateEntry, ProtocolEvent, SignerGate};

/// Context for executing delegated actions.
///
/// Handlers anchor their own read view on the chain via
/// `ctx.pending_chain.view_at(block_hash)` — the field naming the relevant
/// block lives on the `Action` variant itself, so the dispatcher doesn't
/// need to know which actions read state at which anchor.
#[allow(missing_docs)] // bag of references; field names match the borrowed types
pub struct ActionContext<'a, S: ShardStorage, N: Network> {
    /// The batch execution seam the execute handlers drive.
    pub executor: &'a Executor,
    pub topology_snapshot: &'a TopologySnapshot,
    /// The attached signer the action is dispatched under, resolved from
    /// [`crate::Action::signer`] by the dispatch site. `None` for an
    /// action no signer signs; a signing handler finding `None` drops its
    /// action unsigned.
    pub signing: Option<Signing<'a>>,
    /// Dispatching vnode's shard. Equal to the vnode's `local_shard`
    /// for shard-rooted handlers; beacon handlers ignore it.
    pub shard: ShardId,
    /// Chain-state lookup. Handlers that read state call
    /// `pending_chain.view_at(block_hash)` to build an anchored view.
    pub pending_chain: &'a Arc<PendingChain<S>>,
    /// Execution-baseline lookup. The tick execute handler reads through
    /// `tick_chain.view_at(prev)` and appends the tick's output before
    /// notifying completion; nothing else touches it from a handler.
    pub tick_chain: &'a Arc<TickChain<S>>,
    /// Durable safe-vote registers on the shard's backing store. Vote
    /// and timeout sign handlers persist through it before creating the
    /// signature, so no signature can leave the process ahead of the
    /// registers that forbid re-signing its round after a crash.
    pub vote_registers: &'a dyn SafeVoteRegisterStore,
    /// The committed beacon chain, for handlers resolving a window the
    /// live schedule no longer carries. The schedule is a cache over
    /// this store, which holds one state per epoch contiguously from
    /// genesis, so a miss there is a read here rather than a verdict.
    pub beacon_chain: &'a dyn BeaconChainReader,
    /// Network handle for broadcast/notify/request actions.
    pub network: &'a Arc<N>,
    /// Scheme verifier for signature and certificate checks.
    pub verifier: &'a dyn Verifier,
    /// Send a [`ProtocolEvent`] back to the state machine. The single
    /// sink for delegated-action outcomes — the dispatch wrapper at
    /// the I/O loop boundary stamps the emitting vnode's shard and
    /// re-enters the next `step()`. Owned so handlers can clone it
    /// into network-callback closures that outlive the action call.
    pub notify: Arc<dyn Fn(ProtocolEvent) + Send + Sync>,
    /// Hand a freshly prepared block to the `io_loop` for insertion into
    /// `PendingChain` + `prepared_commits`. Only `BuildProposal` and
    /// `VerifyStateRoot` produce these.
    pub commit_prepared: &'a (dyn Fn(PreparedBlock) + Send + Sync),
    /// Parallelism strategy for in-handler batch fan-out. Sourced from
    /// the dispatch backend at spawn time so handlers running on
    /// `PooledDispatch` use rayon `par_iter` (work-stealing across the
    /// current pool's workers) and handlers running on `SyncDispatch`
    /// iterate sequentially for deterministic simulation.
    pub par: Parallelism,
}

impl<S: ShardStorage, N: Network> ActionContext<'_, S, N> {
    /// Invoke `notify`; common spelling at action-handler call sites.
    pub fn notify_protocol(&self, event: ProtocolEvent) {
        (self.notify)(event);
    }
}

/// The attached signer a delegated action signs under.
pub struct Signing<'a> {
    /// The signer's validator identity: the signature's attribution and
    /// the key its durable registers persist under.
    pub me: ValidatorId,
    /// The signer's key, shared from the loop that attached it so a
    /// handler on a dispatch pool signs without re-entering that loop.
    pub key: &'a Arc<dyn Signer>,
    /// The release gate of the attachment that emitted the action.
    pub gate: &'a SignerGate,
}

impl Signing<'_> {
    /// Enter the gate for one persist, sign and notify, or `None` once
    /// the attachment that emitted `action` has ended, in which case the
    /// handler drops it unsigned.
    pub fn enter(&self, action: &'static str) -> Option<GateEntry<'_>> {
        let entry = self.gate.enter();
        if entry.is_none() {
            tracing::trace!(action, signer = ?self.me, "signer detached; dropping its signature");
        }
        entry
    }
}

/// Context for executing beacon-owned delegated actions.
///
/// What a beacon participant's handlers need: signing, verification,
/// broadcast, the durable ratify and beacon vote registers, the outcome
/// sink and the release gate. Storage-free — beacon consensus reads no
/// shard chain state.
#[allow(missing_docs)] // bag of references; field names match ActionContext's
pub struct BeaconActionContext<'a, N: Network> {
    pub topology_snapshot: &'a TopologySnapshot,
    /// Dispatching vnode's validator identity, used for signing, vote
    /// attribution, and self-filtering recipient lists.
    pub me: ValidatorId,
    /// Durable ratification registers on the process's beacon store —
    /// the ratify-vote sign handler persists through them before
    /// creating the signature.
    pub ratify_registers: &'a dyn RatifyRegisterStore,
    /// Durable beacon consensus registers on the process's beacon store
    /// — a signature that would contradict one the validator already
    /// created, before a restart or under an earlier participant on the
    /// host, is never created.
    pub beacon_vote_registers: &'a dyn BeaconVoteRegisterStore,
    pub network: &'a Arc<N>,
    pub signer: &'a Arc<dyn Signer>,
    pub verifier: &'a dyn Verifier,
    /// Send a [`ProtocolEvent`] back to the state machine — the single
    /// sink for handler outcomes.
    pub notify: Arc<dyn Fn(ProtocolEvent) + Send + Sync>,
    /// Hand the locally signed `BeaconProposal` to the process-level
    /// cache that serves inbound `GetBeaconProposalRequest`s.
    pub cache_beacon_proposal:
        &'a (dyn Fn(ValidatorId, Epoch, Arc<Verified<BeaconProposal>>) + Send + Sync),
    /// Hand a candidate this vnode assembled or verified to the
    /// process-level cache that serves inbound
    /// `GetBeaconCandidateRequest`s.
    pub cache_beacon_candidate: &'a (dyn Fn(Arc<Verified<CandidateBeaconBlock>>) + Send + Sync),
    /// The release gate of the identity that emitted the action. Every
    /// signing handler enters it around its persist, sign and notify.
    pub gate: &'a SignerGate,
}

impl<N: Network> BeaconActionContext<'_, N> {
    /// Invoke `notify`; common spelling at action-handler call sites.
    pub fn notify_protocol(&self, event: ProtocolEvent) {
        (self.notify)(event);
    }
}

/// A successful prepare result, ready to insert into `PendingChain` and
/// `prepared_commits`.
#[allow(missing_docs)] // flat bundle threaded straight to the chain insert site
pub struct PreparedBlock {
    pub block_hash: BlockHash,
    pub parent_block_hash: BlockHash,
    pub block_height: BlockHeight,
    pub prepared: PreparedCommit,
    pub jmt_snapshot: Arc<JmtSnapshot>,
    pub settled_txs: Vec<TxHash>,
}
