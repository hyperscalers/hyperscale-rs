//! Action handler for immediately-dispatched computation.
//!
//! [`handle_delegated_action`] routes each delegated [`Action`] variant to the
//! coordinator crate that owns it. Each crate's `handle_action` runs the pure
//! computation and pushes outcomes via `ctx.notify` and `ctx.commit_prepared`.
//!
//! Batched work (execution votes, execution certs) and block commits are
//! handled inline by the I/O loop's flush closures.

use hyperscale_core::{Action, ActionContext};
use hyperscale_engine::Engine;
use hyperscale_storage::Storage;
use hyperscale_types::BlockHash;

/// Which dispatch pool an action should run on in production.
pub enum DispatchPool {
    /// Liveness-critical consensus crypto (QC verification, block votes,
    /// state root verification, proposal building).
    ConsensusCrypto,
    /// General crypto verification (cert aggregation, provision proofs).
    Crypto,
    /// Transaction execution (single-shard, merkle).
    Execution,
}

/// Map a delegated action to its execution pool.
///
/// Returns `None` for actions that are not delegated (network, timers, etc.)
/// and should be handled by the runner directly.
pub const fn dispatch_pool_for(action: &Action) -> Option<DispatchPool> {
    match action {
        // Consensus-critical crypto + state root computation
        Action::VerifyAndBuildQuorumCertificate { .. }
        | Action::VerifyQcSignature { .. }
        | Action::VerifyRemoteHeaderQc { .. }
        | Action::VerifyTransactionRoot { .. }
        | Action::VerifyProvisionRoot { .. }
        | Action::VerifyCertificateRoot { .. }
        | Action::VerifyLocalReceiptRoot { .. }
        | Action::VerifyProvisionTxRoots { .. }
        | Action::VerifyStateRoot { .. }
        | Action::BuildProposal { .. } => Some(DispatchPool::ConsensusCrypto),

        // General crypto (cert aggregation, provision proofs)
        Action::AggregateExecutionCertificate { .. }
        | Action::VerifyAndAggregateExecutionVotes { .. }
        | Action::VerifyExecutionCertificateSignature { .. }
        | Action::VerifyProvisions { .. }
        | Action::FetchAndBroadcastProvisions { .. } => Some(DispatchPool::Crypto),

        // Execution
        Action::ExecuteTransactions { .. } | Action::ExecuteCrossShardTransactions { .. } => {
            Some(DispatchPool::Execution)
        }
        _ => None,
    }
}

/// Anchor block hash for `PendingChain::view_at` for actions that read
/// state via the substate overlay. Returns `None` for actions that
/// don't read state, in which case the dispatcher falls back to
/// `view_at_committed_tip()`.
///
/// The anchor names the block whose state the action reads against:
/// - `BuildProposal`/`VerifyStateRoot` use the parent block (state we
///   build on / verify against).
/// - `Execute*` and `FetchAndBroadcastProvisions` use the kicked-off
///   block (the committed block whose state these actions act on).
pub const fn parent_hash_for(action: &Action) -> Option<BlockHash> {
    match action {
        Action::VerifyStateRoot {
            parent_block_hash, ..
        } => Some(*parent_block_hash),
        Action::BuildProposal { parent_hash, .. } => Some(*parent_hash),
        Action::ExecuteTransactions { block_hash, .. }
        | Action::ExecuteCrossShardTransactions { block_hash, .. }
        | Action::FetchAndBroadcastProvisions { block_hash, .. } => Some(*block_hash),
        _ => None,
    }
}

/// Route a delegated action to the coordinator crate that owns it.
///
/// Outcomes flow through `ctx.notify` (state-machine inputs) and
/// `ctx.commit_prepared` (prepared blocks for the `io_loop`'s chain).
/// No-ops for non-delegated actions; callers gate via [`dispatch_pool_for`].
pub fn handle_delegated_action<S: Storage, E: Engine>(
    action: Action,
    ctx: &ActionContext<'_, S, E>,
) {
    match &action {
        Action::VerifyAndBuildQuorumCertificate { .. }
        | Action::VerifyQcSignature { .. }
        | Action::VerifyRemoteHeaderQc { .. }
        | Action::VerifyTransactionRoot { .. }
        | Action::VerifyProvisionTxRoots { .. }
        | Action::VerifyProvisionRoot { .. }
        | Action::VerifyCertificateRoot { .. }
        | Action::VerifyLocalReceiptRoot { .. }
        | Action::VerifyStateRoot { .. }
        | Action::BuildProposal { .. } => {
            hyperscale_bft::action_handlers::handle_action(action, ctx);
        }

        Action::AggregateExecutionCertificate { .. }
        | Action::VerifyAndAggregateExecutionVotes { .. }
        | Action::VerifyExecutionCertificateSignature { .. }
        | Action::ExecuteTransactions { .. }
        | Action::ExecuteCrossShardTransactions { .. } => {
            hyperscale_execution::action_handlers::handle_action(action, ctx);
        }

        Action::VerifyProvisions { .. } | Action::FetchAndBroadcastProvisions { .. } => {
            hyperscale_provisions::action_handlers::handle_action(action, ctx);
        }

        _ => {}
    }
}
