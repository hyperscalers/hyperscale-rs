//! Node configuration bundling trait.
//!
//! Bundles all type parameters for a node into a single trait, collapsing
//! `IoLoop<C, S, N, D, E, V>` (6 params) into `IoLoop<Cfg: NodeConfig>` (1 param).

use hyperscale_dispatch::Dispatch;
use hyperscale_network::Network;
use hyperscale_storage::{CommitStore, ConsensusStore, SubstateStore};

use crate::{ExecutionBackend, TransactionValidator};

/// Bundles all type parameters for a consensus node.
///
/// This trait collapses the 5 infrastructure type parameters that IoLoop,
/// runners, and related infrastructure need into a single associated-type
/// bundle. All TypeConfig-parameterized types use their ConcreteConfig
/// defaults (bare names), so no `C` associated type is needed.
///
/// # Usage
///
/// ```ignore
/// pub struct IoLoop<Cfg: NodeConfig> {
///     state: NodeStateMachine,       // bare = ConcreteConfig
///     storage: Arc<Cfg::S>,
///     executor: Cfg::E,
///     network: Cfg::N,
///     dispatch: Cfg::D,
///     // ...
/// }
/// ```
pub trait NodeConfig: Send + Sync + 'static {
    /// Storage backend (consensus + commit + substate).
    type S: CommitStore + SubstateStore + ConsensusStore + Send + Sync + 'static;

    /// Network backend.
    type N: Network;

    /// Dispatch backend (thread pool / sync).
    type D: Dispatch + 'static;

    /// Execution backend.
    type E: ExecutionBackend;

    /// Transaction validator.
    type V: TransactionValidator;
}
