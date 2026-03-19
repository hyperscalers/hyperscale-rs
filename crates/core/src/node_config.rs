//! Node configuration bundling trait.
//!
//! Bundles all type parameters for a node into a single trait, collapsing
//! `IoLoop<C, S, N, D, E, V>` (6 params) into `IoLoop<Cfg: NodeConfig>` (1 param).

use hyperscale_dispatch::Dispatch;
use hyperscale_network::Network;
use hyperscale_storage::{CommitStore, ConsensusStore, SubstateStore};
use hyperscale_types::TypeConfig;

use crate::{ExecutionBackend, TransactionValidator};

/// Bundles all type parameters for a consensus node.
///
/// This trait collapses the 6 type parameters that IoLoop, runners, and
/// related infrastructure need into a single associated-type bundle.
///
/// # Usage
///
/// ```ignore
/// pub struct IoLoop<Cfg: NodeConfig> {
///     state: NodeStateMachine<Cfg::C>,
///     storage: Arc<Cfg::S>,
///     executor: Cfg::E,
///     network: Cfg::N,
///     dispatch: Cfg::D,
///     // ...
/// }
/// ```
pub trait NodeConfig: Send + Sync + 'static {
    /// The TypeConfig binding (Transaction, Receipt, StateUpdate types).
    type C: TypeConfig;

    /// Storage backend (consensus + commit + substate).
    type S: CommitStore<Self::C> + SubstateStore + ConsensusStore<Self::C>;

    /// Network backend.
    type N: Network;

    /// Dispatch backend (thread pool / sync).
    type D: Dispatch;

    /// Execution backend.
    type E: ExecutionBackend<Self::C>;

    /// Transaction validator.
    type V: TransactionValidator<Self::C>;
}
