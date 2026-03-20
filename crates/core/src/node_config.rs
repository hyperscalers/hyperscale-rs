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
/// This trait collapses the 6 infrastructure type parameters that IoLoop,
/// runners, and related infrastructure need into a single associated-type
/// bundle.
///
/// # Usage
///
/// ```ignore
/// pub struct IoLoop<Cfg: NodeConfig> {
///     state: NodeStateMachine<Cfg::Types>,
///     storage: Arc<Cfg::Storage>,
///     executor: Cfg::Executor,
///     network: Cfg::Net,
///     dispatch: Cfg::Pool,
///     // ...
/// }
/// ```
pub trait NodeConfig: Send + Sync + 'static {
    /// TypeConfig selecting transaction, receipt, and state update types.
    type Types: TypeConfig;

    /// Storage backend (consensus + commit + substate).
    type Storage: CommitStore<Self::Types>
        + SubstateStore
        + ConsensusStore<Self::Types>
        + Send
        + Sync
        + 'static;

    /// Network backend.
    type Net: Network;

    /// Dispatch backend (thread pool / sync).
    type Pool: Dispatch + 'static;

    /// Execution backend.
    type Executor: ExecutionBackend<Self::Types>;

    /// Transaction validator.
    type Validator: TransactionValidator<Self::Types>;
}
