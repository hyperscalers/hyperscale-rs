//! Test harness for [`super::NodeStateMachine`].
//!
//! Builds a real `NodeStateMachine` wired to real coordinators with
//! in-memory stores. Tests drive `handle()` and assert on:
//!
//! - the returned `Vec<Action>` (the state machine's only externally
//!   observable output), and
//! - mutations on the real coordinators (queryable via the existing
//!   `&ShardCoordinator` / `&MempoolCoordinator` / etc. accessors).
//!
//! No mocks, no dispatch-table tracing — assertions ride on the same
//! contract `NodeHost` consumes in production.

use std::sync::Arc;

use hyperscale_execution::{ExecCertStore, FinalizedWaveStore};
use hyperscale_mempool::{MempoolConfig, TxStore};
use hyperscale_provisions::{ProvisionConfig, ProvisionStore};
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::RecoveredState;
use hyperscale_test_helpers::TestCommittee;
use hyperscale_types::{TopologySnapshot, ValidatorSet};

use super::NodeStateMachine;

/// Real `NodeStateMachine` plus the committee that produced its topology.
/// The committee stays alive so tests can mint signed messages targeting
/// the same validator set the node sees.
pub struct TestNode {
    pub node: NodeStateMachine,
    #[allow(dead_code)] // exposed for tests that mint signed messages
    pub committee: TestCommittee,
}

impl TestNode {
    /// Default-config node: 4-validator committee, 1 shard, local index 0.
    /// Sufficient for tests that don't need a specific committee shape.
    pub fn new() -> Self {
        Self::builder().build()
    }

    pub fn builder() -> TestNodeBuilder {
        TestNodeBuilder::default()
    }
}

pub struct TestNodeBuilder {
    local_idx: usize,
    num_shards: u64,
}

impl Default for TestNodeBuilder {
    fn default() -> Self {
        Self {
            local_idx: 0,
            num_shards: 1,
        }
    }
}

impl TestNodeBuilder {
    pub fn num_shards(mut self, n: u64) -> Self {
        self.num_shards = n;
        self
    }

    pub fn local_idx(mut self, idx: usize) -> Self {
        self.local_idx = idx;
        self
    }

    pub fn build(self) -> TestNode {
        let committee = TestCommittee::new(4, 7);
        let snapshot = committee.topology_snapshot(self.local_idx, self.num_shards);
        let validator_set: ValidatorSet = (**snapshot.global_validator_set()).clone();
        let local_validator_id = committee.validator_id(self.local_idx);
        let topology = Arc::new(TopologySnapshot::new(
            snapshot.network().clone(),
            local_validator_id,
            self.num_shards,
            validator_set,
        ));
        let provision_store = Arc::new(ProvisionStore::new());

        let node = NodeStateMachine::new(
            topology,
            &ShardConsensusConfig::default(),
            RecoveredState::default(),
            MempoolConfig::default(),
            ProvisionConfig::default(),
            provision_store,
            Arc::new(TxStore::new()),
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizedWaveStore::new()),
        );

        TestNode { node, committee }
    }
}

// ─── Action-stream assertions ─────────────────────────────────────────
//
// Match on `Action` variants via pattern matching. `Action` derives
// `Debug` so failure messages dump the offending vec verbatim.

/// Assert that the action stream contains at least one variant matching
/// the supplied pattern. Pattern bindings are not exposed — use
/// [`extract_one`] when the test needs to inspect fields.
#[macro_export]
macro_rules! assert_emits {
    ($actions:expr, $pat:pat $(if $guard:expr)?) => {{
        let actions = &$actions;
        let found = actions.iter().any(|a| matches!(a, $pat $(if $guard)?));
        assert!(
            found,
            "expected action matching {} in {:#?}",
            stringify!($pat $(if $guard)?),
            actions,
        );
    }};
}

/// Assert that no action in the stream matches the supplied pattern.
#[macro_export]
macro_rules! assert_no_emit {
    ($actions:expr, $pat:pat $(if $guard:expr)?) => {{
        let actions = &$actions;
        let found = actions.iter().any(|a| matches!(a, $pat $(if $guard)?));
        assert!(
            !found,
            "expected no action matching {} but found one in {:#?}",
            stringify!($pat $(if $guard)?),
            actions,
        );
    }};
}

/// Extract the single action matching the pattern. Panics on zero or
/// multiple matches. Returns a borrowed reference; bind in the caller via
/// `if let` for field access.
#[macro_export]
macro_rules! extract_one {
    ($actions:expr, $pat:pat $(if $guard:expr)?) => {{
        let actions = &$actions;
        let matches: Vec<&_> = actions
            .iter()
            .filter(|a| matches!(a, $pat $(if $guard)?))
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "expected exactly one action matching {}; found {} in {:#?}",
            stringify!($pat $(if $guard)?),
            matches.len(),
            actions,
        );
        matches.into_iter().next().unwrap()
    }};
}
