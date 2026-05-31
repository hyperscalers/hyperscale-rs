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

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_beacon::coordinator::BeaconCoordinator;
use hyperscale_beacon::genesis::build_genesis_beacon_state;
use hyperscale_execution::{ExecCertStore, FinalizedWaveStore};
use hyperscale_mempool::{MempoolConfig, TxStore};
use hyperscale_provisions::{ProvisionConfig, ProvisionStore};
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::RecoveredState;
use hyperscale_test_helpers::TestCommittee;
use hyperscale_types::{
    BeaconChainConfig, BeaconGenesisConfig, CertifiedBeaconBlock, GenesisPool, GenesisValidator,
    MIN_STAKE_FLOOR, NetworkDefinition, Randomness, ShardGroupId, Stake, StakePoolId, ValidatorId,
    Verified, genesis_config_hash,
};

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
        let topology = Arc::new(committee.topology_snapshot(self.num_shards));
        let me = committee.validator_id(self.local_idx);
        let local_shard = ShardGroupId::new(me.inner() % self.num_shards);
        let provision_store = Arc::new(ProvisionStore::new());
        let beacon_coordinator = test_beacon_coordinator(&committee, me, self.num_shards);

        let node = NodeStateMachine::new(
            me,
            local_shard,
            topology,
            &ShardConsensusConfig::default(),
            RecoveredState::default(),
            beacon_coordinator,
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

/// Build a `BeaconCoordinator` for tests over the `TestCommittee` —
/// every validator on a single pool, the first `BEACON_SIGNER_COUNT`
/// on the beacon committee, every validator placed on shard 0.
fn test_beacon_coordinator(
    committee: &TestCommittee,
    me: ValidatorId,
    _num_shards: u64,
) -> BeaconCoordinator {
    let network = NetworkDefinition::simulator();
    let pool_id = StakePoolId::new(0);
    let n = committee.size();
    let initial_validators: Vec<GenesisValidator> = (0..n)
        .map(|i| GenesisValidator {
            id: committee.validator_id(i),
            pool: pool_id,
            pubkey: *committee.public_key(i),
        })
        .collect();
    let initial_pools = vec![GenesisPool {
        id: pool_id,
        total_stake: Stake::from_attos(n as u128 * MIN_STAKE_FLOOR.attos()),
    }];
    let chain_config = BeaconChainConfig::default();
    let beacon_count = n.min(chain_config.beacon_committee_size as usize);
    let initial_beacon_committee: Vec<_> = (0..beacon_count)
        .map(|i| committee.validator_id(i))
        .collect();
    // Beacon-state shard committees populate shard 0 with every
    // validator. `_num_shards` is reserved for callers that want
    // more shards declared in the topology snapshot for tx routing;
    // the beacon-state placement stays consolidated for test
    // determinism.
    let mut initial_shard_committees: BTreeMap<ShardGroupId, Vec<_>> = BTreeMap::new();
    initial_shard_committees.insert(
        ShardGroupId::new(0),
        (0..n).map(|i| committee.validator_id(i)).collect(),
    );
    let config = BeaconGenesisConfig {
        chain_config: BeaconChainConfig::default(),
        initial_validators,
        initial_pools,
        initial_beacon_committee,
        initial_shard_committees,
        initial_randomness: Randomness::new([0x42; 32]),
    };
    let state = build_genesis_beacon_state(&config);
    let config_hash = genesis_config_hash(&config, &network);
    let block = Arc::new(Verified::<CertifiedBeaconBlock>::genesis(config_hash));
    BeaconCoordinator::new(block, state, me, ShardGroupId::new(0), network, config_hash)
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
