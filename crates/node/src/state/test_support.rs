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

use hyperscale_beacon::coordinator::LocalChainAnchors;
use hyperscale_beacon::genesis::build_genesis_beacon_state;
use hyperscale_beacon::{BeaconFold, ChainRegistration};
use hyperscale_core::{Action, ProtocolEvent, StateMachine};
use hyperscale_crypto_bls::BlsVerifier;
use hyperscale_engine::AllCodeRuns;
use hyperscale_execution::{CrossingIndexSlot, ExecCertStore, FinalizationStore};
use hyperscale_mempool::{MempoolConfig, TxStore};
use hyperscale_provisions::{ProvisionConfig, ProvisionStore};
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::RecoveredState;
use hyperscale_types::test_utils::{StubVmStatics, TestCommittee};
use hyperscale_types::{
    BeaconChainConfig, BeaconGenesisConfig, BeaconState, CertifiedBeaconBlock, GenesisPool,
    GenesisValidator, LocalTimestamp, MIN_STAKE_FLOOR, NetworkDefinition, QuorumCertificate,
    Randomness, RecoveryBinding, Round, ShardId, Stake, StakePoolId, Verified, genesis_config_hash,
};

use super::NodeStateMachine;
use crate::event::BeaconInput;

/// Real `NodeStateMachine` plus the committee that produced its topology
/// and the fold its chain is registered with. The committee stays alive
/// so tests can mint signed messages targeting the same validator set
/// the node sees.
pub struct TestNode {
    pub(crate) node: NodeStateMachine,
    #[allow(dead_code)] // exposed for tests that mint signed messages
    pub(crate) committee: TestCommittee,
    /// The fold the node's chain is registered with, standing in for the
    /// host's beacon loop.
    pub(crate) fold: BeaconFold,
    pub(crate) chain: ChainRegistration,
}

impl TestNode {
    /// Default-config node: 4-validator committee, 1 shard, local index 0.
    /// Sufficient for tests that don't need a specific committee shape.
    pub(crate) fn new() -> Self {
        Self::builder().build()
    }

    pub(crate) fn builder() -> TestNodeBuilder {
        TestNodeBuilder::default()
    }

    /// Feed `event` to the node at `now`, then hand the fold what the
    /// node reported to the beacon, as the host's beacon loop would.
    pub(crate) fn handle(&mut self, now: LocalTimestamp, event: ProtocolEvent) -> Vec<Action> {
        self.fold.set_now(now);
        let actions = self.node.handle(now, event);
        self.report_to_fold();
        actions
    }

    /// Apply what the node reported to the beacon to the fold.
    pub(crate) fn report_to_fold(&mut self) {
        for input in self.node.take_beacon_inputs() {
            match input {
                BeaconInput::LocalCommit { header } => {
                    let _ = self.fold.on_local_block_committed(self.chain, &header);
                }
                BeaconInput::CertifiedHeader { header } => {
                    self.fold.on_certified_local_header(self.chain, &header);
                }
                BeaconInput::SourceHeader { header } => {
                    let _ = self.fold.on_source_header(&header);
                }
                BeaconInput::CommitProven { .. }
                | BeaconInput::ForkProof(_)
                | BeaconInput::VoteEquivocation { .. } => {}
            }
        }
    }

    /// Adopt `block` into the fold at `now` and hand the node the schedule
    /// it folded, as the host's beacon loop does after its commit.
    pub(crate) fn adopt(
        &mut self,
        now: LocalTimestamp,
        block: Arc<Verified<CertifiedBeaconBlock>>,
    ) {
        self.fold.set_now(now);
        let adopted = self.fold.adopt(block).expect("the block extends the tip");
        for action in adopted.actions {
            if let Action::TopologyChanged { epoch, schedule } = action {
                let _ = self.handle(now, ProtocolEvent::BeaconBlockPersisted { epoch, schedule });
            }
        }
    }
}

/// Turns the genesis beacon state into the history the coordinator
/// resumes over, oldest first.
type BeaconHistory = Box<dyn FnOnce(BeaconState) -> Vec<BeaconState>>;

#[derive(Default)]
pub struct TestNodeBuilder {
    local_idx: usize,
    local_shard: Option<ShardId>,
    recovered: RecoveredState,
    recoveries: Vec<(ShardId, Vec<RecoveryBinding>)>,
    beacon_history: Option<BeaconHistory>,
}

impl TestNodeBuilder {
    pub(crate) fn local_idx(mut self, idx: usize) -> Self {
        self.local_idx = idx;
        self
    }

    /// Boot from `recovered`, as a restarted node does, instead of a
    /// fresh start.
    pub(crate) fn recovered(mut self, recovered: RecoveredState) -> Self {
        self.recovered = recovered;
        self
    }

    /// Seat the node on `shard` instead of the root.
    pub(crate) const fn local_shard(mut self, shard: ShardId) -> Self {
        self.local_shard = Some(shard);
        self
    }

    /// Resume the beacon over the history `history` makes of the genesis
    /// state, instead of genesis alone.
    pub(crate) fn beacon_history(
        mut self,
        history: impl FnOnce(BeaconState) -> Vec<BeaconState> + 'static,
    ) -> Self {
        self.beacon_history = Some(Box::new(history));
        self
    }

    /// Genesis beacon state carrying `history` as `shard`'s recoveries.
    pub(crate) fn recoveries(mut self, shard: ShardId, history: Vec<RecoveryBinding>) -> Self {
        self.recoveries.push((shard, history));
        self
    }

    pub(crate) fn build(self) -> TestNode {
        let committee = TestCommittee::new(4, 7);
        let me = committee.validator_id(self.local_idx);
        // The beacon harness consolidates every validator onto the root shard.
        let local_shard = self.local_shard.unwrap_or(ShardId::ROOT);
        let provision_store = Arc::new(ProvisionStore::new());
        let mut fold = test_fold(&committee, self.recoveries, self.beacon_history);
        let chain = fold.register_chain(
            local_shard,
            LocalChainAnchors {
                committee: self.recovered.committee_anchor_wt(),
                block: self.recovered.block_anchor_wt(),
            },
            self.recovered.committed_height,
        );

        let mut node = NodeStateMachine::new(
            Arc::new(BlsVerifier),
            Arc::new(StubVmStatics),
            Arc::new(AllCodeRuns),
            local_shard,
            &ShardConsensusConfig::default(),
            &self.recovered,
            Arc::new(fold.schedule().clone()),
            fold.state().current_epoch,
            MempoolConfig::default(),
            ProvisionConfig::default(),
            provision_store,
            Arc::new(TxStore::new()),
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizationStore::new()),
            Arc::new(CrossingIndexSlot::default()),
        );
        let persisted_qc_round = self
            .recovered
            .latest_qc
            .as_deref()
            .map_or(Round::INITIAL, QuorumCertificate::round);
        let schedule = Arc::clone(node.schedule());
        let epoch = node.schedule_epoch();
        let _ = node.attach_signer(
            LocalTimestamp::ZERO,
            me,
            None,
            persisted_qc_round,
            schedule,
            epoch,
        );

        TestNode {
            node,
            committee,
            fold,
            chain,
        }
    }
}

/// Build a `BeaconFold` for tests over the `TestCommittee` — every
/// validator on a single pool, the first `BEACON_SIGNER_COUNT` on the
/// beacon committee, every validator placed on the ROOT shard.
fn test_fold(
    committee: &TestCommittee,
    recoveries: Vec<(ShardId, Vec<RecoveryBinding>)>,
    history: Option<BeaconHistory>,
) -> BeaconFold {
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
        total_stake: Stake::from_quanta(n as u128 * MIN_STAKE_FLOOR.quanta()),
    }];
    let chain_config = BeaconChainConfig::default();
    let beacon_count = n.min(chain_config.beacon_committee_size as usize);
    let initial_beacon_committee: Vec<_> = (0..beacon_count)
        .map(|i| committee.validator_id(i))
        .collect();
    // The genesis ROOT committee holds every validator.
    let initial_shard_committee: Vec<_> = (0..n).map(|i| committee.validator_id(i)).collect();
    let config = BeaconGenesisConfig {
        chain_config: BeaconChainConfig::default(),
        initial_validators,
        initial_pools,
        initial_beacon_committee,
        initial_shard_committee,
        initial_randomness: Randomness::new([0x42; 32]),
    };
    let mut state = build_genesis_beacon_state(&config);
    state.recoveries.extend(recoveries);
    let config_hash = genesis_config_hash(&config, &network, &[]);
    let block = Arc::new(Verified::<CertifiedBeaconBlock>::genesis(config_hash));
    let history = match history {
        Some(history) => history(state),
        None => vec![state],
    };
    BeaconFold::new(Arc::new(BlsVerifier), block, history, network, config_hash)
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
