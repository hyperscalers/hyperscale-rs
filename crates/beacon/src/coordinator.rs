//! Top-level beacon FSM.
//!
//! [`BeaconCoordinator`] is the per-vnode state machine; it owns the
//! committed [`BeaconState`], the optional current-epoch
//! [`SpcInstance`], and the wall-clock anchor that drives
//! epoch-cadence timers.
//!
//! Constructor is pure synchronous data assembly — the runner is
//! responsible for loading `(latest_block, latest_state)` from
//! [`BeaconChainReader::latest_committed`](hyperscale_storage::BeaconChainReader::latest_committed)
//! and asserting the `header.state_root` ↔ `state_root(&state)`
//! binding before invoking [`BeaconCoordinator::new`]. Same code path
//! handles fresh-genesis and warm-restart: the runner builds and
//! commits the genesis pair on an empty store, then loads it back via
//! the same `latest_committed()` call.

use std::sync::Arc;

use hyperscale_core::{Action, TimerId};
use hyperscale_types::{
    BeaconBlock, BeaconState, Bls12381G1PublicKey, Epoch, LocalTimestamp, NetworkDefinition,
    RECOVERY_TIMEOUT, SpcMessage, ValidatorId, VpcMsgPayload, state_root,
};
use tracing::{trace, warn};

use crate::block_sync::BeaconBlockSyncManager;
use crate::constants::SPC_VIEW_TIMEOUT;
use crate::equivocations::EquivocationObservations;
use crate::pending_blocks::PendingBeaconBlocks;
use crate::recovery_tracker::RecoveryTracker;
use crate::spc::{SpcEffect, SpcEvent, SpcInstance};
use crate::verification::BeaconVerificationPipeline;
use crate::witness_fetcher::ShardWitnessFetchTracker;

/// Per-vnode beacon-chain coordinator.
///
/// Synchronous event-driven FSM. Mirrors `ShardCoordinator`'s public
/// shape: handlers take `&mut self` plus a per-call
/// `&TopologySnapshot` and return `Vec<Action>`. Multiple vnodes
/// share an `Arc<dyn BeaconStorage>` at the runner layer but each
/// holds an independent coordinator, so determinism is per-vnode.
pub struct BeaconCoordinator {
    state: BeaconState,

    /// Latest committed beacon block. Carried so SPC instance
    /// bootstrap can read `prev_block_hash` without a storage
    /// roundtrip.
    latest_block: Arc<BeaconBlock>,

    /// `None` between bootstrap and the first epoch-boundary
    /// trigger, and again briefly between an epoch's commit and the
    /// next instance's bootstrap.
    spc: Option<SpcInstance>,

    /// Gossip-arrival cache for beacon blocks awaiting verification.
    /// Pruned past `state.current_epoch` after every committed epoch.
    pending_blocks: PendingBeaconBlocks,

    /// In-flight and verified slot tracking for async crypto checks
    /// (block aggregate sigs, cert sigs, VRF reveals, witness
    /// Merkle paths).
    verification: BeaconVerificationPipeline,

    /// Per-shard header records, validated-witness pool, and
    /// in-flight fetches; drives proposal-readiness and the
    /// witness drain.
    witness_fetcher: ShardWitnessFetchTracker,

    /// Buckets observed recovery requests and aggregates them into
    /// a `RecoveryCertificate` once quorum lands.
    recovery_tracker: RecoveryTracker,

    /// Equivocation evidence the local vnode has observed but not
    /// yet proposed for inclusion.
    equivocations: EquivocationObservations,

    /// Gap-fill sync state: target epoch, buffered blocks awaiting
    /// their turn through `apply_epoch`, in-flight fetches.
    sync: BeaconBlockSyncManager,

    me: ValidatorId,

    /// Mixed into every signing helper's domain bytes; carried so
    /// per-epoch SPC instances and outbound canonical-bytes
    /// encoders don't re-thread it from the runner.
    #[allow(dead_code)] // read by SPC bootstrap once handlers wire it in
    network: NetworkDefinition,

    /// Local wall-clock time. Drives the epoch-cadence timers; never
    /// fed into deterministic consensus computations — use
    /// `state.current_epoch` or weighted timestamps for that.
    now: LocalTimestamp,
}

impl BeaconCoordinator {
    /// Construct a coordinator from a pre-loaded `(latest_block,
    /// latest_state)` pair.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if
    /// `latest_block.header().state_root() != state_root(&latest_state)`.
    /// The runner is contractually obliged to assert this before
    /// constructing; the `debug_assert!` here is a backstop, not the
    /// primary check.
    #[must_use]
    pub fn new(
        latest_block: Arc<BeaconBlock>,
        latest_state: BeaconState,
        me: ValidatorId,
        network: NetworkDefinition,
    ) -> Self {
        debug_assert_eq!(
            latest_block.header().state_root(),
            state_root(&latest_state),
            "BeaconCoordinator::new: header.state_root != state_root(&state); \
             runner must verify the binding before construction",
        );
        Self {
            state: latest_state,
            latest_block,
            spc: None,
            pending_blocks: PendingBeaconBlocks::new(),
            verification: BeaconVerificationPipeline::new(),
            witness_fetcher: ShardWitnessFetchTracker::new(),
            recovery_tracker: RecoveryTracker::new(),
            equivocations: EquivocationObservations::new(),
            sync: BeaconBlockSyncManager::new(),
            me,
            network,
            now: LocalTimestamp::ZERO,
        }
    }

    /// Whether the local validator sits on the current beacon
    /// committee. The runner gates committee-only event forwarding
    /// (PC votes, SPC messages) on this.
    #[must_use]
    pub fn is_on_committee(&self) -> bool {
        self.state.committee.contains(&self.me)
    }

    /// Runner calls this once before each batch of handler invocations
    /// so every handler in the batch reads a consistent `now`.
    pub const fn set_now(&mut self, now: LocalTimestamp) {
        self.now = now;
    }

    /// Whether the committee-start timer is due — i.e. wall-clock
    /// time has reached the upcoming epoch's wall-clock boundary.
    /// The runner combines this with its own "block not yet
    /// committed" + "local on next committee" checks before actually
    /// bootstrapping an SPC instance.
    #[must_use]
    pub const fn committee_start_due(&self, epoch_boundary: LocalTimestamp) -> bool {
        self.now.as_millis() >= epoch_boundary.as_millis()
    }

    /// Whether the recovery-trigger timer is due — i.e. wall-clock
    /// time has reached `expected_block_time + RECOVERY_TIMEOUT`.
    /// The runner combines this with its own "expected block hasn't
    /// arrived" + "local on active pool" checks before actually
    /// broadcasting a `RecoveryRequest`.
    #[must_use]
    pub fn recovery_trigger_due(&self, expected_block_time: LocalTimestamp) -> bool {
        self.now.as_millis() >= expected_block_time.plus(RECOVERY_TIMEOUT).as_millis()
    }

    /// A peer's PC vote arrived. SBOR-decode and route into the
    /// current epoch's `SpcInstance`; drop with a trace if no
    /// instance is bootstrapped.
    pub fn on_pc_vote_received(&mut self, from: ValidatorId, payload: &[u8]) -> Vec<Action> {
        let Some(msg) = VpcMsgPayload::decode(payload) else {
            warn!(?from, "PC vote payload SBOR-decode failed");
            return Vec::new();
        };
        self.dispatch_spc_event(from, SpcEvent::VpcMsg(Box::new(msg)))
    }

    /// A peer's SPC message arrived (new-view / new-commit /
    /// empty-view / inner-PC vote). SBOR-decode and route in.
    pub fn on_spc_message_received(&mut self, from: ValidatorId, payload: &[u8]) -> Vec<Action> {
        let Some(msg) = SpcMessage::decode(payload) else {
            warn!(?from, "SPC message payload SBOR-decode failed");
            return Vec::new();
        };
        self.dispatch_spc_event(from, SpcEvent::from_message(msg, from))
    }

    /// `TimerId::BeaconSpcView` fired. Route a synthesized
    /// `TimerExpired` into SPC against its current view — the FSM's
    /// stale-view guard no-ops if the view has already advanced.
    pub fn on_beacon_spc_view_timer(&mut self) -> Vec<Action> {
        let Some(spc) = self.spc.as_ref() else {
            trace!("BeaconSpcViewTimer fired but no SPC instance bootstrapped");
            return Vec::new();
        };
        let view = spc.current_view();
        self.dispatch_spc_event(self.me, SpcEvent::TimerExpired { view })
    }

    /// `TimerId::BeaconCommitteeStart` fired — the upcoming epoch's
    /// wall-clock boundary has been reached. If the local validator
    /// is on the next committee and no SPC instance is already
    /// running, bootstrap one. The proposal-Input that kicks the FSM
    /// into outbound traffic arrives via `try_propose` once witness
    /// readiness is satisfied — this handler is pure state mutation.
    pub fn on_beacon_committee_start_timer(&mut self) -> Vec<Action> {
        if self.spc.is_some() {
            trace!("BeaconCommitteeStart fired with SPC already running");
            return Vec::new();
        }
        if !self.is_on_committee() {
            trace!("BeaconCommitteeStart fired but local validator not on committee");
            return Vec::new();
        }
        self.bootstrap_spc_for_next_epoch();
        Vec::new()
    }

    /// Stand up a fresh [`SpcInstance`] for the upcoming epoch.
    /// Pairs each committee member with their pubkey by looking up
    /// `state.validators`. Skips validators absent from the validator
    /// table — a structurally impossible state for an on-chain
    /// committee, so the skip is defensive rather than expected.
    fn bootstrap_spc_for_next_epoch(&mut self) {
        let committee = self.committee_with_pubkeys();
        let next_epoch = self.state.current_epoch.next();
        self.spc = Some(SpcInstance::new(
            self.network.clone(),
            next_epoch,
            committee,
            self.me,
            SPC_VIEW_TIMEOUT,
        ));
    }

    /// Pair every member of the beacon committee with their pubkey
    /// from `state.validators`. Returns the pairs in committee order.
    fn committee_with_pubkeys(&self) -> Vec<(ValidatorId, Bls12381G1PublicKey)> {
        self.state
            .committee
            .iter()
            .filter_map(|id| {
                self.state
                    .validators
                    .get(id)
                    .map(|record| (*id, record.pubkey))
            })
            .collect()
    }

    /// Drive `event` through the current `SpcInstance` and lift the
    /// resulting effects. The `from` argument is logged on the
    /// not-bootstrapped path so dropped messages are attributable.
    fn dispatch_spc_event(&mut self, from: ValidatorId, event: SpcEvent) -> Vec<Action> {
        if self.spc.is_none() {
            trace!(?from, "SPC event received but no SPC instance bootstrapped");
            return Vec::new();
        }
        let recipients = self.spc_recipients();
        let spc = self.spc.as_mut().expect("checked is_none above");
        let epoch = spc.epoch();
        let effects = spc.handle(event);
        self.lift_spc_effects(epoch, &recipients, effects)
    }

    /// Beacon-committee members excluding the local validator —
    /// recipient list for outbound SPC traffic.
    fn spc_recipients(&self) -> Vec<ValidatorId> {
        self.state
            .committee
            .iter()
            .filter(|v| **v != self.me)
            .copied()
            .collect()
    }

    /// Translate the sub-machine's local effect enum into beacon
    /// actions plus internal state mutations (equivocation pool,
    /// future commit pipeline).
    fn lift_spc_effects(
        &mut self,
        epoch: Epoch,
        recipients: &[ValidatorId],
        effects: Vec<SpcEffect>,
    ) -> Vec<Action> {
        let mut actions = Vec::with_capacity(effects.len());
        for effect in effects {
            match effect {
                SpcEffect::SignAndBroadcastPcVote1 { view, v_in } => {
                    actions.push(Action::SignAndBroadcastPcVote1 {
                        epoch,
                        view,
                        v_in,
                        recipients: recipients.to_vec(),
                    });
                }
                SpcEffect::SignAndBroadcastPcVote2 { view, qc1 } => {
                    actions.push(Action::SignAndBroadcastPcVote2 {
                        epoch,
                        view,
                        qc1,
                        recipients: recipients.to_vec(),
                    });
                }
                SpcEffect::SignAndBroadcastPcVote3 { view, qc2 } => {
                    actions.push(Action::SignAndBroadcastPcVote3 {
                        epoch,
                        view,
                        qc2,
                        recipients: recipients.to_vec(),
                    });
                }
                SpcEffect::SignAndBroadcastEmptyView { view, reported } => {
                    actions.push(Action::SignAndBroadcastEmptyView {
                        epoch,
                        view,
                        reported,
                        recipients: recipients.to_vec(),
                    });
                }
                SpcEffect::BroadcastNewView { view, cert } => {
                    actions.push(Action::BroadcastSpcNewView {
                        epoch,
                        view,
                        cert,
                        recipients: recipients.to_vec(),
                    });
                }
                SpcEffect::BroadcastNewCommit { view, value, proof } => {
                    actions.push(Action::BroadcastSpcNewCommit {
                        epoch,
                        view,
                        value,
                        proof,
                        recipients: recipients.to_vec(),
                    });
                }
                SpcEffect::SetTimer { view: _, duration } => {
                    actions.push(Action::SetTimer {
                        id: TimerId::BeaconSpcView,
                        duration,
                    });
                }
                SpcEffect::Equivocation { view: _, evidence } => {
                    self.equivocations.record_pc_equivocation(*evidence);
                }
                SpcEffect::EmptyLowEvidence(evidence) => {
                    warn!(
                        view = evidence.view.inner(),
                        "SPC empty-low evidence — downstream handling deferred",
                    );
                }
                SpcEffect::OutputHigh(_value) => {
                    warn!(
                        epoch = epoch.inner(),
                        "SPC OutputHigh — beacon commit pipeline pending",
                    );
                }
            }
        }
        actions
    }
}

// Flat accessors; their names and return types are the documentation.
#[allow(missing_docs)]
impl BeaconCoordinator {
    #[must_use]
    pub const fn current_state(&self) -> &BeaconState {
        &self.state
    }

    #[must_use]
    pub const fn current_epoch(&self) -> Epoch {
        self.state.current_epoch
    }

    #[must_use]
    pub const fn latest_block(&self) -> &Arc<BeaconBlock> {
        &self.latest_block
    }

    #[must_use]
    pub const fn me(&self) -> ValidatorId {
        self.me
    }

    #[must_use]
    pub const fn now(&self) -> LocalTimestamp {
        self.now
    }
}

impl std::fmt::Debug for BeaconCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BeaconCoordinator")
            .field("current_epoch", &self.state.current_epoch)
            .field("latest_block_hash", &self.latest_block.block_hash())
            .field("me", &self.me)
            .field("spc_active", &self.spc.is_some())
            .field("pending_blocks", &self.pending_blocks.len())
            .field(
                "verifications_in_flight",
                &self.verification.in_flight_count(),
            )
            .field("witness_pool", &self.witness_fetcher.total_pool_len())
            .field("recovery_buckets", &self.recovery_tracker.bucket_count())
            .field("equivocations", &self.equivocations.len())
            .field("syncing", &self.sync.is_syncing())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_types::{
        BeaconBlock, Bls12381G1PublicKey, Epoch, NetworkDefinition, Randomness, ShardGroupId,
        Stake, StakePoolId, ValidatorId, bls_keypair_from_seed, state_root,
    };

    use super::*;
    use crate::constants::MIN_STAKE_FLOOR;
    use crate::genesis::{
        BeaconGenesisConfig, GenesisPool, GenesisValidator, build_genesis_beacon_state,
    };

    fn pubkey(seed: u64) -> Bls12381G1PublicKey {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s).public_key()
    }

    /// 4 validators, all on the beacon committee, all placed on shard 0.
    fn sample_genesis() -> BeaconGenesisConfig {
        let pool_id = StakePoolId::new(0);
        let shard = ShardGroupId::new(0);
        let validators: Vec<GenesisValidator> = (0u64..4)
            .map(|i| GenesisValidator {
                id: ValidatorId::new(i),
                pool: pool_id,
                pubkey: pubkey(i),
            })
            .collect();
        let members: Vec<ValidatorId> = (0u64..4).map(ValidatorId::new).collect();
        BeaconGenesisConfig {
            initial_validators: validators,
            initial_pools: vec![GenesisPool {
                id: pool_id,
                total_stake: Stake::from_attos(4 * MIN_STAKE_FLOOR.attos()),
            }],
            initial_beacon_committee: members.clone(),
            initial_shard_committees: std::iter::once((shard, members)).collect(),
            initial_randomness: Randomness([0xAB; 32]),
        }
    }

    /// The (block, state) pair the runner would produce on an empty
    /// store: build genesis state, hash it, wrap in a genesis block.
    fn genesis_pair() -> (Arc<BeaconBlock>, BeaconState) {
        let state = build_genesis_beacon_state(&sample_genesis());
        let block = BeaconBlock::genesis(state_root(&state));
        (Arc::new(block), state)
    }

    #[test]
    fn new_from_genesis_pair_resumes_at_genesis_epoch() {
        let (block, state) = genesis_pair();
        let coord = BeaconCoordinator::new(
            block,
            state,
            ValidatorId::new(0),
            NetworkDefinition::simulator(),
        );
        assert_eq!(coord.current_epoch(), Epoch::GENESIS);
        assert!(coord.is_on_committee());
        assert_eq!(coord.now(), LocalTimestamp::ZERO);
    }

    #[test]
    fn new_carries_latest_block() {
        let (block, state) = genesis_pair();
        let block_hash = block.block_hash();
        let coord = BeaconCoordinator::new(
            Arc::clone(&block),
            state,
            ValidatorId::new(0),
            NetworkDefinition::simulator(),
        );
        assert_eq!(coord.latest_block().block_hash(), block_hash);
    }

    #[test]
    fn off_committee_validator_reports_not_on_committee() {
        let (block, state) = genesis_pair();
        // 99 isn't in the 0..4 committee.
        let coord = BeaconCoordinator::new(
            block,
            state,
            ValidatorId::new(99),
            NetworkDefinition::simulator(),
        );
        assert!(!coord.is_on_committee());
    }

    #[test]
    fn set_now_advances_local_clock() {
        let (block, state) = genesis_pair();
        let mut coord = BeaconCoordinator::new(
            block,
            state,
            ValidatorId::new(0),
            NetworkDefinition::simulator(),
        );
        let t = LocalTimestamp::from_millis(123_456);
        coord.set_now(t);
        assert_eq!(coord.now(), t);
    }

    #[test]
    #[should_panic(expected = "header.state_root != state_root(&state)")]
    #[cfg(debug_assertions)]
    fn debug_assertion_catches_runner_skipping_binding_check() {
        use hyperscale_types::BeaconStateRoot;
        let state = build_genesis_beacon_state(&sample_genesis());
        let mismatched_block = BeaconBlock::genesis(BeaconStateRoot::ZERO);
        let _coord = BeaconCoordinator::new(
            Arc::new(mismatched_block),
            state,
            ValidatorId::new(0),
            NetworkDefinition::simulator(),
        );
    }

    #[test]
    fn committee_start_due_fires_at_or_after_boundary() {
        let (block, state) = genesis_pair();
        let mut coord = BeaconCoordinator::new(
            block,
            state,
            ValidatorId::new(0),
            NetworkDefinition::simulator(),
        );
        let boundary = LocalTimestamp::from_millis(10_000);
        coord.set_now(LocalTimestamp::from_millis(9_999));
        assert!(!coord.committee_start_due(boundary));
        coord.set_now(LocalTimestamp::from_millis(10_000));
        assert!(coord.committee_start_due(boundary));
        coord.set_now(LocalTimestamp::from_millis(10_001));
        assert!(coord.committee_start_due(boundary));
    }

    #[test]
    fn recovery_trigger_due_fires_one_timeout_past_expected() {
        use hyperscale_types::RECOVERY_TIMEOUT;
        let (block, state) = genesis_pair();
        let mut coord = BeaconCoordinator::new(
            block,
            state,
            ValidatorId::new(0),
            NetworkDefinition::simulator(),
        );
        let expected = LocalTimestamp::from_millis(100_000);
        let timeout_ms: u64 = RECOVERY_TIMEOUT
            .as_millis()
            .try_into()
            .expect("RECOVERY_TIMEOUT fits in u64 millis");

        coord.set_now(LocalTimestamp::from_millis(100_000 + timeout_ms - 1));
        assert!(!coord.recovery_trigger_due(expected));
        coord.set_now(LocalTimestamp::from_millis(100_000 + timeout_ms));
        assert!(coord.recovery_trigger_due(expected));
    }

    #[test]
    fn coordinator_owns_state_independently_from_input() {
        let (block, state) = genesis_pair();
        let original = state.clone();
        let coord = BeaconCoordinator::new(
            block,
            state,
            ValidatorId::new(0),
            NetworkDefinition::simulator(),
        );
        assert_eq!(coord.current_state(), &original);
        assert_eq!(coord.current_state().miss_counters, BTreeMap::new());
    }

    fn fresh_coord() -> BeaconCoordinator {
        let (block, state) = genesis_pair();
        BeaconCoordinator::new(
            block,
            state,
            ValidatorId::new(0),
            NetworkDefinition::simulator(),
        )
    }

    #[test]
    fn on_pc_vote_received_drops_when_no_spc_instance() {
        use hyperscale_types::{Bls12381G2Signature, PcVector, PcVote1, SpcView};
        let mut coord = fresh_coord();
        // Build a real SBOR-encoded VpcMsgPayload so the decode side
        // succeeds; the no-SPC drop path is what we're pinning.
        let payload = VpcMsgPayload::Vote1 {
            view: SpcView::new(1),
            vote: PcVote1::new(
                ValidatorId::new(1),
                PcVector::empty(),
                vec![Bls12381G2Signature([0u8; 96])],
            ),
        }
        .encode_bytes();
        let actions = coord.on_pc_vote_received(ValidatorId::new(1), &payload);
        assert!(actions.is_empty());
    }

    #[test]
    fn on_pc_vote_received_drops_on_malformed_payload() {
        let mut coord = fresh_coord();
        let actions = coord.on_pc_vote_received(ValidatorId::new(1), &[0xFF; 8]);
        assert!(actions.is_empty());
    }

    #[test]
    fn on_spc_message_received_drops_on_malformed_payload() {
        let mut coord = fresh_coord();
        let actions = coord.on_spc_message_received(ValidatorId::new(1), &[0xFF; 8]);
        assert!(actions.is_empty());
    }

    #[test]
    fn on_beacon_spc_view_timer_drops_when_no_spc_instance() {
        let mut coord = fresh_coord();
        assert!(coord.on_beacon_spc_view_timer().is_empty());
    }

    #[test]
    fn committee_start_bootstraps_spc_for_on_committee_local() {
        use hyperscale_types::SpcView;
        let mut coord = fresh_coord();
        assert!(coord.spc.is_none());
        let actions = coord.on_beacon_committee_start_timer();
        assert!(actions.is_empty(), "bootstrap emits no actions");
        let spc = coord.spc.as_ref().expect("SPC bootstrapped");
        assert_eq!(spc.epoch(), Epoch::GENESIS.next());
        assert_eq!(spc.current_view(), SpcView::new(1));
    }

    #[test]
    fn committee_start_no_op_when_off_committee() {
        let (block, state) = genesis_pair();
        let mut coord = BeaconCoordinator::new(
            block,
            state,
            // 99 isn't in the 0..4 committee.
            ValidatorId::new(99),
            NetworkDefinition::simulator(),
        );
        let actions = coord.on_beacon_committee_start_timer();
        assert!(actions.is_empty());
        assert!(coord.spc.is_none());
    }

    #[test]
    fn committee_start_is_idempotent() {
        let mut coord = fresh_coord();
        coord.on_beacon_committee_start_timer();
        let spc_view_first = coord.spc.as_ref().unwrap().current_view();
        // Second fire should not rebuild the instance.
        coord.on_beacon_committee_start_timer();
        let spc_view_second = coord.spc.as_ref().unwrap().current_view();
        assert_eq!(spc_view_first, spc_view_second);
    }
}
