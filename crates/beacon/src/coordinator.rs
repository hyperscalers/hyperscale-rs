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
//! before invoking [`BeaconCoordinator::new`]. The same code path
//! handles fresh-genesis and warm-restart: the runner builds and
//! commits the genesis pair on an empty store, then loads it back via
//! the same `latest_committed()` call. When the loaded block is
//! genesis the constructor debug-asserts its
//! [`SpcCert::Genesis`](hyperscale_types::SpcCert) `config_hash`
//! matches `expected_config_hash` — a tripwire against booting a
//! validator off a chain initialised by a different operator TOML.

use std::sync::Arc;

use hyperscale_core::{Action, TimerId};
use hyperscale_types::{
    BeaconBlock, BeaconProposal, BeaconState, Epoch, GenesisConfigHash, LocalTimestamp,
    NetworkDefinition, PcValueElement, PcVector, RECOVERY_TIMEOUT, SpcCert, SpcMessage,
    ValidatorId, VpcMsgPayload, spc_context,
};
use tracing::{trace, warn};

use crate::block_sync::BeaconBlockSyncManager;
use crate::constants::SPC_VIEW_TIMEOUT;
use crate::equivocations::EquivocationObservations;
use crate::pending_blocks::PendingBeaconBlocks;
use crate::proposal_pool::BeaconProposalPool;
use crate::recovery_tracker::RecoveryTracker;
use crate::spc::{SpcEffect, SpcEvent, SpcInstance, verify_block_cert};
use crate::state::{apply_epoch, derive_beacon_committee};
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

    /// Per-epoch cache of committee members' `BeaconProposal`s.
    /// Scoped to the in-flight epoch (`state.current_epoch.next()`);
    /// reset on commit.
    proposal_pool: BeaconProposalPool,

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
    /// latest_state)` pair. When `latest_block` is genesis, debug-asserts
    /// its cert's `config_hash` matches `expected_config_hash` —
    /// catches a runner that loaded a chain initialised by a different
    /// operator TOML than the one this process is configured for.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if `latest_block.is_genesis()` and the
    /// cert's `config_hash` doesn't match `expected_config_hash`.
    #[must_use]
    pub fn new(
        latest_block: Arc<BeaconBlock>,
        latest_state: BeaconState,
        me: ValidatorId,
        network: NetworkDefinition,
        expected_config_hash: GenesisConfigHash,
    ) -> Self {
        if let SpcCert::Genesis { config_hash } = latest_block.cert() {
            debug_assert_eq!(
                *config_hash, expected_config_hash,
                "genesis block config_hash doesn't match operator config",
            );
        }
        let next_epoch = latest_state.current_epoch.next();
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
            proposal_pool: BeaconProposalPool::new(next_epoch),
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

    /// A peer committee member's `BeaconProposal` arrived. Admit it
    /// to the pool gated on committee membership at `epoch`. The
    /// `IoLoop` has already authenticated `from` and verified the
    /// proposal's VRF reveal against `(network.id, epoch)` under
    /// `from`'s pubkey, so admission here is a pure pool insert.
    ///
    /// When the local validator's own proposal arrives back via the
    /// action handler's feedback, this is also the trigger that
    /// feeds SPC's view-1 PC instance — `compute_view_one_input`
    /// reads the pool's current view of committee proposals and
    /// `SpcEvent::Input` kicks the FSM into outbound traffic.
    pub fn on_beacon_proposal_received(
        &mut self,
        from: ValidatorId,
        epoch: Epoch,
        proposal: Arc<BeaconProposal>,
    ) -> Vec<Action> {
        if !self.state.committee.contains(&from) {
            trace!(
                ?from,
                epoch = epoch.inner(),
                "BeaconProposalReceived from non-committee sender — dropping",
            );
            return Vec::new();
        }
        if !self.proposal_pool.admit(from, epoch, proposal) {
            trace!(
                ?from,
                epoch = epoch.inner(),
                pool_epoch = self.proposal_pool.epoch().inner(),
                "BeaconProposalReceived rejected — wrong epoch or duplicate sender",
            );
            return Vec::new();
        }
        if from == self.me && self.should_feed_view_one_input(epoch) {
            return self.feed_view_one_input(epoch);
        }
        Vec::new()
    }

    /// Whether the current SPC instance is ready to receive its
    /// view-1 `Input`: instance exists, drives `epoch`, and hasn't
    /// been fed already.
    fn should_feed_view_one_input(&self, epoch: Epoch) -> bool {
        self.spc
            .as_ref()
            .is_some_and(|spc| spc.epoch() == epoch && !spc.view_one_input_fed())
    }

    /// Build view 1's local input vector from the current pool view
    /// and drive it into SPC. Lifts the resulting effects.
    fn feed_view_one_input(&mut self, epoch: Epoch) -> Vec<Action> {
        let input = self.compute_view_one_input(epoch);
        let recipients = self.spc_recipients();
        let spc = self.spc.as_mut().expect("checked by should_feed");
        let effects = spc.handle(SpcEvent::Input(input));
        self.lift_spc_effects(epoch, &recipients, effects)
    }

    /// Build the PC input vector for view 1: one `PcValueElement` per
    /// committee position, the hashed proposal if we've seen it or
    /// `PcValueElement::ZERO` (`HASH_BOTTOM`) if not.
    fn compute_view_one_input(&self, epoch: Epoch) -> PcVector {
        let elements: Vec<PcValueElement> = self
            .state
            .committee
            .iter()
            .map(|id| {
                self.proposal_pool
                    .get(*id)
                    .map_or(PcValueElement::ZERO, |p| p.pc_element_hash(epoch))
            })
            .collect();
        PcVector::new(elements)
    }

    /// Local-proposal trigger: if the local validator is on the
    /// committee, an SPC instance is bootstrapped, and we haven't
    /// already proposed this epoch, emit
    /// [`Action::BuildAndBroadcastBeaconProposal`] so the action
    /// handler can VRF-sign and gossip. The signed proposal arrives
    /// back via `on_beacon_proposal_received` which feeds SPC's
    /// view-1 input.
    pub fn try_propose(&mut self) -> Vec<Action> {
        if self.spc.is_none() {
            trace!("try_propose: no SPC instance — deferring");
            return Vec::new();
        }
        if !self.is_on_committee() {
            return Vec::new();
        }
        if self.proposal_pool.contains(self.me) {
            // Already proposed this epoch; admission feedback path
            // will (or did) feed SPC's input.
            return Vec::new();
        }
        let epoch = self.proposal_pool.epoch();
        let recipients = self.spc_recipients();
        // Witness + equivocation draining lands with the proposer-
        // assembly wiring in a follow-up sub-commit. For now ship a
        // VRF-only proposal so the FSM still has byte-distinct
        // per-validator entries to commit on.
        vec![Action::BuildAndBroadcastBeaconProposal {
            epoch,
            witnesses: Vec::new(),
            recipients,
        }]
    }

    /// `TimerId::BeaconCommitteeStart` fired — the upcoming epoch's
    /// wall-clock boundary has been reached. If the local validator
    /// is on the next committee and no SPC instance is already
    /// running, bootstrap one and immediately invoke
    /// [`Self::try_propose`] so the local `BeaconProposal` enters
    /// the gossip + admission cycle.
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
        self.try_propose()
    }

    /// Stand up a fresh [`SpcInstance`] for the upcoming epoch.
    /// Pairs each committee member with their pubkey by looking up
    /// `state.validators`. Skips validators absent from the validator
    /// table — a structurally impossible state for an on-chain
    /// committee, so the skip is defensive rather than expected.
    fn bootstrap_spc_for_next_epoch(&mut self) {
        let committee = derive_beacon_committee(&self.state);
        let next_epoch = self.state.current_epoch.next();
        self.spc = Some(SpcInstance::new(
            self.network.clone(),
            next_epoch,
            committee,
            self.me,
            SPC_VIEW_TIMEOUT,
        ));
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

    /// A peer-aggregated [`BeaconBlock`] arrived via the beacon gossip
    /// topic. After verifying the cert under the current beacon
    /// committee, hand off to [`Self::adopt_block`] for the apply +
    /// commit + bootstrap cycle. Blocks too far ahead of the local tip
    /// land in `pending_blocks` for future redrive.
    ///
    /// Cert verification uses `self.state.committee`. Committee
    /// rotation across epochs means an off-committee observer whose
    /// state has fallen behind the actual signing committee will reject
    /// otherwise-valid blocks. Resolving that without `apply_epoch` is
    /// a state-sync problem handled elsewhere.
    pub fn on_beacon_block_received(&mut self, block: Arc<BeaconBlock>) -> Vec<Action> {
        let epoch = block.epoch();
        let tip_epoch = self.latest_block.epoch();
        if epoch <= tip_epoch {
            trace!(
                epoch = epoch.inner(),
                "BeaconBlockReceived for past/current epoch — dropping",
            );
            return Vec::new();
        }
        let expected_epoch = tip_epoch.next();
        if epoch > expected_epoch {
            trace!(
                epoch = epoch.inner(),
                expected = expected_epoch.inner(),
                "BeaconBlockReceived for future epoch — buffering",
            );
            self.pending_blocks.insert(block);
            return Vec::new();
        }

        if block.prev_block_hash() != self.latest_block.block_hash() {
            warn!(
                epoch = epoch.inner(),
                "BeaconBlockReceived with mismatched prev_block_hash — dropping",
            );
            return Vec::new();
        }
        // Verify the cert under the current beacon committee (which is
        // the committee active for this incoming block's epoch).
        let committee = derive_beacon_committee(&self.state);
        let spc_ctx = spc_context(epoch);
        if !verify_block_cert(block.cert(), &self.network, &spc_ctx, &committee) {
            warn!(
                epoch = epoch.inner(),
                "BeaconBlockReceived cert verification failed — dropping",
            );
            return Vec::new();
        }

        // If our local SPC already produced an OutputHigh, the peer's
        // block ought to match what we'd have built. Either way, the
        // cert verifies, so adopt and advance.
        self.adopt_block(block)
    }

    /// Advance `self.state` / `self.latest_block` to `block` after
    /// running `apply_epoch` over its committed proposals. Resets
    /// per-epoch caches, bootstraps next epoch's SPC if local is on
    /// the new committee. Emits `CommitBeaconBlock` only — no
    /// broadcast (caller decides whether the local node is the
    /// originator).
    fn adopt_block(&mut self, block: Arc<BeaconBlock>) -> Vec<Action> {
        let mut new_state = self.state.clone();
        apply_epoch(
            &mut new_state,
            &self.network,
            block.epoch(),
            block.committed_proposals(),
            block.recovery_cert(),
        );
        self.state = new_state;
        self.latest_block = Arc::clone(&block);
        self.spc = None;

        let next_epoch = self.state.current_epoch.next();
        self.proposal_pool.reset(next_epoch);
        self.pending_blocks
            .prune_committed(self.state.current_epoch);

        let mut actions = vec![Action::CommitBeaconBlock {
            block,
            state: Box::new(self.state.clone()),
        }];

        if self.is_on_committee() {
            self.bootstrap_spc_for_next_epoch();
            actions.extend(self.try_propose());
        }

        actions
    }

    /// SPC has decided this epoch — assemble the [`BeaconBlock`]
    /// directly from the cert SPC produced and the locally-resolved
    /// committed proposals, then emit `CommitBeaconBlock` +
    /// `BroadcastBeaconBlock`. No header-sig collection round: the
    /// SPC cert IS the block's authenticator.
    fn on_spc_output_high(
        &mut self,
        epoch: Epoch,
        output: &PcVector,
        cert: SpcCert,
        _recipients: &[ValidatorId],
    ) -> Vec<Action> {
        let committed = self.decode_committed_proposals(epoch, output);
        // Recovery-cert assembly (`RecoveryTracker::try_assemble`) lands
        // in a follow-up; for now every commit is plain-path.
        let recovery_cert = None;
        let prev_block_hash = self.latest_block.block_hash();
        let block = BeaconBlock::new(epoch, prev_block_hash, cert, recovery_cert, committed);
        let block_arc = Arc::new(block);

        // Advance state via the shared adoption path.
        let mut actions = self.adopt_block(Arc::clone(&block_arc));
        actions.push(Action::BroadcastBeaconBlock { block: block_arc });
        actions
    }

    /// Read the committed `BeaconProposal` list from the proposal
    /// pool, in committee order, matching each non-`ZERO` `PcVector`
    /// element against the corresponding validator's
    /// [`BeaconProposal::pc_element_hash`].
    ///
    /// Mismatches and pool misses get a warn — eventually those want
    /// a fetch path, but for the all-honest case the local pool has
    /// every accepted proposal already.
    fn decode_committed_proposals(
        &self,
        epoch: Epoch,
        output: &PcVector,
    ) -> Vec<(ValidatorId, BeaconProposal)> {
        let mut committed = Vec::new();
        for (i, element) in output.iter().enumerate() {
            if *element == PcValueElement::ZERO {
                continue;
            }
            let Some(validator) = self.state.committee.get(i).copied() else {
                warn!(
                    pos = i,
                    "OutputHigh element past committee bounds — skipping",
                );
                continue;
            };
            let Some(pooled) = self.proposal_pool.get(validator) else {
                warn!(
                    ?validator,
                    epoch = epoch.inner(),
                    "OutputHigh includes proposal we haven't seen — skipping",
                );
                continue;
            };
            if pooled.pc_element_hash(epoch) != *element {
                warn!(
                    ?validator,
                    epoch = epoch.inner(),
                    "OutputHigh hash mismatches pooled proposal — skipping",
                );
                continue;
            }
            committed.push((validator, (**pooled).clone()));
        }
        committed
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
                SpcEffect::OutputHigh { value, cert } => {
                    actions.extend(self.on_spc_output_high(epoch, &value, *cert, recipients));
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
        BeaconBlock, BeaconBlockHash, BeaconGenesisConfig, Bls12381G1PrivateKey,
        Bls12381G1PublicKey, Epoch, GenesisConfigHash, GenesisPool, GenesisValidator,
        NetworkDefinition, PcVector, Randomness, ShardGroupId, SpcCert, SpcView, Stake,
        StakePoolId, ValidatorId, bls_keypair_from_seed, genesis_config_hash, pc_context,
        spc_context,
    };

    use super::*;
    use crate::constants::MIN_STAKE_FLOOR;
    use crate::genesis::build_genesis_beacon_state;
    use crate::pc::{build_qc1, build_qc2, build_qc3, sign_vote1, sign_vote2, sign_vote3};

    fn keypair(seed: u64) -> Bls12381G1PrivateKey {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s)
    }

    fn pubkey(seed: u64) -> Bls12381G1PublicKey {
        keypair(seed).public_key()
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

    /// The (block, state, `config_hash`) trio the runner would produce
    /// on an empty store: build genesis state, hash the config, wrap
    /// the genesis block.
    fn genesis_trio() -> (Arc<BeaconBlock>, BeaconState, GenesisConfigHash) {
        let config = sample_genesis();
        let state = build_genesis_beacon_state(&config);
        let config_hash = genesis_config_hash(&config);
        let block = BeaconBlock::genesis(config_hash);
        (Arc::new(block), state, config_hash)
    }

    fn new_coord(me: ValidatorId) -> BeaconCoordinator {
        let (block, state, config_hash) = genesis_trio();
        BeaconCoordinator::new(
            block,
            state,
            me,
            NetworkDefinition::simulator(),
            config_hash,
        )
    }

    fn fresh_coord() -> BeaconCoordinator {
        new_coord(ValidatorId::new(0))
    }

    #[test]
    fn new_from_genesis_pair_resumes_at_genesis_epoch() {
        let coord = fresh_coord();
        assert_eq!(coord.current_epoch(), Epoch::GENESIS);
        assert!(coord.is_on_committee());
        assert_eq!(coord.now(), LocalTimestamp::ZERO);
    }

    #[test]
    fn new_carries_latest_block() {
        let (block, state, config_hash) = genesis_trio();
        let block_hash = block.block_hash();
        let coord = BeaconCoordinator::new(
            Arc::clone(&block),
            state,
            ValidatorId::new(0),
            NetworkDefinition::simulator(),
            config_hash,
        );
        assert_eq!(coord.latest_block().block_hash(), block_hash);
    }

    #[test]
    fn off_committee_validator_reports_not_on_committee() {
        let coord = new_coord(ValidatorId::new(99));
        assert!(!coord.is_on_committee());
    }

    #[test]
    fn set_now_advances_local_clock() {
        let mut coord = fresh_coord();
        let t = LocalTimestamp::from_millis(123_456);
        coord.set_now(t);
        assert_eq!(coord.now(), t);
    }

    #[test]
    #[should_panic(expected = "genesis block config_hash doesn't match operator config")]
    #[cfg(debug_assertions)]
    fn debug_assertion_catches_runner_loading_mismatched_genesis() {
        use hyperscale_types::Hash;
        let (_block, state, _config_hash) = genesis_trio();
        let mismatched_block = BeaconBlock::genesis(GenesisConfigHash::from_raw(Hash::from_bytes(
            b"other-config",
        )));
        let _coord = BeaconCoordinator::new(
            Arc::new(mismatched_block),
            state,
            ValidatorId::new(0),
            NetworkDefinition::simulator(),
            GenesisConfigHash::ZERO,
        );
    }

    #[test]
    fn committee_start_due_fires_at_or_after_boundary() {
        let mut coord = fresh_coord();
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
        let mut coord = fresh_coord();
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
        let coord = fresh_coord();
        let snapshot = coord.current_state().clone();
        assert_eq!(coord.current_state(), &snapshot);
        assert_eq!(coord.current_state().miss_counters, BTreeMap::new());
    }

    #[test]
    fn on_pc_vote_received_drops_when_no_spc_instance() {
        use hyperscale_types::{Bls12381G2Signature, PcVote1};
        let mut coord = fresh_coord();
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
        let mut coord = fresh_coord();
        assert!(coord.spc.is_none());
        let actions = coord.on_beacon_committee_start_timer();
        let spc = coord.spc.as_ref().expect("SPC bootstrapped");
        assert_eq!(spc.epoch(), Epoch::GENESIS.next());
        assert_eq!(spc.current_view(), SpcView::new(1));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::BuildAndBroadcastBeaconProposal { .. })),
            "expected BuildAndBroadcastBeaconProposal in {actions:?}",
        );
    }

    #[test]
    fn committee_start_no_op_when_off_committee() {
        let mut coord = new_coord(ValidatorId::new(99));
        let actions = coord.on_beacon_committee_start_timer();
        assert!(actions.is_empty());
        assert!(coord.spc.is_none());
    }

    #[test]
    fn committee_start_is_idempotent() {
        let mut coord = fresh_coord();
        coord.on_beacon_committee_start_timer();
        let spc_view_first = coord.spc.as_ref().unwrap().current_view();
        coord.on_beacon_committee_start_timer();
        let spc_view_second = coord.spc.as_ref().unwrap().current_view();
        assert_eq!(spc_view_first, spc_view_second);
    }

    fn sample_proposal(seed: u8) -> Arc<BeaconProposal> {
        use hyperscale_types::{VrfOutput, VrfProof};
        Arc::new(BeaconProposal::vrf_only(
            VrfOutput([seed; 32]),
            VrfProof([seed; 96]),
        ))
    }

    #[test]
    fn on_proposal_received_admits_in_flight_epoch_from_committee_member() {
        let mut coord = fresh_coord();
        let from = ValidatorId::new(1);
        let in_flight = Epoch::GENESIS.next();
        let actions = coord.on_beacon_proposal_received(from, in_flight, sample_proposal(0xAB));
        assert!(actions.is_empty());
        assert!(coord.proposal_pool.contains(from));
    }

    #[test]
    fn on_proposal_received_drops_non_committee_sender() {
        let mut coord = fresh_coord();
        let actions = coord.on_beacon_proposal_received(
            ValidatorId::new(99),
            Epoch::GENESIS.next(),
            sample_proposal(0xAB),
        );
        assert!(actions.is_empty());
        assert!(coord.proposal_pool.is_empty());
    }

    #[test]
    fn on_proposal_received_drops_wrong_epoch() {
        let mut coord = fresh_coord();
        let actions = coord.on_beacon_proposal_received(
            ValidatorId::new(1),
            Epoch::GENESIS,
            sample_proposal(0xAB),
        );
        assert!(actions.is_empty());
        assert!(coord.proposal_pool.is_empty());
    }

    #[test]
    fn try_propose_emits_build_action_after_bootstrap() {
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let actions = coord.try_propose();
        let in_flight = Epoch::GENESIS.next();
        let [
            Action::BuildAndBroadcastBeaconProposal {
                epoch,
                witnesses,
                recipients,
            },
        ] = actions.as_slice()
        else {
            panic!("expected BuildAndBroadcastBeaconProposal, got {actions:?}");
        };
        assert_eq!(*epoch, in_flight);
        assert!(witnesses.is_empty());
        // Three peers in the n=4 committee (self filtered out).
        assert_eq!(recipients.len(), 3);
        assert!(!recipients.contains(&coord.me));
    }

    #[test]
    fn try_propose_is_no_op_without_spc() {
        let mut coord = fresh_coord();
        assert!(coord.try_propose().is_empty());
    }

    #[test]
    fn try_propose_is_no_op_off_committee() {
        let mut coord = new_coord(ValidatorId::new(99));
        assert!(coord.try_propose().is_empty());
    }

    #[test]
    fn try_propose_idempotent_after_own_proposal_in_pool() {
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let first = coord.try_propose();
        assert!(!first.is_empty());
        let me = coord.me;
        let in_flight = Epoch::GENESIS.next();
        coord.on_beacon_proposal_received(me, in_flight, sample_proposal(0xAB));
        assert!(coord.try_propose().is_empty());
    }

    #[test]
    fn own_proposal_feedback_feeds_spc_view_one_input() {
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let me = coord.me;
        let in_flight = Epoch::GENESIS.next();
        assert!(!coord.spc.as_ref().unwrap().view_one_input_fed());
        let actions = coord.on_beacon_proposal_received(me, in_flight, sample_proposal(0xAB));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::SignAndBroadcastPcVote1 { .. })),
            "expected SignAndBroadcastPcVote1 in {actions:?}",
        );
        assert!(coord.spc.as_ref().unwrap().view_one_input_fed());
    }

    #[test]
    fn peer_proposal_does_not_trigger_view_one_input_feed() {
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let actions = coord.on_beacon_proposal_received(
            ValidatorId::new(1),
            Epoch::GENESIS.next(),
            sample_proposal(0xAB),
        );
        assert!(actions.is_empty(), "peer proposal alone doesn't kick PC");
        assert!(!coord.spc.as_ref().unwrap().view_one_input_fed());
    }

    /// Drive `signer_positions` of `committee`'s keys through one
    /// round each of PC voting to assemble a real `Direct` SPC cert
    /// for `(epoch, prev_view)`.
    fn build_direct_cert(
        prev_view: SpcView,
        epoch: Epoch,
        keys: &[Bls12381G1PrivateKey],
        committee: &[(ValidatorId, Bls12381G1PublicKey)],
        signer_positions: &[usize],
    ) -> SpcCert {
        let net = NetworkDefinition::simulator();
        let spc_ctx = spc_context(epoch);
        let pc_ctx = pc_context(&spc_ctx, prev_view);
        let v_in = PcVector::empty();
        let v1s: Vec<_> = signer_positions
            .iter()
            .map(|&i| sign_vote1(&keys[i], committee[i].0, &net, &pc_ctx, v_in.clone()))
            .collect();
        let v1_refs: Vec<&_> = v1s.iter().collect();
        let qc1 = build_qc1(&v1_refs, committee);
        let v2s: Vec<_> = signer_positions
            .iter()
            .map(|&i| sign_vote2(&keys[i], committee[i].0, &net, &pc_ctx, qc1.clone()))
            .collect();
        let v2_refs: Vec<&_> = v2s.iter().collect();
        let qc2 = build_qc2(&v2_refs, committee);
        let v3s: Vec<_> = signer_positions
            .iter()
            .map(|&i| sign_vote3(&keys[i], committee[i].0, &net, &pc_ctx, qc2.clone()))
            .collect();
        let v3_refs: Vec<&_> = v3s.iter().collect();
        let qc3 = build_qc3(&v3_refs, committee);
        let value = qc3.x_pe().clone();
        SpcCert::Direct {
            prev_view,
            value,
            proof: qc3,
        }
    }

    /// Build a peer `BeaconBlock` at `epoch` that verifies under
    /// `coord`'s state. `signer_positions` selects which committee
    /// members contribute to the cert (default `n - f` for honest
    /// quorum).
    fn valid_block_at(
        coord: &BeaconCoordinator,
        epoch: Epoch,
        prev_hash: BeaconBlockHash,
    ) -> Arc<BeaconBlock> {
        let n = coord.state.committee.len();
        let f = n.saturating_sub(1) / 3;
        let q = n - f;
        let keys: Vec<_> = (0..n as u64).map(keypair).collect();
        let committee: Vec<_> = coord
            .state
            .committee
            .iter()
            .copied()
            .zip(keys.iter().map(Bls12381G1PrivateKey::public_key))
            .collect();
        let signer_positions: Vec<usize> = (0..q).collect();
        let cert = build_direct_cert(SpcView::new(1), epoch, &keys, &committee, &signer_positions);
        Arc::new(BeaconBlock::new(epoch, prev_hash, cert, None, Vec::new()))
    }

    #[test]
    fn on_beacon_block_received_drops_past_epoch() {
        let mut coord = fresh_coord();
        let prev = coord.latest_block.block_hash();
        let block = valid_block_at(&coord, Epoch::GENESIS, prev);
        let actions = coord.on_beacon_block_received(block);
        assert!(actions.is_empty());
        assert!(coord.pending_blocks.is_empty());
        assert_eq!(coord.state.current_epoch, Epoch::GENESIS);
    }

    #[test]
    fn on_beacon_block_received_buffers_future_epoch() {
        let mut coord = fresh_coord();
        let prev = coord.latest_block.block_hash();
        let block = valid_block_at(&coord, Epoch::new(5), prev);
        let block_hash = block.block_hash();
        let actions = coord.on_beacon_block_received(block);
        assert!(actions.is_empty());
        assert_eq!(coord.pending_blocks.len(), 1);
        assert!(coord.pending_blocks.contains_key(block_hash));
        assert_eq!(coord.state.current_epoch, Epoch::GENESIS);
    }

    #[test]
    fn on_beacon_block_received_drops_wrong_prev_hash() {
        let mut coord = fresh_coord();
        let block = valid_block_at(&coord, Epoch::new(1), BeaconBlockHash::ZERO);
        let actions = coord.on_beacon_block_received(block);
        assert!(actions.is_empty());
        assert!(coord.pending_blocks.is_empty());
    }

    #[test]
    fn on_beacon_block_received_drops_invalid_cert() {
        let mut coord = fresh_coord();
        let prev = coord.latest_block.block_hash();
        // Genesis cert isn't accepted as a view-entry by verify_block_cert.
        let block = Arc::new(BeaconBlock::new(
            Epoch::new(1),
            prev,
            SpcCert::Genesis {
                config_hash: GenesisConfigHash::ZERO,
            },
            None,
            Vec::new(),
        ));
        let actions = coord.on_beacon_block_received(block);
        assert!(actions.is_empty());
        assert!(coord.pending_blocks.is_empty());
        assert_eq!(coord.state.current_epoch, Epoch::GENESIS);
    }

    #[test]
    fn on_beacon_block_received_adopts_valid_peer_block() {
        let mut coord = fresh_coord();
        let prev = coord.latest_block.block_hash();
        let block = valid_block_at(&coord, Epoch::new(1), prev);
        let block_hash = block.block_hash();
        let actions = coord.on_beacon_block_received(Arc::clone(&block));

        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::CommitBeaconBlock { .. })),
            "expected CommitBeaconBlock in {actions:?}",
        );
        // Adoption skips re-broadcast — peer is disseminating.
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::BroadcastBeaconBlock { .. })),
            "adoption path should not re-broadcast",
        );
        assert_eq!(coord.state.current_epoch, Epoch::new(1));
        assert_eq!(coord.latest_block.block_hash(), block_hash);
        assert!(coord.spc.is_some(), "next epoch's SPC should bootstrap");
    }

    #[test]
    fn off_committee_observer_adopts_valid_peer_block() {
        let mut observer = new_coord(ValidatorId::new(99));
        let prev = observer.latest_block.block_hash();
        let block = valid_block_at(&observer, Epoch::new(1), prev);
        let block_hash = block.block_hash();

        let actions = observer.on_beacon_block_received(Arc::clone(&block));
        // Off-committee observers still advance state via apply_epoch.
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::CommitBeaconBlock { .. })),
            "expected CommitBeaconBlock in {actions:?}",
        );
        assert_eq!(observer.current_epoch(), Epoch::new(1));
        assert_eq!(observer.latest_block().block_hash(), block_hash);
        // Off-committee, so no SPC bootstrap for the next epoch.
        assert!(observer.spc.is_none());
    }

    /// Off-committee observers stay in sync across multiple epochs:
    /// each block chains off the previous adopted block's hash, and
    /// state keeps advancing. The committee derives from `self.state`
    /// at each call, so a stale observer can verify every successor
    /// block as long as it adopted the predecessor.
    #[test]
    fn off_committee_observer_chain_tracks_across_multiple_epochs() {
        let mut observer = new_coord(ValidatorId::new(99));

        for epoch in 1u64..=3 {
            let prev = observer.latest_block.block_hash();
            let block = valid_block_at(&observer, Epoch::new(epoch), prev);
            let block_hash = block.block_hash();
            let actions = observer.on_beacon_block_received(Arc::clone(&block));
            assert!(
                actions
                    .iter()
                    .any(|a| matches!(a, Action::CommitBeaconBlock { .. })),
                "epoch {epoch}: expected CommitBeaconBlock in {actions:?}",
            );
            assert_eq!(observer.current_epoch(), Epoch::new(epoch));
            assert_eq!(observer.latest_block().block_hash(), block_hash);
        }
        assert!(observer.spc.is_none());
    }

    /// `on_spc_output_high` emits `CommitBeaconBlock` immediately
    /// followed by `BroadcastBeaconBlock` — no intermediate
    /// sig-collection step. Pins acceptance criterion #6 from the
    /// cert-as-authenticator design: no round-trip from `OutputHigh`
    /// to `CommitBeaconBlock`.
    #[test]
    fn output_high_emits_commit_and_broadcast_directly() {
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let in_flight = Epoch::GENESIS.next();
        let committee = coord.state.committee.clone();
        let n = committee.len();
        let mut elements = Vec::with_capacity(n);
        for id in &committee {
            let p = sample_proposal(u8::try_from(id.inner()).unwrap_or(0));
            elements.push(p.pc_element_hash(in_flight));
            coord.proposal_pool.admit(*id, in_flight, p);
        }
        let output = PcVector::new(elements);

        // Construct a verifying cert the way the SPC FSM would produce
        // it — same machinery `valid_block_at` uses.
        let keys: Vec<_> = (0..n as u64).map(keypair).collect();
        let cert_committee: Vec<_> = coord
            .state
            .committee
            .iter()
            .copied()
            .zip(keys.iter().map(Bls12381G1PrivateKey::public_key))
            .collect();
        let f = n.saturating_sub(1) / 3;
        let q = n - f;
        let signer_positions: Vec<usize> = (0..q).collect();
        let cert = build_direct_cert(
            SpcView::new(1),
            in_flight,
            &keys,
            &cert_committee,
            &signer_positions,
        );

        let recipients = coord.spc_recipients();
        let actions = coord.on_spc_output_high(in_flight, &output, cert, &recipients);

        // Exactly two actions, in this order: Commit then Broadcast.
        let kinds: Vec<&str> = actions.iter().map(Action::type_name).collect();
        assert_eq!(
            kinds,
            vec!["CommitBeaconBlock", "BroadcastBeaconBlock"],
            "expected [CommitBeaconBlock, BroadcastBeaconBlock] from OutputHigh, got {kinds:?}",
        );
        assert_eq!(coord.state.current_epoch, in_flight);
        assert_eq!(coord.latest_block.epoch(), in_flight);
    }
}
