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
    BeaconBlock, BeaconBlockHeader, BeaconProposal, BeaconState, Bls12381G1PublicKey,
    Bls12381G2Signature, Epoch, LocalTimestamp, NetworkDefinition, PcValueElement, PcVector,
    RECOVERY_TIMEOUT, RecoveryCertificate, SignerBitfield, SpcMessage, ValidatorId, VpcMsgPayload,
    aggregate_verify_bls_different_messages, beacon_block_header_message, compute_proposals_root,
    recovery_cert_hash, state_root, verify_bls12381_v1,
};
use tracing::{trace, warn};

use crate::block_sync::BeaconBlockSyncManager;
use crate::constants::SPC_VIEW_TIMEOUT;
use crate::equivocations::EquivocationObservations;
use crate::pending_blocks::PendingBeaconBlocks;
use crate::proposal_pool::BeaconProposalPool;
use crate::recovery_tracker::RecoveryTracker;
use crate::sig_pool::BeaconBlockSigPool;
use crate::spc::{SpcEffect, SpcEvent, SpcInstance};
use crate::state::apply_epoch;
use crate::verification::BeaconVerificationPipeline;
use crate::witness_fetcher::ShardWitnessFetchTracker;

/// Held between SPC commit (`OutputHigh`) and block assembly (quorum
/// of header sigs). Carries the post-`apply_epoch` state and the
/// header the committee is signing so the aggregator can build the
/// `BeaconBlock` without re-running the apply pipeline.
#[derive(Debug)]
#[allow(dead_code)] // header / new_state / recovery_cert read by the sig-quorum assembler
struct PendingCommit {
    epoch: Epoch,
    header: BeaconBlockHeader,
    new_state: Box<BeaconState>,
    recovery_cert: Option<Box<RecoveryCertificate>>,
}

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

    /// Per-epoch cache of header sigs collected post-OutputHigh; the
    /// committee aggregate over the header is built from this pool
    /// once quorum lands.
    sig_pool: BeaconBlockSigPool,

    /// Set after SPC's `OutputHigh` lands and `apply_epoch` has run:
    /// the post-apply state, the header derived from it, and any
    /// attached recovery cert. The aggregator uses this once the
    /// committee's header sigs gather to quorum.
    commit_in_progress: Option<PendingCommit>,

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
            sig_pool: BeaconBlockSigPool::new(next_epoch),
            commit_in_progress: None,
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

    /// A peer committee member's header sig arrived. Gate on
    /// committee membership + epoch matches the pending commit +
    /// sig verifies under `from`'s pubkey against the locally-derived
    /// header bytes; admit on success. On quorum, aggregate sigs,
    /// build the `BeaconBlock`, advance `state` / `latest_block`,
    /// emit commit + broadcast actions, and bootstrap the next
    /// epoch's `SpcInstance` if local is on the new committee.
    pub fn on_beacon_block_sig_received(
        &mut self,
        from: ValidatorId,
        epoch: Epoch,
        sig: Bls12381G2Signature,
    ) -> Vec<Action> {
        if !self.state.committee.contains(&from) {
            trace!(
                ?from,
                epoch = epoch.inner(),
                "BeaconBlockSig from non-committee sender — dropping",
            );
            return Vec::new();
        }
        let Some(pending) = self.commit_in_progress.as_ref() else {
            trace!(
                ?from,
                epoch = epoch.inner(),
                "BeaconBlockSig with no pending commit — dropping",
            );
            return Vec::new();
        };
        if pending.epoch != epoch {
            trace!(
                ?from,
                sig_epoch = epoch.inner(),
                pending_epoch = pending.epoch.inner(),
                "BeaconBlockSig epoch mismatch — dropping",
            );
            return Vec::new();
        }
        let Some(pubkey) = self.state.validators.get(&from).map(|v| v.pubkey) else {
            warn!(
                ?from,
                "BeaconBlockSig from validator absent from `state.validators` — dropping",
            );
            return Vec::new();
        };
        let msg = beacon_block_header_message(&self.network, &pending.header);
        if !verify_bls12381_v1(&msg, &pubkey, &sig) {
            warn!(
                ?from,
                epoch = epoch.inner(),
                "BeaconBlockSig failed verification — dropping",
            );
            return Vec::new();
        }
        if !self.sig_pool.admit(from, epoch, sig) {
            trace!(?from, "BeaconBlockSig admission rejected (duplicate)");
            return Vec::new();
        }
        if self.sig_pool.len() < self.commit_quorum() {
            return Vec::new();
        }
        self.assemble_and_commit()
    }

    /// A peer-aggregated [`BeaconBlock`] arrived via the beacon gossip
    /// topic. Validate the block; if it matches the local pending
    /// commit, adopt the peer's aggregate sig and advance state
    /// instead of waiting on the local header-sig quorum. Otherwise
    /// buffer in [`PendingBeaconBlocks`] for a future apply path.
    ///
    /// Adoption is the missed-quorum branch: pending commit's derived
    /// `new_state` is already byte-identical to the new committed
    /// state (the header binds it via `state_root`), so the local
    /// sig pool just gets discarded.
    ///
    /// The passive-observer apply-epoch-from-peer-block path (for
    /// vnodes not on the committee, which never set `commit_in_progress`)
    /// stays unbuilt: those blocks land in `pending_blocks` and a
    /// follow-up sub-commit will drive `apply_epoch` from the peer
    /// block's proposals once the proposal-fetch protocol exists.
    pub fn on_beacon_block_received(&mut self, block: Arc<BeaconBlock>) -> Vec<Action> {
        let epoch = block.epoch();
        if epoch <= self.state.current_epoch {
            trace!(
                epoch = epoch.inner(),
                "BeaconBlockReceived for past/current epoch — dropping",
            );
            return Vec::new();
        }
        let expected_epoch = self.state.current_epoch.next();
        if epoch > expected_epoch {
            trace!(
                epoch = epoch.inner(),
                expected = expected_epoch.inner(),
                "BeaconBlockReceived for future epoch — buffering",
            );
            self.pending_blocks.insert(block);
            return Vec::new();
        }

        if block.header().prev_block_hash() != self.latest_block.block_hash() {
            warn!(
                epoch = epoch.inner(),
                "BeaconBlockReceived with mismatched prev_block_hash — dropping",
            );
            return Vec::new();
        }
        if !self.verify_beacon_block_aggregate(&block) {
            warn!(
                epoch = epoch.inner(),
                "BeaconBlockReceived failed aggregate-sig verification — dropping",
            );
            return Vec::new();
        }

        let Some(pending) = self.commit_in_progress.as_ref() else {
            trace!(
                epoch = epoch.inner(),
                "BeaconBlockReceived without local pending commit — buffering",
            );
            self.pending_blocks.insert(block);
            return Vec::new();
        };
        if block.block_hash() != pending.header.hash() {
            warn!(
                epoch = epoch.inner(),
                "BeaconBlockReceived header differs from local pending commit — dropping",
            );
            return Vec::new();
        }

        self.adopt_peer_block(block)
    }

    /// Verify a `BeaconBlock`'s committee-aggregate signature against
    /// the union of its signers' pubkeys, drawn from
    /// `self.state.committee` at the bitfield's set positions.
    ///
    /// Mirrors [`crate::recovery::verify_recovery_cert`]'s shape: same
    /// quorum threshold, same domain helper, same aggregate-verify
    /// primitive.
    fn verify_beacon_block_aggregate(&self, block: &BeaconBlock) -> bool {
        let committee_size = self.state.committee.len();
        if block.signers().num_validators() != committee_size {
            return false;
        }
        if block.signer_count() < self.commit_quorum() {
            return false;
        }
        let signer_pks: Vec<Bls12381G1PublicKey> = block
            .signers()
            .set_indices()
            .filter_map(|i| {
                let id = self.state.committee.get(i)?;
                self.state.validators.get(id).map(|v| v.pubkey)
            })
            .collect();
        if signer_pks.len() != block.signer_count() {
            return false;
        }
        let msg = beacon_block_header_message(&self.network, block.header());
        let msgs: Vec<&[u8]> = std::iter::repeat_n(msg.as_slice(), signer_pks.len()).collect();
        aggregate_verify_bls_different_messages(&msgs, &block.aggregate_sig(), &signer_pks)
    }

    /// Peer-aggregated block matches the local pending commit: swap
    /// in the peer's aggregate-sig'd block, advance state, reset
    /// per-epoch caches, and bootstrap the next epoch if the local
    /// validator is on the new committee.
    ///
    /// No `Action::BroadcastBeaconBlock` — the peer is already
    /// disseminating it.
    fn adopt_peer_block(&mut self, block: Arc<BeaconBlock>) -> Vec<Action> {
        let pending = self
            .commit_in_progress
            .take()
            .expect("adopt_peer_block requires a pending commit");

        self.state = *pending.new_state;
        self.latest_block = Arc::clone(&block);
        self.spc = None;

        let next_epoch = self.state.current_epoch.next();
        self.proposal_pool.reset(next_epoch);
        self.sig_pool.reset(next_epoch);
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

    /// Classic-BFT commit quorum over the beacon committee:
    /// `⌈2N/3⌉ + 1`. Mirrors `verify_recovery_cert`'s threshold.
    const fn commit_quorum(&self) -> usize {
        let n = self.state.committee.len();
        (2 * n).div_ceil(3) + 1
    }

    /// Sig pool reached quorum: aggregate, build the `BeaconBlock`,
    /// advance `self.state` / `self.latest_block` from the pending
    /// commit, emit commit + broadcast actions, reset per-epoch
    /// caches, and bootstrap the next epoch's `SpcInstance` if local
    /// is on the new committee.
    fn assemble_and_commit(&mut self) -> Vec<Action> {
        let pending = self.commit_in_progress.take().expect("checked by caller");

        let mut signers = SignerBitfield::new(self.state.committee.len());
        let mut sigs = Vec::with_capacity(self.sig_pool.len());
        for (signer, sig) in self.sig_pool.iter() {
            // `position` is in O(n) per signer — committee sizes are
            // small (≤ BEACON_SIGNER_COUNT). Worth a re-look if the
            // committee grows.
            let Some(idx) = self.state.committee.iter().position(|v| v == signer) else {
                warn!(
                    ?signer,
                    "sig from committee member with no position — skipping"
                );
                continue;
            };
            signers.set(idx);
            sigs.push(*sig);
        }

        let aggregate_sig = match Bls12381G2Signature::aggregate(&sigs, true) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "BLS aggregate failed — commit deferred");
                // Replant the pending commit so a future sig can
                // retry. The pool already has the sigs.
                self.commit_in_progress = Some(pending);
                return Vec::new();
            }
        };

        let block = BeaconBlock::new(
            pending.header,
            signers,
            aggregate_sig,
            pending.recovery_cert.map(|c| *c),
        );
        let block_arc = Arc::new(block);

        // Advance committed state.
        self.state = *pending.new_state;
        self.latest_block = Arc::clone(&block_arc);
        self.spc = None;

        // Reset per-epoch caches for the next in-flight epoch.
        let next_epoch = self.state.current_epoch.next();
        self.proposal_pool.reset(next_epoch);
        self.sig_pool.reset(next_epoch);

        let mut actions = vec![
            Action::CommitBeaconBlock {
                block: Arc::clone(&block_arc),
                state: Box::new(self.state.clone()),
            },
            Action::BroadcastBeaconBlock { block: block_arc },
        ];

        // Bootstrap the next epoch's SPC if the new committee
        // includes us, and kick try_propose.
        if self.is_on_committee() {
            self.bootstrap_spc_for_next_epoch();
            actions.extend(self.try_propose());
        }

        actions
    }

    /// SPC has decided this epoch — apply the committed proposal
    /// set to `state` on a clone, derive the resulting header, stash
    /// it as the pending commit, and emit
    /// [`Action::SignAndBroadcastBeaconBlockHeader`].
    ///
    /// The local-state mutation lives on `commit_in_progress` until
    /// quorum sigs land (B.8.c.iv); `self.state` and
    /// `self.latest_block` aren't touched yet so a sig-stall doesn't
    /// half-advance the chain.
    fn on_spc_output_high(
        &mut self,
        epoch: Epoch,
        output: &PcVector,
        recipients: &[ValidatorId],
    ) -> Vec<Action> {
        if self.commit_in_progress.is_some() {
            warn!(
                epoch = epoch.inner(),
                "OutputHigh fired with a commit already pending — ignoring duplicate",
            );
            return Vec::new();
        }
        let committed = self.decode_committed_proposals(epoch, output);
        // Recovery-cert assembly (`RecoveryTracker::try_assemble`) lands in a
        // follow-up; for now every commit is plain-path with no attached cert.
        let recovery_cert: Option<RecoveryCertificate> = None;
        let mut new_state = self.state.clone();
        apply_epoch(
            &mut new_state,
            &self.network,
            epoch,
            &committed,
            recovery_cert.as_ref(),
        );
        let header = BeaconBlockHeader::new(
            epoch,
            self.latest_block.block_hash(),
            compute_proposals_root(&committed),
            state_root(&new_state),
            recovery_cert_hash(recovery_cert.as_ref()),
        );
        self.commit_in_progress = Some(PendingCommit {
            epoch,
            header: header.clone(),
            new_state: Box::new(new_state),
            recovery_cert: recovery_cert.map(Box::new),
        });
        vec![Action::SignAndBroadcastBeaconBlockHeader {
            epoch,
            header: Box::new(header),
            recipients: recipients.to_vec(),
        }]
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
                SpcEffect::OutputHigh(output) => {
                    actions.extend(self.on_spc_output_high(epoch, &output, recipients));
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

    #[must_use]
    pub const fn has_pending_commit(&self) -> bool {
        self.commit_in_progress.is_some()
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
        BeaconBlock, BeaconBlockHash, BeaconBlockHeader, Bls12381G1PublicKey, Epoch,
        NetworkDefinition, Randomness, ShardGroupId, Stake, StakePoolId, ValidatorId,
        bls_keypair_from_seed, state_root,
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
        let spc = coord.spc.as_ref().expect("SPC bootstrapped");
        assert_eq!(spc.epoch(), Epoch::GENESIS.next());
        assert_eq!(spc.current_view(), SpcView::new(1));
        // Bootstrap chains into try_propose which emits the
        // local-proposal build-and-broadcast.
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::BuildAndBroadcastBeaconProposal { .. })),
            "expected BuildAndBroadcastBeaconProposal in {actions:?}",
        );
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
            ValidatorId::new(99), // not on committee
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
            // Stale epoch: not the in-flight one.
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
        let (block, state) = genesis_pair();
        let mut coord = BeaconCoordinator::new(
            block,
            state,
            ValidatorId::new(99),
            NetworkDefinition::simulator(),
        );
        // SPC won't bootstrap because off-committee, but try_propose
        // gates first on `is_on_committee()`.
        assert!(coord.try_propose().is_empty());
    }

    #[test]
    fn try_propose_idempotent_after_own_proposal_in_pool() {
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let first = coord.try_propose();
        assert!(!first.is_empty());
        // Simulate the action-handler feedback path: own proposal
        // arrives back.
        let me = coord.me;
        let in_flight = Epoch::GENESIS.next();
        coord.on_beacon_proposal_received(me, in_flight, sample_proposal(0xAB));
        // Second try_propose sees own entry in pool and drops.
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
        // SPC's view-1 PC fires its sign-and-broadcast-vote-1 effect
        // once we feed input; the lifter turns that into the
        // matching beacon action.
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
            ValidatorId::new(1), // peer, not self
            Epoch::GENESIS.next(),
            sample_proposal(0xAB),
        );
        assert!(actions.is_empty(), "peer proposal alone doesn't kick PC");
        assert!(!coord.spc.as_ref().unwrap().view_one_input_fed());
    }

    #[test]
    fn output_high_builds_header_and_emits_sig_request() {
        use hyperscale_types::PcVector;
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let in_flight = Epoch::GENESIS.next();
        // Populate the pool with every committee member's proposal
        // so decode_committed_proposals can resolve every non-bottom
        // element. Then synthesize an OutputHigh that selects them.
        let committee = coord.state.committee.clone();
        let mut elements = Vec::with_capacity(committee.len());
        for id in &committee {
            let p = sample_proposal(id.inner().try_into().unwrap_or(0u8));
            elements.push(p.pc_element_hash(in_flight));
            coord.proposal_pool.admit(*id, in_flight, p);
        }
        let output = PcVector::new(elements);

        let recipients = coord.spc_recipients();
        let actions = coord.on_spc_output_high(in_flight, &output, &recipients);

        // One sign-request action emitted.
        let [
            Action::SignAndBroadcastBeaconBlockHeader {
                epoch,
                header,
                recipients: _,
            },
        ] = actions.as_slice()
        else {
            panic!("expected SignAndBroadcastBeaconBlockHeader, got {actions:?}");
        };
        assert_eq!(*epoch, in_flight);
        assert_eq!(header.epoch(), in_flight);
        assert_eq!(header.prev_block_hash(), coord.latest_block.block_hash());

        // Pending commit captures the post-apply state + header.
        let pending = coord.commit_in_progress.as_ref().expect("pending stashed");
        assert_eq!(pending.epoch, in_flight);
        assert_eq!(pending.new_state.current_epoch, in_flight);
        assert!(pending.recovery_cert.is_none());

        // The pre-commit state on the coordinator is untouched.
        assert_eq!(coord.state.current_epoch, Epoch::GENESIS);
    }

    fn beacon_sign(seed: u64, msg: &[u8]) -> Bls12381G2Signature {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s).sign_v1(msg)
    }

    /// Build a real VRF-signed proposal for validator `seed` at
    /// `epoch`. Required for `apply_epoch` flows: fake VRFs jail
    /// every committee member on the Performance counter.
    fn sample_real_proposal(seed: u64, epoch: Epoch) -> Arc<BeaconProposal> {
        use hyperscale_types::vrf_sign;
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        let sk = bls_keypair_from_seed(&s);
        let (output, proof) = vrf_sign(&sk, &NetworkDefinition::simulator(), epoch);
        Arc::new(BeaconProposal::vrf_only(output, proof))
    }

    /// Drive an honest n=4 commit flow end-to-end: bootstrap, drain
    /// the local proposal back into the pool, populate peer
    /// proposals, force `OutputHigh`, gather quorum sigs, assert
    /// state and `latest_block` advance and a fresh SPC bootstraps.
    #[test]
    fn quorum_sigs_commit_block_and_advance_state() {
        use hyperscale_types::{PcVector, beacon_block_header_message};
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let in_flight = Epoch::GENESIS.next();
        let committee = coord.state.committee.clone();
        // Populate the pool with every committee member's REAL
        // VRF-signed proposal. Fake VRFs would jail every member on
        // the Performance counter during `apply_epoch`, leaving the
        // next committee empty and skipping the bootstrap path.
        let mut elements = Vec::with_capacity(committee.len());
        for id in &committee {
            let p = sample_real_proposal(id.inner(), in_flight);
            elements.push(p.pc_element_hash(in_flight));
            coord.proposal_pool.admit(*id, in_flight, p);
        }
        let output = PcVector::new(elements);
        let recipients = coord.spc_recipients();
        let _ = coord.on_spc_output_high(in_flight, &output, &recipients);
        let pending_header = coord
            .commit_in_progress
            .as_ref()
            .expect("OutputHigh stashed pending commit")
            .header
            .clone();
        let msg = beacon_block_header_message(&coord.network, &pending_header);

        // Quorum for n=4 is ⌈8/3⌉+1 = 4: every signer needs to
        // contribute. Sign as each committee member (seeds match
        // `sample_genesis()`).
        let mut last_actions = Vec::new();
        for id in &committee {
            let sig = beacon_sign(id.inner(), &msg);
            last_actions = coord.on_beacon_block_sig_received(*id, in_flight, sig);
        }

        // Final admission triggered assembly: commit + broadcast +
        // (try_propose for next epoch).
        assert!(
            last_actions
                .iter()
                .any(|a| matches!(a, Action::CommitBeaconBlock { .. })),
            "expected CommitBeaconBlock in {last_actions:?}",
        );
        assert!(
            last_actions
                .iter()
                .any(|a| matches!(a, Action::BroadcastBeaconBlock { .. })),
            "expected BroadcastBeaconBlock in {last_actions:?}",
        );

        // State advanced; latest_block points at the new block.
        assert_eq!(coord.state.current_epoch, in_flight);
        assert_eq!(coord.latest_block.epoch(), in_flight);
        assert!(coord.commit_in_progress.is_none());
        assert!(coord.sig_pool.is_empty());
        // Pool re-targeted to the next in-flight epoch.
        assert_eq!(coord.proposal_pool.epoch(), in_flight.next());

        // Local is still on committee (genesis committee doesn't
        // rotate on a single commit), so a fresh SPC bootstraps and
        // try_propose emits a new proposal action.
        assert!(coord.spc.is_some());
        assert_eq!(coord.spc.as_ref().unwrap().epoch(), in_flight.next());
        assert!(
            last_actions
                .iter()
                .any(|a| matches!(a, Action::BuildAndBroadcastBeaconProposal { .. })),
            "expected next-epoch BuildAndBroadcastBeaconProposal in {last_actions:?}",
        );
    }

    #[test]
    fn sig_dropped_when_no_pending_commit() {
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        // No OutputHigh yet, so no pending commit.
        let actions = coord.on_beacon_block_sig_received(
            ValidatorId::new(1),
            Epoch::GENESIS.next(),
            Bls12381G2Signature([0u8; 96]),
        );
        assert!(actions.is_empty());
        assert!(coord.sig_pool.is_empty());
    }

    #[test]
    fn sig_dropped_from_non_committee_sender() {
        use hyperscale_types::PcVector;
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let in_flight = Epoch::GENESIS.next();
        let committee = coord.state.committee.clone();
        for id in &committee {
            let p = sample_proposal(id.inner().try_into().unwrap_or(0u8));
            coord.proposal_pool.admit(*id, in_flight, p);
        }
        let output = PcVector::new(committee.iter().map(|_| PcValueElement::ZERO));
        let recipients = coord.spc_recipients();
        let _ = coord.on_spc_output_high(in_flight, &output, &recipients);

        let actions = coord.on_beacon_block_sig_received(
            ValidatorId::new(99), // not on committee
            in_flight,
            Bls12381G2Signature([0u8; 96]),
        );
        assert!(actions.is_empty());
        assert!(coord.sig_pool.is_empty());
    }

    /// Build a syntactically valid `BeaconBlock` at `epoch` whose
    /// aggregate sig is over the produced canonical-bytes — passes
    /// [`verify_beacon_block_aggregate`] without needing to match any
    /// particular pending commit. Roots are arbitrary; the verifier
    /// only checks signer count, bitfield width, and BLS validity.
    fn valid_block_at(
        coord: &BeaconCoordinator,
        epoch: Epoch,
        prev_hash: BeaconBlockHash,
    ) -> Arc<BeaconBlock> {
        use hyperscale_types::{BeaconProposalsRoot, BeaconStateRoot, RecoveryCertHash};
        let header = BeaconBlockHeader::new(
            epoch,
            prev_hash,
            BeaconProposalsRoot::ZERO,
            BeaconStateRoot::ZERO,
            RecoveryCertHash::ZERO,
        );
        let msg = beacon_block_header_message(&coord.network, &header);
        let mut sigs = Vec::with_capacity(coord.state.committee.len());
        for id in &coord.state.committee {
            sigs.push(beacon_sign(id.inner(), &msg));
        }
        let aggregate_sig = Bls12381G2Signature::aggregate(&sigs, true).unwrap();
        let mut signers = SignerBitfield::new(coord.state.committee.len());
        for i in 0..coord.state.committee.len() {
            signers.set(i);
        }
        Arc::new(BeaconBlock::new(header, signers, aggregate_sig, None))
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
        // current = GENESIS = 0; expected = 1; future = 5.
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
        use hyperscale_types::BeaconBlockHash;
        let mut coord = fresh_coord();
        let block = valid_block_at(&coord, Epoch::new(1), BeaconBlockHash::ZERO);
        let actions = coord.on_beacon_block_received(block);
        assert!(actions.is_empty());
        assert!(coord.pending_blocks.is_empty());
    }

    #[test]
    fn on_beacon_block_received_drops_invalid_aggregate() {
        use hyperscale_types::{
            BeaconBlockHeader, BeaconProposalsRoot, BeaconStateRoot, RecoveryCertHash,
        };
        let mut coord = fresh_coord();
        let prev = coord.latest_block.block_hash();
        let header = BeaconBlockHeader::new(
            Epoch::new(1),
            prev,
            BeaconProposalsRoot::ZERO,
            BeaconStateRoot::ZERO,
            RecoveryCertHash::ZERO,
        );
        // Full signer bitfield, but a zero (invalid) aggregate sig.
        let mut signers = SignerBitfield::new(coord.state.committee.len());
        for i in 0..coord.state.committee.len() {
            signers.set(i);
        }
        let block = Arc::new(BeaconBlock::new(
            header,
            signers,
            Bls12381G2Signature([0u8; 96]),
            None,
        ));
        let actions = coord.on_beacon_block_received(block);
        assert!(actions.is_empty());
        assert!(coord.pending_blocks.is_empty());
    }

    #[test]
    fn on_beacon_block_received_buffers_when_no_pending_commit() {
        let mut coord = fresh_coord();
        let prev = coord.latest_block.block_hash();
        let block = valid_block_at(&coord, Epoch::new(1), prev);
        let block_hash = block.block_hash();
        // No commit_in_progress (we haven't reached OutputHigh) — block
        // is valid but can't be adopted into the local apply path yet.
        let actions = coord.on_beacon_block_received(block);
        assert!(actions.is_empty());
        assert_eq!(coord.pending_blocks.len(), 1);
        assert!(coord.pending_blocks.contains_key(block_hash));
    }

    /// Drive a coordinator to `OutputHigh` + `commit_in_progress` using
    /// the same path `quorum_sigs_commit_block_and_advance_state` uses,
    /// then return the locally-derived header so a sibling coordinator
    /// can synthesise the peer-aggregated block that triggers
    /// adoption.
    fn drive_to_pending_commit(coord: &mut BeaconCoordinator) -> (Epoch, BeaconBlockHeader) {
        use hyperscale_types::PcVector;
        coord.bootstrap_spc_for_next_epoch();
        let in_flight = Epoch::GENESIS.next();
        let committee = coord.state.committee.clone();
        let mut elements = Vec::with_capacity(committee.len());
        for id in &committee {
            let p = sample_real_proposal(id.inner(), in_flight);
            elements.push(p.pc_element_hash(in_flight));
            coord.proposal_pool.admit(*id, in_flight, p);
        }
        let output = PcVector::new(elements);
        let recipients = coord.spc_recipients();
        let _ = coord.on_spc_output_high(in_flight, &output, &recipients);
        let header = coord
            .commit_in_progress
            .as_ref()
            .expect("OutputHigh stashed pending commit")
            .header
            .clone();
        (in_flight, header)
    }

    #[test]
    fn on_beacon_block_received_adopts_matching_peer_block() {
        let mut coord = fresh_coord();
        let (in_flight, header) = drive_to_pending_commit(&mut coord);
        // Synthesise the peer-aggregated block that the rest of the
        // committee would have built off the same `OutputHigh`. The
        // sim's `assemble_and_commit` produces a byte-identical
        // header across replicas, so we sign THIS header (which is
        // also `commit_in_progress.header`) with every committee
        // member.
        let msg = beacon_block_header_message(&coord.network, &header);
        let mut sigs = Vec::with_capacity(coord.state.committee.len());
        for id in &coord.state.committee {
            sigs.push(beacon_sign(id.inner(), &msg));
        }
        let aggregate_sig = Bls12381G2Signature::aggregate(&sigs, true).unwrap();
        let mut signers = SignerBitfield::new(coord.state.committee.len());
        for i in 0..coord.state.committee.len() {
            signers.set(i);
        }
        let peer_block = Arc::new(BeaconBlock::new(header, signers, aggregate_sig, None));
        let peer_block_hash = peer_block.block_hash();

        let actions = coord.on_beacon_block_received(Arc::clone(&peer_block));

        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::CommitBeaconBlock { .. })),
            "expected CommitBeaconBlock in {actions:?}",
        );
        // Adoption skips BroadcastBeaconBlock — peer is disseminating.
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::BroadcastBeaconBlock { .. })),
            "adoption path should not re-broadcast",
        );
        assert_eq!(coord.state.current_epoch, in_flight);
        assert_eq!(coord.latest_block.block_hash(), peer_block_hash);
        assert!(coord.commit_in_progress.is_none());
        assert!(coord.spc.is_some(), "next epoch's SPC should bootstrap");
    }

    #[test]
    fn on_beacon_block_received_drops_when_header_differs_from_pending() {
        let mut coord = fresh_coord();
        let (_in_flight, _header) = drive_to_pending_commit(&mut coord);
        // Build a block at the right epoch with the right prev_hash
        // but DIFFERENT header roots — won't match `commit_in_progress`
        // even though the aggregate sig is valid.
        let prev = coord.latest_block.block_hash();
        let other_block = valid_block_at(&coord, Epoch::new(1), prev);
        let pending_hash_before = coord.commit_in_progress.as_ref().unwrap().header.hash();
        assert_ne!(other_block.block_hash(), pending_hash_before);

        let actions = coord.on_beacon_block_received(other_block);
        assert!(actions.is_empty());
        // Pending commit still in place; state still at genesis.
        assert!(coord.commit_in_progress.is_some());
        assert_eq!(coord.state.current_epoch, Epoch::GENESIS);
    }

    #[test]
    fn output_high_drops_duplicate_commit() {
        use hyperscale_types::PcVector;
        let mut coord = fresh_coord();
        coord.bootstrap_spc_for_next_epoch();
        let in_flight = Epoch::GENESIS.next();
        let committee = coord.state.committee.clone();
        let mut elements = Vec::with_capacity(committee.len());
        for id in &committee {
            let p = sample_proposal(id.inner().try_into().unwrap_or(0u8));
            elements.push(p.pc_element_hash(in_flight));
            coord.proposal_pool.admit(*id, in_flight, p);
        }
        let output = PcVector::new(elements);
        let recipients = coord.spc_recipients();

        let first = coord.on_spc_output_high(in_flight, &output, &recipients);
        assert!(!first.is_empty());
        // A second OutputHigh for the same epoch (shouldn't happen
        // under honest execution, but defensive guard) is a no-op.
        let second = coord.on_spc_output_high(in_flight, &output, &recipients);
        assert!(second.is_empty());
    }
}
