//! The identity-free follower of the beacon chain.
//!
//! [`BeaconFold`] receives, verifies and adopts committed beacon blocks,
//! folds each into the [`BeaconState`] and the topology schedule, and
//! tracks the source-shard headers and witness chunks every proposal and
//! commit reads. It signs nothing and holds no validator identity: its
//! host drives one [`BeaconParticipant`](crate::participant::BeaconParticipant)
//! per hosted identity against it.

use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::mem;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_core::{BeaconAction, BeaconBlockCheck, BeaconFetchIds, TimerId};
use hyperscale_hbor::Capped;
use hyperscale_types::{
    BeaconBlock, BeaconCert, BeaconProposal, BeaconProposalVerifyContext, BeaconState, BlockHash,
    BlockHeight, CandidateBeaconBlock, CertifiedBeaconBlock, CertifiedBeaconBlockVerifyError,
    CertifiedBlockHeader, CommitProofVerifyError, ConsensusPublicKey, Epoch, GenesisConfigHash,
    Hash, LeafIndex, LocalTimestamp, NetworkDefinition, PcVoteEquivocationContext,
    RATIFY_ROUND_TIMEOUT, RatifyRound, SKIP_TIMEOUT, ShardForkProofVerifyError, ShardId,
    ShardVoteEquivocationContext, ShardWitnessPayload, SlotEffects, TopologySchedule,
    TopologySnapshot, ValidatorId, Verifiable, Verified, Verifier, WeightedTimestamp,
};
use tracing::{trace, warn};

use crate::coordinator::{LocalChainAnchors, resumed_schedule, retention_floor, widen_schedule};
use crate::participant::{BeaconParticipant, ProposalAdmission};
use crate::shard_source::{ChunkFetchId, ShardSourceTracker};
use crate::state::{apply_epoch, apply_input_for};
use crate::verification::BeaconVerificationPipeline;
use crate::{boundary, rules};

/// Human-readable discriminator for a block's authenticating cert,
/// for diagnostics.
const fn cert_kind(cert: &BeaconCert) -> &'static str {
    match cert {
        BeaconCert::Genesis(_) => "genesis",
        BeaconCert::Normal { .. } => "normal",
        BeaconCert::Skip(_) => "skip",
    }
}

/// A token naming one shard chain registered with the fold, unique
/// within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainRegistration(u64);

/// One shard chain registered with the fold, as the fold tracks it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostedChain {
    /// The shard the chain runs.
    pub shard: ShardId,
    /// Highest committed height whose anchors are folded in. A report at
    /// or below it shifts nothing.
    pub height: BlockHeight,
    /// The anchors the chain's committed tip carries.
    pub anchors: LocalChainAnchors,
    /// Set, never cleared, once the fold's own schedule reads the chain's
    /// committed block anchor past its shard's terminal. A latched chain
    /// holds no window open: its terminal record pins what its evidence
    /// names, and the windows past that are evicted with nothing left to
    /// read them.
    pub terminal_committed: bool,
}

/// What one adoption produced: the slot effects the fold returned, for
/// the participants' own reading, and the fold's own actions.
pub struct Adopted {
    /// The epoch the block folded.
    pub epoch: Epoch,
    /// What the epoch's fold settled, for each participant to read.
    pub effects: SlotEffects,
    /// The fold's own actions: the commit, the topology and the witness
    /// fetches the adoption released.
    pub actions: Vec<BeaconAction>,
}

/// A follower of the beacon chain.
pub struct BeaconFold {
    /// Scheme verifier for proposal, cert, and equivocation checks.
    pub(crate) verifier: Arc<dyn Verifier>,

    pub(crate) state: BeaconState,

    /// Latest committed beacon block paired with its authenticating
    /// cert. Carried so SPC instance bootstrap and ratify anchor
    /// checks read `prev_block_hash` without a storage roundtrip.
    pub(crate) latest_block: Verified<CertifiedBeaconBlock>,

    /// Beacon committee that governed the tip epoch, captured before
    /// its fold advanced the state. A competing block for the adopted
    /// epoch verifies against the sets that governed it, not the sets
    /// the fold derived from it — the current state's committee may
    /// have rotated. On a restart the constructor recovers this from
    /// the penultimate history state when one is loaded; otherwise the
    /// live state stands in until the next commit.
    tip_epoch_committee: Vec<(ValidatorId, ConsensusPublicKey)>,
    /// Active pool that governed the tip epoch — the signer base for a
    /// competing block's ratify cert. Same capture discipline as
    /// `tip_epoch_committee`.
    tip_epoch_pool: Vec<(ValidatorId, ConsensusPublicKey)>,

    /// In-flight block-certificate verifications. Dedup-only — the
    /// payload rides through the dispatch/result round-trip in the
    /// action and event themselves, not stashed here.
    pub(crate) verification: BeaconVerificationPipeline,

    /// Per-shard header records, validated-witness pool, and
    /// in-flight fetches; drives proposal-readiness and the
    /// witness drain.
    pub(crate) shard_source: ShardSourceTracker,

    /// Whether any identity the fold's host runs a participant for sits
    /// on the beacon committee, as the host reports it. Witness chunks
    /// are fetched and pooled only while it holds.
    host_on_committee: bool,

    /// Per-epoch committee schedule. Its head is the current epoch's
    /// committee (refreshed on every adoption so consumers reading via
    /// `io_loop`'s `ArcSwap` see the post-`apply_epoch` placement immediately
    /// after commit); its `at` resolves any artifact's committee by weighted
    /// timestamp over the window from [`retention_floor`] through
    /// `current_epoch + 1`. The `+1` lookahead entry is finalized an epoch
    /// before its window opens. A node-local cache, not consensus-critical.
    pub(crate) topology_schedule: Arc<TopologySchedule>,

    /// The shard chains registered with the fold, each with its committed
    /// frontier.
    pub(crate) hosted: BTreeMap<ChainRegistration, HostedChain>,
    next_registration: u64,

    /// Mixed into every signing helper's domain bytes; carried so
    /// per-epoch SPC instances and outbound canonical-bytes
    /// encoders don't re-thread it from the runner.
    pub(crate) network: NetworkDefinition,

    /// Local wall-clock time. Drives the epoch-cadence timers; never
    /// fed into deterministic consensus computations — use
    /// `state.current_epoch` or weighted timestamps for that.
    pub(crate) now: LocalTimestamp,
}

impl BeaconFold {
    /// Build the fold from `latest_block` and a `history` of
    /// recently-committed states (newest last; `history.last()` becomes
    /// the live state). Each state seeds the topology schedule with its
    /// active and lookahead snapshots, so the fold boots able to verify
    /// cross-shard artifacts back across the loaded window. When
    /// `latest_block` is genesis, debug-asserts its cert's `config_hash`
    /// matches `expected_config_hash` — catches a runner that loaded a
    /// chain initialised by a different operator TOML than this process
    /// is configured for.
    ///
    /// # Panics
    ///
    /// Panics if `history` is empty. In debug builds, also panics if
    /// `latest_block.is_genesis()` and the cert's `config_hash` doesn't
    /// match `expected_config_hash`.
    pub fn new(
        verifier: Arc<dyn Verifier>,
        latest_block: Verified<CertifiedBeaconBlock>,
        history: Vec<impl Borrow<BeaconState>>,
        network: NetworkDefinition,
        expected_config_hash: GenesisConfigHash,
    ) -> Self {
        const LATEST_STATE_EXPECT: &str = "history must carry at least the latest committed state";
        if let BeaconCert::Genesis(config_hash) = latest_block.cert() {
            debug_assert_eq!(
                *config_hash, expected_config_hash,
                "genesis block config_hash doesn't match operator config",
            );
        }
        let latest = history.last().expect(LATEST_STATE_EXPECT).borrow();
        let latest_epoch = latest.current_epoch;
        let mut topology_schedule = resumed_schedule(&history, &network);
        // No fold published the genesis window, so at genesis it is its
        // own first publication. A schedule resumed past genesis holds
        // each window as the state before it projected it, and where its
        // history lacks that state the window stays unpublished here.
        if matches!(latest_block.cert(), BeaconCert::Genesis(_)) {
            let head = Arc::clone(topology_schedule.head());
            topology_schedule.insert_lookahead(latest_epoch, head);
        }
        // The tip epoch's signer sets come from the state *before* its
        // fold when the loaded history carries one; the live state
        // stands in otherwise (see the field docs).
        let tip_epoch_source = if history.len() >= 2 {
            history[history.len() - 2].borrow()
        } else {
            latest
        };
        let tip_epoch_committee = tip_epoch_source.derive_beacon_committee();
        let tip_epoch_pool = tip_epoch_source.derive_active_pool();
        let state = history
            .into_iter()
            .next_back()
            .expect(LATEST_STATE_EXPECT)
            .borrow()
            .clone();
        Self {
            verifier,
            state,
            latest_block,
            tip_epoch_committee,
            tip_epoch_pool,
            verification: BeaconVerificationPipeline::new(),
            shard_source: ShardSourceTracker::new(),
            host_on_committee: false,
            topology_schedule: Arc::new(topology_schedule),
            hosted: BTreeMap::new(),
            next_registration: 0,
            network,
            now: LocalTimestamp::ZERO,
        }
    }

    /// Track a shard chain from its recovered committed `height` and the
    /// anchors its tip carries.
    pub fn register_chain(
        &mut self,
        shard: ShardId,
        anchors: LocalChainAnchors,
        height: BlockHeight,
    ) -> ChainRegistration {
        let token = ChainRegistration(self.next_registration);
        self.next_registration += 1;
        let mut chain = HostedChain {
            shard,
            height,
            anchors,
            terminal_committed: false,
        };
        latch_terminal(&self.topology_schedule, &mut chain);
        self.hosted.insert(token, chain);
        token
    }

    /// Stop tracking the chain `token` names. A later input that carries
    /// it is ignored, so a rebuilt chain's old loop cannot touch the
    /// entry its successor registered.
    pub fn deregister_chain(&mut self, token: ChainRegistration) {
        self.hosted.remove(&token);
    }

    /// Whether any identity the fold's host runs a participant for sits
    /// on the beacon committee. Joining fetches the witness chunk of
    /// every crossing the fold already holds, which no further header
    /// may arrive to ask for; leaving drops the pooled witness chunks and
    /// releases the in-flight witness fetches.
    pub fn set_host_on_committee(&mut self, on: bool) -> Vec<BeaconAction> {
        let was = mem::replace(&mut self.host_on_committee, on);
        match (was, on) {
            (false, true) => {
                // Collected up front: `fetch_witness_chunk` borrows `self`
                // mutably, so the loop can't hold the `boundaries` iterator.
                let shards: Vec<ShardId> = self.state.boundaries.keys().copied().collect();
                let mut actions = Vec::new();
                for shard in shards {
                    actions.extend(self.fetch_witness_chunk(shard));
                }
                actions
            }
            (true, false) => abandon_witnesses(self.shard_source.evicted_from_committee()),
            _ => Vec::new(),
        }
    }

    /// The registered pubkey for `validator`, from the fold's permanent
    /// registry. Resolves ex-members and revoked keys alike — exactly
    /// what double-vote evidence about a rotated-out signer needs.
    #[must_use]
    pub fn validator_pubkey(&self, validator: ValidatorId) -> Option<ConsensusPublicKey> {
        self.state.validators.get(&validator).map(|r| r.pubkey)
    }

    /// The committed state at the tip.
    #[must_use]
    pub const fn state(&self) -> &BeaconState {
        &self.state
    }

    /// The tip: the latest adopted block.
    #[must_use]
    pub const fn latest_block(&self) -> &Verified<CertifiedBeaconBlock> {
        &self.latest_block
    }

    /// The topology schedule the fold keeps, from the retention floor
    /// through the lookahead.
    #[must_use]
    pub fn schedule(&self) -> &TopologySchedule {
        &self.topology_schedule
    }

    /// [`Self::schedule`], shared: the copy the fold's next adoption
    /// leaves alone, cloning its own before it changes it.
    #[must_use]
    pub const fn shared_schedule(&self) -> &Arc<TopologySchedule> {
        &self.topology_schedule
    }

    /// Insert the windows `history` carries below the schedule's oldest
    /// retained epoch — see [`widen_schedule`](crate::coordinator::widen_schedule).
    pub fn widen<B: Borrow<BeaconState>>(&mut self, history: &[B]) {
        widen_schedule(
            Arc::make_mut(&mut self.topology_schedule),
            history,
            &self.network,
        );
    }

    /// The source-shard headers and witness chunks the fold holds.
    #[must_use]
    pub const fn shard_source(&self) -> &ShardSourceTracker {
        &self.shard_source
    }

    /// The chain `token` names, while it is registered.
    #[must_use]
    pub fn chain(&self, token: ChainRegistration) -> Option<&HostedChain> {
        self.hosted.get(&token)
    }

    /// Every registered chain, by token.
    pub fn chains(&self) -> impl Iterator<Item = (ChainRegistration, &HostedChain)> {
        self.hosted.iter().map(|(token, chain)| (*token, chain))
    }

    /// The scheme verifier the fold checks certificates with.
    #[must_use]
    pub const fn verifier(&self) -> &Arc<dyn Verifier> {
        &self.verifier
    }

    /// The network identity bound into every beacon signature.
    #[must_use]
    pub const fn network(&self) -> &NetworkDefinition {
        &self.network
    }

    /// The clock the epoch-cadence timers read.
    #[must_use]
    pub const fn now(&self) -> LocalTimestamp {
        self.now
    }

    /// Set the clock every handler in the next batch reads.
    pub const fn set_now(&mut self, now: LocalTimestamp) {
        self.now = now;
    }

    /// The live topology snapshot: the schedule's head.
    #[must_use]
    pub(crate) fn current_topology_snapshot(&self) -> &Arc<TopologySnapshot> {
        self.topology_schedule.head()
    }

    /// A peer-aggregated [`BeaconBlock`] arrived via the beacon gossip
    /// topic. After structural checks, dispatch cert verification to
    /// the crypto pool and stash the block until the result lands; on
    /// success [`Self::on_beacon_block_verified`] hands the verified
    /// block off to [`Self::adopt`]. A block more than one epoch
    /// ahead of the local tip is dropped and triggers gap-fill sync
    /// ([`BeaconAction::StartBeaconBlockSync`]) to fetch the missing epochs in
    /// order.
    ///
    /// Cert verification uses `self.state.committee` for Normal blocks
    /// and the active pool for Skip blocks. Committee rotation across
    /// epochs means an off-committee observer whose state has fallen
    /// behind the actual signing committee will reject otherwise-valid
    /// blocks. Resolving that without `apply_epoch` is a state-sync
    /// problem handled elsewhere.
    pub fn on_beacon_block_received(
        &mut self,
        block: Verifiable<CertifiedBeaconBlock>,
    ) -> Vec<BeaconAction> {
        let epoch = block.epoch();
        let tip_epoch = self.latest_block.epoch();
        if epoch <= tip_epoch {
            if let Some(actions) = self.tip_competitor_verification(&block) {
                return actions;
            }
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
                "BeaconBlockReceived for future epoch — triggering sync",
            );
            // Drop the unverified block and let gap-fill sync fetch the
            // missing epochs in order from storage-backed peers. The
            // claimed epoch is only a target hint — the runner's sync
            // backs off on epochs that don't exist, so a bogus far-future
            // epoch can't busy-loop the network.
            return vec![BeaconAction::StartBeaconBlockSync { target: epoch }];
        }

        if block.prev_block_hash() != self.latest_block.block_hash() {
            warn!(
                epoch = epoch.inner(),
                "BeaconBlockReceived with mismatched prev_block_hash — dropping",
            );
            return Vec::new();
        }
        // Structural checks pass. The ratify cert's own anchor/epoch
        // binding to the block is the pairing invariant, enforced at
        // wire decode.
        if matches!(block.cert(), BeaconCert::Genesis(_)) {
            warn!(
                epoch = epoch.inner(),
                "BeaconBlockReceived with Genesis cert past tip — dropping",
            );
            return Vec::new();
        }
        let committee = self.state.derive_beacon_committee();
        let active_pool = self.state.derive_active_pool();
        let equivocation_signers = self.equivocation_signers_for(block.block());
        self.dispatch_block_verification(block, committee, active_pool, equivocation_signers)
    }

    /// Dispatch verification for a block that competes with the adopted
    /// tip: same epoch, same parent, different hash. A validly certified
    /// competitor is self-proving evidence of two ratification commit
    /// certificates for one epoch — more than a third of the pool
    /// double-signed — and [`Self::on_beacon_block_verified`] halts on
    /// it: the divergence is detected loudly rather than carried
    /// silently. Returns `None` when `block` is not a tip competitor
    /// (the caller's ordinary drop/sync handling applies).
    ///
    /// Verification runs against the signer sets that governed the tip
    /// epoch (`tip_epoch_committee` / `tip_epoch_pool`), captured at
    /// adoption — the live state's sets are post-fold.
    fn tip_competitor_verification(
        &mut self,
        block: &Verifiable<CertifiedBeaconBlock>,
    ) -> Option<Vec<BeaconAction>> {
        if block.epoch() != self.latest_block.epoch()
            || block.epoch() == Epoch::GENESIS
            || block.prev_block_hash() != self.latest_block.prev_block_hash()
            || block.block_hash() == self.latest_block.block_hash()
            || matches!(block.cert(), BeaconCert::Genesis(_))
        {
            return None;
        }
        warn!(
            epoch = block.epoch().inner(),
            competitor = ?block.block_hash(),
            adopted = ?self.latest_block.block_hash(),
            "BeaconBlock competes with the adopted tip — dispatching cert verification",
        );
        let equivocation_signers = self.equivocation_signers_for(block.block());
        Some(self.dispatch_block_verification(
            block.clone(),
            self.tip_epoch_committee.clone(),
            self.tip_epoch_pool.clone(),
            equivocation_signers,
        ))
    }

    /// Pubkey lookup covering every validator referenced by
    /// `PcVoteEquivocation` in `block`'s committed proposals.
    /// Returns an empty `Vec` when the block carries no equivocations —
    /// the common path. Validators referenced by evidence but missing
    /// from `state.validators` are silently elided; the verifier rejects
    /// such evidence at admission via the pubkey-lookup miss.
    pub(crate) fn equivocation_signers_for(
        &self,
        block: &BeaconBlock,
    ) -> Vec<(ValidatorId, ConsensusPublicKey)> {
        let mut signers: Vec<(ValidatorId, ConsensusPublicKey)> = Vec::new();
        let mut seen: BTreeSet<ValidatorId> = BTreeSet::new();
        for (_, proposal) in block.committed_proposals() {
            for ev in proposal.equivocations() {
                if seen.insert(ev.validator)
                    && let Some(rec) = self.state.validators.get(&ev.validator)
                {
                    signers.push((ev.validator, rec.pubkey));
                }
            }
        }
        signers
    }

    /// Dispatch a block's cert + equivocation verification. Returns a
    /// single [`BeaconAction::VerifyBeaconBlock`] on a fresh slot, or an empty
    /// vector when the slot is already in flight or already verified —
    /// the in-flight slot's result drives admission for any duplicate.
    fn dispatch_block_verification(
        &mut self,
        block: Verifiable<CertifiedBeaconBlock>,
        committee: Vec<(ValidatorId, ConsensusPublicKey)>,
        active_pool: Vec<(ValidatorId, ConsensusPublicKey)>,
        equivocation_signers: Vec<(ValidatorId, ConsensusPublicKey)>,
    ) -> Vec<BeaconAction> {
        if !self.verification.mark_block_in_flight(block.block_hash()) {
            return Vec::new();
        }
        vec![BeaconAction::VerifyBeaconBlock(BeaconBlockCheck {
            block,
            committee,
            active_pool,
            equivocation_signers,
        })]
    }

    /// A previously-dispatched [`BeaconAction::VerifyBeaconBlock`] has
    /// returned. Clear the pipeline slot, and on the `Ok` arm adopt
    /// the verified block (unless the tip has since moved past it).
    /// Drops silently on the `Err` arm.
    ///
    /// Stale or duplicate results (slot wasn't in flight) are
    /// tolerated.
    ///
    /// # Panics
    ///
    /// Panics when the verified block competes with the adopted tip —
    /// same epoch, same parent, different hash. Every block carries a
    /// pool ratify cert, so two validly certified blocks for one epoch
    /// mean intersecting pool signers equivocated; there is no
    /// reconciliation between the blocks, so the replica halts with
    /// the evidence rather than continuing on a forked beacon chain.
    pub fn on_beacon_block_verified(
        &mut self,
        result: Result<Verified<CertifiedBeaconBlock>, CertifiedBeaconBlockVerifyError>,
    ) -> Option<Adopted> {
        let block = match result {
            Ok(b) => b,
            Err(err) => {
                warn!(%err, "BeaconBlock cert verification failed — dropping");
                return None;
            }
        };
        let block_hash = block.block_hash();
        // A validly certified block for the adopted epoch, extending the
        // same parent, with a different hash: the ratify quorums behind
        // the two certs intersect, so some pool signers equivocated.
        // There is no reconciliation — every fact the fold derives
        // (committees, schedule, pricing) diverges from here — so halt
        // with the evidence rather than keep operating on a forked
        // beacon chain.
        if block.epoch() == self.latest_block.epoch()
            && block.epoch() > Epoch::GENESIS
            && block.prev_block_hash() == self.latest_block.prev_block_hash()
            && block_hash != self.latest_block.block_hash()
        {
            panic!(
                "beacon dual commit detected: epoch {} carries two validly certified blocks — \
                 adopted {:?} ({} cert) and competitor {:?} ({} cert) both extend {:?}; \
                 halting rather than continuing on a forked beacon chain",
                block.epoch().inner(),
                self.latest_block.block_hash(),
                cert_kind(self.latest_block.cert()),
                block_hash,
                cert_kind(block.cert()),
                block.prev_block_hash(),
            );
        }
        // Idempotency: another path (local ratify cert assembly, an
        // earlier peer-broadcast adoption) may have already advanced
        // the tip at or past this block's epoch.
        if block.epoch() <= self.state.current_epoch
            || block.prev_block_hash() != self.latest_block.block_hash()
        {
            trace!(
                block_epoch = block.epoch().inner(),
                tip_epoch = self.state.current_epoch.inner(),
                "Verified BeaconBlock no longer chains off the tip — dropping",
            );
            return None;
        }
        // The SPC cert authenticates `committed_proposals`, not the
        // `shard_contributions` projected from them. Re-derive the
        // canonical projection and require the block to match it, so a
        // Byzantine assembler's variant (fabricated, stale, extra, or
        // omitted contribution) can't fork the boundary fold off the
        // committed inputs.
        if !rules::contributions_well_formed(&self.state, block.block()) {
            warn!(
                epoch = block.epoch().inner(),
                "Verified BeaconBlock has malformed shard contributions — dropping",
            );
            self.verification.forget_block(block_hash);
            return None;
        }
        self.verification.forget_block(block_hash);
        self.adopt(block)
    }

    /// Fold `block` into the state, the schedule and the hosted chains'
    /// latches, and evict what every consumer frontier has passed. Only
    /// the epoch after the tip adopts: every path that certifies an
    /// epoch reaches here, and the first to arrive is the one that
    /// folds it, so `apply_epoch` never sees a regression.
    pub fn adopt(&mut self, block: Verified<CertifiedBeaconBlock>) -> Option<Adopted> {
        let epoch = block.epoch();
        if epoch != self.state.current_epoch.next() {
            return None;
        }
        // The sets governing the epoch being adopted, captured before
        // its fold advances them — a competing block for this epoch
        // verifies against these.
        self.tip_epoch_committee = self.state.derive_beacon_committee();
        self.tip_epoch_pool = self.state.derive_active_pool();
        let input = apply_input_for(&block);
        let effects = apply_epoch(
            self.verifier.as_ref(),
            &mut self.state,
            &self.network,
            block.epoch(),
            input,
        );
        self.latest_block = block.clone();

        // Refresh the head and record the active snapshot for the just-applied
        // epoch plus the lookahead for the next, then drop entries every
        // consumer frontier has passed. The lookahead entry lets a shard
        // resolve its committee a full epoch before its window opens.
        let head = Arc::new(self.state.derive_topology_snapshot(self.network.clone()));
        let epoch = self.state.current_epoch;
        let schedule = Arc::make_mut(&mut self.topology_schedule);
        schedule.set_head(Arc::clone(&head));
        schedule.insert(epoch, head);
        let lookahead = Arc::new(
            self.state
                .derive_next_topology_snapshot(self.network.clone()),
        );
        schedule.insert_lookahead(epoch.next(), lookahead);
        // Latched before the eviction reads the floor: a chain caught up
        // to its terminal whose last commit preceded this fold reads past
        // its terminal only now, and only while its window is held.
        for chain in self.hosted.values_mut() {
            latch_terminal(&self.topology_schedule, chain);
        }
        let floor = retention_floor(&self.state, self.hosted_committee_floor(), self.now);
        Arc::make_mut(&mut self.topology_schedule).evict_below(floor);

        // Evict chunks the boundary fold has now consumed — those starting
        // below each shard's advanced applied watermark
        // (`boundaries[shard].witness_leaf_count`).
        let consumed: Vec<(ShardId, u64)> = self
            .state
            .boundaries
            .iter()
            .map(|(shard, boundary)| (*shard, boundary.witness_leaf_count.inner()))
            .collect();
        let mut abandoned_witness_ids: Vec<ChunkFetchId> = Vec::new();
        for (shard, watermark) in consumed {
            abandoned_witness_ids.extend(self.shard_source.evict_consumed(shard, watermark));
        }
        abandoned_witness_ids.extend(self.retire_departed_sources());
        self.shard_source.clear_proven_boundaries();

        // TopologyChanged emits on every commit, whether or not the
        // committee actually changed. The commit precedes it so a shard
        // never hears of an epoch that is not yet durable.
        let mut actions = vec![
            BeaconAction::CommitBeaconBlock {
                block,
                state: Box::new(self.state.clone()),
            },
            BeaconAction::TopologyChanged {
                epoch: self.state.current_epoch,
                schedule: Arc::clone(&self.topology_schedule),
            },
        ];
        // Release in-flight witness fetches the boundary fold just consumed
        // — their leaves are below the advanced watermark, so a future
        // contribution can't include them and the runner's slot should
        // free rather than pin on a payload the tracker would only evict.
        actions.extend(abandon_witnesses(abandoned_witness_ids));
        Some(Adopted {
            epoch,
            effects,
            actions,
        })
    }

    /// The oldest committee anchor a hosted chain still keys schedule
    /// lookups on, or `None` when no unlatched chain is hosted.
    fn hosted_committee_floor(&self) -> Option<WeightedTimestamp> {
        self.hosted
            .values()
            .filter(|chain| !chain.terminal_committed)
            .map(|chain| chain.anchors.committee)
            .min()
    }

    /// A hosted chain committed the block `certified_header` heads. The
    /// header is recorded as any source header is; the first report of a
    /// height above the chain's own shifts both anchors up a hop, so
    /// [`LocalChainAnchors::committee`] names the committee that signed
    /// the new tip and [`retention_floor`] keeps the schedule open for it.
    /// A report at or below the chain's height shifts nothing, so a
    /// height reported more than once moves the frontier once.
    pub fn on_local_block_committed(
        &mut self,
        token: ChainRegistration,
        certified_header: &Verified<CertifiedBlockHeader>,
    ) -> Vec<BeaconAction> {
        if !self.hosted.contains_key(&token) {
            return Vec::new();
        }
        let actions = self.on_source_header(certified_header);
        let Some(chain) = self.hosted.get_mut(&token) else {
            return actions;
        };
        if certified_header.height() <= chain.height {
            return actions;
        }
        // The block's own anchor selects the committee of the block
        // *after* it. The committee that signed the block just committed
        // anchors one hop back — the value the previous commit reported —
        // so the retained anchor trails by one.
        let block_anchor = certified_header.header().parent_qc().weighted_timestamp();
        chain.anchors.committee = mem::replace(&mut chain.anchors.block, block_anchor);
        chain.height = certified_header.height();
        latch_terminal(&self.topology_schedule, chain);
        actions
    }

    /// Record a hosted chain's own header the moment it certifies, ahead
    /// of its commit. The witness chunk is not fetched here: the local
    /// shard's chunk is served from this host's own store, the store
    /// holds a block only once it commits, and an empty answer re-drives
    /// the fetch at once, so the committed header fetches it.
    pub fn on_certified_local_header(
        &mut self,
        token: ChainRegistration,
        certified_header: &Verified<CertifiedBlockHeader>,
    ) {
        if self.hosted.contains_key(&token) {
            self.record_source_header(certified_header);
        }
    }

    /// Record a verified source-shard header — a remote shard's via the
    /// remote-header path, or a hosted shard's from its own commit
    /// stream — and note any epoch-boundary crossing it makes visible.
    /// A header is held even while the fold is off the committee, so a
    /// validator drawn onto it admits boundary QCs against the history
    /// already held rather than abstaining until fresh headers arrive.
    /// On the committee the fold also fetches the witness chunk of the
    /// shard's latest observed crossing via
    /// [`fetch_witness_chunk`](Self::fetch_witness_chunk).
    pub fn on_source_header(
        &mut self,
        certified_header: &Verified<CertifiedBlockHeader>,
    ) -> Vec<BeaconAction> {
        self.record_source_header(certified_header);
        if !self.host_on_committee {
            return Vec::new();
        }
        self.fetch_witness_chunk(certified_header.header().shard_id())
    }

    /// Hold a commit-proven boundary block if any of `participants`
    /// asked for it, so proposal admission reads it until the next
    /// adoption clears it. Returns whether it is held, and so whether the
    /// askers' awaiting proposals want re-evaluating.
    pub fn admit_proven_for<'a>(
        &mut self,
        certified_header: &Verified<CertifiedBlockHeader>,
        participants: impl IntoIterator<Item = &'a BeaconParticipant>,
    ) -> bool {
        let (shard, height) = (certified_header.shard_id(), certified_header.height());
        if !participants
            .into_iter()
            .any(|participant| participant.asked(shard, height))
        {
            return false;
        }
        self.shard_source
            .admit_proven_boundary(certified_header.clone());
        true
    }

    /// Hold `certified_header` in the shard's window and note any
    /// epoch-boundary crossing it makes visible.
    fn record_source_header(&mut self, certified_header: &Verified<CertifiedBlockHeader>) {
        self.shard_source
            .on_verified_source_header(certified_header.clone());
        self.shard_source.observe_crossing(
            certified_header.header().shard_id(),
            self.state.chain_config.epoch_windows(),
        );
    }

    /// A shard-witness chunk arrived. Resolve the anchor block's header
    /// from the local [`ShardSourceTracker`],
    /// recompute the window root from the payloads plus the range proof,
    /// and admit the run whole, re-driving the fetch for a newer
    /// crossing's chunk if one has been observed since: a terminated
    /// shard sends no further source header to trigger it.
    ///
    /// `None` refuses the chunk — empty, anchored on a header not held,
    /// or failing the root check. The fetch that delivered it releases
    /// its run as failed, which retries it at once the first time and
    /// on the fetch tick after that: a run this host serves itself comes
    /// back the same each time, with no round trip to let time pass
    /// between asks.
    ///
    /// Admission is all-or-nothing because a range proof only verifies
    /// for the run it names — half a chunk proves nothing, so there is no
    /// partial progress to bank.
    ///
    /// A fold off the committee initiates no fetches, so this handler
    /// takes nothing there — the pool is empty by design for it.
    pub fn on_shard_witnesses_received(
        &mut self,
        shard_id: ShardId,
        anchor: BlockHash,
        lo: LeafIndex,
        payloads: Vec<ShardWitnessPayload>,
        range_proof: Vec<Hash>,
    ) -> Option<Vec<BeaconAction>> {
        if !self.host_on_committee {
            return Some(Vec::new());
        }
        if payloads.is_empty() {
            return None;
        }
        let Some(header) = self
            .shard_source
            .verified_header_by_block_hash(shard_id, anchor)
        else {
            warn!(
                shard = ?shard_id,
                "Witness chunk anchor has no verified header yet — dropping",
            );
            return None;
        };
        let chunk_end = lo.inner() + payloads.len() as u64;
        if !rules::contribution_chunk_valid(
            header.header(),
            &payloads,
            &range_proof,
            lo.inner(),
            chunk_end,
        ) {
            warn!(
                shard = ?shard_id,
                lo = lo.inner(),
                chunk_end,
                "Witness chunk failed root recomputation — dropping",
            );
            return None;
        }
        self.shard_source
            .admit_chunk(shard_id, anchor, lo.inner(), payloads, range_proof);
        Some(self.fetch_witness_chunk(shard_id))
    }

    /// Fetch `shard`'s current witness chunk, anchored to its latest
    /// observed crossing's boundary block.
    ///
    /// The anchor is the boundary block `B` (not whichever header just
    /// arrived): the chunk's range proof lifts to `B`'s
    /// `beacon_witness_root`, and the chunk is the leaves
    /// `[prior, chunk_end)` the boundary fold will apply next (`prior` =
    /// the applied watermark). The whole run is one request: the proof is
    /// range-scoped, so a partial answer proves nothing and there is no
    /// gap-filling to do across responses. `chunk_bounds` already caps the
    /// run at the fold's per-epoch budget, which bounds the work one
    /// header can trigger.
    pub(crate) fn fetch_witness_chunk(&mut self, shard: ShardId) -> Vec<BeaconAction> {
        let (anchor, block_height, prior, chunk_end) = {
            let Some(crossing) =
                boundary::crossing_to_source(&self.state, &self.shard_source, shard)
            else {
                return Vec::new();
            };
            let boundary_header = crossing.boundary_header();
            let (prior, chunk_end) =
                rules::witness_chunk_bounds(&self.state, shard, boundary_header);
            (
                crossing.canonical_qc().block_hash(),
                boundary_header.height(),
                prior,
                chunk_end,
            )
        };
        // A run already pooled is answered: asking again only re-delivers
        // it, and every re-delivery re-drives the same ask. Where the host
        // serves the source shard itself the answer comes back from its own
        // store with no round trip, so the re-drive never yields.
        if chunk_end <= prior
            || self
                .shard_source
                .has_witness_chunk(shard, anchor, prior, chunk_end)
        {
            return Vec::new();
        }
        // An unheld run goes out regardless of in-flight status: the
        // runner's fetch dedups ids it already tracks, a refused run among
        // them, so a re-issue only revives a run the runner abandoned. The
        // tracker's record is for cancellation, not dedup.
        self.shard_source
            .register_pending_fetch(shard, block_height, anchor, prior, chunk_end);
        vec![BeaconAction::Fetch {
            ids: BeaconFetchIds::Witnesses(vec![(
                shard,
                block_height,
                anchor,
                LeafIndex::new(prior),
                LeafIndex::new(chunk_end),
            )]),
            shard,
            preferred: None,
            class: None,
        }]
    }

    /// Re-issue witness-chunk fetches for terminated shards whose terminal
    /// crossing hasn't folded yet.
    ///
    /// [`fetch_witness_chunk`](Self::fetch_witness_chunk) is otherwise driven
    /// by source-header observation, and a terminated shard emits no new
    /// header — so its terminal chunk would stall mid-fetch. Re-issuing it
    /// each commit advances the chunk (and re-sends any leaf whose response
    /// never landed); once it folds, the boundary advances its watermark and
    /// the terminal record drops, ending the re-drive. The fold seeds a
    /// split's children or composes a merge's parent.
    pub fn redrive_terminal_witness_fetches(&mut self) -> Vec<BeaconAction> {
        if !self.host_on_committee {
            return Vec::new();
        }
        // Collected up front: the loop body borrows `self` mutably through
        // `fetch_witness_chunk`, so it can't hold the `boundaries` iterator.
        let terminals: Vec<ShardId> = self
            .state
            .boundaries
            .iter()
            .filter(|(_, b)| b.terminal_epoch.is_some())
            .map(|(shard, _)| *shard)
            .collect();
        let mut actions = Vec::new();
        for shard in terminals {
            actions.extend(self.fetch_witness_chunk(shard));
        }
        actions
    }

    /// Retire the source tracking of every shard whose handoff evidence
    /// window has closed, returning the in-flight chunk fetches dropped
    /// with it.
    ///
    /// Nothing else sheds a shard from [`ShardSourceTracker`]: its
    /// header window is bounded per shard and its crossings are bounded
    /// per shard, but a shard whose chain has ended keeps both for the
    /// life of the process. The bound here is the one the state's own
    /// `gc_terminal_boundaries` closes on, so what goes is what the
    /// proposer has already stopped sourcing and the fold has already
    /// stopped consuming.
    ///
    /// Keyed on the beacon's handoff stamp, never on the shard being
    /// absent from the routable set: a departure this acts on is one the
    /// schedule states. A shard with no departure record is untouched,
    /// which is what keeps a live shard the state has not seated yet
    /// from being read as a dead one.
    ///
    /// The clock is the newest committed block anchor over the hosted
    /// chains, read raw: every committed anchor is a lower bound on now,
    /// so a halted or terminated chain does not freeze retirement. The
    /// sweep is idempotent and re-runs on every beacon commit, so a
    /// reading that slips back only delays it. A shard whose record
    /// leaves the head before the sweep sees the window close is never
    /// retired — the same bound the sibling sweep in the remote-header
    /// store accepts. A fold hosting no chain has no such clock and
    /// retires nothing.
    pub(crate) fn retire_departed_sources(&mut self) -> Vec<ChunkFetchId> {
        let Some(now) = self
            .hosted
            .values()
            .map(|chain| chain.anchors.block)
            .max()
            .filter(|&now| now > self.topology_schedule.windows().origin())
        else {
            return Vec::new();
        };
        let schedule = &self.topology_schedule;
        self.shard_source.retire_departed(|shard| {
            schedule
                .handoff_evidence_expiry(shard)
                .is_some_and(|expiry| now > expiry)
        })
    }

    /// Schedule the first `BeaconCommitteeStart` timer so the upcoming
    /// epoch's SPC instance bootstraps. Subsequent epochs self-arm when a
    /// participant settles an adoption; this only covers the resume gap
    /// from a freshly-built or just-loaded fold.
    ///
    /// Fires at the next epoch's wall-clock boundary (the close of the
    /// current epoch's window), or immediately if
    /// `now` is already past it. Tests that want fast beacon kickoff
    /// override `chain_config.epoch_duration_ms` in the genesis config.
    #[must_use]
    pub fn on_startup(&self) -> Vec<BeaconAction> {
        vec![
            BeaconAction::SetTimer {
                id: TimerId::BeaconCommitteeStart,
                duration: self.duration_until_next_epoch_boundary(),
            },
            BeaconAction::SetTimer {
                id: TimerId::BeaconRatifyTrigger,
                duration: self.duration_until_next_ratify_fire(),
            },
        ]
    }

    /// Wall-clock boundary of the upcoming epoch — the close of the current
    /// epoch's window. The beacon starts the next epoch's SPC only once `now`
    /// reaches this, so its synthetic per-epoch clock tracks wall-clock
    /// instead of racing ahead at SPC-round speed. The window's weighted-time
    /// cut is the same instant on this validator's local clock: both are Unix
    /// milliseconds, so the cut reads as a local timestamp unchanged.
    pub(crate) const fn next_epoch_boundary(&self) -> LocalTimestamp {
        let cut = self
            .state
            .chain_config
            .epoch_windows()
            .window_of(self.state.current_epoch)
            .end;
        LocalTimestamp::from_millis(cut.as_millis())
    }

    /// Wall-clock duration from `now` to [`Self::next_epoch_boundary`].
    /// Saturates to zero if `now` is already past the boundary.
    pub(crate) const fn duration_until_next_epoch_boundary(&self) -> Duration {
        Duration::from_millis(
            self.next_epoch_boundary()
                .as_millis()
                .saturating_sub(self.now.as_millis()),
        )
    }

    /// Whether the committee-start timer is due — i.e. wall-clock time has
    /// reached the upcoming epoch's boundary. Gates both the initial
    /// `BeaconCommitteeStart` timer and the per-commit self-perpetuation in
    /// [`on_adopted`](crate::participant::BeaconParticipant::on_adopted), so
    /// the beacon catches up to wall-clock and then paces to it rather than
    /// cascading ahead.
    #[must_use]
    pub(crate) const fn committee_start_due(&self, epoch_boundary: LocalTimestamp) -> bool {
        self.now.as_millis() >= epoch_boundary.as_millis()
    }

    /// How long the pool waits past an epoch's expected block time before
    /// a member prevotes the canonical skip hash.
    ///
    /// [`SKIP_TIMEOUT`] is sized for the 5-minute production epoch (a small
    /// fraction of it). A shorter epoch skips at its own length, which keeps a
    /// genuinely dead epoch (no proposer the committee can rally behind)
    /// carried within ~one epoch — inside the schedule's `L=1` lookahead —
    /// instead of cascading many epochs behind. Genesis refuses an epoch
    /// under [`MIN_EPOCH_DURATION`](hyperscale_types::MIN_EPOCH_DURATION), so the deadline always leaves an epoch
    /// with a silent member the time to commit a real block.
    ///
    /// Consensus-critical, but `epoch_duration_ms` rides in the shared genesis
    /// config, so every validator derives the same instant.
    pub(crate) fn skip_timeout(&self) -> Duration {
        Duration::from_millis(self.state.chain_config.epoch_duration_ms).min(SKIP_TIMEOUT)
    }

    /// Whether the skip-trigger timer is due — i.e. wall-clock time
    /// has reached `expected_block_time + skip_timeout`. The
    /// runner combines this with its own "expected block hasn't
    /// arrived" + "local on active pool" checks before actually
    /// prevoting the skip hash.
    #[must_use]
    pub(crate) fn skip_trigger_due(&self, expected_block_time: LocalTimestamp) -> bool {
        self.now.as_millis() >= expected_block_time.plus(self.skip_timeout()).as_millis()
    }

    /// The ratify round the wall clock says the pool should be in:
    /// elapsed time past the skip deadline divided by the round
    /// timeout, starting from the round after [`RatifyRound::INITIAL`].
    /// Every pool member reads the same deadline off its own beacon
    /// fold, so members converge on one round despite timer jitter.
    pub(crate) fn wall_clock_ratify_round(&self) -> RatifyRound {
        let deadline = self
            .next_epoch_boundary()
            .plus(self.skip_timeout())
            .as_millis();
        let elapsed = self.now.as_millis().saturating_sub(deadline);
        let timeout_ms: u128 = RATIFY_ROUND_TIMEOUT.as_millis();
        let rounds = u32::try_from(u128::from(elapsed) / timeout_ms).unwrap_or(u32::MAX);
        RatifyRound::new(RatifyRound::INITIAL.inner().saturating_add(rounds))
    }

    /// Duration until the next ratify fire: the epoch's skip deadline,
    /// then each round boundary after it — the same shared schedule
    /// [`Self::wall_clock_ratify_round`] reads, so the timer fires at
    /// the instant the wall-clock round changes. Arming at boundaries
    /// rather than a fixed interval from the previous fire means every
    /// pool member enters a round at the same moment and its votes get
    /// the round's whole window to propagate. A member firing late in
    /// the window casts votes that complete its peers' polkas one round
    /// behind, where they are no longer precommittable — at exact pool
    /// quorum, one such member starves certificate assembly entirely.
    pub(crate) fn duration_until_next_ratify_fire(&self) -> Duration {
        let now = self.now.as_millis();
        let deadline = self
            .next_epoch_boundary()
            .plus(self.skip_timeout())
            .as_millis();
        if now < deadline {
            return Duration::from_millis(deadline - now);
        }
        let timeout_ms = u64::try_from(RATIFY_ROUND_TIMEOUT.as_millis()).unwrap_or(u64::MAX);
        let past_boundary = (now - deadline) % timeout_ms;
        Duration::from_millis(timeout_ms - past_boundary)
    }

    /// Verify the equivocation evidence embedded in `proposal` and
    /// return the proposal with each `Verifiable` marker upgraded in
    /// place. An entry verifies when both signatures check out under the
    /// named validator's pubkey (from `state.validators`). A forged sig
    /// can't be made to pass, so an honest node never votes for it. The
    /// upgraded markers ride the pooled proposal through to `apply_epoch`.
    ///
    /// # Errors
    ///
    /// [`ProposalAdmission::Refuted`] when an entry fails under its
    /// validator's registered key, which never changes, and otherwise
    /// [`ProposalAdmission::Abstained`] when an entry names a validator
    /// this fold has not registered yet.
    pub(crate) fn upgrade_proposal_equivocations(
        &self,
        proposal: &Verified<BeaconProposal>,
    ) -> Result<Verified<BeaconProposal>, ProposalAdmission> {
        let mut equivocations = Vec::with_capacity(proposal.equivocations().len());
        let mut unjudged = false;
        for ev in proposal.equivocations() {
            let Some(rec) = self.state.validators.get(&ev.validator) else {
                unjudged = true;
                continue;
            };
            let mut ev = ev.clone();
            ev.upgrade_in_place(&PcVoteEquivocationContext {
                verifier: self.verifier.as_ref(),
                network: &self.network,
                committee: &[(ev.validator, rec.pubkey)],
            })
            .map_err(|_| ProposalAdmission::Refuted)?;
            equivocations.push(ev);
        }
        if unjudged {
            return Err(ProposalAdmission::Abstained);
        }
        proposal
            .clone()
            .with_verified_equivocations(
                Capped::new(equivocations).expect("a list under the cap its source already met"),
            )
            .map_err(|_| ProposalAdmission::Abstained)
    }

    /// Marker-upgrade every shard double-vote pair in `proposal`. The
    /// registry resolves ex-members and revoked keys alike, so evidence
    /// about a rotated-out signer still admits.
    ///
    /// # Errors
    ///
    /// [`ProposalAdmission::Refuted`] when a pair fails signature
    /// verification under its validator's registered key, and otherwise
    /// [`ProposalAdmission::Abstained`] when a pair names a validator this
    /// fold has not registered yet.
    pub(crate) fn upgrade_proposal_vote_equivocations(
        &self,
        proposal: &Verified<BeaconProposal>,
    ) -> Result<Verified<BeaconProposal>, ProposalAdmission> {
        let mut vote_equivocations = Vec::with_capacity(proposal.vote_equivocations().len());
        let mut unjudged = false;
        for ev in proposal.vote_equivocations() {
            let Some(rec) = self.state.validators.get(&ev.validator) else {
                unjudged = true;
                continue;
            };
            let mut ev = ev.clone();
            ev.upgrade_in_place(&ShardVoteEquivocationContext {
                verifier: self.verifier.as_ref(),
                network: &self.network,
                pubkey: &rec.pubkey,
            })
            .map_err(|_| ProposalAdmission::Refuted)?;
            vote_equivocations.push(ev);
        }
        if unjudged {
            return Err(ProposalAdmission::Abstained);
        }
        proposal
            .clone()
            .with_verified_vote_equivocations(
                Capped::new(vote_equivocations)
                    .expect("a list under the cap its source already met"),
            )
            .map_err(|_| ProposalAdmission::Abstained)
    }

    /// Whether every fork proof in `proposal` verifies against the local
    /// topology schedule and sits under its own shard's map key. A proof
    /// self-authenticates (each side carries the accused committee's
    /// aggregated signatures), so this re-verifies from scratch — the
    /// `Verifiable` marker is never trusted to skip the gate, exactly as
    /// [`boundary::proposal_boundary_qcs_admissible`] treats boundary QCs.
    /// The key check authenticates the map's framing: without it, one
    /// genuine proof re-keyed under other shard ids would nominate every
    /// keyed shard for recovery. A proposal carrying an unverifiable,
    /// unresolvable, or mis-keyed proof is inadmissible, so the vnode
    /// abstains rather than folds it.
    ///
    /// A proof must also name a shard the lookahead seats. A proof
    /// verifies against the committee of the window its QCs were signed
    /// in, which the schedule resolves for as long as it retains that
    /// window, so a genuine proof against a shard that has since left the
    /// trie still verifies; the fold has no committee to re-draw for it.
    /// Every voter on a proposal for one epoch holds the state the epoch
    /// before left, so all read the same seating, and a proposer prunes
    /// its own buffer by the same rule
    /// ([`prune_folded_evidence`](crate::participant::BeaconParticipant::prune_folded_evidence)).
    ///
    /// # Errors
    ///
    /// [`ProposalAdmission::Refuted`] when a proof is mis-keyed or false
    /// by its own structure; otherwise [`ProposalAdmission::Abstained`]
    /// when a proof is judged against the schedule: its QCs' committees
    /// are resolved from a recovery-bridged view a proposer that verified
    /// the proof earlier may not have shared.
    pub(crate) fn fork_proofs_admissible(
        &self,
        proposal: &Verified<BeaconProposal>,
    ) -> Result<(), ProposalAdmission> {
        let mut verdict = Ok(());
        for (shard, proof) in proposal.fork_proofs() {
            let proof = proof.as_unverified();
            if *shard != proof.shard() {
                return Err(ProposalAdmission::Refuted);
            }
            if !self.state.next_shard_committees.contains_key(shard) {
                verdict = Err(ProposalAdmission::Abstained);
                continue;
            }
            match proof.verify(self.verifier.as_ref(), &self.topology_schedule) {
                Ok(()) => {}
                Err(err) if refutes_fork_proof(&err) => return Err(ProposalAdmission::Refuted),
                Err(_) => verdict = Err(ProposalAdmission::Abstained),
            }
        }
        verdict
    }

    /// What `candidate` verifies under, once the fields no signature
    /// covers hold: it extends the tip, and its shard contributions are
    /// the canonical projection of its committed proposals. The SPC cert
    /// authenticates the proposals alone, so a Byzantine assembler's
    /// variant projection (fabricated, stale, extra or omitted) must
    /// never become the value an honest member prevotes. `None` when
    /// either fails.
    #[must_use]
    pub fn candidate_keys(&self, candidate: &CandidateBeaconBlock) -> Option<CandidateKeys> {
        if candidate.prev_block_hash() != self.latest_block.block_hash()
            || candidate.epoch() != self.state.current_epoch.next()
        {
            trace!(
                epoch = candidate.epoch().inner(),
                "BeaconCandidate doesn't extend the local tip — dropping",
            );
            return None;
        }
        if !rules::contributions_well_formed(&self.state, candidate.block()) {
            warn!(
                epoch = candidate.epoch().inner(),
                "BeaconCandidate has malformed shard contributions — dropping",
            );
            return None;
        }
        Some(CandidateKeys {
            committee: self.state.derive_beacon_committee(),
            equivocation_signers: self.equivocation_signers_for(candidate.block()),
        })
    }

    /// VRF-verify a fetched proposal under `validator`'s registered
    /// pubkey, or `None` with a warn when the validator is unknown or
    /// the reveal fails.
    #[must_use]
    pub fn verify_fetched_proposal(
        &self,
        epoch: Epoch,
        validator: ValidatorId,
        proposal: Verifiable<BeaconProposal>,
    ) -> Option<Verified<BeaconProposal>> {
        let Some(record) = self.state.validators.get(&validator) else {
            warn!(
                ?validator,
                "Fetched proposal's validator is not in BeaconState — dropping",
            );
            return None;
        };
        let ctx = BeaconProposalVerifyContext {
            verifier: self.verifier.as_ref(),
            network: &self.network,
            epoch,
            sender_pk: record.pubkey,
        };
        match proposal.upgrade(&ctx) {
            Ok(verified) => Some(verified),
            Err((_, err)) => {
                warn!(
                    ?validator,
                    epoch = epoch.inner(),
                    ?err,
                    "Fetched BeaconProposal failed VRF verification — dropping",
                );
                None
            }
        }
    }
}

/// Whether `err` shows a fork proof false by its own bytes: its commit
/// proofs do not hold together, or the two do not contradict. A QC that
/// fails against a schedule-resolved committee, or a committee the
/// schedule cannot resolve, is a judgement of this member's schedule.
const fn refutes_fork_proof(err: &ShardForkProofVerifyError) -> bool {
    match err {
        ShardForkProofVerifyError::ProofA(proof) | ShardForkProofVerifyError::ProofB(proof) => {
            !matches!(proof, CommitProofVerifyError::Qc(_))
        }
        ShardForkProofVerifyError::ShardMismatch
        | ShardForkProofVerifyError::HeightMismatch
        | ShardForkProofVerifyError::NotConflicting => true,
        ShardForkProofVerifyError::CommitteeUnresolved
        | ShardForkProofVerifyError::CommitteeCountMismatch => false,
    }
}

/// The keys a candidate's certificates verify under.
pub struct CandidateKeys {
    /// The beacon committee, in the positional order the SPC cert's
    /// signer bitfields read.
    pub committee: Vec<(ValidatorId, ConsensusPublicKey)>,
    /// The validators the committed proposals' equivocation evidence
    /// names; empty when it names none.
    pub equivocation_signers: Vec<(ValidatorId, ConsensusPublicKey)>,
}

/// Latch `chain` terminal once `schedule` reads its committed block
/// anchor past its shard's terminal window.
fn latch_terminal(schedule: &TopologySchedule, chain: &mut HostedChain) {
    if !chain.terminal_committed && schedule.past_terminal(chain.shard, chain.anchors.block) {
        chain.terminal_committed = true;
    }
}

fn abandon_witnesses(ids: Vec<ChunkFetchId>) -> Vec<BeaconAction> {
    if ids.is_empty() {
        return Vec::new();
    }
    vec![BeaconAction::AbandonFetch(BeaconFetchIds::Witnesses(ids))]
}
