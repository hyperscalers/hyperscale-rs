//! Multi-coordinator shard-consensus sim. Mirrors the beacon
//! `CoordinatorSim` pattern: drains each replica's emitted
//! [`Action`]s, signs/queues/verifies inline using the same pure
//! helpers the production action handlers wrap, and translates
//! the result into envelopes on a two-queue delivery model
//! (network-first, loopback-second).
//!
//! Single-shard by construction (`ShardId::ROOT`), with no
//! provisions, no remote headers, no execution waves. The full
//! simulator covers those concerns; this sim pins HotStuff-2
//! safety + liveness machinery in isolation.
//!
//! # Why network-first
//!
//! Without it, a proposer's own vote (loopback-queued) races
//! ahead of peer votes (network-queued), and the proposer's
//! `VoteSet` aggregates only its own vote before the QC builder
//! runs. Verifying-then-building a single-vote QC still succeeds
//! (incremental aggregation works), but the aggregate the
//! proposer broadcasts differs from what a quorum-driven path
//! produces — and tests pin byte-identical per-height
//! `committed_state_root` across replicas, which requires every
//! replica to see the same vote set per height.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

use hyperscale_core::{Action, CommitSource, FetchAbandon, TimerId};
use hyperscale_shard::action_handlers::{build_proposal, verify_and_build_qc};
use hyperscale_shard::{ShardConsensusConfig, ShardCoordinator, ShardMemoryStats};
use hyperscale_storage::{ChainEntry, PendingChain, RecoveredState, ShardChainWriter};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_test_helpers::TestCommittee;
use hyperscale_types::{
    BeaconWitnessRoot, BeaconWitnessRootContext, BeaconWitnessRootVerifyError, Block, BlockHash,
    BlockHeader, BlockHeight, BlockManifest, BlockVote, Bls12381G1PrivateKey, Bls12381G1PublicKey,
    Bls12381G2Signature, CertRootVerifyError, CertificateRoot, CertificateRootContext,
    CertifiedBlock, ConsensusReceipt, FinalizedWave, Hash, LocalReceiptRoot,
    LocalReceiptRootContext, LocalReceiptRootVerifyError, LocalTimestamp, NetworkDefinition,
    ProposerTimestamp, ProvisionRootVerifyError, ProvisionTxRootsContext, ProvisionTxRootsMap,
    ProvisionTxRootsVerifyError, Provisions, ProvisionsRoot, ProvisionsRootContext, QcContext,
    QcVerifyError, QuorumCertificate, ReadySignal, Round, RoutableTransaction, ShardId,
    ShardWitnessPayload, StateRoot, StateRootContext, StateRootVerifyError, StoredReceipt, Timeout,
    TimeoutContext, TopologySchedule, TransactionRoot, TransactionRootContext, TxHash,
    TxRootVerifyError, ValidatorId, Verifiable, Verified, Verify, VoteCount, ready_signal_message,
};

use crate::common::fixtures::build_genesis_block;

/// One captured commit event from a replica's
/// [`Action::CommitBlock`] / [`Action::CommitBlockByQcOnly`] emission.
#[derive(Clone)]
pub struct CapturedCommit {
    /// Block height that committed.
    pub height: BlockHeight,
    /// Block hash that committed.
    pub block_hash: BlockHash,
    /// State root from the committed block's header. Pinned across
    /// replicas as the canonical chain-state invariant.
    pub state_root: StateRoot,
    /// The certified block payload, threaded so tests can assert on
    /// block contents (tx set, certs, etc.).
    pub certified: Arc<Verified<CertifiedBlock>>,
    /// Beacon-witness leaves the commit appended, so tests can assert
    /// on derived witnesses (missed proposals, reshape triggers).
    pub witness_leaves: Vec<ShardWitnessPayload>,
}

/// `(to_idx, event)` envelope queued for delivery on a later `step()`.
struct Envelope {
    to_idx: usize,
    event: SimEvent,
}

/// Match predicate for [`ShardCoordinatorSim::hold_matching`].
/// Envelopes that match an active filter on a replica's `holds`
/// list get diverted into `held` instead of delivered, until
/// [`ShardCoordinatorSim::release_held`] runs.
#[derive(Clone, Copy, Debug)]
pub enum HoldFilter {
    /// Match `SimEvent::BlockHeader` envelopes whose header is at
    /// `height`. Delays a specific proposal's delivery at a
    /// single replica.
    BlockHeaderAtHeight(BlockHeight),
    /// Match `SimEvent::BlockHeader` envelopes whose header was
    /// produced by `proposer`. Models a "silent leader": any
    /// header that validator broadcasts is diverted at the
    /// receiver before delivery.
    BlockHeaderFromProposer(ValidatorId),
    /// Match every `SimEvent::BlockHeader`. Keeps the chain from
    /// ever certifying a block so timeout-driven view changes
    /// accrue at a single height.
    AnyHeader,
    /// Match block-vote envelopes (verified or unverified) cast at
    /// `(height, round)`. Lets a test pin which replica aggregates
    /// a given block's QC by withholding that block's votes from
    /// every other would-be aggregator.
    VoteAtHeightRound(BlockHeight, Round),
    /// Match any timeout envelope (verified or unverified). Keeps a
    /// replica from joining the timeout quorum so it can only catch
    /// up via an observed higher-round header.
    AnyTimeout,
}

impl HoldFilter {
    fn matches(self, event: &SimEvent) -> bool {
        match self {
            Self::BlockHeaderAtHeight(h) => {
                matches!(event, SimEvent::BlockHeader { header, .. } if header.height() == h)
            }
            Self::BlockHeaderFromProposer(v) => {
                matches!(event, SimEvent::BlockHeader { header, .. } if header.proposer() == v)
            }
            Self::AnyHeader => matches!(event, SimEvent::BlockHeader { .. }),
            Self::VoteAtHeightRound(h, r) => match event {
                SimEvent::UnverifiedVote { vote } => vote.height() == h && vote.round() == r,
                SimEvent::VerifiedVote { vote } => vote.height() == h && vote.round() == r,
                _ => false,
            },
            Self::AnyTimeout => matches!(
                event,
                SimEvent::UnverifiedTimeout { .. } | SimEvent::VerifiedTimeout { .. }
            ),
        }
    }
}

/// Adversarial transform a flagged replica applies to its next
/// matching outbound action. Each variant fires once, then clears
/// — modelled after the beacon sim's `ByzantineBehaviour`.
#[derive(Clone, Copy, Debug)]
pub enum ByzantineBehaviour {
    /// On the next `BroadcastBlockHeader`, also emit a second
    /// `BlockHeader` envelope to every peer with the same
    /// `(height, round, parent_qc, parent_block_hash, proposer)`
    /// but a perturbed `timestamp` (`+1ms`). The two headers hash
    /// differently, so honest receivers admit both into
    /// `pending_blocks` but the own-vote lock keeps each receiver
    /// from voting on more than one.
    EquivocateProposal,
}

/// Wire-shape events translated from emitted [`Action`]s by
/// `absorb_one` and from incoming envelopes by `deliver`.
#[allow(clippy::large_enum_variant)] // mirrors ProtocolEvent variants; boxing every payload helps neither cache nor LoC
#[derive(Clone)]
enum SimEvent {
    BlockHeader {
        header: Arc<BlockHeader>,
        manifest: BlockManifest,
    },
    UnverifiedVote {
        vote: BlockVote,
    },
    VerifiedVote {
        vote: Verified<BlockVote>,
    },
    UnverifiedTimeout {
        timeout: Timeout,
    },
    VerifiedTimeout {
        timeout: Verified<Timeout>,
    },
    ProposalBuilt {
        height: BlockHeight,
        round: Round,
        block: Arc<Block>,
        block_hash: BlockHash,
        manifest: BlockManifest,
        finalized_waves: Vec<Arc<Verifiable<FinalizedWave>>>,
        provisions: Vec<Arc<Verifiable<Provisions>>>,
        substate_delta: i64,
    },
    QcResult {
        block_hash: BlockHash,
        qc: Option<Verified<QuorumCertificate>>,
        verified_votes: Vec<(usize, Verified<BlockVote>)>,
    },
    QcSignatureVerified {
        block_hash: BlockHash,
        result: Result<Verified<QuorumCertificate>, QcVerifyError>,
    },
    TransactionRootVerified {
        block_hash: BlockHash,
        result: Result<Verified<TransactionRoot>, TxRootVerifyError>,
    },
    CertificateRootVerified {
        block_hash: BlockHash,
        result: Result<Verified<CertificateRoot>, CertRootVerifyError>,
    },
    LocalReceiptRootVerified {
        block_hash: BlockHash,
        result: Result<Verified<LocalReceiptRoot>, LocalReceiptRootVerifyError>,
    },
    ProvisionsRootVerified {
        block_hash: BlockHash,
        result: Result<Verified<ProvisionsRoot>, ProvisionRootVerifyError>,
    },
    ProvisionTxRootsVerified {
        block_hash: BlockHash,
        result: Result<Verified<ProvisionTxRootsMap>, ProvisionTxRootsVerifyError>,
    },
    BeaconWitnessRootVerified {
        block_hash: BlockHash,
        result: Result<Verified<BeaconWitnessRoot>, BeaconWitnessRootVerifyError>,
    },
    StateRootVerified {
        block_hash: BlockHash,
        result: Result<Verified<StateRoot>, StateRootVerifyError>,
        substate_delta: i64,
    },
    BlockReadyToCommit {
        certified: Arc<Verified<CertifiedBlock>>,
        source: CommitSource,
    },
    QuorumCertificateFormed {
        block_hash: BlockHash,
        qc: Verified<QuorumCertificate>,
    },
}

impl SimEvent {
    const fn type_name(&self) -> &'static str {
        match self {
            Self::BlockHeader { .. } => "BlockHeader",
            Self::UnverifiedVote { .. } => "UnverifiedVote",
            Self::VerifiedVote { .. } => "VerifiedVote",
            Self::UnverifiedTimeout { .. } => "UnverifiedTimeout",
            Self::VerifiedTimeout { .. } => "VerifiedTimeout",
            Self::ProposalBuilt { .. } => "ProposalBuilt",
            Self::QcResult { .. } => "QcResult",
            Self::QcSignatureVerified { .. } => "QcSignatureVerified",
            Self::TransactionRootVerified { .. } => "TransactionRootVerified",
            Self::CertificateRootVerified { .. } => "CertificateRootVerified",
            Self::LocalReceiptRootVerified { .. } => "LocalReceiptRootVerified",
            Self::ProvisionsRootVerified { .. } => "ProvisionsRootVerified",
            Self::ProvisionTxRootsVerified { .. } => "ProvisionTxRootsVerified",
            Self::BeaconWitnessRootVerified { .. } => "BeaconWitnessRootVerified",
            Self::StateRootVerified { .. } => "StateRootVerified",
            Self::BlockReadyToCommit { .. } => "BlockReadyToCommit",
            Self::QuorumCertificateFormed { .. } => "QuorumCertificateFormed",
        }
    }
}

/// Multi-coordinator shard sim. Owns n [`ShardCoordinator`]s, their
/// signing keys + per-replica storage, the topology snapshot they all
/// share, and the deterministic delivery queues that ferry events
/// between them.
pub struct ShardCoordinatorSim {
    /// One coordinator per replica.
    pub coordinators: Vec<ShardCoordinator>,
    /// `(validator_id, pubkey)` per replica.
    pub members: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    /// BLS signing keys per replica.
    sks: Vec<Arc<Bls12381G1PrivateKey>>,
    /// In-memory shard storage per replica. Exposed for test
    /// introspection (e.g. asserting JMT roots).
    pub storages: Vec<Arc<SimShardStorage>>,
    /// Pending-chain overlay per replica. Populated when a replica
    /// either builds (proposer) or successfully verifies state-root
    /// (non-proposer) a block, so subsequent `view_at` reads see the
    /// historical version.
    pending_chains: Vec<Arc<PendingChain<SimShardStorage>>>,
    /// Per-replica admitted-tx pool — the sim's stand-in for
    /// `MempoolCoordinator`. `admit_transaction` populates each
    /// pool; `try_propose_for` threads it into the proposer's
    /// `ready_txs`; `on_block_header` reads it through the
    /// `lookup_tx` data-availability closure.
    tx_pools: Vec<HashMap<TxHash, Arc<Verified<RoutableTransaction>>>>,
    /// Identity-agnostic topology shared by every replica. A single-committee
    /// schedule — the sim runs within one epoch, so every weighted timestamp
    /// resolves to the same committee.
    pub topology: TopologySchedule,
    /// Network definition used as the BLS signing domain.
    network: NetworkDefinition,
    /// The single shard this sim hosts.
    pub shard: ShardId,
    /// Per-replica capture log: one push per `CommitBlock` / `CommitBlockByQcOnly`.
    pub commits: Vec<Vec<CapturedCommit>>,
    /// Per-replica counter of inbound envelopes to silently drop on
    /// delivery — modelled the same as beacon's `drop_counters`.
    pub drop_counters: Vec<usize>,
    /// Peer-bound deliveries; drained first.
    network_q: VecDeque<Envelope>,
    /// Self-feedback deliveries; drained second.
    loopback_q: VecDeque<Envelope>,
    /// Per-replica filters that divert matching inbound envelopes
    /// into the `held` buffer instead of delivering them. Models
    /// late-arrival faults where a specific block's header is
    /// delayed at a single replica.
    holds: Vec<Vec<HoldFilter>>,
    /// Per-replica buffer of envelopes that matched an active filter
    /// in `holds`. `release_held` reinjects them into the front of
    /// `network_q` in queue order.
    held: Vec<Vec<Envelope>>,
    /// Per-replica adversarial transform queued for the next matching
    /// outbound action. Fires once, then clears — mirrors beacon's
    /// `byzantine` slot.
    byzantine: Vec<Option<ByzantineBehaviour>>,
    /// Per-replica count of Byzantine transforms that have actually
    /// fired. Exposed for tests to confirm the adversarial path
    /// triggered.
    pub byzantine_fires: Vec<usize>,
    /// Per-replica capture of every `Action::StartBlockSync` target
    /// emitted. Sync tests inspect this to confirm the coordinator
    /// triggered a sync, then drive recovery manually via
    /// [`Self::deliver_synced_block`].
    pub sync_targets: Vec<Vec<BlockHeight>>,
    /// Shared sim clock. Threaded into every coordinator via
    /// `set_time` so per-replica timestamps don't drift.
    pub now: LocalTimestamp,
}

impl ShardCoordinatorSim {
    /// Build an n-party honest-path sim. Single shard, n-validator
    /// committee, fresh `SimShardStorage` per replica seeded with the
    /// shared empty-JMT-root genesis block.
    #[must_use]
    pub fn new(n: usize, seed: u64) -> Self {
        assert!(n >= 1, "ShardCoordinatorSim n must be >= 1");
        let committee = TestCommittee::new(n, seed);
        let topology = TopologySchedule::single(Arc::new(committee.topology_snapshot(1)));
        let network = NetworkDefinition::simulator();
        let shard = ShardId::ROOT;

        let mut sks = Vec::with_capacity(n);
        let mut members = Vec::with_capacity(n);
        let mut storages = Vec::with_capacity(n);
        let mut pending_chains = Vec::with_capacity(n);
        let mut coordinators = Vec::with_capacity(n);

        for idx in 0..n {
            let sk_bytes = committee.keypair(idx).to_bytes();
            let sk =
                Arc::new(Bls12381G1PrivateKey::from_bytes(&sk_bytes).expect("valid bls key bytes"));
            let id = committee.validator_id(idx);
            members.push((id, *committee.public_key(idx)));
            sks.push(sk);

            let storage = Arc::new(SimShardStorage::default());
            let pending_chain = Arc::new(PendingChain::new(Arc::clone(&storage)));
            pending_chains.push(pending_chain);
            storages.push(storage);

            let mut coord = ShardCoordinator::new(
                id,
                shard,
                ShardConsensusConfig::default(),
                RecoveredState::default(),
            );
            // Genesis proposer is arbitrary but shared across
            // replicas so every genesis block is byte-identical.
            let genesis_proposer = members[0].0;
            let genesis = build_genesis_block(&storages[idx], genesis_proposer);
            let actions = coord.initialize_genesis(&genesis);
            // `initialize_genesis` only emits `SetTimer`; tripwire
            // in case that ever changes.
            assert!(
                actions.iter().all(|a| matches!(a, Action::SetTimer { .. })),
                "initialize_genesis emitted non-SetTimer action: {:?}",
                actions.iter().map(Action::type_name).collect::<Vec<_>>(),
            );
            coordinators.push(coord);
        }

        Self {
            coordinators,
            members,
            sks,
            storages,
            pending_chains,
            tx_pools: (0..n).map(|_| HashMap::new()).collect(),
            topology,
            network,
            shard,
            commits: (0..n).map(|_| Vec::new()).collect(),
            drop_counters: vec![0; n],
            network_q: VecDeque::new(),
            loopback_q: VecDeque::new(),
            holds: (0..n).map(|_| Vec::new()).collect(),
            held: (0..n).map(|_| Vec::new()).collect(),
            byzantine: vec![None; n],
            byzantine_fires: vec![0; n],
            sync_targets: (0..n).map(|_| Vec::new()).collect(),
            now: LocalTimestamp::ZERO,
        }
    }

    /// Number of replicas.
    #[must_use]
    pub const fn n(&self) -> usize {
        self.coordinators.len()
    }

    /// Drop the next `n` envelopes addressed to `replica`. Mirrors
    /// beacon `CoordinatorSim::drop_for`.
    pub fn drop_for(&mut self, replica: ValidatorId, n: usize) {
        let idx = self.idx_of(replica);
        self.drop_counters[idx] += n;
    }

    /// Clear `replica`'s drop counter. Counterpart to
    /// [`Self::drop_for`] for tests that deafen a replica
    /// indefinitely and resume delivery later.
    pub fn stop_dropping(&mut self, replica: ValidatorId) {
        let idx = self.idx_of(replica);
        self.drop_counters[idx] = 0;
    }

    /// Hand `certified` to `replica`'s
    /// `on_sync_block_ready_to_apply` and absorb the returned
    /// actions. Mirrors the production runner's block-sync
    /// protocol feeding a fetched block back into the coordinator.
    pub fn deliver_synced_block(&mut self, replica: ValidatorId, certified: &CertifiedBlock) {
        let idx = self.idx_of(replica);
        let actions =
            self.coordinators[idx].on_sync_block_ready_to_apply(&self.topology, certified.clone());
        self.absorb(idx, actions);
    }

    /// Fire `on_block_persisted` on `replica`. In production this
    /// arrives via `ProtocolEvent::BlockPersisted` after storage's
    /// write batch flushes; once the persisted height reaches the
    /// sync target, `on_block_sync_complete` fires and flips out
    /// of sync mode.
    pub fn deliver_block_persisted(&mut self, replica: ValidatorId, height: BlockHeight) {
        let idx = self.idx_of(replica);
        let actions = self.coordinators[idx].on_block_persisted(&self.topology, height, 0);
        self.absorb(idx, actions);
    }

    /// Kick every replica's first proposal attempt. The round-0
    /// height-1 leader emits `BuildProposal`; everyone else's
    /// `try_propose` short-circuits at the proposer check.
    pub fn kick_off(&mut self) {
        for idx in 0..self.n() {
            self.coordinators[idx].set_time(self.now);
            let actions = self.try_propose_for(idx);
            self.absorb(idx, actions);
        }
    }

    /// Trigger a single replica's `try_propose` at its current view
    /// and absorb the result. Used by tests that hand-advance one
    /// replica's view and need it to (re)propose at the new round
    /// without disturbing the others.
    pub fn propose_on(&mut self, replica: ValidatorId) {
        let idx = self.idx_of(replica);
        let actions = self.try_propose_for(idx);
        self.absorb(idx, actions);
    }

    /// Admit `tx` into every replica's local pool. See
    /// [`Self::admit_transaction_on`] for the per-replica variant
    /// used to model partial-availability tests.
    pub fn admit_transaction(&mut self, tx: &Arc<Verified<RoutableTransaction>>) {
        for idx in 0..self.n() {
            self.admit_transaction_on(idx, Arc::clone(tx));
        }
    }

    /// Admit `tx` into only `idx`'s local pool and run
    /// `on_transactions_admitted` + the latched proposal retry on
    /// that replica only. Used to model partial-availability
    /// faults where a single replica's DA gate matters.
    pub fn admit_transaction_on(&mut self, idx: usize, tx: Arc<Verified<RoutableTransaction>>) {
        let hash = tx.hash();
        let tx_slice = [Arc::clone(&tx)];
        self.tx_pools[idx].insert(hash, tx);
        let actions = self.coordinators[idx].on_transactions_admitted(&self.topology, &tx_slice);
        self.absorb(idx, actions);
        // The node's tx-admission arm explicitly latches a retry
        // after `on_transactions_admitted` so the leader's
        // `take_ready_proposal` picks it up — mirror it here.
        self.coordinators[idx].queue_ready_proposal();
        if self.coordinators[idx].take_ready_proposal() {
            let actions = self.try_propose_for(idx);
            self.absorb(idx, actions);
        }
    }

    /// Sign a `ReadySignal` from `signer_idx` covering
    /// `[height_window_start, height_window_end]` and deliver it
    /// to every replica's `on_ready_signal_received`. Tests that
    /// don't care about window eligibility should use a wide
    /// window.
    pub fn emit_ready_signal(
        &mut self,
        signer_idx: usize,
        height_window_start: BlockHeight,
        height_window_end: BlockHeight,
    ) {
        let validator = self.members[signer_idx].0;
        let sk = &self.sks[signer_idx];
        let msg = ready_signal_message(
            &self.network,
            validator,
            height_window_start,
            height_window_end,
        );
        let sig = Bls12381G2Signature(sk.sign_v1(&msg).0);
        let signal = ReadySignal::new(validator, height_window_start, height_window_end, sig);
        for idx in 0..self.n() {
            self.coordinators[idx].on_ready_signal_received(&self.topology, signal.clone());
        }
    }

    /// Fire `check_round_timeout` on `replica` and absorb any
    /// returned view-change actions. No-op when
    /// `should_advance_round` declines (verification in flight,
    /// pending block at tip within `MAX_PROGRESS_WAIT`, or
    /// timeout not yet elapsed).
    pub fn fire_view_change_timer(&mut self, replica: ValidatorId) {
        let idx = self.idx_of(replica);
        if let Some(actions) = self.coordinators[idx].check_round_timeout(&self.topology) {
            self.absorb(idx, actions);
        }
    }

    /// Fire `check_round_timeout` on every replica. Order is fixed
    /// (committee order) so tests stay deterministic.
    pub fn fire_view_change_timer_all(&mut self) {
        for idx in 0..self.n() {
            let replica = self.members[idx].0;
            self.fire_view_change_timer(replica);
        }
    }

    /// Advance the shared sim clock by `delta` and push it to
    /// every coordinator via `set_time`. Used for ready-signal
    /// dwell and view-change timeout tests.
    pub fn advance_clock(&mut self, delta: std::time::Duration) {
        let new_ms = self.now.as_millis().saturating_add(
            u64::try_from(delta.as_millis()).expect("advance_clock delta fits u64 ms"),
        );
        self.now = LocalTimestamp::from_millis(new_ms);
        for idx in 0..self.n() {
            self.coordinators[idx].set_time(self.now);
        }
    }

    /// Call `try_propose` on `idx` with its current admitted-tx
    /// pool as `ready_txs`. Tx-only equivalent of the production
    /// `gather_proposal_inputs` (no finalized waves, no provisions).
    fn try_propose_for(&mut self, idx: usize) -> Vec<Action> {
        let ready_txs: Vec<Arc<Verified<RoutableTransaction>>> =
            self.tx_pools[idx].values().cloned().collect();
        self.coordinators[idx].try_propose(&self.topology, &ready_txs, vec![], vec![])
    }

    /// Drain one envelope through its addressee. Network-priority
    /// before loopback. Returns `false` once both queues empty.
    pub fn step(&mut self) -> bool {
        let env = self
            .network_q
            .pop_front()
            .or_else(|| self.loopback_q.pop_front());
        let Some(env) = env else {
            return false;
        };
        if self.drop_counters[env.to_idx] > 0 {
            self.drop_counters[env.to_idx] -= 1;
            return true;
        }
        // Divert into the held buffer if any active filter matches.
        if self.holds[env.to_idx].iter().any(|f| f.matches(&env.event)) {
            self.held[env.to_idx].push(env);
            return true;
        }
        let to_idx = env.to_idx;
        let actions = self.deliver(env);
        self.absorb(to_idx, actions);
        true
    }

    /// Flag `replica` to apply `behaviour` to its next matching
    /// outbound action. Fires exactly once, then clears. Overwrites
    /// any previously-set unfired behaviour for that replica.
    pub fn with_byzantine(&mut self, replica: ValidatorId, behaviour: ByzantineBehaviour) {
        let idx = self.idx_of(replica);
        self.byzantine[idx] = Some(behaviour);
    }

    /// Install a hold filter for `replica`. Subsequent inbound
    /// envelopes matching `filter` will be diverted into a side
    /// buffer instead of delivered, until [`Self::release_held`]
    /// re-injects them at the front of the network queue.
    pub fn hold_matching(&mut self, replica: ValidatorId, filter: HoldFilter) {
        let idx = self.idx_of(replica);
        self.holds[idx].push(filter);
    }

    /// Reinject every envelope previously diverted into
    /// `replica`'s held buffer, preserving original delivery
    /// order. Clears the replica's hold filters so subsequent
    /// envelopes deliver normally.
    pub fn release_held(&mut self, replica: ValidatorId) {
        let idx = self.idx_of(replica);
        self.holds[idx].clear();
        // Pop from the back and `push_front` so the next `step()`
        // pulls the oldest held envelope first.
        while let Some(env) = self.held[idx].pop() {
            self.network_q.push_front(env);
        }
    }

    /// Number of envelopes currently held for `replica`. Tests use
    /// this to assert hold filters fired before releasing.
    #[must_use]
    pub fn held_count_for(&self, replica: ValidatorId) -> usize {
        let idx = self.idx_of(replica);
        self.held[idx].len()
    }

    /// Drive `step()` up to `max_steps` times or until both queues
    /// drain. Returns the number of steps actually taken. Matches
    /// beacon's `run_for_at_most`.
    pub fn run_for_at_most(&mut self, max_steps: usize) -> usize {
        let mut steps = 0;
        while steps < max_steps && self.step() {
            steps += 1;
        }
        steps
    }

    /// Run until every replica has committed at least `target`
    /// blocks, or `max_steps` elapses.
    ///
    /// # Panics
    ///
    /// Panics on either liveness failure mode — queue draining before
    /// the commit target is reached, or step budget exhaustion. Same
    /// shape as beacon's `run_until_committed`.
    pub fn run_until_committed(&mut self, target: usize, max_steps: usize) -> usize {
        let all: Vec<usize> = (0..self.n()).collect();
        self.run_until_committed_for(&all, target, max_steps)
    }

    /// Variant of [`Self::run_until_committed`] that targets only
    /// a subset of replicas. Tests that deliberately starve a
    /// replica (DA gating, silenced peer) shouldn't require the
    /// starved replica to reach the commit target.
    pub fn run_until_committed_for(
        &mut self,
        idxs: &[usize],
        target: usize,
        max_steps: usize,
    ) -> usize {
        let mut steps = 0;
        while !idxs.iter().all(|i| self.commits[*i].len() >= target) {
            assert!(
                steps < max_steps,
                "sim exceeded {max_steps} steps; commits so far: {:?}",
                self.commit_counts(),
            );
            assert!(
                self.step(),
                "sim went quiescent at step {steps} with commits {:?} < target {target} for idxs {idxs:?}",
                self.commit_counts(),
            );
            steps += 1;
        }
        steps
    }

    fn all_committed_at_least(&self, target: usize) -> bool {
        self.commits.iter().all(|c| c.len() >= target)
    }

    fn commit_counts(&self) -> Vec<usize> {
        self.commits.iter().map(Vec::len).collect()
    }

    /// Sum of pending verifications across every replica's
    /// pipeline. Used by the verify-drain tripwire.
    #[must_use]
    pub fn total_pending_verifications(&self) -> usize {
        self.coordinators
            .iter()
            .map(|c| {
                let ShardMemoryStats {
                    pending_qc_verifications,
                    pending_state_root_verifications,
                    ..
                } = c.memory_stats();
                pending_qc_verifications + pending_state_root_verifications
            })
            .sum()
    }

    fn deliver(&mut self, env: Envelope) -> Vec<Action> {
        let to_idx = env.to_idx;
        let mut actions = self.deliver_inner(env);
        // Mirror the node state machine's post-dispatch hook:
        // drain ready state-root verifications into
        // `VerifyStateRoot` actions, then re-enter `try_propose`
        // once if any path latched a retry.
        let shard = self.shard;
        for ready in self.coordinators[to_idx].drain_ready_state_root_verifications(shard) {
            actions.push(Action::VerifyStateRoot {
                block_hash: ready.block_hash,
                parent_block_hash: ready.parent_block_hash,
                parent_state_root: ready.parent_state_root,
                parent_block_height: ready.parent_block_height,
                expected_root: ready.expected_root,
                expected_local_receipt_root: ready.expected_local_receipt_root,
                finalized_waves: ready.finalized_waves,
                block_height: ready.block_height,
                claimed_split_child_roots: ready.claimed_split_child_roots,
                split_child_roots_required: ready.split_child_roots_required,
            });
        }
        if self.coordinators[to_idx].take_ready_proposal() {
            actions.extend(self.try_propose_for(to_idx));
        }
        actions
    }

    fn deliver_inner(&mut self, env: Envelope) -> Vec<Action> {
        let to_idx = env.to_idx;
        // Split-borrow: `BlockHeader` reads `tx_pools[to_idx]`
        // while mutating `coordinators[to_idx]`. All other arms
        // touch only the coordinator, so re-bind locally below.
        if let SimEvent::BlockHeader { header, manifest } = env.event {
            let pool = &self.tx_pools[to_idx];
            let lookup_tx = |hash: &TxHash| -> Option<Arc<Verifiable<RoutableTransaction>>> {
                pool.get(hash)
                    .map(|tx| Arc::new(Verifiable::from((**tx).clone())))
            };
            return self.coordinators[to_idx].on_block_header(
                &self.topology,
                &header,
                manifest,
                lookup_tx,
                |_| None,
                |_| None,
            );
        }
        let topology = &self.topology;
        let coord = &mut self.coordinators[to_idx];
        match env.event {
            SimEvent::BlockHeader { .. } => unreachable!("handled above"),
            SimEvent::UnverifiedVote { vote } => coord.on_unverified_block_vote(topology, vote),
            SimEvent::VerifiedVote { vote } => coord.on_verified_block_vote(topology, vote),
            SimEvent::UnverifiedTimeout { timeout } => {
                coord.on_unverified_timeout(topology, &timeout)
            }
            SimEvent::VerifiedTimeout { timeout } => coord.on_verified_timeout(topology, timeout),
            SimEvent::ProposalBuilt {
                height,
                round,
                block,
                block_hash,
                manifest,
                finalized_waves,
                provisions,
                substate_delta,
            } => coord.on_proposal_built(
                topology,
                height,
                round,
                &block,
                block_hash,
                &manifest,
                finalized_waves,
                provisions,
                substate_delta,
            ),
            SimEvent::QcResult {
                block_hash,
                qc,
                verified_votes,
            } => coord.on_qc_result(topology, block_hash, qc, verified_votes),
            SimEvent::QcSignatureVerified { block_hash, result } => {
                coord.on_qc_signature_verified(topology, block_hash, result)
            }
            SimEvent::TransactionRootVerified { block_hash, result } => {
                coord.on_transaction_root_verified(topology, block_hash, result)
            }
            SimEvent::CertificateRootVerified { block_hash, result } => {
                coord.on_certificate_root_verified(topology, block_hash, result)
            }
            SimEvent::LocalReceiptRootVerified { block_hash, result } => {
                coord.on_local_receipt_root_verified(topology, block_hash, result)
            }
            SimEvent::ProvisionsRootVerified { block_hash, result } => {
                coord.on_provisions_root_verified(topology, block_hash, result)
            }
            SimEvent::ProvisionTxRootsVerified { block_hash, result } => {
                coord.on_provision_tx_roots_verified(topology, block_hash, result)
            }
            SimEvent::BeaconWitnessRootVerified { block_hash, result } => {
                coord.on_beacon_witness_root_verified(topology, block_hash, result)
            }
            SimEvent::StateRootVerified {
                block_hash,
                result,
                substate_delta,
            } => coord.on_state_root_verified(topology, block_hash, result, substate_delta),
            SimEvent::BlockReadyToCommit { certified, source } => {
                coord.on_block_ready_to_commit(topology, certified, source)
            }
            SimEvent::QuorumCertificateFormed { block_hash, qc } => {
                coord.on_qc_formed(topology, block_hash, &qc, &[], vec![], vec![])
            }
        }
    }

    /// Translate every action `emitter_idx` produced into queued
    /// envelopes (and captured commits). Unhandled action
    /// variants panic so the sim stays honest about which shard
    /// actions it models.
    fn absorb(&mut self, emitter_idx: usize, actions: Vec<Action>) {
        let me = self.members[emitter_idx].0;
        for action in actions {
            self.absorb_one(emitter_idx, me, action);
        }
    }

    #[allow(clippy::too_many_lines)] // single dispatch over shard-emitted Action variants
    fn absorb_one(&mut self, emitter_idx: usize, me: ValidatorId, action: Action) {
        match action {
            Action::BroadcastBlockHeader { header, manifest } => {
                let header = Arc::new(*header);
                let manifest = *manifest;
                let committee_ids: Vec<ValidatorId> = self
                    .topology
                    .head()
                    .committee_for_shard(self.shard)
                    .to_vec();
                for &peer in &committee_ids {
                    if peer == me {
                        continue;
                    }
                    let to_idx = self.idx_of(peer);
                    self.network_q.push_back(Envelope {
                        to_idx,
                        event: SimEvent::BlockHeader {
                            header: Arc::clone(&header),
                            manifest: manifest.clone(),
                        },
                    });
                }
                // No self-loopback: the proposer entered its own
                // block into `pending_blocks` already via
                // `on_proposal_built`.

                // Equivocation transform: emit a second header at
                // the same `(height, round, parent)` with a `+1ms`
                // timestamp perturbation. The two block hashes
                // differ, so honest receivers admit both; the
                // own-vote lock keeps each from voting on more
                // than one.
                if matches!(
                    self.byzantine[emitter_idx],
                    Some(ByzantineBehaviour::EquivocateProposal),
                ) {
                    self.byzantine[emitter_idx] = None;
                    self.byzantine_fires[emitter_idx] += 1;
                    let conflict = Arc::new(perturb_header_timestamp(&header));
                    for &peer in &committee_ids {
                        if peer == me {
                            continue;
                        }
                        let to_idx = self.idx_of(peer);
                        self.network_q.push_back(Envelope {
                            to_idx,
                            event: SimEvent::BlockHeader {
                                header: Arc::clone(&conflict),
                                manifest: manifest.clone(),
                            },
                        });
                    }
                }
            }
            Action::SignAndBroadcastBlockVote {
                block_hash,
                parent_block_hash,
                height,
                round,
                timestamp,
                next_proposers,
            } => {
                let verified = Verified::<BlockVote>::sign_local(
                    &self.network,
                    block_hash,
                    parent_block_hash,
                    self.shard,
                    height,
                    round,
                    me,
                    &self.sks[emitter_idx],
                    timestamp,
                );
                for &recipient in &next_proposers {
                    if recipient == me {
                        continue;
                    }
                    let to_idx = self.idx_of(recipient);
                    // The production gossip handler unwraps
                    // `Verifiable<BlockVote>` to the raw vote
                    // before emitting
                    // `UnverifiedBlockVoteReceived`; mirror that.
                    self.network_q.push_back(Envelope {
                        to_idx,
                        event: SimEvent::UnverifiedVote {
                            vote: verified.clone().into_inner(),
                        },
                    });
                }
                // Self-loopback so local `VoteSet` tracking sees
                // our own vote — mirrors the handler's
                // `notify_protocol(VerifiedBlockVoteReceived)`.
                self.loopback_q.push_back(Envelope {
                    to_idx: emitter_idx,
                    event: SimEvent::VerifiedVote { vote: verified },
                });
            }
            Action::SignAndBroadcastTimeout {
                round,
                high_qc,
                recipients,
            } => {
                let verified = Verified::<Timeout>::sign_local(
                    &self.network,
                    self.shard,
                    round,
                    high_qc,
                    me,
                    &self.sks[emitter_idx],
                );
                for &recipient in &recipients {
                    if recipient == me {
                        continue;
                    }
                    let to_idx = self.idx_of(recipient);
                    // Wire-arrived timeouts always land unverified at the
                    // receiver, mirroring the gossip handler's
                    // `into_verified()` Err arm.
                    self.network_q.push_back(Envelope {
                        to_idx,
                        event: SimEvent::UnverifiedTimeout {
                            timeout: verified.clone().into_inner(),
                        },
                    });
                }
                // Self-loopback so the local `TimeoutKeeper` tallies our
                // own timeout — mirrors the handler's
                // `notify_protocol(VerifiedTimeoutReceived)`.
                self.loopback_q.push_back(Envelope {
                    to_idx: emitter_idx,
                    event: SimEvent::VerifiedTimeout { timeout: verified },
                });
            }
            Action::VerifyTimeout {
                timeout,
                voter_public_key,
            } => {
                // Mirror the production handler: the consensus crypto pool
                // verifies the share (inline here) and feeds the verified
                // timeout back to the emitter's `TimeoutKeeper`.
                if let Ok(verified) = timeout.verify(&TimeoutContext {
                    network: &self.network,
                    voter_public_key: &voter_public_key,
                }) {
                    self.loopback_q.push_back(Envelope {
                        to_idx: emitter_idx,
                        event: SimEvent::VerifiedTimeout { timeout: verified },
                    });
                }
            }
            // `BroadcastCertifiedBlockHeader` is cross-shard
            // light-client gossip; the single-shard sim has
            // nothing to deliver it to. Folds into the no-op
            // bucket below.
            Action::BuildProposal {
                shard_id,
                proposer,
                height,
                round,
                parent_block_hash,
                parent_qc,
                timestamp,
                is_fallback,
                parent_state_root,
                parent_block_height,
                transactions,
                finalized_waves,
                provisions,
                parent_in_flight,
                finalized_tx_count,
                ready_signals,
                reshape_trigger,
                beacon_witness_root,
                beacon_witness_leaf_count,
                beacon_witness_base,
                carry_split_child_roots,
                classification_topology,
            } => {
                let view = self.pending_chains[emitter_idx]
                    .view_at(parent_block_hash, parent_block_height);
                let pending_snapshots = view.pending_snapshots().to_vec();
                let result = build_proposal(
                    &view,
                    proposer,
                    height,
                    round,
                    parent_block_hash,
                    parent_qc,
                    timestamp,
                    is_fallback,
                    parent_state_root,
                    parent_block_height,
                    transactions,
                    finalized_waves.clone(),
                    shard_id,
                    &classification_topology,
                    provisions.clone(),
                    parent_in_flight,
                    finalized_tx_count,
                    ready_signals,
                    reshape_trigger,
                    beacon_witness_root,
                    beacon_witness_leaf_count,
                    beacon_witness_base,
                    carry_split_child_roots,
                    &pending_snapshots,
                );
                let block_hash = result.block_hash;
                let substate_delta = result.jmt_snapshot.leaf_delta;
                // Mirror `make_commit_prepared`: stash the JMT
                // snapshot into `pending_chain` so subsequent
                // child verifications see the overlay.
                self.pending_chains[emitter_idx].insert(
                    block_hash,
                    ChainEntry {
                        parent_block_hash,
                        height,
                        receipts: collect_finalized_receipts(&finalized_waves),
                        jmt_snapshot: result.jmt_snapshot,
                        certified_block: None,
                    },
                );
                self.loopback_q.push_back(Envelope {
                    to_idx: emitter_idx,
                    event: SimEvent::ProposalBuilt {
                        height,
                        round,
                        block: Arc::new(result.block),
                        block_hash,
                        manifest: result.manifest,
                        finalized_waves,
                        provisions,
                        substate_delta,
                    },
                });
            }
            Action::VerifyAndBuildQuorumCertificate {
                block_hash,
                shard_id,
                height,
                round,
                parent_block_hash,
                parent_weighted_timestamp,
                votes_to_verify,
                verified_votes,
                total_votes,
            } => {
                let result = verify_and_build_qc(
                    &self.network,
                    block_hash,
                    shard_id,
                    height,
                    round,
                    parent_block_hash,
                    parent_weighted_timestamp,
                    votes_to_verify,
                    verified_votes,
                    total_votes,
                );
                self.loopback_q.push_back(Envelope {
                    to_idx: emitter_idx,
                    event: SimEvent::QcResult {
                        block_hash: result.block_hash,
                        qc: result.qc,
                        verified_votes: result.verified_votes,
                    },
                });
            }
            Action::VerifyQcSignature {
                qc,
                public_keys,
                quorum_threshold,
                block_hash,
            } => {
                let qc_ctx = QcContext {
                    network: &self.network,
                    public_keys: &public_keys,
                    quorum_threshold,
                };
                let result = qc.upgrade(&qc_ctx).map_err(|(_, e)| e);
                self.loopback_q.push_back(Envelope {
                    to_idx: emitter_idx,
                    event: SimEvent::QcSignatureVerified { block_hash, result },
                });
            }
            Action::VerifyTransactionRoot {
                block_hash,
                expected_root,
                transactions,
                validity_anchor,
            } => {
                let tx_ctx = TransactionRootContext {
                    transactions: &transactions,
                    validity_anchor,
                };
                let result = expected_root.verify(&tx_ctx);
                self.loopback_q.push_back(Envelope {
                    to_idx: emitter_idx,
                    event: SimEvent::TransactionRootVerified { block_hash, result },
                });
            }
            Action::VerifyCertificateRoot {
                block_hash,
                expected_root,
                certificates,
            } => {
                let cert_ctx = CertificateRootContext {
                    certificates: &certificates,
                };
                let result = expected_root.verify(&cert_ctx);
                self.loopback_q.push_back(Envelope {
                    to_idx: emitter_idx,
                    event: SimEvent::CertificateRootVerified { block_hash, result },
                });
            }
            Action::VerifyProvisionRoot {
                block_hash,
                expected_root,
                batch_hashes,
            } => {
                let raw_batch_hashes: Vec<Hash> =
                    batch_hashes.iter().map(|h| h.into_raw()).collect();
                let pr_ctx = ProvisionsRootContext {
                    batch_hashes: &raw_batch_hashes,
                };
                let result = expected_root.verify(&pr_ctx);
                self.loopback_q.push_back(Envelope {
                    to_idx: emitter_idx,
                    event: SimEvent::ProvisionsRootVerified { block_hash, result },
                });
            }
            Action::VerifyProvisionTxRoots {
                block_hash,
                expected,
                transactions,
                topology_snapshot,
            } => {
                let ptx_ctx = ProvisionTxRootsContext {
                    local_shard: self.shard,
                    topology: &topology_snapshot,
                    transactions: &transactions,
                };
                let result = expected.verify(&ptx_ctx);
                self.loopback_q.push_back(Envelope {
                    to_idx: emitter_idx,
                    event: SimEvent::ProvisionTxRootsVerified { block_hash, result },
                });
            }
            Action::VerifyBeaconWitnessRoot {
                block_hash,
                expected_root,
                expected_leaf_count,
                claimed_base,
                parent_leaves_start,
                parent_witness_leaves,
                parent_round,
                height,
                round,
                ready_signals,
                reshape_trigger,
                substate_count,
                thresholds,
                finalized_waves,
                topology_snapshot,
            } => {
                let receipts: Vec<StoredReceipt> = finalized_waves
                    .iter()
                    .flat_map(|fw| fw.receipts().iter().cloned())
                    .collect();
                let bw_ctx = BeaconWitnessRootContext {
                    expected_leaf_count,
                    claimed_base,
                    parent_leaves_start,
                    parent_witness_leaves,
                    parent_round,
                    shard: self.shard,
                    height,
                    round,
                    receipts: &receipts,
                    ready_signals: &ready_signals,
                    reshape_trigger,
                    substate_count,
                    thresholds,
                    topology: &topology_snapshot,
                };
                let result = expected_root.verify(&bw_ctx);
                self.loopback_q.push_back(Envelope {
                    to_idx: emitter_idx,
                    event: SimEvent::BeaconWitnessRootVerified { block_hash, result },
                });
            }
            Action::VerifyStateRoot {
                block_hash,
                parent_block_hash,
                parent_state_root,
                parent_block_height,
                expected_root,
                expected_local_receipt_root,
                finalized_waves,
                block_height,
                claimed_split_child_roots,
                split_child_roots_required,
            } => {
                // Mirrors the production handler: receipt-root
                // pre-flight first, then JMT prep on success.
                let stored_receipts: Vec<StoredReceipt> = finalized_waves
                    .iter()
                    .flat_map(|fw| fw.receipts().iter().cloned())
                    .collect();
                let receipt_ctx = LocalReceiptRootContext {
                    receipts: &stored_receipts,
                };
                let receipt_result = expected_local_receipt_root.verify(&receipt_ctx);
                let receipt_ok = receipt_result.is_ok();
                self.loopback_q.push_back(Envelope {
                    to_idx: emitter_idx,
                    event: SimEvent::LocalReceiptRootVerified {
                        block_hash,
                        result: receipt_result,
                    },
                });
                if !receipt_ok {
                    return;
                }
                let view = self.pending_chains[emitter_idx]
                    .view_at(parent_block_hash, parent_block_height);
                let pending_snapshots = view.pending_snapshots().to_vec();
                let (computed_root, jmt_snapshot, prepared) = view.prepare_block_commit(
                    parent_state_root,
                    parent_block_height,
                    &finalized_waves,
                    block_height,
                    &pending_snapshots,
                    None,
                );
                let verify_result = expected_root.verify(&StateRootContext {
                    computed_root: &computed_root,
                    claimed_split_child_roots,
                    split_child_roots_required,
                });
                let substate_delta = jmt_snapshot.leaf_delta;
                if verify_result.is_ok() {
                    self.pending_chains[emitter_idx].insert(
                        block_hash,
                        ChainEntry {
                            parent_block_hash,
                            height: block_height,
                            receipts: collect_finalized_receipts(&finalized_waves),
                            jmt_snapshot,
                            certified_block: None,
                        },
                    );
                    // Production `io_loop` stashes `prepared` in
                    // `prepared_commits` keyed by `block_hash`;
                    // the sim doesn't model the commit-flush
                    // split, so drop it here and let the eventual
                    // `CommitBlock` rebuild as needed.
                    drop(prepared);
                }
                self.loopback_q.push_back(Envelope {
                    to_idx: emitter_idx,
                    event: SimEvent::StateRootVerified {
                        block_hash,
                        result: verify_result,
                        substate_delta,
                    },
                });
            }
            Action::Continuation(event) => {
                use hyperscale_core::ProtocolEvent;
                match event {
                    ProtocolEvent::QuorumCertificateFormed { block_hash, qc } => {
                        self.loopback_q.push_back(Envelope {
                            to_idx: emitter_idx,
                            event: SimEvent::QuorumCertificateFormed { block_hash, qc },
                        });
                    }
                    ProtocolEvent::BlockReadyToCommit { certified, source } => {
                        self.loopback_q.push_back(Envelope {
                            to_idx: emitter_idx,
                            event: SimEvent::BlockReadyToCommit { certified, source },
                        });
                    }
                    other => panic!(
                        "ShardCoordinatorSim: unmodelled Continuation event {}",
                        other.type_name()
                    ),
                }
            }
            Action::CommitBlock {
                certified,
                source: _,
                witness,
            }
            | Action::CommitBlockByQcOnly {
                certified,
                parent_state_root: _,
                parent_block_height: _,
                source: _,
                witness,
            } => {
                let block = certified.block();
                self.commits[emitter_idx].push(CapturedCommit {
                    height: block.height(),
                    block_hash: block.hash(),
                    state_root: block.header().state_root(),
                    certified,
                    witness_leaves: witness.leaves,
                });
            }
            Action::StartBlockSync { target } => {
                // Tests inspect the captured target and drive
                // recovery via `deliver_synced_block` +
                // `deliver_block_persisted`.
                self.sync_targets[emitter_idx].push(target);
            }
            Action::BroadcastCertifiedBlockHeader { .. }
            | Action::SetTimer { .. }
            | Action::CancelTimer { .. }
            | Action::TopologyChanged { .. }
            | Action::AbandonFetch(_) => {
                // Timers, topology changes, fetch abandons, and
                // cross-shard light-client gossip have no in-sim
                // delivery target.
            }
            other => panic!(
                "ShardCoordinatorSim: unmodelled action variant: {}",
                other.type_name()
            ),
        }
    }

    fn idx_of(&self, id: ValidatorId) -> usize {
        self.members
            .iter()
            .position(|(v, _)| *v == id)
            .expect("validator id present in sim committee")
    }
}

fn collect_finalized_receipts(
    waves: &[Arc<Verifiable<FinalizedWave>>],
) -> Vec<Arc<ConsensusReceipt>> {
    waves
        .iter()
        .flat_map(|fw| fw.consensus_receipts())
        .collect()
}

/// Clone `h` with `timestamp` bumped by 1ms. Mints the
/// conflicting half of an equivocating proposer's pair: every
/// other field stays identical so the receiver's per-root
/// verifiers still pass.
fn perturb_header_timestamp(h: &BlockHeader) -> BlockHeader {
    let waves: Vec<_> = h.waves().iter().cloned().collect();
    let provision_tx_roots: BTreeMap<_, _> = h
        .provision_tx_roots()
        .iter()
        .map(|(k, v)| (*k, *v))
        .collect();
    BlockHeader::new(
        h.shard_id(),
        h.height(),
        h.parent_block_hash(),
        h.parent_qc_verifiable().clone(),
        h.proposer(),
        ProposerTimestamp::from_millis(h.timestamp().as_millis().saturating_add(1)),
        h.round(),
        h.is_fallback(),
        h.state_root(),
        h.transaction_root(),
        h.certificate_root(),
        h.local_receipt_root(),
        h.provision_root(),
        waves,
        provision_tx_roots,
        h.in_flight(),
        h.beacon_witness_root(),
        h.beacon_witness_leaf_count(),
        h.beacon_witness_base(),
        h.split_child_roots(),
    )
}
