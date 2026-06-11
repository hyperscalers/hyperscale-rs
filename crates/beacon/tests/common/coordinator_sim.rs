//! Multi-coordinator beacon-chain sim — drives n `BeaconCoordinator`s
//! through one or more epochs and captures the committed (block,
//! state) pair each replica produces.
//!
//! Adversary-free honest path: every emitted [`Action`] translates into
//! the equivalent inbound event on every recipient (and a self-feedback
//! delivery for sign-and-broadcast variants, mirroring the production
//! action handler's `notify_protocol(... from = me)` loopback). Two
//! priority queues split peer-bound from self-feedback deliveries:
//! `step()` drains the network queue first, only falling back to the
//! loopback queue once peer notifies have closed. Without that
//! ordering, view-1 PC inputs collapse to per-validator singletons and
//! PC commits all-bottoms every epoch — the honest path still
//! terminates but exercises an uninteresting branch.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use hyperscale_beacon::coordinator::BeaconCoordinator;
use hyperscale_beacon::genesis::build_genesis_beacon_state;
use hyperscale_beacon::proposal_pool::BeaconProposalPool;
use hyperscale_core::{Action, FetchRequest};
use hyperscale_types::{
    BEACON_SIGNER_COUNT, BeaconCert, BeaconChainConfig, BeaconGenesisConfig, BeaconProposal,
    BeaconState, BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeader, BlockHeight,
    BlockVote, Bls12381G1PrivateKey, Bls12381G1PublicKey, CertificateRoot, CertifiedBeaconBlock,
    CertifiedBeaconBlockVerifyContext, CertifiedBlockHeader, Epoch, GenesisPool, GenesisValidator,
    Hash, InFlightCount, LeafIndex, LocalReceiptRoot, LocalTimestamp, MIN_STAKE_FLOOR,
    NetworkDefinition, PcValueElement, PcVector, PcVote1, PcVote2, PcVote3, PcVoteEquivocation,
    PcVoteVerifyContext, ProposerTimestamp, ProvisionsRoot, QuorumCertificate, Randomness, Round,
    SKIP_TIMEOUT, ShardId, ShardWitness, ShardWitnessPayload, ShardWitnessProof, SignerBitfield,
    SkipEpochCert, SkipRequest, SkipVerifyContext, SpcEmptyViewMsg, SpcNewCommitMsg,
    SpcProposalObject, SpcVerifyContext, SpcView, Stake, StakePoolId, StateRoot, TransactionRoot,
    ValidatorId, Verifiable, Verified, WeightedTimestamp, bls_keypair_from_seed,
    compute_merkle_root_with_proof, genesis_config_hash, pc_context, sign_empty_view_msg,
    sign_vote1, sign_vote2, sign_vote3, spc_context, verify_skip_cert, verify_vote1, verify_vote2,
    verify_vote3, vrf_sign, zero_bls_signature,
};

/// Adversarial transform a flagged replica applies to its next matching
/// outbound action. Each variant fires once, then clears.
#[derive(Clone, Debug)]
pub enum ByzantineBehaviour {
    /// On the next `BuildAndBroadcastBeaconProposal`, also emit a
    /// second proposal at the same `(epoch, VRF reveal)` carrying an
    /// empty witness list. Both proposals are signed by the same
    /// validator, so an honest replica that receives both records a
    /// proposal-level equivocation.
    EquivocateProposal,
    /// On the next `SignAndBroadcastPcVote1`, also sign and broadcast
    /// a second round-1 vote over a perturbed `v_in`. Both votes are
    /// well-formed signatures from the same validator at the same
    /// `(epoch, view, round)`, which is the PC double-sign condition.
    EquivocatePcVote1,
}

/// One captured commit event from a replica's `Action::CommitBeaconBlock`.
#[derive(Clone)]
pub struct CapturedCommit {
    pub epoch: Epoch,
    pub block: Arc<Verified<CertifiedBeaconBlock>>,
    pub state: BeaconState,
}

/// `(to, event)` envelope queued for delivery on a later `step()`.
struct Envelope {
    to_idx: usize,
    event: SimEvent,
}

#[derive(Clone)]
enum SimEvent {
    PcVote1 {
        from: ValidatorId,
        view: SpcView,
        vote: PcVote1,
    },
    PcVote2 {
        from: ValidatorId,
        view: SpcView,
        vote: Box<PcVote2>,
    },
    PcVote3 {
        from: ValidatorId,
        view: SpcView,
        vote: Box<PcVote3>,
    },
    SpcNewView {
        from: ValidatorId,
        proposal: Arc<Verifiable<SpcProposalObject>>,
    },
    SpcNewCommit {
        from: ValidatorId,
        msg: Arc<Verifiable<SpcNewCommitMsg>>,
    },
    SpcEmptyView {
        msg: Arc<Verifiable<SpcEmptyViewMsg>>,
    },
    BeaconProposal {
        from: ValidatorId,
        epoch: Epoch,
        proposal: Arc<Verified<BeaconProposal>>,
    },
    BeaconBlock {
        block: Arc<Verified<CertifiedBeaconBlock>>,
    },
    SkipRequest {
        request: Arc<Verifiable<SkipRequest>>,
    },
    BeaconProposalFetched {
        epoch: Epoch,
        validator: ValidatorId,
        proposal: Option<Arc<Verifiable<BeaconProposal>>>,
    },
}

/// Multi-coordinator beacon sim. Owns n `BeaconCoordinator`s, their
/// signing keys, and the deterministic delivery queues that ferry
/// actions between them.
pub struct CoordinatorSim {
    pub coordinators: Vec<BeaconCoordinator>,
    pub members: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    sks: Vec<Bls12381G1PrivateKey>,
    network: NetworkDefinition,
    /// Per-replica committed (block, state) tuples, ordered by capture
    /// time. One push per `Action::CommitBeaconBlock` the replica
    /// emits.
    pub commits: Vec<Vec<CapturedCommit>>,
    network_q: VecDeque<Envelope>,
    loopback_q: VecDeque<Envelope>,
    /// Per-replica counter of inbound envelopes to silently drop on
    /// delivery. Decremented each time `step()` is about to deliver to
    /// a replica with a non-zero counter. Exposed for test
    /// introspection.
    pub drop_counters: Vec<usize>,
    /// Per-replica one-shot Byzantine transform applied inside
    /// `absorb_one`. Cleared once fired.
    byzantine: Vec<Option<ByzantineBehaviour>>,
    /// Number of Byzantine transforms each replica has applied so far —
    /// test introspection.
    pub byzantine_fires: Vec<usize>,
    /// Equivocations scheduled to splice into the next
    /// `BuildAndBroadcastBeaconProposal` at the keyed epoch, regardless of
    /// which replica emits it. Consumed (drained) the first time a proposal
    /// at that epoch is absorbed.
    pending_equivocations: BTreeMap<Epoch, Vec<PcVoteEquivocation>>,
    /// Single-shot per-pair filter: when `(sender, receiver)` is
    /// present, the next `BuildAndBroadcastBeaconProposal` from
    /// `sender` skips queuing the envelope addressed to `receiver`,
    /// and the entry is removed. Used to simulate a missed proposal
    /// gossip from `sender` to `receiver`.
    blocked_proposal_pairs: BTreeSet<(ValidatorId, ValidatorId)>,
}

impl CoordinatorSim {
    /// Build an n-party honest-path sim where every validator sits on
    /// both the beacon committee and a single shard committee. No
    /// witnesses lift in this honest-path test, so the shard
    /// assignment is purely bookkeeping that satisfies genesis
    /// validation.
    ///
    /// # Panics
    ///
    /// Panics if `n > BEACON_SIGNER_COUNT` — `build_genesis_beacon_state`
    /// rejects oversized committees.
    #[must_use]
    pub fn new(n: usize, seed: u64) -> Self {
        assert!(
            n <= BEACON_SIGNER_COUNT,
            "CoordinatorSim n={n} exceeds BEACON_SIGNER_COUNT={BEACON_SIGNER_COUNT}",
        );
        let network = NetworkDefinition::simulator();

        let mut sks = Vec::with_capacity(n);
        let mut members = Vec::with_capacity(n);
        for i in 0..n {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&seed.to_le_bytes());
            bytes[8..16].copy_from_slice(&(i as u64).to_le_bytes());
            let sk = bls_keypair_from_seed(&bytes);
            let id = ValidatorId::new(i as u64);
            members.push((id, sk.public_key()));
            sks.push(sk);
        }

        let pool_id = StakePoolId::new(0);
        let shard = ShardId::ROOT;
        let config = BeaconGenesisConfig {
            chain_config: BeaconChainConfig::default(),
            initial_validators: members
                .iter()
                .map(|(id, pk)| GenesisValidator {
                    id: *id,
                    pool: pool_id,
                    pubkey: *pk,
                })
                .collect(),
            initial_pools: vec![GenesisPool {
                id: pool_id,
                total_stake: Stake::from_attos((n as u128) * MIN_STAKE_FLOOR.attos()),
            }],
            initial_beacon_committee: members.iter().map(|(id, _)| *id).collect(),
            initial_shard_committees: std::iter::once((
                shard,
                members.iter().map(|(id, _)| *id).collect(),
            ))
            .collect(),
            initial_randomness: Randomness::new([0x42; 32]),
        };

        let initial_state = build_genesis_beacon_state(&config);
        let config_hash = genesis_config_hash(&config, &network);
        let genesis_block = Arc::new(Verified::<CertifiedBeaconBlock>::genesis(config_hash));

        let next_epoch = initial_state.current_epoch.next();
        let coordinators: Vec<BeaconCoordinator> = (0..n)
            .map(|i| {
                BeaconCoordinator::new(
                    Arc::clone(&genesis_block),
                    vec![initial_state.clone()],
                    members[i].0,
                    ShardId::ROOT,
                    WeightedTimestamp::ZERO,
                    network.clone(),
                    config_hash,
                    Arc::new(BeaconProposalPool::new(next_epoch)),
                )
            })
            .collect();

        Self {
            coordinators,
            members,
            sks,
            network,
            commits: (0..n).map(|_| Vec::new()).collect(),
            network_q: VecDeque::new(),
            loopback_q: VecDeque::new(),
            drop_counters: vec![0; n],
            byzantine: vec![None; n],
            byzantine_fires: vec![0; n],
            pending_equivocations: BTreeMap::new(),
            blocked_proposal_pairs: BTreeSet::new(),
        }
    }

    /// Block the next `BuildAndBroadcastBeaconProposal` from `sender`
    /// from queuing its envelope addressed to `receiver`. Other
    /// recipients still receive the proposal. Single-shot per pair:
    /// the entry is cleared the first time the matching proposal is
    /// absorbed. Used to model a missed proposal-gossip delivery.
    pub fn block_proposal_from(&mut self, sender: ValidatorId, receiver: ValidatorId) {
        self.blocked_proposal_pairs.insert((sender, receiver));
    }

    /// Drop the next `n` envelopes addressed to `replica`. Decrements
    /// the per-replica counter inside `step()` *before* delivery, so
    /// `step()` still returns `true` (it consumed an envelope's worth
    /// of work) but the coordinator never sees it.
    pub fn drop_for(&mut self, replica: ValidatorId, n: usize) {
        let idx = self.idx_of(replica);
        self.drop_counters[idx] += n;
    }

    /// Flag `replica` to apply `behaviour` to its next matching
    /// outbound action. Fires exactly once, then clears. Overwrites
    /// any previously-set unfired behaviour for that replica.
    pub fn with_byzantine(&mut self, replica: ValidatorId, behaviour: ByzantineBehaviour) {
        let idx = self.idx_of(replica);
        self.byzantine[idx] = Some(behaviour);
    }

    /// Splice `equivocations` into the next
    /// `BuildAndBroadcastBeaconProposal` at `epoch` that the sim absorbs.
    /// Tests use this to inject forged equivocation evidence that the
    /// natural sim driver wouldn't otherwise produce. Equivocations for a
    /// given epoch are drained on first fire.
    pub fn inject_equivocations(&mut self, epoch: Epoch, equivocations: Vec<PcVoteEquivocation>) {
        self.pending_equivocations
            .entry(epoch)
            .or_default()
            .extend(equivocations);
    }

    /// Deliver a two-block epoch-boundary crossing for `shard` to every
    /// replica's shard-source tracker, so each on-committee proposer reports
    /// the shard's canonical boundary QC in its next proposal.
    ///
    /// Block `B` at `b_height` carries `state_root` and `leaf_count` and is
    /// the first block across the cut: its predecessor's weighted timestamp
    /// is `pred_wt` (at or before the cut) and its own canonical timestamp
    /// `b_wt` (past it) is read from its committed child `C`'s parent QC.
    /// Returns `B`'s block hash so the caller can assert the recorded
    /// boundary's `block_hash`. Deliver before [`Self::kick_off`] so the
    /// crossing is observed when the committee builds its proposals.
    pub fn deliver_boundary_crossing(
        &mut self,
        shard: ShardId,
        b_height: u64,
        pred_wt: u64,
        b_wt: u64,
        state_root: StateRoot,
        leaf_count: u64,
    ) -> BlockHash {
        let (b, witnesses) =
            Self::build_boundary_block(shard, b_height, pred_wt, state_root, leaf_count);
        // `C`'s parent QC is the canonical QC over `B` — a genuine `2f+1`
        // of the governing shard committee, the form the beacon's
        // boundary-QC verification authenticates.
        let canonical_qc = self.genuine_boundary_qc(shard, &b, b_wt);
        self.deliver_crossing_pair(shard, &b, b_height, canonical_qc, &witnesses)
    }

    /// Build boundary block `B` for `shard` whose beacon-witness
    /// accumulator holds `leaf_count` deposit leaves, plus the matching
    /// per-leaf `ShardWitness`es (merkle-proven against `B`'s root, anchored
    /// to `B`). The leaves are distinct `StakeDeposit`s so the fold has
    /// real payloads to apply.
    fn build_boundary_block(
        shard: ShardId,
        b_height: u64,
        pred_wt: u64,
        state_root: StateRoot,
        leaf_count: u64,
    ) -> (Arc<Verified<CertifiedBlockHeader>>, Vec<Arc<ShardWitness>>) {
        let payloads: Vec<ShardWitnessPayload> = (0..leaf_count)
            .map(|i| ShardWitnessPayload::StakeDeposit {
                pool_id: StakePoolId::new(100 + u32::try_from(i).unwrap_or(u32::MAX)),
                amount: Stake::from_whole_tokens(1),
            })
            .collect();
        let leaf_hashes: Vec<Hash> = payloads
            .iter()
            .map(ShardWitnessPayload::leaf_hash)
            .collect();
        let witness_root = if leaf_hashes.is_empty() {
            BeaconWitnessRoot::ZERO
        } else {
            BeaconWitnessRoot::from_raw(compute_merkle_root_with_proof(&leaf_hashes, 0).0)
        };
        let b = make_linked_source_header(
            shard,
            b_height,
            BlockHash::ZERO,
            pred_wt,
            state_root,
            witness_root,
            leaf_count,
        );
        let b_hash = b.block_hash();
        let witnesses: Vec<Arc<ShardWitness>> = payloads
            .into_iter()
            .enumerate()
            .map(|(i, payload)| {
                let (_, siblings, _) = compute_merkle_root_with_proof(&leaf_hashes, i);
                Arc::new(ShardWitness {
                    payload,
                    proof: ShardWitnessProof {
                        shard_id: shard,
                        committed_block_hash: b_hash,
                        leaf_index: LeafIndex::new(i as u64),
                        siblings: siblings.into(),
                    },
                })
            })
            .collect();
        (b, witnesses)
    }

    /// Like [`Self::deliver_boundary_crossing`], but `C`'s parent QC over
    /// `B` carries a **forged** aggregate signature — signer bits set, but
    /// a zero BLS aggregate that no committee actually produced. The
    /// crossing detector still records it (linkage and timestamps are
    /// well-formed), so a proposer reports it, but the beacon's `2f+1`
    /// admission check rejects every peer's proposal carrying it. Models a
    /// Byzantine committee member fabricating a boundary QC.
    pub fn deliver_forged_boundary_crossing(
        &mut self,
        shard: ShardId,
        b_height: u64,
        pred_wt: u64,
        b_wt: u64,
        state_root: StateRoot,
        leaf_count: u64,
    ) -> BlockHash {
        let (b, witnesses) =
            Self::build_boundary_block(shard, b_height, pred_wt, state_root, leaf_count);
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let forged_qc = QuorumCertificate::new(
            b.block_hash(),
            shard,
            BlockHeight::new(b_height),
            b.header().parent_block_hash(),
            Round::INITIAL,
            signers,
            zero_bls_signature(),
            WeightedTimestamp::from_millis(b_wt),
        );
        self.deliver_crossing_pair(shard, &b, b_height, forged_qc, &witnesses)
    }

    /// Seat boundary block `B`, its child `C` (carrying `canonical_qc` as
    /// its parent QC), and `B`'s witness chunk into every replica's
    /// shard-source tracker. Seating the chunk is what lets a proposer
    /// satisfy the witness-availability coupling and report `shard` in its
    /// `boundary_qcs`, and what lets the assembler embed the contribution.
    fn deliver_crossing_pair(
        &mut self,
        shard: ShardId,
        b: &Arc<Verified<CertifiedBlockHeader>>,
        b_height: u64,
        canonical_qc: QuorumCertificate,
        witnesses: &[Arc<ShardWitness>],
    ) -> BlockHash {
        let b_hash = b.block_hash();
        // `C`'s own beacon-witness fields are never read for `B`'s
        // boundary (the chunk proves against `B`); only `C.parent_qc` —
        // the canonical QC over `B` — matters.
        let c = make_source_header_with_parent_qc(
            shard,
            b_height + 1,
            canonical_qc,
            StateRoot::ZERO,
            BeaconWitnessRoot::ZERO,
            witnesses.len() as u64,
        );
        for idx in 0..self.coordinators.len() {
            let a_b = self.coordinators[idx].on_verified_source_header(b);
            self.absorb(idx, a_b);
            let a_c = self.coordinators[idx].on_verified_source_header(&c);
            self.absorb(idx, a_c);
            let a_w = self.coordinators[idx].on_shard_witnesses_received(shard, witnesses.to_vec());
            self.absorb(idx, a_w);
        }
        b_hash
    }

    /// Build a genuine canonical QC over boundary block `b` — a real
    /// `2f+1` BLS aggregate of `shard`'s committee, the form the beacon's
    /// boundary-QC admission verification authenticates. The committee is
    /// resolved at `b`'s parent-QC weighted timestamp (the window `b` was
    /// produced in), matching how the beacon resolves it. Every member
    /// votes at timestamp `b_wt`, so the aggregate weighted timestamp lands
    /// at `b_wt` — `b`'s own canonical timestamp.
    fn genuine_boundary_qc(
        &self,
        shard: ShardId,
        b: &Arc<Verified<CertifiedBlockHeader>>,
        b_wt: u64,
    ) -> QuorumCertificate {
        let header = b.header();
        let b_hash = b.block_hash();
        let height = header.height();
        let parent_block_hash = header.parent_block_hash();
        let pred_wt = header.parent_qc().weighted_timestamp();
        let snapshot = self.coordinators[0]
            .topology_schedule()
            .at(pred_wt)
            .expect("committee resolvable at the boundary block's parent wt")
            .clone();
        let votes: Vec<(usize, Verified<BlockVote>)> = snapshot
            .committee_for_shard(shard)
            .iter()
            .enumerate()
            .map(|(idx, validator)| {
                let sk = &self.sks[self.idx_of(*validator)];
                let vote = BlockVote::new(
                    &self.network,
                    b_hash,
                    parent_block_hash,
                    shard,
                    height,
                    Round::INITIAL,
                    *validator,
                    sk,
                    ProposerTimestamp::from_millis(b_wt),
                );
                (idx, Verified::<BlockVote>::new_unchecked_for_test(vote))
            })
            .collect();
        Verified::<QuorumCertificate>::from_verified_votes(
            b_hash,
            shard,
            height,
            Round::INITIAL,
            parent_block_hash,
            pred_wt,
            &votes,
        )
        .expect("aggregate boundary QC over a non-empty committee")
        .into_inner()
    }

    /// Hand `block` directly to `replica_idx` via
    /// `on_beacon_block_received`, then drain any verify loopback to
    /// completion so the adoption-path actions land in the returned
    /// list. Useful for asserting `CommitBeaconBlock` was emitted
    /// without manually stepping the verification round-trip.
    pub fn deliver_block_to(
        &mut self,
        replica_idx: usize,
        block: &Arc<Verified<CertifiedBeaconBlock>>,
    ) -> Vec<Action> {
        let wrapped = Arc::new(Verifiable::from((***block).clone()));
        let dispatched = self.coordinators[replica_idx].on_beacon_block_received(wrapped);
        let resolved = self.resolve_verifications(replica_idx, dispatched);
        self.absorb(replica_idx, resolved.clone());
        resolved
    }

    /// Walk `actions`: pass non-verify actions through, and for each
    /// beacon-verify action run the verifier inline, re-enter the
    /// matching result handler, and recursively expand. Returns the
    /// post-verification action list — caller absorbs them in one
    /// pass.
    fn resolve_verifications(&mut self, replica_idx: usize, actions: Vec<Action>) -> Vec<Action> {
        let mut out = Vec::new();
        for action in actions {
            match action {
                Action::VerifyBeaconBlock {
                    block,
                    signers,
                    equivocation_signers,
                } => {
                    let result = Arc::unwrap_or_clone(block)
                        .upgrade(&CertifiedBeaconBlockVerifyContext {
                            network: &self.network,
                            signers: &signers,
                            equivocation_signers: &equivocation_signers,
                        })
                        .map(Arc::new)
                        .map_err(|(_, e)| e);
                    let post = self.coordinators[replica_idx].on_beacon_block_verified(result);
                    out.extend(self.resolve_verifications(replica_idx, post));
                }
                Action::VerifySkipRequest { request, signers } => {
                    let anchor = request.anchor_hash();
                    let epoch_to_skip = request.epoch_to_skip();
                    let signer = request.signer();
                    let result = (*request)
                        .upgrade(&SkipVerifyContext {
                            network: &self.network,
                            active_pool: &signers,
                        })
                        .map_err(|(_, e)| e);
                    let post = self.coordinators[replica_idx].on_skip_request_verified(
                        anchor,
                        epoch_to_skip,
                        signer,
                        result,
                    );
                    out.extend(self.resolve_verifications(replica_idx, post));
                }
                other => out.push(other),
            }
        }
        out
    }

    /// Advance every replica's clock past the next epoch's skip deadline
    /// (its boundary plus `SKIP_TIMEOUT`), the precondition for honest
    /// trackers to count a skip request. Mirrors the real stall a skip
    /// models: the deadline passes on every clock before anyone asks.
    pub fn pass_skip_deadline(&mut self) {
        let timeout_ms: u64 = SKIP_TIMEOUT
            .as_millis()
            .try_into()
            .expect("SKIP_TIMEOUT fits in u64 millis");
        for coord in &mut self.coordinators {
            let next = coord.current_state().current_epoch.next().inner();
            let boundary = next * coord.current_state().chain_config.epoch_duration_ms;
            coord.set_now(LocalTimestamp::from_millis(boundary + timeout_ms));
        }
    }

    /// Fire the skip-trigger path on `signer_idx`: build and sign a
    /// `SkipRequest` against the replica's current tip + next epoch,
    /// then admit it locally and queue it for delivery to every peer.
    /// Mirrors what the production runner does on
    /// `skip_trigger_due() && !is_committed && is_on_active_pool`.
    pub fn fire_skip_trigger(&mut self, signer_idx: usize) {
        let signer = self.members[signer_idx].0;
        let sk = &self.sks[signer_idx];
        let anchor = self.coordinators[signer_idx].latest_block().block_hash();
        let epoch_to_skip = self.coordinators[signer_idx]
            .current_state()
            .current_epoch
            .next();
        let verified =
            Verified::<SkipRequest>::sign_local(sk, signer, &self.network, anchor, epoch_to_skip);
        let verified_arc = Arc::new(verified);
        // Admit locally first — the production runner feeds the
        // request back into the local coordinator via the action
        // handler's loopback. The local arm goes through the verified
        // receive entry.
        let actions = self.coordinators[signer_idx]
            .on_verified_skip_request_received(Arc::clone(&verified_arc));
        self.absorb(signer_idx, actions);
        // Queue for every peer as an unverified wire arrival.
        let wire = Arc::new(Verifiable::from((*verified_arc).clone()));
        for to_idx in 0..self.coordinators.len() {
            if to_idx == signer_idx {
                continue;
            }
            self.network_q.push_back(Envelope {
                to_idx,
                event: SimEvent::SkipRequest {
                    request: Arc::clone(&wire),
                },
            });
        }
    }

    /// Number of replicas.
    #[must_use]
    pub const fn n(&self) -> usize {
        self.coordinators.len()
    }

    /// Fire the wall-clock timers on every replica: the
    /// proposal-collection dwell and the committee-start timer. The
    /// dwell is a no-op until an SPC instance is up, and wherever the
    /// quorum fast path already fed the view-1 input — but on the
    /// quiescence re-kick from `run_until_committed` it is the only
    /// way forward when peers' proposals were dropped (e.g. as
    /// unverifiable) and the pool can't reach quorum. In production
    /// these fire as wall-clock passes the dwell and the upcoming
    /// epoch's boundary; here the sim kicks all replicas in lockstep
    /// so SPC instances bootstrap, feed, and `try_propose` emits the
    /// initial `BuildAndBroadcastBeaconProposal` actions.
    pub fn kick_off(&mut self) {
        for idx in 0..self.n() {
            let actions = self.coordinators[idx].on_spc_input_dwell_timer();
            self.absorb(idx, actions);
        }
        for idx in 0..self.n() {
            let actions = self.coordinators[idx].on_beacon_committee_start_timer();
            self.absorb(idx, actions);
        }
    }

    /// Drain one envelope through its addressee. Network-priority
    /// before loopback. Returns `false` once both queues empty.
    ///
    /// If the addressee has a non-zero drop counter, the envelope is
    /// silently consumed without delivery and the counter decrements —
    /// `step()` still returns `true` to reflect that work happened.
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
        let emitter_idx = env.to_idx;
        let actions = self.deliver(env);
        self.absorb(emitter_idx, actions);
        true
    }

    /// Drive `step()` up to `max_steps` times or until both queues
    /// drain, whichever comes first. Returns the number of steps
    /// actually taken. Never panics on quiescence — used by tests that
    /// expect some replicas not to make progress (silent-voter,
    /// partition scenarios).
    pub fn run_for_at_most(&mut self, max_steps: usize) -> usize {
        let mut steps = 0;
        while steps < max_steps && self.step() {
            steps += 1;
        }
        steps
    }

    /// Fire `on_beacon_spc_view_timer` on every replica and absorb the
    /// resulting actions. Models the synchronous wall-clock expiry of
    /// the SPC view timer that the production runner would have
    /// delivered as a `TimerExpired { view }` event.
    pub fn fire_spc_view_timer_all(&mut self) {
        for idx in 0..self.coordinators.len() {
            let actions = self.coordinators[idx].on_beacon_spc_view_timer();
            self.absorb(idx, actions);
        }
    }

    /// Run until every replica has committed at least `target_commits`
    /// blocks, or `max_steps` elapses without reaching that goal.
    ///
    /// # Panics
    ///
    /// Panics on either liveness failure mode: queue draining before
    /// the commit target is reached, or step budget exhaustion.
    pub fn run_until_committed(&mut self, target_commits: usize, max_steps: usize) -> usize {
        let mut steps = 0;
        while !self.all_committed_at_least(target_commits) {
            assert!(
                steps < max_steps,
                "sim exceeded {max_steps} steps; commits so far: {:?}",
                self.commit_counts(),
            );
            if !self.step() {
                // The beacon paces epoch production to wall-clock, so it goes
                // quiescent between epochs waiting for the next
                // `BeaconCommitteeStart`. Model wall-clock reaching that
                // boundary by firing the timer; if the sim is still quiescent
                // afterwards it is genuinely stuck.
                self.kick_off();
                assert!(
                    self.step(),
                    "sim went quiescent at step {steps} even after starting the next \
                     epoch; commits {:?} < target {target_commits}",
                    self.commit_counts(),
                );
            }
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

    fn deliver(&mut self, env: Envelope) -> Vec<Action> {
        match env.event {
            SimEvent::PcVote1 { view, vote, .. } => {
                self.coordinators[env.to_idx].on_pc_vote1_received(view, vote)
            }
            SimEvent::PcVote2 { view, vote, .. } => {
                self.coordinators[env.to_idx].on_pc_vote2_received(view, vote)
            }
            SimEvent::PcVote3 { view, vote, .. } => {
                self.coordinators[env.to_idx].on_pc_vote3_received(view, vote)
            }
            SimEvent::SpcNewView { from, proposal } => {
                self.coordinators[env.to_idx].on_spc_new_view_received(from, proposal)
            }
            SimEvent::SpcNewCommit { from, msg } => {
                self.coordinators[env.to_idx].on_spc_new_commit_received(from, msg)
            }
            SimEvent::SpcEmptyView { msg } => {
                self.coordinators[env.to_idx].on_unverified_spc_empty_view_received(msg)
            }
            SimEvent::BeaconProposal {
                from,
                epoch,
                proposal,
            } => self.coordinators[env.to_idx].on_beacon_proposal_received(from, epoch, proposal),
            SimEvent::BeaconBlock { block } => {
                let wrapped = Arc::new(Verifiable::from((**block).clone()));
                self.coordinators[env.to_idx].on_beacon_block_received(wrapped)
            }
            SimEvent::SkipRequest { request } => {
                self.coordinators[env.to_idx].on_unverified_skip_request_received(request)
            }
            SimEvent::BeaconProposalFetched {
                epoch,
                validator,
                proposal,
            } => {
                self.coordinators[env.to_idx].on_beacon_proposal_fetched(epoch, validator, proposal)
            }
        }
    }

    /// Translate every action `emitter_idx` produced into queued
    /// envelopes (and captured commits). Unhandled action variants
    /// panic — keeping the sim honest about which beacon actions it
    /// models.
    fn absorb(&mut self, emitter_idx: usize, actions: Vec<Action>) {
        let me = self.members[emitter_idx].0;
        for action in actions {
            self.absorb_one(emitter_idx, me, action);
        }
    }

    #[allow(clippy::too_many_lines)] // single dispatch over beacon-emitted Action variants
    fn absorb_one(&mut self, emitter_idx: usize, me: ValidatorId, action: Action) {
        match action {
            Action::BuildAndBroadcastBeaconProposal {
                epoch,
                boundary_qcs,
                mut equivocations,
                recipients,
            } => {
                // Splice in any test-scheduled equivocations for this epoch
                // before the proposal's VRF reveal is signed. Consumed
                // on first fire so only one replica's broadcast picks
                // them up — that's enough to carry them to commit.
                if let Some(extra_equiv) = self.pending_equivocations.remove(&epoch) {
                    equivocations.extend(extra_equiv);
                }
                let sk = &self.sks[emitter_idx];
                let vrf_proof = vrf_sign(sk, &self.network, epoch);
                let proposal = Arc::new(Verified::new_unchecked_for_test(BeaconProposal::new(
                    boundary_qcs,
                    equivocations,
                    vrf_proof,
                )));
                for rcpt in &recipients {
                    if self.blocked_proposal_pairs.remove(&(me, *rcpt)) {
                        // Single-shot test filter: simulate a dropped
                        // proposal-gossip delivery from `me` to `rcpt`.
                        continue;
                    }
                    let to_idx = self.idx_of(*rcpt);
                    self.network_q.push_back(Envelope {
                        to_idx,
                        event: SimEvent::BeaconProposal {
                            from: me,
                            epoch,
                            proposal: Arc::clone(&proposal),
                        },
                    });
                }
                self.loopback_q.push_back(Envelope {
                    to_idx: emitter_idx,
                    event: SimEvent::BeaconProposal {
                        from: me,
                        epoch,
                        proposal,
                    },
                });
                // Byzantine equivocation: emit a second proposal at the
                // same epoch with an empty witness list. The VRF reveal
                // is the same — deterministic in `(sk, network, epoch)` —
                // so honest replicas see two distinct proposals from one
                // signer at the same epoch.
                if matches!(
                    self.byzantine[emitter_idx],
                    Some(ByzantineBehaviour::EquivocateProposal),
                ) {
                    self.byzantine[emitter_idx] = None;
                    self.byzantine_fires[emitter_idx] += 1;
                    let conflicting = Arc::new(Verified::new_unchecked_for_test(
                        BeaconProposal::new(BTreeMap::new(), Vec::new(), vrf_proof),
                    ));
                    for rcpt in &recipients {
                        let to_idx = self.idx_of(*rcpt);
                        self.network_q.push_back(Envelope {
                            to_idx,
                            event: SimEvent::BeaconProposal {
                                from: me,
                                epoch,
                                proposal: Arc::clone(&conflicting),
                            },
                        });
                    }
                    self.loopback_q.push_back(Envelope {
                        to_idx: emitter_idx,
                        event: SimEvent::BeaconProposal {
                            from: me,
                            epoch,
                            proposal: conflicting,
                        },
                    });
                }
            }
            Action::SignAndBroadcastPcVote1 {
                epoch,
                view,
                v_in,
                recipients,
            } => {
                let pc_ctx = pc_context(&spc_context(epoch), view);
                let vote = sign_vote1(
                    &self.sks[emitter_idx],
                    me,
                    &self.network,
                    &pc_ctx,
                    v_in.clone(),
                );
                self.queue_pc_vote1(emitter_idx, me, &recipients, view, vote);
                // Byzantine equivocation at round 1: sign and broadcast
                // a second vote over a perturbed `v_in` so the same
                // signer attests to two distinct vectors at the same
                // `(epoch, view, round)`. The honest replica's PC
                // instance records the equivocation evidence.
                if matches!(
                    self.byzantine[emitter_idx],
                    Some(ByzantineBehaviour::EquivocatePcVote1),
                ) {
                    self.byzantine[emitter_idx] = None;
                    self.byzantine_fires[emitter_idx] += 1;
                    let conflicting_v_in = perturb_pc_vector(&v_in);
                    let conflicting_vote = sign_vote1(
                        &self.sks[emitter_idx],
                        me,
                        &self.network,
                        &pc_ctx,
                        conflicting_v_in,
                    );
                    self.queue_pc_vote1(emitter_idx, me, &recipients, view, conflicting_vote);
                }
            }
            Action::SignAndBroadcastPcVote2 {
                epoch,
                view,
                qc1,
                recipients,
            } => {
                let pc_ctx = pc_context(&spc_context(epoch), view);
                let vote = sign_vote2(&self.sks[emitter_idx], me, &self.network, &pc_ctx, *qc1);
                self.queue_pc_vote2(emitter_idx, me, &recipients, view, Box::new(vote));
            }
            Action::SignAndBroadcastPcVote3 {
                epoch,
                view,
                qc2,
                recipients,
            } => {
                let pc_ctx = pc_context(&spc_context(epoch), view);
                let vote = sign_vote3(&self.sks[emitter_idx], me, &self.network, &pc_ctx, *qc2);
                self.queue_pc_vote3(emitter_idx, me, &recipients, view, Box::new(vote));
            }
            Action::SignAndBroadcastEmptyView {
                epoch,
                view,
                reported,
                recipients,
            } => {
                let spc_ctx = spc_context(epoch);
                let verified = Verified::<SpcEmptyViewMsg>::sign_local(
                    &self.sks[emitter_idx],
                    me,
                    &self.network,
                    &spc_ctx,
                    view,
                    *reported,
                );
                let msg = Arc::new(Verifiable::from(verified));
                for rcpt in &recipients {
                    let to_idx = self.idx_of(*rcpt);
                    self.network_q.push_back(Envelope {
                        to_idx,
                        event: SimEvent::SpcEmptyView {
                            msg: Arc::clone(&msg),
                        },
                    });
                }
                self.loopback_q.push_back(Envelope {
                    to_idx: emitter_idx,
                    event: SimEvent::SpcEmptyView { msg },
                });
            }
            Action::BroadcastSpcNewView {
                epoch: _,
                proposal,
                recipients,
            } => {
                let proposal = Arc::new(Verifiable::from(*proposal));
                for rcpt in &recipients {
                    let to_idx = self.idx_of(*rcpt);
                    self.network_q.push_back(Envelope {
                        to_idx,
                        event: SimEvent::SpcNewView {
                            from: me,
                            proposal: Arc::clone(&proposal),
                        },
                    });
                }
            }
            Action::BroadcastSpcNewCommit {
                epoch: _,
                msg,
                recipients,
            } => {
                let msg = Arc::new(Verifiable::from(*msg));
                for rcpt in &recipients {
                    let to_idx = self.idx_of(*rcpt);
                    self.network_q.push_back(Envelope {
                        to_idx,
                        event: SimEvent::SpcNewCommit {
                            from: me,
                            msg: Arc::clone(&msg),
                        },
                    });
                }
            }
            Action::BroadcastBeaconBlock { block } => {
                for to_idx in 0..self.coordinators.len() {
                    if to_idx == emitter_idx {
                        continue;
                    }
                    self.network_q.push_back(Envelope {
                        to_idx,
                        event: SimEvent::BeaconBlock {
                            block: Arc::clone(&block),
                        },
                    });
                }
            }
            Action::BroadcastSkipRequest {
                epoch_to_skip,
                anchor,
            } => {
                let sk = &self.sks[emitter_idx];
                let signer = self.members[emitter_idx].0;
                let verified = Verified::<SkipRequest>::sign_local(
                    sk,
                    signer,
                    &self.network,
                    anchor,
                    epoch_to_skip,
                );
                let request = Arc::new(verified);
                // Local loopback: the FSM expects to see its own
                // verified contribution to the skip pool.
                let actions = self.coordinators[emitter_idx]
                    .on_verified_skip_request_received(Arc::clone(&request));
                self.absorb(emitter_idx, actions);
                let wire = Arc::new(Verifiable::from((*request).clone()));
                for to_idx in 0..self.coordinators.len() {
                    if to_idx == emitter_idx {
                        continue;
                    }
                    self.network_q.push_back(Envelope {
                        to_idx,
                        event: SimEvent::SkipRequest {
                            request: Arc::clone(&wire),
                        },
                    });
                }
            }
            Action::CommitBeaconBlock { block, state } => {
                self.commits[emitter_idx].push(CapturedCommit {
                    epoch: block.epoch(),
                    block,
                    state: *state,
                });
            }
            Action::VerifyBeaconBlock {
                block,
                signers,
                equivocation_signers,
            } => {
                // Production runs this on the consensus crypto pool; the
                // sim collapses the round-trip to a synchronous inline
                // verify + result-feedback so verification timing doesn't
                // reshape envelope-delivery ordering.
                let result = Arc::unwrap_or_clone(block)
                    .upgrade(&CertifiedBeaconBlockVerifyContext {
                        network: &self.network,
                        signers: &signers,
                        equivocation_signers: &equivocation_signers,
                    })
                    .map(Arc::new)
                    .map_err(|(_, e)| e);
                let post = self.coordinators[emitter_idx].on_beacon_block_verified(result);
                self.absorb(emitter_idx, post);
            }
            Action::VerifySkipRequest { request, signers } => {
                let anchor = request.anchor_hash();
                let epoch_to_skip = request.epoch_to_skip();
                let signer = request.signer();
                let result = (*request)
                    .upgrade(&SkipVerifyContext {
                        network: &self.network,
                        active_pool: &signers,
                    })
                    .map_err(|(_, e)| e);
                let post = self.coordinators[emitter_idx].on_skip_request_verified(
                    anchor,
                    epoch_to_skip,
                    signer,
                    result,
                );
                self.absorb(emitter_idx, post);
            }
            Action::VerifyPcVote1 {
                epoch,
                view,
                vote,
                committee,
            } => {
                let pc_ctx = pc_context(&spc_context(epoch), view);
                let signer = vote.validator();
                let result = vote.upgrade(&PcVoteVerifyContext {
                    network: &self.network,
                    pc_ctx: &pc_ctx,
                    committee: &committee,
                });
                let post = self.coordinators[emitter_idx].on_pc_vote1_verified(
                    epoch,
                    view,
                    signer,
                    result.map_err(|(_, e)| e),
                );
                self.absorb(emitter_idx, post);
            }
            Action::VerifyPcVote2 {
                epoch,
                view,
                vote,
                committee,
            } => {
                let pc_ctx = pc_context(&spc_context(epoch), view);
                let signer = vote.validator();
                let result = (*vote).upgrade(&PcVoteVerifyContext {
                    network: &self.network,
                    pc_ctx: &pc_ctx,
                    committee: &committee,
                });
                let post = self.coordinators[emitter_idx].on_pc_vote2_verified(
                    epoch,
                    view,
                    signer,
                    result.map_err(|(_, e)| e),
                );
                self.absorb(emitter_idx, post);
            }
            Action::VerifyPcVote3 {
                epoch,
                view,
                vote,
                committee,
            } => {
                let pc_ctx = pc_context(&spc_context(epoch), view);
                let signer = vote.validator();
                let result = (*vote).upgrade(&PcVoteVerifyContext {
                    network: &self.network,
                    pc_ctx: &pc_ctx,
                    committee: &committee,
                });
                let post = self.coordinators[emitter_idx].on_pc_vote3_verified(
                    epoch,
                    view,
                    signer,
                    result.map_err(|(_, e)| e),
                );
                self.absorb(emitter_idx, post);
            }
            Action::VerifySpcNewView {
                epoch,
                from,
                proposal,
                committee,
            } => {
                let spc_ctx = spc_context(epoch);
                let view = proposal.view;
                let result = (*proposal).upgrade(&SpcVerifyContext {
                    network: &self.network,
                    spc_ctx: &spc_ctx,
                    committee: &committee,
                });
                let post = self.coordinators[emitter_idx].on_spc_new_view_verified(
                    epoch,
                    from,
                    view,
                    result.map_err(|(_, e)| e),
                );
                self.absorb(emitter_idx, post);
            }
            Action::VerifySpcNewCommit {
                epoch,
                from,
                msg,
                committee,
            } => {
                let spc_ctx = spc_context(epoch);
                let view = msg.view;
                let result = (*msg).upgrade(&SpcVerifyContext {
                    network: &self.network,
                    spc_ctx: &spc_ctx,
                    committee: &committee,
                });
                let post = self.coordinators[emitter_idx].on_spc_new_commit_verified(
                    epoch,
                    from,
                    view,
                    result.map_err(|(_, e)| e),
                );
                self.absorb(emitter_idx, post);
            }
            Action::VerifySpcEmptyView {
                epoch,
                msg,
                committee,
            } => {
                let spc_ctx = spc_context(epoch);
                let from = msg.signer;
                let view = msg.view;
                let result = (*msg).upgrade(&SpcVerifyContext {
                    network: &self.network,
                    spc_ctx: &spc_ctx,
                    committee: &committee,
                });
                let post = self.coordinators[emitter_idx].on_spc_empty_view_verified(
                    epoch,
                    from,
                    view,
                    result.map_err(|(_, e)| e),
                );
                self.absorb(emitter_idx, post);
            }
            Action::Fetch(FetchRequest::BeaconProposal {
                shard: _,
                epoch,
                validator,
                preferred,
                class: _,
            }) => {
                // Walk every other coordinator (with `preferred` first if
                // set), look up the proposal directly in its
                // `proposal_pool`, and queue the first non-empty response
                // back to the emitter. Empty if no peer has it.
                let mut peer_order: Vec<usize> = (0..self.coordinators.len())
                    .filter(|&i| i != emitter_idx)
                    .collect();
                if let Some(p) = preferred {
                    let preferred_idx = self.idx_of(p);
                    peer_order.sort_by_key(|&i| i32::from(i != preferred_idx));
                }
                let proposal = peer_order.iter().find_map(|&peer_idx| {
                    let pool = self.coordinators[peer_idx].proposal_pool();
                    if pool.epoch() != epoch {
                        return None;
                    }
                    pool.get(validator)
                        .map(|verified| Arc::new(Verifiable::from((*verified).clone())))
                });
                self.loopback_q.push_back(Envelope {
                    to_idx: emitter_idx,
                    event: SimEvent::BeaconProposalFetched {
                        epoch,
                        validator,
                        proposal,
                    },
                });
            }
            Action::Fetch(_)
            | Action::AbandonFetch(_)
            | Action::SetTimer { .. }
            | Action::CancelTimer { .. }
            | Action::TopologyChanged { .. } => {
                // Other Fetch/Abandon variants don't surface from the
                // beacon coordinator under this sim; timers + topology
                // are runner concerns the sim doesn't model.
            }
            other => panic!(
                "CoordinatorSim received unmodelled action variant: {}",
                other.type_name(),
            ),
        }
    }

    fn queue_pc_vote1(
        &mut self,
        emitter_idx: usize,
        me: ValidatorId,
        recipients: &[ValidatorId],
        view: SpcView,
        vote: PcVote1,
    ) {
        for rcpt in recipients {
            let to_idx = self.idx_of(*rcpt);
            self.network_q.push_back(Envelope {
                to_idx,
                event: SimEvent::PcVote1 {
                    from: me,
                    view,
                    vote: vote.clone(),
                },
            });
        }
        self.loopback_q.push_back(Envelope {
            to_idx: emitter_idx,
            event: SimEvent::PcVote1 {
                from: me,
                view,
                vote,
            },
        });
    }

    fn queue_pc_vote2(
        &mut self,
        emitter_idx: usize,
        me: ValidatorId,
        recipients: &[ValidatorId],
        view: SpcView,
        vote: Box<PcVote2>,
    ) {
        for rcpt in recipients {
            let to_idx = self.idx_of(*rcpt);
            self.network_q.push_back(Envelope {
                to_idx,
                event: SimEvent::PcVote2 {
                    from: me,
                    view,
                    vote: vote.clone(),
                },
            });
        }
        self.loopback_q.push_back(Envelope {
            to_idx: emitter_idx,
            event: SimEvent::PcVote2 {
                from: me,
                view,
                vote,
            },
        });
    }

    fn queue_pc_vote3(
        &mut self,
        emitter_idx: usize,
        me: ValidatorId,
        recipients: &[ValidatorId],
        view: SpcView,
        vote: Box<PcVote3>,
    ) {
        for rcpt in recipients {
            let to_idx = self.idx_of(*rcpt);
            self.network_q.push_back(Envelope {
                to_idx,
                event: SimEvent::PcVote3 {
                    from: me,
                    view,
                    vote: vote.clone(),
                },
            });
        }
        self.loopback_q.push_back(Envelope {
            to_idx: emitter_idx,
            event: SimEvent::PcVote3 {
                from: me,
                view,
                vote,
            },
        });
    }

    fn idx_of(&self, id: ValidatorId) -> usize {
        self.members
            .iter()
            .position(|(v, _)| *v == id)
            .expect("validator id present in sim committee")
    }
}

/// Build a verified source-shard `CertifiedBlockHeader` over an explicit
/// `parent_qc`. The header's `parent_block_hash` is taken from the QC, so
/// `parent_qc` doubles as the chain link and the timestamp anchor. Used
/// to seat a child whose `parent_qc` is a genuine canonical QC over its
/// predecessor — the form the beacon's crossing detector and boundary-QC
/// verification read.
fn make_source_header_with_parent_qc(
    shard: ShardId,
    height: u64,
    parent_qc: QuorumCertificate,
    state_root: StateRoot,
    witness_root: BeaconWitnessRoot,
    leaf_count: u64,
) -> Arc<Verified<CertifiedBlockHeader>> {
    let parent_hash = parent_qc.block_hash();
    let parent_wt = parent_qc.weighted_timestamp();
    let header = BlockHeader::new(
        shard,
        BlockHeight::new(height),
        parent_hash,
        parent_qc,
        ValidatorId::new(0),
        ProposerTimestamp::ZERO,
        Round::INITIAL,
        false,
        state_root,
        TransactionRoot::ZERO,
        CertificateRoot::ZERO,
        LocalReceiptRoot::ZERO,
        ProvisionsRoot::ZERO,
        Vec::new(),
        BTreeMap::new(),
        InFlightCount::ZERO,
        witness_root,
        BeaconWitnessLeafCount::new(leaf_count),
        BeaconWitnessLeafCount::ZERO,
    );
    let block_hash = header.hash();
    let qc = QuorumCertificate::new(
        block_hash,
        shard,
        BlockHeight::new(height),
        parent_hash,
        Round::INITIAL,
        SignerBitfield::new(4),
        zero_bls_signature(),
        parent_wt,
    );
    Arc::new(Verified::new_unchecked_for_test(CertifiedBlockHeader::new(
        header, qc,
    )))
}

/// Build a verified source-shard `CertifiedBlockHeader` whose `parent_qc`
/// names `parent_hash` and carries `parent_wt`, the parent's canonical
/// weighted timestamp — a placeholder parent QC (not BLS-genuine) used for
/// the boundary block `B`, whose own QC the beacon doesn't verify (only
/// the canonical QC over `B`, supplied as its child's `parent_qc`, is).
/// `witness_root` commits the block's beacon-witness accumulator.
fn make_linked_source_header(
    shard: ShardId,
    height: u64,
    parent_hash: BlockHash,
    parent_wt: u64,
    state_root: StateRoot,
    witness_root: BeaconWitnessRoot,
    leaf_count: u64,
) -> Arc<Verified<CertifiedBlockHeader>> {
    let parent_qc = QuorumCertificate::new(
        parent_hash,
        shard,
        BlockHeight::new(height.saturating_sub(1)),
        BlockHash::ZERO,
        Round::INITIAL,
        SignerBitfield::new(4),
        zero_bls_signature(),
        WeightedTimestamp::from_millis(parent_wt),
    );
    make_source_header_with_parent_qc(
        shard,
        height,
        parent_qc,
        state_root,
        witness_root,
        leaf_count,
    )
}

/// Build a `PcVector` guaranteed to differ from `v`. Used for round-1
/// equivocation: the Byzantine fork signs over this perturbed input so
/// the resulting vote has a distinct signed value at the same
/// `(epoch, view, round)`.
fn perturb_pc_vector(v: &PcVector) -> PcVector {
    // Sentinel element unlikely to collide with any natural input.
    let sentinel = PcValueElement::new([0xCC; 32]);
    let mut elements: Vec<PcValueElement> = v.iter().copied().collect();
    if elements.first() == Some(&sentinel) {
        // Vanishingly unlikely, but defends the property "result !=
        // input" against a worst-case collision.
        elements.insert(0, PcValueElement::new([0xDD; 32]));
    } else {
        elements.insert(0, sentinel);
    }
    PcVector::new(elements)
}
