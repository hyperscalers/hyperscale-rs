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
//! PC commits all-`HASH_BOTTOM`s every epoch — the honest path still
//! terminates but exercises an uninteresting branch.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use hyperscale_beacon::coordinator::BeaconCoordinator;
use hyperscale_beacon::genesis::build_genesis_beacon_state;
use hyperscale_core::Action;
use hyperscale_types::network::request::beacon::GetBeaconProposalRequest;
use hyperscale_types::{
    BEACON_SIGNER_COUNT, BeaconCert, BeaconGenesisConfig, BeaconProposal, BeaconState,
    Bls12381G1PrivateKey, Bls12381G1PublicKey, CertifiedBeaconBlock,
    CertifiedBeaconBlockVerifyContext, Epoch, GenesisPool, GenesisValidator, MIN_STAKE_FLOOR,
    NetworkDefinition, PcValueElement, PcVector, PcVote1, PcVote2, PcVote3, PcVoteVerifyContext,
    Randomness, ShardGroupId, SkipEpochCert, SkipRequest, SkipVerifyContext, SpcEmptyViewMsg,
    SpcNewCommitMsg, SpcProposalObject, SpcVerifyContext, SpcView, Stake, StakePoolId, ValidatorId,
    Verifiable, Verified, Witness, bls_keypair_from_seed, genesis_config_hash, pc_context,
    sign_empty_view_msg, sign_vote1, sign_vote2, sign_vote3, spc_context, verify_skip_cert,
    verify_vote1, verify_vote2, verify_vote3, vrf_sign,
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
    ///
    /// Round-2 and round-3 equivocation are not modelled: they require
    /// fabricating divergent embedded QC1/QC2s, which the protocol's
    /// pool aggregation makes structurally hard to forge.
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
    SkipCert {
        cert: Arc<Verifiable<SkipEpochCert>>,
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
    /// Witnesses scheduled to splice into the next `BuildAndBroadcastBeaconProposal`
    /// at the keyed epoch, regardless of which replica emits it.
    /// Consumed (drained) the first time a proposal at that epoch is
    /// absorbed.
    pending_topology_changes: BTreeMap<Epoch, Vec<Witness>>,
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
        let shard = ShardGroupId::new(0);
        let config = BeaconGenesisConfig {
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

        let coordinators: Vec<BeaconCoordinator> = (0..n)
            .map(|i| {
                BeaconCoordinator::new(
                    Arc::clone(&genesis_block),
                    initial_state.clone(),
                    members[i].0,
                    network.clone(),
                    config_hash,
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
            pending_topology_changes: BTreeMap::new(),
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

    /// Splice `witnesses` into the next `BuildAndBroadcastBeaconProposal`
    /// at `epoch` that the sim absorbs. Tests use this to inject
    /// topology-mutating witnesses (e.g. `DeactivateValidator`) that the
    /// natural sim driver wouldn't otherwise produce. Witnesses for a
    /// given epoch are drained on first fire.
    pub fn inject_topology_change(&mut self, epoch: Epoch, witnesses: Vec<Witness>) {
        self.pending_topology_changes
            .entry(epoch)
            .or_default()
            .extend(witnesses);
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
                    let result = (*request)
                        .upgrade(&SkipVerifyContext {
                            network: &self.network,
                            active_pool: &signers,
                        })
                        .map_err(|(_, e)| e);
                    let post = self.coordinators[replica_idx].on_skip_request_verified(result);
                    out.extend(self.resolve_verifications(replica_idx, post));
                }
                other => out.push(other),
            }
        }
        out
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

    /// Fire the committee-start timer on every replica. In production
    /// this happens once wall-clock reaches the upcoming epoch's
    /// boundary; here the sim just kicks all replicas in lockstep so
    /// the first epoch's SPC instances bootstrap and `try_propose`
    /// emits the initial `BuildAndBroadcastBeaconProposal` actions.
    pub fn kick_off(&mut self) {
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
            assert!(
                self.step(),
                "sim went quiescent at step {steps} with commits {:?} < target {target_commits}",
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

    fn deliver(&mut self, env: Envelope) -> Vec<Action> {
        match env.event {
            SimEvent::PcVote1 { from, view, vote } => {
                self.coordinators[env.to_idx].on_pc_vote1_received(from, view, vote)
            }
            SimEvent::PcVote2 { from, view, vote } => {
                self.coordinators[env.to_idx].on_pc_vote2_received(from, view, vote)
            }
            SimEvent::PcVote3 { from, view, vote } => {
                self.coordinators[env.to_idx].on_pc_vote3_received(from, view, vote)
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
            SimEvent::SkipCert { cert } => {
                self.coordinators[env.to_idx].on_skip_cert_received(cert)
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
                mut witnesses,
                recipients,
            } => {
                // Splice in any test-scheduled witnesses for this epoch
                // before the proposal's VRF reveal is signed. Consumed
                // on first fire so only one replica's broadcast picks
                // them up — that's enough to carry them to commit.
                if let Some(extras) = self.pending_topology_changes.remove(&epoch) {
                    witnesses.extend(extras);
                }
                let sk = &self.sks[emitter_idx];
                let (vrf_output, vrf_proof) = vrf_sign(sk, &self.network, epoch);
                let proposal = Arc::new(Verified::new_unchecked_for_test(BeaconProposal::new(
                    witnesses, vrf_output, vrf_proof,
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
                        BeaconProposal::new(Vec::new(), vrf_output, vrf_proof),
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
            Action::BroadcastSkipRequest { request } => {
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
            Action::BroadcastSkipCert { cert } => {
                let wire = Arc::new(Verifiable::from((*cert).clone()));
                for to_idx in 0..self.coordinators.len() {
                    if to_idx == emitter_idx {
                        continue;
                    }
                    self.network_q.push_back(Envelope {
                        to_idx,
                        event: SimEvent::SkipCert {
                            cert: Arc::clone(&wire),
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
                // verify + result-feedback so the verification-bound
                // pipeline doesn't reshape envelope-delivery ordering
                // relative to the pre-async flow.
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
                let result = (*request)
                    .upgrade(&SkipVerifyContext {
                        network: &self.network,
                        active_pool: &signers,
                    })
                    .map_err(|(_, e)| e);
                let post = self.coordinators[emitter_idx].on_skip_request_verified(result);
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
            Action::FetchBeaconProposal {
                epoch,
                validator,
                peers,
            } => {
                // Walk the recipient peers, ask each in turn for the
                // proposal via its `serve_beacon_proposal_request`
                // method, and queue the first non-empty response back
                // to the emitter. Empty if no peer has it.
                let req = GetBeaconProposalRequest::new(epoch, validator);
                let proposal = peers.iter().find_map(|peer| {
                    let peer_idx = self.idx_of(*peer);
                    self.coordinators[peer_idx]
                        .serve_beacon_proposal_request(&req)
                        .proposal
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
            Action::SetTimer { .. }
            | Action::CancelTimer { .. }
            | Action::TopologyChanged { .. } => {}
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
