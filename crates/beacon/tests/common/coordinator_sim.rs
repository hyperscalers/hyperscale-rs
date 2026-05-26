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

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use hyperscale_beacon::constants::{BEACON_SIGNER_COUNT, MIN_STAKE_FLOOR};
use hyperscale_beacon::coordinator::BeaconCoordinator;
use hyperscale_beacon::genesis::build_genesis_beacon_state;
use hyperscale_beacon::pc::{sign_vote1, sign_vote2, sign_vote3};
use hyperscale_beacon::skip::{sign_skip_request, verify_skip_cert, verify_skip_request};
use hyperscale_beacon::spc::{sign_empty_view_msg, verify_block_cert};
use hyperscale_core::Action;
use hyperscale_types::{
    BeaconCert, BeaconGenesisConfig, BeaconProposal, BeaconState, Bls12381G1PrivateKey,
    Bls12381G1PublicKey, CertifiedBeaconBlock, Epoch, GenesisPool, GenesisValidator,
    NetworkDefinition, PcValueElement, PcVector, Randomness, ShardGroupId, SkipEpochCert,
    SkipRequest, SpcMessage, Stake, StakePoolId, ValidatorId, VpcMsgPayload, Witness,
    bls_keypair_from_seed, genesis_config_hash, pc_context, spc_context, vrf_sign,
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
    pub block: Arc<CertifiedBeaconBlock>,
    pub state: BeaconState,
}

/// `(to, event)` envelope queued for delivery on a later `step()`.
struct Envelope {
    to_idx: usize,
    event: SimEvent,
}

#[derive(Clone)]
enum SimEvent {
    PcVote {
        from: ValidatorId,
        payload: Vec<u8>,
    },
    SpcMessage {
        from: ValidatorId,
        payload: Vec<u8>,
    },
    BeaconProposal {
        from: ValidatorId,
        epoch: Epoch,
        proposal: Arc<BeaconProposal>,
    },
    BeaconBlock {
        block: Arc<CertifiedBeaconBlock>,
    },
    SkipRequest {
        request: SkipRequest,
    },
    SkipCert {
        cert: SkipEpochCert,
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
        let genesis_block = Arc::new(CertifiedBeaconBlock::genesis(config_hash));

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
        }
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
        block: Arc<CertifiedBeaconBlock>,
    ) -> Vec<Action> {
        let dispatched = self.coordinators[replica_idx].on_beacon_block_received(block);
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
                Action::VerifyBeaconBlock { block, signers } => {
                    let valid = match block.cert() {
                        BeaconCert::Normal(cert) => verify_block_cert(
                            cert,
                            &self.network,
                            &spc_context(block.epoch()),
                            &signers,
                        ),
                        BeaconCert::Skip(cert) => verify_skip_cert(cert, &self.network, &signers),
                        BeaconCert::Genesis(_) => false,
                    };
                    let post =
                        self.coordinators[replica_idx].on_beacon_block_verified(block, valid);
                    out.extend(self.resolve_verifications(replica_idx, post));
                }
                Action::VerifySkipRequest {
                    request,
                    active_pool,
                } => {
                    let valid = verify_skip_request(&request, &self.network, &active_pool);
                    let post =
                        self.coordinators[replica_idx].on_skip_request_verified(*request, valid);
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
        let request = sign_skip_request(sk, signer, &self.network, anchor, epoch_to_skip);
        // Admit locally first — the production runner feeds the
        // request back into the local coordinator via the action
        // handler's loopback.
        let actions = self.coordinators[signer_idx].on_skip_request_received(request.clone());
        self.absorb(signer_idx, actions);
        // Queue for every peer.
        for to_idx in 0..self.coordinators.len() {
            if to_idx == signer_idx {
                continue;
            }
            self.network_q.push_back(Envelope {
                to_idx,
                event: SimEvent::SkipRequest {
                    request: request.clone(),
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
            SimEvent::PcVote { from, payload } => {
                self.coordinators[env.to_idx].on_pc_vote_received(from, &payload)
            }
            SimEvent::SpcMessage { from, payload } => {
                self.coordinators[env.to_idx].on_spc_message_received(from, &payload)
            }
            SimEvent::BeaconProposal {
                from,
                epoch,
                proposal,
            } => self.coordinators[env.to_idx].on_beacon_proposal_received(from, epoch, proposal),
            SimEvent::BeaconBlock { block } => {
                self.coordinators[env.to_idx].on_beacon_block_received(block)
            }
            SimEvent::SkipRequest { request } => {
                self.coordinators[env.to_idx].on_skip_request_received(request)
            }
            SimEvent::SkipCert { cert } => {
                self.coordinators[env.to_idx].on_skip_cert_received(cert)
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
                let proposal = Arc::new(BeaconProposal::new(witnesses, vrf_output, vrf_proof));
                for rcpt in &recipients {
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
                    let conflicting =
                        Arc::new(BeaconProposal::new(Vec::new(), vrf_output, vrf_proof));
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
                let payload = VpcMsgPayload::Vote1 { view, vote };
                let bytes = payload.encode_bytes();
                self.queue_pc_vote(emitter_idx, me, &recipients, bytes);
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
                    let conflicting_payload = VpcMsgPayload::Vote1 {
                        view,
                        vote: conflicting_vote,
                    };
                    let conflicting_bytes = conflicting_payload.encode_bytes();
                    self.queue_pc_vote(emitter_idx, me, &recipients, conflicting_bytes);
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
                let payload = VpcMsgPayload::Vote2 {
                    view,
                    vote: Box::new(vote),
                };
                let bytes = payload.encode_bytes();
                self.queue_pc_vote(emitter_idx, me, &recipients, bytes);
            }
            Action::SignAndBroadcastPcVote3 {
                epoch,
                view,
                qc2,
                recipients,
            } => {
                let pc_ctx = pc_context(&spc_context(epoch), view);
                let vote = sign_vote3(&self.sks[emitter_idx], me, &self.network, &pc_ctx, *qc2);
                let payload = VpcMsgPayload::Vote3 {
                    view,
                    vote: Box::new(vote),
                };
                let bytes = payload.encode_bytes();
                self.queue_pc_vote(emitter_idx, me, &recipients, bytes);
            }
            Action::SignAndBroadcastEmptyView {
                epoch,
                view,
                reported,
                recipients,
            } => {
                let spc_ctx = spc_context(epoch);
                let msg = sign_empty_view_msg(
                    &self.sks[emitter_idx],
                    me,
                    &self.network,
                    &spc_ctx,
                    view,
                    *reported,
                );
                let wire = SpcMessage::EmptyView(Box::new(msg));
                let bytes = wire.encode_bytes();
                self.queue_spc_message(emitter_idx, me, &recipients, bytes);
            }
            Action::BroadcastSpcNewView {
                epoch: _,
                view,
                cert,
                recipients,
            } => {
                let wire = SpcMessage::NewView { view, cert };
                let bytes = wire.encode_bytes();
                for rcpt in &recipients {
                    let to_idx = self.idx_of(*rcpt);
                    self.network_q.push_back(Envelope {
                        to_idx,
                        event: SimEvent::SpcMessage {
                            from: me,
                            payload: bytes.clone(),
                        },
                    });
                }
            }
            Action::BroadcastSpcNewCommit {
                epoch: _,
                view,
                value,
                proof,
                recipients,
            } => {
                let wire = SpcMessage::NewCommit { view, value, proof };
                let bytes = wire.encode_bytes();
                for rcpt in &recipients {
                    let to_idx = self.idx_of(*rcpt);
                    self.network_q.push_back(Envelope {
                        to_idx,
                        event: SimEvent::SpcMessage {
                            from: me,
                            payload: bytes.clone(),
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
                request,
                recipients: _,
            } => {
                let req = (*request).clone();
                for to_idx in 0..self.coordinators.len() {
                    if to_idx == emitter_idx {
                        continue;
                    }
                    self.network_q.push_back(Envelope {
                        to_idx,
                        event: SimEvent::SkipRequest {
                            request: req.clone(),
                        },
                    });
                }
            }
            Action::BroadcastSkipCert {
                cert,
                recipients: _,
            } => {
                let cert = (*cert).clone();
                for to_idx in 0..self.coordinators.len() {
                    if to_idx == emitter_idx {
                        continue;
                    }
                    self.network_q.push_back(Envelope {
                        to_idx,
                        event: SimEvent::SkipCert { cert: cert.clone() },
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
            Action::VerifyBeaconBlock { block, signers } => {
                // Production runs this on the consensus crypto pool; the
                // sim collapses the round-trip to a synchronous inline
                // verify + result-feedback so the verification-bound
                // pipeline doesn't reshape envelope-delivery ordering
                // relative to the pre-async flow.
                let valid = match block.cert() {
                    BeaconCert::Normal(cert) => verify_block_cert(
                        cert,
                        &self.network,
                        &spc_context(block.epoch()),
                        &signers,
                    ),
                    BeaconCert::Skip(cert) => verify_skip_cert(cert, &self.network, &signers),
                    BeaconCert::Genesis(_) => false,
                };
                let post = self.coordinators[emitter_idx].on_beacon_block_verified(block, valid);
                self.absorb(emitter_idx, post);
            }
            Action::VerifySkipRequest {
                request,
                active_pool,
            } => {
                let valid = verify_skip_request(&request, &self.network, &active_pool);
                let post = self.coordinators[emitter_idx].on_skip_request_verified(*request, valid);
                self.absorb(emitter_idx, post);
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

    fn queue_pc_vote(
        &mut self,
        emitter_idx: usize,
        me: ValidatorId,
        recipients: &[ValidatorId],
        bytes: Vec<u8>,
    ) {
        for rcpt in recipients {
            let to_idx = self.idx_of(*rcpt);
            self.network_q.push_back(Envelope {
                to_idx,
                event: SimEvent::PcVote {
                    from: me,
                    payload: bytes.clone(),
                },
            });
        }
        self.loopback_q.push_back(Envelope {
            to_idx: emitter_idx,
            event: SimEvent::PcVote {
                from: me,
                payload: bytes,
            },
        });
    }

    fn queue_spc_message(
        &mut self,
        emitter_idx: usize,
        me: ValidatorId,
        recipients: &[ValidatorId],
        bytes: Vec<u8>,
    ) {
        for rcpt in recipients {
            let to_idx = self.idx_of(*rcpt);
            self.network_q.push_back(Envelope {
                to_idx,
                event: SimEvent::SpcMessage {
                    from: me,
                    payload: bytes.clone(),
                },
            });
        }
        self.loopback_q.push_back(Envelope {
            to_idx: emitter_idx,
            event: SimEvent::SpcMessage {
                from: me,
                payload: bytes,
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
