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

use std::collections::VecDeque;
use std::sync::Arc;

use hyperscale_beacon::constants::{BEACON_SIGNER_COUNT, MIN_STAKE_FLOOR};
use hyperscale_beacon::coordinator::BeaconCoordinator;
use hyperscale_beacon::genesis::{
    BeaconGenesisConfig, GenesisPool, GenesisValidator, build_genesis_beacon_state,
};
use hyperscale_beacon::pc::{sign_vote1, sign_vote2, sign_vote3};
use hyperscale_beacon::spc::sign_empty_view_msg;
use hyperscale_core::Action;
use hyperscale_types::{
    BeaconBlock, BeaconProposal, BeaconState, Bls12381G1PrivateKey, Bls12381G1PublicKey,
    Bls12381G2Signature, Epoch, NetworkDefinition, Randomness, ShardGroupId, SpcMessage, Stake,
    StakePoolId, ValidatorId, VpcMsgPayload, beacon_block_header_message, bls_keypair_from_seed,
    pc_context, spc_context, state_root, vrf_sign,
};

/// One captured commit event from a replica's `Action::CommitBeaconBlock`.
#[derive(Clone)]
pub struct CapturedCommit {
    pub epoch: Epoch,
    pub block: Arc<BeaconBlock>,
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
    BeaconBlockSig {
        from: ValidatorId,
        epoch: Epoch,
        sig: Bls12381G2Signature,
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
            initial_randomness: Randomness([0x42; 32]),
        };

        let initial_state = build_genesis_beacon_state(&config);
        let genesis_block = Arc::new(BeaconBlock::genesis(state_root(&initial_state)));

        let coordinators: Vec<BeaconCoordinator> = (0..n)
            .map(|i| {
                BeaconCoordinator::new(
                    Arc::clone(&genesis_block),
                    initial_state.clone(),
                    members[i].0,
                    network.clone(),
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
    pub fn step(&mut self) -> bool {
        let env = self
            .network_q
            .pop_front()
            .or_else(|| self.loopback_q.pop_front());
        let Some(env) = env else {
            return false;
        };
        let emitter_idx = env.to_idx;
        let actions = self.deliver(env);
        self.absorb(emitter_idx, actions);
        true
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
            SimEvent::BeaconBlockSig { from, epoch, sig } => {
                self.coordinators[env.to_idx].on_beacon_block_sig_received(from, epoch, sig)
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
                witnesses,
                recipients,
            } => {
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
            }
            Action::SignAndBroadcastPcVote1 {
                epoch,
                view,
                v_in,
                recipients,
            } => {
                let pc_ctx = pc_context(&spc_context(epoch), view);
                let vote = sign_vote1(&self.sks[emitter_idx], me, &self.network, &pc_ctx, v_in);
                let payload = VpcMsgPayload::Vote1 { view, vote };
                let bytes = payload.encode_bytes();
                self.queue_pc_vote(emitter_idx, me, &recipients, bytes);
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
            Action::SignAndBroadcastBeaconBlockHeader {
                epoch,
                header,
                recipients,
            } => {
                let msg = beacon_block_header_message(&self.network, &header);
                let sig = self.sks[emitter_idx].sign_v1(&msg);
                for rcpt in &recipients {
                    let to_idx = self.idx_of(*rcpt);
                    self.network_q.push_back(Envelope {
                        to_idx,
                        event: SimEvent::BeaconBlockSig {
                            from: me,
                            epoch,
                            sig,
                        },
                    });
                }
                self.loopback_q.push_back(Envelope {
                    to_idx: emitter_idx,
                    event: SimEvent::BeaconBlockSig {
                        from: me,
                        epoch,
                        sig,
                    },
                });
            }
            Action::CommitBeaconBlock { block, state } => {
                self.commits[emitter_idx].push(CapturedCommit {
                    epoch: block.epoch(),
                    block,
                    state: *state,
                });
            }
            Action::BroadcastBeaconBlock { .. }
            | Action::SetTimer { .. }
            | Action::CancelTimer { .. } => {}
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
