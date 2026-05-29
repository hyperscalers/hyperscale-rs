//! Minimal multi-party SPC sim — drives a set of [`SpcInstance`]s by
//! fan-out-broadcasting their emitted effects to every peer's inbox.
//!
//! Deterministic and adversary-free, mirroring `PcSim`'s shape:
//! every broadcast lands at every peer (other than the sender) on the
//! next `step()`. `SetTimer` effects are ignored — timer-driven view
//! changes need a `Duration`-aware test scaffold that this skeleton
//! deliberately omits.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_beacon::spc::{SpcEffect, SpcEvent, SpcInstance, sign_empty_view_msg};
use hyperscale_types::{
    Bls12381G1PrivateKey, Bls12381G1PublicKey, Epoch, NetworkDefinition, PcVector, SpcView,
    ValidatorId, bls_keypair_from_seed, pc_context, sign_vote1, sign_vote2, sign_vote3,
    spc_context,
};

/// One pending event in the network: an `SpcEvent` addressed to a
/// specific party.
struct Envelope {
    to: ValidatorId,
    event: SpcEvent,
}

pub struct SpcSim {
    pub instances: Vec<SpcInstance>,
    pub members: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    pub sks: Vec<Arc<Bls12381G1PrivateKey>>,
    network: NetworkDefinition,
    epoch: Epoch,
    pending: VecDeque<Envelope>,
    pub outputs: Vec<Option<PcVector>>,
}

impl SpcSim {
    /// Build an `n`-party sim. Each party gets a deterministic BLS
    /// keypair seeded from `(seed, validator_id)` and a fresh
    /// [`SpcInstance`] for `epoch`.
    #[must_use]
    pub fn new(n: usize, seed: u64, epoch: Epoch, view_timeout: Duration) -> Self {
        let network = NetworkDefinition::simulator();
        let mut sks = Vec::with_capacity(n);
        let mut members = Vec::with_capacity(n);
        for i in 0..n {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&seed.to_le_bytes());
            bytes[8..16].copy_from_slice(&(i as u64).to_le_bytes());
            let sk = bls_keypair_from_seed(&bytes);
            members.push((ValidatorId::new(i as u64), sk.public_key()));
            sks.push(Arc::new(sk));
        }
        let instances: Vec<SpcInstance> = (0..n)
            .map(|i| SpcInstance::new(epoch, members.clone(), members[i].0, view_timeout))
            .collect();
        let outputs = vec![None; n];
        Self {
            instances,
            members,
            sks,
            network,
            epoch,
            pending: VecDeque::new(),
            outputs,
        }
    }

    /// Feed party `idx`'s local input vector.
    pub fn input(&mut self, idx: usize, v: PcVector) {
        let effects = self.instances[idx].handle(SpcEvent::Input(v));
        self.absorb(idx, effects);
    }

    /// Drive one pending message through the sim. Returns `true` if a
    /// message was delivered, `false` once the queue drains.
    pub fn step(&mut self) -> bool {
        let Some(env) = self.pending.pop_front() else {
            return false;
        };
        let idx = self
            .members
            .iter()
            .position(|(id, _)| *id == env.to)
            .expect("addressed party in committee");
        let effects = self.instances[idx].handle(env.event);
        self.absorb(idx, effects);
        true
    }

    /// Run the sim until the pending queue drains or `max_steps` is
    /// exceeded.
    ///
    /// # Panics
    ///
    /// Panics if `max_steps` is exceeded — typically a liveness bug.
    pub fn run_until_quiescent(&mut self, max_steps: usize) -> usize {
        let mut steps = 0;
        while self.step() {
            steps += 1;
            assert!(
                steps <= max_steps,
                "sim exceeded {max_steps} steps without quiescence"
            );
        }
        steps
    }

    /// Whether every party has latched `OutputHigh`.
    #[must_use]
    pub fn all_decided(&self) -> bool {
        self.outputs.iter().all(Option::is_some)
    }

    /// Read party `idx`'s high output if it's been latched.
    #[must_use]
    pub fn output(&self, idx: usize) -> Option<&PcVector> {
        self.outputs[idx].as_ref()
    }

    fn absorb(&mut self, sender_idx: usize, effects: Vec<SpcEffect>) {
        let sender = self.members[sender_idx].0;
        let sk = Arc::clone(&self.sks[sender_idx]);
        for effect in effects {
            match effect {
                SpcEffect::SignAndBroadcastPcVote1 { view, v_in } => {
                    let pc_ctx = pc_context(&spc_context(self.epoch), view);
                    let vote = sign_vote1(&sk, sender, &self.network, &pc_ctx, v_in);
                    self.deliver_to_all(&SpcEvent::PcVote1Verified { view, vote });
                }
                SpcEffect::SignAndBroadcastPcVote2 { view, qc1 } => {
                    let pc_ctx = pc_context(&spc_context(self.epoch), view);
                    let vote = sign_vote2(&sk, sender, &self.network, &pc_ctx, *qc1);
                    self.deliver_to_all(&SpcEvent::PcVote2Verified {
                        view,
                        vote: Box::new(vote),
                    });
                }
                SpcEffect::SignAndBroadcastPcVote3 { view, qc2 } => {
                    let pc_ctx = pc_context(&spc_context(self.epoch), view);
                    let vote = sign_vote3(&sk, sender, &self.network, &pc_ctx, *qc2);
                    self.deliver_to_all(&SpcEvent::PcVote3Verified {
                        view,
                        vote: Box::new(vote),
                    });
                }
                SpcEffect::BroadcastNewView { view, cert } => {
                    let from = sender;
                    self.fanout(sender_idx, |_| SpcEvent::NewViewVerified {
                        from,
                        view,
                        cert: cert.clone(),
                    });
                }
                SpcEffect::BroadcastNewCommit { view, value, proof } => {
                    self.fanout(sender_idx, |_| SpcEvent::NewCommitVerified {
                        view,
                        value: value.clone(),
                        proof: proof.clone(),
                    });
                }
                SpcEffect::SignAndBroadcastEmptyView { view, reported } => {
                    let spc_ctx = spc_context(self.epoch);
                    let msg =
                        sign_empty_view_msg(&sk, sender, &self.network, &spc_ctx, view, *reported);
                    self.deliver_to_all(&SpcEvent::EmptyViewVerified(Box::new(msg)));
                }
                SpcEffect::SetTimer { .. } | SpcEffect::Equivocation { .. } => {
                    // Honest path: no timer firing, no equivocation to absorb.
                }
                SpcEffect::OutputHigh { value, cert: _ } => {
                    self.outputs[sender_idx] = Some(value);
                }
            }
        }
    }

    /// Deliver `event` to every party in the committee, including the
    /// sender — the production action handler feeds locally-signed
    /// PC votes back into the state machine, so the sim's own vote
    /// lands the same way.
    fn deliver_to_all(&mut self, event: &SpcEvent) {
        for (id, _) in &self.members {
            self.pending.push_back(Envelope {
                to: *id,
                event: event.clone(),
            });
        }
    }

    fn fanout(&mut self, sender_idx: usize, mut mk_event: impl FnMut(ValidatorId) -> SpcEvent) {
        for (id, _) in &self.members {
            if self.members[sender_idx].0 == *id {
                continue;
            }
            self.pending.push_back(Envelope {
                to: *id,
                event: mk_event(*id),
            });
        }
    }
}
