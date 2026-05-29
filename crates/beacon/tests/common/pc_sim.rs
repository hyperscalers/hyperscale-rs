//! Minimal multi-party PC sim — drives a set of [`PcInstance`]s by
//! fan-out-broadcasting their emitted vote effects to every peer's
//! inbox.
//!
//! Deterministic and adversary-free: every broadcast lands at every
//! peer (other than the sender) on the next `step()`. Adversarial
//! variants (silent parties, equivocation, message reordering) build
//! on this skeleton.

use std::collections::VecDeque;
use std::sync::Arc;

use hyperscale_beacon::pc::{PcEffect, PcEvent, PcInstance};
use hyperscale_types::{
    Bls12381G1PrivateKey, Bls12381G1PublicKey, Epoch, NetworkDefinition, PcContext, PcQc3,
    PcVector, SpcView, ValidatorId, bls_keypair_from_seed, pc_context, sign_vote1, sign_vote2,
    sign_vote3, spc_context,
};

/// One pending message in the network: a vote event addressed to a
/// specific party.
struct Envelope {
    to: ValidatorId,
    event: PcEvent,
}

pub struct PcSim {
    pub instances: Vec<PcInstance>,
    pub members: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    pub sks: Vec<Arc<Bls12381G1PrivateKey>>,
    network: NetworkDefinition,
    pc_ctx: PcContext,
    pending: VecDeque<Envelope>,
    pub decided: Vec<Option<Box<PcQc3>>>,
}

impl PcSim {
    /// Build an `n`-party sim. Each party gets a deterministic BLS
    /// keypair seeded from `(seed, validator_id)` and a fresh
    /// [`PcInstance`] for `(epoch, view)`.
    #[must_use]
    pub fn new(n: usize, seed: u64, epoch: Epoch, view: SpcView) -> Self {
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
        let instances: Vec<PcInstance> = (0..n)
            .map(|_| PcInstance::new(epoch, view, members.clone()))
            .collect();
        let decided = vec![None; n];
        let pc_ctx = pc_context(&spc_context(epoch), view);
        Self {
            instances,
            members,
            sks,
            network,
            pc_ctx,
            pending: VecDeque::new(),
            decided,
        }
    }

    /// Tuple-up `(secret_key, validator_id)` for each of the indices —
    /// used by SPC tests that need to sign empty-view messages with
    /// the same keys PC used.
    #[must_use]
    pub fn sks_for_indices(
        &self,
        indices: &[usize],
    ) -> Vec<(Arc<Bls12381G1PrivateKey>, ValidatorId)> {
        indices
            .iter()
            .map(|&i| (Arc::clone(&self.sks[i]), self.members[i].0))
            .collect()
    }

    /// Feed party `idx`'s local input vector. Drains the resulting
    /// broadcast effects into pending envelopes.
    pub fn input(&mut self, idx: usize, v: PcVector) {
        let effects = self.instances[idx].handle(PcEvent::Input(v));
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
    /// exceeded. Returns the actual step count taken.
    ///
    /// # Panics
    ///
    /// Panics if `max_steps` is exceeded — typically signals a sim
    /// liveness bug rather than something to handle silently.
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

    /// Whether every party has emitted a `Decided` effect.
    #[must_use]
    pub fn all_decided(&self) -> bool {
        self.decided.iter().all(Option::is_some)
    }

    /// Read party `idx`'s terminal cert if it's been emitted.
    #[must_use]
    pub fn decided(&self, idx: usize) -> Option<&PcQc3> {
        self.decided[idx].as_deref()
    }

    fn absorb(&mut self, sender_idx: usize, effects: Vec<PcEffect>) {
        let sender = self.members[sender_idx].0;
        let sk = Arc::clone(&self.sks[sender_idx]);
        for effect in effects {
            match effect {
                PcEffect::SignAndBroadcastVote1 { v_in } => {
                    let vote = sign_vote1(&sk, sender, &self.network, &self.pc_ctx, v_in);
                    self.deliver_to_all(&PcEvent::Vote1Verified(vote));
                }
                PcEffect::SignAndBroadcastVote2 { qc1 } => {
                    let vote = sign_vote2(&sk, sender, &self.network, &self.pc_ctx, *qc1);
                    self.deliver_to_all(&PcEvent::Vote2Verified(Box::new(vote)));
                }
                PcEffect::SignAndBroadcastVote3 { qc2 } => {
                    let vote = sign_vote3(&sk, sender, &self.network, &self.pc_ctx, *qc2);
                    self.deliver_to_all(&PcEvent::Vote3Verified(Box::new(vote)));
                }
                PcEffect::EquivocationObserved(_) => {
                    // Honest path: no equivocations to absorb.
                }
                PcEffect::Decided(qc3) => {
                    self.decided[sender_idx] = Some(qc3);
                }
            }
        }
    }

    /// Deliver `event` to every party in the committee, including the
    /// sender — the production action handler feeds locally-signed
    /// votes back into the state machine, so the sim's own vote lands
    /// the same way.
    fn deliver_to_all(&mut self, event: &PcEvent) {
        for (id, _) in &self.members {
            self.pending.push_back(Envelope {
                to: *id,
                event: event.clone(),
            });
        }
    }
}
