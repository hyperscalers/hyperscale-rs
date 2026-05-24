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
    Bls12381G1PrivateKey, Bls12381G1PublicKey, NetworkDefinition, PcQc3, PcVector, Slot, SpcView,
    ValidatorId, bls_keypair_from_seed,
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
    pending: VecDeque<Envelope>,
    pub decided: Vec<Option<Box<PcQc3>>>,
}

impl PcSim {
    /// Build an `n`-party sim. Each party gets a deterministic BLS
    /// keypair seeded from `(seed, validator_id)` and a fresh
    /// [`PcInstance`] for `(slot, view)`.
    #[must_use]
    pub fn new(n: usize, seed: u64, slot: Slot, view: SpcView) -> Self {
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
            .map(|i| {
                PcInstance::new(
                    network.clone(),
                    slot,
                    view,
                    members.clone(),
                    members[i].0,
                    Arc::clone(&sks[i]),
                )
            })
            .collect();
        let decided = vec![None; n];
        Self {
            instances,
            members,
            sks,
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
        for effect in effects {
            match effect {
                PcEffect::BroadcastVote1(vote) => {
                    for (id, _) in &self.members {
                        if self.members[sender_idx].0 == *id {
                            continue;
                        }
                        self.pending.push_back(Envelope {
                            to: *id,
                            event: PcEvent::Vote1Received((*vote).clone()),
                        });
                    }
                }
                PcEffect::BroadcastVote2(vote) => {
                    for (id, _) in &self.members {
                        if self.members[sender_idx].0 == *id {
                            continue;
                        }
                        self.pending.push_back(Envelope {
                            to: *id,
                            event: PcEvent::Vote2Received(vote.clone()),
                        });
                    }
                }
                PcEffect::BroadcastVote3(vote) => {
                    for (id, _) in &self.members {
                        if self.members[sender_idx].0 == *id {
                            continue;
                        }
                        self.pending.push_back(Envelope {
                            to: *id,
                            event: PcEvent::Vote3Received(vote.clone()),
                        });
                    }
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
}
