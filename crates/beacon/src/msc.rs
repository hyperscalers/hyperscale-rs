#![allow(dead_code)]

//! Multi-Slot Consensus — pure helpers + verifiers.
//!
//! MSC composes per-slot [`SpcInstance`](crate::spc::SpcInstance)s
//! into the beacon's slot pipeline. Each slot's SPC committee submits
//! their [`MscSlotProposal`] payloads; MSC hashes them into a
//! [`PcVector`] input that the slot's SPC then drives to consensus.
//!
//! This module hosts the **verify** side of MSC — pure functions over
//! the wire types in `hyperscale_types::beacon::msc`. The FSM
//! ([`MscInstance`](`crate::msc::MscInstance`)), per-slot SPC plumbing,
//! and accusation/rank bookkeeping live in their own sub-modules.
//!
//! # `update_rank` and the demotion rule
//!
//! Each slot starts with a `rank^MC_{i,s}` ranking that determines the
//! slot's proposer-rotation. The slot's high output `b_i,s^out` then
//! drives `update_rank` to compute `rank^MC_{i,s+1}`:
//!
//! - Validators in `accused` (empty-low witnesses from the prior
//!   slot's inner SPC views) get demoted to the end of the ranking.
//! - If the prior slot's high vector is shorter than the committee
//!   (`|prev_high| < n`), the validator at position `|prev_high|` is
//!   also demoted (their proposal didn't make the cut).
//! - Non-demoted validators preserve their relative order.
//!
//! Refuses to demote everyone: with `≥ n` demotions the next slot
//! would have no head for its cyclic rotation, breaking liveness. By
//! the protocol's safety theorem an honest committee never produces
//! more than `f` empty-low accusations per slot, so even with the
//! first-excluded fold-in we have at most `f + 1 ≤ n - 1` demotions
//! in honest execution.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use blake3::Hasher;
use hyperscale_types::{
    Bls12381G1PrivateKey, Bls12381G1PublicKey, MscEmptyLowAccusation, MscSlotProposal,
    NetworkDefinition, PC_VALUE_ELEMENT_BYTES, PcValueElement, PcVector, PcVoteEquivocation, Slot,
    SpcEmptyLowEvidence, SpcView, ValidatorId, spc_context,
};
use sbor::basic_encode;

use crate::spc::{
    SpcEffect, SpcEvent, SpcInstance, SpcMessage, rank_shift_for_view, verify_empty_low_evidence,
};

/// Largest gap between a peer's claimed `slot` and our current slot
/// for which we still buffer the proposal. Beyond this we drop —
/// catch-up via state-sync is the right move at that distance.
const FUTURE_SLOT_LOOKAHEAD: u64 = 4;

/// Cap on `pending_inputs`. Inputs past this are silently dropped —
/// the application sees rate-mismatch via lack of slot progress.
#[allow(clippy::cast_possible_truncation)] // `FUTURE_SLOT_LOOKAHEAD = 4` fits in any pointer width
const PENDING_INPUTS_CAP: usize = 16 * FUTURE_SLOT_LOOKAHEAD as usize;

/// Domain tag for the canonical encoding of an [`MscSlotProposal`]
/// when hashing into a [`PcValueElement`] for the slot's SPC input.
const SLOT_PROPOSAL_DOMAIN: &[u8] = b"hyperscale-msc-slot-proposal-v1";

/// Domain tag for the bottom-collision rehash fallback in
/// [`hash_proposal_msc`].
const SLOT_PROPOSAL_BOTTOM_DOMAIN: &[u8] = b"hyperscale-msc-slot-proposal-bottom-collision-v1";

/// All-zero sentinel for "no proposal from this position" in a slot's
/// SPC input vector. Distinct from
/// [`crate::spc::HASH_BOTTOM`](crate::spc) at the byte level only —
/// both are the same `[0; 32]` value but used in different namespaces.
const HASH_BOTTOM: PcValueElement = PcValueElement::new([0u8; PC_VALUE_ELEMENT_BYTES]);

/// Canonical bytes for an [`MscSlotProposal`] — the preimage of
/// [`hash_proposal_msc`]. Layout: `domain || slot (8 LE) || content
/// (SBOR)`. Not signed; consumed only by the proposal-hash pipeline.
fn slot_proposal_message(p: &MscSlotProposal) -> Vec<u8> {
    let mut buf = Vec::with_capacity(SLOT_PROPOSAL_DOMAIN.len() + 8 + 256);
    buf.extend_from_slice(SLOT_PROPOSAL_DOMAIN);
    buf.extend_from_slice(&p.slot.to_le_bytes());
    let content_bytes = basic_encode(&p.content).expect("PcVector SBOR encoding should never fail");
    buf.extend_from_slice(&content_bytes);
    buf
}

/// Blake3-hash an [`MscSlotProposal`] into a [`PcValueElement`]
/// suitable for the slot's SPC input vector.
///
/// Fallback rehash avoids accidental collision with [`HASH_BOTTOM`]:
/// if the natural digest happens to land on all-zeros, a tag-prefixed
/// rehash moves it elsewhere while preserving full collision
/// resistance against other inputs.
#[must_use]
pub fn hash_proposal_msc(p: &MscSlotProposal) -> PcValueElement {
    let bytes = slot_proposal_message(p);
    let mut raw = [0u8; PC_VALUE_ELEMENT_BYTES];
    raw.copy_from_slice(Hasher::new().update(&bytes).finalize().as_bytes());
    if PcValueElement::new(raw) == HASH_BOTTOM {
        let mut h2 = Hasher::new();
        h2.update(SLOT_PROPOSAL_BOTTOM_DOMAIN);
        h2.update(&raw);
        raw.copy_from_slice(h2.finalize().as_bytes());
    }
    PcValueElement::new(raw)
}

/// Verify an [`MscEmptyLowAccusation`]: the embedded `PcQc3` verifies
/// under the SPC context for `accusation.slot` and certifies an
/// empty low at `accusation.view` (which must be `> 1`).
///
/// The accusation's `slot` field determines the SPC context, so a
/// `PcQc3` produced under a different slot's SPC won't verify here —
/// peers can't cross-pollute accusations between slots.
#[must_use]
pub fn verify_empty_low_accusation(
    accusation: &MscEmptyLowAccusation,
    network: &NetworkDefinition,
    committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    let spc_ctx = spc_context(accusation.slot);
    let evidence = SpcEmptyLowEvidence {
        view: accusation.view,
        proof: accusation.proof.clone(),
    };
    verify_empty_low_evidence(&evidence, network, &spc_ctx, committee)
}

/// Compute the validator the accusation demotes — the cyclic-first
/// party in the accused view's ranking within the slot's SPC instance.
///
/// `slot_initial_rank` is the slot's SPC initial ranking; the accused
/// validator is at position `rank_shift_for_view(accusation.view, n)`
/// after the rotation. Returns `None` only if `slot_initial_rank` is
/// empty.
#[must_use]
pub fn accusation_demotes(
    accusation: &MscEmptyLowAccusation,
    slot_initial_rank: &[ValidatorId],
) -> Option<ValidatorId> {
    if slot_initial_rank.is_empty() {
        return None;
    }
    let shifts = rank_shift_for_view(accusation.view, slot_initial_rank.len());
    Some(slot_initial_rank[shifts])
}

/// Compute the next slot's ranking from the prior slot's `(rank,
/// high_output, accused)` triple.
///
/// Validators in `accused` get demoted to the end of the ranking. If
/// `prev_high.len() < prev_rank.len()`, the validator at position
/// `prev_high.len()` is also demoted (their proposal didn't make the
/// cut). Non-demoted validators preserve their relative order.
///
/// **Refuses to demote everyone:** if the computed demoted-set would
/// cover the entire `prev_rank`, returns `prev_rank` unchanged. This
/// preserves liveness — an honest committee never produces `≥ n`
/// accusations per slot, so this branch only fires on a Byzantine-
/// constructed accusation stream that's already evidence on its own.
#[must_use]
pub fn update_rank(
    prev_rank: &[ValidatorId],
    prev_high: &PcVector,
    accused: &BTreeSet<ValidatorId>,
) -> Vec<ValidatorId> {
    let n = prev_rank.len();
    let l = prev_high.len();

    let mut demoted: BTreeSet<ValidatorId> = accused.iter().copied().collect();
    if l < n {
        demoted.insert(prev_rank[l]);
    }
    if demoted.len() >= n || demoted.is_empty() {
        return prev_rank.to_vec();
    }

    let mut kept = Vec::with_capacity(n);
    let mut tail = Vec::with_capacity(demoted.len());
    for &p in prev_rank {
        if demoted.contains(&p) {
            tail.push(p);
        } else {
            kept.push(p);
        }
    }
    kept.extend(tail);
    kept
}

// ─── FSM ───────────────────────────────────────────────────────────────────

/// What [`MscInstance::handle`] tells the beacon coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MscEffect {
    /// Broadcast our own slot proposal to peers (paper line 10).
    BroadcastProposal {
        /// Slot this proposal targets.
        slot: Slot,
        /// Application-encoded payload for the slot.
        content: PcVector,
        /// Empty-low accusations harvested from prior slots' inner
        /// SPC views and bundled into this proposal.
        accusations: Vec<MscEmptyLowAccusation>,
    },
    /// Broadcast an inner-SPC message, tagged with the slot it belongs
    /// to so peers route it to the right `SpcInstance`.
    BroadcastSpcMsg {
        /// Slot whose SPC instance produced this message.
        slot: Slot,
        /// The wire-form SPC message.
        msg: Box<SpcMessage>,
    },
    /// Schedule a timer. The parent (coordinator) fires
    /// [`MscEvent::TimerExpired`] when it elapses.
    SetTimer {
        /// Which timer this is — `Slot` for proposal-collection
        /// timeouts, `View` for SPC view timers.
        id: MscTimerId,
        /// How long to wait before firing.
        duration: Duration,
    },
    /// A slot's high output committed. `included` lists the preimages
    /// of every non-bottom entry in rank order — the slot's agreed
    /// output set `b_i,s^out`.
    SlotCommitted {
        /// Committed slot.
        slot: Slot,
        /// `(sender, content)` pairs in rank order, skipping bottom
        /// slots.
        included: Vec<(ValidatorId, PcVector)>,
    },
    /// Pass-through of an inner-PC equivocation surfaced by SPC.
    /// Tagged with `(slot, view)` so a downstream verifier can
    /// rebuild the inner PC context.
    Equivocation {
        /// Slot whose SPC instance routed this equivocation.
        slot: Slot,
        /// SPC view within that slot.
        view: SpcView,
        /// Slim wire-form evidence of the double-sign.
        evidence: Box<PcVoteEquivocation>,
    },
}

/// Events [`MscInstance::handle`] consumes.
#[derive(Debug, Clone)]
pub enum MscEvent {
    /// Application input for the next slot. Queued and consumed when
    /// the prior slot's commit clears the way.
    Input(PcVector),
    /// `proposal = (s, b_p,s)` from a peer, with any empty-low
    /// accusations the sender accumulated from earlier slots' SPC
    /// views.
    Proposal {
        /// Validator that relayed this proposal.
        from: ValidatorId,
        /// Slot the proposal targets.
        slot: Slot,
        /// Application-encoded payload for the slot.
        content: PcVector,
        /// Empty-low accusations attached to this proposal.
        accusations: Vec<MscEmptyLowAccusation>,
    },
    /// Inner-SPC message from a peer, tagged with the slot it belongs
    /// to.
    SpcMsg {
        /// Transport-level sender id.
        from: ValidatorId,
        /// Slot whose SPC instance owns this message.
        slot: Slot,
        /// The wire-form SPC message.
        msg: Box<SpcMessage>,
    },
    /// Timer expiry — slot proposal-collection deadline or SPC view
    /// timer.
    TimerExpired {
        /// Which timer fired.
        id: MscTimerId,
    },
}

/// Timer identifiers used by [`MscEffect::SetTimer`] /
/// [`MscEvent::TimerExpired`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MscTimerId {
    /// `2Δ` slot proposal-collection timer.
    Slot(Slot),
    /// SPC view timer for `slot`'s instance at `view`.
    View {
        /// Slot whose SPC instance owns this view timer.
        slot: Slot,
        /// View the timer applies to.
        view: SpcView,
    },
}

/// Per-slot local state owned by [`MscInstance`].
struct SlotState {
    /// `B_i,s[·]` — buffered slot proposals indexed by sender.
    proposals: BTreeMap<ValidatorId, MscSlotProposal>,
    /// `rank^MC_{i,s}` — ranking used for this slot's hash-vector
    /// ordering. Retained even for pruned slots so cross-slot
    /// accusation processing can still resolve cyclic-first parties.
    rank: Vec<ValidatorId>,
    /// Inner SPC instance, lazily constructed on slot entry.
    spc: SpcInstance,
    /// `true` once we've fed input into the inner SPC.
    spc_input_fed: bool,
    /// Cached high output once committed.
    committed_high: Option<PcVector>,
    /// Whether [`MscEffect::SlotCommitted`] has been emitted for this
    /// slot. (Effect itself lands in B.4.3.c.)
    output_emitted: bool,
    /// Validated accusations attached to peers' proposals for this
    /// slot. Their union, deduplicated by accused validator, drives
    /// the demotion step of [`update_rank`] for the next slot.
    accusations: Vec<MscEmptyLowAccusation>,
}

/// One MSC FSM instance, scoped to a single beacon chain. Owns the
/// per-slot [`SpcInstance`]s and drives them through the slot
/// pipeline.
pub struct MscInstance {
    network: NetworkDefinition,
    committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
    me: ValidatorId,
    me_sk: Arc<Bls12381G1PrivateKey>,
    initial_rank: Vec<ValidatorId>,
    slot_timeout: Duration,
    view_timeout: Duration,

    /// Highest slot we've started. `0` means slot 1 not yet started
    /// (waiting for first input).
    current_slot: u64,
    slots: BTreeMap<Slot, SlotState>,
    /// Queue of application inputs waiting to be used.
    pending_inputs: VecDeque<PcVector>,
    /// Hash → proposal preimages, populated as we accept proposals.
    /// Lookup table for commit resolution.
    proposals_by_hash: BTreeMap<PcValueElement, (ValidatorId, MscSlotProposal)>,
    /// Empty-low evidences emitted by the inner SPC of `current_slot`,
    /// queued for inclusion in the *next* slot's outgoing proposal.
    /// Populated by B.4.3.c when the SPC plumbing lands.
    pending_accusations: Vec<MscEmptyLowAccusation>,
    /// `(slot, view)` pairs already folded into a rank computation.
    /// Re-presentation by peers is rejected at storage time.
    consumed_accusations: BTreeSet<(Slot, SpcView)>,
    /// Proposals received for slots strictly in the future. Keyed by
    /// `(slot, sender)` so a single peer can hold at most one buffered
    /// entry per future slot. Drained on `start_next_slot`.
    future_proposals:
        BTreeMap<Slot, BTreeMap<ValidatorId, (MscSlotProposal, Vec<MscEmptyLowAccusation>)>>,
}

impl MscInstance {
    /// Construct a fresh MSC instance.
    ///
    /// `initial_rank` is the ranking used for slot 1's SPC committee
    /// rotation; must list every validator in `committee` exactly
    /// once.
    ///
    /// # Panics
    ///
    /// Panics if `initial_rank.len() != committee.len()` or if
    /// `committee.len() < 4` (inherited from `SpcInstance`).
    #[must_use]
    pub fn new(
        network: NetworkDefinition,
        committee: Vec<(ValidatorId, Bls12381G1PublicKey)>,
        me: ValidatorId,
        me_sk: Arc<Bls12381G1PrivateKey>,
        initial_rank: Vec<ValidatorId>,
        slot_timeout: Duration,
        view_timeout: Duration,
    ) -> Self {
        assert_eq!(
            initial_rank.len(),
            committee.len(),
            "initial_rank must list every validator exactly once",
        );
        Self {
            network,
            committee,
            me,
            me_sk,
            initial_rank,
            slot_timeout,
            view_timeout,
            current_slot: 0,
            slots: BTreeMap::new(),
            pending_inputs: VecDeque::new(),
            proposals_by_hash: BTreeMap::new(),
            pending_accusations: Vec::new(),
            consumed_accusations: BTreeSet::new(),
            future_proposals: BTreeMap::new(),
        }
    }

    /// Highest slot started. `0` before slot 1 begins.
    #[must_use]
    pub const fn current_slot(&self) -> u64 {
        self.current_slot
    }

    /// Read the ranking used by `slot`'s SPC instance. Returns `None`
    /// for slots not yet started.
    #[must_use]
    pub fn slot_rank(&self, slot: Slot) -> Option<&[ValidatorId]> {
        self.slots.get(&slot).map(|s| s.rank.as_slice())
    }

    /// Count of validated accusations stored against `slot`. Returns
    /// `None` for slots not yet started.
    #[must_use]
    pub fn accusation_count(&self, slot: Slot) -> Option<usize> {
        self.slots.get(&slot).map(|s| s.accusations.len())
    }

    /// Process one event; returns the resulting effects, possibly
    /// empty.
    pub fn handle(&mut self, event: MscEvent) -> Vec<MscEffect> {
        match event {
            MscEvent::Input(v) => self.on_input(v),
            MscEvent::Proposal {
                from,
                slot,
                content,
                accusations,
            } => self.on_proposal(from, slot, content, accusations),
            MscEvent::SpcMsg { from, slot, msg } => self.on_spc_msg(from, slot, *msg),
            MscEvent::TimerExpired { id } => self.on_timer_expired(id),
        }
    }

    fn on_spc_msg(&mut self, from: ValidatorId, slot: Slot, msg: SpcMessage) -> Vec<MscEffect> {
        let Some(slot_state) = self.slots.get_mut(&slot) else {
            return vec![];
        };
        let event = msg.into_event(from);
        let spc_effects = slot_state.spc.handle(event);
        self.translate_spc_effects(slot, spc_effects)
    }

    fn on_timer_expired(&mut self, id: MscTimerId) -> Vec<MscEffect> {
        match id {
            // Slot timer: B.4.3.d adds proposal-collection-deadline
            // handling (forces SPC input with whatever's buffered).
            MscTimerId::Slot(_) => vec![],
            MscTimerId::View { slot, view } => {
                let Some(slot_state) = self.slots.get_mut(&slot) else {
                    return vec![];
                };
                let spc_effects = slot_state.spc.handle(SpcEvent::TimerExpired { view });
                self.translate_spc_effects(slot, spc_effects)
            }
        }
    }

    /// Lift the effects produced by a slot's [`SpcInstance`] into
    /// MSC's effect surface. Broadcast effects get slot-tagged into
    /// [`MscEffect::BroadcastSpcMsg`]; the terminal `OutputHigh`
    /// triggers the slot commit walk.
    fn translate_spc_effects(&mut self, slot: Slot, spc_effects: Vec<SpcEffect>) -> Vec<MscEffect> {
        let mut out = vec![];
        for effect in spc_effects {
            match effect {
                SpcEffect::BroadcastVpcMsg(payload) => {
                    out.push(MscEffect::BroadcastSpcMsg {
                        slot,
                        msg: Box::new(SpcMessage::VpcMsg(payload)),
                    });
                }
                SpcEffect::BroadcastNewView { view, cert } => {
                    out.push(MscEffect::BroadcastSpcMsg {
                        slot,
                        msg: Box::new(SpcMessage::NewView { view, cert }),
                    });
                }
                SpcEffect::BroadcastNewCommit { view, value, proof } => {
                    out.push(MscEffect::BroadcastSpcMsg {
                        slot,
                        msg: Box::new(SpcMessage::NewCommit { view, value, proof }),
                    });
                }
                SpcEffect::BroadcastEmptyView(msg) => {
                    out.push(MscEffect::BroadcastSpcMsg {
                        slot,
                        msg: Box::new(SpcMessage::EmptyView(msg)),
                    });
                }
                SpcEffect::SetTimer { view, duration } => {
                    out.push(MscEffect::SetTimer {
                        id: MscTimerId::View { slot, view },
                        duration,
                    });
                }
                SpcEffect::EmptyLowEvidence(evidence) => {
                    // Slot-tag and queue for the next slot's outgoing
                    // proposal.
                    self.pending_accusations.push(MscEmptyLowAccusation {
                        slot,
                        view: evidence.view,
                        proof: evidence.proof,
                    });
                }
                SpcEffect::Equivocation { view, evidence } => {
                    out.push(MscEffect::Equivocation {
                        slot,
                        view,
                        evidence,
                    });
                }
                SpcEffect::OutputHigh(high) => {
                    out.extend(self.commit_slot(slot, &high));
                }
            }
        }
        out
    }

    /// Resolve each non-bottom hash in `high` against
    /// `proposals_by_hash` and emit [`MscEffect::SlotCommitted`] with
    /// the included `(sender, content)` pairs in rank order.
    fn commit_slot(&mut self, slot: Slot, high: &PcVector) -> Vec<MscEffect> {
        let Some(slot_state) = self.slots.get_mut(&slot) else {
            return vec![];
        };
        if slot_state.output_emitted {
            return vec![];
        }
        slot_state.committed_high = Some(high.clone());
        slot_state.output_emitted = true;

        let mut included = Vec::new();
        for entry in high.iter() {
            if *entry == HASH_BOTTOM {
                continue;
            }
            if let Some((signer, prop)) = self.proposals_by_hash.get(entry) {
                included.push((*signer, prop.content.clone()));
            }
        }
        vec![MscEffect::SlotCommitted { slot, included }]
    }

    /// Try to feed the slot's SPC instance its input vector. Fires
    /// only when the slot has all `n` proposals buffered and the SPC
    /// hasn't already been fed. Returns the resulting SPC-effect-
    /// translated `MscEffect`s.
    fn try_feed_slot_input(&mut self, slot: Slot) -> Vec<MscEffect> {
        let Some(slot_state) = self.slots.get_mut(&slot) else {
            return vec![];
        };
        if slot_state.spc_input_fed {
            return vec![];
        }
        let n = self.committee.len();
        if slot_state.proposals.len() < n {
            return vec![];
        }
        slot_state.spc_input_fed = true;
        let input = self.compute_slot_input(slot);
        let Some(slot_state) = self.slots.get_mut(&slot) else {
            return vec![];
        };
        let spc_effects = slot_state.spc.handle(SpcEvent::Input(input));
        self.translate_spc_effects(slot, spc_effects)
    }

    /// Compute the SPC input vector for `slot`: each rank position
    /// holds either the hash of the proposal from that validator, or
    /// [`HASH_BOTTOM`] if no proposal arrived.
    fn compute_slot_input(&self, slot: Slot) -> PcVector {
        let slot_state = self.slots.get(&slot).expect("slot present");
        let elements: Vec<PcValueElement> = slot_state
            .rank
            .iter()
            .map(|p| {
                slot_state
                    .proposals
                    .get(p)
                    .map_or(HASH_BOTTOM, hash_proposal_msc)
            })
            .collect();
        PcVector::new(elements)
    }

    fn on_input(&mut self, v: PcVector) -> Vec<MscEffect> {
        if self.pending_inputs.len() >= PENDING_INPUTS_CAP {
            return vec![];
        }
        self.pending_inputs.push_back(v);
        if self.can_start_next_slot() {
            self.start_next_slot()
        } else {
            vec![]
        }
    }

    fn on_proposal(
        &mut self,
        from: ValidatorId,
        slot: Slot,
        content: PcVector,
        accusations: Vec<MscEmptyLowAccusation>,
    ) -> Vec<MscEffect> {
        let proposal = MscSlotProposal { slot, content };
        // Reject proposals from outside the committee.
        if !self.committee.iter().any(|(id, _)| *id == from) {
            return vec![];
        }
        // Past slots: drop.
        if slot.inner() < self.current_slot {
            return vec![];
        }
        // Future slots: buffer if within the lookahead window.
        if slot.inner() > self.current_slot {
            if slot.inner() > self.current_slot + FUTURE_SLOT_LOOKAHEAD {
                return vec![];
            }
            let bucket = self.future_proposals.entry(slot).or_default();
            bucket.entry(from).or_insert((proposal, accusations));
            return vec![];
        }
        // Current slot.
        self.store_proposal(from, proposal, accusations)
    }

    /// True when no slot is in flight: either MSC hasn't started yet,
    /// or the current slot has already had its high committed.
    fn can_start_next_slot(&self) -> bool {
        if self.current_slot == 0 {
            return true;
        }
        self.slots
            .get(&Slot::new(self.current_slot))
            .is_some_and(|s| s.committed_high.is_some())
    }

    fn start_next_slot(&mut self) -> Vec<MscEffect> {
        let Some(input) = self.pending_inputs.pop_front() else {
            return vec![];
        };
        let new_slot_raw = self.current_slot + 1;
        let new_slot = Slot::new(new_slot_raw);
        self.current_slot = new_slot_raw;
        let rank = self.derive_slot_rank(new_slot);

        // Mark accusations from the just-departed slot as consumed.
        // `derive_slot_rank` already folded them into `rank`, so
        // future re-presentation is a no-op for the rank chain.
        if new_slot_raw > 1
            && let Some(prev) = self.slots.get(&Slot::new(new_slot_raw - 1))
        {
            for ev in &prev.accusations {
                self.consumed_accusations.insert((ev.slot, ev.view));
            }
        }

        let spc = SpcInstance::new(
            self.network.clone(),
            new_slot,
            self.committee.clone(),
            self.me,
            Arc::clone(&self.me_sk),
            self.view_timeout,
        );
        self.slots.insert(
            new_slot,
            SlotState {
                proposals: BTreeMap::new(),
                rank,
                spc,
                spc_input_fed: false,
                committed_high: None,
                output_emitted: false,
                accusations: Vec::new(),
            },
        );

        // Drain accusations accumulated during prior slots and ship
        // them with this slot's proposal.
        let outgoing_accusations = std::mem::take(&mut self.pending_accusations);

        // Build and store our own proposal locally, then emit the
        // broadcast effect.
        let mut out = vec![];
        let proposal = MscSlotProposal {
            slot: new_slot,
            content: input.clone(),
        };
        out.extend(self.store_proposal(self.me, proposal, outgoing_accusations.clone()));
        out.push(MscEffect::BroadcastProposal {
            slot: new_slot,
            content: input,
            accusations: outgoing_accusations,
        });
        out.push(MscEffect::SetTimer {
            id: MscTimerId::Slot(new_slot),
            duration: self.slot_timeout,
        });

        // Drain any future-slot proposals we buffered while waiting
        // for our own input.
        self.future_proposals
            .retain(|s, _| s.inner() >= new_slot_raw);
        if let Some(buffered) = self.future_proposals.remove(&new_slot) {
            for (from, (prop, accs)) in buffered {
                if from == self.me {
                    continue;
                }
                out.extend(self.store_proposal(from, prop, accs));
            }
        }

        out
    }

    fn derive_slot_rank(&self, slot: Slot) -> Vec<ValidatorId> {
        if slot.inner() == 1 {
            return self.initial_rank.clone();
        }
        let prev_slot = Slot::new(slot.inner() - 1);
        let Some(prev) = self.slots.get(&prev_slot) else {
            return self.initial_rank.clone();
        };
        let prev_high = prev.committed_high.as_ref();
        // Accusations attached to the prev slot demote the accused
        // validators in `rank`. Resolve via prev slot's initial rank
        // — that's what their `accusation_demotes` indexes into.
        let mut accused: BTreeSet<ValidatorId> = BTreeSet::new();
        for acc in &prev.accusations {
            if let Some(demoted) = accusation_demotes(acc, &prev.rank) {
                accused.insert(demoted);
            }
        }
        update_rank(
            &prev.rank,
            prev_high.unwrap_or(&PcVector::empty()),
            &accused,
        )
    }

    /// Add a proposal to the slot's local state. Validates accusations
    /// against the committee, dedups via `consumed_accusations`, and
    /// indexes the proposal in `proposals_by_hash` for commit
    /// resolution.
    fn store_proposal(
        &mut self,
        from: ValidatorId,
        proposal: MscSlotProposal,
        accusations: Vec<MscEmptyLowAccusation>,
    ) -> Vec<MscEffect> {
        let Some(slot_state) = self.slots.get_mut(&proposal.slot) else {
            return vec![];
        };
        // First proposal from this sender for this slot wins; ignore
        // re-presentations to avoid bandwidth amplification on
        // duplicate-proposal floods.
        if slot_state.proposals.contains_key(&from) {
            return vec![];
        }
        let slot = proposal.slot;
        let h = hash_proposal_msc(&proposal);
        slot_state.proposals.insert(from, proposal.clone());
        self.proposals_by_hash.insert(h, (from, proposal));

        // Validate + dedup accusations. Any accusation whose
        // `(slot, view)` has already been consumed gets dropped
        // here (its demotion is already in the rank chain).
        for acc in accusations {
            if self.consumed_accusations.contains(&(acc.slot, acc.view)) {
                continue;
            }
            if !verify_empty_low_accusation(&acc, &self.network, &self.committee) {
                continue;
            }
            if let Some(slot_state) = self.slots.get_mut(&slot) {
                slot_state.accusations.push(acc);
            }
        }

        // If we now have all `n` proposals for this slot, kick the
        // inner SPC. (Timer-driven partial-buffer flush lands later.)
        self.try_feed_slot_input(slot)
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        PcQc2, PcQc3, PcXpProof, SignerBitfield, Slot, SpcView, generate_bls_keypair,
    };

    use super::*;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn committee(n: usize) -> Vec<(ValidatorId, Bls12381G1PublicKey)> {
        (0..n as u64)
            .map(|i| (ValidatorId::new(i), generate_bls_keypair().public_key()))
            .collect()
    }

    fn dummy_pc_qc3() -> PcQc3 {
        let qc2 = PcQc2::new(
            PcVector::empty(),
            SignerBitfield::new(4),
            generate_bls_keypair().sign_v1(b"unused"),
            PcXpProof::Full {
                length_multi_sig: generate_bls_keypair().sign_v1(b"unused"),
            },
        );
        PcQc3::new(
            PcVector::empty(),
            qc2,
            None,
            None,
            Vec::new(),
            generate_bls_keypair().sign_v1(b"unused"),
        )
    }

    fn elem(b: u8) -> PcValueElement {
        PcValueElement::new([b; PC_VALUE_ELEMENT_BYTES])
    }

    /// `hash_proposal_msc` is deterministic + avoids `HASH_BOTTOM`.
    #[test]
    fn hash_proposal_msc_deterministic_and_avoids_bottom() {
        let p = MscSlotProposal {
            slot: Slot::new(7),
            content: PcVector::new([elem(1), elem(2)]),
        };
        let h1 = hash_proposal_msc(&p);
        let h2 = hash_proposal_msc(&p);
        assert_eq!(h1, h2);
        assert_ne!(h1, HASH_BOTTOM);
    }

    /// Different slots or different content produce distinct hashes —
    /// the slot field is bound into the canonical bytes so two
    /// identical-content proposals at different slots don't collide.
    #[test]
    fn hash_proposal_msc_differs_across_slots_and_content() {
        let content = PcVector::new([elem(0xAA)]);
        let a = hash_proposal_msc(&MscSlotProposal {
            slot: Slot::new(1),
            content: content.clone(),
        });
        let b = hash_proposal_msc(&MscSlotProposal {
            slot: Slot::new(2),
            content,
        });
        let c = hash_proposal_msc(&MscSlotProposal {
            slot: Slot::new(1),
            content: PcVector::new([elem(0xBB)]),
        });
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    /// `verify_empty_low_accusation` rejects accusations whose view
    /// is `<= 1` (view 1 is excused).
    #[test]
    fn verify_empty_low_accusation_rejects_view_one() {
        let c = committee(4);
        let acc = MscEmptyLowAccusation {
            slot: Slot::new(5),
            view: SpcView::new(1),
            proof: dummy_pc_qc3(),
        };
        assert!(!verify_empty_low_accusation(&acc, &net(), &c));
    }

    /// `update_rank` is the identity when `accused` is empty and
    /// `prev_high.len() == prev_rank.len()`.
    #[test]
    fn update_rank_identity_when_no_demotions() {
        let rank: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let high = PcVector::new([elem(1), elem(2), elem(3), elem(4)]);
        let accused = BTreeSet::new();
        assert_eq!(update_rank(&rank, &high, &accused), rank);
    }

    /// When `prev_high.len() < n`, the validator at position
    /// `prev_high.len()` gets demoted to the end.
    #[test]
    fn update_rank_demotes_first_excluded_when_high_short() {
        let rank: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        // Short high: only the first 2 entries are filled, so the
        // validator at position 2 (id=2) gets demoted.
        let high = PcVector::new([elem(1), elem(2)]);
        let accused = BTreeSet::new();
        let next = update_rank(&rank, &high, &accused);
        assert_eq!(
            next,
            vec![
                ValidatorId::new(0),
                ValidatorId::new(1),
                ValidatorId::new(3),
                ValidatorId::new(2),
            ],
        );
    }

    /// Explicit accusations move named validators to the tail; their
    /// relative order is preserved among kept and among demoted.
    #[test]
    fn update_rank_demotes_accused_to_tail() {
        let rank: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let high = PcVector::new([elem(1), elem(2), elem(3), elem(4)]); // full-length
        let mut accused = BTreeSet::new();
        accused.insert(ValidatorId::new(1));
        accused.insert(ValidatorId::new(3));
        let next = update_rank(&rank, &high, &accused);
        // 0, 2 kept; 1, 3 to tail in original order.
        assert_eq!(
            next,
            vec![
                ValidatorId::new(0),
                ValidatorId::new(2),
                ValidatorId::new(1),
                ValidatorId::new(3),
            ],
        );
    }

    /// Refuses to demote the entire committee — preserves liveness
    /// against Byzantine-built accusation streams that would otherwise
    /// leave no head for the next slot's rotation.
    #[test]
    fn update_rank_refuses_to_demote_everyone() {
        let rank: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let high = PcVector::empty(); // length 0 ⇒ position-0 demotion folds in
        let mut accused = BTreeSet::new();
        accused.insert(ValidatorId::new(1));
        accused.insert(ValidatorId::new(2));
        accused.insert(ValidatorId::new(3));
        // Demoted would be {0, 1, 2, 3} — entire committee. Refuse.
        let next = update_rank(&rank, &high, &accused);
        assert_eq!(next, rank);
    }

    /// `accusation_demotes` returns the cyclic-first party in the
    /// accused view's ranking, derived from `rank_shift_for_view`.
    #[test]
    fn accusation_demotes_resolves_via_rank_shift() {
        let rank: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        // view 3 in a 4-party committee → shift = 1 → demotes rank[1].
        let acc = MscEmptyLowAccusation {
            slot: Slot::new(1),
            view: SpcView::new(3),
            proof: dummy_pc_qc3(),
        };
        assert_eq!(accusation_demotes(&acc, &rank), Some(ValidatorId::new(1)));
    }

    /// Empty rank → `None`.
    #[test]
    fn accusation_demotes_empty_rank_returns_none() {
        let acc = MscEmptyLowAccusation {
            slot: Slot::new(1),
            view: SpcView::new(3),
            proof: dummy_pc_qc3(),
        };
        assert_eq!(accusation_demotes(&acc, &[]), None);
    }

    // ─── FSM tests ─────────────────────────────────────────────────────

    use hyperscale_types::bls_keypair_from_seed;

    fn msc_committee(
        n: usize,
    ) -> (
        Vec<Arc<Bls12381G1PrivateKey>>,
        Vec<(ValidatorId, Bls12381G1PublicKey)>,
    ) {
        let mut sks = Vec::with_capacity(n);
        let mut members = Vec::with_capacity(n);
        for i in 0..n {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let sk = bls_keypair_from_seed(&seed);
            members.push((ValidatorId::new(i as u64), sk.public_key()));
            sks.push(Arc::new(sk));
        }
        (sks, members)
    }

    fn msc_instance(idx: usize) -> MscInstance {
        let (sks, members) = msc_committee(4);
        let initial_rank: Vec<ValidatorId> = members.iter().map(|(id, _)| *id).collect();
        MscInstance::new(
            net(),
            members.clone(),
            members[idx].0,
            Arc::clone(&sks[idx]),
            initial_rank,
            Duration::from_millis(100),
            Duration::from_millis(100),
        )
    }

    /// Fresh `MscInstance` starts at slot 0 (slot 1 not yet started)
    /// with empty state.
    #[test]
    fn msc_instance_initial_state() {
        let fsm = msc_instance(0);
        assert_eq!(fsm.current_slot(), 0);
        assert!(fsm.slot_rank(Slot::new(1)).is_none());
    }

    /// `MscInstance::new` panics when `initial_rank.len() !=
    /// committee.len()` — guards the slot-1 SPC bootstrap against a
    /// malformed config.
    #[test]
    #[should_panic(expected = "initial_rank must list every validator exactly once")]
    fn msc_instance_rejects_rank_size_mismatch() {
        let (sks, members) = msc_committee(4);
        let bad_rank = vec![ValidatorId::new(0), ValidatorId::new(1)]; // 2 vs n=4
        let _ = MscInstance::new(
            net(),
            members.clone(),
            members[0].0,
            Arc::clone(&sks[0]),
            bad_rank,
            Duration::from_millis(100),
            Duration::from_millis(100),
        );
    }

    /// First `Input` event starts slot 1: bumps `current_slot`,
    /// installs the slot-1 rank, broadcasts our own proposal, sets
    /// the slot timer.
    #[test]
    fn input_starts_slot_one() {
        let mut fsm = msc_instance(0);
        let v = PcVector::new([elem(7)]);
        let effects = fsm.handle(MscEvent::Input(v));
        assert_eq!(fsm.current_slot(), 1);
        // Effects: BroadcastProposal + SetTimer.
        assert_eq!(effects.len(), 2);
        assert!(matches!(
            effects[0],
            MscEffect::BroadcastProposal { slot, .. } if slot == Slot::new(1)
        ));
        assert!(matches!(
            effects[1],
            MscEffect::SetTimer { id: MscTimerId::Slot(s), .. } if s == Slot::new(1)
        ));
        assert!(fsm.slot_rank(Slot::new(1)).is_some());
    }

    /// `on_proposal` from outside the committee is dropped.
    #[test]
    fn proposal_from_non_committee_rejected() {
        let mut fsm = msc_instance(0);
        let _ = fsm.handle(MscEvent::Input(PcVector::empty()));
        let effects = fsm.handle(MscEvent::Proposal {
            from: ValidatorId::new(999),
            slot: Slot::new(1),
            content: PcVector::empty(),
            accusations: vec![],
        });
        assert!(effects.is_empty());
    }

    /// Future-slot proposals get buffered (within the lookahead
    /// window) and don't error out.
    #[test]
    fn future_proposal_buffered_within_lookahead() {
        let mut fsm = msc_instance(0);
        let _ = fsm.handle(MscEvent::Input(PcVector::empty()));
        // current_slot = 1. Propose for slot 3 — within the window.
        let effects = fsm.handle(MscEvent::Proposal {
            from: ValidatorId::new(1),
            slot: Slot::new(3),
            content: PcVector::empty(),
            accusations: vec![],
        });
        assert!(effects.is_empty()); // buffered, no effects
    }

    /// Future-slot proposals beyond `FUTURE_SLOT_LOOKAHEAD` are
    /// dropped.
    #[test]
    fn future_proposal_beyond_lookahead_dropped() {
        let mut fsm = msc_instance(0);
        let _ = fsm.handle(MscEvent::Input(PcVector::empty()));
        // current_slot = 1. Propose for slot 100 — way past the window.
        let effects = fsm.handle(MscEvent::Proposal {
            from: ValidatorId::new(1),
            slot: Slot::new(100),
            content: PcVector::empty(),
            accusations: vec![],
        });
        assert!(effects.is_empty());
    }
}
