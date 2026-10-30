//! The pieces every reshape duty shares: the adopt-and-seat tail, the
//! stage queue, the ready re-assertion schedule, and the split terminal
//! fetch.

use std::time::Duration;

use hyperscale_storage::ImportProgress;
use hyperscale_types::network::request::{BlockIntent, GetBlockRequest};
use hyperscale_types::network::response::GetBlockResponse;
use hyperscale_types::{
    BlockHeader, LocalTimestamp, QuorumCertificate, ShardAnchor, ShardId, SubstateLeaf,
    ValidatorId, Verifier, WeightedTimestamp,
};

use super::io::{AdoptKind, ReshapeRequest};
use crate::reshape::genesis::DerivedGenesis;
use crate::reshape::observer::{ObserverTail, TailOutcome, TerminalSighting, TwoChainCheck};
use crate::reshape::split_flip::split_genesis_from_terminal;
use crate::reshape::view::ReshapeView;

/// Wait between a seat's first two ready assertions.
pub(super) const READY_REASSERT_MIN: Duration = Duration::from_secs(1);

/// Wait before asking again after a fetch that failed or answered with
/// something the duty could not use: a terminal fetch that did not deliver
/// the terminal, a walk whose answer or unproven run was refused, or a walk
/// at the chain's tip that found nothing above it yet.
pub(super) const REFETCH_WAIT: Duration = Duration::from_secs(1);

/// Pace a walk after the answer that produced `outcome`. One that could
/// not advance it — nothing held at the height yet, or a refusal — holds
/// the next fetch back by [`REFETCH_WAIT`]; every answer pumps the
/// orchestrator at once, so a walk at the tip would otherwise ask again as
/// fast as the peer replies. An accepted answer asks again at once, so a
/// walk behind the tip is not slowed.
pub(super) fn paced(
    tail: &mut ObserverTail,
    outcome: TailOutcome,
    now: LocalTimestamp,
    duty: ShardId,
) {
    match outcome {
        TailOutcome::Accepted => {}
        TailOutcome::NotYetAvailable => tail.defer(now.plus(REFETCH_WAIT)),
        TailOutcome::Rejected(reason) => {
            tracing::warn!(?duty, reason, "refused an answer to a reshape walk");
            tail.defer(now.plus(REFETCH_WAIT));
        }
    }
}

/// When a terminal fetch may go out: one at a time, and after an answer
/// that did not deliver the terminal, not again until
/// [`REFETCH_WAIT`] has passed. Every answer pumps the orchestrator
/// at once, so without the wait a peer answering wrongly would be asked
/// again as fast as it replies.
#[derive(Debug, Clone, Copy)]
pub(super) enum TerminalAsk {
    /// No fetch in flight; the next may go out from this instant.
    Due(LocalTimestamp),
    InFlight,
}

impl TerminalAsk {
    pub(super) const NOW: Self = Self::Due(LocalTimestamp::ZERO);

    /// Whether a fetch goes out at `now`, marking it in flight if so.
    pub(super) fn begin(&mut self, now: LocalTimestamp) -> bool {
        match *self {
            Self::Due(at) if now >= at => {
                *self = Self::InFlight;
                true
            }
            _ => false,
        }
    }

    /// The fetch in flight did not deliver the terminal.
    pub(super) fn missed(&mut self, now: LocalTimestamp) {
        *self = Self::Due(now.plus(REFETCH_WAIT));
    }
}

/// Ceiling the re-assert wait doubles up to, so a seat the beacon never
/// credits keeps asserting rather than falling silent.
///
/// The anchor window turns over about once an epoch and restarts the
/// backoff, so this governs how many assertions a seat makes inside one
/// epoch rather than how long it can go quiet. Held well under the epoch
/// because the readiness gate needs a quorum of seats pooled at one
/// committee at one time, and an emitter cannot see how close that is:
/// raising the ceiling to 16s drops a 30s-epoch cohort to about five
/// assertions per epoch, which is under what a halt recovery's committee
/// churn needs to reach its gate.
pub(super) const READY_REASSERT_MAX: Duration = Duration::from_secs(4);

/// One seat's ready assertion schedule.
///
/// A ready signal only says something new when the anchor window it is cut
/// from turns over, which happens once per epoch — the boundary record the
/// emitter windows from refreshes at the epoch fold, and the gate that
/// consumes the signal re-evaluates at the same fold. Everything between is
/// retransmission against loss, so it backs off rather than repeating at
/// the pump's rate.
///
/// Real time, not steps: the production supervisor pumps the orchestrator on
/// a timer while the simulation drives it to a fixpoint, so a step means
/// different things on either side and only a clock reads the same on both.
pub(super) struct ReadyAssert {
    /// Anchor window start the last assertion was cut from. A different
    /// value is a genuinely new signal and restarts the backoff.
    window: WeightedTimestamp,
    /// Committee the last assertion went to. A pool is per member and
    /// local, so a member seated since then holds nothing this seat sent —
    /// a committee redraw or shuffle silently undoes every assertion so
    /// far, and only re-sending repairs it.
    recipients: Vec<ValidatorId>,
    /// When the next assertion comes due.
    due: LocalTimestamp,
    /// Wait applied after the next assertion, doubling to
    /// [`READY_REASSERT_MAX`].
    backoff: Duration,
}

impl ReadyAssert {
    /// Whether to assert at `now` for an anchor windowed at `window`,
    /// addressed to `recipients`, advancing the schedule when it answers
    /// `true`.
    ///
    /// Asserts immediately for anything it has not asserted for — a fresh
    /// window, or a committee it has not sent this window to — then backs
    /// off geometrically.
    pub(super) fn should_assert(
        slot: &mut Option<Self>,
        window: WeightedTimestamp,
        recipients: &[ValidatorId],
        now: LocalTimestamp,
    ) -> bool {
        match slot {
            Some(state) if state.window == window && state.recipients == recipients => {
                if now < state.due {
                    return false;
                }
                state.backoff = (state.backoff * 2).min(READY_REASSERT_MAX);
                state.due = now.plus(state.backoff);
            }
            _ => {
                *slot = Some(Self {
                    window,
                    recipients: recipients.to_vec(),
                    due: now.plus(READY_REASSERT_MIN),
                    backoff: READY_REASSERT_MIN,
                });
            }
        }
        true
    }
}

/// The adopt-and-seat tail every duty runs once it holds its derived
/// genesis.
pub(super) enum SeatTail {
    /// Genesis derived; the next advance emits the adopt.
    Adopting(Box<DerivedGenesis>),
    /// Adopt emitted; awaiting the verified adopted root.
    AwaitingAdopt,
    /// Genesis adopted into the store; awaiting the placement that seats it.
    Prepared,
    /// Seat emitted.
    Seated,
}

impl SeatTail {
    /// Emit the adopt of `shard`'s genesis, and once one of `seats` sits on
    /// `shard`'s committee, the seat.
    pub(super) fn advance<'a>(
        &mut self,
        shard: ShardId,
        kind: AdoptKind,
        seats: impl IntoIterator<Item = &'a ValidatorId>,
        view: &ReshapeView,
        out: &mut Vec<ReshapeRequest>,
    ) {
        match std::mem::replace(self, Self::AwaitingAdopt) {
            Self::Adopting(genesis) => out.push(ReshapeRequest::Adopt {
                shard,
                kind,
                genesis,
            }),
            Self::Prepared => {
                let committee = view.committee(shard);
                *self = if seats.into_iter().any(|seat| committee.contains(seat)) {
                    out.push(ReshapeRequest::Seat { shard });
                    Self::Seated
                } else {
                    Self::Prepared
                };
            }
            other => *self = other,
        }
    }

    /// The adopt landed, its root verified against the genesis's.
    pub(super) fn on_adopted(&mut self) {
        if matches!(self, Self::AwaitingAdopt) {
            *self = Self::Prepared;
        }
    }
}

/// The verified snap-sync chunks a duty stages into its store.
#[derive(Default)]
pub(super) struct StageQueue {
    /// Verified chunks awaiting a [`ReshapeRequest::StageChunk`] emit on
    /// the next advance.
    pub(super) pending: Vec<(ImportProgress, Vec<SubstateLeaf>)>,
    /// Stage writes emitted but not yet acknowledged; a finalize waits for
    /// zero so every staged chunk is durable first.
    pub(super) unacked: usize,
}

impl StageQueue {
    pub(super) fn push(&mut self, progress: ImportProgress, leaves: Vec<SubstateLeaf>) {
        self.pending.push((progress, leaves));
    }

    /// Emit a stage write into `shard`'s store for every pending chunk.
    pub(super) fn emit(&mut self, shard: ShardId, out: &mut Vec<ReshapeRequest>) {
        for (progress, leaves) in self.pending.drain(..) {
            self.unacked += 1;
            out.push(ReshapeRequest::StageChunk {
                shard,
                progress,
                leaves,
            });
        }
    }

    pub(super) const fn on_staged(&mut self) {
        self.unacked = self.unacked.saturating_sub(1);
    }

    /// Hand a chunk whose write failed back to the front of the queue: the
    /// next emit re-sends it, so a transient write failure retries instead
    /// of pinning the unacked count above zero forever.
    pub(super) fn on_stage_failed(&mut self, progress: ImportProgress, leaves: Vec<SubstateLeaf>) {
        self.unacked = self.unacked.saturating_sub(1);
        self.pending.insert(0, (progress, leaves));
    }

    /// Whether every emitted stage write has been acknowledged.
    pub(super) const fn is_durable(&self) -> bool {
        self.unacked == 0
    }
}

/// A split duty's fetch of the parent's certified terminal on the anchor
/// fallback, deriving the child's genesis against the anchor the beacon
/// seeded it with.
pub(super) struct TerminalFetch {
    /// The beacon-seeded child anchor the derivation verifies against.
    anchor: ShardAnchor,
    ask: TerminalAsk,
}

impl TerminalFetch {
    pub(super) const fn new(anchor: ShardAnchor) -> Self {
        Self {
            anchor,
            ask: TerminalAsk::NOW,
        }
    }

    /// The terminal fetch to send at `now`, when one is due.
    pub(super) fn next_request(
        &mut self,
        view: &ReshapeView,
        parent: ShardId,
        now: LocalTimestamp,
    ) -> Option<GetBlockRequest> {
        self.ask
            .begin(now)
            .then(|| split_terminal_request(view, parent, &self.anchor))
    }

    /// The fetch in flight failed at the transport level.
    pub(super) fn on_failure(&mut self, now: LocalTimestamp) {
        self.ask.missed(now);
    }

    /// The genesis an answer derives, checked against the anchor; `None`
    /// when the answer did not deliver it.
    pub(super) fn on_block(
        &mut self,
        child: ShardId,
        response: &GetBlockResponse,
        now: LocalTimestamp,
    ) -> Option<DerivedGenesis> {
        self.ask.missed(now);
        let elided = response.block()?;
        anchored_split_genesis(child, elided.header(), elided.qc(), &self.anchor)
    }
}

/// Whether one of `seats` can still seat on `shard`: it sits on the
/// shard's committee, or the shard has no committee yet to sit on. A
/// successor's committee forms with every seat its reshape placed, so one
/// that names none of a duty's seats never will, and the duty's prepared
/// store has nothing to seat.
pub(super) fn seats_on<'a>(
    view: &ReshapeView,
    shard: ShardId,
    mut seats: impl Iterator<Item = &'a ValidatorId>,
) -> bool {
    let committee = view.committee(shard);
    committee.is_empty() || seats.any(|seat| committee.contains(seat))
}

/// The fetch for a split parent's certified terminal, the block just
/// below the child's seeded genesis.
///
/// The fold that seeds the child's anchor from the terminal contribution
/// records that same crossing as the parent's boundary, so while the
/// parent's record stands at the terminal's height it names the block: a
/// certified sibling at the height does not answer. A record at any other
/// height is not this crossing, and the request asks by height alone.
pub(super) fn split_terminal_request(
    view: &ReshapeView,
    parent: ShardId,
    child_anchor: &ShardAnchor,
) -> GetBlockRequest {
    let terminal = child_anchor.height.prev().unwrap_or(child_anchor.height);
    let request = GetBlockRequest::new(terminal, BlockIntent::Execute);
    match view.boundary(parent) {
        Some(record) if record.height == terminal && record.terminal_epoch.is_some() => {
            request.naming(record.block_hash)
        }
        _ => request,
    }
}

/// Derive a successor's genesis on the anchor fallback path, checking it
/// against the anchor the beacon attested.
///
/// The derivation is shared with the cut-over flip and the beacon fold, so
/// it takes no anchor. This path holds one, so it compares: agreement is
/// free, and disagreement means the local parent chain and the network
/// disagree about a committed block. The cut-over flip has no anchor to
/// compare against yet — its guard is the commitment proof at the front.
pub(super) fn anchored_split_genesis(
    child: ShardId,
    terminal: &BlockHeader,
    qc: &QuorumCertificate,
    anchor: &ShardAnchor,
) -> Option<DerivedGenesis> {
    let genesis = split_genesis_from_terminal(child, terminal, qc)
        .inspect_err(|error| {
            tracing::warn!(?child, %error, "split child genesis derivation failed");
        })
        .ok()?;
    if genesis.block.hash() != anchor.block_hash {
        tracing::error!(
            ?child,
            derived = ?genesis.block.hash(),
            anchored = ?anchor.block_hash,
            "derived split-child genesis does not reconstruct the beacon anchor"
        );
        return None;
    }
    Some(genesis)
}

/// Whether a recognizing walk's terminal of `shard` is commit-proven — the
/// gate its flip keys on.
///
/// Two QCs can exist at one height; two commits cannot. Certification
/// alone would let a superseded block seed the successor. Each QC of the
/// proof verifies against `shard`'s committee for its own window, as the
/// schedule resolves it, so the serving peer is trusted for availability
/// alone: the walk's headers below the terminal are pinned by hash to it,
/// and nothing the flip derives reads the block the walk passed it by.
///
/// `Pending` while no round-contiguous pair has formed yet, or its window
/// is above what this host's beacon has folded.
pub(super) fn terminal_commit(
    shard: ShardId,
    sighting: &TerminalSighting,
    verifier: &dyn Verifier,
    view: &ReshapeView,
) -> TwoChainCheck {
    let height = sighting.header.height().inner();
    let Some(terminal_proof) = &sighting.commit_proof else {
        return TwoChainCheck::Pending;
    };
    // What the proof commits must be the block the genesis derives from.
    // A prefix proof's two-chain sits above the terminal, so the link's
    // foot is the only thing tying it back down; checked before the
    // signature work, which is the expensive half.
    let check = if terminal_proof.proof.proven_block_hash() == sighting.header.hash() {
        terminal_proof.check(verifier, view.network(), |anchor_wt, qc_wt| {
            view.certifying_committee(shard, anchor_wt, qc_wt)
        })
    } else {
        TwoChainCheck::Refuted("the commit proof commits a block other than the terminal")
    };
    if let TwoChainCheck::Refuted(reason) = check {
        tracing::warn!(
            ?shard,
            height,
            reason,
            "refused the terminal's commit proof; walking again from the anchor"
        );
    }
    check
}

/// A ready signal's recipients — `shard`'s committee minus the signer.
pub(super) fn recipients_for(
    view: &ReshapeView,
    shard: ShardId,
    validator: ValidatorId,
) -> Vec<ValidatorId> {
    view.committee(shard)
        .iter()
        .copied()
        .filter(|&v| v != validator)
        .collect()
}
