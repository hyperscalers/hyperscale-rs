//! Durable record of the SPC consensus messages a beacon committee
//! member has signed.
//!
//! The inner-PC votes and the SPC empty-view attestation each sign one
//! [`PcVector`] at a slot `(epoch, view, kind)`, and signing two vectors
//! at one slot is a double-sign: a PC vote pair is self-authenticating
//! evidence the fold convicts the signer's whole pool on, and an
//! empty-view pair hands an indirect-cert aggregator a choice between
//! two reported highs. The vectors a member signs derive from in-memory
//! state (the proposals it pooled, the votes it aggregated, the highest
//! triple it saw), so a restarted process recomputes them differently.
//! The record is what it consults before signing: a slot it already
//! holds re-signs only the vector it holds.

use std::collections::BTreeMap;

use blake3::Hasher;
use hyperscale_hbor::Hbor;

use crate::{
    Epoch, Hash, PcQc1, PcQc2, PcVector, SpcHighTriple, SpcView, hash_high_value, skip_target,
};

/// How many views back from the highest it holds a record keeps its
/// slots. Signing jobs run concurrently, so a vote for one view can
/// reach the register after a vote for the next; anything older than
/// the window is refused, since its slot may have been dropped.
pub const BEACON_VOTE_VIEW_WINDOW: u32 = 8;

/// Domain tag for a register's content digest.
const CONTENT_DOMAIN: &[u8] = b"hyperscale-beacon-vote-register-v1";

/// Which message a slot holds within one SPC view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub enum BeaconVoteKind {
    /// Inner-PC round-1 vote, over the member's input vector.
    PcVote1,
    /// Inner-PC round-2 vote, over its round-1 QC's certified prefix.
    PcVote2,
    /// Inner-PC round-3 vote, over its round-2 QC's certified prefix.
    PcVote3,
    /// Empty-view attestation, over its skip target.
    EmptyView,
}

/// One signing slot within an epoch's SPC instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub struct BeaconVoteSlot {
    /// SPC view the message belongs to.
    pub view: SpcView,
    /// Which message of the view.
    pub kind: BeaconVoteKind,
}

/// A signature a beacon committee member is about to create: its slot
/// and a digest of the vector it covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconVote {
    epoch: Epoch,
    slot: BeaconVoteSlot,
    content: Hash,
    /// An empty view's reported high view, which never falls below one
    /// the member reported earlier in the epoch: its highest triple
    /// only rises.
    reported: Option<SpcView>,
}

impl BeaconVote {
    /// A round-1 vote over `v_in`.
    #[must_use]
    pub fn pc_vote1(epoch: Epoch, view: SpcView, v_in: &PcVector) -> Self {
        Self::pc(epoch, view, BeaconVoteKind::PcVote1, v_in)
    }

    /// A round-2 vote built from `qc1`, which signs `qc1`'s certified
    /// prefix: two QCs certifying the same prefix are one vote.
    #[must_use]
    pub fn pc_vote2(epoch: Epoch, view: SpcView, qc1: &PcQc1) -> Self {
        Self::pc(epoch, view, BeaconVoteKind::PcVote2, qc1.x())
    }

    /// A round-3 vote built from `qc2`, which signs `qc2`'s certified
    /// prefix.
    #[must_use]
    pub fn pc_vote3(epoch: Epoch, view: SpcView, qc2: &PcQc2) -> Self {
        Self::pc(epoch, view, BeaconVoteKind::PcVote3, qc2.x_p())
    }

    /// An empty-view attestation for `view` reporting `reported`, which
    /// signs the skip target binding the reported view and value.
    #[must_use]
    pub fn empty_view(epoch: Epoch, view: SpcView, reported: &SpcHighTriple) -> Self {
        Self::skip(epoch, view, reported.view, &reported.value)
    }

    fn skip(epoch: Epoch, view: SpcView, reported_view: SpcView, reported: &PcVector) -> Self {
        let target = skip_target(view, reported_view, hash_high_value(reported));
        Self {
            reported: Some(reported_view),
            ..Self::pc(epoch, view, BeaconVoteKind::EmptyView, &target)
        }
    }

    fn pc(epoch: Epoch, view: SpcView, kind: BeaconVoteKind, vector: &PcVector) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(CONTENT_DOMAIN);
        for element in vector {
            hasher.update(element.as_bytes());
        }
        Self {
            epoch,
            slot: BeaconVoteSlot { view, kind },
            content: Hash::from_hash_bytes(hasher.finalize().as_bytes()),
            reported: None,
        }
    }

    /// Epoch whose SPC instance the message belongs to.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The slot the message consumes.
    #[must_use]
    pub const fn slot(&self) -> BeaconVoteSlot {
        self.slot
    }
}

/// What a register does with a [`BeaconVote`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeaconVoteAdmission {
    /// The slot is fresh: persist this record, then sign.
    Record(BeaconVoteRecord),
    /// The slot already holds this vector: sign it again, nothing to
    /// persist.
    Repeat,
    /// Signing would contradict the record: a different vector at a
    /// held slot, an epoch or view the record has moved past, or an
    /// empty view reporting a lower high than one already reported.
    Refuse,
}

/// One validator's signed SPC slots for its newest epoch.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct BeaconVoteRecord {
    /// Epoch the slots belong to; a vote for a newer one supersedes
    /// the record.
    epoch: Epoch,
    /// Content digest per signed slot, for the
    /// [`BEACON_VOTE_VIEW_WINDOW`] views up to the highest held.
    signed: BTreeMap<BeaconVoteSlot, Hash>,
    /// Highest view any of the epoch's empty views reported.
    reported_floor: Option<SpcView>,
}

impl BeaconVoteRecord {
    const fn new(epoch: Epoch) -> Self {
        Self {
            epoch,
            signed: BTreeMap::new(),
            reported_floor: None,
        }
    }

    /// Decide `vote` against the `stored` record.
    #[must_use]
    pub fn admit(stored: Option<&Self>, vote: &BeaconVote) -> BeaconVoteAdmission {
        let mut record = match stored {
            Some(stored) if stored.epoch > vote.epoch => return BeaconVoteAdmission::Refuse,
            Some(stored) if stored.epoch == vote.epoch => stored.clone(),
            _ => Self::new(vote.epoch),
        };
        let top = record.signed.keys().map(|slot| slot.view).max();
        if top.is_some_and(|top| below_window(vote.slot.view, top)) {
            return BeaconVoteAdmission::Refuse;
        }
        match record.signed.get(&vote.slot) {
            Some(held) if *held == vote.content => return BeaconVoteAdmission::Repeat,
            Some(_) => return BeaconVoteAdmission::Refuse,
            None => {}
        }
        if let Some(reported) = vote.reported {
            if record.reported_floor.is_some_and(|floor| reported < floor) {
                return BeaconVoteAdmission::Refuse;
            }
            record.reported_floor = Some(reported);
        }
        record.signed.insert(vote.slot, vote.content);
        let top = top.map_or(vote.slot.view, |top| top.max(vote.slot.view));
        record
            .signed
            .retain(|slot, _| !below_window(slot.view, top));
        BeaconVoteAdmission::Record(record)
    }
}

const fn below_window(view: SpcView, top: SpcView) -> bool {
    view.inner().saturating_add(BEACON_VOTE_VIEW_WINDOW) <= top.inner()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PcValueElement;

    fn vector(tag: u8) -> PcVector {
        PcVector::new([PcValueElement::new([tag; 32])])
    }

    fn admit(record: &mut Option<BeaconVoteRecord>, vote: &BeaconVote) -> BeaconVoteAdmission {
        let admission = BeaconVoteRecord::admit(record.as_ref(), vote);
        if let BeaconVoteAdmission::Record(next) = &admission {
            *record = Some(next.clone());
        }
        admission
    }

    fn records(admission: &BeaconVoteAdmission) -> bool {
        matches!(admission, BeaconVoteAdmission::Record(_))
    }

    #[test]
    fn a_held_slot_re_signs_only_its_own_vector() {
        let (e, v) = (Epoch::new(3), SpcView::new(1));
        let mut record = None;
        assert!(records(&admit(
            &mut record,
            &BeaconVote::pc_vote1(e, v, &vector(1))
        )));
        assert_eq!(
            admit(&mut record, &BeaconVote::pc_vote1(e, v, &vector(1))),
            BeaconVoteAdmission::Repeat
        );
        assert_eq!(
            admit(&mut record, &BeaconVote::pc_vote1(e, v, &vector(2))),
            BeaconVoteAdmission::Refuse
        );
        // Another kind, or another view, is another slot.
        assert!(records(&admit(
            &mut record,
            &BeaconVote::pc(e, v, BeaconVoteKind::PcVote2, &vector(2))
        )));
        assert!(records(&admit(
            &mut record,
            &BeaconVote::pc_vote1(e, SpcView::new(2), &vector(2))
        )));
    }

    #[test]
    fn a_newer_epoch_supersedes_and_an_older_one_is_refused() {
        let v = SpcView::new(1);
        let mut record = None;
        admit(
            &mut record,
            &BeaconVote::pc_vote1(Epoch::new(3), v, &vector(1)),
        );
        assert!(records(&admit(
            &mut record,
            &BeaconVote::pc_vote1(Epoch::new(4), v, &vector(2))
        )));
        let held = record.as_ref().expect("recorded");
        assert_eq!(held.epoch, Epoch::new(4));
        assert_eq!(held.signed.len(), 1);
        assert_eq!(
            admit(
                &mut record,
                &BeaconVote::pc_vote1(Epoch::new(3), v, &vector(1))
            ),
            BeaconVoteAdmission::Refuse
        );
    }

    #[test]
    fn views_below_the_window_drop_and_are_refused() {
        let e = Epoch::new(1);
        let mut record = None;
        admit(
            &mut record,
            &BeaconVote::pc_vote1(e, SpcView::new(1), &vector(1)),
        );
        admit(
            &mut record,
            &BeaconVote::pc_vote1(e, SpcView::new(2), &vector(1)),
        );
        let top = SpcView::new(1 + BEACON_VOTE_VIEW_WINDOW);
        admit(&mut record, &BeaconVote::pc_vote1(e, top, &vector(1)));
        let held = record.as_ref().expect("recorded");
        assert!(held.signed.keys().all(|slot| slot.view.inner() > 1));
        assert_eq!(held.signed.len(), 2);
        assert_eq!(
            admit(
                &mut record,
                &BeaconVote::pc_vote1(e, SpcView::new(1), &vector(1))
            ),
            BeaconVoteAdmission::Refuse
        );
        // A late vote inside the window still lands.
        assert!(records(&admit(
            &mut record,
            &BeaconVote::pc(e, SpcView::new(2), BeaconVoteKind::PcVote2, &vector(1))
        )));
    }

    #[test]
    fn an_empty_view_never_reports_below_an_earlier_report() {
        let e = Epoch::new(1);
        let skip = |view: u32, reported: u32| {
            BeaconVote::skip(e, SpcView::new(view), SpcView::new(reported), &vector(9))
        };
        let mut record = None;
        assert!(records(&admit(&mut record, &skip(4, 3))));
        assert_eq!(admit(&mut record, &skip(5, 2)), BeaconVoteAdmission::Refuse);
        assert!(records(&admit(&mut record, &skip(5, 3))));
        assert_eq!(
            admit(&mut record, &skip(5, 4)),
            BeaconVoteAdmission::Refuse,
            "a held slot keeps the triple it reported"
        );
    }
}
