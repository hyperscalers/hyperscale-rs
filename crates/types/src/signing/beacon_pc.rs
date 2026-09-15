//! Signing messages for beacon PC inner-consensus votes.
//!
//! Every PC-level signature covers a typed message naming the scope it
//! runs under, the round the vote belongs to, and the vector voted on.
//! The round rides inside the signed content: under a canonical encoding
//! two distinct rounds produce distinct preimages, so a round-1 signature
//! can never verify as a round-3 signature — the same guarantee per-round
//! domain tags gave, with one domain for the family.

use hyperscale_hbor::Hbor;

use crate::signing::NetworkId;
use crate::{Epoch, Hash, PcVector, SpcView};

/// One PC instance's identity: the epoch and SPC view it runs under.
///
/// Passing the pair as one typed value keeps sign and verify sites from
/// silently cross-feeding an epoch where a view belongs — the same
/// mistake-proofing the signing messages get from their typed fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub struct PcScope {
    /// The epoch whose SPC instance the PC run belongs to.
    pub epoch: Epoch,
    /// The SPC view whose PC instance the run belongs to.
    pub view: SpcView,
}

/// Which PC round a vote signature belongs to.
///
/// `Vote2Length` is the length attestation rider on a round-2 vote: each
/// round-2 vote carries an extra sig over a single-element vector
/// containing its `x.len()`, binding the signer to a specific `x` length
/// and closing a splice vulnerability in the short-witness construction.
/// A Byzantine prover that lacks the signer's length sig can't splice a
/// long round-2 vote's prefix sigs to fake a "shorter x" claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub enum PcRound {
    /// Round-1 votes.
    Vote1,
    /// Round-2 votes (per-prefix sigs).
    Vote2,
    /// The length attestation rider on a round-2 vote.
    Vote2Length,
    /// Round-3 votes.
    Vote3,
}

/// What a PC round vote's signature covers.
///
/// The scope binds the vote to one PC instance: the same vector signed in
/// one view will not verify against another.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-pc-vote-v1", signing_context = NetworkId)]
pub struct PcVoteMessage {
    /// The round the vote belongs to — inside the signed content, so
    /// rounds cannot replay against each other.
    pub round: PcRound,
    /// The PC instance the vote belongs to.
    pub scope: PcScope,
    /// The vector voted on.
    pub vector: PcVector,
}

/// What an SPC empty-view skip statement's signature covers.
///
/// The vector carries the `(empty_view, reported_max_view)` pair for the
/// view-change protocol; the binding is per-epoch — an empty-view
/// statement is about views, so it cannot be scoped to one.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-spc-empty-view-v1", signing_context = NetworkId)]
pub struct SpcEmptyViewMessage {
    /// The epoch whose SPC instance the statement belongs to.
    pub(crate) epoch: Epoch,
    /// The `(empty_view, reported_max_view)` pair, as a vector.
    pub(crate) vector: PcVector,
}

/// Which SPC relay notification a sender attestation covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub enum SpcRelayKind {
    /// A relayed [`SpcProposalObject`](crate::SpcProposalObject).
    NewView,
    /// A relayed [`SpcNewCommitMsg`](crate::SpcNewCommitMsg).
    NewCommit,
}

/// What a sender-attestation signature on an SPC relay notification
/// covers.
///
/// The attestation attributes "this validator relayed this payload for
/// `(epoch, view)`" — the inner cert is self-authenticating, so this is
/// purely accountability plus pipeline-slot dedup, not content
/// authentication. A swapped payload or a replay across `(epoch, view)`
/// invalidates the sig.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "hyperscale-spc-relay-v1", signing_context = NetworkId)]
pub struct SpcRelayMessage {
    /// Which notification kind is being relayed.
    pub kind: SpcRelayKind,
    /// The epoch the relay belongs to.
    pub epoch: Epoch,
    /// The view the relay belongs to.
    pub view: SpcView,
    /// The relayed payload's content hash.
    pub content_hash: Hash,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::signed_bytes;
    use crate::{NetworkDefinition, PC_VALUE_ELEMENT_BYTES, PcValueElement};

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn ve(n: u8) -> PcValueElement {
        PcValueElement::new([n; PC_VALUE_ELEMENT_BYTES])
    }

    /// Distinct rounds must produce distinct signing bytes for the same
    /// `(scope, vector)`. Cross-round replay protection inside a single
    /// SPC view depends on this.
    #[test]
    fn pc_vote_message_separates_rounds() {
        let v = PcVector::new(vec![ve(7)]);
        let mk = |round| {
            signed_bytes(
                &PcVoteMessage {
                    round,
                    scope: PcScope {
                        epoch: Epoch::new(1),
                        view: SpcView::new(1),
                    },
                    vector: v.clone(),
                },
                &net(),
            )
        };
        let all = [
            mk(PcRound::Vote1),
            mk(PcRound::Vote2),
            mk(PcRound::Vote2Length),
            mk(PcRound::Vote3),
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    /// The two relay kinds sign different bytes for the same payload.
    #[test]
    fn relay_kinds_separate() {
        let hash = Hash::from_bytes(b"payload");
        let mk = |kind| {
            signed_bytes(
                &SpcRelayMessage {
                    kind,
                    epoch: Epoch::new(1),
                    view: SpcView::new(2),
                    content_hash: hash,
                },
                &net(),
            )
        };
        assert_ne!(mk(SpcRelayKind::NewView), mk(SpcRelayKind::NewCommit));
    }
}
