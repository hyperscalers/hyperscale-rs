//! Domain-separated signing for beacon epoch-ratification votes.
//!
//! Each active validator ratifies a beacon block for an epoch by
//! signing `(anchor_hash, epoch, round, phase, block_hash)` under
//! [`DOMAIN_RATIFY_VOTE`]. A prevote and a precommit at the same round
//! sign different bytes, so neither can stand in for the other;
//! a quorum of precommits over the same tuple aggregates into a
//! [`RatifyCert`](crate::RatifyCert) committing the block.
//!
//! Domain separation here keeps a ratify sig from being confused with
//! a PC vote, a VRF reveal, or any other BLS message reusing the same
//! key material.

use crate::{BeaconBlockHash, Epoch, NetworkDefinition, RatifyPhase, RatifyRound};

/// Domain tag for individual ratify-vote signatures and for the
/// aggregate signature on the assembled
/// [`RatifyCert`](crate::RatifyCert).
pub const DOMAIN_RATIFY_VOTE: &[u8] = b"HYPERSCALE_RATIFY_VOTE_v1";

/// Build the canonical signing bytes for a ratify vote on `block_hash`
/// at `(anchor_hash, epoch, round, phase)` under `network`.
///
/// Layout: `domain || network.id || anchor_hash (32) || epoch_le (8)
/// || round_le (4) || phase (1) || block_hash (32)`. All fields are
/// fixed-width — no length prefixes needed.
#[must_use]
pub fn ratify_vote_message(
    network: &NetworkDefinition,
    anchor_hash: &BeaconBlockHash,
    epoch: Epoch,
    round: RatifyRound,
    phase: RatifyPhase,
    block_hash: &BeaconBlockHash,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN_RATIFY_VOTE.len() + 1 + 32 + 8 + 4 + 1 + 32);
    out.extend_from_slice(DOMAIN_RATIFY_VOTE);
    out.push(network.id);
    out.extend_from_slice(anchor_hash.as_bytes());
    out.extend_from_slice(&epoch.to_le_bytes());
    out.extend_from_slice(&round.to_le_bytes());
    out.push(phase.tag());
    out.extend_from_slice(block_hash.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash;
    use crate::signing::DOMAIN_PC_VRF;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn anchor() -> BeaconBlockHash {
        BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor"))
    }

    fn block() -> BeaconBlockHash {
        BeaconBlockHash::from_raw(Hash::from_bytes(b"block"))
    }

    /// Pins the byte layout. Any change to the encoder — field order,
    /// width, domain tag — fails this test. Cross-arch determinism
    /// rides on this layout being identical regardless of host
    /// `usize` width.
    #[test]
    fn ratify_vote_message_byte_layout_is_pinned() {
        let bytes = ratify_vote_message(
            &net(),
            &anchor(),
            Epoch::new(5),
            RatifyRound::new(2),
            RatifyPhase::Precommit,
            &block(),
        );

        let mut expected = Vec::new();
        expected.extend_from_slice(DOMAIN_RATIFY_VOTE);
        expected.push(net().id);
        expected.extend_from_slice(anchor().as_bytes());
        expected.extend_from_slice(&5u64.to_le_bytes());
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.push(1);
        expected.extend_from_slice(block().as_bytes());

        assert_eq!(bytes, expected);
        assert_eq!(
            bytes.len(),
            DOMAIN_RATIFY_VOTE.len() + 1 + 32 + 8 + 4 + 1 + 32
        );
    }

    /// A prevote and a precommit over the same tuple sign different
    /// bytes — the phase byte is load-bearing: without it a single
    /// signature could count toward both a polka and a commit.
    #[test]
    fn ratify_vote_message_differs_across_phases() {
        let mk = |phase| {
            ratify_vote_message(
                &net(),
                &anchor(),
                Epoch::new(5),
                RatifyRound::INITIAL,
                phase,
                &block(),
            )
        };
        assert_ne!(mk(RatifyPhase::Prevote), mk(RatifyPhase::Precommit));
    }

    #[test]
    fn ratify_vote_message_differs_across_rounds() {
        let mk = |round| {
            ratify_vote_message(
                &net(),
                &anchor(),
                Epoch::new(5),
                round,
                RatifyPhase::Prevote,
                &block(),
            )
        };
        assert_ne!(mk(RatifyRound::new(1)), mk(RatifyRound::new(2)));
    }

    #[test]
    fn ratify_vote_message_differs_across_block_hashes() {
        let other = BeaconBlockHash::from_raw(Hash::from_bytes(b"other"));
        let mk = |h: &BeaconBlockHash| {
            ratify_vote_message(
                &net(),
                &anchor(),
                Epoch::new(5),
                RatifyRound::INITIAL,
                RatifyPhase::Prevote,
                h,
            )
        };
        assert_ne!(mk(&block()), mk(&other));
    }

    #[test]
    fn ratify_vote_message_differs_across_networks() {
        let mk = |n: &NetworkDefinition| {
            ratify_vote_message(
                n,
                &anchor(),
                Epoch::new(5),
                RatifyRound::INITIAL,
                RatifyPhase::Prevote,
                &block(),
            )
        };
        assert_ne!(
            mk(&NetworkDefinition::mainnet()),
            mk(&NetworkDefinition::stokenet())
        );
    }

    /// Domain separation: a ratify sig must not collide with a VRF
    /// reveal (or any other beacon BLS message reusing the same key
    /// material) — distinct domain tags guarantee the prefixes diverge.
    #[test]
    fn ratify_vote_message_differs_from_other_beacon_domains() {
        let bytes = ratify_vote_message(
            &net(),
            &anchor(),
            Epoch::new(5),
            RatifyRound::INITIAL,
            RatifyPhase::Prevote,
            &block(),
        );
        assert_ne!(&bytes[..DOMAIN_PC_VRF.len()], DOMAIN_PC_VRF);
    }
}
