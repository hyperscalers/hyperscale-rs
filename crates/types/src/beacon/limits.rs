//! Beacon proposal content limits.
//!
//! Hard caps applied at decode time on peer-supplied proposal payloads.
//! Wire decoders enforce them on the [`BoundedVec`](crate::BoundedVec)
//! length prefix before any per-element work, so an oversized proposal
//! is rejected before allocator pressure builds.
//!
//! These are protocol invariants, not operator-tunable config.

/// Per-proposer fair-share cap on witnesses in a single
/// [`BeaconProposal`](crate::BeaconProposal).
///
/// Bounds the proposer's raw wire-bandwidth contribution and the
/// allocator pressure their proposal can impose at decode time. Sized
/// to cover legitimate committee turnover (registrations, jails,
/// unjails) plus headroom; a proposer that tries to crowd in more
/// loses everything past the cap before any per-witness work runs.
pub const MAX_WITNESSES_PER_PROPOSER: usize = 32;

/// Hard cap on a [`PcVector`](crate::PcVector)'s element count.
///
/// Bounds attacker-controlled length prefixes on PC vote / QC
/// payloads at decode time. Sized well above any realistic per-slot
/// vector length (the committee agrees on a single proposal hash per
/// member, so legitimate vectors stay in the committee-size range).
pub const MAX_VOTE_VECTOR_LEN: usize = 1024;

/// Cap on the per-vote prefix-signature list.
///
/// A signer's `prefix_sigs` array carries one signature per prefix of
/// their input vector, so its length is exactly
/// `v_in.len() + 1` (the empty-prefix slot through the full-length
/// slot). Cap follows directly from [`MAX_VOTE_VECTOR_LEN`].
pub const MAX_PREFIX_SIGS: usize = MAX_VOTE_VECTOR_LEN + 1;

/// Cap on the `skip_sigs` vector inside an [`SpcCert::Indirect`](crate::SpcCert).
///
/// An indirect cert authorises view-entry via `f+1` empty-view
/// attestations. `f+1 ≤ n`, and `n` is bounded by
/// [`MAX_VALIDATORS`](crate::SignerBitfield) — sized identically here
/// for the wire-decode bound. Consensus-layer validation pins the
/// actual count against the committee size at the cert's slot.
pub const MAX_SKIP_SIGS: usize = 4096;
