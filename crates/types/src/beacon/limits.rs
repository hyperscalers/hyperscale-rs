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

/// Cap on the `accusations` vector carried by an
/// [`MscSlotProposalNotification`](crate::network::notification::beacon::MscSlotProposalNotification).
///
/// Accusations accumulate across recent slots' SPC views that produced
/// empty-low outputs; the proposer attaches the batch to their next
/// outgoing slot proposal so MSC's ranking update can demote the
/// accused validators. Steady-state count is near zero; cap sized for
/// burst recovery after a partition or extended thrash window.
pub const MAX_ACCUSATIONS_PER_PROPOSAL: usize = 256;

/// Cap on the depth of a [`ShardWitnessProof`](crate::ShardWitnessProof)'s
/// Merkle path.
///
/// Each level contributes one sibling hash. Sized to handle accumulators
/// up to `2^64` leaves with headroom — overkill for any realistic
/// shard-witness volume but cheap on the wire and safe against
/// pathological inputs.
pub const MAX_WITNESS_PROOF_DEPTH: usize = 64;

/// Per-request cap on the number of shard witnesses a beacon validator
/// pulls in one round-trip.
///
/// Bounds the `leaf_indices` request array and the matching `witnesses`
/// response array at decode time. Sized at a moderate batch — beacon
/// validators typically fetch a handful of witnesses per slot
/// (committee turnover, jails); larger batches degrade to multiple
/// round-trips rather than ballooning a single request.
pub const MAX_WITNESSES_PER_FETCH: usize = 128;
