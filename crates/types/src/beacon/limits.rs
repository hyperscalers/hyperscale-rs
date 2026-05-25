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

/// Per-transaction cap on
/// [`BeaconWitnessEvent`](crate::BeaconWitnessEvent) entries in a
/// [`ConsensusReceipt::Succeeded`](crate::ConsensusReceipt::Succeeded)
/// at decode time.
///
/// Bounds allocator pressure from peer-shipped receipts before any
/// per-event work runs. A single transaction's staking-contract
/// emissions stay well below this in any realistic workload; the cap
/// rejects obviously oversized arrivals.
pub const MAX_BEACON_WITNESS_EVENTS_PER_TX: usize = 32;

/// Cap on [`ReadySignal`](crate::ReadySignal) entries in a single
/// [`BlockManifest`](crate::BlockManifest).
///
/// Bounds proposer-included signals per block at decode time. Steady-state
/// emission rate is near zero — a validator only emits when their
/// `OnShard { ready: false }` placement transitions; the cap covers burst
/// scenarios (committee shuffle aftermath) with headroom.
pub const MAX_READY_SIGNALS_PER_BLOCK: usize = 32;

/// Maximum span of block heights a
/// [`ReadySignal`](crate::ReadySignal)'s `[start, end]` window may cover.
///
/// Bounds replay surface: a signal validates only within its window, so a
/// proposer that hoards a signal past the window can't include it after.
/// Sized to a few minutes at the target shard block rate; validators
/// re-emit if their original signal expires uncollected.
pub const MAX_READY_WINDOW_BLOCKS: u64 = 1024;

/// Cap on the cumulative `excluded_validators` field carried in a
/// [`RecoveryCertificate`](crate::RecoveryCertificate).
///
/// Sized as `BEACON_SIGNER_COUNT × MAX_RECOVERY_ROUNDS_PER_EPOCH`
/// (128 × 8 = 1024) — the maximum cumulative exclusion across all
/// failed recovery rounds for one epoch before the chain is deemed
/// unrecoverable algorithmically and falls to social-consensus hard
/// fork. Any update to either of those constants in
/// [`crates/beacon/src/constants.rs`](../../../beacon/src/constants.rs)
/// must keep this number in sync.
pub const MAX_EXCLUDED_VALIDATORS: usize = 1024;
