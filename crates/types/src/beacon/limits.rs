//! Beacon proposal content limits.
//!
//! Hard caps applied at decode time on peer-supplied proposal payloads.
//! Wire decoders enforce them on the length prefix before any
//! per-element work, so an oversized proposal is rejected before
//! allocator pressure builds.
//!
//! These are protocol invariants, not operator-tunable config.

/// Committee-exact cap on a beacon block's `committed_proposals` (one
/// per committed committee member) and on any per-committee-member map.
///
/// A beacon committee holds at most `chain_config.beacon_committee_size`
/// members, so a committed-proposal list never exceeds this. Genesis
/// validates `beacon_committee_size <= MAX_BEACON_COMMITTEE`. Tighter
/// than the generic [`MAX_SIGNERS`](crate::primitives::signer_bitfield::MAX_SIGNERS) wire cap that
/// other signer collections use.
pub const MAX_BEACON_COMMITTEE: usize = 128;

/// Hard cap on the number of distinct shards referenced in a single
/// beacon proposal or block (the `boundary_qcs` /
/// `shard_contributions` per-shard maps).
///
/// A wire/memory bound: at ~250 B per boundary QC this caps a malicious
/// proposal's per-shard maps at ~1 MB. It is also the hard ceiling on
/// how far resharding can grow the live-shard set; the real-world
/// ceiling is lower (`active validators / SHARD_CAPACITY`).
pub const MAX_SHARDS: usize = 4096;

/// Per-shard cap on the witnesses carried in one
/// `ShardEpochContribution` — the fold's per-epoch drain budget.
///
/// In steady state the fold drains a crossing's whole backlog each
/// epoch and never touches this cap; it binds only on catch-up, when
/// the beacon lagged a live, producing shard. Leaf production tracks
/// staking-contract activity, committee turnover, and reshape signals —
/// not block rate — so steady-state windows sit far below the cap. It is
/// sized against the burst case instead: a block's receipts can each emit
/// up to [`MAX_BEACON_WITNESS_EVENTS_PER_TX`] leaves, so a fold capped
/// below a burst can never catch up, and the reshape lifecycle (whose
/// ready signals ride the same stream) would livelock on its readiness
/// TTL. The cap also bounds the deepest live backlog the crossing
/// retention window can accumulate before the topology-schedule floor
/// would park the fold.
pub const MAX_WITNESSES_PER_SHARD: usize = 4096;

/// Per-proposer cap on equivocation evidence in a single
/// [`BeaconProposal`](crate::BeaconProposal).
///
/// Slashing evidence rides its own reserved slots so a flood of routine
/// shard witnesses can't crowd it out. Each entry costs two verifies
/// at admission; the cap times the committee size — gated to one
/// evaluation per proposer per epoch by the coordinator's dedup — bounds
/// a Byzantine proposer's forged-evidence verification cost.
pub const MAX_EQUIVOCATIONS_PER_PROPOSER: usize = 16;

/// Per-proposer cap on shard fork proofs in a single
/// [`BeaconProposal`](crate::BeaconProposal).
///
/// Tighter than the equivocation cap because a fork proof costs far more
/// to admit: four QC verifies against committees resolved from the
/// schedule, plus a parent-hash walk over two ancestry links that reach
/// [`MAX_COMMIT_PROOF_ANCESTRY`](crate::MAX_COMMIT_PROOF_ANCESTRY)
/// headers each. Sizing by shard count instead would let one proposer
/// claim orders of magnitude more bytes than a frame carries.
///
/// A cap rather than the live shard count is sound because a fork needs
/// f+1 corrupt seats on the shard it forks: a cohort holding that in
/// more shards at once than this has broken the security assumption at a
/// scale no proposal size recovers from. The overflow is not dropped —
/// the observation buffer holds what a build leaves behind and carries it
/// into the next proposal — so the cost of the bound is epochs to work
/// through a mass fork, not forks that go unreported.
pub const MAX_FORK_PROOFS_PER_PROPOSER: usize = 8;

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

/// Cap on the depth of a shard's beacon-witness accumulator tree.
///
/// Sized to handle accumulators up to `2^64` leaves with headroom —
/// overkill for any realistic shard-witness volume, but it is what bounds
/// [`MAX_RANGE_PROOF_NODES`] and so belongs on the generous side.
pub const MAX_WITNESS_PROOF_DEPTH: usize = 64;

/// Cap on the node count of a witness-chunk range multiproof.
///
/// A range proof carries at most one left and one right flank per tree
/// level, so twice [`MAX_WITNESS_PROOF_DEPTH`] covers any window the
/// depth cap admits. Realistic proofs are far smaller: a chunk ending at
/// the window's leaf count needs no right flank at any level, so it costs
/// at most one node per level and usually fewer.
pub const MAX_RANGE_PROOF_NODES: usize = 2 * MAX_WITNESS_PROOF_DEPTH;

/// Page size for the bootstrap witness-history sync.
///
/// Bounds one `GetWitnessHistoryResponse`'s payload array at decode time.
/// The beacon's own chunk fetch does not page: a range proof only
/// verifies for the whole run it covers, so that path is bounded by
/// [`MAX_WITNESSES_PER_SHARD`] instead.
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
