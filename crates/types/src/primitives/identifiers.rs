//! Domain-specific identifier types.

use std::fmt::{self, Display};
use std::iter::Sum;
use std::ops::{Add, AddAssign, Sub, SubAssign};

use hex::encode as hex_encode;
use sbor::prelude::*;

/// Validator identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, BasicSbor)]
#[sbor(transparent)]
pub struct ValidatorId(u64);

impl ValidatorId {
    /// Construct a validator id from a raw `u64`.
    ///
    /// Boundary constructor — committee enumeration, wire decode, sentinel
    /// values (`ValidatorId::new(u64::MAX)` for fetched-no-real-sender), and
    /// tests.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Inner `u64`. Use sparingly — at boundaries (display, structured log
    /// fields, hashing) only.
    #[must_use]
    pub const fn inner(self) -> u64 {
        self.0
    }

    /// Little-endian byte representation of the inner value.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

impl Display for ValidatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Validator({})", self.0)
    }
}

/// Shard group identifier — a node in the binary trie over the
/// `blake3(node_id)` keyspace, identified by its prefix path.
///
/// The root (whole keyspace) has depth 0; a node at `depth` owns every node id
/// whose hash begins with `path`'s `depth` bits (most-significant first). A
/// shard is a leaf of the active [`ShardTrie`](crate::ShardTrie). The id is
/// self-describing — depth, path, ancestors, and children need no external
/// context — and orders by keyspace position (left to right), shallower
/// ancestors before their descendants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BasicSbor)]
pub struct ShardId {
    /// Trie depth; 0 is the root, at most 63. (Padded to a `u64` boundary by
    /// `path`'s alignment, so `u32` costs nothing over `u8` and avoids casts
    /// at the `leading_zeros`/`trailing_zeros` boundaries.)
    depth: u32,
    /// The `depth`-bit hash prefix (most-significant first) in the low `depth`
    /// bits; 0 for the root.
    path: u64,
}

impl ShardId {
    /// The root shard: the whole keyspace, depth 0. The sole shard before any
    /// split.
    pub const ROOT: Self = Self { depth: 0, path: 0 };

    /// Construct the trie leaf at `depth` whose path is the integer `path` (the
    /// first `depth` node-hash bits, most-significant first).
    ///
    /// # Panics
    /// Panics if `depth >= 64` or `path` does not fit in `depth` bits.
    #[must_use]
    pub const fn leaf(depth: u32, path: u64) -> Self {
        assert!(depth < 64, "shard depth must be < 64");
        assert!(
            depth == 0 || path < (1u64 << depth),
            "path must fit in depth bits"
        );
        Self { depth, path }
    }

    /// Depth of this node in the trie (root is 0).
    #[must_use]
    pub const fn depth(self) -> u32 {
        self.depth
    }

    /// The `depth`-bit path (node-hash prefix, MSB-first) as an integer.
    #[must_use]
    pub const fn path(self) -> u64 {
        self.path
    }

    /// Parent node, or `None` for the root.
    #[must_use]
    pub const fn parent(self) -> Option<Self> {
        if self.depth == 0 {
            None
        } else {
            Some(Self {
                depth: self.depth - 1,
                path: self.path >> 1,
            })
        }
    }

    /// The two children (`path||0`, `path||1`) produced by splitting this node.
    #[must_use]
    pub const fn children(self) -> (Self, Self) {
        let depth = self.depth + 1;
        (
            Self {
                depth,
                path: self.path << 1,
            },
            Self {
                depth,
                path: (self.path << 1) | 1,
            },
        )
    }

    /// Sibling node (shares a parent), or `None` for the root.
    #[must_use]
    pub const fn sibling(self) -> Option<Self> {
        if self.depth == 0 {
            None
        } else {
            Some(Self {
                depth: self.depth,
                path: self.path ^ 1,
            })
        }
    }

    /// Whether `self` is an ancestor of (or equal to) `other` — i.e. `other`
    /// lies in `self`'s subtree.
    #[must_use]
    pub const fn is_ancestor_of(self, other: Self) -> bool {
        self.depth <= other.depth && (other.path >> (other.depth - self.depth)) == self.path
    }

    /// Canonical scalar encoding (heap index `(1 << depth) | path`) for storage
    /// keys, structured-log fields, and hashing. Round-trips via
    /// [`Self::from_heap_index`].
    #[must_use]
    pub const fn inner(self) -> u64 {
        (1u64 << self.depth) | self.path
    }

    /// Decode a shard from its [`Self::inner`] scalar. Boundary constructor for
    /// storage / wire decode.
    ///
    /// # Panics
    /// Panics if `heap_index` is 0 (not a valid encoding).
    #[must_use]
    pub const fn from_heap_index(heap_index: u64) -> Self {
        assert!(heap_index >= 1, "heap index must be >= 1");
        let depth = heap_index.ilog2();
        Self {
            depth,
            path: heap_index & !(1u64 << depth),
        }
    }

    /// Little-endian bytes of the [`Self::inner`] scalar.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 8] {
        self.inner().to_le_bytes()
    }
}

impl Ord for ShardId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Keyspace order: by the MSB-aligned path, then shallower (ancestor)
        // before deeper.
        let align = |s: &Self| -> u64 {
            if s.depth == 0 {
                0
            } else {
                s.path << (64 - s.depth)
            }
        };
        align(self)
            .cmp(&align(other))
            .then(self.depth.cmp(&other.depth))
    }
}

impl PartialOrd for ShardId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for ShardId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Shard(d{}p{})", self.depth, self.path)
    }
}

/// Block height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, BasicSbor)]
#[sbor(transparent)]
pub struct BlockHeight(u64);

impl BlockHeight {
    /// The absolute height floor — the genesis height of chains born at
    /// network genesis. Not every chain starts here: a child chain
    /// created by a shard split inherits its genesis height from its
    /// `ChainOrigin` (parent terminal height + 1), so "is genesis" checks
    /// must use the structural predicates on headers and QCs, never a
    /// comparison against this constant.
    pub const GENESIS: Self = Self(0);

    /// Construct a block height from a raw `u64`.
    ///
    /// Most call sites should use [`BlockHeight::next`] or arithmetic
    /// operators instead — this constructor is the escape hatch for
    /// boundaries (storage decode, sync ranges, tests) where the height
    /// genuinely originates as a raw integer.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Inner `u64`. Use sparingly — at boundaries (display, storage encode,
    /// hashing, distance arithmetic that the operator overloads don't cover)
    /// only.
    #[must_use]
    pub const fn inner(self) -> u64 {
        self.0
    }

    /// Get the next block height.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }

    /// Get the previous block height (returns None if at genesis).
    #[must_use]
    pub const fn prev(self) -> Option<Self> {
        if self.0 > 0 {
            Some(Self(self.0 - 1))
        } else {
            None
        }
    }

    /// Saturating subtraction by a raw offset.
    #[must_use]
    pub const fn saturating_sub(self, rhs: u64) -> Self {
        Self(self.0.saturating_sub(rhs))
    }

    /// Little-endian byte representation of the inner value.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

impl Add<u64> for BlockHeight {
    type Output = Self;
    fn add(self, rhs: u64) -> Self {
        Self(
            self.0
                .checked_add(rhs)
                .expect("BlockHeight + u64 overflowed"),
        )
    }
}

impl Sub<u64> for BlockHeight {
    type Output = Self;
    fn sub(self, rhs: u64) -> Self {
        Self(
            self.0
                .checked_sub(rhs)
                .expect("BlockHeight - u64 underflowed"),
        )
    }
}

impl Sub<Self> for BlockHeight {
    type Output = u64;
    fn sub(self, rhs: Self) -> u64 {
        self.0
            .checked_sub(rhs.0)
            .expect("BlockHeight distance underflowed (lhs < rhs)")
    }
}

impl AddAssign<u64> for BlockHeight {
    fn add_assign(&mut self, rhs: u64) {
        self.0 = self
            .0
            .checked_add(rhs)
            .expect("BlockHeight += u64 overflowed");
    }
}

impl Display for BlockHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Block({})", self.0)
    }
}

/// Beacon-chain epoch number.
///
/// Coarse grouping of slots; increments on epoch boundaries (committee
/// resample, validator-set rotation). Stored on `BeaconState`; not
/// generally on the wire except inside state-root proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, BasicSbor)]
#[sbor(transparent)]
pub struct Epoch(u64);

impl Epoch {
    /// Genesis epoch.
    pub const GENESIS: Self = Self(0);

    /// Construct an epoch from a raw `u64`.
    ///
    /// Most call sites should use [`Epoch::next`] instead — this
    /// constructor is the escape hatch for boundaries (state decode,
    /// tests) where the epoch genuinely originates as a raw integer.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Inner `u64`. Use sparingly — at boundaries (display, structured
    /// log fields, hashing) only.
    #[must_use]
    pub const fn inner(self) -> u64 {
        self.0
    }

    /// Get the next epoch.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }

    /// Saturating subtraction. Beacon cooldown and unbonding checks
    /// compare `current_epoch.saturating_sub(initiated_at_epoch.inner())`
    /// against the relevant `*_EPOCHS` constant; saturating semantics
    /// keep the comparison well-defined if a record from a never-reached
    /// future epoch ever shows up.
    #[must_use]
    pub const fn saturating_sub(self, rhs: u64) -> Self {
        Self(self.0.saturating_sub(rhs))
    }

    /// Little-endian byte representation of the inner value.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

impl Display for Epoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Epoch({})", self.0)
    }
}

/// Aggregate stake committed to a beacon-chain validator pool.
///
/// Beacon-side accounting only — delegator-level deposits and withdrawals
/// live in the staking contract on the shard layer; the beacon tracks
/// per-pool aggregate `Stake` deltas via `ShardWitnessPayload::StakeDeposit`
/// / `StakeWithdraw`.
///
/// Denominated in **attos** (10⁻¹⁸ whole tokens) for lossless interop
/// with Radix's [`Decimal`](https://docs.rs/radix-common). `u128` gives
/// ~3.4 × 10²⁰ whole tokens of headroom — vastly more than any realistic
/// supply, so arithmetic doesn't need to be defensive against overflow
/// at protocol-reasonable values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, BasicSbor)]
#[sbor(transparent)]
pub struct Stake(u128);

impl Stake {
    /// Whole tokens per atto — the unit shift factor `10^18`. Matches
    /// Radix `Decimal`'s 18-decimal scale.
    pub const ATTOS_PER_WHOLE: u128 = 1_000_000_000_000_000_000;

    /// Zero stake.
    pub const ZERO: Self = Self(0);

    /// Saturating upper bound used as the "no active validator" sentinel
    /// in `min_stake` computations: an empty active-validator set imposes
    /// no eject ceiling, so the field reads as `Stake::MAX` and the
    /// `.min(...)` clamp picks the admit-threshold or floor instead.
    pub const MAX: Self = Self(u128::MAX);

    /// Construct from a raw atto count. The canonical primary
    /// constructor — sites that hold a Radix-derived atto value pass it
    /// straight through, no rounding policy needed.
    #[must_use]
    pub const fn from_attos(attos: u128) -> Self {
        Self(attos)
    }

    /// Construct from a whole-token count.
    ///
    /// `n * ATTOS_PER_WHOLE` always fits in `u128` for any `u64` input
    /// (`u64::MAX * 10^18` is ~1.8 × 10³⁷, well below `u128::MAX` of
    /// ~3.4 × 10³⁸), so the multiplication is overflow-safe by
    /// construction.
    #[must_use]
    pub const fn from_whole_tokens(n: u64) -> Self {
        Self((n as u128) * Self::ATTOS_PER_WHOLE)
    }

    /// Inner atto count. Use at boundaries (display, threshold
    /// arithmetic, Radix-side conversion via
    /// `Decimal::from_attos`) only.
    #[must_use]
    pub const fn attos(self) -> u128 {
        self.0
    }

    /// Saturating sum. Beacon stake-accumulation sites (deposits,
    /// reward distribution) should use this rather than reaching for the
    /// inner attos, so the saturating semantics live with the type.
    #[must_use]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    /// Saturating difference. Used by withdrawal accounting and
    /// `effective_stake` to keep the result non-negative when bookkeeping
    /// drifts (e.g. a bogus over-withdrawal that survives upstream
    /// validation).
    #[must_use]
    pub const fn saturating_sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }

    /// Divide this stake equally across `n` shares, returning the
    /// per-share amount with the integer-division remainder discarded.
    /// Returns `None` when `n == 0`; callers handle that as "no shares,
    /// no distribution."
    #[must_use]
    pub const fn checked_div_count(self, n: u64) -> Option<Self> {
        if n == 0 {
            None
        } else {
            Some(Self(self.0 / n as u128))
        }
    }
}

impl Display for Stake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Identifier for a beacon-chain stake pool — a dPoS-style aggregation
/// of delegator stake that operates one or more validator nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, BasicSbor)]
#[sbor(transparent)]
pub struct StakePoolId(u32);

impl StakePoolId {
    /// Construct a stake-pool id from a raw `u32`.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Inner `u32`. Use sparingly — at boundaries (display, structured
    /// log fields) only.
    #[must_use]
    pub const fn inner(self) -> u32 {
        self.0
    }
}

impl Display for StakePoolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pool({})", self.0)
    }
}

/// Position in a shard's monotonic beacon-witness accumulator.
///
/// Stable across the shard's lifetime — leaf `N` is leaf `N` forever.
/// Used by the beacon's per-shard high-water mark for witness replay
/// protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, BasicSbor)]
#[sbor(transparent)]
pub struct LeafIndex(u64);

impl LeafIndex {
    /// Construct a leaf index from a raw `u64`.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Inner `u64`. Use sparingly — at boundaries (display, accumulator
    /// arithmetic, structured log fields) only.
    #[must_use]
    pub const fn inner(self) -> u64 {
        self.0
    }
}

impl Display for LeafIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Leaf({})", self.0)
    }
}

/// Total leaves in a shard's beacon-witness accumulator at a given
/// committed block.
///
/// Paired with [`BeaconWitnessRoot`](crate::BeaconWitnessRoot) on
/// [`BlockHeader`](crate::BlockHeader) so a verifier holding only the
/// header can check any inclusion proof anchored at that block — the
/// padded-perfect-tree shape that the accumulator produces is fully
/// determined by the count, so no side-channel hint is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, BasicSbor)]
#[sbor(transparent)]
pub struct BeaconWitnessLeafCount(u64);

impl BeaconWitnessLeafCount {
    /// Empty accumulator.
    pub const ZERO: Self = Self(0);

    /// Construct a leaf count from a raw `u64`.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Inner `u64`. Use sparingly — at boundaries (display, accumulator
    /// arithmetic against `Vec<_>::len()`, structured log fields) only.
    #[must_use]
    pub const fn inner(self) -> u64 {
        self.0
    }
}

impl Display for BeaconWitnessLeafCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BeaconWitnessLeafCount({})", self.0)
    }
}

/// Strong Prefix Consensus view counter.
///
/// SPC drives one slot through a sequence of views. Each view runs an
/// inner Prefix Consensus instance under a distinct domain context
/// (`spc_ctx || view.to_le_bytes()`); a `(slot, view)` pair uniquely
/// identifies the PC instance whose round-3 cert any embedded `PcQc3`
/// belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, BasicSbor)]
#[sbor(transparent)]
pub struct SpcView(u32);

impl SpcView {
    /// Initial view (per the paper, the first SPC view is `1`).
    pub const INITIAL: Self = Self(1);

    /// Construct an SPC view from a raw `u32`.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Inner `u32`. Use sparingly — at boundaries (display, BLS
    /// signing-bytes construction, structured log fields) only.
    #[must_use]
    pub const fn inner(self) -> u32 {
        self.0
    }

    /// Get the next view.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }

    /// Little-endian byte representation of the inner value.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
}

impl Display for SpcView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SpcView({})", self.0)
    }
}

/// shard round / view number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, BasicSbor)]
#[sbor(transparent)]
pub struct Round(u64);

impl Round {
    /// Initial round.
    pub const INITIAL: Self = Self(0);

    /// Construct a round from a raw `u64`.
    ///
    /// Most call sites should use [`Round::next`] or arithmetic operators
    /// instead — this constructor is the escape hatch for boundaries
    /// (storage decode, wire decode, tests) where the round genuinely
    /// originates as a raw integer.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Inner `u64`. Use sparingly — at boundaries (display, storage encode,
    /// hashing) only.
    #[must_use]
    pub const fn inner(self) -> u64 {
        self.0
    }

    /// Get the next round.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }

    /// Saturating subtraction by a raw offset.
    #[must_use]
    pub const fn saturating_sub(self, rhs: u64) -> Self {
        Self(self.0.saturating_sub(rhs))
    }

    /// Little-endian byte representation of the inner value.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }
}

impl Add<u64> for Round {
    type Output = Self;
    fn add(self, rhs: u64) -> Self {
        Self(self.0.checked_add(rhs).expect("Round + u64 overflowed"))
    }
}

impl Sub<u64> for Round {
    type Output = Self;
    fn sub(self, rhs: u64) -> Self {
        Self(self.0.checked_sub(rhs).expect("Round - u64 underflowed"))
    }
}

impl Sub<Self> for Round {
    type Output = u64;
    fn sub(self, rhs: Self) -> u64 {
        self.0
            .checked_sub(rhs.0)
            .expect("Round distance underflowed (lhs < rhs)")
    }
}

impl AddAssign<u64> for Round {
    fn add_assign(&mut self, rhs: u64) {
        self.0 = self.0.checked_add(rhs).expect("Round += u64 overflowed");
    }
}

impl Display for Round {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Round({})", self.0)
    }
}

/// Wave-leader rotation counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, BasicSbor)]
#[sbor(transparent)]
pub struct Attempt(u32);

impl Attempt {
    /// Initial attempt.
    pub const INITIAL: Self = Self(0);

    /// Construct an attempt from a raw `u32`.
    ///
    /// Most call sites should use [`Attempt::next`] or arithmetic operators
    /// instead — this constructor is the escape hatch for boundaries (wire
    /// decode, tests) where the attempt genuinely originates as a raw
    /// integer.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Inner `u32`. Use sparingly — at boundaries (display, structured log
    /// fields) only.
    #[must_use]
    pub const fn inner(self) -> u32 {
        self.0
    }

    /// Get the next attempt.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }

    /// Little-endian byte representation of the inner value.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
}

impl Add<u32> for Attempt {
    type Output = Self;
    fn add(self, rhs: u32) -> Self {
        Self(self.0.checked_add(rhs).expect("Attempt + u32 overflowed"))
    }
}

impl Sub<u32> for Attempt {
    type Output = Self;
    fn sub(self, rhs: u32) -> Self {
        Self(self.0.checked_sub(rhs).expect("Attempt - u32 underflowed"))
    }
}

impl AddAssign<u32> for Attempt {
    fn add_assign(&mut self, rhs: u32) {
        self.0 = self.0.checked_add(rhs).expect("Attempt += u32 overflowed");
    }
}

impl Display for Attempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Attempt({})", self.0)
    }
}

/// A tally of votes.
///
/// Every validator on a committee is worth exactly one vote
/// ([`VoteCount::MIN`]); this is the unit consensus counts in — signers toward
/// a quorum, committee size as the denominator. It is a count, not a stake
/// weight: stake gates how many validators a pool may run, not how much any one
/// validator's vote is worth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, BasicSbor)]
#[sbor(transparent)]
pub struct VoteCount(u64);

impl VoteCount {
    /// No votes — the accumulator initial value.
    pub const ZERO: Self = Self(0);

    /// A single vote — every validator contributes exactly this.
    pub const MIN: Self = Self(1);

    /// Construct a vote count from a raw `u64`.
    ///
    /// Most call sites should use [`VoteCount::of`], the `Add`/`Sub` operators,
    /// or [`VoteCount::ZERO`] / [`VoteCount::MIN`]. This is the escape hatch for
    /// boundaries (decode, tests) where the count originates as a raw integer.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Vote count for a collection of `len` voters — one vote each. The
    /// idiomatic way to turn a committee size or signer count into a
    /// `VoteCount`.
    #[must_use]
    pub const fn of(len: usize) -> Self {
        Self(len as u64)
    }

    /// Inner `u64`. Use sparingly — at boundaries (display, hashing,
    /// weighted-timestamp arithmetic that needs `u128` widening) only.
    #[must_use]
    pub const fn inner(self) -> u64 {
        self.0
    }

    /// Saturating addition.
    #[must_use]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    /// Calculate if `voted` constitutes 2f+1 quorum (>2/3 of `total`).
    #[must_use]
    pub const fn has_quorum(voted: Self, total: Self) -> bool {
        (voted.0 as u128) * 3 > (total.0 as u128) * 2
    }

    /// Calculate if `voted` exceeds the f+1 fault threshold (>1/3 of `total`)
    /// — enough to guarantee at least one honest contributor. Used for Bracha
    /// timeout amplification: on f+1 timeouts a replica broadcasts its own.
    #[must_use]
    pub const fn has_one_third(voted: Self, total: Self) -> bool {
        (voted.0 as u128) * 3 > (total.0 as u128)
    }

    /// Minimum vote count required for 2f+1 quorum out of `total`.
    ///
    /// Equivalent to `total * 2 / 3 + 1` but divides first so the multiply
    /// cannot overflow when `total` is near `u64::MAX`.
    #[must_use]
    pub const fn quorum_threshold(total: Self) -> Self {
        Self(total.0 / 3 * 2 + (total.0 % 3) * 2 / 3 + 1)
    }
}

impl Add for VoteCount {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(
            self.0
                .checked_add(rhs.0)
                .expect("VoteCount + VoteCount overflowed"),
        )
    }
}

impl AddAssign for VoteCount {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = self
            .0
            .checked_add(rhs.0)
            .expect("VoteCount += VoteCount overflowed");
    }
}

impl Sub for VoteCount {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(
            self.0
                .checked_sub(rhs.0)
                .expect("VoteCount - VoteCount underflowed"),
        )
    }
}

impl SubAssign for VoteCount {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = self
            .0
            .checked_sub(rhs.0)
            .expect("VoteCount -= VoteCount underflowed");
    }
}

impl Sum for VoteCount {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, Add::add)
    }
}

impl<'a> Sum<&'a Self> for VoteCount {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.copied().fold(Self::ZERO, Add::add)
    }
}

impl Display for VoteCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// In-flight transaction count on a shard at block-proposal time.
///
/// "In-flight" = txs admitted to the proposer's mempool but not yet finalized
/// by a wave certificate. Carried in `BlockHeader` and gossiped cross-shard so
/// remote nodes can shed RPC submissions targeting congested shards. Verified
/// deterministically as `parent + new - finalized`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, BasicSbor)]
#[sbor(transparent)]
pub struct InFlightCount(u32);

impl InFlightCount {
    /// Zero in-flight (genesis).
    pub const ZERO: Self = Self(0);

    /// Construct an in-flight count from a raw `u32`.
    ///
    /// Most call sites should use [`InFlightCount::saturating_add`] /
    /// [`InFlightCount::saturating_sub`] instead — this constructor is the
    /// escape hatch for boundaries (mempool-derived thresholds, tests) where
    /// the count genuinely originates as a raw integer.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Inner `u32`. Use sparingly — at boundaries (display, structured log
    /// fields) only.
    #[must_use]
    pub const fn inner(self) -> u32 {
        self.0
    }

    /// Add `new_txs` (admissions in this block), saturating at `u32::MAX`.
    #[must_use]
    pub const fn saturating_add(self, new_txs: u32) -> Self {
        Self(self.0.saturating_add(new_txs))
    }

    /// Subtract `finalized_txs` (finalizations in this block), saturating at zero.
    #[must_use]
    pub const fn saturating_sub(self, finalized_txs: u32) -> Self {
        Self(self.0.saturating_sub(finalized_txs))
    }
}

impl Display for InFlightCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Maximum number of consecutive committed block headers to return in one
/// `GetRemoteHeadersRequest` round-trip.
///
/// Capped on both ends: callers clamp to this value when building requests,
/// and responders clamp the field again before iterating storage. Lives next
/// to `BlockHeight` on the wire — typing it prevents an argument-order swap
/// between the two `u64` fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, BasicSbor)]
#[sbor(transparent)]
pub struct HeaderFetchCount(u64);

impl HeaderFetchCount {
    /// Zero headers requested.
    pub const ZERO: Self = Self(0);

    /// Construct a header-fetch count from a raw `u64`.
    ///
    /// Most call sites should use [`HeaderFetchCount::min`] against the
    /// configured cap instead — this constructor is the escape hatch for
    /// boundaries (FSM-internal counts, request-builder constants, tests)
    /// where the count genuinely originates as a raw integer.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Inner `u64`. Use sparingly — at boundaries (loop bounds, FSM input,
    /// arithmetic against raw `BlockHeight` offsets, structured log fields)
    /// only.
    #[must_use]
    pub const fn inner(self) -> u64 {
        self.0
    }

    /// Return the smaller of `self` and `cap`.
    #[must_use]
    pub const fn min(self, cap: Self) -> Self {
        if self.0 < cap.0 { self } else { cap }
    }
}

impl Display for HeaderFetchCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Node identifier (30-byte address).
///
/// This is a simplified version that doesn't depend on Radix types.
/// It represents an address in the state tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, BasicSbor)]
pub struct NodeId(pub [u8; 30]);

impl NodeId {
    /// Create a `NodeId` from bytes.
    ///
    /// # Panics
    ///
    /// Panics if bytes length is not exactly 30.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 30, "NodeId must be exactly 30 bytes");
        let mut arr = [0u8; 30];
        arr.copy_from_slice(bytes);
        Self(arr)
    }

    /// Get the bytes as a slice.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 30] {
        &self.0
    }
}

impl Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({}..)", hex_encode(&self.0[..4]))
    }
}

/// Partition number within a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, BasicSbor)]
#[sbor(transparent)]
pub struct PartitionNumber(pub u8);

impl PartitionNumber {
    /// Create a new partition number.
    #[must_use]
    pub const fn new(n: u8) -> Self {
        Self(n)
    }
}

impl Display for PartitionNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Partition({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_height_next_prev() {
        let height = BlockHeight::new(10);
        assert_eq!(height.next(), BlockHeight::new(11));
        assert_eq!(height.prev(), Some(BlockHeight::new(9)));

        assert_eq!(BlockHeight::GENESIS.prev(), None);
        assert_eq!(BlockHeight::GENESIS.next(), BlockHeight::new(1));
    }

    #[test]
    fn test_vote_count_quorum() {
        let total = VoteCount::new(4);

        assert!(!VoteCount::has_quorum(VoteCount::new(2), total)); // 2/4 = 50% (not enough)
        assert!(VoteCount::has_quorum(VoteCount::new(3), total)); // 3/4 = 75% (quorum!)
        assert!(VoteCount::has_quorum(VoteCount::new(4), total)); // 4/4 = 100% (quorum!)
    }

    #[test]
    fn test_vote_count_one_third() {
        // f+1 (Bracha) threshold: strictly greater than 1/3 of total.
        let total = VoteCount::new(4);

        assert!(!VoteCount::has_one_third(VoteCount::new(1), total)); // 1/4 = 25% (not enough)
        assert!(VoteCount::has_one_third(VoteCount::new(2), total)); // 2/4 = 50% (≥ f+1)
        assert!(VoteCount::has_one_third(VoteCount::new(3), total)); // 3/4 (quorum implies f+1)

        // Exactly 1/3 is not enough — need strictly greater.
        let q = |v, t| VoteCount::has_one_third(VoteCount::new(v), VoteCount::new(t));
        assert!(!q(3, 9), "exactly 1/3 should not clear the f+1 threshold");
        assert!(q(4, 9), "just over 1/3 should clear the f+1 threshold");
    }

    #[test]
    fn test_vote_count_quorum_boundary_conditions() {
        // BFT safety requires STRICTLY GREATER than 2/3
        // Formula: voted * 3 > total * 2
        let q = |v, t| VoteCount::has_quorum(VoteCount::new(v), VoteCount::new(t));

        // Exact 2/3 should NOT be quorum (need > 2/3)
        // 6/9 = 2/3 exactly: 6*3 = 18, 9*2 = 18, 18 > 18 is false
        assert!(!q(6, 9), "Exactly 2/3 should not be quorum");

        // Just over 2/3 should be quorum
        // 7/10 = 70%: 7*3 = 21, 10*2 = 20, 21 > 20 is true
        assert!(q(7, 10), "Just over 2/3 should be quorum");

        // Just under 2/3 should NOT be quorum
        // 6/10 = 60%: 6*3 = 18, 10*2 = 20, 18 > 20 is false
        assert!(!q(6, 10), "60% should not be quorum");

        // Edge case: total of 3 (smallest BFT)
        // Need > 2/3, so need > 2 votes = 3 votes
        assert!(!q(2, 3), "2/3 should not be quorum");
        assert!(q(3, 3), "3/3 should be quorum");

        // Edge case: total of 1
        assert!(q(1, 1), "1/1 should be quorum");
        assert!(!q(0, 1), "0/1 should not be quorum");

        // Edge case: zero total (degenerate)
        assert!(!q(0, 0), "0/0 should not be quorum");

        // Common committee sizes
        // n=4: need > 8/3 = 2.67, so need 3
        assert!(!q(2, 4));
        assert!(q(3, 4));

        // n=7: need > 14/3 = 4.67, so need 5
        assert!(!q(4, 7));
        assert!(q(5, 7));

        // n=10: need > 20/3 = 6.67, so need 7
        assert!(!q(6, 10));
        assert!(q(7, 10));

        // n=100: need > 200/3 = 66.67, so need 67
        assert!(!q(66, 100));
        assert!(q(67, 100));
    }

    #[test]
    fn test_vote_count_quorum_large_values() {
        // Test with large values to ensure no overflow issues
        // The formula is: voted * 3 > total * 2
        // Maximum safe values before overflow: u64::MAX / 3 for voted

        let max_safe_voted = u64::MAX / 3;

        // With max safe values, quorum should still work correctly
        // voted = max/3, total = max/3 + 1
        // voted * 3 = max (approximately)
        // total * 2 = (max/3 + 1) * 2 = 2*max/3 + 2
        // max > 2*max/3 + 2 is true
        assert!(
            VoteCount::has_quorum(
                VoteCount::new(max_safe_voted),
                VoteCount::new(max_safe_voted + 1)
            ),
            "Large values near u64::MAX/3 should work"
        );

        // The arithmetic widens to u128 internally, so even pathological
        // voting powers near u64::MAX cannot overflow. This guard pins the
        // edge case so a future regression to plain u64 multiplication
        // would surface here.
        assert!(VoteCount::has_quorum(
            VoteCount::new(u64::MAX),
            VoteCount::new(u64::MAX)
        ));
        assert!(!VoteCount::has_quorum(
            VoteCount::ZERO,
            VoteCount::new(u64::MAX)
        ));
    }

    #[test]
    fn test_vote_count_quorum_unequal_distribution() {
        // Test quorum with realistic unequal voting power distributions
        // In practice, validators may have different stakes
        let q = |v, t| VoteCount::has_quorum(VoteCount::new(v), VoteCount::new(t));

        // Scenario: 4 validators with powers [3, 2, 2, 1] = 8 total
        // Need > 16/3 = 5.33, so need 6 power for quorum
        assert!(!q(5, 8), "5/8 should not be quorum");
        assert!(q(6, 8), "6/8 should be quorum");

        // Byzantine scenario: One validator has 40% power
        // 4 validators: [4, 2, 2, 2] = 10 total
        // Need > 20/3 = 6.67, so need 7 power
        // If Byzantine (power 4) colludes with one honest (power 2), they have 6 (not enough)
        assert!(
            !q(6, 10),
            "Byzantine + 1 honest (6/10) should not be quorum"
        );
        assert!(q(7, 10), "7/10 should be quorum");
    }

    #[test]
    fn test_node_id() {
        let bytes = [42u8; 30];
        let node_id = NodeId(bytes);
        assert_eq!(node_id.as_bytes(), &bytes);
    }
}
