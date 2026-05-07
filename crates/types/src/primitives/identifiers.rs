//! Domain-specific identifier types.

use std::fmt::{self, Display};
use std::iter::Sum;
use std::ops::{Add, AddAssign, Sub, SubAssign};

use hex::encode as hex_encode;
use sbor::prelude::*;

/// Validator identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, BasicSbor)]
#[sbor(transparent)]
pub struct ValidatorId(pub u64);

impl Display for ValidatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Validator({})", self.0)
    }
}

/// Shard group identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, BasicSbor)]
#[sbor(transparent)]
pub struct ShardGroupId(pub u64);

impl Display for ShardGroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Shard({})", self.0)
    }
}

/// Block height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, BasicSbor)]
#[sbor(transparent)]
pub struct BlockHeight(u64);

impl BlockHeight {
    /// Genesis block height.
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

/// BFT round / view number.
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

/// Vote power (stake weight).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, BasicSbor)]
#[sbor(transparent)]
pub struct VotePower(u64);

impl VotePower {
    /// Zero vote power — used as an accumulator initial value.
    pub const ZERO: Self = Self(0);

    /// Minimum positive vote power.
    pub const MIN: Self = Self(1);

    /// Construct vote power from a raw `u64`.
    ///
    /// Most call sites should use the `Add`/`Sub` operators or
    /// [`VotePower::saturating_add`] instead — this constructor is the escape
    /// hatch for boundaries (topology decode, tests) where the power genuinely
    /// originates as a raw integer. Use [`VotePower::ZERO`] / [`VotePower::MIN`]
    /// for the obvious sentinels rather than `new(0)` / `new(1)`.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Inner `u64`. Use sparingly — at boundaries (display, hashing,
    /// stake-weighted timestamp arithmetic that needs `u128` widening) only.
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

    /// Minimum voting power required for 2f+1 quorum out of `total`.
    ///
    /// Equivalent to `total * 2 / 3 + 1` but divides first so the multiply
    /// cannot overflow when `total` is near `u64::MAX`.
    #[must_use]
    pub const fn quorum_threshold(total: Self) -> Self {
        Self(total.0 / 3 * 2 + (total.0 % 3) * 2 / 3 + 1)
    }
}

impl Add for VotePower {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(
            self.0
                .checked_add(rhs.0)
                .expect("VotePower + VotePower overflowed"),
        )
    }
}

impl AddAssign for VotePower {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = self
            .0
            .checked_add(rhs.0)
            .expect("VotePower += VotePower overflowed");
    }
}

impl Sub for VotePower {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(
            self.0
                .checked_sub(rhs.0)
                .expect("VotePower - VotePower underflowed"),
        )
    }
}

impl SubAssign for VotePower {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = self
            .0
            .checked_sub(rhs.0)
            .expect("VotePower -= VotePower underflowed");
    }
}

impl Sum for VotePower {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, Add::add)
    }
}

impl<'a> Sum<&'a Self> for VotePower {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.copied().fold(Self::ZERO, Add::add)
    }
}

impl Display for VotePower {
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
    fn test_vote_power_quorum() {
        let total = VotePower::new(4);

        assert!(!VotePower::has_quorum(VotePower::new(2), total)); // 2/4 = 50% (not enough)
        assert!(VotePower::has_quorum(VotePower::new(3), total)); // 3/4 = 75% (quorum!)
        assert!(VotePower::has_quorum(VotePower::new(4), total)); // 4/4 = 100% (quorum!)
    }

    #[test]
    fn test_vote_power_quorum_boundary_conditions() {
        // BFT safety requires STRICTLY GREATER than 2/3
        // Formula: voted * 3 > total * 2
        let q = |v, t| VotePower::has_quorum(VotePower::new(v), VotePower::new(t));

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
    fn test_vote_power_quorum_large_values() {
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
            VotePower::has_quorum(
                VotePower::new(max_safe_voted),
                VotePower::new(max_safe_voted + 1)
            ),
            "Large values near u64::MAX/3 should work"
        );

        // The arithmetic widens to u128 internally, so even pathological
        // voting powers near u64::MAX cannot overflow. This guard pins the
        // edge case so a future regression to plain u64 multiplication
        // would surface here.
        assert!(VotePower::has_quorum(
            VotePower::new(u64::MAX),
            VotePower::new(u64::MAX)
        ));
        assert!(!VotePower::has_quorum(
            VotePower::ZERO,
            VotePower::new(u64::MAX)
        ));
    }

    #[test]
    fn test_vote_power_quorum_unequal_distribution() {
        // Test quorum with realistic unequal voting power distributions
        // In practice, validators may have different stakes
        let q = |v, t| VotePower::has_quorum(VotePower::new(v), VotePower::new(t));

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
