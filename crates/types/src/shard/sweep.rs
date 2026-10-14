//! How far a chain's sweep has reached.

use hyperscale_hbor::Hbor;
use hyperscale_vm_types::{
    LEAF_KEY_BYTES, SWEEP_BUCKET_BYTES, SWEEP_BUCKET_SHIFT, SubstateKey, SweepBucket,
};

use crate::WeightedTimestamp;

/// A position in a chain's sweep: the leaf key rotated to put the expiry
/// bucket first.
///
/// `bucket ++ owner ++ local[SWEEP_BUCKET_BYTES..]` — the same bytes a
/// sweepable leaf key holds and none added, since the bucket already
/// leads that key's local half. Rotating them is what makes byte order
/// the order a sweep visits cells in: the index is keyed
/// `(bucket, owner)`, and one row's leaves sort by their local half.
///
/// A plain leaf key would not do. Leaf keys are owner-major, because an
/// owner prefix fixes a key's shard, so their order interleaves buckets
/// and a walk over them is not a walk by expiry.
///
/// Positions between cells are nameable, which is what lets a frontier
/// say it finished an empty bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
#[hbor(transparent)]
pub struct SweepFrontier(pub [u8; LEAF_KEY_BYTES]);

impl SweepFrontier {
    /// Where a chain's sweep starts: below every cell.
    ///
    /// A structural genesis resolves here — a split child, a merged
    /// parent — rather than inheriting a predecessor's. A frontier is
    /// only safe carried down: a merge that adopted the higher of two
    /// cursors would leave every cell the other predecessor held between
    /// them below the successor's cursor, unswept and unreachable.
    pub const ZERO: Self = Self([0; LEAF_KEY_BYTES]);

    /// The position a sweepable cell occupies.
    #[must_use]
    pub fn of_leaf(key: SubstateKey) -> Self {
        let mut bytes = [0u8; LEAF_KEY_BYTES];
        bytes[..SWEEP_BUCKET_BYTES].copy_from_slice(&key.local.0[..SWEEP_BUCKET_BYTES]);
        bytes[SWEEP_BUCKET_BYTES..SWEEP_BUCKET_BYTES + 32].copy_from_slice(&key.owner.to_bytes());
        bytes[SWEEP_BUCKET_BYTES + 32..].copy_from_slice(&key.local.0[SWEEP_BUCKET_BYTES..]);
        Self(bytes)
    }

    /// The bucket this position sits in.
    #[must_use]
    pub const fn bucket(self) -> SweepBucket {
        SweepBucket(u32::from_be_bytes([
            self.0[0], self.0[1], self.0[2], self.0[3],
        ]))
    }

    /// The first position in `bucket` — below every cell it holds.
    #[must_use]
    pub fn start_of(bucket: SweepBucket) -> Self {
        let mut bytes = [0u8; LEAF_KEY_BYTES];
        bytes[..SWEEP_BUCKET_BYTES].copy_from_slice(&bucket.to_bytes());
        Self(bytes)
    }

    /// The furthest a block anchored at `clock` may advance its frontier:
    /// the start of the bucket `clock` itself falls in.
    ///
    /// Every position below this is in a bucket wholly in the past, so a
    /// cell the frontier passes is expired by construction and its
    /// ordering never has to be decided from an expiry the walk would
    /// have to read. The cost is that a removal lags its expiry by up to
    /// one bucket, which delays a removal and can never advance one.
    #[must_use]
    pub fn ceiling_at(clock: WeightedTimestamp) -> Self {
        Self::start_of(SweepBucket::of(clock.as_millis()))
    }
}

/// Whether `expiry_ms` is old enough for a block anchored at `clock` to
/// remove the cell that carries it.
///
/// The frontier's ceiling already implies this for anything it passes;
/// this is the direct statement of it.
#[must_use]
pub const fn expired_at(expiry_ms: u64, clock: WeightedTimestamp) -> bool {
    expiry_ms <= clock.as_millis()
}

/// A bucket spans this many milliseconds.
pub const SWEEP_BUCKET_MS: u64 = 1 << SWEEP_BUCKET_SHIFT;

#[cfg(test)]
mod tests {
    use hyperscale_vm_types::{Address, AddressClass, LocalKey};

    use super::*;

    fn leaf(bucket: u32, owner: u8, body: u8) -> SubstateKey {
        let mut local = [body; 16];
        local[..SWEEP_BUCKET_BYTES].copy_from_slice(&bucket.to_be_bytes());
        SubstateKey {
            owner: Address::new([owner; 31], AddressClass::Principal),
            local: LocalKey(local),
        }
    }

    #[test]
    fn the_frontier_orders_by_bucket_before_owner() {
        // The property leaf keys do not have: a later bucket under an
        // earlier owner still sorts after.
        let early_bucket_late_owner = SweepFrontier::of_leaf(leaf(1, 0xFF, 0));
        let late_bucket_early_owner = SweepFrontier::of_leaf(leaf(2, 0x00, 0));
        assert!(early_bucket_late_owner < late_bucket_early_owner);
        assert!(leaf(2, 0x00, 0).to_bytes() < leaf(1, 0xFF, 0).to_bytes());
    }

    #[test]
    fn within_a_bucket_the_frontier_orders_as_the_leaves_do() {
        for (a, b) in [
            (leaf(5, 1, 0), leaf(5, 1, 9)),
            (leaf(5, 1, 9), leaf(5, 2, 0)),
        ] {
            assert!(SweepFrontier::of_leaf(a) < SweepFrontier::of_leaf(b));
            assert!(a.to_bytes() < b.to_bytes());
        }
    }

    #[test]
    fn a_buckets_start_sits_below_every_cell_in_it_and_above_the_one_before() {
        let start = SweepFrontier::start_of(SweepBucket(5));
        assert!(start < SweepFrontier::of_leaf(leaf(5, 0, 0)));
        assert!(SweepFrontier::of_leaf(leaf(4, 0xFF, 0xFF)) < start);
        assert_eq!(start.bucket(), SweepBucket(5));
        assert_eq!(SweepFrontier::ZERO.bucket(), SweepBucket(0));
    }

    #[test]
    fn the_ceiling_excludes_the_clocks_own_bucket() {
        let clock = WeightedTimestamp::from_millis(3 * SWEEP_BUCKET_MS + 7);
        let ceiling = SweepFrontier::ceiling_at(clock);
        assert_eq!(ceiling, SweepFrontier::start_of(SweepBucket(3)));
        // A cell expiring inside the clock's own bucket is not reachable
        // even when it is already past. That is the lag the layout buys.
        assert!(SweepFrontier::of_leaf(leaf(3, 0, 0)) > ceiling);
        assert!(expired_at(3 * SWEEP_BUCKET_MS, clock));
        // Everything the ceiling does admit is expired by construction:
        // the last instant of the last bucket below it is still past.
        assert!(expired_at(3 * SWEEP_BUCKET_MS - 1, clock));
    }
}
