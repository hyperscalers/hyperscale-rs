//! The shard's attested load, as a block header states it.

use hyperscale_hbor::Hbor;
use hyperscale_vm_types::{BASIS_POINTS, DeclaredWork, FiveWay, Utilization};

/// What a block attests about its shard's load: what the chain has
/// consumed, what its blocks reserved, and the state it holds.
///
/// Every figure is header content, so a consumer reads them off a header
/// it already holds — the beacon off the boundary header it sources each
/// epoch, a joining node off the block it joined at — and every replica
/// recomputes them before voting. The pair is deliberately two shapes:
///
/// - [`cumulative_work`](Self::cumulative_work) is a **flow**, carried as a
///   running total over the chain's whole history. A consumer wanting one
///   epoch's consumption differences it against the total it last
///   recorded, which makes the quantity monotone and its application
///   idempotent: a missed boundary crossing is absorbed by the next one
///   instead of lost. Carrying the total rather than the increment is
///   also what lets a node that joined mid-chain continue the count —
///   the block it synced to states the running total, so nothing has to
///   reconstruct it from history the joiner does not have.
/// - [`used`](Self::used) is a flow on the same terms, kept per
///   dimension because its consumer moves each price row by its own
///   dimension's use — a scalar would hide a network saturating disk
///   while compute idles, which is the thing the vector exists to show.
/// - [`substate_bytes`](Self::substate_bytes) is a **level**, the byte
///   total behind the block's parent state. A consumer records it as-is,
///   and a missed crossing simply leaves the value unrefreshed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hbor)]
pub struct ShardLoad {
    /// Work this chain has attested over its whole history, through the
    /// certificates the block itself carries.
    ///
    /// Priced by the engine's schedule, which combines the compute an
    /// execution consumed with the footprint its declaration claimed —
    /// so a participant that applied almost nothing still reports the
    /// exclusivity it held. Consensus carries the one scalar and never
    /// the ratio behind it.
    ///
    /// Accumulation saturates rather than wrapping. Wrapping would break
    /// the monotonicity a differencing consumer relies on, and it has no
    /// honest reading: the epoch it straddles would come out as zero
    /// consumption or as the whole counter's width.
    pub cumulative_work: u64,
    /// What this chain's blocks have reserved against their per-block
    /// caps over its whole history, dimension by dimension.
    ///
    /// A flow like [`cumulative_work`](Self::cumulative_work) and for
    /// the same reasons, but a vector rather than a scalar: the beacon
    /// moves each row of the price table by its own dimension's use, so
    /// a network saturating disk while compute idles has to be readable
    /// as exactly that. Differenced across an epoch against the block
    /// count, it is the utilization the controller steps on.
    ///
    /// Declared, never measured: the figure is the sum of what the
    /// block's transactions reserved on this shard, which is what
    /// `BLOCK_CAPS` capped and what every replica recomputes before
    /// voting.
    pub used: DeclaredWork,
    /// Committed substate byte total behind the block's parent state —
    /// the same quantity the reshape predicate evaluates.
    ///
    /// `None` under exactly the condition that takes that predicate out
    /// of play: the block's ancestry crosses a halt recovery's
    /// sync-admitted suffix, where the total is unknowable until the
    /// suffix commits. Every replica that can vote on the block resolves
    /// the same absence, so the claim stays agreed.
    pub substate_bytes: Option<u64>,
}

impl ShardLoad {
    /// Nothing consumed and no resolved byte total.
    ///
    /// Every structural genesis header's load: a chain starts its own
    /// count at zero — including a split child or a merged parent, which
    /// inherit state but not their predecessor's attested work — and a
    /// genesis block has no parent state to have a total behind.
    pub const ZERO: Self = Self {
        cumulative_work: 0,
        used: DeclaredWork::ZERO,
        substate_bytes: None,
    };

    /// This load advanced by `work` and `used`, and re-anchored on
    /// `substate_bytes`.
    ///
    /// The successor relation the proposer applies and every verifier
    /// recomputes, so neither side can drift on the arithmetic.
    #[must_use]
    pub const fn advance(self, work: u64, used: DeclaredWork, substate_bytes: Option<u64>) -> Self {
        Self {
            cumulative_work: self.cumulative_work.saturating_add(work),
            used: self.used.saturating_add(used),
            substate_bytes,
        }
    }
}

/// Epochs a shard's fullness mean remembers.
///
/// The time constant of the mean below, not a window: one epoch moves a
/// row by an eighth of the distance to the reading, so a single busy
/// epoch cannot trip a split and a shard that has been busy for an hour
/// cannot avoid one. At the production epoch that is forty minutes to
/// most of the way, which is the order a split should take — it costs a
/// committee, a state handoff and a keyspace cut.
pub const FULLNESS_EPOCHS: u32 = 8;

/// The share of its block caps a shard's blocks have been spending, per
/// dimension, in basis points.
///
/// A mean the beacon advances once per epoch from the same deltas the
/// price controller reads, and the second thing that can make a shard
/// too big: the controller's own reading is the network's mean, which by
/// construction cannot see one hot shard among idle ones, so what
/// answers a hotspot is capacity rather than a price every sender pays.
///
/// Per dimension, so a shard saturating disk while its compute idles is
/// readable as exactly that — the reason the declared vector stays a
/// vector.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub struct ShardFullness {
    /// Fuel declared against fuel available.
    pub compute: u32,
    /// Read bytes declared against read bytes available.
    pub read_bytes: u32,
    /// Write bytes declared against write bytes available.
    pub write_bytes: u32,
    /// Footprint declared against footprint available.
    pub footprint: u32,
    /// Retained bytes declared against retained bytes available.
    pub retention: u32,
}

impl ShardFullness {
    /// A shard that has declared nothing against its caps.
    ///
    /// What a chain starts at, a split child included: a child inherits
    /// state but not its parent's spending, so it earns its own split
    /// over [`FULLNESS_EPOCHS`] rather than being born eligible for one.
    pub const IDLE: Self = Self {
        compute: 0,
        read_bytes: 0,
        write_bytes: 0,
        footprint: 0,
        retention: 0,
    };

    /// This mean advanced by one epoch's `reading`.
    ///
    /// Each row moves an [`FULLNESS_EPOCHS`]th of the way to what the
    /// epoch declared. A dimension the epoch had no capacity in holds
    /// where it is, for the reason the price controller holds a row:
    /// there was no reading, and reading an outage as idleness would
    /// walk a busy shard back under its threshold while it was down.
    #[must_use]
    pub fn folding(self, reading: &FiveWay) -> Self {
        Self {
            compute: fold_row(self.compute, reading.compute),
            read_bytes: fold_row(self.read_bytes, reading.read_bytes),
            write_bytes: fold_row(self.write_bytes, reading.write_bytes),
            footprint: fold_row(self.footprint, reading.footprint),
            retention: fold_row(self.retention, reading.retention),
        }
    }

    /// The fullest dimension, which is the one a threshold is read
    /// against: a shard is too busy when any one of its caps is the
    /// thing binding it.
    #[must_use]
    pub const fn peak(&self) -> u32 {
        let mut most = self.compute;
        if self.read_bytes > most {
            most = self.read_bytes;
        }
        if self.write_bytes > most {
            most = self.write_bytes;
        }
        if self.footprint > most {
            most = self.footprint;
        }
        if self.retention > most {
            most = self.retention;
        }
        most
    }
}

/// One row of the mean, moved an [`FULLNESS_EPOCHS`]th of the way to
/// this epoch's ratio.
fn fold_row(mean: u32, reading: Utilization) -> u32 {
    let Utilization { used, capacity } = reading;
    if capacity == 0 {
        return mean;
    }
    // A block cannot declare past its own budget, so a figure that does
    // is a defect rather than a reading and enters as a full epoch.
    let ratio =
        (used.saturating_mul(u128::from(BASIS_POINTS)) / capacity).min(u128::from(BASIS_POINTS));
    let epochs = u64::from(FULLNESS_EPOCHS);
    #[allow(clippy::cast_possible_truncation)] // both terms are under BASIS_POINTS
    let ratio = ratio as u64;
    let next = (u64::from(mean) * (epochs - 1) + ratio) / epochs;
    #[allow(clippy::cast_possible_truncation)] // a mean of figures under BASIS_POINTS
    {
        next as u32
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;

    /// A vector with `compute` set and nothing else, so a test can move
    /// one dimension and read that the others held.
    const fn compute(compute: u64) -> DeclaredWork {
        DeclaredWork {
            compute,
            ..DeclaredWork::ZERO
        }
    }

    #[test]
    fn advance_accumulates_the_flows_and_replaces_the_byte_level() {
        let start = ShardLoad::ZERO;
        let next = start.advance(70, compute(7), Some(4_096));
        assert_eq!(next.cumulative_work, 70);
        assert_eq!(next.used.compute, 7);
        assert_eq!(next.substate_bytes, Some(4_096));

        // Both flows accumulate; the byte total is a level, so it
        // replaces.
        let later = next.advance(30, compute(3), Some(8_192));
        assert_eq!(later.cumulative_work, 100);
        assert_eq!(later.used.compute, 10);
        assert_eq!(later.substate_bytes, Some(8_192));

        // An unresolved byte total does not disturb either flow.
        let unresolved = later.advance(5, compute(1), None);
        assert_eq!(unresolved.cumulative_work, 105);
        assert_eq!(unresolved.used.compute, 11);
        assert_eq!(unresolved.substate_bytes, None);

        // Each dimension accumulates on its own: a block declaring only
        // reads leaves the compute total where it was.
        let reads = unresolved.advance(
            0,
            DeclaredWork {
                read_bytes: 4_096,
                ..DeclaredWork::ZERO
            },
            None,
        );
        assert_eq!(reads.used.compute, 11);
        assert_eq!(reads.used.read_bytes, 4_096);
    }

    #[test]
    fn saturating_accumulation_does_not_wrap() {
        let brim = ShardLoad::ZERO.advance(u64::MAX, compute(u64::MAX), None);
        let past = brim.advance(1_000, compute(1_000), None);
        assert_eq!(past.cumulative_work, u64::MAX);
        assert_eq!(past.used.compute, u64::MAX);
    }

    #[test]
    fn hbor_round_trip_covers_both_byte_total_arms() {
        for load in [
            ShardLoad::ZERO,
            ShardLoad::ZERO.advance(1, compute(1), Some(0)),
            ShardLoad::ZERO.advance(u64::MAX, compute(u64::MAX), Some(u64::MAX)),
        ] {
            let bytes = hbor_to_vec(&load).unwrap();
            assert_eq!(hbor_from_slice::<ShardLoad>(&bytes).unwrap(), load);
        }
    }
}
